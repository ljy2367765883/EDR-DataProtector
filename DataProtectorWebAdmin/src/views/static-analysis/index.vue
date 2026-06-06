<script setup lang="tsx">
import { computed, h, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import LogicFlow from '@logicflow/core';
import '@logicflow/core/dist/index.css';
import type { DataTableColumns, PaginationProps, UploadCustomRequestOptions } from 'naive-ui';
import { NButton, NProgress, NTag, useMessage } from 'naive-ui';
import {
  fetchRemoveStaticAnalysisSample,
  fetchResetStaticAnalysisRules,
  fetchSaveStaticAnalysisConfig,
  fetchSaveStaticAnalysisRules,
  fetchStartStaticAnalysis,
  fetchStaticAnalysisConfig,
  fetchStaticAnalysisRules,
  fetchStaticAnalysisSamples,
  fetchStaticAnalysisSource,
  fetchSubmitStaticAnalysisSample
} from '@/service/api';

defineOptions({
  name: 'StaticAnalysis'
});

type StaticReport = {
  schema?: string;
  runId?: string;
  generatedUtc?: string;
  sample?: Record<string, any>;
  engine?: Record<string, any>;
  ghidra?: {
    program?: Record<string, any>;
    imports?: Array<Record<string, any>>;
    strings?: Array<Record<string, any>>;
    functions?: Array<Record<string, any>>;
    callGraph?: Array<Record<string, any>>;
    features?: {
      hits?: string[];
      histogram?: Record<string, number>;
    };
    limits?: Record<string, any>;
  };
  ruleScore?: {
    score: number;
    verdict: string;
    severity: string;
    hits?: Array<{
      ruleId: string;
      name: string;
      target: string;
      pattern: string;
      weight: number;
      severity: string;
      verdict: string;
      description: string;
      evidence?: string[];
    }>;
  };
  ai?: {
    enabled: boolean;
    status: string;
    model: string;
    verdict: string;
    summary: string;
    raw: string;
    error: string;
    endpoint?: string;
    streamed?: boolean;
    httpStatus?: number;
    elapsedMs?: number;
    requestBytes?: number;
    responseBytes?: number;
    contentChars?: number;
  };
};

type FlowGraphData = Parameters<LogicFlow['render']>[0];

const message = useMessage();
const loading = ref(false);
const configLoading = ref(false);
const ruleLoading = ref(false);
const uploading = ref(false);
const analyzing = ref(false);
const savingConfig = ref(false);
const savingRules = ref(false);
const response = ref<Api.DataProtector.StaticAnalysisSampleQueryResponse | null>(null);
const config = ref<Api.DataProtector.StaticAnalysisConfiguration | null>(null);
const rules = ref<Api.DataProtector.StaticAnalysisRule[]>([]);
const sourceInfo = ref<Api.DataProtector.StaticAnalysisSourceInfo | null>(null);
const selectedSampleId = ref('');
const callGraphRef = ref<HTMLElement | null>(null);
let callGraphFlow: LogicFlow | null = null;
let pollTimer: number | null = null;

const query = reactive<Api.DataProtector.StaticAnalysisSampleQuery>({
  page: 1,
  pageSize: 30,
  status: 'all',
  verdict: 'all',
  search: ''
});

const configForm = reactive<Api.DataProtector.StaticAnalysisConfigurationRequest>({
  enabled: true,
  aiEnabled: false,
  ghidraRoot: '',
  javaPath: '',
  baseUrl: '',
  token: '',
  clearToken: false,
  model: 'gpt-4.1-mini',
  temperature: 0.1,
  maxFunctions: 220,
  maxDecompilerChars: 160000,
  timeoutSeconds: 900,
  actor: 'web-admin'
});

const analyzeForm = reactive({
  maxFunctions: 220,
  maxDecompilerChars: 160000,
  aiEnabled: true
});

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 30,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [20, 30, 50, 100],
  onChange(page) {
    query.page = page;
    pagination.page = page;
    refreshSamples(false);
  },
  onUpdatePageSize(pageSize) {
    query.pageSize = pageSize;
    query.page = 1;
    pagination.pageSize = pageSize;
    pagination.page = 1;
    refreshSamples(false);
  }
});

const samples = computed(() => response.value?.items || []);
const selectedSample = computed(() => samples.value.find(item => item.sampleId === selectedSampleId.value) || null);
const report = computed(() => parseJson<StaticReport | null>(selectedSample.value?.reportJson, null));
const stats = computed(() => ({
  total: response.value?.total || 0,
  running: response.value?.runningTotal || 0,
  completed: response.value?.completedTotal || 0,
  failed: response.value?.failedTotal || 0,
  malicious: response.value?.maliciousTotal || 0,
  suspicious: response.value?.suspiciousTotal || 0
}));

const dangerousImports = computed(() => (report.value?.ghidra?.imports || []).filter(item => item.danger).slice(0, 80));
const suspiciousStrings = computed(() => (report.value?.ghidra?.strings || []).filter(item => item.suspicious).slice(0, 80));
const highSignalFunctions = computed(() =>
  (report.value?.ghidra?.functions || [])
    .filter(item => Array.isArray(item.featureHits) && item.featureHits.length > 0)
    .slice(0, 80)
);
const featureHits = computed(() => report.value?.ghidra?.features?.hits?.slice(0, 120) || []);
const ruleHits = computed(() => report.value?.ruleScore?.hits || []);
const callGraph = computed<FlowGraphData>(() => buildCallGraph(report.value));
const aiMarkdown = computed(() => renderMarkdown(report.value?.ai?.summary || '未启用 AI，当前仅展示规则评分和 Ghidra 证据。'));
const aiMeta = computed(() => {
  const ai = report.value?.ai;
  if (!ai) return [];
  return [
    { label: '状态', value: ai.status || '-' },
    { label: '模型', value: ai.model || '-' },
    { label: '判定', value: ai.verdict || '-' },
    { label: 'HTTP', value: ai.httpStatus ? String(ai.httpStatus) : '-' },
    { label: '耗时', value: ai.elapsedMs ? `${ai.elapsedMs} ms` : '-' },
    { label: '流式', value: ai.streamed ? '是' : '否' },
    { label: '请求', value: ai.requestBytes ? formatBytes(ai.requestBytes) : '-' },
    { label: '响应', value: ai.responseBytes ? formatBytes(ai.responseBytes) : '-' }
  ];
});

const statusOptions = [
  { label: '全部状态', value: 'all' },
  { label: '待分析', value: 'queued' },
  { label: '分析中', value: 'running' },
  { label: '已完成', value: 'completed' },
  { label: '失败', value: 'failed' }
];

const verdictOptions = [
  { label: '全部结论', value: 'all' },
  { label: '恶意', value: 'malicious' },
  { label: '可疑', value: 'suspicious' },
  { label: '观察', value: 'observed' },
  { label: '干净', value: 'clean' },
  { label: '失败', value: 'failed' }
];

const ruleTargetOptions = [
  { label: '任意证据', value: 'any' },
  { label: '导入表', value: 'import' },
  { label: '字符串', value: 'string' },
  { label: '函数摘要', value: 'function' },
  { label: '反伪代码', value: 'pseudocode' },
  { label: '特征命中', value: 'feature' }
];

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '警告', value: 'warning' },
  { label: '信息', value: 'info' }
];

const ruleVerdictOptions = [
  { label: '恶意', value: 'malicious' },
  { label: '可疑', value: 'suspicious' },
  { label: '观察', value: 'observed' },
  { label: '干净', value: 'clean' }
];

const sampleColumns = computed<DataTableColumns<Api.DataProtector.StaticAnalysisSample>>(() => [
  {
    title: '样本',
    key: 'fileName',
    minWidth: 260,
    render(row) {
      return h('div', { class: 'cell-stack' }, [
        h('strong', row.fileName || '-'),
        h('span', row.sha256 || '-')
      ]);
    }
  },
  {
    title: '结论',
    key: 'verdict',
    width: 135,
    render(row) {
      return h(NTag, { type: verdictTag(row.verdict), bordered: false }, { default: () => verdictLabel(row.verdict) });
    }
  },
  {
    title: '分数',
    key: 'score',
    width: 110,
    sorter: (a, b) => (a.score || 0) - (b.score || 0),
    render(row) {
      return h('div', { class: 'score-cell' }, [h('strong', row.score || 0), h('span', '/100')]);
    }
  },
  {
    title: '状态',
    key: 'status',
    width: 190,
    render(row) {
      return h('div', { class: 'progress-cell' }, [
        h('div', { class: 'progress-head' }, [
          h(NTag, { type: statusTag(row.status), bordered: false }, { default: () => statusLabel(row.status) }),
          h('span', `${normalizeProgress(row.progress)}%`)
        ]),
        h(NProgress, {
          type: 'line',
          percentage: normalizeProgress(row.progress),
          showIndicator: false,
          height: 6,
          processing: row.status === 'running',
          status: row.status === 'failed' ? 'error' : row.status === 'completed' ? 'success' : 'info'
        }),
        h('span', { class: 'stage-line' }, row.stageText || stageLabel(row.stage) || '-')
      ]);
    }
  },
  {
    title: '文件信息',
    key: 'sizeBytes',
    minWidth: 220,
    render(row) {
      return h('div', { class: 'cell-stack' }, [
        h('strong', `${row.architecture || 'unknown'} / ${formatBytes(row.sizeBytes)}`),
        h('span', row.signatureStatus === 'signed' ? row.signer || 'signed' : 'unsigned')
      ]);
    }
  },
  {
    title: '提交时间',
    key: 'submittedUtc',
    width: 190,
    render(row) {
      return formatTime(row.submittedUtc);
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 250,
    render(row) {
      return h('div', { class: 'action-row' }, [
        h(
          NButton,
          {
            size: 'small',
            type: 'primary',
            ghost: true,
            disabled: row.status === 'running',
            loading: analyzing.value && selectedSampleId.value === row.sampleId,
            onClick: (event: MouseEvent) => {
              event.stopPropagation();
              analyze(row);
            }
          },
          { default: () => '分析' }
        ),
        h(
          NButton,
          {
            size: 'small',
            ghost: true,
            disabled: !row.reportJson,
            onClick: (event: MouseEvent) => {
              event.stopPropagation();
              selectSample(row);
              scrollToReport();
            }
          },
          { default: () => '报告' }
        ),
        h(
          NButton,
          {
            size: 'small',
            type: 'error',
            ghost: true,
            disabled: row.status === 'running',
            onClick: (event: MouseEvent) => {
              event.stopPropagation();
              removeSample(row);
            }
          },
          { default: () => '删除' }
        )
      ]);
    }
  }
]);

const ruleColumns = computed<DataTableColumns<Api.DataProtector.StaticAnalysisRule>>(() => [
  {
    title: '启用',
    key: 'enabled',
    width: 82,
    render(row) {
      return h('input', {
        type: 'checkbox',
        checked: row.enabled,
        onChange: (event: Event) => {
          row.enabled = (event.target as HTMLInputElement).checked;
        }
      });
    }
  },
  {
    title: '规则',
    key: 'name',
    minWidth: 220,
    render(row) {
      return h('div', { class: 'cell-stack' }, [
        h('strong', row.name || '-'),
        h('span', row.description || '-')
      ]);
    }
  },
  {
    title: '目标',
    key: 'target',
    width: 130,
    render(row) {
      return h(NTag, { bordered: false }, { default: () => targetLabel(row.target) });
    }
  },
  { title: '模式', key: 'pattern', minWidth: 260, ellipsis: { tooltip: true } },
  {
    title: '权重',
    key: 'weight',
    width: 100,
    render(row) {
      return h('strong', row.weight);
    }
  },
  {
    title: '等级',
    key: 'severity',
    width: 110,
    render(row) {
      return h(NTag, { type: severityTag(row.severity), bordered: false }, { default: () => severityLabel(row.severity) });
    }
  }
]);

function syncConfigForm(value: Api.DataProtector.StaticAnalysisConfiguration | null) {
  if (!value) return;
  configForm.enabled = value.enabled;
  configForm.aiEnabled = value.aiEnabled;
  configForm.ghidraRoot = value.ghidraRoot || '';
  configForm.javaPath = value.javaPath || '';
  configForm.baseUrl = value.baseUrl || '';
  configForm.token = '';
  configForm.clearToken = false;
  configForm.model = value.model || 'gpt-4.1-mini';
  configForm.temperature = value.temperature ?? 0.1;
  configForm.maxFunctions = value.maxFunctions || 220;
  configForm.maxDecompilerChars = value.maxDecompilerChars || 160000;
  configForm.timeoutSeconds = value.timeoutSeconds || 900;
  analyzeForm.maxFunctions = configForm.maxFunctions;
  analyzeForm.maxDecompilerChars = configForm.maxDecompilerChars;
  analyzeForm.aiEnabled = value.aiEnabled;
}

async function refreshConfig() {
  configLoading.value = true;
  try {
    const [configResult, sourceResult] = await Promise.all([fetchStaticAnalysisConfig(), fetchStaticAnalysisSource()]);
    if (!configResult.error) {
      config.value = configResult.data;
      syncConfigForm(configResult.data);
    }
    if (!sourceResult.error) {
      sourceInfo.value = sourceResult.data;
    }
  } finally {
    configLoading.value = false;
  }
}

async function refreshRules() {
  ruleLoading.value = true;
  try {
    const { error, data } = await fetchStaticAnalysisRules();
    if (!error) {
      rules.value = data;
    }
  } finally {
    ruleLoading.value = false;
  }
}

async function refreshSamples(silent: boolean) {
  if (!silent) loading.value = true;
  try {
    const { error, data } = await fetchStaticAnalysisSamples(query);
    if (!error) {
      response.value = data;
      pagination.itemCount = data.total;
      pagination.page = data.page;
      pagination.pageSize = data.pageSize;
      if (!selectedSampleId.value && data.items.length) selectedSampleId.value = data.items[0].sampleId;
      if (selectedSampleId.value && !data.items.some(item => item.sampleId === selectedSampleId.value) && data.items.length) {
        selectedSampleId.value = data.items[0].sampleId;
      }
      renderCallGraph();
    }
  } finally {
    loading.value = false;
  }
}

async function saveConfig() {
  savingConfig.value = true;
  try {
    const { error, data } = await fetchSaveStaticAnalysisConfig({ ...configForm, actor: 'web-admin' });
    if (!error && data.succeeded) {
      message.success('静态分析配置已保存。');
      await refreshConfig();
    }
  } finally {
    savingConfig.value = false;
  }
}

async function saveRules() {
  savingRules.value = true;
  try {
    const { error, data } = await fetchSaveStaticAnalysisRules({ rules: rules.value, actor: 'web-admin' });
    if (!error && data.succeeded) {
      message.success('评分规则已保存。');
      await refreshRules();
    }
  } finally {
    savingRules.value = false;
  }
}

async function resetRules() {
  const { error, data } = await fetchResetStaticAnalysisRules();
  if (!error && data.succeeded) {
    message.success('评分规则已恢复默认。');
    await refreshRules();
  }
}

async function uploadSample(options: UploadCustomRequestOptions) {
  const file = options.file.file;
  if (!file) {
    options.onError?.();
    return;
  }

  if (!file.name.toLowerCase().endsWith('.exe')) {
    message.warning('目前仅支持 EXE 样本。');
    options.onError?.();
    return;
  }

  uploading.value = true;
  try {
    const contentBase64 = await fileToBase64(file);
    const { error, data } = await fetchSubmitStaticAnalysisSample({
      fileName: file.name,
      contentBase64,
      source: 'web',
      notes: 'Web 管理端手动提交',
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success('样本已提交到静态分析队列。');
      await refreshSamples(true);
      options.onFinish?.();
      return;
    }
    options.onError?.();
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error));
    options.onError?.();
  } finally {
    uploading.value = false;
  }
}

async function analyze(row = selectedSample.value) {
  if (!row) return;
  selectedSampleId.value = row.sampleId;
  analyzing.value = true;
  try {
    const { error, data } = await fetchStartStaticAnalysis({
      sampleId: row.sampleId,
      maxFunctions: analyzeForm.maxFunctions,
      maxDecompilerChars: analyzeForm.maxDecompilerChars,
      aiEnabled: analyzeForm.aiEnabled,
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success('智慧静态分析已启动。');
      startPolling();
      await refreshSamples(false);
    }
  } finally {
    analyzing.value = false;
  }
}

function selectSample(row: Api.DataProtector.StaticAnalysisSample) {
  selectedSampleId.value = row.sampleId;
  window.requestAnimationFrame(renderCallGraph);
}

function rowKey(row: Api.DataProtector.StaticAnalysisSample) {
  return row.sampleId;
}

function rowProps(row: Api.DataProtector.StaticAnalysisSample) {
  return {
    class: row.sampleId === selectedSampleId.value ? 'selected-row' : '',
    onClick: () => selectSample(row)
  };
}

function removeSample(row: Api.DataProtector.StaticAnalysisSample) {
  window.$dialog?.warning({
    title: '删除静态分析样本',
    content: `确认删除 ${row.fileName} 的样本、报告和运行目录吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveStaticAnalysisSample({ sampleId: row.sampleId, actor: 'web-admin' });
      if (!error && data.succeeded) {
        if (selectedSampleId.value === row.sampleId) selectedSampleId.value = '';
        message.success('样本已删除。');
        await refreshSamples(false);
      }
    }
  });
}

function clearSamples() {
  window.$dialog?.warning({
    title: '清空静态分析历史',
    content: '确认清空所有样本记录、报告和服务器样本文件吗？',
    positiveText: '清空',
    negativeText: '取消',
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveStaticAnalysisSample({ all: true, actor: 'web-admin' });
      if (!error && data.succeeded) {
        selectedSampleId.value = '';
        message.success('静态分析历史已清空。');
        await refreshSamples(false);
      }
    }
  });
}

function addRule() {
  rules.value.unshift({
    ruleId: `web-${Date.now()}`,
    name: '新静态规则',
    enabled: true,
    target: 'any',
    pattern: '',
    regex: false,
    weight: 10,
    severity: 'warning',
    verdict: 'suspicious',
    description: ''
  });
}

function removeRule(index: number) {
  rules.value.splice(index, 1);
}

function startPolling() {
  stopPolling();
  pollTimer = window.setInterval(async () => {
    await refreshSamples(true);
    if (!samples.value.some(item => item.status === 'running')) stopPolling();
  }, 3000);
}

function stopPolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
}

function scrollToReport() {
  window.requestAnimationFrame(() => {
    document.getElementById('static-analysis-report')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

function buildCallGraph(value: StaticReport | null): FlowGraphData {
  const edges = value?.ghidra?.callGraph || [];
  const nodes = new Map<string, { id: string; text: string; x: number; y: number; type: string; properties: Record<string, any> }>();
  const flowEdges: any[] = [];
  const limitedEdges = edges.slice(0, 120);
  const addNode = (name: string, external = false) => {
    const id = safeNodeId(name || 'unknown');
    if (!nodes.has(id)) {
      const index = nodes.size;
      nodes.set(id, {
        id,
        type: 'rect',
        x: 150 + (index % 4) * 230,
        y: 70 + Math.floor(index / 4) * 96,
        text: truncate(name || 'unknown', 24),
        properties: {
          style: {
            width: 176,
            height: 44,
            radius: 4,
            fill: external ? '#f8fafc' : '#ffffff',
            stroke: external ? '#cbd5e1' : '#64748b',
            strokeWidth: 1.2
          }
        }
      });
    }
    return id;
  };

  limitedEdges.forEach((edge, index) => {
    const from = String(edge.from || edge.fromEntry || 'entry');
    const to = String(edge.to || edge.toEntry || 'unknown');
    const fromId = addNode(from, false);
    const toId = addNode(to, Boolean(edge.external));
    flowEdges.push({
      id: `static-call-edge-${index}`,
      type: 'polyline',
      sourceNodeId: fromId,
      targetNodeId: toId,
      properties: { style: { stroke: '#94a3b8', strokeWidth: 1.2 } }
    });
  });

  if (!nodes.size) {
    nodes.set('empty', {
      id: 'empty',
      type: 'rect',
      x: 240,
      y: 120,
      text: '暂无调用图',
      properties: {
        style: { width: 180, height: 44, radius: 4, fill: '#ffffff', stroke: '#cbd5e1' }
      }
    });
  }

  return { nodes: Array.from(nodes.values()), edges: flowEdges };
}

function createLogicFlow(container: HTMLElement) {
  const lf = new LogicFlow({
    container,
    grid: { size: 20, visible: true, type: 'mesh', config: { color: '#eef2f7', thickness: 1 } },
    isSilentMode: false,
    stopScrollGraph: false,
    stopZoomGraph: false,
    stopMoveGraph: false,
    adjustEdge: false,
    textEdit: false,
    nodeTextEdit: false,
    edgeTextEdit: false,
    allowRotate: false,
    allowResize: false,
    edgeType: 'polyline',
    style: {
      rect: { radius: 4 },
      nodeText: { color: '#334155', fontSize: 11, lineHeight: 14, overflowMode: 'ellipsis' },
      polyline: { stroke: '#94a3b8', strokeWidth: 1.2, fill: 'none' },
      arrow: { offset: 4, verticalLength: 2, endArrowType: 'none' }
    }
  });
  lf.updateEditConfig({
    adjustNodePosition: false,
    textEdit: false,
    nodeTextEdit: false,
    edgeTextEdit: false,
    hideAnchors: true
  });
  return lf;
}

function renderCallGraph() {
  if (!callGraphRef.value) return;
  callGraphFlow ??= createLogicFlow(callGraphRef.value);
  callGraphFlow.render(callGraph.value);
  window.setTimeout(() => {
    callGraphFlow?.resetZoom();
    callGraphFlow?.translateCenter();
  }, 0);
}

function renderMarkdown(value: string) {
  const lines = String(value || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const html: string[] = [];
  let paragraph: string[] = [];
  let listOpen = false;

  const closeParagraph = () => {
    if (paragraph.length) {
      html.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
      paragraph = [];
    }
  };
  const closeList = () => {
    if (listOpen) {
      html.push('</ul>');
      listOpen = false;
    }
  };

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    const line = raw.trim();
    if (!line) {
      closeParagraph();
      closeList();
      continue;
    }

    if (line.startsWith('|') && line.endsWith('|')) {
      closeParagraph();
      closeList();
      const rows: string[] = [];
      while (index < lines.length) {
        const tableLine = lines[index].trim();
        if (!tableLine.startsWith('|') || !tableLine.endsWith('|')) break;
        rows.push(tableLine);
        index += 1;
      }
      index -= 1;
      html.push(renderMarkdownTable(rows));
      continue;
    }

    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    if (heading) {
      closeParagraph();
      closeList();
      const level = Math.min(4, heading[1].length + 2);
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    const bullet = /^[-*]\s+(.+)$/.exec(line);
    if (bullet) {
      closeParagraph();
      if (!listOpen) {
        html.push('<ul>');
        listOpen = true;
      }
      html.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
      continue;
    }

    paragraph.push(line);
  }

  closeParagraph();
  closeList();
  return html.join('');
}

function renderMarkdownTable(rows: string[]) {
  const parsed = rows
    .map(row =>
      row
        .split('|')
        .slice(1, -1)
        .map(cell => cell.trim())
    )
    .filter(cells => cells.length > 0);
  if (!parsed.length) return '';
  const [head, maybeDivider, ...rest] = parsed;
  const body = (maybeDivider || []).every(cell => /^:?-{3,}:?$/.test(cell)) ? rest : parsed.slice(1);
  return [
    '<div class="markdown-table-wrap"><table>',
    '<thead><tr>',
    ...head.map(cell => `<th>${inlineMarkdown(cell)}</th>`),
    '</tr></thead>',
    '<tbody>',
    ...body.map(row => `<tr>${row.map(cell => `<td>${inlineMarkdown(cell)}</td>`).join('')}</tr>`),
    '</tbody></table></div>'
  ].join('');
}

function inlineMarkdown(value: string) {
  return escapeHtml(value)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function escapeHtml(value: string) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeNodeId(value: string) {
  return `fn-${value.replace(/[^a-z0-9_:-]/gi, '_').slice(0, 80)}`;
}

function fileToBase64(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const value = String(reader.result || '');
      const comma = value.indexOf(',');
      resolve(comma >= 0 ? value.slice(comma + 1) : value);
    };
    reader.readAsDataURL(file);
  });
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function truncate(value: unknown, max = 160) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString() : '-';
}

function formatBytes(value: number) {
  if (!Number.isFinite(value)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function statusLabel(value?: string) {
  return ({ queued: '待分析', running: '分析中', completed: '已完成', failed: '失败' } as Record<string, string>)[value || ''] || '未知';
}

function stageLabel(value?: string) {
  return (
    {
      queued: '等待分析',
      preflight: '准备样本',
      ghidra: 'Ghidra 分析',
      scoring: '规则评分',
      ai: 'AI 判定',
      report: '生成报告',
      completed: '分析完成',
      failed: '分析失败'
    } as Record<string, string>
  )[value || ''] || value || '-';
}

function normalizeProgress(value?: number) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(Number(value))));
}

function verdictLabel(value?: string) {
  return ({ malicious: '恶意', suspicious: '可疑', observed: '观察', clean: '干净', failed: '失败', queued: '待分析' } as Record<string, string>)[value || ''] || '未知';
}

function severityLabel(value?: string) {
  return ({ critical: '严重', warning: '警告', info: '信息' } as Record<string, string>)[value || ''] || '信息';
}

function targetLabel(value?: string) {
  return ({ any: '任意', import: '导入表', string: '字符串', function: '函数', pseudocode: '反伪代码', feature: '特征' } as Record<string, string>)[value || ''] || value || '-';
}

function statusTag(value?: string) {
  if (value === 'completed') return 'success';
  if (value === 'running') return 'info';
  if (value === 'failed') return 'error';
  return 'default';
}

function verdictTag(value?: string) {
  if (value === 'malicious') return 'error';
  if (value === 'suspicious') return 'warning';
  if (value === 'clean') return 'success';
  return 'default';
}

function severityTag(value?: string) {
  if (value === 'critical') return 'error';
  if (value === 'warning') return 'warning';
  return 'info';
}

onMounted(async () => {
  await Promise.all([refreshConfig(), refreshRules(), refreshSamples(false)]);
  if (samples.value.some(item => item.status === 'running')) startPolling();
  await nextTick();
  renderCallGraph();
});

watch(
  () => selectedSample.value?.reportJson,
  async () => {
    await nextTick();
    renderCallGraph();
  }
);

onBeforeUnmount(() => {
  stopPolling();
  callGraphFlow?.destroy();
  callGraphFlow = null;
});
</script>

<template>
  <div class="static-analysis-page">
    <NCard :bordered="false" class="hero-card">
      <div class="hero-content">
        <div>
          <div class="eyebrow">Ghidra Source-Derived Analyzer</div>
          <h1>智慧静态分析大师</h1>
          <p>基于 Ghidra 源码架构抽取改造，导出反汇编、反伪代码、调用图，并结合规则评分与 AI 判定。</p>
        </div>
        <NSpace align="center" wrap>
          <NTag :type="config?.ghidraDetected ? 'success' : 'warning'" :bordered="false">
            {{ config?.ghidraDetected ? 'Ghidra 已检测' : '待配置 Ghidra' }}
          </NTag>
          <NUpload :show-file-list="false" accept=".exe,application/x-msdownload" :custom-request="uploadSample">
            <NButton type="primary" :loading="uploading">
              <template #icon><SvgIcon icon="mdi:file-upload-outline" /></template>
              上传样本
            </NButton>
          </NUpload>
        </NSpace>
      </div>
    </NCard>

    <NGrid :cols="6" :x-gap="16" :y-gap="16" responsive="screen">
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="样本总数" :value="stats.total" /></NCard></NGi>
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="分析中" :value="stats.running" /></NCard></NGi>
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="已完成" :value="stats.completed" /></NCard></NGi>
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="失败" :value="stats.failed" /></NCard></NGi>
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="恶意" :value="stats.malicious" /></NCard></NGi>
      <NGi><NCard :bordered="false" class="metric-card"><NStatistic label="可疑" :value="stats.suspicious" /></NCard></NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 xl:15">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>样本队列</span>
              <NSpace wrap>
                <NSelect v-model:value="query.status" class="filter-control" :options="statusOptions" @update:value="refreshSamples(false)" />
                <NSelect v-model:value="query.verdict" class="filter-control" :options="verdictOptions" @update:value="refreshSamples(false)" />
                <NInput v-model:value="query.search" class="search-control" clearable placeholder="样本名、哈希、签名、结论" @keyup.enter="refreshSamples(false)" />
                <NButton :loading="loading" @click="refreshSamples(false)">刷新</NButton>
                <NButton type="error" ghost @click="clearSamples">清空</NButton>
              </NSpace>
            </div>
          </template>
          <NDataTable
            remote
            :loading="loading"
            :columns="sampleColumns"
            :data="samples"
            :pagination="pagination"
            :row-key="rowKey"
            :row-props="rowProps"
            :scroll-x="1450"
          />
        </NCard>
      </NGi>

      <NGi span="24 xl:9">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>分析控制</span>
              <NTag :type="selectedSample ? verdictTag(selectedSample.verdict) : 'default'" :bordered="false">
                {{ selectedSample ? verdictLabel(selectedSample.verdict) : '未选择' }}
              </NTag>
            </div>
          </template>
          <NEmpty v-if="!selectedSample" description="请选择一个样本。" />
          <template v-else>
            <div class="sample-brief">
              <strong>{{ selectedSample.fileName }}</strong>
              <span>{{ selectedSample.sha256 }}</span>
            </div>
            <NGrid :x-gap="12" :y-gap="12" cols="1 m:2" class="m-t-14px">
              <NGi>
                <NFormItem label="函数上限" :show-feedback="false">
                  <NInputNumber v-model:value="analyzeForm.maxFunctions" :min="10" :max="3000" class="w-full" />
                </NFormItem>
              </NGi>
              <NGi>
                <NFormItem label="反伪代码字符上限" :show-feedback="false">
                  <NInputNumber v-model:value="analyzeForm.maxDecompilerChars" :min="20000" :max="2500000" class="w-full" />
                </NFormItem>
              </NGi>
            </NGrid>
            <NCheckbox v-model:checked="analyzeForm.aiEnabled">本次调用 AI 判定</NCheckbox>
            <div class="action-row m-t-14px">
              <NButton type="primary" :loading="analyzing" :disabled="selectedSample.status === 'running'" @click="analyze()">开始分析</NButton>
              <NButton :disabled="!selectedSample.reportJson" @click="scrollToReport">查看报告</NButton>
            </div>
            <div class="analysis-progress m-t-16px">
              <div class="progress-head">
                <strong>{{ selectedSample.stageText || stageLabel(selectedSample.stage) }}</strong>
                <span>{{ normalizeProgress(selectedSample.progress) }}%</span>
              </div>
              <NProgress
                type="line"
                :percentage="normalizeProgress(selectedSample.progress)"
                :show-indicator="false"
                :height="8"
                :processing="selectedSample.status === 'running'"
                :status="selectedSample.status === 'failed' ? 'error' : selectedSample.status === 'completed' ? 'success' : 'info'"
              />
              <span>最近更新：{{ formatTime(selectedSample.lastProgressUtc) }}</span>
            </div>
            <NDescriptions class="m-t-16px" :column="1" bordered size="small">
              <NDescriptionsItem label="状态">{{ statusLabel(selectedSample.status) }}</NDescriptionsItem>
              <NDescriptionsItem label="阶段">{{ selectedSample.stageText || stageLabel(selectedSample.stage) }}</NDescriptionsItem>
              <NDescriptionsItem label="架构">{{ selectedSample.architecture || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="签名">{{ selectedSample.signatureStatus }} {{ selectedSample.signer || '' }}</NDescriptionsItem>
              <NDescriptionsItem label="错误">{{ selectedSample.error || '-' }}</NDescriptionsItem>
            </NDescriptions>
            <div class="analysis-log m-t-16px">
              <div class="log-title">
                <strong>分析日志</strong>
                <span>{{ selectedSample.runId || '-' }}</span>
              </div>
              <pre>{{ selectedSample.logText || '暂无日志。' }}</pre>
            </div>
          </template>
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 xl:10">
        <NCard :bordered="false" class="work-panel" title="引擎与 AI 配置">
          <NSpin :show="configLoading || savingConfig">
            <NForm label-placement="top">
              <NGrid :x-gap="12" :y-gap="12" cols="1 m:2">
                <NGi><NFormItem label="启用模块"><NSwitch v-model:value="configForm.enabled" /></NFormItem></NGi>
                <NGi><NFormItem label="默认启用 AI"><NSwitch v-model:value="configForm.aiEnabled" /></NFormItem></NGi>
                <NGi span="1 m:2"><NFormItem label="Ghidra 源码/发行版根目录"><NInput v-model:value="configForm.ghidraRoot" placeholder="包含 support\\analyzeHeadless.bat 或 Ghidra\\RuntimeScripts 的目录" /></NFormItem></NGi>
                <NGi span="1 m:2"><NFormItem label="Java/JDK 路径"><NInput v-model:value="configForm.javaPath" placeholder="可留空使用系统 PATH/JAVA_HOME" /></NFormItem></NGi>
                <NGi><NFormItem label="AI Base URL"><NInput v-model:value="configForm.baseUrl" placeholder="https://api.example.com/v1" /></NFormItem></NGi>
                <NGi><NFormItem label="AI Token"><NInput v-model:value="configForm.token" type="password" :placeholder="config?.tokenConfigured ? config.maskedToken : '未配置'" /></NFormItem></NGi>
                <NGi><NFormItem label="模型"><NInput v-model:value="configForm.model" /></NFormItem></NGi>
                <NGi><NFormItem label="温度"><NInputNumber v-model:value="configForm.temperature" :min="0" :max="2" :step="0.1" class="w-full" /></NFormItem></NGi>
                <NGi><NFormItem label="函数上限"><NInputNumber v-model:value="configForm.maxFunctions" :min="10" :max="3000" class="w-full" /></NFormItem></NGi>
                <NGi><NFormItem label="超时（秒）"><NInputNumber v-model:value="configForm.timeoutSeconds" :min="60" :max="7200" class="w-full" /></NFormItem></NGi>
              </NGrid>
              <NSpace align="center">
                <NButton type="primary" :loading="savingConfig" @click="saveConfig">保存配置</NButton>
                <NCheckbox v-model:checked="configForm.clearToken">保存时清空 Token</NCheckbox>
              </NSpace>
            </NForm>
            <NDescriptions class="m-t-16px" :column="1" bordered size="small">
              <NDescriptionsItem label="分析脚本">{{ config?.analyzerScript || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="Ghidra 来源">{{ sourceInfo?.upstream || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="源码 Commit">{{ sourceInfo?.upstreamCommit || '-' }}</NDescriptionsItem>
            </NDescriptions>
          </NSpin>
        </NCard>
      </NGi>

      <NGi span="24 xl:14">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>自定义评分规则</span>
              <NSpace>
                <NButton size="small" @click="addRule">新增</NButton>
                <NButton size="small" @click="resetRules">恢复默认</NButton>
                <NButton size="small" type="primary" :loading="savingRules" @click="saveRules">保存规则</NButton>
              </NSpace>
            </div>
          </template>
          <NSpin :show="ruleLoading">
            <NDataTable :columns="ruleColumns" :data="rules" :pagination="{ pageSize: 8 }" :scroll-x="960" />
            <NCollapse class="m-t-12px">
              <NCollapseItem title="编辑规则明细" name="rules">
                <div class="rule-editor-list">
                  <div v-for="(rule, index) in rules" :key="rule.ruleId" class="rule-editor">
                    <NGrid :x-gap="10" :y-gap="10" cols="1 m:6">
                      <NGi span="1 m:2"><NInput v-model:value="rule.name" placeholder="规则名" /></NGi>
                      <NGi><NSelect v-model:value="rule.target" :options="ruleTargetOptions" /></NGi>
                      <NGi><NInputNumber v-model:value="rule.weight" :min="0" :max="100" class="w-full" /></NGi>
                      <NGi><NSelect v-model:value="rule.severity" :options="severityOptions" /></NGi>
                      <NGi><NSelect v-model:value="rule.verdict" :options="ruleVerdictOptions" /></NGi>
                      <NGi span="1 m:4"><NInput v-model:value="rule.pattern" placeholder="关键词或正则" /></NGi>
                      <NGi><NCheckbox v-model:checked="rule.regex">正则</NCheckbox></NGi>
                      <NGi><NButton type="error" ghost @click="removeRule(index)">删除</NButton></NGi>
                      <NGi span="1 m:6"><NInput v-model:value="rule.description" placeholder="规则说明" /></NGi>
                    </NGrid>
                  </div>
                </div>
              </NCollapseItem>
            </NCollapse>
          </NSpin>
        </NCard>
      </NGi>
    </NGrid>

    <NCard id="static-analysis-report" :bordered="false" class="work-panel">
      <template #header>
        <div class="panel-title">
          <span>分析报告</span>
          <NSpace v-if="selectedSample" align="center">
            <NTag :type="verdictTag(selectedSample.verdict)" :bordered="false">{{ verdictLabel(selectedSample.verdict) }}</NTag>
            <NTag :type="severityTag(selectedSample.severity)" :bordered="false">{{ severityLabel(selectedSample.severity) }}</NTag>
          </NSpace>
        </div>
      </template>

      <NEmpty v-if="!selectedSample" description="请选择一个样本。" />
      <NEmpty v-else-if="!report" description="当前样本还没有分析报告。" />
      <template v-else>
        <div class="report-summary">
          <div>
            <span>规则分数</span>
            <strong>{{ report.ruleScore?.score ?? selectedSample.score }}</strong>
          </div>
          <div>
            <span>规则命中</span>
            <strong>{{ ruleHits.length }}</strong>
          </div>
          <div>
            <span>危险导入</span>
            <strong>{{ dangerousImports.length }}</strong>
          </div>
          <div>
            <span>可疑字符串</span>
            <strong>{{ suspiciousStrings.length }}</strong>
          </div>
          <div>
            <span>高信号函数</span>
            <strong>{{ highSignalFunctions.length }}</strong>
          </div>
        </div>

        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive class="m-t-16px">
          <NGi span="24 xl:10">
            <NCard :bordered="false" embedded title="AI 判定">
              <NAlert v-if="report.ai?.error" type="warning" :bordered="false">{{ report.ai.error }}</NAlert>
              <div class="ai-meta">
                <span v-for="item in aiMeta" :key="item.label">
                  <b>{{ item.label }}</b>{{ item.value }}
                </span>
              </div>
              <div class="analysis-markdown" v-html="aiMarkdown"></div>
            </NCard>
          </NGi>
          <NGi span="24 xl:14">
            <NCard :bordered="false" embedded title="调用图">
              <div ref="callGraphRef" class="call-graph"></div>
            </NCard>
          </NGi>
        </NGrid>

        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive class="m-t-16px">
          <NGi span="24 xl:12">
            <NCard :bordered="false" embedded title="规则命中">
              <NList bordered>
                <NListItem v-for="hit in ruleHits" :key="hit.ruleId">
                  <div class="hit-item">
                    <div>
                      <strong>{{ hit.name }}</strong>
                      <span>{{ hit.description || hit.pattern }}</span>
                    </div>
                    <NTag :type="severityTag(hit.severity)" :bordered="false">+{{ hit.weight }}</NTag>
                  </div>
                  <div class="evidence-list">
                    <code v-for="item in hit.evidence || []" :key="item">{{ truncate(item, 220) }}</code>
                  </div>
                </NListItem>
              </NList>
            </NCard>
          </NGi>
          <NGi span="24 xl:12">
            <NCard :bordered="false" embedded title="特征命中">
              <div class="tag-cloud">
                <NTag v-for="item in featureHits" :key="item" :bordered="false">{{ truncate(item, 120) }}</NTag>
              </div>
            </NCard>
          </NGi>
        </NGrid>

        <NCollapse class="m-t-16px">
          <NCollapseItem title="危险导入表" name="imports">
            <NDataTable :data="dangerousImports" :columns="[
              { title: '名称', key: 'name', minWidth: 180 },
              { title: '命名空间', key: 'namespace', minWidth: 260, ellipsis: { tooltip: true } },
              { title: '地址', key: 'address', width: 140 }
            ]" :pagination="{ pageSize: 10 }" />
          </NCollapseItem>
          <NCollapseItem title="可疑字符串" name="strings">
            <NDataTable :data="suspiciousStrings" :columns="[
              { title: '地址', key: 'address', width: 140 },
              { title: '内容', key: 'value', minWidth: 520, ellipsis: { tooltip: true } }
            ]" :pagination="{ pageSize: 10 }" />
          </NCollapseItem>
          <NCollapseItem title="高信号函数" name="functions">
            <NDataTable :data="highSignalFunctions" :columns="[
              { title: '函数', key: 'name', minWidth: 220, ellipsis: { tooltip: true } },
              { title: '入口', key: 'entry', width: 140 },
              { title: '特征', key: 'featureHits', minWidth: 260, render: row => Array.isArray(row.featureHits) ? row.featureHits.join(', ') : '-' },
              { title: '反伪代码', key: 'pseudocode', minWidth: 520, ellipsis: { tooltip: true } }
            ]" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
        </NCollapse>
      </template>
    </NCard>
  </div>
</template>

<style scoped>
.static-analysis-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.hero-card,
.metric-card,
.work-panel {
  border-radius: 8px;
}

.hero-content,
.panel-title,
.action-row,
.hit-item {
  display: flex;
  gap: 12px;
  align-items: center;
}

.hero-content,
.panel-title,
.hit-item {
  justify-content: space-between;
}

.hero-content h1 {
  margin: 4px 0 6px;
  font-size: 24px;
  font-weight: 800;
}

.hero-content p,
.cell-stack span,
.sample-brief span,
.hit-item span {
  color: var(--n-text-color-3);
}

.eyebrow {
  color: #475569;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
}

.filter-control {
  width: 150px;
}

.search-control {
  width: min(360px, 100%);
}

.cell-stack,
.sample-brief {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.cell-stack strong,
.cell-stack span,
.sample-brief strong,
.sample-brief span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.score-cell {
  display: inline-flex;
  align-items: baseline;
  gap: 2px;
}

.score-cell strong {
  font-size: 18px;
}

.score-cell span {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.progress-cell,
.analysis-progress {
  display: grid;
  gap: 6px;
}

.progress-head,
.log-title {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: center;
}

.progress-head span,
.stage-line,
.analysis-progress span,
.log-title span {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.stage-line {
  display: block;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.analysis-log {
  display: grid;
  gap: 8px;
}

.analysis-log pre {
  min-height: 160px;
  max-height: 280px;
  margin: 0;
  padding: 12px;
  overflow: auto;
  color: #334155;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.rule-editor-list {
  display: grid;
  gap: 12px;
}

.rule-editor {
  padding: 12px;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.report-summary {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}

.report-summary div {
  display: grid;
  gap: 6px;
  padding: 14px;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.report-summary span {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.report-summary strong {
  font-size: 22px;
}

.ai-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.ai-meta span {
  display: inline-flex;
  gap: 6px;
  align-items: center;
  padding: 5px 9px;
  color: #475569;
  font-size: 12px;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 6px;
}

.ai-meta b {
  color: #0f172a;
}

.analysis-markdown {
  min-height: 260px;
  max-height: 520px;
  padding: 14px;
  overflow: auto;
  color: #334155;
  line-height: 1.68;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.analysis-markdown :deep(h3),
.analysis-markdown :deep(h4),
.analysis-markdown :deep(h5),
.analysis-markdown :deep(p) {
  margin: 0 0 12px;
}

.analysis-markdown :deep(h3),
.analysis-markdown :deep(h4),
.analysis-markdown :deep(h5) {
  color: #0f172a;
  font-size: 15px;
}

.analysis-markdown :deep(ul) {
  padding-left: 18px;
  margin: 0 0 12px;
}

.analysis-markdown :deep(code) {
  padding: 1px 5px;
  color: #334155;
  background: #e2e8f0;
  border-radius: 4px;
}

.analysis-markdown :deep(.markdown-table-wrap) {
  width: 100%;
  margin: 0 0 14px;
  overflow-x: auto;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.analysis-markdown :deep(table) {
  width: 100%;
  min-width: 620px;
  border-collapse: collapse;
  background: #ffffff;
}

.analysis-markdown :deep(th),
.analysis-markdown :deep(td) {
  padding: 9px 11px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid rgb(226 232 240);
}

.analysis-markdown :deep(th) {
  color: #0f172a;
  font-weight: 650;
  background: #f1f5f9;
}

.analysis-markdown :deep(tr:last-child td) {
  border-bottom: 0;
}

.call-graph {
  height: 360px;
  overflow: hidden;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
}

.hit-item strong {
  display: block;
  margin-bottom: 4px;
}

.evidence-list {
  display: grid;
  gap: 6px;
  margin-top: 10px;
}

.evidence-list code {
  display: block;
  padding: 8px;
  overflow-wrap: anywhere;
  color: #475569;
  background: #f8fafc;
  border-radius: 6px;
}

.tag-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

:deep(.selected-row td) {
  background: rgb(248 250 252) !important;
}

@media (max-width: 960px) {
  .hero-content,
  .panel-title {
    align-items: flex-start;
    flex-direction: column;
  }

  .report-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 560px) {
  .report-summary {
    grid-template-columns: 1fr;
  }
}
</style>
