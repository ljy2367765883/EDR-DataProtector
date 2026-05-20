<script setup lang="tsx">
import { computed, h, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import LogicFlow from '@logicflow/core';
import '@logicflow/core/dist/index.css';
import type { DataTableColumns, PaginationProps, UploadCustomRequestOptions } from 'naive-ui';
import { NButton, NTag, useMessage } from 'naive-ui';
import {
  fetchRemoveSandboxLogs,
  fetchRemoveSandboxSample,
  fetchSandboxSamples,
  fetchStartSandboxAnalysis,
  fetchSubmitSandboxSample
} from '@/service/api';
import { $t } from '@/locales';
import { useAppStore } from '@/store/modules/app';

defineOptions({
  name: 'Sandbox'
});

type SandboxBehavior = {
  type: string;
  severity: string;
  detail: string;
  pid: number;
  timeUtc: string;
};

type SandboxProcess = {
  pid: number;
  parentPid: number;
  name: string;
  path: string;
  commandLine: string;
  createdUtc: string;
  signature?: {
    status: string;
    signer: string;
  };
};

type SandboxNetwork = {
  pid: number;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  timeUtc: string;
};

type SandboxFileArtifact = {
  path: string;
  size: number;
  modifiedUtc: string;
  sha256: string;
};

type SandboxRuntimeEvent = {
  timestampUtc: string;
  pid: number;
  action: string;
  target: string;
  processImage: string;
  status: string;
  blocked: boolean;
};

type SandboxKernelSensor = {
  enabled: boolean;
  status: string;
  serviceName: string;
  driverPath: string;
  policyStatus: string;
  win32: number;
  message: string;
};

type SandboxKernelEvent = {
  sequence: number;
  pid: number;
  parentPid: number;
  operation: number;
  operationName: string;
  status: string;
  flags: string;
  target: string;
  processImage: string;
  description: string;
};

type SandboxService = {
  name: string;
  displayName: string;
  pathName: string;
  serviceType: string;
  startMode: string;
  state: string;
  change: string;
};

type SandboxScheduledTask = {
  name: string;
  command: string;
  state: string;
  change: string;
};

type SandboxReport = {
  schema: string;
  isolation: string;
  runId: string;
  startedUtc: string;
  completedUtc: string;
  host?: string;
  sample?: {
    hostPath: string;
    fileName: string;
    sha256: string;
    architecture: string;
    signer: string;
    sandboxPath?: string;
  };
  execution?: {
    pid: number;
    exitCode: number | null;
    timedOut: boolean;
    timeoutSeconds: number;
  };
  isolationControls?: Record<string, string>;
  analysisHardening?: Record<string, string>;
  behaviors?: SandboxBehavior[];
  processes?: SandboxProcess[];
  network?: SandboxNetwork[];
  fileArtifacts?: SandboxFileArtifact[];
  runtimeEvents?: SandboxRuntimeEvent[];
  services?: SandboxService[];
  scheduledTasks?: SandboxScheduledTask[];
  telemetry?: Record<string, string | boolean>;
  kernelSensor?: SandboxKernelSensor;
  kernelEvents?: SandboxKernelEvent[];
  stdout?: string;
  stderr?: string;
  errors?: string[];
  error?: string;
  hostReportRoot?: string;
  hostConfigPath?: string;
};

type AttackFlowStage = {
  key: string;
  label: string;
  detail: string;
  active: boolean;
  severity: string;
  count: number;
  icon: string;
};

type AttackStoryProcessNode = {
  pid: number;
  parentPid: number;
  name: string;
  path: string;
  risk: string;
  depth: number;
  order: number;
};

type AttackStoryEvent = {
  id: string;
  time: string;
  type: string;
  title: string;
  detail: string;
  severity: string;
  icon: string;
  pid: number;
};

type AttackStoryEntity = {
  key: string;
  label: string;
  value: number;
  icon: string;
};

type AttackStory = {
  stages: AttackFlowStage[];
  processes: AttackStoryProcessNode[];
  events: AttackStoryEvent[];
  entities: AttackStoryEntity[];
};

type AttackGraphNodeKind = 'sample' | 'process' | 'processLabel' | 'event' | 'eventLabel' | 'summary' | 'empty';

type AttackGraphNodeDetail = {
  id: string;
  kind: AttackGraphNodeKind;
  title: string;
  subtitle: string;
  severity: string;
  category: string;
  description: string;
  pid?: number;
  parentPid?: number;
  path?: string;
  command?: string;
  signer?: string;
  target?: string;
  status?: string;
  time?: string;
  stage?: string;
  source?: string;
};

type AttackGraphMiniPoint = {
  id: string;
  x: number;
  y: number;
  severity: string;
};

type AttackGraph = {
  flow: FlowGraphData;
  details: AttackGraphNodeDetail[];
  miniPoints: AttackGraphMiniPoint[];
  height: number;
};

type FlowGraphData = Parameters<LogicFlow['render']>[0];

const message = useMessage();
const appStore = useAppStore();
const loading = ref(false);
const uploading = ref(false);
const analyzing = ref(false);
const response = ref<Api.DataProtector.SandboxSampleQueryResponse | null>(null);
const selectedSampleId = ref('');
const pollTimer = ref<number | null>(null);
const sandboxAttackFlowRef = ref<HTMLElement | null>(null);
const selectedAttackNodeId = ref('');
let sandboxAttackFlow: LogicFlow | null = null;

const query = reactive<Api.DataProtector.SandboxSampleQuery>({
  page: 1,
  pageSize: 20,
  status: 'all',
  source: 'all',
  host: '',
  search: ''
});

const analysisForm = reactive({
  arguments: '',
  timeoutSeconds: 120,
  networkEnabled: false,
  closeWhenDone: true
});

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  prefix: page => $t('datatable.itemCount', { total: page.itemCount }),
  onUpdatePage(page) {
    pagination.page = page;
    query.page = page;
    refresh(false);
  },
  onUpdatePageSize(pageSize) {
    pagination.page = 1;
    pagination.pageSize = pageSize;
    query.page = 1;
    query.pageSize = pageSize;
    refresh(false);
  }
});

const samples = computed(() => response.value?.items ?? []);
const selectedSample = computed(() => samples.value.find(item => item.sampleId === selectedSampleId.value) || samples.value[0] || null);
const rawReport = computed(() => parseJson<SandboxReport | null>(selectedSample.value?.reportJson, null));
const report = computed(() => sanitizeSandboxReport(rawReport.value));
const attackStory = computed(() => buildAttackStory(report.value));
const attackGraph = computed(() => buildSandboxAttackGraph(report.value, selectedSample.value));
const selectedAttackNode = computed(
  () => attackGraph.value.details.find(item => item.id === selectedAttackNodeId.value) || attackGraph.value.details[0] || null
);
const activeAttackFlowStageCount = computed(() => attackStory.value.stages.filter(item => item.active).length);
const reportParseFailed = computed(() => Boolean(selectedSample.value?.reportJson && !rawReport.value));
const reportSignalCounts = computed(() => ({
  behaviors: report.value?.behaviors?.length || 0,
  processes: report.value?.processes?.length || 0,
  network: report.value?.network?.length || 0,
  artifacts: report.value?.fileArtifacts?.length || 0,
  runtime: report.value?.runtimeEvents?.length || 0,
  kernel: report.value?.kernelEvents?.length || 0,
  services: report.value?.services?.length || 0,
  tasks: report.value?.scheduledTasks?.length || 0
}));
const reportSignalTotal = computed(
  () =>
    reportSignalCounts.value.behaviors +
    reportSignalCounts.value.network +
    reportSignalCounts.value.artifacts +
    reportSignalCounts.value.runtime +
    reportSignalCounts.value.kernel +
    reportSignalCounts.value.services +
    reportSignalCounts.value.tasks
);
const reportRiskSeverity = computed(() => calculateReportRiskSeverity(report.value, selectedSample.value));
const reportSummaryText = computed(() => buildReportSummaryText(report.value, selectedSample.value));
const reportTopFindings = computed(() => attackStory.value.events.slice(0, 3));
const stats = computed(() => ({
  total: response.value?.total ?? 0,
  queued: response.value?.queuedTotal ?? 0,
  running: response.value?.runningTotal ?? 0,
  completed: response.value?.completedTotal ?? 0,
  failed: response.value?.failedTotal ?? 0
}));

const statusOptions = computed(() => [
  { label: $t('dataprotector.sandbox.filters.allStatus'), value: 'all' },
  { label: $t('dataprotector.sandbox.status.queued'), value: 'queued' },
  { label: $t('dataprotector.sandbox.status.running'), value: 'running' },
  { label: $t('dataprotector.sandbox.status.completed'), value: 'completed' },
  { label: $t('dataprotector.sandbox.status.failed'), value: 'failed' }
]);

const sourceOptions = computed(() => [
  { label: $t('dataprotector.sandbox.filters.allSources'), value: 'all' },
  { label: $t('dataprotector.sandbox.sources.web'), value: 'web' },
  { label: $t('dataprotector.sandbox.sources.agent'), value: 'agent' }
]);

const sampleColumns = computed<DataTableColumns<Api.DataProtector.SandboxSample>>(() => [
  {
    title: $t('dataprotector.sandbox.columns.sample'),
    key: 'fileName',
    minWidth: 320,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.fileName || '-'}</div>
          <div class="cell-muted mono">{row.sha256 || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.status'),
    key: 'status',
    width: 130,
    render(row) {
      return <NTag type={statusTagType(row.status)} bordered={false}>{statusLabel(row.status)}</NTag>;
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.source'),
    key: 'source',
    width: 150,
    render(row) {
      return (
        <div class="cell-stack">
          <NTag type={row.source === 'agent' ? 'warning' : 'info'} bordered={false}>{sourceLabel(row.source)}</NTag>
          <div class="cell-muted">{row.host || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.fileInfo'),
    key: 'signatureStatus',
    minWidth: 280,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.fileDescription || row.productName || row.architecture || '-'}</div>
          <div class="cell-muted">{row.signer || row.companyName || row.signatureStatus || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.reason'),
    key: 'suspicion',
    minWidth: 260,
    ellipsis: { tooltip: true }
  },
  {
    title: $t('dataprotector.sandbox.columns.submitted'),
    key: 'submittedUtc',
    width: 190,
    render(row) {
      return formatTime(row.submittedUtc);
    }
  },
  {
    title: $t('dataprotector.common.action'),
    key: 'actions',
    width: 320,
    render(row) {
      return (
        <div class="action-row">
          <NButton size="small" type="primary" secondary disabled={row.status === 'running'} onClick={() => analyze(row)}>
            {$t('dataprotector.sandbox.analyze')}
          </NButton>
          <NButton size="small" secondary onClick={() => openReport(row)}>
            {$t('dataprotector.sandbox.report')}
          </NButton>
          <NButton size="small" secondary disabled={row.status === 'running' || !row.reportJson} onClick={() => removeLogs(row)}>
            {$t('dataprotector.sandbox.deleteLogs')}
          </NButton>
          <NButton size="small" type="error" secondary disabled={row.status === 'running'} onClick={() => removeSample(row)}>
            {$t('dataprotector.common.delete')}
          </NButton>
        </div>
      );
    }
  }
]);

const behaviorColumns = computed<DataTableColumns<SandboxBehavior>>(() => [
  {
    title: $t('dataprotector.sandbox.columns.severity'),
    key: 'severity',
    width: 110,
    render(row) {
      return <NTag type={severityTagType(row.severity)} bordered={false}>{severityLabel(row.severity)}</NTag>;
    }
  },
  { title: $t('dataprotector.sandbox.columns.type'), key: 'type', width: 190, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.detail'), key: 'detail', minWidth: 360, ellipsis: { tooltip: true } },
  { title: 'PID', key: 'pid', width: 90 },
  {
    title: $t('dataprotector.sandbox.columns.time'),
    key: 'timeUtc',
    width: 180,
    render(row) {
      return formatTime(row.timeUtc);
    }
  }
]);

const processColumns = computed<DataTableColumns<SandboxProcess>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  { title: 'PPID', key: 'parentPid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'name', width: 170, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.sandbox.columns.signature'),
    key: 'signature',
    width: 160,
    render(row) {
      return row.signature?.status || '-';
    }
  },
  { title: $t('dataprotector.sandbox.columns.path'), key: 'path', minWidth: 360, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.command'), key: 'commandLine', minWidth: 360, ellipsis: { tooltip: true } }
]);

const networkColumns = computed<DataTableColumns<SandboxNetwork>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  {
    title: $t('dataprotector.sandbox.columns.remote'),
    key: 'remoteAddress',
    minWidth: 220,
    render(row) {
      return `${row.remoteAddress}:${row.remotePort}`;
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.local'),
    key: 'localAddress',
    minWidth: 220,
    render(row) {
      return `${row.localAddress}:${row.localPort}`;
    }
  },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 130 },
  {
    title: $t('dataprotector.sandbox.columns.time'),
    key: 'timeUtc',
    width: 180,
    render(row) {
      return formatTime(row.timeUtc);
    }
  }
]);

const fileColumns = computed<DataTableColumns<SandboxFileArtifact>>(() => [
  { title: $t('dataprotector.sandbox.columns.path'), key: 'path', minWidth: 360, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.sandbox.columns.size'),
    key: 'size',
    width: 120,
    render(row) {
      return formatBytes(row.size);
    }
  },
  { title: 'SHA256', key: 'sha256', minWidth: 320, ellipsis: { tooltip: true } }
]);

const runtimeColumns = computed<DataTableColumns<SandboxRuntimeEvent>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.action'), key: 'action', minWidth: 260, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.target'), key: 'target', minWidth: 280, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.statusText'), key: 'status', width: 130 },
  {
    title: $t('dataprotector.sandbox.columns.blocked'),
    key: 'blocked',
    width: 110,
    render(row) {
      return <NTag type={row.blocked ? 'error' : 'success'} bordered={false}>{row.blocked ? 'Yes' : 'No'}</NTag>;
    }
  },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'processImage', minWidth: 300, ellipsis: { tooltip: true } }
]);

const kernelColumns = computed<DataTableColumns<SandboxKernelEvent>>(() => [
  { title: $t('dataprotector.sandbox.columns.sequence'), key: 'sequence', width: 110 },
  { title: 'PID', key: 'pid', width: 90 },
  { title: 'PPID', key: 'parentPid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.operation'), key: 'operationName', minWidth: 220, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.statusText'), key: 'status', width: 130 },
  { title: $t('dataprotector.sandbox.columns.target'), key: 'target', minWidth: 360, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'processImage', minWidth: 300, ellipsis: { tooltip: true } }
]);

const serviceColumns = computed<DataTableColumns<SandboxService>>(() => [
  { title: $t('dataprotector.sandbox.columns.change'), key: 'change', width: 120 },
  { title: $t('dataprotector.sandbox.columns.service'), key: 'name', width: 180, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.type'), key: 'serviceType', width: 160, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 120 },
  { title: $t('dataprotector.sandbox.columns.path'), key: 'pathName', minWidth: 420, ellipsis: { tooltip: true } }
]);

const taskColumns = computed<DataTableColumns<SandboxScheduledTask>>(() => [
  { title: $t('dataprotector.sandbox.columns.change'), key: 'change', width: 120 },
  { title: $t('dataprotector.sandbox.columns.task'), key: 'name', minWidth: 260, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 120 },
  { title: $t('dataprotector.sandbox.columns.command'), key: 'command', minWidth: 420, ellipsis: { tooltip: true } }
]);

async function refresh(resetPage = false) {
  if (resetPage) {
    pagination.page = 1;
    query.page = 1;
  }

  query.page = pagination.page;
  query.pageSize = pagination.pageSize;
  loading.value = true;
  try {
    const { error, data } = await fetchSandboxSamples(query);
    if (!error) {
      response.value = data;
      pagination.itemCount = data.total;
      pagination.page = data.page;
      pagination.pageSize = data.pageSize;
      if (!selectedSampleId.value && data.items.length) {
        selectedSampleId.value = data.items[0].sampleId;
      }
      if (selectedSampleId.value && !data.items.some(item => item.sampleId === selectedSampleId.value) && data.items.length) {
        selectedSampleId.value = data.items[0].sampleId;
      }
    }
  } finally {
    loading.value = false;
  }
}

async function uploadSample(options: UploadCustomRequestOptions) {
  const file = options.file.file;
  if (!file) {
    options.onError?.();
    return;
  }

  if (!file.name.toLowerCase().endsWith('.exe')) {
    message.warning($t('dataprotector.sandbox.exeOnly'));
    options.onError?.();
    return;
  }

  uploading.value = true;
  try {
    const contentBase64 = await fileToBase64(file);
    const { error, data } = await fetchSubmitSandboxSample({
      fileName: file.name,
      contentBase64,
      source: 'web',
      host: 'web-admin',
      suspicion: $t('dataprotector.sandbox.webUploadReason'),
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success($t('dataprotector.sandbox.uploaded'));
      await refresh(true);
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

  analyzing.value = true;
  try {
    const { error, data } = await fetchStartSandboxAnalysis({
      sampleId: row.sampleId,
      arguments: analysisForm.arguments,
      timeoutSeconds: analysisForm.timeoutSeconds,
      networkEnabled: analysisForm.networkEnabled,
      closeWhenDone: analysisForm.closeWhenDone,
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success($t('dataprotector.sandbox.started'));
      startPolling();
      await refresh(false);
    }
  } finally {
    analyzing.value = false;
  }
}

function selectSample(row: Api.DataProtector.SandboxSample) {
  selectedSampleId.value = row.sampleId;
}

function openReport(row: Api.DataProtector.SandboxSample) {
  selectSample(row);
  scrollToReport();
}

function scrollToReport() {
  window.requestAnimationFrame(() => {
    document.getElementById('sandbox-report-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

function removeSample(row: Api.DataProtector.SandboxSample) {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.deleteTitle'),
    content: $t('dataprotector.sandbox.deleteContent', { name: row.fileName }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveSandboxSample({ sampleId: row.sampleId, actor: 'web-admin' });
      if (!error && data.succeeded) {
        if (selectedSampleId.value === row.sampleId) selectedSampleId.value = '';
        message.success($t('dataprotector.sandbox.deleted'));
        await refresh(false);
      }
    }
  });
}

function removeLogs(row: Api.DataProtector.SandboxSample) {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.deleteLogsTitle'),
    content: $t('dataprotector.sandbox.deleteLogsContent', { name: row.fileName }),
    positiveText: $t('dataprotector.sandbox.deleteLogs'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const reportValue = parseJson<SandboxReport | null>(row.reportJson, null);
      const { error, data } = await fetchRemoveSandboxLogs({
        sampleId: row.sampleId,
        runId: reportValue?.runId,
        actor: 'web-admin'
      });
      if (!error && data.succeeded) {
        message.success($t('dataprotector.sandbox.logsDeleted'));
        await refresh(false);
      }
    }
  });
}

function clearLogs() {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.clearLogsTitle'),
    content: $t('dataprotector.sandbox.clearLogsContent'),
    positiveText: $t('dataprotector.sandbox.clearLogs'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveSandboxLogs({ all: true, actor: 'web-admin' });
      if (!error && data.succeeded) {
        selectedSampleId.value = '';
        response.value = {
          page: pagination.page || 1,
          pageSize: pagination.pageSize || 20,
          total: 0,
          queuedTotal: 0,
          runningTotal: 0,
          completedTotal: 0,
          failedTotal: 0,
          items: []
        };
        pagination.itemCount = 0;
        message.success($t('dataprotector.sandbox.logsCleared'));
        await refresh(false);
      }
    }
  });
}

function startPolling() {
  stopPolling();
  pollTimer.value = window.setInterval(async () => {
    await refresh(false);
    if (!samples.value.some(item => item.status === 'running')) {
      stopPolling();
    }
  }, 3000);
}

function stopPolling() {
  if (pollTimer.value !== null) {
    window.clearInterval(pollTimer.value);
    pollTimer.value = null;
  }
}

function rowKey(row: Api.DataProtector.SandboxSample) {
  return row.sampleId;
}

function rowProps(row: Api.DataProtector.SandboxSample) {
  return {
    class: row.sampleId === selectedSampleId.value ? 'selected-row' : '',
    onClick: () => selectSample(row)
  };
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

function sanitizeSandboxReport(value: SandboxReport | null) {
  if (!value) return null;

  const reportClone: SandboxReport = {
    ...value,
    behaviors: [...(value.behaviors || [])],
    processes: [...(value.processes || [])],
    network: [...(value.network || [])],
    fileArtifacts: [...(value.fileArtifacts || [])],
    runtimeEvents: [...(value.runtimeEvents || [])],
    kernelEvents: [...(value.kernelEvents || [])],
    services: [...(value.services || [])],
    scheduledTasks: [...(value.scheduledTasks || [])]
  };

  const internalPids = new Set(
    (reportClone.processes || [])
      .filter(process => isInternalProcess(process))
      .map(process => process.pid)
      .filter(pid => Number.isFinite(pid))
  );

  reportClone.behaviors = reportClone.behaviors?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.type) &&
      !isInternalTelemetryText(item.detail)
  );
  reportClone.processes = reportClone.processes?.filter(item => item && !internalPids.has(item.pid) && !isInternalProcess(item));
  reportClone.network = reportClone.network?.filter(item => item && !internalPids.has(item.pid));
  reportClone.fileArtifacts = reportClone.fileArtifacts?.filter(item => item && !isInternalTelemetryText(item.path));
  reportClone.runtimeEvents = reportClone.runtimeEvents?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.action) &&
      !isInternalTelemetryText(item.target) &&
      !isInternalTelemetryText(item.processImage)
  );
  reportClone.kernelEvents = reportClone.kernelEvents?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.operationName) &&
      !isInternalTelemetryText(item.target) &&
      !isInternalTelemetryText(item.processImage) &&
      !isInternalTelemetryText(item.description)
  );
  reportClone.services = reportClone.services?.filter(
    item =>
      item &&
      !isInternalTelemetryText(item.name) &&
      !isInternalTelemetryText(item.displayName) &&
      !isInternalTelemetryText(item.pathName)
  );
  reportClone.scheduledTasks = reportClone.scheduledTasks?.filter(
    item => item && !isInternalTelemetryText(item.name) && !isInternalTelemetryText(item.command)
  );

  return reportClone;
}

function isInternalProcess(process: SandboxProcess) {
  return (
    isInternalTelemetryText(process.name) ||
    isInternalTelemetryText(process.path) ||
    isInternalTelemetryText(process.commandLine)
  );
}

function isInternalTelemetryText(value?: string) {
  const text = String(value || '').toLowerCase();
  if (!text) return false;

  return [
    'dataprotectorsandboxtelemetry',
    'dataprotectorsandbox',
    'dataprotectoruserhookruntime',
    'dataprotectorpolicyapi',
    'dataprotector.sys',
    'dataprotectorsandbox.sys',
    'dataprotector\\sandbox',
    '\\dataprotector\\userhook',
    'userhook',
    'sandbox telemetry',
    'userhook runtime',
    'user hook runtime',
    'userhook_runtime',
    'userhook.observed',
    'sandbox-kernel-sensor',
    'kernel-early-injection-policy'
  ].some(token => text.includes(token));
}

function buildAttackStory(value: SandboxReport | null): AttackStory {
  return {
    stages: buildAttackFlowStages(value),
    processes: buildAttackProcessGraph(value).slice(0, 8),
    events: buildAttackStoryEvents(value).slice(0, 10),
    entities: buildAttackStoryEntities(value)
  };
}

function buildAttackFlowStages(value: SandboxReport | null): AttackFlowStage[] {
  const behaviors = value?.behaviors || [];
  const processes = value?.processes || [];
  const network = value?.network || [];
  const artifacts = value?.fileArtifacts || [];
  const runtimeEvents = value?.runtimeEvents || [];
  const kernelEvents = value?.kernelEvents || [];
  const services = value?.services || [];
  const tasks = value?.scheduledTasks || [];

  const childProcessCount = processes.filter(process => process.parentPid && process.pid !== value?.execution?.pid).length;
  const commandCount = countTextMatches(
    [...behaviors.map(item => `${item.type} ${item.detail}`), ...processes.map(item => item.commandLine)],
    ['process', 'command', 'powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'wscript', 'cscript', 'mshta']
  );
  const memoryCount = countTextMatches(
    [
      ...behaviors.map(item => `${item.type} ${item.detail}`),
      ...runtimeEvents.map(item => `${item.action} ${item.target}`),
      ...kernelEvents.map(item => `${item.operationName} ${item.description} ${item.target}`)
    ],
    ['virtualalloc', 'writeprocessmemory', 'createremotethread', 'syscall', 'unhook', 'executable memory', 'module reload', 'native-module']
  );
  const persistenceCount =
    services.length +
    tasks.length +
    countTextMatches(
      [...behaviors.map(item => `${item.type} ${item.detail}`), ...runtimeEvents.map(item => `${item.action} ${item.target}`)],
      ['registry', 'autorun', 'run key', 'scheduled task', 'service', 'driver']
    );
  const artifactCount =
    artifacts.length +
    countTextMatches(
      [...behaviors.map(item => `${item.type} ${item.detail}`), ...kernelEvents.map(item => `${item.operationName} ${item.target}`)],
      ['file-artifacts', 'drop', 'write-file', 'driver']
    );

  return [
    createAttackFlowStage('launch', true, 1, 'medium', 'mdi:rocket-launch-outline'),
    createAttackFlowStage('process', childProcessCount > 0 || commandCount > 0, childProcessCount + commandCount, 'high', 'mdi:family-tree'),
    createAttackFlowStage('apiMemory', memoryCount > 0, memoryCount, 'critical', 'mdi:memory'),
    createAttackFlowStage('network', network.length > 0, network.length, 'medium', 'mdi:access-point-network'),
    createAttackFlowStage('persistence', persistenceCount > 0, persistenceCount, 'critical', 'mdi:shield-key-outline'),
    createAttackFlowStage('artifact', artifactCount > 0, artifactCount, 'high', 'mdi:file-cog-outline')
  ];
}

function calculateReportRiskSeverity(value: SandboxReport | null, sample: Api.DataProtector.SandboxSample | null) {
  if (reportParseFailed.value) return 'high';
  if (sample?.status === 'failed' || value?.error || value?.errors?.length) return 'high';
  if (!value) return sample?.status === 'running' ? 'medium' : 'info';

  let severity = 'info';
  for (const behavior of value.behaviors || []) {
    severity = maxSeverity(severity, behavior?.severity);
  }
  if ((value.runtimeEvents || []).some(item => item?.blocked)) {
    severity = maxSeverity(severity, 'high');
  } else if ((value.runtimeEvents || []).length) {
    severity = maxSeverity(severity, 'medium');
  }
  if ((value.kernelEvents || []).length) {
    severity = maxSeverity(severity, 'high');
  }
  if ((value.network || []).length || (value.fileArtifacts || []).length) {
    severity = maxSeverity(severity, 'medium');
  }
  if (value.execution?.timedOut || (typeof value.execution?.exitCode === 'number' && value.execution.exitCode !== 0)) {
    severity = maxSeverity(severity, 'medium');
  }

  return severity;
}

function buildReportSummaryText(value: SandboxReport | null, sample: Api.DataProtector.SandboxSample | null) {
  if (!sample) return $t('dataprotector.sandbox.summary.noSelection');
  if (reportParseFailed.value) return $t('dataprotector.sandbox.summary.invalid');
  if (sample.status === 'running') return $t('dataprotector.sandbox.summary.running');
  if (sample.status === 'queued') return $t('dataprotector.sandbox.summary.queued');
  if (!value) {
    if (sample.status === 'failed') {
      return sample.error || $t('dataprotector.sandbox.summary.failed');
    }
    if (sample.status === 'completed') {
      return $t('dataprotector.sandbox.summary.completedNoReport');
    }
    return $t('dataprotector.sandbox.summary.noReport');
  }

  if (value.execution?.timedOut) {
    return $t('dataprotector.sandbox.summary.timedOut');
  }

  if (typeof value.execution?.exitCode === 'number' && value.execution.exitCode !== 0) {
    return $t('dataprotector.sandbox.summary.nonZeroExit', { exitCode: value.execution.exitCode });
  }

  if (reportSignalTotal.value > 0) {
    return $t('dataprotector.sandbox.summary.signals', {
      count: reportSignalTotal.value,
      severity: severityLabel(reportRiskSeverity.value)
    });
  }

  return $t('dataprotector.sandbox.summary.clean');
}

function buildAttackProcessGraph(value: SandboxReport | null): AttackStoryProcessNode[] {
  const processes = [...(value?.processes || [])].sort((left, right) => {
    const leftTime = Date.parse(left.createdUtc || '') || 0;
    const rightTime = Date.parse(right.createdUtc || '') || 0;
    return leftTime - rightTime;
  });
  const pidSet = new Set(processes.map(item => item.pid));
  const riskByPid = new Map<number, string>();

  for (const behavior of value?.behaviors || []) {
    if (!behavior?.pid) continue;
    riskByPid.set(behavior.pid, maxSeverity(riskByPid.get(behavior.pid), behavior.severity));
  }
  for (const event of value?.runtimeEvents || []) {
    if (!event?.pid) continue;
    riskByPid.set(event.pid, maxSeverity(riskByPid.get(event.pid), event.blocked ? 'high' : 'medium'));
  }
  for (const event of value?.kernelEvents || []) {
    if (!event?.pid) continue;
    riskByPid.set(event.pid, maxSeverity(riskByPid.get(event.pid), 'high'));
  }

  return processes.map((process, index) => ({
    pid: process.pid,
    parentPid: process.parentPid,
    name: process.name || basename(process.path) || `PID ${process.pid}`,
    path: process.path || process.commandLine || '-',
    risk: riskByPid.get(process.pid) || 'info',
    depth: process.parentPid && pidSet.has(process.parentPid) ? 1 : 0,
    order: index + 1
  }));
}

function buildAttackStoryEvents(value: SandboxReport | null): AttackStoryEvent[] {
  const events: AttackStoryEvent[] = [];

  for (const behavior of value?.behaviors || []) {
    events.push({
      id: `behavior-${events.length}`,
      time: behavior.timeUtc,
      type: behavior.type || 'behavior',
      title: normalizeEventTitle(behavior.type || 'behavior'),
      detail: behavior.detail || '-',
      severity: behavior.severity || 'info',
      icon: eventIcon(behavior.type),
      pid: behavior.pid || 0
    });
  }

  for (const runtime of value?.runtimeEvents || []) {
    events.push({
      id: `runtime-${events.length}`,
      time: runtime.timestampUtc,
      type: runtime.action || 'runtime',
      title: normalizeEventTitle(runtime.action || 'runtime'),
      detail: runtime.target || runtime.processImage || '-',
      severity: runtime.blocked ? 'high' : 'medium',
      icon: eventIcon(runtime.action),
      pid: runtime.pid || 0
    });
  }

  for (const kernel of value?.kernelEvents || []) {
    events.push({
      id: `kernel-${events.length}`,
      time: value?.completedUtc || value?.startedUtc || '',
      type: kernel.operationName || 'kernel',
      title: normalizeEventTitle(kernel.operationName || 'kernel'),
      detail: kernel.target || kernel.description || kernel.processImage || '-',
      severity: 'high',
      icon: eventIcon(kernel.operationName),
      pid: kernel.pid || 0
    });
  }

  return events.sort((left, right) => (Date.parse(left.time || '') || 0) - (Date.parse(right.time || '') || 0));
}

function buildAttackStoryEntities(value: SandboxReport | null): AttackStoryEntity[] {
  return [
    {
      key: 'processes',
      label: $t('dataprotector.sandbox.attackFlow.entities.processes'),
      value: value?.processes?.length || 0,
      icon: 'mdi:family-tree'
    },
    {
      key: 'network',
      label: $t('dataprotector.sandbox.attackFlow.entities.network'),
      value: value?.network?.length || 0,
      icon: 'mdi:access-point-network'
    },
    {
      key: 'persistence',
      label: $t('dataprotector.sandbox.attackFlow.entities.persistence'),
      value: (value?.services?.length || 0) + (value?.scheduledTasks?.length || 0),
      icon: 'mdi:shield-key-outline'
    },
    {
      key: 'artifacts',
      label: $t('dataprotector.sandbox.attackFlow.entities.artifacts'),
      value: value?.fileArtifacts?.length || 0,
      icon: 'mdi:file-cog-outline'
    }
  ];
}

function createAttackFlowStage(key: string, active: boolean, count: number, severity: string, icon: string) {
  const stageKey = key as keyof typeof attackFlowStageLabelKeys;
  return {
    key,
    label: $t(attackFlowStageLabelKeys[stageKey]),
    detail: active
      ? $t(attackFlowStageDetailKeys[stageKey], { count: Math.max(count, 1) })
      : $t('dataprotector.sandbox.attackFlow.details.idle'),
    active,
    severity,
    count,
    icon
  };
}

const attackFlowStageLabelKeys = {
  launch: 'dataprotector.sandbox.attackFlow.stages.launch',
  process: 'dataprotector.sandbox.attackFlow.stages.process',
  apiMemory: 'dataprotector.sandbox.attackFlow.stages.apiMemory',
  network: 'dataprotector.sandbox.attackFlow.stages.network',
  persistence: 'dataprotector.sandbox.attackFlow.stages.persistence',
  artifact: 'dataprotector.sandbox.attackFlow.stages.artifact'
} as const satisfies Record<string, App.I18n.I18nKey>;

const attackFlowStageDetailKeys = {
  launch: 'dataprotector.sandbox.attackFlow.details.launch',
  process: 'dataprotector.sandbox.attackFlow.details.process',
  apiMemory: 'dataprotector.sandbox.attackFlow.details.apiMemory',
  network: 'dataprotector.sandbox.attackFlow.details.network',
  persistence: 'dataprotector.sandbox.attackFlow.details.persistence',
  artifact: 'dataprotector.sandbox.attackFlow.details.artifact'
} as const satisfies Record<string, App.I18n.I18nKey>;

function countTextMatches(values: string[], tokens: string[]) {
  return values.reduce((count, value) => {
    const text = String(value || '').toLowerCase();
    return count + (tokens.some(token => text.includes(token)) ? 1 : 0);
  }, 0);
}

function maxSeverity(current: string | undefined, next: string | undefined) {
  const score: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const currentSeverity = current || 'info';
  const nextSeverity = next || 'info';
  return (score[nextSeverity] ?? 0) > (score[currentSeverity] ?? 0) ? nextSeverity : currentSeverity;
}

function basename(path?: string) {
  const value = String(path || '');
  const index = Math.max(value.lastIndexOf('\\'), value.lastIndexOf('/'));
  return index >= 0 ? value.slice(index + 1) : value;
}

function normalizeEventTitle(value?: string) {
  const text = String(value || '').replace(/[-_.]+/g, ' ').trim();
  if (!text) return '-';
  return text.replace(/\b\w/g, char => char.toUpperCase());
}

function eventIcon(value?: string) {
  const text = String(value || '').toLowerCase();
  if (text.includes('network') || text.includes('connect') || text.includes('dns')) return 'mdi:access-point-network';
  if (text.includes('registry') || text.includes('task') || text.includes('service') || text.includes('persist')) return 'mdi:shield-key-outline';
  if (text.includes('memory') || text.includes('hook') || text.includes('syscall') || text.includes('virtual')) return 'mdi:memory';
  if (text.includes('file') || text.includes('driver') || text.includes('drop')) return 'mdi:file-cog-outline';
  if (text.includes('process') || text.includes('command') || text.includes('injection')) return 'mdi:source-branch';
  return 'mdi:radar';
}

function compactFlowText(value?: string, fallback = '-') {
  const text = (value || fallback).replace(/\s+/g, ' ').trim();
  if (text.length <= 30) return text;
  return `${text.slice(0, 27)}...`;
}

function compactNodeText(value?: string, fallback = '-', maxLength = 18) {
  const text = (value || fallback).replace(/\s+/g, ' ').trim();
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(1, maxLength - 3))}...`;
}

function graphSeverityColor(severity?: string) {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#64748b',
    info: '#94a3b8'
  };
  return colors[severity || 'info'] || colors.info;
}

function graphNodeFill(severity?: string, active = true) {
  if (!active) return '#e5e7eb';
  if (severity === 'critical') return '#ef4444';
  if (severity === 'high') return '#f97316';
  if (severity === 'medium') return '#f59e0b';
  if (severity === 'low') return '#64748b';
  return '#7c8a99';
}

function graphTextStyle(textWidth = 120, lineHeight = 14, color = '#334155', fontSize = 11) {
  return {
    color,
    fontSize,
    textWidth,
    overflowMode: 'ellipsis' as const,
    lineHeight
  };
}

function buildSandboxAttackGraph(value: SandboxReport | null, sample: Api.DataProtector.SandboxSample | null): AttackGraph {
  const nodes: NonNullable<FlowGraphData['nodes']> = [];
  const edges: NonNullable<FlowGraphData['edges']> = [];
  const details: AttackGraphNodeDetail[] = [];
  const miniPoints: AttackGraphMiniPoint[] = [];

  if (!value || !sample) {
    const emptyId = 'sandbox-graph-empty';
    nodes.push({
      id: emptyId,
      type: 'rect',
      x: 450,
      y: 260,
      text: {
        x: 450,
        y: 260,
        value: $t('dataprotector.sandbox.attackFlow.empty'),
        ...graphTextStyle(220, 16, '#64748b', 12)
      },
      properties: {
        width: 260,
        height: 58,
        radius: 6,
        style: { fill: '#ffffff', stroke: '#cbd5e1', strokeWidth: 1 }
      }
    });
    details.push({
      id: emptyId,
      kind: 'empty',
      title: $t('dataprotector.sandbox.attackFlow.empty'),
      subtitle: '-',
      severity: 'info',
      category: $t('dataprotector.sandbox.attackFlow.detailsPanel.noSelection'),
      description: $t('dataprotector.sandbox.summary.noReport')
    });
    miniPoints.push({ id: emptyId, x: 50, y: 50, severity: 'info' });
    return { flow: { nodes, edges }, details, miniPoints, height: 560 };
  }

  const orderedProcesses = buildAttackProcessGraph(value).slice(0, 8);
  const processSource = new Map((value.processes || []).map(process => [process.pid, process]));
  const graphProcesses = orderedProcesses.length
    ? orderedProcesses
    : [
        {
          pid: value.execution?.pid || 0,
          parentPid: 0,
          name: sample.fileName || basename(sample.processPath) || 'sample',
          path: sample.processPath || sample.fileName || '-',
          risk: reportRiskSeverity.value,
          depth: 0,
          order: 1
        }
      ];
  const processDetails = new Map<number, AttackGraphNodeDetail>();
  graphProcesses.forEach(process => {
    const source = processSource.get(process.pid);
    processDetails.set(process.pid, {
      id: '',
      kind: 'process',
      title: process.name || `PID ${process.pid}`,
      subtitle: `PID ${process.pid || '-'} / PPID ${process.parentPid || '-'}`,
      severity: process.risk || 'info',
      category: $t('dataprotector.sandbox.attackFlow.detailsPanel.process'),
      description: source?.commandLine || process.path || '-',
      pid: process.pid,
      parentPid: process.parentPid,
      path: source?.path || process.path,
      command: source?.commandLine,
      signer: source?.signature?.signer || source?.signature?.status,
      time: source?.createdUtc,
      stage: $t('dataprotector.sandbox.attackFlow.stages.process'),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.processSource')
    });
  });

  const rawEvents = buildDetailedAttackEvents(value);
  const visibleEvents = compactAttackEvents(rawEvents, 18);
  const mainX = 520;
  const leftX = 330;
  const rightX = 710;
  const topY = 84;
  const rowGap = 76;
  const rows: AttackGraphNodeDetail[] = [];

  const sampleId = 'sandbox-graph-sample';
  const sampleDetail: AttackGraphNodeDetail = {
    id: sampleId,
    kind: 'sample',
    title: sample.fileName || 'sample',
    subtitle: sample.sha256 || '-',
    severity: reportRiskSeverity.value,
    category: $t('dataprotector.sandbox.attackFlow.detailsPanel.sample'),
    description: reportSummaryText.value,
    path: sample.processPath,
    signer: sample.signer || sample.signatureStatus,
    time: sample.submittedUtc,
    source: sourceLabel(sample.source),
    stage: $t('dataprotector.sandbox.attackFlow.stages.launch')
  };
  rows.push(sampleDetail);

  const seenProcessPids = new Set<number>();
  for (const event of visibleEvents) {
    const pid = event.pid || 0;
    const process = processDetails.get(pid);
    if (process && !seenProcessPids.has(pid)) {
      seenProcessPids.add(pid);
      rows.push({ ...process, id: `sandbox-graph-process-${pid || seenProcessPids.size}` });
    }
    rows.push(event);
  }
  for (const process of graphProcesses) {
    if (!seenProcessPids.has(process.pid)) {
      rows.push({ ...processDetails.get(process.pid)!, id: `sandbox-graph-process-${process.pid || rows.length}` });
    }
  }

  nodes.push({
    id: sampleId,
    type: 'rect',
    x: mainX,
    y: topY,
    text: {
      x: mainX,
      y: topY,
      value: `${compactNodeText(sample.fileName, 'sample', 24)}\n${sample.architecture || sample.source || '-'}`,
      ...graphTextStyle(168, 13, '#334155', 11)
    },
    properties: {
      width: 190,
      height: 48,
      radius: 4,
      style: { fill: '#ffffff', stroke: '#d1d5db', strokeWidth: 1 },
      textStyle: { fontWeight: 700 }
    }
  });
  details.push(sampleDetail);

  let previousMainId = sampleId;
  rows.slice(1).forEach((row, index) => {
    const y = topY + (index + 1) * rowGap;
    const eventIndex = index + 1;
    const isProcess = row.kind === 'process';
    const nodeId = row.id || `sandbox-graph-row-${index}`;
    const laneX = isProcess ? mainX : eventIndex % 2 === 0 ? leftX : rightX;
    const labelX = isProcess ? mainX : laneX + (laneX < mainX ? -108 : 108);
    const labelAnchor = laneX < mainX ? 'end' : 'start';
    const active = row.severity !== 'info';

    nodes.push({
      id: `sandbox-graph-time-${index}`,
      type: 'text',
      x: mainX - 28,
      y,
      text: {
        x: mainX - 28,
        y,
        value: String(eventIndex),
        ...graphTextStyle(42, 12, '#b6c1cf', 10)
      },
      properties: {
        textStyle: { textAnchor: 'end' }
      }
    });

    nodes.push({
      id: nodeId,
      type: isProcess ? 'circle' : 'circle',
      x: laneX,
      y,
      text: '',
      properties: {
        r: isProcess ? 16 : active ? 9 : 6,
        style: {
          fill: graphNodeFill(row.severity, active),
          stroke: '#ffffff',
          strokeWidth: isProcess ? 3 : 2,
          filter: active ? 'drop-shadow(0 5px 14px rgba(15, 23, 42, 0.22))' : undefined
        }
      }
    });

    nodes.push({
      id: `${nodeId}-label`,
      type: 'rect',
      x: labelX,
      y,
      text: {
        x: labelX,
        y,
        value: isProcess
          ? `${compactNodeText(row.title, `PID ${row.pid}`, 24)} (${row.pid || '-'})`
          : `${compactNodeText(row.title, row.category, 24)}\n${compactNodeText(row.stage || row.category, row.category, 24)}`,
        ...graphTextStyle(isProcess ? 152 : 166, isProcess ? 12 : 13, isProcess ? '#334155' : '#475569', isProcess ? 11 : 10)
      },
      properties: {
        width: isProcess ? 162 : 176,
        height: isProcess ? 26 : 38,
        radius: 3,
        style: { fill: '#ffffff', stroke: '#e2e8f0', strokeWidth: 1, filter: 'drop-shadow(0 2px 7px rgba(15, 23, 42, 0.10))' },
        textStyle: {
          textAnchor: isProcess ? 'middle' : labelAnchor
        }
      }
    });

    if (isProcess) {
      edges.push(createGraphEdge(`sandbox-graph-main-edge-${index}`, previousMainId, nodeId, '#93c5fd', false));
      previousMainId = nodeId;
    } else {
      edges.push(createGraphEdge(`sandbox-graph-event-edge-${index}`, previousMainId, nodeId, active ? '#cbd5e1' : '#e5e7eb', true));
    }

    details.push({ ...row, id: nodeId });
  });

  const graphHeight = Math.max(560, topY + Math.max(1, rows.length) * rowGap + 120);
  nodes.unshift({
    id: 'sandbox-graph-axis',
    type: 'rect',
    x: mainX,
    y: graphHeight / 2,
    text: '',
    properties: {
      width: 2,
      height: graphHeight - 110,
      style: { fill: '#bfdbfe', stroke: '#bfdbfe', strokeWidth: 0 }
    }
  });

  rows.forEach((row, index) => {
    const y = topY + index * rowGap;
    miniPoints.push({
      id: row.id || (index === 0 ? sampleId : `sandbox-graph-row-${index}`),
      x: row.kind === 'event' ? (index % 2 === 0 ? 34 : 66) : 50,
      y: Math.min(94, Math.max(8, (y / graphHeight) * 100)),
      severity: row.severity
    });
  });

  const summaryY = graphHeight - 42;
  attackStory.value.entities.forEach((entity, index) => {
    const id = `sandbox-graph-entity-${entity.key}`;
    const x = 292 + index * 152;
    nodes.push({
      id,
      type: 'rect',
      x,
      y: summaryY,
      text: {
        x,
        y: summaryY,
        value: `${entity.label}\n${entity.value}`,
        ...graphTextStyle(112, 13, '#475569', 11)
      },
      properties: {
        width: 112,
        height: 46,
        radius: 4,
        style: { fill: '#ffffff', stroke: '#e5e7eb', strokeWidth: 1 }
      }
    });
    details.push({
      id,
      kind: 'summary',
      title: entity.label,
      subtitle: String(entity.value),
      severity: entity.value > 0 ? 'medium' : 'info',
      category: $t('dataprotector.sandbox.attackFlow.detailsPanel.entity'),
      description: $t('dataprotector.sandbox.attackFlow.detailsPanel.entityDescription', { count: entity.value })
    });
    miniPoints.push({ id, x: 24 + index * 18, y: 96, severity: entity.value > 0 ? 'medium' : 'info' });
  });

  return { flow: { nodes, edges }, details, miniPoints, height: graphHeight };
}

function buildDetailedAttackEvents(value: SandboxReport | null): AttackGraphNodeDetail[] {
  const events: AttackGraphNodeDetail[] = [];

  for (const behavior of value?.behaviors || []) {
    events.push({
      id: `behavior-${events.length}`,
      kind: 'event',
      title: normalizeEventTitle(behavior.type || 'behavior'),
      subtitle: formatTime(behavior.timeUtc),
      severity: behavior.severity || 'info',
      category: $t('dataprotector.sandbox.sections.behaviors'),
      description: behavior.detail || '-',
      pid: behavior.pid || 0,
      target: behavior.detail,
      time: behavior.timeUtc,
      stage: eventStageLabel(behavior.type, behavior.detail),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.behaviorSource')
    });
  }

  for (const runtime of value?.runtimeEvents || []) {
    events.push({
      id: `runtime-${events.length}`,
      kind: 'event',
      title: normalizeEventTitle(runtime.action || 'runtime'),
      subtitle: runtime.blocked
        ? $t('dataprotector.sandbox.attackFlow.detailsPanel.blocked')
        : $t('dataprotector.sandbox.attackFlow.detailsPanel.observed'),
      severity: runtime.blocked ? 'high' : 'medium',
      category: $t('dataprotector.sandbox.sections.runtime'),
      description: runtime.target || runtime.processImage || '-',
      pid: runtime.pid || 0,
      target: runtime.target,
      status: runtime.status,
      time: runtime.timestampUtc,
      stage: eventStageLabel(runtime.action, runtime.target),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.runtimeSource')
    });
  }

  for (const kernel of value?.kernelEvents || []) {
    events.push({
      id: `kernel-${events.length}`,
      kind: 'event',
      title: normalizeEventTitle(kernel.operationName || 'kernel'),
      subtitle: kernel.status || '-',
      severity: 'high',
      category: $t('dataprotector.sandbox.sections.kernel'),
      description: kernel.description || kernel.target || '-',
      pid: kernel.pid || 0,
      parentPid: kernel.parentPid || 0,
      target: kernel.target,
      status: kernel.status,
      time: value?.completedUtc || value?.startedUtc,
      stage: eventStageLabel(kernel.operationName, `${kernel.description} ${kernel.target}`),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.kernelSource')
    });
  }

  for (const item of value?.network || []) {
    events.push({
      id: `network-${events.length}`,
      kind: 'event',
      title: `${item.remoteAddress}:${item.remotePort}`,
      subtitle: item.state || '-',
      severity: 'medium',
      category: $t('dataprotector.sandbox.sections.network'),
      description: `${item.localAddress}:${item.localPort} -> ${item.remoteAddress}:${item.remotePort}`,
      pid: item.pid || 0,
      target: `${item.remoteAddress}:${item.remotePort}`,
      status: item.state,
      time: item.timeUtc,
      stage: $t('dataprotector.sandbox.attackFlow.stages.network'),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.networkSource')
    });
  }

  for (const artifact of value?.fileArtifacts || []) {
    events.push({
      id: `artifact-${events.length}`,
      kind: 'event',
      title: basename(artifact.path) || $t('dataprotector.sandbox.sections.artifacts'),
      subtitle: formatBytes(artifact.size),
      severity: 'medium',
      category: $t('dataprotector.sandbox.sections.artifacts'),
      description: artifact.path || '-',
      target: artifact.path,
      time: artifact.modifiedUtc,
      stage: $t('dataprotector.sandbox.attackFlow.stages.artifact'),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.fileSource')
    });
  }

  for (const service of value?.services || []) {
    events.push({
      id: `service-${events.length}`,
      kind: 'event',
      title: service.name || service.displayName || $t('dataprotector.sandbox.sections.services'),
      subtitle: service.change || service.state || '-',
      severity: 'high',
      category: $t('dataprotector.sandbox.sections.services'),
      description: service.pathName || service.displayName || '-',
      target: service.pathName,
      status: service.state,
      stage: $t('dataprotector.sandbox.attackFlow.stages.persistence'),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.serviceSource')
    });
  }

  for (const task of value?.scheduledTasks || []) {
    events.push({
      id: `task-${events.length}`,
      kind: 'event',
      title: task.name || $t('dataprotector.sandbox.sections.tasks'),
      subtitle: task.change || task.state || '-',
      severity: 'high',
      category: $t('dataprotector.sandbox.sections.tasks'),
      description: task.command || '-',
      target: task.command,
      status: task.state,
      stage: $t('dataprotector.sandbox.attackFlow.stages.persistence'),
      source: $t('dataprotector.sandbox.attackFlow.detailsPanel.taskSource')
    });
  }

  return events.sort((left, right) => (Date.parse(left.time || '') || 0) - (Date.parse(right.time || '') || 0));
}

function compactAttackEvents(events: AttackGraphNodeDetail[], maxCount: number) {
  const visible = events.filter(event => !isInternalTelemetryText(`${event.title} ${event.description} ${event.target} ${event.source}`));
  if (visible.length <= maxCount) return visible;

  const headCount = Math.max(1, Math.floor(maxCount * 0.58));
  const tailCount = Math.max(1, maxCount - headCount - 1);
  const hiddenCount = visible.length - headCount - tailCount;
  const head = visible.slice(0, headCount);
  const tail = visible.slice(visible.length - tailCount);
  const folded: AttackGraphNodeDetail = {
    id: 'sandbox-graph-folded-events',
    kind: 'event',
    title: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedTitle', { count: hiddenCount }),
    subtitle: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedSubtitle'),
    severity: 'info',
    category: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedCategory'),
    description: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedDescription', { count: hiddenCount }),
    stage: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedCategory'),
    source: $t('dataprotector.sandbox.attackFlow.detailsPanel.foldedCategory')
  };
  return [...head, folded, ...tail];
}

function eventStageLabel(type?: string, detail?: string) {
  const text = `${type || ''} ${detail || ''}`.toLowerCase();
  if (text.includes('network') || text.includes('connect') || text.includes('dns')) return $t('dataprotector.sandbox.attackFlow.stages.network');
  if (text.includes('registry') || text.includes('task') || text.includes('service') || text.includes('persist')) {
    return $t('dataprotector.sandbox.attackFlow.stages.persistence');
  }
  if (text.includes('memory') || text.includes('hook') || text.includes('syscall') || text.includes('virtual')) {
    return $t('dataprotector.sandbox.attackFlow.stages.apiMemory');
  }
  if (text.includes('file') || text.includes('driver') || text.includes('drop')) return $t('dataprotector.sandbox.attackFlow.stages.artifact');
  if (text.includes('process') || text.includes('command') || text.includes('injection')) {
    return $t('dataprotector.sandbox.attackFlow.stages.process');
  }
  return $t('dataprotector.sandbox.attackFlow.stages.launch');
}

function createGraphEdge(id: string, sourceNodeId: string, targetNodeId: string, stroke: string, subtle: boolean) {
  return {
    id,
    type: 'polyline',
    sourceNodeId,
    targetNodeId,
    properties: {
      style: {
        stroke,
        strokeWidth: subtle ? 1 : 1.4,
        strokeDasharray: subtle ? '4 4' : undefined
      }
    }
  };
}

function createLogicFlow(container: HTMLElement) {
  const lf = new LogicFlow({
    container,
    grid: {
      size: 24,
      visible: true,
      type: 'mesh',
      config: {
        color: '#eef2f7',
        thickness: 1
      }
    },
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
    hoverOutline: false,
    nodeSelectedOutline: true,
    edgeSelectedOutline: false,
    outline: false,
    history: false,
    keyboard: { enabled: false },
    edgeType: 'polyline',
    style: {
      rect: { radius: 4 },
      circle: { stroke: '#ffffff', strokeWidth: 2 },
      nodeText: {
        color: '#334155',
        fontSize: 11,
        lineHeight: 14,
        overflowMode: 'ellipsis'
      },
      text: {
        color: '#94a3b8',
        fontSize: 10,
        lineHeight: 12,
        overflowMode: 'ellipsis'
      },
      polyline: {
        stroke: '#93c5fd',
        strokeWidth: 1.4,
        fill: 'none'
      },
      arrow: {
        offset: 4,
        verticalLength: 2,
        endArrowType: 'none'
      },
      outline: {
        stroke: '#2563eb',
        strokeWidth: 1.5,
        strokeDasharray: '3 3'
      }
    }
  });
  lf.updateEditConfig({
    adjustNodePosition: false,
    textEdit: false,
    nodeTextEdit: false,
    edgeTextEdit: false,
    nodeTextDraggable: false,
    edgeTextDraggable: false,
    hideAnchors: true
  });
  lf.on('node:click', ({ data }) => {
    if (data?.id) selectedAttackNodeId.value = data.id;
  });

  return lf;
}

function renderLogicFlow(lf: LogicFlow, data: FlowGraphData) {
  lf.render(data);
  nextTick(() => {
    window.setTimeout(() => {
      lf.resetZoom();
      lf.fitView(72, 110);
      const transform = lf.getTransform();
      if (transform.SCALE_X > 1.08) {
        lf.zoom(1 / transform.SCALE_X);
        lf.translateCenter();
      }
    }, 0);
  });
}

function renderSandboxFlows() {
  nextTick(() => {
    if (sandboxAttackFlowRef.value) {
      sandboxAttackFlow ??= createLogicFlow(sandboxAttackFlowRef.value);
      renderLogicFlow(sandboxAttackFlow, attackGraph.value.flow);
      if (!selectedAttackNodeId.value || !attackGraph.value.details.some(item => item.id === selectedAttackNodeId.value)) {
        selectedAttackNodeId.value = attackGraph.value.details[0]?.id || '';
      }
    }
  });
}

function zoomSandboxAttackFlow(zoomIn: boolean) {
  sandboxAttackFlow?.zoom(zoomIn);
}

function statusTagType(status: string) {
  if (status === 'completed') return 'success';
  if (status === 'running') return 'info';
  if (status === 'failed') return 'error';
  return 'warning';
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: $t('dataprotector.sandbox.status.queued'),
    running: $t('dataprotector.sandbox.status.running'),
    completed: $t('dataprotector.sandbox.status.completed'),
    failed: $t('dataprotector.sandbox.status.failed')
  };
  return labels[status] || status;
}

function sourceLabel(source: string) {
  return source === 'agent' ? $t('dataprotector.sandbox.sources.agent') : $t('dataprotector.sandbox.sources.web');
}

function severityTagType(severity: string) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'info';
  return 'default';
}

function severityLabel(severity: string) {
  const labels: Record<string, string> = {
    critical: $t('dataprotector.sandbox.severity.critical'),
    high: $t('dataprotector.sandbox.severity.high'),
    medium: $t('dataprotector.sandbox.severity.medium'),
    low: $t('dataprotector.sandbox.severity.low'),
    info: $t('dataprotector.sandbox.severity.info')
  };
  return labels[severity] || labels.info;
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

watch([attackStory, () => appStore.locale], renderSandboxFlows, { deep: true });

onMounted(async () => {
  renderSandboxFlows();
  await refresh(false);
  if (samples.value.some(item => item.status === 'running')) startPolling();
});

onBeforeUnmount(() => {
  stopPolling();
  sandboxAttackFlow?.destroy();
  sandboxAttackFlow = null;
});
</script>

<template>
  <div class="sandbox-page">
    <NCard :bordered="false" class="hero-card">
      <div class="hero-content">
        <div>
          <div class="eyebrow">{{ $t('dataprotector.sandbox.eyebrow') }}</div>
          <h1>{{ $t('dataprotector.sandbox.title') }}</h1>
          <p>{{ $t('dataprotector.sandbox.subtitle') }}</p>
        </div>
        <NSpace align="center" wrap>
          <NTag type="success" :bordered="false">{{ $t('dataprotector.sandbox.serverOnly') }}</NTag>
          <NUpload :show-file-list="false" accept=".exe,application/x-msdownload" :custom-request="uploadSample">
            <NButton type="primary" :loading="uploading">
              <template #icon><SvgIcon icon="mdi:upload-lock-outline" /></template>
              {{ $t('dataprotector.sandbox.upload') }}
            </NButton>
          </NUpload>
        </NSpace>
      </div>
    </NCard>

    <NGrid :cols="5" :x-gap="16" :y-gap="16" responsive="screen">
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.total')" :value="stats.total" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.queued')" :value="stats.queued" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.running')" :value="stats.running" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.completed')" :value="stats.completed" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.failed')" :value="stats.failed" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 xl:15">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>{{ $t('dataprotector.sandbox.queue') }}</span>
              <NSpace align="center" wrap>
                <NButton secondary :disabled="loading || samples.some(item => item.status === 'running')" @click="clearLogs">
                  <template #icon><SvgIcon icon="mdi:delete-sweep-outline" /></template>
                  {{ $t('dataprotector.sandbox.clearLogs') }}
                </NButton>
                <NButton type="primary" :loading="loading" @click="refresh(false)">
                  <template #icon><SvgIcon icon="mdi:refresh" /></template>
                  {{ $t('dataprotector.common.refresh') }}
                </NButton>
              </NSpace>
            </div>
          </template>

          <NSpace align="center" wrap class="filters">
            <NSelect v-model:value="query.status" :options="statusOptions" class="filter-control" />
            <NSelect v-model:value="query.source" :options="sourceOptions" class="filter-control" />
            <NInput v-model:value="query.host" clearable :placeholder="$t('dataprotector.sandbox.filters.host')" class="filter-control" />
            <NInput
              v-model:value="query.search"
              clearable
              :placeholder="$t('dataprotector.sandbox.filters.search')"
              class="search-control"
              @keyup.enter="refresh(true)"
            />
            <NButton secondary @click="refresh(true)">{{ $t('dataprotector.common.apply') }}</NButton>
          </NSpace>

          <NDataTable
            :columns="sampleColumns"
            :data="samples"
            :loading="loading"
            :row-key="rowKey"
            :row-props="rowProps"
            :pagination="pagination"
            remote
            :scroll-x="1880"
            size="small"
          />
        </NCard>
      </NGi>

      <NGi span="24 xl:9">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>{{ $t('dataprotector.sandbox.analysis') }}</span>
              <NTag v-if="selectedSample" :type="statusTagType(selectedSample.status)" :bordered="false">
                {{ statusLabel(selectedSample.status) }}
              </NTag>
            </div>
          </template>

          <template v-if="selectedSample">
            <div class="sample-summary">
              <div class="cell-strong">{{ selectedSample.fileName }}</div>
              <div class="cell-muted mono">{{ selectedSample.sha256 }}</div>
              <div class="tag-row">
                <NTag :type="selectedSample.source === 'agent' ? 'warning' : 'info'" :bordered="false">
                  {{ sourceLabel(selectedSample.source) }}
                </NTag>
                <NTag :type="selectedSample.signatureStatus === 'signed' ? 'success' : 'error'" :bordered="false">
                  {{ selectedSample.signatureStatus || $t('dataprotector.common.unknown') }}
                </NTag>
                <NTag :bordered="false">{{ selectedSample.architecture || '-' }}</NTag>
              </div>
            </div>

            <div class="selected-report-brief" :class="`severity-${reportRiskSeverity}`">
              <div class="brief-main">
                <div class="brief-icon">
                  <SvgIcon icon="mdi:shield-search" />
                </div>
                <div class="brief-copy">
                  <div class="brief-title">
                    {{ report ? $t('dataprotector.sandbox.summary.ready') : statusLabel(selectedSample.status) }}
                  </div>
                  <div class="brief-text">{{ reportSummaryText }}</div>
                </div>
                <NTag :type="severityTagType(reportRiskSeverity)" :bordered="false">
                  {{ severityLabel(reportRiskSeverity) }}
                </NTag>
              </div>
              <div class="brief-metrics">
                <div>
                  <span>{{ $t('dataprotector.sandbox.reportMetrics.behaviors') }}</span>
                  <strong>{{ reportSignalCounts.behaviors }}</strong>
                </div>
                <div>
                  <span>{{ $t('dataprotector.sandbox.reportMetrics.kernel') }}</span>
                  <strong>{{ reportSignalCounts.kernel }}</strong>
                </div>
                <div>
                  <span>{{ $t('dataprotector.sandbox.reportMetrics.runtime') }}</span>
                  <strong>{{ reportSignalCounts.runtime }}</strong>
                </div>
                <div>
                  <span>{{ $t('dataprotector.sandbox.reportMetrics.network') }}</span>
                  <strong>{{ reportSignalCounts.network }}</strong>
                </div>
              </div>
              <div v-if="reportTopFindings.length" class="brief-findings">
                <div v-for="finding in reportTopFindings" :key="finding.id" class="brief-finding">
                  <SvgIcon :icon="finding.icon" />
                  <span>{{ finding.title }}</span>
                </div>
              </div>
              <NAlert v-if="reportParseFailed" type="error" :bordered="false" class="m-t-10px">
                {{ $t('dataprotector.sandbox.summary.invalid') }}
              </NAlert>
              <NButton v-if="report" class="m-t-10px" secondary block @click="scrollToReport">
                <template #icon><SvgIcon icon="mdi:file-chart-outline" /></template>
                {{ $t('dataprotector.sandbox.summary.openReport') }}
              </NButton>
            </div>

            <NForm label-placement="top" class="analysis-form">
              <NFormItem :label="$t('dataprotector.sandbox.arguments')">
                <NInput v-model:value="analysisForm.arguments" clearable :placeholder="$t('dataprotector.sandbox.argumentsPlaceholder')" />
              </NFormItem>
              <NGrid :x-gap="12" :y-gap="12" cols="1 m:2">
                <NGi>
                  <NFormItem :label="$t('dataprotector.sandbox.timeout')">
                    <NInputNumber v-model:value="analysisForm.timeoutSeconds" :min="15" :max="1800" class="w-full" />
                  </NFormItem>
                </NGi>
                <NGi>
                  <NFormItem :label="$t('dataprotector.sandbox.options')">
                    <div class="checks">
                      <NCheckbox v-model:checked="analysisForm.networkEnabled">
                        {{ $t('dataprotector.sandbox.enableNetwork') }}
                      </NCheckbox>
                      <NCheckbox v-model:checked="analysisForm.closeWhenDone">
                        {{ $t('dataprotector.sandbox.closeWhenDone') }}
                      </NCheckbox>
                    </div>
                  </NFormItem>
                </NGi>
              </NGrid>
              <NButton type="primary" :loading="analyzing || selectedSample.status === 'running'" @click="analyze(selectedSample)">
                <template #icon><SvgIcon icon="mdi:shield-search" /></template>
                {{ $t('dataprotector.sandbox.analyze') }}
              </NButton>
            </NForm>

            <NDescriptions class="m-t-14px" :column="1" bordered size="small">
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.host')">{{ selectedSample.host || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.path')">{{ selectedSample.processPath || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.reason')">{{ selectedSample.suspicion || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.error')">{{ selectedSample.error || '-' }}</NDescriptionsItem>
            </NDescriptions>
          </template>
          <NEmpty v-else :description="$t('dataprotector.sandbox.empty')" />
        </NCard>
      </NGi>
    </NGrid>

    <NCard id="sandbox-report-panel" :bordered="false" class="work-panel">
      <template #header>
        <div class="panel-title">
          <span>{{ $t('dataprotector.sandbox.report') }}</span>
          <NButton
            v-if="selectedSample"
            secondary
            type="error"
            :disabled="selectedSample.status === 'running' || !selectedSample.reportJson"
            @click="removeLogs(selectedSample)"
          >
            <template #icon><SvgIcon icon="mdi:file-document-remove-outline" /></template>
            {{ $t('dataprotector.sandbox.deleteLogs') }}
          </NButton>
        </div>
      </template>
      <template v-if="selectedSample && report">
        <div class="verdict-panel" :class="`severity-${reportRiskSeverity}`">
          <div class="verdict-copy">
            <div class="eyebrow">{{ $t('dataprotector.sandbox.summary.verdict') }}</div>
            <h3>{{ severityLabel(reportRiskSeverity) }}</h3>
            <p>{{ reportSummaryText }}</p>
          </div>
          <div class="verdict-meta">
            <div>
              <span>{{ $t('dataprotector.sandbox.exitCode') }}</span>
              <strong>{{ report.execution?.exitCode ?? '-' }}</strong>
            </div>
            <div>
              <span>{{ $t('dataprotector.sandbox.duration') }}</span>
              <strong>{{ report.execution?.timeoutSeconds || selectedSample.timeoutSeconds || '-' }}s</strong>
            </div>
          </div>
        </div>

        <div class="report-summary">
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.behaviors') }}</span>
            <strong>{{ report.behaviors?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.processes') }}</span>
            <strong>{{ report.processes?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.network') }}</span>
            <strong>{{ report.network?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.artifacts') }}</span>
            <strong>{{ report.fileArtifacts?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.runtime') }}</span>
            <strong>{{ report.runtimeEvents?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.kernel') }}</span>
            <strong>{{ report.kernelEvents?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.services') }}</span>
            <strong>{{ report.services?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.tasks') }}</span>
            <strong>{{ report.scheduledTasks?.length || 0 }}</strong>
          </div>
        </div>

        <div class="attack-flow-panel">
          <div class="attack-flow-header">
            <div>
              <div class="eyebrow">{{ $t('dataprotector.sandbox.attackFlow.eyebrow') }}</div>
              <h3>{{ $t('dataprotector.sandbox.attackFlow.title') }}</h3>
              <p>{{ $t('dataprotector.sandbox.attackFlow.caption') }}</p>
            </div>
            <NTag type="info" :bordered="false">
              {{ $t('dataprotector.sandbox.attackFlow.active', { count: activeAttackFlowStageCount }) }}
            </NTag>
          </div>

          <div class="story-stage-summary">
            <NTag
              v-for="stage in attackStory.stages"
              :key="stage.key"
              size="small"
              :type="stage.active ? severityTagType(stage.severity) : 'default'"
              :bordered="false"
            >
              {{ stage.label }} {{ stage.count || 0 }}
            </NTag>
          </div>

          <div class="attack-investigation-layout">
            <div class="attack-graph-shell">
              <div ref="sandboxAttackFlowRef" class="logic-flow-panel attack-graph-canvas" :style="{ height: `${attackGraph.height}px` }"></div>
              <div class="attack-graph-tools">
                <NButton quaternary circle size="small" @click="renderSandboxFlows">
                  <template #icon><SvgIcon icon="mdi:fit-to-page-outline" /></template>
                </NButton>
                <NButton quaternary circle size="small" @click="zoomSandboxAttackFlow(true)">
                  <template #icon><SvgIcon icon="mdi:magnify-plus-outline" /></template>
                </NButton>
                <NButton quaternary circle size="small" @click="zoomSandboxAttackFlow(false)">
                  <template #icon><SvgIcon icon="mdi:magnify-minus-outline" /></template>
                </NButton>
              </div>
              <div class="attack-mini-map">
                <div class="mini-map-title">{{ $t('dataprotector.sandbox.attackFlow.navigation') }}</div>
                <div class="mini-map-body">
                  <button
                    v-for="point in attackGraph.miniPoints"
                    :key="point.id"
                    class="mini-map-point"
                    :class="{ active: selectedAttackNodeId === point.id }"
                    :style="{ left: `${point.x}%`, top: `${point.y}%`, background: graphSeverityColor(point.severity) }"
                    @click="selectedAttackNodeId = point.id"
                  />
                </div>
              </div>
            </div>

            <aside class="attack-detail-panel">
              <template v-if="selectedAttackNode">
                <div class="detail-back">
                  <SvgIcon icon="mdi:chevron-left" />
                  <span>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.back') }}</span>
                </div>
                <div class="detail-title-row">
                  <h4>{{ selectedAttackNode.title }}</h4>
                  <NTag :type="severityTagType(selectedAttackNode.severity)" :bordered="false">
                    {{ severityLabel(selectedAttackNode.severity) }}
                  </NTag>
                </div>
                <div class="detail-subtitle">{{ selectedAttackNode.subtitle }}</div>
                <p class="detail-description">{{ selectedAttackNode.description }}</p>
                <div class="detail-tabs">
                  <span class="active">{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.processTab') }}</span>
                  <span>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.fileTab') }}</span>
                  <span>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.otherTab') }}</span>
                </div>
                <div class="detail-fields">
                  <div>
                    <span>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.category') }}</span>
                    <strong>{{ selectedAttackNode.category || '-' }}</strong>
                  </div>
                  <div>
                    <span>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.stage') }}</span>
                    <strong>{{ selectedAttackNode.stage || '-' }}</strong>
                  </div>
                  <div>
                    <span>PID</span>
                    <strong>{{ selectedAttackNode.pid || '-' }}</strong>
                  </div>
                  <div>
                    <span>PPID</span>
                    <strong>{{ selectedAttackNode.parentPid || '-' }}</strong>
                  </div>
                  <div>
                    <span>{{ $t('dataprotector.sandbox.columns.path') }}</span>
                    <strong>{{ selectedAttackNode.path || '-' }}</strong>
                  </div>
                  <div>
                    <span>{{ $t('dataprotector.sandbox.columns.command') }}</span>
                    <strong>{{ selectedAttackNode.command || selectedAttackNode.target || '-' }}</strong>
                  </div>
                  <div>
                    <span>{{ $t('dataprotector.sandbox.columns.signature') }}</span>
                    <strong>{{ selectedAttackNode.signer || '-' }}</strong>
                  </div>
                  <div>
                    <span>{{ $t('dataprotector.sandbox.columns.time') }}</span>
                    <strong>{{ formatTime(selectedAttackNode.time) }}</strong>
                  </div>
                </div>
                <div class="attack-tactics">
                  <div>{{ $t('dataprotector.sandbox.attackFlow.detailsPanel.attackInfo') }}</div>
                  <NTag v-if="selectedAttackNode.stage" size="small" :bordered="false">{{ selectedAttackNode.stage }}</NTag>
                  <NTag size="small" :bordered="false">{{ selectedAttackNode.source || selectedAttackNode.kind }}</NTag>
                </div>
              </template>
              <NEmpty v-else :description="$t('dataprotector.sandbox.attackFlow.empty')" />
            </aside>
          </div>

          <div class="attack-evidence-strip">
            <div
              v-for="event in attackGraph.details.filter(item => item.kind === 'event' && item.id !== 'sandbox-graph-folded-events').slice(0, 8)"
              :key="event.id"
              class="evidence-chip"
              :class="{ active: selectedAttackNodeId === event.id }"
              @click="selectedAttackNodeId = event.id"
            >
              <span :style="{ background: graphSeverityColor(event.severity) }"></span>
              <strong>{{ event.title }}</strong>
              <small>PID {{ event.pid || '-' }}</small>
            </div>
          </div>
        </div>

        <NAlert v-if="report.error || report.errors?.length" type="warning" :bordered="false" class="m-b-12px">
          {{ report.error || report.errors?.join('; ') }}
        </NAlert>

        <NDescriptions :column="2" bordered size="small" class="m-b-14px">
          <NDescriptionsItem :label="$t('dataprotector.sandbox.boundary')">
            {{ report.isolationControls?.boundary || report.isolation }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.network')">
            {{ report.isolationControls?.network || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.exitCode')">
            {{ report.execution?.exitCode ?? '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.duration')">
            {{ formatTime(report.startedUtc) }} - {{ formatTime(report.completedUtc) }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.telemetryMode')">
            {{ report.telemetry?.mode || report.schema || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.runtimeHook')">
            {{ report.telemetry?.runtimeHook || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.kernelSensor')">
            {{ report.kernelSensor?.status || report.telemetry?.kernelSensor || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.kernelPolicy')">
            {{ report.kernelSensor?.policyStatus || '-' }}
          </NDescriptionsItem>
        </NDescriptions>

        <NCollapse>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.behaviors')" name="behaviors">
            <NDataTable :columns="behaviorColumns" :data="report.behaviors || []" :scroll-x="920" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.processes')" name="processes">
            <NDataTable :columns="processColumns" :data="report.processes || []" :scroll-x="1200" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.network')" name="network">
            <NDataTable :columns="networkColumns" :data="report.network || []" :scroll-x="900" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.artifacts')" name="artifacts">
            <NDataTable :columns="fileColumns" :data="report.fileArtifacts || []" :scroll-x="860" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.runtime')" name="runtime">
            <NDataTable :columns="runtimeColumns" :data="report.runtimeEvents || []" :scroll-x="1260" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.kernel')" name="kernel">
            <NDescriptions v-if="report.kernelSensor" :column="2" bordered size="small" class="m-b-12px">
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.status')">{{ report.kernelSensor.status }}</NDescriptionsItem>
              <NDescriptionsItem label="Win32">{{ report.kernelSensor.win32 || 0 }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.service')">{{ report.kernelSensor.serviceName || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.message')">{{ report.kernelSensor.message || '-' }}</NDescriptionsItem>
            </NDescriptions>
            <NDataTable :columns="kernelColumns" :data="report.kernelEvents || []" :scroll-x="1360" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.services')" name="services">
            <NDataTable :columns="serviceColumns" :data="report.services || []" :scroll-x="1200" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.tasks')" name="tasks">
            <NDataTable :columns="taskColumns" :data="report.scheduledTasks || []" :scroll-x="1100" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.output')" name="output">
            <pre class="sandbox-output">{{ report.stdout || report.stderr || selectedSample.reportJson }}</pre>
          </NCollapseItem>
        </NCollapse>
      </template>
      <template v-else-if="selectedSample">
        <NAlert v-if="reportParseFailed" type="error" :bordered="false">
          {{ $t('dataprotector.sandbox.summary.invalid') }}
        </NAlert>
        <NAlert v-else-if="selectedSample.status === 'completed'" type="warning" :bordered="false">
          {{ $t('dataprotector.sandbox.summary.completedNoReport') }}
        </NAlert>
        <NAlert v-else-if="selectedSample.status === 'failed'" type="error" :bordered="false">
          {{ selectedSample.error || $t('dataprotector.sandbox.summary.failed') }}
        </NAlert>
        <NEmpty v-else :description="$t('dataprotector.sandbox.noReport')" />
      </template>
      <NEmpty v-else :description="$t('dataprotector.sandbox.noReport')" />
    </NCard>
  </div>
</template>

<style scoped>
.sandbox-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.hero-card,
.metric-card,
.work-panel {
  border-radius: 8px;
}

.hero-content {
  display: flex;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
}

.hero-content h1 {
  margin: 4px 0 6px;
  font-size: 24px;
  font-weight: 800;
}

.hero-content p {
  margin: 0;
  color: var(--n-text-color-3);
}

.eyebrow {
  color: #7c3aed;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
}

.panel-title,
.action-row,
.tag-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.action-row {
  flex-wrap: wrap;
}

.panel-title {
  justify-content: space-between;
}

.filters {
  margin-bottom: 16px;
}

.filter-control {
  width: 180px;
}

.search-control {
  width: min(380px, 100%);
}

.cell-stack,
.sample-summary {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}

.cell-strong {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color);
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-muted {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color-3);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace;
}

.analysis-form {
  margin-top: 16px;
}

.checks {
  display: grid;
  gap: 8px;
}

.selected-report-brief,
.verdict-panel {
  margin-top: 14px;
  padding: 14px;
  overflow: hidden;
  background:
    linear-gradient(135deg, rgb(35 24 63 / 94%), rgb(15 23 42 / 96%)),
    radial-gradient(circle at 12% 0%, rgb(139 92 246 / 24%), transparent 34%);
  border: 1px solid rgb(167 139 250 / 28%);
  border-radius: 8px;
  box-shadow: inset 0 1px 0 rgb(255 255 255 / 8%);
}

.brief-main,
.verdict-panel {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.brief-icon {
  display: grid;
  flex: 0 0 40px;
  width: 40px;
  height: 40px;
  place-items: center;
  color: #ffffff;
  font-size: 22px;
  background: rgb(124 58 237 / 32%);
  border: 1px solid rgb(196 181 253 / 30%);
  border-radius: 8px;
}

.brief-copy,
.verdict-copy {
  min-width: 0;
}

.brief-title,
.verdict-copy h3 {
  color: #ffffff;
  font-weight: 850;
}

.brief-title {
  font-size: 15px;
}

.brief-text,
.verdict-copy p {
  margin: 4px 0 0;
  color: rgb(203 213 225);
  font-size: 12px;
  line-height: 1.5;
}

.brief-metrics,
.verdict-meta {
  display: grid;
  gap: 8px;
}

.brief-metrics {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin-top: 12px;
}

.brief-metrics div,
.verdict-meta div {
  min-width: 0;
  padding: 9px 10px;
  background: rgb(15 23 42 / 42%);
  border: 1px solid rgb(148 163 184 / 16%);
  border-radius: 8px;
}

.brief-metrics span,
.verdict-meta span {
  display: block;
  overflow: hidden;
  color: rgb(148 163 184);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.brief-metrics strong,
.verdict-meta strong {
  display: block;
  margin-top: 2px;
  color: #ffffff;
  font-size: 18px;
}

.brief-findings {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 12px;
}

.brief-finding {
  display: inline-flex;
  max-width: 100%;
  gap: 6px;
  align-items: center;
  padding: 6px 8px;
  color: rgb(226 232 240);
  font-size: 12px;
  background: rgb(15 23 42 / 44%);
  border: 1px solid rgb(148 163 184 / 16%);
  border-radius: 8px;
}

.brief-finding span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.selected-report-brief.severity-critical,
.selected-report-brief.severity-high,
.verdict-panel.severity-critical,
.verdict-panel.severity-high {
  border-color: rgb(251 113 133 / 34%);
}

.selected-report-brief.severity-medium,
.verdict-panel.severity-medium {
  border-color: rgb(251 191 36 / 34%);
}

.verdict-panel {
  margin: 0 0 14px;
}

.verdict-copy h3 {
  margin: 3px 0 0;
  font-size: 24px;
}

.verdict-meta {
  grid-template-columns: repeat(2, minmax(120px, 1fr));
  min-width: 260px;
}

.report-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.report-metric {
  padding: 12px;
  background: rgb(249 250 251);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.report-metric span {
  display: block;
  color: var(--n-text-color-3);
  font-size: 12px;
}

.report-metric strong {
  display: block;
  margin-top: 4px;
  font-size: 22px;
}

.attack-flow-panel {
  position: relative;
  padding: 0;
  overflow: hidden;
  background: #f4f6f8;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
  margin-bottom: 14px;
}

.attack-flow-header {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
  padding: 14px 16px 10px;
  background: rgb(255 255 255 / 82%);
  border-bottom: 1px solid rgb(226 232 240);
}

.attack-flow-header h3 {
  margin: 3px 0 0;
  font-size: 17px;
  font-weight: 800;
}

.attack-flow-header p {
  max-width: 760px;
  margin: 4px 0 0;
  color: var(--n-text-color-3);
  font-size: 12px;
  line-height: 1.45;
}

.logic-flow-panel {
  overflow: hidden;
  background: #f4f6f8;
}

.story-stage-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  padding: 12px 16px;
  background: #ffffff;
  border-bottom: 1px solid rgb(226 232 240);
}

.attack-investigation-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  min-height: 680px;
}

.attack-graph-shell {
  position: relative;
  min-width: 0;
  max-height: 760px;
  min-height: 560px;
  overflow: auto;
  background:
    linear-gradient(90deg, rgb(226 232 240 / 32%) 1px, transparent 1px),
    linear-gradient(rgb(226 232 240 / 32%) 1px, transparent 1px),
    #f5f7f9;
  background-size: 42px 42px;
}

.attack-graph-canvas {
  width: 100%;
  min-height: 560px;
  border: 0;
  border-radius: 0;
}

.attack-graph-tools {
  position: absolute;
  top: 12px;
  left: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.attack-graph-tools :deep(.n-button) {
  background: rgb(255 255 255 / 92%);
  border: 1px solid rgb(226 232 240);
  box-shadow: 0 5px 14px rgb(15 23 42 / 10%);
}

.attack-mini-map {
  position: absolute;
  bottom: 14px;
  left: 14px;
  width: 170px;
  padding: 8px;
  background: rgb(255 255 255 / 92%);
  border: 1px solid rgb(203 213 225);
  border-radius: 4px;
  box-shadow: 0 10px 28px rgb(15 23 42 / 12%);
}

.mini-map-title {
  margin-bottom: 6px;
  color: #64748b;
  font-size: 11px;
  font-weight: 700;
}

.mini-map-body {
  position: relative;
  height: 118px;
  overflow: hidden;
  background:
    linear-gradient(90deg, rgb(226 232 240 / 72%) 1px, transparent 1px),
    linear-gradient(rgb(226 232 240 / 72%) 1px, transparent 1px),
    #f8fafc;
  background-size: 18px 18px;
  border: 1px solid rgb(226 232 240);
}

.mini-map-point {
  position: absolute;
  width: 8px;
  height: 8px;
  padding: 0;
  border: 1px solid #ffffff;
  border-radius: 999px;
  box-shadow: 0 1px 4px rgb(15 23 42 / 18%);
  transform: translate(-50%, -50%);
}

.mini-map-point.active {
  width: 13px;
  height: 13px;
  outline: 2px solid rgb(96 165 250 / 48%);
}

.attack-detail-panel {
  min-width: 0;
  padding: 18px 22px;
  overflow: auto;
  background: #ffffff;
  border-left: 1px solid rgb(226 232 240);
}

.detail-back {
  display: inline-flex;
  gap: 4px;
  align-items: center;
  margin-bottom: 20px;
  color: #60a5fa;
  font-size: 12px;
}

.detail-title-row {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  justify-content: space-between;
}

.detail-title-row h4 {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: #1f2937;
  font-size: 17px;
  line-height: 1.35;
}

.detail-subtitle {
  margin-top: 8px;
  overflow-wrap: anywhere;
  color: #64748b;
  font-size: 12px;
}

.detail-description {
  margin: 20px 0 18px;
  overflow-wrap: anywhere;
  color: #374151;
  font-size: 13px;
  line-height: 1.65;
}

.detail-tabs {
  display: flex;
  gap: 28px;
  margin-bottom: 16px;
  border-bottom: 1px solid rgb(226 232 240);
}

.detail-tabs span {
  padding-bottom: 9px;
  color: #94a3b8;
  font-size: 13px;
  font-weight: 700;
}

.detail-tabs span.active {
  color: #2563eb;
  border-bottom: 2px solid #60a5fa;
}

.detail-fields {
  display: grid;
  gap: 11px;
}

.detail-fields div {
  display: grid;
  grid-template-columns: 112px minmax(0, 1fr);
  gap: 14px;
  align-items: start;
}

.detail-fields span {
  color: #64748b;
  font-size: 12px;
}

.detail-fields strong {
  min-width: 0;
  overflow-wrap: anywhere;
  color: #374151;
  font-size: 12px;
  font-weight: 600;
}

.attack-tactics {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 28px;
  padding-top: 16px;
  border-top: 1px solid rgb(226 232 240);
}

.attack-tactics div {
  flex: 0 0 100%;
  color: #475569;
  font-size: 13px;
  font-weight: 800;
}

.attack-evidence-strip {
  display: flex;
  gap: 8px;
  padding: 12px 16px 14px;
  overflow: auto;
  background: #ffffff;
  border-top: 1px solid rgb(226 232 240);
}

.evidence-chip {
  display: inline-grid;
  grid-template-columns: auto minmax(120px, 1fr);
  grid-template-rows: auto auto;
  min-width: 178px;
  max-width: 240px;
  column-gap: 8px;
  row-gap: 2px;
  align-items: center;
  padding: 8px 10px;
  cursor: pointer;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 4px;
}

.evidence-chip.active {
  background: #eff6ff;
  border-color: #93c5fd;
}

.evidence-chip span {
  grid-row: 1 / span 2;
  width: 8px;
  height: 8px;
  border-radius: 999px;
}

.evidence-chip strong {
  overflow: hidden;
  color: #334155;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.evidence-chip small {
  color: #94a3b8;
  font-size: 11px;
}

.sandbox-output {
  max-height: 360px;
  padding: 14px;
  overflow: auto;
  color: rgb(209 250 229);
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  background: rgb(17 24 39);
  border-radius: 8px;
}

:deep(.selected-row td) {
  background: rgb(245 243 255) !important;
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

  .brief-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .attack-investigation-layout,
  .verdict-panel {
    grid-template-columns: 1fr;
  }

  .attack-detail-panel {
    max-height: none;
    border-top: 1px solid rgb(226 232 240);
    border-left: 0;
  }

  .brief-main,
  .verdict-panel {
    align-items: flex-start;
    flex-direction: column;
  }

  .verdict-meta {
    width: 100%;
    min-width: 0;
  }
}

@media (max-width: 560px) {
  .report-summary,
  .brief-metrics {
    grid-template-columns: 1fr;
  }
}

</style>
