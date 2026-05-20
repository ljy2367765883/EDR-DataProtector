<script setup lang="ts">
import { computed, h, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import LogicFlow from '@logicflow/core';
import '@logicflow/core/dist/index.css';
import { NButton, NTag, type DataTableColumns, type PaginationProps } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import { fetchAuditAttackFlow, fetchAuditEvents, fetchClearAuditEvents, fetchDevices, fetchRemoveAuditEvent } from '@/service/api';
import { $t } from '@/locales';
import { useAppStore } from '@/store/modules/app';

defineOptions({
  name: 'Audit'
});

type AuditCategory = Api.DataProtector.AuditCategory;
type AuditSeverity = Api.DataProtector.AuditSeverity;
type AuditDisposition = Api.DataProtector.AuditDisposition;

interface CategoryOption {
  label: string;
  value: AuditCategory;
  icon: string;
  tagType: 'default' | 'error' | 'info' | 'success' | 'warning';
}

interface AuditSummary {
  category: AuditCategory;
  label: string;
  count: number;
  critical: number;
}

interface HostSummary {
  host: string;
  total: number;
  critical: number;
  warning: number;
  blocked: number;
}

interface AuditTimelineItem {
  id: string;
  timeUtc: string;
  lastTimeUtc?: string;
  stage: string;
  category: string;
  action: string;
  title: string;
  detail: string;
  severity: string;
  disposition: string;
  source: string;
  target: string;
  object: string;
  remote: string;
  raw: string;
  count?: number;
}

interface AuditGraphPoint {
  id: string;
  x: number;
  y: number;
  severity: string;
}

interface AuditGraph {
  flow: FlowGraphData;
  miniPoints: AuditGraphPoint[];
  height: number;
}

type FlowGraphData = Parameters<LogicFlow['render']>[0];

const loading = ref(false);
const appStore = useAppStore();
const auditResponse = ref<Api.DataProtector.AuditQueryResponse | null>(null);
const attackFlow = ref<Api.DataProtector.AuditAttackFlowResponse | null>(null);
const devices = ref<Api.DataProtector.Device[]>([]);
const activeCategory = ref<AuditCategory>('all');
const timeRange = ref<[number, number] | null>(null);
const selectedAuditRecord = ref<Api.DataProtector.AuditRecord | null>(null);
const auditDetailVisible = ref(false);
const auditDetailLoading = ref(false);
const attackDetailFlowRef = ref<HTMLElement | null>(null);
const selectedDetailEventId = ref('');
let attackDetailFlow: LogicFlow | null = null;

const filters = reactive({
  host: 'all',
  severity: 'all' as AuditSeverity,
  disposition: 'all' as AuditDisposition,
  search: ''
});

let suppressPaginationRefresh = false;

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 30,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [15, 30, 50, 100],
  prefix: page => $t('datatable.itemCount', { total: page.itemCount }),
  onUpdatePage(page) {
    pagination.page = page;
    if (!suppressPaginationRefresh) refresh(false);
  },
  onUpdatePageSize(pageSize) {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    if (!suppressPaginationRefresh) refresh(false);
  }
});

const categoryOptions = computed<CategoryOption[]>(() => [
  { label: $t('dataprotector.audit.allEvents'), value: 'all', icon: 'mdi:format-list-bulleted', tagType: 'default' },
  { label: $t('dataprotector.audit.policy'), value: 'policy', icon: 'mdi:shield-key-outline', tagType: 'info' },
  { label: $t('dataprotector.audit.networkDefense'), value: 'network', icon: 'mdi:lan-connect', tagType: 'warning' },
  { label: $t('dataprotector.audit.smtpAudit'), value: 'smtp', icon: 'mdi:email-fast-outline', tagType: 'success' },
  { label: $t('dataprotector.audit.webshell'), value: 'webshell', icon: 'mdi:webhook', tagType: 'error' },
  { label: $t('dataprotector.audit.hashdump'), value: 'hashdump', icon: 'mdi:account-lock-outline', tagType: 'error' },
  { label: $t('dataprotector.audit.lateral'), value: 'lateral', icon: 'mdi:lan-disconnect', tagType: 'error' },
  { label: $t('dataprotector.audit.userhook'), value: 'userhook', icon: 'mdi:vector-polyline', tagType: 'error' },
  { label: $t('dataprotector.audit.dlp'), value: 'dlp', icon: 'mdi:clipboard-lock-outline', tagType: 'warning' },
  { label: $t('dataprotector.audit.remoteOps'), value: 'remote', icon: 'mdi:remote-desktop', tagType: 'info' },
  { label: $t('dataprotector.audit.agentSync'), value: 'agent', icon: 'mdi:desktop-classic', tagType: 'success' },
  { label: $t('dataprotector.audit.system'), value: 'system', icon: 'mdi:cog-outline', tagType: 'default' }
]);

const severityOptions = computed(() => [
  { label: $t('dataprotector.audit.allSeverity'), value: 'all' },
  { label: $t('dataprotector.audit.critical'), value: 'critical' },
  { label: $t('dataprotector.audit.warning'), value: 'warning' },
  { label: $t('dataprotector.audit.info'), value: 'info' },
  { label: $t('dataprotector.audit.operational'), value: 'operational' }
]);

const dispositionOptions = computed(() => [
  { label: $t('dataprotector.audit.allDisposition'), value: 'all' },
  { label: $t('dataprotector.common.blocked'), value: 'blocked' },
  { label: $t('dataprotector.audit.observed'), value: 'observed' },
  { label: $t('dataprotector.common.completed'), value: 'completed' },
  { label: $t('dataprotector.common.failed'), value: 'failed' }
]);

const categoryMap = computed(() => new Map(categoryOptions.value.map(item => [item.value, item])));
const categorySelectOptions = computed(() => categoryOptions.value.map(item => ({ label: item.label, value: item.value })));

const events = computed(() => auditResponse.value?.items ?? []);
const totalCount = computed(() => auditResponse.value?.total ?? 0);
const criticalCount = computed(() => auditResponse.value?.criticalTotal ?? 0);
const warningCount = computed(() => auditResponse.value?.warningTotal ?? 0);
const blockedCount = computed(() => auditResponse.value?.blockedTotal ?? 0);
const attackFlowEvents = computed(() => attackFlow.value?.events ?? []);
const attackFlowStages = computed(() => attackFlow.value?.stages ?? []);
const detailTimelineEvents = computed<AuditTimelineItem[]>(() => {
  const items = compactTimelineEvents(attackFlowEvents.value.map(normalizeAttackFlowEvent));
  if (items.length) return items.slice(0, 18);

  return selectedAuditRecord.value ? [normalizeAuditRecordEvent(selectedAuditRecord.value)] : [];
});
const attackStoryEvents = computed(() => detailTimelineEvents.value);
const auditDetailGraph = computed(() => buildAuditDetailGraph());
const selectedDetailEvent = computed(
  () => attackStoryEvents.value.find(item => item.id === selectedDetailEventId.value) || attackStoryEvents.value[0] || null
);

const categorySummaries = computed<AuditSummary[]>(() =>
  categoryOptions.value.filter(item => item.value !== 'all').map(item => {
    const summary = auditResponse.value?.categorySummaries?.find(one => one.category === item.value);

    return {
      category: item.value,
      label: item.label,
      count: summary?.count ?? 0,
      critical: summary?.critical ?? 0
    };
  })
);

const onlineHostnames = computed(() =>
  Array.from(
    new Set(
      devices.value
        .filter(device => device.online && device.machine)
        .map(device => device.machine.trim())
        .filter(Boolean)
    )
  ).sort((a, b) => a.localeCompare(b))
);

const hostOptions = computed(() => {
  return [{ label: $t('dataprotector.audit.allOnlineAgents'), value: 'all' }, ...onlineHostnames.value.map(host => ({ label: host, value: host }))];
});

const hostSummaries = computed<HostSummary[]>(() => {
  const onlineHosts = new Set(onlineHostnames.value.map(host => host.toLowerCase()));
  const summaries = auditResponse.value?.hostSummaries ?? [];
  if (onlineHosts.size === 0) return summaries.slice(0, 12);

  return summaries
    .filter(item => onlineHosts.has(item.host.toLowerCase()))
    .slice(0, 12);
});

const trendBuckets = computed(() => auditResponse.value?.trendBuckets ?? []);

const categoryChartData = computed(() =>
  categorySummaries.value
    .filter(item => item.count > 0)
    .map(item => ({
      name: item.label,
      value: item.count
    }))
);

const hostRiskChartData = computed(() =>
  hostSummaries.value.map(item => ({
    name: item.host,
    critical: item.critical,
    warning: item.warning,
    blocked: item.blocked,
    total: item.total
  }))
);

const { domRef: trendChartRef, updateOptions: updateTrendChart } = useEcharts(() => ({
  color: ['#d03050', '#f0a020', '#2080f0'],
  tooltip: { trigger: 'axis' },
  legend: { top: 0, data: [$t('dataprotector.audit.critical'), $t('dataprotector.audit.warning'), $t('dataprotector.audit.total')] },
  grid: { left: 36, right: 18, top: 44, bottom: 28 },
  xAxis: { type: 'category', boundaryGap: false, data: [] as string[] },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    { name: $t('dataprotector.audit.critical'), type: 'line', smooth: true, data: [] as number[] },
    { name: $t('dataprotector.audit.warning'), type: 'line', smooth: true, data: [] as number[] },
    { name: $t('dataprotector.audit.total'), type: 'line', smooth: true, data: [] as number[] }
  ]
}));

const { domRef: categoryChartRef, updateOptions: updateCategoryChart } = useEcharts(() => ({
  color: ['#2080f0', '#18a058', '#f0a020', '#d03050', '#8a63d2', '#00a2ae', '#909399'],
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, left: 'center' },
  series: [
    {
      name: $t('dataprotector.audit.eventType'),
      type: 'pie',
      radius: ['46%', '72%'],
      avoidLabelOverlap: true,
      label: { formatter: '{b}: {c}' },
      data: [] as { name: string; value: number }[]
    }
  ]
}));

const { domRef: hostRiskChartRef, updateOptions: updateHostRiskChart } = useEcharts(() => ({
  color: ['#d03050', '#f0a020', '#7c3aed'],
  tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
  legend: { top: 0, data: [$t('dataprotector.audit.critical'), $t('dataprotector.audit.warning'), $t('dataprotector.common.blocked')] },
  grid: { left: 90, right: 18, top: 44, bottom: 28 },
  xAxis: { type: 'value', minInterval: 1 },
  yAxis: { type: 'category', data: [] as string[] },
  series: [
    { name: $t('dataprotector.audit.critical'), type: 'bar', stack: 'risk', data: [] as number[] },
    { name: $t('dataprotector.audit.warning'), type: 'bar', stack: 'risk', data: [] as number[] },
    { name: $t('dataprotector.common.blocked'), type: 'bar', stack: 'risk', data: [] as number[] }
  ]
}));

const hostColumns = computed<DataTableColumns<HostSummary>>(() => [
  { title: $t('dataprotector.audit.columns.host'), key: 'host', minWidth: 180, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.audit.columns.events'), key: 'total', width: 90, sorter: (a, b) => a.total - b.total },
  {
    title: $t('dataprotector.audit.critical'),
    key: 'critical',
    width: 100,
    sorter: (a, b) => a.critical - b.critical,
    render(row) {
      return h(NTag, { type: row.critical ? 'error' : 'default', bordered: false }, { default: () => row.critical });
    }
  },
  {
    title: $t('dataprotector.audit.warning'),
    key: 'warning',
    width: 100,
    sorter: (a, b) => a.warning - b.warning,
    render(row) {
      return h(NTag, { type: row.warning ? 'warning' : 'default', bordered: false }, { default: () => row.warning });
    }
  },
  {
    title: $t('dataprotector.common.blocked'),
    key: 'blocked',
    width: 100,
    sorter: (a, b) => a.blocked - b.blocked,
    render(row) {
      return h(NTag, { type: row.blocked ? 'error' : 'default', bordered: false }, { default: () => row.blocked });
    }
  }
]);

const columns = computed<DataTableColumns<Api.DataProtector.AuditRecord>>(() => [
  {
    title: $t('dataprotector.audit.columns.time'),
    key: 'TimestampUtc',
    width: 190,
    render(row) {
      return row.TimestampUtc ? new Date(row.TimestampUtc).toLocaleString() : '-';
    }
  },
  {
    title: $t('dataprotector.audit.columns.type'),
    key: 'category',
    width: 150,
    render(row) {
      const option = categoryMap.value.get(classifyAudit(row)) || categoryMap.value.get('system')!;

      return h(
        NTag,
        { type: option.tagType, bordered: false },
        {
          default: () => option.label,
          icon: () => h(resolveSvgIcon(option.icon))
        }
      );
    }
  },
  {
    title: $t('dataprotector.audit.columns.host'),
    key: 'Host',
    width: 160,
    ellipsis: { tooltip: true },
    render(row) {
      return resolveHost(row) || '-';
    }
  },
  {
    title: $t('dataprotector.audit.severity'),
    key: 'severity',
    width: 120,
    render(row) {
      const severity = resolveSeverity(row);
      return h(
        NTag,
        { type: severityTagType(severity), bordered: false },
        { default: () => severityLabel(severity) }
      );
    }
  },
  {
    title: $t('dataprotector.audit.disposition'),
    key: 'disposition',
    width: 130,
    render(row) {
      const disposition = resolveDisposition(row);
      return h(
        NTag,
        { type: dispositionTagType(disposition), bordered: false },
        { default: () => dispositionLabel(disposition) }
      );
    }
  },
  {
    title: $t('dataprotector.audit.columns.source'),
    key: 'SourceProcess',
    minWidth: 300,
    render(row) {
      const source = resolveSourceInfo(row);
      return h('div', { class: 'audit-cell-stack' }, [
        h('div', { class: 'audit-cell-strong' }, source.primary || '-'),
        h('div', { class: 'audit-cell-muted' }, source.secondary || '-')
      ]);
    }
  },
  {
    title: $t('dataprotector.audit.columns.object'),
    key: 'ObjectName',
    minWidth: 320,
    render(row) {
      const target = resolveTargetInfo(row);
      return h('div', { class: 'audit-cell-stack' }, [
        h('div', { class: 'audit-cell-strong' }, target.primary || '-'),
        h('div', { class: 'audit-cell-muted' }, target.secondary || '-')
      ]);
    }
  },
  { title: $t('dataprotector.audit.columns.action'), key: 'Action', width: 220, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.audit.columns.status'), key: 'Status', width: 130 },
  { title: $t('dataprotector.audit.columns.message'), key: 'Message', minWidth: 320, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.common.action'),
    key: 'actions',
    width: 190,
    fixed: 'right',
    render(row) {
      return h('div', { class: 'audit-row-actions' }, [
        h(
          NButton,
          { size: 'small', type: 'primary', secondary: true, onClick: () => openAuditDetail(row) },
          { default: () => $t('dataprotector.audit.viewDetail') }
        ),
        h(
          NButton,
          { size: 'small', type: 'error', secondary: true, onClick: () => removeAuditEvent(row) },
          { default: () => $t('dataprotector.common.delete') }
        )
      ]);
    }
  }
]);

function resolveSvgIcon(icon: string) {
  return () => h('span', { class: 'inline-flex text-16px' }, [h('i', { class: 'iconify', 'data-icon': icon })]);
}

function classifyAudit(record: Api.DataProtector.AuditRecord): AuditCategory {
  const action = record.Action || '';

  if (action.startsWith('webshell.') || action.includes('.webshell.') || action.endsWith('.webshell')) return 'webshell';
  if (action.startsWith('hashdump.') || action.startsWith('hashprotect.') || action.includes('.hashdump.')) {
    return 'hashdump';
  }
  if (action.startsWith('lateral.') || action.startsWith('policy.lateral') || action.startsWith('central.policy.lateral') || action.includes('.lateral.')) {
    return 'lateral';
  }
  if (
    action.startsWith('userhook.') ||
    action.startsWith('behavior.chain.') ||
    action.startsWith('policy.userhook') ||
    action.startsWith('central.policy.userhook') ||
    action.includes('.userhook.')
  ) {
    return 'userhook';
  }
  if (action.startsWith('dlp.') || action.startsWith('policy.dlp') || action.startsWith('central.policy.dlp') || action.includes('.dlp.')) {
    return 'dlp';
  }
  if (action.startsWith('network.smtp') || action.endsWith('.smtp')) return 'smtp';
  if (action.includes('.network.') || action.startsWith('policy.network') || action.startsWith('central.policy.network')) {
    return 'network';
  }
  if (action.startsWith('remote.')) return 'remote';
  if (action.startsWith('agent.')) return 'agent';
  if (action.startsWith('policy.') || action.startsWith('central.policy.')) return 'policy';

  return 'system';
}

function resolveHost(record: Api.DataProtector.AuditRecord) {
  return record.Host || record.Actor || '';
}

function resolveSourceInfo(record: Api.DataProtector.AuditRecord) {
  const fields = parseMessageFields(record.Message);
  const process = firstText(record.SourceProcess, fields.process, fields.source, record.Extension);
  const pid = firstText(record.SourcePid, fields.pid, fields.sourcePid);
  const user = firstText(record.SourceUser, record.Actor);
  const host = firstText(record.SourceHost, record.Host);
  const primary = process || user || host || '-';
  const secondary = [pid ? `PID ${pid}` : '', user, host].filter(Boolean).join(' / ');
  return { primary, secondary };
}

function resolveTargetInfo(record: Api.DataProtector.AuditRecord) {
  const fields = parseMessageFields(record.Message);
  const objectType = firstText(record.ObjectType, inferObjectType(record, fields));
  const objectName = firstText(record.ObjectName, record.TargetProcess, record.Target, fields.object);
  const objectFormat = firstText(record.ObjectFormat, fields.formats);
  const targetPid = firstText(record.TargetPid, fields.targetPid);
  const windowTitle = fields.window;
  const primary = [objectType, objectName].filter(Boolean).join(' / ') || '-';
  const secondary = [objectFormat, targetPid ? `PID ${targetPid}` : '', windowTitle].filter(Boolean).join(' / ');
  return { primary, secondary };
}

function normalizeAttackFlowEvent(event: Api.DataProtector.AuditAttackFlowEvent): AuditTimelineItem {
  return {
    id: event.id || `${event.timeUtc}-${event.action}-${event.objectName}`,
    timeUtc: event.timeUtc || '',
    stage: event.stage || '',
    category: event.category || '',
    action: event.action || '',
    title: conciseEventTitle(firstText(event.title, event.action, event.objectName, event.remoteIdentity), event.stage),
    detail: conciseEventDetail(firstText(event.detail, event.rawMessage)),
    severity: event.severity || 'info',
    disposition: event.disposition || 'observed',
    source: firstText(event.sourceProcess, event.sourcePid, event.sourceUser, event.host),
    target: firstText(event.targetProcess, event.targetPid, event.objectName, event.remoteIdentity),
    object: [event.objectType, event.objectName, event.objectFormat].filter(Boolean).join(' / '),
    remote: event.remoteIdentity || '',
    raw: event.rawMessage || ''
  };
}

function normalizeAuditRecordEvent(record: Api.DataProtector.AuditRecord): AuditTimelineItem {
  const source = resolveSourceInfo(record);
  const target = resolveTargetInfo(record);
  const category = classifyAudit(record);
  const stage = inferTimelineStage(record);
  return {
    id: `${record.TimestampUtc}-${record.Action}-${record.Target}`,
    timeUtc: record.TimestampUtc || '',
    stage,
    category,
    action: record.Action || '',
    title: conciseEventTitle(firstText(target.primary, record.Action), stage),
    detail: conciseEventDetail(firstText(record.EventDetails, record.Message, target.secondary)),
    severity: resolveSeverity(record),
    disposition: resolveDisposition(record),
    source: [source.primary, source.secondary].filter(item => item && item !== '-').join(' / '),
    target: [target.primary, target.secondary].filter(item => item && item !== '-').join(' / '),
    object: firstText(record.ObjectName, record.Target),
    remote: firstText(record.TargetHost, record.Target),
    raw: record.Message || ''
  };
}

function compactTimelineEvents(items: AuditTimelineItem[]) {
  const compacted: AuditTimelineItem[] = [];
  const buckets = new Map<string, AuditTimelineItem>();

  for (const item of items) {
    const key = [
      item.stage,
      item.action,
      item.source.toLowerCase(),
      item.target.toLowerCase(),
      item.object.toLowerCase(),
      item.remote.toLowerCase()
    ].join('|');
    const existing = buckets.get(key);
    if (!existing) {
      const clone = { ...item, count: 1, lastTimeUtc: item.timeUtc };
      buckets.set(key, clone);
      compacted.push(clone);
      continue;
    }

    existing.count = (existing.count || 1) + 1;
    existing.lastTimeUtc = item.timeUtc || existing.lastTimeUtc;
    existing.severity = maxTimelineSeverity(existing.severity, item.severity);
  }

  return compacted.sort((a, b) => new Date(a.timeUtc || 0).getTime() - new Date(b.timeUtc || 0).getTime());
}

function conciseEventTitle(value: string, stage: string) {
  const text = (value || '').replace(/\s+/g, ' ').trim();
  if (!text) return stageLabel(stage);
  const withoutStage = text.replace(/^(Delivery \/ Landing|Execution|Behavior|Credential Access|Lateral Movement|Network \/ C2|Persistence|Impact \/ Data|Risk Behavior):\s*/i, '');
  return withoutStage.length > 120 ? `${withoutStage.slice(0, 117)}...` : withoutStage;
}

function conciseEventDetail(value: string) {
  const text = (value || '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  const parts = text
    .split(/\s+\/\s+|;\s*/)
    .map(item => item.trim())
    .filter(Boolean);
  const unique = Array.from(new Set(parts));
  const compact = unique.slice(0, 5).join(' / ');
  return compact.length > 260 ? `${compact.slice(0, 257)}...` : compact;
}

function maxTimelineSeverity(left?: string, right?: string) {
  return timelineSeverityRank(right) > timelineSeverityRank(left) ? right || left || 'info' : left || right || 'info';
}

function timelineSeverityRank(value?: string) {
  if (value === 'critical' || value === 'high') return 4;
  if (value === 'warning' || value === 'medium') return 3;
  if (value === 'info' || value === 'low') return 2;
  return 1;
}

function inferTimelineStage(record: Api.DataProtector.AuditRecord) {
  const action = record.Action || '';
  const objectType = record.ObjectType || '';
  const message = record.Message || '';
  if (action.startsWith('webshell.') || objectType.includes('file')) return 'delivery';
  if (action.includes('process-create')) return 'execution';
  if (action.startsWith('hashdump.') || objectType.includes('credential')) return 'credential';
  if (action.startsWith('lateral.')) return 'lateral';
  if (action.startsWith('network.')) return 'network';
  if (action.startsWith('dlp.')) return 'impact';
  if (/registry|scheduled|service/i.test(message)) return 'persistence';
  return 'behavior';
}

function buildDetailQuery(record: Api.DataProtector.AuditRecord): Api.DataProtector.AuditQuery {
  const parsedCenter = record.TimestampUtc ? new Date(record.TimestampUtc).getTime() : Number.NaN;
  const center = Number.isFinite(parsedCenter) ? parsedCenter : Date.now();
  const from = new Date(center - 15 * 60 * 1000).toISOString();
  const to = new Date(center + 15 * 60 * 1000).toISOString();
  const source = resolveSourceInfo(record);
  const target = resolveTargetInfo(record);
  const search = firstText(record.SourcePid, record.SourceProcess, record.TargetPid, record.TargetProcess, source.primary, target.primary, record.Action);

  return {
    page: 1,
    pageSize: 80,
    limit: 80,
    category: 'all',
    host: resolveHost(record) || 'all',
    severity: 'all',
    disposition: 'all',
    fromUtc: from,
    toUtc: to,
    search
  };
}

async function openAuditDetail(record: Api.DataProtector.AuditRecord) {
  attackDetailFlow?.destroy();
  attackDetailFlow = null;
  selectedAuditRecord.value = record;
  selectedDetailEventId.value = '';
  auditDetailVisible.value = true;
  attackFlow.value = null;
  auditDetailLoading.value = true;
  try {
    const { error, data } = await fetchAuditAttackFlow(buildDetailQuery(record));
    if (!error) attackFlow.value = data;
  } finally {
    auditDetailLoading.value = false;
    if (!selectedDetailEventId.value && attackStoryEvents.value[0]) selectedDetailEventId.value = attackStoryEvents.value[0].id;
    renderAttackFlows();
  }
}

function parseMessageFields(message?: string) {
  const fields: Record<string, string> = {};
  const text = message || '';
  for (const part of text.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key && value && !fields[key]) fields[key] = value;
  }
  const labeled = [
    ['Process: ', 'process'],
    ['Parent: ', 'parentProcess'],
    ['Command: ', 'commandLine'],
    ['TargetPID: ', 'targetPid'],
    ['Severity=', 'severity'],
    ['disposition=', 'disposition'],
    ['score=', 'score'],
    ['events=', 'events']
  ] as const;
  for (const [prefix, key] of labeled) {
    if (fields[key]) continue;
    const index = text.toLowerCase().indexOf(prefix.toLowerCase());
    if (index < 0) continue;
    const start = index + prefix.length;
    const semicolonEnd = text.indexOf(';', start);
    const fieldEnd = findLabeledFieldEnd(text, start);
    const candidates = [fieldEnd, semicolonEnd].filter(item => item >= 0);
    const end = candidates.length ? Math.min(...candidates) : -1;
    fields[key] = (end < 0 ? text.slice(start) : text.slice(start, end)).trim();
  }
  if (!fields.pid) {
    const match = /\bPID\s+(\d+)/i.exec(text);
    if (match) fields.pid = match[1];
  }
  return fields;
}

function findLabeledFieldEnd(text: string, start: number) {
  for (let index = start; index < text.length; index += 1) {
    const current = text[index];
    if (current === ';') return index;
    if (current !== '.') continue;

    const next = text[index + 1] || '';
    const previous = text[index - 1] || '';
    const nextIsSeparator = !next || /\s/.test(next);
    const previousIsPathOrExtension = /[a-z0-9]/i.test(previous) && /[a-z0-9]/i.test(next);
    if (nextIsSeparator && !previousIsPathOrExtension) return index;
  }

  return -1;
}

function inferObjectType(record: Api.DataProtector.AuditRecord, fields: Record<string, string>) {
  const action = record.Action || '';
  const channel = fields.channel || '';
  if (action.startsWith('dlp.') || channel) {
    if (action.includes('screenshot') || channel.includes('image')) return 'screenshot';
    if (action.includes('clipboard') || channel.includes('clipboard')) return 'clipboard';
    return fields.object || channel || 'dlp';
  }
  if (action.startsWith('webshell.')) return 'file';
  if (action.startsWith('hashdump.')) return 'credential';
  if (action.startsWith('lateral.')) return 'lateral-target';
  if (action.startsWith('network.smtp')) return 'smtp';
  if (action.startsWith('userhook.') || action.startsWith('behavior.chain.')) return 'process-behavior';
  return '';
}

function firstText(...values: Array<string | undefined>) {
  return values.find(value => value && value.trim())?.trim() || '';
}

function resolveSeverity(record: Api.DataProtector.AuditRecord): Exclude<AuditSeverity, 'all'> {
  if (record.Severity && ['critical', 'warning', 'info', 'operational'].includes(record.Severity)) {
    return record.Severity as Exclude<AuditSeverity, 'all'>;
  }

  const action = record.Action || '';
  const message = record.Message || '';
  const status = record.Status || '';

  if (
    action.startsWith('webshell.danger') ||
    action.startsWith('hashdump.blocked') ||
    action.startsWith('lateral.blocked') ||
    action.startsWith('userhook.blocked') ||
    action.startsWith('behavior.chain.') ||
    action.startsWith('dlp.clipboard.blocked') ||
    action.startsWith('dlp.screenshot.blocked') ||
    action.includes('.blocked') ||
    status.toUpperCase() === '0XC0000022'
  ) {
    return 'critical';
  }

  if (action.startsWith('webshell.warning') || action.startsWith('security.audit.drain.failed') || action.includes('.failed') || /failed/i.test(message)) {
    return 'warning';
  }

  if (
    action.startsWith('userhook.runtime.unhook-detected') ||
    action.startsWith('userhook.runtime.hook-overwrite-detected') ||
    action.startsWith('userhook.runtime.syscall-bypass-risk') ||
    action.startsWith('userhook.runtime.memory-manual-map') ||
    action.startsWith('userhook.runtime.memory-rwx') ||
    action.startsWith('userhook.runtime.memory-private-syscall-stub')
  ) {
    return 'warning';
  }

  if (action.startsWith('webshell.notice') || action.startsWith('network.smtp') || action.startsWith('userhook.')) {
    return 'info';
  }

  return 'operational';
}

function resolveDisposition(record: Api.DataProtector.AuditRecord): Exclude<AuditDisposition, 'all'> {
  if (record.Disposition && ['blocked', 'observed', 'completed', 'failed'].includes(record.Disposition)) {
    return record.Disposition as Exclude<AuditDisposition, 'all'>;
  }

  const action = record.Action || '';
  const message = record.Message || '';
  const status = record.Status || '';

  if (status.toUpperCase() === '0XC0000022' || /blocked|denied/i.test(message)) return 'blocked';
  if (!record.Succeeded) return 'failed';
  if (
    action.startsWith('webshell.') ||
    action.startsWith('hashdump.') ||
    action.startsWith('lateral.') ||
    action.startsWith('userhook.') ||
    action.startsWith('behavior.chain.') ||
    action.startsWith('dlp.') ||
    action.startsWith('network.smtp')
  )
    return 'observed';

  return 'completed';
}

function severityLabel(severity: Exclude<AuditSeverity, 'all'>) {
  const labels = {
    critical: $t('dataprotector.audit.critical'),
    warning: $t('dataprotector.audit.warning'),
    info: $t('dataprotector.audit.info'),
    operational: $t('dataprotector.audit.operational')
  };

  return labels[severity];
}

function dispositionLabel(disposition: Exclude<AuditDisposition, 'all'>) {
  const labels = {
    blocked: $t('dataprotector.common.blocked'),
    observed: $t('dataprotector.audit.observed'),
    completed: $t('dataprotector.common.completed'),
    failed: $t('dataprotector.common.failed')
  };

  return labels[disposition];
}

function timelineDispositionLabel(value?: string) {
  if (value === 'blocked' || value === 'observed' || value === 'completed' || value === 'failed') {
    return dispositionLabel(value);
  }

  return value || '-';
}

function severityTagType(severity: Exclude<AuditSeverity, 'all'>) {
  if (severity === 'critical') return 'error';
  if (severity === 'warning') return 'warning';
  if (severity === 'info') return 'info';
  return 'default';
}

function dispositionTagType(disposition: Exclude<AuditDisposition, 'all'>) {
  if (disposition === 'blocked') return 'error';
  if (disposition === 'failed') return 'warning';
  if (disposition === 'observed') return 'info';
  return 'success';
}

function stageLabel(stage: string) {
  const labels: Record<string, string> = {
    delivery: $t('dataprotector.audit.attackFlow.stages.delivery'),
    execution: $t('dataprotector.audit.attackFlow.stages.execution'),
    behavior: $t('dataprotector.audit.attackFlow.stages.behavior'),
    credential: $t('dataprotector.audit.attackFlow.stages.credential'),
    lateral: $t('dataprotector.audit.attackFlow.stages.lateral'),
    network: $t('dataprotector.audit.attackFlow.stages.network'),
    persistence: $t('dataprotector.audit.attackFlow.stages.persistence'),
    impact: $t('dataprotector.audit.attackFlow.stages.impact')
  };

  return labels[stage] || stage || '-';
}

function attackSeverityTagType(value?: string) {
  if (value === 'critical' || value === 'high') return 'error';
  if (value === 'warning' || value === 'medium') return 'warning';
  if (value === 'info') return 'info';
  return 'default';
}

function attackSeverityLabel(value?: string) {
  if (value === 'critical' || value === 'high') return $t('dataprotector.audit.critical');
  if (value === 'warning' || value === 'medium') return $t('dataprotector.audit.warning');
  if (value === 'info') return $t('dataprotector.audit.info');
  return $t('dataprotector.audit.operational');
}

function formatAttackTime(value?: string) {
  return value ? new Date(value).toLocaleString() : '-';
}

function formatTimelineTime(value?: string) {
  if (!value) return '-';
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function graphSeverityColor(severity?: string) {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    warning: '#f59e0b',
    medium: '#f59e0b',
    info: '#64748b',
    operational: '#94a3b8'
  };
  return colors[severity || 'info'] || colors.info;
}

function graphNodeFill(severity?: string, active = true) {
  if (!active) return '#e5e7eb';
  return graphSeverityColor(severity);
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

function buildStoryFlowData(): FlowGraphData {
  return auditDetailGraph.value.flow;
}

function buildAuditDetailGraph(): AuditGraph {
  const events = attackStoryEvents.value.slice(0, 24);
  const nodes: NonNullable<FlowGraphData['nodes']> = [];
  const edges: NonNullable<FlowGraphData['edges']> = [];
  const miniPoints: AuditGraphPoint[] = [];
  const mainX = 168;
  const topY = 62;
  const rowGap = 76;

  if (!events.length) {
    const emptyId = 'audit-detail-empty';
    nodes.push({
      id: emptyId,
      type: 'rect',
      x: mainX,
      y: topY,
      text: {
        x: mainX,
        y: topY,
        value: '-',
        ...graphTextStyle(28, 14, '#64748b', 12)
      },
      properties: {
        width: 52,
        height: 52,
        radius: 6,
        style: { fill: '#ffffff', stroke: '#cbd5e1', strokeWidth: 1 }
      }
    });
    miniPoints.push({ id: emptyId, x: 50, y: 50, severity: 'info' });
    return { flow: { nodes, edges }, miniPoints, height: 360 };
  }

  const startId = 'audit-detail-start';
  nodes.push({
    id: startId,
    type: 'rect',
    x: mainX,
    y: topY,
    text: {
      x: mainX,
      y: topY,
      value: 'START',
      ...graphTextStyle(58, 14, '#334155', 11)
    },
    properties: {
      width: 74,
      height: 34,
      radius: 4,
      style: { fill: '#ffffff', stroke: '#94a3b8', strokeWidth: 1.4 },
      textStyle: { fontWeight: 700 }
    }
  });

  let previousId = startId;
  events.forEach((event, index) => {
    const y = topY + (index + 1) * rowGap;
    const nodeId = `audit-event-${event.id || index}`;
    const active = event.severity !== 'info' && event.severity !== 'operational';

    nodes.push({
      id: `audit-event-time-${index}`,
      type: 'text',
      x: mainX - 72,
      y,
      text: {
        x: mainX - 72,
        y,
        value: formatTimelineTime(event.timeUtc),
        ...graphTextStyle(62, 12, '#94a3b8', 10)
      },
      properties: {
        textStyle: { textAnchor: 'end' }
      }
    });

    nodes.push({
      id: nodeId,
      type: 'circle',
      x: mainX,
      y,
      text: {
        x: mainX,
        y,
        value: String(index + 1),
        ...graphTextStyle(24, 13, '#ffffff', 10)
      },
      properties: {
        r: active ? 15 : 12,
        style: {
          fill: graphNodeFill(event.severity, true),
          stroke: '#ffffff',
          strokeWidth: 2.5,
          filter: active ? 'drop-shadow(0 5px 14px rgba(15, 23, 42, 0.22))' : undefined
        },
        textStyle: {
          fontWeight: 800
        }
      }
    });

    edges.push(createGraphEdge(`audit-event-edge-${index}`, previousId, nodeId, active ? '#94a3b8' : '#cbd5e1', false));
    previousId = nodeId;
  });

  const graphHeight = Math.max(360, topY + (events.length + 1) * rowGap + 54);
  nodes.unshift({
    id: 'audit-detail-axis',
    type: 'rect',
    x: mainX,
    y: graphHeight / 2,
    text: '',
    properties: {
      width: 2,
      height: graphHeight - 96,
      style: { fill: '#dbe4ee', stroke: '#dbe4ee', strokeWidth: 0 }
    }
  });

  events.forEach((event, index) => {
    const y = topY + (index + 1) * rowGap;
    miniPoints.push({
      id: event.id,
      x: 50,
      y: Math.min(94, Math.max(8, (y / graphHeight) * 100)),
      severity: event.severity
    });
  });

  return { flow: { nodes, edges }, miniPoints, height: graphHeight };
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
    const id = String(data?.id || '').replace(/^audit-event-/, '');
    if (id && attackStoryEvents.value.some(item => item.id === id)) {
      selectedDetailEventId.value = id;
    }
  });

  return lf;
}

function renderLogicFlow(lf: LogicFlow, data: FlowGraphData) {
  lf.render(data);
  nextTick(() => {
    window.setTimeout(() => {
      lf.resetZoom();
      lf.translateCenter();
    }, 0);
  });
}

function renderAttackFlows() {
  nextTick(() => {
    if (attackDetailFlowRef.value) {
      attackDetailFlow ??= createLogicFlow(attackDetailFlowRef.value);
      renderLogicFlow(attackDetailFlow, buildStoryFlowData());
      if (!selectedDetailEventId.value && attackStoryEvents.value[0]) selectedDetailEventId.value = attackStoryEvents.value[0].id;
    }
  });
}

function zoomAuditDetailFlow(zoomIn: boolean) {
  attackDetailFlow?.zoom(zoomIn);
}

function updateCharts() {
  updateTrendChart(opts => {
    const critical = $t('dataprotector.audit.critical');
    const warning = $t('dataprotector.audit.warning');
    const total = $t('dataprotector.audit.total');
    opts.legend.data = [critical, warning, total];
    opts.xAxis.data = trendBuckets.value.map(item => item.label);
    opts.series[0].name = critical;
    opts.series[0].data = trendBuckets.value.map(item => item.critical);
    opts.series[1].name = warning;
    opts.series[1].data = trendBuckets.value.map(item => item.warning);
    opts.series[2].name = total;
    opts.series[2].data = trendBuckets.value.map(item => item.total);
    return opts;
  });

  updateCategoryChart(opts => {
    opts.series[0].name = $t('dataprotector.audit.eventType');
    opts.series[0].data = categoryChartData.value.length ? categoryChartData.value : [{ name: $t('dataprotector.audit.noEvents'), value: 0 }];
    return opts;
  });

  updateHostRiskChart(opts => {
    const critical = $t('dataprotector.audit.critical');
    const warning = $t('dataprotector.audit.warning');
    const blocked = $t('dataprotector.common.blocked');
    const items = [...hostRiskChartData.value].reverse();
    opts.legend.data = [critical, warning, blocked];
    opts.yAxis.data = items.map(item => item.name);
    opts.series[0].name = critical;
    opts.series[0].data = items.map(item => item.critical);
    opts.series[1].name = warning;
    opts.series[1].data = items.map(item => item.warning);
    opts.series[2].name = blocked;
    opts.series[2].data = items.map(item => item.blocked);
    return opts;
  });
}

function buildQuery(): Api.DataProtector.AuditQuery {
  const query: Api.DataProtector.AuditQuery = {
    page: pagination.page,
    pageSize: pagination.pageSize,
    limit: pagination.pageSize,
    category: activeCategory.value,
    host: filters.host,
    severity: filters.severity,
    disposition: filters.disposition,
    search: filters.search.trim()
  };

  if (timeRange.value) {
    query.fromUtc = new Date(timeRange.value[0]).toISOString();
    query.toUtc = new Date(timeRange.value[1]).toISOString();
  }

  return query;
}

async function refresh(resetPage = false) {
  if (resetPage) {
    pagination.page = 1;
  }

  loading.value = true;
  try {
    const query = buildQuery();
    const [auditResult, deviceResult] = await Promise.all([fetchAuditEvents(query), fetchDevices()]);
    if (!auditResult.error) {
      auditResponse.value = auditResult.data;
      suppressPaginationRefresh = true;
      pagination.itemCount = auditResult.data.total;
      pagination.page = auditResult.data.page;
      pagination.pageSize = auditResult.data.pageSize;
      suppressPaginationRefresh = false;
    }
    if (!deviceResult.error) devices.value = deviceResult.data;
  } finally {
    loading.value = false;
  }
}

function resetFilters() {
  activeCategory.value = 'all';
  filters.host = 'all';
  filters.severity = 'all';
  filters.disposition = 'all';
  filters.search = '';
  timeRange.value = null;
  refresh(true);
}

function applyFilters() {
  refresh(true);
}

function setActiveCategory(value: string | number) {
  const category = String(value) as AuditCategory;
  if (activeCategory.value === category) return;

  activeCategory.value = category;
  applyFilters();
}

async function clearAuditEvents() {
  window.$dialog?.warning({
    title: $t('dataprotector.audit.clearTitle'),
    content: $t('dataprotector.audit.clearContent'),
    positiveText: $t('dataprotector.common.clear'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchClearAuditEvents();
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.audit.clearSuccess'));
        await refresh(true);
      }
    }
  });
}

async function removeAuditEvent(record: Api.DataProtector.AuditRecord) {
  window.$dialog?.warning({
    title: $t('dataprotector.audit.deleteTitle'),
    content: $t('dataprotector.audit.deleteContent', { action: record.Action || '-', target: record.Target || '-' }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveAuditEvent({
        TimestampUtc: record.TimestampUtc,
        Action: record.Action,
        Target: record.Target,
        Status: record.Status,
        Message: record.Message,
        Actor: 'web-admin'
      });
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.audit.deleteSuccess'));
        await refresh(false);
      }
    }
  });
}

watch([auditResponse, () => appStore.locale], updateCharts, { deep: true });
watch([attackFlow, selectedAuditRecord, () => appStore.locale], renderAttackFlows, { deep: true });

onMounted(() => {
  refresh();
});

onBeforeUnmount(() => {
  attackDetailFlow?.destroy();
  attackDetailFlow = null;
});
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-16px">
        <div>
          <h1 class="m-0 text-24px font-700">{{ $t('dataprotector.audit.title') }}</h1>
        </div>
        <NSpace align="center">
          <NButton secondary @click="resetFilters">{{ $t('dataprotector.common.reset') }}</NButton>
          <NButton type="error" secondary @click="clearAuditEvents">
            <template #icon><SvgIcon icon="mdi:delete-sweep-outline" /></template>
            {{ $t('dataprotector.common.clear') }}
          </NButton>
          <NButton type="primary" :loading="loading" @click="refresh(false)">
            <template #icon><SvgIcon icon="mdi:refresh" /></template>
            {{ $t('dataprotector.common.refresh') }}
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NCard :bordered="false" class="card-wrapper">
      <NGrid :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
        <NGi span="24 m:6">
          <NFormItem :label="$t('dataprotector.audit.eventType')" :show-feedback="false">
            <NSelect :value="activeCategory" :options="categorySelectOptions" @update:value="setActiveCategory" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:6">
          <NFormItem :label="$t('dataprotector.audit.host')" :show-feedback="false">
            <NSelect v-model:value="filters.host" :options="hostOptions" filterable />
          </NFormItem>
        </NGi>
        <NGi span="24 m:5">
          <NFormItem :label="$t('dataprotector.audit.severity')" :show-feedback="false">
            <NSelect v-model:value="filters.severity" :options="severityOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:7">
          <NFormItem :label="$t('dataprotector.audit.disposition')" :show-feedback="false">
            <NSelect v-model:value="filters.disposition" :options="dispositionOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:12">
          <NFormItem :label="$t('dataprotector.audit.timeRange')" :show-feedback="false">
            <NDatePicker v-model:value="timeRange" type="datetimerange" clearable class="w-full" />
          </NFormItem>
        </NGi>
        <NGi span="24">
          <NInputGroup>
            <NInput
              v-model:value="filters.search"
              clearable
              :placeholder="$t('dataprotector.audit.searchPlaceholder')"
              @keyup.enter="applyFilters"
            />
            <NButton type="primary" ghost @click="applyFilters">
              <template #icon><SvgIcon icon="mdi:magnify" /></template>
              {{ $t('dataprotector.common.search') }}
            </NButton>
          </NInputGroup>
        </NGi>
      </NGrid>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.audit.loadedEvents')" :value="totalCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.audit.criticalEvents')" :value="criticalCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.audit.warningEvents')" :value="warningCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.audit.blockedActions')" :value="blockedCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 l:12">
        <NCard :title="$t('dataprotector.audit.securityTrend')" :bordered="false" class="card-wrapper">
          <div ref="trendChartRef" class="h-320px overflow-hidden"></div>
        </NCard>
      </NGi>
      <NGi span="24 l:12">
        <NCard :title="$t('dataprotector.audit.eventTypeDistribution')" :bordered="false" class="card-wrapper">
          <div ref="categoryChartRef" class="h-320px overflow-hidden"></div>
        </NCard>
      </NGi>
    </NGrid>

    <NCard :title="$t('dataprotector.audit.hostAnalytics')" :bordered="false" class="card-wrapper">
      <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
        <NGi span="24 l:13">
          <div ref="hostRiskChartRef" class="h-300px overflow-hidden"></div>
        </NGi>
        <NGi span="24 l:11">
          <NDataTable
            :columns="hostColumns"
            :data="hostSummaries"
            :pagination="false"
            :bordered="false"
            :max-height="300"
          />
        </NGi>
      </NGrid>
    </NCard>

    <NCard :title="$t('dataprotector.audit.eventClassification')" :bordered="false" class="card-wrapper">
      <NGrid :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
        <NGi v-for="item in categorySummaries" :key="item.category" span="24 s:12 m:8 l:6">
          <div
            class="cursor-pointer rounded-8px border border-gray-200 px-14px py-12px transition hover:border-primary"
            :class="{ 'border-primary bg-primary/8': activeCategory === item.category }"
            @click="setActiveCategory(item.category)"
          >
            <div class="flex items-center justify-between">
              <span class="font-600">{{ item.label }}</span>
              <NTag v-if="item.critical" type="error" size="small" :bordered="false">
                {{ $t('dataprotector.audit.criticalCount', { count: item.critical }) }}
              </NTag>
            </div>
            <div class="m-t-8px text-24px font-700">{{ item.count }}</div>
          </div>
        </NGi>
      </NGrid>
    </NCard>

    <NCard :title="$t('dataprotector.audit.auditEvents')" :bordered="false" class="card-wrapper">
      <NSpace vertical :size="12">
        <NTabs :value="activeCategory" type="line" animated @update:value="setActiveCategory">
          <NTabPane
            v-for="item in categoryOptions"
            :key="item.value"
            :name="item.value"
            :tab="`${item.label} ${item.value === 'all' ? totalCount : categorySummaries.find(one => one.category === item.value)?.count || 0}`"
          />
        </NTabs>
        <NDataTable
          :columns="columns"
          :data="events"
          :loading="loading"
          :pagination="pagination"
          :scroll-x="1920"
          remote
        />
      </NSpace>
    </NCard>

    <NModal
      v-model:show="auditDetailVisible"
      preset="card"
      class="audit-detail-modal"
      :title="$t('dataprotector.audit.detail.title')"
      :auto-focus="false"
    >
      <template v-if="selectedAuditRecord">
        <NSpin :show="auditDetailLoading">
          <div class="detail-investigation-panel">
            <div class="attack-flow-header">
              <div>
                <div class="eyebrow">{{ $t('dataprotector.audit.detail.eventOverview') }}</div>
                <h3>{{ selectedAuditRecord.Action || '-' }}</h3>
                <p>{{ attackFlow?.summary || selectedAuditRecord.Message || selectedAuditRecord.EventDetails || '-' }}</p>
              </div>
              <NSpace>
                <NTag :type="severityTagType(resolveSeverity(selectedAuditRecord))" :bordered="false">
                  {{ severityLabel(resolveSeverity(selectedAuditRecord)) }}
                </NTag>
                <NTag :type="dispositionTagType(resolveDisposition(selectedAuditRecord))" :bordered="false">
                  {{ dispositionLabel(resolveDisposition(selectedAuditRecord)) }}
                </NTag>
              </NSpace>
            </div>

            <div class="story-stage-summary">
              <NTag
                v-for="stage in attackFlowStages"
                :key="stage.key"
                size="small"
                :type="stage.active ? attackSeverityTagType(stage.severity) : 'default'"
                :bordered="false"
              >
                {{ stageLabel(stage.key) }} {{ stage.count || 0 }}
              </NTag>
              <NTag v-if="!attackFlowStages.length" size="small" :bordered="false">
                {{ stageLabel(inferTimelineStage(selectedAuditRecord)) }} 1
              </NTag>
            </div>

            <div class="attack-investigation-layout">
              <div class="attack-graph-shell">
                <div
                  ref="attackDetailFlowRef"
                  class="logic-flow-panel attack-graph-canvas"
                  :style="{ height: `${auditDetailGraph.height}px` }"
                ></div>
                <div class="attack-graph-tools">
                  <NButton quaternary circle size="small" @click="renderAttackFlows">
                    <template #icon><SvgIcon icon="mdi:fit-to-page-outline" /></template>
                  </NButton>
                  <NButton quaternary circle size="small" @click="zoomAuditDetailFlow(true)">
                    <template #icon><SvgIcon icon="mdi:magnify-plus-outline" /></template>
                  </NButton>
                  <NButton quaternary circle size="small" @click="zoomAuditDetailFlow(false)">
                    <template #icon><SvgIcon icon="mdi:magnify-minus-outline" /></template>
                  </NButton>
                </div>
                <div class="attack-mini-map">
                  <div class="mini-map-title">{{ $t('dataprotector.audit.detail.navigation') }}</div>
                  <div class="mini-map-body">
                    <button
                      v-for="point in auditDetailGraph.miniPoints"
                      :key="point.id"
                      type="button"
                      class="mini-map-point"
                      :class="{ active: selectedDetailEventId === point.id }"
                      :style="{ left: `${point.x}%`, top: `${point.y}%`, background: graphSeverityColor(point.severity) }"
                      @click="selectedDetailEventId = point.id"
                    />
                  </div>
                </div>
              </div>

              <div class="attack-event-timeline">
                <div class="timeline-list-header">
                  <div>
                    <strong>{{ $t('dataprotector.audit.attackFlow.timeline') }}</strong>
                    <span>{{ $t('dataprotector.audit.detail.timelineCaption') }}</span>
                  </div>
                  <NTag :bordered="false">{{ $t('dataprotector.audit.attackFlow.events', { count: attackStoryEvents.length }) }}</NTag>
                </div>
                <div v-if="attackStoryEvents.length" class="timeline-event-list">
                  <button
                    v-for="(event, index) in attackStoryEvents"
                    :key="event.id || index"
                    type="button"
                    class="timeline-event-card"
                    :class="{ active: selectedDetailEventId === event.id }"
                    @click="selectedDetailEventId = event.id"
                  >
                    <span class="event-step" :style="{ background: graphSeverityColor(event.severity) }">
                      {{ index + 1 }}
                    </span>
                    <span class="event-content">
                      <span class="event-card-top">
                        <span class="event-time">{{ formatAttackTime(event.timeUtc) }}</span>
                        <NTag size="small" :type="attackSeverityTagType(event.severity)" :bordered="false">
                          {{ attackSeverityLabel(event.severity) }}
                        </NTag>
                        <NTag v-if="event.count && event.count > 1" size="small" :bordered="false">
                          x{{ event.count }}
                        </NTag>
                      </span>
                      <strong>{{ event.title || event.action || '-' }}</strong>
                      <small>{{ stageLabel(event.stage) }}</small>
                      <span class="event-target">{{ event.detail || event.raw || event.target || '-' }}</span>
                      <span class="event-meta">
                        <span>{{ $t('dataprotector.audit.columns.source') }} {{ event.source || '-' }}</span>
                        <span>{{ $t('dataprotector.audit.columns.object') }} {{ event.target || event.object || '-' }}</span>
                      </span>
                    </span>
                  </button>
                </div>
                <NEmpty v-else :description="$t('dataprotector.audit.attackFlow.empty')" />
              </div>

              <aside class="attack-detail-panel">
                <template v-if="selectedDetailEvent">
                  <div class="detail-back">
                    <SvgIcon icon="mdi:chevron-left" />
                    <span>{{ $t('dataprotector.audit.detail.selectedEvidence') }}</span>
                  </div>
                  <div class="detail-title-row">
                    <h4>{{ selectedDetailEvent.title || selectedDetailEvent.action || '-' }}</h4>
                    <NTag :type="attackSeverityTagType(selectedDetailEvent.severity)" :bordered="false">
                      {{ attackSeverityLabel(selectedDetailEvent.severity) }}
                    </NTag>
                  </div>
                  <div class="detail-subtitle">
                    {{ stageLabel(selectedDetailEvent.stage) }} / {{ timelineDispositionLabel(selectedDetailEvent.disposition) }}
                  </div>
                  <p class="detail-description">{{ selectedDetailEvent.detail || selectedDetailEvent.raw || '-' }}</p>
                  <div class="detail-tabs">
                    <span class="active">{{ $t('dataprotector.audit.detail.processTab') }}</span>
                    <span>{{ $t('dataprotector.audit.detail.objectTab') }}</span>
                    <span>{{ $t('dataprotector.audit.detail.policyTab') }}</span>
                  </div>
                  <div class="detail-fields">
                    <div>
                      <span>{{ $t('dataprotector.audit.columns.time') }}</span>
                      <strong>{{ formatAttackTime(selectedDetailEvent.timeUtc) }}</strong>
                    </div>
                    <div>
                      <span>{{ $t('dataprotector.audit.columns.action') }}</span>
                      <strong>{{ selectedDetailEvent.action || '-' }}</strong>
                    </div>
                    <div>
                      <span>{{ $t('dataprotector.audit.columns.source') }}</span>
                      <strong>{{ selectedDetailEvent.source || '-' }}</strong>
                    </div>
                    <div>
                      <span>{{ $t('dataprotector.audit.columns.object') }}</span>
                      <strong>{{ selectedDetailEvent.target || selectedDetailEvent.object || '-' }}</strong>
                    </div>
                    <div>
                      <span>{{ $t('dataprotector.audit.detail.remote') }}</span>
                      <strong>{{ selectedDetailEvent.remote || '-' }}</strong>
                    </div>
                    <div>
                      <span>{{ $t('dataprotector.audit.disposition') }}</span>
                      <strong>{{ timelineDispositionLabel(selectedDetailEvent.disposition) }}</strong>
                    </div>
                  </div>
                  <div class="attack-tactics">
                    <div>{{ $t('dataprotector.audit.detail.evidenceInfo') }}</div>
                    <NTag size="small" :bordered="false">{{ stageLabel(selectedDetailEvent.stage) }}</NTag>
                    <NTag size="small" :bordered="false">{{ selectedDetailEvent.category || classifyAudit(selectedAuditRecord) }}</NTag>
                  </div>
                </template>
                <NEmpty v-else :description="$t('dataprotector.audit.detail.singleEventHint')" />
              </aside>
            </div>
          </div>
        </NSpin>
      </template>
    </NModal>
  </NSpace>
</template>

<style scoped>
.audit-cell-stack {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}

.audit-cell-strong,
.audit-cell-muted {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-cell-strong {
  color: var(--n-text-color);
  font-weight: 700;
}

.audit-cell-muted {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.audit-row-actions {
  display: inline-flex;
  gap: 8px;
  align-items: center;
}

.audit-detail-modal {
  width: min(1560px, calc(100vw - 48px));
}

.audit-detail-modal :deep(.n-card__content) {
  padding: 0;
}

.detail-investigation-panel {
  overflow: hidden;
  background: #f4f6f8;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
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
  overflow-wrap: anywhere;
  color: #111827;
  font-size: 17px;
  font-weight: 800;
}

.attack-flow-header p {
  max-width: 880px;
  margin: 4px 0 0;
  color: var(--n-text-color-3);
  font-size: 12px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.eyebrow {
  color: #64748b;
  font-size: 12px;
  font-weight: 700;
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
  grid-template-columns: 330px minmax(420px, 1fr) 360px;
  min-height: 620px;
}

.attack-graph-shell {
  position: relative;
  min-width: 0;
  max-height: 760px;
  min-height: 520px;
  overflow: auto;
  background:
    linear-gradient(90deg, rgb(226 232 240 / 22%) 1px, transparent 1px),
    linear-gradient(rgb(226 232 240 / 22%) 1px, transparent 1px),
    #f8fafc;
  background-size: 36px 36px;
  border-right: 1px solid rgb(226 232 240);
}

.attack-graph-canvas {
  width: 100%;
  min-height: 520px;
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
  width: 148px;
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
  height: 104px;
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
  cursor: pointer;
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

.attack-event-timeline {
  min-width: 0;
  max-height: 760px;
  min-height: 520px;
  overflow: auto;
  background: #ffffff;
  border-right: 1px solid rgb(226 232 240);
}

.timeline-list-header {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
  padding: 16px 18px 12px;
  background: rgb(255 255 255 / 94%);
  border-bottom: 1px solid rgb(226 232 240);
  backdrop-filter: blur(12px);
}

.timeline-list-header strong {
  display: block;
  color: #111827;
  font-size: 15px;
  font-weight: 800;
}

.timeline-list-header span {
  display: block;
  margin-top: 3px;
  color: #64748b;
  font-size: 12px;
  line-height: 1.45;
}

.timeline-event-list {
  display: grid;
  gap: 10px;
  padding: 14px 16px 18px;
}

.timeline-event-card {
  display: grid;
  grid-template-columns: 34px minmax(0, 1fr);
  gap: 12px;
  width: 100%;
  padding: 12px;
  font: inherit;
  text-align: left;
  cursor: pointer;
  background: #f8fafc;
  border: 1px solid rgb(226 232 240);
  border-radius: 8px;
  transition:
    background 0.15s ease,
    border-color 0.15s ease,
    box-shadow 0.15s ease;
}

.timeline-event-card:hover,
.timeline-event-card.active {
  background: #ffffff;
  border-color: #93c5fd;
  box-shadow: 0 10px 26px rgb(15 23 42 / 10%);
}

.event-step {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  color: #ffffff;
  font-size: 12px;
  font-weight: 800;
  border: 2px solid #ffffff;
  border-radius: 999px;
  box-shadow: 0 5px 14px rgb(15 23 42 / 16%);
}

.event-content {
  display: grid;
  min-width: 0;
  gap: 5px;
}

.event-card-top {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

.event-time {
  color: #64748b;
  font-size: 11px;
  font-weight: 700;
}

.event-content strong {
  min-width: 0;
  overflow-wrap: anywhere;
  color: #172033;
  font-size: 14px;
  font-weight: 800;
  line-height: 1.35;
}

.event-content small {
  color: #2563eb;
  font-size: 12px;
  font-weight: 700;
}

.event-target {
  display: -webkit-box;
  overflow: hidden;
  overflow-wrap: anywhere;
  color: #475569;
  font-size: 12px;
  line-height: 1.5;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
}

.event-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  color: #94a3b8;
  font-size: 11px;
  font-weight: 700;
}

.attack-detail-panel {
  min-width: 0;
  max-height: 760px;
  min-height: 520px;
  padding: 18px 22px;
  overflow: auto;
  background: #ffffff;
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

@media (max-width: 1100px) {
  .audit-detail-modal {
    width: calc(100vw - 24px);
  }

  .attack-flow-header {
    flex-direction: column;
  }

  .attack-investigation-layout {
    grid-template-columns: 1fr;
  }

  .attack-graph-shell,
  .attack-event-timeline,
  .attack-detail-panel {
    max-height: none;
    min-height: 360px;
    border-right: 0;
  }

  .attack-detail-panel {
    border-top: 1px solid rgb(226 232 240);
  }
}
</style>
