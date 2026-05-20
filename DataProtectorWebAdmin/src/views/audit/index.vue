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

type FlowGraphData = Parameters<LogicFlow['render']>[0];

const loading = ref(false);
const appStore = useAppStore();
const auditResponse = ref<Api.DataProtector.AuditQueryResponse | null>(null);
const attackFlow = ref<Api.DataProtector.AuditAttackFlowResponse | null>(null);
const devices = ref<Api.DataProtector.Device[]>([]);
const activeCategory = ref<AuditCategory>('all');
const timeRange = ref<[number, number] | null>(null);
const attackStageFlowRef = ref<HTMLElement | null>(null);
const attackStoryFlowRef = ref<HTMLElement | null>(null);
let attackStageFlow: LogicFlow | null = null;
let attackStoryFlow: LogicFlow | null = null;

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
const attackFlowIncidents = computed(() => attackFlow.value?.incidents ?? []);
const attackFlowProcesses = computed(() => attackFlow.value?.processes ?? []);
const attackFlowEntities = computed(() => attackFlow.value?.entities ?? []);
const activeAttackStageCount = computed(() => attackFlowStages.value.filter(item => item.active).length);
const attackStoryEvents = computed(() => attackFlowEvents.value.slice(0, 40));

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

const attackIncidentColumns = computed<DataTableColumns<Api.DataProtector.AuditAttackFlowIncident>>(() => [
  {
    title: $t('dataprotector.audit.attackFlow.columns.root'),
    key: 'rootProcess',
    minWidth: 260,
    render(row) {
      return h('div', { class: 'audit-cell-stack' }, [
        h('div', { class: 'audit-cell-strong' }, row.rootProcess || row.host || '-'),
        h('div', { class: 'audit-cell-muted' }, [row.host, row.rootPid ? `PID ${row.rootPid}` : ''].filter(Boolean).join(' / ') || '-')
      ]);
    }
  },
  {
    title: $t('dataprotector.audit.attackFlow.columns.stages'),
    key: 'stages',
    minWidth: 220,
    render(row) {
      return h('div', { class: 'attack-tag-list' }, row.stages.map(stage => h(NTag, { size: 'small', bordered: false }, { default: () => stageLabel(stage) })));
    }
  },
  {
    title: $t('dataprotector.audit.attackFlow.columns.remotes'),
    key: 'remotes',
    minWidth: 220,
    render(row) {
      return row.remotes?.length ? row.remotes.slice(0, 3).join(' / ') : '-';
    }
  },
  { title: $t('dataprotector.audit.attackFlow.columns.events'), key: 'eventCount', width: 90 },
  { title: $t('dataprotector.audit.attackFlow.columns.score'), key: 'score', width: 90 },
  {
    title: $t('dataprotector.audit.severity'),
    key: 'severity',
    width: 110,
    render(row) {
      return h(NTag, { type: attackSeverityTagType(row.severity), bordered: false }, { default: () => attackSeverityLabel(row.severity) });
    }
  }
]);

const attackProcessColumns = computed<DataTableColumns<Api.DataProtector.AuditAttackFlowProcess>>(() => [
  {
    title: $t('dataprotector.audit.attackFlow.columns.process'),
    key: 'path',
    minWidth: 280,
    render(row) {
      return h('div', { class: 'audit-cell-stack' }, [
        h('div', { class: 'audit-cell-strong' }, row.name || row.path || '-'),
        h('div', { class: 'audit-cell-muted' }, row.path || '-')
      ]);
    }
  },
  { title: 'PID', key: 'pid', width: 90 },
  { title: $t('dataprotector.audit.columns.host'), key: 'host', minWidth: 140, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.audit.attackFlow.columns.events'), key: 'eventCount', width: 90 },
  {
    title: $t('dataprotector.audit.severity'),
    key: 'severity',
    width: 110,
    render(row) {
      return h(NTag, { type: attackSeverityTagType(row.severity), bordered: false }, { default: () => attackSeverityLabel(row.severity) });
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
    width: 110,
    fixed: 'right',
    render(row) {
      return h(
        NButton,
        { size: 'small', type: 'error', secondary: true, onClick: () => removeAuditEvent(row) },
        { default: () => $t('dataprotector.common.delete') }
      );
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
    action.startsWith('userhook.runtime.unhook-detected') ||
    action.startsWith('userhook.runtime.hook-overwrite-detected') ||
    action.startsWith('userhook.runtime.syscall-bypass-risk') ||
    action.startsWith('userhook.runtime.memory-manual-map') ||
    action.startsWith('userhook.runtime.memory-rwx') ||
    action.startsWith('userhook.runtime.memory-private-syscall-stub') ||
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

function compactFlowText(value?: string, fallback = '-') {
  const text = (value || fallback).replace(/\s+/g, ' ').trim();
  if (text.length <= 28) return text;
  return `${text.slice(0, 25)}...`;
}

function flowTextStyle() {
  return {
    fontSize: 12,
    textWidth: 132,
    overflowMode: 'ellipsis' as const,
    lineHeight: 16
  };
}

function buildStageFlowData(): FlowGraphData {
  const stages = attackFlowStages.value.length
    ? attackFlowStages.value
    : [
        {
          key: 'empty',
          label: $t('dataprotector.audit.attackFlow.empty'),
          active: false,
          count: 0,
          severity: 'info',
          firstSeenUtc: '',
          lastSeenUtc: '',
          detail: ''
        }
      ];

  const nodes = stages.map((stage, index) => ({
    id: `stage-${stage.key || index}`,
    type: 'rect',
    x: 96 + index * 190,
    y: 76,
    text: {
      x: 96 + index * 190,
      y: 76,
      value: `${stageLabel(stage.key)}\n${stage.count || 0} ${$t('dataprotector.audit.attackFlow.columns.events')}`,
      ...flowTextStyle()
    },
    properties: {
      width: 150,
      height: 64
    }
  }));

  const edges = stages.slice(1).map((stage, index) => ({
    id: `stage-edge-${index}`,
    type: 'polyline',
    sourceNodeId: `stage-${stages[index].key || index}`,
    targetNodeId: `stage-${stage.key || index + 1}`
  }));

  return { nodes, edges };
}

function buildStoryFlowData(): FlowGraphData {
  const events = attackStoryEvents.value;

  if (!events.length) {
    return {
      nodes: [
        {
          id: 'story-empty',
          type: 'rect',
          x: 120,
          y: 90,
          text: {
            x: 120,
            y: 90,
            value: $t('dataprotector.audit.attackFlow.empty'),
            ...flowTextStyle()
          },
          properties: {
            width: 180,
            height: 56
          }
        }
      ],
      edges: []
    };
  }

  const nodes = events.map((event, index) => {
    const row = Math.floor(index / 8);
    const column = index % 8;
    const x = 116 + column * 184;
    const y = 86 + row * 116;
    const title = compactFlowText(event.title || event.action || stageLabel(event.stage));
    const meta = compactFlowText(event.sourceProcess || event.host || event.remoteIdentity || event.objectName || '-', '');

    return {
      id: `story-${event.id || index}`,
      type: 'rect',
      x,
      y,
      text: {
        x,
        y,
        value: `${title}\n${formatAttackTime(event.timeUtc)}${meta ? `\n${meta}` : ''}`,
        ...flowTextStyle(),
        textWidth: 142,
        lineHeight: 15
      },
      properties: {
        width: 158,
        height: 76
      }
    };
  });

  const edges = events.slice(1).map((event, index) => ({
    id: `story-edge-${index}`,
    type: 'polyline',
    sourceNodeId: `story-${events[index].id || index}`,
    targetNodeId: `story-${event.id || index + 1}`
  }));

  return { nodes, edges };
}

function createLogicFlow(container: HTMLElement) {
  const lf = new LogicFlow({
    container,
    grid: false,
    isSilentMode: true,
    stopScrollGraph: true,
    stopZoomGraph: true,
    stopMoveGraph: false,
    adjustEdge: false,
    history: false,
    keyboard: { enabled: false },
    edgeType: 'polyline'
  });

  return lf;
}

function renderLogicFlow(lf: LogicFlow, data: FlowGraphData) {
  lf.render(data);
  nextTick(() => {
    window.setTimeout(() => {
      lf.fitView(24, 24);
      lf.translateCenter();
    }, 0);
  });
}

function renderAttackFlows() {
  nextTick(() => {
    if (attackStageFlowRef.value) {
      attackStageFlow ??= createLogicFlow(attackStageFlowRef.value);
      renderLogicFlow(attackStageFlow, buildStageFlowData());
    }

    if (attackStoryFlowRef.value) {
      attackStoryFlow ??= createLogicFlow(attackStoryFlowRef.value);
      renderLogicFlow(attackStoryFlow, buildStoryFlowData());
    }
  });
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
    const [auditResult, flowResult, deviceResult] = await Promise.all([fetchAuditEvents(query), fetchAuditAttackFlow(query), fetchDevices()]);
    if (!auditResult.error) {
      auditResponse.value = auditResult.data;
      suppressPaginationRefresh = true;
      pagination.itemCount = auditResult.data.total;
      pagination.page = auditResult.data.page;
      pagination.pageSize = auditResult.data.pageSize;
      suppressPaginationRefresh = false;
    }
    if (!flowResult.error) attackFlow.value = flowResult.data;
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
watch([attackFlow, () => appStore.locale], renderAttackFlows, { deep: true });

onMounted(() => {
  renderAttackFlows();
  refresh();
});

onBeforeUnmount(() => {
  attackStageFlow?.destroy();
  attackStoryFlow?.destroy();
  attackStageFlow = null;
  attackStoryFlow = null;
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

    <NCard :bordered="false" class="card-wrapper">
      <template #header>
        <div class="flex flex-wrap items-center justify-between gap-12px">
          <div>
            <div class="text-16px font-700">{{ $t('dataprotector.audit.attackFlow.title') }}</div>
            <div class="m-t-4px text-12px text-gray-500">{{ attackFlow?.summary || $t('dataprotector.audit.attackFlow.empty') }}</div>
          </div>
          <NSpace>
            <NTag type="error" :bordered="false">{{ $t('dataprotector.audit.attackFlow.activeStages', { count: activeAttackStageCount }) }}</NTag>
            <NTag type="info" :bordered="false">{{ $t('dataprotector.audit.attackFlow.events', { count: attackFlow?.eventTotal || 0 }) }}</NTag>
          </NSpace>
        </div>
      </template>

      <NSpace vertical :size="16">
        <div>
          <div class="story-panel-title">{{ $t('dataprotector.audit.attackFlow.stagesTitle') }}</div>
          <div ref="attackStageFlowRef" class="logic-flow-panel logic-flow-stage"></div>
        </div>

        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 l:13">
            <div class="story-panel-title">{{ $t('dataprotector.audit.attackFlow.incidents') }}</div>
            <NDataTable
              :columns="attackIncidentColumns"
              :data="attackFlowIncidents"
              :pagination="{ pageSize: 5 }"
              :bordered="false"
              :scroll-x="980"
            />
          </NGi>
          <NGi span="24 l:11">
            <div class="story-panel-title">{{ $t('dataprotector.audit.attackFlow.processes') }}</div>
            <NDataTable
              :columns="attackProcessColumns"
              :data="attackFlowProcesses"
              :pagination="{ pageSize: 5 }"
              :bordered="false"
              :scroll-x="820"
            />
          </NGi>
        </NGrid>

        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 l:15">
            <div class="story-panel-title">{{ $t('dataprotector.audit.attackFlow.timeline') }}</div>
            <div ref="attackStoryFlowRef" class="logic-flow-panel logic-flow-story"></div>
            <div v-if="attackStoryEvents.length" class="flow-story-caption">
              {{ $t('dataprotector.audit.attackFlow.storyCaption', { count: attackStoryEvents.length }) }}
            </div>
          </NGi>
          <NGi span="24 l:9">
            <div class="story-panel-title">{{ $t('dataprotector.audit.attackFlow.entities') }}</div>
            <div class="attack-entity-list">
              <div v-for="entity in attackFlowEntities" :key="entity.key" class="attack-entity">
                <div>
                  <div class="entity-label">{{ entity.label }}</div>
                  <div class="entity-type">{{ entity.type }}</div>
                </div>
                <NTag size="small" :type="attackSeverityTagType(entity.severity)" :bordered="false">{{ entity.count }}</NTag>
              </div>
              <NEmpty v-if="!attackFlowEntities.length" :description="$t('dataprotector.audit.attackFlow.empty')" />
            </div>
          </NGi>
        </NGrid>
      </NSpace>
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
          :scroll-x="1840"
          remote
        />
      </NSpace>
    </NCard>
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

.story-panel-title,
.entity-label {
  font-weight: 700;
}

.entity-type {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color-3);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.story-panel-title {
  margin-bottom: 10px;
  font-size: 14px;
}

.logic-flow-panel {
  overflow: hidden;
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 8px;
  background: #fff;
}

.logic-flow-stage {
  height: 180px;
}

.logic-flow-story {
  height: 520px;
}

.flow-story-caption {
  margin-top: 8px;
  color: var(--n-text-color-3);
  font-size: 12px;
}

.attack-tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.attack-entity-list {
  display: flex;
  max-height: 520px;
  flex-direction: column;
  gap: 8px;
  overflow: auto;
  padding-right: 4px;
}

.attack-entity {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  border: 1px solid rgba(148, 163, 184, 0.2);
  border-radius: 8px;
  padding: 10px 12px;
  background: rgba(255, 255, 255, 0.48);
}
</style>
