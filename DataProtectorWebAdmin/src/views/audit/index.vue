<script setup lang="ts">
import { computed, h, onMounted, reactive, ref, watch } from 'vue';
import { NButton, NTag, type DataTableColumns } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import { fetchAuditEvents, fetchDevices } from '@/service/api';

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

const loading = ref(false);
const events = ref<Api.DataProtector.AuditRecord[]>([]);
const devices = ref<Api.DataProtector.Device[]>([]);
const activeCategory = ref<AuditCategory>('all');
const timeRange = ref<[number, number] | null>(null);

const filters = reactive({
  limit: 500,
  host: 'all',
  severity: 'all' as AuditSeverity,
  disposition: 'all' as AuditDisposition,
  search: ''
});

const categoryOptions: CategoryOption[] = [
  { label: 'All events', value: 'all', icon: 'mdi:format-list-bulleted', tagType: 'default' },
  { label: 'Policy', value: 'policy', icon: 'mdi:shield-key-outline', tagType: 'info' },
  { label: 'Network defense', value: 'network', icon: 'mdi:lan-connect', tagType: 'warning' },
  { label: 'SMTP audit', value: 'smtp', icon: 'mdi:email-fast-outline', tagType: 'success' },
  { label: 'WebShell', value: 'webshell', icon: 'mdi:webhook', tagType: 'error' },
  { label: 'Remote ops', value: 'remote', icon: 'mdi:remote-desktop', tagType: 'info' },
  { label: 'Agent sync', value: 'agent', icon: 'mdi:desktop-classic', tagType: 'success' },
  { label: 'System', value: 'system', icon: 'mdi:cog-outline', tagType: 'default' }
];

const severityOptions = [
  { label: 'All severity', value: 'all' },
  { label: 'Critical', value: 'critical' },
  { label: 'Warning', value: 'warning' },
  { label: 'Info', value: 'info' },
  { label: 'Operational', value: 'operational' }
];

const dispositionOptions = [
  { label: 'All disposition', value: 'all' },
  { label: 'Blocked', value: 'blocked' },
  { label: 'Observed', value: 'observed' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' }
];

const limitOptions = [
  { label: 'Last 200', value: 200 },
  { label: 'Last 500', value: 500 },
  { label: 'Last 1000', value: 1000 }
];

const categoryMap = computed(() => new Map(categoryOptions.map(item => [item.value, item])));
const categorySelectOptions = computed(() => categoryOptions.map(item => ({ label: item.label, value: item.value })));

const criticalCount = computed(() => events.value.filter(item => resolveSeverity(item) === 'critical').length);
const warningCount = computed(() => events.value.filter(item => resolveSeverity(item) === 'warning').length);
const blockedCount = computed(() => events.value.filter(item => resolveDisposition(item) === 'blocked').length);

const categorySummaries = computed<AuditSummary[]>(() =>
  categoryOptions
    .filter(item => item.value !== 'all')
    .map(item => {
      const items = events.value.filter(record => classifyAudit(record) === item.value);

      return {
        category: item.value,
        label: item.label,
        count: items.length,
        critical: items.filter(record => resolveSeverity(record) === 'critical').length
      };
    })
);

const visibleEvents = computed(() => {
  if (activeCategory.value === 'all') return events.value;

  return events.value.filter(record => classifyAudit(record) === activeCategory.value);
});

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
  return [{ label: 'All online agents', value: 'all' }, ...onlineHostnames.value.map(host => ({ label: host, value: host }))];
});

const hostSummaries = computed(() => {
  const groups = new Map<string, HostSummary>();
  const onlineHosts = onlineHostnames.value;

  for (const host of onlineHosts) {
    groups.set(host, { host, total: 0, critical: 0, warning: 0, blocked: 0 });
  }

  for (const record of visibleEvents.value) {
    const host = resolveOnlineHost(record, onlineHosts);
    if (!host) continue;

    const current = groups.get(host) || { host, total: 0, critical: 0, warning: 0, blocked: 0 };
    current.total += 1;
    if (resolveSeverity(record) === 'critical') current.critical += 1;
    if (resolveSeverity(record) === 'warning') current.warning += 1;
    if (resolveDisposition(record) === 'blocked') current.blocked += 1;
    groups.set(host, current);
  }

  return Array.from(groups.values())
    .sort(
      (left, right) =>
        right.critical - left.critical || right.warning - left.warning || right.blocked - left.blocked || right.total - left.total || left.host.localeCompare(right.host)
    )
    .slice(0, 12);
});

const trendBuckets = computed(() => buildTrendBuckets(events.value));

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
  legend: { top: 0, data: ['Critical', 'Warning', 'Total'] },
  grid: { left: 36, right: 18, top: 44, bottom: 28 },
  xAxis: { type: 'category', boundaryGap: false, data: [] as string[] },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    { name: 'Critical', type: 'line', smooth: true, data: [] as number[] },
    { name: 'Warning', type: 'line', smooth: true, data: [] as number[] },
    { name: 'Total', type: 'line', smooth: true, data: [] as number[] }
  ]
}));

const { domRef: categoryChartRef, updateOptions: updateCategoryChart } = useEcharts(() => ({
  color: ['#2080f0', '#18a058', '#f0a020', '#d03050', '#8a63d2', '#00a2ae', '#909399'],
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, left: 'center' },
  series: [
    {
      name: 'Event type',
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
  legend: { top: 0, data: ['Critical', 'Warning', 'Blocked'] },
  grid: { left: 90, right: 18, top: 44, bottom: 28 },
  xAxis: { type: 'value', minInterval: 1 },
  yAxis: { type: 'category', data: [] as string[] },
  series: [
    { name: 'Critical', type: 'bar', stack: 'risk', data: [] as number[] },
    { name: 'Warning', type: 'bar', stack: 'risk', data: [] as number[] },
    { name: 'Blocked', type: 'bar', stack: 'risk', data: [] as number[] }
  ]
}));

const hostColumns: DataTableColumns<HostSummary> = [
  { title: 'Host', key: 'host', minWidth: 180, ellipsis: { tooltip: true } },
  { title: 'Events', key: 'total', width: 90, sorter: (a, b) => a.total - b.total },
  {
    title: 'Critical',
    key: 'critical',
    width: 100,
    sorter: (a, b) => a.critical - b.critical,
    render(row) {
      return h(NTag, { type: row.critical ? 'error' : 'default', bordered: false }, { default: () => row.critical });
    }
  },
  {
    title: 'Warning',
    key: 'warning',
    width: 100,
    sorter: (a, b) => a.warning - b.warning,
    render(row) {
      return h(NTag, { type: row.warning ? 'warning' : 'default', bordered: false }, { default: () => row.warning });
    }
  },
  {
    title: 'Blocked',
    key: 'blocked',
    width: 100,
    sorter: (a, b) => a.blocked - b.blocked,
    render(row) {
      return h(NTag, { type: row.blocked ? 'error' : 'default', bordered: false }, { default: () => row.blocked });
    }
  }
];

const columns: DataTableColumns<Api.DataProtector.AuditRecord> = [
  {
    title: 'Time',
    key: 'TimestampUtc',
    width: 190,
    sorter: (a, b) => new Date(a.TimestampUtc).getTime() - new Date(b.TimestampUtc).getTime(),
    render(row) {
      return row.TimestampUtc ? new Date(row.TimestampUtc).toLocaleString() : '-';
    }
  },
  {
    title: 'Type',
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
    title: 'Host',
    key: 'Host',
    width: 160,
    ellipsis: { tooltip: true },
    render(row) {
      return resolveHost(row) || '-';
    }
  },
  {
    title: 'Severity',
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
    title: 'Disposition',
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
  { title: 'Action', key: 'Action', width: 240, ellipsis: { tooltip: true } },
  { title: 'Target', key: 'Target', minWidth: 260, ellipsis: { tooltip: true } },
  { title: 'Status', key: 'Status', width: 130 },
  { title: 'Message', key: 'Message', minWidth: 320, ellipsis: { tooltip: true } }
];

function resolveSvgIcon(icon: string) {
  return () => h('span', { class: 'inline-flex text-16px' }, [h('i', { class: 'iconify', 'data-icon': icon })]);
}

function classifyAudit(record: Api.DataProtector.AuditRecord): AuditCategory {
  const action = record.Action || '';

  if (action.startsWith('webshell.') || action.includes('.webshell.') || action.endsWith('.webshell')) return 'webshell';
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

function resolveOnlineHost(record: Api.DataProtector.AuditRecord, onlineHosts: string[]) {
  const host = (record.Host || '').trim();
  if (!host) return '';

  return onlineHosts.find(item => item.localeCompare(host, undefined, { sensitivity: 'accent' }) === 0) || '';
}

function resolveSeverity(record: Api.DataProtector.AuditRecord): Exclude<AuditSeverity, 'all'> {
  const action = record.Action || '';
  const message = record.Message || '';
  const status = record.Status || '';

  if (action.startsWith('webshell.danger') || action.includes('.blocked') || status.toUpperCase() === '0XC0000022') {
    return 'critical';
  }

  if (action.startsWith('webshell.warning') || action.startsWith('security.audit.drain.failed') || action.includes('.failed') || /failed/i.test(message)) {
    return 'warning';
  }

  if (action.startsWith('webshell.notice') || action.startsWith('network.smtp')) {
    return 'info';
  }

  return 'operational';
}

function resolveDisposition(record: Api.DataProtector.AuditRecord): Exclude<AuditDisposition, 'all'> {
  const action = record.Action || '';
  const message = record.Message || '';
  const status = record.Status || '';

  if (status.toUpperCase() === '0XC0000022' || /blocked|denied/i.test(message)) return 'blocked';
  if (!record.Succeeded) return 'failed';
  if (action.startsWith('webshell.') || action.startsWith('network.smtp')) return 'observed';

  return 'completed';
}

function severityLabel(severity: Exclude<AuditSeverity, 'all'>) {
  const labels = {
    critical: 'Critical',
    warning: 'Warning',
    info: 'Info',
    operational: 'Operational'
  };

  return labels[severity];
}

function dispositionLabel(disposition: Exclude<AuditDisposition, 'all'>) {
  const labels = {
    blocked: 'Blocked',
    observed: 'Observed',
    completed: 'Completed',
    failed: 'Failed'
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

function buildTrendBuckets(records: Api.DataProtector.AuditRecord[]) {
  const sorted = [...records].sort((a, b) => new Date(a.TimestampUtc).getTime() - new Date(b.TimestampUtc).getTime());
  const buckets = new Map<string, { label: string; critical: number; warning: number; total: number }>();

  for (const record of sorted) {
    const date = new Date(record.TimestampUtc);
    if (Number.isNaN(date.getTime())) continue;

    const key = `${date.getMonth() + 1}/${date.getDate()} ${String(date.getHours()).padStart(2, '0')}:00`;
    const bucket = buckets.get(key) || { label: key, critical: 0, warning: 0, total: 0 };
    bucket.total += 1;
    if (resolveSeverity(record) === 'critical') bucket.critical += 1;
    if (resolveSeverity(record) === 'warning') bucket.warning += 1;
    buckets.set(key, bucket);
  }

  return Array.from(buckets.values()).slice(-24);
}

function updateCharts() {
  updateTrendChart(opts => {
    opts.xAxis.data = trendBuckets.value.map(item => item.label);
    opts.series[0].data = trendBuckets.value.map(item => item.critical);
    opts.series[1].data = trendBuckets.value.map(item => item.warning);
    opts.series[2].data = trendBuckets.value.map(item => item.total);
    return opts;
  });

  updateCategoryChart(opts => {
    opts.series[0].data = categoryChartData.value.length ? categoryChartData.value : [{ name: 'No events', value: 0 }];
    return opts;
  });

  updateHostRiskChart(opts => {
    const items = [...hostRiskChartData.value].reverse();
    opts.yAxis.data = items.map(item => item.name);
    opts.series[0].data = items.map(item => item.critical);
    opts.series[1].data = items.map(item => item.warning);
    opts.series[2].data = items.map(item => item.blocked);
    return opts;
  });
}

function buildQuery(): Api.DataProtector.AuditQuery {
  const query: Api.DataProtector.AuditQuery = {
    limit: filters.limit,
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

async function refresh() {
  loading.value = true;
  try {
    const [auditResult, deviceResult] = await Promise.all([fetchAuditEvents(buildQuery()), fetchDevices()]);
    if (!auditResult.error) events.value = auditResult.data;
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
  refresh();
}

watch([events, activeCategory], updateCharts, { deep: true });

onMounted(refresh);
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-16px">
        <div>
          <h1 class="m-0 text-24px font-700">Audit Center</h1>
        </div>
        <NSpace align="center">
          <NSelect v-model:value="filters.limit" :options="limitOptions" class="w-130px" />
          <NButton secondary @click="resetFilters">Reset</NButton>
          <NButton type="primary" :loading="loading" @click="refresh">
            <template #icon><SvgIcon icon="mdi:refresh" /></template>
            Refresh
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NCard :bordered="false" class="card-wrapper">
      <NGrid :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
        <NGi span="24 m:6">
          <NFormItem label="Event type" :show-feedback="false">
            <NSelect v-model:value="activeCategory" :options="categorySelectOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:6">
          <NFormItem label="Host" :show-feedback="false">
            <NSelect v-model:value="filters.host" :options="hostOptions" filterable />
          </NFormItem>
        </NGi>
        <NGi span="24 m:5">
          <NFormItem label="Severity" :show-feedback="false">
            <NSelect v-model:value="filters.severity" :options="severityOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:7">
          <NFormItem label="Disposition" :show-feedback="false">
            <NSelect v-model:value="filters.disposition" :options="dispositionOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:12">
          <NFormItem label="Time range" :show-feedback="false">
            <NDatePicker v-model:value="timeRange" type="datetimerange" clearable class="w-full" />
          </NFormItem>
        </NGi>
        <NGi span="24">
          <NInputGroup>
            <NInput v-model:value="filters.search" clearable placeholder="Search action, host, target, status, or message" @keyup.enter="refresh" />
            <NButton type="primary" ghost @click="refresh">
              <template #icon><SvgIcon icon="mdi:magnify" /></template>
              Search
            </NButton>
          </NInputGroup>
        </NGi>
      </NGrid>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Loaded events" :value="events.length" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Critical events" :value="criticalCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Warning events" :value="warningCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:12 l:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Blocked actions" :value="blockedCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 l:12">
        <NCard title="Security Trend" :bordered="false" class="card-wrapper">
          <div ref="trendChartRef" class="h-320px overflow-hidden"></div>
        </NCard>
      </NGi>
      <NGi span="24 l:12">
        <NCard title="Event Type Distribution" :bordered="false" class="card-wrapper">
          <div ref="categoryChartRef" class="h-320px overflow-hidden"></div>
        </NCard>
      </NGi>
    </NGrid>

    <NCard title="Host Analytics" :bordered="false" class="card-wrapper">
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

    <NCard title="Event Classification" :bordered="false" class="card-wrapper">
      <NGrid :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
        <NGi v-for="item in categorySummaries" :key="item.category" span="24 s:12 m:8 l:6">
          <div
            class="cursor-pointer rounded-8px border border-gray-200 px-14px py-12px transition hover:border-primary"
            :class="{ 'border-primary bg-primary/8': activeCategory === item.category }"
            @click="activeCategory = item.category"
          >
            <div class="flex items-center justify-between">
              <span class="font-600">{{ item.label }}</span>
              <NTag v-if="item.critical" type="error" size="small" :bordered="false">{{ item.critical }} critical</NTag>
            </div>
            <div class="m-t-8px text-24px font-700">{{ item.count }}</div>
          </div>
        </NGi>
      </NGrid>
    </NCard>

    <NCard title="Audit Events" :bordered="false" class="card-wrapper">
      <NSpace vertical :size="12">
        <NTabs v-model:value="activeCategory" type="line" animated>
          <NTabPane
            v-for="item in categoryOptions"
            :key="item.value"
            :name="item.value"
            :tab="`${item.label} ${
              item.value === 'all' ? events.length : categorySummaries.find(one => one.category === item.value)?.count || 0
            }`"
          />
        </NTabs>
        <NDataTable
          :columns="columns"
          :data="visibleEvents"
          :loading="loading"
          :pagination="{ pageSize: 15 }"
          :scroll-x="1720"
          remote
        />
      </NSpace>
    </NCard>
  </NSpace>
</template>
