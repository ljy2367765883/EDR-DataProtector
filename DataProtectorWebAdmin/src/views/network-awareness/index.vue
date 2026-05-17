<script setup lang="tsx">
import { computed, h, onMounted, reactive, ref, watch } from 'vue';
import type { DataTableColumns } from 'naive-ui';
import { NButton, NTag, type PaginationProps, useMessage } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import { fetchClearIpInfoConfig, fetchDevices, fetchIpInfoConfig, fetchNetworkInsights, fetchSaveIpInfoConfig } from '@/service/api';
import { $t } from '@/locales';

const message = useMessage();
const loading = ref(false);
const savingIpInfo = ref(false);
const response = ref<Api.DataProtector.NetworkInsightResponse | null>(null);
const devices = ref<Api.DataProtector.Device[]>([]);
const ipInfoConfig = ref<Api.DataProtector.IpInfoConfiguration | null>(null);
const ipInfoToken = ref('');
let suppressPaginationRefresh = false;

const query = reactive<Api.DataProtector.NetworkInsightQuery>({
  baselineHours: 24,
  windowHours: 24 * 31,
  eventType: 'all',
  host: 'all',
  page: 1,
  pageSize: 30,
  limit: 30,
  search: '',
  includePrivateRemotes: false
});

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 30,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [15, 30, 50, 100],
  prefix: page => $t('datatable.itemCount', { total: page.itemCount }),
  onUpdatePage(page) {
    pagination.page = page;
    query.page = page;
    if (!suppressPaginationRefresh) refresh(false);
  },
  onUpdatePageSize(pageSize) {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    query.pageSize = pageSize;
    query.limit = pageSize;
    query.page = 1;
    if (!suppressPaginationRefresh) refresh(false);
  }
});

const baselineOptions = computed(() => [
  { label: $t('dataprotector.networkAwareness.baselines.hours5'), value: 5 },
  { label: $t('dataprotector.networkAwareness.baselines.day1'), value: 24 },
  { label: $t('dataprotector.networkAwareness.baselines.days3'), value: 72 },
  { label: $t('dataprotector.networkAwareness.baselines.days7'), value: 168 },
  { label: $t('dataprotector.networkAwareness.baselines.month1'), value: 24 * 31 }
]);

const eventTypeOptions = computed(() => [
  { label: $t('dataprotector.networkAwareness.eventTypes.all'), value: 'all' },
  { label: $t('dataprotector.networkAwareness.eventTypes.connection'), value: 'connection' },
  { label: $t('dataprotector.networkAwareness.eventTypes.dns'), value: 'dns' },
  { label: $t('dataprotector.networkAwareness.eventTypes.quic'), value: 'quic' },
  { label: $t('dataprotector.networkAwareness.eventTypes.http3'), value: 'http3' },
  { label: $t('dataprotector.networkAwareness.eventTypes.blocked'), value: 'blocked' }
]);

const hostOptions = computed(() => [
  { label: $t('dataprotector.networkAwareness.allHosts'), value: 'all' },
  ...devices.value.map(device => ({
    label: `${device.machine || device.deviceId}${device.online ? ` ${$t('dataprotector.common.online')}` : ''}`,
    value: device.machine || device.deviceId
  }))
]);

const items = computed(() => response.value?.items ?? []);

const stats = computed(() => {
  return {
    total: response.value?.total ?? 0,
    fresh: response.value?.newTotal ?? 0,
    http3: response.value?.http3Total ?? 0,
    unsigned: response.value?.unsignedTotal ?? 0
  };
});

const trendRows = computed(() => response.value?.trendBuckets ?? []);

const protocolRows = computed(() => {
  return (response.value?.eventDistribution ?? [])
    .map(item => ({ name: eventTypeLabel(item.name), value: item.value }))
    .filter(item => item.value > 0);
});

const trendChartLabels = computed(() => ({
  observed: $t('dataprotector.networkAwareness.charts.observed'),
  new: $t('dataprotector.networkAwareness.charts.new'),
  quic: $t('dataprotector.networkAwareness.charts.quic')
}));

const { domRef: trendChartRef, updateOptions: updateTrendChart } = useEcharts(() => ({
  color: ['#2080f0', '#d03050', '#18a058'],
  tooltip: { trigger: 'axis' },
  legend: { top: 0, data: [$t('dataprotector.networkAwareness.charts.observed'), $t('dataprotector.networkAwareness.charts.new'), $t('dataprotector.networkAwareness.charts.quic')] },
  grid: { left: 40, right: 18, top: 44, bottom: 28 },
  xAxis: { type: 'category', boundaryGap: false, data: [] as string[] },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    { name: $t('dataprotector.networkAwareness.charts.observed'), type: 'line', smooth: true, data: [] as number[] },
    { name: $t('dataprotector.networkAwareness.charts.new'), type: 'line', smooth: true, data: [] as number[] },
    { name: $t('dataprotector.networkAwareness.charts.quic'), type: 'line', smooth: true, data: [] as number[] }
  ]
}));

const { domRef: protocolChartRef, updateOptions: updateProtocolChart } = useEcharts(() => ({
  color: ['#2080f0', '#f0a020', '#18a058', '#8a63d2', '#d03050'],
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, left: 'center' },
  series: [
    {
      name: $t('dataprotector.networkAwareness.charts.eventType'),
      type: 'pie',
      radius: ['48%', '72%'],
      label: { formatter: '{b}: {c}' },
      data: [] as { name: string; value: number }[]
    }
  ]
}));

const columns = computed<DataTableColumns<Api.DataProtector.NetworkInsightItem>>(() => [
  {
    title: $t('dataprotector.networkAwareness.columns.remote'),
    key: 'remoteIdentity',
    width: 280,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.remoteIdentity || row.remoteEndpoint || '-'}</div>
          <div class="cell-muted">{row.remoteEndpoint || row.remoteAddress || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.process'),
    key: 'processPath',
    width: 380,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{fileName(row.processPath)}</div>
          <div class="cell-muted mono">{row.processPath || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.type'),
    key: 'type',
    width: 190,
    render(row) {
      const tags = [];
      if (row.isNew) tags.push(<NTag type="error" bordered={false}>{$t('dataprotector.networkAwareness.charts.new')}</NTag>);
      if (row.isHttp3) tags.push(<NTag type="info" bordered={false}>HTTP/3</NTag>);
      else if (row.isQuic) tags.push(<NTag type="success" bordered={false}>QUIC</NTag>);
      if (row.isDns) tags.push(<NTag type="warning" bordered={false}>DNS</NTag>);
      if (row.blocked) tags.push(<NTag type="error" bordered={false}>{$t('dataprotector.common.blocked')}</NTag>);
      return <div class="tag-row">{tags.length ? tags : <NTag bordered={false}>{$t('dataprotector.networkAwareness.charts.observed')}</NTag>}</div>;
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.ipInfo'),
    key: 'ipInfo',
    width: 280,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{formatIpOwner(row)}</div>
          <div class="cell-muted">{formatIpLocation(row)}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.signature'),
    key: 'signatureStatus',
    width: 240,
    render(row) {
      const type = row.signatureStatus === 'signed' ? 'success' : row.signatureStatus === 'unsigned' ? 'error' : 'default';
      return (
        <div class="cell-stack">
          <NTag type={type} bordered={false}>{row.signatureStatus || $t('dataprotector.networkAwareness.columns.unknown')}</NTag>
          <div class="cell-muted">{row.signer || row.companyName || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.file'),
    key: 'fileDescription',
    width: 300,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.fileDescription || row.productName || '-'}</div>
          <div class="cell-muted">{row.companyName || row.fileVersion || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.hash'),
    key: 'sha256',
    width: 260,
    render(row) {
      return <span class="cell-muted mono">{row.sha256 || '-'}</span>;
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.host'),
    key: 'hosts',
    width: 180,
    render(row) {
      return row.hosts?.join(', ') || '-';
    }
  },
  {
    title: $t('dataprotector.networkAwareness.columns.seen'),
    key: 'lastSeenUtc',
    width: 210,
    render(row) {
      return (
        <div class="cell-stack">
          <div>{formatTime(row.lastSeenUtc)}</div>
          <div class="cell-muted">{$t('dataprotector.networkAwareness.columns.count', { count: row.count })}</div>
        </div>
      );
    }
  }
]);

async function refresh(resetPage = false) {
  if (resetPage) {
    pagination.page = 1;
    query.page = 1;
  }

  query.page = pagination.page;
  query.pageSize = pagination.pageSize;
  query.limit = pagination.pageSize;

  loading.value = true;
  try {
    const [deviceResult, insightResult, ipInfoResult] = await Promise.all([
      fetchDevices(),
      fetchNetworkInsights(query),
      fetchIpInfoConfig()
    ]);

    if (!deviceResult.error) devices.value = deviceResult.data;
    if (!insightResult.error) {
      response.value = insightResult.data;
      suppressPaginationRefresh = true;
      pagination.itemCount = insightResult.data.total;
      pagination.page = insightResult.data.page;
      pagination.pageSize = insightResult.data.pageSize;
      query.page = insightResult.data.page;
      query.pageSize = insightResult.data.pageSize;
      query.limit = insightResult.data.pageSize;
      suppressPaginationRefresh = false;
    }
    if (!ipInfoResult.error) ipInfoConfig.value = ipInfoResult.data;
  } finally {
    loading.value = false;
  }
}

async function saveIpInfoToken() {
  const token = ipInfoToken.value.trim();
  if (!token) {
    message.warning($t('dataprotector.networkAwareness.tokenRequired'));
    return;
  }

  savingIpInfo.value = true;
  try {
    const result = await fetchSaveIpInfoConfig({ token });
    if (!result.error) {
      ipInfoToken.value = '';
      message.success(result.data.message || $t('dataprotector.networkAwareness.tokenSaved'));
      await refresh(false);
    }
  } finally {
    savingIpInfo.value = false;
  }
}

async function clearIpInfoToken() {
  savingIpInfo.value = true;
  try {
    const result = await fetchClearIpInfoConfig();
    if (!result.error) {
      ipInfoToken.value = '';
      message.success(result.data.message || $t('dataprotector.networkAwareness.tokenCleared'));
      await refresh(false);
    }
  } finally {
    savingIpInfo.value = false;
  }
}

function fileName(path: string) {
  if (!path) return '-';
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function formatTime(value: string) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function formatIpOwner(row: Api.DataProtector.NetworkInsightItem) {
  if (row.ipInfoStatus === 'disabled') return $t('dataprotector.networkAwareness.notConfigured');
  if (row.ipInfoStatus === 'pending') return row.ipInfoIp ? `${row.ipInfoIp} ${$t('dataprotector.networkAwareness.pending')}` : $t('dataprotector.networkAwareness.pending');
  if (row.ipInfoStatus === 'error') return row.ipInfoIp ? `${row.ipInfoIp} ${$t('dataprotector.networkAwareness.lookupFailed')}` : $t('dataprotector.networkAwareness.lookupFailed');
  if (row.ipInfoStatus === 'not_applicable') return $t('dataprotector.networkAwareness.privateRemote');

  const owner = row.asName || row.asDomain || row.asn;
  if (!owner) return row.ipInfoIp || '-';

  return row.asn ? `${row.asn} ${owner}` : owner;
}

function formatIpLocation(row: Api.DataProtector.NetworkInsightItem) {
  if (row.ipInfoStatus === 'disabled') return $t('dataprotector.networkAwareness.setTokenHint');
  if (row.ipInfoStatus === 'not_applicable') return row.remoteIdentity || row.remoteEndpoint || '-';

  const parts = [row.country || row.countryCode, row.continent || row.continentCode].filter(Boolean);
  if (parts.length) return parts.join(' / ');
  return row.asDomain || row.ipInfoStatus || '-';
}

function eventTypeLabel(name: string) {
  if (name === 'dns') return $t('dataprotector.networkAwareness.eventTypes.dns');
  if (name === 'quic') return $t('dataprotector.networkAwareness.eventTypes.quic');
  if (name === 'http3') return $t('dataprotector.networkAwareness.eventTypes.http3');
  if (name === 'blocked') return $t('dataprotector.networkAwareness.eventTypes.blocked');
  return $t('dataprotector.networkAwareness.eventTypes.connection');
}

function rowKey(row: Api.DataProtector.NetworkInsightItem) {
  return row.key;
}

watch(
  [trendRows, trendChartLabels],
  ([rows, labels]) => {
    updateTrendChart(opts => {
      opts.legend.data = [labels.observed, labels.new, labels.quic];
      opts.xAxis.data = rows.map(item => item.label);
      opts.series[0].name = labels.observed;
      opts.series[0].data = rows.map(item => item.total);
      opts.series[1].name = labels.new;
      opts.series[1].data = rows.map(item => item.fresh);
      opts.series[2].name = labels.quic;
      opts.series[2].data = rows.map(item => item.quic);
      return opts;
    });
  },
  { immediate: true }
);

watch(
  protocolRows,
  rows => {
    updateProtocolChart(opts => {
      opts.series[0].name = $t('dataprotector.networkAwareness.charts.eventType');
      opts.series[0].data = rows;
      return opts;
    });
  },
  { immediate: true }
);

onMounted(refresh);
</script>

<template>
  <div class="network-awareness">
    <NGrid :cols="4" :x-gap="16" :y-gap="16" responsive="screen">
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.networkAwareness.newConnections')" :value="stats.total" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.networkAwareness.newSinceBaseline')" :value="stats.fresh" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.networkAwareness.http3Candidates')" :value="stats.http3" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.networkAwareness.unsignedProcesses')" :value="stats.unsigned" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 l:16">
        <NCard :title="$t('dataprotector.networkAwareness.connectionTrend')" :bordered="false" class="work-panel">
          <div ref="trendChartRef" class="chart"></div>
        </NCard>
      </NGi>
      <NGi span="24 l:8">
        <NCard :title="$t('dataprotector.networkAwareness.eventDistribution')" :bordered="false" class="work-panel">
          <div ref="protocolChartRef" class="chart"></div>
        </NCard>
      </NGi>
    </NGrid>

    <NCard :title="$t('dataprotector.networkAwareness.ipIntelligence')" :bordered="false" class="work-panel">
      <NSpace align="center" wrap>
        <NTag :type="ipInfoConfig?.enabled ? 'success' : 'warning'" :bordered="false">
          {{
            ipInfoConfig?.enabled
              ? $t('dataprotector.networkAwareness.configuredBy', { source: ipInfoConfig.source })
              : $t('dataprotector.networkAwareness.notConfigured')
          }}
        </NTag>
        <span class="cell-muted mono">{{ ipInfoConfig?.maskedToken || ipInfoConfig?.tokenFilePath || '-' }}</span>
        <NInput
          v-model:value="ipInfoToken"
          type="password"
          show-password-on="click"
          clearable
          :placeholder="$t('dataprotector.networkAwareness.tokenPlaceholder')"
          class="token-control"
          @keyup.enter="saveIpInfoToken"
        />
        <NButton type="primary" :loading="savingIpInfo" @click="saveIpInfoToken">
          {{ $t('dataprotector.networkAwareness.saveToken') }}
        </NButton>
        <NButton secondary :loading="savingIpInfo" @click="clearIpInfoToken">
          {{ $t('dataprotector.networkAwareness.clearToken') }}
        </NButton>
      </NSpace>
    </NCard>

    <NCard :bordered="false" class="work-panel">
      <template #header>
        <div class="panel-title">
          <span>{{ $t('dataprotector.networkAwareness.title') }}</span>
          <NButton type="primary" :loading="loading" @click="refresh(false)">
            {{ $t('dataprotector.common.refresh') }}
          </NButton>
        </div>
      </template>

      <NSpace align="center" wrap class="filters">
        <NSelect v-model:value="query.baselineHours" :options="baselineOptions" class="filter-control" />
        <NSelect v-model:value="query.eventType" :options="eventTypeOptions" class="filter-control" />
        <NSelect v-model:value="query.host" :options="hostOptions" class="filter-control" />
        <NInput
          v-model:value="query.search"
          clearable
          :placeholder="$t('dataprotector.networkAwareness.searchPlaceholder')"
          class="search-control"
          @keyup.enter="refresh(true)"
        />
        <NSwitch v-model:value="query.includePrivateRemotes" />
        <span class="cell-muted">{{ $t('dataprotector.networkAwareness.showLanRemotes') }}</span>
        <NButton secondary @click="refresh(true)">{{ $t('dataprotector.common.apply') }}</NButton>
      </NSpace>

      <NDataTable
        :columns="columns"
        :data="items"
        :loading="loading"
        :row-key="rowKey"
        :pagination="pagination"
        remote
        :scroll-x="2120"
        size="small"
      />
    </NCard>
  </div>
</template>

<style scoped>
.network-awareness {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.metric-card,
.work-panel {
  border-radius: 8px;
}

.chart {
  height: 280px;
}

.panel-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.filters {
  margin-bottom: 16px;
}

.filter-control {
  width: 180px;
}

.search-control {
  width: min(360px, 100%);
}

.token-control {
  width: min(420px, 100%);
}

.cell-stack {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.cell-strong {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color);
  font-weight: 600;
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

.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
