<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { NButton, NTag, type DataTableColumns } from 'naive-ui';
import { fetchAuditEvents } from '@/service/api';

defineOptions({
  name: 'Audit'
});

type AuditCategory = Api.DataProtector.AuditCategory;
type AuditResult = Api.DataProtector.AuditResult;

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
  failed: number;
}

const loading = ref(false);
const events = ref<Api.DataProtector.AuditRecord[]>([]);
const activeCategory = ref<AuditCategory>('all');
const timeRange = ref<[number, number] | null>(null);

const filters = reactive({
  limit: 500,
  host: 'all',
  result: 'all' as AuditResult,
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

const resultOptions = [
  { label: 'All results', value: 'all' },
  { label: 'Success only', value: 'success' },
  { label: 'Failed only', value: 'failed' }
];

const limitOptions = [
  { label: 'Last 200', value: 200 },
  { label: 'Last 500', value: 500 },
  { label: 'Last 1000', value: 1000 }
];

const categoryMap = computed(() => new Map(categoryOptions.map(item => [item.value, item])));
const categorySelectOptions = computed(() => categoryOptions.map(item => ({ label: item.label, value: item.value })));

const successCount = computed(() => events.value.filter(item => item.Succeeded).length);
const failureCount = computed(() => events.value.length - successCount.value);

const categorySummaries = computed<AuditSummary[]>(() =>
  categoryOptions
    .filter(item => item.value !== 'all')
    .map(item => {
      const items = events.value.filter(record => classifyAudit(record) === item.value);

      return {
        category: item.value,
        label: item.label,
        count: items.length,
        failed: items.filter(record => !record.Succeeded).length
      };
    })
);

const visibleEvents = computed(() => {
  if (activeCategory.value === 'all') return events.value;

  return events.value.filter(record => classifyAudit(record) === activeCategory.value);
});

const hostOptions = computed(() => {
  const hosts = Array.from(new Set(events.value.map(record => resolveHost(record)).filter(Boolean))).sort((a, b) =>
    a.localeCompare(b)
  );

  return [{ label: 'All hosts', value: 'all' }, ...hosts.map(host => ({ label: host, value: host }))];
});

const hostSummaries = computed(() => {
  const groups = new Map<string, { host: string; count: number; failed: number }>();

  for (const record of visibleEvents.value) {
    const host = resolveHost(record) || 'Unknown';
    const current = groups.get(host) || { host, count: 0, failed: 0 };
    current.count += 1;
    if (!record.Succeeded) current.failed += 1;
    groups.set(host, current);
  }

  return Array.from(groups.values())
    .sort((left, right) => right.count - left.count || left.host.localeCompare(right.host))
    .slice(0, 8);
});

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
    title: 'Result',
    key: 'Succeeded',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.Succeeded ? 'success' : 'error', bordered: false },
        { default: () => (row.Succeeded ? 'Success' : 'Failed') }
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

function buildQuery(): Api.DataProtector.AuditQuery {
  const query: Api.DataProtector.AuditQuery = {
    limit: filters.limit,
    host: filters.host,
    result: filters.result,
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
    const { error, data } = await fetchAuditEvents(buildQuery());
    if (!error) events.value = data;
  } finally {
    loading.value = false;
  }
}

function resetFilters() {
  activeCategory.value = 'all';
  filters.host = 'all';
  filters.result = 'all';
  filters.search = '';
  timeRange.value = null;
  refresh();
}

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
          <NFormItem label="Result" :show-feedback="false">
            <NSelect v-model:value="filters.result" :options="resultOptions" />
          </NFormItem>
        </NGi>
        <NGi span="24 m:7">
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
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Loaded events" :value="events.length" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Successful" :value="successCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Failed" :value="failureCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 l:14">
        <NCard title="Event Classification" :bordered="false" class="card-wrapper">
          <NGrid :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
            <NGi v-for="item in categorySummaries" :key="item.category" span="24 s:12 m:8">
              <div
                class="cursor-pointer rounded-8px border border-gray-200 px-14px py-12px transition hover:border-primary"
                :class="{ 'border-primary bg-primary/8': activeCategory === item.category }"
                @click="activeCategory = item.category"
              >
                <div class="flex items-center justify-between">
                  <span class="font-600">{{ item.label }}</span>
                  <NTag v-if="item.failed" type="error" size="small" :bordered="false">{{ item.failed }} failed</NTag>
                </div>
                <div class="m-t-8px text-24px font-700">{{ item.count }}</div>
              </div>
            </NGi>
          </NGrid>
        </NCard>
      </NGi>
      <NGi span="24 l:10">
        <NCard title="Host Distribution" :bordered="false" class="card-wrapper">
          <NSpace vertical :size="10">
            <div v-for="item in hostSummaries" :key="item.host" class="flex items-center justify-between gap-12px">
              <div class="min-w-0 flex-1">
                <div class="truncate font-600">{{ item.host }}</div>
                <NProgress
                  type="line"
                  :percentage="events.length ? Math.round((item.count / events.length) * 100) : 0"
                  :show-indicator="false"
                  :height="6"
                />
              </div>
              <NSpace align="center" :size="6">
                <NTag v-if="item.failed" type="error" size="small" :bordered="false">{{ item.failed }}</NTag>
                <span class="w-42px text-right font-600">{{ item.count }}</span>
              </NSpace>
            </div>
            <NEmpty v-if="!hostSummaries.length" description="No host data" />
          </NSpace>
        </NCard>
      </NGi>
    </NGrid>

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
          :scroll-x="1600"
          remote
        />
      </NSpace>
    </NCard>
  </NSpace>
</template>
