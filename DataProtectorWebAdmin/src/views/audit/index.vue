<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue';
import { NTag, type DataTableColumns } from 'naive-ui';
import { fetchAuditEvents } from '@/service/api';

defineOptions({
  name: 'Audit'
});

const loading = ref(false);
const events = ref<Api.DataProtector.AuditRecord[]>([]);
const limit = ref(200);

const successCount = computed(() => events.value.filter(item => item.Succeeded).length);
const failureCount = computed(() => events.value.length - successCount.value);

const columns: DataTableColumns<Api.DataProtector.AuditRecord> = [
  {
    title: 'Time',
    key: 'TimestampUtc',
    width: 220,
    render(row) {
      return new Date(row.TimestampUtc).toLocaleString();
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
  { title: 'Action', key: 'Action', width: 230 },
  { title: 'Extension', key: 'Extension', width: 120 },
  { title: 'Target', key: 'Target', ellipsis: { tooltip: true } },
  { title: 'Status', key: 'Status', width: 120 },
  { title: 'Message', key: 'Message', ellipsis: { tooltip: true } }
];

async function refresh() {
  loading.value = true;
  try {
    const { error, data } = await fetchAuditEvents(limit.value);
    if (!error) events.value = data;
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-16px">
        <div>
          <h1 class="m-0 text-24px font-700">Audit Trail</h1>
          <p class="m-t-8px text-14px text-gray-500">
            Central audit records for policy changes, agent synchronization, and client-side apply results.
          </p>
        </div>
        <NSpace align="center">
          <NInputNumber v-model:value="limit" :min="1" :max="1000" class="w-120px" />
          <NButton type="primary" :loading="loading" @click="refresh">
            <template #icon><SvgIcon icon="mdi:refresh" /></template>
            Refresh
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Loaded events" :value="events.length" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Successful operations" :value="successCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Failed operations" :value="failureCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NCard title="Events" :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="events" :loading="loading" :pagination="{ pageSize: 15 }" />
    </NCard>
  </NSpace>
</template>
