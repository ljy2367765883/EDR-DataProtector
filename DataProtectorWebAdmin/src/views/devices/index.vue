<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue';
import { NTag, type DataTableColumns } from 'naive-ui';
import { fetchDevices } from '@/service/api';

defineOptions({
  name: 'Devices'
});

const loading = ref(false);
const devices = ref<Api.DataProtector.Device[]>([]);

const onlineCount = computed(() => devices.value.filter(item => item.online).length);
const protectedCount = computed(() => devices.value.filter(item => item.driverConnected).length);

const columns: DataTableColumns<Api.DataProtector.Device> = [
  {
    title: 'Agent',
    key: 'machine',
    width: 180,
    render(row) {
      return row.machine || row.deviceId;
    }
  },
  {
    title: 'Online',
    key: 'online',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.online ? 'success' : 'error', bordered: false },
        { default: () => (row.online ? 'Online' : 'Offline') }
      );
    }
  },
  {
    title: 'Driver',
    key: 'driverConnected',
    width: 120,
    render(row) {
      return h(
        NTag,
        { type: row.driverConnected ? 'success' : 'warning', bordered: false },
        { default: () => (row.driverConnected ? row.driverStatus : row.driverStatus || 'offline') }
      );
    }
  },
  { title: 'User', key: 'user', width: 140 },
  { title: 'Policy', key: 'policyVersion', width: 100 },
  {
    title: 'Last Seen',
    key: 'lastSeenUtc',
    width: 200,
    render(row) {
      return row.lastSeenUtc ? new Date(row.lastSeenUtc).toLocaleString() : '-';
    }
  },
  { title: 'Apply Result', key: 'lastApplyMessage', ellipsis: { tooltip: true } },
  { title: 'Device ID', key: 'deviceId', width: 260, ellipsis: { tooltip: true } }
];

async function refresh() {
  loading.value = true;
  try {
    const { error, data } = await fetchDevices();
    if (!error) devices.value = data;
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
          <h1 class="m-0 text-24px font-700">Agent Devices</h1>
          <p class="m-t-8px text-14px text-gray-500">
            Clients actively synchronize with the central server and apply policy to their local driver.
          </p>
        </div>
        <NButton type="primary" :loading="loading" @click="refresh">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
          Refresh
        </NButton>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Registered agents" :value="devices.length" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Online agents" :value="onlineCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Driver connected" :value="protectedCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NCard title="Agent Inventory" :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="devices" :loading="loading" :pagination="{ pageSize: 15 }" />
    </NCard>
  </NSpace>
</template>
