<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue';
import { NButton, NTag, type DataTableColumns } from 'naive-ui';
import { fetchDevices, fetchRemoveDevice } from '@/service/api';
import { $t } from '@/locales';

defineOptions({
  name: 'Devices'
});

const loading = ref(false);
const devices = ref<Api.DataProtector.Device[]>([]);

const onlineCount = computed(() => devices.value.filter(item => item.online).length);
const protectedCount = computed(() => devices.value.filter(item => item.driverConnected).length);

const columns = computed<DataTableColumns<Api.DataProtector.Device>>(() => [
  {
    title: $t('dataprotector.devices.columns.agent'),
    key: 'machine',
    width: 180,
    render(row) {
      return row.machine || row.deviceId;
    }
  },
  {
    title: $t('dataprotector.devices.columns.online'),
    key: 'online',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.online ? 'success' : 'error', bordered: false },
        { default: () => (row.online ? $t('dataprotector.common.online') : $t('dataprotector.common.offline')) }
      );
    }
  },
  {
    title: $t('dataprotector.devices.columns.driver'),
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
  { title: $t('dataprotector.devices.columns.user'), key: 'user', width: 140 },
  { title: $t('dataprotector.devices.columns.policy'), key: 'policyVersion', width: 100 },
  {
    title: $t('dataprotector.devices.columns.lastSeen'),
    key: 'lastSeenUtc',
    width: 200,
    render(row) {
      return row.lastSeenUtc ? new Date(row.lastSeenUtc).toLocaleString() : '-';
    }
  },
  { title: $t('dataprotector.devices.columns.applyResult'), key: 'lastApplyMessage', ellipsis: { tooltip: true } },
  { title: $t('dataprotector.devices.columns.deviceId'), key: 'deviceId', width: 260, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.common.action'),
    key: 'actions',
    width: 110,
    fixed: 'right',
    render(row) {
      return h(
        NButton,
        { size: 'small', type: 'error', secondary: true, onClick: () => removeDevice(row) },
        { default: () => $t('dataprotector.common.delete') }
      );
    }
  }
]);

async function refresh() {
  loading.value = true;
  try {
    const { error, data } = await fetchDevices();
    if (!error) devices.value = data;
  } finally {
    loading.value = false;
  }
}

async function removeDevice(device: Api.DataProtector.Device) {
  window.$dialog?.warning({
    title: $t('dataprotector.devices.deleteTitle'),
    content: $t('dataprotector.devices.deleteContent', { name: device.machine || device.deviceId }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveDevice({ deviceId: device.deviceId, actor: 'web-admin' });
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.devices.deleteSuccess'));
        await refresh();
      }
    }
  });
}

onMounted(refresh);
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-16px">
        <div>
          <h1 class="m-0 text-24px font-700">{{ $t('dataprotector.devices.title') }}</h1>
          <p class="m-t-8px text-14px text-gray-500">
            {{ $t('dataprotector.devices.subtitle') }}
          </p>
        </div>
        <NButton type="primary" :loading="loading" @click="refresh">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
          {{ $t('dataprotector.common.refresh') }}
        </NButton>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.devices.registeredAgents')" :value="devices.length" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.devices.onlineAgents')" :value="onlineCount" />
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic :label="$t('dataprotector.devices.driverConnected')" :value="protectedCount" />
        </NCard>
      </NGi>
    </NGrid>

    <NCard :title="$t('dataprotector.devices.inventory')" :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="devices" :loading="loading" :pagination="{ pageSize: 15 }" :scroll-x="1540" />
    </NCard>
  </NSpace>
</template>
