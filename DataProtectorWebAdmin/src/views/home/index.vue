<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { fetchAuditEvents, fetchBridgeStatus, fetchDevices, fetchPolicyRules } from '@/service/api';

defineOptions({
  name: 'Home'
});

const loading = ref(false);
const status = ref<Api.DataProtector.BridgeStatus | null>(null);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const audits = ref<Api.DataProtector.AuditRecord[]>([]);
const devices = ref<Api.DataProtector.Device[]>([]);

const trustedRuleCount = computed(
  () => rules.value.filter(rule => rule.kind === 'processName' || rule.kind === 'processDirectory').length
);
const excludedRuleCount = computed(() => rules.value.filter(rule => rule.kind === 'excludedDirectory').length);
const extensions = computed(() => Array.from(new Set(rules.value.map(rule => rule.extension))).sort());
const onlineDeviceCount = computed(() => devices.value.filter(device => device.online).length);

async function refresh() {
  loading.value = true;
  try {
    const [statusResult, rulesResult, auditResult, devicesResult] = await Promise.all([
      fetchBridgeStatus(),
      fetchPolicyRules(),
      fetchAuditEvents(5),
      fetchDevices()
    ]);

    if (!statusResult.error) status.value = statusResult.data;
    if (!rulesResult.error) rules.value = rulesResult.data;
    if (!auditResult.error) audits.value = auditResult.data;
    if (!devicesResult.error) devices.value = devicesResult.data;
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-start justify-between gap-16px">
        <div>
          <h1 class="m-0 text-28px font-700">DataProtector Operations</h1>
          <p class="m-t-8px max-w-760px text-14px text-gray-500">
            Central control plane for endpoint policy distribution, agent health, and audit visibility.
          </p>
        </div>
        <NButton type="primary" :loading="loading" @click="refresh">
          <template #icon>
            <SvgIcon icon="mdi:refresh" />
          </template>
          Refresh
        </NButton>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Central server" :value="status?.connected ? 'Online' : 'Offline'">
            <template #prefix>
              <SvgIcon :icon="status?.connected ? 'mdi:lan-connect' : 'mdi:lan-disconnect'" />
            </template>
          </NStatistic>
          <NTag class="m-t-12px" :type="status?.connected ? 'success' : 'error'">
            {{ status?.status || 'unknown' }}
          </NTag>
        </NCard>
      </NGi>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Online agents" :value="status?.onlineDeviceCount ?? onlineDeviceCount">
            <template #prefix>
              <SvgIcon icon="mdi:desktop-classic" />
            </template>
          </NStatistic>
          <div class="m-t-12px text-13px text-gray-500">Registered: {{ status?.deviceCount ?? devices.length }}</div>
        </NCard>
      </NGi>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Trusted rules" :value="trustedRuleCount">
            <template #prefix>
              <SvgIcon icon="mdi:account-check" />
            </template>
          </NStatistic>
          <div class="m-t-12px text-13px text-gray-500">Excluded directories: {{ excludedRuleCount }}</div>
        </NCard>
      </NGi>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Policy version" :value="status?.policyVersion ?? 0">
            <template #prefix>
              <SvgIcon icon="mdi:file-key" />
            </template>
          </NStatistic>
          <div class="m-t-12px flex flex-wrap gap-6px">
            <NTag v-for="item in extensions" :key="item" size="small" type="info">{{ item }}</NTag>
            <span v-if="!extensions.length" class="text-13px text-gray-500">No rules yet</span>
          </div>
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 m:14">
        <NCard title="Central Server Details" :bordered="false" class="card-wrapper">
          <NDescriptions :column="1" bordered label-placement="left">
            <NDescriptionsItem label="Message">{{ status?.message || 'Bridge not queried yet.' }}</NDescriptionsItem>
            <NDescriptionsItem label="Machine">{{ status?.machine || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="User">{{ status?.user || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="Process ID">{{ status?.bridgePid || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="State path">{{ status?.auditPath || '-' }}</NDescriptionsItem>
          </NDescriptions>
        </NCard>
      </NGi>
      <NGi span="24 m:10">
        <NCard title="Agent Health" :bordered="false" class="card-wrapper">
          <NList>
            <NListItem v-for="item in devices.slice(0, 5)" :key="item.deviceId">
              <div class="flex items-center justify-between gap-12px">
                <div class="min-w-0">
                  <div class="truncate text-14px font-600">{{ item.machine || item.deviceId }}</div>
                  <div class="truncate text-12px text-gray-500">{{ item.lastApplyMessage || item.driverMessage }}</div>
                </div>
                <NTag size="small" :type="item.online && item.driverConnected ? 'success' : 'error'">
                  {{ item.online ? item.driverStatus : 'offline' }}
                </NTag>
              </div>
            </NListItem>
            <NEmpty v-if="!devices.length" description="No agents registered" />
          </NList>
        </NCard>
      </NGi>
    </NGrid>

    <NCard title="Recent Audit" :bordered="false" class="card-wrapper">
      <NList>
        <NListItem v-for="item in audits" :key="`${item.TimestampUtc}-${item.Action}-${item.Target}`">
          <div class="flex items-center justify-between gap-12px">
            <div class="min-w-0">
              <div class="truncate text-14px font-600">{{ item.Action }}</div>
              <div class="truncate text-12px text-gray-500">{{ item.Target }} {{ item.Extension }}</div>
            </div>
            <NTag size="small" :type="item.Succeeded ? 'success' : 'error'">{{ item.Status }}</NTag>
          </div>
        </NListItem>
        <NEmpty v-if="!audits.length" description="No audit events" />
      </NList>
    </NCard>
  </NSpace>
</template>
