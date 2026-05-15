<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { fetchAuditEvents, fetchBridgeStatus, fetchPolicyRules } from '@/service/api';

defineOptions({
  name: 'Home'
});

const loading = ref(false);
const status = ref<Api.DataProtector.BridgeStatus | null>(null);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const audits = ref<Api.DataProtector.AuditRecord[]>([]);

const trustedRuleCount = computed(
  () => rules.value.filter(rule => rule.kind === 'processName' || rule.kind === 'processDirectory').length
);
const excludedRuleCount = computed(() => rules.value.filter(rule => rule.kind === 'excludedDirectory').length);
const extensions = computed(() => Array.from(new Set(rules.value.map(rule => rule.extension))).sort());

async function refresh() {
  loading.value = true;
  try {
    const [statusResult, rulesResult, auditResult] = await Promise.all([
      fetchBridgeStatus(),
      fetchPolicyRules(),
      fetchAuditEvents(5)
    ]);

    if (!statusResult.error) status.value = statusResult.data;
    if (!rulesResult.error) rules.value = rulesResult.data;
    if (!auditResult.error) audits.value = auditResult.data;
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
            Local web console for transparent encryption policy, bridge health, and operator audit visibility.
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
          <NStatistic label="Bridge status" :value="status?.connected ? 'Online' : 'Offline'">
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
          <NStatistic label="Trusted rules" :value="trustedRuleCount">
            <template #prefix>
              <SvgIcon icon="mdi:account-check" />
            </template>
          </NStatistic>
          <div class="m-t-12px text-13px text-gray-500">Process name and process directory rules</div>
        </NCard>
      </NGi>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Excluded directories" :value="excludedRuleCount">
            <template #prefix>
              <SvgIcon icon="mdi:folder-lock-open" />
            </template>
          </NStatistic>
          <div class="m-t-12px text-13px text-gray-500">Extension-scoped bypass locations</div>
        </NCard>
      </NGi>
      <NGi span="24 s:12 m:6">
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="Protected extensions" :value="extensions.length">
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
        <NCard title="Bridge Details" :bordered="false" class="card-wrapper">
          <NDescriptions :column="1" bordered label-placement="left">
            <NDescriptionsItem label="Message">{{ status?.message || 'Bridge not queried yet.' }}</NDescriptionsItem>
            <NDescriptionsItem label="Machine">{{ status?.machine || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="User">{{ status?.user || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="Process ID">{{ status?.bridgePid || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="Audit path">{{ status?.auditPath || '-' }}</NDescriptionsItem>
          </NDescriptions>
        </NCard>
      </NGi>
      <NGi span="24 m:10">
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
      </NGi>
    </NGrid>
  </NSpace>
</template>
