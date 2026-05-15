<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { NButton, NTag, type DataTableColumns, type FormInst, type FormRules } from 'naive-ui';
import {
  fetchAddNetworkRule,
  fetchAddPolicyRule,
  fetchBridgeStatus,
  fetchClearNetworkRules,
  fetchClearPolicyRules,
  fetchNetworkRules,
  fetchPolicyRules,
  fetchRemoveNetworkRule,
  fetchRemovePolicyRule
} from '@/service/api';

defineOptions({
  name: 'Policy'
});

const loading = ref(false);
const submitting = ref(false);
const networkSubmitting = ref(false);
const connected = ref(false);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const networkRules = ref<Api.DataProtector.NetworkRule[]>([]);
const formRef = ref<FormInst | null>(null);
const networkFormRef = ref<FormInst | null>(null);

const form = reactive<Api.DataProtector.PolicyRuleRequest>({
  kind: 'processName',
  value: '',
  extension: '.dpf',
  actor: 'web-admin'
});

const networkForm = reactive<Api.DataProtector.NetworkRuleRequest>({
  ruleId: 0,
  kind: 'domain',
  action: 'block',
  protocol: 'any',
  direction: 'outbound',
  localAddress: '',
  localPort: 0,
  remoteAddress: '',
  remotePort: 0,
  domain: '',
  actor: 'web-admin'
});

const formRules: FormRules = {
  kind: { required: true, message: 'Rule kind is required', trigger: 'change' },
  value: { required: true, message: 'Rule value is required', trigger: 'input' },
  extension: { required: true, message: 'Extension is required', trigger: 'input' }
};

const networkFormRules: FormRules = {
  kind: { required: true, message: 'Rule kind is required', trigger: 'change' },
  action: { required: true, message: 'Action is required', trigger: 'change' },
  protocol: { required: true, message: 'Protocol is required', trigger: 'change' },
  direction: { required: true, message: 'Direction is required', trigger: 'change' },
  domain: {
    trigger: 'input',
    validator() {
      if (networkForm.kind !== 'domain') return true;
      return networkForm.domain.trim().length > 0 ? true : new Error('Domain is required');
    }
  },
  remoteAddress: {
    trigger: 'input',
    validator() {
      if (networkForm.kind !== 'ip') return true;
      return networkForm.remoteAddress.trim().length > 0 ? true : new Error('Remote address is required');
    }
  }
};

const kindOptions = [
  { label: 'Process name', value: 'processName' },
  { label: 'Process directory', value: 'processDirectory' },
  { label: 'Excluded directory', value: 'excludedDirectory' }
];

const kindLabel: Record<Api.DataProtector.RuleKind, string> = {
  processName: 'Process name',
  processDirectory: 'Process directory',
  excludedDirectory: 'Excluded directory'
};

const networkKindOptions = [
  { label: 'Domain', value: 'domain' },
  { label: 'IPv4 / CIDR', value: 'ip' }
];

const networkActionOptions = [
  { label: 'Block', value: 'block' },
  { label: 'Allow', value: 'allow' }
];

const networkProtocolOptions = [
  { label: 'Any', value: 'any' },
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' }
];

const networkDirectionOptions = [
  { label: 'Outbound', value: 'outbound' },
  { label: 'Inbound', value: 'inbound' },
  { label: 'Both', value: 'both' }
];

const ruleGroups = computed(() => ({
  processName: rules.value.filter(rule => rule.kind === 'processName').length,
  processDirectory: rules.value.filter(rule => rule.kind === 'processDirectory').length,
  excludedDirectory: rules.value.filter(rule => rule.kind === 'excludedDirectory').length
}));

const networkGroups = computed(() => ({
  domain: networkRules.value.filter(rule => rule.kind === 'domain').length,
  ip: networkRules.value.filter(rule => rule.kind === 'ip').length,
  blocked: networkRules.value.filter(rule => rule.action === 'block').length
}));

const columns: DataTableColumns<Api.DataProtector.PolicyRule> = [
  {
    title: 'Kind',
    key: 'kind',
    width: 180,
    render(row) {
      const type = row.kind === 'excludedDirectory' ? 'warning' : 'info';
      return h(NTag, { type, bordered: false }, { default: () => kindLabel[row.kind] });
    }
  },
  {
    title: 'Extension',
    key: 'extension',
    width: 120,
    render(row) {
      return h(NTag, { type: 'success', bordered: false }, { default: () => row.extension });
    }
  },
  {
    title: 'Value',
    key: 'value',
    ellipsis: { tooltip: true }
  },
  {
    title: 'Action',
    key: 'actions',
    width: 120,
    render(row) {
      return h(
        NButton,
        {
          size: 'small',
          type: 'error',
          secondary: true,
          onClick: () => removeRule(row)
        },
        { default: () => 'Remove' }
      );
    }
  }
];

const networkColumns: DataTableColumns<Api.DataProtector.NetworkRule> = [
  {
    title: 'Action',
    key: 'action',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.action === 'block' ? 'error' : 'success', bordered: false },
        { default: () => row.action.toUpperCase() }
      );
    }
  },
  {
    title: 'Kind',
    key: 'kind',
    width: 120,
    render(row) {
      return h(NTag, { type: row.kind === 'domain' ? 'info' : 'warning', bordered: false }, { default: () => row.kind });
    }
  },
  {
    title: 'Target',
    key: 'displayTarget',
    ellipsis: { tooltip: true },
    render(row) {
      return row.displayTarget || row.domain || row.remoteAddress || '*';
    }
  },
  {
    title: 'Protocol',
    key: 'protocol',
    width: 110,
    render(row) {
      return row.protocol.toUpperCase();
    }
  },
  {
    title: 'Direction',
    key: 'direction',
    width: 120
  },
  {
    title: 'Port',
    key: 'remotePort',
    width: 100,
    render(row) {
      return row.remotePort ? String(row.remotePort) : '*';
    }
  },
  {
    title: 'Rule ID',
    key: 'ruleId',
    width: 130
  },
  {
    title: 'Action',
    key: 'actions',
    width: 120,
    render(row) {
      return h(
        NButton,
        {
          size: 'small',
          type: 'error',
          secondary: true,
          onClick: () => removeNetworkRule(row)
        },
        { default: () => 'Remove' }
      );
    }
  }
];

async function refresh() {
  loading.value = true;
  try {
    const [statusResult, rulesResult, networkRulesResult] = await Promise.all([
      fetchBridgeStatus(),
      fetchPolicyRules(),
      fetchNetworkRules()
    ]);
    connected.value = Boolean(statusResult.data?.connected);
    if (!rulesResult.error) rules.value = rulesResult.data;
    if (!networkRulesResult.error) networkRules.value = networkRulesResult.data;
  } finally {
    loading.value = false;
  }
}

async function addRule() {
  await formRef.value?.validate();
  submitting.value = true;
  try {
    const { error, data } = await fetchAddPolicyRule({ ...form });
    if (!error && data.succeeded) {
      window.$message?.success('Rule added to central policy.');
      form.value = '';
      await refresh();
    }
  } finally {
    submitting.value = false;
  }
}

async function addNetworkRule() {
  await networkFormRef.value?.validate();
  networkSubmitting.value = true;
  try {
    const payload: Api.DataProtector.NetworkRuleRequest = {
      ...networkForm,
      domain: networkForm.kind === 'domain' ? networkForm.domain.trim() : '',
      remoteAddress: networkForm.kind === 'ip' ? networkForm.remoteAddress.trim() : networkForm.remoteAddress.trim(),
      actor: 'web-admin'
    };
    const { error, data } = await fetchAddNetworkRule(payload);
    if (!error && data.succeeded) {
      window.$message?.success('Network rule added to central policy.');
      networkForm.domain = '';
      networkForm.remoteAddress = '';
      await refresh();
    }
  } finally {
    networkSubmitting.value = false;
  }
}

async function removeRule(rule: Api.DataProtector.PolicyRule) {
  const { error, data } = await fetchRemovePolicyRule({ ...rule, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success('Rule removed from central policy.');
    await refresh();
  }
}

async function removeNetworkRule(rule: Api.DataProtector.NetworkRule) {
  const { error, data } = await fetchRemoveNetworkRule({ ruleId: rule.ruleId, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success('Network rule removed from central policy.');
    await refresh();
  }
}

async function clearRules() {
  window.$dialog?.warning({
    title: 'Clear all rules',
    content: 'This removes all trusted process and excluded directory rules from the central policy.',
    positiveText: 'Clear',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      const { error, data } = await fetchClearPolicyRules();
      if (!error && data.succeeded) {
        window.$message?.success('Central policy cleared.');
        await refresh();
      }
    }
  });
}

async function clearNetworkRules() {
  window.$dialog?.warning({
    title: 'Clear network rules',
    content: 'This removes all central network defense rules. Agents will clear local WFP rules on next sync.',
    positiveText: 'Clear',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      const { error, data } = await fetchClearNetworkRules();
      if (!error && data.succeeded) {
        window.$message?.success('Central network policy cleared.');
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
          <h1 class="m-0 text-24px font-700">Policy Management</h1>
          <p class="m-t-8px text-14px text-gray-500">
            Extension-bound central policy distributed to all registered DataProtector agents.
          </p>
        </div>
        <NSpace>
          <NTag :type="connected ? 'success' : 'error'">{{ connected ? 'Central server online' : 'Server offline' }}</NTag>
          <NButton :loading="loading" @click="refresh">
            <template #icon><SvgIcon icon="mdi:refresh" /></template>
            Refresh
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NTabs type="line" animated>
      <NTabPane name="file" tab="File Policy">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard title="Add File Rule" :bordered="false" class="card-wrapper">
              <NForm ref="formRef" :model="form" :rules="formRules" label-placement="top">
                <NFormItem label="Rule kind" path="kind">
                  <NSelect v-model:value="form.kind" :options="kindOptions" />
                </NFormItem>
                <NFormItem label="Extension" path="extension">
                  <NInput v-model:value="form.extension" placeholder=".dpf" />
                </NFormItem>
                <NFormItem label="Rule value" path="value">
                  <NInput
                    v-model:value="form.value"
                    :placeholder="form.kind === 'processName' ? 'notepad.exe' : 'C:\\Program Files\\WPS Office\\'"
                  />
                </NFormItem>
                <NButton block type="primary" :loading="submitting" @click="addRule">
                  <template #icon><SvgIcon icon="mdi:plus" /></template>
                  Add to Central Policy
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard title="Central File Rule Inventory" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">Process: {{ ruleGroups.processName }}</NTag>
                  <NTag type="info">Directory: {{ ruleGroups.processDirectory }}</NTag>
                  <NTag type="warning">Excluded: {{ ruleGroups.excludedDirectory }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearRules">Clear</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="columns" :data="rules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="network" tab="Network Defense">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard title="Add Network Rule" :bordered="false" class="card-wrapper">
              <NForm ref="networkFormRef" :model="networkForm" :rules="networkFormRules" label-placement="top">
                <NFormItem label="Rule kind" path="kind">
                  <NSelect v-model:value="networkForm.kind" :options="networkKindOptions" />
                </NFormItem>
                <NFormItem label="Action" path="action">
                  <NSelect v-model:value="networkForm.action" :options="networkActionOptions" />
                </NFormItem>
                <NFormItem v-if="networkForm.kind === 'domain'" label="Domain" path="domain">
                  <NInput v-model:value="networkForm.domain" placeholder="*.example.com" />
                </NFormItem>
                <NFormItem v-else label="Remote IPv4 / CIDR" path="remoteAddress">
                  <NInput v-model:value="networkForm.remoteAddress" placeholder="203.0.113.10 or 203.0.113.0/24" />
                </NFormItem>
                <NGrid :x-gap="12" :y-gap="0" cols="2">
                  <NGi>
                    <NFormItem label="Protocol" path="protocol">
                      <NSelect v-model:value="networkForm.protocol" :options="networkProtocolOptions" />
                    </NFormItem>
                  </NGi>
                  <NGi>
                    <NFormItem label="Direction" path="direction">
                      <NSelect v-model:value="networkForm.direction" :options="networkDirectionOptions" />
                    </NFormItem>
                  </NGi>
                </NGrid>
                <NGrid :x-gap="12" :y-gap="0" cols="2">
                  <NGi>
                    <NFormItem label="Local port">
                      <NInputNumber v-model:value="networkForm.localPort" :min="0" :max="65535" class="w-full" />
                    </NFormItem>
                  </NGi>
                  <NGi>
                    <NFormItem label="Remote port">
                      <NInputNumber v-model:value="networkForm.remotePort" :min="0" :max="65535" class="w-full" />
                    </NFormItem>
                  </NGi>
                </NGrid>
                <NButton block type="primary" :loading="networkSubmitting" @click="addNetworkRule">
                  <template #icon><SvgIcon icon="mdi:shield-plus-outline" /></template>
                  Add Network Rule
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard title="Central Network Rule Inventory" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">Domains: {{ networkGroups.domain }}</NTag>
                  <NTag type="warning">IP: {{ networkGroups.ip }}</NTag>
                  <NTag type="error">Blocked: {{ networkGroups.blocked }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearNetworkRules">Clear</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="networkColumns" :data="networkRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>
    </NTabs>
  </NSpace>
</template>
