<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { NButton, NTag, type DataTableColumns, type FormInst, type FormRules } from 'naive-ui';
import {
  fetchAddPolicyRule,
  fetchBridgeStatus,
  fetchClearPolicyRules,
  fetchPolicyRules,
  fetchRemovePolicyRule
} from '@/service/api';

defineOptions({
  name: 'Policy'
});

const loading = ref(false);
const submitting = ref(false);
const connected = ref(false);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const formRef = ref<FormInst | null>(null);

const form = reactive<Api.DataProtector.PolicyRuleRequest>({
  kind: 'processName',
  value: '',
  extension: '.dpf',
  actor: 'web-admin'
});

const formRules: FormRules = {
  kind: { required: true, message: 'Rule kind is required', trigger: 'change' },
  value: { required: true, message: 'Rule value is required', trigger: 'input' },
  extension: { required: true, message: 'Extension is required', trigger: 'input' }
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

const ruleGroups = computed(() => ({
  processName: rules.value.filter(rule => rule.kind === 'processName').length,
  processDirectory: rules.value.filter(rule => rule.kind === 'processDirectory').length,
  excludedDirectory: rules.value.filter(rule => rule.kind === 'excludedDirectory').length
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

async function refresh() {
  loading.value = true;
  try {
    const [statusResult, rulesResult] = await Promise.all([fetchBridgeStatus(), fetchPolicyRules()]);
    connected.value = Boolean(statusResult.data?.connected);
    if (!rulesResult.error) rules.value = rulesResult.data;
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

async function removeRule(rule: Api.DataProtector.PolicyRule) {
  const { error, data } = await fetchRemovePolicyRule({ ...rule, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success('Rule removed from central policy.');
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

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 m:8">
        <NCard title="Add Rule" :bordered="false" class="card-wrapper">
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
        <NCard title="Central Rule Inventory" :bordered="false" class="card-wrapper">
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
  </NSpace>
</template>
