<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { NButton, NTag, type DataTableColumns, type FormInst, type FormRules } from 'naive-ui';
import {
  fetchAddDeviceRule,
  fetchAddNetworkRule,
  fetchAddPolicyRule,
  fetchAuthorizeRemovableDevice,
  fetchClearDeviceRules,
  fetchBridgeStatus,
  fetchClearNetworkRules,
  fetchClearPolicyRules,
  fetchClearWebShellRules,
  fetchDeviceRules,
  fetchNetworkRules,
  fetchPolicyRules,
  fetchWebShellRules,
  fetchRemoveDeviceRule,
  fetchRemoveNetworkRule,
  fetchRemovePolicyRule,
  fetchRemoveRemovableDeviceAuthorization,
  fetchRemovableDevices,
  fetchAddWebShellRule,
  fetchRemoveWebShellRule
} from '@/service/api';

defineOptions({
  name: 'Policy'
});

const loading = ref(false);
const submitting = ref(false);
const networkSubmitting = ref(false);
const webShellSubmitting = ref(false);
const deviceSubmitting = ref(false);
const connected = ref(false);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const networkRules = ref<Api.DataProtector.NetworkRule[]>([]);
const webShellRules = ref<Api.DataProtector.WebShellRule[]>([]);
const deviceRules = ref<Api.DataProtector.DeviceRule[]>([]);
const removableDevices = ref<Api.DataProtector.RemovableDevice[]>([]);
const formRef = ref<FormInst | null>(null);
const networkFormRef = ref<FormInst | null>(null);
const webShellFormRef = ref<FormInst | null>(null);
const deviceFormRef = ref<FormInst | null>(null);

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

const webShellForm = reactive<Api.DataProtector.WebShellRuleRequest>({
  directory: '',
  actor: 'web-admin'
});

const deviceForm = reactive<Api.DataProtector.DeviceRuleRequest>({
  deviceId: '*',
  allowInsert: true,
  allowWrite: false,
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
      if (networkForm.protocol === 'icmp') return true;
      return networkForm.remoteAddress.trim().length > 0 ? true : new Error('Remote address is required');
    }
  }
};

const webShellFormRules: FormRules = {
  directory: { required: true, message: 'Protected web directory is required', trigger: 'input' }
};

const deviceFormRules: FormRules = {
  deviceId: { required: true, message: 'Device identifier is required', trigger: 'input' }
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
  { label: 'ICMP', value: 'icmp' },
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
  icmp: networkRules.value.filter(rule => rule.protocol === 'icmp').length,
  blocked: networkRules.value.filter(rule => rule.action === 'block').length
}));

const webShellGroups = computed(() => ({
  directories: webShellRules.value.length
}));

const deviceGroups = computed(() => ({
  total: deviceRules.value.length,
  blockedInsert: deviceRules.value.filter(rule => !rule.allowInsert).length,
  readOnly: deviceRules.value.filter(rule => rule.allowInsert && !rule.allowWrite).length,
  writable: deviceRules.value.filter(rule => rule.allowInsert && rule.allowWrite).length,
  pendingHardware: removableDevices.value.filter(device => device.status === 'pending').length,
  authorizedHardware: removableDevices.value.filter(device => device.status === 'authorized').length,
  blockedHardware: removableDevices.value.filter(device => device.status === 'blocked').length
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

const webShellColumns: DataTableColumns<Api.DataProtector.WebShellRule> = [
  {
    title: 'Protected web directory',
    key: 'directory',
    ellipsis: { tooltip: true }
  },
  {
    title: 'Detection',
    key: 'detection',
    width: 170,
    render() {
      return h(NTag, { type: 'warning', bordered: false }, { default: () => 'Web scripts' });
    }
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
          onClick: () => removeWebShellRule(row)
        },
        { default: () => 'Remove' }
      );
    }
  }
];

const deviceColumns: DataTableColumns<Api.DataProtector.DeviceRule> = [
  {
    title: 'Device identifier',
    key: 'deviceId',
    ellipsis: { tooltip: true },
    render(row) {
      return row.deviceId === '*' ? 'All removable storage' : row.deviceId;
    }
  },
  {
    title: 'Access',
    key: 'allowInsert',
    width: 150,
    render(row) {
      return h(
        NTag,
        { type: row.allowInsert ? 'success' : 'error', bordered: false },
        { default: () => (row.allowInsert ? 'Allowed' : 'Blocked') }
      );
    }
  },
  {
    title: 'Write',
    key: 'allowWrite',
    width: 150,
    render(row) {
      return h(
        NTag,
        { type: row.allowWrite ? 'success' : 'warning', bordered: false },
        { default: () => (row.allowWrite ? 'Writable' : 'Read-only') }
      );
    }
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
          onClick: () => removeDeviceRule(row)
        },
        { default: () => 'Remove' }
      );
    }
  }
];

const removableDeviceColumns: DataTableColumns<Api.DataProtector.RemovableDevice> = [
  {
    title: 'Device',
    key: 'model',
    minWidth: 260,
    render(row) {
      return h('div', { class: 'min-w-0' }, [
        h('div', { class: 'truncate text-14px font-600' }, row.model || row.volumeLabel || 'Removable storage'),
        h('div', { class: 'truncate text-12px text-gray-500' }, `${row.driveLetter || '-'} ${row.volumeGuid || ''}`)
      ]);
    }
  },
  {
    title: 'Host',
    key: 'host',
    width: 170,
    render(row) {
      return h('div', { class: 'min-w-0' }, [
        h('div', { class: 'truncate text-13px font-600' }, row.host || '-'),
        h('div', { class: 'truncate text-12px text-gray-500' }, row.user || '-')
      ]);
    }
  },
  {
    title: 'Hardware code',
    key: 'hardwareId',
    minWidth: 260,
    ellipsis: { tooltip: true }
  },
  {
    title: 'Status',
    key: 'status',
    width: 130,
    render(row) {
      const type = row.status === 'authorized' ? 'success' : row.status === 'blocked' ? 'error' : 'warning';
      const label = row.status === 'authorized' && !row.allowWrite ? 'Read-only' : row.status;
      return h(NTag, { type, bordered: false }, { default: () => label });
    }
  },
  {
    title: 'Seen',
    key: 'lastSeenUtc',
    width: 120,
    render(row) {
      return h(NTag, { type: row.online ? 'success' : 'default', bordered: false }, { default: () => (row.online ? 'Online' : 'Offline') });
    }
  },
  {
    title: 'Action',
    key: 'actions',
    width: 290,
    render(row) {
      return h(
        'div',
        { class: 'flex flex-wrap gap-8px' },
        [
          h(
            NButton,
            { size: 'small', type: 'success', secondary: true, onClick: () => authorizeRemovableDevice(row, true) },
            { default: () => 'Authorize' }
          ),
          h(
            NButton,
            { size: 'small', type: 'warning', secondary: true, onClick: () => authorizeRemovableDevice(row, false) },
            { default: () => 'Read-only' }
          ),
          h(
            NButton,
            { size: 'small', type: 'error', secondary: true, onClick: () => blockRemovableDevice(row) },
            { default: () => 'Block' }
          ),
          h(
            NButton,
            { size: 'small', secondary: true, onClick: () => removeRemovableAuthorization(row) },
            { default: () => 'Reset' }
          )
        ]
      );
    }
  }
];

async function refresh() {
  loading.value = true;
  try {
    const [statusResult, rulesResult, networkRulesResult, webShellRulesResult, deviceRulesResult, removableDevicesResult] = await Promise.all([
      fetchBridgeStatus(),
      fetchPolicyRules(),
      fetchNetworkRules(),
      fetchWebShellRules(),
      fetchDeviceRules(),
      fetchRemovableDevices()
    ]);
    connected.value = Boolean(statusResult.data?.connected);
    if (!rulesResult.error) rules.value = rulesResult.data;
    if (!networkRulesResult.error) networkRules.value = networkRulesResult.data;
    if (!webShellRulesResult.error) webShellRules.value = webShellRulesResult.data;
    if (!deviceRulesResult.error) deviceRules.value = deviceRulesResult.data;
    if (!removableDevicesResult.error) removableDevices.value = removableDevicesResult.data;
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
      remoteAddress:
        networkForm.kind === 'ip' && networkForm.protocol === 'icmp'
          ? networkForm.remoteAddress.trim() || '*'
          : networkForm.remoteAddress.trim(),
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

async function addBlockPingRule() {
  networkSubmitting.value = true;
  try {
    const payload: Api.DataProtector.NetworkRuleRequest = {
      ruleId: 0x50494e47,
      kind: 'ip',
      action: 'block',
      protocol: 'icmp',
      direction: 'inbound',
      localAddress: '',
      localPort: 8,
      remoteAddress: '*',
      remotePort: 0,
      domain: '',
      actor: 'web-admin'
    };
    const { error, data } = await fetchAddNetworkRule(payload);
    if (!error && data.succeeded) {
      window.$message?.success('Inbound ping blocking rule added to central policy.');
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

async function addWebShellRule() {
  await webShellFormRef.value?.validate();
  webShellSubmitting.value = true;
  try {
    const { error, data } = await fetchAddWebShellRule({
      directory: webShellForm.directory.trim(),
      actor: 'web-admin'
    });
    if (!error && data.succeeded) {
      window.$message?.success('WebShell protected directory added to central policy.');
      webShellForm.directory = '';
      await refresh();
    }
  } finally {
    webShellSubmitting.value = false;
  }
}

async function removeWebShellRule(rule: Api.DataProtector.WebShellRule) {
  const { error, data } = await fetchRemoveWebShellRule({ directory: rule.directory, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success('WebShell protected directory removed from central policy.');
    await refresh();
  }
}

async function clearWebShellRules() {
  window.$dialog?.warning({
    title: 'Clear WebShell rules',
    content: 'This removes all protected web directories from the central policy.',
    positiveText: 'Clear',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      const { error, data } = await fetchClearWebShellRules();
      if (!error && data.succeeded) {
        window.$message?.success('Central WebShell policy cleared.');
        await refresh();
      }
    }
  });
}

function setDeviceInsert(value: boolean) {
  deviceForm.allowInsert = value;
  if (!value) {
    deviceForm.allowWrite = false;
  }
}

async function addDeviceRule() {
  await deviceFormRef.value?.validate();
  deviceSubmitting.value = true;
  try {
    const { error, data } = await fetchAddDeviceRule({
      deviceId: deviceForm.deviceId.trim(),
      allowInsert: deviceForm.allowInsert,
      allowWrite: deviceForm.allowInsert ? deviceForm.allowWrite : false,
      actor: 'web-admin'
    });
    if (!error && data.succeeded) {
      window.$message?.success('Device control rule added to central policy.');
      await refresh();
    }
  } finally {
    deviceSubmitting.value = false;
  }
}

async function removeDeviceRule(rule: Api.DataProtector.DeviceRule) {
  const { error, data } = await fetchRemoveDeviceRule({ ...rule, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success('Device control rule removed from central policy.');
    await refresh();
  }
}

async function clearDeviceRules() {
  window.$dialog?.warning({
    title: 'Clear device control rules',
    content: 'This removes all removable storage access and write policies from the central policy.',
    positiveText: 'Clear',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      const { error, data } = await fetchClearDeviceRules();
      if (!error && data.succeeded) {
        window.$message?.success('Central device control policy cleared.');
        await refresh();
      }
    }
  });
}

async function authorizeRemovableDevice(device: Api.DataProtector.RemovableDevice, allowWrite: boolean) {
  deviceSubmitting.value = true;
  try {
    const { error, data } = await fetchAuthorizeRemovableDevice({
      hardwareId: device.hardwareId,
      status: 'authorized',
      allowInsert: true,
      allowWrite,
      actor: 'web-admin'
    });
    if (!error && data.succeeded) {
      window.$message?.success(allowWrite ? 'Removable device authorized.' : 'Removable device authorized as read-only.');
      await refresh();
    }
  } finally {
    deviceSubmitting.value = false;
  }
}

async function blockRemovableDevice(device: Api.DataProtector.RemovableDevice) {
  deviceSubmitting.value = true;
  try {
    const { error, data } = await fetchAuthorizeRemovableDevice({
      hardwareId: device.hardwareId,
      status: 'blocked',
      allowInsert: false,
      allowWrite: false,
      actor: 'web-admin'
    });
    if (!error && data.succeeded) {
      window.$message?.success('Removable device blocked.');
      await refresh();
    }
  } finally {
    deviceSubmitting.value = false;
  }
}

async function removeRemovableAuthorization(device: Api.DataProtector.RemovableDevice) {
  const { error, data } = await fetchRemoveRemovableDeviceAuthorization({
    hardwareId: device.hardwareId,
    actor: 'web-admin'
  });
  if (!error && data.succeeded) {
    window.$message?.success('Removable device authorization reset.');
    await refresh();
  }
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
          <NGi span="24">
            <NCard title="Quick Network Actions" :bordered="false" class="card-wrapper">
              <div class="flex flex-wrap items-center justify-between gap-16px">
                <NSpace :size="12" align="center">
                  <NTag type="error" :bordered="false">Inbound ICMP</NTag>
                  <NTag type="warning" :bordered="false">Endpoint hardening</NTag>
                </NSpace>
                <NButton type="warning" :loading="networkSubmitting" @click="addBlockPingRule">
                  <template #icon><SvgIcon icon="mdi:lan-disconnect" /></template>
                  Disable Inbound Ping
                </NButton>
              </div>
            </NCard>
          </NGi>

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
                  <NInput
                    v-model:value="networkForm.remoteAddress"
                    :placeholder="networkForm.protocol === 'icmp' ? '* for all ping targets' : '203.0.113.10 or 203.0.113.0/24'"
                  />
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
                  <NTag type="error">ICMP: {{ networkGroups.icmp }}</NTag>
                  <NTag type="error">Blocked: {{ networkGroups.blocked }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearNetworkRules">Clear</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="networkColumns" :data="networkRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="webshell" tab="WebShell Defense">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard title="Add Protected Web Directory" :bordered="false" class="card-wrapper">
              <NForm ref="webShellFormRef" :model="webShellForm" :rules="webShellFormRules" label-placement="top">
                <NFormItem label="Web root directory" path="directory">
                  <NInput v-model:value="webShellForm.directory" placeholder="C:\\inetpub\\wwwroot" />
                </NFormItem>
                <NButton block type="primary" :loading="webShellSubmitting" @click="addWebShellRule">
                  <template #icon><SvgIcon icon="mdi:shield-bug-outline" /></template>
                  Add WebShell Defense Rule
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard title="Protected Web Directory Inventory" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="warning">Directories: {{ webShellGroups.directories }}</NTag>
                  <NTag type="error">Danger blocks enabled</NTag>
                  <NButton size="small" type="error" secondary @click="clearWebShellRules">Clear</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="webShellColumns" :data="webShellRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="device" tab="Device Control">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24">
            <NCard title="Discovered Removable Devices" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="warning">Pending: {{ deviceGroups.pendingHardware }}</NTag>
                  <NTag type="success">Authorized: {{ deviceGroups.authorizedHardware }}</NTag>
                  <NTag type="error">Blocked: {{ deviceGroups.blockedHardware }}</NTag>
                </NSpace>
              </template>
              <NDataTable
                :columns="removableDeviceColumns"
                :data="removableDevices"
                :loading="loading || deviceSubmitting"
                :pagination="{ pageSize: 8 }"
                :scroll-x="1180"
              />
            </NCard>
          </NGi>

          <NGi span="24 m:8">
            <NCard title="Add Removable Storage Rule" :bordered="false" class="card-wrapper">
              <NForm ref="deviceFormRef" :model="deviceForm" :rules="deviceFormRules" label-placement="top">
                <NFormItem label="Device identifier" path="deviceId">
                  <NInput v-model:value="deviceForm.deviceId" placeholder="* or \\?\\Volume{...}" />
                </NFormItem>
                <NFormItem label="Insertion access">
                  <NSwitch :value="deviceForm.allowInsert" @update:value="setDeviceInsert">
                    <template #checked>Allowed</template>
                    <template #unchecked>Blocked</template>
                  </NSwitch>
                </NFormItem>
                <NFormItem label="Write access">
                  <NSwitch v-model:value="deviceForm.allowWrite" :disabled="!deviceForm.allowInsert">
                    <template #checked>Writable</template>
                    <template #unchecked>Read-only</template>
                  </NSwitch>
                </NFormItem>
                <NButton block type="primary" :loading="deviceSubmitting" @click="addDeviceRule">
                  <template #icon><SvgIcon icon="mdi:usb-flash-drive-outline" /></template>
                  Add Device Control Rule
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard title="Central Device Control Inventory" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">Rules: {{ deviceGroups.total }}</NTag>
                  <NTag type="error">Blocked: {{ deviceGroups.blockedInsert }}</NTag>
                  <NTag type="warning">Read-only: {{ deviceGroups.readOnly }}</NTag>
                  <NTag type="success">Writable: {{ deviceGroups.writable }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearDeviceRules">Clear</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="deviceColumns" :data="deviceRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>
    </NTabs>
  </NSpace>
</template>
