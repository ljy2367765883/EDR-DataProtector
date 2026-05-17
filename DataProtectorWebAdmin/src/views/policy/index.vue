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
  fetchHashProtectPolicy,
  fetchLateralDefensePolicy,
  fetchNetworkRules,
  fetchPolicyRules,
  fetchWebShellRules,
  fetchRemoveDeviceRule,
  fetchRemoveNetworkRule,
  fetchRemovePolicyRule,
  fetchRemoveRemovableDevice,
  fetchRemoveRemovableDeviceAuthorization,
  fetchRemovableDevices,
  fetchAddWebShellRule,
  fetchRemoveWebShellRule,
  fetchUpdateHashProtectPolicy,
  fetchUpdateLateralDefensePolicy,
  fetchUpdateUsbCryptPolicy,
  fetchUsbCryptPolicy
} from '@/service/api';
import { $t } from '@/locales';

defineOptions({
  name: 'Policy'
});

const loading = ref(false);
const submitting = ref(false);
const networkSubmitting = ref(false);
const webShellSubmitting = ref(false);
const deviceSubmitting = ref(false);
const hashProtectSubmitting = ref(false);
const lateralDefenseSubmitting = ref(false);
const usbCryptSubmitting = ref(false);
const connected = ref(false);
const rules = ref<Api.DataProtector.PolicyRule[]>([]);
const networkRules = ref<Api.DataProtector.NetworkRule[]>([]);
const webShellRules = ref<Api.DataProtector.WebShellRule[]>([]);
const deviceRules = ref<Api.DataProtector.DeviceRule[]>([]);
const removableDevices = ref<Api.DataProtector.RemovableDevice[]>([]);
const hashProtectPolicy = reactive<Api.DataProtector.HashProtectPolicy>({
  enabled: true,
  protectLsass: true,
  protectCredentialFiles: true,
  protectRegistryHives: true,
  protectRawExtents: true,
  flags: 0x0000001f,
  actor: 'web-admin'
});
const lateralDefensePolicy = reactive<Api.DataProtector.LateralDefensePolicy>({
  enabled: true,
  blockSmbExecutableCopy: true,
  blockIpcScheduledTasks: true,
  blockIpcServiceCreation: true,
  blockRemoteAdminTools: true,
  flags: 0x0000001f,
  actor: 'web-admin'
});
const usbCryptPolicy = reactive<Api.DataProtector.UsbCryptPolicy>({
  enabled: false,
  algorithm: 'rc4',
  publicToolAreaBytes: 5 * 1024 * 1024,
  allowClientProvisioning: false,
  requireHardwareAuthorization: true,
  keyMaterialId: '',
  actor: 'web-admin'
});
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

const formRules = computed<FormRules>(() => ({
  kind: { required: true, message: $t('dataprotector.policy.validation.ruleKind'), trigger: 'change' },
  value: { required: true, message: $t('dataprotector.policy.validation.ruleValue'), trigger: 'input' },
  extension: { required: true, message: $t('dataprotector.policy.validation.extension'), trigger: 'input' }
}));

const networkFormRules = computed<FormRules>(() => ({
  kind: { required: true, message: $t('dataprotector.policy.validation.ruleKind'), trigger: 'change' },
  action: { required: true, message: $t('dataprotector.policy.validation.action'), trigger: 'change' },
  protocol: { required: true, message: $t('dataprotector.policy.validation.protocol'), trigger: 'change' },
  direction: { required: true, message: $t('dataprotector.policy.validation.direction'), trigger: 'change' },
  domain: {
    trigger: 'input',
    validator() {
      if (networkForm.kind !== 'domain') return true;
      return networkForm.domain.trim().length > 0 ? true : new Error($t('dataprotector.policy.validation.domain'));
    }
  },
  remoteAddress: {
    trigger: 'input',
    validator() {
      if (networkForm.kind !== 'ip') return true;
      if (networkForm.protocol === 'icmp') return true;
      return networkForm.remoteAddress.trim().length > 0 ? true : new Error($t('dataprotector.policy.validation.remoteAddress'));
    }
  }
}));

const webShellFormRules = computed<FormRules>(() => ({
  directory: { required: true, message: $t('dataprotector.policy.validation.protectedDirectory'), trigger: 'input' }
}));

const deviceFormRules = computed<FormRules>(() => ({
  deviceId: { required: true, message: $t('dataprotector.policy.validation.deviceId'), trigger: 'input' }
}));

const kindOptions = computed(() => [
  { label: $t('dataprotector.policy.file.processName'), value: 'processName' },
  { label: $t('dataprotector.policy.file.processDirectory'), value: 'processDirectory' },
  { label: $t('dataprotector.policy.file.excludedDirectory'), value: 'excludedDirectory' }
]);

function ruleKindLabel(kind: Api.DataProtector.RuleKind) {
  const labels: Record<Api.DataProtector.RuleKind, string> = {
    processName: $t('dataprotector.policy.file.processName'),
    processDirectory: $t('dataprotector.policy.file.processDirectory'),
    excludedDirectory: $t('dataprotector.policy.file.excludedDirectory')
  };
  return labels[kind] || kind;
}

const networkKindOptions = computed(() => [
  { label: $t('dataprotector.policy.network.domain'), value: 'domain' },
  { label: $t('dataprotector.policy.network.remoteIp'), value: 'ip' }
]);

const networkActionOptions = computed(() => [
  { label: $t('dataprotector.common.block'), value: 'block' },
  { label: $t('dataprotector.policy.network.allow'), value: 'allow' }
]);

const networkProtocolOptions = computed(() => [
  { label: $t('dataprotector.policy.network.any'), value: 'any' },
  { label: 'ICMP', value: 'icmp' },
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' }
]);

const networkDirectionOptions = computed(() => [
  { label: $t('dataprotector.policy.network.outbound'), value: 'outbound' },
  { label: $t('dataprotector.policy.network.inbound'), value: 'inbound' },
  { label: $t('dataprotector.policy.network.both'), value: 'both' }
]);

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

const hashProtectGroups = computed(() => {
  const enabledFeatures = [
    hashProtectPolicy.protectLsass,
    hashProtectPolicy.protectCredentialFiles,
    hashProtectPolicy.protectRegistryHives,
    hashProtectPolicy.protectRawExtents
  ].filter(Boolean).length;

  return {
    mode: hashProtectPolicy.enabled ? $t('dataprotector.common.enforcing') : $t('dataprotector.common.disabled'),
    enabledFeatures,
    protectedAssets: hashProtectPolicy.enabled ? enabledFeatures : 0,
    flags: `0x${hashProtectPolicy.flags.toString(16).toUpperCase().padStart(8, '0')}`
  };
});

const hashProtectAssets = computed(() => [
  {
    key: 'lsass',
    title: $t('dataprotector.policy.hashprotect.assetsList.lsassTitle'),
    detail: $t('dataprotector.policy.hashprotect.assetsList.lsassDetail'),
    enabled: hashProtectPolicy.enabled && hashProtectPolicy.protectLsass,
    icon: 'mdi:memory'
  },
  {
    key: 'credential-files',
    title: $t('dataprotector.policy.hashprotect.assetsList.filesTitle'),
    detail: $t('dataprotector.policy.hashprotect.assetsList.filesDetail'),
    enabled: hashProtectPolicy.enabled && hashProtectPolicy.protectCredentialFiles,
    icon: 'mdi:file-lock-outline'
  },
  {
    key: 'registry-hives',
    title: $t('dataprotector.policy.hashprotect.assetsList.registryTitle'),
    detail: $t('dataprotector.policy.hashprotect.assetsList.registryDetail'),
    enabled: hashProtectPolicy.enabled && hashProtectPolicy.protectRegistryHives,
    icon: 'mdi:database-lock-outline'
  },
  {
    key: 'raw-extents',
    title: $t('dataprotector.policy.hashprotect.assetsList.rawTitle'),
    detail: $t('dataprotector.policy.hashprotect.assetsList.rawDetail'),
    enabled: hashProtectPolicy.enabled && hashProtectPolicy.protectRawExtents,
    icon: 'mdi:harddisk'
  }
]);

const lateralDefenseGroups = computed(() => {
  const enabledFeatures = [
    lateralDefensePolicy.blockSmbExecutableCopy,
    lateralDefensePolicy.blockIpcScheduledTasks,
    lateralDefensePolicy.blockIpcServiceCreation,
    lateralDefensePolicy.blockRemoteAdminTools
  ].filter(Boolean).length;

  return {
    mode: lateralDefensePolicy.enabled ? $t('dataprotector.common.enforcing') : $t('dataprotector.common.disabled'),
    enabledFeatures,
    activeControls: lateralDefensePolicy.enabled ? enabledFeatures : 0,
    flags: `0x${lateralDefensePolicy.flags.toString(16).toUpperCase().padStart(8, '0')}`
  };
});

const usbCryptGroups = computed(() => ({
  mode: usbCryptPolicy.enabled ? $t('dataprotector.common.enforcing') : $t('dataprotector.common.disabled'),
  algorithm: usbCryptPolicy.algorithm.toUpperCase(),
  toolAreaMb: Math.round(usbCryptPolicy.publicToolAreaBytes / 1024 / 1024),
  provisioning: usbCryptPolicy.allowClientProvisioning ? $t('dataprotector.common.enabled') : $t('dataprotector.common.disabled')
}));

const lateralDefenseControls = computed(() => [
  {
    key: 'smb-executable',
    title: $t('dataprotector.policy.lateral.smbStaging'),
    detail: $t('dataprotector.policy.lateral.smbStagingDesc'),
    enabled: lateralDefensePolicy.enabled && lateralDefensePolicy.blockSmbExecutableCopy,
    icon: 'mdi:file-alert-outline'
  },
  {
    key: 'ipc-tasks',
    title: $t('dataprotector.policy.lateral.ipcTaskScheduler'),
    detail: $t('dataprotector.policy.lateral.ipcTaskSchedulerDesc'),
    enabled: lateralDefensePolicy.enabled && lateralDefensePolicy.blockIpcScheduledTasks,
    icon: 'mdi:calendar-lock-outline'
  },
  {
    key: 'ipc-services',
    title: $t('dataprotector.policy.lateral.ipcServiceControl'),
    detail: $t('dataprotector.policy.lateral.ipcServiceControlDesc'),
    enabled: lateralDefensePolicy.enabled && lateralDefensePolicy.blockIpcServiceCreation,
    icon: 'mdi:cog-stop-outline'
  },
  {
    key: 'remote-admin-tools',
    title: $t('dataprotector.policy.lateral.remoteAdminLaunch'),
    detail: $t('dataprotector.policy.lateral.remoteAdminLaunchDesc'),
    enabled: lateralDefensePolicy.enabled && lateralDefensePolicy.blockRemoteAdminTools,
    icon: 'mdi:console-network-outline'
  }
]);

function formatRemovableVolumes(device: Api.DataProtector.RemovableDevice) {
  const volumes = device.volumes?.length
    ? device.volumes
    : [
        {
          driveLetter: device.driveLetter,
          volumeGuid: device.volumeGuid,
          volumeLabel: device.volumeLabel,
          fileSystem: device.fileSystem,
          sizeBytes: device.sizeBytes,
          online: device.online
        }
      ];

  const driveLetters = volumes
    .map(volume => volume.driveLetter)
    .filter(Boolean)
    .join(', ');

  const volumeGuids = volumes
    .map(volume => volume.volumeGuid)
    .filter(Boolean)
    .join(' | ');

  return {
    driveLetters: driveLetters || '-',
    volumeGuids: volumeGuids || '-',
    count: volumes.length
  };
}

const columns = computed<DataTableColumns<Api.DataProtector.PolicyRule>>(() => [
  {
    title: $t('dataprotector.policy.file.kind'),
    key: 'kind',
    width: 180,
    render(row) {
      const type = row.kind === 'excludedDirectory' ? 'warning' : 'info';
      return h(NTag, { type, bordered: false }, { default: () => ruleKindLabel(row.kind) });
    }
  },
  {
    title: $t('dataprotector.policy.file.extension'),
    key: 'extension',
    width: 120,
    render(row) {
      return h(NTag, { type: 'success', bordered: false }, { default: () => row.extension });
    }
  },
  {
    title: $t('dataprotector.policy.file.value'),
    key: 'value',
    ellipsis: { tooltip: true }
  },
  {
    title: $t('dataprotector.common.action'),
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
        { default: () => $t('dataprotector.common.remove') }
      );
    }
  }
]);

const networkColumns = computed<DataTableColumns<Api.DataProtector.NetworkRule>>(() => [
  {
    title: $t('dataprotector.policy.network.action'),
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
    title: $t('dataprotector.policy.network.kind'),
    key: 'kind',
    width: 120,
    render(row) {
      return h(NTag, { type: row.kind === 'domain' ? 'info' : 'warning', bordered: false }, { default: () => row.kind });
    }
  },
  {
    title: $t('dataprotector.policy.network.target'),
    key: 'displayTarget',
    ellipsis: { tooltip: true },
    render(row) {
      return row.displayTarget || row.domain || row.remoteAddress || '*';
    }
  },
  {
    title: $t('dataprotector.policy.network.protocol'),
    key: 'protocol',
    width: 110,
    render(row) {
      return row.protocol.toUpperCase();
    }
  },
  {
    title: $t('dataprotector.policy.network.direction'),
    key: 'direction',
    width: 120
  },
  {
    title: $t('dataprotector.policy.network.port'),
    key: 'remotePort',
    width: 100,
    render(row) {
      return row.remotePort ? String(row.remotePort) : '*';
    }
  },
  {
    title: $t('dataprotector.policy.network.ruleId'),
    key: 'ruleId',
    width: 130
  },
  {
    title: $t('dataprotector.common.action'),
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
        { default: () => $t('dataprotector.common.remove') }
      );
    }
  }
]);

const webShellColumns = computed<DataTableColumns<Api.DataProtector.WebShellRule>>(() => [
  {
    title: $t('dataprotector.policy.webshell.protectedDirectory'),
    key: 'directory',
    ellipsis: { tooltip: true }
  },
  {
    title: $t('dataprotector.policy.webshell.detection'),
    key: 'detection',
    width: 170,
    render() {
      return h(NTag, { type: 'warning', bordered: false }, { default: () => $t('dataprotector.policy.webshell.webScripts') });
    }
  },
  {
    title: $t('dataprotector.common.action'),
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
        { default: () => $t('dataprotector.common.remove') }
      );
    }
  }
]);

const deviceColumns = computed<DataTableColumns<Api.DataProtector.DeviceRule>>(() => [
  {
    title: $t('dataprotector.policy.device.deviceId'),
    key: 'deviceId',
    ellipsis: { tooltip: true },
    render(row) {
      return row.deviceId === '*' ? $t('dataprotector.policy.device.allStorage') : row.deviceId;
    }
  },
  {
    title: $t('dataprotector.policy.device.access'),
    key: 'allowInsert',
    width: 150,
    render(row) {
      return h(
        NTag,
        { type: row.allowInsert ? 'success' : 'error', bordered: false },
        { default: () => (row.allowInsert ? $t('dataprotector.policy.device.allowed') : $t('dataprotector.common.blocked')) }
      );
    }
  },
  {
    title: $t('dataprotector.policy.device.write'),
    key: 'allowWrite',
    width: 150,
    render(row) {
      return h(
        NTag,
        { type: row.allowWrite ? 'success' : 'warning', bordered: false },
        { default: () => (row.allowWrite ? $t('dataprotector.common.writable') : $t('dataprotector.common.readOnly')) }
      );
    }
  },
  {
    title: $t('dataprotector.common.action'),
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
        { default: () => $t('dataprotector.common.remove') }
      );
    }
  }
]);

const removableDeviceColumns = computed<DataTableColumns<Api.DataProtector.RemovableDevice>>(() => [
  {
    title: $t('dataprotector.policy.device.device'),
    key: 'model',
    minWidth: 260,
    render(row) {
      const volumeInfo = formatRemovableVolumes(row);
      return h('div', { class: 'min-w-0' }, [
        h('div', { class: 'truncate text-14px font-600' }, row.model || row.volumeLabel || $t('dataprotector.policy.device.removableStorage')),
        h('div', { class: 'truncate text-12px text-gray-500' }, `${volumeInfo.driveLetters} (${$t('dataprotector.policy.device.volumeCount', { count: volumeInfo.count })})`)
      ]);
    }
  },
  {
    title: $t('dataprotector.policy.device.host'),
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
    title: $t('dataprotector.policy.device.volumes'),
    key: 'volumes',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render(row) {
      return formatRemovableVolumes(row).volumeGuids;
    }
  },
  {
    title: $t('dataprotector.policy.device.hardwareCode'),
    key: 'hardwareId',
    minWidth: 260,
    ellipsis: { tooltip: true }
  },
  {
    title: $t('dataprotector.policy.device.status'),
    key: 'status',
    width: 130,
    render(row) {
      const type = row.status === 'authorized' ? 'success' : row.status === 'blocked' ? 'error' : 'warning';
      const label = row.status === 'authorized' && !row.allowWrite ? $t('dataprotector.common.readOnly') : deviceStatusLabel(row.status);
      return h(NTag, { type, bordered: false }, { default: () => label });
    }
  },
  {
    title: $t('dataprotector.policy.device.seen'),
    key: 'lastSeenUtc',
    width: 120,
    render(row) {
      return h(NTag, { type: row.online ? 'success' : 'default', bordered: false }, { default: () => (row.online ? $t('dataprotector.common.online') : $t('dataprotector.common.offline')) });
    }
  },
  {
    title: $t('dataprotector.common.action'),
    key: 'actions',
    width: 360,
    render(row) {
      return h(
        'div',
        { class: 'flex flex-wrap gap-8px' },
        [
          h(
            NButton,
            { size: 'small', type: 'success', secondary: true, onClick: () => authorizeRemovableDevice(row, true) },
            { default: () => $t('dataprotector.common.authorize') }
          ),
          h(
            NButton,
            { size: 'small', type: 'warning', secondary: true, onClick: () => authorizeRemovableDevice(row, false) },
            { default: () => $t('dataprotector.common.readOnly') }
          ),
          h(
            NButton,
            { size: 'small', type: 'error', secondary: true, onClick: () => blockRemovableDevice(row) },
            { default: () => $t('dataprotector.common.block') }
          ),
          h(
            NButton,
            { size: 'small', secondary: true, onClick: () => removeRemovableAuthorization(row) },
            { default: () => $t('dataprotector.common.reset') }
          ),
          h(
            NButton,
            { size: 'small', type: 'error', secondary: true, onClick: () => deleteRemovableDevice(row) },
            { default: () => $t('dataprotector.common.delete') }
          )
        ]
      );
    }
  }
]);

function deviceStatusLabel(status: string) {
  if (status === 'authorized') return $t('dataprotector.policy.device.authorized');
  if (status === 'blocked') return $t('dataprotector.policy.device.blocked');
  return $t('dataprotector.policy.device.pending');
}

function applyHashProtectPolicy(policy?: Api.DataProtector.HashProtectPolicy) {
  if (!policy) return;

  hashProtectPolicy.enabled = Boolean(policy.enabled);
  hashProtectPolicy.protectLsass = Boolean(policy.protectLsass);
  hashProtectPolicy.protectCredentialFiles = Boolean(policy.protectCredentialFiles);
  hashProtectPolicy.protectRegistryHives = Boolean(policy.protectRegistryHives);
  hashProtectPolicy.protectRawExtents = Boolean(policy.protectRawExtents);
  hashProtectPolicy.flags = policy.flags ?? calculateHashProtectFlags();
  hashProtectPolicy.actor = 'web-admin';
}

function calculateHashProtectFlags() {
  let flags = 0;
  if (hashProtectPolicy.enabled) flags |= 0x00000001;
  if (hashProtectPolicy.protectLsass) flags |= 0x00000002;
  if (hashProtectPolicy.protectCredentialFiles) flags |= 0x00000004;
  if (hashProtectPolicy.protectRegistryHives) flags |= 0x00000008;
  if (hashProtectPolicy.protectRawExtents) flags |= 0x00000010;
  return flags;
}

function syncHashProtectFlags() {
  hashProtectPolicy.flags = calculateHashProtectFlags();
}

function setHashProtectEnabled(value: boolean) {
  hashProtectPolicy.enabled = value;
  syncHashProtectFlags();
}

function setHashProtectFeature(
  key: 'protectLsass' | 'protectCredentialFiles' | 'protectRegistryHives' | 'protectRawExtents',
  value: boolean
) {
  hashProtectPolicy[key] = value;
  syncHashProtectFlags();
}

function applyLateralDefensePolicy(policy?: Api.DataProtector.LateralDefensePolicy) {
  if (!policy) return;

  lateralDefensePolicy.enabled = Boolean(policy.enabled);
  lateralDefensePolicy.blockSmbExecutableCopy = Boolean(policy.blockSmbExecutableCopy);
  lateralDefensePolicy.blockIpcScheduledTasks = Boolean(policy.blockIpcScheduledTasks);
  lateralDefensePolicy.blockIpcServiceCreation = Boolean(policy.blockIpcServiceCreation);
  lateralDefensePolicy.blockRemoteAdminTools = Boolean(policy.blockRemoteAdminTools);
  lateralDefensePolicy.flags = policy.flags ?? calculateLateralDefenseFlags();
  lateralDefensePolicy.actor = 'web-admin';
}

function calculateLateralDefenseFlags() {
  let flags = 0;
  if (lateralDefensePolicy.enabled) flags |= 0x00000001;
  if (lateralDefensePolicy.blockSmbExecutableCopy) flags |= 0x00000002;
  if (lateralDefensePolicy.blockIpcScheduledTasks) flags |= 0x00000004;
  if (lateralDefensePolicy.blockIpcServiceCreation) flags |= 0x00000008;
  if (lateralDefensePolicy.blockRemoteAdminTools) flags |= 0x00000010;
  return flags;
}

function syncLateralDefenseFlags() {
  lateralDefensePolicy.flags = calculateLateralDefenseFlags();
}

function setLateralDefenseEnabled(value: boolean) {
  lateralDefensePolicy.enabled = value;
  syncLateralDefenseFlags();
}

function setLateralDefenseFeature(
  key: 'blockSmbExecutableCopy' | 'blockIpcScheduledTasks' | 'blockIpcServiceCreation' | 'blockRemoteAdminTools',
  value: boolean
) {
  lateralDefensePolicy[key] = value;
  syncLateralDefenseFlags();
}

function applyUsbCryptPolicy(policy?: Api.DataProtector.UsbCryptPolicy) {
  if (!policy) return;

  usbCryptPolicy.enabled = Boolean(policy.enabled);
  usbCryptPolicy.algorithm = 'rc4';
  usbCryptPolicy.publicToolAreaBytes = policy.publicToolAreaBytes || 5 * 1024 * 1024;
  usbCryptPolicy.allowClientProvisioning = Boolean(policy.allowClientProvisioning);
  usbCryptPolicy.requireHardwareAuthorization = policy.requireHardwareAuthorization !== false;
  usbCryptPolicy.keyMaterialId = policy.keyMaterialId || '';
  usbCryptPolicy.actor = 'web-admin';
}

async function refresh() {
  loading.value = true;
  try {
    const [
      statusResult,
      rulesResult,
      networkRulesResult,
      webShellRulesResult,
      deviceRulesResult,
      removableDevicesResult,
      hashProtectPolicyResult,
      lateralDefensePolicyResult,
      usbCryptPolicyResult
    ] = await Promise.all([
      fetchBridgeStatus(),
      fetchPolicyRules(),
      fetchNetworkRules(),
      fetchWebShellRules(),
      fetchDeviceRules(),
      fetchRemovableDevices(),
      fetchHashProtectPolicy(),
      fetchLateralDefensePolicy(),
      fetchUsbCryptPolicy()
    ]);
    connected.value = Boolean(statusResult.data?.connected);
    if (!rulesResult.error) rules.value = rulesResult.data;
    if (!networkRulesResult.error) networkRules.value = networkRulesResult.data;
    if (!webShellRulesResult.error) webShellRules.value = webShellRulesResult.data;
    if (!deviceRulesResult.error) deviceRules.value = deviceRulesResult.data;
    if (!removableDevicesResult.error) removableDevices.value = removableDevicesResult.data;
    if (!hashProtectPolicyResult.error) applyHashProtectPolicy(hashProtectPolicyResult.data);
    if (!lateralDefensePolicyResult.error) applyLateralDefensePolicy(lateralDefensePolicyResult.data);
    if (!usbCryptPolicyResult.error) applyUsbCryptPolicy(usbCryptPolicyResult.data);
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
      window.$message?.success($t('dataprotector.policy.file.added'));
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
      window.$message?.success($t('dataprotector.policy.network.added'));
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
      window.$message?.success($t('dataprotector.policy.network.pingAdded'));
      await refresh();
    }
  } finally {
    networkSubmitting.value = false;
  }
}

async function removeRule(rule: Api.DataProtector.PolicyRule) {
  const { error, data } = await fetchRemovePolicyRule({ ...rule, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success($t('dataprotector.policy.file.removed'));
    await refresh();
  }
}

async function removeNetworkRule(rule: Api.DataProtector.NetworkRule) {
  const { error, data } = await fetchRemoveNetworkRule({ ruleId: rule.ruleId, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success($t('dataprotector.policy.network.removed'));
    await refresh();
  }
}

async function clearRules() {
  window.$dialog?.warning({
    title: $t('dataprotector.policy.file.clearTitle'),
    content: $t('dataprotector.policy.file.clearContent'),
    positiveText: $t('dataprotector.common.clear'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchClearPolicyRules();
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.policy.file.clearSuccess'));
        await refresh();
      }
    }
  });
}

async function clearNetworkRules() {
  window.$dialog?.warning({
    title: $t('dataprotector.policy.network.clearTitle'),
    content: $t('dataprotector.policy.network.clearContent'),
    positiveText: $t('dataprotector.common.clear'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchClearNetworkRules();
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.policy.network.clearSuccess'));
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
      window.$message?.success($t('dataprotector.policy.webshell.added'));
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
    window.$message?.success($t('dataprotector.policy.webshell.removed'));
    await refresh();
  }
}

async function clearWebShellRules() {
  window.$dialog?.warning({
    title: $t('dataprotector.policy.webshell.clearTitle'),
    content: $t('dataprotector.policy.webshell.clearContent'),
    positiveText: $t('dataprotector.common.clear'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchClearWebShellRules();
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.policy.webshell.clearSuccess'));
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
      window.$message?.success($t('dataprotector.policy.device.added'));
      await refresh();
    }
  } finally {
    deviceSubmitting.value = false;
  }
}

async function removeDeviceRule(rule: Api.DataProtector.DeviceRule) {
  const { error, data } = await fetchRemoveDeviceRule({ ...rule, actor: 'web-admin' });
  if (!error && data.succeeded) {
    window.$message?.success($t('dataprotector.policy.device.removed'));
    await refresh();
  }
}

async function clearDeviceRules() {
  window.$dialog?.warning({
    title: $t('dataprotector.policy.device.clearTitle'),
    content: $t('dataprotector.policy.device.clearContent'),
    positiveText: $t('dataprotector.common.clear'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchClearDeviceRules();
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.policy.device.clearSuccess'));
        await refresh();
      }
    }
  });
}

async function saveHashProtectPolicy() {
  syncHashProtectFlags();
  hashProtectSubmitting.value = true;
  try {
    const { error, data } = await fetchUpdateHashProtectPolicy({
      enabled: hashProtectPolicy.enabled,
      protectLsass: hashProtectPolicy.protectLsass,
      protectCredentialFiles: hashProtectPolicy.protectCredentialFiles,
      protectRegistryHives: hashProtectPolicy.protectRegistryHives,
      protectRawExtents: hashProtectPolicy.protectRawExtents,
      actor: 'web-admin'
    });

    if (!error && data.succeeded) {
      window.$message?.success($t('dataprotector.policy.hashprotect.saved'));
      await refresh();
    }
  } finally {
    hashProtectSubmitting.value = false;
  }
}

async function saveLateralDefensePolicy() {
  syncLateralDefenseFlags();
  lateralDefenseSubmitting.value = true;
  try {
    const { error, data } = await fetchUpdateLateralDefensePolicy({
      enabled: lateralDefensePolicy.enabled,
      blockSmbExecutableCopy: lateralDefensePolicy.blockSmbExecutableCopy,
      blockIpcScheduledTasks: lateralDefensePolicy.blockIpcScheduledTasks,
      blockIpcServiceCreation: lateralDefensePolicy.blockIpcServiceCreation,
      blockRemoteAdminTools: lateralDefensePolicy.blockRemoteAdminTools,
      actor: 'web-admin'
    });

    if (!error && data.succeeded) {
      window.$message?.success($t('dataprotector.policy.lateral.saved'));
      await refresh();
    }
  } finally {
    lateralDefenseSubmitting.value = false;
  }
}

async function saveUsbCryptPolicy() {
  usbCryptSubmitting.value = true;
  try {
    const { error, data } = await fetchUpdateUsbCryptPolicy({
      enabled: usbCryptPolicy.enabled,
      algorithm: 'rc4',
      publicToolAreaBytes: usbCryptPolicy.publicToolAreaBytes,
      allowClientProvisioning: usbCryptPolicy.allowClientProvisioning,
      requireHardwareAuthorization: usbCryptPolicy.requireHardwareAuthorization,
      keyMaterialId: usbCryptPolicy.keyMaterialId,
      actor: 'web-admin'
    });

    if (!error && data.succeeded) {
      window.$message?.success($t('dataprotector.policy.usbcrypt.saved'));
      await refresh();
    }
  } finally {
    usbCryptSubmitting.value = false;
  }
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
      window.$message?.success(
        allowWrite ? $t('dataprotector.policy.device.authorizedWritable') : $t('dataprotector.policy.device.authorizedReadonly')
      );
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
      window.$message?.success($t('dataprotector.policy.device.blockedDevice'));
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
    window.$message?.success($t('dataprotector.policy.device.authorizationRemoved'));
    await refresh();
  }
}

async function deleteRemovableDevice(device: Api.DataProtector.RemovableDevice) {
  window.$dialog?.warning({
    title: $t('dataprotector.policy.device.deleteInventoryTitle'),
    content: $t('dataprotector.policy.device.deleteInventoryContent', { code: device.hardwareId }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveRemovableDevice({
        hardwareId: device.hardwareId,
        actor: 'web-admin'
      });
      if (!error && data.succeeded) {
        window.$message?.success($t('dataprotector.policy.device.inventoryDeleted'));
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
          <h1 class="m-0 text-24px font-700">{{ $t('dataprotector.policy.title') }}</h1>
          <p class="m-t-8px text-14px text-gray-500">
            {{ $t('dataprotector.policy.subtitle') }}
          </p>
        </div>
        <NSpace>
          <NTag :type="connected ? 'success' : 'error'">
            {{ connected ? $t('dataprotector.policy.centralOnline') : $t('dataprotector.policy.serverOffline') }}
          </NTag>
          <NButton :loading="loading" @click="refresh">
            <template #icon><SvgIcon icon="mdi:refresh" /></template>
            {{ $t('dataprotector.common.refresh') }}
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NTabs type="line" animated>
      <NTabPane name="file" :tab="$t('dataprotector.policy.tabs.file')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.file.addTitle')" :bordered="false" class="card-wrapper">
              <NForm ref="formRef" :model="form" :rules="formRules" label-placement="top">
                <NFormItem :label="$t('dataprotector.policy.file.ruleKind')" path="kind">
                  <NSelect v-model:value="form.kind" :options="kindOptions" />
                </NFormItem>
                <NFormItem :label="$t('dataprotector.policy.file.extension')" path="extension">
                  <NInput v-model:value="form.extension" placeholder=".dpf" />
                </NFormItem>
                <NFormItem :label="$t('dataprotector.policy.file.ruleValue')" path="value">
                  <NInput
                    v-model:value="form.value"
                    :placeholder="form.kind === 'processName' ? 'notepad.exe' : 'C:\\Program Files\\WPS Office\\'"
                  />
                </NFormItem>
                <NButton block type="primary" :loading="submitting" @click="addRule">
                  <template #icon><SvgIcon icon="mdi:plus" /></template>
                  {{ $t('dataprotector.policy.file.addButton') }}
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.file.inventory')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">{{ $t('dataprotector.policy.file.process') }}: {{ ruleGroups.processName }}</NTag>
                  <NTag type="info">{{ $t('dataprotector.policy.file.directory') }}: {{ ruleGroups.processDirectory }}</NTag>
                  <NTag type="warning">{{ $t('dataprotector.policy.file.excluded') }}: {{ ruleGroups.excludedDirectory }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearRules">{{ $t('dataprotector.common.clear') }}</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="columns" :data="rules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="network" :tab="$t('dataprotector.policy.tabs.network')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24">
            <NCard :title="$t('dataprotector.policy.network.quickActions')" :bordered="false" class="card-wrapper">
              <div class="flex flex-wrap items-center justify-between gap-16px">
                <NSpace :size="12" align="center">
                  <NTag type="error" :bordered="false">{{ $t('dataprotector.policy.network.inboundIcmp') }}</NTag>
                  <NTag type="warning" :bordered="false">{{ $t('dataprotector.policy.network.hardening') }}</NTag>
                </NSpace>
                <NButton type="warning" :loading="networkSubmitting" @click="addBlockPingRule">
                  <template #icon><SvgIcon icon="mdi:lan-disconnect" /></template>
                  {{ $t('dataprotector.policy.network.disablePing') }}
                </NButton>
              </div>
            </NCard>
          </NGi>

          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.network.addTitle')" :bordered="false" class="card-wrapper">
              <NForm ref="networkFormRef" :model="networkForm" :rules="networkFormRules" label-placement="top">
                <NFormItem :label="$t('dataprotector.policy.network.kind')" path="kind">
                  <NSelect v-model:value="networkForm.kind" :options="networkKindOptions" />
                </NFormItem>
                <NFormItem :label="$t('dataprotector.policy.network.action')" path="action">
                  <NSelect v-model:value="networkForm.action" :options="networkActionOptions" />
                </NFormItem>
                <NFormItem v-if="networkForm.kind === 'domain'" :label="$t('dataprotector.policy.network.domain')" path="domain">
                  <NInput v-model:value="networkForm.domain" placeholder="*.example.com" />
                </NFormItem>
                <NFormItem v-else :label="$t('dataprotector.policy.network.remoteIp')" path="remoteAddress">
                  <NInput
                    v-model:value="networkForm.remoteAddress"
                    :placeholder="
                      networkForm.protocol === 'icmp'
                        ? $t('dataprotector.policy.network.allPingTargets')
                        : $t('dataprotector.policy.network.cidrPlaceholder')
                    "
                  />
                </NFormItem>
                <NGrid :x-gap="12" :y-gap="0" cols="2">
                  <NGi>
                    <NFormItem :label="$t('dataprotector.policy.network.protocol')" path="protocol">
                      <NSelect v-model:value="networkForm.protocol" :options="networkProtocolOptions" />
                    </NFormItem>
                  </NGi>
                  <NGi>
                    <NFormItem :label="$t('dataprotector.policy.network.direction')" path="direction">
                      <NSelect v-model:value="networkForm.direction" :options="networkDirectionOptions" />
                    </NFormItem>
                  </NGi>
                </NGrid>
                <NGrid :x-gap="12" :y-gap="0" cols="2">
                  <NGi>
                    <NFormItem :label="$t('dataprotector.policy.network.localPort')">
                      <NInputNumber v-model:value="networkForm.localPort" :min="0" :max="65535" class="w-full" />
                    </NFormItem>
                  </NGi>
                  <NGi>
                    <NFormItem :label="$t('dataprotector.policy.network.remotePort')">
                      <NInputNumber v-model:value="networkForm.remotePort" :min="0" :max="65535" class="w-full" />
                    </NFormItem>
                  </NGi>
                </NGrid>
                <NButton block type="primary" :loading="networkSubmitting" @click="addNetworkRule">
                  <template #icon><SvgIcon icon="mdi:shield-plus-outline" /></template>
                  {{ $t('dataprotector.policy.network.addButton') }}
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.network.inventory')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">{{ $t('dataprotector.policy.network.domains') }}: {{ networkGroups.domain }}</NTag>
                  <NTag type="warning">{{ $t('dataprotector.policy.network.ip') }}: {{ networkGroups.ip }}</NTag>
                  <NTag type="error">ICMP: {{ networkGroups.icmp }}</NTag>
                  <NTag type="error">{{ $t('dataprotector.common.blocked') }}: {{ networkGroups.blocked }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearNetworkRules">{{ $t('dataprotector.common.clear') }}</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="networkColumns" :data="networkRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="lateral" :tab="$t('dataprotector.policy.tabs.lateral')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.lateral.title')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NTag :type="lateralDefensePolicy.enabled ? 'success' : 'error'" :bordered="false">
                  {{ lateralDefenseGroups.mode }}
                </NTag>
              </template>

              <NSpace vertical :size="18">
                <div class="flex items-center justify-between gap-16px rounded-8px bg-gray-50 p-14px dark:bg-dark-3">
                  <div class="min-w-0">
                    <div class="text-15px font-700">{{ $t('dataprotector.policy.lateral.enforcement') }}</div>
                    <div class="m-t-4px text-12px text-gray-500">{{ $t('dataprotector.policy.lateral.enforcementDesc') }}</div>
                  </div>
                  <NSwitch :value="lateralDefensePolicy.enabled" @update:value="setLateralDefenseEnabled">
                    <template #checked>{{ $t('dataprotector.common.enabled') }}</template>
                    <template #unchecked>{{ $t('dataprotector.common.disabled') }}</template>
                  </NSwitch>
                </div>

                <NGrid :x-gap="12" :y-gap="12" cols="1 m:2">
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.lateral.smbCopy') }}</div>
                        <NSwitch
                          :value="lateralDefensePolicy.blockSmbExecutableCopy"
                          :disabled="!lateralDefensePolicy.enabled"
                          @update:value="value => setLateralDefenseFeature('blockSmbExecutableCopy', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.lateral.smbCopyDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.lateral.ipcTasks') }}</div>
                        <NSwitch
                          :value="lateralDefensePolicy.blockIpcScheduledTasks"
                          :disabled="!lateralDefensePolicy.enabled"
                          @update:value="value => setLateralDefenseFeature('blockIpcScheduledTasks', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.lateral.ipcTasksDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.lateral.ipcServices') }}</div>
                        <NSwitch
                          :value="lateralDefensePolicy.blockIpcServiceCreation"
                          :disabled="!lateralDefensePolicy.enabled"
                          @update:value="value => setLateralDefenseFeature('blockIpcServiceCreation', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.lateral.ipcServicesDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.lateral.remoteTools') }}</div>
                        <NSwitch
                          :value="lateralDefensePolicy.blockRemoteAdminTools"
                          :disabled="!lateralDefensePolicy.enabled"
                          @update:value="value => setLateralDefenseFeature('blockRemoteAdminTools', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.lateral.remoteToolsDesc') }}</div>
                    </div>
                  </NGi>
                </NGrid>

                <div class="flex flex-wrap items-center justify-between gap-12px">
                  <NSpace>
                    <NTag type="info">{{ $t('dataprotector.policy.lateral.controls', { count: lateralDefenseGroups.enabledFeatures }) }}</NTag>
                    <NTag type="warning">{{ $t('dataprotector.policy.lateral.flags', { flags: lateralDefenseGroups.flags }) }}</NTag>
                    <NTag :type="lateralDefensePolicy.enabled ? 'success' : 'default'">
                      {{ $t('dataprotector.policy.lateral.active', { count: lateralDefenseGroups.activeControls }) }}
                    </NTag>
                  </NSpace>
                  <NButton type="primary" :loading="lateralDefenseSubmitting" @click="saveLateralDefensePolicy">
                    <template #icon><SvgIcon icon="mdi:content-save-cog-outline" /></template>
                    {{ $t('dataprotector.policy.lateral.save') }}
                  </NButton>
                </div>
              </NSpace>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.lateral.surfaces')" :bordered="false" class="card-wrapper">
              <NGrid :x-gap="12" :y-gap="12" cols="1 l:2 xl:4">
                <NGi v-for="control in lateralDefenseControls" :key="control.key">
                  <div class="h-full rounded-8px border border-gray-200 p-16px dark:border-gray-700">
                    <div class="flex items-start justify-between gap-12px">
                      <div class="flex min-w-0 items-center gap-10px">
                        <SvgIcon :icon="control.icon" class="text-22px text-primary" />
                        <div class="min-w-0">
                          <div class="truncate text-15px font-700">{{ control.title }}</div>
                          <div class="m-t-6px text-12px leading-5 text-gray-500">{{ control.detail }}</div>
                        </div>
                      </div>
                      <NTag :type="control.enabled ? 'success' : 'default'" :bordered="false">
                        {{ control.enabled ? $t('dataprotector.common.active') : $t('dataprotector.common.inactiveState') }}
                      </NTag>
                    </div>
                  </div>
                </NGi>
              </NGrid>
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="webshell" :tab="$t('dataprotector.policy.tabs.webshell')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.webshell.addTitle')" :bordered="false" class="card-wrapper">
              <NForm ref="webShellFormRef" :model="webShellForm" :rules="webShellFormRules" label-placement="top">
                <NFormItem :label="$t('dataprotector.policy.webshell.webRoot')" path="directory">
                  <NInput v-model:value="webShellForm.directory" placeholder="C:\\inetpub\\wwwroot" />
                </NFormItem>
                <NButton block type="primary" :loading="webShellSubmitting" @click="addWebShellRule">
                  <template #icon><SvgIcon icon="mdi:shield-bug-outline" /></template>
                  {{ $t('dataprotector.policy.webshell.addButton') }}
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.webshell.inventory')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="warning">{{ $t('dataprotector.policy.webshell.directories') }}: {{ webShellGroups.directories }}</NTag>
                  <NTag type="error">{{ $t('dataprotector.policy.webshell.dangerEnabled') }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearWebShellRules">{{ $t('dataprotector.common.clear') }}</NButton>
                </NSpace>
              </template>
              <NDataTable :columns="webShellColumns" :data="webShellRules" :loading="loading" :pagination="{ pageSize: 10 }" />
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="hashprotect" :tab="$t('dataprotector.policy.tabs.hashprotect')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.hashprotect.title')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NTag :type="hashProtectPolicy.enabled ? 'success' : 'error'" :bordered="false">
                  {{ hashProtectGroups.mode }}
                </NTag>
              </template>

              <NSpace vertical :size="18">
                <div class="flex items-center justify-between gap-16px rounded-8px bg-gray-50 p-14px dark:bg-dark-3">
                  <div class="min-w-0">
                    <div class="text-15px font-700">{{ $t('dataprotector.policy.hashprotect.enforcement') }}</div>
                    <div class="m-t-4px text-12px text-gray-500">{{ $t('dataprotector.policy.hashprotect.enforcementDesc') }}</div>
                  </div>
                  <NSwitch :value="hashProtectPolicy.enabled" @update:value="setHashProtectEnabled">
                    <template #checked>{{ $t('dataprotector.common.enabled') }}</template>
                    <template #unchecked>{{ $t('dataprotector.common.disabled') }}</template>
                  </NSwitch>
                </div>

                <NGrid :x-gap="12" :y-gap="12" cols="1 m:2 xl:4">
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.hashprotect.lsass') }}</div>
                        <NSwitch
                          :value="hashProtectPolicy.protectLsass"
                          :disabled="!hashProtectPolicy.enabled"
                          @update:value="value => setHashProtectFeature('protectLsass', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.hashprotect.lsassDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.hashprotect.credentialFiles') }}</div>
                        <NSwitch
                          :value="hashProtectPolicy.protectCredentialFiles"
                          :disabled="!hashProtectPolicy.enabled"
                          @update:value="value => setHashProtectFeature('protectCredentialFiles', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.hashprotect.credentialFilesDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.hashprotect.registryHives') }}</div>
                        <NSwitch
                          :value="hashProtectPolicy.protectRegistryHives"
                          :disabled="!hashProtectPolicy.enabled"
                          @update:value="value => setHashProtectFeature('protectRegistryHives', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.hashprotect.registryHivesDesc') }}</div>
                    </div>
                  </NGi>
                  <NGi>
                    <div class="rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                      <div class="flex items-center justify-between gap-10px">
                        <div class="font-700">{{ $t('dataprotector.policy.hashprotect.rawExtents') }}</div>
                        <NSwitch
                          :value="hashProtectPolicy.protectRawExtents"
                          :disabled="!hashProtectPolicy.enabled"
                          @update:value="value => setHashProtectFeature('protectRawExtents', value)"
                        />
                      </div>
                      <div class="m-t-6px text-12px text-gray-500">{{ $t('dataprotector.policy.hashprotect.rawExtentsDesc') }}</div>
                    </div>
                  </NGi>
                </NGrid>

                <div class="flex flex-wrap items-center justify-between gap-12px">
                  <NSpace>
                    <NTag type="info">{{ $t('dataprotector.policy.hashprotect.features', { count: hashProtectGroups.enabledFeatures }) }}</NTag>
                    <NTag type="warning">{{ $t('dataprotector.policy.lateral.flags', { flags: hashProtectGroups.flags }) }}</NTag>
                    <NTag :type="hashProtectPolicy.enabled ? 'success' : 'default'">
                      {{ $t('dataprotector.policy.hashprotect.assets', { count: hashProtectGroups.protectedAssets }) }}
                    </NTag>
                  </NSpace>
                  <NButton type="primary" :loading="hashProtectSubmitting" @click="saveHashProtectPolicy">
                    <template #icon><SvgIcon icon="mdi:content-save-shield-outline" /></template>
                    {{ $t('dataprotector.policy.hashprotect.save') }}
                  </NButton>
                </div>
              </NSpace>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.hashprotect.surfaces')" :bordered="false" class="card-wrapper">
              <NGrid :x-gap="12" :y-gap="12" cols="1 l:2 xl:4">
                <NGi v-for="asset in hashProtectAssets" :key="asset.key">
                  <div class="h-full rounded-8px border border-gray-200 p-16px dark:border-gray-700">
                    <div class="flex items-start justify-between gap-12px">
                      <div class="flex min-w-0 items-center gap-10px">
                        <SvgIcon :icon="asset.icon" class="text-22px text-primary" />
                        <div class="min-w-0">
                          <div class="truncate text-15px font-700">{{ asset.title }}</div>
                          <div class="m-t-6px text-12px leading-5 text-gray-500">{{ asset.detail }}</div>
                        </div>
                      </div>
                      <NTag :type="asset.enabled ? 'success' : 'default'" :bordered="false">
                        {{ asset.enabled ? $t('dataprotector.common.active') : $t('dataprotector.common.inactiveState') }}
                      </NTag>
                    </div>
                  </div>
                </NGi>
              </NGrid>
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="device" :tab="$t('dataprotector.policy.tabs.device')">
        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24">
            <NCard :title="$t('dataprotector.policy.usbcrypt.title')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag :type="usbCryptPolicy.enabled ? 'success' : 'default'" :bordered="false">
                    {{ usbCryptGroups.mode }}
                  </NTag>
                  <NTag type="info" :bordered="false">{{ usbCryptGroups.algorithm }}</NTag>
                  <NTag type="warning" :bordered="false">
                    {{ $t('dataprotector.policy.usbcrypt.toolArea', { size: usbCryptGroups.toolAreaMb }) }}
                  </NTag>
                </NSpace>
              </template>

              <NGrid :x-gap="16" :y-gap="12" cols="1 m:2 xl:4">
                <NGi>
                  <div class="h-full rounded-8px border border-gray-200 p-14px dark:border-gray-700">
                    <div class="flex items-center justify-between gap-12px">
                      <div class="min-w-0">
                        <div class="text-14px font-700">{{ $t('dataprotector.policy.usbcrypt.enforcement') }}</div>
                        <div class="m-t-4px text-12px text-gray-500">{{ $t('dataprotector.policy.usbcrypt.enforcementDesc') }}</div>
                      </div>
                      <NSwitch v-model:value="usbCryptPolicy.enabled">
                        <template #checked>{{ $t('dataprotector.common.enabled') }}</template>
                        <template #unchecked>{{ $t('dataprotector.common.disabled') }}</template>
                      </NSwitch>
                    </div>
                  </div>
                </NGi>
                <NGi>
                  <NFormItem :label="$t('dataprotector.policy.usbcrypt.keyMaterial')">
                    <NInput
                      v-model:value="usbCryptPolicy.keyMaterialId"
                      clearable
                      :placeholder="$t('dataprotector.policy.usbcrypt.keyPlaceholder')"
                    />
                  </NFormItem>
                </NGi>
                <NGi>
                  <NFormItem :label="$t('dataprotector.policy.usbcrypt.publicAreaMb')">
                    <NInputNumber
                      :value="Math.round(usbCryptPolicy.publicToolAreaBytes / 1024 / 1024)"
                      :min="5"
                      :max="128"
                      class="w-full"
                      @update:value="value => (usbCryptPolicy.publicToolAreaBytes = Math.max(5, value || 5) * 1024 * 1024)"
                    />
                  </NFormItem>
                </NGi>
                <NGi>
                  <NSpace vertical :size="10">
                    <NCheckbox v-model:checked="usbCryptPolicy.requireHardwareAuthorization">
                      {{ $t('dataprotector.policy.usbcrypt.requireAuthorization') }}
                    </NCheckbox>
                    <NCheckbox v-model:checked="usbCryptPolicy.allowClientProvisioning">
                      {{ $t('dataprotector.policy.usbcrypt.allowProvisioning') }}
                    </NCheckbox>
                  </NSpace>
                </NGi>
              </NGrid>

              <div class="m-t-12px flex flex-wrap items-center justify-between gap-12px">
                <NSpace>
                  <NTag type="info">{{ $t('dataprotector.policy.usbcrypt.algorithm') }}: RC4</NTag>
                  <NTag :type="usbCryptPolicy.allowClientProvisioning ? 'warning' : 'default'">
                    {{ $t('dataprotector.policy.usbcrypt.provisioning') }}: {{ usbCryptGroups.provisioning }}
                  </NTag>
                </NSpace>
                <NButton type="primary" :loading="usbCryptSubmitting" @click="saveUsbCryptPolicy">
                  <template #icon><SvgIcon icon="mdi:usb-flash-drive-outline" /></template>
                  {{ $t('dataprotector.policy.usbcrypt.save') }}
                </NButton>
              </div>
            </NCard>
          </NGi>

          <NGi span="24">
            <NCard :title="$t('dataprotector.policy.device.discovered')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="warning">{{ $t('dataprotector.policy.device.pending') }}: {{ deviceGroups.pendingHardware }}</NTag>
                  <NTag type="success">{{ $t('dataprotector.policy.device.authorized') }}: {{ deviceGroups.authorizedHardware }}</NTag>
                  <NTag type="error">{{ $t('dataprotector.policy.device.blocked') }}: {{ deviceGroups.blockedHardware }}</NTag>
                </NSpace>
              </template>
              <NDataTable
                :columns="removableDeviceColumns"
                :data="removableDevices"
                :loading="loading || deviceSubmitting"
                :pagination="{ pageSize: 8 }"
                :scroll-x="1540"
              />
            </NCard>
          </NGi>

          <NGi span="24 m:8">
            <NCard :title="$t('dataprotector.policy.device.addTitle')" :bordered="false" class="card-wrapper">
              <NForm ref="deviceFormRef" :model="deviceForm" :rules="deviceFormRules" label-placement="top">
                <NFormItem :label="$t('dataprotector.policy.device.deviceId')" path="deviceId">
                  <NInput v-model:value="deviceForm.deviceId" placeholder="* or \\?\\Volume{...}" />
                </NFormItem>
                <NFormItem :label="$t('dataprotector.policy.device.insertionAccess')">
                  <NSwitch :value="deviceForm.allowInsert" @update:value="setDeviceInsert">
                    <template #checked>{{ $t('dataprotector.policy.device.allowed') }}</template>
                    <template #unchecked>{{ $t('dataprotector.common.blocked') }}</template>
                  </NSwitch>
                </NFormItem>
                <NFormItem :label="$t('dataprotector.policy.device.writeAccess')">
                  <NSwitch v-model:value="deviceForm.allowWrite" :disabled="!deviceForm.allowInsert">
                    <template #checked>{{ $t('dataprotector.common.writable') }}</template>
                    <template #unchecked>{{ $t('dataprotector.common.readOnly') }}</template>
                  </NSwitch>
                </NFormItem>
                <NButton block type="primary" :loading="deviceSubmitting" @click="addDeviceRule">
                  <template #icon><SvgIcon icon="mdi:usb-flash-drive-outline" /></template>
                  {{ $t('dataprotector.policy.device.addButton') }}
                </NButton>
              </NForm>
            </NCard>
          </NGi>

          <NGi span="24 m:16">
            <NCard :title="$t('dataprotector.policy.device.inventory')" :bordered="false" class="card-wrapper">
              <template #header-extra>
                <NSpace>
                  <NTag type="info">{{ $t('dataprotector.policy.device.rules') }}: {{ deviceGroups.total }}</NTag>
                  <NTag type="error">{{ $t('dataprotector.common.blocked') }}: {{ deviceGroups.blockedInsert }}</NTag>
                  <NTag type="warning">{{ $t('dataprotector.common.readOnly') }}: {{ deviceGroups.readOnly }}</NTag>
                  <NTag type="success">{{ $t('dataprotector.common.writable') }}: {{ deviceGroups.writable }}</NTag>
                  <NButton size="small" type="error" secondary @click="clearDeviceRules">{{ $t('dataprotector.common.clear') }}</NButton>
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
