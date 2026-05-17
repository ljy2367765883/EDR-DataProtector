<script setup lang="ts">
import { computed, h, nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { Icon } from '@iconify/vue';
import { NButton, NTag, type DataTableColumns } from 'naive-ui';
import { fetchCreateRemoteTask, fetchDevices, fetchRemoteTasks } from '@/service/api';
import { $t } from '@/locales';

defineOptions({
  name: 'RemoteOps'
});

type WorkbenchTab = 'files' | 'processes' | 'apps' | 'startup' | 'shell' | 'desktop' | 'accounts';

type InstalledApp = {
  displayName: string;
  displayVersion: string;
  publisher: string;
  installLocation: string;
  uninstallString: string;
  displayIcon: string;
  iconBase64: string;
};

type StartupItem = {
  location: string;
  name: string;
  command: string;
  enabled: boolean;
};

type DriveItem = {
  name: string;
  path: string;
  driveType: string;
  volumeLabel: string;
  fileSystem: string;
  isReady: boolean;
  totalSize: number;
  freeSpace: number;
};

type FileItem = {
  name: string;
  path: string;
  isDirectory: boolean;
  size: number;
  lastWriteUtc: string;
};

type ProcessItem = {
  pid: number;
  name: string;
  path: string;
  user: string;
  memoryBytes: number;
  startTimeUtc: string;
};

type TerminalSnapshot = {
  running: boolean;
  sequence: number;
  output: string;
};

const devices = ref<Api.DataProtector.Device[]>([]);
const selectedDeviceId = ref('');
const activeTab = ref<WorkbenchTab>('files');
const loadingDevices = ref(false);
const panelLoading = ref(false);
const activity = ref<string[]>([]);

const drives = ref<DriveItem[]>([]);
const currentPath = ref('');
const pathInput = ref('');
const fileItems = ref<FileItem[]>([]);
const renameVisible = ref(false);
const renameName = ref('');
const renameTarget = ref<FileItem | null>(null);
const fileContext = reactive({
  show: false,
  x: 0,
  y: 0,
  row: null as FileItem | null
});

const processes = ref<ProcessItem[]>([]);
const processSearch = ref('');
const processContext = reactive({
  show: false,
  x: 0,
  y: 0,
  row: null as ProcessItem | null
});
const apps = ref<InstalledApp[]>([]);
const startupItems = ref<StartupItem[]>([]);
const terminalInput = ref('');
const terminalOutput = ref('');
const terminalRunning = ref(false);
const terminalPolling = ref<number | null>(null);
const terminalReadPending = ref(false);
const terminalRef = ref<HTMLElement | null>(null);
const terminalAutoFollow = ref(true);
const screenshotSrc = ref('');
const screenshotError = ref('');
const accountForm = reactive({
  username: '',
  newPassword: ''
});

const selectedDevice = computed(() => devices.value.find(device => device.deviceId === selectedDeviceId.value) || null);
const onlineDevices = computed(() => devices.value.filter(device => device.online).length);
const filteredProcesses = computed(() => {
  const keyword = processSearch.value.trim().toLowerCase();
  if (!keyword) return processes.value;
  return processes.value.filter(item =>
    `${item.pid} ${item.name} ${item.path} ${item.user}`.toLowerCase().includes(keyword)
  );
});

const fileMenuOptions = computed(() => [
  {
    label: $t('dataprotector.common.open'),
    key: 'open',
    disabled: !fileContext.row?.isDirectory
  },
  {
    label: $t('dataprotector.common.rename'),
    key: 'rename'
  },
  {
    label: $t('dataprotector.common.delete'),
    key: 'delete'
  }
]);

const processMenuOptions = computed(() => [
  {
    label: $t('dataprotector.remote.processes.terminate'),
    key: 'terminate',
    disabled: !processContext.row
  }
]);

const fileColumns = computed<DataTableColumns<FileItem>>(() => [
  {
    title: $t('dataprotector.remote.columns.name'),
    key: 'name',
    minWidth: 260,
    ellipsis: { tooltip: true },
    render(row) {
      return h('div', { class: 'manager-name-cell' }, [
        h(Icon, {
          icon: row.isDirectory ? 'mdi:folder' : 'mdi:file-document-outline',
          class: row.isDirectory ? 'manager-icon manager-icon-folder' : 'manager-icon'
        }),
        h('span', row.name)
      ]);
    }
  },
  {
    title: $t('dataprotector.remote.columns.type'),
    key: 'isDirectory',
    width: 110,
    render(row) {
      return row.isDirectory ? $t('dataprotector.remote.columns.folder') : $t('dataprotector.remote.columns.file');
    }
  },
  {
    title: $t('dataprotector.remote.columns.size'),
    key: 'size',
    width: 130,
    render(row) {
      return row.isDirectory ? '-' : formatBytes(row.size);
    }
  },
  {
    title: $t('dataprotector.remote.columns.modified'),
    key: 'lastWriteUtc',
    width: 190,
    render(row) {
      return formatTime(row.lastWriteUtc);
    }
  }
]);

const processColumns = computed<DataTableColumns<ProcessItem>>(() => [
  { title: 'PID', key: 'pid', width: 100, sorter: 'default' },
  {
    title: $t('dataprotector.remote.columns.process'),
    key: 'name',
    minWidth: 220,
    sorter: 'default',
    render(row) {
      return h('div', { class: 'manager-name-cell' }, [
        h(Icon, { icon: 'mdi:application-cog-outline', class: 'manager-icon manager-icon-process' }),
        h('span', row.name)
      ]);
    }
  },
  {
    title: $t('dataprotector.remote.columns.memory'),
    key: 'memoryBytes',
    width: 130,
    sorter: (a, b) => a.memoryBytes - b.memoryBytes,
    render(row) {
      return formatBytes(row.memoryBytes);
    }
  },
  {
    title: $t('dataprotector.remote.columns.started'),
    key: 'startTimeUtc',
    width: 190,
    render(row) {
      return formatTime(row.startTimeUtc);
    }
  },
  { title: $t('dataprotector.remote.columns.path'), key: 'path', minWidth: 360, ellipsis: { tooltip: true } }
]);

const startupColumns = computed<DataTableColumns<StartupItem>>(() => [
  { title: $t('dataprotector.remote.columns.location'), key: 'location', width: 180 },
  { title: $t('dataprotector.remote.columns.name'), key: 'name', width: 220, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.remote.columns.command'), key: 'command', minWidth: 520, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.remote.columns.state'),
    key: 'enabled',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.enabled ? 'success' : 'default', bordered: false },
        { default: () => (row.enabled ? $t('dataprotector.common.enabled') : $t('dataprotector.common.disabled')) }
      );
    }
  }
]);

async function refreshDevices() {
  loadingDevices.value = true;
  try {
    const { error, data } = await fetchDevices();
    if (!error) {
      devices.value = data;
      if (!selectedDeviceId.value && data.length) {
        selectedDeviceId.value = data[0].deviceId;
      }
    }
  } finally {
    loadingDevices.value = false;
  }
}

async function selectDevice(deviceId: string) {
  if (selectedDeviceId.value === deviceId) return;
  selectedDeviceId.value = deviceId;
  resetPanelState();
}

function resetPanelState() {
  drives.value = [];
  fileItems.value = [];
  currentPath.value = '';
  pathInput.value = '';
  processes.value = [];
  apps.value = [];
  startupItems.value = [];
  terminalInput.value = '';
  terminalOutput.value = '';
  terminalRunning.value = false;
  terminalAutoFollow.value = true;
  stopTerminalPolling();
  screenshotSrc.value = '';
}

async function refreshActivePanel() {
  if (!selectedDevice.value) return;

  if (activeTab.value === 'files') {
    if (currentPath.value) {
      await openPath(currentPath.value);
    } else {
      await loadDrives();
    }
    return;
  }

  if (activeTab.value === 'processes') {
    await loadProcesses();
    return;
  }

  if (activeTab.value === 'apps') {
    await loadApps();
    return;
  }

  if (activeTab.value === 'startup') {
    await loadStartupItems();
    return;
  }

  if (activeTab.value === 'desktop') {
    await captureScreenshot();
  }
}

async function handleTabChange(value: string) {
  activeTab.value = value as WorkbenchTab;
}

async function loadDrives() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('file.drives', {});
    drives.value = parseJson<DriveItem[]>(task.output, []);
    currentPath.value = '';
    pathInput.value = '';
    fileItems.value = [];
  } finally {
    panelLoading.value = false;
  }
}

async function openPath(path: string) {
  if (!path) return;
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('file.list', { path, limit: 500 });
    fileItems.value = parseJson<FileItem[]>(task.output, []);
    currentPath.value = path;
    pathInput.value = path;
  } finally {
    panelLoading.value = false;
  }
}

async function goToPath() {
  await openPath(pathInput.value.trim());
}

async function goUp() {
  const parent = parentPath(currentPath.value);
  if (parent) {
    await openPath(parent);
  } else {
    await loadDrives();
  }
}

function fileRowProps(row: FileItem) {
  return {
    onDblclick: () => {
      if (row.isDirectory) {
        openPath(row.path);
      }
    },
    onContextmenu: (event: MouseEvent) => {
      event.preventDefault();
      fileContext.row = row;
      fileContext.x = event.clientX;
      fileContext.y = event.clientY;
      fileContext.show = true;
    }
  };
}

function processRowProps(row: ProcessItem) {
  return {
    onContextmenu: (event: MouseEvent) => {
      event.preventDefault();
      processContext.row = row;
      processContext.x = event.clientX;
      processContext.y = event.clientY;
      processContext.show = true;
    }
  };
}

function handleFileMenuSelect(key: string) {
  const row = fileContext.row;
  fileContext.show = false;
  if (!row) return;

  if (key === 'open' && row.isDirectory) {
    openPath(row.path);
  } else if (key === 'rename') {
    showRename(row);
  } else if (key === 'delete') {
    confirmDelete(row);
  }
}

function handleProcessMenuSelect(key: string) {
  const row = processContext.row;
  processContext.show = false;
  if (!row) return;

  if (key === 'terminate') {
    confirmKillProcess(row);
  }
}

function showRename(row: FileItem) {
  renameTarget.value = row;
  renameName.value = row.name;
  renameVisible.value = true;
}

async function submitRename() {
  if (!renameTarget.value) return;

  panelLoading.value = true;
  try {
    await runRemoteTask('file.rename', {
      path: renameTarget.value.path,
      newName: renameName.value
    });
    renameVisible.value = false;
    pushActivity($t('dataprotector.remote.activity.renamed', { name: renameTarget.value.name }));
    await openPath(currentPath.value);
  } finally {
    panelLoading.value = false;
  }
}

function confirmDelete(row: FileItem) {
  window.$dialog?.warning({
    title: $t('dataprotector.remote.files.deleteTitle'),
    content: $t('dataprotector.remote.files.deleteContent', { path: row.path }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      panelLoading.value = true;
      try {
        await runRemoteTask('file.delete', { path: row.path });
        pushActivity($t('dataprotector.remote.activity.deleted', { name: row.name }));
        await openPath(currentPath.value);
      } finally {
        panelLoading.value = false;
      }
    }
  });
}

async function loadProcesses() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('process.list', {});
    processes.value = parseJson<ProcessItem[]>(task.output, []);
  } finally {
    panelLoading.value = false;
  }
}

function confirmKillProcess(row: ProcessItem) {
  window.$dialog?.warning({
    title: $t('dataprotector.remote.processes.terminateTitle'),
    content: $t('dataprotector.remote.processes.terminateContent', {
      name: row.name,
      pid: row.pid,
      target: selectedDevice.value?.machine || selectedDeviceId.value
    }),
    positiveText: $t('dataprotector.remote.processes.terminate'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      panelLoading.value = true;
      try {
        await runRemoteTask('process.kill', { pid: row.pid });
        pushActivity($t('dataprotector.remote.activity.terminated', { name: row.name, pid: row.pid }));
        await loadProcesses();
      } finally {
        panelLoading.value = false;
      }
    }
  });
}

async function loadApps() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('inventory.installedApps', {});
    apps.value = parseJson<InstalledApp[]>(task.output, []);
  } finally {
    panelLoading.value = false;
  }
}

async function loadStartupItems() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('inventory.startupItems', {});
    startupItems.value = parseJson<StartupItem[]>(task.output, []);
  } finally {
    panelLoading.value = false;
  }
}

async function startTerminal() {
  panelLoading.value = true;
  try {
    terminalAutoFollow.value = true;
    const task = await runRemoteTask('terminal.start', {});
    applyTerminalSnapshot(task.output);
    startTerminalPolling();
  } finally {
    panelLoading.value = false;
  }
}

async function sendTerminalInput() {
  const input = terminalInput.value;
  if (!input.trim()) return;

  terminalInput.value = '';
  try {
    terminalAutoFollow.value = true;
    const task = await runRemoteTask('terminal.input', { input });
    applyTerminalSnapshot(task.output);
    startTerminalPolling();
  } finally {
    if (terminalAutoFollow.value) {
      await scrollTerminalToBottom();
    }
  }
}

async function readTerminal() {
  if (!selectedDevice.value || !terminalRunning.value || terminalReadPending.value) return;

  terminalReadPending.value = true;
  try {
    terminalAutoFollow.value = terminalAutoFollow.value && isTerminalNearBottom();
    const task = await runRemoteTask('terminal.read', {}, false);
    applyTerminalSnapshot(task.output);
  } catch {
    stopTerminalPolling();
  } finally {
    terminalReadPending.value = false;
  }
}

async function stopTerminal() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('terminal.stop', {});
    applyTerminalSnapshot(task.output);
    stopTerminalPolling();
  } finally {
    panelLoading.value = false;
  }
}

function applyTerminalSnapshot(value: string) {
  const snapshot = parseJson<TerminalSnapshot>(value, { running: false, sequence: 0, output: value || '' });
  terminalRunning.value = snapshot.running;
  terminalOutput.value = snapshot.output || terminalOutput.value;
  if (terminalAutoFollow.value) {
    scrollTerminalToBottom();
  }
}

function startTerminalPolling() {
  if (terminalPolling.value !== null) return;
  terminalPolling.value = window.setInterval(() => {
    readTerminal();
  }, 1200);
}

function stopTerminalPolling() {
  if (terminalPolling.value === null) return;
  window.clearInterval(terminalPolling.value);
  terminalPolling.value = null;
}

async function scrollTerminalToBottom() {
  await nextTick();
  if (terminalRef.value) {
    terminalRef.value.scrollTop = terminalRef.value.scrollHeight;
  }
}

function isTerminalNearBottom() {
  const element = terminalRef.value;
  if (!element) return true;
  const distance = element.scrollHeight - element.scrollTop - element.clientHeight;
  return distance < 48;
}

function handleTerminalScroll() {
  terminalAutoFollow.value = isTerminalNearBottom();
}

async function captureScreenshot() {
  panelLoading.value = true;
  try {
    const task = await runRemoteTask('desktop.screenshot', {});
    screenshotError.value = '';
    screenshotSrc.value = normalizePngDataUrl(task.output);
    if (!screenshotSrc.value) {
      screenshotError.value = $t('dataprotector.remote.desktop.invalidScreenshot');
      window.$message?.error(screenshotError.value);
    }
  } finally {
    panelLoading.value = false;
  }
}

async function changePassword() {
  panelLoading.value = true;
  try {
    await runRemoteTask('user.changePassword', {
      username: accountForm.username,
      newPassword: accountForm.newPassword
    });
    pushActivity($t('dataprotector.remote.activity.passwordChanged', { username: accountForm.username }));
    window.$message?.success($t('dataprotector.remote.accounts.passwordChanged'));
  } finally {
    panelLoading.value = false;
  }
}

async function lockScreen() {
  panelLoading.value = true;
  try {
    await runRemoteTask('session.lock', {});
    pushActivity($t('dataprotector.remote.activity.lockRequested'));
  } finally {
    panelLoading.value = false;
  }
}

async function runRemoteTask(kind: string, args: Record<string, unknown>, logActivity = true) {
  if (!selectedDevice.value) {
    throw new Error($t('dataprotector.remote.errors.selectEndpoint'));
  }

  const createResult = await fetchCreateRemoteTask({
    deviceId: selectedDevice.value.deviceId,
    kind,
    argumentsJson: JSON.stringify(args || {}),
    actor: 'web-admin'
  });

  if (createResult.error) {
    throw new Error($t('dataprotector.remote.errors.queueFailed'));
  }

  const taskId = createResult.data.taskId;
  if (logActivity) {
    pushActivity($t('dataprotector.remote.activity.queued', { operation: operationLabel(kind) }));
  }

  for (let attempt = 0; attempt < 40; attempt += 1) {
    await sleep(1000);
    const tasksResult = await fetchRemoteTasks({ deviceId: selectedDevice.value.deviceId, limit: 100 });
    if (tasksResult.error) continue;

    const task = tasksResult.data.find(item => item.taskId === taskId);
    if (!task) continue;

    if (task.status === 'completed' || task.status === 'failed') {
      if (task.status === 'completed' && task.succeeded) {
        if (logActivity) {
          pushActivity($t('dataprotector.remote.activity.completed', { operation: operationLabel(kind) }));
        }
        return task;
      }

      throw new Error(task.error || task.output || $t('dataprotector.remote.errors.operationFailed', { operation: operationLabel(kind) }));
    }
  }

  throw new Error($t('dataprotector.remote.errors.timeout', { operation: operationLabel(kind) }));
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function normalizePngDataUrl(value: string | undefined) {
  if (!value) return '';

  const trimmed = value.trim().replace(/^"|"$/g, '');
  const base64 = trimmed.startsWith('data:image/png;base64,') ? trimmed.slice('data:image/png;base64,'.length) : trimmed;
  const compact = base64.replace(/\s+/g, '');

  if (!compact || compact.includes('[truncated]')) return '';
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return '';
  if (compact.length % 4 !== 0) return '';

  return `data:image/png;base64,${compact}`;
}

function pushActivity(message: string) {
  activity.value = [`${new Date().toLocaleTimeString()} ${message}`, ...activity.value].slice(0, 8);
}

function operationLabel(kind: string) {
  const labels: Record<string, string> = {
    'file.drives': $t('dataprotector.remote.operations.file.drives'),
    'file.list': $t('dataprotector.remote.operations.file.list'),
    'file.delete': $t('dataprotector.remote.operations.file.delete'),
    'file.rename': $t('dataprotector.remote.operations.file.rename'),
    'process.list': $t('dataprotector.remote.operations.process.list'),
    'process.kill': $t('dataprotector.remote.operations.process.kill'),
    'inventory.installedApps': $t('dataprotector.remote.operations.inventory.installedApps'),
    'inventory.startupItems': $t('dataprotector.remote.operations.inventory.startupItems'),
    'cmd.run': $t('dataprotector.remote.operations.cmd.run'),
    'terminal.start': $t('dataprotector.remote.operations.terminal.start'),
    'terminal.input': $t('dataprotector.remote.operations.terminal.input'),
    'terminal.read': $t('dataprotector.remote.operations.terminal.read'),
    'terminal.stop': $t('dataprotector.remote.operations.terminal.stop'),
    'desktop.screenshot': $t('dataprotector.remote.operations.desktop.screenshot'),
    'session.lock': $t('dataprotector.remote.operations.session.lock'),
    'user.changePassword': $t('dataprotector.remote.operations.user.changePassword')
  };
  return labels[kind] || kind;
}

function parentPath(path: string) {
  const normalized = path.replace(/[\\/]+$/, '');
  if (!normalized || /^[A-Za-z]:$/.test(normalized)) return '';
  const lastSlash = Math.max(normalized.lastIndexOf('\\'), normalized.lastIndexOf('/'));
  if (lastSlash <= 2 && /^[A-Za-z]:/.test(normalized)) return `${normalized.slice(0, 2)}\\`;
  return lastSlash > 0 ? normalized.slice(0, lastSlash) : '';
}

function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString() : '-';
}

function formatBytes(value: number) {
  if (!Number.isFinite(value)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function sleep(ms: number) {
  return new Promise(resolve => {
    window.setTimeout(resolve, ms);
  });
}

onMounted(async () => {
  await refreshDevices();
});

onBeforeUnmount(() => {
  stopTerminalPolling();
});
</script>

<template>
  <div class="remote-workbench">
    <aside class="endpoint-pane">
      <div class="pane-header">
        <div>
          <div class="eyebrow">{{ $t('dataprotector.remote.endpoints') }}</div>
          <h2>{{ $t('dataprotector.remote.clients') }}</h2>
        </div>
        <NButton quaternary circle :loading="loadingDevices" @click="refreshDevices">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
        </NButton>
      </div>

      <div class="endpoint-summary">
        <NTag type="success" :bordered="false">{{ $t('dataprotector.remote.online', { count: onlineDevices }) }}</NTag>
        <span>{{ $t('dataprotector.remote.registered', { count: devices.length }) }}</span>
      </div>

      <div class="endpoint-list">
        <button
          v-for="device in devices"
          :key="device.deviceId"
          class="endpoint-item"
          :class="{ active: device.deviceId === selectedDeviceId }"
          type="button"
          @click="selectDevice(device.deviceId)"
        >
          <div class="endpoint-icon">
            <SvgIcon icon="mdi:desktop-tower-monitor" />
          </div>
          <div class="endpoint-meta">
            <div class="endpoint-name">{{ device.machine || device.deviceId }}</div>
            <div class="endpoint-sub">{{ device.user || '-' }} / {{ device.driverStatus || $t('dataprotector.remote.driverUnknown') }}</div>
          </div>
          <span class="status-dot" :class="{ online: device.online }"></span>
        </button>
        <NEmpty v-if="!devices.length" :description="$t('dataprotector.remote.noRegisteredEndpoints')" />
      </div>
    </aside>

    <main class="operation-pane">
      <NCard :bordered="false" class="selected-device-card">
        <div class="selected-device">
          <div>
            <div class="eyebrow">{{ $t('dataprotector.remote.remoteManagement') }}</div>
            <h1>{{ selectedDevice?.machine || $t('dataprotector.remote.selectEndpoint') }}</h1>
            <p v-if="selectedDevice">
              {{ selectedDevice.user || '-' }} / agent {{ selectedDevice.agentVersion || '-' }} /
              {{ selectedDevice.online ? $t('dataprotector.remote.status.online') : $t('dataprotector.remote.status.offline') }}
            </p>
          </div>
          <NSpace>
            <NButton secondary :disabled="!selectedDevice" @click="lockScreen">
              <template #icon><SvgIcon icon="mdi:lock" /></template>
              {{ $t('dataprotector.common.lock') }}
            </NButton>
            <NButton type="primary" :disabled="!selectedDevice" :loading="panelLoading" @click="refreshActivePanel">
              <template #icon><SvgIcon icon="mdi:refresh" /></template>
              {{ $t('dataprotector.common.refreshPanel') }}
            </NButton>
          </NSpace>
        </div>
      </NCard>

      <NCard :bordered="false" class="module-card">
        <NTabs :value="activeTab" type="line" animated @update:value="handleTabChange">
          <NTab name="files">{{ $t('dataprotector.remote.tabs.files') }}</NTab>
          <NTab name="processes">{{ $t('dataprotector.remote.tabs.processes') }}</NTab>
          <NTab name="apps">{{ $t('dataprotector.remote.tabs.apps') }}</NTab>
          <NTab name="startup">{{ $t('dataprotector.remote.tabs.startup') }}</NTab>
          <NTab name="shell">{{ $t('dataprotector.remote.tabs.shell') }}</NTab>
          <NTab name="desktop">{{ $t('dataprotector.remote.tabs.desktop') }}</NTab>
          <NTab name="accounts">{{ $t('dataprotector.remote.tabs.accounts') }}</NTab>
        </NTabs>

        <div class="module-body" :class="{ loading: panelLoading }">
          <template v-if="activeTab === 'files'">
            <div class="toolbar">
              <NInputGroup>
                <NButton secondary :disabled="!currentPath" @click="goUp">
                  <template #icon><SvgIcon icon="mdi:arrow-up" /></template>
                </NButton>
                <NInput v-model:value="pathInput" :placeholder="$t('dataprotector.remote.files.pathPlaceholder')" @keyup.enter="goToPath" />
                <NButton type="primary" :disabled="!pathInput" @click="goToPath">{{ $t('dataprotector.common.open') }}</NButton>
              </NInputGroup>
              <NButton type="primary" :loading="panelLoading" @click="refreshActivePanel">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                {{ $t('dataprotector.common.refresh') }}
              </NButton>
            </div>
            <div class="interaction-hint">{{ $t('dataprotector.remote.files.hint') }}</div>

            <div v-if="!currentPath" class="drive-grid">
              <button
                v-for="drive in drives"
                :key="drive.path"
                class="drive-tile"
                :disabled="!drive.isReady"
                type="button"
                @dblclick="openPath(drive.path)"
              >
                <SvgIcon icon="mdi:harddisk" />
                <div>
                  <div class="drive-name">{{ drive.name }} {{ drive.volumeLabel }}</div>
                  <div class="drive-sub">{{ drive.driveType }} / {{ drive.fileSystem || $t('dataprotector.remote.files.notReady') }}</div>
                  <div class="drive-sub">
                    {{ $t('dataprotector.remote.files.freeOf', { free: formatBytes(drive.freeSpace), total: formatBytes(drive.totalSize) }) }}
                  </div>
                </div>
              </button>
              <NEmpty v-if="!drives.length && !panelLoading" :description="$t('dataprotector.remote.files.noDrives')" />
            </div>

            <NDataTable
              v-else
              :columns="fileColumns"
              :data="fileItems"
              :loading="panelLoading"
              :row-props="fileRowProps"
              :scroll-x="900"
              :pagination="{ pageSize: 15 }"
            />

            <NDropdown
              trigger="manual"
              placement="bottom-start"
              :show="fileContext.show"
              :x="fileContext.x"
              :y="fileContext.y"
              :options="fileMenuOptions"
              @select="handleFileMenuSelect"
              @clickoutside="fileContext.show = false"
            />
          </template>

          <template v-else-if="activeTab === 'processes'">
            <div class="toolbar">
              <NInput v-model:value="processSearch" clearable :placeholder="$t('dataprotector.remote.processes.searchPlaceholder')" />
              <NButton type="primary" :loading="panelLoading" @click="loadProcesses">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                {{ $t('dataprotector.common.refresh') }}
              </NButton>
            </div>
            <div class="interaction-hint">{{ $t('dataprotector.remote.processes.hint') }}</div>
            <NDataTable
              :columns="processColumns"
              :data="filteredProcesses"
              :loading="panelLoading"
              :row-props="processRowProps"
              :scroll-x="1120"
              :pagination="{ pageSize: 15 }"
            />
            <NDropdown
              trigger="manual"
              placement="bottom-start"
              :show="processContext.show"
              :x="processContext.x"
              :y="processContext.y"
              :options="processMenuOptions"
              @select="handleProcessMenuSelect"
              @clickoutside="processContext.show = false"
            />
          </template>

          <template v-else-if="activeTab === 'apps'">
            <div class="toolbar">
              <div class="module-count">{{ $t('dataprotector.remote.apps.installed', { count: apps.length }) }}</div>
              <NButton type="primary" :loading="panelLoading" @click="loadApps">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                {{ $t('dataprotector.common.refresh') }}
              </NButton>
            </div>
            <div class="app-grid">
              <div v-for="app in apps" :key="`${app.displayName}-${app.displayVersion}-${app.publisher}`" class="app-tile">
                <NAvatar :src="app.iconBase64 ? `data:image/png;base64,${app.iconBase64}` : undefined" :size="42">
                  <SvgIcon icon="mdi:application" />
                </NAvatar>
                <div class="min-w-0">
                  <div class="truncate text-14px font-600">{{ app.displayName || $t('dataprotector.remote.apps.unnamed') }}</div>
                  <div class="truncate text-12px text-gray-500">{{ app.publisher || $t('dataprotector.remote.apps.unknownPublisher') }}</div>
                  <div class="truncate text-12px text-gray-400">{{ app.displayVersion || '-' }}</div>
                </div>
              </div>
            </div>
          </template>

          <template v-else-if="activeTab === 'startup'">
            <div class="toolbar">
              <div class="module-count">{{ $t('dataprotector.remote.startup.entries', { count: startupItems.length }) }}</div>
              <NButton type="primary" :loading="panelLoading" @click="loadStartupItems">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                {{ $t('dataprotector.common.refresh') }}
              </NButton>
            </div>
            <NDataTable
              :columns="startupColumns"
              :data="startupItems"
              :loading="panelLoading"
              :scroll-x="1120"
              :pagination="{ pageSize: 12 }"
            />
          </template>

          <template v-else-if="activeTab === 'shell'">
            <div class="terminal-panel">
              <div class="terminal-toolbar">
                <NTag :type="terminalRunning ? 'success' : 'default'" :bordered="false">
                  {{ terminalRunning ? $t('dataprotector.remote.shell.connected') : $t('dataprotector.remote.shell.stopped') }}
                </NTag>
                <NSpace>
                  <NButton type="primary" :loading="panelLoading" :disabled="terminalRunning" @click="startTerminal">
                    <template #icon><SvgIcon icon="mdi:play" /></template>
                    {{ $t('dataprotector.common.start') }}
                  </NButton>
                  <NButton secondary :disabled="!terminalRunning" @click="readTerminal">
                    <template #icon><SvgIcon icon="mdi:refresh" /></template>
                    {{ $t('dataprotector.common.read') }}
                  </NButton>
                  <NButton secondary type="error" :loading="panelLoading" :disabled="!terminalRunning" @click="stopTerminal">
                    <template #icon><SvgIcon icon="mdi:stop" /></template>
                    {{ $t('dataprotector.common.stop') }}
                  </NButton>
                </NSpace>
              </div>
              <pre ref="terminalRef" class="terminal-output" @scroll="handleTerminalScroll">{{
                terminalOutput || $t('dataprotector.remote.shell.empty')
              }}</pre>
              <NInputGroup>
                <NInput
                  v-model:value="terminalInput"
                  :disabled="!terminalRunning"
                  :placeholder="$t('dataprotector.remote.shell.inputPlaceholder')"
                  @keyup.enter="sendTerminalInput"
                />
                <NButton type="primary" :disabled="!terminalRunning || !terminalInput.trim()" @click="sendTerminalInput">
                  {{ $t('dataprotector.common.send') }}
                </NButton>
              </NInputGroup>
            </div>
          </template>

          <template v-else-if="activeTab === 'desktop'">
            <div class="toolbar">
              <div class="module-count">{{ $t('dataprotector.remote.desktop.title') }}</div>
              <NButton type="primary" :loading="panelLoading" @click="captureScreenshot">
                <template #icon><SvgIcon icon="mdi:monitor-screenshot" /></template>
                {{ $t('dataprotector.common.capture') }}
              </NButton>
            </div>
            <div class="screenshot-frame">
              <img v-if="screenshotSrc" :src="screenshotSrc" :alt="$t('dataprotector.remote.desktop.screenshotAlt')" />
              <NEmpty v-else :description="screenshotError || $t('dataprotector.remote.desktop.noScreenshot')" />
            </div>
          </template>

          <template v-else>
            <div class="account-panel">
              <NForm label-placement="top">
                <NFormItem :label="$t('dataprotector.remote.accounts.username')">
                  <NInput v-model:value="accountForm.username" />
                </NFormItem>
                <NFormItem :label="$t('dataprotector.remote.accounts.newPassword')">
                  <NInput v-model:value="accountForm.newPassword" type="password" show-password-on="click" />
                </NFormItem>
                <NButton type="primary" :loading="panelLoading" @click="changePassword">
                  <template #icon><SvgIcon icon="mdi:account-key" /></template>
                  {{ $t('dataprotector.remote.accounts.changePassword') }}
                </NButton>
              </NForm>
            </div>
          </template>
        </div>
      </NCard>

      <NCard :title="$t('dataprotector.remote.activity.title')" :bordered="false" class="activity-card">
        <div v-if="activity.length" class="activity-list">
          <div v-for="item in activity" :key="item" class="activity-item">{{ item }}</div>
        </div>
        <NEmpty v-else :description="$t('dataprotector.remote.activity.empty')" />
      </NCard>
    </main>

    <NModal v-model:show="renameVisible" preset="card" :title="$t('dataprotector.remote.files.renameTitle')" class="rename-modal">
      <NForm label-placement="top">
        <NFormItem :label="$t('dataprotector.remote.files.currentPath')">
          <NInput :value="renameTarget?.path || ''" readonly />
        </NFormItem>
        <NFormItem :label="$t('dataprotector.remote.files.newName')">
          <NInput v-model:value="renameName" @keyup.enter="submitRename" />
        </NFormItem>
        <div class="modal-actions">
          <NButton @click="renameVisible = false">{{ $t('dataprotector.common.cancel') }}</NButton>
          <NButton type="primary" :loading="panelLoading" @click="submitRename">{{ $t('dataprotector.common.rename') }}</NButton>
        </div>
      </NForm>
    </NModal>
  </div>
</template>

<style scoped>
.remote-workbench {
  display: grid;
  grid-template-columns: minmax(260px, 320px) minmax(0, 1fr);
  gap: 16px;
  min-height: calc(100vh - 128px);
}

.endpoint-pane,
.operation-pane {
  min-width: 0;
}

.endpoint-pane {
  padding: 16px;
  background: rgb(255 255 255);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.pane-header,
.selected-device,
.toolbar,
.modal-actions {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.pane-header h2,
.selected-device h1 {
  margin: 4px 0 0;
  font-size: 20px;
  font-weight: 700;
}

.selected-device p {
  margin: 8px 0 0;
  color: rgb(107 114 128);
  font-size: 13px;
}

.eyebrow {
  color: rgb(37 99 235);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

.endpoint-summary {
  display: flex;
  gap: 8px;
  align-items: center;
  margin: 14px 0;
  color: rgb(107 114 128);
  font-size: 13px;
}

.endpoint-list {
  display: grid;
  gap: 8px;
}

.endpoint-item {
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr) 10px;
  gap: 10px;
  align-items: center;
  width: 100%;
  padding: 10px;
  color: rgb(31 41 55);
  text-align: left;
  cursor: pointer;
  background: rgb(249 250 251);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.endpoint-item.active {
  background: rgb(239 246 255);
  border-color: rgb(37 99 235);
}

.endpoint-icon {
  display: grid;
  width: 36px;
  height: 36px;
  color: rgb(37 99 235);
  background: rgb(219 234 254);
  place-items: center;
  border-radius: 8px;
}

.endpoint-name,
.endpoint-sub {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.endpoint-name {
  font-size: 14px;
  font-weight: 700;
}

.endpoint-sub {
  margin-top: 2px;
  color: rgb(107 114 128);
  font-size: 12px;
}

.status-dot {
  width: 8px;
  height: 8px;
  background: rgb(156 163 175);
  border-radius: 999px;
}

.status-dot.online {
  background: rgb(22 163 74);
}

.operation-pane {
  display: grid;
  gap: 16px;
}

.module-card :deep(.n-card__content) {
  padding-top: 4px;
}

.module-body {
  position: relative;
  min-height: 420px;
  padding-top: 16px;
}

.module-body.loading {
  cursor: progress;
}

.toolbar {
  margin-bottom: 14px;
}

.interaction-hint {
  margin: -4px 0 12px;
  color: rgb(107 114 128);
  font-size: 12px;
}

.module-count {
  color: rgb(75 85 99);
  font-size: 13px;
  font-weight: 600;
}

.drive-grid,
.app-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
  gap: 12px;
}

.drive-tile {
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr);
  gap: 12px;
  align-items: center;
  min-height: 92px;
  padding: 14px;
  color: rgb(31 41 55);
  text-align: left;
  cursor: pointer;
  background: rgb(255 255 255);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.drive-tile:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.drive-tile:not(:disabled):hover {
  background: rgb(239 246 255);
  border-color: rgb(37 99 235);
}

.drive-tile svg {
  color: rgb(37 99 235);
  font-size: 30px;
}

.drive-name {
  font-size: 14px;
  font-weight: 700;
}

.drive-sub {
  margin-top: 4px;
  color: rgb(107 114 128);
  font-size: 12px;
}

.manager-name-cell {
  display: flex;
  gap: 8px;
  align-items: center;
  min-width: 0;
}

.manager-icon {
  flex: 0 0 auto;
  color: rgb(75 85 99);
  font-size: 18px;
}

.manager-icon-folder {
  color: rgb(217 119 6);
}

.manager-icon-process {
  color: rgb(37 99 235);
}

.app-tile {
  display: flex;
  gap: 12px;
  align-items: center;
  min-height: 76px;
  padding: 12px;
  background: rgb(255 255 255);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.terminal-panel {
  display: grid;
  gap: 12px;
}

.terminal-toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.terminal-output {
  min-height: 300px;
  max-height: 520px;
  padding: 16px;
  overflow: auto;
  color: rgb(209 250 229);
  font-family: Consolas, 'Courier New', monospace;
  line-height: 1.55;
  white-space: pre-wrap;
  background: rgb(17 24 39);
  border-radius: 8px;
}

.screenshot-frame {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 420px;
  padding: 12px;
  overflow: auto;
  background: rgb(17 24 39);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.screenshot-frame img {
  max-width: 100%;
  height: auto;
}

.account-panel {
  max-width: 480px;
}

.activity-list {
  display: grid;
  gap: 8px;
}

.activity-item {
  padding: 8px 10px;
  color: rgb(55 65 81);
  font-size: 13px;
  background: rgb(249 250 251);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.rename-modal {
  width: min(560px, calc(100vw - 32px));
}

@media (max-width: 960px) {
  .remote-workbench {
    grid-template-columns: 1fr;
  }
}
</style>
