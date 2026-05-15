<script setup lang="ts">
import { computed, h, nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { Icon } from '@iconify/vue';
import { NButton, NTag, type DataTableColumns } from 'naive-ui';
import { fetchCreateRemoteTask, fetchDevices, fetchRemoteTasks } from '@/service/api';

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
    label: 'Open',
    key: 'open',
    disabled: !fileContext.row?.isDirectory
  },
  {
    label: 'Rename',
    key: 'rename'
  },
  {
    label: 'Delete',
    key: 'delete'
  }
]);

const processMenuOptions = computed(() => [
  {
    label: 'Terminate',
    key: 'terminate',
    disabled: !processContext.row
  }
]);

const fileColumns: DataTableColumns<FileItem> = [
  {
    title: 'Name',
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
    title: 'Type',
    key: 'isDirectory',
    width: 110,
    render(row) {
      return row.isDirectory ? 'Folder' : 'File';
    }
  },
  {
    title: 'Size',
    key: 'size',
    width: 130,
    render(row) {
      return row.isDirectory ? '-' : formatBytes(row.size);
    }
  },
  {
    title: 'Modified',
    key: 'lastWriteUtc',
    width: 190,
    render(row) {
      return formatTime(row.lastWriteUtc);
    }
  }
];

const processColumns: DataTableColumns<ProcessItem> = [
  { title: 'PID', key: 'pid', width: 100, sorter: 'default' },
  {
    title: 'Process',
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
    title: 'Memory',
    key: 'memoryBytes',
    width: 130,
    sorter: (a, b) => a.memoryBytes - b.memoryBytes,
    render(row) {
      return formatBytes(row.memoryBytes);
    }
  },
  {
    title: 'Started',
    key: 'startTimeUtc',
    width: 190,
    render(row) {
      return formatTime(row.startTimeUtc);
    }
  },
  { title: 'Path', key: 'path', minWidth: 360, ellipsis: { tooltip: true } },
];

const startupColumns: DataTableColumns<StartupItem> = [
  { title: 'Location', key: 'location', width: 180 },
  { title: 'Name', key: 'name', width: 220, ellipsis: { tooltip: true } },
  { title: 'Command', key: 'command', minWidth: 520, ellipsis: { tooltip: true } },
  {
    title: 'State',
    key: 'enabled',
    width: 110,
    render(row) {
      return h(
        NTag,
        { type: row.enabled ? 'success' : 'default', bordered: false },
        { default: () => (row.enabled ? 'Enabled' : 'Disabled') }
      );
    }
  }
];

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
    pushActivity(`Renamed ${renameTarget.value.name}`);
    await openPath(currentPath.value);
  } finally {
    panelLoading.value = false;
  }
}

function confirmDelete(row: FileItem) {
  window.$dialog?.warning({
    title: 'Delete remote item',
    content: `Delete ${row.path}?`,
    positiveText: 'Delete',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      panelLoading.value = true;
      try {
        await runRemoteTask('file.delete', { path: row.path });
        pushActivity(`Deleted ${row.name}`);
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
    title: 'Terminate process',
    content: `Terminate ${row.name} (${row.pid}) on ${selectedDevice.value?.machine || selectedDeviceId.value}?`,
    positiveText: 'Terminate',
    negativeText: 'Cancel',
    onPositiveClick: async () => {
      panelLoading.value = true;
      try {
        await runRemoteTask('process.kill', { pid: row.pid });
        pushActivity(`Terminated ${row.name} (${row.pid})`);
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
    screenshotSrc.value = task.output ? `data:image/png;base64,${task.output}` : '';
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
    pushActivity(`Password changed for ${accountForm.username}`);
    window.$message?.success('Password change task completed.');
  } finally {
    panelLoading.value = false;
  }
}

async function lockScreen() {
  panelLoading.value = true;
  try {
    await runRemoteTask('session.lock', {});
    pushActivity('Remote workstation lock requested');
  } finally {
    panelLoading.value = false;
  }
}

async function runRemoteTask(kind: string, args: Record<string, unknown>, logActivity = true) {
  if (!selectedDevice.value) {
    throw new Error('Select an endpoint first.');
  }

  const createResult = await fetchCreateRemoteTask({
    deviceId: selectedDevice.value.deviceId,
    kind,
    argumentsJson: JSON.stringify(args || {}),
    actor: 'web-admin'
  });

  if (createResult.error) {
    throw new Error('Unable to queue remote operation.');
  }

  const taskId = createResult.data.taskId;
  if (logActivity) {
    pushActivity(`Queued ${operationLabel(kind)}`);
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
          pushActivity(`Completed ${operationLabel(kind)}`);
        }
        return task;
      }

      throw new Error(task.error || task.output || `${operationLabel(kind)} failed.`);
    }
  }

  throw new Error(`${operationLabel(kind)} timed out waiting for the endpoint.`);
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function pushActivity(message: string) {
  activity.value = [`${new Date().toLocaleTimeString()} ${message}`, ...activity.value].slice(0, 8);
}

function operationLabel(kind: string) {
  const labels: Record<string, string> = {
    'file.drives': 'drive inventory',
    'file.list': 'directory listing',
    'file.delete': 'file deletion',
    'file.rename': 'file rename',
    'process.list': 'process inventory',
    'process.kill': 'process termination',
    'inventory.installedApps': 'application inventory',
    'inventory.startupItems': 'startup inventory',
    'cmd.run': 'remote command',
    'terminal.start': 'terminal start',
    'terminal.input': 'terminal input',
    'terminal.read': 'terminal output read',
    'terminal.stop': 'terminal stop',
    'desktop.screenshot': 'desktop screenshot',
    'session.lock': 'screen lock',
    'user.changePassword': 'password change'
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
          <div class="eyebrow">Endpoints</div>
          <h2>Clients</h2>
        </div>
        <NButton quaternary circle :loading="loadingDevices" @click="refreshDevices">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
        </NButton>
      </div>

      <div class="endpoint-summary">
        <NTag type="success" :bordered="false">{{ onlineDevices }} online</NTag>
        <span>{{ devices.length }} registered</span>
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
            <div class="endpoint-sub">{{ device.user || '-' }} / {{ device.driverStatus || 'driver unknown' }}</div>
          </div>
          <span class="status-dot" :class="{ online: device.online }"></span>
        </button>
        <NEmpty v-if="!devices.length" description="No registered endpoints" />
      </div>
    </aside>

    <main class="operation-pane">
      <NCard :bordered="false" class="selected-device-card">
        <div class="selected-device">
          <div>
            <div class="eyebrow">Remote Management</div>
            <h1>{{ selectedDevice?.machine || 'Select an endpoint' }}</h1>
            <p v-if="selectedDevice">
              {{ selectedDevice.user || '-' }} / agent {{ selectedDevice.agentVersion || '-' }} /
              {{ selectedDevice.online ? 'online' : 'offline' }}
            </p>
          </div>
          <NSpace>
            <NButton secondary :disabled="!selectedDevice" @click="lockScreen">
              <template #icon><SvgIcon icon="mdi:lock" /></template>
              Lock
            </NButton>
            <NButton type="primary" :disabled="!selectedDevice" :loading="panelLoading" @click="refreshActivePanel">
              <template #icon><SvgIcon icon="mdi:refresh" /></template>
              Refresh Panel
            </NButton>
          </NSpace>
        </div>
      </NCard>

      <NCard :bordered="false" class="module-card">
        <NTabs :value="activeTab" type="line" animated @update:value="handleTabChange">
          <NTab name="files">File Manager</NTab>
          <NTab name="processes">Process Manager</NTab>
          <NTab name="apps">Applications</NTab>
          <NTab name="startup">Startup</NTab>
          <NTab name="shell">Command</NTab>
          <NTab name="desktop">Desktop</NTab>
          <NTab name="accounts">Accounts</NTab>
        </NTabs>

        <div class="module-body" :class="{ loading: panelLoading }">
          <template v-if="activeTab === 'files'">
            <div class="toolbar">
              <NInputGroup>
                <NButton secondary :disabled="!currentPath" @click="goUp">
                  <template #icon><SvgIcon icon="mdi:arrow-up" /></template>
                </NButton>
                <NInput v-model:value="pathInput" placeholder="Select a drive or enter a remote path" @keyup.enter="goToPath" />
                <NButton type="primary" :disabled="!pathInput" @click="goToPath">Open</NButton>
              </NInputGroup>
              <NButton type="primary" :loading="panelLoading" @click="refreshActivePanel">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                Refresh
              </NButton>
            </div>
            <div class="interaction-hint">Double-click folders or drives to enter. Right-click items for actions.</div>

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
                  <div class="drive-sub">{{ drive.driveType }} / {{ drive.fileSystem || 'not ready' }}</div>
                  <div class="drive-sub">{{ formatBytes(drive.freeSpace) }} free of {{ formatBytes(drive.totalSize) }}</div>
                </div>
              </button>
              <NEmpty v-if="!drives.length && !panelLoading" description="No drives returned" />
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
              <NInput v-model:value="processSearch" clearable placeholder="Search process name, PID, path, or user" />
              <NButton type="primary" :loading="panelLoading" @click="loadProcesses">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                Refresh
              </NButton>
            </div>
            <div class="interaction-hint">Right-click a process to terminate it.</div>
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
              <div class="module-count">{{ apps.length }} installed applications</div>
              <NButton type="primary" :loading="panelLoading" @click="loadApps">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                Refresh
              </NButton>
            </div>
            <div class="app-grid">
              <div v-for="app in apps" :key="`${app.displayName}-${app.displayVersion}-${app.publisher}`" class="app-tile">
                <NAvatar :src="app.iconBase64 ? `data:image/png;base64,${app.iconBase64}` : undefined" :size="42">
                  <SvgIcon icon="mdi:application" />
                </NAvatar>
                <div class="min-w-0">
                  <div class="truncate text-14px font-600">{{ app.displayName || 'Unnamed application' }}</div>
                  <div class="truncate text-12px text-gray-500">{{ app.publisher || 'Unknown publisher' }}</div>
                  <div class="truncate text-12px text-gray-400">{{ app.displayVersion || '-' }}</div>
                </div>
              </div>
            </div>
          </template>

          <template v-else-if="activeTab === 'startup'">
            <div class="toolbar">
              <div class="module-count">{{ startupItems.length }} startup entries</div>
              <NButton type="primary" :loading="panelLoading" @click="loadStartupItems">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                Refresh
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
                  {{ terminalRunning ? 'Connected' : 'Stopped' }}
                </NTag>
                <NSpace>
                  <NButton type="primary" :loading="panelLoading" :disabled="terminalRunning" @click="startTerminal">
                    <template #icon><SvgIcon icon="mdi:play" /></template>
                    Start
                  </NButton>
                  <NButton secondary :disabled="!terminalRunning" @click="readTerminal">
                    <template #icon><SvgIcon icon="mdi:refresh" /></template>
                    Read
                  </NButton>
                  <NButton secondary type="error" :loading="panelLoading" :disabled="!terminalRunning" @click="stopTerminal">
                    <template #icon><SvgIcon icon="mdi:stop" /></template>
                    Stop
                  </NButton>
                </NSpace>
              </div>
              <pre ref="terminalRef" class="terminal-output" @scroll="handleTerminalScroll">{{
                terminalOutput || 'Start a session, then type commands below. Press Enter to send.'
              }}</pre>
              <NInputGroup>
                <NInput
                  v-model:value="terminalInput"
                  :disabled="!terminalRunning"
                  placeholder="Type a command and press Enter"
                  @keyup.enter="sendTerminalInput"
                />
                <NButton type="primary" :disabled="!terminalRunning || !terminalInput.trim()" @click="sendTerminalInput">
                  Send
                </NButton>
              </NInputGroup>
            </div>
          </template>

          <template v-else-if="activeTab === 'desktop'">
            <div class="toolbar">
              <div class="module-count">Remote desktop snapshot</div>
              <NButton type="primary" :loading="panelLoading" @click="captureScreenshot">
                <template #icon><SvgIcon icon="mdi:monitor-screenshot" /></template>
                Capture
              </NButton>
            </div>
            <div class="screenshot-frame">
              <img v-if="screenshotSrc" :src="screenshotSrc" alt="Remote desktop screenshot" />
              <NEmpty v-else description="No screenshot captured" />
            </div>
          </template>

          <template v-else>
            <div class="account-panel">
              <NForm label-placement="top">
                <NFormItem label="Username">
                  <NInput v-model:value="accountForm.username" />
                </NFormItem>
                <NFormItem label="New password">
                  <NInput v-model:value="accountForm.newPassword" type="password" show-password-on="click" />
                </NFormItem>
                <NButton type="primary" :loading="panelLoading" @click="changePassword">
                  <template #icon><SvgIcon icon="mdi:account-key" /></template>
                  Change Password
                </NButton>
              </NForm>
            </div>
          </template>
        </div>
      </NCard>

      <NCard title="Activity" :bordered="false" class="activity-card">
        <div v-if="activity.length" class="activity-list">
          <div v-for="item in activity" :key="item" class="activity-item">{{ item }}</div>
        </div>
        <NEmpty v-else description="No remote operations in this session" />
      </NCard>
    </main>

    <NModal v-model:show="renameVisible" preset="card" title="Rename Remote Item" class="rename-modal">
      <NForm label-placement="top">
        <NFormItem label="Current path">
          <NInput :value="renameTarget?.path || ''" readonly />
        </NFormItem>
        <NFormItem label="New name">
          <NInput v-model:value="renameName" @keyup.enter="submitRename" />
        </NFormItem>
        <div class="modal-actions">
          <NButton @click="renameVisible = false">Cancel</NButton>
          <NButton type="primary" :loading="panelLoading" @click="submitRename">Rename</NButton>
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
