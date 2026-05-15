<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { Icon } from '@iconify/vue';
import { NButton, NTag, type DataTableColumns, type FormInst, type FormRules } from 'naive-ui';
import { fetchCreateRemoteTask, fetchDevices, fetchRemoteTasks } from '@/service/api';

defineOptions({
  name: 'RemoteOps'
});

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

type FileItem = {
  name: string;
  path: string;
  isDirectory: boolean;
  size: number;
  lastWriteUtc: string;
};

const loading = ref(false);
const submitting = ref(false);
const devices = ref<Api.DataProtector.Device[]>([]);
const tasks = ref<Api.DataProtector.RemoteTask[]>([]);
const selectedTaskId = ref('');
const formRef = ref<FormInst | null>(null);

const form = reactive({
  deviceId: '',
  kind: 'inventory.installedApps',
  path: 'C:\\',
  command: 'whoami',
  username: '',
  newPassword: '',
  timeoutSeconds: 30
});

const taskOptions = [
  { label: 'Installed apps', value: 'inventory.installedApps' },
  { label: 'Startup items', value: 'inventory.startupItems' },
  { label: 'File list', value: 'file.list' },
  { label: 'Screenshot', value: 'desktop.screenshot' },
  { label: 'Run command', value: 'cmd.run' },
  { label: 'Change password', value: 'user.changePassword' },
  { label: 'Lock screen', value: 'session.lock' }
];

const formRules: FormRules = {
  deviceId: { required: true, message: 'Device is required', trigger: 'change' },
  kind: { required: true, message: 'Task type is required', trigger: 'change' }
};

const deviceOptions = computed(() =>
  devices.value.map(device => ({
    label: `${device.machine || device.deviceId} ${device.online ? '(online)' : '(offline)'}`,
    value: device.deviceId
  }))
);

const selectedDevice = computed(() => devices.value.find(device => device.deviceId === form.deviceId));
const selectedTask = computed(
  () => tasks.value.find(task => task.taskId === selectedTaskId.value) || tasks.value[0] || null
);

const onlineDevices = computed(() => devices.value.filter(device => device.online).length);
const successfulTasks = computed(() => tasks.value.filter(task => task.status === 'completed' && task.succeeded).length);
const failedTasks = computed(() =>
  tasks.value.filter(task => task.status === 'failed' || (task.status === 'completed' && !task.succeeded)).length
);
const pendingTasks = computed(() =>
  tasks.value.filter(task => task.status !== 'completed' && task.status !== 'failed').length
);

const installedApps = computed(() => parseJson<InstalledApp[]>(selectedTask.value?.output, []));
const startupItems = computed(() => parseJson<StartupItem[]>(selectedTask.value?.output, []));
const fileItems = computed(() => parseJson<FileItem[]>(selectedTask.value?.output, []));
const screenshotSrc = computed(() =>
  selectedTask.value?.kind === 'desktop.screenshot' && selectedTask.value.output
    ? `data:image/png;base64,${selectedTask.value.output}`
    : ''
);

const taskColumns: DataTableColumns<Api.DataProtector.RemoteTask> = [
  {
    title: 'Status',
    key: 'status',
    width: 118,
    render(row) {
      return h(NTag, { type: statusType(row), bordered: false }, { default: () => taskStatusLabel(row) });
    }
  },
  {
    title: 'Task',
    key: 'kind',
    width: 220,
    render(row) {
      return h('div', { class: 'task-kind-cell' }, [
        h(Icon, { icon: taskIcon(row.kind), class: 'task-kind-icon' }),
        h('span', taskLabel(row.kind))
      ]);
    }
  },
  {
    title: 'Device',
    key: 'deviceId',
    width: 180,
    ellipsis: { tooltip: true },
    render(row) {
      return deviceName(row.deviceId);
    }
  },
  {
    title: 'Created',
    key: 'createdUtc',
    width: 180,
    render(row) {
      return formatTime(row.createdUtc);
    }
  },
  {
    title: 'Result',
    key: 'result',
    ellipsis: { tooltip: true },
    render(row) {
      return resultSummary(row);
    }
  },
  {
    title: 'Open',
    key: 'open',
    width: 92,
    render(row) {
      return h(
        NButton,
        {
          size: 'small',
          secondary: selectedTaskId.value !== row.taskId,
          type: selectedTaskId.value === row.taskId ? 'primary' : 'default',
          onClick: () => {
            selectedTaskId.value = row.taskId;
          }
        },
        { default: () => 'View' }
      );
    }
  }
];

const startupColumns: DataTableColumns<StartupItem> = [
  { title: 'Location', key: 'location', width: 180 },
  { title: 'Name', key: 'name', width: 220, ellipsis: { tooltip: true } },
  { title: 'Command', key: 'command', minWidth: 420, ellipsis: { tooltip: true } },
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

const fileColumns: DataTableColumns<FileItem> = [
  {
    title: 'Name',
    key: 'name',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render(row) {
      return h('div', { class: 'file-name-cell' }, [
        h(Icon, {
          class: row.isDirectory ? 'file-icon file-icon-folder' : 'file-icon',
          icon: row.isDirectory ? 'mdi:folder' : 'mdi:file-document-outline'
        }),
        h('span', row.name)
      ]);
    }
  },
  {
    title: 'Size',
    key: 'size',
    width: 120,
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
  },
  { title: 'Path', key: 'path', minWidth: 360, ellipsis: { tooltip: true } }
];

function buildArguments() {
  if (form.kind === 'file.list') {
    return { path: form.path, limit: 200 };
  }

  if (form.kind === 'cmd.run') {
    return { command: form.command, timeoutSeconds: form.timeoutSeconds };
  }

  if (form.kind === 'user.changePassword') {
    return { username: form.username, newPassword: form.newPassword };
  }

  return {};
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function deviceName(deviceId: string) {
  const device = devices.value.find(item => item.deviceId === deviceId);
  return device?.machine || deviceId;
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

function resultSummary(task: Api.DataProtector.RemoteTask) {
  if (task.status !== 'completed' && task.status !== 'failed') {
    return task.status === 'sent' ? 'Sent to endpoint' : 'Queued for endpoint';
  }

  if (task.kind === 'inventory.installedApps') return `${parseJson<InstalledApp[]>(task.output, []).length} apps`;
  if (task.kind === 'inventory.startupItems') return `${parseJson<StartupItem[]>(task.output, []).length} startup items`;
  if (task.kind === 'file.list') return `${parseJson<FileItem[]>(task.output, []).length} entries`;
  if (task.kind === 'desktop.screenshot') return task.output ? 'Screenshot captured' : 'No image';
  return shortText(task.output || task.error || '-');
}

function statusType(task: Api.DataProtector.RemoteTask): 'success' | 'warning' | 'error' {
  if (task.status === 'completed' && task.succeeded) return 'success';
  if (task.status === 'failed' || (task.status === 'completed' && !task.succeeded)) return 'error';
  return 'warning';
}

function taskLabel(value: string) {
  return taskOptions.find(item => item.value === value)?.label || value;
}

function taskIcon(value: string) {
  const icons: Record<string, string> = {
    'inventory.installedApps': 'mdi:application-cog',
    'inventory.startupItems': 'mdi:rocket-launch',
    'file.list': 'mdi:folder-search',
    'desktop.screenshot': 'mdi:monitor-screenshot',
    'cmd.run': 'mdi:console',
    'user.changePassword': 'mdi:account-key',
    'session.lock': 'mdi:lock'
  };

  return icons[value] || 'mdi:clipboard-text-clock';
}

function taskStatusLabel(task: Api.DataProtector.RemoteTask) {
  if (task.status === 'completed' && task.succeeded) return 'Completed';
  if (task.status === 'failed' || (task.status === 'completed' && !task.succeeded)) return 'Failed';
  if (task.status === 'sent') return 'Sent';
  return task.status || 'Queued';
}

function resultStatus(task: Api.DataProtector.RemoteTask): 'success' | 'error' | 'info' {
  const type = statusType(task);
  if (type === 'success') return 'success';
  if (type === 'error') return 'error';
  return 'info';
}

function resultTitle(task: Api.DataProtector.RemoteTask) {
  if (statusType(task) === 'error') return 'Task failed';
  if (statusType(task) === 'success') return 'Task completed';
  return task.status === 'sent' ? 'Waiting for endpoint result' : 'Task queued';
}

function shortText(value: string, maxLength = 160) {
  if (!value) return '-';
  const normalized = value.replace(/\s+/g, ' ').trim();
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength)}...` : normalized;
}

function formatJson(value?: string) {
  if (!value) return '-';
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

async function refresh() {
  loading.value = true;
  try {
    const [devicesResult, tasksResult] = await Promise.all([fetchDevices(), fetchRemoteTasks({ limit: 100 })]);
    if (!devicesResult.error) {
      devices.value = devicesResult.data;
      if (!form.deviceId && devices.value.length) {
        form.deviceId = devices.value[0].deviceId;
      }
    }
    if (!tasksResult.error) {
      tasks.value = tasksResult.data;
      if (!selectedTaskId.value && tasks.value.length) {
        selectedTaskId.value = tasks.value[0].taskId;
      }
    }
  } finally {
    loading.value = false;
  }
}

async function submitTask() {
  await formRef.value?.validate();
  submitting.value = true;
  try {
    const { error, data } = await fetchCreateRemoteTask({
      deviceId: form.deviceId,
      kind: form.kind,
      argumentsJson: JSON.stringify(buildArguments()),
      actor: 'web-admin'
    });

    if (!error) {
      selectedTaskId.value = data.taskId;
      window.$message?.success('Remote task queued.');
      await refresh();
    }
  } finally {
    submitting.value = false;
  }
}

onMounted(refresh);
</script>

<template>
  <NSpace vertical :size="16">
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-16px">
        <div>
          <div class="eyebrow">EDR Response Center</div>
          <h1 class="m-0 m-t-4px text-24px font-700">Remote Operations</h1>
        </div>
        <NButton type="primary" :loading="loading" @click="refresh">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
          Refresh
        </NButton>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="metric-card">
          <div class="metric-icon metric-icon-blue"><SvgIcon icon="mdi:desktop-tower-monitor" /></div>
          <NStatistic label="Registered endpoints" :value="devices.length" />
          <div class="metric-caption">{{ onlineDevices }} online now</div>
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="metric-card">
          <div class="metric-icon metric-icon-green"><SvgIcon icon="mdi:check-decagram" /></div>
          <NStatistic label="Successful tasks" :value="successfulTasks" />
          <div class="metric-caption">{{ pendingTasks }} waiting for endpoint</div>
        </NCard>
      </NGi>
      <NGi span="24 s:8">
        <NCard :bordered="false" class="metric-card">
          <div class="metric-icon metric-icon-red"><SvgIcon icon="mdi:alert-octagon" /></div>
          <NStatistic label="Failed tasks" :value="failedTasks" />
          <div class="metric-caption">Last 100 remote actions</div>
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 m:7">
        <NCard title="Command Center" :bordered="false" class="card-wrapper">
          <NForm ref="formRef" :model="form" :rules="formRules" label-placement="top">
            <NFormItem label="Device" path="deviceId">
              <NSelect v-model:value="form.deviceId" :options="deviceOptions" filterable />
            </NFormItem>
            <NAlert v-if="selectedDevice" :type="selectedDevice.online ? 'success' : 'warning'" class="m-b-16px">
              <div class="device-alert">
                <div class="font-600">{{ selectedDevice.machine || selectedDevice.deviceId }}</div>
                <div class="text-12px">
                  {{ selectedDevice.user || 'unknown user' }} / {{ selectedDevice.driverStatus || 'unknown driver' }}
                </div>
              </div>
            </NAlert>
            <NFormItem label="Task" path="kind">
              <NSelect v-model:value="form.kind" :options="taskOptions" />
            </NFormItem>
            <NFormItem v-if="form.kind === 'file.list'" label="Path">
              <NInput v-model:value="form.path" />
            </NFormItem>
            <NFormItem v-if="form.kind === 'cmd.run'" label="Command">
              <NInput v-model:value="form.command" type="textarea" :autosize="{ minRows: 3, maxRows: 6 }" />
            </NFormItem>
            <NFormItem v-if="form.kind === 'cmd.run'" label="Timeout seconds">
              <NInputNumber v-model:value="form.timeoutSeconds" :min="1" :max="300" class="w-full" />
            </NFormItem>
            <NFormItem v-if="form.kind === 'user.changePassword'" label="Username">
              <NInput v-model:value="form.username" />
            </NFormItem>
            <NFormItem v-if="form.kind === 'user.changePassword'" label="New password">
              <NInput v-model:value="form.newPassword" type="password" show-password-on="click" />
            </NFormItem>
            <NButton block type="primary" :loading="submitting" @click="submitTask">
              <template #icon><SvgIcon icon="mdi:send" /></template>
              Queue Task
            </NButton>
          </NForm>
        </NCard>
      </NGi>

      <NGi span="24 m:17">
        <NSpace vertical :size="16">
          <NCard :bordered="false" class="card-wrapper">
            <template #header>
              <div class="result-heading">
                <div v-if="selectedTask" class="result-heading-icon">
                  <SvgIcon :icon="taskIcon(selectedTask.kind)" />
                </div>
                <div>
                  <div class="text-16px font-700">Result Detail</div>
                  <div v-if="selectedTask" class="text-12px text-gray-500">
                    {{ taskLabel(selectedTask.kind) }} on {{ deviceName(selectedTask.deviceId) }}
                  </div>
                </div>
              </div>
            </template>
            <template v-if="selectedTask" #header-extra>
              <NSpace align="center">
                <NTag :type="statusType(selectedTask)">{{ taskStatusLabel(selectedTask) }}</NTag>
                <NTag>{{ taskLabel(selectedTask.kind) }}</NTag>
              </NSpace>
            </template>

            <NEmpty v-if="!selectedTask" description="No remote task selected" />

            <template v-else>
              <NDescriptions :column="2" bordered label-placement="left" class="m-b-16px">
                <NDescriptionsItem label="Device">{{ deviceName(selectedTask.deviceId) }}</NDescriptionsItem>
                <NDescriptionsItem label="Actor">{{ selectedTask.actor || '-' }}</NDescriptionsItem>
                <NDescriptionsItem label="Created">{{ formatTime(selectedTask.createdUtc) }}</NDescriptionsItem>
                <NDescriptionsItem label="Completed">{{ formatTime(selectedTask.completedUtc) }}</NDescriptionsItem>
                <NDescriptionsItem label="Summary">{{ resultSummary(selectedTask) }}</NDescriptionsItem>
                <NDescriptionsItem label="Exit code">{{ selectedTask.exitCode }}</NDescriptionsItem>
              </NDescriptions>

              <template v-if="selectedTask.kind === 'inventory.installedApps'">
                <NGrid v-if="installedApps.length" :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
                  <NGi
                    v-for="app in installedApps"
                    :key="`${app.displayName}-${app.displayVersion}-${app.publisher}`"
                    span="24 s:12 l:8"
                  >
                    <div class="app-tile">
                      <NAvatar
                        :src="app.iconBase64 ? `data:image/png;base64,${app.iconBase64}` : undefined"
                        :size="44"
                        class="app-avatar"
                      >
                        <SvgIcon icon="mdi:application" />
                      </NAvatar>
                      <div class="min-w-0">
                        <div class="truncate text-14px font-600">{{ app.displayName || 'Unnamed application' }}</div>
                        <div class="truncate text-12px text-gray-500">{{ app.publisher || 'Unknown publisher' }}</div>
                        <div class="truncate text-12px text-gray-400">{{ app.displayVersion || '-' }}</div>
                      </div>
                    </div>
                  </NGi>
                </NGrid>
                <NEmpty v-else description="No installed applications returned" />
              </template>

              <NDataTable
                v-else-if="selectedTask.kind === 'inventory.startupItems'"
                :columns="startupColumns"
                :data="startupItems"
                :scroll-x="980"
                :pagination="{ pageSize: 8 }"
              />

              <NDataTable
                v-else-if="selectedTask.kind === 'file.list'"
                :columns="fileColumns"
                :data="fileItems"
                :scroll-x="980"
                :pagination="{ pageSize: 10 }"
              />

              <div v-else-if="selectedTask.kind === 'desktop.screenshot'" class="screenshot-frame">
                <img v-if="screenshotSrc" :src="screenshotSrc" alt="Remote screenshot" />
                <NEmpty v-else description="No screenshot returned" />
              </div>

              <pre v-else-if="selectedTask.kind === 'cmd.run'" class="terminal-output">{{
                selectedTask.output || selectedTask.error || 'No command output returned.'
              }}</pre>

              <NResult
                v-else
                :status="resultStatus(selectedTask)"
                :title="resultTitle(selectedTask)"
                :description="selectedTask.output || selectedTask.error || 'No output returned.'"
              />

              <div class="evidence-panel">
                <div class="evidence-title">Task Evidence</div>
                <NDescriptions :column="1" bordered label-placement="left">
                  <NDescriptionsItem label="Task ID">{{ selectedTask.taskId }}</NDescriptionsItem>
                  <NDescriptionsItem label="Arguments">
                    <pre class="evidence-code">{{ formatJson(selectedTask.argumentsJson) }}</pre>
                  </NDescriptionsItem>
                  <NDescriptionsItem v-if="selectedTask.error" label="Error">
                    <pre class="evidence-code evidence-code-error">{{ selectedTask.error }}</pre>
                  </NDescriptionsItem>
                </NDescriptions>
              </div>
            </template>
          </NCard>

          <NCard title="Task History" :bordered="false" class="card-wrapper">
            <NDataTable
              :columns="taskColumns"
              :data="tasks"
              :loading="loading"
              :scroll-x="1060"
              :pagination="{ pageSize: 8 }"
            />
          </NCard>
        </NSpace>
      </NGi>
    </NGrid>
  </NSpace>
</template>

<style scoped>
.eyebrow {
  color: rgb(37 99 235);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

.metric-card :deep(.n-card__content) {
  position: relative;
  min-height: 116px;
  padding-right: 72px;
}

.metric-icon {
  position: absolute;
  top: 20px;
  right: 20px;
  display: grid;
  width: 44px;
  height: 44px;
  color: rgb(255 255 255);
  place-items: center;
  border-radius: 8px;
}

.metric-icon-blue {
  background: rgb(37 99 235);
}

.metric-icon-green {
  background: rgb(22 163 74);
}

.metric-icon-red {
  background: rgb(220 38 38);
}

.metric-caption {
  margin-top: 12px;
  color: rgb(107 114 128);
  font-size: 13px;
}

.device-alert {
  line-height: 1.5;
}

.result-heading {
  display: flex;
  gap: 12px;
  align-items: center;
}

.result-heading-icon {
  display: grid;
  width: 36px;
  height: 36px;
  color: rgb(37 99 235);
  background: rgb(239 246 255);
  place-items: center;
  border-radius: 8px;
}

.task-kind-cell,
.file-name-cell {
  display: flex;
  gap: 8px;
  align-items: center;
  min-width: 0;
}

.task-kind-icon {
  flex: 0 0 auto;
  color: rgb(37 99 235);
  font-size: 18px;
}

.file-icon {
  flex: 0 0 auto;
  color: rgb(75 85 99);
  font-size: 18px;
}

.file-icon-folder {
  color: rgb(217 119 6);
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

.app-avatar {
  flex: 0 0 auto;
  background: rgb(243 244 246);
}

.screenshot-frame {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 360px;
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

.terminal-output {
  min-height: 280px;
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

.evidence-panel {
  margin-top: 16px;
}

.evidence-title {
  margin-bottom: 8px;
  color: rgb(55 65 81);
  font-size: 13px;
  font-weight: 700;
}

.evidence-code {
  max-height: 220px;
  margin: 0;
  overflow: auto;
  color: rgb(31 41 55);
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
}

.evidence-code-error {
  color: rgb(185 28 28);
}
</style>
