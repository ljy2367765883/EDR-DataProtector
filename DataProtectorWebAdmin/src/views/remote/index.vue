<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import { NTag, type DataTableColumns, type FormInst, type FormRules } from 'naive-ui';
import { fetchCreateRemoteTask, fetchDevices, fetchRemoteTasks } from '@/service/api';

defineOptions({
  name: 'RemoteOps'
});

const loading = ref(false);
const submitting = ref(false);
const devices = ref<Api.DataProtector.Device[]>([]);
const tasks = ref<Api.DataProtector.RemoteTask[]>([]);
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

const deviceOptions = computed(() =>
  devices.value.map(device => ({
    label: `${device.machine || device.deviceId} ${device.online ? '(online)' : '(offline)'}`,
    value: device.deviceId
  }))
);

const formRules: FormRules = {
  deviceId: { required: true, message: 'Device is required', trigger: 'change' },
  kind: { required: true, message: 'Task type is required', trigger: 'change' }
};

const columns: DataTableColumns<Api.DataProtector.RemoteTask> = [
  {
    title: 'Status',
    key: 'status',
    width: 120,
    render(row) {
      const type = row.status === 'completed' ? 'success' : row.status === 'failed' ? 'error' : 'warning';
      return h(NTag, { type, bordered: false }, { default: () => row.status });
    }
  },
  { title: 'Kind', key: 'kind', width: 190 },
  { title: 'Device', key: 'deviceId', width: 240, ellipsis: { tooltip: true } },
  {
    title: 'Created',
    key: 'createdUtc',
    width: 190,
    render(row) {
      return row.createdUtc ? new Date(row.createdUtc).toLocaleString() : '-';
    }
  },
  { title: 'Exit', key: 'exitCode', width: 80 },
  { title: 'Result', key: 'output', ellipsis: { tooltip: true } },
  { title: 'Error', key: 'error', ellipsis: { tooltip: true } }
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
    if (!tasksResult.error) tasks.value = tasksResult.data;
  } finally {
    loading.value = false;
  }
}

async function submitTask() {
  await formRef.value?.validate();
  submitting.value = true;
  try {
    const { error } = await fetchCreateRemoteTask({
      deviceId: form.deviceId,
      kind: form.kind,
      argumentsJson: JSON.stringify(buildArguments()),
      actor: 'web-admin'
    });

    if (!error) {
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
          <h1 class="m-0 text-24px font-700">Remote Operations</h1>
          <p class="m-t-8px text-14px text-gray-500">
            Audited EDR tasks delivered through the endpoint agent polling channel.
          </p>
        </div>
        <NButton :loading="loading" @click="refresh">
          <template #icon><SvgIcon icon="mdi:refresh" /></template>
          Refresh
        </NButton>
      </div>
    </NCard>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 m:8">
        <NCard title="Create Task" :bordered="false" class="card-wrapper">
          <NForm ref="formRef" :model="form" :rules="formRules" label-placement="top">
            <NFormItem label="Device" path="deviceId">
              <NSelect v-model:value="form.deviceId" :options="deviceOptions" filterable />
            </NFormItem>
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

      <NGi span="24 m:16">
        <NCard title="Task History" :bordered="false" class="card-wrapper">
          <NDataTable :columns="columns" :data="tasks" :loading="loading" :pagination="{ pageSize: 10 }" />
        </NCard>
      </NGi>
    </NGrid>
  </NSpace>
</template>
