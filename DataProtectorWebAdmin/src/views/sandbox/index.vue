<script setup lang="tsx">
import { computed, h, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import type { DataTableColumns, PaginationProps, UploadCustomRequestOptions } from 'naive-ui';
import { NButton, NTag, useMessage } from 'naive-ui';
import {
  fetchRemoveSandboxLogs,
  fetchRemoveSandboxSample,
  fetchSandboxSamples,
  fetchStartSandboxAnalysis,
  fetchSubmitSandboxSample
} from '@/service/api';
import { $t } from '@/locales';

defineOptions({
  name: 'Sandbox'
});

type SandboxBehavior = {
  type: string;
  severity: string;
  detail: string;
  pid: number;
  timeUtc: string;
};

type SandboxProcess = {
  pid: number;
  parentPid: number;
  name: string;
  path: string;
  commandLine: string;
  createdUtc: string;
  signature?: {
    status: string;
    signer: string;
  };
};

type SandboxNetwork = {
  pid: number;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  timeUtc: string;
};

type SandboxFileArtifact = {
  path: string;
  size: number;
  modifiedUtc: string;
  sha256: string;
};

type SandboxRuntimeEvent = {
  timestampUtc: string;
  pid: number;
  action: string;
  target: string;
  processImage: string;
  status: string;
  blocked: boolean;
};

type SandboxKernelSensor = {
  enabled: boolean;
  status: string;
  serviceName: string;
  driverPath: string;
  policyStatus: string;
  win32: number;
  message: string;
};

type SandboxKernelEvent = {
  sequence: number;
  pid: number;
  parentPid: number;
  operation: number;
  operationName: string;
  status: string;
  flags: string;
  target: string;
  processImage: string;
  description: string;
};

type SandboxService = {
  name: string;
  displayName: string;
  pathName: string;
  serviceType: string;
  startMode: string;
  state: string;
  change: string;
};

type SandboxScheduledTask = {
  name: string;
  command: string;
  state: string;
  change: string;
};

type SandboxReport = {
  schema: string;
  isolation: string;
  runId: string;
  startedUtc: string;
  completedUtc: string;
  host?: string;
  sample?: {
    hostPath: string;
    fileName: string;
    sha256: string;
    architecture: string;
    signer: string;
    sandboxPath?: string;
  };
  execution?: {
    pid: number;
    exitCode: number | null;
    timedOut: boolean;
    timeoutSeconds: number;
  };
  isolationControls?: Record<string, string>;
  analysisHardening?: Record<string, string>;
  behaviors?: SandboxBehavior[];
  processes?: SandboxProcess[];
  network?: SandboxNetwork[];
  fileArtifacts?: SandboxFileArtifact[];
  runtimeEvents?: SandboxRuntimeEvent[];
  services?: SandboxService[];
  scheduledTasks?: SandboxScheduledTask[];
  telemetry?: Record<string, string | boolean>;
  kernelSensor?: SandboxKernelSensor;
  kernelEvents?: SandboxKernelEvent[];
  stdout?: string;
  stderr?: string;
  errors?: string[];
  error?: string;
  hostReportRoot?: string;
  hostConfigPath?: string;
};

type AttackFlowStage = {
  key: string;
  label: string;
  detail: string;
  active: boolean;
  severity: string;
  count: number;
  icon: string;
};

type AttackStoryProcessNode = {
  pid: number;
  parentPid: number;
  name: string;
  path: string;
  risk: string;
  depth: number;
  order: number;
};

type AttackStoryEvent = {
  id: string;
  time: string;
  type: string;
  title: string;
  detail: string;
  severity: string;
  icon: string;
  pid: number;
};

type AttackStoryEntity = {
  key: string;
  label: string;
  value: number;
  icon: string;
};

type AttackStory = {
  stages: AttackFlowStage[];
  processes: AttackStoryProcessNode[];
  events: AttackStoryEvent[];
  entities: AttackStoryEntity[];
};

const message = useMessage();
const loading = ref(false);
const uploading = ref(false);
const analyzing = ref(false);
const response = ref<Api.DataProtector.SandboxSampleQueryResponse | null>(null);
const selectedSampleId = ref('');
const pollTimer = ref<number | null>(null);

const query = reactive<Api.DataProtector.SandboxSampleQuery>({
  page: 1,
  pageSize: 20,
  status: 'all',
  source: 'all',
  host: '',
  search: ''
});

const analysisForm = reactive({
  arguments: '',
  timeoutSeconds: 120,
  networkEnabled: false,
  closeWhenDone: true
});

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  prefix: page => $t('datatable.itemCount', { total: page.itemCount }),
  onUpdatePage(page) {
    pagination.page = page;
    query.page = page;
    refresh(false);
  },
  onUpdatePageSize(pageSize) {
    pagination.page = 1;
    pagination.pageSize = pageSize;
    query.page = 1;
    query.pageSize = pageSize;
    refresh(false);
  }
});

const samples = computed(() => response.value?.items ?? []);
const selectedSample = computed(() => samples.value.find(item => item.sampleId === selectedSampleId.value) || samples.value[0] || null);
const rawReport = computed(() => parseJson<SandboxReport | null>(selectedSample.value?.reportJson, null));
const report = computed(() => sanitizeSandboxReport(rawReport.value));
const attackStory = computed(() => buildAttackStory(report.value));
const activeAttackFlowStageCount = computed(() => attackStory.value.stages.filter(item => item.active).length);
const stats = computed(() => ({
  total: response.value?.total ?? 0,
  queued: response.value?.queuedTotal ?? 0,
  running: response.value?.runningTotal ?? 0,
  completed: response.value?.completedTotal ?? 0,
  failed: response.value?.failedTotal ?? 0
}));

const statusOptions = computed(() => [
  { label: $t('dataprotector.sandbox.filters.allStatus'), value: 'all' },
  { label: $t('dataprotector.sandbox.status.queued'), value: 'queued' },
  { label: $t('dataprotector.sandbox.status.running'), value: 'running' },
  { label: $t('dataprotector.sandbox.status.completed'), value: 'completed' },
  { label: $t('dataprotector.sandbox.status.failed'), value: 'failed' }
]);

const sourceOptions = computed(() => [
  { label: $t('dataprotector.sandbox.filters.allSources'), value: 'all' },
  { label: $t('dataprotector.sandbox.sources.web'), value: 'web' },
  { label: $t('dataprotector.sandbox.sources.agent'), value: 'agent' }
]);

const sampleColumns = computed<DataTableColumns<Api.DataProtector.SandboxSample>>(() => [
  {
    title: $t('dataprotector.sandbox.columns.sample'),
    key: 'fileName',
    minWidth: 320,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.fileName || '-'}</div>
          <div class="cell-muted mono">{row.sha256 || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.status'),
    key: 'status',
    width: 130,
    render(row) {
      return <NTag type={statusTagType(row.status)} bordered={false}>{statusLabel(row.status)}</NTag>;
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.source'),
    key: 'source',
    width: 150,
    render(row) {
      return (
        <div class="cell-stack">
          <NTag type={row.source === 'agent' ? 'warning' : 'info'} bordered={false}>{sourceLabel(row.source)}</NTag>
          <div class="cell-muted">{row.host || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.fileInfo'),
    key: 'signatureStatus',
    minWidth: 280,
    render(row) {
      return (
        <div class="cell-stack">
          <div class="cell-strong">{row.fileDescription || row.productName || row.architecture || '-'}</div>
          <div class="cell-muted">{row.signer || row.companyName || row.signatureStatus || '-'}</div>
        </div>
      );
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.reason'),
    key: 'suspicion',
    minWidth: 260,
    ellipsis: { tooltip: true }
  },
  {
    title: $t('dataprotector.sandbox.columns.submitted'),
    key: 'submittedUtc',
    width: 190,
    render(row) {
      return formatTime(row.submittedUtc);
    }
  },
  {
    title: $t('dataprotector.common.action'),
    key: 'actions',
    width: 320,
    render(row) {
      return (
        <div class="action-row">
          <NButton size="small" type="primary" secondary disabled={row.status === 'running'} onClick={() => analyze(row)}>
            {$t('dataprotector.sandbox.analyze')}
          </NButton>
          <NButton size="small" secondary onClick={() => selectSample(row)}>
            {$t('dataprotector.sandbox.report')}
          </NButton>
          <NButton size="small" secondary disabled={row.status === 'running' || !row.reportJson} onClick={() => removeLogs(row)}>
            {$t('dataprotector.sandbox.deleteLogs')}
          </NButton>
          <NButton size="small" type="error" secondary disabled={row.status === 'running'} onClick={() => removeSample(row)}>
            {$t('dataprotector.common.delete')}
          </NButton>
        </div>
      );
    }
  }
]);

const behaviorColumns = computed<DataTableColumns<SandboxBehavior>>(() => [
  {
    title: $t('dataprotector.sandbox.columns.severity'),
    key: 'severity',
    width: 110,
    render(row) {
      return <NTag type={severityTagType(row.severity)} bordered={false}>{severityLabel(row.severity)}</NTag>;
    }
  },
  { title: $t('dataprotector.sandbox.columns.type'), key: 'type', width: 190, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.detail'), key: 'detail', minWidth: 360, ellipsis: { tooltip: true } },
  { title: 'PID', key: 'pid', width: 90 },
  {
    title: $t('dataprotector.sandbox.columns.time'),
    key: 'timeUtc',
    width: 180,
    render(row) {
      return formatTime(row.timeUtc);
    }
  }
]);

const processColumns = computed<DataTableColumns<SandboxProcess>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  { title: 'PPID', key: 'parentPid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'name', width: 170, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.sandbox.columns.signature'),
    key: 'signature',
    width: 160,
    render(row) {
      return row.signature?.status || '-';
    }
  },
  { title: $t('dataprotector.sandbox.columns.path'), key: 'path', minWidth: 360, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.command'), key: 'commandLine', minWidth: 360, ellipsis: { tooltip: true } }
]);

const networkColumns = computed<DataTableColumns<SandboxNetwork>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  {
    title: $t('dataprotector.sandbox.columns.remote'),
    key: 'remoteAddress',
    minWidth: 220,
    render(row) {
      return `${row.remoteAddress}:${row.remotePort}`;
    }
  },
  {
    title: $t('dataprotector.sandbox.columns.local'),
    key: 'localAddress',
    minWidth: 220,
    render(row) {
      return `${row.localAddress}:${row.localPort}`;
    }
  },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 130 },
  {
    title: $t('dataprotector.sandbox.columns.time'),
    key: 'timeUtc',
    width: 180,
    render(row) {
      return formatTime(row.timeUtc);
    }
  }
]);

const fileColumns = computed<DataTableColumns<SandboxFileArtifact>>(() => [
  { title: $t('dataprotector.sandbox.columns.path'), key: 'path', minWidth: 360, ellipsis: { tooltip: true } },
  {
    title: $t('dataprotector.sandbox.columns.size'),
    key: 'size',
    width: 120,
    render(row) {
      return formatBytes(row.size);
    }
  },
  { title: 'SHA256', key: 'sha256', minWidth: 320, ellipsis: { tooltip: true } }
]);

const runtimeColumns = computed<DataTableColumns<SandboxRuntimeEvent>>(() => [
  { title: 'PID', key: 'pid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.action'), key: 'action', minWidth: 260, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.target'), key: 'target', minWidth: 280, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.statusText'), key: 'status', width: 130 },
  {
    title: $t('dataprotector.sandbox.columns.blocked'),
    key: 'blocked',
    width: 110,
    render(row) {
      return <NTag type={row.blocked ? 'error' : 'success'} bordered={false}>{row.blocked ? 'Yes' : 'No'}</NTag>;
    }
  },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'processImage', minWidth: 300, ellipsis: { tooltip: true } }
]);

const kernelColumns = computed<DataTableColumns<SandboxKernelEvent>>(() => [
  { title: $t('dataprotector.sandbox.columns.sequence'), key: 'sequence', width: 110 },
  { title: 'PID', key: 'pid', width: 90 },
  { title: 'PPID', key: 'parentPid', width: 90 },
  { title: $t('dataprotector.sandbox.columns.operation'), key: 'operationName', minWidth: 220, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.statusText'), key: 'status', width: 130 },
  { title: $t('dataprotector.sandbox.columns.target'), key: 'target', minWidth: 360, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.process'), key: 'processImage', minWidth: 300, ellipsis: { tooltip: true } }
]);

const serviceColumns = computed<DataTableColumns<SandboxService>>(() => [
  { title: $t('dataprotector.sandbox.columns.change'), key: 'change', width: 120 },
  { title: $t('dataprotector.sandbox.columns.service'), key: 'name', width: 180, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.type'), key: 'serviceType', width: 160, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 120 },
  { title: $t('dataprotector.sandbox.columns.path'), key: 'pathName', minWidth: 420, ellipsis: { tooltip: true } }
]);

const taskColumns = computed<DataTableColumns<SandboxScheduledTask>>(() => [
  { title: $t('dataprotector.sandbox.columns.change'), key: 'change', width: 120 },
  { title: $t('dataprotector.sandbox.columns.task'), key: 'name', minWidth: 260, ellipsis: { tooltip: true } },
  { title: $t('dataprotector.sandbox.columns.state'), key: 'state', width: 120 },
  { title: $t('dataprotector.sandbox.columns.command'), key: 'command', minWidth: 420, ellipsis: { tooltip: true } }
]);

async function refresh(resetPage = false) {
  if (resetPage) {
    pagination.page = 1;
    query.page = 1;
  }

  query.page = pagination.page;
  query.pageSize = pagination.pageSize;
  loading.value = true;
  try {
    const { error, data } = await fetchSandboxSamples(query);
    if (!error) {
      response.value = data;
      pagination.itemCount = data.total;
      pagination.page = data.page;
      pagination.pageSize = data.pageSize;
      if (!selectedSampleId.value && data.items.length) {
        selectedSampleId.value = data.items[0].sampleId;
      }
      if (selectedSampleId.value && !data.items.some(item => item.sampleId === selectedSampleId.value) && data.items.length) {
        selectedSampleId.value = data.items[0].sampleId;
      }
    }
  } finally {
    loading.value = false;
  }
}

async function uploadSample(options: UploadCustomRequestOptions) {
  const file = options.file.file;
  if (!file) {
    options.onError?.();
    return;
  }

  if (!file.name.toLowerCase().endsWith('.exe')) {
    message.warning($t('dataprotector.sandbox.exeOnly'));
    options.onError?.();
    return;
  }

  uploading.value = true;
  try {
    const contentBase64 = await fileToBase64(file);
    const { error, data } = await fetchSubmitSandboxSample({
      fileName: file.name,
      contentBase64,
      source: 'web',
      host: 'web-admin',
      suspicion: $t('dataprotector.sandbox.webUploadReason'),
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success($t('dataprotector.sandbox.uploaded'));
      await refresh(true);
      options.onFinish?.();
      return;
    }

    options.onError?.();
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error));
    options.onError?.();
  } finally {
    uploading.value = false;
  }
}

async function analyze(row = selectedSample.value) {
  if (!row) return;

  analyzing.value = true;
  try {
    const { error, data } = await fetchStartSandboxAnalysis({
      sampleId: row.sampleId,
      arguments: analysisForm.arguments,
      timeoutSeconds: analysisForm.timeoutSeconds,
      networkEnabled: analysisForm.networkEnabled,
      closeWhenDone: analysisForm.closeWhenDone,
      actor: 'web-admin'
    });
    if (!error) {
      selectedSampleId.value = data.sampleId;
      message.success($t('dataprotector.sandbox.started'));
      startPolling();
      await refresh(false);
    }
  } finally {
    analyzing.value = false;
  }
}

function selectSample(row: Api.DataProtector.SandboxSample) {
  selectedSampleId.value = row.sampleId;
}

function removeSample(row: Api.DataProtector.SandboxSample) {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.deleteTitle'),
    content: $t('dataprotector.sandbox.deleteContent', { name: row.fileName }),
    positiveText: $t('dataprotector.common.delete'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveSandboxSample({ sampleId: row.sampleId, actor: 'web-admin' });
      if (!error && data.succeeded) {
        if (selectedSampleId.value === row.sampleId) selectedSampleId.value = '';
        message.success($t('dataprotector.sandbox.deleted'));
        await refresh(false);
      }
    }
  });
}

function removeLogs(row: Api.DataProtector.SandboxSample) {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.deleteLogsTitle'),
    content: $t('dataprotector.sandbox.deleteLogsContent', { name: row.fileName }),
    positiveText: $t('dataprotector.sandbox.deleteLogs'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const reportValue = parseJson<SandboxReport | null>(row.reportJson, null);
      const { error, data } = await fetchRemoveSandboxLogs({
        sampleId: row.sampleId,
        runId: reportValue?.runId,
        actor: 'web-admin'
      });
      if (!error && data.succeeded) {
        message.success($t('dataprotector.sandbox.logsDeleted'));
        await refresh(false);
      }
    }
  });
}

function clearLogs() {
  window.$dialog?.warning({
    title: $t('dataprotector.sandbox.clearLogsTitle'),
    content: $t('dataprotector.sandbox.clearLogsContent'),
    positiveText: $t('dataprotector.sandbox.clearLogs'),
    negativeText: $t('dataprotector.common.cancel'),
    onPositiveClick: async () => {
      const { error, data } = await fetchRemoveSandboxLogs({ all: true, actor: 'web-admin' });
      if (!error && data.succeeded) {
        selectedSampleId.value = '';
        response.value = {
          page: pagination.page || 1,
          pageSize: pagination.pageSize || 20,
          total: 0,
          queuedTotal: 0,
          runningTotal: 0,
          completedTotal: 0,
          failedTotal: 0,
          items: []
        };
        pagination.itemCount = 0;
        message.success($t('dataprotector.sandbox.logsCleared'));
        await refresh(false);
      }
    }
  });
}

function startPolling() {
  stopPolling();
  pollTimer.value = window.setInterval(async () => {
    await refresh(false);
    if (!samples.value.some(item => item.status === 'running')) {
      stopPolling();
    }
  }, 3000);
}

function stopPolling() {
  if (pollTimer.value !== null) {
    window.clearInterval(pollTimer.value);
    pollTimer.value = null;
  }
}

function rowKey(row: Api.DataProtector.SandboxSample) {
  return row.sampleId;
}

function rowProps(row: Api.DataProtector.SandboxSample) {
  return {
    class: row.sampleId === selectedSampleId.value ? 'selected-row' : '',
    onClick: () => selectSample(row)
  };
}

function fileToBase64(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const value = String(reader.result || '');
      const comma = value.indexOf(',');
      resolve(comma >= 0 ? value.slice(comma + 1) : value);
    };
    reader.readAsDataURL(file);
  });
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function sanitizeSandboxReport(value: SandboxReport | null) {
  if (!value) return null;

  const reportClone: SandboxReport = {
    ...value,
    behaviors: [...(value.behaviors || [])],
    processes: [...(value.processes || [])],
    network: [...(value.network || [])],
    fileArtifacts: [...(value.fileArtifacts || [])],
    runtimeEvents: [...(value.runtimeEvents || [])],
    kernelEvents: [...(value.kernelEvents || [])],
    services: [...(value.services || [])],
    scheduledTasks: [...(value.scheduledTasks || [])]
  };

  const internalPids = new Set(
    (reportClone.processes || [])
      .filter(process => isInternalProcess(process))
      .map(process => process.pid)
      .filter(pid => Number.isFinite(pid))
  );

  reportClone.behaviors = reportClone.behaviors?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.type) &&
      !isInternalTelemetryText(item.detail)
  );
  reportClone.processes = reportClone.processes?.filter(item => item && !internalPids.has(item.pid) && !isInternalProcess(item));
  reportClone.network = reportClone.network?.filter(item => item && !internalPids.has(item.pid));
  reportClone.fileArtifacts = reportClone.fileArtifacts?.filter(item => item && !isInternalTelemetryText(item.path));
  reportClone.runtimeEvents = reportClone.runtimeEvents?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.action) &&
      !isInternalTelemetryText(item.target) &&
      !isInternalTelemetryText(item.processImage)
  );
  reportClone.kernelEvents = reportClone.kernelEvents?.filter(
    item =>
      item &&
      !internalPids.has(item.pid) &&
      !isInternalTelemetryText(item.operationName) &&
      !isInternalTelemetryText(item.target) &&
      !isInternalTelemetryText(item.processImage) &&
      !isInternalTelemetryText(item.description)
  );
  reportClone.services = reportClone.services?.filter(
    item =>
      item &&
      !isInternalTelemetryText(item.name) &&
      !isInternalTelemetryText(item.displayName) &&
      !isInternalTelemetryText(item.pathName)
  );
  reportClone.scheduledTasks = reportClone.scheduledTasks?.filter(
    item => item && !isInternalTelemetryText(item.name) && !isInternalTelemetryText(item.command)
  );

  return reportClone;
}

function isInternalProcess(process: SandboxProcess) {
  return (
    isInternalTelemetryText(process.name) ||
    isInternalTelemetryText(process.path) ||
    isInternalTelemetryText(process.commandLine)
  );
}

function isInternalTelemetryText(value?: string) {
  const text = String(value || '').toLowerCase();
  if (!text) return false;

  return [
    'dataprotectorsandboxtelemetry',
    'dataprotectorsandbox',
    'dataprotectoruserhookruntime',
    'dataprotectorpolicyapi',
    'dataprotector.sys',
    'dataprotectorsandbox.sys',
    'dataprotector\\sandbox',
    '\\dataprotector\\userhook',
    'userhook.observed',
    'sandbox-kernel-sensor',
    'kernel-early-injection-policy'
  ].some(token => text.includes(token));
}

function buildAttackStory(value: SandboxReport | null): AttackStory {
  return {
    stages: buildAttackFlowStages(value),
    processes: buildAttackProcessGraph(value).slice(0, 8),
    events: buildAttackStoryEvents(value).slice(0, 10),
    entities: buildAttackStoryEntities(value)
  };
}

function buildAttackFlowStages(value: SandboxReport | null): AttackFlowStage[] {
  const behaviors = value?.behaviors || [];
  const processes = value?.processes || [];
  const network = value?.network || [];
  const artifacts = value?.fileArtifacts || [];
  const runtimeEvents = value?.runtimeEvents || [];
  const kernelEvents = value?.kernelEvents || [];
  const services = value?.services || [];
  const tasks = value?.scheduledTasks || [];

  const childProcessCount = processes.filter(process => process.parentPid && process.pid !== value?.execution?.pid).length;
  const commandCount = countTextMatches(
    [...behaviors.map(item => `${item.type} ${item.detail}`), ...processes.map(item => item.commandLine)],
    ['process', 'command', 'powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'wscript', 'cscript', 'mshta']
  );
  const memoryCount = countTextMatches(
    [
      ...behaviors.map(item => `${item.type} ${item.detail}`),
      ...runtimeEvents.map(item => `${item.action} ${item.target}`),
      ...kernelEvents.map(item => `${item.operationName} ${item.description} ${item.target}`)
    ],
    ['virtualalloc', 'writeprocessmemory', 'createremotethread', 'syscall', 'unhook', 'executable memory', 'module reload', 'native-module']
  );
  const persistenceCount =
    services.length +
    tasks.length +
    countTextMatches(
      [...behaviors.map(item => `${item.type} ${item.detail}`), ...runtimeEvents.map(item => `${item.action} ${item.target}`)],
      ['registry', 'autorun', 'run key', 'scheduled task', 'service', 'driver']
    );
  const artifactCount =
    artifacts.length +
    countTextMatches(
      [...behaviors.map(item => `${item.type} ${item.detail}`), ...kernelEvents.map(item => `${item.operationName} ${item.target}`)],
      ['file-artifacts', 'drop', 'write-file', 'driver']
    );

  return [
    createAttackFlowStage('launch', true, 1, 'medium', 'mdi:rocket-launch-outline'),
    createAttackFlowStage('process', childProcessCount > 0 || commandCount > 0, childProcessCount + commandCount, 'high', 'mdi:family-tree'),
    createAttackFlowStage('apiMemory', memoryCount > 0, memoryCount, 'critical', 'mdi:memory'),
    createAttackFlowStage('network', network.length > 0, network.length, 'medium', 'mdi:access-point-network'),
    createAttackFlowStage('persistence', persistenceCount > 0, persistenceCount, 'critical', 'mdi:shield-key-outline'),
    createAttackFlowStage('artifact', artifactCount > 0, artifactCount, 'high', 'mdi:file-cog-outline')
  ];
}

function buildAttackProcessGraph(value: SandboxReport | null): AttackStoryProcessNode[] {
  const processes = [...(value?.processes || [])].sort((left, right) => {
    const leftTime = Date.parse(left.createdUtc || '') || 0;
    const rightTime = Date.parse(right.createdUtc || '') || 0;
    return leftTime - rightTime;
  });
  const pidSet = new Set(processes.map(item => item.pid));
  const riskByPid = new Map<number, string>();

  for (const behavior of value?.behaviors || []) {
    if (!behavior?.pid) continue;
    riskByPid.set(behavior.pid, maxSeverity(riskByPid.get(behavior.pid), behavior.severity));
  }
  for (const event of value?.runtimeEvents || []) {
    if (!event?.pid) continue;
    riskByPid.set(event.pid, maxSeverity(riskByPid.get(event.pid), event.blocked ? 'high' : 'medium'));
  }
  for (const event of value?.kernelEvents || []) {
    if (!event?.pid) continue;
    riskByPid.set(event.pid, maxSeverity(riskByPid.get(event.pid), 'high'));
  }

  return processes.map((process, index) => ({
    pid: process.pid,
    parentPid: process.parentPid,
    name: process.name || basename(process.path) || `PID ${process.pid}`,
    path: process.path || process.commandLine || '-',
    risk: riskByPid.get(process.pid) || 'info',
    depth: process.parentPid && pidSet.has(process.parentPid) ? 1 : 0,
    order: index + 1
  }));
}

function buildAttackStoryEvents(value: SandboxReport | null): AttackStoryEvent[] {
  const events: AttackStoryEvent[] = [];

  for (const behavior of value?.behaviors || []) {
    events.push({
      id: `behavior-${events.length}`,
      time: behavior.timeUtc,
      type: behavior.type || 'behavior',
      title: normalizeEventTitle(behavior.type || 'behavior'),
      detail: behavior.detail || '-',
      severity: behavior.severity || 'info',
      icon: eventIcon(behavior.type),
      pid: behavior.pid || 0
    });
  }

  for (const runtime of value?.runtimeEvents || []) {
    events.push({
      id: `runtime-${events.length}`,
      time: runtime.timestampUtc,
      type: runtime.action || 'runtime',
      title: normalizeEventTitle(runtime.action || 'runtime'),
      detail: runtime.target || runtime.processImage || '-',
      severity: runtime.blocked ? 'high' : 'medium',
      icon: eventIcon(runtime.action),
      pid: runtime.pid || 0
    });
  }

  for (const kernel of value?.kernelEvents || []) {
    events.push({
      id: `kernel-${events.length}`,
      time: value?.completedUtc || value?.startedUtc || '',
      type: kernel.operationName || 'kernel',
      title: normalizeEventTitle(kernel.operationName || 'kernel'),
      detail: kernel.target || kernel.description || kernel.processImage || '-',
      severity: 'high',
      icon: eventIcon(kernel.operationName),
      pid: kernel.pid || 0
    });
  }

  return events.sort((left, right) => (Date.parse(left.time || '') || 0) - (Date.parse(right.time || '') || 0));
}

function buildAttackStoryEntities(value: SandboxReport | null): AttackStoryEntity[] {
  return [
    {
      key: 'processes',
      label: $t('dataprotector.sandbox.attackFlow.entities.processes'),
      value: value?.processes?.length || 0,
      icon: 'mdi:family-tree'
    },
    {
      key: 'network',
      label: $t('dataprotector.sandbox.attackFlow.entities.network'),
      value: value?.network?.length || 0,
      icon: 'mdi:access-point-network'
    },
    {
      key: 'persistence',
      label: $t('dataprotector.sandbox.attackFlow.entities.persistence'),
      value: (value?.services?.length || 0) + (value?.scheduledTasks?.length || 0),
      icon: 'mdi:shield-key-outline'
    },
    {
      key: 'artifacts',
      label: $t('dataprotector.sandbox.attackFlow.entities.artifacts'),
      value: value?.fileArtifacts?.length || 0,
      icon: 'mdi:file-cog-outline'
    }
  ];
}

function createAttackFlowStage(key: string, active: boolean, count: number, severity: string, icon: string) {
  const stageKey = key as keyof typeof attackFlowStageLabelKeys;
  return {
    key,
    label: $t(attackFlowStageLabelKeys[stageKey]),
    detail: active
      ? $t(attackFlowStageDetailKeys[stageKey], { count: Math.max(count, 1) })
      : $t('dataprotector.sandbox.attackFlow.details.idle'),
    active,
    severity,
    count,
    icon
  };
}

const attackFlowStageLabelKeys = {
  launch: 'dataprotector.sandbox.attackFlow.stages.launch',
  process: 'dataprotector.sandbox.attackFlow.stages.process',
  apiMemory: 'dataprotector.sandbox.attackFlow.stages.apiMemory',
  network: 'dataprotector.sandbox.attackFlow.stages.network',
  persistence: 'dataprotector.sandbox.attackFlow.stages.persistence',
  artifact: 'dataprotector.sandbox.attackFlow.stages.artifact'
} as const satisfies Record<string, App.I18n.I18nKey>;

const attackFlowStageDetailKeys = {
  launch: 'dataprotector.sandbox.attackFlow.details.launch',
  process: 'dataprotector.sandbox.attackFlow.details.process',
  apiMemory: 'dataprotector.sandbox.attackFlow.details.apiMemory',
  network: 'dataprotector.sandbox.attackFlow.details.network',
  persistence: 'dataprotector.sandbox.attackFlow.details.persistence',
  artifact: 'dataprotector.sandbox.attackFlow.details.artifact'
} as const satisfies Record<string, App.I18n.I18nKey>;

function countTextMatches(values: string[], tokens: string[]) {
  return values.reduce((count, value) => {
    const text = String(value || '').toLowerCase();
    return count + (tokens.some(token => text.includes(token)) ? 1 : 0);
  }, 0);
}

function maxSeverity(current: string | undefined, next: string | undefined) {
  const score: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const currentSeverity = current || 'info';
  const nextSeverity = next || 'info';
  return (score[nextSeverity] ?? 0) > (score[currentSeverity] ?? 0) ? nextSeverity : currentSeverity;
}

function basename(path?: string) {
  const value = String(path || '');
  const index = Math.max(value.lastIndexOf('\\'), value.lastIndexOf('/'));
  return index >= 0 ? value.slice(index + 1) : value;
}

function normalizeEventTitle(value?: string) {
  const text = String(value || '').replace(/[-_.]+/g, ' ').trim();
  if (!text) return '-';
  return text.replace(/\b\w/g, char => char.toUpperCase());
}

function eventIcon(value?: string) {
  const text = String(value || '').toLowerCase();
  if (text.includes('network') || text.includes('connect') || text.includes('dns')) return 'mdi:access-point-network';
  if (text.includes('registry') || text.includes('task') || text.includes('service') || text.includes('persist')) return 'mdi:shield-key-outline';
  if (text.includes('memory') || text.includes('hook') || text.includes('syscall') || text.includes('virtual')) return 'mdi:memory';
  if (text.includes('file') || text.includes('driver') || text.includes('drop')) return 'mdi:file-cog-outline';
  if (text.includes('process') || text.includes('command') || text.includes('injection')) return 'mdi:source-branch';
  return 'mdi:radar';
}

function statusTagType(status: string) {
  if (status === 'completed') return 'success';
  if (status === 'running') return 'info';
  if (status === 'failed') return 'error';
  return 'warning';
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: $t('dataprotector.sandbox.status.queued'),
    running: $t('dataprotector.sandbox.status.running'),
    completed: $t('dataprotector.sandbox.status.completed'),
    failed: $t('dataprotector.sandbox.status.failed')
  };
  return labels[status] || status;
}

function sourceLabel(source: string) {
  return source === 'agent' ? $t('dataprotector.sandbox.sources.agent') : $t('dataprotector.sandbox.sources.web');
}

function severityTagType(severity: string) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'info';
  return 'default';
}

function severityLabel(severity: string) {
  const labels: Record<string, string> = {
    critical: $t('dataprotector.sandbox.severity.critical'),
    high: $t('dataprotector.sandbox.severity.high'),
    medium: $t('dataprotector.sandbox.severity.medium'),
    low: $t('dataprotector.sandbox.severity.low'),
    info: $t('dataprotector.sandbox.severity.info')
  };
  return labels[severity] || labels.info;
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

onMounted(async () => {
  await refresh(false);
  if (samples.value.some(item => item.status === 'running')) startPolling();
});

onBeforeUnmount(stopPolling);
</script>

<template>
  <div class="sandbox-page">
    <NCard :bordered="false" class="hero-card">
      <div class="hero-content">
        <div>
          <div class="eyebrow">{{ $t('dataprotector.sandbox.eyebrow') }}</div>
          <h1>{{ $t('dataprotector.sandbox.title') }}</h1>
          <p>{{ $t('dataprotector.sandbox.subtitle') }}</p>
        </div>
        <NSpace align="center" wrap>
          <NTag type="success" :bordered="false">{{ $t('dataprotector.sandbox.serverOnly') }}</NTag>
          <NUpload :show-file-list="false" accept=".exe,application/x-msdownload" :custom-request="uploadSample">
            <NButton type="primary" :loading="uploading">
              <template #icon><SvgIcon icon="mdi:upload-lock-outline" /></template>
              {{ $t('dataprotector.sandbox.upload') }}
            </NButton>
          </NUpload>
        </NSpace>
      </div>
    </NCard>

    <NGrid :cols="5" :x-gap="16" :y-gap="16" responsive="screen">
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.total')" :value="stats.total" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.queued')" :value="stats.queued" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.running')" :value="stats.running" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.completed')" :value="stats.completed" />
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="metric-card">
          <NStatistic :label="$t('dataprotector.sandbox.metrics.failed')" :value="stats.failed" />
        </NCard>
      </NGi>
    </NGrid>

    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 xl:15">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>{{ $t('dataprotector.sandbox.queue') }}</span>
              <NSpace align="center" wrap>
                <NButton secondary :disabled="loading || samples.some(item => item.status === 'running')" @click="clearLogs">
                  <template #icon><SvgIcon icon="mdi:delete-sweep-outline" /></template>
                  {{ $t('dataprotector.sandbox.clearLogs') }}
                </NButton>
                <NButton type="primary" :loading="loading" @click="refresh(false)">
                  <template #icon><SvgIcon icon="mdi:refresh" /></template>
                  {{ $t('dataprotector.common.refresh') }}
                </NButton>
              </NSpace>
            </div>
          </template>

          <NSpace align="center" wrap class="filters">
            <NSelect v-model:value="query.status" :options="statusOptions" class="filter-control" />
            <NSelect v-model:value="query.source" :options="sourceOptions" class="filter-control" />
            <NInput v-model:value="query.host" clearable :placeholder="$t('dataprotector.sandbox.filters.host')" class="filter-control" />
            <NInput
              v-model:value="query.search"
              clearable
              :placeholder="$t('dataprotector.sandbox.filters.search')"
              class="search-control"
              @keyup.enter="refresh(true)"
            />
            <NButton secondary @click="refresh(true)">{{ $t('dataprotector.common.apply') }}</NButton>
          </NSpace>

          <NDataTable
            :columns="sampleColumns"
            :data="samples"
            :loading="loading"
            :row-key="rowKey"
            :row-props="rowProps"
            :pagination="pagination"
            remote
            :scroll-x="1880"
            size="small"
          />
        </NCard>
      </NGi>

      <NGi span="24 xl:9">
        <NCard :bordered="false" class="work-panel">
          <template #header>
            <div class="panel-title">
              <span>{{ $t('dataprotector.sandbox.analysis') }}</span>
              <NTag v-if="selectedSample" :type="statusTagType(selectedSample.status)" :bordered="false">
                {{ statusLabel(selectedSample.status) }}
              </NTag>
            </div>
          </template>

          <template v-if="selectedSample">
            <div class="sample-summary">
              <div class="cell-strong">{{ selectedSample.fileName }}</div>
              <div class="cell-muted mono">{{ selectedSample.sha256 }}</div>
              <div class="tag-row">
                <NTag :type="selectedSample.source === 'agent' ? 'warning' : 'info'" :bordered="false">
                  {{ sourceLabel(selectedSample.source) }}
                </NTag>
                <NTag :type="selectedSample.signatureStatus === 'signed' ? 'success' : 'error'" :bordered="false">
                  {{ selectedSample.signatureStatus || $t('dataprotector.common.unknown') }}
                </NTag>
                <NTag :bordered="false">{{ selectedSample.architecture || '-' }}</NTag>
              </div>
            </div>

            <NForm label-placement="top" class="analysis-form">
              <NFormItem :label="$t('dataprotector.sandbox.arguments')">
                <NInput v-model:value="analysisForm.arguments" clearable :placeholder="$t('dataprotector.sandbox.argumentsPlaceholder')" />
              </NFormItem>
              <NGrid :x-gap="12" :y-gap="12" cols="1 m:2">
                <NGi>
                  <NFormItem :label="$t('dataprotector.sandbox.timeout')">
                    <NInputNumber v-model:value="analysisForm.timeoutSeconds" :min="15" :max="1800" class="w-full" />
                  </NFormItem>
                </NGi>
                <NGi>
                  <NFormItem :label="$t('dataprotector.sandbox.options')">
                    <div class="checks">
                      <NCheckbox v-model:checked="analysisForm.networkEnabled">
                        {{ $t('dataprotector.sandbox.enableNetwork') }}
                      </NCheckbox>
                      <NCheckbox v-model:checked="analysisForm.closeWhenDone">
                        {{ $t('dataprotector.sandbox.closeWhenDone') }}
                      </NCheckbox>
                    </div>
                  </NFormItem>
                </NGi>
              </NGrid>
              <NButton type="primary" :loading="analyzing || selectedSample.status === 'running'" @click="analyze(selectedSample)">
                <template #icon><SvgIcon icon="mdi:shield-search" /></template>
                {{ $t('dataprotector.sandbox.analyze') }}
              </NButton>
            </NForm>

            <NDescriptions class="m-t-14px" :column="1" bordered size="small">
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.host')">{{ selectedSample.host || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.path')">{{ selectedSample.processPath || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.reason')">{{ selectedSample.suspicion || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.error')">{{ selectedSample.error || '-' }}</NDescriptionsItem>
            </NDescriptions>
          </template>
          <NEmpty v-else :description="$t('dataprotector.sandbox.empty')" />
        </NCard>
      </NGi>
    </NGrid>

    <NCard :bordered="false" class="work-panel">
      <template #header>
        <div class="panel-title">
          <span>{{ $t('dataprotector.sandbox.report') }}</span>
          <NButton
            v-if="selectedSample"
            secondary
            type="error"
            :disabled="selectedSample.status === 'running' || !selectedSample.reportJson"
            @click="removeLogs(selectedSample)"
          >
            <template #icon><SvgIcon icon="mdi:file-document-remove-outline" /></template>
            {{ $t('dataprotector.sandbox.deleteLogs') }}
          </NButton>
        </div>
      </template>
      <template v-if="selectedSample && report">
        <div class="report-summary">
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.behaviors') }}</span>
            <strong>{{ report.behaviors?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.processes') }}</span>
            <strong>{{ report.processes?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.network') }}</span>
            <strong>{{ report.network?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.artifacts') }}</span>
            <strong>{{ report.fileArtifacts?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.runtime') }}</span>
            <strong>{{ report.runtimeEvents?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.kernel') }}</span>
            <strong>{{ report.kernelEvents?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.services') }}</span>
            <strong>{{ report.services?.length || 0 }}</strong>
          </div>
          <div class="report-metric">
            <span>{{ $t('dataprotector.sandbox.reportMetrics.tasks') }}</span>
            <strong>{{ report.scheduledTasks?.length || 0 }}</strong>
          </div>
        </div>

        <div class="attack-flow-panel">
          <div class="attack-flow-header">
            <div>
              <div class="eyebrow">{{ $t('dataprotector.sandbox.attackFlow.eyebrow') }}</div>
              <h3>{{ $t('dataprotector.sandbox.attackFlow.title') }}</h3>
            </div>
            <NTag type="info" :bordered="false">
              {{ $t('dataprotector.sandbox.attackFlow.active', { count: activeAttackFlowStageCount }) }}
            </NTag>
          </div>

          <div class="story-stage-rail">
            <div
              v-for="stage in attackStory.stages"
              :key="stage.key"
              class="story-stage"
              :class="[{ active: stage.active }, `severity-${stage.severity}`]"
            >
              <SvgIcon :icon="stage.icon" />
              <span>{{ stage.label }}</span>
            </div>
          </div>

          <div class="attack-story-grid">
            <div class="story-process-panel">
              <div class="story-panel-title">{{ $t('dataprotector.sandbox.attackFlow.processGraph') }}</div>
              <div class="process-graph">
                <div
                  v-for="node in attackStory.processes"
                  :key="`${node.pid}-${node.order}`"
                  class="process-node"
                  :class="[`severity-${node.risk}`, { child: node.depth > 0 }]"
                  :style="{ marginLeft: `${node.depth * 22}px` }"
                >
                  <div class="process-dot" />
                  <div class="process-copy">
                    <div class="process-name">{{ node.name }}</div>
                    <div class="process-meta">PID {{ node.pid }} · PPID {{ node.parentPid || '-' }}</div>
                    <div class="process-path">{{ node.path }}</div>
                  </div>
                </div>
                <NEmpty v-if="!attackStory.processes.length" :description="$t('dataprotector.sandbox.attackFlow.empty')" />
              </div>
            </div>

            <div class="story-timeline-panel">
              <div class="story-panel-title">{{ $t('dataprotector.sandbox.attackFlow.timeline') }}</div>
              <div class="story-timeline">
                <div
                  v-for="event in attackStory.events"
                  :key="event.id"
                  class="timeline-event"
                  :class="`severity-${event.severity}`"
                >
                  <div class="timeline-marker">
                    <SvgIcon :icon="event.icon" />
                  </div>
                  <div class="timeline-card">
                    <div class="timeline-topline">
                      <span>{{ event.title }}</span>
                      <small>{{ formatTime(event.time) }}</small>
                    </div>
                    <div class="timeline-detail">{{ event.detail }}</div>
                    <div class="timeline-meta">PID {{ event.pid || '-' }} · {{ severityLabel(event.severity) }}</div>
                  </div>
                </div>
                <NEmpty v-if="!attackStory.events.length" :description="$t('dataprotector.sandbox.attackFlow.empty')" />
              </div>
            </div>
          </div>

          <div class="story-entity-row">
            <div v-for="entity in attackStory.entities" :key="entity.key" class="story-entity">
              <SvgIcon :icon="entity.icon" />
              <span>{{ entity.label }}</span>
              <strong>{{ entity.value }}</strong>
            </div>
          </div>
        </div>

        <NAlert v-if="report.error || report.errors?.length" type="warning" :bordered="false" class="m-b-12px">
          {{ report.error || report.errors?.join('; ') }}
        </NAlert>

        <NDescriptions :column="2" bordered size="small" class="m-b-14px">
          <NDescriptionsItem :label="$t('dataprotector.sandbox.boundary')">
            {{ report.isolationControls?.boundary || report.isolation }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.network')">
            {{ report.isolationControls?.network || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.exitCode')">
            {{ report.execution?.exitCode ?? '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.duration')">
            {{ formatTime(report.startedUtc) }} - {{ formatTime(report.completedUtc) }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.telemetryMode')">
            {{ report.telemetry?.mode || report.schema || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.runtimeHook')">
            {{ report.telemetry?.runtimeHook || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.kernelSensor')">
            {{ report.kernelSensor?.status || report.telemetry?.kernelSensor || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="$t('dataprotector.sandbox.kernelPolicy')">
            {{ report.kernelSensor?.policyStatus || '-' }}
          </NDescriptionsItem>
        </NDescriptions>

        <NCollapse>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.behaviors')" name="behaviors">
            <NDataTable :columns="behaviorColumns" :data="report.behaviors || []" :scroll-x="920" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.processes')" name="processes">
            <NDataTable :columns="processColumns" :data="report.processes || []" :scroll-x="1200" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.network')" name="network">
            <NDataTable :columns="networkColumns" :data="report.network || []" :scroll-x="900" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.artifacts')" name="artifacts">
            <NDataTable :columns="fileColumns" :data="report.fileArtifacts || []" :scroll-x="860" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.runtime')" name="runtime">
            <NDataTable :columns="runtimeColumns" :data="report.runtimeEvents || []" :scroll-x="1260" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.kernel')" name="kernel">
            <NDescriptions v-if="report.kernelSensor" :column="2" bordered size="small" class="m-b-12px">
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.status')">{{ report.kernelSensor.status }}</NDescriptionsItem>
              <NDescriptionsItem label="Win32">{{ report.kernelSensor.win32 || 0 }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.service')">{{ report.kernelSensor.serviceName || '-' }}</NDescriptionsItem>
              <NDescriptionsItem :label="$t('dataprotector.sandbox.columns.message')">{{ report.kernelSensor.message || '-' }}</NDescriptionsItem>
            </NDescriptions>
            <NDataTable :columns="kernelColumns" :data="report.kernelEvents || []" :scroll-x="1360" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.services')" name="services">
            <NDataTable :columns="serviceColumns" :data="report.services || []" :scroll-x="1200" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.tasks')" name="tasks">
            <NDataTable :columns="taskColumns" :data="report.scheduledTasks || []" :scroll-x="1100" :pagination="{ pageSize: 8 }" />
          </NCollapseItem>
          <NCollapseItem :title="$t('dataprotector.sandbox.sections.output')" name="output">
            <pre class="sandbox-output">{{ report.stdout || report.stderr || selectedSample.reportJson }}</pre>
          </NCollapseItem>
        </NCollapse>
      </template>
      <NEmpty v-else :description="$t('dataprotector.sandbox.noReport')" />
    </NCard>
  </div>
</template>

<style scoped>
.sandbox-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.hero-card,
.metric-card,
.work-panel {
  border-radius: 8px;
}

.hero-content {
  display: flex;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
}

.hero-content h1 {
  margin: 4px 0 6px;
  font-size: 24px;
  font-weight: 800;
}

.hero-content p {
  margin: 0;
  color: var(--n-text-color-3);
}

.eyebrow {
  color: #7c3aed;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
}

.panel-title,
.action-row,
.tag-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.action-row {
  flex-wrap: wrap;
}

.panel-title {
  justify-content: space-between;
}

.filters {
  margin-bottom: 16px;
}

.filter-control {
  width: 180px;
}

.search-control {
  width: min(380px, 100%);
}

.cell-stack,
.sample-summary {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}

.cell-strong {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color);
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-muted {
  min-width: 0;
  overflow: hidden;
  color: var(--n-text-color-3);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace;
}

.analysis-form {
  margin-top: 16px;
}

.checks {
  display: grid;
  gap: 8px;
}

.report-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.report-metric {
  padding: 12px;
  background: rgb(249 250 251);
  border: 1px solid rgb(229 231 235);
  border-radius: 8px;
}

.report-metric span {
  display: block;
  color: var(--n-text-color-3);
  font-size: 12px;
}

.report-metric strong {
  display: block;
  margin-top: 4px;
  font-size: 22px;
}

.attack-flow-panel {
  position: relative;
  padding: 16px;
  overflow: hidden;
  background:
    linear-gradient(135deg, rgb(37 24 66 / 95%), rgb(11 18 32 / 97%)),
    radial-gradient(circle at 20% 18%, rgb(125 92 255 / 22%), transparent 34%);
  border: 1px solid rgb(167 139 250 / 26%);
  border-radius: 8px;
  box-shadow: inset 0 1px 0 rgb(255 255 255 / 8%), 0 18px 42px rgb(30 21 54 / 18%);
  margin-bottom: 14px;
}

.attack-flow-panel::before {
  position: absolute;
  inset: 0;
  pointer-events: none;
  content: '';
  background: linear-gradient(110deg, transparent 0%, rgb(255 255 255 / 8%) 46%, transparent 62%);
  opacity: 0.7;
  transform: translateX(-120%);
  animation: flow-sheen 6s ease-in-out infinite;
}

.attack-flow-header {
  position: relative;
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 14px;
}

.attack-flow-header h3 {
  margin: 3px 0 0;
  color: #ffffff;
  font-size: 17px;
  font-weight: 800;
}

.story-stage-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 14px;
}

.story-stage {
  display: flex;
  min-width: 0;
  gap: 7px;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 8px;
  color: rgb(203 213 225);
  font-size: 12px;
  font-weight: 800;
  background: rgb(15 23 42 / 48%);
  border: 1px solid rgb(148 163 184 / 18%);
  border-radius: 8px;
}

.story-stage.active {
  color: #ffffff;
  background: linear-gradient(135deg, rgb(124 58 237 / 42%), rgb(8 145 178 / 24%));
  border-color: rgb(103 232 249 / 44%);
  animation: flow-node-pulse 2.8s ease-in-out infinite;
}

.attack-story-grid {
  position: relative;
  display: grid;
  grid-template-columns: minmax(280px, 0.85fr) minmax(360px, 1.15fr);
  gap: 12px;
}

.story-process-panel,
.story-timeline-panel {
  min-width: 0;
  padding: 14px;
  background: rgb(2 6 23 / 42%);
  border: 1px solid rgb(148 163 184 / 16%);
  border-radius: 8px;
}

.story-panel-title {
  margin-bottom: 12px;
  color: rgb(226 232 240);
  font-size: 13px;
  font-weight: 800;
}

.process-graph {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 9px;
}

.process-graph::before {
  position: absolute;
  top: 18px;
  bottom: 18px;
  left: 9px;
  width: 1px;
  content: '';
  background: linear-gradient(180deg, rgb(103 232 249 / 12%), rgb(103 232 249 / 56%), rgb(167 139 250 / 12%));
}

.process-node {
  position: relative;
  display: flex;
  min-width: 0;
  gap: 10px;
  align-items: flex-start;
  padding: 10px 11px;
  color: rgb(226 232 240);
  background: rgb(15 23 42 / 58%);
  border: 1px solid rgb(148 163 184 / 18%);
  border-radius: 8px;
}

.process-node.child::before {
  position: absolute;
  top: 19px;
  left: -21px;
  width: 20px;
  height: 1px;
  content: '';
  background: rgb(103 232 249 / 35%);
}

.process-dot {
  flex: 0 0 10px;
  width: 10px;
  height: 10px;
  margin-top: 5px;
  background: rgb(103 232 249);
  border-radius: 50%;
  box-shadow: 0 0 16px rgb(34 211 238 / 60%);
}

.process-copy {
  min-width: 0;
}

.process-name {
  overflow: hidden;
  color: #ffffff;
  font-size: 13px;
  font-weight: 800;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.process-meta,
.process-path,
.timeline-meta {
  overflow: hidden;
  color: rgb(148 163 184);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.process-path {
  margin-top: 3px;
}

.story-timeline {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.story-timeline::before {
  position: absolute;
  top: 12px;
  bottom: 12px;
  left: 16px;
  width: 2px;
  content: '';
  background: linear-gradient(180deg, rgb(34 211 238 / 12%), rgb(34 211 238 / 58%), rgb(168 85 247 / 12%));
}

.timeline-event {
  position: relative;
  display: grid;
  grid-template-columns: 34px minmax(0, 1fr);
  gap: 10px;
}

.timeline-marker {
  z-index: 1;
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  color: #ffffff;
  font-size: 18px;
  background: rgb(30 41 59);
  border: 1px solid rgb(103 232 249 / 42%);
  border-radius: 8px;
  box-shadow: 0 0 20px rgb(14 165 233 / 18%);
}

.severity-critical .process-dot,
.severity-critical .timeline-marker,
.severity-high .process-dot,
.severity-high .timeline-marker {
  background: rgb(244 63 94);
  border-color: rgb(251 113 133 / 52%);
  box-shadow: 0 0 20px rgb(244 63 94 / 34%);
}

.severity-medium .process-dot,
.severity-medium .timeline-marker {
  background: rgb(245 158 11);
  border-color: rgb(251 191 36 / 46%);
  box-shadow: 0 0 18px rgb(245 158 11 / 28%);
}

.timeline-card {
  min-width: 0;
  padding: 10px 12px;
  background: rgb(15 23 42 / 62%);
  border: 1px solid rgb(148 163 184 / 18%);
  border-radius: 8px;
}

.timeline-topline {
  display: flex;
  min-width: 0;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
}

.timeline-topline span {
  overflow: hidden;
  color: #ffffff;
  font-size: 13px;
  font-weight: 800;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-topline small {
  flex: 0 0 auto;
  color: rgb(148 163 184);
  font-size: 11px;
}

.timeline-detail {
  display: -webkit-box;
  margin-top: 5px;
  overflow: hidden;
  color: rgb(203 213 225);
  font-size: 12px;
  line-height: 1.45;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.story-entity-row {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.story-entity {
  display: flex;
  min-width: 0;
  gap: 8px;
  align-items: center;
  padding: 10px 12px;
  color: rgb(203 213 225);
  background: rgb(15 23 42 / 46%);
  border: 1px solid rgb(148 163 184 / 16%);
  border-radius: 8px;
}

.story-entity span {
  min-width: 0;
  overflow: hidden;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.story-entity strong {
  margin-left: auto;
  color: #ffffff;
  font-size: 18px;
}

.sandbox-output {
  max-height: 360px;
  padding: 14px;
  overflow: auto;
  color: rgb(209 250 229);
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  background: rgb(17 24 39);
  border-radius: 8px;
}

:deep(.selected-row td) {
  background: rgb(245 243 255) !important;
}

@media (max-width: 960px) {
  .hero-content,
  .panel-title {
    align-items: flex-start;
    flex-direction: column;
  }

  .report-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .story-stage-rail,
  .attack-story-grid,
  .story-entity-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 560px) {
  .report-summary {
    grid-template-columns: 1fr;
  }
}

@keyframes flow-sheen {
  0%,
  42% {
    transform: translateX(-120%);
  }
  72%,
  100% {
    transform: translateX(120%);
  }
}

@keyframes flow-node-pulse {
  0%,
  100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-2px);
  }
}

</style>
