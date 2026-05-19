<script setup lang="tsx">
import { computed, h, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import type { DataTableColumns, PaginationProps, UploadCustomRequestOptions } from 'naive-ui';
import { NButton, NTag, useMessage } from 'naive-ui';
import {
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
  stdout?: string;
  stderr?: string;
  errors?: string[];
  error?: string;
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
const report = computed(() => parseJson<SandboxReport | null>(selectedSample.value?.reportJson, null));
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
    width: 230,
    render(row) {
      return (
        <div class="action-row">
          <NButton size="small" type="primary" secondary disabled={row.status === 'running'} onClick={() => analyze(row)}>
            {$t('dataprotector.sandbox.analyze')}
          </NButton>
          <NButton size="small" secondary onClick={() => selectSample(row)}>
            {$t('dataprotector.sandbox.report')}
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
              <NButton type="primary" :loading="loading" @click="refresh(false)">
                <template #icon><SvgIcon icon="mdi:refresh" /></template>
                {{ $t('dataprotector.common.refresh') }}
              </NButton>
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
            :scroll-x="1780"
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

    <NCard :title="$t('dataprotector.sandbox.report')" :bordered="false" class="work-panel">
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
    grid-template-columns: 1fr;
  }
}
</style>
