import { request } from '../request';

export function fetchBridgeStatus() {
  return request<Api.DataProtector.BridgeStatus>({
    url: '/status',
    method: 'get'
  });
}

export function fetchPolicyRules() {
  return request<Api.DataProtector.PolicyRule[]>({
    url: '/policy/rules',
    method: 'get'
  });
}

export function fetchDevices() {
  return request<Api.DataProtector.Device[]>({
    url: '/devices',
    method: 'get'
  });
}

export function fetchRemoveDevice(data: Api.DataProtector.DeviceDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/devices',
    method: 'delete',
    data
  });
}

export function fetchRemoteTasks(params: { deviceId?: string; limit?: number } = {}) {
  return request<Api.DataProtector.RemoteTask[]>({
    url: '/tasks',
    method: 'get',
    params
  });
}

export function fetchCreateRemoteTask(data: Api.DataProtector.RemoteTaskRequest) {
  return request<Api.DataProtector.RemoteTask>({
    url: '/tasks',
    method: 'post',
    data
  });
}

export function fetchAddPolicyRule(data: Api.DataProtector.PolicyRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/policy/rules',
    method: 'post',
    data
  });
}

export function fetchRemovePolicyRule(data: Api.DataProtector.PolicyRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/policy/rules',
    method: 'delete',
    data
  });
}

export function fetchClearPolicyRules() {
  return request<Api.DataProtector.OperationResult>({
    url: '/policy/clear',
    method: 'post'
  });
}

export function fetchNetworkRules() {
  return request<Api.DataProtector.NetworkRule[]>({
    url: '/network/rules',
    method: 'get'
  });
}

export function fetchAddNetworkRule(data: Api.DataProtector.NetworkRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/network/rules',
    method: 'post',
    data
  });
}

export function fetchRemoveNetworkRule(data: Pick<Api.DataProtector.NetworkRule, 'ruleId'> & { actor?: string }) {
  return request<Api.DataProtector.OperationResult>({
    url: '/network/rules',
    method: 'delete',
    data
  });
}

export function fetchClearNetworkRules() {
  return request<Api.DataProtector.OperationResult>({
    url: '/network/clear',
    method: 'post'
  });
}

export function fetchNetworkInsights(params: Api.DataProtector.NetworkInsightQuery = {}) {
  return request<Api.DataProtector.NetworkInsightResponse>({
    url: '/network/insights',
    method: 'get',
    params
  });
}

export function fetchIpInfoConfig() {
  return request<Api.DataProtector.IpInfoConfiguration>({
    url: '/network/ipinfo/config',
    method: 'get'
  });
}

export function fetchSaveIpInfoConfig(data: Api.DataProtector.IpInfoConfigurationRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/network/ipinfo/config',
    method: 'post',
    data
  });
}

export function fetchClearIpInfoConfig() {
  return request<Api.DataProtector.OperationResult>({
    url: '/network/ipinfo/config',
    method: 'delete'
  });
}

export function fetchWebShellRules() {
  return request<Api.DataProtector.WebShellRule[]>({
    url: '/webshell/rules',
    method: 'get'
  });
}

export function fetchAddWebShellRule(data: Api.DataProtector.WebShellRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/webshell/rules',
    method: 'post',
    data
  });
}

export function fetchRemoveWebShellRule(data: Api.DataProtector.WebShellRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/webshell/rules',
    method: 'delete',
    data
  });
}

export function fetchClearWebShellRules() {
  return request<Api.DataProtector.OperationResult>({
    url: '/webshell/clear',
    method: 'post'
  });
}

export function fetchDeviceRules() {
  return request<Api.DataProtector.DeviceRule[]>({
    url: '/device/rules',
    method: 'get'
  });
}

export function fetchAddDeviceRule(data: Api.DataProtector.DeviceRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/rules',
    method: 'post',
    data
  });
}

export function fetchRemoveDeviceRule(data: Api.DataProtector.DeviceRuleRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/rules',
    method: 'delete',
    data
  });
}

export function fetchClearDeviceRules() {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/clear',
    method: 'post'
  });
}

export function fetchHashProtectPolicy() {
  return request<Api.DataProtector.HashProtectPolicy>({
    url: '/hashprotect/policy',
    method: 'get'
  });
}

export function fetchUpdateHashProtectPolicy(data: Api.DataProtector.HashProtectPolicyRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/hashprotect/policy',
    method: 'post',
    data
  });
}

export function fetchLateralDefensePolicy() {
  return request<Api.DataProtector.LateralDefensePolicy>({
    url: '/lateral/policy',
    method: 'get'
  });
}

export function fetchUpdateLateralDefensePolicy(data: Api.DataProtector.LateralDefensePolicyRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/lateral/policy',
    method: 'post',
    data
  });
}

export function fetchUserHookDefensePolicy() {
  return request<Api.DataProtector.UserHookDefensePolicy>({
    url: '/userhook/policy',
    method: 'get'
  });
}

export function fetchUpdateUserHookDefensePolicy(data: Api.DataProtector.UserHookDefensePolicyRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/userhook/policy',
    method: 'post',
    data
  });
}

export function fetchUsbCryptPolicy() {
  return request<Api.DataProtector.UsbCryptPolicy>({
    url: '/usbcrypt/policy',
    method: 'get'
  });
}

export function fetchUpdateUsbCryptPolicy(data: Api.DataProtector.UsbCryptPolicyRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/usbcrypt/policy',
    method: 'post',
    data
  });
}

export function fetchDlpProtectionPolicy() {
  return request<Api.DataProtector.DlpProtectionPolicy>({
    url: '/dlp/policy',
    method: 'get'
  });
}

export function fetchUpdateDlpProtectionPolicy(data: Api.DataProtector.DlpProtectionPolicyRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/dlp/policy',
    method: 'post',
    data
  });
}

export function fetchUsbCryptDriverPackage() {
  return request<Api.DataProtector.UsbCryptDriverPackageInfo>({
    url: '/usbcrypt/driver-package',
    method: 'get'
  });
}

export function fetchUploadUsbCryptDriverPackage(data: Api.DataProtector.UsbCryptDriverPackageUploadRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/usbcrypt/driver-package',
    method: 'post',
    data
  });
}

export function fetchInitializeUsbCrypt(data: Api.DataProtector.UsbCryptInitializationRequest) {
  return request<Api.DataProtector.RemoteTask>({
    url: '/usbcrypt/initialize',
    method: 'post',
    data
  });
}

export function fetchSandboxSamples(params: Api.DataProtector.SandboxSampleQuery = {}) {
  return request<Api.DataProtector.SandboxSampleQueryResponse>({
    url: '/sandbox/samples',
    method: 'get',
    params
  });
}

export function fetchSubmitSandboxSample(data: Api.DataProtector.SandboxSampleUploadRequest) {
  return request<Api.DataProtector.SandboxSample>({
    url: '/sandbox/samples',
    method: 'post',
    data
  });
}

export function fetchStartSandboxAnalysis(data: Api.DataProtector.SandboxAnalyzeRequest) {
  return request<Api.DataProtector.SandboxSample>({
    url: '/sandbox/analyze',
    method: 'post',
    data
  });
}

export function fetchRemoveSandboxSample(data: Api.DataProtector.SandboxSampleDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/sandbox/samples',
    method: 'delete',
    data
  });
}

export function fetchRemoveSandboxLogs(data: Api.DataProtector.SandboxLogDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/sandbox/logs',
    method: 'delete',
    data
  });
}

export function fetchStaticAnalysisConfig() {
  return request<Api.DataProtector.StaticAnalysisConfiguration>({
    url: '/static-analysis/config',
    method: 'get'
  });
}

export function fetchSaveStaticAnalysisConfig(data: Api.DataProtector.StaticAnalysisConfigurationRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/static-analysis/config',
    method: 'post',
    data
  });
}

export function fetchStaticAnalysisRules() {
  return request<Api.DataProtector.StaticAnalysisRule[]>({
    url: '/static-analysis/rules',
    method: 'get'
  });
}

export function fetchSaveStaticAnalysisRules(data: Api.DataProtector.StaticAnalysisRuleSaveRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/static-analysis/rules',
    method: 'post',
    data
  });
}

export function fetchResetStaticAnalysisRules() {
  return request<Api.DataProtector.OperationResult>({
    url: '/static-analysis/rules/reset',
    method: 'post'
  });
}

export function fetchStaticAnalysisSource() {
  return request<Api.DataProtector.StaticAnalysisSourceInfo>({
    url: '/static-analysis/source',
    method: 'get'
  });
}

export function fetchStaticAnalysisSamples(params: Api.DataProtector.StaticAnalysisSampleQuery = {}) {
  return request<Api.DataProtector.StaticAnalysisSampleQueryResponse>({
    url: '/static-analysis/samples',
    method: 'get',
    params
  });
}

export function fetchSubmitStaticAnalysisSample(data: Api.DataProtector.StaticAnalysisSampleUploadRequest) {
  return request<Api.DataProtector.StaticAnalysisSample>({
    url: '/static-analysis/samples',
    method: 'post',
    data
  });
}

export function fetchStartStaticAnalysis(data: Api.DataProtector.StaticAnalysisAnalyzeRequest) {
  return request<Api.DataProtector.StaticAnalysisSample>({
    url: '/static-analysis/analyze',
    method: 'post',
    data
  });
}

export function fetchRemoveStaticAnalysisSample(data: Api.DataProtector.StaticAnalysisSampleDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/static-analysis/samples',
    method: 'delete',
    data
  });
}

export function fetchRemovableDevices() {
  return request<Api.DataProtector.RemovableDevice[]>({
    url: '/device/removable',
    method: 'get'
  });
}

export function fetchRemoveRemovableDevice(data: Api.DataProtector.RemovableDeviceDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/removable',
    method: 'delete',
    data
  });
}

export function fetchAuthorizeRemovableDevice(data: Api.DataProtector.RemovableDeviceAuthorizationRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/removable/authorization',
    method: 'post',
    data
  });
}

export function fetchRemoveRemovableDeviceAuthorization(data: Pick<Api.DataProtector.RemovableDeviceAuthorizationRequest, 'hardwareId'> & { actor?: string }) {
  return request<Api.DataProtector.OperationResult>({
    url: '/device/removable/authorization',
    method: 'delete',
    data
  });
}

export function fetchAuditEvents(params: number | Api.DataProtector.AuditQuery = 200) {
  const query = typeof params === 'number' ? { limit: params } : params;

  return request<Api.DataProtector.AuditQueryResponse>({
    url: '/audit/events',
    method: 'get',
    params: query
  });
}

export function fetchAuditAttackFlow(params: Api.DataProtector.AuditQuery = {}) {
  return request<Api.DataProtector.AuditAttackFlowResponse>({
    url: '/audit/attack-flow',
    method: 'get',
    params
  });
}

export function fetchRemoveAuditEvent(data: Api.DataProtector.AuditDeleteRequest) {
  return request<Api.DataProtector.OperationResult>({
    url: '/audit/events',
    method: 'delete',
    data
  });
}

export function fetchClearAuditEvents() {
  return request<Api.DataProtector.OperationResult>({
    url: '/audit/clear',
    method: 'post'
  });
}
