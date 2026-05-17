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

export function fetchRemovableDevices() {
  return request<Api.DataProtector.RemovableDevice[]>({
    url: '/device/removable',
    method: 'get'
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

  return request<Api.DataProtector.AuditRecord[]>({
    url: '/audit/events',
    method: 'get',
    params: query
  });
}
