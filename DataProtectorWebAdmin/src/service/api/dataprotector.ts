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

export function fetchAuditEvents(limit = 200) {
  return request<Api.DataProtector.AuditRecord[]>({
    url: '/audit/events',
    method: 'get',
    params: { limit }
  });
}
