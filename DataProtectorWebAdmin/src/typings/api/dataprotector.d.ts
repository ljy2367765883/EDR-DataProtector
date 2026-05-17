declare namespace Api {
  namespace DataProtector {
    type RuleKind = 'processName' | 'processDirectory' | 'excludedDirectory';
    type NetworkRuleKind = 'ip' | 'domain';
    type NetworkAction = 'allow' | 'block';
    type NetworkProtocol = 'any' | 'icmp' | 'tcp' | 'udp';
    type NetworkDirection = 'inbound' | 'outbound' | 'both';

    interface BridgeStatus {
      mode?: string;
      connected: boolean;
      status: string;
      message: string;
      bridgePid: number;
      machine: string;
      user: string;
      auditPath: string;
      policyVersion?: number;
      deviceCount?: number;
      onlineDeviceCount?: number;
    }

    interface Device {
      deviceId: string;
      machine: string;
      user: string;
      agentVersion: string;
      driverConnected: boolean;
      driverStatus: string;
      driverMessage: string;
      policyVersion: number;
      firstSeenUtc: string;
      lastSeenUtc: string;
      lastApplyStatus: string;
      lastApplyMessage: string;
      online: boolean;
    }

    interface PolicyRule {
      kind: RuleKind;
      value: string;
      extension: string;
    }

    interface PolicyRuleRequest extends PolicyRule {
      actor?: string;
    }

    interface NetworkRule {
      ruleId: number;
      kind: NetworkRuleKind;
      action: NetworkAction;
      protocol: NetworkProtocol;
      direction: NetworkDirection;
      localAddress: string;
      localPort: number;
      remoteAddress: string;
      remotePort: number;
      domain: string;
      displayTarget: string;
      actor?: string;
    }

    interface NetworkRuleRequest extends Omit<NetworkRule, 'displayTarget'> {
      displayTarget?: string;
    }

    type NetworkInsightEventType = 'all' | 'connection' | 'dns' | 'quic' | 'http3' | 'blocked';

    interface NetworkInsightQuery {
      baselineHours?: number;
      windowHours?: number;
      limit?: number;
      host?: string;
      eventType?: NetworkInsightEventType;
      search?: string;
    }

    interface NetworkInsightItem {
      key: string;
      isNew: boolean;
      firstSeenUtc: string;
      lastSeenUtc: string;
      count: number;
      hosts: string[];
      remoteIdentity: string;
      remoteAddress: string;
      remoteEndpoint: string;
      domain: string;
      processPath: string;
      direction: string;
      protocolName: string;
      isDns: boolean;
      isQuic: boolean;
      isHttp3: boolean;
      blocked: boolean;
      fileExists: boolean;
      fileSize: number;
      fileModifiedUtc: string;
      productName: string;
      companyName: string;
      fileDescription: string;
      fileVersion: string;
      sha256: string;
      signatureStatus: string;
      signer: string;
      ipInfoEnabled: boolean;
      ipInfoStatus: string;
      ipInfoIp: string;
      asn: string;
      asName: string;
      asDomain: string;
      countryCode: string;
      country: string;
      continentCode: string;
      continent: string;
    }

    interface NetworkInsightResponse {
      baselineHours: number;
      windowHours: number;
      generatedUtc: string;
      total: number;
      newTotal: number;
      items: NetworkInsightItem[];
    }

    interface WebShellRule {
      directory: string;
      actor?: string;
    }

    interface WebShellRuleRequest extends WebShellRule {}

    interface OperationResult {
      succeeded: boolean;
      status: number;
      statusText: string;
      message: string;
    }

    interface RemoteTask {
      taskId: string;
      deviceId: string;
      kind: string;
      argumentsJson: string;
      actor: string;
      status: string;
      createdUtc: string;
      sentUtc: string;
      completedUtc: string;
      succeeded: boolean;
      exitCode: number;
      output: string;
      error: string;
    }

    interface RemoteTaskRequest {
      deviceId: string;
      kind: string;
      argumentsJson: string;
      actor?: string;
    }

    interface AuditRecord {
      TimestampUtc: string;
      Host?: string;
      Actor: string;
      Action: string;
      Target: string;
      Extension: string;
      Succeeded: boolean;
      Status: string;
      Message: string;
    }

    type AuditCategory = 'all' | 'policy' | 'network' | 'smtp' | 'webshell' | 'remote' | 'agent' | 'system';
    type AuditResult = 'all' | 'success' | 'failed';
    type AuditSeverity = 'all' | 'critical' | 'warning' | 'info' | 'operational';
    type AuditDisposition = 'all' | 'blocked' | 'observed' | 'completed' | 'failed';

    interface AuditQuery {
      limit?: number;
      category?: AuditCategory;
      host?: string;
      result?: AuditResult;
      severity?: AuditSeverity;
      disposition?: AuditDisposition;
      fromUtc?: string;
      toUtc?: string;
      search?: string;
    }
  }
}
