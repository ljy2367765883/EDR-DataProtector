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
      includePrivateRemotes?: boolean;
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

    interface IpInfoConfiguration {
      enabled: boolean;
      source: string;
      maskedToken: string;
      tokenFilePath: string;
    }

    interface IpInfoConfigurationRequest {
      token: string;
    }

    interface WebShellRule {
      directory: string;
      actor?: string;
    }

    interface WebShellRuleRequest extends WebShellRule {}

    interface DeviceRule {
      deviceId: string;
      allowInsert: boolean;
      allowWrite: boolean;
      actor?: string;
    }

    interface DeviceRuleRequest extends DeviceRule {}

    interface HashProtectPolicy {
      enabled: boolean;
      protectLsass: boolean;
      protectCredentialFiles: boolean;
      protectRegistryHives: boolean;
      protectRawExtents: boolean;
      flags: number;
      actor?: string;
    }

    interface HashProtectPolicyRequest extends Omit<HashProtectPolicy, 'flags'> {
      flags?: number;
    }

    interface LateralDefensePolicy {
      enabled: boolean;
      blockSmbExecutableCopy: boolean;
      blockIpcScheduledTasks: boolean;
      blockIpcServiceCreation: boolean;
      blockRemoteAdminTools: boolean;
      flags: number;
      actor?: string;
    }

    interface LateralDefensePolicyRequest extends Omit<LateralDefensePolicy, 'flags'> {
      flags?: number;
    }

    type RemovableDeviceStatus = 'pending' | 'authorized' | 'blocked';

    interface RemovableVolume {
      deviceId: string;
      host: string;
      user: string;
      driveLetter: string;
      volumeGuid: string;
      volumeLabel: string;
      fileSystem: string;
      sizeBytes: number;
      firstSeenUtc: string;
      lastSeenUtc: string;
      online: boolean;
    }

    interface RemovableDevice {
      hardwareId: string;
      deviceId: string;
      host: string;
      user: string;
      driveLetter: string;
      volumeGuid: string;
      volumeLabel: string;
      fileSystem: string;
      sizeBytes: number;
      model: string;
      serialNumber: string;
      pnpDeviceId: string;
      interfaceType: string;
      mediaType: string;
      firstSeenUtc: string;
      lastSeenUtc: string;
      online: boolean;
      volumes?: RemovableVolume[];
      status: RemovableDeviceStatus;
      allowWrite: boolean;
      authorizedBy: string;
      authorizedUtc: string;
      note: string;
    }

    interface RemovableDeviceAuthorizationRequest {
      hardwareId: string;
      status: 'authorized' | 'blocked';
      allowInsert?: boolean;
      allowWrite: boolean;
      actor?: string;
      note?: string;
    }

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

    type AuditCategory = 'all' | 'policy' | 'network' | 'smtp' | 'webshell' | 'hashdump' | 'lateral' | 'remote' | 'agent' | 'system';
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
