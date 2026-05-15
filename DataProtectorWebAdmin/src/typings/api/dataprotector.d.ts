declare namespace Api {
  namespace DataProtector {
    type RuleKind = 'processName' | 'processDirectory' | 'excludedDirectory';

    interface BridgeStatus {
      connected: boolean;
      status: string;
      message: string;
      bridgePid: number;
      machine: string;
      user: string;
      auditPath: string;
    }

    interface PolicyRule {
      kind: RuleKind;
      value: string;
      extension: string;
    }

    interface PolicyRuleRequest extends PolicyRule {
      actor?: string;
    }

    interface OperationResult {
      succeeded: boolean;
      status: number;
      statusText: string;
      message: string;
    }

    interface AuditRecord {
      TimestampUtc: string;
      Actor: string;
      Action: string;
      Target: string;
      Extension: string;
      Succeeded: boolean;
      Status: string;
      Message: string;
    }
  }
}
