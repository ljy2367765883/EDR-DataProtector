using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DataProtectorWebBridge.Native;

namespace DataProtectorWebBridge.Services
{
    internal sealed class PolicyBridgeService
    {
        private const uint SuccessStatus = 0;
        private const uint BufferTooSmallStatus = 0xE0010005;
        private const uint RuleTypeProcessName = 1;
        private const uint RuleTypeProcessDirectory = 2;
        private const uint RuleTypeExcludedDirectory = 3;
        private const uint NetworkRuleTypeIp = 1;
        private const uint NetworkRuleTypeDomain = 2;
        private const uint NetworkActionAllow = 0;
        private const uint NetworkActionBlock = 1;
        private const uint NetworkProtocolAny = 0;
        private const uint NetworkProtocolIcmp = 1;
        private const uint NetworkProtocolTcp = 6;
        private const uint NetworkProtocolUdp = 17;
        private const uint NetworkDirectionInbound = 0;
        private const uint NetworkDirectionOutbound = 1;
        private const uint NetworkDirectionBoth = 2;
        private const uint NetworkEventFlagDns = 0x00000001;
        private const uint NetworkEventFlagQuic = 0x00000002;
        private const uint NetworkEventFlagHttp3 = 0x00000004;
        private const uint NetworkEventFlagBlocked = 0x00000008;
        private const uint WebShellSeverityNotify = 1;
        private const uint WebShellSeverityWarning = 2;
        private const uint WebShellSeverityDanger = 3;
        private const uint WebShellOperationCreate = 1;
        private const uint WebShellOperationWrite = 2;
        private const uint WebShellOperationRename = 3;
        private const uint WebShellOperationCleanup = 4;
        private const uint HashOperationLsassHandle = 1;
        private const uint HashOperationCredentialFile = 2;
        private const uint HashOperationRegistryHive = 3;
        private const uint HashOperationRawExtent = 4;
        private const uint HashProtectFlagEnabled = 0x00000001;
        private const uint HashProtectFlagLsassHandles = 0x00000002;
        private const uint HashProtectFlagCredentialFiles = 0x00000004;
        private const uint HashProtectFlagRegistryHives = 0x00000008;
        private const uint HashProtectFlagRawExtents = 0x00000010;
        private const uint HashProtectAllowedFlags =
            HashProtectFlagEnabled |
            HashProtectFlagLsassHandles |
            HashProtectFlagCredentialFiles |
            HashProtectFlagRegistryHives |
            HashProtectFlagRawExtents;
        private const uint LateralOperationSmbExecutableCreate = 1;
        private const uint LateralOperationSmbExecutableWrite = 2;
        private const uint LateralOperationSmbExecutableRename = 3;
        private const uint LateralOperationIpcTaskScheduler = 4;
        private const uint LateralOperationIpcServiceControl = 5;
        private const uint LateralOperationRemoteScheduledTaskTool = 6;
        private const uint LateralOperationRemoteServiceTool = 7;
        private const uint LateralOperationWmiProcessCreate = 8;
        private const uint LateralOperationPowerShellRemoteTask = 9;
        private const uint LateralDefenseFlagEnabled = 0x00000001;
        private const uint LateralDefenseFlagSmbExecutables = 0x00000002;
        private const uint LateralDefenseFlagIpcTasks = 0x00000004;
        private const uint LateralDefenseFlagIpcServices = 0x00000008;
        private const uint LateralDefenseFlagProcessTools = 0x00000010;
        private const uint LateralDefenseAllowedFlags =
            LateralDefenseFlagEnabled |
            LateralDefenseFlagSmbExecutables |
            LateralDefenseFlagIpcTasks |
            LateralDefenseFlagIpcServices |
            LateralDefenseFlagProcessTools;
        private const uint UserHookOperationProcessCreate = 1;
        private const uint UserHookOperationHookSurfaceImageLoad = 2;
        private const uint UserHookOperationRuntimeRequired = 3;
        private const uint UserHookOperationRuntimeMissing = 4;
        private const uint UserHookOperationRuntimeRejected = 5;
        private const uint UserHookOperationSuspiciousHookAttempt = 6;
        private const uint UserHookDefenseFlagEnabled = 0x00000001;
        private const uint UserHookDefenseFlagEarlyProcessMonitor = 0x00000002;
        private const uint UserHookDefenseFlagImageLoadMonitor = 0x00000004;
        private const uint UserHookDefenseFlagRequireSignedRuntime = 0x00000008;
        private const uint UserHookDefenseFlagBlockUntrustedRuntime = 0x00000010;
        private const uint UserHookDefenseFlagAuditOnly = 0x00000020;
        private const uint UserHookDefenseFlagMonitorSystemProcesses = 0x00000040;
        private const uint UserHookDefenseAllowedFlags =
            UserHookDefenseFlagEnabled |
            UserHookDefenseFlagEarlyProcessMonitor |
            UserHookDefenseFlagImageLoadMonitor |
            UserHookDefenseFlagRequireSignedRuntime |
            UserHookDefenseFlagBlockUntrustedRuntime |
            UserHookDefenseFlagAuditOnly |
            UserHookDefenseFlagMonitorSystemProcesses;
        private const int MessageBufferChars = 512;
        private const int MaxQueryAttempts = 4;

        private readonly AuditLog auditLog;

        public PolicyBridgeService(AuditLog auditLog)
        {
            this.auditLog = auditLog;
        }

        public object GetStatus()
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyCheckConnection);
            return new
            {
                connected = result.succeeded,
                status = result.statusText,
                message = result.message,
                bridgePid = System.Diagnostics.Process.GetCurrentProcess().Id,
                machine = Environment.MachineName,
                user = Environment.UserName,
                auditPath = auditLog.FilePath
            };
        }

        public PolicyRuleDto[] QueryRules()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                    new DataProtectorPolicyNative.NativePolicyRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativePolicyRule[] nativeRules =
                    new DataProtectorPolicyNative.NativePolicyRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        List<PolicyRuleDto> rules = new List<PolicyRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver rule set changed while querying. Please retry.");
        }

        public NetworkRuleDto[] QueryNetworkRules()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryNetworkRules(
                    new DataProtectorPolicyNative.NativeNetworkRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeNetworkRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeNetworkRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryNetworkRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        List<NetworkRuleDto> rules = new List<NetworkRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertNetworkRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver network rule set changed while querying. Please retry.");
        }

        public OperationResult AddRule(PolicyRuleRequest request)
        {
            PolicyRuleRequest normalized = NormalizeRequest(request);
            OperationResult result = Invoke(() =>
            {
                if (normalized.Kind == "processName")
                {
                    return DataProtectorPolicyNative.DpPolicyAddProcessNameRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "processDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyAddProcessDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "excludedDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyAddExcludedDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                throw new BridgeException(1, "Unsupported rule kind.");
            });

            auditLog.Append(normalized.Actor, "policy.rule.add." + normalized.Kind, normalized.Value, normalized.Extension, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveRule(PolicyRuleRequest request)
        {
            PolicyRuleRequest normalized = NormalizeRequest(request);
            OperationResult result = Invoke(() =>
            {
                if (normalized.Kind == "processName")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveProcessNameRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "processDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveProcessDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "excludedDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveExcludedDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                throw new BridgeException(1, "Unsupported rule kind.");
            });

            auditLog.Append(normalized.Actor, "policy.rule.remove." + normalized.Kind, normalized.Value, normalized.Extension, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearProcessRules);
            auditLog.Append(actor, "policy.rules.clear", "*", "*", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult AddNetworkRule(NetworkRuleRequest request)
        {
            NetworkRuleDto normalized = NormalizeNetworkRule(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeNetworkRule nativeRule = ToNativeNetworkRule(normalized);
                try
                {
                    return DataProtectorPolicyNative.DpPolicyAddNetworkRule(ref nativeRule);
                }
                finally
                {
                    FreeNativeNetworkRule(nativeRule);
                }
            });

            auditLog.Append(normalized.actor, "policy.network.add." + normalized.kind, normalized.displayTarget, string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveNetworkRule(NetworkRuleRequest request)
        {
            if (request == null || request.ruleId == 0)
            {
                throw new BridgeException(1, "Network rule id is required.");
            }

            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyRemoveNetworkRule(request.ruleId));
            auditLog.Append(request.actor, "policy.network.remove", request.ruleId.ToString(CultureInfo.InvariantCulture), string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearNetworkRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearNetworkRules);
            auditLog.Append(actor, "policy.network.clear", "*", string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public WebShellRuleDto[] QueryWebShellRules()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryWebShellRules(
                    new DataProtectorPolicyNative.NativeWebShellRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeWebShellRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeWebShellRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryWebShellRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        List<WebShellRuleDto> rules = new List<WebShellRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertWebShellRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver WebShell rule set changed while querying. Please retry.");
        }

        public OperationResult AddWebShellRule(WebShellRuleRequest request)
        {
            WebShellRuleDto normalized = NormalizeWebShellRule(request);
            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyAddWebShellRule(normalized.directory));
            auditLog.Append(normalized.actor, "policy.webshell.add", normalized.directory, "web-script", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveWebShellRule(WebShellRuleRequest request)
        {
            WebShellRuleDto normalized = NormalizeWebShellRule(request);
            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyRemoveWebShellRule(normalized.directory));
            auditLog.Append(normalized.actor, "policy.webshell.remove", normalized.directory, "web-script", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearWebShellRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearWebShellRules);
            auditLog.Append(actor, "policy.webshell.clear", "*", "web-script", result.succeeded, result.status, result.message);
            return result;
        }

        public DeviceRuleDto[] QueryDeviceRules()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryDeviceRules(
                    new DataProtectorPolicyNative.NativeDeviceRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeDeviceRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeDeviceRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryDeviceRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        List<DeviceRuleDto> rules = new List<DeviceRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertDeviceRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver device rule set changed while querying. Please retry.");
        }

        public OperationResult AddDeviceRule(DeviceRuleRequest request)
        {
            DeviceRuleDto normalized = NormalizeDeviceRule(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeDeviceRule nativeRule = ToNativeDeviceRule(normalized);
                try
                {
                    return DataProtectorPolicyNative.DpPolicyAddDeviceRule(ref nativeRule);
                }
                finally
                {
                    FreeNativeDeviceRule(nativeRule);
                }
            });

            auditLog.Append(normalized.actor, "policy.device.add", normalized.deviceId, "removable-storage", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveDeviceRule(DeviceRuleRequest request)
        {
            DeviceRuleDto normalized = NormalizeDeviceRule(request);
            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyRemoveDeviceRule(normalized.deviceId));
            auditLog.Append(normalized.actor, "policy.device.remove", normalized.deviceId, "removable-storage", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearDeviceRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearDeviceRules);
            auditLog.Append(actor, "policy.device.clear", "*", "removable-storage", result.succeeded, result.status, result.message);
            return result;
        }

        public SmtpEventDto[] QuerySmtpEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQuerySmtpEvents(
                    new DataProtectorPolicyNative.NativeSmtpEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeSmtpEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeSmtpEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQuerySmtpEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<SmtpEventDto> events = new List<SmtpEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertSmtpEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver SMTP event queue changed while querying. Please retry.");
        }

        public WebShellEventDto[] QueryWebShellEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryWebShellEvents(
                    new DataProtectorPolicyNative.NativeWebShellEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeWebShellEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeWebShellEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryWebShellEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<WebShellEventDto> events = new List<WebShellEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertWebShellEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver WebShell event queue changed while querying. Please retry.");
        }

        public HashProtectEventDto[] QueryHashProtectEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryHashProtectEvents(
                    new DataProtectorPolicyNative.NativeHashProtectEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeHashProtectEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeHashProtectEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryHashProtectEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<HashProtectEventDto> events = new List<HashProtectEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertHashProtectEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver hash protection event queue changed while querying. Please retry.");
        }

        public HashProtectPolicyDto QueryHashProtectPolicy()
        {
            DataProtectorPolicyNative.NativeHashProtectPolicy nativePolicy;
            uint status = DataProtectorPolicyNative.DpPolicyQueryHashProtectPolicy(out nativePolicy);
            if (status != SuccessStatus)
            {
                throw new BridgeException(status, ReadLastErrorMessage());
            }

            return FromHashProtectFlags(nativePolicy.Flags);
        }

        public LateralDefensePolicyDto QueryLateralDefensePolicy()
        {
            DataProtectorPolicyNative.NativeLateralDefensePolicy nativePolicy;
            uint status = DataProtectorPolicyNative.DpPolicyQueryLateralDefensePolicy(out nativePolicy);
            if (status != SuccessStatus)
            {
                throw new BridgeException(status, ReadLastErrorMessage());
            }

            return FromLateralDefenseFlags(nativePolicy.Flags);
        }

        public OperationResult SetHashProtectPolicy(HashProtectPolicyRequest request)
        {
            HashProtectPolicyDto normalized = NormalizeHashProtectPolicy(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeHashProtectPolicy nativePolicy = new DataProtectorPolicyNative.NativeHashProtectPolicy
                {
                    Flags = ToHashProtectFlags(normalized)
                };

                return DataProtectorPolicyNative.DpPolicySetHashProtectPolicy(ref nativePolicy);
            });

            auditLog.Append(
                normalized.actor,
                "policy.hashprotect.update",
                "anti-dump",
                HashProtectPolicySummary(normalized),
                result.succeeded,
                result.status,
                result.message);
            return result;
        }

        public OperationResult SetLateralDefensePolicy(LateralDefensePolicyRequest request)
        {
            LateralDefensePolicyDto normalized = NormalizeLateralDefensePolicy(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeLateralDefensePolicy nativePolicy = new DataProtectorPolicyNative.NativeLateralDefensePolicy
                {
                    Flags = ToLateralDefenseFlags(normalized)
                };

                return DataProtectorPolicyNative.DpPolicySetLateralDefensePolicy(ref nativePolicy);
            });

            auditLog.Append(
                normalized.actor,
                "policy.lateral.update",
                "lateral-defense",
                LateralDefensePolicySummary(normalized),
                result.succeeded,
                result.status,
                result.message);
            return result;
        }

        public UserHookDefensePolicyDto QueryUserHookDefensePolicy()
        {
            DataProtectorPolicyNative.NativeUserHookDefensePolicy nativePolicy;
            uint status = DataProtectorPolicyNative.DpPolicyQueryUserHookDefensePolicy(out nativePolicy);
            if (status != SuccessStatus)
            {
                throw new BridgeException(status, ReadLastErrorMessage());
            }

            return FromUserHookDefenseFlags(nativePolicy.Flags);
        }

        public OperationResult SetUserHookDefensePolicy(UserHookDefensePolicyRequest request)
        {
            UserHookDefensePolicyDto normalized = NormalizeUserHookDefensePolicy(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeUserHookDefensePolicy nativePolicy = new DataProtectorPolicyNative.NativeUserHookDefensePolicy
                {
                    Flags = ToUserHookDefenseFlags(normalized)
                };

                return DataProtectorPolicyNative.DpPolicySetUserHookDefensePolicy(ref nativePolicy);
            });

            auditLog.Append(
                normalized.actor,
                "policy.userhook.update",
                "application-hook-defense",
                UserHookDefensePolicySummary(normalized),
                result.succeeded,
                result.status,
                result.message);
            return result;
        }

        public NetworkConnectionEventDto[] QueryNetworkConnectionEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryNetworkConnectionEvents(
                    new DataProtectorPolicyNative.NativeNetworkConnectionEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeNetworkConnectionEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeNetworkConnectionEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryNetworkConnectionEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<NetworkConnectionEventDto> events = new List<NetworkConnectionEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            NetworkConnectionEventDto item = ConvertNetworkConnectionEvent(nativeEvents[index]);
                            if (!IsNoiseNetworkProcess(item.processPath))
                            {
                                EnrichNetworkConnectionEvent(item);
                                events.Add(item);
                            }
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver network connection event queue changed while querying. Please retry.");
        }

        public LateralDefenseEventDto[] QueryLateralDefenseEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryLateralDefenseEvents(
                    new DataProtectorPolicyNative.NativeLateralDefenseEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeLateralDefenseEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeLateralDefenseEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryLateralDefenseEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<LateralDefenseEventDto> events = new List<LateralDefenseEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertLateralDefenseEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver lateral defense event queue changed while querying. Please retry.");
        }

        public UserHookDefenseEventDto[] QueryUserHookDefenseEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryUserHookDefenseEvents(
                    new DataProtectorPolicyNative.NativeUserHookDefenseEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeUserHookDefenseEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeUserHookDefenseEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryUserHookDefenseEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<UserHookDefenseEventDto> events = new List<UserHookDefenseEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertUserHookDefenseEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }

            throw new BridgeException(BufferTooSmallStatus, "The driver user hook defense event queue changed while querying. Please retry.");
        }

        public AuditLog.AuditRecord[] DrainSmtpAuditRecords()
        {
            SmtpEventDto[] events = QuerySmtpEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (SmtpEventDto item in events)
            {
                string endpoint = item.remoteEndpoint;
                string target = item.from + " -> " + item.to;
                string message = "SMTP envelope observed on " + endpoint + " by PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "network-sensor",
                    Action = "network.smtp.send",
                    Target = target,
                    Extension = endpoint,
                    Succeeded = true,
                    Status = "0x00000000",
                    Message = message
                };

                records.Add(record);
                TryAppendAudit(record);
            }

            return records.ToArray();
        }

        public AuditLog.AuditRecord[] DrainSecurityAuditRecords()
        {
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();
            records.AddRange(TryDrainSecurityAuditSource("smtp", DrainSmtpAuditRecords));
            records.AddRange(TryDrainSecurityAuditSource("webshell", DrainWebShellAuditRecords));
            records.AddRange(TryDrainSecurityAuditSource("hashprotect", DrainHashProtectAuditRecords));
            records.AddRange(TryDrainSecurityAuditSource("lateral", DrainLateralDefenseAuditRecords));
            records.AddRange(TryDrainSecurityAuditSource("userhook", DrainUserHookDefenseAuditRecords));
            return records.ToArray();
        }

        public AuditLog.AuditRecord[] DrainWebShellAuditRecords()
        {
            WebShellEventDto[] events = QueryWebShellEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (WebShellEventDto item in events)
            {
                string action = "webshell." + item.severity;
                string message = "WebShell " + item.severity + " on " + item.operation + " by PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                bool allowed = !string.Equals(item.severity, "danger", StringComparison.OrdinalIgnoreCase);
                uint status = allowed ? SuccessStatus : 0xC0000022u;
                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "webshell-sensor",
                    Action = action,
                    Target = item.path,
                    Extension = item.extension,
                    Succeeded = allowed,
                    Status = "0x" + status.ToString("X8"),
                    Message = message + " Sample: " + item.sample
                };

                records.Add(record);
                TryAppendAudit(record);
            }

            return records.ToArray();
        }

        public AuditLog.AuditRecord[] DrainLateralDefenseAuditRecords()
        {
            LateralDefenseEventDto[] events = QueryLateralDefenseEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (LateralDefenseEventDto item in events)
            {
                string message = "Lateral movement attempt blocked: " + item.operation + " by PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                if (!string.IsNullOrWhiteSpace(item.processImage))
                {
                    message += " Process: " + item.processImage + ".";
                }

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "lateral-defense-sensor",
                    Action = "lateral.blocked." + item.operation,
                    Target = item.target,
                    Extension = item.processImage,
                    Succeeded = true,
                    Status = item.statusText,
                    Message = message + " DesiredAccess: 0x" + item.desiredAccess.ToString("X8", CultureInfo.InvariantCulture) + "."
                };

                records.Add(record);
                TryAppendAudit(record);
            }

            return records.ToArray();
        }

        public AuditLog.AuditRecord[] DrainHashProtectAuditRecords()
        {
            HashProtectEventDto[] events = QueryHashProtectEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (HashProtectEventDto item in events)
            {
                string message = "Credential hash dump attempt blocked: " + item.operation + " by PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                if (!string.IsNullOrWhiteSpace(item.processImage))
                {
                    message += " Process: " + item.processImage + ".";
                }

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "hash-protect-sensor",
                    Action = "hashdump.blocked." + item.operation,
                    Target = item.target,
                    Extension = item.processImage,
                    Succeeded = true,
                    Status = item.statusText,
                    Message = message + " DesiredAccess: 0x" + item.desiredAccess.ToString("X8", CultureInfo.InvariantCulture) + "."
                };

                records.Add(record);
                TryAppendAudit(record);
            }

            return records.ToArray();
        }

        public AuditLog.AuditRecord[] DrainUserHookDefenseAuditRecords()
        {
            UserHookDefenseEventDto[] events = QueryUserHookDefenseEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (UserHookDefenseEventDto item in events)
            {
                string message = "Application hook defense observed " + item.operation + " for PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                if (!string.IsNullOrWhiteSpace(item.processImage))
                {
                    message += " Process: " + item.processImage + ".";
                }

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "user-hook-defense-sensor",
                    Action = "userhook." + item.operation,
                    Target = item.target,
                    Extension = item.processImage,
                    Succeeded = true,
                    Status = item.statusText,
                    Message = message + " ParentPID: " + item.parentProcessId.ToString(CultureInfo.InvariantCulture) + ". Flags: 0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture) + "."
                };

                records.Add(record);
                TryAppendAudit(record);
            }

            return records.ToArray();
        }

        private AuditLog.AuditRecord[] TryDrainSecurityAuditSource(string source, Func<AuditLog.AuditRecord[]> drain)
        {
            try
            {
                return drain();
            }
            catch (Exception ex)
            {
                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "security-audit",
                    Action = "security.audit.drain.failed." + source,
                    Target = source,
                    Extension = string.Empty,
                    Succeeded = false,
                    Status = "0x00000001",
                    Message = ex.Message
                };

                TryAppendAudit(record);
                return new[] { record };
            }
        }

        private void TryAppendAudit(AuditLog.AuditRecord record)
        {
            if (record == null)
            {
                return;
            }

            try
            {
                auditLog.AppendRecord(record);
            }
            catch
            {
                // Central upload must not depend on local JSONL availability.
            }
        }

        private static PolicyRuleRequest NormalizeRequest(PolicyRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Request body is required.");
            }

            string kind = (request.Kind ?? string.Empty).Trim();
            string value = (request.Value ?? string.Empty).Trim();
            string extension = NormalizeExtension(request.Extension);

            if (string.IsNullOrWhiteSpace(kind))
            {
                throw new BridgeException(1, "Rule kind is required.");
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new BridgeException(1, "Rule value is required.");
            }

            if (kind == "processName" && !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                value += ".exe";
            }

            return new PolicyRuleRequest
            {
                Kind = kind,
                Value = value,
                Extension = extension,
                Actor = request.Actor
            };
        }

        private static string NormalizeExtension(string extension)
        {
            string normalized = string.IsNullOrWhiteSpace(extension) ? ".dpf" : extension.Trim();
            return normalized.StartsWith(".", StringComparison.Ordinal) ? normalized : "." + normalized;
        }

        private static NetworkRuleDto NormalizeNetworkRule(NetworkRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Request body is required.");
            }

            string kind = (request.kind ?? string.Empty).Trim();
            string action = NormalizeNetworkToken(request.action, "block");
            string protocol = NormalizeNetworkToken(request.protocol, "any");
            string direction = NormalizeNetworkToken(request.direction, "outbound");
            string domain = (request.domain ?? string.Empty).Trim().ToLowerInvariant();
            string remoteAddress = (request.remoteAddress ?? string.Empty).Trim();
            string localAddress = (request.localAddress ?? string.Empty).Trim();

            if (request.ruleId == 0)
            {
                throw new BridgeException(1, "Network rule id is required.");
            }

            if (kind != "ip" && kind != "domain")
            {
                throw new BridgeException(1, "Network rule kind must be ip or domain.");
            }

            if (action != "allow" && action != "block")
            {
                throw new BridgeException(1, "Network rule action must be allow or block.");
            }

            if (protocol != "any" && protocol != "icmp" && protocol != "tcp" && protocol != "udp")
            {
                throw new BridgeException(1, "Network protocol must be any, icmp, tcp, or udp.");
            }

            if (direction != "inbound" && direction != "outbound" && direction != "both")
            {
                throw new BridgeException(1, "Network direction must be inbound, outbound, or both.");
            }

            if (kind == "domain" && string.IsNullOrWhiteSpace(domain))
            {
                throw new BridgeException(1, "Domain rule requires a domain.");
            }

            if (kind == "domain" && protocol == "icmp")
            {
                throw new BridgeException(1, "Domain rules do not support ICMP.");
            }

            if (kind == "ip" && string.IsNullOrWhiteSpace(remoteAddress))
            {
                remoteAddress = "*";
            }

            NetworkRuleDto normalized = new NetworkRuleDto
            {
                ruleId = request.ruleId,
                kind = kind,
                action = action,
                protocol = protocol,
                direction = direction,
                localAddress = localAddress,
                localPort = request.localPort,
                remoteAddress = remoteAddress,
                remotePort = request.remotePort,
                domain = domain,
                actor = request.actor
            };

            normalized.displayTarget = kind == "domain" ? domain : remoteAddress;
            return normalized;
        }

        private static string NormalizeNetworkToken(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant();
        }

        private static PolicyRuleDto ConvertRule(DataProtectorPolicyNative.NativePolicyRule nativeRule)
        {
            string kind = "unknown";
            if (nativeRule.RuleType == RuleTypeProcessName)
            {
                kind = "processName";
            }
            else if (nativeRule.RuleType == RuleTypeProcessDirectory)
            {
                kind = "processDirectory";
            }
            else if (nativeRule.RuleType == RuleTypeExcludedDirectory)
            {
                kind = "excludedDirectory";
            }

            return new PolicyRuleDto
            {
                kind = kind,
                value = Marshal.PtrToStringUni(nativeRule.Value) ?? string.Empty,
                extension = Marshal.PtrToStringUni(nativeRule.Extension) ?? ".dpf"
            };
        }

        private static NetworkRuleDto ConvertNetworkRule(DataProtectorPolicyNative.NativeNetworkRule nativeRule)
        {
            return new NetworkRuleDto
            {
                ruleId = nativeRule.RuleId,
                kind = nativeRule.Kind == NetworkRuleTypeDomain ? "domain" : "ip",
                action = nativeRule.Action == NetworkActionAllow ? "allow" : "block",
                protocol = FromProtocol(nativeRule.Protocol),
                direction = FromDirection(nativeRule.Direction),
                localAddress = FormatAddress(nativeRule.LocalAddress, nativeRule.LocalAddressMask),
                localPort = nativeRule.LocalPort,
                remoteAddress = FormatAddress(nativeRule.RemoteAddress, nativeRule.RemoteAddressMask),
                remotePort = nativeRule.RemotePort,
                domain = Marshal.PtrToStringUni(nativeRule.Domain) ?? string.Empty,
                displayTarget = nativeRule.Kind == NetworkRuleTypeDomain
                    ? (Marshal.PtrToStringUni(nativeRule.Domain) ?? string.Empty)
                    : FormatAddress(nativeRule.RemoteAddress, nativeRule.RemoteAddressMask)
            };
        }

        private static SmtpEventDto ConvertSmtpEvent(DataProtectorPolicyNative.NativeSmtpEvent nativeEvent)
        {
            string localEndpoint = FormatEndpoint(nativeEvent.LocalAddress, nativeEvent.LocalPort);
            string remoteEndpoint = FormatEndpoint(nativeEvent.RemoteAddress, nativeEvent.RemotePort);

            return new SmtpEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                localAddress = FormatAddress(nativeEvent.LocalAddress, 0xFFFFFFFFu),
                remoteAddress = FormatAddress(nativeEvent.RemoteAddress, 0xFFFFFFFFu),
                localPort = nativeEvent.LocalPort,
                remotePort = nativeEvent.RemotePort,
                localEndpoint = localEndpoint,
                remoteEndpoint = remoteEndpoint,
                from = Marshal.PtrToStringUni(nativeEvent.From) ?? string.Empty,
                to = Marshal.PtrToStringUni(nativeEvent.To) ?? string.Empty
            };
        }

        private static NetworkConnectionEventDto ConvertNetworkConnectionEvent(DataProtectorPolicyNative.NativeNetworkConnectionEvent nativeEvent)
        {
            string domain = Marshal.PtrToStringUni(nativeEvent.Domain) ?? string.Empty;
            string remoteAddress = FormatAddress(nativeEvent.RemoteAddress, 0xFFFFFFFFu);
            string remoteEndpoint = FormatEndpoint(nativeEvent.RemoteAddress, nativeEvent.RemotePort);
            string protocolName = FromProtocol(nativeEvent.Protocol);
            bool isHttp3 = (nativeEvent.Flags & NetworkEventFlagHttp3) != 0;
            bool isQuic = (nativeEvent.Flags & NetworkEventFlagQuic) != 0;

            return new NetworkConnectionEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                direction = FromDirection(nativeEvent.Direction),
                protocol = nativeEvent.Protocol,
                protocolName = protocolName,
                localAddress = FormatAddress(nativeEvent.LocalAddress, 0xFFFFFFFFu),
                remoteAddress = remoteAddress,
                localPort = nativeEvent.LocalPort,
                remotePort = nativeEvent.RemotePort,
                localEndpoint = FormatEndpoint(nativeEvent.LocalAddress, nativeEvent.LocalPort),
                remoteEndpoint = remoteEndpoint,
                domain = domain,
                remoteIdentity = string.IsNullOrWhiteSpace(domain) ? remoteEndpoint : domain,
                processPath = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.ProcessPath) ?? string.Empty),
                flags = nativeEvent.Flags,
                isDns = (nativeEvent.Flags & NetworkEventFlagDns) != 0,
                isQuic = isQuic,
                isHttp3 = isHttp3,
                blocked = (nativeEvent.Flags & NetworkEventFlagBlocked) != 0
            };
        }

        private static WebShellRuleDto ConvertWebShellRule(DataProtectorPolicyNative.NativeWebShellRule nativeRule)
        {
            return new WebShellRuleDto
            {
                directory = Marshal.PtrToStringUni(nativeRule.Directory) ?? string.Empty
            };
        }

        private static DeviceRuleDto ConvertDeviceRule(DataProtectorPolicyNative.NativeDeviceRule nativeRule)
        {
            return new DeviceRuleDto
            {
                deviceId = Marshal.PtrToStringUni(nativeRule.DeviceId) ?? string.Empty,
                allowInsert = nativeRule.AllowInsert != 0,
                allowWrite = nativeRule.AllowWrite != 0
            };
        }

        private static WebShellEventDto ConvertWebShellEvent(DataProtectorPolicyNative.NativeWebShellEvent nativeEvent)
        {
            string sample = DecodeWebShellSample(nativeEvent.Sample, checked((int)Math.Min(nativeEvent.SampleLength, 100u)));

            return new WebShellEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                severity = FromWebShellSeverity(nativeEvent.Severity),
                operation = FromWebShellOperation(nativeEvent.Operation),
                fileSize = nativeEvent.FileSize,
                path = Marshal.PtrToStringUni(nativeEvent.Path) ?? string.Empty,
                extension = Marshal.PtrToStringUni(nativeEvent.Extension) ?? string.Empty,
                sample = sample
            };
        }

        private static HashProtectEventDto ConvertHashProtectEvent(DataProtectorPolicyNative.NativeHashProtectEvent nativeEvent)
        {
            return new HashProtectEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                operation = FromHashProtectOperation(nativeEvent.Operation),
                status = nativeEvent.Status,
                statusText = "0x" + nativeEvent.Status.ToString("X8", CultureInfo.InvariantCulture),
                desiredAccess = nativeEvent.DesiredAccess,
                target = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.Target) ?? string.Empty),
                processImage = Marshal.PtrToStringUni(nativeEvent.ProcessImage) ?? string.Empty
            };
        }

        private static LateralDefenseEventDto ConvertLateralDefenseEvent(DataProtectorPolicyNative.NativeLateralDefenseEvent nativeEvent)
        {
            return new LateralDefenseEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                operation = FromLateralDefenseOperation(nativeEvent.Operation),
                status = nativeEvent.Status,
                statusText = "0x" + nativeEvent.Status.ToString("X8", CultureInfo.InvariantCulture),
                desiredAccess = nativeEvent.DesiredAccess,
                flags = nativeEvent.Flags,
                target = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.Target) ?? string.Empty),
                processImage = Marshal.PtrToStringUni(nativeEvent.ProcessImage) ?? string.Empty
            };
        }

        private static UserHookDefenseEventDto ConvertUserHookDefenseEvent(DataProtectorPolicyNative.NativeUserHookDefenseEvent nativeEvent)
        {
            return new UserHookDefenseEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                parentProcessId = nativeEvent.ParentProcessId,
                operation = FromUserHookDefenseOperation(nativeEvent.Operation),
                status = nativeEvent.Status,
                statusText = "0x" + nativeEvent.Status.ToString("X8", CultureInfo.InvariantCulture),
                flags = nativeEvent.Flags,
                target = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.Target) ?? string.Empty),
                processImage = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.ProcessImage) ?? string.Empty)
            };
        }

        private static HashProtectPolicyDto FromHashProtectFlags(uint flags)
        {
            return new HashProtectPolicyDto
            {
                enabled = (flags & HashProtectFlagEnabled) != 0,
                protectLsass = (flags & HashProtectFlagLsassHandles) != 0,
                protectCredentialFiles = (flags & HashProtectFlagCredentialFiles) != 0,
                protectRegistryHives = (flags & HashProtectFlagRegistryHives) != 0,
                protectRawExtents = (flags & HashProtectFlagRawExtents) != 0,
                flags = flags & HashProtectAllowedFlags
            };
        }

        internal static uint ToHashProtectFlags(HashProtectPolicyDto policy)
        {
            if (policy == null)
            {
                return HashProtectAllowedFlags;
            }

            uint flags = 0;
            if (policy.enabled) flags |= HashProtectFlagEnabled;
            if (policy.protectLsass) flags |= HashProtectFlagLsassHandles;
            if (policy.protectCredentialFiles) flags |= HashProtectFlagCredentialFiles;
            if (policy.protectRegistryHives) flags |= HashProtectFlagRegistryHives;
            if (policy.protectRawExtents) flags |= HashProtectFlagRawExtents;
            return flags & HashProtectAllowedFlags;
        }

        internal static HashProtectPolicyDto DefaultHashProtectPolicy()
        {
            return FromHashProtectFlags(HashProtectAllowedFlags);
        }

        internal static HashProtectPolicyDto CloneHashProtectPolicy(HashProtectPolicyDto policy)
        {
            HashProtectPolicyDto source = policy ?? DefaultHashProtectPolicy();
            return new HashProtectPolicyDto
            {
                enabled = source.enabled,
                protectLsass = source.protectLsass,
                protectCredentialFiles = source.protectCredentialFiles,
                protectRegistryHives = source.protectRegistryHives,
                protectRawExtents = source.protectRawExtents,
                flags = ToHashProtectFlags(source),
                actor = source.actor
            };
        }

        internal static HashProtectPolicyDto NormalizeHashProtectPolicy(HashProtectPolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Hash protection policy body is required.");
            }

            HashProtectPolicyDto normalized = new HashProtectPolicyDto
            {
                enabled = request.enabled,
                protectLsass = request.protectLsass,
                protectCredentialFiles = request.protectCredentialFiles,
                protectRegistryHives = request.protectRegistryHives,
                protectRawExtents = request.protectRawExtents || request.actor == null,
                actor = request.actor
            };

            normalized.flags = ToHashProtectFlags(normalized);
            return normalized;
        }

        internal static string HashProtectPolicySummary(HashProtectPolicyDto policy)
        {
            HashProtectPolicyDto normalized = CloneHashProtectPolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};lsass={1};credentialFiles={2};registryHives={3};rawExtents={4};flags=0x{5:X8}",
                normalized.enabled,
                normalized.protectLsass,
                normalized.protectCredentialFiles,
                normalized.protectRegistryHives,
                normalized.protectRawExtents,
                normalized.flags);
        }

        private static LateralDefensePolicyDto FromLateralDefenseFlags(uint flags)
        {
            return new LateralDefensePolicyDto
            {
                enabled = (flags & LateralDefenseFlagEnabled) != 0,
                blockSmbExecutableCopy = (flags & LateralDefenseFlagSmbExecutables) != 0,
                blockIpcScheduledTasks = (flags & LateralDefenseFlagIpcTasks) != 0,
                blockIpcServiceCreation = (flags & LateralDefenseFlagIpcServices) != 0,
                blockRemoteAdminTools = (flags & LateralDefenseFlagProcessTools) != 0,
                flags = flags & LateralDefenseAllowedFlags
            };
        }

        internal static uint ToLateralDefenseFlags(LateralDefensePolicyDto policy)
        {
            if (policy == null)
            {
                return LateralDefenseAllowedFlags;
            }

            uint flags = 0;
            if (policy.enabled) flags |= LateralDefenseFlagEnabled;
            if (policy.blockSmbExecutableCopy) flags |= LateralDefenseFlagSmbExecutables;
            if (policy.blockIpcScheduledTasks) flags |= LateralDefenseFlagIpcTasks;
            if (policy.blockIpcServiceCreation) flags |= LateralDefenseFlagIpcServices;
            if (policy.blockRemoteAdminTools) flags |= LateralDefenseFlagProcessTools;
            return flags & LateralDefenseAllowedFlags;
        }

        internal static LateralDefensePolicyDto DefaultLateralDefensePolicy()
        {
            return FromLateralDefenseFlags(LateralDefenseAllowedFlags);
        }

        internal static LateralDefensePolicyDto CloneLateralDefensePolicy(LateralDefensePolicyDto policy)
        {
            LateralDefensePolicyDto source = policy ?? DefaultLateralDefensePolicy();
            return new LateralDefensePolicyDto
            {
                enabled = source.enabled,
                blockSmbExecutableCopy = source.blockSmbExecutableCopy,
                blockIpcScheduledTasks = source.blockIpcScheduledTasks,
                blockIpcServiceCreation = source.blockIpcServiceCreation,
                blockRemoteAdminTools = source.blockRemoteAdminTools,
                flags = ToLateralDefenseFlags(source),
                actor = source.actor
            };
        }

        internal static LateralDefensePolicyDto NormalizeLateralDefensePolicy(LateralDefensePolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Lateral defense policy body is required.");
            }

            LateralDefensePolicyDto normalized = new LateralDefensePolicyDto
            {
                enabled = request.enabled,
                blockSmbExecutableCopy = request.blockSmbExecutableCopy,
                blockIpcScheduledTasks = request.blockIpcScheduledTasks,
                blockIpcServiceCreation = request.blockIpcServiceCreation,
                blockRemoteAdminTools = request.blockRemoteAdminTools,
                actor = request.actor
            };

            normalized.flags = ToLateralDefenseFlags(normalized);
            return normalized;
        }

        internal static string LateralDefensePolicySummary(LateralDefensePolicyDto policy)
        {
            LateralDefensePolicyDto normalized = CloneLateralDefensePolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};smbExecutables={1};ipcTasks={2};ipcServices={3};remoteTools={4};flags=0x{5:X8}",
                normalized.enabled,
                normalized.blockSmbExecutableCopy,
                normalized.blockIpcScheduledTasks,
                normalized.blockIpcServiceCreation,
                normalized.blockRemoteAdminTools,
                normalized.flags);
        }

        private static UserHookDefensePolicyDto FromUserHookDefenseFlags(uint flags)
        {
            return new UserHookDefensePolicyDto
            {
                enabled = (flags & UserHookDefenseFlagEnabled) != 0,
                monitorEarlyProcesses = (flags & UserHookDefenseFlagEarlyProcessMonitor) != 0,
                monitorImageLoads = (flags & UserHookDefenseFlagImageLoadMonitor) != 0,
                requireSignedRuntime = (flags & UserHookDefenseFlagRequireSignedRuntime) != 0,
                blockUntrustedRuntime = (flags & UserHookDefenseFlagBlockUntrustedRuntime) != 0,
                auditOnly = (flags & UserHookDefenseFlagAuditOnly) != 0,
                monitorSystemProcesses = (flags & UserHookDefenseFlagMonitorSystemProcesses) != 0,
                flags = flags & UserHookDefenseAllowedFlags
            };
        }

        internal static uint ToUserHookDefenseFlags(UserHookDefensePolicyDto policy)
        {
            if (policy == null)
            {
                return UserHookDefenseFlagEnabled |
                       UserHookDefenseFlagEarlyProcessMonitor |
                       UserHookDefenseFlagImageLoadMonitor |
                       UserHookDefenseFlagRequireSignedRuntime |
                       UserHookDefenseFlagAuditOnly;
            }

            uint flags = 0;
            if (policy.enabled) flags |= UserHookDefenseFlagEnabled;
            if (policy.monitorEarlyProcesses) flags |= UserHookDefenseFlagEarlyProcessMonitor;
            if (policy.monitorImageLoads) flags |= UserHookDefenseFlagImageLoadMonitor;
            if (policy.requireSignedRuntime) flags |= UserHookDefenseFlagRequireSignedRuntime;
            if (policy.blockUntrustedRuntime) flags |= UserHookDefenseFlagBlockUntrustedRuntime;
            if (policy.auditOnly) flags |= UserHookDefenseFlagAuditOnly;
            if (policy.monitorSystemProcesses) flags |= UserHookDefenseFlagMonitorSystemProcesses;
            return flags & UserHookDefenseAllowedFlags;
        }

        internal static UserHookDefensePolicyDto DefaultUserHookDefensePolicy()
        {
            return FromUserHookDefenseFlags(
                UserHookDefenseFlagEnabled |
                UserHookDefenseFlagEarlyProcessMonitor |
                UserHookDefenseFlagImageLoadMonitor |
                UserHookDefenseFlagRequireSignedRuntime |
                UserHookDefenseFlagAuditOnly);
        }

        internal static UserHookDefensePolicyDto CloneUserHookDefensePolicy(UserHookDefensePolicyDto policy)
        {
            UserHookDefensePolicyDto source = policy ?? DefaultUserHookDefensePolicy();
            return new UserHookDefensePolicyDto
            {
                enabled = source.enabled,
                monitorEarlyProcesses = source.monitorEarlyProcesses,
                monitorImageLoads = source.monitorImageLoads,
                requireSignedRuntime = source.requireSignedRuntime,
                blockUntrustedRuntime = source.blockUntrustedRuntime,
                auditOnly = source.auditOnly,
                monitorSystemProcesses = source.monitorSystemProcesses,
                flags = ToUserHookDefenseFlags(source),
                actor = source.actor
            };
        }

        internal static UserHookDefensePolicyDto NormalizeUserHookDefensePolicy(UserHookDefensePolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Application hook defense policy body is required.");
            }

            UserHookDefensePolicyDto normalized = new UserHookDefensePolicyDto
            {
                enabled = request.enabled,
                monitorEarlyProcesses = request.monitorEarlyProcesses,
                monitorImageLoads = request.monitorImageLoads,
                requireSignedRuntime = request.requireSignedRuntime,
                blockUntrustedRuntime = request.blockUntrustedRuntime,
                auditOnly = request.auditOnly,
                monitorSystemProcesses = request.monitorSystemProcesses,
                actor = request.actor
            };

            normalized.flags = ToUserHookDefenseFlags(normalized);
            return normalized;
        }

        internal static string UserHookDefensePolicySummary(UserHookDefensePolicyDto policy)
        {
            UserHookDefensePolicyDto normalized = CloneUserHookDefensePolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};earlyProcess={1};imageLoad={2};signedRuntime={3};blockUntrusted={4};auditOnly={5};system={6};flags=0x{7:X8}",
                normalized.enabled,
                normalized.monitorEarlyProcesses,
                normalized.monitorImageLoads,
                normalized.requireSignedRuntime,
                normalized.blockUntrustedRuntime,
                normalized.auditOnly,
                normalized.monitorSystemProcesses,
                normalized.flags);
        }

        internal static UsbCryptPolicyDto DefaultUsbCryptPolicy()
        {
            return new UsbCryptPolicyDto
            {
                enabled = false,
                algorithm = "rc4",
                publicToolAreaBytes = 5 * 1024 * 1024,
                allowClientProvisioning = false,
                requireHardwareAuthorization = true,
                keyMaterialId = string.Empty,
                actor = string.Empty
            };
        }

        internal static UsbCryptPolicyDto CloneUsbCryptPolicy(UsbCryptPolicyDto policy)
        {
            UsbCryptPolicyDto source = policy ?? DefaultUsbCryptPolicy();
            return new UsbCryptPolicyDto
            {
                enabled = source.enabled,
                algorithm = string.IsNullOrWhiteSpace(source.algorithm) ? "rc4" : source.algorithm,
                publicToolAreaBytes = source.publicToolAreaBytes <= 0 ? 5 * 1024 * 1024 : source.publicToolAreaBytes,
                allowClientProvisioning = source.allowClientProvisioning,
                requireHardwareAuthorization = source.requireHardwareAuthorization,
                keyMaterialId = source.keyMaterialId ?? string.Empty,
                actor = source.actor ?? string.Empty
            };
        }

        internal static UsbCryptPolicyDto NormalizeUsbCryptPolicy(UsbCryptPolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "USB encryption policy body is required.");
            }

            string algorithm = string.IsNullOrWhiteSpace(request.algorithm)
                ? "rc4"
                : request.algorithm.Trim().ToLowerInvariant();
            if (!string.Equals(algorithm, "rc4", StringComparison.OrdinalIgnoreCase))
            {
                throw new BridgeException(1, "Only RC4 is supported by this USB encryption policy version.");
            }

            long toolArea = request.publicToolAreaBytes <= 0 ? 5 * 1024 * 1024 : request.publicToolAreaBytes;
            if (toolArea < 5 * 1024 * 1024)
            {
                toolArea = 5 * 1024 * 1024;
            }

            return new UsbCryptPolicyDto
            {
                enabled = request.enabled,
                algorithm = algorithm,
                publicToolAreaBytes = toolArea,
                allowClientProvisioning = request.allowClientProvisioning,
                requireHardwareAuthorization = request.requireHardwareAuthorization,
                keyMaterialId = (request.keyMaterialId ?? string.Empty).Trim(),
                actor = request.actor
            };
        }

        internal static string UsbCryptPolicySummary(UsbCryptPolicyDto policy)
        {
            UsbCryptPolicyDto normalized = CloneUsbCryptPolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};algorithm={1};toolArea={2};clientProvisioning={3};hardwareAuthorization={4};key={5}",
                normalized.enabled,
                normalized.algorithm,
                normalized.publicToolAreaBytes,
                normalized.allowClientProvisioning,
                normalized.requireHardwareAuthorization,
                string.IsNullOrWhiteSpace(normalized.keyMaterialId) ? "(none)" : normalized.keyMaterialId);
        }

        internal static DlpProtectionPolicyDto DefaultDlpProtectionPolicy()
        {
            return new DlpProtectionPolicyDto
            {
                enabled = false,
                protectClipboard = true,
                protectScreenshots = true,
                clipboardMode = "clear",
                screenshotMode = "block",
                clearClipboardText = true,
                clearClipboardImages = true,
                clearClipboardFiles = true,
                clearScreenshotClipboard = true,
                blockPrintScreenHotkeys = true,
                trustedProcessNames = new string[0],
                trustedProcessDirectories = new string[0],
                actor = "system"
            };
        }

        internal static DlpProtectionPolicyDto CloneDlpProtectionPolicy(DlpProtectionPolicyDto policy)
        {
            DlpProtectionPolicyDto source = policy ?? DefaultDlpProtectionPolicy();
            return new DlpProtectionPolicyDto
            {
                enabled = source.enabled,
                protectClipboard = source.protectClipboard,
                protectScreenshots = source.protectScreenshots,
                clipboardMode = NormalizeDlpMode(source.clipboardMode, "clear"),
                screenshotMode = NormalizeDlpMode(source.screenshotMode, "block"),
                clearClipboardText = source.clearClipboardText,
                clearClipboardImages = source.clearClipboardImages,
                clearClipboardFiles = source.clearClipboardFiles,
                clearScreenshotClipboard = source.clearScreenshotClipboard,
                blockPrintScreenHotkeys = source.blockPrintScreenHotkeys,
                trustedProcessNames = NormalizeDlpStringList(source.trustedProcessNames),
                trustedProcessDirectories = NormalizeDlpStringList(source.trustedProcessDirectories),
                actor = string.IsNullOrWhiteSpace(source.actor) ? "system" : source.actor.Trim()
            };
        }

        internal static DlpProtectionPolicyDto NormalizeDlpProtectionPolicy(DlpProtectionPolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "DLP protection policy body is required.");
            }

            return new DlpProtectionPolicyDto
            {
                enabled = request.enabled,
                protectClipboard = request.protectClipboard,
                protectScreenshots = request.protectScreenshots,
                clipboardMode = NormalizeDlpMode(request.clipboardMode, "clear"),
                screenshotMode = NormalizeDlpMode(request.screenshotMode, "block"),
                clearClipboardText = request.clearClipboardText,
                clearClipboardImages = request.clearClipboardImages,
                clearClipboardFiles = request.clearClipboardFiles,
                clearScreenshotClipboard = request.clearScreenshotClipboard,
                blockPrintScreenHotkeys = request.blockPrintScreenHotkeys,
                trustedProcessNames = NormalizeDlpStringList(request.trustedProcessNames),
                trustedProcessDirectories = NormalizeDlpStringList(request.trustedProcessDirectories),
                actor = string.IsNullOrWhiteSpace(request.actor) ? "web-admin" : request.actor.Trim()
            };
        }

        internal static string DlpProtectionPolicySummary(DlpProtectionPolicyDto policy)
        {
            DlpProtectionPolicyDto normalized = CloneDlpProtectionPolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};clipboard={1};clipboardMode={2};screenshots={3};screenshotMode={4};hotkeys={5};trustedProcesses={6};trustedDirectories={7}",
                normalized.enabled,
                normalized.protectClipboard,
                normalized.clipboardMode,
                normalized.protectScreenshots,
                normalized.screenshotMode,
                normalized.blockPrintScreenHotkeys,
                normalized.trustedProcessNames.Length,
                normalized.trustedProcessDirectories.Length);
        }

        internal static bool SameDlpProtectionPolicy(DlpProtectionPolicyDto left, DlpProtectionPolicyDto right)
        {
            DlpProtectionPolicyDto a = CloneDlpProtectionPolicy(left);
            DlpProtectionPolicyDto b = CloneDlpProtectionPolicy(right);
            return a.enabled == b.enabled &&
                   a.protectClipboard == b.protectClipboard &&
                   a.protectScreenshots == b.protectScreenshots &&
                   string.Equals(a.clipboardMode, b.clipboardMode, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(a.screenshotMode, b.screenshotMode, StringComparison.OrdinalIgnoreCase) &&
                   a.clearClipboardText == b.clearClipboardText &&
                   a.clearClipboardImages == b.clearClipboardImages &&
                   a.clearClipboardFiles == b.clearClipboardFiles &&
                   a.clearScreenshotClipboard == b.clearScreenshotClipboard &&
                   a.blockPrintScreenHotkeys == b.blockPrintScreenHotkeys &&
                   SameStringSet(a.trustedProcessNames, b.trustedProcessNames) &&
                   SameStringSet(a.trustedProcessDirectories, b.trustedProcessDirectories);
        }

        private static string NormalizeDlpMode(string value, string fallback)
        {
            string mode = (value ?? string.Empty).Trim().ToLowerInvariant();
            if (mode == "audit" || mode == "clear" || mode == "block")
            {
                return mode;
            }

            return fallback;
        }

        private static string[] NormalizeDlpStringList(string[] values)
        {
            if (values == null)
            {
                return new string[0];
            }

            return values
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .Take(512)
                .ToArray();
        }

        private static bool SameStringSet(string[] left, string[] right)
        {
            string[] a = NormalizeDlpStringList(left);
            string[] b = NormalizeDlpStringList(right);
            if (a.Length != b.Length)
            {
                return false;
            }

            for (int index = 0; index < a.Length; index++)
            {
                if (!string.Equals(a[index], b[index], StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }

        private static unsafe string DecodeWebShellSample(DataProtectorPolicyNative.SampleBuffer sample, int length)
        {
            if (length <= 0)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(length);
            int take = Math.Min(length, 100);
            for (int index = 0; index < take; index++)
            {
                byte value = sample.Bytes[index];
                if (value == 0)
                {
                    continue;
                }

                if (value == (byte)'\r' || value == (byte)'\n' || value == (byte)'\t' || (value >= 0x20 && value <= 0x7E))
                {
                    builder.Append((char)value);
                }
            }

            return builder.ToString();
        }

        private static WebShellRuleDto NormalizeWebShellRule(WebShellRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "WebShell rule request body is required.");
            }

            string directory = (request.directory ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new BridgeException(1, "Protected web directory is required.");
            }

            return new WebShellRuleDto
            {
                directory = directory,
                actor = request.actor
            };
        }

        private static DeviceRuleDto NormalizeDeviceRule(DeviceRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Device rule request body is required.");
            }

            string deviceId = (request.deviceId ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                throw new BridgeException(1, "Device id is required. Use * for all removable storage.");
            }

            if (deviceId.Length > 259)
            {
                throw new BridgeException(1, "Device id is too long.");
            }

            return new DeviceRuleDto
            {
                deviceId = deviceId,
                allowInsert = request.allowInsert,
                allowWrite = request.allowInsert && request.allowWrite,
                actor = request.actor
            };
        }

        private static DataProtectorPolicyNative.NativeNetworkRule ToNativeNetworkRule(NetworkRuleDto rule)
        {
            uint localAddress;
            uint localMask;
            uint remoteAddress;
            uint remoteMask;
            ParseAddress(rule.localAddress, out localAddress, out localMask);
            ParseAddress(rule.remoteAddress, out remoteAddress, out remoteMask);

            return new DataProtectorPolicyNative.NativeNetworkRule
            {
                RuleId = rule.ruleId,
                Kind = rule.kind == "domain" ? NetworkRuleTypeDomain : NetworkRuleTypeIp,
                Action = rule.action == "allow" ? NetworkActionAllow : NetworkActionBlock,
                Protocol = ToProtocol(rule.protocol),
                Direction = ToDirection(rule.direction),
                LocalAddress = localAddress,
                LocalAddressMask = localMask,
                RemoteAddress = remoteAddress,
                RemoteAddressMask = remoteMask,
                LocalPort = rule.localPort,
                RemotePort = rule.kind == "domain" && rule.remotePort == 0 ? (ushort)53 : rule.remotePort,
                Domain = string.IsNullOrWhiteSpace(rule.domain) ? IntPtr.Zero : Marshal.StringToHGlobalUni(rule.domain)
            };
        }

        internal static void FreeNativeNetworkRule(DataProtectorPolicyNative.NativeNetworkRule rule)
        {
            if (rule.Domain != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rule.Domain);
            }
        }

        private static DataProtectorPolicyNative.NativeDeviceRule ToNativeDeviceRule(DeviceRuleDto rule)
        {
            return new DataProtectorPolicyNative.NativeDeviceRule
            {
                DeviceId = Marshal.StringToHGlobalUni(rule.deviceId),
                AllowInsert = rule.allowInsert ? 1u : 0u,
                AllowWrite = rule.allowWrite ? 1u : 0u
            };
        }

        internal static void FreeNativeDeviceRule(DataProtectorPolicyNative.NativeDeviceRule rule)
        {
            if (rule.DeviceId != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rule.DeviceId);
            }
        }

        private static uint ToProtocol(string protocol)
        {
            if (string.Equals(protocol, "icmp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolIcmp;
            if (string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolTcp;
            if (string.Equals(protocol, "udp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolUdp;
            return NetworkProtocolAny;
        }

        private static string FromProtocol(uint protocol)
        {
            if (protocol == NetworkProtocolIcmp) return "icmp";
            if (protocol == NetworkProtocolTcp) return "tcp";
            if (protocol == NetworkProtocolUdp) return "udp";
            return "any";
        }

        private static uint ToDirection(string direction)
        {
            if (string.Equals(direction, "inbound", StringComparison.OrdinalIgnoreCase)) return NetworkDirectionInbound;
            if (string.Equals(direction, "both", StringComparison.OrdinalIgnoreCase)) return NetworkDirectionBoth;
            return NetworkDirectionOutbound;
        }

        private static string FromDirection(uint direction)
        {
            if (direction == NetworkDirectionInbound) return "inbound";
            if (direction == NetworkDirectionBoth) return "both";
            return "outbound";
        }

        private static string FromWebShellSeverity(uint severity)
        {
            if (severity == WebShellSeverityDanger) return "danger";
            if (severity == WebShellSeverityWarning) return "warning";
            return "notify";
        }

        private static string FromWebShellOperation(uint operation)
        {
            if (operation == WebShellOperationCreate) return "create";
            if (operation == WebShellOperationRename) return "rename";
            if (operation == WebShellOperationCleanup) return "cleanup";
            return "write";
        }

        private static string FromHashProtectOperation(uint operation)
        {
            if (operation == HashOperationLsassHandle) return "lsass-handle";
            if (operation == HashOperationCredentialFile) return "credential-file";
            if (operation == HashOperationRegistryHive) return "registry-hive";
            if (operation == HashOperationRawExtent) return "raw-extents";
            return "unknown";
        }

        private static string FromLateralDefenseOperation(uint operation)
        {
            if (operation == LateralOperationSmbExecutableCreate) return "smb-executable-create";
            if (operation == LateralOperationSmbExecutableWrite) return "smb-executable-write";
            if (operation == LateralOperationSmbExecutableRename) return "smb-executable-rename";
            if (operation == LateralOperationIpcTaskScheduler) return "ipc-task-scheduler";
            if (operation == LateralOperationIpcServiceControl) return "ipc-service-control";
            if (operation == LateralOperationRemoteScheduledTaskTool) return "remote-scheduled-task-tool";
            if (operation == LateralOperationRemoteServiceTool) return "remote-service-tool";
            if (operation == LateralOperationWmiProcessCreate) return "wmi-process-create";
            if (operation == LateralOperationPowerShellRemoteTask) return "powershell-remote-task";
            return "unknown";
        }

        private static string FromUserHookDefenseOperation(uint operation)
        {
            if (operation == UserHookOperationProcessCreate) return "process-create";
            if (operation == UserHookOperationHookSurfaceImageLoad) return "hook-surface-image-load";
            if (operation == UserHookOperationRuntimeRequired) return "runtime-required";
            if (operation == UserHookOperationRuntimeMissing) return "runtime-missing";
            if (operation == UserHookOperationRuntimeRejected) return "runtime-rejected";
            if (operation == UserHookOperationSuspiciousHookAttempt) return "suspicious-hook-attempt";
            return "unknown";
        }

        private static void ParseAddress(string value, out uint address, out uint mask)
        {
            address = 0;
            mask = 0;

            if (string.IsNullOrWhiteSpace(value) || value == "*" || value == "0.0.0.0/0")
            {
                return;
            }

            string[] parts = value.Split('/');
            IPAddress ip;
            if (!IPAddress.TryParse(parts[0], out ip))
            {
                throw new BridgeException(1, "Invalid IPv4 address: " + value);
            }

            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length != 4)
            {
                throw new BridgeException(1, "Only IPv4 network rules are supported.");
            }

            address = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            mask = 0xFFFFFFFFu;

            if (parts.Length > 1)
            {
                int prefix;
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > 32)
                {
                    throw new BridgeException(1, "Invalid IPv4 CIDR prefix: " + value);
                }

                mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
            }
        }

        private static string FormatAddress(uint address, uint mask)
        {
            if (address == 0 && mask == 0)
            {
                return string.Empty;
            }

            string ip = string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}",
                (address >> 24) & 0xFF,
                (address >> 16) & 0xFF,
                (address >> 8) & 0xFF,
                address & 0xFF);

            if (mask == 0xFFFFFFFFu)
            {
                return ip;
            }

            return ip + "/" + CountPrefix(mask).ToString(CultureInfo.InvariantCulture);
        }

        private static string FormatEndpoint(uint address, ushort port)
        {
            string ip = FormatAddress(address, 0xFFFFFFFFu);
            return port == 0 ? ip : ip + ":" + port.ToString(CultureInfo.InvariantCulture);
        }

        private static string NormalizeDevicePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            string value = path.Trim();
            string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (value.StartsWith("\\Device\\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            {
                string suffix = value;
                int usersIndex = value.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase);
                if (usersIndex >= 0)
                {
                    string systemDrive = Path.GetPathRoot(systemRoot);
                    return (systemDrive ?? string.Empty).TrimEnd('\\') + suffix.Substring(usersIndex);
                }

                int programFilesIndex = value.IndexOf("\\Program Files", StringComparison.OrdinalIgnoreCase);
                if (programFilesIndex >= 0)
                {
                    string systemDrive = Path.GetPathRoot(systemRoot);
                    return (systemDrive ?? string.Empty).TrimEnd('\\') + suffix.Substring(programFilesIndex);
                }

                int windowsIndex = value.IndexOf("\\Windows\\", StringComparison.OrdinalIgnoreCase);
                if (windowsIndex >= 0)
                {
                    string systemDrive = Path.GetPathRoot(systemRoot);
                    return (systemDrive ?? string.Empty).TrimEnd('\\') + suffix.Substring(windowsIndex);
                }
            }

            return value;
        }

        private static bool IsNoiseNetworkProcess(string processPath)
        {
            string fileName = string.IsNullOrWhiteSpace(processPath)
                ? string.Empty
                : Path.GetFileName(processPath).ToLowerInvariant();

            if (string.IsNullOrWhiteSpace(fileName))
            {
                return false;
            }

            string[] ignored =
            {
                "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "opera_gx.exe",
                "msedgewebview2.exe", "chromium.exe", "brave.exe", "vivaldi.exe", "safari.exe",
                "ucbrowser.exe", "browser.exe", "qqbrowser.exe", "sogouexplorer.exe", "360se.exe",
                "360chrome.exe", "liebao.exe", "maxthon.exe", "2345explorer.exe", "baidubrowser.exe",
                "theworld.exe", "wechat.exe", "weixin.exe", "wechatappex.exe", "wxwork.exe",
                "enterprisewechat.exe", "wecom.exe", "qq.exe", "tim.exe", "dingtalk.exe",
                "feishu.exe", "lark.exe", "teams.exe", "slack.exe", "telegram.exe",
                "discord.exe", "skype.exe", "zoom.exe", "tencentmeeting.exe", "wemeetapp.exe",
                "outlook.exe", "thunderbird.exe", "foxmail.exe", "whatsapp.exe", "signal.exe",
                "line.exe", "viber.exe", "mattermost.exe"
            };

            for (int index = 0; index < ignored.Length; index++)
            {
                if (string.Equals(fileName, ignored[index], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static void EnrichNetworkConnectionEvent(NetworkConnectionEventDto item)
        {
            if (item == null)
            {
                return;
            }

            string path = item.processPath;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                item.fileExists = false;
                item.signatureStatus = "unknown";
                return;
            }

            item.fileExists = true;

            try
            {
                FileInfo file = new FileInfo(path);
                item.fileSize = file.Length;
                item.fileModifiedUtc = file.LastWriteTimeUtc.ToString("o");
            }
            catch
            {
                item.fileSize = 0;
                item.fileModifiedUtc = string.Empty;
            }

            try
            {
                System.Diagnostics.FileVersionInfo version = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                item.productName = version.ProductName ?? string.Empty;
                item.companyName = version.CompanyName ?? string.Empty;
                item.fileDescription = version.FileDescription ?? string.Empty;
                item.fileVersion = version.FileVersion ?? string.Empty;
            }
            catch
            {
                item.productName = string.Empty;
                item.companyName = string.Empty;
                item.fileDescription = string.Empty;
                item.fileVersion = string.Empty;
            }

            try
            {
                using (SHA256 sha256 = SHA256.Create())
                using (FileStream stream = File.OpenRead(path))
                {
                    item.sha256 = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty).ToLowerInvariant();
                }
            }
            catch
            {
                item.sha256 = string.Empty;
            }

            try
            {
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
                X509Certificate2 certificate2 = new X509Certificate2(certificate);
                item.signatureStatus = "signed";
                item.signer = certificate2.Subject ?? string.Empty;
            }
            catch
            {
                item.signatureStatus = "unsigned";
                item.signer = string.Empty;
            }
        }

        private static int CountPrefix(uint mask)
        {
            int prefix = 0;
            for (int bit = 31; bit >= 0; bit--)
            {
                if ((mask & (1u << bit)) == 0)
                {
                    break;
                }

                prefix++;
            }

            return prefix;
        }

        private static OperationResult Invoke(Func<uint> operation)
        {
            try
            {
                uint status = operation();
                bool succeeded = status == SuccessStatus;
                return new OperationResult
                {
                    succeeded = succeeded,
                    status = status,
                    statusText = ToStatusText(status),
                    message = succeeded ? "Success." : ReadLastErrorMessage()
                };
            }
            catch (BridgeException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new OperationResult
                {
                    succeeded = false,
                    status = 1,
                    statusText = ToStatusText(1),
                    message = ex.Message
                };
            }
        }

        private static string ReadLastErrorMessage()
        {
            try
            {
                StringBuilder buffer = new StringBuilder(MessageBufferChars);
                DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(buffer, (uint)buffer.Capacity);
                return buffer.ToString();
            }
            catch (Exception ex)
            {
                return "Cannot read native policy API error: " + ex.Message;
            }
        }

        private static void ZeroMemory(IntPtr buffer, int bytes)
        {
            byte[] zeros = new byte[bytes];
            Marshal.Copy(zeros, 0, buffer, bytes);
        }

        private static string ToStatusText(uint status)
        {
            return "0x" + status.ToString("X8");
        }

        public sealed class PolicyRuleRequest
        {
            public string Kind { get; set; }
            public string Value { get; set; }
            public string Extension { get; set; }
            public string Actor { get; set; }
        }

        public sealed class PolicyRuleDto
        {
            public string kind { get; set; }
            public string value { get; set; }
            public string extension { get; set; }
        }

        public class NetworkRuleRequest
        {
            public uint ruleId { get; set; }
            public string kind { get; set; }
            public string action { get; set; }
            public string protocol { get; set; }
            public string direction { get; set; }
            public string localAddress { get; set; }
            public ushort localPort { get; set; }
            public string remoteAddress { get; set; }
            public ushort remotePort { get; set; }
            public string domain { get; set; }
            public string actor { get; set; }
        }

        public sealed class NetworkRuleDto : NetworkRuleRequest
        {
            public string displayTarget { get; set; }
        }

        public sealed class SmtpEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string localAddress { get; set; }
            public string remoteAddress { get; set; }
            public ushort localPort { get; set; }
            public ushort remotePort { get; set; }
            public string localEndpoint { get; set; }
            public string remoteEndpoint { get; set; }
            public string from { get; set; }
            public string to { get; set; }
        }

        public sealed class NetworkConnectionEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string direction { get; set; }
            public uint protocol { get; set; }
            public string protocolName { get; set; }
            public string localAddress { get; set; }
            public string remoteAddress { get; set; }
            public ushort localPort { get; set; }
            public ushort remotePort { get; set; }
            public string localEndpoint { get; set; }
            public string remoteEndpoint { get; set; }
            public string domain { get; set; }
            public string remoteIdentity { get; set; }
            public string processPath { get; set; }
            public uint flags { get; set; }
            public bool isDns { get; set; }
            public bool isQuic { get; set; }
            public bool isHttp3 { get; set; }
            public bool blocked { get; set; }
            public bool fileExists { get; set; }
            public long fileSize { get; set; }
            public string fileModifiedUtc { get; set; }
            public string productName { get; set; }
            public string companyName { get; set; }
            public string fileDescription { get; set; }
            public string fileVersion { get; set; }
            public string sha256 { get; set; }
            public string signatureStatus { get; set; }
            public string signer { get; set; }
        }

        public class WebShellRuleRequest
        {
            public string directory { get; set; }
            public string actor { get; set; }
        }

        public sealed class WebShellRuleDto : WebShellRuleRequest
        {
        }

        public class DeviceRuleRequest
        {
            public string deviceId { get; set; }
            public bool allowInsert { get; set; }
            public bool allowWrite { get; set; }
            public string actor { get; set; }
        }

        public sealed class DeviceRuleDto : DeviceRuleRequest
        {
        }

        public sealed class WebShellEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string severity { get; set; }
            public string operation { get; set; }
            public uint fileSize { get; set; }
            public string path { get; set; }
            public string extension { get; set; }
            public string sample { get; set; }
        }

        public sealed class HashProtectEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string operation { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public uint desiredAccess { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
        }

        public sealed class LateralDefenseEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string operation { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public uint desiredAccess { get; set; }
            public uint flags { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
        }

        public sealed class UserHookDefenseEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public ulong parentProcessId { get; set; }
            public string operation { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public uint flags { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
        }

        public class HashProtectPolicyRequest
        {
            public bool enabled { get; set; }
            public bool protectLsass { get; set; }
            public bool protectCredentialFiles { get; set; }
            public bool protectRegistryHives { get; set; }
            public bool protectRawExtents { get; set; }
            public string actor { get; set; }
        }

        public sealed class HashProtectPolicyDto : HashProtectPolicyRequest
        {
            public uint flags { get; set; }
        }

        public class LateralDefensePolicyRequest
        {
            public bool enabled { get; set; }
            public bool blockSmbExecutableCopy { get; set; }
            public bool blockIpcScheduledTasks { get; set; }
            public bool blockIpcServiceCreation { get; set; }
            public bool blockRemoteAdminTools { get; set; }
            public string actor { get; set; }
        }

        public sealed class LateralDefensePolicyDto : LateralDefensePolicyRequest
        {
            public uint flags { get; set; }
        }

        public class UserHookDefensePolicyRequest
        {
            public bool enabled { get; set; }
            public bool monitorEarlyProcesses { get; set; }
            public bool monitorImageLoads { get; set; }
            public bool requireSignedRuntime { get; set; }
            public bool blockUntrustedRuntime { get; set; }
            public bool auditOnly { get; set; }
            public bool monitorSystemProcesses { get; set; }
            public string actor { get; set; }
        }

        public sealed class UserHookDefensePolicyDto : UserHookDefensePolicyRequest
        {
            public uint flags { get; set; }
        }

        public class UsbCryptPolicyRequest
        {
            public bool enabled { get; set; }
            public string algorithm { get; set; }
            public long publicToolAreaBytes { get; set; }
            public bool allowClientProvisioning { get; set; }
            public bool requireHardwareAuthorization { get; set; }
            public string keyMaterialId { get; set; }
            public string actor { get; set; }
        }

        public sealed class UsbCryptPolicyDto : UsbCryptPolicyRequest
        {
        }

        public class DlpProtectionPolicyRequest
        {
            public bool enabled { get; set; }
            public bool protectClipboard { get; set; }
            public bool protectScreenshots { get; set; }
            public string clipboardMode { get; set; }
            public string screenshotMode { get; set; }
            public bool clearClipboardText { get; set; }
            public bool clearClipboardImages { get; set; }
            public bool clearClipboardFiles { get; set; }
            public bool clearScreenshotClipboard { get; set; }
            public bool blockPrintScreenHotkeys { get; set; }
            public string[] trustedProcessNames { get; set; }
            public string[] trustedProcessDirectories { get; set; }
            public string actor { get; set; }
        }

        public sealed class DlpProtectionPolicyDto : DlpProtectionPolicyRequest
        {
        }

        public sealed class OperationResult
        {
            public bool succeeded { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public string message { get; set; }
        }

        public sealed class BridgeException : Exception
        {
            public BridgeException(uint status, string message)
                : base(message)
            {
                Status = status;
            }

            public uint Status { get; private set; }
        }
    }
}
