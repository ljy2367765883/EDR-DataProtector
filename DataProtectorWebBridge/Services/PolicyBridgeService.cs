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
using System.Web.Script.Serialization;
using DataProtectorWebBridge.Native;

namespace DataProtectorWebBridge.Services
{
    internal sealed class PolicyBridgeService
    {
        private const uint SuccessStatus = 0;
        private const uint BufferTooSmallStatus = 0xE0010005;
        private const uint PathBufferChars = 2048;
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
        private const uint UserHookOperationRuntimeInjectionRequired = 7;
        private const uint UserHookOperationRuntimeInjectionQueued = 8;
        private const uint UserHookOperationRuntimeInjectionFailed = 9;
        private const uint UserHookOperationRuntimeInjectionSkipped = 10;
        private const uint UserHookOperationBehaviorProcessAccess = 11;
        private const uint UserHookOperationBehaviorThreadAccess = 12;
        private const uint UserHookOperationSensitiveImageReload = 13;
        private const uint UserHookOperationSensitiveImageAbnormalPath = 14;
        private const uint UserHookOperationBehaviorRemoteThreadCreate = 15;
        private const uint UserHookDefenseFlagEnabled = 0x00000001;
        private const uint UserHookDefenseFlagEarlyProcessInjection = 0x00000002;
        private const uint UserHookDefenseFlagImageLoadMonitor = 0x00000004;
        private const uint UserHookDefenseFlagRequireSignedRuntime = 0x00000008;
        private const uint UserHookDefenseFlagBlockUntrustedRuntime = 0x00000010;
        private const uint UserHookDefenseFlagAuditOnly = 0x00000020;
        private const uint UserHookDefenseFlagMonitorSystemProcesses = 0x00000040;
        private const uint UserHookDefenseFlagRuntimeApiBehavior = 0x00000080;
        private const uint UserHookDefenseFlagRuntimeMemoryScan = 0x00000100;
        private const uint UserHookDefenseFlagEtwTamperMonitor = 0x00000200;
        private const uint UserHookDefenseAllowedFlags =
            UserHookDefenseFlagEnabled |
            UserHookDefenseFlagEarlyProcessInjection |
            UserHookDefenseFlagImageLoadMonitor |
            UserHookDefenseFlagRequireSignedRuntime |
            UserHookDefenseFlagBlockUntrustedRuntime |
            UserHookDefenseFlagAuditOnly |
            UserHookDefenseFlagMonitorSystemProcesses |
            UserHookDefenseFlagRuntimeApiBehavior |
            UserHookDefenseFlagRuntimeMemoryScan |
            UserHookDefenseFlagEtwTamperMonitor;
        private const int MaxBehaviorChainRules = 64;
        private const int MaxBehaviorAtomsPerRule = 16;
        private const int MaxBehaviorRuleText = 256;
        private const int MessageBufferChars = 512;
        private const int MaxQueryAttempts = 4;

        private readonly AuditLog auditLog;
        private readonly object userHookCorrelatorLock = new object();
        private UserHookBehaviorCorrelator userHookCorrelator;
        private string userHookCorrelatorSignature;

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

        public FileHunterRuleDto[] QueryFileHunterRules()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryFileHunterRules(
                    new DataProtectorPolicyNative.NativeFileHunterRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeFileHunterRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeFileHunterRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryFileHunterRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        List<FileHunterRuleDto> rules = new List<FileHunterRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertFileHunterRule(nativeRules[index]));
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

            throw new BridgeException(BufferTooSmallStatus, "The driver file hunter rule set changed while querying. Please retry.");
        }

        public FileHunterDiagnosticsDto QueryFileHunterDiagnostics(DlpProtectionPolicyDto dlpPolicy)
        {
            OperationResult connection = Invoke(DataProtectorPolicyNative.DpPolicyCheckConnection);
            FileHunterRuleDto[] rules = new FileHunterRuleDto[0];
            string rulesStatus = "0x00000000";
            string rulesMessage = "Success.";

            try
            {
                rules = QueryFileHunterRules();
            }
            catch (BridgeException ex)
            {
                rulesStatus = "0x" + ex.Status.ToString("X8", CultureInfo.InvariantCulture);
                rulesMessage = ex.Message;
            }
            catch (Exception ex)
            {
                rulesStatus = "0x00000001";
                rulesMessage = ex.Message;
            }

            string[] safeFolders = dlpPolicy == null || dlpPolicy.safeFolders == null
                ? new string[0]
                : dlpPolicy.safeFolders.Where(item => !string.IsNullOrWhiteSpace(item)).Select(item => item.Trim()).ToArray();

            return new FileHunterDiagnosticsDto
            {
                connected = connection.succeeded,
                status = connection.statusText,
                message = connection.message,
                driverRuleStatus = rulesStatus,
                driverRuleMessage = rulesMessage,
                driverRuleCount = rules.Length,
                driverRules = rules,
                dlpSafeFolderCount = safeFolders.Length,
                dlpSafeFolders = safeFolders,
                auditPath = auditLog.FilePath,
                bridgePid = System.Diagnostics.Process.GetCurrentProcess().Id,
                machine = Environment.MachineName,
                note = "Diagnostics does not query the event queue, so successful read events are not drained here."
            };
        }

        public OperationResult AddFileHunterRule(FileHunterRuleRequest request)
        {
            FileHunterRuleDto normalized = NormalizeFileHunterRule(request);
            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyAddFileHunterRule(normalized.directory));
            auditLog.Append(normalized.actor, "policy.filehunter.add", normalized.directory, "safe-folder", result.succeeded, result.status, result.message);
            Console.WriteLine(
                DateTime.Now.ToString("s") +
                " File hunter add rule: directory=" +
                normalized.directory +
                "; status=" +
                result.statusText +
                "; success=" +
                result.succeeded +
                "; message=" +
                result.message);
            return result;
        }

        public OperationResult RemoveFileHunterRule(FileHunterRuleRequest request)
        {
            FileHunterRuleDto normalized = NormalizeFileHunterRule(request);
            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyRemoveFileHunterRule(normalized.directory));
            auditLog.Append(normalized.actor, "policy.filehunter.remove", normalized.directory, "safe-folder", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearFileHunterRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearFileHunterRules);
            auditLog.Append(actor, "policy.filehunter.clear", "*", "safe-folder", result.succeeded, result.status, result.message);
            Console.WriteLine(
                DateTime.Now.ToString("s") +
                " File hunter clear rules: actor=" +
                (actor ?? string.Empty) +
                "; status=" +
                result.statusText +
                "; success=" +
                result.succeeded +
                "; message=" +
                result.message);
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

        public FileHunterEventDto[] QueryFileHunterEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryFileHunterEvents(
                    new DataProtectorPolicyNative.NativeFileHunterEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " File hunter event sizing query failed: status=0x" + status.ToString("X8", CultureInfo.InvariantCulture) + "; message=" + ReadLastErrorMessage());
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                if (eventCount > 0)
                {
                    Console.WriteLine(DateTime.Now.ToString("s") + " File hunter event queue has " + eventCount.ToString(CultureInfo.InvariantCulture) + " pending event(s).");
                }

                DataProtectorPolicyNative.NativeFileHunterEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeFileHunterEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryFileHunterEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<FileHunterEventDto> events = new List<FileHunterEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertFileHunterEvent(nativeEvents[index]));
                        }

                        if (events.Count > 0)
                        {
                            Console.WriteLine(DateTime.Now.ToString("s") + " File hunter drained " + events.Count.ToString(CultureInfo.InvariantCulture) + " event(s) from driver.");
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        Console.Error.WriteLine(DateTime.Now.ToString("s") + " File hunter event drain failed: status=0x" + status.ToString("X8", CultureInfo.InvariantCulture) + "; message=" + ReadLastErrorMessage());
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

            throw new BridgeException(BufferTooSmallStatus, "The driver file hunter event queue changed while querying. Please retry.");
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
            return QueryUserHookDefensePolicy(usePreparedRuntimeFallback: true);
        }

        internal UserHookDefensePolicyDto QueryKernelUserHookDefensePolicy()
        {
            return QueryUserHookDefensePolicy(usePreparedRuntimeFallback: false);
        }

        private UserHookDefensePolicyDto QueryUserHookDefensePolicy(bool usePreparedRuntimeFallback)
        {
            DataProtectorPolicyNative.NativeUserHookDefensePolicy nativePolicy;
            uint status = DataProtectorPolicyNative.DpPolicyQueryUserHookDefensePolicy(out nativePolicy);
            if (status != SuccessStatus)
            {
                throw new BridgeException(status, ReadLastErrorMessage());
            }

            UserHookDefensePolicyDto policy = FromUserHookDefenseFlags(nativePolicy.Flags);
            policy.excludedProcessNames = NormalizeStringList(
                SplitUserHookPolicyList(Marshal.PtrToStringUni(nativePolicy.ExcludedProcessNames)),
                DefaultUserHookExcludedProcessNames());
            policy.excludedProcessDirectories = NormalizeStringList(
                SplitUserHookPolicyList(NormalizeDevicePathList(Marshal.PtrToStringUni(nativePolicy.ExcludedProcessDirectories))),
                DefaultUserHookExcludedProcessDirectories());
            policy.excludedProcessPaths = NormalizeStringList(
                SplitUserHookPolicyList(NormalizeDevicePathList(Marshal.PtrToStringUni(nativePolicy.ExcludedProcessPaths))),
                DefaultUserHookExcludedProcessPaths());
            policy.trustedSignerSubjects = NormalizeStringList(
                SplitUserHookPolicyList(Marshal.PtrToStringUni(nativePolicy.TrustedSignerSubjects)),
                DefaultUserHookTrustedSignerSubjects());
            string runtimePath = Marshal.PtrToStringUni(nativePolicy.RuntimeDllPath);
            policy.runtimePath = usePreparedRuntimeFallback && string.IsNullOrWhiteSpace(runtimePath)
                ? GetPreparedUserHookRuntimePath()
                : (runtimePath ?? string.Empty);
            return policy;
        }

        public OperationResult SetUserHookDefensePolicy(UserHookDefensePolicyRequest request)
        {
            UserHookDefensePolicyDto normalized = NormalizeUserHookDefensePolicy(request);
            OperationResult result = Invoke(() =>
            {
                IntPtr excludedNames = IntPtr.Zero;
                IntPtr excludedDirectories = IntPtr.Zero;
                IntPtr excludedPaths = IntPtr.Zero;
                IntPtr trustedSigners = IntPtr.Zero;
                IntPtr runtimeDllPath = IntPtr.Zero;

                try
                {
                    string runtimePath = PrepareUserHookRuntimeDll();
                    excludedNames = Marshal.StringToHGlobalUni(string.Join("\n", normalized.excludedProcessNames ?? new string[0]));
                    excludedDirectories = Marshal.StringToHGlobalUni(string.Join("\n", ConvertUserHookPathsForKernel(normalized.excludedProcessDirectories ?? new string[0])));
                    excludedPaths = Marshal.StringToHGlobalUni(string.Join("\n", ConvertUserHookPathsForKernel(normalized.excludedProcessPaths ?? new string[0])));
                    trustedSigners = Marshal.StringToHGlobalUni(string.Join("\n", normalized.trustedSignerSubjects ?? new string[0]));
                    runtimeDllPath = Marshal.StringToHGlobalUni(runtimePath);
                    DataProtectorPolicyNative.NativeUserHookDefensePolicy nativePolicy = new DataProtectorPolicyNative.NativeUserHookDefensePolicy
                    {
                        Flags = ToUserHookDefenseFlags(normalized),
                        ExcludedProcessNames = excludedNames,
                        ExcludedProcessDirectories = excludedDirectories,
                        ExcludedProcessPaths = excludedPaths,
                        TrustedSignerSubjects = trustedSigners,
                        RuntimeDllPath = runtimeDllPath
                    };

                    return DataProtectorPolicyNative.DpPolicySetUserHookDefensePolicy(ref nativePolicy);
                }
                finally
                {
                    if (excludedNames != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(excludedNames);
                    }

                    if (excludedDirectories != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(excludedDirectories);
                    }

                    if (excludedPaths != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(excludedPaths);
                    }

                    if (trustedSigners != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(trustedSigners);
                    }

                    if (runtimeDllPath != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(runtimeDllPath);
                    }
                }
            });

            if (result.succeeded)
            {
                WriteUserHookRuntimePolicy(normalized);
            }

            auditLog.Append(
                normalized.actor,
                "policy.userhook.update",
                "process-threat-insight",
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
            records.AddRange(TryDrainSecurityAuditSource("filehunter", DrainFileHunterAuditRecords));
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

        public AuditLog.AuditRecord[] DrainFileHunterAuditRecords()
        {
            FileHunterEventDto[] events = QueryFileHunterEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (FileHunterEventDto item in events)
            {
                string process = string.IsNullOrWhiteSpace(item.processImage) ? "unknown" : item.processImage;
                string readKind = DescribeFileHunterReadFlags(item.flags);
                string message =
                    "process=" + process +
                    ";pid=" + item.processId.ToString(CultureInfo.InvariantCulture) +
                    ";object=file;path=" + item.path +
                    ";bytes=" + item.bytesRead.ToString(CultureInfo.InvariantCulture) +
                    ";offset=" + item.byteOffset.ToString(CultureInfo.InvariantCulture) +
                    ";readKind=" + readKind +
                    ";flags=0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture) +
                    ";disposition=observed;severity=warning";

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "file-hunter-sensor",
                    Action = "dlp.file.read",
                    Target = item.path,
                    Extension = process,
                    Succeeded = true,
                    Status = item.statusText,
                    Message = message,
                    SourceHost = Environment.MachineName,
                    SourceProcess = process,
                    SourcePid = item.processId.ToString(CultureInfo.InvariantCulture),
                    ObjectType = "file",
                    ObjectName = item.path,
                    ObjectFormat = "bytes=" + item.bytesRead.ToString(CultureInfo.InvariantCulture) +
                        ";offset=" + item.byteOffset.ToString(CultureInfo.InvariantCulture) +
                        ";readKind=" + readKind +
                        ";flags=0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture),
                    PolicyName = "file-thief-hunter",
                    Disposition = "observed",
                    Severity = "warning",
                    EventDetails = message
                };

                records.Add(record);
                TryAppendAudit(record);
                Console.WriteLine(
                    DateTime.Now.ToString("s") +
                    " File hunter audit appended: pid=" +
                    item.processId.ToString(CultureInfo.InvariantCulture) +
                    "; process=" +
                    process +
                    "; readKind=" +
                    readKind +
                    "; bytes=" +
                    item.bytesRead.ToString(CultureInfo.InvariantCulture) +
                    "; path=" +
                    item.path);
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
            return DrainUserHookDefenseAuditRecords(null);
        }

        public AuditLog.AuditRecord[] DrainUserHookDefenseAuditRecords(UserHookDefensePolicyDto policy)
        {
            UserHookDefenseEventDto[] events = QueryUserHookDefenseEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();
            UserHookBehaviorCorrelator correlator = GetUserHookBehaviorCorrelator(policy);

            foreach (UserHookDefenseEventDto item in events)
            {
                string message = BuildUserHookAuditMessage(item);
                bool coverageEvent = IsUserHookCoverageOperation(item.operation);
                bool successLikeStatus = item.status == SuccessStatus || item.status == 0x00000103;

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = coverageEvent ? "process-protection" : "user-hook-defense-sensor",
                    Action = coverageEvent ? "userhook.health." + item.operation : "userhook." + item.operation,
                    Target = item.target,
                    Extension = item.processImage,
                    Succeeded = coverageEvent || successLikeStatus,
                    Status = item.statusText,
                    Message = message,
                    SourceHost = Environment.MachineName,
                    SourceProcess = item.processImage,
                    SourcePid = item.processId.ToString(CultureInfo.InvariantCulture),
                    TargetProcess = ExtractKernelTargetProcess(item.target),
                    TargetPid = ExtractKernelDecimalField(item.target, "targetPid="),
                    ObjectType = coverageEvent ? "sensor-health" : "process-behavior",
                    ObjectName = FirstNonEmpty(ExtractKernelTargetProcess(item.target), item.target),
                    ObjectFormat = "flags=0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture),
                    PolicyName = coverageEvent ? "process-protection-coverage" : "process-threat-insight",
                    Disposition = coverageEvent || successLikeStatus ? "observed" : "blocked",
                    Severity = coverageEvent ? "warning" : (successLikeStatus ? "info" : "critical"),
                    EventDetails = message
                };

                AddUserHookBehaviorMatches(records, correlator.Observe(record));
                if (ShouldUploadAtomicUserHookRecord(record))
                {
                    records.Add(record);
                    TryAppendAudit(record);
                }
            }

            foreach (AuditLog.AuditRecord record in DrainUserHookRuntimeAuditRecords(policy))
            {
                AddUserHookBehaviorMatches(records, correlator.Observe(record));
                if (ShouldUploadAtomicUserHookRecord(record))
                {
                    records.Add(record);
                    TryAppendAudit(record);
                }
            }

            return records.ToArray();
        }

        private UserHookBehaviorCorrelator GetUserHookBehaviorCorrelator(UserHookDefensePolicyDto policy)
        {
            UserHookDefensePolicyDto normalized = CloneUserHookDefensePolicy(policy);
            string signature = BuildUserHookBehaviorPolicySignature(normalized);
            lock (userHookCorrelatorLock)
            {
                if (userHookCorrelator == null ||
                    !string.Equals(userHookCorrelatorSignature, signature, StringComparison.Ordinal))
                {
                    userHookCorrelator = new UserHookBehaviorCorrelator(normalized);
                    userHookCorrelatorSignature = signature;
                }

                return userHookCorrelator;
            }
        }

        private static string BuildUserHookBehaviorPolicySignature(UserHookDefensePolicyDto policy)
        {
            JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
            return serializer.Serialize(NormalizeUserHookBehaviorRules(policy == null ? null : policy.behaviorRules));
        }

        private void AddUserHookBehaviorMatches(List<AuditLog.AuditRecord> records, AuditLog.AuditRecord[] matches)
        {
            if (matches == null || matches.Length == 0)
            {
                return;
            }

            foreach (AuditLog.AuditRecord match in matches)
            {
                if (match == null)
                {
                    continue;
                }

                records.Add(match);
                TryAppendAudit(match);
            }
        }

        private static bool ShouldUploadAtomicUserHookRecord(AuditLog.AuditRecord record)
        {
            if (record == null)
            {
                return false;
            }

            string action = record.Action ?? string.Empty;
            string disposition = record.Disposition ?? string.Empty;
            string status = record.Status ?? string.Empty;

            if (IsUserHookCoverageAction(action))
            {
                return false;
            }

            if (action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (action.StartsWith("userhook.runtime.drain.failed", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.parse.failed", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.policy-signer-untrusted", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.policy-signer-excluded", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (action.StartsWith("userhook.blocked.", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".blocked.", StringComparison.OrdinalIgnoreCase) >= 0 ||
                string.Equals(disposition, "blocked", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(status, "0xC0000022", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static string BuildUserHookAuditMessage(UserHookDefenseEventDto item)
        {
            if (item != null && IsUserHookCoverageOperation(item.operation))
            {
                string coverage = "User hook coverage state: " + item.operation + " for PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
                if (!string.IsNullOrWhiteSpace(item.processImage))
                {
                    coverage += " Process: " + item.processImage + ".";
                }

                coverage += " This records protection coverage, not a confirmed malicious behavior.";
                if (!string.IsNullOrWhiteSpace(item.target))
                {
                    coverage += " Target: " + item.target + ".";
                }

                coverage += " Flags: 0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture) + ".";
                return coverage;
            }

            string message = "Process threat insight " + item.operation + " for PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";
            if (!string.IsNullOrWhiteSpace(item.processImage))
            {
                message += " Process: " + item.processImage + ".";
            }

            message += " ParentPID: " + item.parentProcessId.ToString(CultureInfo.InvariantCulture) + ".";
            string targetPid = ExtractKernelDecimalField(item.target, "targetPid=");
            if (!string.IsNullOrWhiteSpace(targetPid))
            {
                message += " TargetPID: " + targetPid + ".";
            }

            string targetProcess = ExtractKernelTargetProcess(item.target);
            if (!string.IsNullOrWhiteSpace(targetProcess))
            {
                message += " TargetProcess: " + targetProcess + ".";
            }

            message += " Flags: 0x" + item.flags.ToString("X8", CultureInfo.InvariantCulture) + ".";
            return message;
        }

        private static string ExtractKernelTargetProcess(string target)
        {
            return ExtractKernelTextField(target, "target=");
        }

        private static string ExtractKernelDecimalField(string text, string prefix)
        {
            string value = ExtractKernelTextField(text, prefix);
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            long parsed;
            return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed)
                ? parsed.ToString(CultureInfo.InvariantCulture)
                : value;
        }

        private static string ExtractKernelTextField(string text, string prefix)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prefix))
            {
                return string.Empty;
            }

            int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return string.Empty;
            }

            index += prefix.Length;
            int end = text.IndexOf(' ', index);
            if (end < 0)
            {
                end = text.Length;
            }

            return text.Substring(index, end - index).Trim();
        }

        private AuditLog.AuditRecord[] DrainUserHookRuntimeAuditRecords(UserHookDefensePolicyDto policy)
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string path = Path.Combine(dataRoot, "DataProtector", "UserHookRuntimeEvents.jsonl");
            string[] lines;
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();
            JavaScriptSerializer serializer = JsonResponse.CreateSerializer();

            if (!File.Exists(path))
            {
                return records.ToArray();
            }

            try
            {
                lines = File.ReadAllLines(path, Encoding.UTF8)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Take(2048)
                    .ToArray();
                File.WriteAllText(path, string.Empty, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                return new[]
                {
                    new AuditLog.AuditRecord
                    {
                        TimestampUtc = DateTime.UtcNow.ToString("o"),
                        Host = Environment.MachineName,
                        Actor = "user-hook-runtime",
                        Action = "userhook.runtime.drain.failed",
                        Target = path,
                        Extension = string.Empty,
                        Succeeded = false,
                        Status = "0x00000001",
                        Message = ex.Message
                    }
                };
            }

            foreach (string line in lines)
            {
                try
                {
                    UserHookRuntimeEvent runtimeEvent = serializer.Deserialize<UserHookRuntimeEvent>(line);
                    if (runtimeEvent == null)
                    {
                        continue;
                    }

                    bool blocked = runtimeEvent.blocked ||
                        (runtimeEvent.action ?? string.Empty).IndexOf(".blocked.", StringComparison.OrdinalIgnoreCase) >= 0;
                    AuditLog.AuditRecord record = new AuditLog.AuditRecord
                    {
                        TimestampUtc = string.IsNullOrWhiteSpace(runtimeEvent.timestampUtc) ? DateTime.UtcNow.ToString("o") : runtimeEvent.timestampUtc,
                        Host = string.IsNullOrWhiteSpace(runtimeEvent.host) ? Environment.MachineName : runtimeEvent.host,
                        Actor = "user-hook-runtime",
                        Action = runtimeEvent.action ?? "userhook.runtime.event",
                        Target = runtimeEvent.target ?? string.Empty,
                        Extension = runtimeEvent.processImage ?? string.Empty,
                        Succeeded = !blocked,
                        Status = string.IsNullOrWhiteSpace(runtimeEvent.status) ? "0x00000000" : runtimeEvent.status,
                        Message = BuildUserHookRuntimeMessage(runtimeEvent),
                        SourceHost = string.IsNullOrWhiteSpace(runtimeEvent.host) ? Environment.MachineName : runtimeEvent.host,
                        SourceProcess = runtimeEvent.processImage ?? string.Empty,
                        SourcePid = runtimeEvent.pid.ToString(CultureInfo.InvariantCulture),
                        TargetPid = runtimeEvent.targetPid == 0 ? string.Empty : runtimeEvent.targetPid.ToString(CultureInfo.InvariantCulture),
                        TargetProcess = runtimeEvent.target ?? string.Empty,
                        ObjectType = FirstNonEmpty(runtimeEvent.category, "process-behavior"),
                        ObjectName = FirstNonEmpty(runtimeEvent.target, runtimeEvent.api, runtimeEvent.action),
                        ObjectFormat = BuildUserHookRuntimeObjectFormat(runtimeEvent),
                        PolicyName = "process-threat-insight",
                        Disposition = blocked ? "blocked" : "observed",
                        Severity = ResolveUserHookRuntimeSeverity(runtimeEvent, blocked),
                        EventDetails = BuildUserHookRuntimeMessage(runtimeEvent)
                    };

                    records.Add(record);
                }
                catch
                {
                    AuditLog.AuditRecord record = new AuditLog.AuditRecord
                    {
                        TimestampUtc = DateTime.UtcNow.ToString("o"),
                        Host = Environment.MachineName,
                        Actor = "user-hook-runtime",
                        Action = "userhook.runtime.parse.failed",
                        Target = "UserHookRuntimeEvents.jsonl",
                        Extension = string.Empty,
                        Succeeded = false,
                        Status = "0x00000001",
                        Message = line
                    };
                    records.Add(record);
                }
            }

            return records.ToArray();
        }

        private static string BuildUserHookRuntimeMessage(UserHookRuntimeEvent runtimeEvent)
        {
            string message = "Process threat runtime event from PID " + runtimeEvent.pid.ToString(CultureInfo.InvariantCulture) + ".";
            message += " Category: " + (runtimeEvent.category ?? "behavior") + ".";
            if (!string.IsNullOrWhiteSpace(runtimeEvent.api))
            {
                message += " API: " + runtimeEvent.api + ".";
            }

            if (runtimeEvent.targetPid != 0)
            {
                message += " TargetPID: " + runtimeEvent.targetPid.ToString(CultureInfo.InvariantCulture) + ".";
            }

            if (!string.IsNullOrWhiteSpace(runtimeEvent.commandLine))
            {
                message += " Command: " + runtimeEvent.commandLine + ".";
            }

            if (runtimeEvent.size != 0)
            {
                message += " Size: " + runtimeEvent.size.ToString(CultureInfo.InvariantCulture) + ".";
            }

            return message;
        }

        private static bool IsUserHookCoverageOperation(string operation)
        {
            if (string.IsNullOrWhiteSpace(operation))
            {
                return false;
            }

            return string.Equals(operation, "runtime-required", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-missing", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-required", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-queued", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-skipped", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsUserHookCoverageAction(string action)
        {
            if (string.IsNullOrWhiteSpace(action))
            {
                return false;
            }

            if (action.StartsWith("userhook.health.", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return IsUserHookCoverageOperation(action.Substring("userhook.".Length));
        }

        private static string BuildUserHookRuntimeObjectFormat(UserHookRuntimeEvent runtimeEvent)
        {
            List<string> parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(runtimeEvent.api))
            {
                parts.Add("api=" + runtimeEvent.api);
            }

            if (runtimeEvent.size != 0)
            {
                parts.Add("size=" + runtimeEvent.size.ToString(CultureInfo.InvariantCulture));
            }

            if (runtimeEvent.flags != 0)
            {
                parts.Add("flags=0x" + runtimeEvent.flags.ToString("X8", CultureInfo.InvariantCulture));
            }

            return string.Join(";", parts.ToArray());
        }

        private static string ResolveUserHookRuntimeSeverity(UserHookRuntimeEvent runtimeEvent, bool blocked)
        {
            string action = runtimeEvent == null ? string.Empty : (runtimeEvent.action ?? string.Empty);
            string category = runtimeEvent == null ? string.Empty : (runtimeEvent.category ?? string.Empty);

            if (blocked ||
                action.IndexOf(".blocked.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "critical";
            }

            if (
                action.IndexOf("unhook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                action.IndexOf("syscall-bypass", StringComparison.OrdinalIgnoreCase) >= 0 ||
                action.IndexOf("manual-map", StringComparison.OrdinalIgnoreCase) >= 0 ||
                category.IndexOf("injection", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "warning";
            }

            if (action.IndexOf("memory-private-executable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                action.IndexOf("etw", StringComparison.OrdinalIgnoreCase) >= 0 ||
                category.IndexOf("memory", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "warning";
            }

            return "info";
        }

        private static string FirstNonEmpty(params string[] values)
        {
            if (values == null)
            {
                return string.Empty;
            }

            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
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

        private static FileHunterRuleDto ConvertFileHunterRule(DataProtectorPolicyNative.NativeFileHunterRule nativeRule)
        {
            return new FileHunterRuleDto
            {
                directory = NormalizeDevicePath(Marshal.PtrToStringUni(nativeRule.Directory) ?? string.Empty)
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

        private static FileHunterEventDto ConvertFileHunterEvent(DataProtectorPolicyNative.NativeFileHunterEvent nativeEvent)
        {
            return new FileHunterEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                bytesRead = nativeEvent.BytesRead,
                byteOffset = nativeEvent.ByteOffset,
                status = nativeEvent.Status,
                statusText = "0x" + nativeEvent.Status.ToString("X8", CultureInfo.InvariantCulture),
                flags = nativeEvent.Flags,
                path = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.Path) ?? string.Empty),
                processImage = NormalizeDevicePath(Marshal.PtrToStringUni(nativeEvent.ProcessImage) ?? string.Empty)
            };
        }

        private static string DescribeFileHunterReadFlags(uint flags)
        {
            List<string> values = new List<string>();
            if ((flags & 0x00000001u) != 0)
            {
                values.Add("paging-read");
            }

            if ((flags & 0x00000002u) != 0)
            {
                values.Add("read-open");
            }

            if ((flags & 0x00000004u) != 0)
            {
                values.Add("section-map");
            }

            if ((flags & 0x00000008u) != 0)
            {
                values.Add("image-section");
            }

            if ((flags & 0x00000010u) != 0)
            {
                values.Add("execute-access");
            }

            return values.Count == 0 ? "read" : string.Join("+", values.ToArray());
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
                monitorEarlyProcesses = (flags & UserHookDefenseFlagEarlyProcessInjection) != 0,
                monitorImageLoads = (flags & UserHookDefenseFlagImageLoadMonitor) != 0,
                requireSignedRuntime = (flags & UserHookDefenseFlagRequireSignedRuntime) != 0,
                blockUntrustedRuntime = (flags & UserHookDefenseFlagBlockUntrustedRuntime) != 0,
                auditOnly = (flags & UserHookDefenseFlagAuditOnly) != 0,
                monitorSystemProcesses = (flags & UserHookDefenseFlagMonitorSystemProcesses) != 0,
                monitorRuntimeApiBehavior = (flags & UserHookDefenseFlagRuntimeApiBehavior) != 0,
                scanExecutableMemory = (flags & UserHookDefenseFlagRuntimeMemoryScan) != 0,
                monitorEtwTamper = (flags & UserHookDefenseFlagEtwTamperMonitor) != 0,
                excludedProcessNames = DefaultUserHookExcludedProcessNames(),
                excludedProcessDirectories = DefaultUserHookExcludedProcessDirectories(),
                excludedProcessPaths = DefaultUserHookExcludedProcessPaths(),
                trustedSignerSubjects = DefaultUserHookTrustedSignerSubjects(),
                runtimePath = GetPreparedUserHookRuntimePath(),
                behaviorRules = DefaultUserHookBehaviorRules(),
                flags = flags & UserHookDefenseAllowedFlags
            };
        }

        internal static uint ToUserHookDefenseFlags(UserHookDefensePolicyDto policy)
        {
            if (policy == null)
            {
                return UserHookDefenseFlagEnabled |
                       UserHookDefenseFlagEarlyProcessInjection |
                       UserHookDefenseFlagImageLoadMonitor |
                       UserHookDefenseFlagRequireSignedRuntime |
                       UserHookDefenseFlagRuntimeApiBehavior |
                       UserHookDefenseFlagRuntimeMemoryScan |
                       UserHookDefenseFlagEtwTamperMonitor |
                       UserHookDefenseFlagAuditOnly;
            }

            uint flags = 0;
            if (policy.enabled)
            {
                flags |= UserHookDefenseFlagEnabled;
                flags |= UserHookDefenseFlagEarlyProcessInjection;
            }
            else if (policy.monitorEarlyProcesses)
            {
                flags |= UserHookDefenseFlagEarlyProcessInjection;
            }
            if (policy.monitorImageLoads) flags |= UserHookDefenseFlagImageLoadMonitor;
            if (policy.requireSignedRuntime) flags |= UserHookDefenseFlagRequireSignedRuntime;
            if (policy.blockUntrustedRuntime) flags |= UserHookDefenseFlagBlockUntrustedRuntime;
            if (policy.auditOnly) flags |= UserHookDefenseFlagAuditOnly;
            if (policy.monitorSystemProcesses) flags |= UserHookDefenseFlagMonitorSystemProcesses;
            if (policy.monitorRuntimeApiBehavior != false) flags |= UserHookDefenseFlagRuntimeApiBehavior;
            if (policy.scanExecutableMemory != false) flags |= UserHookDefenseFlagRuntimeMemoryScan;
            if (policy.monitorEtwTamper != false) flags |= UserHookDefenseFlagEtwTamperMonitor;
            return flags & UserHookDefenseAllowedFlags;
        }

        internal static UserHookDefensePolicyDto DefaultUserHookDefensePolicy()
        {
            return FromUserHookDefenseFlags(
                UserHookDefenseFlagEnabled |
                UserHookDefenseFlagEarlyProcessInjection |
                UserHookDefenseFlagImageLoadMonitor |
                UserHookDefenseFlagRequireSignedRuntime |
                UserHookDefenseFlagRuntimeApiBehavior |
                UserHookDefenseFlagRuntimeMemoryScan |
                UserHookDefenseFlagEtwTamperMonitor |
                UserHookDefenseFlagAuditOnly);
        }

        internal static UserHookDefensePolicyDto CloneUserHookDefensePolicy(UserHookDefensePolicyDto policy)
        {
            UserHookDefensePolicyDto source = policy ?? DefaultUserHookDefensePolicy();
            return new UserHookDefensePolicyDto
            {
                enabled = source.enabled,
                monitorEarlyProcesses = source.enabled || source.monitorEarlyProcesses,
                monitorImageLoads = source.monitorImageLoads,
                requireSignedRuntime = source.requireSignedRuntime,
                blockUntrustedRuntime = source.blockUntrustedRuntime,
                auditOnly = source.auditOnly,
                monitorSystemProcesses = source.monitorSystemProcesses,
                monitorRuntimeApiBehavior = source.monitorRuntimeApiBehavior != false,
                scanExecutableMemory = source.scanExecutableMemory != false,
                monitorEtwTamper = source.monitorEtwTamper != false,
                excludedProcessNames = NormalizeStringList(source.excludedProcessNames, DefaultUserHookExcludedProcessNames()),
                excludedProcessDirectories = NormalizeStringList(source.excludedProcessDirectories, DefaultUserHookExcludedProcessDirectories()),
                excludedProcessPaths = NormalizeStringList(source.excludedProcessPaths, DefaultUserHookExcludedProcessPaths()),
                trustedSignerSubjects = NormalizeStringList(source.trustedSignerSubjects, DefaultUserHookTrustedSignerSubjects()),
                runtimePath = string.IsNullOrWhiteSpace(source.runtimePath) ? GetPreparedUserHookRuntimePath() : source.runtimePath,
                behaviorRules = NormalizeUserHookBehaviorRules(source.behaviorRules),
                flags = ToUserHookDefenseFlags(source),
                actor = source.actor
            };
        }

        internal static UserHookDefensePolicyDto NormalizeUserHookDefensePolicy(UserHookDefensePolicyRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Process threat insight policy body is required.");
            }

            UserHookDefensePolicyDto normalized = new UserHookDefensePolicyDto
            {
                enabled = request.enabled,
                monitorEarlyProcesses = request.enabled || request.monitorEarlyProcesses,
                monitorImageLoads = request.monitorImageLoads,
                requireSignedRuntime = request.requireSignedRuntime,
                blockUntrustedRuntime = request.blockUntrustedRuntime,
                auditOnly = request.auditOnly,
                monitorSystemProcesses = request.monitorSystemProcesses,
                monitorRuntimeApiBehavior = request.monitorRuntimeApiBehavior != false,
                scanExecutableMemory = request.scanExecutableMemory != false,
                monitorEtwTamper = request.monitorEtwTamper != false,
                excludedProcessNames = NormalizeStringList(request.excludedProcessNames, DefaultUserHookExcludedProcessNames()),
                excludedProcessDirectories = NormalizeStringList(request.excludedProcessDirectories, DefaultUserHookExcludedProcessDirectories()),
                excludedProcessPaths = NormalizeStringList(request.excludedProcessPaths, DefaultUserHookExcludedProcessPaths()),
                trustedSignerSubjects = NormalizeStringList(request.trustedSignerSubjects, DefaultUserHookTrustedSignerSubjects()),
                runtimePath = GetPreparedUserHookRuntimePath(),
                behaviorRules = NormalizeUserHookBehaviorRules(request.behaviorRules),
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
                "enabled={0};earlyInject={1};imageLoad={2};signedRuntime={3};blockUntrusted={4};auditOnly={5};system={6};runtimeApi={7};memoryScan={8};etwTamper={9};rules={10};excludedNames={11};excludedDirs={12};excludedPaths={13};trustedSigners={14};flags=0x{15:X8}",
                normalized.enabled,
                normalized.monitorEarlyProcesses,
                normalized.monitorImageLoads,
                normalized.requireSignedRuntime,
                normalized.blockUntrustedRuntime,
                normalized.auditOnly,
                normalized.monitorSystemProcesses,
                normalized.monitorRuntimeApiBehavior,
                normalized.scanExecutableMemory,
                normalized.monitorEtwTamper,
                normalized.behaviorRules == null ? 0 : normalized.behaviorRules.Count(rule => rule != null && rule.enabled),
                normalized.excludedProcessNames.Length,
                normalized.excludedProcessDirectories.Length,
                normalized.excludedProcessPaths.Length,
                normalized.trustedSignerSubjects.Length,
                normalized.flags);
        }

        private static string[] DefaultUserHookExcludedProcessNames()
        {
            return new[]
            {
                "DataProtectorWebBridge.exe",
                "DataProtectorAgentClient.exe",
                "DataProtectorAdmin.exe",
                "DataProtectorUsbTool.exe",
                "explorer.exe",
                "dwm.exe",
                "SearchIndexer.exe",
                "RuntimeBroker.exe",
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "WINWORD.EXE",
                "EXCEL.EXE",
                "POWERPNT.EXE",
                "OUTLOOK.EXE",
                "Teams.exe",
                "WeChat.exe",
                "QQ.exe",
                "DingTalk.exe",
                "Feishu.exe"
            };
        }

        private static string[] DefaultUserHookExcludedProcessDirectories()
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            return NormalizeStringList(
                new[]
                {
                    Path.Combine(windows, "System32"),
                    Path.Combine(windows, "SysWOW64"),
                    Path.Combine(windows, "WinSxS"),
                    Path.Combine(programFiles, "DataProtector"),
                    Path.Combine(programFilesX86, "DataProtector")
                },
                new string[0]);
        }

        private static string[] DefaultUserHookExcludedProcessPaths()
        {
            return new string[0];
        }

        private static string[] DefaultUserHookTrustedSignerSubjects()
        {
            return new string[0];
        }

        internal static UserHookBehaviorRule[] DefaultUserHookBehaviorRules()
        {
            return new[]
            {
                NewBehaviorRule(
                    "dp.behavior.injection-chain",
                    "跨进程注入链",
                    new[] { "userhook.behavior-process-access", "userhook.behavior-thread-access", "userhook.observed.remote-executable-memory", "userhook.observed.nt-allocate-executable-memory", "userhook.observed.write-process-memory", "userhook.observed.nt-write-virtual-memory", "userhook.behavior-remote-thread-create", "userhook.observed.create-remote-thread", "userhook.observed.nt-create-thread-ex" },
                    null,
                    90,
                    4,
                    100,
                    "critical",
                    "malicious",
                    "Defense Evasion / Privilege Escalation",
                    "T1055 Process Injection",
                    "OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread 类行为在同一进程窗口内连续出现，按注入链判定。"),
                NewBehaviorRule(
                    "dp.behavior.remote-dll-injection",
                    "远程 DLL 注入链",
                    new[] { "userhook.behavior-process-access", "userhook.observed.remote-dll-path-write", "userhook.observed.write-process-memory", "userhook.observed.nt-write-virtual-memory", "userhook.observed.create-remote-thread", "userhook.observed.create-remote-thread-ex", "userhook.observed.nt-create-thread-ex", "userhook.behavior-remote-thread-create" },
                    new[] { "userhook.observed.remote-executable-memory", "userhook.observed.nt-allocate-executable-memory" },
                    90,
                    4,
                    100,
                    "critical",
                    "malicious",
                    "Defense Evasion / Execution",
                    "T1055.001 Dynamic-link library injection",
                    "打开目标进程、写入 DLL 路径并通过远程线程或 NtCreateThreadEx 触发加载，按 DLL 注入闭环判定。"),
                NewBehaviorRule(
                    "dp.behavior.shellcode-injection",
                    "远程 Shellcode 注入链",
                    new[] { "userhook.behavior-process-access", "userhook.observed.remote-executable-memory", "userhook.observed.nt-allocate-executable-memory", "userhook.observed.remote-executable-protect", "userhook.observed.nt-protect-executable-memory", "userhook.observed.write-process-memory", "userhook.observed.nt-write-virtual-memory", "userhook.observed.remote-pe-image-write", "userhook.observed.create-remote-thread", "userhook.observed.nt-create-thread-ex", "userhook.behavior-remote-thread-create" },
                    null,
                    90,
                    4,
                    100,
                    "critical",
                    "malicious",
                    "Defense Evasion / Execution",
                    "T1055 Process Injection",
                    "目标进程内出现远程可执行内存、远程写入和远程执行，按 Shellcode/PE 载荷注入闭环判定。"),
                NewBehaviorRule(
                    "dp.behavior.process-hollowing",
                    "进程空洞化链",
                    new[] { "userhook.observed.suspended-process-create", "userhook.observed.nt-unmap-view", "userhook.observed.write-process-memory", "userhook.observed.set-thread-context", "userhook.observed.resume-thread" },
                    null,
                    120,
                    4,
                    95,
                    "critical",
                    "malicious",
                    "Defense Evasion",
                    "T1055.012 Process Hollowing",
                    "挂起创建、卸载映像、写入内存、改线程上下文、恢复线程组成典型空洞化行为。"),
                NewBehaviorRule(
                    "dp.behavior.apc-injection",
                    "APC 注入链",
                    new[] { "userhook.observed.queue-user-apc" },
                    new[] { "userhook.observed.write-process-memory", "userhook.observed.nt-write-virtual-memory", "userhook.observed.remote-executable-memory", "userhook.observed.nt-allocate-executable-memory" },
                    90,
                    2,
                    80,
                    "critical",
                    "malicious",
                    "Defense Evasion / Execution",
                    "T1055.004 APC Injection",
                    "跨进程写入或分配可执行内存后排队 APC，属于常见无远程线程注入变体。"),
                NewBehaviorRule(
                    "dp.behavior.thread-hijack",
                    "线程劫持注入链",
                    new[] { "userhook.behavior-thread-access", "userhook.observed.write-process-memory", "userhook.observed.nt-write-virtual-memory", "userhook.observed.remote-executable-memory", "userhook.observed.nt-allocate-executable-memory", "userhook.observed.set-thread-context", "userhook.observed.resume-thread" },
                    null,
                    120,
                    4,
                    95,
                    "critical",
                    "malicious",
                    "Defense Evasion / Execution",
                    "T1055.003 Thread Execution Hijacking",
                    "获取远程线程权限后写入载荷、修改线程上下文并恢复线程，按线程劫持注入判定。"),
                NewBehaviorRule(
                    "dp.behavior.ntdll-reload-bypass",
                    "NTDLL 重载与 Hook 绕过链",
                    new[] { "userhook.sensitive-image-reload", "userhook.sensitive-image-abnormal-path", "userhook.runtime.unhook-detected", "userhook.runtime.hook-overwrite-detected", "userhook.runtime.syscall-bypass-risk", "userhook.runtime.memory-private-syscall-stub" },
                    null,
                    180,
                    2,
                    90,
                    "critical",
                    "suspicious",
                    "Defense Evasion",
                    "T1562 Impair Defenses / T1106 Native API",
                    "检测 NTDLL 等敏感模块重载、异常路径加载、Hook 被还原或私有 syscall stub，用于识别绕过用户态 Hook 的行为链。"),
                NewBehaviorRule(
                    "dp.behavior.hook-bypass",
                    "Hook 绕过与直接系统调用",
                    new[] { "userhook.runtime.unhook-detected", "userhook.runtime.hook-overwrite-detected", "userhook.runtime.syscall-bypass-risk", "userhook.runtime.memory-private-syscall-stub" },
                    null,
                    120,
                    1,
                    90,
                    "critical",
                    "suspicious",
                    "Defense Evasion",
                    "T1562 Impair Defenses",
                    "检测到 hook 被还原/覆盖、私有 syscall stub 或直接系统调用迹象。"),
                NewBehaviorRule(
                    "dp.behavior.telemetry-impairment",
                    "遥测削弱与 ETW Patch",
                    new[] { "userhook.runtime.etw-prepatched-detected", "userhook.runtime.etw-return-patch-detected", "userhook.runtime.etw-jump-patch-detected" },
                    null,
                    120,
                    1,
                    95,
                    "critical",
                    "suspicious",
                    "Defense Evasion",
                    "T1562.002 Impair Defenses: Disable Windows Event Logging",
                    "检测 ETW EventWrite/EtwEventWrite 等遥测入口被 ret/跳转补丁、预补丁或异常注销，防止恶意程序通过 patch ETW 逃避审计。"),
                NewBehaviorRule(
                    "dp.behavior.manual-map",
                    "内存驻留载荷",
                    new[] { "userhook.runtime.memory-manual-map", "userhook.runtime.memory-private-executable", "userhook.runtime.memory-private-syscall-stub" },
                    null,
                    180,
                    2,
                    80,
                    "critical",
                    "suspicious",
                    "Defense Evasion",
                    "T1620 Reflective Code Loading",
                    "发现私有可执行内存、RWX 区域或疑似手工映射 PE。"),
                NewBehaviorRule(
                    "dp.behavior.lolbin-download-exec",
                    "LOLBIN 下载执行",
                    new[] { "userhook.observed.process-create", "userhook.observed.network-connect", "userhook.observed.network-wsaconnect" },
                    null,
                    180,
                    2,
                    70,
                    "warning",
                    "suspicious",
                    "Command and Control / Execution",
                    "T1105 / T1218",
                    "certutil、bitsadmin、mshta、regsvr32、rundll32、msiexec、installutil 等 LOLBin 启动后建立外联。"),
                NewBehaviorRule(
                    "dp.behavior.office-script-exec",
                    "Office 脚本执行链",
                    new[] { "userhook.observed.process-create" },
                    null,
                    60,
                    1,
                    75,
                    "critical",
                    "suspicious",
                    "Initial Access / Execution",
                    "T1204 / T1059",
                    "Office 进程拉起 powershell、cmd、wscript、cscript、mshta 等脚本解释器。"),
                NewBehaviorRule(
                    "dp.behavior.recovery-inhibit",
                    "系统恢复破坏",
                    new[] { "userhook.observed.process-create" },
                    null,
                    60,
                    1,
                    85,
                    "critical",
                    "malicious",
                    "Impact",
                    "T1490 Inhibit System Recovery",
                    "vssadmin、wbadmin、bcdedit、wmic shadowcopy、reagentc 等恢复破坏命令。"),
                NewBehaviorRule(
                    "dp.behavior.persistence-autostart",
                    "自启动持久化",
                    new[] { "userhook.observed.registry-set-value", "userhook.observed.process-create" },
                    null,
                    180,
                    1,
                    55,
                    "warning",
                    "suspicious",
                    "Persistence",
                    "T1547.001 Registry Run Keys / Startup Folder",
                    "Run/RunOnce、启动目录、计划任务或服务创建相关行为。"),
                NewBehaviorRule(
                    "dp.behavior.script-network",
                    "脚本解释器外联",
                    new[] { "userhook.observed.process-create", "userhook.observed.network-connect", "userhook.observed.network-wsaconnect" },
                    null,
                    180,
                    2,
                    60,
                    "warning",
                    "suspicious",
                    "Execution / Command and Control",
                    "T1059 Command and Scripting Interpreter",
                    "powershell、wscript、cscript、mshta、cmd 等脚本宿主启动后外联。"),
                NewBehaviorRule(
                    "dp.behavior.script-download-execute",
                    "脚本下载执行链",
                    new[] { "userhook.observed.process-create", "userhook.observed.network-connect", "userhook.observed.network-wsaconnect" },
                    null,
                    180,
                    1,
                    90,
                    "critical",
                    "malicious",
                    "Execution / Command and Control",
                    "T1059 / T1105",
                    "脚本解释器带下载、解码、IEX 或远程脚本参数启动，并在同一窗口内出现外联。"),
                NewBehaviorRule(
                    "dp.behavior.credential-dump-chain",
                    "凭据转储链",
                    new[] { "userhook.behavior-process-access", "userhook.observed.process-create" },
                    null,
                    120,
                    1,
                    95,
                    "critical",
                    "malicious",
                    "Credential Access",
                    "T1003 OS Credential Dumping",
                    "发现 LSASS/注册表凭据目标访问，或 procdump/comsvcs/reg save/mimikatz 语义命令。"),
                NewBehaviorRule(
                    "dp.behavior.defense-impairment",
                    "安全防护削弱链",
                    new[] { "userhook.observed.process-create", "userhook.observed.registry-set-value" },
                    null,
                    120,
                    1,
                    95,
                    "critical",
                    "malicious",
                    "Defense Evasion",
                    "T1562 Impair Defenses",
                    "检测 Defender/EDR 停止、排除项添加、安全服务禁用、日志清理或策略篡改命令。"),
                NewBehaviorRule(
                    "dp.behavior.service-persistence",
                    "服务持久化链",
                    new[] { "userhook.observed.process-create", "userhook.observed.registry-set-value" },
                    null,
                    120,
                    1,
                    85,
                    "critical",
                    "suspicious",
                    "Persistence / Privilege Escalation",
                    "T1543.003 Windows Service",
                    "sc/new-service/服务注册表写入创建自动启动服务。"),
                NewBehaviorRule(
                    "dp.behavior.scheduled-task-persistence",
                    "计划任务持久化链",
                    new[] { "userhook.observed.process-create" },
                    null,
                    120,
                    1,
                    80,
                    "warning",
                    "suspicious",
                    "Persistence",
                    "T1053.005 Scheduled Task",
                    "schtasks /create 或 PowerShell ScheduledTask 创建自启动任务。"),
                NewBehaviorRule(
                    "dp.behavior.lateral-tool-execution",
                    "横向移动工具链",
                    new[] { "userhook.observed.process-create", "userhook.observed.network-connect", "userhook.observed.network-wsaconnect" },
                    null,
                    240,
                    1,
                    90,
                    "critical",
                    "suspicious",
                    "Lateral Movement",
                    "T1021 Remote Services / T1047 WMI",
                    "wmic/psexec/sc/schtasks/PowerShell 远程执行或管理工具带远程主机参数启动。"),
                NewBehaviorRule(
                    "dp.behavior.ransomware-impact-chain",
                    "勒索破坏前置链",
                    new[] { "userhook.observed.process-create", "userhook.observed.registry-set-value" },
                    null,
                    180,
                    1,
                    95,
                    "critical",
                    "malicious",
                    "Impact",
                    "T1486 Data Encrypted for Impact / T1490",
                    "恢复破坏、启动修复关闭、安全模式/日志/备份清理等勒索前置行为。"),
                NewBehaviorRule(
                    "dp.behavior.archive-exfil-chain",
                    "归档外传链",
                    new[] { "userhook.observed.process-create", "userhook.observed.network-connect", "userhook.observed.network-wsaconnect" },
                    null,
                    300,
                    2,
                    75,
                    "warning",
                    "suspicious",
                    "Collection / Exfiltration",
                    "T1560 Archive Collected Data / T1041 Exfiltration Over C2 Channel",
                    "归档工具或脚本压缩敏感目录后同进程外联，按外传准备链判定。"),
                NewBehaviorRule(
                    "dp.behavior.global-windows-hook",
                    "全局 Windows Hook 链",
                    new[] { "userhook.observed.windows-hook", "userhook.blocked.global-windows-hook" },
                    null,
                    60,
                    1,
                    75,
                    "warning",
                    "suspicious",
                    "Credential Access / Collection",
                    "T1056 Input Capture / T1179 Hooking",
                    "非受信进程注册全局 Windows Hook，可能用于键盘记录、消息窃取或注入。"),
                NewBehaviorRule(
                    "dp.behavior.user-writable-dll-load",
                    "用户可写目录 DLL 加载链",
                    new[] { "userhook.observed.load-library", "userhook.observed.load-library-ex" },
                    null,
                    120,
                    1,
                    70,
                    "warning",
                    "suspicious",
                    "Defense Evasion / Persistence",
                    "T1574 Hijack Execution Flow",
                    "进程从用户可写目录加载 DLL，按 DLL 劫持/侧载可疑链处理。")
            };
        }

        private static UserHookBehaviorRule NewBehaviorRule(
            string ruleId,
            string name,
            string[] actions,
            string[] anyActions,
            int windowSeconds,
            int threshold,
            int weight,
            string severity,
            string disposition,
            string tactic,
            string technique,
            string description)
        {
            return new UserHookBehaviorRule
            {
                ruleId = ruleId,
                name = FriendlyDefaultBehaviorRuleName(ruleId, name),
                enabled = true,
                actions = actions ?? new string[0],
                anyActions = anyActions ?? new string[0],
                processNames = DefaultRuleProcessNames(ruleId),
                parentProcessNames = DefaultRuleParentProcessNames(ruleId),
                targetContains = DefaultRuleTargetTokens(ruleId),
                commandLineContains = DefaultRuleCommandTokens(ruleId),
                windowSeconds = windowSeconds,
                threshold = threshold,
                weight = weight,
                severity = severity,
                disposition = disposition,
                tactic = tactic,
                technique = technique,
                description = FriendlyDefaultBehaviorRuleDescription(ruleId, description),
                references = DefaultRuleReferences(ruleId)
            };
        }

        private static string FriendlyDefaultBehaviorRuleName(string ruleId, string fallback)
        {
            if (string.Equals(ruleId, "dp.behavior.injection-chain", StringComparison.OrdinalIgnoreCase)) return "Cross-process injection chain";
            if (string.Equals(ruleId, "dp.behavior.remote-dll-injection", StringComparison.OrdinalIgnoreCase)) return "Remote DLL injection chain";
            if (string.Equals(ruleId, "dp.behavior.shellcode-injection", StringComparison.OrdinalIgnoreCase)) return "Remote shellcode injection chain";
            if (string.Equals(ruleId, "dp.behavior.process-hollowing", StringComparison.OrdinalIgnoreCase)) return "Process hollowing chain";
            if (string.Equals(ruleId, "dp.behavior.apc-injection", StringComparison.OrdinalIgnoreCase)) return "APC injection chain";
            if (string.Equals(ruleId, "dp.behavior.thread-hijack", StringComparison.OrdinalIgnoreCase)) return "Thread hijacking injection chain";
            if (string.Equals(ruleId, "dp.behavior.ntdll-reload-bypass", StringComparison.OrdinalIgnoreCase)) return "NTDLL reload and hook bypass chain";
            if (string.Equals(ruleId, "dp.behavior.hook-bypass", StringComparison.OrdinalIgnoreCase)) return "Hook bypass and direct syscall behavior";
            if (string.Equals(ruleId, "dp.behavior.telemetry-impairment", StringComparison.OrdinalIgnoreCase)) return "Telemetry impairment and ETW tamper";
            if (string.Equals(ruleId, "dp.behavior.manual-map", StringComparison.OrdinalIgnoreCase)) return "Manual map or executable memory chain";
            if (string.Equals(ruleId, "dp.behavior.lolbin-download-exec", StringComparison.OrdinalIgnoreCase)) return "LOLBin download or execution chain";
            if (string.Equals(ruleId, "dp.behavior.office-script-exec", StringComparison.OrdinalIgnoreCase)) return "Office child script execution";
            if (string.Equals(ruleId, "dp.behavior.recovery-inhibit", StringComparison.OrdinalIgnoreCase)) return "System recovery inhibition";
            if (string.Equals(ruleId, "dp.behavior.persistence-autostart", StringComparison.OrdinalIgnoreCase)) return "Autostart persistence chain";
            if (string.Equals(ruleId, "dp.behavior.script-network", StringComparison.OrdinalIgnoreCase)) return "Script interpreter network chain";
            if (string.Equals(ruleId, "dp.behavior.script-download-execute", StringComparison.OrdinalIgnoreCase)) return "Script download and execute chain";
            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase)) return "Credential dumping chain";
            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase)) return "Security defense impairment chain";
            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase)) return "Service persistence chain";
            if (string.Equals(ruleId, "dp.behavior.scheduled-task-persistence", StringComparison.OrdinalIgnoreCase)) return "Scheduled task persistence chain";
            if (string.Equals(ruleId, "dp.behavior.lateral-tool-execution", StringComparison.OrdinalIgnoreCase)) return "Lateral movement tool execution chain";
            if (string.Equals(ruleId, "dp.behavior.ransomware-impact-chain", StringComparison.OrdinalIgnoreCase)) return "Ransomware impact preparation chain";
            if (string.Equals(ruleId, "dp.behavior.archive-exfil-chain", StringComparison.OrdinalIgnoreCase)) return "Archive and exfiltration chain";
            if (string.Equals(ruleId, "dp.behavior.global-windows-hook", StringComparison.OrdinalIgnoreCase)) return "Global Windows hook behavior";
            if (string.Equals(ruleId, "dp.behavior.user-writable-dll-load", StringComparison.OrdinalIgnoreCase)) return "User-writable DLL load chain";
            return string.IsNullOrWhiteSpace(fallback) ? ruleId : fallback;
        }

        private static string FriendlyDefaultBehaviorRuleDescription(string ruleId, string fallback)
        {
            if (string.Equals(ruleId, "dp.behavior.injection-chain", StringComparison.OrdinalIgnoreCase)) return "Correlates cross-process access, executable memory, memory write and remote execution before alerting.";
            if (string.Equals(ruleId, "dp.behavior.remote-dll-injection", StringComparison.OrdinalIgnoreCase)) return "Correlates target process access, remote DLL-path write and remote thread creation as a DLL injection chain.";
            if (string.Equals(ruleId, "dp.behavior.shellcode-injection", StringComparison.OrdinalIgnoreCase)) return "Correlates remote executable memory allocation or protection, remote payload write and remote execution.";
            if (string.Equals(ruleId, "dp.behavior.process-hollowing", StringComparison.OrdinalIgnoreCase)) return "Correlates suspended process creation, image unmap, remote write, thread context changes and resume behavior.";
            if (string.Equals(ruleId, "dp.behavior.apc-injection", StringComparison.OrdinalIgnoreCase)) return "Correlates QueueUserAPC with remote memory allocation or cross-process memory writes.";
            if (string.Equals(ruleId, "dp.behavior.thread-hijack", StringComparison.OrdinalIgnoreCase)) return "Correlates remote thread access, payload write, thread context manipulation and thread resume.";
            if (string.Equals(ruleId, "dp.behavior.ntdll-reload-bypass", StringComparison.OrdinalIgnoreCase)) return "Correlates sensitive module reloads, abnormal module paths, hook overwrite and private syscall stub evidence.";
            if (string.Equals(ruleId, "dp.behavior.hook-bypass", StringComparison.OrdinalIgnoreCase)) return "Correlates hook tamper, private syscall stubs and direct NT API behavior.";
            if (string.Equals(ruleId, "dp.behavior.telemetry-impairment", StringComparison.OrdinalIgnoreCase)) return "Detects verified ETW patching or telemetry entry-point tamper signals.";
            if (string.Equals(ruleId, "dp.behavior.manual-map", StringComparison.OrdinalIgnoreCase)) return "Correlates manual mapped PE evidence, RWX memory and private executable memory.";
            if (string.Equals(ruleId, "dp.behavior.lolbin-download-exec", StringComparison.OrdinalIgnoreCase)) return "Correlates LOLBin execution with suspicious command-line or network behavior.";
            if (string.Equals(ruleId, "dp.behavior.office-script-exec", StringComparison.OrdinalIgnoreCase)) return "Detects Office spawning script interpreters or proxy execution tools with risky arguments.";
            if (string.Equals(ruleId, "dp.behavior.recovery-inhibit", StringComparison.OrdinalIgnoreCase)) return "Detects VSS, backup or boot recovery destruction command execution.";
            if (string.Equals(ruleId, "dp.behavior.persistence-autostart", StringComparison.OrdinalIgnoreCase)) return "Correlates Run, RunOnce, startup folder, task or service persistence behavior.";
            if (string.Equals(ruleId, "dp.behavior.script-network", StringComparison.OrdinalIgnoreCase)) return "Correlates script interpreter execution with outbound network behavior.";
            if (string.Equals(ruleId, "dp.behavior.script-download-execute", StringComparison.OrdinalIgnoreCase)) return "Requires a script interpreter with download/decode/execute intent and optional same-process network activity.";
            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase)) return "Requires LSASS, SAM/SYSTEM/SECURITY, procdump, comsvcs, reg save or Mimikatz-like credential access intent.";
            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase)) return "Detects commands or registry writes that disable Defender, logging, services or security telemetry.";
            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase)) return "Detects service creation or service registry autorun writes.";
            if (string.Equals(ruleId, "dp.behavior.scheduled-task-persistence", StringComparison.OrdinalIgnoreCase)) return "Detects scheduled task creation through schtasks or PowerShell scheduled task APIs.";
            if (string.Equals(ruleId, "dp.behavior.lateral-tool-execution", StringComparison.OrdinalIgnoreCase)) return "Detects remote execution tools and commands with remote host/service/WMI intent.";
            if (string.Equals(ruleId, "dp.behavior.ransomware-impact-chain", StringComparison.OrdinalIgnoreCase)) return "Detects recovery destruction and common ransomware preparation commands.";
            if (string.Equals(ruleId, "dp.behavior.archive-exfil-chain", StringComparison.OrdinalIgnoreCase)) return "Correlates archive collection command intent with network activity.";
            if (string.Equals(ruleId, "dp.behavior.global-windows-hook", StringComparison.OrdinalIgnoreCase)) return "Detects global Windows hook registration from monitored processes.";
            if (string.Equals(ruleId, "dp.behavior.user-writable-dll-load", StringComparison.OrdinalIgnoreCase)) return "Detects DLL loads from user-writable directories often used for side-loading or hijacking.";
            return fallback ?? string.Empty;
        }

        private static string[] DefaultRuleProcessNames(string ruleId)
        {
            if (string.Equals(ruleId, "dp.behavior.lolbin-download-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "powershell.exe", "pwsh.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.office-script-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.recovery-inhibit", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe", "powershell.exe", "cmd.exe", "reagentc.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.script-network", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.script-download-execute", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "procdump.exe", "rundll32.exe", "reg.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "taskmgr.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe", "sc.exe", "net.exe", "net1.exe", "wevtutil.exe", "bcdedit.exe", "auditpol.exe", "wmic.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "sc.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.scheduled-task-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "schtasks.exe", "powershell.exe", "pwsh.exe", "cmd.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.lateral-tool-execution", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "wmic.exe", "psexec.exe", "paexec.exe", "sc.exe", "schtasks.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "net.exe", "net1.exe", "winrs.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.ransomware-impact-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "reagentc.exe", "wevtutil.exe", "fsutil.exe" };
            }

            if (string.Equals(ruleId, "dp.behavior.archive-exfil-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "powershell.exe", "pwsh.exe", "cmd.exe", "rar.exe", "winrar.exe", "7z.exe", "7za.exe", "tar.exe", "makecab.exe" };
            }

            return new string[0];
        }

        private static string[] DefaultRuleParentProcessNames(string ruleId)
        {
            if (string.Equals(ruleId, "dp.behavior.office-script-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "visio.exe", "msaccess.exe", "onenote.exe" };
            }

            return new string[0];
        }

        private static string[] DefaultRuleTargetTokens(string ruleId)
        {
            if (string.Equals(ruleId, "dp.behavior.persistence-autostart", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "\\run", "\\runonce", "currentversion\\run", "startup", "create service", "new-service", "sc.exe create" };
            }

            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "lsass", "sam", "security", "system", "ntds.dit", "comsvcs.dll", "minidump", "procdump" };
            }

            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "windefend", "defender", "real-time protection", "disableantispyware", "disablerealtimemonitoring", "exclusionpath", "eventlog", "sysmon", "dataprotector", "security center" };
            }

            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "\\services\\", "imagepath", "start", "objectname", "sc create", "new-service" };
            }

            if (string.Equals(ruleId, "dp.behavior.user-writable-dll-load", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\downloads\\", ".dll" };
            }

            return new string[0];
        }

        private static string[] DefaultRuleCommandTokens(string ruleId)
        {
            if (string.Equals(ruleId, "dp.behavior.lolbin-download-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "http://", "https://", "urlcache", "download", "scrobj.dll", "javascript:", "vbscript:", "/i:", "-url", "http" };
            }

            if (string.Equals(ruleId, "dp.behavior.office-script-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "-enc", "-encodedcommand", "downloadstring", "frombase64string", "iex", "invoke-expression", "http://", "https://", "rundll32", "regsvr32", "mshta" };
            }

            if (string.Equals(ruleId, "dp.behavior.recovery-inhibit", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "delete shadows", "shadowcopy delete", "resize shadowstorage", "wbadmin delete", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "reagentc /disable" };
            }

            if (string.Equals(ruleId, "dp.behavior.persistence-autostart", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "schtasks /create", "schtasks.exe /create", " /create ", "sc create", "new-service", "currentversion\\run", "runonce", "startup" };
            }

            if (string.Equals(ruleId, "dp.behavior.script-download-execute", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "curl ", "wget ", "invoke-expression", " iex ", "http://", "https://", "mshta", "regsvr32", "rundll32", "javascript:", "vbscript:" };
            }

            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "lsass", "sekurlsa", "lsadump", "privilege::debug", "procdump", "comsvcs.dll", "minidump", "reg save hklm\\sam", "reg save hklm\\system", "reg save hklm\\security", "ntds.dit", "vssadmin", "esentutl" };
            }

            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "set-mppreference", "disablerealtimemonitoring", "disableantispyware", "add-mppreference", "exclusionpath", "windefend", "sc stop", "sc config", "net stop", "wevtutil cl", "auditpol /clear", "sysmon", "eventlog", "dataprotector", "tamperprotection" };
            }

            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "sc create", "sc.exe create", "new-service", "create service", "start= auto", "binpath=", "\\services\\", "imagepath" };
            }

            if (string.Equals(ruleId, "dp.behavior.scheduled-task-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "schtasks /create", "schtasks.exe /create", "new-scheduledtask", "register-scheduledtask", " /sc ", " /tn ", " /tr ", " /ru " };
            }

            if (string.Equals(ruleId, "dp.behavior.lateral-tool-execution", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "\\\\", "/node:", "process call create", "wmic ", "psexec", "paexec", "winrs", "invoke-command", "enter-pssession", "new-pssession", "sc \\\\", "schtasks /s", " /s " };
            }

            if (string.Equals(ruleId, "dp.behavior.ransomware-impact-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "delete shadows", "shadowcopy delete", "resize shadowstorage", "wbadmin delete", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "reagentc /disable", "wevtutil cl", "bcdedit", "vssadmin", "cipher /w" };
            }

            if (string.Equals(ruleId, "dp.behavior.archive-exfil-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { ".zip", ".rar", ".7z", "compress-archive", "makecab", "tar -", " a -", " -mx", "desktop", "documents", "downloads", "http://", "https://" };
            }

            return new string[0];
        }

        private static string[] DefaultRuleReferences(string ruleId)
        {
            if (string.Equals(ruleId, "dp.behavior.injection-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1055", "MITRE DET0106", "Sysmon Event ID 8/10" };
            }

            if (string.Equals(ruleId, "dp.behavior.remote-dll-injection", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1055.001", "Sysmon Event ID 8/10", "OpenProcess/WriteProcessMemory/CreateRemoteThread" };
            }

            if (string.Equals(ruleId, "dp.behavior.shellcode-injection", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1055", "VirtualAllocEx/WriteProcessMemory/CreateRemoteThread", "NtAllocateVirtualMemory/NtCreateThreadEx" };
            }

            if (string.Equals(ruleId, "dp.behavior.thread-hijack", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1055.003", "SetThreadContext", "ResumeThread" };
            }

            if (string.Equals(ruleId, "dp.behavior.ntdll-reload-bypass", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1562", "MITRE ATT&CK T1106", "Ntdll reload / direct syscall evasion" };
            }

            if (string.Equals(ruleId, "dp.behavior.recovery-inhibit", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1490", "Sigma/Elastic recovery inhibition rules" };
            }

            if (string.Equals(ruleId, "dp.behavior.telemetry-impairment", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1562.002", "Microsoft ETW EventWrite/EtwEventWrite", "Sysmon telemetry model" };
            }

            if (string.Equals(ruleId, "dp.behavior.lolbin-download-exec", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "LOLBAS", "MITRE ATT&CK T1218/T1105" };
            }

            if (string.Equals(ruleId, "dp.behavior.credential-dump-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1003", "LSASS access", "Mimikatz/procdump/comsvcs/reg save patterns" };
            }

            if (string.Equals(ruleId, "dp.behavior.defense-impairment", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1562", "Defender tamper patterns", "Windows Event Log clearing" };
            }

            if (string.Equals(ruleId, "dp.behavior.service-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1543.003", "Windows service creation" };
            }

            if (string.Equals(ruleId, "dp.behavior.scheduled-task-persistence", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1053.005", "Scheduled task creation" };
            }

            if (string.Equals(ruleId, "dp.behavior.lateral-tool-execution", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1021/T1047", "WMI/SMB/WinRM remote execution" };
            }

            if (string.Equals(ruleId, "dp.behavior.ransomware-impact-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1486/T1490", "Ransomware recovery destruction patterns" };
            }

            if (string.Equals(ruleId, "dp.behavior.archive-exfil-chain", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "MITRE ATT&CK T1560/T1041", "Archive and exfiltration behavior" };
            }

            return new[] { "MITRE ATT&CK", "Sigma / Elastic public detection engineering patterns" };
        }

        private static UserHookBehaviorRule[] NormalizeUserHookBehaviorRules(UserHookBehaviorRule[] rules)
        {
            IEnumerable<UserHookBehaviorRule> source = rules == null || rules.Length == 0
                ? DefaultUserHookBehaviorRules()
                : rules;

            return MergeDefaultBehaviorRules(source)
                .Where(rule => rule != null)
                .Select(NormalizeUserHookBehaviorRule)
                .Where(rule => !string.IsNullOrWhiteSpace(rule.ruleId))
                .GroupBy(rule => rule.ruleId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(MaxBehaviorChainRules)
                .ToArray();
        }

        private static IEnumerable<UserHookBehaviorRule> MergeDefaultBehaviorRules(IEnumerable<UserHookBehaviorRule> rules)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<UserHookBehaviorRule> merged = new List<UserHookBehaviorRule>();

            foreach (UserHookBehaviorRule rule in rules ?? new UserHookBehaviorRule[0])
            {
                if (rule == null || string.IsNullOrWhiteSpace(rule.ruleId) || !seen.Add(rule.ruleId))
                {
                    continue;
                }

                merged.Add(rule);
            }

            foreach (UserHookBehaviorRule rule in DefaultUserHookBehaviorRules())
            {
                if (rule == null || string.IsNullOrWhiteSpace(rule.ruleId) || !seen.Add(rule.ruleId))
                {
                    continue;
                }

                merged.Add(rule);
            }

            return merged;
        }

        private static UserHookBehaviorRule NormalizeUserHookBehaviorRule(UserHookBehaviorRule rule)
        {
            string ruleId = NormalizeRuleText(rule == null ? string.Empty : rule.ruleId, MaxBehaviorRuleText);
            string name = NormalizeRuleText(rule == null ? string.Empty : rule.name, MaxBehaviorRuleText);
            return new UserHookBehaviorRule
            {
                ruleId = ruleId,
                name = string.IsNullOrWhiteSpace(name) ? ruleId : name,
                enabled = rule == null || rule.enabled,
                actions = NormalizeBehaviorRuleActions(ruleId, rule == null ? null : rule.actions),
                anyActions = NormalizeBehaviorRuleActions(ruleId, rule == null ? null : rule.anyActions),
                processNames = NormalizeRuleList(rule == null ? null : rule.processNames),
                parentProcessNames = NormalizeRuleList(rule == null ? null : rule.parentProcessNames),
                targetContains = NormalizeRuleList(rule == null ? null : rule.targetContains),
                commandLineContains = NormalizeRuleList(rule == null ? null : rule.commandLineContains),
                windowSeconds = Clamp(rule == null ? 120 : rule.windowSeconds, 5, 3600),
                threshold = Clamp(rule == null ? 1 : rule.threshold, 1, 64),
                weight = Clamp(rule == null ? 50 : rule.weight, 1, 100),
                severity = NormalizeSeverity(rule == null ? string.Empty : rule.severity),
                disposition = NormalizeDisposition(rule == null ? string.Empty : rule.disposition),
                tactic = NormalizeRuleText(rule == null ? string.Empty : rule.tactic, MaxBehaviorRuleText),
                technique = NormalizeRuleText(rule == null ? string.Empty : rule.technique, MaxBehaviorRuleText),
                description = NormalizeRuleText(rule == null ? string.Empty : rule.description, 1024),
                references = NormalizeRuleList(rule == null ? null : rule.references)
            };
        }

        private static string[] NormalizeBehaviorRuleActions(string ruleId, string[] values)
        {
            string[] actions = NormalizeRuleList(values);
            if (string.Equals(ruleId, "dp.behavior.telemetry-impairment", StringComparison.OrdinalIgnoreCase))
            {
                actions = actions
                    .Where(action => !string.Equals(action, "userhook.observed.etw-provider-unregister", StringComparison.OrdinalIgnoreCase))
                    .Where(action => !string.Equals(action, "userhook.observed.etw-provider-register", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            }

            return actions;
        }

        private static string[] NormalizeRuleList(string[] values)
        {
            return (values ?? new string[0])
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => NormalizeRuleText(item, MaxBehaviorRuleText))
                .Where(item => item.Length != 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxBehaviorAtomsPerRule)
                .ToArray();
        }

        private static string NormalizeRuleText(string value, int maxChars)
        {
            string text = (value ?? string.Empty).Trim();
            if (text.Length > maxChars)
            {
                text = text.Substring(0, maxChars);
            }

            return text.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
        }

        private static string NormalizeSeverity(string value)
        {
            string text = (value ?? string.Empty).Trim().ToLowerInvariant();
            return text == "critical" || text == "warning" || text == "info" || text == "operational" ? text : "warning";
        }

        private static string NormalizeDisposition(string value)
        {
            string text = (value ?? string.Empty).Trim().ToLowerInvariant();
            return text == "malicious" || text == "suspicious" || text == "observed" || text == "blocked" ? text : "suspicious";
        }

        private static int Clamp(int value, int min, int max)
        {
            if (value < min) return min;
            if (value > max) return max;
            return value;
        }

        private static string[] NormalizeStringList(string[] values, string[] fallback)
        {
            IEnumerable<string> source = values == null || values.Length == 0
                ? (fallback ?? new string[0])
                : values;

            return source
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(128)
                .ToArray();
        }

        private static string[] SplitUserHookPolicyList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return new string[0];
            }

            return value
                .Split(new[] { '\r', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(item => item.Trim())
                .Where(item => item.Length != 0)
                .ToArray();
        }

        private static string NormalizeDevicePathList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            return string.Join(
                "\n",
                SplitUserHookPolicyList(value).Select(NormalizeDevicePath).Where(item => !string.IsNullOrWhiteSpace(item)));
        }

        private static string[] ConvertUserHookPathsForKernel(string[] values)
        {
            string[] normalized = NormalizeStringList(values, new string[0]);
            List<string> converted = new List<string>(normalized.Length);

            foreach (string value in normalized)
            {
                string convertedPath;
                if (TryConvertDosPathToNtPath(value, out convertedPath))
                {
                    converted.Add(convertedPath);
                }
                else
                {
                    converted.Add(value);
                }
            }

            return converted.ToArray();
        }

        private static bool TryConvertDosPathToNtPath(string value, out string converted)
        {
            converted = value;
            if (string.IsNullOrWhiteSpace(value) ||
                value.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            try
            {
                StringBuilder buffer = new StringBuilder((int)PathBufferChars);
                uint status = DataProtectorPolicyNative.DpPolicyConvertDosPathToNtPath(value, buffer, PathBufferChars);
                if (status != SuccessStatus)
                {
                    return false;
                }

                string ntPath = buffer.ToString();
                if (string.IsNullOrWhiteSpace(ntPath))
                {
                    return false;
                }

                converted = ntPath;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void WriteUserHookRuntimePolicy(UserHookDefensePolicyDto policy)
        {
            try
            {
                UserHookDefensePolicyDto normalized = CloneUserHookDefensePolicy(policy);
                string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string directory = Path.Combine(dataRoot, "DataProtector");
                Directory.CreateDirectory(directory);
                string path = Path.Combine(directory, "UserHookRuntimePolicy.json");
                JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
                File.WriteAllText(path, serializer.Serialize(normalized), Encoding.UTF8);
            }
            catch
            {
                // Runtime policy cache is best-effort; kernel policy application remains authoritative.
            }
        }

        private static string GetPreparedUserHookRuntimePath()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string runtimeDirectory = Path.Combine(dataRoot, "DataProtector", "Runtime");
            string sourcePath = FindUserHookRuntimeSource();

            if (!string.IsNullOrWhiteSpace(sourcePath) && File.Exists(sourcePath))
            {
                try
                {
                    return BuildVersionedUserHookRuntimePath(runtimeDirectory, ComputeFileSha256Hex(sourcePath));
                }
                catch
                {
                    // SetUserHookDefensePolicy will report the concrete copy/hash error.
                }
            }

            try
            {
                DirectoryInfo directory = new DirectoryInfo(runtimeDirectory);
                FileInfo newestRuntime = directory.Exists
                    ? directory.GetFiles("DataProtectorUserHookRuntime.dll", SearchOption.AllDirectories)
                        .OrderByDescending(file => file.LastWriteTimeUtc)
                        .FirstOrDefault()
                    : null;
                if (newestRuntime != null)
                {
                    return newestRuntime.FullName;
                }
            }
            catch
            {
                // Best-effort status fallback only.
            }

            return Path.Combine(runtimeDirectory, "DataProtectorUserHookRuntime.dll");
        }

        private static string PrepareUserHookRuntimeDll()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string runtimeDirectory = Path.Combine(dataRoot, "DataProtector", "Runtime");
            string sourcePath = FindUserHookRuntimeSource();
            string sourceHash;
            string runtimePath;

            Directory.CreateDirectory(runtimeDirectory);
            if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
            {
                throw new BridgeException(1, "User hook runtime DLL was not found beside the agent/server executable. Expected DataProtectorUserHookRuntime.dll in " + AppDomain.CurrentDomain.BaseDirectory + " or " + Environment.CurrentDirectory + ".");
            }

            sourceHash = ComputeFileSha256Hex(sourcePath);
            runtimePath = BuildVersionedUserHookRuntimePath(runtimeDirectory, sourceHash);
            Directory.CreateDirectory(Path.GetDirectoryName(runtimePath));

            if (File.Exists(runtimePath))
            {
                if (!FileHashEquals(runtimePath, sourceHash))
                {
                    throw new BridgeException(1, "Versioned user hook runtime DLL hash mismatch at " + runtimePath + ". Remove the stale version directory and retry.");
                }
            }
            else
            {
                File.Copy(sourcePath, runtimePath, false);
            }

            if (!File.Exists(runtimePath))
            {
                throw new BridgeException(1, "User hook runtime DLL could not be prepared at " + runtimePath + ".");
            }

            return runtimePath;
        }

        private static string BuildVersionedUserHookRuntimePath(string runtimeDirectory, string sha256Hex)
        {
            string version = string.IsNullOrWhiteSpace(sha256Hex)
                ? "unknown"
                : sha256Hex.Trim().ToLowerInvariant();
            return Path.Combine(runtimeDirectory, version, "DataProtectorUserHookRuntime.dll");
        }

        private static string FindUserHookRuntimeSource()
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates =
            {
                Path.Combine(baseDirectory, "DataProtectorUserHookRuntime.dll"),
                Path.Combine(baseDirectory, "agent", "DataProtectorUserHookRuntime.dll"),
                Path.Combine(baseDirectory, "server", "DataProtectorUserHookRuntime.dll"),
                Path.Combine(Environment.CurrentDirectory, "DataProtectorUserHookRuntime.dll")
            };

            foreach (string candidate in candidates)
            {
                if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return string.Empty;
        }

        private static bool FileHashesEqual(string leftPath, string rightPath)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                using (FileStream left = OpenReadShared(leftPath))
                using (FileStream right = OpenReadShared(rightPath))
                {
                    byte[] leftHash = sha256.ComputeHash(left);
                    byte[] rightHash = sha256.ComputeHash(right);
                    return leftHash.SequenceEqual(rightHash);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool FileHashEquals(string path, string expectedSha256Hex)
        {
            try
            {
                return string.Equals(ComputeFileSha256Hex(path), expectedSha256Hex, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string ComputeFileSha256Hex(string path)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (FileStream stream = OpenReadShared(path))
            {
                return BytesToHex(sha256.ComputeHash(stream));
            }
        }

        private static FileStream OpenReadShared(string path)
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }

        private static string BytesToHex(byte[] bytes)
        {
            StringBuilder builder = new StringBuilder((bytes == null ? 0 : bytes.Length) * 2);
            if (bytes == null)
            {
                return string.Empty;
            }

            foreach (byte value in bytes)
            {
                builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
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
                safeFolders = new string[0],
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
                safeFolders = NormalizeDlpStringList(source.safeFolders),
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
                safeFolders = NormalizeDlpStringList(request.safeFolders),
                actor = string.IsNullOrWhiteSpace(request.actor) ? "web-admin" : request.actor.Trim()
            };
        }

        internal static string DlpProtectionPolicySummary(DlpProtectionPolicyDto policy)
        {
            DlpProtectionPolicyDto normalized = CloneDlpProtectionPolicy(policy);
            return string.Format(
                CultureInfo.InvariantCulture,
                "enabled={0};clipboard={1};clipboardMode={2};screenshots={3};screenshotMode={4};hotkeys={5};trustedProcesses={6};trustedDirectories={7};safeFolders={8}",
                normalized.enabled,
                normalized.protectClipboard,
                normalized.clipboardMode,
                normalized.protectScreenshots,
                normalized.screenshotMode,
                normalized.blockPrintScreenHotkeys,
                normalized.trustedProcessNames.Length,
                normalized.trustedProcessDirectories.Length,
                normalized.safeFolders.Length);
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
                   SameStringSet(a.trustedProcessDirectories, b.trustedProcessDirectories) &&
                   SameStringSet(a.safeFolders, b.safeFolders);
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

        private static FileHunterRuleDto NormalizeFileHunterRule(FileHunterRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "File hunter rule request body is required.");
            }

            string directory = (request.directory ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new BridgeException(1, "Safe folder directory is required.");
            }

            return new FileHunterRuleDto
            {
                directory = directory,
                actor = string.IsNullOrWhiteSpace(request.actor) ? "web-admin" : request.actor.Trim()
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
            if (operation == UserHookOperationRuntimeInjectionRequired) return "runtime-injection-required";
            if (operation == UserHookOperationRuntimeInjectionQueued) return "runtime-injection-queued";
            if (operation == UserHookOperationRuntimeInjectionFailed) return "runtime-injection-failed";
            if (operation == UserHookOperationRuntimeInjectionSkipped) return "runtime-injection-skipped";
            if (operation == UserHookOperationBehaviorProcessAccess) return "behavior-process-access";
            if (operation == UserHookOperationBehaviorThreadAccess) return "behavior-thread-access";
            if (operation == UserHookOperationSensitiveImageReload) return "sensitive-image-reload";
            if (operation == UserHookOperationSensitiveImageAbnormalPath) return "sensitive-image-abnormal-path";
            if (operation == UserHookOperationBehaviorRemoteThreadCreate) return "behavior-remote-thread-create";
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

        private sealed class UserHookRuntimeEvent
        {
            public string timestampUtc { get; set; }
            public string host { get; set; }
            public uint pid { get; set; }
            public uint targetPid { get; set; }
            public string action { get; set; }
            public string category { get; set; }
            public string api { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
            public string commandLine { get; set; }
            public string status { get; set; }
            public ulong size { get; set; }
            public uint flags { get; set; }
            public bool blocked { get; set; }
        }

        private sealed class UserHookBehaviorCorrelator
        {
            private readonly UserHookBehaviorRule[] rules;
            private readonly List<UserHookBehaviorAtom> atoms = new List<UserHookBehaviorAtom>();
            private readonly HashSet<string> emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            public UserHookBehaviorCorrelator(UserHookDefensePolicyDto policy)
            {
                UserHookDefensePolicyDto normalized = CloneUserHookDefensePolicy(policy);
                rules = NormalizeUserHookBehaviorRules(normalized.behaviorRules);
            }

            public AuditLog.AuditRecord[] Observe(AuditLog.AuditRecord record)
            {
                List<AuditLog.AuditRecord> matches = new List<AuditLog.AuditRecord>();
                UserHookBehaviorAtom atom;
                if (!TryBuildAtom(record, out atom))
                {
                    return matches.ToArray();
                }

                atoms.Add(atom);
                TrimAtoms(atom.TimestampUtc);

                foreach (UserHookBehaviorRule rule in rules)
                {
                    AuditLog.AuditRecord match;
                    if (TryMatchRule(rule, atom, out match))
                    {
                        matches.Add(match);
                    }
                }

                return matches.ToArray();
            }

            private bool TryMatchRule(UserHookBehaviorRule rule, UserHookBehaviorAtom atom, out AuditLog.AuditRecord record)
            {
                DateTime windowStart;
                List<UserHookBehaviorAtom> candidates;
                HashSet<string> matchedActions;
                BehaviorMatchEvaluation evaluation;
                int score;
                string dedupKey;
                string message;

                record = null;
                if (rule == null || !rule.enabled || !AtomMatchesRule(rule, atom))
                {
                    return false;
                }

                if (IsBenignBehaviorAtom(atom))
                {
                    return false;
                }

                windowStart = atom.TimestampUtc.AddSeconds(-Clamp(rule.windowSeconds, 5, 3600));
                candidates = atoms
                    .Where(item => item.TimestampUtc >= windowStart)
                    .Where(item => IsRelatedBehaviorScope(rule, atom, item))
                    .Where(item => AtomMatchesRule(rule, item))
                    .Where(item => !IsBenignBehaviorAtom(item))
                    .OrderBy(item => item.TimestampUtc)
                    .ToList();

                matchedActions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (UserHookBehaviorAtom item in candidates)
                {
                    matchedActions.Add(item.Action);
                }

                evaluation = EvaluateBehaviorChain(rule, atom, candidates, matchedActions);
                score = evaluation.Score;
                if (!evaluation.Alert)
                {
                    return false;
                }

                dedupKey = rule.ruleId + "|" + evaluation.ScopeKey + "|" + (long)(atom.TimestampUtc.Subtract(DateTime.MinValue).TotalSeconds / Clamp(rule.windowSeconds, 5, 3600));
                if (!emitted.Add(dedupKey))
                {
                    return false;
                }

                message = BuildRuleMatchMessage(rule, matchedActions, candidates, evaluation);
                record = new AuditLog.AuditRecord
                {
                    TimestampUtc = atom.TimestampUtc.ToString("o"),
                    Host = atom.Host,
                    Actor = "behavior-chain-engine",
                    Action = "behavior.chain." + rule.ruleId,
                    Target = evaluation.PrimaryTarget,
                    Extension = evaluation.PrimaryProcess,
                    Succeeded = !string.Equals(rule.disposition, "malicious", StringComparison.OrdinalIgnoreCase),
                    Status = string.Equals(rule.severity, "critical", StringComparison.OrdinalIgnoreCase) ? "0xE0020001" : "0xE0020000",
                    Message = message,
                    SourceHost = atom.Host,
                    SourceProcess = evaluation.PrimaryProcess,
                    SourcePid = atom.ProcessPid,
                    TargetProcess = evaluation.PrimaryTarget,
                    TargetPid = evaluation.PrimaryTargetPid,
                    ObjectType = "behavior-chain",
                    ObjectName = string.IsNullOrWhiteSpace(rule.name) ? rule.ruleId : rule.name,
                    ObjectFormat = BuildRuleObjectFormat(rule, matchedActions, candidates.Count, score, evaluation),
                    PolicyName = "process-threat-insight",
                    Disposition = NormalizeBehaviorDisposition(rule.disposition),
                    Severity = NormalizeBehaviorSeverity(rule.severity),
                    EventDetails = message
                };
                return true;
            }

            private static string BuildRuleObjectFormat(UserHookBehaviorRule rule, HashSet<string> matchedActions, int eventCount, int score, BehaviorMatchEvaluation evaluation)
            {
                List<string> parts = new List<string>();
                if (!string.IsNullOrWhiteSpace(rule.ruleId))
                {
                    parts.Add("rule=" + rule.ruleId);
                }

                if (!string.IsNullOrWhiteSpace(rule.tactic))
                {
                    parts.Add("tactic=" + rule.tactic);
                }

                if (!string.IsNullOrWhiteSpace(rule.technique))
                {
                    parts.Add("technique=" + rule.technique);
                }

                parts.Add("score=" + score.ToString(CultureInfo.InvariantCulture));
                parts.Add("events=" + eventCount.ToString(CultureInfo.InvariantCulture));
                parts.Add("classes=" + string.Join(",", evaluation.EvidenceClasses.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray()));
                if (!string.IsNullOrWhiteSpace(evaluation.ScopeKey))
                {
                    parts.Add("scope=" + evaluation.ScopeKey);
                }

                if (!string.IsNullOrWhiteSpace(evaluation.Reason))
                {
                    parts.Add("reason=" + evaluation.Reason);
                }

                if (!string.IsNullOrWhiteSpace(evaluation.AttackStory))
                {
                    parts.Add("story=" + evaluation.AttackStory);
                }

                parts.Add("actions=" + string.Join(",", matchedActions.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray()));
                return string.Join(";", parts.ToArray());
            }

            private static string NormalizeBehaviorSeverity(string value)
            {
                if (string.Equals(value, "critical", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "warning", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "info", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "operational", StringComparison.OrdinalIgnoreCase))
                {
                    return value.ToLowerInvariant();
                }

                if (string.Equals(value, "high", StringComparison.OrdinalIgnoreCase))
                {
                    return "critical";
                }

                if (string.Equals(value, "medium", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "low", StringComparison.OrdinalIgnoreCase))
                {
                    return "warning";
                }

                return "warning";
            }

            private static string NormalizeBehaviorDisposition(string value)
            {
                if (string.Equals(value, "blocked", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "observed", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "completed", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "failed", StringComparison.OrdinalIgnoreCase))
                {
                    return value.ToLowerInvariant();
                }

                if (string.Equals(value, "malicious", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(value, "suspicious", StringComparison.OrdinalIgnoreCase))
                {
                    return "observed";
                }

                return "observed";
            }

            private static string BuildRuleMatchMessage(UserHookBehaviorRule rule, HashSet<string> matchedActions, List<UserHookBehaviorAtom> candidates, BehaviorMatchEvaluation evaluation)
            {
                string message = "检测到行为链：" + rule.name + "。";
                message += " 结论=" + rule.disposition + "；级别=" + rule.severity + "；评分=" + evaluation.Score.ToString(CultureInfo.InvariantCulture) + "；事件数=" + candidates.Count.ToString(CultureInfo.InvariantCulture) + "。";
                if (!string.IsNullOrWhiteSpace(rule.technique))
                {
                    message += " 技术=" + rule.technique + "。";
                }

                message += " 来源进程=" + evaluation.PrimaryProcess + "；目标=" + evaluation.PrimaryTarget + "。";
                if (!string.IsNullOrWhiteSpace(evaluation.AttackStory))
                {
                    message += " 攻击流程=" + evaluation.AttackStory;
                }

                if (!string.IsNullOrWhiteSpace(evaluation.Reason))
                {
                    message += " 判定原因=" + evaluation.Reason + "。";
                }

                message += " 时间线：" + BuildBehaviorTimeline(candidates) + "。";
                if (!string.IsNullOrWhiteSpace(rule.description))
                {
                    message += " 规则说明：" + rule.description;
                }

                return message;
            }

            private static string BuildBehaviorTimeline(List<UserHookBehaviorAtom> candidates)
            {
                if (candidates == null || candidates.Count == 0)
                {
                    return "无事件";
                }

                return string.Join(" -> ",
                    candidates
                        .OrderBy(item => item.TimestampUtc)
                        .Take(8)
                        .Select(DescribeBehaviorAtom)
                        .ToArray());
            }

            private static string DescribeBehaviorAtom(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return "未知行为";
                }

                string action = atom.Action ?? string.Empty;
                if (action.IndexOf("behavior-process-access", StringComparison.OrdinalIgnoreCase) >= 0) return "打开目标进程句柄";
                if (action.IndexOf("behavior-thread-access", StringComparison.OrdinalIgnoreCase) >= 0) return "打开目标线程句柄";
                if (action.IndexOf("remote-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-allocate-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0) return "申请远程可执行内存";
                if (action.IndexOf("remote-executable-protect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-protect-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0) return "改远程内存为可执行";
                if (action.IndexOf("remote-dll-path-write", StringComparison.OrdinalIgnoreCase) >= 0) return "写入 DLL 路径";
                if (action.IndexOf("remote-pe-image-write", StringComparison.OrdinalIgnoreCase) >= 0) return "写入 PE 载荷";
                if (action.IndexOf("write-process-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-write-virtual-memory", StringComparison.OrdinalIgnoreCase) >= 0) return "写入远程进程内存";
                if (action.IndexOf("remote-thread-create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("create-remote-thread", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-create-thread-ex", StringComparison.OrdinalIgnoreCase) >= 0) return "创建远程线程执行";
                if (action.IndexOf("queue-user-apc", StringComparison.OrdinalIgnoreCase) >= 0) return "排队 APC 执行";
                if (action.IndexOf("set-thread-context", StringComparison.OrdinalIgnoreCase) >= 0) return "改写线程上下文";
                if (action.IndexOf("resume-thread", StringComparison.OrdinalIgnoreCase) >= 0) return "恢复线程";
                if (action.IndexOf("nt-unmap-view", StringComparison.OrdinalIgnoreCase) >= 0) return "卸载进程原始映像";
                if (action.IndexOf("suspended-process-create", StringComparison.OrdinalIgnoreCase) >= 0) return "挂起创建进程";
                if (action.IndexOf("process-create", StringComparison.OrdinalIgnoreCase) >= 0) return "启动进程/命令";
                if (action.IndexOf("network-connect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("network-wsaconnect", StringComparison.OrdinalIgnoreCase) >= 0) return "建立网络连接";
                if (action.IndexOf("registry-set-value", StringComparison.OrdinalIgnoreCase) >= 0) return "写入注册表";
                if (action.IndexOf("windows-hook", StringComparison.OrdinalIgnoreCase) >= 0) return "注册 Windows Hook";
                if (action.IndexOf("load-library", StringComparison.OrdinalIgnoreCase) >= 0) return "加载 DLL";
                if (action.IndexOf("syscall", StringComparison.OrdinalIgnoreCase) >= 0) return "出现 syscall 绕过信号";
                if (action.IndexOf("unhook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("hook-overwrite", StringComparison.OrdinalIgnoreCase) >= 0) return "Hook 被篡改";
                if (action.IndexOf("sensitive-image", StringComparison.OrdinalIgnoreCase) >= 0) return "敏感模块重载异常";
                return action;
            }

            private static string BuildBehaviorTargetDisplay(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return string.Empty;
                }

                string targetProcess = ExtractKernelTargetProcess(atom.Target);
                if (!string.IsNullOrWhiteSpace(targetProcess))
                {
                    return string.IsNullOrWhiteSpace(atom.TargetPid)
                        ? targetProcess
                        : targetProcess + "(PID " + atom.TargetPid + ")";
                }

                if (!string.IsNullOrWhiteSpace(atom.TargetPid) &&
                    (string.Equals(atom.Target, "CreateRemoteThread", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "CreateRemoteThreadEx", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "NtCreateThreadEx", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "WriteProcessMemory", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "VirtualAllocEx", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "SetThreadContext", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(atom.Target, "QueueUserAPC", StringComparison.OrdinalIgnoreCase)))
                {
                    return "PID " + atom.TargetPid;
                }

                return atom.Target ?? string.Empty;
            }

            private static BehaviorMatchEvaluation EvaluateBehaviorChain(UserHookBehaviorRule rule, UserHookBehaviorAtom atom, List<UserHookBehaviorAtom> candidates, HashSet<string> matchedActions)
            {
                BehaviorMatchEvaluation evaluation = new BehaviorMatchEvaluation();
                int requiredActions = Clamp(rule.threshold, 1, 64);
                int baseWeight = Clamp(rule.weight, 1, 100);
                bool hasRequiredAction = rule.actions == null || rule.actions.Length == 0 || matchedActions.Any(action => MatchesAction(rule.actions, action));
                bool hasAnyAction = rule.anyActions == null || rule.anyActions.Length == 0 || matchedActions.Any(action => MatchesAction(rule.anyActions, action));
                bool isSingleHighConfidenceRule = IsHighConfidenceSingleEventRule(rule);
                bool ordered = HasPlausibleOrder(candidates);

                evaluation.PrimaryProcess = FirstNonEmpty(atom.ProcessImage, candidates.Select(item => item.ProcessImage).FirstOrDefault(item => !string.IsNullOrWhiteSpace(item)), "-");
                evaluation.PrimaryTarget = FirstNonEmpty(BuildBehaviorTargetDisplay(atom), candidates.Select(BuildBehaviorTargetDisplay).FirstOrDefault(item => !string.IsNullOrWhiteSpace(item)), "-");
                evaluation.PrimaryTargetPid = FirstNonEmpty(atom.TargetPid, candidates.Select(item => item.TargetPid).FirstOrDefault(item => !string.IsNullOrWhiteSpace(item)), string.Empty);
                evaluation.ScopeKey = BuildScopeKey(rule, atom);

                foreach (UserHookBehaviorAtom item in candidates)
                {
                    evaluation.EvidenceClasses.Add(item.EvidenceClass);
                    evaluation.Score += Math.Max(5, baseWeight / 3);
                    evaluation.Score += item.RiskScore;
                    if (item.Blocked)
                    {
                        evaluation.Score += 30;
                    }

                    if (item.IsCrossProcess)
                    {
                        evaluation.Score += 12;
                    }

                    if (item.IsSuspiciousProcess)
                    {
                        evaluation.Score += 12;
                    }

                    if (item.HasSuspiciousCommand)
                    {
                        evaluation.Score += 16;
                    }

                    if (item.IsUserWritableProcess)
                    {
                        evaluation.Score += 8;
                    }

                    if (!string.IsNullOrWhiteSpace(item.TargetPid) &&
                        !string.Equals(item.TargetPid, item.ProcessPid, StringComparison.OrdinalIgnoreCase))
                    {
                        evaluation.Score += 8;
                    }
                }

                evaluation.Score += matchedActions.Count * 8;
                evaluation.Score += Math.Max(0, evaluation.EvidenceClasses.Count - 1) * 12;
                if (hasRequiredAction) evaluation.Score += 12;
                if (hasAnyAction) evaluation.Score += 8;
                if (ordered) evaluation.Score += 12;

                if (!hasRequiredAction || !hasAnyAction)
                {
                    evaluation.Reason = "missing required behavior atom";
                    return evaluation;
                }

                if (matchedActions.Count < requiredActions && !isSingleHighConfidenceRule)
                {
                    evaluation.Reason = "not enough distinct actions";
                    return evaluation;
                }

                if (evaluation.EvidenceClasses.Count < 2 && !isSingleHighConfidenceRule)
                {
                    evaluation.Reason = "not enough behavior classes";
                    return evaluation;
                }

                if (RuleRequiresCrossProcess(rule) && !candidates.Any(item => item.IsCrossProcess))
                {
                    evaluation.Reason = "no cross-process relationship";
                    return evaluation;
                }

                if (RuleRequiresSuspiciousContext(rule) &&
                    !candidates.Any(item => item.IsSuspiciousProcess || item.HasSuspiciousCommand || item.IsUserWritableProcess || item.Blocked))
                {
                    evaluation.Reason = "no suspicious process, command, writable path or response context";
                    return evaluation;
                }

                if (RuleRequiresEtwPatchEvidence(rule) && !candidates.Any(IsVerifiedEtwTamperAtom))
                {
                    evaluation.Reason = "no verified ETW patch evidence";
                    return evaluation;
                }

                if (RuleRequiresExplicitMaliciousIntent(rule) && !candidates.Any(HasExplicitMaliciousIntent))
                {
                    evaluation.Reason = "no explicit malicious intent";
                    return evaluation;
                }

                if (RuleRequiresExecutableMemoryContext(rule) && !candidates.Any(HasStrongExecutableMemoryEvidence))
                {
                    evaluation.Reason = "no strong executable memory evidence";
                    return evaluation;
                }

                if (!EvaluateTechniqueRequirements(rule, candidates, matchedActions, evaluation))
                {
                    return evaluation;
                }

                if (!ordered)
                {
                    evaluation.Reason = "events are not in a plausible order";
                    return evaluation;
                }

                int alertThreshold = isSingleHighConfidenceRule ? 70 : Math.Max(70, requiredActions * Math.Max(20, baseWeight / 2));
                evaluation.Alert = evaluation.Score >= alertThreshold;
                evaluation.Reason = evaluation.Alert ? "multi-signal behavior chain" : "score below threshold";
                return evaluation;
            }

            private static bool EvaluateTechniqueRequirements(UserHookBehaviorRule rule, List<UserHookBehaviorAtom> candidates, HashSet<string> matchedActions, BehaviorMatchEvaluation evaluation)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);

                if (id.IndexOf("remote-dll-injection", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!HasActionLike(matchedActions, "process-access") &&
                        !HasActionLike(matchedActions, "thread-access"))
                    {
                        evaluation.Reason = "missing target process or thread access";
                        return false;
                    }

                    if (!candidates.Any(IsRemoteDllPathWriteAtom) && !HasActionLike(matchedActions, "dll-path-write"))
                    {
                        evaluation.Reason = "missing remote DLL path write";
                        return false;
                    }

                    if (!candidates.Any(IsRemoteExecutionAtom))
                    {
                        evaluation.Reason = "missing remote execution trigger";
                        return false;
                    }

                    evaluation.AttackStory = "目标进程被打开后写入 DLL 路径，并通过远程线程/NtCreateThreadEx 触发加载。";
                    evaluation.Reason = "remote DLL injection chain";
                    evaluation.Score += 50;
                    return true;
                }

                if (id.IndexOf("shellcode-injection", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    string.Equals(id, "dp.behavior.injection-chain", StringComparison.OrdinalIgnoreCase))
                {
                    if (!candidates.Any(item => item.EvidenceClass == "memory" || IsRemotePayloadWriteAtom(item)) &&
                        !HasActionLike(matchedActions, "executable-memory") &&
                        !HasActionLike(matchedActions, "pe-image-write"))
                    {
                        evaluation.Reason = "missing remote executable memory or PE payload write";
                        return false;
                    }

                    if (!candidates.Any(item => item.EvidenceClass == "write" || IsRemotePayloadWriteAtom(item)) &&
                        !HasActionLike(matchedActions, "write-memory") &&
                        !HasActionLike(matchedActions, "dll-path-write") &&
                        !HasActionLike(matchedActions, "pe-image-write"))
                    {
                        evaluation.Reason = "missing remote memory write";
                        return false;
                    }

                    if (!candidates.Any(IsRemoteExecutionAtom))
                    {
                        evaluation.Reason = "missing remote execution trigger";
                        return false;
                    }

                    evaluation.AttackStory = "目标进程内出现远程内存准备、载荷写入和远程执行触发，形成注入闭环。";
                    evaluation.Reason = "remote payload injection chain";
                    evaluation.Score += 40;
                    return true;
                }

                if (id.IndexOf("process-hollowing", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.Action.IndexOf("suspended-process-create", StringComparison.OrdinalIgnoreCase) >= 0) ||
                        !candidates.Any(item => item.Action.IndexOf("nt-unmap-view", StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!candidates.Any(item => item.EvidenceClass == "write" || IsRemotePayloadWriteAtom(item)) && !HasActionLike(matchedActions, "write-memory")) ||
                        !candidates.Any(item => item.Action.IndexOf("set-thread-context", StringComparison.OrdinalIgnoreCase) >= 0) ||
                        !candidates.Any(item => item.Action.IndexOf("resume-thread", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        evaluation.Reason = "missing hollowing stage";
                        return false;
                    }

                    evaluation.AttackStory = "进程被挂起创建后卸载原始映像、写入新载荷、改写线程上下文并恢复执行。";
                    evaluation.Reason = "process hollowing chain";
                    evaluation.Score += 45;
                    return true;
                }

                if (id.IndexOf("apc", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.EvidenceClass == "apc"))
                    {
                        evaluation.Reason = "missing APC queue";
                        return false;
                    }

                    if (!candidates.Any(item => item.EvidenceClass == "write" || item.EvidenceClass == "memory" || IsRemotePayloadWriteAtom(item)))
                    {
                        evaluation.Reason = "missing remote memory preparation before APC";
                        return false;
                    }

                    if (!candidates.Any(item => item.Action.IndexOf("thread-access", StringComparison.OrdinalIgnoreCase) >= 0) &&
                        !candidates.Any(item => item.Action.IndexOf("process-access", StringComparison.OrdinalIgnoreCase) >= 0) &&
                        !candidates.Any(item => item.IsCrossProcess && (item.EvidenceClass == "write" || item.EvidenceClass == "memory")))
                    {
                        evaluation.Reason = "missing cross-process target context before APC";
                        return false;
                    }

                    evaluation.AttackStory = "远程内存准备或载荷写入后向目标线程排队 APC，符合 APC 注入流程。";
                    evaluation.Reason = "APC injection chain";
                    evaluation.Score += 35;
                    return true;
                }

                if (id.IndexOf("thread-hijack", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.Action.IndexOf("thread-access", StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!candidates.Any(item => item.EvidenceClass == "write" || IsRemotePayloadWriteAtom(item)) && !HasActionLike(matchedActions, "write-memory")) ||
                        !candidates.Any(item => item.Action.IndexOf("set-thread-context", StringComparison.OrdinalIgnoreCase) >= 0) ||
                        !candidates.Any(item => item.Action.IndexOf("resume-thread", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        evaluation.Reason = "missing thread hijack stage";
                        return false;
                    }

                    evaluation.AttackStory = "目标线程被获取后写入载荷、改写线程上下文并恢复执行，符合线程劫持注入。";
                    evaluation.Reason = "thread hijacking chain";
                    evaluation.Score += 40;
                    return true;
                }

                if (id.IndexOf("ntdll-reload-bypass", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.Action.IndexOf("sensitive-image-reload", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                item.Action.IndexOf("sensitive-image-abnormal-path", StringComparison.OrdinalIgnoreCase) >= 0) &&
                        !candidates.Any(item => item.Action.IndexOf("syscall", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                item.Action.IndexOf("unhook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                item.Action.IndexOf("hook-overwrite", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        evaluation.Reason = "missing sensitive module reload or hook bypass evidence";
                        return false;
                    }

                    evaluation.AttackStory = "敏感系统模块重载/异常路径加载与 Hook 篡改或 syscall 绕过信号同窗出现。";
                    evaluation.Reason = "module reload and hook bypass chain";
                    evaluation.Score += 35;
                    return true;
                }

                if (id.IndexOf("script-download-execute", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.EvidenceClass == "process" && IsScriptInterpreterProcess(item) && HasScriptDownloadIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing script download or encoded execution intent";
                        return false;
                    }

                    evaluation.AttackStory = "脚本解释器带下载、解码或 IEX 执行参数启动，并出现外联或远程脚本语义。";
                    evaluation.Reason = "script download execution chain";
                    evaluation.Score += candidates.Any(item => item.EvidenceClass == "network") ? 35 : 20;
                    return true;
                }

                if (id.IndexOf("script-network", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.EvidenceClass == "process" && IsScriptInterpreterProcess(item)))
                    {
                        evaluation.Reason = "missing script interpreter process";
                        return false;
                    }

                    if (!candidates.Any(item => item.EvidenceClass == "network") && !candidates.Any(item => HasPublicNetworkIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing network activity";
                        return false;
                    }

                    evaluation.AttackStory = "脚本解释器启动后同进程出现外联，符合脚本型下载/控制链。";
                    evaluation.Reason = "script interpreter network chain";
                    evaluation.Score += 25;
                    return true;
                }

                if (id.IndexOf("lolbin-download-exec", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(IsLolbinProcessAtom))
                    {
                        evaluation.Reason = "missing LOLBin process";
                        return false;
                    }

                    if (!candidates.Any(item => HasLolbinDownloadIntent(GetAtomText(item))) &&
                        !candidates.Any(item => item.EvidenceClass == "network"))
                    {
                        evaluation.Reason = "missing download or network intent";
                        return false;
                    }

                    evaluation.AttackStory = "系统自带工具带下载/代理执行参数启动，并伴随外联或远程资源语义。";
                    evaluation.Reason = "LOLBIN download execution chain";
                    evaluation.Score += 30;
                    return true;
                }

                if (id.IndexOf("credential-dump", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsCredentialIntent(GetAtomText(item)) || IsLsassSensitiveAccess(item)))
                    {
                        evaluation.Reason = "missing credential target or dump intent";
                        return false;
                    }

                    evaluation.AttackStory = "进程访问 LSASS/凭据文件或执行 procdump、comsvcs、reg save、Mimikatz 语义命令。";
                    evaluation.Reason = "credential dumping chain";
                    evaluation.Score += candidates.Any(IsLsassSensitiveAccess) ? 45 : 30;
                    return true;
                }

                if (id.IndexOf("defense-impairment", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsDefenseImpairmentIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing defense impairment intent";
                        return false;
                    }

                    evaluation.AttackStory = "进程尝试关闭安全服务、添加排除项、清理日志或削弱系统遥测。";
                    evaluation.Reason = "defense impairment chain";
                    evaluation.Score += 35;
                    return true;
                }

                if (id.IndexOf("service-persistence", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsServicePersistenceIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing service persistence intent";
                        return false;
                    }

                    evaluation.AttackStory = "创建或修改自动启动服务，具备服务型持久化特征。";
                    evaluation.Reason = "service persistence chain";
                    evaluation.Score += 30;
                    return true;
                }

                if (id.IndexOf("scheduled-task", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsScheduledTaskIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing scheduled task creation intent";
                        return false;
                    }

                    evaluation.AttackStory = "创建计划任务用于定时或登录自启动执行。";
                    evaluation.Reason = "scheduled task persistence chain";
                    evaluation.Score += 25;
                    return true;
                }

                if (id.IndexOf("lateral-tool", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsLateralMovementIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing remote execution or lateral movement intent";
                        return false;
                    }

                    evaluation.AttackStory = "远程管理/执行工具带远程主机、WMI、SMB、WinRM 或远程服务参数启动。";
                    evaluation.Reason = "lateral movement execution chain";
                    evaluation.Score += candidates.Any(item => item.EvidenceClass == "network") ? 35 : 25;
                    return true;
                }

                if (id.IndexOf("ransomware-impact", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsRecoveryInhibitIntent(GetAtomText(item)) || ContainsRansomwareImpactIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing ransomware impact preparation intent";
                        return false;
                    }

                    evaluation.AttackStory = "删除影子副本、关闭恢复、清理日志或破坏备份，符合勒索前置行为。";
                    evaluation.Reason = "ransomware impact preparation chain";
                    evaluation.Score += 35;
                    return true;
                }

                if (id.IndexOf("archive-exfil", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => ContainsArchiveIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing archive collection intent";
                        return false;
                    }

                    if (!candidates.Any(item => item.EvidenceClass == "network" || HasPublicNetworkIntent(GetAtomText(item))))
                    {
                        evaluation.Reason = "missing exfiltration network context";
                        return false;
                    }

                    evaluation.AttackStory = "归档工具或脚本压缩用户数据后出现外联，符合收集后外传链。";
                    evaluation.Reason = "archive and exfiltration chain";
                    evaluation.Score += 25;
                    return true;
                }

                if (id.IndexOf("user-writable-dll-load", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!candidates.Any(item => item.EvidenceClass == "module" && IsUserWritablePath(item.Target) && item.Target.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        evaluation.Reason = "missing user-writable DLL load";
                        return false;
                    }

                    evaluation.AttackStory = "进程从用户可写目录加载 DLL，可能是 DLL 劫持、侧载或投递后加载。";
                    evaluation.Reason = "user-writable DLL load";
                    evaluation.Score += 20;
                    return true;
                }

                return true;
            }

            private static bool IsRelatedBehaviorScope(UserHookBehaviorRule rule, UserHookBehaviorAtom anchor, UserHookBehaviorAtom candidate)
            {
                if (!string.Equals(anchor.Host, candidate.Host, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (IsProcessHollowingRule(rule))
                {
                    if (string.Equals(anchor.ProcessKey, candidate.ProcessKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    if (!string.IsNullOrWhiteSpace(anchor.ParentProcessKey) &&
                        string.Equals(anchor.ParentProcessKey, candidate.ProcessKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    if (!string.IsNullOrWhiteSpace(candidate.ParentProcessKey) &&
                        string.Equals(candidate.ParentProcessKey, anchor.ProcessKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                if (RuleRequiresCrossProcess(rule))
                {
                    if (!string.Equals(anchor.ProcessKey, candidate.ProcessKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    if (string.IsNullOrWhiteSpace(anchor.TargetPid) || string.IsNullOrWhiteSpace(candidate.TargetPid))
                    {
                        return true;
                    }

                    return string.Equals(anchor.TargetPid, candidate.TargetPid, StringComparison.OrdinalIgnoreCase);
                }

                if (string.Equals(anchor.ProcessKey, candidate.ProcessKey, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                return !string.IsNullOrWhiteSpace(anchor.ParentProcessKey) &&
                       string.Equals(anchor.ParentProcessKey, candidate.ProcessKey, StringComparison.OrdinalIgnoreCase);
            }

            private static string BuildScopeKey(UserHookBehaviorRule rule, UserHookBehaviorAtom atom)
            {
                if (IsProcessHollowingRule(rule))
                {
                    return atom.ProcessKey;
                }

                if (RuleRequiresCrossProcess(rule))
                {
                    return atom.ProcessKey + "->" + FirstNonEmpty(atom.TargetPid, atom.Target, "unknown-target");
                }

                return atom.ProcessKey;
            }

            private static bool IsProcessHollowingRule(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("process-hollowing", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool IsHighConfidenceSingleEventRule(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("telemetry-impairment", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("recovery-inhibit", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool RuleRequiresCrossProcess(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("injection", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("hollow", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("apc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("thread-hijack", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool RuleRequiresSuspiciousContext(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("lolbin", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-download", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("office-script", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("persistence", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("defense-impairment", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("lateral-tool", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("ransomware", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("archive-exfil", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool RuleRequiresEtwPatchEvidence(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("telemetry-impairment", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool RuleRequiresExplicitMaliciousIntent(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("persistence", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("recovery-inhibit", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("lolbin", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-download", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("defense-impairment", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("lateral-tool", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("ransomware", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("archive-exfil", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("service-persistence", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("scheduled-task", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("user-writable-dll-load", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool RuleRequiresExecutableMemoryContext(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("manual-map", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("hook-bypass", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool IsVerifiedEtwTamperAtom(UserHookBehaviorAtom atom)
            {
                string action = atom == null ? string.Empty : (atom.Action ?? string.Empty);
                return action.IndexOf("etw-prepatched-detected", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("etw-return-patch-detected", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("etw-jump-patch-detected", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool HasExplicitMaliciousIntent(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return false;
                }

                return atom.HasSuspiciousCommand ||
                       atom.Blocked ||
                       ContainsCredentialIntent(atom.CommandLine) ||
                       ContainsCredentialIntent(atom.Target) ||
                       ContainsPersistenceIntent(atom.CommandLine) ||
                       ContainsPersistenceIntent(atom.Target) ||
                       ContainsRecoveryInhibitIntent(atom.CommandLine) ||
                       ContainsRecoveryInhibitIntent(atom.Target) ||
                       ContainsDefenseImpairmentIntent(atom.CommandLine) ||
                       ContainsDefenseImpairmentIntent(atom.Target) ||
                       ContainsScriptDownloadIntent(atom.CommandLine) ||
                       ContainsScriptDownloadIntent(atom.Target) ||
                       ContainsLateralMovementIntent(atom.CommandLine) ||
                       ContainsLateralMovementIntent(atom.Target) ||
                       ContainsRansomwareImpactIntent(atom.CommandLine) ||
                       ContainsRansomwareImpactIntent(atom.Target) ||
                       ContainsArchiveIntent(atom.CommandLine) ||
                       ContainsArchiveIntent(atom.Target) ||
                       HasPublicNetworkIntent(atom.CommandLine) ||
                       HasPublicNetworkIntent(atom.Target);
            }

            private static bool HasStrongExecutableMemoryEvidence(UserHookBehaviorAtom atom)
            {
                string action = atom == null ? string.Empty : (atom.Action ?? string.Empty);
                return action.IndexOf("memory-manual-map", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("memory-private-executable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("memory-private-syscall-stub", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("syscall-bypass", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("unhook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       action.IndexOf("hook-overwrite", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool HasActionLike(HashSet<string> actions, string normalizedAction)
            {
                if (actions == null || string.IsNullOrWhiteSpace(normalizedAction))
                {
                    return false;
                }

                return actions.Any(action => string.Equals(NormalizeActionAtom(action), normalizedAction, StringComparison.OrdinalIgnoreCase));
            }

            private static bool IsRemoteDllPathWriteAtom(UserHookBehaviorAtom atom)
            {
                return atom != null &&
                       atom.IsCrossProcess &&
                       atom.Action.IndexOf("remote-dll-path-write", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool IsRemotePayloadWriteAtom(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return false;
                }

                return atom.Action.IndexOf("remote-dll-path-write", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       atom.Action.IndexOf("remote-pe-image-write", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool IsRemoteExecutionAtom(UserHookBehaviorAtom atom)
            {
                if (atom == null || !atom.IsCrossProcess)
                {
                    return false;
                }

                return atom.EvidenceClass == "execute" ||
                       atom.Action.IndexOf("remote-thread-create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       atom.Action.IndexOf("create-remote-thread", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       atom.Action.IndexOf("nt-create-thread-ex", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static string GetAtomText(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return string.Empty;
                }

                return (atom.Action ?? string.Empty) + " " +
                       (atom.ProcessImage ?? string.Empty) + " " +
                       (atom.Target ?? string.Empty) + " " +
                       (atom.CommandLine ?? string.Empty) + " " +
                       (atom.ParentImage ?? string.Empty);
            }

            private static bool IsScriptInterpreterProcess(UserHookBehaviorAtom atom)
            {
                string name = ExtractFileName(FirstNonEmpty(atom == null ? string.Empty : atom.ProcessImage, atom == null ? string.Empty : atom.Target));
                string text = GetAtomText(atom);
                string[] names = { "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe" };
                return names.Any(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase)) ||
                       names.Any(item => text.IndexOf(item, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool IsLolbinProcessAtom(UserHookBehaviorAtom atom)
            {
                string name = ExtractFileName(FirstNonEmpty(atom == null ? string.Empty : atom.ProcessImage, atom == null ? string.Empty : atom.Target));
                string text = GetAtomText(atom);
                string[] names =
                {
                    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
                    "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "powershell.exe", "pwsh.exe",
                    "msbuild.exe", "forfiles.exe", "mshta.exe", "odbcconf.exe"
                };

                return names.Any(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase)) ||
                       names.Any(item => text.IndexOf(item, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool IsLsassSensitiveAccess(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return false;
                }

                string text = GetAtomText(atom);
                if (text.IndexOf("lsass", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }

                int access = ExtractHexInt(atom.Target, "access=");
                if (access == 0)
                {
                    return atom.Action.IndexOf("process-access", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                const int vmRead = 0x00000010;
                const int dupHandle = 0x00000040;
                const int queryInfo = 0x00000400;
                const int queryLimited = 0x00001000;
                return (access & (vmRead | dupHandle | queryInfo | queryLimited)) != 0;
            }

            private static bool HasPlausibleOrder(List<UserHookBehaviorAtom> candidates)
            {
                if (candidates == null || candidates.Count < 2)
                {
                    return true;
                }

                int processIndex = candidates.FindIndex(item => item.EvidenceClass == "process");
                int memoryIndex = candidates.FindIndex(item => item.EvidenceClass == "memory");
                int writeIndex = candidates.FindIndex(item => item.EvidenceClass == "write");
                int executeIndex = candidates.FindIndex(item => item.EvidenceClass == "execute");
                int apcIndex = candidates.FindIndex(item => item.EvidenceClass == "apc");

                if (writeIndex >= 0 && executeIndex >= 0 && writeIndex > executeIndex)
                {
                    return false;
                }

                if (memoryIndex >= 0 && executeIndex >= 0 && memoryIndex > executeIndex)
                {
                    return false;
                }

                if (processIndex >= 0 && executeIndex >= 0 && processIndex > executeIndex)
                {
                    return false;
                }

                if (writeIndex >= 0 && apcIndex >= 0 && writeIndex > apcIndex)
                {
                    return false;
                }

                return true;
            }

            private static bool AtomMatchesRule(UserHookBehaviorRule rule, UserHookBehaviorAtom atom)
            {
                if (!MatchesAction(rule.actions, atom.Action) && !MatchesAction(rule.anyActions, atom.Action))
                {
                    return false;
                }

                if (RuleUsesTechniqueLevelFiltering(rule))
                {
                    return true;
                }

                if (!MatchesOptionalList(rule.processNames, atom.ProcessImage) &&
                    !MatchesOptionalList(rule.processNames, atom.Target) &&
                    !MatchesOptionalList(rule.processNames, atom.CommandLine))
                {
                    return false;
                }

                if (!MatchesOptionalList(rule.parentProcessNames, atom.ParentImage))
                {
                    return false;
                }

                if (!ContainsOptionalToken(rule.targetContains, atom.Target))
                {
                    return false;
                }

                if (!ContainsOptionalToken(rule.commandLineContains, atom.CommandLine))
                {
                    return false;
                }

                return true;
            }

            private static bool RuleUsesTechniqueLevelFiltering(UserHookBehaviorRule rule)
            {
                string id = rule == null ? string.Empty : (rule.ruleId ?? string.Empty);
                return id.IndexOf("lolbin", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("script-download", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("defense-impairment", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("service-persistence", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("scheduled-task", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("lateral-tool", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("ransomware", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("archive-exfil", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       id.IndexOf("user-writable-dll-load", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool MatchesAction(string[] actions, string action)
            {
                if (actions == null || actions.Length == 0)
                {
                    return false;
                }

                return actions.Any(item => ActionEquivalent(item, action));
            }

            private static bool ActionEquivalent(string expected, string actual)
            {
                string left = NormalizeActionAtom(expected);
                string right = NormalizeActionAtom(actual);
                return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
            }

            private static string NormalizeActionAtom(string action)
            {
                string value = (action ?? string.Empty).Trim().ToLowerInvariant();
                if (value.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase))
                {
                    value = value.Substring("userhook.".Length);
                }

                if (value.StartsWith("observed.", StringComparison.OrdinalIgnoreCase))
                {
                    value = value.Substring("observed.".Length);
                }

                if (value.StartsWith("blocked.", StringComparison.OrdinalIgnoreCase))
                {
                    value = value.Substring("blocked.".Length);
                }

                value = value.Replace("nt-", string.Empty);
                value = value.Replace("behavior-", string.Empty);
                value = value.Replace("-ex", string.Empty);
                value = value.Replace("-", string.Empty);

                if (value == "createremotethread" || value == "remotethreadcreate" || value == "createthread")
                {
                    return "remote-thread";
                }

                if (value == "createremotethread" || value == "createremotethreadex" || value == "ntcreatethreadex")
                {
                    return "remote-thread";
                }

                if (value == "writeprocessmemory" || value == "writevirtualmemory")
                {
                    return "write-memory";
                }

                if (value == "writeprocessmemory" || value == "ntwritevirtualmemory")
                {
                    return "write-memory";
                }

                if (value == "remotedllpathwrite")
                {
                    return "dll-path-write";
                }

                if (value == "remotepeimagewrite")
                {
                    return "pe-image-write";
                }

                if (value == "remoteexecutablememory" || value == "allocateexecutablememory" || value == "protectexecutablememory")
                {
                    return "executable-memory";
                }

                if (value == "virtualallocex" || value == "virtualprotectex" || value == "ntallocatevirtualmemory" || value == "ntprotectvirtualmemory")
                {
                    return "executable-memory";
                }

                if (value == "queueuserapc")
                {
                    return "queue-apc";
                }

                if (value == "processaccess")
                {
                    return "process-access";
                }

                if (value == "threadaccess")
                {
                    return "thread-access";
                }

                return value;
            }

            private static bool MatchesOptionalList(string[] values, string source)
            {
                if (values == null || values.Length == 0)
                {
                    return true;
                }

                string name = ExtractFileName(source);
                return values.Any(item =>
                    string.Equals(item, name, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrWhiteSpace(source) && source.IndexOf(item, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            private static bool ContainsOptionalToken(string[] tokens, string source)
            {
                if (tokens == null || tokens.Length == 0)
                {
                    return true;
                }

                if (string.IsNullOrWhiteSpace(source))
                {
                    return false;
                }

                return tokens.Any(token => source.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static string ExtractFileName(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return string.Empty;
                }

                try
                {
                    return Path.GetFileName(value.Trim().Trim('"'));
                }
                catch
                {
                    return value;
                }
            }

            private static bool TryBuildAtom(AuditLog.AuditRecord record, out UserHookBehaviorAtom atom)
            {
                DateTime timestamp;
                atom = null;
                if (record == null || string.IsNullOrWhiteSpace(record.Action))
                {
                    return false;
                }

                if (!record.Action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (IsUserHookCoverageAction(record.Action) ||
                    string.Equals(record.ObjectType, "sensor-health", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (!DateTime.TryParse(record.TimestampUtc, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out timestamp))
                {
                    timestamp = DateTime.UtcNow;
                }

                atom = new UserHookBehaviorAtom
                {
                    TimestampUtc = timestamp.ToUniversalTime(),
                    Host = record.Host ?? Environment.MachineName,
                    Action = record.Action ?? string.Empty,
                    Target = record.Target ?? string.Empty,
                    ProcessImage = FirstNonEmpty(record.SourceProcess, record.Extension),
                    CommandLine = FirstNonEmpty(ExtractMessageField(record.Message, "Command: "), record.Message),
                    ParentImage = ExtractMessageField(record.Message, "Parent: "),
                    ProcessPid = FirstNonEmpty(record.SourcePid, ExtractPid(record.Message)),
                    TargetPid = record.TargetPid ?? string.Empty,
                    Status = record.Status ?? string.Empty,
                    Blocked = string.Equals(record.Disposition, "blocked", StringComparison.OrdinalIgnoreCase) ||
                              (record.Action ?? string.Empty).IndexOf(".blocked.", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              string.Equals(record.Status, "0xC0000022", StringComparison.OrdinalIgnoreCase)
                };
                atom.ProcessKey = string.IsNullOrWhiteSpace(atom.ProcessImage)
                    ? atom.Host + "|" + ExtractPid(record.Message)
                    : atom.Host + "|" + FirstNonEmpty(atom.ProcessPid, atom.ProcessImage);
                atom.ParentProcessKey = string.IsNullOrWhiteSpace(atom.ParentImage) ? string.Empty : atom.Host + "|" + atom.ParentImage;
                atom.EvidenceClass = ClassifyEvidenceClass(atom);
                atom.IsCrossProcess = IsCrossProcessAtom(atom);
                atom.IsSuspiciousProcess = IsSuspiciousProcess(atom.ProcessImage) || IsSuspiciousProcess(atom.Target) || IsSuspiciousProcess(atom.CommandLine);
                atom.HasSuspiciousCommand = HasSuspiciousCommand(atom.CommandLine) || HasSuspiciousCommand(atom.Target);
                atom.IsUserWritableProcess = IsUserWritablePath(atom.ProcessImage) || IsUserWritablePath(atom.Target) || IsUserWritablePath(atom.CommandLine);
                atom.IsBenignSystemActivity = IsBenignSystemActivity(atom);
                atom.RiskScore = ComputeAtomRisk(atom);
                return true;
            }

            private static string ClassifyEvidenceClass(UserHookBehaviorAtom atom)
            {
                string action = atom == null ? string.Empty : (atom.Action ?? string.Empty);
                string api = (atom == null ? string.Empty : (atom.Target ?? string.Empty)) + " " + (atom == null ? string.Empty : (atom.CommandLine ?? string.Empty));

                if (action.IndexOf("write-process-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-write-virtual-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("remote-dll-path-write", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("remote-pe-image-write", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "write";
                }

                if (action.IndexOf("remote-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("allocate-executable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("protect-executable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("memory-rwx", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("memory-private-executable", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "memory";
                }

                if (action.IndexOf("remote-thread", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-create-thread-ex", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "execute";
                }

                if (action.IndexOf("queue-user-apc", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "apc";
                }

                if (action.IndexOf("set-thread-context", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("resume-thread", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("nt-unmap-view", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "thread";
                }

                if (action.IndexOf("process-create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    api.IndexOf("CreateProcess", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "process";
                }

                if (action.IndexOf("network-connect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("network-wsaconnect", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "network";
                }

                if (action.IndexOf("registry-set-value", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "registry";
                }

                if (action.IndexOf("load-library", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("manual-map", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "module";
                }

                if (action.IndexOf("etw", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("unhook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("hook-overwrite", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    action.IndexOf("syscall", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "evasion";
                }

                return "behavior";
            }

            private static bool IsCrossProcessAtom(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(atom.TargetPid))
                {
                if (atom.Action.IndexOf("process-create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    atom.Action.IndexOf("load-library", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    atom.Action.IndexOf("registry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    atom.Action.IndexOf("network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    atom.Action.IndexOf("windows-hook", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }

                    return atom.Action.IndexOf("remote", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           atom.Action.IndexOf("process-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           atom.Action.IndexOf("thread", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                return !string.Equals(atom.TargetPid, atom.ProcessPid, StringComparison.OrdinalIgnoreCase);
            }

            private static bool IsSuspiciousProcess(string value)
            {
                string name = ExtractFileName(value);
                string[] names =
                {
                    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe", "installutil.exe",
                    "regasm.exe", "regsvcs.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "reagentc.exe",
                    "schtasks.exe", "sc.exe", "psexec.exe", "paexec.exe", "procdump.exe", "reg.exe", "wevtutil.exe",
                    "auditpol.exe", "net.exe", "net1.exe", "winrs.exe", "7z.exe", "7za.exe", "rar.exe", "winrar.exe"
                };

                return names.Any(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase));
            }

            private static bool IsBenignBehaviorAtom(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return true;
                }

                if (atom.IsBenignSystemActivity)
                {
                    return true;
                }

                if ((atom.Action ?? string.Empty).IndexOf("create-hook-failed", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }

                if ((atom.Action ?? string.Empty).IndexOf("memory-rwx", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    !HasStrongExecutableMemoryEvidence(atom) &&
                    !atom.HasSuspiciousCommand)
                {
                    return true;
                }

                return false;
            }

            private static bool IsBenignSystemActivity(UserHookBehaviorAtom atom)
            {
                if (atom == null)
                {
                    return false;
                }

                string processName = ExtractFileName(atom.ProcessImage).ToLowerInvariant();
                string targetName = ExtractFileName(atom.Target).ToLowerInvariant();
                string text = ((atom.Target ?? string.Empty) + " " + (atom.CommandLine ?? string.Empty)).ToLowerInvariant();

                if (IsInternalTelemetryProcess(processName) || IsInternalTelemetryProcess(targetName) || IsInternalTelemetryText(text))
                {
                    return true;
                }

                if (IsKnownBenignWindowsServicePair(processName, targetName) &&
                    !IsRemoteExecutionAtom(atom) &&
                    !IsRemotePayloadWriteAtom(atom) &&
                    !HasExplicitMaliciousIntent(atom))
                {
                    return true;
                }

                if (IsBenignSystemProcess(processName) && IsQueryOnlyProcessAccess(atom) && !ContainsCredentialIntent(text))
                {
                    return true;
                }

                if (processName == "schtasks.exe" && targetName == "conhost.exe")
                {
                    return true;
                }

                if (processName == "conhost.exe" && (targetName == "cmd.exe" || targetName == "powershell.exe" || targetName == "schtasks.exe"))
                {
                    return true;
                }

                return false;
            }

            private static bool IsKnownBenignWindowsServicePair(string processName, string targetName)
            {
                if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(targetName))
                {
                    return false;
                }

                if (processName == "svchost.exe" &&
                    (targetName == "consent.exe" ||
                     targetName == "smartscreen.exe" ||
                     targetName == "explorer.exe" ||
                     targetName == "everything.exe"))
                {
                    return true;
                }

                if (processName == "searchindexer.exe" &&
                    (targetName == "searchfilterhost.exe" ||
                     targetName == "searchprotocolhost.exe" ||
                     targetName == "searchprotocol"))
                {
                    return true;
                }

                if (processName == "consent.exe" && targetName == "svchost.exe")
                {
                    return true;
                }

                return false;
            }

            private static bool IsQueryOnlyProcessAccess(UserHookBehaviorAtom atom)
            {
                string action = atom == null ? string.Empty : (atom.Action ?? string.Empty);
                if (action.IndexOf("process-access", StringComparison.OrdinalIgnoreCase) < 0 &&
                    action.IndexOf("thread-access", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }

                int access = ExtractHexInt(atom.Target, "access=");
                return access == 0x00001410 ||
                       access == 0x00001400 ||
                       access == 0x00001000 ||
                       access == 0x00000410 ||
                       access == 0x00001402;
            }

            private static bool IsBenignSystemProcess(string name)
            {
                string[] names =
                {
                    "wmiprvse.exe", "wmiadap.exe", "wmiapsrv.exe", "svchost.exe", "explorer.exe", "conhost.exe",
                    "taskhostw.exe", "dllhost.exe", "runtimebroker.exe", "searchhost.exe", "sihost.exe", "ctfmon.exe",
                    "fontdrvhost.exe", "dwm.exe", "spoolsv.exe", "wudfhost.exe", "smartscreen.exe"
                };

                return names.Any(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase));
            }

            private static bool IsInternalTelemetryProcess(string name)
            {
                return name.IndexOf("dataprotectorsandbox", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       name.IndexOf("dataprotectors", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       name.IndexOf("dataprotectorwebbridge", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       name.IndexOf("dataprotectoragentclient", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       name.IndexOf("dataprotectorwebadmin", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static bool IsInternalTelemetryText(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string text = value.ToLowerInvariant();
                return text.Contains("dataprotectorsandbox") ||
                       text.Contains("dataprotectors") ||
                       text.Contains("dataprotectoruserhookruntime") ||
                       text.Contains("dataprotectorwebbridge") ||
                       text.Contains("dataprotectoragentclient") ||
                       text.Contains("dataprotectorpolicyapi") ||
                       text.Contains("runtime-injection-queued") ||
                       text.Contains("runtime-injection-skipped") ||
                       text.Contains("hook-surface-image-load");
            }

            private static bool HasSuspiciousCommand(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "-enc", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression", " iex ",
                    "http://", "https://", "urlcache", "scrobj.dll", "javascript:", "vbscript:", "delete shadows",
                    "shadowcopy delete", "resize shadowstorage", "wbadmin delete", "recoveryenabled no",
                    "bootstatuspolicy ignoreallfailures", "currentversion\\run", "\\runonce", "schtasks", "/create",
                    "sc create", "new-service", "virtualallocex", "writeprocessmemory", "createremotethread"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) ||
                       ContainsCredentialIntent(value) ||
                       ContainsPersistenceIntent(value) ||
                       ContainsRecoveryInhibitIntent(value) ||
                       ContainsDefenseImpairmentIntent(value) ||
                       ContainsScriptDownloadIntent(value) ||
                       ContainsLateralMovementIntent(value) ||
                       ContainsRansomwareImpactIntent(value);
            }

            private static bool HasScriptDownloadIntent(string value)
            {
                return ContainsScriptDownloadIntent(value);
            }

            private static bool ContainsScriptDownloadIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
                    "invoke-webrequest", "invoke-restmethod", " iwr ", " irm ", "curl ", "wget ",
                    "invoke-expression", " iex ", "http://", "https://", "javascript:", "vbscript:",
                    "mshta", "regsvr32", "scrobj.dll", "/i:", "rundll32"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool HasLolbinDownloadIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "urlcache", "split", "decode", "download", "http://", "https://", "scrobj.dll",
                    "javascript:", "vbscript:", "/i:", "installutil", "regasm", "regsvcs", "mshta",
                    "rundll32", "regsvr32", "bitsadmin", "certutil"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsCredentialIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "sekurlsa", "lsadump", "privilege::debug", "token::", "vault::", "kerberos::",
                    "hklm\\sam", "hklm\\system", "hklm\\security", "reg save hklm\\sam", "reg save hklm\\system",
                    "ntds.dit", "lsass", "comsvcs.dll", "minidump", "procdump"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsPersistenceIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "currentversion\\run", "\\runonce", "startup", "schtasks /create", "schtasks.exe /create",
                    " /create ", "sc create", "new-service", "create service", "start= auto", "autostart"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsServicePersistenceIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "sc create", "sc.exe create", "new-service", "create service", "start= auto",
                    "binpath=", "\\services\\", "imagepath", "service control", "servicemain"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsScheduledTaskIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "schtasks /create", "schtasks.exe /create", "new-scheduledtask", "register-scheduledtask",
                    " /sc ", " /tn ", " /tr ", " /ru ", "\\tasks\\"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsRecoveryInhibitIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "delete shadows", "shadowcopy delete", "resize shadowstorage", "wbadmin delete",
                    "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "reagentc /disable"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsDefenseImpairmentIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "set-mppreference", "disablerealtimemonitoring", "disableantispyware", "add-mppreference",
                    "exclusionpath", "windefend", "sc stop", "sc config", "net stop", "wevtutil cl",
                    "auditpol /clear", "tamperprotection", "defender", "securityhealthservice", "eventlog",
                    "sysmon", "dataprotector", "disablebehavior monitoring", "disablescriptscanning"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsLateralMovementIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "\\\\", "/node:", "process call create", "wmic ", "psexec", "paexec", "winrs",
                    "invoke-command", "enter-pssession", "new-pssession", "sc \\\\", "schtasks /s",
                    " /s ", "admin$", "ipc$", "remote service", "smbexec", "wmiexec"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsRansomwareImpactIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "delete shadows", "shadowcopy delete", "resize shadowstorage", "wbadmin delete",
                    "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "reagentc /disable",
                    "wevtutil cl", "cipher /w", "vssadmin", "bcdedit", "fsutil usn deletejournal"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool ContainsArchiveIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string[] tokens =
                {
                    "compress-archive", ".zip", ".rar", ".7z", " 7z", "7za", "winrar", "rar a",
                    "tar -", "makecab", "documents", "desktop", "downloads", "users\\", "appdata"
                };

                return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            private static bool HasPublicNetworkIntent(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string text = value.ToLowerInvariant();
                return (text.Contains("http://") || text.Contains("https://")) &&
                       !text.Contains("localhost") &&
                       !text.Contains("127.0.0.1") &&
                       !text.Contains("192.168.") &&
                       !text.Contains("10.");
            }

            private static bool IsUserWritablePath(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                string text = value.Trim().Trim('"');
                string lower = text.ToLowerInvariant();
                return lower.IndexOf("\\users\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       lower.IndexOf("\\appdata\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       lower.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       lower.IndexOf("\\programdata\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       lower.IndexOf("\\downloads\\", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private static int ComputeAtomRisk(UserHookBehaviorAtom atom)
            {
                int score = 0;
                if (atom == null)
                {
                    return score;
                }

                switch (atom.EvidenceClass)
                {
                    case "write":
                    case "memory":
                    case "execute":
                    case "evasion":
                        score += 25;
                        break;
                    case "thread":
                    case "module":
                        score += 18;
                        break;
                    case "process":
                    case "network":
                    case "registry":
                        score += 12;
                        break;
                    default:
                        score += 5;
                        break;
                }

                if (atom.Blocked) score += 25;
                if (atom.IsCrossProcess) score += 12;
                if (atom.IsSuspiciousProcess) score += 10;
                if (atom.HasSuspiciousCommand) score += 14;
                if (atom.IsUserWritableProcess) score += 8;
                return score;
            }

            private static string ExtractMessageField(string message, string prefix)
            {
                int index;
                int end;
                if (string.IsNullOrWhiteSpace(message) || string.IsNullOrWhiteSpace(prefix))
                {
                    return string.Empty;
                }

                index = message.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
                if (index < 0)
                {
                    return string.Empty;
                }

                index += prefix.Length;
                end = message.IndexOf(".", index, StringComparison.Ordinal);
                if (end < 0)
                {
                    end = message.Length;
                }

                return message.Substring(index, end - index).Trim();
            }

            private static string ExtractPid(string message)
            {
                string value = ExtractMessageField(message, "PID ");
                return string.IsNullOrWhiteSpace(value) ? "unknown" : value;
            }

            private static int ExtractHexInt(string text, string prefix)
            {
                if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prefix))
                {
                    return 0;
                }

                int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
                if (index < 0)
                {
                    return 0;
                }

                index += prefix.Length;
                int end = text.IndexOf(' ', index);
                if (end < 0)
                {
                    end = text.Length;
                }

                string value = text.Substring(index, end - index).Trim();
                if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    value = value.Substring(2);
                }

                int parsed;
                return int.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed) ? parsed : 0;
            }

            private void TrimAtoms(DateTime now)
            {
                DateTime cutoff = now.AddHours(-1);
                atoms.RemoveAll(item => item.TimestampUtc < cutoff);
                if (atoms.Count > 2048)
                {
                    atoms.RemoveRange(0, atoms.Count - 2048);
                }
            }
        }

        private sealed class UserHookBehaviorAtom
        {
            public DateTime TimestampUtc { get; set; }
            public string Host { get; set; }
            public string Action { get; set; }
            public string Target { get; set; }
            public string ProcessImage { get; set; }
            public string CommandLine { get; set; }
            public string ParentImage { get; set; }
            public string ProcessKey { get; set; }
            public string ParentProcessKey { get; set; }
            public string ProcessPid { get; set; }
            public string TargetPid { get; set; }
            public string Status { get; set; }
            public string EvidenceClass { get; set; }
            public bool Blocked { get; set; }
            public bool IsCrossProcess { get; set; }
            public bool IsSuspiciousProcess { get; set; }
            public bool HasSuspiciousCommand { get; set; }
            public bool IsUserWritableProcess { get; set; }
            public bool IsBenignSystemActivity { get; set; }
            public int RiskScore { get; set; }
        }

        private sealed class BehaviorMatchEvaluation
        {
            public bool Alert { get; set; }
            public int Score { get; set; }
            public string Reason { get; set; }
            public string ScopeKey { get; set; }
            public string PrimaryProcess { get; set; }
            public string PrimaryTarget { get; set; }
            public string PrimaryTargetPid { get; set; }
            public string AttackStory { get; set; }
            public HashSet<string> EvidenceClasses { get; private set; }

            public BehaviorMatchEvaluation()
            {
                EvidenceClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Reason = string.Empty;
                ScopeKey = string.Empty;
                PrimaryProcess = string.Empty;
                PrimaryTarget = string.Empty;
                PrimaryTargetPid = string.Empty;
                AttackStory = string.Empty;
            }
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
            public bool? monitorRuntimeApiBehavior { get; set; }
            public bool? scanExecutableMemory { get; set; }
            public bool? monitorEtwTamper { get; set; }
            public string[] excludedProcessNames { get; set; }
            public string[] excludedProcessDirectories { get; set; }
            public string[] excludedProcessPaths { get; set; }
            public string[] trustedSignerSubjects { get; set; }
            public string runtimePath { get; set; }
            public UserHookBehaviorRule[] behaviorRules { get; set; }
            public string actor { get; set; }
        }

        public sealed class UserHookDefensePolicyDto : UserHookDefensePolicyRequest
        {
            public uint flags { get; set; }
        }

        public sealed class UserHookBehaviorRule
        {
            public string ruleId { get; set; }
            public string name { get; set; }
            public bool enabled { get; set; }
            public string[] actions { get; set; }
            public string[] anyActions { get; set; }
            public string[] processNames { get; set; }
            public string[] parentProcessNames { get; set; }
            public string[] targetContains { get; set; }
            public string[] commandLineContains { get; set; }
            public int windowSeconds { get; set; }
            public int threshold { get; set; }
            public int weight { get; set; }
            public string severity { get; set; }
            public string disposition { get; set; }
            public string tactic { get; set; }
            public string technique { get; set; }
            public string description { get; set; }
            public string[] references { get; set; }
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
            public string[] safeFolders { get; set; }
            public string actor { get; set; }
        }

        public sealed class DlpProtectionPolicyDto : DlpProtectionPolicyRequest
        {
        }

        public class FileHunterRuleRequest
        {
            public string directory { get; set; }
            public string actor { get; set; }
        }

        public sealed class FileHunterRuleDto : FileHunterRuleRequest
        {
        }

        public sealed class FileHunterDiagnosticsDto
        {
            public bool connected { get; set; }
            public string status { get; set; }
            public string message { get; set; }
            public string driverRuleStatus { get; set; }
            public string driverRuleMessage { get; set; }
            public int driverRuleCount { get; set; }
            public FileHunterRuleDto[] driverRules { get; set; }
            public int dlpSafeFolderCount { get; set; }
            public string[] dlpSafeFolders { get; set; }
            public string auditPath { get; set; }
            public int bridgePid { get; set; }
            public string machine { get; set; }
            public string note { get; set; }
        }

        public sealed class FileHunterEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public ulong bytesRead { get; set; }
            public ulong byteOffset { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public uint flags { get; set; }
            public string path { get; set; }
            public string processImage { get; set; }
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
