using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class CentralPolicyStore
    {
        private const int DefaultLimit = 200;
        private const int MaxIpInfoCacheEntries = 10000;
        private const int MaxIpInfoLookupsPerQuery = 12;
        private const string IpInfoTokenEnvironmentVariable = "DATAPROTECTOR_IPINFO_TOKEN";
        private const string LegacyIpInfoTokenEnvironmentVariable = "IPINFO_TOKEN";
        private const string IpInfoTokenFileName = "IpInfoToken.txt";
        private const string UsbCryptPackageDirectoryName = "UsbCryptPackages";
        private const string UsbCryptPackageFileName = "current.zip";
        private const string SandboxSampleDirectoryName = "SandboxSamples";
        private const string SandboxRunDirectoryName = "Sandbox";
        private const int MaxSandboxSampleBytes = 50 * 1024 * 1024;
        private const int MaxSandboxSampleRecords = 1000;
        private readonly object syncRoot = new object();
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly string filePath;
        private readonly Dictionary<string, string> volatileTaskArguments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly VirtualSandboxRunner sandboxRunner = new VirtualSandboxRunner();
        private CentralState state;

        public CentralPolicyStore()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            DirectoryPath = Path.Combine(dataRoot, "DataProtector");
            filePath = Path.Combine(DirectoryPath, "CentralState.json");
            state = Load();
        }

        public string DirectoryPath { get; private set; }

        public string FilePath
        {
            get { return filePath; }
        }

        public object GetStatus()
        {
            lock (syncRoot)
            {
                return new
                {
                    mode = "server",
                    connected = true,
                    status = "0x00000000",
                    message = "Central server is running.",
                    bridgePid = System.Diagnostics.Process.GetCurrentProcess().Id,
                    machine = Environment.MachineName,
                    user = Environment.UserName,
                    auditPath = filePath,
                    policyVersion = state.PolicyVersion,
                    hashProtectEnabled = QueryHashProtectPolicy().enabled,
                    lateralDefenseEnabled = QueryLateralDefensePolicy().enabled,
                    userHookDefenseEnabled = QueryUserHookDefensePolicy().enabled,
                    usbCryptEnabled = QueryUsbCryptPolicy().enabled,
                    deviceCount = state.Devices.Count,
                    onlineDeviceCount = state.Devices.Values.Count(IsOnline),
                    pendingTaskCount = state.Tasks.Count(task => task.status == "queued" || task.status == "sent"),
                    dlpProtectionEnabled = QueryDlpProtectionPolicy().enabled
                };
            }
        }

        public PolicyBridgeService.PolicyRuleDto[] QueryRules()
        {
            lock (syncRoot)
            {
                return state.Rules
                    .Select(CloneRule)
                    .OrderBy(rule => rule.extension, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(rule => rule.kind, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(rule => rule.value, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public PolicyBridgeService.NetworkRuleDto[] QueryNetworkRules()
        {
            lock (syncRoot)
            {
                return state.NetworkRules
                    .Select(CloneNetworkRule)
                    .OrderBy(rule => rule.ruleId)
                    .ToArray();
            }
        }

        public PolicyBridgeService.WebShellRuleDto[] QueryWebShellRules()
        {
            lock (syncRoot)
            {
                return state.WebShellRules
                    .Select(CloneWebShellRule)
                    .OrderBy(rule => rule.directory, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public PolicyBridgeService.DeviceRuleDto[] QueryDeviceRules()
        {
            lock (syncRoot)
            {
                return state.DeviceRules
                    .Select(CloneDeviceRule)
                    .OrderBy(rule => rule.deviceId, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public PolicyBridgeService.HashProtectPolicyDto QueryHashProtectPolicy()
        {
            lock (syncRoot)
            {
                EnsureHashProtectPolicy();
                return PolicyBridgeService.CloneHashProtectPolicy(state.HashProtectPolicy);
            }
        }

        public PolicyBridgeService.LateralDefensePolicyDto QueryLateralDefensePolicy()
        {
            lock (syncRoot)
            {
                EnsureLateralDefensePolicy();
                return PolicyBridgeService.CloneLateralDefensePolicy(state.LateralDefensePolicy);
            }
        }

        public PolicyBridgeService.UserHookDefensePolicyDto QueryUserHookDefensePolicy()
        {
            lock (syncRoot)
            {
                EnsureUserHookDefensePolicy();
                return PolicyBridgeService.CloneUserHookDefensePolicy(state.UserHookDefensePolicy);
            }
        }

        public PolicyBridgeService.UsbCryptPolicyDto QueryUsbCryptPolicy()
        {
            lock (syncRoot)
            {
                EnsureUsbCryptPolicy();
                return PolicyBridgeService.CloneUsbCryptPolicy(state.UsbCryptPolicy);
            }
        }

        public PolicyBridgeService.DlpProtectionPolicyDto QueryDlpProtectionPolicy()
        {
            lock (syncRoot)
            {
                EnsureDlpProtectionPolicy();
                return PolicyBridgeService.CloneDlpProtectionPolicy(state.DlpProtectionPolicy);
            }
        }

        public UsbCryptDriverPackageInfo QueryUsbCryptDriverPackage()
        {
            lock (syncRoot)
            {
                EnsureUsbCryptDriverPackage();
                return CloneUsbCryptDriverPackage(state.UsbCryptDriverPackage);
            }
        }

        public PolicyBridgeService.OperationResult SaveUsbCryptDriverPackage(UsbCryptDriverPackageUploadRequest request, string actor)
        {
            UsbCryptDriverPackageUploadRequest normalized = NormalizeUsbCryptDriverPackageUpload(request);
            byte[] packageBytes;
            try
            {
                packageBytes = Convert.FromBase64String(normalized.base64Package);
            }
            catch
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package must be a valid base64 zip payload.");
            }

            if (packageBytes.Length <= 0)
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package is empty.");
            }

            if (packageBytes.Length > 64 * 1024 * 1024)
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package exceeds the 64 MB server limit.");
            }

            ValidateUsbCryptPackageBytes(packageBytes);
            string sha256 = ComputeSha256Hex(packageBytes);
            string packagePath = GetUsbCryptPackagePath();
            Directory.CreateDirectory(Path.GetDirectoryName(packagePath));
            File.WriteAllBytes(packagePath, packageBytes);

            lock (syncRoot)
            {
                state.UsbCryptDriverPackage = new UsbCryptDriverPackageInfo
                {
                    configured = true,
                    version = normalized.version,
                    fileName = string.IsNullOrWhiteSpace(normalized.fileName) ? UsbCryptPackageFileName : normalized.fileName,
                    sha256 = sha256,
                    sizeBytes = packageBytes.Length,
                    uploadedUtc = DateTime.UtcNow.ToString("o"),
                    uploadedBy = string.IsNullOrWhiteSpace(actor) ? Environment.UserName : actor,
                    downloadPath = "/api/usbcrypt/driver-package/download"
                };

                AppendAudit(actor, "central.usbcrypt.driver.upload", state.UsbCryptDriverPackage.version, "usb-runtime-package", true, "0x00000000", "USB crypt runtime package uploaded.");
                Save();
            }

            return Success("USB crypt runtime package uploaded.");
        }

        public string GetUsbCryptPackagePath()
        {
            return Path.Combine(DirectoryPath, UsbCryptPackageDirectoryName, UsbCryptPackageFileName);
        }

        public RemovableDeviceDto[] QueryRemovableDevices()
        {
            lock (syncRoot)
            {
                EnsureDeviceAuthorizationState();
                return state.RemovableDevices.Values
                    .Select(ToRemovableDeviceDto)
                    .OrderByDescending(device => device.online)
                    .ThenBy(device => device.status, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(device => device.host, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(device => device.driveLetter, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public PolicyBridgeService.OperationResult AuthorizeRemovableDevice(RemovableDeviceAuthorizationRequest request)
        {
            RemovableDeviceAuthorizationRule normalized = NormalizeRemovableAuthorizationRequest(request);
            lock (syncRoot)
            {
                EnsureDeviceAuthorizationState();
                state.RemovableAuthorizations[normalized.hardwareId] = normalized;
                state.PolicyVersion++;
                AppendAudit(normalized.actor, "central.device.authorization." + normalized.status, normalized.hardwareId, "removable-storage", true, "0x00000000", "Removable device authorization updated.");
                Save();
            }

            return Success("Removable device authorization updated.");
        }

        public PolicyBridgeService.OperationResult RemoveRemovableDeviceAuthorization(RemovableDeviceAuthorizationRequest request)
        {
            string hardwareId = NormalizeHardwareId(request == null ? string.Empty : request.hardwareId);
            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Hardware id is required.");
            }

            lock (syncRoot)
            {
                EnsureDeviceAuthorizationState();
                if (state.RemovableAuthorizations.Remove(hardwareId))
                {
                    state.PolicyVersion++;
                }

                AppendAudit(request == null ? string.Empty : request.actor, "central.device.authorization.remove", hardwareId, "removable-storage", true, "0x00000000", "Removable device authorization removed.");
                Save();
            }

            return Success("Removable device authorization removed.");
        }

        public PolicyBridgeService.OperationResult RemoveDevice(DeviceDeleteRequest request)
        {
            string deviceId = NormalizeDeviceText(request == null ? string.Empty : request.deviceId);
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Device id is required.");
            }

            lock (syncRoot)
            {
                bool removed = state.Devices.Remove(deviceId);
                int taskCount = state.Tasks.RemoveAll(task => string.Equals(task.deviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                int networkCount = state.NetworkConnections.RemoveAll(item => string.Equals(item.deviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                MarkRemovableVolumesOffline(deviceId);

                AppendAudit(
                    request == null ? string.Empty : request.actor,
                    "central.agent.remove",
                    deviceId,
                    "agent",
                    true,
                    "0x00000000",
                    "Agent inventory removed. device=" + removed + ", tasks=" + taskCount + ", network=" + networkCount + ".");
                Save();
            }

            return Success("Agent inventory removed.");
        }

        public PolicyBridgeService.OperationResult RemoveRemovableDevice(RemovableDeviceDeleteRequest request)
        {
            string hardwareId = NormalizeHardwareId(request == null ? string.Empty : request.hardwareId);
            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Hardware id is required.");
            }

            lock (syncRoot)
            {
                EnsureDeviceAuthorizationState();
                bool removedInventory = state.RemovableDevices.Remove(hardwareId);
                bool removedAuthorization = state.RemovableAuthorizations.Remove(hardwareId);
                if (removedInventory || removedAuthorization)
                {
                    state.PolicyVersion++;
                }

                AppendAudit(
                    request == null ? string.Empty : request.actor,
                    "central.device.removable.remove",
                    hardwareId,
                    "removable-storage",
                    true,
                    "0x00000000",
                    "Removable device inventory removed.");
                Save();
            }

            return Success("Removable device inventory removed.");
        }

        public PolicyBridgeService.OperationResult AddRule(PolicyBridgeService.PolicyRuleRequest request)
        {
            PolicyBridgeService.PolicyRuleRequest normalized = NormalizeRequest(request);
            lock (syncRoot)
            {
                if (!state.Rules.Any(rule => SameRule(rule, normalized)))
                {
                    state.Rules.Add(new PolicyBridgeService.PolicyRuleDto
                    {
                        kind = normalized.Kind,
                        value = normalized.Value,
                        extension = normalized.Extension
                    });
                    state.PolicyVersion++;
                }

                AppendAudit(normalized.Actor, "central.policy.rule.add." + normalized.Kind, normalized.Value, normalized.Extension, true, "0x00000000", "Policy rule stored on central server.");
                Save();
            }

            return Success("Policy rule stored on central server.");
        }

        public PolicyBridgeService.OperationResult RemoveRule(PolicyBridgeService.PolicyRuleRequest request)
        {
            PolicyBridgeService.PolicyRuleRequest normalized = NormalizeRequest(request);
            lock (syncRoot)
            {
                int removed = state.Rules.RemoveAll(rule => SameRule(rule, normalized));
                if (removed > 0)
                {
                    state.PolicyVersion++;
                }

                AppendAudit(normalized.Actor, "central.policy.rule.remove." + normalized.Kind, normalized.Value, normalized.Extension, true, "0x00000000", "Policy rule removed from central server.");
                Save();
            }

            return Success("Policy rule removed from central server.");
        }

        public PolicyBridgeService.OperationResult ClearRules(string actor)
        {
            lock (syncRoot)
            {
                if (state.Rules.Count > 0)
                {
                    state.Rules.Clear();
                    state.PolicyVersion++;
                }

                AppendAudit(actor, "central.policy.rules.clear", "*", "*", true, "0x00000000", "All central policy rules cleared.");
                Save();
            }

            return Success("All central policy rules cleared.");
        }

        public PolicyBridgeService.OperationResult AddNetworkRule(PolicyBridgeService.NetworkRuleRequest request)
        {
            PolicyBridgeService.NetworkRuleDto normalized = NormalizeNetworkRequest(request, true);
            lock (syncRoot)
            {
                int existing = state.NetworkRules.FindIndex(rule => rule.ruleId == normalized.ruleId);
                if (existing >= 0)
                {
                    state.NetworkRules[existing] = normalized;
                }
                else
                {
                    state.NetworkRules.Add(normalized);
                }

                state.PolicyVersion++;
                AppendAudit(normalized.actor, "central.policy.network.add." + normalized.kind, normalized.displayTarget, string.Empty, true, "0x00000000", "Network rule stored on central server.");
                Save();
            }

            return Success("Network rule stored on central server.");
        }

        public PolicyBridgeService.OperationResult RemoveNetworkRule(PolicyBridgeService.NetworkRuleRequest request)
        {
            if (request == null || request.ruleId == 0)
            {
                throw new PolicyBridgeService.BridgeException(1, "Network rule id is required.");
            }

            lock (syncRoot)
            {
                int removed = state.NetworkRules.RemoveAll(rule => rule.ruleId == request.ruleId);
                if (removed > 0)
                {
                    state.PolicyVersion++;
                }

                AppendAudit(request.actor, "central.policy.network.remove", request.ruleId.ToString(), string.Empty, true, "0x00000000", "Network rule removed from central server.");
                Save();
            }

            return Success("Network rule removed from central server.");
        }

        public PolicyBridgeService.OperationResult ClearNetworkRules(string actor)
        {
            lock (syncRoot)
            {
                if (state.NetworkRules.Count > 0)
                {
                    state.NetworkRules.Clear();
                    state.PolicyVersion++;
                }

                AppendAudit(actor, "central.policy.network.clear", "*", string.Empty, true, "0x00000000", "All central network rules cleared.");
                Save();
            }

            return Success("All central network rules cleared.");
        }

        public PolicyBridgeService.OperationResult AddWebShellRule(PolicyBridgeService.WebShellRuleRequest request)
        {
            PolicyBridgeService.WebShellRuleDto normalized = NormalizeWebShellRequest(request);
            lock (syncRoot)
            {
                if (!state.WebShellRules.Any(rule => SameWebShellRule(rule, normalized)))
                {
                    state.WebShellRules.Add(normalized);
                    state.PolicyVersion++;
                }

                AppendAudit(normalized.actor, "central.policy.webshell.add", normalized.directory, "web-script", true, "0x00000000", "WebShell protected directory stored on central server.");
                Save();
            }

            return Success("WebShell protected directory stored on central server.");
        }

        public PolicyBridgeService.OperationResult RemoveWebShellRule(PolicyBridgeService.WebShellRuleRequest request)
        {
            PolicyBridgeService.WebShellRuleDto normalized = NormalizeWebShellRequest(request);
            lock (syncRoot)
            {
                int removed = state.WebShellRules.RemoveAll(rule => SameWebShellRule(rule, normalized));
                if (removed > 0)
                {
                    state.PolicyVersion++;
                }

                AppendAudit(normalized.actor, "central.policy.webshell.remove", normalized.directory, "web-script", true, "0x00000000", "WebShell protected directory removed from central server.");
                Save();
            }

            return Success("WebShell protected directory removed from central server.");
        }

        public PolicyBridgeService.OperationResult ClearWebShellRules(string actor)
        {
            lock (syncRoot)
            {
                if (state.WebShellRules.Count > 0)
                {
                    state.WebShellRules.Clear();
                    state.PolicyVersion++;
                }

                AppendAudit(actor, "central.policy.webshell.clear", "*", "web-script", true, "0x00000000", "All central WebShell rules cleared.");
                Save();
            }

            return Success("All central WebShell rules cleared.");
        }

        public PolicyBridgeService.OperationResult AddDeviceRule(PolicyBridgeService.DeviceRuleRequest request)
        {
            PolicyBridgeService.DeviceRuleDto normalized = NormalizeDeviceRequest(request);
            lock (syncRoot)
            {
                int existing = state.DeviceRules.FindIndex(rule => SameDeviceRule(rule, normalized));
                if (existing >= 0)
                {
                    state.DeviceRules[existing] = normalized;
                }
                else
                {
                    state.DeviceRules.Add(normalized);
                }

                state.PolicyVersion++;
                AppendAudit(normalized.actor, "central.policy.device.add", normalized.deviceId, "removable-storage", true, "0x00000000", "Device control rule stored on central server.");
                Save();
            }

            return Success("Device control rule stored on central server.");
        }

        public PolicyBridgeService.OperationResult RemoveDeviceRule(PolicyBridgeService.DeviceRuleRequest request)
        {
            PolicyBridgeService.DeviceRuleDto normalized = NormalizeDeviceRequest(request);
            lock (syncRoot)
            {
                int removed = state.DeviceRules.RemoveAll(rule => SameDeviceRule(rule, normalized));
                if (removed > 0)
                {
                    state.PolicyVersion++;
                }

                AppendAudit(normalized.actor, "central.policy.device.remove", normalized.deviceId, "removable-storage", true, "0x00000000", "Device control rule removed from central server.");
                Save();
            }

            return Success("Device control rule removed from central server.");
        }

        public PolicyBridgeService.OperationResult ClearDeviceRules(string actor)
        {
            lock (syncRoot)
            {
                if (state.DeviceRules.Count > 0)
                {
                    state.DeviceRules.Clear();
                    state.PolicyVersion++;
                }

                AppendAudit(actor, "central.policy.device.clear", "*", "removable-storage", true, "0x00000000", "All central device control rules cleared.");
                Save();
            }

            return Success("All central device control rules cleared.");
        }

        public PolicyBridgeService.OperationResult UpdateHashProtectPolicy(PolicyBridgeService.HashProtectPolicyRequest request)
        {
            PolicyBridgeService.HashProtectPolicyDto normalized = PolicyBridgeService.NormalizeHashProtectPolicy(request);
            lock (syncRoot)
            {
                EnsureHashProtectPolicy();
                if (PolicyBridgeService.ToHashProtectFlags(state.HashProtectPolicy) != PolicyBridgeService.ToHashProtectFlags(normalized))
                {
                    state.HashProtectPolicy = PolicyBridgeService.CloneHashProtectPolicy(normalized);
                    state.PolicyVersion++;
                }
                else
                {
                    state.HashProtectPolicy = PolicyBridgeService.CloneHashProtectPolicy(normalized);
                }

                AppendAudit(
                    normalized.actor,
                    "central.policy.hashprotect.update",
                    "anti-dump",
                    PolicyBridgeService.HashProtectPolicySummary(normalized),
                    true,
                    "0x00000000",
                    "Hash dump protection policy stored on central server.");
                Save();
            }

            return Success("Hash dump protection policy stored on central server.");
        }

        public PolicyBridgeService.OperationResult UpdateLateralDefensePolicy(PolicyBridgeService.LateralDefensePolicyRequest request)
        {
            PolicyBridgeService.LateralDefensePolicyDto normalized = PolicyBridgeService.NormalizeLateralDefensePolicy(request);
            lock (syncRoot)
            {
                EnsureLateralDefensePolicy();
                if (PolicyBridgeService.ToLateralDefenseFlags(state.LateralDefensePolicy) != PolicyBridgeService.ToLateralDefenseFlags(normalized))
                {
                    state.LateralDefensePolicy = PolicyBridgeService.CloneLateralDefensePolicy(normalized);
                    state.PolicyVersion++;
                }
                else
                {
                    state.LateralDefensePolicy = PolicyBridgeService.CloneLateralDefensePolicy(normalized);
                }

                AppendAudit(
                    normalized.actor,
                    "central.policy.lateral.update",
                    "lateral-defense",
                    PolicyBridgeService.LateralDefensePolicySummary(normalized),
                    true,
                    "0x00000000",
                    "IPC and SMB lateral movement defense policy stored on central server.");
                Save();
            }

            return Success("IPC and SMB lateral movement defense policy stored on central server.");
        }

        public PolicyBridgeService.OperationResult UpdateUserHookDefensePolicy(PolicyBridgeService.UserHookDefensePolicyRequest request)
        {
            PolicyBridgeService.UserHookDefensePolicyDto normalized = PolicyBridgeService.NormalizeUserHookDefensePolicy(request);
            lock (syncRoot)
            {
                EnsureUserHookDefensePolicy();
                if (PolicyBridgeService.ToUserHookDefenseFlags(state.UserHookDefensePolicy) != PolicyBridgeService.ToUserHookDefenseFlags(normalized) ||
                    !StringArrayEquals(state.UserHookDefensePolicy.excludedProcessNames, normalized.excludedProcessNames) ||
                    !StringArrayEquals(state.UserHookDefensePolicy.excludedProcessDirectories, normalized.excludedProcessDirectories) ||
                    !StringArrayEquals(state.UserHookDefensePolicy.excludedProcessPaths, normalized.excludedProcessPaths) ||
                    !StringArrayEquals(state.UserHookDefensePolicy.trustedSignerSubjects, normalized.trustedSignerSubjects) ||
                    state.UserHookDefensePolicy.monitorRuntimeApiBehavior != normalized.monitorRuntimeApiBehavior ||
                    state.UserHookDefensePolicy.scanExecutableMemory != normalized.scanExecutableMemory ||
                    state.UserHookDefensePolicy.monitorEtwTamper != normalized.monitorEtwTamper ||
                    !SameBehaviorRules(state.UserHookDefensePolicy.behaviorRules, normalized.behaviorRules))
                {
                    state.UserHookDefensePolicy = PolicyBridgeService.CloneUserHookDefensePolicy(normalized);
                    state.PolicyVersion++;
                }
                else
                {
                    state.UserHookDefensePolicy = PolicyBridgeService.CloneUserHookDefensePolicy(normalized);
                }

                AppendAudit(
                    normalized.actor,
                    "central.policy.userhook.update",
                    "process-threat-insight",
                    PolicyBridgeService.UserHookDefensePolicySummary(normalized),
                    true,
                    "0x00000000",
                    "Process threat insight policy stored on central server.");
                Save();
            }

            return Success("Process threat insight policy stored on central server.");
        }

        private static bool StringArrayEquals(string[] left, string[] right)
        {
            return (left ?? new string[0]).SequenceEqual(right ?? new string[0], StringComparer.OrdinalIgnoreCase);
        }

        private static bool SameBehaviorRules(PolicyBridgeService.UserHookBehaviorRule[] left, PolicyBridgeService.UserHookBehaviorRule[] right)
        {
            JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
            return string.Equals(
                serializer.Serialize(left ?? new PolicyBridgeService.UserHookBehaviorRule[0]),
                serializer.Serialize(right ?? new PolicyBridgeService.UserHookBehaviorRule[0]),
                StringComparison.Ordinal);
        }

        public PolicyBridgeService.OperationResult UpdateUsbCryptPolicy(PolicyBridgeService.UsbCryptPolicyRequest request)
        {
            PolicyBridgeService.UsbCryptPolicyDto normalized = PolicyBridgeService.NormalizeUsbCryptPolicy(request);
            lock (syncRoot)
            {
                EnsureUsbCryptPolicy();
                if (!SameUsbCryptPolicy(state.UsbCryptPolicy, normalized))
                {
                    state.UsbCryptPolicy = PolicyBridgeService.CloneUsbCryptPolicy(normalized);
                    state.PolicyVersion++;
                }
                else
                {
                    state.UsbCryptPolicy = PolicyBridgeService.CloneUsbCryptPolicy(normalized);
                }

                AppendAudit(
                    normalized.actor,
                    "central.policy.usbcrypt.update",
                    "usb-removable-media",
                    PolicyBridgeService.UsbCryptPolicySummary(normalized),
                    true,
                    "0x00000000",
                    "USB encryption policy stored on central server.");
                Save();
            }

            return Success("USB encryption policy stored on central server.");
        }

        public PolicyBridgeService.OperationResult UpdateDlpProtectionPolicy(PolicyBridgeService.DlpProtectionPolicyRequest request)
        {
            PolicyBridgeService.DlpProtectionPolicyDto normalized = PolicyBridgeService.NormalizeDlpProtectionPolicy(request);
            lock (syncRoot)
            {
                EnsureDlpProtectionPolicy();
                if (!PolicyBridgeService.SameDlpProtectionPolicy(state.DlpProtectionPolicy, normalized))
                {
                    state.DlpProtectionPolicy = PolicyBridgeService.CloneDlpProtectionPolicy(normalized);
                    state.PolicyVersion++;
                }
                else
                {
                    state.DlpProtectionPolicy = PolicyBridgeService.CloneDlpProtectionPolicy(normalized);
                }

                AppendAudit(
                    normalized.actor,
                    "central.policy.dlp.update",
                    "dlp-protection",
                    PolicyBridgeService.DlpProtectionPolicySummary(normalized),
                    true,
                    "0x00000000",
                    "Screenshot and clipboard DLP policy stored on central server.");
                Save();
            }

            return Success("Screenshot and clipboard DLP policy stored on central server.");
        }

        public AuditLog.AuditRecord[] ReadRecentAudit(int limit)
        {
            return QueryAudit(new AuditLog.AuditQueryOptions { Limit = limit }).items;
        }

        public AuditLog.AuditQueryResponse QueryAudit(AuditLog.AuditQueryOptions options)
        {
            AuditLog.AuditQueryOptions query = options ?? new AuditLog.AuditQueryOptions();

            lock (syncRoot)
            {
                return AuditLog.BuildQueryResponse(state.Audit.Select(CloneAudit).ToArray(), query);
            }
        }

        public AuditAttackFlowResponse QueryAuditAttackFlow(AuditLog.AuditQueryOptions options)
        {
            AuditLog.AuditQueryOptions query = options ?? new AuditLog.AuditQueryOptions();
            AuditLog.AuditRecord[] auditRecords;
            NetworkConnectionObservation[] networkRecords;

            lock (syncRoot)
            {
                auditRecords = state.Audit
                    .Select(CloneAudit)
                    .Where(record => AuditLog.Matches(record, query))
                    .ToArray();
                networkRecords = state.NetworkConnections
                    .Select(CloneNetworkObservation)
                    .Where(item => IsNetworkObservationInAuditScope(item, query))
                    .ToArray();
            }

            return BuildAuditAttackFlow(auditRecords, networkRecords, query);
        }

        public PolicyBridgeService.OperationResult ClearAudit(string actor)
        {
            lock (syncRoot)
            {
                int removed = state.Audit.Count;
                state.Audit.Clear();
                AppendAudit(actor, "central.audit.events.clear", "*", "audit", true, "0x00000000", "Central audit log cleared. Removed records: " + removed + ".");
                Save();
            }

            return Success("Central audit log cleared.");
        }

        public PolicyBridgeService.OperationResult RemoveAudit(AuditLog.AuditDeleteOptions request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Audit delete request body is required.");
            }

            lock (syncRoot)
            {
                int removed = state.Audit.RemoveAll(record => IsAuditDeleteMatch(record, request));
                AppendAudit(
                    request.Actor,
                    "central.audit.event.remove",
                    string.IsNullOrWhiteSpace(request.Target) ? request.TimestampUtc : request.Target,
                    "audit",
                    true,
                    "0x00000000",
                    "Central audit event delete request removed " + removed + " record(s).");
                Save();
            }

            return Success("Central audit event delete request completed.");
        }

        public SandboxSampleQueryResponse QuerySandboxSamples(SandboxSampleQuery query)
        {
            SandboxSampleQuery normalized = NormalizeSandboxSampleQuery(query);
            lock (syncRoot)
            {
                IEnumerable<SandboxSampleState> rows = state.SandboxSamples ?? Enumerable.Empty<SandboxSampleState>();
                if (!string.IsNullOrWhiteSpace(normalized.status) &&
                    !string.Equals(normalized.status, "all", StringComparison.OrdinalIgnoreCase))
                {
                    rows = rows.Where(item => string.Equals(item.status, normalized.status, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(normalized.source) &&
                    !string.Equals(normalized.source, "all", StringComparison.OrdinalIgnoreCase))
                {
                    rows = rows.Where(item => string.Equals(item.source, normalized.source, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(normalized.host))
                {
                    rows = rows.Where(item => (item.host ?? string.Empty).IndexOf(normalized.host, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                if (!string.IsNullOrWhiteSpace(normalized.search))
                {
                    rows = rows.Where(item => SandboxSampleHaystack(item).IndexOf(normalized.search, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                bool restoredReports = false;
                foreach (SandboxSampleState item in rows)
                {
                    if (TryRestoreSandboxReport(item))
                    {
                        restoredReports = true;
                    }
                }

                if (restoredReports)
                {
                    Save();
                }

                SandboxSampleDto[] all = rows
                    .OrderByDescending(item => item.submittedUtc, StringComparer.OrdinalIgnoreCase)
                    .Select(ToSandboxSampleDto)
                    .ToArray();
                int skip = Math.Max(0, (normalized.page - 1) * normalized.pageSize);
                return new SandboxSampleQueryResponse
                {
                    page = normalized.page,
                    pageSize = normalized.pageSize,
                    total = all.Length,
                    queuedTotal = all.Count(item => string.Equals(item.status, "queued", StringComparison.OrdinalIgnoreCase)),
                    runningTotal = all.Count(item => string.Equals(item.status, "running", StringComparison.OrdinalIgnoreCase)),
                    completedTotal = all.Count(item => string.Equals(item.status, "completed", StringComparison.OrdinalIgnoreCase)),
                    failedTotal = all.Count(item => string.Equals(item.status, "failed", StringComparison.OrdinalIgnoreCase)),
                    items = all.Skip(skip).Take(normalized.pageSize).ToArray()
                };
            }
        }

        public SandboxSampleDto SubmitSandboxSample(SandboxSampleUploadRequest request, string actor)
        {
            SandboxSampleUploadRequest normalized = NormalizeSandboxUpload(request);
            byte[] sampleBytes;
            try
            {
                sampleBytes = Convert.FromBase64String(normalized.contentBase64);
            }
            catch
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample must be valid base64 content.");
            }

            if (sampleBytes.Length <= 0)
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample is empty.");
            }

            if (sampleBytes.Length > MaxSandboxSampleBytes)
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample exceeds the 50 MB server limit.");
            }

            if (!IsExecutableImage(sampleBytes))
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox currently accepts Windows PE executable samples only.");
            }

            SandboxSampleSubmission submission = new SandboxSampleSubmission
            {
                fileName = normalized.fileName,
                contentBase64 = normalized.contentBase64,
                sha256 = NormalizeSha256(normalized.sha256),
                source = string.IsNullOrWhiteSpace(normalized.source) ? "web" : normalized.source,
                host = string.IsNullOrWhiteSpace(normalized.host) ? Environment.MachineName : normalized.host,
                deviceId = normalized.deviceId,
                processPath = normalized.processPath,
                suspicion = normalized.suspicion,
                actor = string.IsNullOrWhiteSpace(actor) ? normalized.actor : actor
            };

            lock (syncRoot)
            {
                SandboxSampleState sample = IngestSandboxSample(submission, sampleBytes, DateTime.UtcNow, true);
                Save();
                return ToSandboxSampleDto(sample);
            }
        }

        public SandboxSampleDto StartSandboxAnalysis(SandboxAnalyzeRequest request, string actor)
        {
            string sampleId = NormalizeDeviceText(request == null ? string.Empty : request.sampleId);
            if (string.IsNullOrWhiteSpace(sampleId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample id is required.");
            }

            SandboxSampleState sample;
            Dictionary<string, object> args;
            lock (syncRoot)
            {
                EnsureSandboxState();
                sample = state.SandboxSamples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample == null)
                {
                    throw new PolicyBridgeService.BridgeException(1, "Sandbox sample was not found.");
                }

                if (string.Equals(sample.status, "running", StringComparison.OrdinalIgnoreCase))
                {
                    return ToSandboxSampleDto(sample);
                }

                if (string.IsNullOrWhiteSpace(sample.storagePath) || !File.Exists(sample.storagePath))
                {
                    sample.status = "failed";
                    sample.error = "Sandbox sample file is missing from the server sample store.";
                    sample.completedUtc = DateTime.UtcNow.ToString("o");
                    AppendAudit(actor, "sandbox.analysis.failed", sample.sampleId, sample.fileName, false, "0x00000001", sample.error);
                    Save();
                    return ToSandboxSampleDto(sample);
                }

                sample.status = "running";
                sample.startedUtc = DateTime.UtcNow.ToString("o");
                sample.completedUtc = string.Empty;
                sample.error = string.Empty;
                sample.reportJson = string.Empty;
                sample.timeoutSeconds = ClampInt(request == null ? 120 : request.timeoutSeconds, 15, 1800);
                sample.networkEnabled = request != null && request.networkEnabled;
                sample.closeWhenDone = request == null || request.closeWhenDone;
                sample.arguments = request == null ? string.Empty : request.arguments ?? string.Empty;
                AppendAudit(actor, "sandbox.analysis.started", sample.sampleId, sample.fileName, true, "0x00000000", "Server-side sandbox analysis started.");
                args = BuildSandboxRunnerArgs(sample);
                Save();
            }

            ThreadPool.QueueUserWorkItem(_ => RunSandboxAnalysisWorker(sampleId, args, actor));
            lock (syncRoot)
            {
                SandboxSampleState refreshed = state.SandboxSamples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                return ToSandboxSampleDto(refreshed ?? sample);
            }
        }

        public PolicyBridgeService.OperationResult RemoveSandboxSample(SandboxSampleDeleteRequest request)
        {
            string sampleId = NormalizeDeviceText(request == null ? string.Empty : request.sampleId);
            if (string.IsNullOrWhiteSpace(sampleId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample id is required.");
            }

            lock (syncRoot)
            {
                EnsureSandboxState();
                SandboxSampleState sample = state.SandboxSamples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample != null)
                {
                    if (!string.IsNullOrWhiteSpace(sample.storagePath) && File.Exists(sample.storagePath))
                    {
                        TryDeleteFile(sample.storagePath);
                    }

                    state.SandboxSamples.Remove(sample);
                }

                AppendAudit(request == null ? string.Empty : request.actor, "sandbox.sample.remove", sampleId, "sandbox", true, "0x00000000", "Sandbox sample record removed.");
                Save();
            }

            return Success("Sandbox sample removed.");
        }

        public PolicyBridgeService.OperationResult RemoveSandboxLogs(SandboxLogDeleteRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox log delete request body is required.");
            }

            string actor = NormalizeDeviceText(request.actor);
            string sampleId = NormalizeDeviceText(request.sampleId);
            string runId = NormalizeDeviceText(request.runId);
            int removedRuns = 0;
            int clearedReports = 0;

            lock (syncRoot)
            {
                EnsureSandboxState();
                if (request.all)
                {
                    if (state.SandboxSamples.Any(item => string.Equals(item.status, "running", StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new PolicyBridgeService.BridgeException(1, "Sandbox logs cannot be cleared while analysis is running.");
                    }

                    removedRuns = DeleteAllSandboxRunDirectories();
                    int removedRecords = state.SandboxSamples.Count;
                    int removedSampleFiles = 0;
                    foreach (SandboxSampleState sampleRecord in state.SandboxSamples.ToArray())
                    {
                        if (!string.IsNullOrWhiteSpace(sampleRecord.storagePath))
                        {
                            removedSampleFiles += TryDeleteFile(sampleRecord.storagePath) ? 1 : 0;
                        }
                    }

                    removedSampleFiles += DeleteAllSandboxSampleStoreFiles();
                    state.SandboxSamples.Clear();

                    AppendAudit(actor, "sandbox.logs.clear", "*", "sandbox", true, "0x00000000", "Sandbox history cleared. Removed run directories: " + removedRuns + ", sample records: " + removedRecords + ", sample files: " + removedSampleFiles + ".");
                    Save();
                    return Success("Sandbox logs cleared.");
                }

                if (string.IsNullOrWhiteSpace(sampleId) && string.IsNullOrWhiteSpace(runId))
                {
                    throw new PolicyBridgeService.BridgeException(1, "Sandbox sample id or run id is required.");
                }

                SandboxSampleState sample = null;
                if (!string.IsNullOrWhiteSpace(sampleId))
                {
                    sample = state.SandboxSamples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                    if (sample == null)
                    {
                        throw new PolicyBridgeService.BridgeException(1, "Sandbox sample was not found.");
                    }

                    if (string.Equals(sample.status, "running", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new PolicyBridgeService.BridgeException(1, "Sandbox logs cannot be removed while analysis is running.");
                    }
                }

                HashSet<string> runDirectoryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrWhiteSpace(runId))
                {
                    AddSandboxRunDirectoryCandidate(runDirectoryPaths, runId);
                }

                if (sample != null)
                {
                    AddSandboxReportDirectoryCandidates(runDirectoryPaths, sample.reportJson);
                    if (ClearSandboxSampleReport(sample))
                    {
                        clearedReports++;
                    }
                }

                foreach (string path in runDirectoryPaths)
                {
                    if (TryDeleteDirectory(path))
                    {
                        removedRuns++;
                    }
                }

                AppendAudit(actor, "sandbox.logs.remove", string.IsNullOrWhiteSpace(sampleId) ? runId : sampleId, "sandbox", true, "0x00000000", "Sandbox run logs removed. Removed run directories: " + removedRuns + ", cleared reports: " + clearedReports + ".");
                Save();
            }

            return Success("Sandbox logs removed.");
        }

        public NetworkInsightResponse QueryNetworkInsights(NetworkInsightQuery query)
        {
            NetworkInsightQuery normalized = NormalizeNetworkInsightQuery(query);
            DateTime nowUtc = DateTime.UtcNow;
            DateTime sinceUtc = nowUtc - normalized.window;
            DateTime baselineUtc = nowUtc - normalized.baseline;
            NetworkInsightItem[] pageItems;
            NetworkInsightItem[] allItems;
            Dictionary<string, IpInfoCacheEntry> ipInfoCache;

            lock (syncRoot)
            {
                List<NetworkConnectionObservation> current = state.NetworkConnections
                    .Where(item => IsNetworkInsightMatch(item, normalized) && ParseUtcOrMin(item.lastSeenUtc) >= sinceUtc)
                    .Select(CloneNetworkObservation)
                    .ToList();

                Dictionary<string, NetworkConnectionObservation> firstSeenByKey = state.NetworkConnections
                    .Where(item => item != null)
                    .GroupBy(NetworkObservationKey, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(
                        group => group.Key,
                        group => group
                            .OrderBy(item => ParseUtcOrMax(item.firstSeenUtc))
                            .First(),
                        StringComparer.OrdinalIgnoreCase);

                allItems = current
                    .GroupBy(NetworkObservationKey, StringComparer.OrdinalIgnoreCase)
                    .Select(group => ToNetworkInsightItem(group.ToList(), firstSeenByKey, baselineUtc))
                    .Where(item => IsNetworkNewnessMatch(item, normalized.newness))
                    .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                int skip = Math.Max(0, (normalized.page - 1) * normalized.pageSize);
                pageItems = allItems
                    .Skip(skip)
                    .Take(normalized.pageSize)
                    .ToArray();

                ipInfoCache = CloneIpInfoCache();
            }

            IpInfoCacheEntry[] resolvedEntries = ResolveMissingIpInfo(pageItems, ipInfoCache, nowUtc);
            if (resolvedEntries.Length > 0)
            {
                lock (syncRoot)
                {
                    EnsureIpInfoCache();
                    foreach (IpInfoCacheEntry entry in resolvedEntries)
                    {
                        state.IpInfoCache[entry.ip] = entry;
                    }

                    TrimIpInfoCache();
                    Save();
                    ipInfoCache = CloneIpInfoCache();
                }
            }

            AttachIpInfo(pageItems, ipInfoCache, IsIpInfoEnabled());

            return new NetworkInsightResponse
            {
                page = normalized.page,
                pageSize = normalized.pageSize,
                baselineHours = normalized.baseline.TotalHours,
                windowHours = normalized.window.TotalHours,
                generatedUtc = DateTime.UtcNow.ToString("o"),
                total = allItems.Length,
                newTotal = allItems.Count(item => item.isNew),
                http3Total = allItems.Count(item => item.isHttp3),
                unsignedTotal = allItems.Count(item => string.Equals(item.signatureStatus, "unsigned", StringComparison.OrdinalIgnoreCase)),
                trendBuckets = BuildNetworkTrendBuckets(allItems),
                eventDistribution = BuildNetworkEventDistribution(allItems),
                items = pageItems
            };
        }

        public IpInfoConfiguration QueryIpInfoConfiguration()
        {
            string token = GetIpInfoToken(out string source);
            return new IpInfoConfiguration
            {
                enabled = !string.IsNullOrWhiteSpace(token),
                source = source,
                maskedToken = MaskSecret(token),
                tokenFilePath = GetIpInfoTokenFilePath()
            };
        }

        public PolicyBridgeService.OperationResult SaveIpInfoConfiguration(IpInfoConfigurationRequest request, string actor)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "IP intelligence configuration body is required.");
            }

            string token = NormalizeSecret(request.token);
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new PolicyBridgeService.BridgeException(1, "IPInfo token is required.");
            }

            lock (syncRoot)
            {
                Directory.CreateDirectory(DirectoryPath);
                File.WriteAllText(GetIpInfoTokenFilePath(), token, Encoding.UTF8);
                EnsureIpInfoCache();
                state.IpInfoCache.Clear();
                AppendAudit(actor, "network.ipinfo.configure", "ipinfo", string.Empty, true, "0x00000000", "IP intelligence token was configured.");
                Save();
            }

            return Success("IP intelligence token configured.");
        }

        public PolicyBridgeService.OperationResult ClearIpInfoConfiguration(string actor)
        {
            lock (syncRoot)
            {
                string tokenPath = GetIpInfoTokenFilePath();
                if (File.Exists(tokenPath))
                {
                    File.Delete(tokenPath);
                }

                EnsureIpInfoCache();
                state.IpInfoCache.Clear();
                AppendAudit(actor, "network.ipinfo.clear", "ipinfo", string.Empty, true, "0x00000000", "IP intelligence file token and cache were cleared.");
                Save();
            }

            return Success("IP intelligence file token and cache cleared.");
        }

        public CentralDeviceDto[] QueryDevices()
        {
            lock (syncRoot)
            {
                return state.Devices.Values
                    .Select(ToDeviceDto)
                    .OrderBy(device => device.machine, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(device => device.deviceId, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public RemoteTaskDto[] QueryTasks(string deviceId, int limit)
        {
            int take = limit <= 0 ? DefaultLimit : Math.Min(limit, 1000);
            lock (syncRoot)
            {
                IEnumerable<RemoteTaskState> query = state.Tasks;
                if (!string.IsNullOrWhiteSpace(deviceId))
                {
                    query = query.Where(task => string.Equals(task.deviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                }

                return query
                    .OrderByDescending(task => task.createdUtc, StringComparer.OrdinalIgnoreCase)
                    .Take(take)
                    .Select(CloneTask)
                    .ToArray();
            }
        }

        public RemoteTaskDto CreateTask(RemoteTaskRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Remote task request body is required.");
            }

            string deviceId = (request.deviceId ?? string.Empty).Trim();
            string kind = (request.kind ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Target device id is required.");
            }

            if (string.IsNullOrWhiteSpace(kind))
            {
                throw new PolicyBridgeService.BridgeException(1, "Task kind is required.");
            }

            if (string.Equals(kind, "usbcrypt.initialize", StringComparison.OrdinalIgnoreCase))
            {
                throw new PolicyBridgeService.BridgeException(1, "USB encryption initialization must use the dedicated /api/usbcrypt/initialize endpoint.");
            }

            if (string.Equals(kind, "sandbox.run", StringComparison.OrdinalIgnoreCase))
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox analysis is server-side only. Use /api/sandbox/samples and /api/sandbox/analyze.");
            }

            lock (syncRoot)
            {
                if (!state.Devices.ContainsKey(deviceId))
                {
                    throw new PolicyBridgeService.BridgeException(1, "Target device is not registered.");
                }

                RemoteTaskState task = new RemoteTaskState
                {
                    taskId = Guid.NewGuid().ToString("N"),
                    deviceId = deviceId,
                    kind = kind,
                    argumentsJson = string.IsNullOrWhiteSpace(request.argumentsJson) ? "{}" : request.argumentsJson,
                    actor = string.IsNullOrWhiteSpace(request.actor) ? Environment.UserName : request.actor,
                    status = "queued",
                    createdUtc = DateTime.UtcNow.ToString("o"),
                    output = string.Empty,
                    error = string.Empty
                };

                state.Tasks.Add(task);
                AppendAudit(task.actor, "remote.task.create." + task.kind, task.deviceId, string.Empty, true, "0x00000000", "Remote task queued: " + task.taskId);
                Save();
                return CloneTask(task);
            }
        }

        public RemoteTaskDto CreateUsbCryptInitializationTask(UsbCryptInitializationTaskRequest request)
        {
            UsbCryptInitializationTaskRequest normalized = NormalizeUsbCryptInitializationTaskRequest(request);
            lock (syncRoot)
            {
                if (!state.Devices.ContainsKey(normalized.deviceId))
                {
                    throw new PolicyBridgeService.BridgeException(1, "Target agent is not registered.");
                }

                EnsureDeviceAuthorizationState();
                RemovableDeviceState removable;
                if (!state.RemovableDevices.TryGetValue(normalized.hardwareId, out removable) || !IsRemovableDeviceOnline(removable))
                {
                    throw new PolicyBridgeService.BridgeException(1, "Target removable device is not online.");
                }

                RemovableDeviceAuthorizationRule authorization = ResolveRemovableAuthorization(normalized.hardwareId);
                if (authorization == null || !string.Equals(authorization.status, "authorized", StringComparison.OrdinalIgnoreCase))
                {
                    throw new PolicyBridgeService.BridgeException(1, "Target removable device must be authorized before USB encryption initialization.");
                }

                UsbCryptDriverPackageInfo package = GetCurrentUsbCryptPackageForTask();
                string argumentsJson = serializer.Serialize(new
                {
                    hardwareId = normalized.hardwareId,
                    password = normalized.password,
                    publicToolAreaBytes = normalized.publicToolAreaBytes,
                    dataLengthBytes = normalized.dataLengthBytes,
                    confirmed = normalized.confirmed,
                    driverPackageVersion = package.version,
                    driverPackageSha256 = package.sha256,
                    driverPackageDownloadPath = package.downloadPath
                });

                RemoteTaskState task = new RemoteTaskState
                {
                    taskId = Guid.NewGuid().ToString("N"),
                    deviceId = normalized.deviceId,
                    kind = "usbcrypt.initialize",
                    argumentsJson = argumentsJson,
                    actor = string.IsNullOrWhiteSpace(normalized.actor) ? Environment.UserName : normalized.actor,
                    status = "queued",
                    createdUtc = DateTime.UtcNow.ToString("o"),
                    output = string.Empty,
                    error = string.Empty
                };

                task.argumentsJson = RedactUsbCryptInitializationArgs(argumentsJson);
                volatileTaskArguments[task.taskId] = argumentsJson;
                state.Tasks.Add(task);
                AppendAudit(task.actor, "usbcrypt.initialize.queued", normalized.hardwareId, "usb-removable-media", true, "0x00000000", normalized.confirmed ? "USB encryption initialization task queued." : "USB encryption initialization dry run queued.");
                Save();
                return CloneTask(task);
            }
        }

        public AgentSyncResponse SyncAgent(AgentSyncRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Agent sync request body is required.");
            }

            string deviceId = string.IsNullOrWhiteSpace(request.DeviceId)
                ? Guid.NewGuid().ToString("N")
                : request.DeviceId.Trim();

            lock (syncRoot)
            {
                CentralDeviceState device;
                if (!state.Devices.TryGetValue(deviceId, out device))
                {
                    device = new CentralDeviceState { DeviceId = deviceId, FirstSeenUtc = DateTime.UtcNow.ToString("o") };
                    state.Devices[deviceId] = device;
                }

                device.Machine = request.Machine ?? string.Empty;
                device.User = request.User ?? string.Empty;
                device.AgentVersion = request.AgentVersion ?? string.Empty;
                device.DriverConnected = request.DriverConnected;
                device.DriverStatus = request.DriverStatus ?? string.Empty;
                device.DriverMessage = request.DriverMessage ?? string.Empty;
                device.PolicyVersion = request.PolicyVersion;
                device.LastSeenUtc = DateTime.UtcNow.ToString("o");
                device.LastApplyStatus = request.LastApplyStatus ?? string.Empty;
                device.LastApplyMessage = request.LastApplyMessage ?? string.Empty;

                if (request.TaskResults != null)
                {
                    foreach (RemoteTaskResult result in request.TaskResults)
                    {
                        ApplyTaskResult(deviceId, result);
                    }
                }

                if (request.NetworkConnections != null)
                {
                    foreach (PolicyBridgeService.NetworkConnectionEventDto item in request.NetworkConnections)
                    {
                        TryIngestNetworkObservation(deviceId, device, item, DateTime.UtcNow.ToString("o"), string.Empty, string.Empty);
                    }

                    if (request.NetworkConnections.Length > 0)
                    {
                        Console.WriteLine(DateTime.Now.ToString("s") + " Central received " + request.NetworkConnections.Length + " network awareness event(s) from " + device.Machine + " (" + device.DeviceId + ").");
                    }
                }

                if (request.RemovableDevices != null)
                {
                    int removableCount = 0;
                    bool dynamicDevicePolicyChanged = false;
                    HashSet<string> seenRemovableVolumes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (RemovableDeviceObservation item in request.RemovableDevices)
                    {
                        bool policyAffectingChange;
                        if (IngestRemovableDevice(deviceId, device, item, seenRemovableVolumes, out policyAffectingChange))
                        {
                            removableCount++;
                            dynamicDevicePolicyChanged = dynamicDevicePolicyChanged || policyAffectingChange;
                        }
                    }

                    dynamicDevicePolicyChanged = MarkMissingRemovableVolumesOffline(deviceId, seenRemovableVolumes) || dynamicDevicePolicyChanged;
                    if (dynamicDevicePolicyChanged)
                    {
                        state.PolicyVersion++;
                    }

                    if (removableCount > 0)
                    {
                        Console.WriteLine(DateTime.Now.ToString("s") + " Central received " + removableCount + " removable device observation(s) from " + device.Machine + " (" + device.DeviceId + ").");
                    }
                }

                if (request.SandboxSamples != null)
                {
                    int sandboxSampleCount = 0;
                    foreach (SandboxSampleSubmission submission in request.SandboxSamples)
                    {
                        if (TryIngestSandboxSampleFromAgent(deviceId, device, submission))
                        {
                            sandboxSampleCount++;
                        }
                    }

                    if (sandboxSampleCount > 0)
                    {
                        Console.WriteLine(DateTime.Now.ToString("s") + " Central received " + sandboxSampleCount + " sandbox sample(s) from " + device.Machine + " (" + device.DeviceId + ").");
                    }
                }

                if (request.Audit != null)
                {
                    int acceptedAuditCount = 0;
                    foreach (AuditLog.AuditRecord record in request.Audit)
                    {
                        AuditLog.AuditRecord normalized = CloneAudit(record);
                        normalized.Host = string.IsNullOrWhiteSpace(normalized.Host)
                            ? device.Machine
                            : normalized.Host;
                        normalized.Actor = string.IsNullOrWhiteSpace(normalized.Actor)
                            ? device.Machine
                            : normalized.Actor;
                        normalized.Target = string.IsNullOrWhiteSpace(normalized.Target)
                            ? device.DeviceId
                            : normalized.Target;
                        AuditLog.EnrichRecord(normalized);

                        if (TryIngestNetworkObservation(deviceId, device, normalized))
                        {
                            continue;
                        }

                        state.Audit.Add(normalized);
                        acceptedAuditCount++;
                    }

                    if (acceptedAuditCount > 0)
                    {
                        Console.WriteLine(DateTime.Now.ToString("s") + " Central received " + acceptedAuditCount + " audit event(s) from " + device.Machine + " (" + device.DeviceId + ").");
                    }
                }

                if (!request.ResultOnly && request.PolicyVersion != state.PolicyVersion)
                {
                    AppendAudit(device.Machine, "agent.policy.pending", device.DeviceId, string.Empty, true, "0x00000000", "Agent will apply central policy version " + state.PolicyVersion + ".");
                }

                RemoteTaskDto[] assignedTasks = request.ResultOnly ? new RemoteTaskDto[0] : AssignTasks(deviceId);
                TrimAudit();
                Save();

                return new AgentSyncResponse
                {
                    accepted = true,
                    deviceId = deviceId,
                    serverTimeUtc = DateTime.UtcNow.ToString("o"),
                    policyVersion = state.PolicyVersion,
                    rules = QueryRules(),
                    networkRules = QueryNetworkRules(),
                    webShellRules = QueryWebShellRules(),
                    deviceRules = BuildEffectiveDeviceRules(deviceId),
                    hashProtectPolicy = QueryHashProtectPolicy(),
                    lateralDefensePolicy = QueryLateralDefensePolicy(),
                    userHookDefensePolicy = QueryUserHookDefensePolicy(),
                    usbCryptPolicy = QueryUsbCryptPolicy(),
                    dlpProtectionPolicy = QueryDlpProtectionPolicy(),
                    tasks = assignedTasks
                };
            }
        }

        private CentralState Load()
        {
            lock (syncRoot)
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        return new CentralState();
                    }

                    string json = File.ReadAllText(filePath, Encoding.UTF8);
                    CentralState loaded = serializer.Deserialize<CentralState>(json);
                    if (loaded != null && loaded.NetworkRules == null)
                    {
                        loaded.NetworkRules = new List<PolicyBridgeService.NetworkRuleDto>();
                    }
                    if (loaded != null && loaded.WebShellRules == null)
                    {
                        loaded.WebShellRules = new List<PolicyBridgeService.WebShellRuleDto>();
                    }
                    if (loaded != null && loaded.DeviceRules == null)
                    {
                        loaded.DeviceRules = new List<PolicyBridgeService.DeviceRuleDto>();
                    }
                    if (loaded != null && loaded.RemovableDevices == null)
                    {
                        loaded.RemovableDevices = new Dictionary<string, RemovableDeviceState>(StringComparer.OrdinalIgnoreCase);
                    }
                    if (loaded != null && loaded.RemovableAuthorizations == null)
                    {
                        loaded.RemovableAuthorizations = new Dictionary<string, RemovableDeviceAuthorizationRule>(StringComparer.OrdinalIgnoreCase);
                    }
                    if (loaded != null && loaded.NetworkConnections == null)
                    {
                        loaded.NetworkConnections = new List<NetworkConnectionObservation>();
                    }
                    if (loaded != null && loaded.IpInfoCache == null)
                    {
                        loaded.IpInfoCache = new Dictionary<string, IpInfoCacheEntry>(StringComparer.OrdinalIgnoreCase);
                    }
                    if (loaded != null && loaded.HashProtectPolicy == null)
                    {
                        loaded.HashProtectPolicy = PolicyBridgeService.DefaultHashProtectPolicy();
                    }
                    if (loaded != null && loaded.LateralDefensePolicy == null)
                    {
                        loaded.LateralDefensePolicy = PolicyBridgeService.DefaultLateralDefensePolicy();
                    }

                    if (loaded != null && loaded.UserHookDefensePolicy == null)
                    {
                        loaded.UserHookDefensePolicy = PolicyBridgeService.DefaultUserHookDefensePolicy();
                    }
                    if (loaded != null && (loaded.UserHookDefensePolicy.behaviorRules == null || loaded.UserHookDefensePolicy.behaviorRules.Length == 0))
                    {
                        loaded.UserHookDefensePolicy.behaviorRules = PolicyBridgeService.DefaultUserHookBehaviorRules();
                    }
                    if (loaded != null && loaded.UsbCryptPolicy == null)
                    {
                        loaded.UsbCryptPolicy = PolicyBridgeService.DefaultUsbCryptPolicy();
                    }
                    if (loaded != null && loaded.DlpProtectionPolicy == null)
                    {
                        loaded.DlpProtectionPolicy = PolicyBridgeService.DefaultDlpProtectionPolicy();
                    }
                    if (loaded != null && loaded.UsbCryptDriverPackage == null)
                    {
                        loaded.UsbCryptDriverPackage = new UsbCryptDriverPackageInfo();
                    }
                    if (loaded != null && loaded.SandboxSamples == null)
                    {
                        loaded.SandboxSamples = new List<SandboxSampleState>();
                    }
                    return loaded ?? new CentralState();
                }
                catch
                {
                    return new CentralState();
                }
            }
        }

        private void Save()
        {
            Directory.CreateDirectory(DirectoryPath);
            TrimAudit();
            TrimTasks();
            TrimNetworkConnections();
            TrimRemovableDevices();
            TrimIpInfoCache();
            TrimSandboxSamples();
            string json = serializer.Serialize(state);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        private void AppendAudit(string actor, string action, string target, string extension, bool succeeded, string status, string message)
        {
            AuditLog.AuditRecord record = new AuditLog.AuditRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Host = Environment.MachineName,
                Actor = string.IsNullOrWhiteSpace(actor) ? Environment.UserName : actor,
                Action = action ?? string.Empty,
                Target = target ?? string.Empty,
                Extension = extension ?? string.Empty,
                Succeeded = succeeded,
                Status = status ?? "0x00000000",
                Message = message ?? string.Empty
            };
            AuditLog.EnrichRecord(record);
            state.Audit.Add(record);
        }

        private static AuditAttackFlowResponse BuildAuditAttackFlow(
            AuditLog.AuditRecord[] auditRecords,
            NetworkConnectionObservation[] networkRecords,
            AuditLog.AuditQueryOptions query)
        {
            List<AuditAttackFlowEvent> events = new List<AuditAttackFlowEvent>();
            Dictionary<string, AuditAttackFlowProcess> processes = new Dictionary<string, AuditAttackFlowProcess>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, AuditAttackFlowEntity> entityMap = new Dictionary<string, AuditAttackFlowEntity>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, AttackIncidentAccumulator> incidentMap = new Dictionary<string, AttackIncidentAccumulator>(StringComparer.OrdinalIgnoreCase);
            DateTime firstUtc = DateTime.MaxValue;
            DateTime lastUtc = DateTime.MinValue;

            foreach (AuditLog.AuditRecord record in (auditRecords ?? new AuditLog.AuditRecord[0]))
            {
                if (record == null)
                {
                    continue;
                }

                AuditLog.EnrichRecord(record);
                AuditAttackFlowEvent flowEvent = BuildAttackFlowEvent(record);
                if (flowEvent == null)
                {
                    continue;
                }

                events.Add(flowEvent);
                TrackFlowTime(flowEvent.timeUtc, ref firstUtc, ref lastUtc);
                AddProcessNode(processes, flowEvent.host, flowEvent.sourcePid, flowEvent.sourceProcess, string.Empty, flowEvent.sourceUser, flowEvent.severity);
                AddProcessNode(processes, flowEvent.host, flowEvent.targetPid, flowEvent.targetProcess, flowEvent.sourcePid, string.Empty, flowEvent.severity);
                AddEntity(entityMap, "host", flowEvent.host, flowEvent.host, flowEvent.severity);
                AddEntity(entityMap, "process", ProcessEntityKey(flowEvent.host, flowEvent.sourcePid, flowEvent.sourceProcess), FirstNonEmpty(flowEvent.sourceProcess, flowEvent.sourcePid), flowEvent.severity);
                AddEntity(entityMap, flowEvent.objectType, FirstNonEmpty(flowEvent.objectName, flowEvent.targetProcess, flowEvent.targetPid, flowEvent.action), FirstNonEmpty(flowEvent.objectName, flowEvent.targetProcess, flowEvent.action), flowEvent.severity);
                AddToIncident(incidentMap, flowEvent);
            }

            foreach (NetworkConnectionObservation item in (networkRecords ?? new NetworkConnectionObservation[0]))
            {
                if (item == null)
                {
                    continue;
                }

                AuditAttackFlowEvent flowEvent = BuildNetworkAttackFlowEvent(item);
                events.Add(flowEvent);
                TrackFlowTime(flowEvent.timeUtc, ref firstUtc, ref lastUtc);
                AddProcessNode(processes, flowEvent.host, flowEvent.sourcePid, flowEvent.sourceProcess, string.Empty, flowEvent.sourceUser, flowEvent.severity);
                AddEntity(entityMap, "host", flowEvent.host, flowEvent.host, flowEvent.severity);
                AddEntity(entityMap, "process", ProcessEntityKey(flowEvent.host, flowEvent.sourcePid, flowEvent.sourceProcess), FirstNonEmpty(flowEvent.sourceProcess, flowEvent.sourcePid), flowEvent.severity);
                AddEntity(entityMap, "remote", flowEvent.remoteIdentity, flowEvent.remoteIdentity, flowEvent.severity);
                AddToIncident(incidentMap, flowEvent);
            }

            AuditAttackFlowEvent[] orderedEvents = events
                .OrderBy(item => ParseUtcOrMin(item.timeUtc))
                .Take(500)
                .ToArray();
            AuditAttackFlowStage[] stages = BuildAttackFlowStages(orderedEvents);
            AuditAttackFlowIncident[] incidents = incidentMap.Values
                .Select(item => item.ToIncident())
                .OrderByDescending(item => item.score)
                .ThenByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                .Take(24)
                .ToArray();

            return new AuditAttackFlowResponse
            {
                generatedUtc = DateTime.UtcNow.ToString("o"),
                fromUtc = firstUtc == DateTime.MaxValue ? string.Empty : firstUtc.ToString("o"),
                toUtc = lastUtc == DateTime.MinValue ? string.Empty : lastUtc.ToString("o"),
                eventTotal = orderedEvents.Length,
                incidentTotal = incidents.Length,
                criticalTotal = orderedEvents.Count(item => string.Equals(item.severity, "critical", StringComparison.OrdinalIgnoreCase)),
                hostTotal = orderedEvents.Select(item => item.host).Where(item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                processTotal = processes.Count,
                remoteTotal = orderedEvents.Select(item => item.remoteIdentity).Where(item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                summary = BuildAttackFlowSummary(stages, incidents, orderedEvents),
                stages = stages,
                incidents = incidents,
                processes = processes.Values
                    .OrderBy(item => item.host, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(item => item.pid, StringComparer.OrdinalIgnoreCase)
                    .Take(200)
                    .ToArray(),
                entities = entityMap.Values
                    .OrderByDescending(item => SeverityScore(item.severity))
                    .ThenByDescending(item => item.count)
                    .Take(80)
                    .ToArray(),
                events = orderedEvents
            };
        }

        private static AuditAttackFlowEvent BuildAttackFlowEvent(AuditLog.AuditRecord record)
        {
            string action = record.Action ?? string.Empty;
            string stage = ClassifyAttackStage(record);
            string severity = AuditLog.ResolveSeverity(record);
            string disposition = AuditLog.ResolveDisposition(record);
            string sourceProcess = FirstNonEmpty(record.SourceProcess, record.Extension);
            string targetProcess = FirstNonEmpty(record.TargetProcess, LooksLikeProcessPath(record.Target) ? record.Target : string.Empty);
            string objectType = FirstNonEmpty(record.ObjectType, InferAttackObjectType(action));
            string objectName = FirstNonEmpty(record.ObjectName, record.Target, targetProcess, action);

            return new AuditAttackFlowEvent
            {
                id = BuildStableId(record.TimestampUtc, action, record.Target, record.Message),
                timeUtc = record.TimestampUtc ?? string.Empty,
                host = FirstNonEmpty(record.SourceHost, record.Host, record.Actor),
                user = FirstNonEmpty(record.SourceUser, record.Actor),
                stage = stage,
                category = AuditLog.ClassifyCategory(record),
                action = action,
                title = BuildAttackEventTitle(record, stage),
                detail = BuildAttackEventDetail(record),
                severity = severity,
                disposition = disposition,
                sourceProcess = sourceProcess,
                sourcePid = record.SourcePid ?? string.Empty,
                sourceUser = FirstNonEmpty(record.SourceUser, record.Actor),
                targetProcess = targetProcess,
                targetPid = record.TargetPid ?? string.Empty,
                objectType = objectType,
                objectName = objectName,
                objectFormat = record.ObjectFormat ?? string.Empty,
                policyName = record.PolicyName ?? string.Empty,
                remoteIdentity = IsRemoteStage(stage) ? FirstNonEmpty(record.TargetHost, record.Target, record.ObjectName) : string.Empty,
                rawMessage = record.Message ?? string.Empty
            };
        }

        private static AuditAttackFlowEvent BuildNetworkAttackFlowEvent(NetworkConnectionObservation item)
        {
            string remote = FirstNonEmpty(item.remoteIdentity, item.domain, item.remoteEndpoint, item.remoteAddress);
            string protocol = FirstNonEmpty(item.protocolName, item.isHttp3 ? "HTTP/3" : item.isQuic ? "QUIC" : string.Empty);
            string detail = JoinCompact(" / ", protocol, item.direction, item.remoteEndpoint, item.signer, item.signatureStatus);

            return new AuditAttackFlowEvent
            {
                id = BuildStableId(item.lastSeenUtc, "network.connection.observed", remote, item.processPath),
                timeUtc = item.lastSeenUtc ?? string.Empty,
                host = item.host ?? string.Empty,
                user = item.user ?? string.Empty,
                stage = "network",
                category = "network",
                action = item.blocked ? "network.connection.blocked" : "network.connection.observed",
                title = item.blocked ? "Network connection blocked" : "Network connection observed",
                detail = detail,
                severity = item.blocked || string.Equals(item.signatureStatus, "unsigned", StringComparison.OrdinalIgnoreCase) ? "warning" : "info",
                disposition = item.blocked ? "blocked" : "observed",
                sourceProcess = item.processPath ?? string.Empty,
                sourcePid = item.processId == 0 ? string.Empty : item.processId.ToString(CultureInfo.InvariantCulture),
                sourceUser = item.user ?? string.Empty,
                targetProcess = string.Empty,
                targetPid = string.Empty,
                objectType = item.isHttp3 ? "http3-connection" : item.isQuic ? "quic-connection" : "network-connection",
                objectName = remote,
                objectFormat = detail,
                policyName = "network-awareness",
                remoteIdentity = remote,
                rawMessage = detail
            };
        }

        private static string ClassifyAttackStage(AuditLog.AuditRecord record)
        {
            string action = record == null ? string.Empty : record.Action ?? string.Empty;
            string objectType = record == null ? string.Empty : record.ObjectType ?? string.Empty;
            string message = record == null ? string.Empty : record.Message ?? string.Empty;

            if (action.StartsWith("sandbox.sample", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase) ||
                objectType.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "delivery";
            }

            if (action.StartsWith("userhook.observed.process-create", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.observed.suspended-process-create", StringComparison.OrdinalIgnoreCase))
            {
                return "execution";
            }

            if (action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase))
            {
                return "behavior";
            }

            if (action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase) ||
                objectType.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "credential";
            }

            if (action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase))
            {
                return "lateral";
            }

            if (action.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("network.smtp", StringComparison.OrdinalIgnoreCase))
            {
                return "network";
            }

            if (action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase))
            {
                return "impact";
            }

            if (message.IndexOf("registry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                message.IndexOf("scheduled", StringComparison.OrdinalIgnoreCase) >= 0 ||
                message.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "persistence";
            }

            return "behavior";
        }

        private static AuditAttackFlowStage[] BuildAttackFlowStages(AuditAttackFlowEvent[] events)
        {
            string[] order = new[] { "delivery", "execution", "behavior", "credential", "lateral", "network", "persistence", "impact" };
            return order.Select(stage =>
            {
                AuditAttackFlowEvent[] matched = (events ?? new AuditAttackFlowEvent[0])
                    .Where(item => string.Equals(item.stage, stage, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                string severity = matched.Length == 0 ? "info" : matched.Select(item => item.severity).OrderByDescending(SeverityScore).First();
                return new AuditAttackFlowStage
                {
                    key = stage,
                    label = AttackStageLabel(stage),
                    count = matched.Length,
                    active = matched.Length > 0,
                    severity = severity,
                    firstSeenUtc = matched.Length == 0 ? string.Empty : matched.Min(item => item.timeUtc),
                    lastSeenUtc = matched.Length == 0 ? string.Empty : matched.Max(item => item.timeUtc),
                    detail = BuildStageDetail(stage, matched)
                };
            }).ToArray();
        }

        private static string BuildStageDetail(string stage, AuditAttackFlowEvent[] events)
        {
            if (events == null || events.Length == 0)
            {
                return "No telemetry observed for this stage.";
            }

            string sample = FirstNonEmpty(events[0].sourceProcess, events[0].objectName, events[0].action);
            return events.Length.ToString(CultureInfo.InvariantCulture) + " event(s), first evidence: " + sample;
        }

        private static string BuildAttackFlowSummary(AuditAttackFlowStage[] stages, AuditAttackFlowIncident[] incidents, AuditAttackFlowEvent[] events)
        {
            int activeStages = (stages ?? new AuditAttackFlowStage[0]).Count(item => item.active);
            int critical = (events ?? new AuditAttackFlowEvent[0]).Count(item => string.Equals(item.severity, "critical", StringComparison.OrdinalIgnoreCase));
            if (incidents != null && incidents.Length > 0)
            {
                return "Detected " + incidents.Length.ToString(CultureInfo.InvariantCulture) +
                       " correlated attack flow(s) across " + activeStages.ToString(CultureInfo.InvariantCulture) +
                       " stage(s), with " + critical.ToString(CultureInfo.InvariantCulture) + " critical event(s).";
            }

            return "No high-confidence attack chain was reconstructed from the selected audit scope.";
        }

        private static void AddToIncident(Dictionary<string, AttackIncidentAccumulator> incidents, AuditAttackFlowEvent item)
        {
            if (item == null || incidents == null)
            {
                return;
            }

            string key = IncidentKey(item);
            AttackIncidentAccumulator incident;
            if (!incidents.TryGetValue(key, out incident))
            {
                incident = new AttackIncidentAccumulator
                {
                    key = key,
                    host = item.host ?? string.Empty,
                    rootProcess = FirstNonEmpty(item.sourceProcess, item.targetProcess),
                    rootPid = FirstNonEmpty(item.sourcePid, item.targetPid),
                    firstSeenUtc = item.timeUtc ?? string.Empty,
                    lastSeenUtc = item.timeUtc ?? string.Empty,
                    severity = item.severity ?? "info"
                };
                incidents[key] = incident;
            }

            incident.eventCount++;
            incident.firstSeenUtc = EarlierUtc(incident.firstSeenUtc, item.timeUtc);
            incident.lastSeenUtc = LaterUtc(incident.lastSeenUtc, item.timeUtc);
            incident.severity = MaxSeverity(incident.severity, item.severity);
            incident.stages.Add(item.stage ?? string.Empty);
            incident.actions.Add(item.action ?? string.Empty);
            if (!string.IsNullOrWhiteSpace(item.remoteIdentity))
            {
                incident.remotes.Add(item.remoteIdentity);
            }

            if (!string.IsNullOrWhiteSpace(item.objectName))
            {
                incident.objects.Add(item.objectName);
            }

            incident.score += 10 + SeverityScore(item.severity) * 15 + (string.Equals(item.disposition, "blocked", StringComparison.OrdinalIgnoreCase) ? 20 : 0);
        }

        private static string IncidentKey(AuditAttackFlowEvent item)
        {
            return string.Join("|", new[]
            {
                item.host ?? string.Empty,
                FirstNonEmpty(item.sourceProcess, item.targetProcess),
                FirstNonEmpty(item.sourcePid, item.targetPid)
            });
        }

        private static void AddProcessNode(Dictionary<string, AuditAttackFlowProcess> processes, string host, string pid, string path, string parentPid, string user, string severity)
        {
            if (processes == null || string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(pid))
            {
                return;
            }

            string key = ProcessEntityKey(host, pid, path);
            AuditAttackFlowProcess node;
            if (!processes.TryGetValue(key, out node))
            {
                node = new AuditAttackFlowProcess
                {
                    key = key,
                    host = host ?? string.Empty,
                    pid = pid ?? string.Empty,
                    parentPid = parentPid ?? string.Empty,
                    name = SafeFileName(path),
                    path = path ?? string.Empty,
                    user = user ?? string.Empty,
                    severity = severity ?? "info",
                    eventCount = 0
                };
                processes[key] = node;
            }

            node.eventCount++;
            node.severity = MaxSeverity(node.severity, severity);
            node.path = PreferNonEmpty(path, node.path);
            node.user = PreferNonEmpty(user, node.user);
            node.parentPid = PreferNonEmpty(parentPid, node.parentPid);
            node.name = PreferNonEmpty(SafeFileName(node.path), node.name);
        }

        private static void AddEntity(Dictionary<string, AuditAttackFlowEntity> entities, string type, string key, string label, string severity)
        {
            if (entities == null || string.IsNullOrWhiteSpace(key))
            {
                return;
            }

            string normalizedType = string.IsNullOrWhiteSpace(type) ? "object" : type;
            string entityKey = normalizedType + "|" + key;
            AuditAttackFlowEntity entity;
            if (!entities.TryGetValue(entityKey, out entity))
            {
                entity = new AuditAttackFlowEntity
                {
                    key = entityKey,
                    type = normalizedType,
                    label = string.IsNullOrWhiteSpace(label) ? key : label,
                    severity = severity ?? "info",
                    count = 0
                };
                entities[entityKey] = entity;
            }

            entity.count++;
            entity.severity = MaxSeverity(entity.severity, severity);
        }

        private static string BuildAttackEventTitle(AuditLog.AuditRecord record, string stage)
        {
            if (!string.IsNullOrWhiteSpace(record.ObjectName))
            {
                return AttackStageLabel(stage) + ": " + record.ObjectName;
            }

            if (!string.IsNullOrWhiteSpace(record.Target))
            {
                return AttackStageLabel(stage) + ": " + record.Target;
            }

            return AttackStageLabel(stage) + ": " + (record.Action ?? "event");
        }

        private static string BuildAttackEventDetail(AuditLog.AuditRecord record)
        {
            return JoinCompact(" / ",
                AuditLog.ResolveSourceDisplay(record),
                AuditLog.ResolveTargetDisplay(record),
                record.EventDetails,
                record.Message);
        }

        private static string AttackStageLabel(string stage)
        {
            if (string.Equals(stage, "delivery", StringComparison.OrdinalIgnoreCase)) return "Delivery / Landing";
            if (string.Equals(stage, "execution", StringComparison.OrdinalIgnoreCase)) return "Execution";
            if (string.Equals(stage, "behavior", StringComparison.OrdinalIgnoreCase)) return "Behavior";
            if (string.Equals(stage, "credential", StringComparison.OrdinalIgnoreCase)) return "Credential Access";
            if (string.Equals(stage, "lateral", StringComparison.OrdinalIgnoreCase)) return "Lateral Movement";
            if (string.Equals(stage, "network", StringComparison.OrdinalIgnoreCase)) return "Network / C2";
            if (string.Equals(stage, "persistence", StringComparison.OrdinalIgnoreCase)) return "Persistence";
            if (string.Equals(stage, "impact", StringComparison.OrdinalIgnoreCase)) return "Impact / Data";
            return "Telemetry";
        }

        private static string InferAttackObjectType(string action)
        {
            if (string.IsNullOrWhiteSpace(action)) return "object";
            if (action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase)) return "file";
            if (action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase)) return "credential";
            if (action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase)) return "remote-admin";
            if (action.StartsWith("network.", StringComparison.OrdinalIgnoreCase)) return "remote";
            if (action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase)) return "sensitive-data";
            if (action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase)) return "process-behavior";
            return "object";
        }

        private static bool IsNetworkObservationInAuditScope(NetworkConnectionObservation item, AuditLog.AuditQueryOptions query)
        {
            if (item == null)
            {
                return false;
            }

            if (query == null)
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(query.Category) &&
                !string.Equals(query.Category, "all", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(query.Category, "network", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(query.Host) &&
                !string.Equals(query.Host, "all", StringComparison.OrdinalIgnoreCase) &&
                (item.host ?? string.Empty).IndexOf(query.Host, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }

            DateTime timestamp = ParseUtcOrMin(item.lastSeenUtc);
            DateTime fromUtc;
            DateTime toUtc;
            if (TryParseAuditUtc(query.FromUtc, out fromUtc) && timestamp < fromUtc)
            {
                return false;
            }

            if (TryParseAuditUtc(query.ToUtc, out toUtc) && timestamp > toUtc)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(query.Search))
            {
                string haystack = JoinCompact("\n",
                    item.host,
                    item.user,
                    item.processPath,
                    item.remoteIdentity,
                    item.remoteAddress,
                    item.remoteEndpoint,
                    item.domain,
                    item.protocolName,
                    item.signatureStatus,
                    item.signer);
                if (haystack.IndexOf(query.Search, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool TryParseAuditUtc(string value, out DateTime timestampUtc)
        {
            if (DateTime.TryParse(value, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out timestampUtc))
            {
                timestampUtc = timestampUtc.ToUniversalTime();
                return true;
            }

            return false;
        }

        private static void TrackFlowTime(string value, ref DateTime firstUtc, ref DateTime lastUtc)
        {
            DateTime parsed = ParseUtcOrMin(value);
            if (parsed == DateTime.MinValue)
            {
                return;
            }

            if (parsed < firstUtc) firstUtc = parsed;
            if (parsed > lastUtc) lastUtc = parsed;
        }

        private static string EarlierUtc(string left, string right)
        {
            DateTime leftUtc = ParseUtcOrMax(left);
            DateTime rightUtc = ParseUtcOrMax(right);
            return leftUtc <= rightUtc ? (left ?? string.Empty) : (right ?? string.Empty);
        }

        private static string LaterUtc(string left, string right)
        {
            DateTime leftUtc = ParseUtcOrMin(left);
            DateTime rightUtc = ParseUtcOrMin(right);
            return leftUtc >= rightUtc ? (left ?? string.Empty) : (right ?? string.Empty);
        }

        private static string MaxSeverity(string left, string right)
        {
            return SeverityScore(right) > SeverityScore(left) ? (right ?? "info") : (left ?? "info");
        }

        private static int SeverityScore(string severity)
        {
            if (string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase)) return 4;
            if (string.Equals(severity, "high", StringComparison.OrdinalIgnoreCase)) return 3;
            if (string.Equals(severity, "warning", StringComparison.OrdinalIgnoreCase)) return 2;
            if (string.Equals(severity, "medium", StringComparison.OrdinalIgnoreCase)) return 2;
            if (string.Equals(severity, "info", StringComparison.OrdinalIgnoreCase)) return 1;
            return 0;
        }

        private static string ProcessEntityKey(string host, string pid, string path)
        {
            return string.Join("|", new[] { host ?? string.Empty, pid ?? string.Empty, path ?? string.Empty });
        }

        private static string SafeFileName(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFileName(path.Trim().Trim('"'));
            }
            catch
            {
                return path;
            }
        }

        private static bool LooksLikeProcessPath(string value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   (value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    value.IndexOf("\\", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static bool IsRemoteStage(string stage)
        {
            return string.Equals(stage, "network", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(stage, "lateral", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildStableId(params string[] values)
        {
            unchecked
            {
                uint hash = 2166136261u;
                string text = string.Join("|", values ?? new string[0]);
                foreach (char ch in text)
                {
                    hash ^= ch;
                    hash *= 16777619u;
                }

                return hash.ToString("x8", CultureInfo.InvariantCulture);
            }
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

        private static string JoinCompact(string separator, params string[] values)
        {
            return string.Join(separator, (values ?? new string[0]).Where(value => !string.IsNullOrWhiteSpace(value)).ToArray());
        }

        private void EnsureHashProtectPolicy()
        {
            if (state.HashProtectPolicy == null)
            {
                state.HashProtectPolicy = PolicyBridgeService.DefaultHashProtectPolicy();
            }
            else
            {
                state.HashProtectPolicy = PolicyBridgeService.CloneHashProtectPolicy(state.HashProtectPolicy);
            }
        }

        private void EnsureLateralDefensePolicy()
        {
            if (state.LateralDefensePolicy == null)
            {
                state.LateralDefensePolicy = PolicyBridgeService.DefaultLateralDefensePolicy();
            }
            else
            {
                state.LateralDefensePolicy = PolicyBridgeService.CloneLateralDefensePolicy(state.LateralDefensePolicy);
            }
        }

        private void EnsureUserHookDefensePolicy()
        {
            if (state.UserHookDefensePolicy == null)
            {
                state.UserHookDefensePolicy = PolicyBridgeService.DefaultUserHookDefensePolicy();
            }
            else
            {
                state.UserHookDefensePolicy = PolicyBridgeService.CloneUserHookDefensePolicy(state.UserHookDefensePolicy);
            }
        }

        private void EnsureUsbCryptPolicy()
        {
            if (state.UsbCryptPolicy == null)
            {
                state.UsbCryptPolicy = PolicyBridgeService.DefaultUsbCryptPolicy();
            }
            else
            {
                state.UsbCryptPolicy = PolicyBridgeService.CloneUsbCryptPolicy(state.UsbCryptPolicy);
            }
        }

        private void EnsureDlpProtectionPolicy()
        {
            if (state.DlpProtectionPolicy == null)
            {
                state.DlpProtectionPolicy = PolicyBridgeService.DefaultDlpProtectionPolicy();
            }
            else
            {
                state.DlpProtectionPolicy = PolicyBridgeService.CloneDlpProtectionPolicy(state.DlpProtectionPolicy);
            }
        }

        private void EnsureUsbCryptDriverPackage()
        {
            if (state.UsbCryptDriverPackage == null)
            {
                state.UsbCryptDriverPackage = new UsbCryptDriverPackageInfo();
            }

            if (File.Exists(GetUsbCryptPackagePath()) && string.IsNullOrWhiteSpace(state.UsbCryptDriverPackage.downloadPath))
            {
                state.UsbCryptDriverPackage.downloadPath = "/api/usbcrypt/driver-package/download";
            }
        }

        private void EnsureSandboxState()
        {
            if (state.SandboxSamples == null)
            {
                state.SandboxSamples = new List<SandboxSampleState>();
            }
        }

        private void TrimAudit()
        {
            const int maxAuditRecords = 10000;
            if (state.Audit.Count > maxAuditRecords)
            {
                state.Audit = state.Audit.Skip(state.Audit.Count - maxAuditRecords).ToList();
            }
        }

        private void TrimNetworkConnections()
        {
            const int maxNetworkObservations = 50000;
            if (state.NetworkConnections.Count > maxNetworkObservations)
            {
                state.NetworkConnections = state.NetworkConnections
                    .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                    .Take(maxNetworkObservations)
                .ToList();
            }
        }

        private void TrimRemovableDevices()
        {
            EnsureDeviceAuthorizationState();
            foreach (RemovableDeviceState device in state.RemovableDevices.Values)
            {
                NormalizeRemovableVolumeState(device);
            }

            if (state.RemovableDevices.Count <= 5000)
            {
                return;
            }

            state.RemovableDevices = state.RemovableDevices
                .Values
                .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                .Take(5000)
                .Where(item => !string.IsNullOrWhiteSpace(item.hardwareId))
                .ToDictionary(item => item.hardwareId, item => item, StringComparer.OrdinalIgnoreCase);
        }

        private void TrimIpInfoCache()
        {
            EnsureIpInfoCache();
            if (state.IpInfoCache.Count > MaxIpInfoCacheEntries)
            {
                state.IpInfoCache = state.IpInfoCache
                    .Values
                    .OrderByDescending(item => item.resolvedUtc, StringComparer.OrdinalIgnoreCase)
                    .Take(MaxIpInfoCacheEntries)
                    .Where(item => !string.IsNullOrWhiteSpace(item.ip))
                    .ToDictionary(item => item.ip, item => item, StringComparer.OrdinalIgnoreCase);
            }
        }

        private void TrimSandboxSamples()
        {
            EnsureSandboxState();
            if (state.SandboxSamples.Count <= MaxSandboxSampleRecords)
            {
                return;
            }

            List<SandboxSampleState> ordered = state.SandboxSamples
                .OrderByDescending(item => item.submittedUtc, StringComparer.OrdinalIgnoreCase)
                .Take(MaxSandboxSampleRecords)
                .ToList();
            HashSet<string> keep = new HashSet<string>(ordered.Select(item => item.sampleId), StringComparer.OrdinalIgnoreCase);
            foreach (SandboxSampleState item in state.SandboxSamples)
            {
                if (!keep.Contains(item.sampleId) &&
                    !string.IsNullOrWhiteSpace(item.storagePath) &&
                    File.Exists(item.storagePath))
                {
                    TryDeleteFile(item.storagePath);
                }
            }

            state.SandboxSamples = ordered;
        }

        private bool TryIngestNetworkObservation(string deviceId, CentralDeviceState device, AuditLog.AuditRecord record)
        {
            if (record == null ||
                string.IsNullOrWhiteSpace(record.Action) ||
                !record.Action.StartsWith("network.connection.", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            PolicyBridgeService.NetworkConnectionEventDto details = TryDeserializeNetworkConnectionDetails(record.Message);
            return TryIngestNetworkObservation(deviceId,
                                               device,
                                               details,
                                               record.TimestampUtc,
                                               record.Target,
                                               record.Extension);
        }

        private bool TryIngestNetworkObservation(
            string deviceId,
            CentralDeviceState device,
            PolicyBridgeService.NetworkConnectionEventDto details,
            string timestampUtc,
            string fallbackRemoteIdentity,
            string fallbackProcessPath)
        {
            if (details == null)
            {
                return false;
            }

            string remoteIdentity = string.IsNullOrWhiteSpace(details.remoteIdentity)
                ? fallbackRemoteIdentity
                : details.remoteIdentity;
            string processPath = string.IsNullOrWhiteSpace(details.processPath)
                ? fallbackProcessPath
                : details.processPath;
            string observedUtc = string.IsNullOrWhiteSpace(timestampUtc)
                ? DateTime.UtcNow.ToString("o")
                : timestampUtc;

            if (string.IsNullOrWhiteSpace(remoteIdentity) &&
                string.IsNullOrWhiteSpace(details.remoteEndpoint) &&
                string.IsNullOrWhiteSpace(details.remoteAddress) &&
                string.IsNullOrWhiteSpace(details.domain))
            {
                return false;
            }

            NetworkConnectionObservation observation = new NetworkConnectionObservation
            {
                deviceId = deviceId,
                host = device == null ? string.Empty : device.Machine,
                user = device == null ? string.Empty : device.User,
                remoteIdentity = remoteIdentity,
                remoteAddress = details.remoteAddress ?? string.Empty,
                remoteEndpoint = details.remoteEndpoint ?? string.Empty,
                domain = details.domain ?? string.Empty,
                processPath = processPath,
                processId = details.processId,
                direction = details.direction ?? string.Empty,
                protocolName = details.protocolName ?? string.Empty,
                localEndpoint = details.localEndpoint ?? string.Empty,
                remotePort = details.remotePort,
                isDns = details.isDns,
                isQuic = details.isQuic,
                isHttp3 = details.isHttp3,
                blocked = details.blocked,
                fileExists = details.fileExists,
                fileSize = details.fileSize,
                fileModifiedUtc = details.fileModifiedUtc ?? string.Empty,
                productName = details.productName ?? string.Empty,
                companyName = details.companyName ?? string.Empty,
                fileDescription = details.fileDescription ?? string.Empty,
                fileVersion = details.fileVersion ?? string.Empty,
                sha256 = details.sha256 ?? string.Empty,
                signatureStatus = details.signatureStatus ?? string.Empty,
                signer = details.signer ?? string.Empty,
                firstSeenUtc = observedUtc,
                lastSeenUtc = observedUtc,
                count = 1
            };

            string key = NetworkObservationStorageKey(observation);
            NetworkConnectionObservation existing = state.NetworkConnections.FirstOrDefault(item =>
                string.Equals(NetworkObservationStorageKey(item), key, StringComparison.OrdinalIgnoreCase));

            if (existing == null)
            {
                state.NetworkConnections.Add(observation);
            }
            else
            {
                existing.host = PreferNonEmpty(observation.host, existing.host);
                existing.user = PreferNonEmpty(observation.user, existing.user);
                existing.remoteIdentity = PreferNonEmpty(observation.remoteIdentity, existing.remoteIdentity);
                existing.remoteAddress = PreferNonEmpty(observation.remoteAddress, existing.remoteAddress);
                existing.remoteEndpoint = PreferNonEmpty(observation.remoteEndpoint, existing.remoteEndpoint);
                existing.domain = PreferNonEmpty(observation.domain, existing.domain);
                existing.lastSeenUtc = observation.lastSeenUtc;
                existing.count++;
                existing.processId = observation.processId;
                existing.direction = PreferNonEmpty(observation.direction, existing.direction);
                existing.protocolName = PreferNonEmpty(observation.protocolName, existing.protocolName);
                existing.localEndpoint = observation.localEndpoint;
                existing.remotePort = observation.remotePort != 0 ? observation.remotePort : existing.remotePort;
                existing.isDns = existing.isDns || observation.isDns;
                existing.isQuic = existing.isQuic || observation.isQuic;
                existing.isHttp3 = existing.isHttp3 || observation.isHttp3;
                existing.blocked = existing.blocked || observation.blocked;
                existing.fileExists = observation.fileExists;
                existing.fileSize = observation.fileSize;
                existing.fileModifiedUtc = observation.fileModifiedUtc;
                existing.productName = observation.productName;
                existing.companyName = observation.companyName;
                existing.fileDescription = observation.fileDescription;
                existing.fileVersion = observation.fileVersion;
                existing.sha256 = observation.sha256;
                existing.signatureStatus = observation.signatureStatus;
                existing.signer = observation.signer;
            }

            TrimNetworkConnections();
            return true;
        }

        private bool TryIngestSandboxSampleFromAgent(string deviceId, CentralDeviceState device, SandboxSampleSubmission submission)
        {
            if (submission == null || string.IsNullOrWhiteSpace(submission.contentBase64))
            {
                return false;
            }

            byte[] sampleBytes;
            try
            {
                sampleBytes = Convert.FromBase64String(submission.contentBase64);
            }
            catch
            {
                AppendAudit(device == null ? deviceId : device.Machine, "sandbox.sample.agent.rejected", deviceId, "sandbox", false, "0x00000001", "Agent submitted an invalid base64 sandbox sample.");
                return false;
            }

            if (sampleBytes.Length <= 0 || sampleBytes.Length > MaxSandboxSampleBytes || !IsExecutableImage(sampleBytes))
            {
                AppendAudit(device == null ? deviceId : device.Machine, "sandbox.sample.agent.rejected", deviceId, "sandbox", false, "0x00000001", "Agent submitted a sandbox sample that is empty, too large, or not a PE executable.");
                return false;
            }

            submission.deviceId = deviceId;
            submission.host = device == null ? submission.host : device.Machine;
            submission.source = "agent";
            IngestSandboxSample(submission, sampleBytes, DateTime.UtcNow, false);
            return true;
        }

        private SandboxSampleState IngestSandboxSample(SandboxSampleSubmission submission, byte[] sampleBytes, DateTime submittedUtc, bool queueAudit)
        {
            EnsureSandboxState();
            string sha256 = NormalizeSha256(submission == null ? string.Empty : submission.sha256);
            if (string.IsNullOrWhiteSpace(sha256))
            {
                sha256 = ComputeSha256Hex(sampleBytes);
            }

            string fileName = NormalizeFileName(submission == null ? string.Empty : submission.fileName);
            string source = NormalizeSandboxSource(submission == null ? string.Empty : submission.source);
            string host = NormalizeDeviceText(submission == null ? string.Empty : submission.host);
            string deviceId = NormalizeDeviceText(submission == null ? string.Empty : submission.deviceId);
            string processPath = submission == null ? string.Empty : submission.processPath ?? string.Empty;
            string sampleId = "sbx-" + sha256.Substring(0, Math.Min(16, sha256.Length));
            SandboxSampleState existing = state.SandboxSamples.FirstOrDefault(item =>
                string.Equals(item.sha256, sha256, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(item.source, source, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(item.host, host, StringComparison.OrdinalIgnoreCase));

            if (existing != null)
            {
                existing.fileName = string.IsNullOrWhiteSpace(existing.fileName) ? fileName : existing.fileName;
                existing.deviceId = PreferNonEmpty(deviceId, existing.deviceId);
                existing.processPath = PreferNonEmpty(processPath, existing.processPath);
                existing.suspicion = PreferNonEmpty(submission == null ? string.Empty : submission.suspicion, existing.suspicion);
                existing.lastSubmittedUtc = submittedUtc.ToString("o");
                existing.submitCount++;
                if (queueAudit)
                {
                    AppendAudit(submission == null ? string.Empty : submission.actor, "sandbox.sample.deduplicated", existing.sampleId, existing.fileName, true, "0x00000000", "Sandbox sample already exists on the server.");
                }

                return existing;
            }

            if (state.SandboxSamples.Any(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase)))
            {
                sampleId = sampleId + "-" + ComputeCrc32(source + "|" + host + "|" + deviceId + "|" + processPath).ToString("x8", CultureInfo.InvariantCulture);
            }

            string sampleDirectory = GetSandboxSampleDirectory();
            Directory.CreateDirectory(sampleDirectory);
            string storagePath = Path.Combine(sampleDirectory, sampleId + "-" + SafeStorageFileName(fileName));
            int suffix = 1;
            while (File.Exists(storagePath))
            {
                storagePath = Path.Combine(sampleDirectory, sampleId + "-" + suffix.ToString(CultureInfo.InvariantCulture) + "-" + SafeStorageFileName(fileName));
                suffix++;
            }

            File.WriteAllBytes(storagePath, sampleBytes);

            SandboxSampleState sample = new SandboxSampleState
            {
                sampleId = sampleId,
                sha256 = sha256,
                fileName = fileName,
                sizeBytes = sampleBytes.Length,
                source = source,
                host = host,
                deviceId = deviceId,
                processPath = processPath,
                suspicion = submission == null ? string.Empty : submission.suspicion ?? string.Empty,
                submittedUtc = submittedUtc.ToString("o"),
                lastSubmittedUtc = submittedUtc.ToString("o"),
                submitCount = 1,
                status = "queued",
                storagePath = storagePath,
                architecture = ReadPeArchitecture(storagePath),
                signer = TryReadSignerSubject(storagePath),
                signatureStatus = ReadSignatureStatus(storagePath),
                productName = ReadVersionInfo(storagePath, "ProductName"),
                companyName = ReadVersionInfo(storagePath, "CompanyName"),
                fileDescription = ReadVersionInfo(storagePath, "FileDescription"),
                fileVersion = ReadVersionInfo(storagePath, "FileVersion"),
                timeoutSeconds = 120,
                closeWhenDone = true
            };

            state.SandboxSamples.Add(sample);
            AppendAudit(submission == null ? string.Empty : submission.actor, "sandbox.sample.submitted." + source, sample.sampleId, sample.fileName, true, "0x00000000", "Sandbox sample submitted to the server.");
            TrimSandboxSamples();
            return sample;
        }

        private bool IngestRemovableDevice(
            string deviceId,
            CentralDeviceState device,
            RemovableDeviceObservation observation,
            HashSet<string> seenVolumeKeys,
            out bool policyAffectingChange)
        {
            policyAffectingChange = false;
            if (observation == null)
            {
                return false;
            }

            string hardwareId = NormalizeHardwareId(observation.hardwareId);
            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                return false;
            }

            EnsureDeviceAuthorizationState();

            RemovableDeviceState existing;
            bool isNew = !state.RemovableDevices.TryGetValue(hardwareId, out existing);
            if (isNew)
            {
                existing = new RemovableDeviceState
                {
                    hardwareId = hardwareId,
                    firstSeenUtc = DateTime.UtcNow.ToString("o")
                };
                state.RemovableDevices[hardwareId] = existing;
            }

            NormalizeRemovableVolumeState(existing);

            string now = DateTime.UtcNow.ToString("o");
            existing.deviceId = deviceId ?? string.Empty;
            existing.host = device == null ? string.Empty : device.Machine ?? string.Empty;
            existing.user = device == null ? string.Empty : device.User ?? string.Empty;
            existing.lastSeenUtc = now;
            existing.online = true;
            existing.model = NormalizeDeviceText(observation.model);
            existing.serialNumber = NormalizeDeviceText(observation.serialNumber);
            existing.pnpDeviceId = NormalizeDeviceText(observation.pnpDeviceId);
            existing.interfaceType = NormalizeDeviceText(observation.interfaceType);
            existing.mediaType = NormalizeDeviceText(observation.mediaType);

            RemovableVolumeState volume = UpsertRemovableVolume(existing, deviceId, device, observation, now, out policyAffectingChange);
            if (policyAffectingChange && ResolveRemovableAuthorization(hardwareId) == null)
            {
                policyAffectingChange = false;
            }
            if (volume != null)
            {
                existing.driveLetter = volume.driveLetter;
                existing.volumeGuid = volume.volumeGuid;
                existing.volumeLabel = volume.volumeLabel;
                existing.fileSystem = volume.fileSystem;
                existing.sizeBytes = volume.sizeBytes;

                if (seenVolumeKeys != null)
                {
                    seenVolumeKeys.Add(RemovableVolumeKey(existing.hardwareId, volume));
                }
            }

            if (isNew)
            {
                AppendAudit(existing.host, "central.device.removable.discovered", hardwareId, "removable-storage", true, "0x00000000", "New removable device discovered on " + existing.host + ".");
            }

            return true;
        }

        private bool MarkMissingRemovableVolumesOffline(string endpointDeviceId, HashSet<string> seenVolumeKeys)
        {
            if (string.IsNullOrWhiteSpace(endpointDeviceId))
            {
                return false;
            }

            EnsureDeviceAuthorizationState();
            HashSet<string> seen = seenVolumeKeys ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool changed = false;

            foreach (RemovableDeviceState device in state.RemovableDevices.Values)
            {
                if (device == null)
                {
                    continue;
                }

                NormalizeRemovableVolumeState(device);
                if (device.volumes == null)
                {
                    continue;
                }

                foreach (RemovableVolumeState volume in device.volumes)
                {
                    if (volume == null ||
                        !string.Equals(volume.deviceId, endpointDeviceId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (!seen.Contains(RemovableVolumeKey(device.hardwareId, volume)))
                    {
                        if (volume.online)
                        {
                            volume.online = false;
                            changed = ResolveRemovableAuthorization(device.hardwareId) != null || changed;
                        }
                    }
                }

                RemovableVolumeState primary = SelectPrimaryRemovableVolume(device);
                if (primary != null)
                {
                    device.deviceId = primary.deviceId;
                    device.host = primary.host;
                    device.user = primary.user;
                    device.driveLetter = primary.driveLetter;
                    device.volumeGuid = primary.volumeGuid;
                    device.volumeLabel = primary.volumeLabel;
                    device.fileSystem = primary.fileSystem;
                    device.sizeBytes = primary.sizeBytes;
                    device.lastSeenUtc = primary.lastSeenUtc;
                    device.online = IsRemovableVolumeOnline(primary);
                }
                else
                {
                    device.online = false;
                }
            }

            return changed;
        }

        private void MarkRemovableVolumesOffline(string endpointDeviceId)
        {
            if (string.IsNullOrWhiteSpace(endpointDeviceId))
            {
                return;
            }

            EnsureDeviceAuthorizationState();
            foreach (RemovableDeviceState device in state.RemovableDevices.Values)
            {
                if (device == null)
                {
                    continue;
                }

                NormalizeRemovableVolumeState(device);
                foreach (RemovableVolumeState volume in device.volumes)
                {
                    if (volume != null && string.Equals(volume.deviceId, endpointDeviceId, StringComparison.OrdinalIgnoreCase))
                    {
                        volume.online = false;
                    }
                }

                RemovableVolumeState primary = SelectPrimaryRemovableVolume(device);
                if (primary == null)
                {
                    device.online = false;
                    continue;
                }

                device.deviceId = primary.deviceId;
                device.host = primary.host;
                device.user = primary.user;
                device.driveLetter = primary.driveLetter;
                device.volumeGuid = primary.volumeGuid;
                device.volumeLabel = primary.volumeLabel;
                device.fileSystem = primary.fileSystem;
                device.sizeBytes = primary.sizeBytes;
                device.lastSeenUtc = primary.lastSeenUtc;
                device.online = IsRemovableVolumeOnline(primary);
            }
        }

        private static RemovableVolumeState UpsertRemovableVolume(
            RemovableDeviceState device,
            string deviceId,
            CentralDeviceState endpoint,
            RemovableDeviceObservation observation,
            string now,
            out bool policyAffectingChange)
        {
            policyAffectingChange = false;
            if (device == null || observation == null)
            {
                return null;
            }

            NormalizeRemovableVolumeState(device);

            string volumeGuid = NormalizeDeviceText(observation.volumeGuid);
            string driveLetter = NormalizeDeviceText(observation.driveLetter).ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(volumeGuid) && string.IsNullOrWhiteSpace(driveLetter))
            {
                return null;
            }

            RemovableVolumeState volume = device.volumes.FirstOrDefault(item =>
                item != null &&
                !string.IsNullOrWhiteSpace(volumeGuid) &&
                string.Equals(item.volumeGuid, volumeGuid, StringComparison.OrdinalIgnoreCase));

            if (volume == null)
            {
                volume = device.volumes.FirstOrDefault(item =>
                    item != null &&
                    !string.IsNullOrWhiteSpace(driveLetter) &&
                    string.Equals(item.driveLetter, driveLetter, StringComparison.OrdinalIgnoreCase));
            }

            if (volume == null)
            {
                volume = new RemovableVolumeState
                {
                    firstSeenUtc = now
                };
                device.volumes.Add(volume);
                policyAffectingChange = true;
            }
            else if (!volume.online ||
                     !string.Equals(volume.deviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                     !string.Equals(volume.volumeGuid, volumeGuid, StringComparison.OrdinalIgnoreCase))
            {
                policyAffectingChange = true;
            }

            volume.deviceId = deviceId ?? string.Empty;
            volume.host = endpoint == null ? string.Empty : endpoint.Machine ?? string.Empty;
            volume.user = endpoint == null ? string.Empty : endpoint.User ?? string.Empty;
            volume.driveLetter = driveLetter;
            volume.volumeGuid = volumeGuid;
            volume.volumeLabel = NormalizeDeviceText(observation.volumeLabel);
            volume.fileSystem = NormalizeDeviceText(observation.fileSystem);
            volume.sizeBytes = observation.sizeBytes;
            volume.lastSeenUtc = now;
            volume.online = true;

            return volume;
        }

        private PolicyBridgeService.NetworkConnectionEventDto TryDeserializeNetworkConnectionDetails(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return new PolicyBridgeService.NetworkConnectionEventDto();
            }

            try
            {
                if (message.StartsWith("{", StringComparison.Ordinal))
                {
                    return serializer.Deserialize<PolicyBridgeService.NetworkConnectionEventDto>(message) ??
                        new PolicyBridgeService.NetworkConnectionEventDto();
                }
            }
            catch
            {
            }

            return new PolicyBridgeService.NetworkConnectionEventDto();
        }

        private static NetworkInsightQuery NormalizeNetworkInsightQuery(NetworkInsightQuery query)
        {
            NetworkInsightQuery normalized = query ?? new NetworkInsightQuery();
            normalized.page = AuditLog.NormalizePage(normalized.page);
            normalized.pageSize = AuditLog.NormalizePageSize(normalized.pageSize, normalized.limit);
            normalized.limit = normalized.pageSize;
            normalized.baselineHours = ClampHours(normalized.baselineHours <= 0 ? 24 : normalized.baselineHours, 1, 24 * 31);
            normalized.windowHours = ClampHours(normalized.windowHours <= 0 ? normalized.baselineHours : normalized.windowHours, 1, 24 * 31);
            normalized.host = normalized.host ?? string.Empty;
            normalized.eventType = normalized.eventType ?? "all";
            normalized.newness = NormalizeNetworkInsightNewness(normalized.newness);
            normalized.search = normalized.search ?? string.Empty;
            normalized.baseline = TimeSpan.FromHours(normalized.baselineHours);
            normalized.window = TimeSpan.FromHours(normalized.windowHours);
            return normalized;
        }

        private PolicyBridgeService.DeviceRuleDto[] BuildEffectiveDeviceRules(string endpointDeviceId)
        {
            EnsureDeviceAuthorizationState();

            List<PolicyBridgeService.DeviceRuleDto> rules = state.DeviceRules
                .Select(CloneDeviceRule)
                .ToList();

            foreach (RemovableDeviceState device in state.RemovableDevices.Values)
            {
                if (device == null ||
                    string.IsNullOrWhiteSpace(device.hardwareId) ||
                    !IsRemovableDeviceOnline(device))
                {
                    continue;
                }

                RemovableDeviceAuthorizationRule authorization = ResolveRemovableAuthorization(device.hardwareId);
                if (authorization == null)
                {
                    continue;
                }

                foreach (RemovableVolumeState volume in EnumerateOnlineRemovableVolumes(device, endpointDeviceId))
                {
                    if (volume == null || string.IsNullOrWhiteSpace(volume.volumeGuid))
                    {
                        continue;
                    }

                    PolicyBridgeService.DeviceRuleDto rule = new PolicyBridgeService.DeviceRuleDto
                    {
                        deviceId = volume.volumeGuid,
                        allowInsert = string.Equals(authorization.status, "authorized", StringComparison.OrdinalIgnoreCase),
                        allowWrite = string.Equals(authorization.status, "authorized", StringComparison.OrdinalIgnoreCase) && authorization.allowWrite,
                        actor = "central-device-authorization"
                    };

                    int existing = rules.FindIndex(item => string.Equals(item.deviceId, rule.deviceId, StringComparison.OrdinalIgnoreCase));
                    if (existing >= 0)
                    {
                        rules[existing] = rule;
                    }
                    else
                    {
                        rules.Add(rule);
                    }
                }
            }

            return rules
                .OrderBy(rule => rule.deviceId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private RemovableDeviceAuthorizationRule ResolveRemovableAuthorization(string hardwareId)
        {
            RemovableDeviceAuthorizationRule authorization;
            return state.RemovableAuthorizations.TryGetValue(NormalizeHardwareId(hardwareId), out authorization)
                ? authorization
                : null;
        }

        private static bool IsRemovableDeviceOnline(RemovableDeviceState device)
        {
            NormalizeRemovableVolumeState(device);
            if (device != null &&
                device.volumes != null &&
                device.volumes.Any(IsRemovableVolumeOnline))
            {
                return true;
            }

            DateTime lastSeen;
            return device != null &&
                   DateTime.TryParse(device.lastSeenUtc, out lastSeen) &&
                   DateTime.UtcNow - lastSeen.ToUniversalTime() < TimeSpan.FromMinutes(3);
        }

        private static bool IsRemovableVolumeOnline(RemovableVolumeState volume)
        {
            DateTime lastSeen;
            return volume != null &&
                   volume.online &&
                   DateTime.TryParse(volume.lastSeenUtc, out lastSeen) &&
                   DateTime.UtcNow - lastSeen.ToUniversalTime() < TimeSpan.FromMinutes(3);
        }

        private static IEnumerable<RemovableVolumeState> EnumerateOnlineRemovableVolumes(RemovableDeviceState device, string endpointDeviceId)
        {
            NormalizeRemovableVolumeState(device);
            if (device == null || device.volumes == null)
            {
                yield break;
            }

            foreach (RemovableVolumeState volume in device.volumes)
            {
                if (volume == null ||
                    string.IsNullOrWhiteSpace(volume.volumeGuid) ||
                    !string.Equals(volume.deviceId, endpointDeviceId, StringComparison.OrdinalIgnoreCase) ||
                    !IsRemovableVolumeOnline(volume))
                {
                    continue;
                }

                yield return volume;
            }
        }

        private static int ClampHours(int value, int min, int max)
        {
            return Math.Max(min, Math.Min(max, value));
        }

        private static bool IsNetworkInsightMatch(NetworkConnectionObservation item, NetworkInsightQuery query)
        {
            if (item == null)
            {
                return false;
            }

            if (!query.includePrivateRemotes && IsPrivateRemote(item))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(query.host) &&
                !string.Equals(query.host, "all", StringComparison.OrdinalIgnoreCase) &&
                (item.host ?? string.Empty).IndexOf(query.host, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(query.eventType) &&
                !string.Equals(query.eventType, "all", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(query.eventType, "http3", StringComparison.OrdinalIgnoreCase) && !item.isHttp3) return false;
                if (string.Equals(query.eventType, "quic", StringComparison.OrdinalIgnoreCase) && !item.isQuic) return false;
                if (string.Equals(query.eventType, "dns", StringComparison.OrdinalIgnoreCase) && !item.isDns) return false;
                if (string.Equals(query.eventType, "blocked", StringComparison.OrdinalIgnoreCase) && !item.blocked) return false;
                if (string.Equals(query.eventType, "connection", StringComparison.OrdinalIgnoreCase) &&
                    (item.isDns || item.isHttp3 || item.isQuic || item.blocked)) return false;
            }

            if (!string.IsNullOrWhiteSpace(query.search))
            {
                string haystack = string.Join("\n", new[]
                {
                    item.host ?? string.Empty,
                    item.remoteIdentity ?? string.Empty,
                    item.remoteAddress ?? string.Empty,
                    item.remoteEndpoint ?? string.Empty,
                    item.domain ?? string.Empty,
                    item.processPath ?? string.Empty,
                    item.companyName ?? string.Empty,
                    item.productName ?? string.Empty,
                    item.fileDescription ?? string.Empty,
                    item.signer ?? string.Empty,
                    item.sha256 ?? string.Empty
                });

                if (haystack.IndexOf(query.search, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static string NormalizeNetworkInsightNewness(string value)
        {
            if (string.Equals(value, "all", StringComparison.OrdinalIgnoreCase))
            {
                return "all";
            }

            if (string.Equals(value, "existing", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "known", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "old", StringComparison.OrdinalIgnoreCase))
            {
                return "existing";
            }

            return "new";
        }

        private static bool IsNetworkNewnessMatch(NetworkInsightItem item, string newness)
        {
            if (item == null)
            {
                return false;
            }

            if (string.Equals(newness, "all", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(newness, "existing", StringComparison.OrdinalIgnoreCase))
            {
                return !item.isNew;
            }

            return item.isNew;
        }

        private Dictionary<string, IpInfoCacheEntry> CloneIpInfoCache()
        {
            EnsureIpInfoCache();
            return state.IpInfoCache
                .Where(pair => !string.IsNullOrWhiteSpace(pair.Key) && pair.Value != null)
                .ToDictionary(pair => pair.Key, pair => CloneIpInfo(pair.Value), StringComparer.OrdinalIgnoreCase);
        }

        private void EnsureIpInfoCache()
        {
            if (state.IpInfoCache == null)
            {
                state.IpInfoCache = new Dictionary<string, IpInfoCacheEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private IpInfoCacheEntry[] ResolveMissingIpInfo(NetworkInsightItem[] items, Dictionary<string, IpInfoCacheEntry> cache, DateTime nowUtc)
        {
            string token = GetIpInfoToken();
            if (string.IsNullOrWhiteSpace(token) || items == null || items.Length == 0)
            {
                return new IpInfoCacheEntry[0];
            }

            HashSet<string> lookupIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (NetworkInsightItem item in items)
            {
                string ip = ExtractPublicRemoteIp(item);
                if (string.IsNullOrWhiteSpace(ip))
                {
                    continue;
                }

                if (TryGetFreshIpInfo(cache, ip, nowUtc, out _))
                {
                    continue;
                }

                lookupIps.Add(ip);
                if (lookupIps.Count >= MaxIpInfoLookupsPerQuery)
                {
                    break;
                }
            }

            List<IpInfoCacheEntry> resolved = new List<IpInfoCacheEntry>();
            foreach (string ip in lookupIps)
            {
                resolved.Add(QueryIpInfoLite(ip, token, nowUtc));
            }

            return resolved.ToArray();
        }

        private static void AttachIpInfo(NetworkInsightItem[] items, Dictionary<string, IpInfoCacheEntry> cache, bool enrichmentEnabled)
        {
            if (items == null || items.Length == 0)
            {
                return;
            }

            foreach (NetworkInsightItem item in items)
            {
                string ip = ExtractPublicRemoteIp(item);
                item.ipInfoEnabled = enrichmentEnabled;
                item.ipInfoIp = ip;
                if (string.IsNullOrWhiteSpace(ip))
                {
                    item.ipInfoStatus = "not_applicable";
                    continue;
                }

                if (!TryGetFreshIpInfo(cache, ip, DateTime.UtcNow, out IpInfoCacheEntry entry))
                {
                    item.ipInfoStatus = enrichmentEnabled ? "pending" : "disabled";
                    continue;
                }

                item.ipInfoStatus = string.IsNullOrWhiteSpace(entry.error) ? "resolved" : "error";
                item.asn = entry.asn;
                item.asName = entry.as_name;
                item.asDomain = entry.as_domain;
                item.countryCode = entry.country_code;
                item.country = entry.country;
                item.continentCode = entry.continent_code;
                item.continent = entry.continent;
            }
        }

        private static bool TryGetFreshIpInfo(Dictionary<string, IpInfoCacheEntry> cache, string ip, DateTime nowUtc, out IpInfoCacheEntry entry)
        {
            entry = null;
            if (cache == null ||
                string.IsNullOrWhiteSpace(ip) ||
                !cache.TryGetValue(ip, out entry) ||
                entry == null)
            {
                return false;
            }

            DateTime resolvedUtc = ParseUtcOrMin(entry.resolvedUtc);
            TimeSpan maxAge = string.IsNullOrWhiteSpace(entry.error) ? TimeSpan.FromDays(7) : TimeSpan.FromHours(1);
            return resolvedUtc != DateTime.MinValue && nowUtc - resolvedUtc <= maxAge;
        }

        private static IpInfoCacheEntry QueryIpInfoLite(string ip, string token, DateTime nowUtc)
        {
            IpInfoCacheEntry entry = new IpInfoCacheEntry
            {
                ip = ip,
                resolvedUtc = nowUtc.ToString("o")
            };

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://api.ipinfo.io/lite/" + Uri.EscapeDataString(ip));
                request.Method = "GET";
                request.Timeout = 3000;
                request.ReadWriteTimeout = 3000;
                request.UserAgent = "DataProtector-Central/1.0";
                request.Headers["Authorization"] = "Bearer " + token;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream responseStream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(responseStream ?? Stream.Null, Encoding.UTF8))
                {
                    string json = reader.ReadToEnd();
                    JavaScriptSerializer localSerializer = JsonResponse.CreateSerializer();
                    IpInfoLiteResponse data = localSerializer.Deserialize<IpInfoLiteResponse>(json) ?? new IpInfoLiteResponse();
                    entry.asn = data.asn ?? string.Empty;
                    entry.as_name = data.as_name ?? string.Empty;
                    entry.as_domain = data.as_domain ?? string.Empty;
                    entry.country_code = data.country_code ?? string.Empty;
                    entry.country = data.country ?? string.Empty;
                    entry.continent_code = data.continent_code ?? string.Empty;
                    entry.continent = data.continent ?? string.Empty;
                    entry.error = string.Empty;
                }
            }
            catch (Exception ex)
            {
                entry.error = ex.GetType().Name;
            }

            return entry;
        }

        private static string GetIpInfoToken()
        {
            string source;
            return GetIpInfoToken(out source);
        }

        private static string GetIpInfoToken(out string source)
        {
            source = "none";
            string token = NormalizeSecret(Environment.GetEnvironmentVariable(IpInfoTokenEnvironmentVariable));
            if (!string.IsNullOrWhiteSpace(token))
            {
                source = "environment";
                return token;
            }

            token = string.Empty;
            if (string.IsNullOrWhiteSpace(token))
            {
                token = NormalizeSecret(Environment.GetEnvironmentVariable(LegacyIpInfoTokenEnvironmentVariable));
                if (!string.IsNullOrWhiteSpace(token))
                {
                    source = "environment";
                    return token;
                }
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                try
                {
                    string tokenPath = GetIpInfoTokenFilePath();
                    if (File.Exists(tokenPath))
                    {
                        token = NormalizeSecret(File.ReadAllText(tokenPath, Encoding.UTF8));
                        if (!string.IsNullOrWhiteSpace(token))
                        {
                            source = "file";
                            return token;
                        }
                    }
                }
                catch
                {
                    token = string.Empty;
                }
            }

            return token ?? string.Empty;
        }

        private static string GetIpInfoTokenFilePath()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(dataRoot, "DataProtector", IpInfoTokenFileName);
        }

        private static string NormalizeSecret(string value)
        {
            return (value ?? string.Empty).Trim().Trim('"', '\'');
        }

        private static string MaskSecret(string value)
        {
            string token = NormalizeSecret(value);
            if (string.IsNullOrWhiteSpace(token))
            {
                return string.Empty;
            }

            if (token.Length <= 8)
            {
                return new string('*', token.Length);
            }

            return token.Substring(0, 4) + new string('*', Math.Max(4, token.Length - 8)) + token.Substring(token.Length - 4);
        }

        private static string ComputeSha256Hex(byte[] bytes)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return BitConverter.ToString(sha256.ComputeHash(bytes ?? new byte[0])).Replace("-", string.Empty).ToLowerInvariant();
            }
        }

        private static string ComputeSha256Hex(string path)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty).ToLowerInvariant();
            }
        }

        private string GetSandboxSampleDirectory()
        {
            return Path.Combine(DirectoryPath, SandboxSampleDirectoryName);
        }

        private string GetSandboxRunDirectory()
        {
            return Path.Combine(DirectoryPath, SandboxRunDirectoryName);
        }

        private int DeleteAllSandboxRunDirectories()
        {
            string root = GetSandboxRunDirectory();
            if (!Directory.Exists(root))
            {
                return 0;
            }

            int removed = 0;
            foreach (string directory in Directory.GetDirectories(root))
            {
                if (TryDeleteDirectory(directory))
                {
                    removed++;
                }
            }

            return removed;
        }

        private bool ClearSandboxSampleReport(SandboxSampleState sample)
        {
            if (sample == null)
            {
                return false;
            }

            bool hadReport = !string.IsNullOrWhiteSpace(sample.reportJson) ||
                             !string.IsNullOrWhiteSpace(sample.startedUtc) ||
                             !string.IsNullOrWhiteSpace(sample.completedUtc) ||
                             !string.IsNullOrWhiteSpace(sample.error) ||
                             sample.exitCode != 0;
            sample.reportJson = string.Empty;
            sample.startedUtc = string.Empty;
            sample.completedUtc = string.Empty;
            sample.error = string.Empty;
            sample.exitCode = 0;
            if (!string.Equals(sample.status, "running", StringComparison.OrdinalIgnoreCase))
            {
                sample.status = "queued";
            }

            return hadReport;
        }

        private bool TryRestoreSandboxReport(SandboxSampleState sample)
        {
            if (sample == null ||
                !string.IsNullOrWhiteSpace(sample.reportJson) ||
                !string.Equals(sample.status, "completed", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string reportPath = TryFindSandboxReportPath(sample);
            if (string.IsNullOrWhiteSpace(reportPath))
            {
                return false;
            }

            try
            {
                FileInfo reportFile = new FileInfo(reportPath);
                if (!reportFile.Exists || reportFile.Length <= 0 || reportFile.Length > 4 * 1024 * 1024)
                {
                    return false;
                }

                string reportJson = File.ReadAllText(reportPath, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(reportJson) ||
                    reportJson.IndexOf("\"dataprotector.sandbox.report", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }

                sample.reportJson = Truncate(reportJson, 4 * 1024 * 1024);
                sample.error = string.Empty;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private string TryFindSandboxReportPath(SandboxSampleState sample)
        {
            string root = GetSandboxRunDirectory();
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                return string.Empty;
            }

            List<string> candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(sample.startedUtc) && DateTime.TryParse(sample.startedUtc, out DateTime startedUtc))
            {
                foreach (DirectoryInfo directory in new DirectoryInfo(root).EnumerateDirectories().OrderByDescending(item => item.LastWriteTimeUtc).Take(50))
                {
                    if (Math.Abs((directory.LastWriteTimeUtc - startedUtc.ToUniversalTime()).TotalHours) <= 12)
                    {
                        candidates.Add(Path.Combine(directory.FullName, "report", "report.json"));
                    }
                }
            }
            else
            {
                candidates.AddRange(new DirectoryInfo(root)
                    .EnumerateDirectories()
                    .OrderByDescending(item => item.LastWriteTimeUtc)
                    .Take(50)
                    .Select(item => Path.Combine(item.FullName, "report", "report.json")));
            }

            string expectedSha256 = NormalizeSha256(sample.sha256);
            string expectedName = sample.fileName ?? string.Empty;
            foreach (string candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (IsSandboxReportForSample(candidate, expectedSha256, expectedName))
                {
                    return candidate;
                }
            }

            return string.Empty;
        }

        private bool IsSandboxReportForSample(string reportPath, string expectedSha256, string expectedName)
        {
            if (string.IsNullOrWhiteSpace(reportPath) || !File.Exists(reportPath))
            {
                return false;
            }

            try
            {
                string reportJson = File.ReadAllText(reportPath, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(reportJson))
                {
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(expectedSha256) &&
                    reportJson.IndexOf(expectedSha256, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }

                return !string.IsNullOrWhiteSpace(expectedName) &&
                       reportJson.IndexOf(expectedName, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch
            {
                return false;
            }
        }

        private void AddSandboxReportDirectoryCandidates(HashSet<string> paths, string reportJson)
        {
            if (paths == null || string.IsNullOrWhiteSpace(reportJson))
            {
                return;
            }

            try
            {
                Dictionary<string, object> report = serializer.Deserialize<Dictionary<string, object>>(reportJson);
                if (report == null)
                {
                    return;
                }

                object hostReportRoot;
                if (report.TryGetValue("hostReportRoot", out hostReportRoot))
                {
                    AddSandboxRunDirectoryPathCandidate(paths, Convert.ToString(hostReportRoot, CultureInfo.InvariantCulture));
                }

                object runId;
                if (report.TryGetValue("runId", out runId))
                {
                    AddSandboxRunDirectoryCandidate(paths, Convert.ToString(runId, CultureInfo.InvariantCulture));
                }
            }
            catch
            {
            }
        }

        private void AddSandboxRunDirectoryCandidate(HashSet<string> paths, string runId)
        {
            if (paths == null || string.IsNullOrWhiteSpace(runId))
            {
                return;
            }

            string safeRunId = new string(runId.Trim().Where(ch => char.IsLetterOrDigit(ch) || ch == '-' || ch == '_').ToArray());
            if (string.IsNullOrWhiteSpace(safeRunId))
            {
                return;
            }

            AddSandboxRunDirectoryPathCandidate(paths, Path.Combine(GetSandboxRunDirectory(), safeRunId));
        }

        private void AddSandboxRunDirectoryPathCandidate(HashSet<string> paths, string candidate)
        {
            string safePath;
            if (paths == null || !TryGetSafeSandboxRunDirectory(candidate, out safePath))
            {
                return;
            }

            paths.Add(safePath);
        }

        private bool TryGetSafeSandboxRunDirectory(string candidate, out string safePath)
        {
            safePath = string.Empty;
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return false;
            }

            try
            {
                string root = Path.GetFullPath(GetSandboxRunDirectory()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(candidate.Trim().Trim('"'))).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (string.Equals(full, root, StringComparison.OrdinalIgnoreCase) ||
                    !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                safePath = full;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void RunSandboxAnalysisWorker(string sampleId, Dictionary<string, object> args, string actor)
        {
            VirtualSandboxRunner.SandboxTaskResult result;
            Exception failure = null;
            try
            {
                result = sandboxRunner.Run(args);
            }
            catch (Exception ex)
            {
                result = null;
                failure = ex;
            }

            lock (syncRoot)
            {
                EnsureSandboxState();
                SandboxSampleState sample = state.SandboxSamples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample == null)
                {
                    return;
                }

                sample.completedUtc = DateTime.UtcNow.ToString("o");
                if (failure != null)
                {
                    sample.status = "failed";
                    sample.error = failure.Message;
                    sample.exitCode = 1;
                    AppendAudit(actor, "sandbox.analysis.failed", sample.sampleId, sample.fileName, false, "0x00000001", failure.Message);
                }
                else
                {
                    sample.exitCode = result.ExitCode;
                    sample.reportJson = Truncate(result.Output, 4 * 1024 * 1024);
                    sample.error = result.ExitCode == 0 ? string.Empty : "Sandbox analysis finished with exit code " + result.ExitCode.ToString(CultureInfo.InvariantCulture) + ".";
                    sample.status = result.ExitCode == 0 ? "completed" : "failed";
                    AppendAudit(actor, "sandbox.analysis." + sample.status, sample.sampleId, sample.fileName, result.ExitCode == 0, result.ExitCode == 0 ? "0x00000000" : "0x00000001", result.ExitCode == 0 ? "Server-side sandbox analysis completed." : sample.error);
                }

                Save();
            }
        }

        private static Dictionary<string, object> BuildSandboxRunnerArgs(SandboxSampleState sample)
        {
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "path", sample.storagePath ?? string.Empty },
                { "arguments", sample.arguments ?? string.Empty },
                { "timeoutSeconds", sample.timeoutSeconds },
                { "networkEnabled", sample.networkEnabled },
                { "copyInputDirectory", false },
                { "closeWhenDone", sample.closeWhenDone }
            };
        }

        private static SandboxSampleDto ToSandboxSampleDto(SandboxSampleState sample)
        {
            if (sample == null)
            {
                return new SandboxSampleDto();
            }

            return new SandboxSampleDto
            {
                sampleId = sample.sampleId,
                sha256 = sample.sha256,
                fileName = sample.fileName,
                sizeBytes = sample.sizeBytes,
                source = sample.source,
                host = sample.host,
                deviceId = sample.deviceId,
                processPath = sample.processPath,
                suspicion = sample.suspicion,
                submittedUtc = sample.submittedUtc,
                lastSubmittedUtc = sample.lastSubmittedUtc,
                submitCount = sample.submitCount,
                status = sample.status,
                startedUtc = sample.startedUtc,
                completedUtc = sample.completedUtc,
                timeoutSeconds = sample.timeoutSeconds,
                networkEnabled = sample.networkEnabled,
                closeWhenDone = sample.closeWhenDone,
                exitCode = sample.exitCode,
                error = sample.error,
                reportJson = sample.reportJson,
                architecture = sample.architecture,
                signer = sample.signer,
                signatureStatus = sample.signatureStatus,
                productName = sample.productName,
                companyName = sample.companyName,
                fileDescription = sample.fileDescription,
                fileVersion = sample.fileVersion
            };
        }

        private static SandboxSampleQuery NormalizeSandboxSampleQuery(SandboxSampleQuery query)
        {
            SandboxSampleQuery source = query ?? new SandboxSampleQuery();
            return new SandboxSampleQuery
            {
                page = ClampInt(source.page <= 0 ? 1 : source.page, 1, 1000000),
                pageSize = ClampInt(source.pageSize <= 0 ? 30 : source.pageSize, 1, 100),
                status = NormalizeDeviceText(source.status),
                source = NormalizeDeviceText(source.source),
                host = NormalizeDeviceText(source.host),
                search = NormalizeDeviceText(source.search)
            };
        }

        private static SandboxSampleUploadRequest NormalizeSandboxUpload(SandboxSampleUploadRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample upload body is required.");
            }

            if (string.IsNullOrWhiteSpace(request.contentBase64))
            {
                throw new PolicyBridgeService.BridgeException(1, "Sandbox sample payload is required.");
            }

            return new SandboxSampleUploadRequest
            {
                fileName = NormalizeFileName(request.fileName),
                contentBase64 = request.contentBase64.Trim(),
                sha256 = NormalizeSha256(request.sha256),
                source = string.IsNullOrWhiteSpace(request.source) ? "web" : NormalizeSandboxSource(request.source),
                host = NormalizeDeviceText(request.host),
                deviceId = NormalizeDeviceText(request.deviceId),
                processPath = request.processPath ?? string.Empty,
                suspicion = NormalizeDeviceText(request.suspicion),
                actor = NormalizeDeviceText(request.actor)
            };
        }

        private static string SandboxSampleHaystack(SandboxSampleState item)
        {
            return string.Join("\n", new[]
            {
                item.fileName ?? string.Empty,
                item.sha256 ?? string.Empty,
                item.source ?? string.Empty,
                item.host ?? string.Empty,
                item.deviceId ?? string.Empty,
                item.processPath ?? string.Empty,
                item.suspicion ?? string.Empty,
                item.signer ?? string.Empty,
                item.signatureStatus ?? string.Empty,
                item.productName ?? string.Empty,
                item.companyName ?? string.Empty,
                item.fileDescription ?? string.Empty
            });
        }

        private static string NormalizeSandboxSource(string value)
        {
            string normalized = NormalizeDeviceText(value).ToLowerInvariant();
            return string.Equals(normalized, "agent", StringComparison.OrdinalIgnoreCase) ? "agent" : "web";
        }

        private static string NormalizeSha256(string value)
        {
            string normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
            if (normalized.Length != 64 || normalized.Any(ch => !Uri.IsHexDigit(ch)))
            {
                return string.Empty;
            }

            return normalized;
        }

        private static string NormalizeFileName(string value)
        {
            string name = Path.GetFileName((value ?? string.Empty).Trim());
            if (string.IsNullOrWhiteSpace(name))
            {
                name = "sample.exe";
            }

            return name.Length > 180 ? name.Substring(0, 180) : name;
        }

        private static string SafeStorageFileName(string value)
        {
            string name = NormalizeFileName(value);
            foreach (char ch in Path.GetInvalidFileNameChars())
            {
                name = name.Replace(ch, '_');
            }

            return name;
        }

        private static bool IsExecutableImage(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 0x40 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(bytes, 0x3C);
            return peOffset > 0 &&
                   peOffset + 4 < bytes.Length &&
                   bytes[peOffset] == (byte)'P' &&
                   bytes[peOffset + 1] == (byte)'E' &&
                   bytes[peOffset + 2] == 0 &&
                   bytes[peOffset + 3] == 0;
        }

        private static string ReadPeArchitecture(string path)
        {
            try
            {
                using (BinaryReader reader = new BinaryReader(File.OpenRead(path)))
                {
                    if (reader.BaseStream.Length < 0x40)
                    {
                        return "unknown";
                    }

                    reader.BaseStream.Seek(0x3C, SeekOrigin.Begin);
                    int peOffset = reader.ReadInt32();
                    if (peOffset <= 0 || peOffset + 6 > reader.BaseStream.Length)
                    {
                        return "unknown";
                    }

                    reader.BaseStream.Seek(peOffset, SeekOrigin.Begin);
                    if (reader.ReadUInt32() != 0x00004550)
                    {
                        return "unknown";
                    }

                    ushort machine = reader.ReadUInt16();
                    if (machine == 0x014C) return "x86";
                    if (machine == 0x8664) return "x64";
                    if (machine == 0xAA64) return "arm64";
                    return "machine-0x" + machine.ToString("X4", CultureInfo.InvariantCulture);
                }
            }
            catch
            {
                return "unknown";
            }
        }

        private static string TryReadSignerSubject(string path)
        {
            try
            {
                System.Security.Cryptography.X509Certificates.X509Certificate certificate =
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                return certificate == null ? string.Empty : certificate.Subject;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string ReadSignatureStatus(string path)
        {
            return string.IsNullOrWhiteSpace(TryReadSignerSubject(path)) ? "unsigned" : "signed";
        }

        private static string ReadVersionInfo(string path, string field)
        {
            try
            {
                FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
                if (string.Equals(field, "ProductName", StringComparison.OrdinalIgnoreCase)) return info.ProductName ?? string.Empty;
                if (string.Equals(field, "CompanyName", StringComparison.OrdinalIgnoreCase)) return info.CompanyName ?? string.Empty;
                if (string.Equals(field, "FileDescription", StringComparison.OrdinalIgnoreCase)) return info.FileDescription ?? string.Empty;
                if (string.Equals(field, "FileVersion", StringComparison.OrdinalIgnoreCase)) return info.FileVersion ?? string.Empty;
            }
            catch
            {
            }

            return string.Empty;
        }

        private static int ClampInt(int value, int min, int max)
        {
            return Math.Max(min, Math.Min(max, value));
        }

        private static bool TryDeleteFile(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return false;
                }

                File.Delete(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private int DeleteAllSandboxSampleStoreFiles()
        {
            string root = GetSandboxSampleDirectory();
            if (!Directory.Exists(root))
            {
                return 0;
            }

            int removed = 0;
            foreach (string file in Directory.GetFiles(root))
            {
                if (TryDeleteFile(file))
                {
                    removed++;
                }
            }

            foreach (string directory in Directory.GetDirectories(root))
            {
                if (TryDeleteDirectory(directory))
                {
                    removed++;
                }
            }

            return removed;
        }

        private static bool TryDeleteDirectory(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
                {
                    return false;
                }

                Directory.Delete(path, true);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void ValidateUsbCryptPackageBytes(byte[] packageBytes)
        {
            bool hasTool = false;
            bool hasDriver = false;

            try
            {
                using (MemoryStream memory = new MemoryStream(packageBytes))
                using (System.IO.Compression.ZipArchive archive = new System.IO.Compression.ZipArchive(memory, System.IO.Compression.ZipArchiveMode.Read))
                {
                    foreach (System.IO.Compression.ZipArchiveEntry entry in archive.Entries)
                    {
                        string name = Path.GetFileName(entry.FullName ?? string.Empty);
                        hasTool = hasTool || string.Equals(name, "DataProtectorUsbTool.exe", StringComparison.OrdinalIgnoreCase);
                        hasDriver = hasDriver || string.Equals(name, "DataProtectorUsbCrypt.sys", StringComparison.OrdinalIgnoreCase);
                    }
                }
            }
            catch
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package must be a valid zip archive.");
            }

            if (!hasTool || !hasDriver)
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package must contain DataProtectorUsbTool.exe and DataProtectorUsbCrypt.sys.");
            }
        }

        private static bool IsIpInfoEnabled()
        {
            return !string.IsNullOrWhiteSpace(GetIpInfoToken());
        }

        private static NetworkInsightItem ToNetworkInsightItem(
            List<NetworkConnectionObservation> items,
            Dictionary<string, NetworkConnectionObservation> firstSeenByKey,
            DateTime baselineUtc)
        {
            NetworkConnectionObservation latest = items
                .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                .First();
            NetworkConnectionObservation first;
            if (firstSeenByKey == null ||
                !firstSeenByKey.TryGetValue(NetworkObservationKey(latest), out first) ||
                first == null)
            {
                first = items
                    .OrderBy(item => ParseUtcOrMax(item.firstSeenUtc))
                    .First();
            }

            DateTime firstSeenUtc = ParseUtcOrMin(first.firstSeenUtc);

            return new NetworkInsightItem
            {
                key = NetworkObservationFingerprint(latest),
                isNew = firstSeenUtc == DateTime.MinValue || firstSeenUtc > baselineUtc,
                firstSeenUtc = first.firstSeenUtc,
                lastSeenUtc = latest.lastSeenUtc,
                count = items.Sum(item => item.count),
                hosts = items.Select(item => item.host).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value).ToArray(),
                remoteIdentity = latest.remoteIdentity,
                remoteAddress = latest.remoteAddress,
                remoteEndpoint = latest.remoteEndpoint,
                domain = latest.domain,
                processPath = latest.processPath,
                direction = latest.direction,
                protocolName = latest.protocolName,
                isDns = latest.isDns,
                isQuic = latest.isQuic,
                isHttp3 = latest.isHttp3,
                blocked = latest.blocked,
                fileExists = latest.fileExists,
                fileSize = latest.fileSize,
                fileModifiedUtc = latest.fileModifiedUtc,
                productName = latest.productName,
                companyName = latest.companyName,
                fileDescription = latest.fileDescription,
                fileVersion = latest.fileVersion,
                sha256 = latest.sha256,
                signatureStatus = latest.signatureStatus,
                signer = latest.signer
            };
        }

        private static NetworkTrendBucket[] BuildNetworkTrendBuckets(IEnumerable<NetworkInsightItem> items)
        {
            return (items ?? Enumerable.Empty<NetworkInsightItem>())
                .Select(item => new { item, timestamp = ParseUtcOrMin(item.lastSeenUtc) })
                .Where(item => item.timestamp != DateTime.MinValue)
                .GroupBy(item => new DateTime(item.timestamp.Year, item.timestamp.Month, item.timestamp.Day, item.timestamp.Hour, 0, 0, DateTimeKind.Utc))
                .OrderBy(group => group.Key)
                .Select(group => new NetworkTrendBucket
                {
                    label = group.Key.ToLocalTime().ToString("M/d HH':00'", CultureInfo.InvariantCulture),
                    total = group.Sum(item => Math.Max(1, item.item.count)),
                    fresh = group.Where(item => item.item.isNew).Sum(item => Math.Max(1, item.item.count)),
                    quic = group.Where(item => item.item.isQuic || item.item.isHttp3).Sum(item => Math.Max(1, item.item.count))
                })
                .TakeLastCompat(24)
                .ToArray();
        }

        private static NetworkDistributionItem[] BuildNetworkEventDistribution(IEnumerable<NetworkInsightItem> items)
        {
            NetworkInsightItem[] rows = (items ?? Enumerable.Empty<NetworkInsightItem>()).ToArray();
            return new[]
            {
                new NetworkDistributionItem { name = "connection", value = rows.Count(item => !item.isDns && !item.isQuic && !item.blocked) },
                new NetworkDistributionItem { name = "dns", value = rows.Count(item => item.isDns) },
                new NetworkDistributionItem { name = "quic", value = rows.Count(item => item.isQuic && !item.isHttp3) },
                new NetworkDistributionItem { name = "http3", value = rows.Count(item => item.isHttp3) },
                new NetworkDistributionItem { name = "blocked", value = rows.Count(item => item.blocked) }
            }
            .Where(item => item.value > 0)
            .ToArray();
        }

        private static string NetworkObservationKey(NetworkConnectionObservation item)
        {
            if (item == null)
            {
                return string.Empty;
            }

            return NormalizeIdentityPart(item.processPath).Replace('/', '\\') + "|" + NetworkObservationRemoteKey(item);
        }

        private static string NetworkObservationStorageKey(NetworkConnectionObservation item)
        {
            if (item == null)
            {
                return string.Empty;
            }

            string deviceKey = NormalizeIdentityPart(item.deviceId);
            if (string.IsNullOrWhiteSpace(deviceKey))
            {
                deviceKey = NormalizeIdentityPart(item.host);
            }

            return deviceKey + "|" + NetworkObservationKey(item);
        }

        private static string NetworkObservationFingerprint(NetworkConnectionObservation item)
        {
            return "nwa-" + ComputeCrc32(NetworkObservationKey(item)).ToString("x8", CultureInfo.InvariantCulture);
        }

        private static string NetworkObservationRemoteKey(NetworkConnectionObservation item)
        {
            string remote = PreferNonEmpty(item.domain, item.remoteAddress);
            remote = PreferNonEmpty(remote, item.remoteIdentity);
            remote = PreferNonEmpty(remote, item.remoteEndpoint);
            return NormalizeRemoteIdentity(remote);
        }

        private static bool IsPrivateRemote(NetworkConnectionObservation item)
        {
            if (item == null)
            {
                return false;
            }

            return IsPrivateRemote(item.remoteAddress) ||
                   IsPrivateRemote(item.remoteEndpoint) ||
                   IsPrivateRemote(item.remoteIdentity) ||
                   IsPrivateRemote(item.domain);
        }

        private static bool IsPrivateRemote(string value)
        {
            string normalized = NormalizeRemoteIdentity(value);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return false;
            }

            IPAddress address;
            return IPAddress.TryParse(normalized, out address) && !IsPublicIpAddress(address);
        }

        private static string ExtractPublicRemoteIp(NetworkInsightItem item)
        {
            if (item == null)
            {
                return string.Empty;
            }

            string ip = ExtractPublicIp(item.remoteAddress);
            if (!string.IsNullOrWhiteSpace(ip)) return ip;

            ip = ExtractPublicIp(item.remoteEndpoint);
            if (!string.IsNullOrWhiteSpace(ip)) return ip;

            ip = ExtractPublicIp(item.remoteIdentity);
            if (!string.IsNullOrWhiteSpace(ip)) return ip;

            return ExtractPublicIp(item.domain);
        }

        private static string ExtractPublicIp(string value)
        {
            string normalized = NormalizeRemoteIdentity(value);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return string.Empty;
            }

            IPAddress address;
            if (!IPAddress.TryParse(normalized, out address))
            {
                return string.Empty;
            }

            return IsPublicIpAddress(address) ? address.ToString() : string.Empty;
        }

        private static bool IsPublicIpAddress(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                byte first = bytes[0];
                byte second = bytes[1];
                if (first == 10) return false;
                if (first == 127) return false;
                if (first == 169 && second == 254) return false;
                if (first == 172 && second >= 16 && second <= 31) return false;
                if (first == 192 && second == 168) return false;
                if (first == 0) return false;
                if (first >= 224) return false;
                return true;
            }

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (address.Equals(IPAddress.IPv6Loopback)) return false;
                if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) return false;
                if ((bytes[0] & 0xFE) == 0xFC) return false;
                return true;
            }

            return false;
        }

        private static string NormalizeIdentityPart(string value)
        {
            return (value ?? string.Empty).Trim().ToLowerInvariant();
        }

        private static string NormalizeRemoteIdentity(string value)
        {
            string remote = NormalizeIdentityPart(value).TrimEnd('.');
            if (remote.Length == 0)
            {
                return remote;
            }

            if (remote[0] == '[')
            {
                int endBracket = remote.IndexOf(']');
                if (endBracket > 1)
                {
                    return remote.Substring(1, endBracket - 1);
                }
            }

            int lastColon = remote.LastIndexOf(':');
            if (lastColon > 0 &&
                remote.IndexOf(':') == lastColon &&
                lastColon + 1 < remote.Length &&
                remote.Substring(lastColon + 1).All(char.IsDigit))
            {
                return remote.Substring(0, lastColon);
            }

            return remote;
        }

        private static string PreferNonEmpty(string preferred, string fallback)
        {
            return string.IsNullOrWhiteSpace(preferred) ? (fallback ?? string.Empty) : preferred;
        }

        private static uint ComputeCrc32(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
            uint crc = 0xFFFFFFFF;
            for (int i = 0; i < bytes.Length; i++)
            {
                crc ^= bytes[i];
                for (int bit = 0; bit < 8; bit++)
                {
                    uint mask = (uint)-(int)(crc & 1);
                    crc = (crc >> 1) ^ (0xEDB88320 & mask);
                }
            }

            return ~crc;
        }

        private static IpInfoCacheEntry CloneIpInfo(IpInfoCacheEntry item)
        {
            if (item == null)
            {
                return null;
            }

            return new IpInfoCacheEntry
            {
                ip = item.ip,
                asn = item.asn,
                as_name = item.as_name,
                as_domain = item.as_domain,
                country_code = item.country_code,
                country = item.country,
                continent_code = item.continent_code,
                continent = item.continent,
                resolvedUtc = item.resolvedUtc,
                error = item.error
            };
        }

        private static NetworkConnectionObservation CloneNetworkObservation(NetworkConnectionObservation item)
        {
            return new NetworkConnectionObservation
            {
                deviceId = item.deviceId,
                host = item.host,
                user = item.user,
                remoteIdentity = item.remoteIdentity,
                remoteAddress = item.remoteAddress,
                remoteEndpoint = item.remoteEndpoint,
                domain = item.domain,
                processPath = item.processPath,
                processId = item.processId,
                direction = item.direction,
                protocolName = item.protocolName,
                localEndpoint = item.localEndpoint,
                remotePort = item.remotePort,
                isDns = item.isDns,
                isQuic = item.isQuic,
                isHttp3 = item.isHttp3,
                blocked = item.blocked,
                fileExists = item.fileExists,
                fileSize = item.fileSize,
                fileModifiedUtc = item.fileModifiedUtc,
                productName = item.productName,
                companyName = item.companyName,
                fileDescription = item.fileDescription,
                fileVersion = item.fileVersion,
                sha256 = item.sha256,
                signatureStatus = item.signatureStatus,
                signer = item.signer,
                firstSeenUtc = item.firstSeenUtc,
                lastSeenUtc = item.lastSeenUtc,
                count = item.count
            };
        }

        private static DateTime ParseUtcOrMin(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out parsed)
                ? parsed.ToUniversalTime()
                : DateTime.MinValue;
        }

        private static DateTime ParseUtcOrMax(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out parsed)
                ? parsed.ToUniversalTime()
                : DateTime.MaxValue;
        }

        private void TrimTasks()
        {
            const int maxTaskRecords = 5000;
            if (state.Tasks.Count > maxTaskRecords)
            {
                state.Tasks = state.Tasks
                    .OrderByDescending(task => task.createdUtc, StringComparer.OrdinalIgnoreCase)
                    .Take(maxTaskRecords)
                    .ToList();
            }
        }

        private RemoteTaskDto[] AssignTasks(string deviceId)
        {
            DateTime now = DateTime.UtcNow;
            List<RemoteTaskDto> tasks = new List<RemoteTaskDto>();

            foreach (RemoteTaskState task in state.Tasks
                .Where(task => string.Equals(task.deviceId, deviceId, StringComparison.OrdinalIgnoreCase))
                .Where(task => task.status == "queued" || IsStaleSentTask(task, now))
                .OrderBy(task => task.createdUtc, StringComparer.OrdinalIgnoreCase)
                .Take(5))
            {
                string secretArguments = null;
                if (IsOneShotSecretTask(task.kind) &&
                    !volatileTaskArguments.TryGetValue(task.taskId, out secretArguments))
                {
                    task.status = "failed";
                    task.completedUtc = now.ToString("o");
                    task.succeeded = false;
                    task.exitCode = 1;
                    task.output = string.Empty;
                    task.error = "One-shot task secret is no longer available. Queue the initialization again.";
                    AppendAudit(deviceId, "remote.task.secret.expired." + task.kind, task.taskId, string.Empty, false, "0x00000001", task.error);
                    continue;
                }

                task.status = "sent";
                task.sentUtc = now.ToString("o");
                if (IsOneShotSecretTask(task.kind))
                {
                    RemoteTaskDto dto = CloneTask(task);
                    dto.argumentsJson = secretArguments;
                    volatileTaskArguments.Remove(task.taskId);
                    tasks.Add(dto);
                }
                else
                {
                    tasks.Add(CloneTask(task));
                }
            }

            return tasks.ToArray();
        }

        private void ApplyTaskResult(string deviceId, RemoteTaskResult result)
        {
            if (result == null || string.IsNullOrWhiteSpace(result.taskId))
            {
                return;
            }

            RemoteTaskState task = state.Tasks.FirstOrDefault(item =>
                string.Equals(item.taskId, result.taskId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(item.deviceId, deviceId, StringComparison.OrdinalIgnoreCase));

            if (task == null)
            {
                AppendAudit(deviceId, "remote.task.result.unknown", result.taskId, string.Empty, false, "0x00000001", "Agent returned an unknown task result.");
                return;
            }

            task.status = result.succeeded ? "completed" : "failed";
            task.completedUtc = DateTime.UtcNow.ToString("o");
            task.succeeded = result.succeeded;
            task.exitCode = result.exitCode;
            task.output = Truncate(result.output, GetTaskOutputLimit(task.kind));
            task.error = Truncate(result.error, 65536);
            RedactSensitiveTaskArgs(task);
            AppendAudit(deviceId, "remote.task.result." + task.kind, task.taskId, string.Empty, result.succeeded, result.succeeded ? "0x00000000" : "0x00000001", result.succeeded ? "Remote task completed." : task.error);
        }

        private static bool IsStaleSentTask(RemoteTaskState task, DateTime now)
        {
            TimeSpan timeout = TimeSpan.FromMinutes(5);
            DateTime sent;
            return task.status == "sent"
                && !IsOneShotSecretTask(task.kind)
                && DateTime.TryParse(task.sentUtc, out sent)
                && now - sent.ToUniversalTime() > timeout;
        }

        private static bool IsOneShotSecretTask(string kind)
        {
            return string.Equals(kind, "usbcrypt.initialize", StringComparison.OrdinalIgnoreCase);
        }

        private static void RedactSensitiveTaskArgs(RemoteTaskState task)
        {
            if (string.Equals(task.kind, "user.changePassword", StringComparison.OrdinalIgnoreCase))
            {
                task.argumentsJson = "{\"username\":\"redacted\",\"newPassword\":\"redacted\"}";
            }

            if (string.Equals(task.kind, "usbcrypt.initialize", StringComparison.OrdinalIgnoreCase))
            {
                task.argumentsJson = RedactUsbCryptInitializationArgs(task.argumentsJson);
            }
        }

        private static string RedactUsbCryptInitializationArgs(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return "{}";
            }

            try
            {
                JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
                Dictionary<string, object> args = serializer.Deserialize<Dictionary<string, object>>(json);
                if (args == null)
                {
                    return "{}";
                }

                if (args.ContainsKey("password"))
                {
                    args["password"] = "redacted";
                }

                return serializer.Serialize(args);
            }
            catch
            {
                return "{\"password\":\"redacted\"}";
            }
        }

        private static string Truncate(string value, int maxChars)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, maxChars) + "\n[truncated]";
        }

        private static int GetTaskOutputLimit(string kind)
        {
            if (string.Equals(kind, "desktop.screenshot", StringComparison.OrdinalIgnoreCase))
            {
                return 16 * 1024 * 1024;
            }

            return 262144;
        }

        private static bool IsOnline(CentralDeviceState device)
        {
            DateTime lastSeen;
            return DateTime.TryParse(device.LastSeenUtc, out lastSeen) && DateTime.UtcNow - lastSeen.ToUniversalTime() < TimeSpan.FromMinutes(3);
        }

        private RemovableDeviceDto ToRemovableDeviceDto(RemovableDeviceState device)
        {
            NormalizeRemovableVolumeState(device);
            RemovableVolumeState primary = SelectPrimaryRemovableVolume(device);
            RemovableDeviceAuthorizationRule authorization = ResolveRemovableAuthorization(device.hardwareId);
            string status = authorization == null ? "pending" : authorization.status;
            bool allowWrite = authorization != null && authorization.allowWrite;
            RemovableVolumeDto[] volumes = device.volumes == null
                ? new RemovableVolumeDto[0]
                : device.volumes
                    .Where(volume => volume != null)
                    .OrderByDescending(IsRemovableVolumeOnline)
                    .ThenBy(volume => volume.driveLetter, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(volume => volume.volumeGuid, StringComparer.OrdinalIgnoreCase)
                    .Select(ToRemovableVolumeDto)
                    .ToArray();

            return new RemovableDeviceDto
            {
                hardwareId = device.hardwareId,
                deviceId = primary == null ? device.deviceId : primary.deviceId,
                host = primary == null ? device.host : primary.host,
                user = primary == null ? device.user : primary.user,
                driveLetter = primary == null ? device.driveLetter : primary.driveLetter,
                volumeGuid = primary == null ? device.volumeGuid : primary.volumeGuid,
                volumeLabel = primary == null ? device.volumeLabel : primary.volumeLabel,
                fileSystem = primary == null ? device.fileSystem : primary.fileSystem,
                sizeBytes = device.volumes == null || device.volumes.Count == 0 ? device.sizeBytes : device.volumes.Sum(volume => volume == null ? 0 : volume.sizeBytes),
                model = device.model,
                serialNumber = device.serialNumber,
                pnpDeviceId = device.pnpDeviceId,
                interfaceType = device.interfaceType,
                mediaType = device.mediaType,
                firstSeenUtc = device.firstSeenUtc,
                lastSeenUtc = primary == null ? device.lastSeenUtc : primary.lastSeenUtc,
                online = IsRemovableDeviceOnline(device),
                volumes = volumes,
                status = status,
                allowWrite = allowWrite,
                authorizedBy = authorization == null ? string.Empty : authorization.actor,
                authorizedUtc = authorization == null ? string.Empty : authorization.updatedUtc,
                note = authorization == null ? string.Empty : authorization.note
            };
        }

        private static RemovableVolumeDto ToRemovableVolumeDto(RemovableVolumeState volume)
        {
            return new RemovableVolumeDto
            {
                deviceId = volume.deviceId,
                host = volume.host,
                user = volume.user,
                driveLetter = volume.driveLetter,
                volumeGuid = volume.volumeGuid,
                volumeLabel = volume.volumeLabel,
                fileSystem = volume.fileSystem,
                sizeBytes = volume.sizeBytes,
                firstSeenUtc = volume.firstSeenUtc,
                lastSeenUtc = volume.lastSeenUtc,
                online = IsRemovableVolumeOnline(volume)
            };
        }

        private static CentralDeviceDto ToDeviceDto(CentralDeviceState device)
        {
            return new CentralDeviceDto
            {
                deviceId = device.DeviceId,
                machine = device.Machine,
                user = device.User,
                agentVersion = device.AgentVersion,
                driverConnected = device.DriverConnected,
                driverStatus = device.DriverStatus,
                driverMessage = device.DriverMessage,
                policyVersion = device.PolicyVersion,
                firstSeenUtc = device.FirstSeenUtc,
                lastSeenUtc = device.LastSeenUtc,
                lastApplyStatus = device.LastApplyStatus,
                lastApplyMessage = device.LastApplyMessage,
                online = IsOnline(device)
            };
        }

        private static RemovableDeviceAuthorizationRule NormalizeRemovableAuthorizationRequest(RemovableDeviceAuthorizationRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Removable device authorization request body is required.");
            }

            string hardwareId = NormalizeHardwareId(request.hardwareId);
            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Hardware id is required.");
            }

            string status = (request.status ?? string.Empty).Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(status))
            {
                status = request.allowInsert ? "authorized" : "blocked";
            }

            if (status != "authorized" && status != "blocked")
            {
                throw new PolicyBridgeService.BridgeException(1, "Authorization status must be authorized or blocked.");
            }

            return new RemovableDeviceAuthorizationRule
            {
                hardwareId = hardwareId,
                status = status,
                allowWrite = status == "authorized" && request.allowWrite,
                actor = string.IsNullOrWhiteSpace(request.actor) ? "web-admin" : request.actor.Trim(),
                note = NormalizeDeviceText(request.note),
                updatedUtc = DateTime.UtcNow.ToString("o")
            };
        }

        private static string NormalizeHardwareId(string value)
        {
            return (value ?? string.Empty).Trim().ToLowerInvariant();
        }

        private static string NormalizeDeviceText(string value)
        {
            return (value ?? string.Empty).Trim();
        }

        private static void NormalizeRemovableVolumeState(RemovableDeviceState device)
        {
            if (device == null)
            {
                return;
            }

            if (device.volumes == null)
            {
                device.volumes = new List<RemovableVolumeState>();
            }

            if (!string.IsNullOrWhiteSpace(device.volumeGuid) ||
                !string.IsNullOrWhiteSpace(device.driveLetter))
            {
                bool exists = device.volumes.Any(volume =>
                    volume != null &&
                    ((!string.IsNullOrWhiteSpace(device.volumeGuid) &&
                      string.Equals(volume.volumeGuid, device.volumeGuid, StringComparison.OrdinalIgnoreCase)) ||
                     (!string.IsNullOrWhiteSpace(device.driveLetter) &&
                      string.Equals(volume.driveLetter, device.driveLetter, StringComparison.OrdinalIgnoreCase))));

                if (!exists)
                {
                    device.volumes.Add(new RemovableVolumeState
                    {
                        deviceId = device.deviceId ?? string.Empty,
                        host = device.host ?? string.Empty,
                        user = device.user ?? string.Empty,
                        driveLetter = (device.driveLetter ?? string.Empty).ToUpperInvariant(),
                        volumeGuid = device.volumeGuid ?? string.Empty,
                        volumeLabel = device.volumeLabel ?? string.Empty,
                        fileSystem = device.fileSystem ?? string.Empty,
                        sizeBytes = device.sizeBytes,
                        firstSeenUtc = device.firstSeenUtc ?? string.Empty,
                        lastSeenUtc = device.lastSeenUtc ?? string.Empty,
                        online = device.online
                    });
                }
            }
        }

        private static RemovableVolumeState SelectPrimaryRemovableVolume(RemovableDeviceState device)
        {
            NormalizeRemovableVolumeState(device);
            if (device == null || device.volumes == null || device.volumes.Count == 0)
            {
                return null;
            }

            return device.volumes
                .Where(volume => volume != null)
                .OrderByDescending(IsRemovableVolumeOnline)
                .ThenByDescending(volume => volume.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                .ThenBy(volume => volume.driveLetter, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        }

        private static string RemovableVolumeKey(string hardwareId, RemovableVolumeState volume)
        {
            if (volume == null)
            {
                return NormalizeHardwareId(hardwareId) + "|";
            }

            string identity = string.IsNullOrWhiteSpace(volume.volumeGuid)
                ? volume.driveLetter
                : volume.volumeGuid;
            return NormalizeHardwareId(hardwareId) + "|" + NormalizeDeviceText(identity).ToUpperInvariant();
        }

        private static PolicyBridgeService.PolicyRuleRequest NormalizeRequest(PolicyBridgeService.PolicyRuleRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Request body is required.");
            }

            string kind = (request.Kind ?? string.Empty).Trim();
            string value = (request.Value ?? string.Empty).Trim();
            string extension = NormalizeExtension(request.Extension);

            if (string.IsNullOrWhiteSpace(kind))
            {
                throw new PolicyBridgeService.BridgeException(1, "Rule kind is required.");
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new PolicyBridgeService.BridgeException(1, "Rule value is required.");
            }

            if (kind == "processName" && !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                value += ".exe";
            }

            return new PolicyBridgeService.PolicyRuleRequest
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

        private static bool SameRule(PolicyBridgeService.PolicyRuleDto rule, PolicyBridgeService.PolicyRuleRequest request)
        {
            return string.Equals(rule.kind, request.Kind, StringComparison.OrdinalIgnoreCase)
                && string.Equals(rule.value, request.Value, StringComparison.OrdinalIgnoreCase)
                && string.Equals(rule.extension, request.Extension, StringComparison.OrdinalIgnoreCase);
        }

        private static PolicyBridgeService.NetworkRuleDto NormalizeNetworkRequest(PolicyBridgeService.NetworkRuleRequest request, bool assignId)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Network rule request body is required.");
            }

            string kind = (request.kind ?? string.Empty).Trim().ToLowerInvariant();
            string action = string.IsNullOrWhiteSpace(request.action) ? "block" : request.action.Trim().ToLowerInvariant();
            string protocol = string.IsNullOrWhiteSpace(request.protocol) ? "any" : request.protocol.Trim().ToLowerInvariant();
            string direction = string.IsNullOrWhiteSpace(request.direction) ? "outbound" : request.direction.Trim().ToLowerInvariant();
            string domain = (request.domain ?? string.Empty).Trim().ToLowerInvariant();
            string remoteAddress = (request.remoteAddress ?? string.Empty).Trim();
            string localAddress = (request.localAddress ?? string.Empty).Trim();

            if (kind != "ip" && kind != "domain")
            {
                throw new PolicyBridgeService.BridgeException(1, "Network rule kind must be ip or domain.");
            }

            if (action != "allow" && action != "block")
            {
                throw new PolicyBridgeService.BridgeException(1, "Network rule action must be allow or block.");
            }

            if (protocol != "any" && protocol != "icmp" && protocol != "tcp" && protocol != "udp")
            {
                throw new PolicyBridgeService.BridgeException(1, "Network protocol must be any, icmp, tcp, or udp.");
            }

            if (direction != "inbound" && direction != "outbound" && direction != "both")
            {
                throw new PolicyBridgeService.BridgeException(1, "Network direction must be inbound, outbound, or both.");
            }

            if (kind == "domain" && string.IsNullOrWhiteSpace(domain))
            {
                throw new PolicyBridgeService.BridgeException(1, "Domain rule requires a domain.");
            }

            if (kind == "domain" && protocol == "icmp")
            {
                throw new PolicyBridgeService.BridgeException(1, "Domain rules do not support ICMP.");
            }

            if (kind == "ip" && string.IsNullOrWhiteSpace(remoteAddress))
            {
                remoteAddress = "*";
            }

            uint ruleId = request.ruleId;
            if (ruleId == 0 && assignId)
            {
                ruleId = GenerateRuleId(kind,
                                        action,
                                        protocol,
                                        direction,
                                        domain,
                                        localAddress,
                                        request.localPort,
                                        remoteAddress,
                                        request.remotePort);
            }

            return new PolicyBridgeService.NetworkRuleDto
            {
                ruleId = ruleId,
                kind = kind,
                action = action,
                protocol = protocol,
                direction = direction,
                localAddress = localAddress,
                localPort = request.localPort,
                remoteAddress = remoteAddress,
                remotePort = request.remotePort,
                domain = domain,
                displayTarget = kind == "domain" ? domain : remoteAddress,
                actor = request.actor
            };
        }

        private static PolicyBridgeService.WebShellRuleDto NormalizeWebShellRequest(PolicyBridgeService.WebShellRuleRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "WebShell rule request body is required.");
            }

            string directory = (request.directory ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new PolicyBridgeService.BridgeException(1, "Protected web directory is required.");
            }

            return new PolicyBridgeService.WebShellRuleDto
            {
                directory = directory,
                actor = request.actor
            };
        }

        private static PolicyBridgeService.DeviceRuleDto NormalizeDeviceRequest(PolicyBridgeService.DeviceRuleRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Device rule request body is required.");
            }

            string deviceId = (request.deviceId ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Device id is required. Use * for all removable storage.");
            }

            if (deviceId.Length > 259)
            {
                throw new PolicyBridgeService.BridgeException(1, "Device id is too long.");
            }

            return new PolicyBridgeService.DeviceRuleDto
            {
                deviceId = deviceId,
                allowInsert = request.allowInsert,
                allowWrite = request.allowInsert && request.allowWrite,
                actor = request.actor
            };
        }

        private static uint GenerateRuleId(
            string kind,
            string action,
            string protocol,
            string direction,
            string domain,
            string localAddress,
            ushort localPort,
            string remoteAddress,
            ushort remotePort)
        {
            unchecked
            {
                string key = (kind ?? string.Empty) +
                             "|" + (action ?? string.Empty) +
                             "|" + (protocol ?? string.Empty) +
                             "|" + (direction ?? string.Empty) +
                             "|" + (domain ?? string.Empty) +
                             "|" + (localAddress ?? string.Empty) +
                             "|" + localPort.ToString() +
                             "|" + (remoteAddress ?? string.Empty) +
                             "|" + remotePort.ToString();
                uint hash = 2166136261u;
                foreach (char ch in key)
                {
                    hash ^= ch;
                    hash *= 16777619u;
                }

                return hash == 0 ? 1u : hash;
            }
        }

        private static PolicyBridgeService.PolicyRuleDto CloneRule(PolicyBridgeService.PolicyRuleDto rule)
        {
            return new PolicyBridgeService.PolicyRuleDto
            {
                kind = rule.kind,
                value = rule.value,
                extension = rule.extension
            };
        }

        private static PolicyBridgeService.NetworkRuleDto CloneNetworkRule(PolicyBridgeService.NetworkRuleDto rule)
        {
            return new PolicyBridgeService.NetworkRuleDto
            {
                ruleId = rule.ruleId,
                kind = rule.kind,
                action = rule.action,
                protocol = rule.protocol,
                direction = rule.direction,
                localAddress = rule.localAddress,
                localPort = rule.localPort,
                remoteAddress = rule.remoteAddress,
                remotePort = rule.remotePort,
                domain = rule.domain,
                displayTarget = rule.displayTarget,
                actor = rule.actor
            };
        }

        private static PolicyBridgeService.WebShellRuleDto CloneWebShellRule(PolicyBridgeService.WebShellRuleDto rule)
        {
            return new PolicyBridgeService.WebShellRuleDto
            {
                directory = rule.directory,
                actor = rule.actor
            };
        }

        private static PolicyBridgeService.DeviceRuleDto CloneDeviceRule(PolicyBridgeService.DeviceRuleDto rule)
        {
            return new PolicyBridgeService.DeviceRuleDto
            {
                deviceId = rule.deviceId,
                allowInsert = rule.allowInsert,
                allowWrite = rule.allowWrite,
                actor = rule.actor
            };
        }

        private static UsbCryptDriverPackageInfo CloneUsbCryptDriverPackage(UsbCryptDriverPackageInfo package)
        {
            UsbCryptDriverPackageInfo source = package ?? new UsbCryptDriverPackageInfo();
            return new UsbCryptDriverPackageInfo
            {
                configured = source.configured,
                version = source.version ?? string.Empty,
                fileName = source.fileName ?? string.Empty,
                sha256 = source.sha256 ?? string.Empty,
                sizeBytes = source.sizeBytes,
                uploadedUtc = source.uploadedUtc ?? string.Empty,
                uploadedBy = source.uploadedBy ?? string.Empty,
                downloadPath = string.IsNullOrWhiteSpace(source.downloadPath) ? "/api/usbcrypt/driver-package/download" : source.downloadPath
            };
        }

        private static bool SameWebShellRule(PolicyBridgeService.WebShellRuleDto rule, PolicyBridgeService.WebShellRuleDto request)
        {
            return string.Equals(rule.directory, request.directory, StringComparison.OrdinalIgnoreCase);
        }

        private static bool SameDeviceRule(PolicyBridgeService.DeviceRuleDto rule, PolicyBridgeService.DeviceRuleDto request)
        {
            return string.Equals(rule.deviceId, request.deviceId, StringComparison.OrdinalIgnoreCase);
        }

        private static bool SameUsbCryptPolicy(PolicyBridgeService.UsbCryptPolicyDto rule, PolicyBridgeService.UsbCryptPolicyDto request)
        {
            PolicyBridgeService.UsbCryptPolicyDto left = PolicyBridgeService.CloneUsbCryptPolicy(rule);
            PolicyBridgeService.UsbCryptPolicyDto right = PolicyBridgeService.CloneUsbCryptPolicy(request);
            return left.enabled == right.enabled &&
                   string.Equals(left.algorithm, right.algorithm, StringComparison.OrdinalIgnoreCase) &&
                   left.publicToolAreaBytes == right.publicToolAreaBytes &&
                   left.allowClientProvisioning == right.allowClientProvisioning &&
                   left.requireHardwareAuthorization == right.requireHardwareAuthorization &&
                   string.Equals(left.keyMaterialId, right.keyMaterialId, StringComparison.OrdinalIgnoreCase);
        }

        private static UsbCryptInitializationTaskRequest NormalizeUsbCryptInitializationTaskRequest(UsbCryptInitializationTaskRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "USB initialization request body is required.");
            }

            string deviceId = NormalizeDeviceText(request.deviceId);
            string hardwareId = NormalizeHardwareId(request.hardwareId);
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Target agent device id is required.");
            }

            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                throw new PolicyBridgeService.BridgeException(1, "USB hardware id is required.");
            }

            if (string.IsNullOrEmpty(request.password) || request.password.Length < 8)
            {
                throw new PolicyBridgeService.BridgeException(1, "Initialization password must contain at least 8 characters.");
            }

            long publicToolAreaBytes = request.publicToolAreaBytes <= 0 ? 5L * 1024L * 1024L : request.publicToolAreaBytes;
            if (publicToolAreaBytes < 5L * 1024L * 1024L)
            {
                publicToolAreaBytes = 5L * 1024L * 1024L;
            }

            return new UsbCryptInitializationTaskRequest
            {
                deviceId = deviceId,
                hardwareId = hardwareId,
                password = request.password,
                publicToolAreaBytes = publicToolAreaBytes,
                dataLengthBytes = Math.Max(0, request.dataLengthBytes),
                confirmed = request.confirmed,
                actor = request.actor
            };
        }

        private UsbCryptDriverPackageInfo GetCurrentUsbCryptPackageForTask()
        {
            EnsureUsbCryptDriverPackage();
            if (state.UsbCryptDriverPackage == null ||
                !state.UsbCryptDriverPackage.configured ||
                string.IsNullOrWhiteSpace(state.UsbCryptDriverPackage.sha256) ||
                !File.Exists(GetUsbCryptPackagePath()))
            {
                throw new PolicyBridgeService.BridgeException(1, "Upload a USB crypt runtime package before initializing USB encryption.");
            }

            UsbCryptDriverPackageInfo package = CloneUsbCryptDriverPackage(state.UsbCryptDriverPackage);
            package.downloadPath = "/api/usbcrypt/driver-package/download";
            return package;
        }

        private static UsbCryptDriverPackageUploadRequest NormalizeUsbCryptDriverPackageUpload(UsbCryptDriverPackageUploadRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package upload body is required.");
            }

            if (string.IsNullOrWhiteSpace(request.base64Package))
            {
                throw new PolicyBridgeService.BridgeException(1, "USB crypt runtime package payload is required.");
            }

            string version = NormalizeDeviceText(request.version);
            if (string.IsNullOrWhiteSpace(version))
            {
                version = DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
            }

            return new UsbCryptDriverPackageUploadRequest
            {
                version = version,
                fileName = NormalizeDeviceText(request.fileName),
                base64Package = request.base64Package.Trim()
            };
        }

        private void EnsureDeviceAuthorizationState()
        {
            if (state.RemovableDevices == null)
            {
                state.RemovableDevices = new Dictionary<string, RemovableDeviceState>(StringComparer.OrdinalIgnoreCase);
            }

            if (state.RemovableAuthorizations == null)
            {
                state.RemovableAuthorizations = new Dictionary<string, RemovableDeviceAuthorizationRule>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static RemoteTaskDto CloneTask(RemoteTaskState task)
        {
            return new RemoteTaskDto
            {
                taskId = task.taskId,
                deviceId = task.deviceId,
                kind = task.kind,
                argumentsJson = task.argumentsJson,
                actor = task.actor,
                status = task.status,
                createdUtc = task.createdUtc,
                sentUtc = task.sentUtc,
                completedUtc = task.completedUtc,
                succeeded = task.succeeded,
                exitCode = task.exitCode,
                output = task.output,
                error = task.error
            };
        }

        private static AuditLog.AuditRecord CloneAudit(AuditLog.AuditRecord record)
        {
            if (record == null)
            {
                return new AuditLog.AuditRecord();
            }

            AuditLog.AuditRecord clone = new AuditLog.AuditRecord
            {
                TimestampUtc = string.IsNullOrWhiteSpace(record.TimestampUtc) ? DateTime.UtcNow.ToString("o") : record.TimestampUtc,
                Host = record.Host ?? string.Empty,
                Actor = record.Actor ?? string.Empty,
                Action = record.Action ?? string.Empty,
                Target = record.Target ?? string.Empty,
                Extension = record.Extension ?? string.Empty,
                Succeeded = record.Succeeded,
                Status = record.Status ?? string.Empty,
                Message = record.Message ?? string.Empty,
                SourceHost = record.SourceHost ?? string.Empty,
                SourceUser = record.SourceUser ?? string.Empty,
                SourceProcess = record.SourceProcess ?? string.Empty,
                SourcePid = record.SourcePid ?? string.Empty,
                TargetHost = record.TargetHost ?? string.Empty,
                TargetProcess = record.TargetProcess ?? string.Empty,
                TargetPid = record.TargetPid ?? string.Empty,
                ObjectType = record.ObjectType ?? string.Empty,
                ObjectName = record.ObjectName ?? string.Empty,
                ObjectFormat = record.ObjectFormat ?? string.Empty,
                PolicyName = record.PolicyName ?? string.Empty,
                Disposition = record.Disposition ?? string.Empty,
                Severity = record.Severity ?? string.Empty,
                EventDetails = record.EventDetails ?? string.Empty
            };
            AuditLog.EnrichRecord(clone);
            return clone;
        }

        private static bool IsAuditDeleteMatch(AuditLog.AuditRecord record, AuditLog.AuditDeleteOptions options)
        {
            if (record == null || options == null)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.TimestampUtc) &&
                !string.Equals(record.TimestampUtc, options.TimestampUtc, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Action) &&
                !string.Equals(record.Action, options.Action, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Target) &&
                !string.Equals(record.Target, options.Target, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Status) &&
                !string.Equals(record.Status, options.Status, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Message) &&
                !string.Equals(record.Message, options.Message, StringComparison.Ordinal))
            {
                return false;
            }

            return !string.IsNullOrWhiteSpace(options.TimestampUtc) ||
                   !string.IsNullOrWhiteSpace(options.Action) ||
                   !string.IsNullOrWhiteSpace(options.Target);
        }

        private static PolicyBridgeService.OperationResult Success(string message)
        {
            return new PolicyBridgeService.OperationResult
            {
                succeeded = true,
                status = 0,
                statusText = "0x00000000",
                message = message
            };
        }

        private sealed class CentralState
        {
            public CentralState()
            {
                PolicyVersion = 1;
                Rules = new List<PolicyBridgeService.PolicyRuleDto>();
                NetworkRules = new List<PolicyBridgeService.NetworkRuleDto>();
                WebShellRules = new List<PolicyBridgeService.WebShellRuleDto>();
                DeviceRules = new List<PolicyBridgeService.DeviceRuleDto>();
                HashProtectPolicy = PolicyBridgeService.DefaultHashProtectPolicy();
                LateralDefensePolicy = PolicyBridgeService.DefaultLateralDefensePolicy();
                UserHookDefensePolicy = PolicyBridgeService.DefaultUserHookDefensePolicy();
                UsbCryptPolicy = PolicyBridgeService.DefaultUsbCryptPolicy();
                DlpProtectionPolicy = PolicyBridgeService.DefaultDlpProtectionPolicy();
                UsbCryptDriverPackage = new UsbCryptDriverPackageInfo();
                Devices = new Dictionary<string, CentralDeviceState>(StringComparer.OrdinalIgnoreCase);
                RemovableDevices = new Dictionary<string, RemovableDeviceState>(StringComparer.OrdinalIgnoreCase);
                RemovableAuthorizations = new Dictionary<string, RemovableDeviceAuthorizationRule>(StringComparer.OrdinalIgnoreCase);
                Audit = new List<AuditLog.AuditRecord>();
                Tasks = new List<RemoteTaskState>();
                NetworkConnections = new List<NetworkConnectionObservation>();
                IpInfoCache = new Dictionary<string, IpInfoCacheEntry>(StringComparer.OrdinalIgnoreCase);
                SandboxSamples = new List<SandboxSampleState>();
            }

            public long PolicyVersion { get; set; }
            public List<PolicyBridgeService.PolicyRuleDto> Rules { get; set; }
            public List<PolicyBridgeService.NetworkRuleDto> NetworkRules { get; set; }
            public List<PolicyBridgeService.WebShellRuleDto> WebShellRules { get; set; }
            public List<PolicyBridgeService.DeviceRuleDto> DeviceRules { get; set; }
            public PolicyBridgeService.HashProtectPolicyDto HashProtectPolicy { get; set; }
            public PolicyBridgeService.LateralDefensePolicyDto LateralDefensePolicy { get; set; }
            public PolicyBridgeService.UserHookDefensePolicyDto UserHookDefensePolicy { get; set; }
            public PolicyBridgeService.UsbCryptPolicyDto UsbCryptPolicy { get; set; }
            public PolicyBridgeService.DlpProtectionPolicyDto DlpProtectionPolicy { get; set; }
            public UsbCryptDriverPackageInfo UsbCryptDriverPackage { get; set; }
            public Dictionary<string, CentralDeviceState> Devices { get; set; }
            public Dictionary<string, RemovableDeviceState> RemovableDevices { get; set; }
            public Dictionary<string, RemovableDeviceAuthorizationRule> RemovableAuthorizations { get; set; }
            public List<AuditLog.AuditRecord> Audit { get; set; }
            public List<RemoteTaskState> Tasks { get; set; }
            public List<NetworkConnectionObservation> NetworkConnections { get; set; }
            public Dictionary<string, IpInfoCacheEntry> IpInfoCache { get; set; }
            public List<SandboxSampleState> SandboxSamples { get; set; }
        }

        public sealed class NetworkInsightQuery
        {
            internal TimeSpan baseline;
            internal TimeSpan window;
            public int baselineHours { get; set; }
            public int windowHours { get; set; }
            public int limit { get; set; }
            public int page { get; set; }
            public int pageSize { get; set; }
            public string host { get; set; }
            public string eventType { get; set; }
            public string newness { get; set; }
            public string search { get; set; }
            public bool includePrivateRemotes { get; set; }
        }

        public sealed class NetworkInsightResponse
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public double baselineHours { get; set; }
            public double windowHours { get; set; }
            public string generatedUtc { get; set; }
            public int total { get; set; }
            public int newTotal { get; set; }
            public int http3Total { get; set; }
            public int unsignedTotal { get; set; }
            public NetworkTrendBucket[] trendBuckets { get; set; }
            public NetworkDistributionItem[] eventDistribution { get; set; }
            public NetworkInsightItem[] items { get; set; }
        }

        public sealed class AuditAttackFlowResponse
        {
            public string generatedUtc { get; set; }
            public string fromUtc { get; set; }
            public string toUtc { get; set; }
            public int eventTotal { get; set; }
            public int incidentTotal { get; set; }
            public int criticalTotal { get; set; }
            public int hostTotal { get; set; }
            public int processTotal { get; set; }
            public int remoteTotal { get; set; }
            public string summary { get; set; }
            public AuditAttackFlowStage[] stages { get; set; }
            public AuditAttackFlowIncident[] incidents { get; set; }
            public AuditAttackFlowProcess[] processes { get; set; }
            public AuditAttackFlowEntity[] entities { get; set; }
            public AuditAttackFlowEvent[] events { get; set; }
        }

        public sealed class AuditAttackFlowStage
        {
            public string key { get; set; }
            public string label { get; set; }
            public bool active { get; set; }
            public int count { get; set; }
            public string severity { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public string detail { get; set; }
        }

        public sealed class AuditAttackFlowIncident
        {
            public string key { get; set; }
            public string host { get; set; }
            public string rootProcess { get; set; }
            public string rootPid { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public string severity { get; set; }
            public int score { get; set; }
            public int eventCount { get; set; }
            public string[] stages { get; set; }
            public string[] actions { get; set; }
            public string[] remotes { get; set; }
            public string[] objects { get; set; }
        }

        public sealed class AuditAttackFlowProcess
        {
            public string key { get; set; }
            public string host { get; set; }
            public string pid { get; set; }
            public string parentPid { get; set; }
            public string name { get; set; }
            public string path { get; set; }
            public string user { get; set; }
            public string severity { get; set; }
            public int eventCount { get; set; }
        }

        public sealed class AuditAttackFlowEntity
        {
            public string key { get; set; }
            public string type { get; set; }
            public string label { get; set; }
            public string severity { get; set; }
            public int count { get; set; }
        }

        public sealed class AuditAttackFlowEvent
        {
            public string id { get; set; }
            public string timeUtc { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string stage { get; set; }
            public string category { get; set; }
            public string action { get; set; }
            public string title { get; set; }
            public string detail { get; set; }
            public string severity { get; set; }
            public string disposition { get; set; }
            public string sourceProcess { get; set; }
            public string sourcePid { get; set; }
            public string sourceUser { get; set; }
            public string targetProcess { get; set; }
            public string targetPid { get; set; }
            public string objectType { get; set; }
            public string objectName { get; set; }
            public string objectFormat { get; set; }
            public string policyName { get; set; }
            public string remoteIdentity { get; set; }
            public string rawMessage { get; set; }
        }

        private sealed class AttackIncidentAccumulator
        {
            public string key { get; set; }
            public string host { get; set; }
            public string rootProcess { get; set; }
            public string rootPid { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public string severity { get; set; }
            public int score { get; set; }
            public int eventCount { get; set; }
            public HashSet<string> stages { get; private set; }
            public HashSet<string> actions { get; private set; }
            public HashSet<string> remotes { get; private set; }
            public HashSet<string> objects { get; private set; }

            public AttackIncidentAccumulator()
            {
                stages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                actions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                remotes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                objects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public AuditAttackFlowIncident ToIncident()
            {
                return new AuditAttackFlowIncident
                {
                    key = key ?? string.Empty,
                    host = host ?? string.Empty,
                    rootProcess = rootProcess ?? string.Empty,
                    rootPid = rootPid ?? string.Empty,
                    firstSeenUtc = firstSeenUtc ?? string.Empty,
                    lastSeenUtc = lastSeenUtc ?? string.Empty,
                    severity = severity ?? "info",
                    score = score,
                    eventCount = eventCount,
                    stages = stages.Where(item => !string.IsNullOrWhiteSpace(item)).OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray(),
                    actions = actions.Where(item => !string.IsNullOrWhiteSpace(item)).OrderBy(item => item, StringComparer.OrdinalIgnoreCase).Take(12).ToArray(),
                    remotes = remotes.Where(item => !string.IsNullOrWhiteSpace(item)).OrderBy(item => item, StringComparer.OrdinalIgnoreCase).Take(12).ToArray(),
                    objects = objects.Where(item => !string.IsNullOrWhiteSpace(item)).OrderBy(item => item, StringComparer.OrdinalIgnoreCase).Take(12).ToArray()
                };
            }
        }

        public sealed class NetworkTrendBucket
        {
            public string label { get; set; }
            public int total { get; set; }
            public int fresh { get; set; }
            public int quic { get; set; }
        }

        public sealed class NetworkDistributionItem
        {
            public string name { get; set; }
            public int value { get; set; }
        }

        public sealed class IpInfoConfiguration
        {
            public bool enabled { get; set; }
            public string source { get; set; }
            public string maskedToken { get; set; }
            public string tokenFilePath { get; set; }
        }

        public sealed class IpInfoConfigurationRequest
        {
            public string token { get; set; }
        }

        public sealed class UsbCryptDriverPackageInfo
        {
            public bool configured { get; set; }
            public string version { get; set; }
            public string fileName { get; set; }
            public string sha256 { get; set; }
            public long sizeBytes { get; set; }
            public string uploadedUtc { get; set; }
            public string uploadedBy { get; set; }
            public string downloadPath { get; set; }
        }

        public sealed class UsbCryptDriverPackageUploadRequest
        {
            public string version { get; set; }
            public string fileName { get; set; }
            public string base64Package { get; set; }
        }

        public sealed class SandboxSampleQuery
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public string status { get; set; }
            public string source { get; set; }
            public string host { get; set; }
            public string search { get; set; }
        }

        public sealed class SandboxSampleQueryResponse
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public int total { get; set; }
            public int queuedTotal { get; set; }
            public int runningTotal { get; set; }
            public int completedTotal { get; set; }
            public int failedTotal { get; set; }
            public SandboxSampleDto[] items { get; set; }
        }

        public class SandboxSampleSubmission
        {
            public string fileName { get; set; }
            public string contentBase64 { get; set; }
            public string sha256 { get; set; }
            public string source { get; set; }
            public string host { get; set; }
            public string deviceId { get; set; }
            public string processPath { get; set; }
            public string suspicion { get; set; }
            public string actor { get; set; }
        }

        public sealed class SandboxSampleUploadRequest : SandboxSampleSubmission
        {
        }

        public sealed class SandboxAnalyzeRequest
        {
            public string sampleId { get; set; }
            public string arguments { get; set; }
            public int timeoutSeconds { get; set; }
            public bool networkEnabled { get; set; }
            public bool closeWhenDone { get; set; }
            public string actor { get; set; }
        }

        public sealed class SandboxSampleDeleteRequest
        {
            public string sampleId { get; set; }
            public string actor { get; set; }
        }

        public sealed class SandboxLogDeleteRequest
        {
            public string sampleId { get; set; }
            public string runId { get; set; }
            public bool all { get; set; }
            public string actor { get; set; }
        }

        public sealed class SandboxSampleDto
        {
            public string sampleId { get; set; }
            public string sha256 { get; set; }
            public string fileName { get; set; }
            public long sizeBytes { get; set; }
            public string source { get; set; }
            public string host { get; set; }
            public string deviceId { get; set; }
            public string processPath { get; set; }
            public string suspicion { get; set; }
            public string submittedUtc { get; set; }
            public string lastSubmittedUtc { get; set; }
            public int submitCount { get; set; }
            public string status { get; set; }
            public string startedUtc { get; set; }
            public string completedUtc { get; set; }
            public int timeoutSeconds { get; set; }
            public bool networkEnabled { get; set; }
            public bool closeWhenDone { get; set; }
            public int exitCode { get; set; }
            public string error { get; set; }
            public string reportJson { get; set; }
            public string architecture { get; set; }
            public string signer { get; set; }
            public string signatureStatus { get; set; }
            public string productName { get; set; }
            public string companyName { get; set; }
            public string fileDescription { get; set; }
            public string fileVersion { get; set; }
        }

        public sealed class NetworkInsightItem
        {
            public string key { get; set; }
            public bool isNew { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public int count { get; set; }
            public string[] hosts { get; set; }
            public string remoteIdentity { get; set; }
            public string remoteAddress { get; set; }
            public string remoteEndpoint { get; set; }
            public string domain { get; set; }
            public string processPath { get; set; }
            public string direction { get; set; }
            public string protocolName { get; set; }
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
            public bool ipInfoEnabled { get; set; }
            public string ipInfoStatus { get; set; }
            public string ipInfoIp { get; set; }
            public string asn { get; set; }
            public string asName { get; set; }
            public string asDomain { get; set; }
            public string countryCode { get; set; }
            public string country { get; set; }
            public string continentCode { get; set; }
            public string continent { get; set; }
        }

        private sealed class NetworkConnectionObservation
        {
            public string deviceId { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string remoteIdentity { get; set; }
            public string remoteAddress { get; set; }
            public string remoteEndpoint { get; set; }
            public string domain { get; set; }
            public string processPath { get; set; }
            public ulong processId { get; set; }
            public string direction { get; set; }
            public string protocolName { get; set; }
            public string localEndpoint { get; set; }
            public ushort remotePort { get; set; }
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
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public int count { get; set; }
        }

        private sealed class IpInfoCacheEntry
        {
            public string ip { get; set; }
            public string asn { get; set; }
            public string as_name { get; set; }
            public string as_domain { get; set; }
            public string country_code { get; set; }
            public string country { get; set; }
            public string continent_code { get; set; }
            public string continent { get; set; }
            public string resolvedUtc { get; set; }
            public string error { get; set; }
        }

        private sealed class IpInfoLiteResponse
        {
            public string ip { get; set; }
            public string asn { get; set; }
            public string as_name { get; set; }
            public string as_domain { get; set; }
            public string country_code { get; set; }
            public string country { get; set; }
            public string continent_code { get; set; }
            public string continent { get; set; }
        }

        private sealed class SandboxSampleState
        {
            public string sampleId { get; set; }
            public string sha256 { get; set; }
            public string fileName { get; set; }
            public long sizeBytes { get; set; }
            public string source { get; set; }
            public string host { get; set; }
            public string deviceId { get; set; }
            public string processPath { get; set; }
            public string suspicion { get; set; }
            public string submittedUtc { get; set; }
            public string lastSubmittedUtc { get; set; }
            public int submitCount { get; set; }
            public string status { get; set; }
            public string startedUtc { get; set; }
            public string completedUtc { get; set; }
            public int timeoutSeconds { get; set; }
            public bool networkEnabled { get; set; }
            public bool closeWhenDone { get; set; }
            public string arguments { get; set; }
            public int exitCode { get; set; }
            public string error { get; set; }
            public string reportJson { get; set; }
            public string storagePath { get; set; }
            public string architecture { get; set; }
            public string signer { get; set; }
            public string signatureStatus { get; set; }
            public string productName { get; set; }
            public string companyName { get; set; }
            public string fileDescription { get; set; }
            public string fileVersion { get; set; }
        }

        private sealed class CentralDeviceState
        {
            public string DeviceId { get; set; }
            public string Machine { get; set; }
            public string User { get; set; }
            public string AgentVersion { get; set; }
            public bool DriverConnected { get; set; }
            public string DriverStatus { get; set; }
            public string DriverMessage { get; set; }
            public long PolicyVersion { get; set; }
            public string FirstSeenUtc { get; set; }
            public string LastSeenUtc { get; set; }
            public string LastApplyStatus { get; set; }
            public string LastApplyMessage { get; set; }
        }

        private sealed class RemovableDeviceState
        {
            public string hardwareId { get; set; }
            public string deviceId { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string driveLetter { get; set; }
            public string volumeGuid { get; set; }
            public string volumeLabel { get; set; }
            public string fileSystem { get; set; }
            public long sizeBytes { get; set; }
            public string model { get; set; }
            public string serialNumber { get; set; }
            public string pnpDeviceId { get; set; }
            public string interfaceType { get; set; }
            public string mediaType { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public bool online { get; set; }
            public List<RemovableVolumeState> volumes { get; set; }
        }

        private sealed class RemovableVolumeState
        {
            public string deviceId { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string driveLetter { get; set; }
            public string volumeGuid { get; set; }
            public string volumeLabel { get; set; }
            public string fileSystem { get; set; }
            public long sizeBytes { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public bool online { get; set; }
        }

        private sealed class RemovableDeviceAuthorizationRule
        {
            public string hardwareId { get; set; }
            public string status { get; set; }
            public bool allowWrite { get; set; }
            public string actor { get; set; }
            public string note { get; set; }
            public string updatedUtc { get; set; }
        }

        public sealed class CentralDeviceDto
        {
            public string deviceId { get; set; }
            public string machine { get; set; }
            public string user { get; set; }
            public string agentVersion { get; set; }
            public bool driverConnected { get; set; }
            public string driverStatus { get; set; }
            public string driverMessage { get; set; }
            public long policyVersion { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public string lastApplyStatus { get; set; }
            public string lastApplyMessage { get; set; }
            public bool online { get; set; }
        }

        public class RemovableDeviceObservation
        {
            public string hardwareId { get; set; }
            public string driveLetter { get; set; }
            public string volumeGuid { get; set; }
            public string volumeLabel { get; set; }
            public string fileSystem { get; set; }
            public long sizeBytes { get; set; }
            public string model { get; set; }
            public string serialNumber { get; set; }
            public string pnpDeviceId { get; set; }
            public string interfaceType { get; set; }
            public string mediaType { get; set; }
            public string lastSeenUtc { get; set; }
        }

        public sealed class RemovableDeviceDto : RemovableDeviceObservation
        {
            public string deviceId { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string firstSeenUtc { get; set; }
            public bool online { get; set; }
            public RemovableVolumeDto[] volumes { get; set; }
            public string status { get; set; }
            public bool allowWrite { get; set; }
            public string authorizedBy { get; set; }
            public string authorizedUtc { get; set; }
            public string note { get; set; }
        }

        public sealed class RemovableVolumeDto
        {
            public string deviceId { get; set; }
            public string host { get; set; }
            public string user { get; set; }
            public string driveLetter { get; set; }
            public string volumeGuid { get; set; }
            public string volumeLabel { get; set; }
            public string fileSystem { get; set; }
            public long sizeBytes { get; set; }
            public string firstSeenUtc { get; set; }
            public string lastSeenUtc { get; set; }
            public bool online { get; set; }
        }

        public sealed class RemovableDeviceAuthorizationRequest
        {
            public string hardwareId { get; set; }
            public string status { get; set; }
            public bool allowInsert { get; set; }
            public bool allowWrite { get; set; }
            public string actor { get; set; }
            public string note { get; set; }
        }

        public sealed class DeviceDeleteRequest
        {
            public string deviceId { get; set; }
            public string actor { get; set; }
        }

        public sealed class RemovableDeviceDeleteRequest
        {
            public string hardwareId { get; set; }
            public string actor { get; set; }
        }

        public sealed class UsbCryptInitializationTaskRequest
        {
            public string deviceId { get; set; }
            public string hardwareId { get; set; }
            public string password { get; set; }
            public long publicToolAreaBytes { get; set; }
            public long dataLengthBytes { get; set; }
            public bool confirmed { get; set; }
            public string actor { get; set; }
            public string driverPackageVersion { get; set; }
            public string driverPackageSha256 { get; set; }
            public string driverPackageDownloadPath { get; set; }
        }

        public sealed class AgentSyncRequest
        {
            public string DeviceId { get; set; }
            public string Machine { get; set; }
            public string User { get; set; }
            public string AgentVersion { get; set; }
            public bool DriverConnected { get; set; }
            public string DriverStatus { get; set; }
            public string DriverMessage { get; set; }
            public long PolicyVersion { get; set; }
            public string LastApplyStatus { get; set; }
            public string LastApplyMessage { get; set; }
            public AuditLog.AuditRecord[] Audit { get; set; }
            public PolicyBridgeService.NetworkConnectionEventDto[] NetworkConnections { get; set; }
            public RemovableDeviceObservation[] RemovableDevices { get; set; }
            public SandboxSampleSubmission[] SandboxSamples { get; set; }
            public RemoteTaskResult[] TaskResults { get; set; }
            public bool ResultOnly { get; set; }
        }

        public sealed class AgentSyncResponse
        {
            public bool accepted { get; set; }
            public string deviceId { get; set; }
            public string serverTimeUtc { get; set; }
            public long policyVersion { get; set; }
            public PolicyBridgeService.PolicyRuleDto[] rules { get; set; }
            public PolicyBridgeService.NetworkRuleDto[] networkRules { get; set; }
            public PolicyBridgeService.WebShellRuleDto[] webShellRules { get; set; }
            public PolicyBridgeService.DeviceRuleDto[] deviceRules { get; set; }
            public PolicyBridgeService.HashProtectPolicyDto hashProtectPolicy { get; set; }
            public PolicyBridgeService.LateralDefensePolicyDto lateralDefensePolicy { get; set; }
            public PolicyBridgeService.UserHookDefensePolicyDto userHookDefensePolicy { get; set; }
            public PolicyBridgeService.UsbCryptPolicyDto usbCryptPolicy { get; set; }
            public PolicyBridgeService.DlpProtectionPolicyDto dlpProtectionPolicy { get; set; }
            public RemoteTaskDto[] tasks { get; set; }
        }

        private sealed class RemoteTaskState
        {
            public string taskId { get; set; }
            public string deviceId { get; set; }
            public string kind { get; set; }
            public string argumentsJson { get; set; }
            public string actor { get; set; }
            public string status { get; set; }
            public string createdUtc { get; set; }
            public string sentUtc { get; set; }
            public string completedUtc { get; set; }
            public bool succeeded { get; set; }
            public int exitCode { get; set; }
            public string output { get; set; }
            public string error { get; set; }
        }

        public sealed class RemoteTaskRequest
        {
            public string deviceId { get; set; }
            public string kind { get; set; }
            public string argumentsJson { get; set; }
            public string actor { get; set; }
        }

        public sealed class RemoteTaskDto
        {
            public string taskId { get; set; }
            public string deviceId { get; set; }
            public string kind { get; set; }
            public string argumentsJson { get; set; }
            public string actor { get; set; }
            public string status { get; set; }
            public string createdUtc { get; set; }
            public string sentUtc { get; set; }
            public string completedUtc { get; set; }
            public bool succeeded { get; set; }
            public int exitCode { get; set; }
            public string output { get; set; }
            public string error { get; set; }
        }

        public sealed class RemoteTaskResult
        {
            public string taskId { get; set; }
            public bool succeeded { get; set; }
            public int exitCode { get; set; }
            public string output { get; set; }
            public string error { get; set; }
        }
    }
}
