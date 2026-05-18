using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class AgentSyncClient
    {
        private const string AgentVersion = "1.0";
        private readonly Uri serverSyncUri;
        private readonly TimeSpan interval;
        private readonly PolicyBridgeService policyService;
        private readonly DlpProtectionService dlpProtectionService;
        private readonly string statePath;
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly RemoteTaskExecutor taskExecutor;
        private readonly RemovableDeviceInventory removableDeviceInventory = new RemovableDeviceInventory();
        private readonly List<CentralPolicyStore.RemoteTaskResult> pendingTaskResults = new List<CentralPolicyStore.RemoteTaskResult>();
        private readonly string usbCryptPolicyPath;
        private string deviceId;
        private long appliedPolicyVersion;
        private string lastApplyStatus = "0x00000000";
        private string lastApplyMessage = "Agent started.";
        private long heartbeatIndex;

        public AgentSyncClient(string serverBaseUrl, TimeSpan interval, PolicyBridgeService policyService)
        {
            if (string.IsNullOrWhiteSpace(serverBaseUrl))
            {
                throw new ArgumentException("Central server URL is required for agent mode.", "serverBaseUrl");
            }

            this.interval = interval <= TimeSpan.Zero ? TimeSpan.FromSeconds(15) : interval;
            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            dlpProtectionService = new DlpProtectionService();
            serverSyncUri = BuildSyncUri(serverBaseUrl);
            taskExecutor = new RemoteTaskExecutor(BuildServerBaseUri(serverBaseUrl));

            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string directory = Path.Combine(dataRoot, "DataProtector");
            statePath = Path.Combine(directory, "AgentState.json");
            usbCryptPolicyPath = Path.Combine(directory, "UsbCryptPolicy.json");
            Directory.CreateDirectory(directory);
            LoadState();
            dlpProtectionService.UpdatePolicy(PolicyBridgeService.DefaultDlpProtectionPolicy());
        }

        public void Run()
        {
            Console.WriteLine("DataProtector Agent connecting to " + serverSyncUri);
            Console.WriteLine("Agent state: " + statePath);
            Console.WriteLine("Agent executable: " + Assembly.GetExecutingAssembly().Location);
            Console.WriteLine("Agent PID: " + System.Diagnostics.Process.GetCurrentProcess().Id);
            Console.WriteLine("Policy API DLL: " + GetPolicyApiPath());

            while (true)
            {
                try
                {
                    SyncOnce();
                }
                catch (Exception ex)
                {
                    lastApplyStatus = "0x00000001";
                    lastApplyMessage = ex.Message;
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " Agent sync failed: " + ex.Message);
                }

                Thread.Sleep(interval);
            }
        }

        private void SyncOnce()
        {
            object rawStatus = policyService.GetStatus();
            AuditLog.AuditRecord[] auditRecords = DrainLocalAuditRecords();
            PolicyBridgeService.NetworkConnectionEventDto[] networkConnections = DrainNetworkConnectionsIfDue();
            CentralPolicyStore.RemovableDeviceObservation[] removableDevices = removableDeviceInventory.Snapshot();
            if (auditRecords.Length > 0)
            {
                Console.WriteLine(DateTime.Now.ToString("s") + " Security audit drained " + auditRecords.Length + " event(s).");
            }

            CentralPolicyStore.AgentSyncRequest request = new CentralPolicyStore.AgentSyncRequest
            {
                DeviceId = deviceId,
                Machine = Environment.MachineName,
                User = Environment.UserName,
                AgentVersion = AgentVersion,
                DriverConnected = GetBool(rawStatus, "connected"),
                DriverStatus = GetString(rawStatus, "status"),
                DriverMessage = GetString(rawStatus, "message"),
                PolicyVersion = appliedPolicyVersion,
                LastApplyStatus = lastApplyStatus,
                LastApplyMessage = lastApplyMessage,
                Audit = auditRecords,
                NetworkConnections = networkConnections,
                RemovableDevices = removableDevices,
                TaskResults = pendingTaskResults.ToArray(),
                ResultOnly = false
            };

            CentralPolicyStore.AgentSyncResponse response = Post<CentralPolicyStore.AgentSyncRequest, CentralPolicyStore.AgentSyncResponse>(serverSyncUri, request);
            if (response == null || !response.accepted)
            {
                throw new InvalidOperationException("Central server rejected agent synchronization.");
            }

            if (!string.IsNullOrWhiteSpace(response.deviceId) && !string.Equals(deviceId, response.deviceId, StringComparison.OrdinalIgnoreCase))
            {
                deviceId = response.deviceId;
                SaveState();
            }

            if (response.policyVersion != appliedPolicyVersion)
            {
                ApplyPolicy(
                    response.rules ?? new PolicyBridgeService.PolicyRuleDto[0],
                    response.networkRules ?? new PolicyBridgeService.NetworkRuleDto[0],
                    response.webShellRules ?? new PolicyBridgeService.WebShellRuleDto[0],
                    response.deviceRules ?? new PolicyBridgeService.DeviceRuleDto[0],
                    response.hashProtectPolicy ?? PolicyBridgeService.DefaultHashProtectPolicy(),
                    response.lateralDefensePolicy ?? PolicyBridgeService.DefaultLateralDefensePolicy(),
                    response.usbCryptPolicy ?? PolicyBridgeService.DefaultUsbCryptPolicy(),
                    response.dlpProtectionPolicy ?? PolicyBridgeService.DefaultDlpProtectionPolicy(),
                    response.policyVersion);
            }

            pendingTaskResults.Clear();
            ExecuteTasks(response.tasks ?? new CentralPolicyStore.RemoteTaskDto[0]);
            if (pendingTaskResults.Count > 0)
            {
                FlushTaskResults();
            }
            Console.WriteLine(DateTime.Now.ToString("s") + " Agent synchronized. Policy version " + appliedPolicyVersion + ", uploaded audit " + auditRecords.Length + ", network " + networkConnections.Length + ", removable volumes " + removableDevices.Length + ".");
        }

        private void ExecuteTasks(CentralPolicyStore.RemoteTaskDto[] tasks)
        {
            foreach (CentralPolicyStore.RemoteTaskDto task in tasks)
            {
                CentralPolicyStore.RemoteTaskResult result = taskExecutor.Execute(task);
                pendingTaskResults.Add(result);
                Console.WriteLine(DateTime.Now.ToString("s") + " Task " + task.taskId + " " + task.kind + " completed: " + result.succeeded);
            }
        }

        private void FlushTaskResults()
        {
            object rawStatus = policyService.GetStatus();
            AuditLog.AuditRecord[] auditRecords = DrainLocalAuditRecords();
            PolicyBridgeService.NetworkConnectionEventDto[] networkConnections = DrainNetworkConnectionsIfDue();
            CentralPolicyStore.RemovableDeviceObservation[] removableDevices = removableDeviceInventory.Snapshot();
            if (auditRecords.Length > 0)
            {
                Console.WriteLine(DateTime.Now.ToString("s") + " Security audit drained " + auditRecords.Length + " event(s) during task result flush.");
            }

            CentralPolicyStore.AgentSyncRequest request = new CentralPolicyStore.AgentSyncRequest
            {
                DeviceId = deviceId,
                Machine = Environment.MachineName,
                User = Environment.UserName,
                AgentVersion = AgentVersion,
                DriverConnected = GetBool(rawStatus, "connected"),
                DriverStatus = GetString(rawStatus, "status"),
                DriverMessage = GetString(rawStatus, "message"),
                PolicyVersion = appliedPolicyVersion,
                LastApplyStatus = lastApplyStatus,
                LastApplyMessage = lastApplyMessage,
                Audit = auditRecords,
                NetworkConnections = networkConnections,
                RemovableDevices = removableDevices,
                TaskResults = pendingTaskResults.ToArray(),
                ResultOnly = true
            };

            Post<CentralPolicyStore.AgentSyncRequest, CentralPolicyStore.AgentSyncResponse>(serverSyncUri, request);
            pendingTaskResults.Clear();
        }

        private AuditLog.AuditRecord[] DrainLocalAuditRecords()
        {
            heartbeatIndex++;
            AuditLog.AuditRecord[] smtpRecords = DrainAuditSource("smtp", policyService.DrainSmtpAuditRecords);
            AuditLog.AuditRecord[] webShellRecords = DrainAuditSource("webshell", policyService.DrainWebShellAuditRecords);
            AuditLog.AuditRecord[] hashProtectRecords = DrainAuditSource("hashprotect", policyService.DrainHashProtectAuditRecords);
            AuditLog.AuditRecord[] lateralRecords = DrainAuditSource("lateral", policyService.DrainLateralDefenseAuditRecords);
            AuditLog.AuditRecord[] dlpRecords = DrainAuditSource("dlp", dlpProtectionService.DrainAuditRecords);
            if (smtpRecords.Length > 0 || webShellRecords.Length > 0 || hashProtectRecords.Length > 0 || lateralRecords.Length > 0 || dlpRecords.Length > 0)
            {
                Console.WriteLine(DateTime.Now.ToString("s") + " Security audit source counts: smtp=" + smtpRecords.Length + ", webshell=" + webShellRecords.Length + ", hashprotect=" + hashProtectRecords.Length + ", lateral=" + lateralRecords.Length + ", dlp=" + dlpRecords.Length + ".");
            }

            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>(smtpRecords.Length + webShellRecords.Length + hashProtectRecords.Length + lateralRecords.Length + dlpRecords.Length);
            records.AddRange(smtpRecords);
            records.AddRange(webShellRecords);
            records.AddRange(hashProtectRecords);
            records.AddRange(lateralRecords);
            records.AddRange(dlpRecords);
            return records.ToArray();
        }

        private PolicyBridgeService.NetworkConnectionEventDto[] DrainNetworkConnectionsIfDue()
        {
            if (heartbeatIndex % 2 != 0)
            {
                return new PolicyBridgeService.NetworkConnectionEventDto[0];
            }

            try
            {
                PolicyBridgeService.NetworkConnectionEventDto[] events = policyService.QueryNetworkConnectionEvents();
                if (events.Length > 0)
                {
                    Console.WriteLine(DateTime.Now.ToString("s") + " Network awareness drained " + events.Length + " event(s).");
                }

                return events;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " network awareness drain failed: " + ex.Message);
                return new PolicyBridgeService.NetworkConnectionEventDto[0];
            }
        }

        private AuditLog.AuditRecord[] DrainAuditSource(string source, Func<AuditLog.AuditRecord[]> drain)
        {
            try
            {
                return drain();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " security audit drain failed for " + source + ": " + ex.Message);
                return new[]
                {
                    new AuditLog.AuditRecord
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
                    }
                };
            }
        }

        private static string GetPolicyApiPath()
        {
            IntPtr handle;
            if (!GetModuleHandleEx(0, "DataProtectorPolicyApi.dll", out handle) || handle == IntPtr.Zero)
            {
                try
                {
                    DataProtectorWebBridge.Native.DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(new StringBuilder(2), 2);
                    if (!GetModuleHandleEx(0, "DataProtectorPolicyApi.dll", out handle) || handle == IntPtr.Zero)
                    {
                        return "DataProtectorPolicyApi.dll is not loaded.";
                    }
                }
                catch (Exception ex)
                {
                    return "DataProtectorPolicyApi.dll load probe failed: " + ex.Message;
                }
            }

            StringBuilder path = new StringBuilder(1024);
            uint length = GetModuleFileName(handle, path, path.Capacity);
            return length == 0 ? "DataProtectorPolicyApi.dll loaded, path unavailable." : path.ToString();
        }

        private void ApplyPolicy(
            PolicyBridgeService.PolicyRuleDto[] rules,
            PolicyBridgeService.NetworkRuleDto[] networkRules,
            PolicyBridgeService.WebShellRuleDto[] webShellRules,
            PolicyBridgeService.DeviceRuleDto[] deviceRules,
            PolicyBridgeService.HashProtectPolicyDto hashProtectPolicy,
            PolicyBridgeService.LateralDefensePolicyDto lateralDefensePolicy,
            PolicyBridgeService.UsbCryptPolicyDto usbCryptPolicy,
            PolicyBridgeService.DlpProtectionPolicyDto dlpProtectionPolicy,
            long policyVersion)
        {
            PolicyBridgeService.OperationResult clear = policyService.ClearRules("central-agent");
            if (!clear.succeeded)
            {
                lastApplyStatus = clear.statusText;
                lastApplyMessage = "Cannot clear local policy before central apply: " + clear.message;
                SaveState();
                return;
            }

            clear = policyService.ClearNetworkRules("central-agent");
            if (!clear.succeeded)
            {
                lastApplyStatus = clear.statusText;
                lastApplyMessage = "Cannot clear local network policy before central apply: " + clear.message;
                SaveState();
                return;
            }

            clear = policyService.ClearWebShellRules("central-agent");
            if (!clear.succeeded)
            {
                lastApplyStatus = clear.statusText;
                lastApplyMessage = "Cannot clear local WebShell policy before central apply: " + clear.message;
                SaveState();
                return;
            }

            clear = policyService.ClearDeviceRules("central-agent");
            if (!clear.succeeded)
            {
                lastApplyStatus = clear.statusText;
                lastApplyMessage = "Cannot clear local device control policy before central apply: " + clear.message;
                SaveState();
                return;
            }

            foreach (PolicyBridgeService.PolicyRuleDto rule in rules)
            {
                PolicyBridgeService.OperationResult result = policyService.AddRule(new PolicyBridgeService.PolicyRuleRequest
                {
                    Kind = rule.kind,
                    Value = rule.value,
                    Extension = rule.extension,
                    Actor = "central-agent"
                });

                if (!result.succeeded)
                {
                    lastApplyStatus = result.statusText;
                    lastApplyMessage = "Cannot apply central rule " + rule.kind + " " + rule.value + " " + rule.extension + ": " + result.message;
                    SaveState();
                    return;
                }
            }

            foreach (PolicyBridgeService.NetworkRuleDto rule in networkRules)
            {
                PolicyBridgeService.OperationResult result = policyService.AddNetworkRule(new PolicyBridgeService.NetworkRuleRequest
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
                    actor = "central-agent"
                });

                if (!result.succeeded)
                {
                    lastApplyStatus = result.statusText;
                    lastApplyMessage = "Cannot apply central network rule " + rule.kind + " " + rule.displayTarget + ": " + result.message;
                    SaveState();
                    return;
                }
            }

            foreach (PolicyBridgeService.WebShellRuleDto rule in webShellRules)
            {
                PolicyBridgeService.OperationResult result = policyService.AddWebShellRule(new PolicyBridgeService.WebShellRuleRequest
                {
                    directory = rule.directory,
                    actor = "central-agent"
                });

                if (!result.succeeded)
                {
                    lastApplyStatus = result.statusText;
                    lastApplyMessage = "Cannot apply central WebShell rule " + rule.directory + ": " + result.message;
                    SaveState();
                    return;
                }
            }

            foreach (PolicyBridgeService.DeviceRuleDto rule in deviceRules)
            {
                PolicyBridgeService.OperationResult result = policyService.AddDeviceRule(new PolicyBridgeService.DeviceRuleRequest
                {
                    deviceId = rule.deviceId,
                    allowInsert = rule.allowInsert,
                    allowWrite = rule.allowWrite,
                    actor = "central-agent"
                });

                if (!result.succeeded)
                {
                    lastApplyStatus = result.statusText;
                    lastApplyMessage = "Cannot apply central device rule " + rule.deviceId + ": " + result.message;
                    SaveState();
                    return;
                }
            }

            PolicyBridgeService.OperationResult hashPolicyResult = policyService.SetHashProtectPolicy(new PolicyBridgeService.HashProtectPolicyRequest
            {
                enabled = hashProtectPolicy.enabled,
                protectLsass = hashProtectPolicy.protectLsass,
                protectCredentialFiles = hashProtectPolicy.protectCredentialFiles,
                protectRegistryHives = hashProtectPolicy.protectRegistryHives,
                protectRawExtents = hashProtectPolicy.protectRawExtents,
                actor = "central-agent"
            });

            if (!hashPolicyResult.succeeded)
            {
                lastApplyStatus = hashPolicyResult.statusText;
                lastApplyMessage = "Cannot apply central hash dump protection policy: " + hashPolicyResult.message;
                SaveState();
                return;
            }

            PolicyBridgeService.OperationResult lateralPolicyResult = policyService.SetLateralDefensePolicy(new PolicyBridgeService.LateralDefensePolicyRequest
            {
                enabled = lateralDefensePolicy.enabled,
                blockSmbExecutableCopy = lateralDefensePolicy.blockSmbExecutableCopy,
                blockIpcScheduledTasks = lateralDefensePolicy.blockIpcScheduledTasks,
                blockIpcServiceCreation = lateralDefensePolicy.blockIpcServiceCreation,
                blockRemoteAdminTools = lateralDefensePolicy.blockRemoteAdminTools,
                actor = "central-agent"
            });

            if (!lateralPolicyResult.succeeded)
            {
                lastApplyStatus = lateralPolicyResult.statusText;
                lastApplyMessage = "Cannot apply central lateral movement defense policy: " + lateralPolicyResult.message;
                SaveState();
                return;
            }

            PersistUsbCryptPolicy(usbCryptPolicy);
            dlpProtectionService.UpdatePolicy(dlpProtectionPolicy);

            appliedPolicyVersion = policyVersion;
            lastApplyStatus = "0x00000000";
            lastApplyMessage = "Central policy applied. File rules: " + rules.Length + ", network rules: " + networkRules.Length + ", WebShell rules: " + webShellRules.Length + ", device rules: " + deviceRules.Length + ", hash protection: " + PolicyBridgeService.HashProtectPolicySummary(hashProtectPolicy) + ", lateral defense: " + PolicyBridgeService.LateralDefensePolicySummary(lateralDefensePolicy) + ", USB crypt: " + PolicyBridgeService.UsbCryptPolicySummary(usbCryptPolicy) + ", DLP: " + PolicyBridgeService.DlpProtectionPolicySummary(dlpProtectionPolicy);
            SaveState();
        }

        private void PersistUsbCryptPolicy(PolicyBridgeService.UsbCryptPolicyDto policy)
        {
            PolicyBridgeService.UsbCryptPolicyDto normalized = PolicyBridgeService.CloneUsbCryptPolicy(policy);
            File.WriteAllText(usbCryptPolicyPath, serializer.Serialize(normalized), Encoding.UTF8);
            Console.WriteLine(DateTime.Now.ToString("s") + " USB crypt policy saved: " + usbCryptPolicyPath + " (" + PolicyBridgeService.UsbCryptPolicySummary(normalized) + ").");
        }

        private TResponse Post<TRequest, TResponse>(Uri uri, TRequest request)
        {
            string json = serializer.Serialize(request);
            byte[] bytes = Encoding.UTF8.GetBytes(json);

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(uri);
            webRequest.Method = "POST";
            webRequest.ContentType = "application/json; charset=utf-8";
            webRequest.Accept = "application/json";
            webRequest.Timeout = 15000;
            webRequest.ContentLength = bytes.Length;

            using (Stream requestStream = webRequest.GetRequestStream())
            {
                requestStream.Write(bytes, 0, bytes.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
            {
                string payload = reader.ReadToEnd();
                ApiEnvelope<TResponse> envelope = serializer.Deserialize<ApiEnvelope<TResponse>>(payload);
                if (envelope == null || envelope.code != "0000")
                {
                    throw new InvalidOperationException(envelope == null ? "Invalid central server response." : envelope.msg);
                }

                return envelope.data;
            }
        }

        private void LoadState()
        {
            try
            {
                if (File.Exists(statePath))
                {
                    AgentState state = serializer.Deserialize<AgentState>(File.ReadAllText(statePath, Encoding.UTF8));
                    if (state != null)
                    {
                        deviceId = state.DeviceId;
                        appliedPolicyVersion = state.AppliedPolicyVersion;
                        lastApplyStatus = state.LastApplyStatus ?? lastApplyStatus;
                        lastApplyMessage = state.LastApplyMessage ?? lastApplyMessage;
                    }
                }

                if (string.IsNullOrWhiteSpace(deviceId))
                {
                    deviceId = Guid.NewGuid().ToString("N");
                    SaveState();
                }
            }
            catch
            {
                deviceId = Guid.NewGuid().ToString("N");
                appliedPolicyVersion = 0;
                SaveState();
            }
        }

        private void SaveState()
        {
            AgentState state = new AgentState
            {
                DeviceId = deviceId,
                AppliedPolicyVersion = appliedPolicyVersion,
                LastApplyStatus = lastApplyStatus,
                LastApplyMessage = lastApplyMessage
            };

            File.WriteAllText(statePath, serializer.Serialize(state), Encoding.UTF8);
        }

        private static Uri BuildSyncUri(string serverBaseUrl)
        {
            return new Uri(BuildServerBaseUri(serverBaseUrl), "api/agent/sync");
        }

        private static Uri BuildServerBaseUri(string serverBaseUrl)
        {
            string value = serverBaseUrl.Trim();
            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                value += "/";
            }

            return new Uri(value);
        }

        private static bool GetBool(object instance, string name)
        {
            object value = GetPropertyValue(instance, name);
            return value is bool && (bool)value;
        }

        private static string GetString(object instance, string name)
        {
            object value = GetPropertyValue(instance, name);
            return value == null ? string.Empty : value.ToString();
        }

        private static object GetPropertyValue(object instance, string name)
        {
            if (instance == null)
            {
                return null;
            }

            System.Reflection.PropertyInfo property = instance.GetType().GetProperty(name);
            return property == null ? null : property.GetValue(instance, null);
        }

        private sealed class ApiEnvelope<T>
        {
            public string code { get; set; }
            public string msg { get; set; }
            public T data { get; set; }
        }

        private sealed class AgentState
        {
            public string DeviceId { get; set; }
            public long AppliedPolicyVersion { get; set; }
            public string LastApplyStatus { get; set; }
            public string LastApplyMessage { get; set; }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetModuleHandleEx(uint flags, string moduleName, out IntPtr moduleHandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileName(IntPtr moduleHandle, StringBuilder fileName, int size);
    }
}
