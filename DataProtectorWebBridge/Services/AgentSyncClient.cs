using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
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
        private readonly string statePath;
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();
        private readonly RemoteTaskExecutor taskExecutor = new RemoteTaskExecutor();
        private readonly List<CentralPolicyStore.RemoteTaskResult> pendingTaskResults = new List<CentralPolicyStore.RemoteTaskResult>();
        private string deviceId;
        private long appliedPolicyVersion;
        private string lastApplyStatus = "0x00000000";
        private string lastApplyMessage = "Agent started.";

        public AgentSyncClient(string serverBaseUrl, TimeSpan interval, PolicyBridgeService policyService)
        {
            if (string.IsNullOrWhiteSpace(serverBaseUrl))
            {
                throw new ArgumentException("Central server URL is required for agent mode.", "serverBaseUrl");
            }

            this.interval = interval <= TimeSpan.Zero ? TimeSpan.FromSeconds(15) : interval;
            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            serverSyncUri = BuildSyncUri(serverBaseUrl);

            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string directory = Path.Combine(dataRoot, "DataProtector");
            statePath = Path.Combine(directory, "AgentState.json");
            Directory.CreateDirectory(directory);
            LoadState();
        }

        public void Run()
        {
            Console.WriteLine("DataProtector Agent connecting to " + serverSyncUri);
            Console.WriteLine("Agent state: " + statePath);

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
                Audit = new AuditLog.AuditRecord[0],
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
                    response.policyVersion);
            }

            pendingTaskResults.Clear();
            ExecuteTasks(response.tasks ?? new CentralPolicyStore.RemoteTaskDto[0]);
            if (pendingTaskResults.Count > 0)
            {
                FlushTaskResults();
            }
            Console.WriteLine(DateTime.Now.ToString("s") + " Agent synchronized. Policy version " + appliedPolicyVersion + ".");
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
                Audit = new AuditLog.AuditRecord[0],
                TaskResults = pendingTaskResults.ToArray(),
                ResultOnly = true
            };

            Post<CentralPolicyStore.AgentSyncRequest, CentralPolicyStore.AgentSyncResponse>(serverSyncUri, request);
            pendingTaskResults.Clear();
        }

        private void ApplyPolicy(
            PolicyBridgeService.PolicyRuleDto[] rules,
            PolicyBridgeService.NetworkRuleDto[] networkRules,
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

            appliedPolicyVersion = policyVersion;
            lastApplyStatus = "0x00000000";
            lastApplyMessage = "Central policy applied. File rules: " + rules.Length + ", network rules: " + networkRules.Length;
            SaveState();
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
            string value = serverBaseUrl.Trim();
            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                value += "/";
            }

            return new Uri(new Uri(value), "api/agent/sync");
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
    }
}
