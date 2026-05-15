using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class CentralPolicyStore
    {
        private const int DefaultLimit = 200;
        private readonly object syncRoot = new object();
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();
        private readonly string filePath;
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
                    deviceCount = state.Devices.Count,
                    onlineDeviceCount = state.Devices.Values.Count(IsOnline),
                    pendingTaskCount = state.Tasks.Count(task => task.status == "queued" || task.status == "sent")
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

        public AuditLog.AuditRecord[] ReadRecentAudit(int limit)
        {
            int take = limit <= 0 ? DefaultLimit : Math.Min(limit, 1000);
            lock (syncRoot)
            {
                return state.Audit
                    .AsEnumerable()
                    .Reverse()
                    .Take(take)
                    .Select(CloneAudit)
                    .ToArray();
            }
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

                if (request.Audit != null)
                {
                    foreach (AuditLog.AuditRecord record in request.Audit)
                    {
                        AuditLog.AuditRecord normalized = CloneAudit(record);
                        normalized.Actor = string.IsNullOrWhiteSpace(normalized.Actor)
                            ? device.Machine
                            : normalized.Actor;
                        normalized.Target = string.IsNullOrWhiteSpace(normalized.Target)
                            ? device.DeviceId
                            : normalized.Target;
                        state.Audit.Add(normalized);
                    }
                }

                AppendAudit(device.Machine, "agent.sync", device.DeviceId, string.Empty, true, "0x00000000", "Agent synchronized with central server.");
                RemoteTaskDto[] assignedTasks = AssignTasks(deviceId);
                TrimAudit();
                Save();

                return new AgentSyncResponse
                {
                    accepted = true,
                    deviceId = deviceId,
                    serverTimeUtc = DateTime.UtcNow.ToString("o"),
                    policyVersion = state.PolicyVersion,
                    rules = QueryRules(),
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
            string json = serializer.Serialize(state);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        private void AppendAudit(string actor, string action, string target, string extension, bool succeeded, string status, string message)
        {
            state.Audit.Add(new AuditLog.AuditRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Actor = string.IsNullOrWhiteSpace(actor) ? Environment.UserName : actor,
                Action = action ?? string.Empty,
                Target = target ?? string.Empty,
                Extension = extension ?? string.Empty,
                Succeeded = succeeded,
                Status = status ?? "0x00000000",
                Message = message ?? string.Empty
            });
        }

        private void TrimAudit()
        {
            const int maxAuditRecords = 10000;
            if (state.Audit.Count > maxAuditRecords)
            {
                state.Audit = state.Audit.Skip(state.Audit.Count - maxAuditRecords).ToList();
            }
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
                task.status = "sent";
                task.sentUtc = now.ToString("o");
                tasks.Add(CloneTask(task));
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
            task.output = Truncate(result.output, 262144);
            task.error = Truncate(result.error, 65536);
            RedactSensitiveTaskArgs(task);
            AppendAudit(deviceId, "remote.task.result." + task.kind, task.taskId, string.Empty, result.succeeded, result.succeeded ? "0x00000000" : "0x00000001", result.succeeded ? "Remote task completed." : task.error);
        }

        private static bool IsStaleSentTask(RemoteTaskState task, DateTime now)
        {
            DateTime sent;
            return task.status == "sent"
                && DateTime.TryParse(task.sentUtc, out sent)
                && now - sent.ToUniversalTime() > TimeSpan.FromMinutes(5);
        }

        private static void RedactSensitiveTaskArgs(RemoteTaskState task)
        {
            if (string.Equals(task.kind, "user.changePassword", StringComparison.OrdinalIgnoreCase))
            {
                task.argumentsJson = "{\"username\":\"redacted\",\"newPassword\":\"redacted\"}";
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

        private static bool IsOnline(CentralDeviceState device)
        {
            DateTime lastSeen;
            return DateTime.TryParse(device.LastSeenUtc, out lastSeen) && DateTime.UtcNow - lastSeen.ToUniversalTime() < TimeSpan.FromMinutes(3);
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

        private static PolicyBridgeService.PolicyRuleDto CloneRule(PolicyBridgeService.PolicyRuleDto rule)
        {
            return new PolicyBridgeService.PolicyRuleDto
            {
                kind = rule.kind,
                value = rule.value,
                extension = rule.extension
            };
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

            return new AuditLog.AuditRecord
            {
                TimestampUtc = string.IsNullOrWhiteSpace(record.TimestampUtc) ? DateTime.UtcNow.ToString("o") : record.TimestampUtc,
                Actor = record.Actor ?? string.Empty,
                Action = record.Action ?? string.Empty,
                Target = record.Target ?? string.Empty,
                Extension = record.Extension ?? string.Empty,
                Succeeded = record.Succeeded,
                Status = record.Status ?? string.Empty,
                Message = record.Message ?? string.Empty
            };
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
                Devices = new Dictionary<string, CentralDeviceState>(StringComparer.OrdinalIgnoreCase);
                Audit = new List<AuditLog.AuditRecord>();
                Tasks = new List<RemoteTaskState>();
            }

            public long PolicyVersion { get; set; }
            public List<PolicyBridgeService.PolicyRuleDto> Rules { get; set; }
            public Dictionary<string, CentralDeviceState> Devices { get; set; }
            public List<AuditLog.AuditRecord> Audit { get; set; }
            public List<RemoteTaskState> Tasks { get; set; }
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
            public RemoteTaskResult[] TaskResults { get; set; }
        }

        public sealed class AgentSyncResponse
        {
            public bool accepted { get; set; }
            public string deviceId { get; set; }
            public string serverTimeUtc { get; set; }
            public long policyVersion { get; set; }
            public PolicyBridgeService.PolicyRuleDto[] rules { get; set; }
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
