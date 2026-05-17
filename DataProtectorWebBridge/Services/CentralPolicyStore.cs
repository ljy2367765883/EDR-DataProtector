using System;
using System.Collections.Generic;
using System.Globalization;
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
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
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

        public AuditLog.AuditRecord[] ReadRecentAudit(int limit)
        {
            return QueryAudit(new AuditLog.AuditQueryOptions { Limit = limit });
        }

        public AuditLog.AuditRecord[] QueryAudit(AuditLog.AuditQueryOptions options)
        {
            AuditLog.AuditQueryOptions query = options ?? new AuditLog.AuditQueryOptions();
            int take = AuditLog.NormalizeLimit(query.Limit);

            lock (syncRoot)
            {
                return state.Audit
                    .AsEnumerable()
                    .Reverse()
                    .Where(record => AuditLog.Matches(record, query))
                    .Take(take)
                    .Select(CloneAudit)
                    .ToArray();
            }
        }

        public NetworkInsightResponse QueryNetworkInsights(NetworkInsightQuery query)
        {
            NetworkInsightQuery normalized = NormalizeNetworkInsightQuery(query);
            DateTime sinceUtc = DateTime.UtcNow - normalized.window;
            DateTime baselineUtc = DateTime.UtcNow - normalized.baseline;

            lock (syncRoot)
            {
                List<NetworkConnectionObservation> current = state.NetworkConnections
                    .Where(item => IsNetworkInsightMatch(item, normalized) && ParseUtcOrMin(item.lastSeenUtc) >= sinceUtc)
                    .Select(CloneNetworkObservation)
                    .ToList();

                HashSet<string> baselineKeys = new HashSet<string>(
                    state.NetworkConnections
                        .Where(item => IsNetworkInsightMatch(item, normalized) && ParseUtcOrMin(item.firstSeenUtc) < baselineUtc)
                        .Select(NetworkObservationKey),
                    StringComparer.OrdinalIgnoreCase);

                NetworkInsightItem[] items = current
                    .GroupBy(NetworkObservationKey, StringComparer.OrdinalIgnoreCase)
                    .Select(group => ToNetworkInsightItem(group.ToList(), baselineKeys))
                    .Where(item => item.isNew)
                    .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                    .Take(normalized.limit)
                    .ToArray();

                return new NetworkInsightResponse
                {
                    baselineHours = normalized.baseline.TotalHours,
                    windowHours = normalized.window.TotalHours,
                    generatedUtc = DateTime.UtcNow.ToString("o"),
                    total = items.Length,
                    newTotal = items.Length,
                    items = items
                };
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
                    if (loaded != null && loaded.NetworkConnections == null)
                    {
                        loaded.NetworkConnections = new List<NetworkConnectionObservation>();
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
            string json = serializer.Serialize(state);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        private void AppendAudit(string actor, string action, string target, string extension, bool succeeded, string status, string message)
        {
            state.Audit.Add(new AuditLog.AuditRecord
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
            normalized.limit = normalized.limit <= 0 ? DefaultLimit : Math.Min(normalized.limit, 1000);
            normalized.baselineHours = ClampHours(normalized.baselineHours <= 0 ? 24 : normalized.baselineHours, 1, 24 * 31);
            normalized.windowHours = ClampHours(normalized.windowHours <= 0 ? normalized.baselineHours : normalized.windowHours, 1, 24 * 31);
            normalized.host = normalized.host ?? string.Empty;
            normalized.eventType = normalized.eventType ?? "all";
            normalized.search = normalized.search ?? string.Empty;
            normalized.baseline = TimeSpan.FromHours(normalized.baselineHours);
            normalized.window = TimeSpan.FromHours(normalized.windowHours);
            return normalized;
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

        private static NetworkInsightItem ToNetworkInsightItem(List<NetworkConnectionObservation> items, HashSet<string> baselineKeys)
        {
            NetworkConnectionObservation latest = items
                .OrderByDescending(item => item.lastSeenUtc, StringComparer.OrdinalIgnoreCase)
                .First();

            return new NetworkInsightItem
            {
                key = NetworkObservationFingerprint(latest),
                isNew = !baselineKeys.Contains(NetworkObservationKey(latest)),
                firstSeenUtc = items.Min(item => item.firstSeenUtc),
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
            task.output = Truncate(result.output, GetTaskOutputLimit(task.kind));
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

        private static bool SameWebShellRule(PolicyBridgeService.WebShellRuleDto rule, PolicyBridgeService.WebShellRuleDto request)
        {
            return string.Equals(rule.directory, request.directory, StringComparison.OrdinalIgnoreCase);
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
                Host = record.Host ?? string.Empty,
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
                NetworkRules = new List<PolicyBridgeService.NetworkRuleDto>();
                WebShellRules = new List<PolicyBridgeService.WebShellRuleDto>();
                Devices = new Dictionary<string, CentralDeviceState>(StringComparer.OrdinalIgnoreCase);
                Audit = new List<AuditLog.AuditRecord>();
                Tasks = new List<RemoteTaskState>();
                NetworkConnections = new List<NetworkConnectionObservation>();
            }

            public long PolicyVersion { get; set; }
            public List<PolicyBridgeService.PolicyRuleDto> Rules { get; set; }
            public List<PolicyBridgeService.NetworkRuleDto> NetworkRules { get; set; }
            public List<PolicyBridgeService.WebShellRuleDto> WebShellRules { get; set; }
            public Dictionary<string, CentralDeviceState> Devices { get; set; }
            public List<AuditLog.AuditRecord> Audit { get; set; }
            public List<RemoteTaskState> Tasks { get; set; }
            public List<NetworkConnectionObservation> NetworkConnections { get; set; }
        }

        public sealed class NetworkInsightQuery
        {
            internal TimeSpan baseline;
            internal TimeSpan window;
            public int baselineHours { get; set; }
            public int windowHours { get; set; }
            public int limit { get; set; }
            public string host { get; set; }
            public string eventType { get; set; }
            public string search { get; set; }
        }

        public sealed class NetworkInsightResponse
        {
            public double baselineHours { get; set; }
            public double windowHours { get; set; }
            public string generatedUtc { get; set; }
            public int total { get; set; }
            public int newTotal { get; set; }
            public NetworkInsightItem[] items { get; set; }
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
            public PolicyBridgeService.NetworkConnectionEventDto[] NetworkConnections { get; set; }
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
