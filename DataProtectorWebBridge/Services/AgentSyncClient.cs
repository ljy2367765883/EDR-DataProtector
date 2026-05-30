using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class AgentSyncClient
    {
        private const string AgentVersion = "1.0";
        private const int SandboxMaxUploadBytes = 20 * 1024 * 1024;
        private const int SandboxMaxUploadsPerHeartbeat = 2;
        private const int SandboxMaxKnownHashes = 1000;
        private const int SandboxMaxPendingEvents = 128;
        private const int SandboxFileReadyRetries = 6;
        private const int SandboxFileReadyDelayMs = 500;
        private readonly Uri serverSyncUri;
        private readonly TimeSpan interval;
        private readonly PolicyBridgeService policyService;
        private readonly DlpProtectionService dlpProtectionService;
        private readonly StaticScanService staticScanService;
        private readonly string statePath;
        private readonly string sandboxUploadStatePath;
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly RemoteTaskExecutor taskExecutor;
        private readonly RemovableDeviceInventory removableDeviceInventory = new RemovableDeviceInventory();
        private readonly List<CentralPolicyStore.RemoteTaskResult> pendingTaskResults = new List<CentralPolicyStore.RemoteTaskResult>();
        private readonly HashSet<string> sandboxUploadedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<SandboxExecutableEvent> pendingSandboxExecutableEvents = new Queue<SandboxExecutableEvent>();
        private readonly HashSet<string> pendingSandboxExecutablePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> sandboxExecutableWatchers = new List<FileSystemWatcher>();
        private readonly object sandboxExecutableLock = new object();
        private readonly List<AuditLog.AuditRecord> localScanAuditRecords = new List<AuditLog.AuditRecord>();
        private readonly object localScanAuditLock = new object();
        private readonly string usbCryptPolicyPath;
        private string deviceId;
        private long appliedPolicyVersion;
        private string lastApplyStatus = "0x00000000";
        private string lastApplyMessage = "Agent started.";
        private long heartbeatIndex;
        private PolicyBridgeService.UserHookDefensePolicyDto currentUserHookDefensePolicy = PolicyBridgeService.DefaultUserHookDefensePolicy();

        public AgentSyncClient(string serverBaseUrl, TimeSpan interval, PolicyBridgeService policyService)
        {
            if (string.IsNullOrWhiteSpace(serverBaseUrl))
            {
                throw new ArgumentException("Central server URL is required for agent mode.", "serverBaseUrl");
            }

            this.interval = interval <= TimeSpan.Zero ? TimeSpan.FromSeconds(15) : interval;
            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            dlpProtectionService = new DlpProtectionService();
            staticScanService = new StaticScanService(this.policyService,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataProtector"));
            serverSyncUri = BuildSyncUri(serverBaseUrl);
            taskExecutor = new RemoteTaskExecutor(BuildServerBaseUri(serverBaseUrl));

            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string directory = Path.Combine(dataRoot, "DataProtector");
            statePath = Path.Combine(directory, "AgentState.json");
            sandboxUploadStatePath = Path.Combine(directory, "SandboxUploadedSamples.json");
            usbCryptPolicyPath = Path.Combine(directory, "UsbCryptPolicy.json");
            Directory.CreateDirectory(directory);
            LoadState();
            LoadSandboxUploadState();
            StartSandboxExecutableWatchers();
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
            CentralPolicyStore.SandboxSampleSubmission[] sandboxSamples = CollectSandboxExecutableEvents();

            //
            // Drain kernel executable-scan requests and submit verdicts. The
            // signed user-mode engine pipeline (YARA + heuristics + hash
            // reputation) classifies; the kernel only enforces the verdict.
            //
            try
            {
                int scanned = staticScanService.ProcessPendingRequests();
                if (scanned > 0)
                {
                    Console.WriteLine(DateTime.Now.ToString("s") + " Static scan processed " + scanned + " executable request(s).");
                }
            }
            catch (Exception scanEx)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " static scan cycle failed: " + scanEx.Message);
            }

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
                SandboxSamples = sandboxSamples,
                TaskResults = pendingTaskResults.ToArray(),
                ResultOnly = false
            };

            CentralPolicyStore.AgentSyncResponse response;
            try
            {
                response = Post<CentralPolicyStore.AgentSyncRequest, CentralPolicyStore.AgentSyncResponse>(serverSyncUri, request);
            }
            catch
            {
                RequeueSandboxSamples(sandboxSamples);
                throw;
            }

            if (response == null || !response.accepted)
            {
                RequeueSandboxSamples(sandboxSamples);
                throw new InvalidOperationException("Central server rejected agent synchronization.");
            }

            MarkSandboxSamplesUploaded(sandboxSamples);

            if (!string.IsNullOrWhiteSpace(response.deviceId) && !string.Equals(deviceId, response.deviceId, StringComparison.OrdinalIgnoreCase))
            {
                deviceId = response.deviceId;
                SaveState();
            }

            string localPolicyRefreshReason = string.Empty;
            long previousAppliedPolicyVersion = appliedPolicyVersion;
            bool serverPolicyVersionChanged = response.policyVersion != appliedPolicyVersion;
            bool shouldApplyPolicy = serverPolicyVersionChanged ||
                                     ShouldRefreshLocalUserHookPolicy(response, rawStatus, out localPolicyRefreshReason);
            if (shouldApplyPolicy)
            {
                string applyReason = serverPolicyVersionChanged
                    ? "central policy version changed from " + appliedPolicyVersion + " to " + response.policyVersion
                    : localPolicyRefreshReason;
                Console.WriteLine(DateTime.Now.ToString("s") + " Central policy apply required: " + applyReason);

                if (!serverPolicyVersionChanged && !string.IsNullOrWhiteSpace(localPolicyRefreshReason))
                {
                    Console.WriteLine(DateTime.Now.ToString("s") + " Local process threat insight policy refresh required: " + localPolicyRefreshReason);
                }

                ApplyPolicy(
                    response.rules ?? new PolicyBridgeService.PolicyRuleDto[0],
                    response.networkRules ?? new PolicyBridgeService.NetworkRuleDto[0],
                    response.webShellRules ?? new PolicyBridgeService.WebShellRuleDto[0],
                    response.deviceRules ?? new PolicyBridgeService.DeviceRuleDto[0],
                    response.hashProtectPolicy ?? PolicyBridgeService.DefaultHashProtectPolicy(),
                    response.lateralDefensePolicy ?? PolicyBridgeService.DefaultLateralDefensePolicy(),
                    response.userHookDefensePolicy ?? PolicyBridgeService.DefaultUserHookDefensePolicy(),
                    response.usbCryptPolicy ?? PolicyBridgeService.DefaultUsbCryptPolicy(),
                    response.dlpProtectionPolicy ?? PolicyBridgeService.DefaultDlpProtectionPolicy(),
                    response.policyVersion);

                if (appliedPolicyVersion != response.policyVersion || !string.Equals(lastApplyStatus, "0x00000000", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine(
                        DateTime.Now.ToString("s") +
                        " Central policy apply incomplete. serverVersion=" +
                        response.policyVersion +
                        "; previousLocalVersion=" +
                        previousAppliedPolicyVersion +
                        "; currentLocalVersion=" +
                        appliedPolicyVersion +
                        "; status=" +
                        lastApplyStatus +
                        "; message=" +
                        lastApplyMessage);
                }
            }

            pendingTaskResults.Clear();
            ExecuteTasks(response.tasks ?? new CentralPolicyStore.RemoteTaskDto[0]);
            if (pendingTaskResults.Count > 0)
            {
                FlushTaskResults();
            }
            Console.WriteLine(DateTime.Now.ToString("s") + " Agent synchronized. Policy version " + appliedPolicyVersion + ", uploaded audit " + auditRecords.Length + ", network " + networkConnections.Length + ", removable volumes " + removableDevices.Length + ", sandbox samples " + sandboxSamples.Length + ".");
        }

        private bool ShouldRefreshLocalUserHookPolicy(CentralPolicyStore.AgentSyncResponse response, object rawStatus, out string reason)
        {
            reason = string.Empty;
            if (response == null || !GetBool(rawStatus, "connected"))
            {
                return false;
            }

            PolicyBridgeService.UserHookDefensePolicyDto desired = NormalizeAgentUserHookPolicy(response.userHookDefensePolicy);
            string desiredSummary = PolicyBridgeService.UserHookDefensePolicySummary(desired);
            string currentSummary = PolicyBridgeService.UserHookDefensePolicySummary(currentUserHookDefensePolicy);
            if (!string.Equals(desiredSummary, currentSummary, StringComparison.Ordinal))
            {
                reason = "central process threat insight policy content differs from local applied cache. desired=" +
                         desiredSummary +
                         "; local=" +
                         currentSummary;
                return true;
            }

            try
            {
                PolicyBridgeService.UserHookDefensePolicyDto actual = policyService.QueryKernelUserHookDefensePolicy();
                uint desiredFlags = PolicyBridgeService.ToUserHookDefenseFlags(desired);
                if (actual.flags != desiredFlags)
                {
                    reason = "kernel flags are 0x" + actual.flags.ToString("X8") + ", expected 0x" + desiredFlags.ToString("X8");
                    return true;
                }

                if (desired.enabled && desired.monitorEarlyProcesses)
                {
                    if (string.IsNullOrWhiteSpace(actual.runtimePath))
                    {
                        reason = "kernel runtime DLL path is empty";
                        return true;
                    }

                    if (!RuntimeDllPathExists(actual.runtimePath))
                    {
                        reason = "configured runtime DLL is missing: " + actual.runtimePath;
                        return true;
                    }
                }

                if (!StringSetsEqual(actual.excludedProcessNames, desired.excludedProcessNames) ||
                    !StringSetsEqual(actual.trustedSignerSubjects, desired.trustedSignerSubjects))
                {
                    reason = "kernel allowlist does not match central policy";
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (desired.enabled)
                {
                    reason = "kernel policy query failed: " + ex.Message;
                    return true;
                }
            }

            return false;
        }

        private static bool RuntimeDllPathExists(string runtimePath)
        {
            string normalized = NormalizeRuntimeDllPath(runtimePath);
            if (!string.IsNullOrWhiteSpace(normalized) && File.Exists(normalized))
            {
                return true;
            }

            string runtimeDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "DataProtector",
                "Runtime");
            string prepared = Path.Combine(runtimeDirectory, "DataProtectorUserHookRuntime.dll");
            if (File.Exists(prepared))
            {
                return true;
            }

            try
            {
                return Directory.Exists(runtimeDirectory) &&
                       Directory.EnumerateFiles(runtimeDirectory, "DataProtectorUserHookRuntime.dll", SearchOption.AllDirectories).Any();
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeRuntimeDllPath(string runtimePath)
        {
            string value = (runtimePath ?? string.Empty).Trim();
            if (value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
            {
                value = value.Substring(4);
            }

            return value;
        }

        private static bool StringSetsEqual(string[] left, string[] right)
        {
            string[] normalizedLeft = (left ?? new string[0])
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item.Trim())
                .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            string[] normalizedRight = (right ?? new string[0])
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item.Trim())
                .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return normalizedLeft.SequenceEqual(normalizedRight, StringComparer.OrdinalIgnoreCase);
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
                SandboxSamples = new CentralPolicyStore.SandboxSampleSubmission[0],
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
            AuditLog.AuditRecord[] fileHunterRecords = DrainAuditSource("filehunter", policyService.DrainFileHunterAuditRecords);
            AuditLog.AuditRecord[] hashProtectRecords = DrainAuditSource("hashprotect", policyService.DrainHashProtectAuditRecords);
            AuditLog.AuditRecord[] lateralRecords = DrainAuditSource("lateral", policyService.DrainLateralDefenseAuditRecords);
            AuditLog.AuditRecord[] userHookRecords = DrainAuditSource("userhook", () => policyService.DrainUserHookDefenseAuditRecords(currentUserHookDefensePolicy));
            AuditLog.AuditRecord[] dlpRecords = DrainAuditSource("dlp", dlpProtectionService.DrainAuditRecords);
            AuditLog.AuditRecord[] staticScanRecords = DrainAuditSource("staticscan", DrainLocalScanAuditRecords);
            if (fileHunterRecords.Length > 0)
            {
                foreach (AuditLog.AuditRecord record in fileHunterRecords.Take(5))
                {
                    Console.WriteLine(
                        DateTime.Now.ToString("s") +
                        " File hunter upload candidate: source=" +
                        (record.SourceProcess ?? record.Extension ?? string.Empty) +
                        "; pid=" +
                        (record.SourcePid ?? string.Empty) +
                        "; target=" +
                        (record.Target ?? string.Empty));
                }
            }

            if (fileHunterRecords.Length == 0 && heartbeatIndex % 20 == 0)
            {
                try
                {
                    PolicyBridgeService.FileHunterRuleDto[] rules = policyService.QueryFileHunterRules();
                    if (rules.Length > 0)
                    {
                        Console.WriteLine(
                            DateTime.Now.ToString("s") +
                            " File hunter heartbeat: driverRules=" +
                            rules.Length.ToString() +
                            "; no read events drained in this heartbeat.");
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " File hunter heartbeat diagnostics failed: " + ex.Message);
                }
            }

            if (smtpRecords.Length > 0 || webShellRecords.Length > 0 || fileHunterRecords.Length > 0 || hashProtectRecords.Length > 0 || lateralRecords.Length > 0 || userHookRecords.Length > 0 || dlpRecords.Length > 0)
            {
                Console.WriteLine(DateTime.Now.ToString("s") + " Security audit source counts: smtp=" + smtpRecords.Length + ", webshell=" + webShellRecords.Length + ", filehunter=" + fileHunterRecords.Length + ", hashprotect=" + hashProtectRecords.Length + ", lateral=" + lateralRecords.Length + ", userhook=" + userHookRecords.Length + ", dlp=" + dlpRecords.Length + ".");
            }

            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>(smtpRecords.Length + webShellRecords.Length + fileHunterRecords.Length + hashProtectRecords.Length + lateralRecords.Length + userHookRecords.Length + dlpRecords.Length + staticScanRecords.Length);
            records.AddRange(smtpRecords);
            records.AddRange(webShellRecords);
            records.AddRange(fileHunterRecords);
            records.AddRange(hashProtectRecords);
            records.AddRange(lateralRecords);
            records.AddRange(userHookRecords);
            records.AddRange(dlpRecords);
            records.AddRange(staticScanRecords);
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

        private CentralPolicyStore.SandboxSampleSubmission[] CollectSandboxExecutableEvents()
        {
            try
            {
                HashSet<string> batchHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                int scanned = 0;
                while (scanned < SandboxMaxUploadsPerHeartbeat)
                {
                    SandboxExecutableEvent executableEvent = DequeueSandboxExecutableEvent();
                    if (executableEvent == null)
                    {
                        break;
                    }

                    SandboxExecutableReadiness readiness = ProbeSandboxExecutableReadiness(executableEvent);
                    if (readiness == SandboxExecutableReadiness.Waiting && executableEvent.Attempts < SandboxFileReadyRetries)
                    {
                        executableEvent.Attempts++;
                        executableEvent.NotBeforeUtc = DateTime.UtcNow.AddMilliseconds(SandboxFileReadyDelayMs);
                        RequeueSandboxExecutableEvent(executableEvent);
                        continue;
                    }

                    if (readiness != SandboxExecutableReadiness.Ready)
                    {
                        continue;
                    }

                    // Local scan instead of upload. The watched-directory exe is
                    // analyzed on this endpoint by the signed scan-engine
                    // pipeline (YARA + heuristics + hash reputation); nothing is
                    // sent to the central server for sandbox detonation.
                    ScanWatchedExecutableLocally(executableEvent, batchHashes);
                    scanned++;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " sandbox executable event collection failed: " + ex.Message);
            }

            // The sandbox upload channel is retired in favor of local scanning;
            // always return an empty submission set so nothing is uploaded.
            return new CentralPolicyStore.SandboxSampleSubmission[0];
        }

        private void ScanWatchedExecutableLocally(SandboxExecutableEvent executableEvent, HashSet<string> batchHashes)
        {
            string path = executableEvent.Path;
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            try
            {
                string hash = ComputeSha256Hex(path);
                if (!string.IsNullOrEmpty(hash) && !batchHashes.Add(hash))
                {
                    return;
                }

                LocalScanResult result = staticScanService.ScanFile(path);

                bool flagged = result.Verdict >= StaticScanService.VerdictSuspicious;
                bool malicious = result.Verdict >= StaticScanService.VerdictMalicious;
                string verdictText = result.VerdictText ?? "clean";
                string eventReason = string.Equals(executableEvent.EventKind, "renamed", StringComparison.OrdinalIgnoreCase)
                    ? "renamed-to-exe"
                    : "created";

                string matchedRulesText = (result.MatchedRules != null && result.MatchedRules.Length > 0)
                    ? string.Join(", ", result.MatchedRules)
                    : string.Empty;

                Console.WriteLine(DateTime.Now.ToString("s") +
                    " Local executable scan verdict=" + verdictText +
                    " score=" + result.Score.ToString(CultureInfo.InvariantCulture) +
                    (matchedRulesText.Length > 0 ? (" rules=[" + matchedRulesText + "]") : string.Empty) +
                    " path=" + path);

                // Identify who dropped the file (the process that owns the
                // watched directory event) for the attack-flow view. The
                // FileSystemWatcher does not carry the writer PID, so we record
                // the agent host/user context and the file lineage we know.
                string fileName = Path.GetFileName(path);
                string directory = string.Empty;
                try { directory = Path.GetDirectoryName(path) ?? string.Empty; } catch { }

                string detailJson = BuildStaticScanEvidence(result, executableEvent, eventReason, matchedRulesText, directory);

                AuditLog.AuditRecord record = new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = "static-scan",
                    Action = "static-scan.detection",
                    Target = path,
                    Extension = SafeExtensionForAudit(path),
                    Succeeded = false,
                    Status = malicious ? "0xC0000022" : "0x00000001",
                    Disposition = malicious ? "blocked" : "suspicious",
                    Severity = malicious ? "critical" : "high",
                    Message = "Malicious file detected by local static scan (" + eventReason + "): verdict=" + verdictText +
                              ", score=" + result.Score.ToString(CultureInfo.InvariantCulture) +
                              (matchedRulesText.Length > 0 ? (", rules=" + matchedRulesText) : (", reasons=" + (result.ReasonText ?? string.Empty))) +
                              ", sha256=" + (result.Sha256 ?? string.Empty),
                    SourceHost = Environment.MachineName,
                    SourceUser = Environment.UserName,
                    SourceProcess = fileName,
                    TargetHost = Environment.MachineName,
                    TargetProcess = fileName,
                    ObjectType = "executable",
                    ObjectName = path,
                    ObjectFormat = result.Sha256 ?? string.Empty,
                    PolicyName = "static-scan",
                    EventDetails = detailJson
                };

                // Forward both detections and (for visibility) clean executable
                // scans? No - only flagged results go to the console to avoid
                // flooding; clean scans are logged locally.
                if (flagged)
                {
                    lock (localScanAuditLock)
                    {
                        localScanAuditRecords.Add(record);
                    }
                }

                MarkSandboxHashProcessed(hash);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " local executable scan failed for " + path + ": " + ex.Message);
            }
        }

        private static string SafeExtensionForAudit(string path)
        {
            try
            {
                string ext = Path.GetExtension(path);
                return string.IsNullOrEmpty(ext) ? string.Empty : ext.ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        // Build a structured evidence payload (JSON) for the console's detail /
        // attack-flow view: where the file came from, who/what landed it, the
        // matched rules, hash, and verdict.
        private string BuildStaticScanEvidence(
            LocalScanResult result,
            SandboxExecutableEvent executableEvent,
            string eventReason,
            string matchedRulesText,
            string directory)
        {
            try
            {
                Dictionary<string, object> evidence = new Dictionary<string, object>
                {
                    { "kind", "static-scan" },
                    { "verdict", result.VerdictText ?? string.Empty },
                    { "score", result.Score },
                    { "sha256", result.Sha256 ?? string.Empty },
                    { "filePath", result.Path ?? string.Empty },
                    { "fileName", Path.GetFileName(result.Path ?? string.Empty) },
                    { "directory", directory },
                    { "landingReason", eventReason },
                    { "previousPath", executableEvent.PreviousPath ?? string.Empty },
                    { "fileSize", result.FileSize },
                    { "matchedRules", result.MatchedRules ?? new string[0] },
                    { "matchedRuleCount", result.MatchedRules == null ? 0 : result.MatchedRules.Length },
                    { "reasons", result.ReasonText ?? string.Empty },
                    { "engines", result.EngineStatus ?? new string[0] },
                    { "detectedHost", Environment.MachineName },
                    { "detectedUser", Environment.UserName },
                    { "detectedUtc", DateTime.UtcNow.ToString("o") }
                };

                return serializer.Serialize(evidence);
            }
            catch
            {
                return string.Empty;
            }
        }

        private void MarkSandboxHashProcessed(string hash)
        {
            if (string.IsNullOrEmpty(hash))
            {
                return;
            }

            lock (sandboxExecutableLock)
            {
                if (sandboxUploadedHashes.Add(hash))
                {
                    while (sandboxUploadedHashes.Count > SandboxMaxKnownHashes)
                    {
                        using (HashSet<string>.Enumerator e = sandboxUploadedHashes.GetEnumerator())
                        {
                            if (e.MoveNext())
                            {
                                sandboxUploadedHashes.Remove(e.Current);
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        private AuditLog.AuditRecord[] DrainLocalScanAuditRecords()
        {
            lock (localScanAuditLock)
            {
                if (localScanAuditRecords.Count == 0)
                {
                    return new AuditLog.AuditRecord[0];
                }

                AuditLog.AuditRecord[] drained = localScanAuditRecords.ToArray();
                localScanAuditRecords.Clear();
                return drained;
            }
        }

        private void StartSandboxExecutableWatchers()
        {
            foreach (string directory in GetSandboxExecutableWatchDirectories())
            {
                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher(directory)
                    {
                        Filter = "*.*",
                        IncludeSubdirectories = false,
                        InternalBufferSize = 64 * 1024,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size
                    };
                    watcher.Created += OnSandboxExecutableCreated;
                    watcher.Renamed += OnSandboxExecutableRenamed;
                    watcher.Error += OnSandboxExecutableWatcherError;
                    watcher.EnableRaisingEvents = true;
                    sandboxExecutableWatchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " sandbox executable watcher failed for " + directory + ": " + ex.Message);
                }
            }

            if (sandboxExecutableWatchers.Count > 0)
            {
                Console.WriteLine(DateTime.Now.ToString("s") + " Sandbox executable watcher armed for " + sandboxExecutableWatchers.Count + " directory/directories. Only newly created .exe files and rename targets ending in .exe will be submitted.");
            }
        }

        private IEnumerable<string> GetSandboxExecutableWatchDirectories()
        {
            HashSet<string> directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddCandidateDirectory(directories, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            AddCandidateDirectory(directories, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            AddCandidateDirectory(directories, Path.GetTempPath());
            AddCandidateDirectory(directories, Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            AddCandidateDirectory(directories, EnsureDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataProtector", "Incoming")));
            return directories;
        }

        private void OnSandboxExecutableCreated(object sender, FileSystemEventArgs e)
        {
            EnqueueSandboxExecutableEvent(e == null ? string.Empty : e.FullPath, "created", string.Empty);
        }

        private void OnSandboxExecutableRenamed(object sender, RenamedEventArgs e)
        {
            EnqueueSandboxExecutableEvent(e == null ? string.Empty : e.FullPath, "renamed", e == null ? string.Empty : e.OldFullPath);
        }

        private void OnSandboxExecutableWatcherError(object sender, ErrorEventArgs e)
        {
            Exception error = e == null ? null : e.GetException();
            Console.Error.WriteLine(DateTime.Now.ToString("s") + " sandbox executable watcher error: " + (error == null ? "unknown error" : error.Message));
        }

        private void EnqueueSandboxExecutableEvent(string path, string eventKind, string previousPath)
        {
            path = NormalizeLocalPath(path);
            if (!IsExecutablePath(path))
            {
                return;
            }

            lock (sandboxExecutableLock)
            {
                if (pendingSandboxExecutablePaths.Contains(path))
                {
                    return;
                }

                while (pendingSandboxExecutableEvents.Count >= SandboxMaxPendingEvents)
                {
                    SandboxExecutableEvent dropped = pendingSandboxExecutableEvents.Dequeue();
                    if (dropped != null)
                    {
                        pendingSandboxExecutablePaths.Remove(dropped.Path);
                    }
                }

                SandboxExecutableEvent executableEvent = new SandboxExecutableEvent
                {
                    Path = path,
                    PreviousPath = NormalizeLocalPath(previousPath),
                    EventKind = string.Equals(eventKind, "renamed", StringComparison.OrdinalIgnoreCase) ? "renamed" : "created",
                    FirstSeenUtc = DateTime.UtcNow,
                    NotBeforeUtc = DateTime.UtcNow.AddMilliseconds(SandboxFileReadyDelayMs),
                    LastLength = -1
                };
                pendingSandboxExecutableEvents.Enqueue(executableEvent);
                pendingSandboxExecutablePaths.Add(path);
            }

            Console.WriteLine(DateTime.Now.ToString("s") + " Sandbox executable event queued kind=" + eventKind + " path=" + path);
        }

        private SandboxExecutableEvent DequeueSandboxExecutableEvent()
        {
            lock (sandboxExecutableLock)
            {
                DateTime now = DateTime.UtcNow;
                int count = pendingSandboxExecutableEvents.Count;
                for (int index = 0; index < count; index++)
                {
                    SandboxExecutableEvent executableEvent = pendingSandboxExecutableEvents.Dequeue();
                    pendingSandboxExecutablePaths.Remove(executableEvent.Path);
                    if (executableEvent.NotBeforeUtc > now)
                    {
                        pendingSandboxExecutableEvents.Enqueue(executableEvent);
                        pendingSandboxExecutablePaths.Add(executableEvent.Path);
                        continue;
                    }

                    return executableEvent;
                }
            }

            return null;
        }

        private void RequeueSandboxExecutableEvent(SandboxExecutableEvent executableEvent)
        {
            if (executableEvent == null || !IsExecutablePath(executableEvent.Path))
            {
                return;
            }

            lock (sandboxExecutableLock)
            {
                if (pendingSandboxExecutablePaths.Contains(executableEvent.Path))
                {
                    return;
                }

                while (pendingSandboxExecutableEvents.Count >= SandboxMaxPendingEvents)
                {
                    SandboxExecutableEvent dropped = pendingSandboxExecutableEvents.Dequeue();
                    if (dropped != null)
                    {
                        pendingSandboxExecutablePaths.Remove(dropped.Path);
                    }
                }

                pendingSandboxExecutableEvents.Enqueue(executableEvent);
                pendingSandboxExecutablePaths.Add(executableEvent.Path);
            }
        }

        private void RequeueSandboxSamples(CentralPolicyStore.SandboxSampleSubmission[] samples)
        {
            if (samples == null || samples.Length == 0)
            {
                return;
            }

            foreach (CentralPolicyStore.SandboxSampleSubmission sample in samples)
            {
                if (sample == null || string.IsNullOrWhiteSpace(sample.processPath))
                {
                    continue;
                }

                RequeueSandboxExecutableEvent(new SandboxExecutableEvent
                {
                    Path = NormalizeLocalPath(sample.processPath),
                    EventKind = "created",
                    FirstSeenUtc = DateTime.UtcNow,
                    NotBeforeUtc = DateTime.UtcNow.AddSeconds(1),
                    Attempts = 0,
                    LastLength = -1
                });
            }
        }

        private SandboxExecutableReadiness ProbeSandboxExecutableReadiness(SandboxExecutableEvent executableEvent)
        {
            if (executableEvent == null || !IsExecutablePath(executableEvent.Path))
            {
                return SandboxExecutableReadiness.Invalid;
            }

            FileInfo info;
            try
            {
                info = new FileInfo(executableEvent.Path);
            }
            catch
            {
                return SandboxExecutableReadiness.Invalid;
            }

            if (!info.Exists)
            {
                return SandboxExecutableReadiness.Invalid;
            }

            if (info.Length <= 0)
            {
                return SandboxExecutableReadiness.Waiting;
            }

            if (info.Length > SandboxMaxUploadBytes)
            {
                return SandboxExecutableReadiness.Invalid;
            }

            if (executableEvent.LastLength >= 0 && executableEvent.LastLength != info.Length)
            {
                executableEvent.LastLength = info.Length;
                return SandboxExecutableReadiness.Waiting;
            }

            executableEvent.LastLength = info.Length;
            if (info.LastWriteTimeUtc > DateTime.UtcNow.AddMilliseconds(-SandboxFileReadyDelayMs))
            {
                return SandboxExecutableReadiness.Waiting;
            }

            return ProbePortableExecutableHeader(executableEvent.Path);
        }

        private static void AddCandidateDirectory(HashSet<string> directories, string directory)
        {
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                directories.Add(directory);
            }
        }

        private CentralPolicyStore.SandboxSampleSubmission TryBuildSandboxSubmission(SandboxExecutableEvent executableEvent)
        {
            try
            {
                string path = executableEvent.Path;
                string hash = ComputeSha256Hex(path);
                if (sandboxUploadedHashes.Contains(hash))
                {
                    return null;
                }

                string suspicion = BuildSandboxSuspicion(executableEvent);
                byte[] bytes = File.ReadAllBytes(path);
                return new CentralPolicyStore.SandboxSampleSubmission
                {
                    fileName = Path.GetFileName(path),
                    contentBase64 = Convert.ToBase64String(bytes),
                    sha256 = hash,
                    source = "agent",
                    host = Environment.MachineName,
                    deviceId = deviceId,
                    processPath = path,
                    suspicion = suspicion,
                    actor = "agent-suspicious-exe"
                };
            }
            catch
            {
                return null;
            }
        }

        private static string BuildSandboxSuspicion(SandboxExecutableEvent executableEvent)
        {
            string path = executableEvent.Path;
            FileInfo info = new FileInfo(path);
            string directory = (info.DirectoryName ?? string.Empty).ToLowerInvariant();
            string signer = TryReadSignerSubject(path);
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            bool unsigned = string.IsNullOrWhiteSpace(signer);
            bool userWritableLocation =
                directory.Contains("\\downloads") ||
                directory.Contains("\\desktop") ||
                directory.Contains("\\temp") ||
                directory.Contains("\\appdata\\local\\temp");
            bool weakMetadata =
                string.IsNullOrWhiteSpace(version.CompanyName) &&
                string.IsNullOrWhiteSpace(version.ProductName) &&
                string.IsNullOrWhiteSpace(version.FileDescription);

            string eventReason = string.Equals(executableEvent.EventKind, "renamed", StringComparison.OrdinalIgnoreCase)
                ? "Executable file was renamed to an .exe target"
                : "New executable file was created";

            if (unsigned && userWritableLocation)
            {
                return eventReason + "; unsigned executable in a user-writable location.";
            }

            if (unsigned && weakMetadata)
            {
                return eventReason + "; unsigned executable with weak version metadata.";
            }

            return eventReason + "; executable event captured for server-side sandbox analysis.";
        }

        private static SandboxExecutableReadiness ProbePortableExecutableHeader(string path)
        {
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (stream.Length < 2)
                    {
                        return SandboxExecutableReadiness.Waiting;
                    }

                    int first = stream.ReadByte();
                    int second = stream.ReadByte();
                    return first == 'M' && second == 'Z'
                        ? SandboxExecutableReadiness.Ready
                        : SandboxExecutableReadiness.Invalid;
                }
            }
            catch (IOException)
            {
                return SandboxExecutableReadiness.Waiting;
            }
            catch (UnauthorizedAccessException)
            {
                return SandboxExecutableReadiness.Waiting;
            }
        }

        private static bool IsExecutablePath(string path)
        {
            return !string.IsNullOrWhiteSpace(path) &&
                   string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeLocalPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFullPath(path);
            }
            catch
            {
                return path.Trim();
            }
        }

        private static string EnsureDirectory(string directory)
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                return string.Empty;
            }

            try
            {
                Directory.CreateDirectory(directory);
            }
            catch
            {
            }

            return directory;
        }

        private void MarkSandboxSamplesUploaded(CentralPolicyStore.SandboxSampleSubmission[] samples)
        {
            if (samples == null || samples.Length == 0)
            {
                return;
            }

            foreach (CentralPolicyStore.SandboxSampleSubmission sample in samples)
            {
                if (sample != null && IsSha256(sample.sha256))
                {
                    sandboxUploadedHashes.Add(sample.sha256);
                }
            }

            SaveSandboxUploadState();
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
            PolicyBridgeService.UserHookDefensePolicyDto userHookDefensePolicy,
            PolicyBridgeService.UsbCryptPolicyDto usbCryptPolicy,
            PolicyBridgeService.DlpProtectionPolicyDto dlpProtectionPolicy,
            long policyVersion)
        {
            userHookDefensePolicy = NormalizeAgentUserHookPolicy(userHookDefensePolicy);
            uint desiredUserHookFlags = PolicyBridgeService.ToUserHookDefenseFlags(userHookDefensePolicy);

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

            clear = policyService.ClearFileHunterRules("central-agent");
            if (!clear.succeeded)
            {
                lastApplyStatus = clear.statusText;
                lastApplyMessage = "Cannot clear local file hunter policy before central apply: " + clear.message;
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

            foreach (string safeFolder in dlpProtectionPolicy.safeFolders ?? new string[0])
            {
                PolicyBridgeService.OperationResult result = policyService.AddFileHunterRule(new PolicyBridgeService.FileHunterRuleRequest
                {
                    directory = safeFolder,
                    actor = "central-agent"
                });

                if (!result.succeeded)
                {
                    lastApplyStatus = result.statusText;
                    lastApplyMessage = "Cannot apply central safe folder " + safeFolder + ": " + result.message;
                    SaveState();
                    return;
                }
            }

            try
            {
                PolicyBridgeService.FileHunterRuleDto[] hunterRules = policyService.QueryFileHunterRules();
                Console.WriteLine(
                    DateTime.Now.ToString("s") +
                    " File hunter central safe folders applied: requested=" +
                    (dlpProtectionPolicy.safeFolders == null ? 0 : dlpProtectionPolicy.safeFolders.Length).ToString() +
                    "; driverRules=" +
                    hunterRules.Length.ToString() +
                    "; rules=" +
                    string.Join(" | ", hunterRules.Select(rule => rule.directory ?? string.Empty).ToArray()));
            }
            catch (Exception ex)
            {
                lastApplyStatus = "0x00000001";
                lastApplyMessage = "Cannot verify local file hunter safe folder policy after apply: " + ex.Message;
                SaveState();
                return;
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

            PolicyBridgeService.OperationResult userHookPolicyResult = policyService.SetUserHookDefensePolicy(new PolicyBridgeService.UserHookDefensePolicyRequest
            {
                enabled = userHookDefensePolicy.enabled,
                monitorEarlyProcesses = userHookDefensePolicy.enabled || userHookDefensePolicy.monitorEarlyProcesses,
                monitorImageLoads = userHookDefensePolicy.monitorImageLoads,
                requireSignedRuntime = userHookDefensePolicy.requireSignedRuntime,
                blockUntrustedRuntime = userHookDefensePolicy.blockUntrustedRuntime,
                auditOnly = userHookDefensePolicy.auditOnly,
                monitorSystemProcesses = userHookDefensePolicy.monitorSystemProcesses,
                monitorRuntimeApiBehavior = userHookDefensePolicy.monitorRuntimeApiBehavior,
                scanExecutableMemory = userHookDefensePolicy.scanExecutableMemory,
                monitorEtwTamper = userHookDefensePolicy.monitorEtwTamper,
                excludedProcessNames = userHookDefensePolicy.excludedProcessNames,
                excludedProcessDirectories = userHookDefensePolicy.excludedProcessDirectories,
                excludedProcessPaths = userHookDefensePolicy.excludedProcessPaths,
                trustedSignerSubjects = userHookDefensePolicy.trustedSignerSubjects,
                runtimePath = userHookDefensePolicy.runtimePath,
                actor = "central-agent"
            });

            if (!userHookPolicyResult.succeeded)
            {
                lastApplyStatus = userHookPolicyResult.statusText;
                lastApplyMessage = "Cannot apply central process threat insight policy: " + userHookPolicyResult.message;
                SaveState();
                return;
            }

            try
            {
                PolicyBridgeService.UserHookDefensePolicyDto kernelUserHookPolicy = policyService.QueryKernelUserHookDefensePolicy();
                uint kernelFlags = kernelUserHookPolicy.flags;
                string message = "Process threat insight policy written. desiredFlags=0x" +
                                 desiredUserHookFlags.ToString("X8") +
                                 "; kernelFlags=0x" +
                                 kernelFlags.ToString("X8") +
                                 "; " +
                                 PolicyBridgeService.UserHookDefensePolicySummary(kernelUserHookPolicy);
                Console.WriteLine(DateTime.Now.ToString("s") + " " + message);
                if (kernelFlags != desiredUserHookFlags)
                {
                    lastApplyStatus = "0x00000001";
                    lastApplyMessage = "Central process threat insight policy write mismatch: " + message;
                    SaveState();
                    return;
                }
            }
            catch (Exception ex)
            {
                lastApplyStatus = "0x00000001";
                lastApplyMessage = "Cannot verify local process threat insight policy after apply: " + ex.Message;
                SaveState();
                return;
            }

            currentUserHookDefensePolicy = PolicyBridgeService.CloneUserHookDefensePolicy(userHookDefensePolicy);
            PersistUsbCryptPolicy(usbCryptPolicy);
            dlpProtectionService.UpdatePolicy(dlpProtectionPolicy);

            appliedPolicyVersion = policyVersion;
            lastApplyStatus = "0x00000000";
            lastApplyMessage = "Central policy applied. File rules: " + rules.Length + ", network rules: " + networkRules.Length + ", WebShell rules: " + webShellRules.Length + ", safe folders: " + (dlpProtectionPolicy.safeFolders == null ? 0 : dlpProtectionPolicy.safeFolders.Length) + ", device rules: " + deviceRules.Length + ", hash protection: " + PolicyBridgeService.HashProtectPolicySummary(hashProtectPolicy) + ", lateral defense: " + PolicyBridgeService.LateralDefensePolicySummary(lateralDefensePolicy) + ", process threat insight: " + PolicyBridgeService.UserHookDefensePolicySummary(userHookDefensePolicy) + ", USB crypt: " + PolicyBridgeService.UsbCryptPolicySummary(usbCryptPolicy) + ", DLP: " + PolicyBridgeService.DlpProtectionPolicySummary(dlpProtectionPolicy);
            SaveState();
        }

        private static PolicyBridgeService.UserHookDefensePolicyDto NormalizeAgentUserHookPolicy(PolicyBridgeService.UserHookDefensePolicyDto policy)
        {
            PolicyBridgeService.UserHookDefensePolicyDto normalized = PolicyBridgeService.CloneUserHookDefensePolicy(
                policy ?? PolicyBridgeService.DefaultUserHookDefensePolicy());
            if (normalized.enabled)
            {
                normalized.monitorEarlyProcesses = true;
                normalized.flags = PolicyBridgeService.ToUserHookDefenseFlags(normalized);
            }

            return normalized;
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

        private void LoadSandboxUploadState()
        {
            try
            {
                if (!File.Exists(sandboxUploadStatePath))
                {
                    return;
                }

                SandboxUploadState state = serializer.Deserialize<SandboxUploadState>(File.ReadAllText(sandboxUploadStatePath, Encoding.UTF8));
                if (state == null || state.Hashes == null)
                {
                    return;
                }

                foreach (string hash in state.Hashes.Where(IsSha256))
                {
                    sandboxUploadedHashes.Add(hash);
                }
            }
            catch
            {
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

        private void SaveSandboxUploadState()
        {
            try
            {
                TrimSandboxUploadHashes();
                File.WriteAllText(sandboxUploadStatePath, serializer.Serialize(new SandboxUploadState
                {
                    Hashes = sandboxUploadedHashes.ToArray()
                }), Encoding.UTF8);
            }
            catch
            {
            }
        }

        private void TrimSandboxUploadHashes()
        {
            if (sandboxUploadedHashes.Count <= SandboxMaxKnownHashes)
            {
                return;
            }

            string[] keep = sandboxUploadedHashes.Take(SandboxMaxKnownHashes).ToArray();
            sandboxUploadedHashes.Clear();
            foreach (string hash in keep)
            {
                sandboxUploadedHashes.Add(hash);
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

        private static bool IsSha256(string value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   value.Length == 64 &&
                   value.All(Uri.IsHexDigit);
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

        private sealed class SandboxUploadState
        {
            public string[] Hashes { get; set; }
        }

        private enum SandboxExecutableReadiness
        {
            Invalid = 0,
            Waiting = 1,
            Ready = 2
        }

        private sealed class SandboxExecutableEvent
        {
            public string Path { get; set; }
            public string PreviousPath { get; set; }
            public string EventKind { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime NotBeforeUtc { get; set; }
            public int Attempts { get; set; }
            public long LastLength { get; set; }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetModuleHandleEx(uint flags, string moduleName, out IntPtr moduleHandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileName(IntPtr moduleHandle, StringBuilder fileName, int size);
    }
}
