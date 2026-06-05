using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    /// <summary>
    /// User-mode executable scanning service. Drains scan REQUESTS the kernel
    /// captured on executable writes, runs an extensible pipeline of scan
    /// engines (YARA, heuristic PE analysis, hash reputation, future ML/cloud),
    /// fuses their results into a verdict, and submits the verdict back to the
    /// kernel which enforces quarantine.
    ///
    /// This is the commercial EDR shape: detection content lives entirely in
    /// user mode and is updatable without reloading a signed kernel driver. New
    /// engines plug in by implementing IScanEngine and registering here; no
    /// kernel change is required.
    /// </summary>
    internal sealed class StaticScanService
    {
        // Mirrors DP_STATIC_SCAN_VERDICT.
        public const uint VerdictClean = 0;
        public const uint VerdictLowRisk = 1;
        public const uint VerdictSuspicious = 2;
        public const uint VerdictMalicious = 3;

        // Default fusion thresholds (0..100). Tunable via policy later.
        private const int DefaultSuspiciousThreshold = 60;
        private const int DefaultMaliciousThreshold = 75;

        // Bound the read so a huge file cannot exhaust the agent.
        private const int MaxScanBytes = 16 * 1024 * 1024;

        // Engines never run forever per heartbeat.
        private const int MaxRequestsPerCycle = 16;

        private readonly PolicyBridgeService policyService;
        private readonly List<IScanEngine> engines = new List<IScanEngine>();
        private readonly object syncRoot = new object();
        private readonly object auditRoot = new object();
        private readonly List<AuditLog.AuditRecord> auditRecords = new List<AuditLog.AuditRecord>();
        private readonly string quarantineRoot;
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly Timer requestPump;
        private int suspiciousThreshold = DefaultSuspiciousThreshold;
        private int maliciousThreshold = DefaultMaliciousThreshold;
        private int processingRequests;

        public StaticScanService(PolicyBridgeService policyService, string ruleRoot)
        {
            this.policyService = policyService ?? throw new ArgumentNullException("policyService");

            string baseRoot = string.IsNullOrWhiteSpace(ruleRoot)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataProtector")
                : ruleRoot;
            string scanRoot = Path.Combine(baseRoot, "StaticScan");
            quarantineRoot = Path.Combine(scanRoot, "quarantine");
            try
            {
                Directory.CreateDirectory(scanRoot);
                Directory.CreateDirectory(quarantineRoot);
            }
            catch
            {
                // Non-fatal: engines that need on-disk rules will report unavailable.
            }

            // Register engines. Order is informational; all engines run and the
            // strongest result wins. New engines (ML, cloud reputation) plug in
            // here without touching the kernel or the request/verdict transport.
            //
            // YARA loads rules from the runtime-updatable ProgramData directory
            // (synced from the central server) AND the 'yara-rules' folder that
            // ships beside the agent executable (the bundled baseline sets).
            string runtimeRulesDir = Path.Combine(scanRoot, "rules");
            string bundledRulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory ?? ".", "yara-rules");
            YaraScanEngine yara = new YaraScanEngine(runtimeRulesDir, bundledRulesDir);
            engines.Add(yara);
            engines.Add(new HeuristicPeScanEngine());
            engines.Add(new HashReputationScanEngine(Path.Combine(scanRoot, "hash-reputation")));

            // Compile YARA rules off the request path so the first executable
            // scan is not blocked by a multi-thousand-file compile and the
            // memory footprint settles before steady-state work begins.
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    yara.Warmup();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " YARA warmup failed: " + ex.Message);
                }
            });

            requestPump = new Timer(_ => ProcessPendingRequests(), null, TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(500));
        }

        public string[] EngineStatus()
        {
            List<string> status = new List<string>();
            lock (syncRoot)
            {
                foreach (IScanEngine engine in engines)
                {
                    status.Add(engine.Name + "=" + (engine.IsAvailable ? "ready" : "unavailable"));
                }
            }

            return status.ToArray();
        }

        public void UpdateThresholds(uint maliciousThresholdValue, uint suspiciousThresholdValue)
        {
            lock (syncRoot)
            {
                if (maliciousThresholdValue > 0 && maliciousThresholdValue <= 100)
                {
                    maliciousThreshold = (int)maliciousThresholdValue;
                }

                if (suspiciousThresholdValue > 0 && suspiciousThresholdValue <= 100)
                {
                    suspiciousThreshold = (int)suspiciousThresholdValue;
                }
            }
        }

        /// <summary>
        /// Drain pending kernel scan requests, scan each, and submit verdicts.
        /// Returns the number of requests processed. Safe to call from the agent
        /// heartbeat; never throws into the caller's sync loop.
        /// </summary>
        public int ProcessPendingRequests()
        {
            if (Interlocked.Exchange(ref processingRequests, 1) != 0)
            {
                return 0;
            }

            PolicyBridgeService.StaticScanRequestDto[] requests;
            try
            {
                requests = policyService.QueryStaticScanRequests();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " static scan request drain failed: " + ex.Message);
                Interlocked.Exchange(ref processingRequests, 0);
                return 0;
            }

            if (requests == null || requests.Length == 0)
            {
                Interlocked.Exchange(ref processingRequests, 0);
                return 0;
            }

            int processed = 0;
            try
            {
                PolicyBridgeService.StaticScanPolicyDto policy = QueryPolicyOrDefault();

                foreach (PolicyBridgeService.StaticScanRequestDto request in requests)
                {
                    if (processed >= MaxRequestsPerCycle)
                    {
                        break;
                    }

                    try
                    {
                        ScanResultFusion fusion = ScanOne(request);
                        string quarantinePath = string.Empty;
                        string quarantineStatus = string.Empty;

                        if (ShouldQuarantine(policy, fusion.Verdict))
                        {
                            quarantinePath = TryCopyToQuarantine(request, fusion, out quarantineStatus);
                            if (!string.IsNullOrWhiteSpace(quarantinePath))
                            {
                                fusion.ReasonText = AppendReason(fusion.ReasonText, "quarantine=" + quarantinePath);
                            }
                            else if (!string.IsNullOrWhiteSpace(quarantineStatus))
                            {
                                fusion.ReasonText = AppendReason(fusion.ReasonText, "quarantine-error=" + quarantineStatus);
                            }
                        }

                        PolicyBridgeService.StaticScanVerdictRequest verdict = new PolicyBridgeService.StaticScanVerdictRequest
                        {
                            requestId = request.requestId,
                            processId = request.processId,
                            fileSize = request.fileSize,
                            operation = request.operation,
                            path = request.path,
                            verdict = fusion.Verdict,
                            score = (uint)fusion.Score,
                            reasonFlags = fusion.ReasonFlags,
                            reasonText = fusion.ReasonText
                        };

                        policyService.SubmitStaticScanVerdict(verdict);
                        processed++;

                        if (fusion.Verdict >= VerdictSuspicious)
                        {
                            QueueAuditRecord(request, fusion, quarantinePath, quarantineStatus);
                            Console.WriteLine(DateTime.Now.ToString("s") +
                                " static scan verdict=" + VerdictText(fusion.Verdict) +
                                " score=" + fusion.Score.ToString(CultureInfo.InvariantCulture) +
                                " source=" + (request.processImage ?? string.Empty) +
                                " path=" + (request.path ?? string.Empty));
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine(DateTime.Now.ToString("s") + " static scan failed for request " +
                            request.requestId.ToString(CultureInfo.InvariantCulture) + ": " + ex.Message);
                    }
                }
            }
            finally
            {
                Interlocked.Exchange(ref processingRequests, 0);
            }

            return processed;
        }

        public AuditLog.AuditRecord[] DrainAuditRecords()
        {
            lock (auditRoot)
            {
                if (auditRecords.Count == 0)
                {
                    return new AuditLog.AuditRecord[0];
                }

                AuditLog.AuditRecord[] records = auditRecords.ToArray();
                auditRecords.Clear();
                return records;
            }
        }

        private PolicyBridgeService.StaticScanPolicyDto QueryPolicyOrDefault()
        {
            try
            {
                return policyService.QueryStaticScanPolicy();
            }
            catch
            {
                return new PolicyBridgeService.StaticScanPolicyDto
                {
                    enabled = true,
                    scanPe = true,
                    scanScripts = true,
                    blockMalicious = true,
                    blockSuspicious = false,
                    auditOnly = false
                };
            }
        }

        private static bool ShouldQuarantine(PolicyBridgeService.StaticScanPolicyDto policy, uint verdict)
        {
            if (policy == null || !policy.enabled || policy.auditOnly)
            {
                return false;
            }

            return (verdict >= VerdictMalicious && policy.blockMalicious) ||
                   (verdict >= VerdictSuspicious && policy.blockSuspicious);
        }

        private static string AppendReason(string reason, string extra)
        {
            string value = string.IsNullOrWhiteSpace(reason) ? extra : reason + "; " + extra;
            return value.Length > 250 ? value.Substring(0, 250) : value;
        }

        private string TryCopyToQuarantine(PolicyBridgeService.StaticScanRequestDto request, ScanResultFusion fusion, out string status)
        {
            status = string.Empty;
            string path = request == null ? string.Empty : request.path;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                status = "source-missing";
                return string.Empty;
            }

            try
            {
                Directory.CreateDirectory(quarantineRoot);
                string safeName = MakeSafeFileName(Path.GetFileName(path));
                string hashPart = string.IsNullOrWhiteSpace(fusion.Sha256) ? "nohash" : fusion.Sha256.Substring(0, Math.Min(16, fusion.Sha256.Length));
                string quarantinePath = Path.Combine(
                    quarantineRoot,
                    DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", CultureInfo.InvariantCulture) +
                    "-" + request.requestId.ToString(CultureInfo.InvariantCulture) +
                    "-" + hashPart +
                    "-" + safeName +
                    ".quarantine");

                using (FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (FileStream output = new FileStream(quarantinePath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                {
                    byte[] buffer = new byte[1024 * 1024];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, read);
                    }
                }

                WriteQuarantineMetadata(quarantinePath, request, fusion);
                status = "copied";
                return quarantinePath;
            }
            catch (Exception ex)
            {
                status = ex.Message;
                return string.Empty;
            }
        }

        private void WriteQuarantineMetadata(string quarantinePath, PolicyBridgeService.StaticScanRequestDto request, ScanResultFusion fusion)
        {
            try
            {
                Dictionary<string, object> metadata = new Dictionary<string, object>
                {
                    { "requestId", request.requestId },
                    { "originalPath", request.path ?? string.Empty },
                    { "sourceProcess", request.processImage ?? string.Empty },
                    { "sourcePid", request.processId },
                    { "operation", request.operationText ?? string.Empty },
                    { "verdict", VerdictText(fusion.Verdict) },
                    { "score", fusion.Score },
                    { "sha256", fusion.Sha256 ?? string.Empty },
                    { "reason", fusion.ReasonText ?? string.Empty },
                    { "matchedRules", fusion.MatchedRules ?? new string[0] },
                    { "quarantinedUtc", DateTime.UtcNow.ToString("o") }
                };
                File.WriteAllText(quarantinePath + ".json", serializer.Serialize(metadata), Encoding.UTF8);
            }
            catch
            {
            }
        }

        private static string MakeSafeFileName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return "sample";
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(name.Length);
            foreach (char ch in name)
            {
                builder.Append(Array.IndexOf(invalid, ch) >= 0 ? '_' : ch);
            }

            return builder.Length == 0 ? "sample" : builder.ToString();
        }

        private void QueueAuditRecord(PolicyBridgeService.StaticScanRequestDto request, ScanResultFusion fusion, string quarantinePath, string quarantineStatus)
        {
            string fileName = Path.GetFileName(request.path ?? string.Empty);
            string rules = (fusion.MatchedRules != null && fusion.MatchedRules.Length > 0)
                ? string.Join(", ", fusion.MatchedRules)
                : string.Empty;
            Dictionary<string, object> evidence = new Dictionary<string, object>
            {
                { "kind", "kernel-static-scan" },
                { "requestId", request.requestId },
                { "sourcePid", request.processId },
                { "sourceProcess", request.processImage ?? string.Empty },
                { "operation", request.operationText ?? string.Empty },
                { "filePath", request.path ?? string.Empty },
                { "fileName", fileName ?? string.Empty },
                { "fileSize", request.fileSize },
                { "verdict", VerdictText(fusion.Verdict) },
                { "score", fusion.Score },
                { "sha256", fusion.Sha256 ?? string.Empty },
                { "matchedRules", fusion.MatchedRules ?? new string[0] },
                { "reasons", fusion.ReasonText ?? string.Empty },
                { "quarantinePath", quarantinePath ?? string.Empty },
                { "quarantineStatus", quarantineStatus ?? string.Empty },
                { "engines", EngineStatus() },
                { "detectedHost", Environment.MachineName },
                { "detectedUtc", DateTime.UtcNow.ToString("o") }
            };

            AuditLog.AuditRecord record = new AuditLog.AuditRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Host = Environment.MachineName,
                Actor = "static-scan",
                Action = "static-scan.detection",
                Target = request.path ?? string.Empty,
                Extension = request.processImage ?? string.Empty,
                SourcePid = request.processId.ToString(CultureInfo.InvariantCulture),
                SourceHost = Environment.MachineName,
                SourceUser = Environment.UserName,
                SourceProcess = request.processImage ?? string.Empty,
                TargetHost = Environment.MachineName,
                TargetProcess = fileName ?? string.Empty,
                ObjectType = "executable",
                ObjectName = request.path ?? string.Empty,
                ObjectFormat = fusion.Sha256 ?? string.Empty,
                PolicyName = "static-scan",
                Succeeded = false,
                Status = fusion.Verdict >= VerdictMalicious ? "0xC0000022" : "0x00000001",
                Disposition = fusion.Verdict >= VerdictMalicious ? "blocked" : "suspicious",
                Severity = fusion.Verdict >= VerdictMalicious ? "critical" : "high",
                Message = "Static scan detection: source=" + (request.processImage ?? string.Empty) +
                          ", pid=" + request.processId.ToString(CultureInfo.InvariantCulture) +
                          ", op=" + (request.operationText ?? string.Empty) +
                          ", verdict=" + VerdictText(fusion.Verdict) +
                          ", score=" + fusion.Score.ToString(CultureInfo.InvariantCulture) +
                          (rules.Length > 0 ? (", rules=" + rules) : (", reasons=" + (fusion.ReasonText ?? string.Empty))) +
                          (string.IsNullOrWhiteSpace(quarantinePath) ? string.Empty : (", quarantine=" + quarantinePath)),
                EventDetails = serializer.Serialize(evidence)
            };

            lock (auditRoot)
            {
                auditRecords.Add(record);
            }
        }

        private ScanResultFusion ScanOne(PolicyBridgeService.StaticScanRequestDto request)
        {
            return ScanPathCore(request.path, request.fileSize);
        }

        /// <summary>
        /// Scan an arbitrary local file on demand (used by the agent's
        /// file-watch flow so executables are analyzed locally instead of being
        /// uploaded). Returns a public result with verdict, score, and reasons.
        /// </summary>
        public LocalScanResult ScanFile(string path)
        {
            ulong size = 0;
            try
            {
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    size = (ulong)new FileInfo(path).Length;
                }
            }
            catch
            {
            }

            ScanResultFusion fusion = ScanPathCore(path, size);
            return new LocalScanResult
            {
                Path = path ?? string.Empty,
                FileSize = size,
                Verdict = fusion.Verdict,
                VerdictText = VerdictText(fusion.Verdict),
                Score = fusion.Score,
                ReasonFlags = fusion.ReasonFlags,
                ReasonText = fusion.ReasonText,
                EngineStatus = EngineStatus(),
                MatchedRules = fusion.MatchedRules,
                Sha256 = fusion.Sha256
            };
        }

        private ScanResultFusion ScanPathCore(string path, ulong fileSize)
        {
            ScanResultFusion fusion = new ScanResultFusion();

            // Trust check: a valid Authenticode signature is conclusive.
            // Set the flag and return clean immediately; no engine runs.
            if (!string.IsNullOrWhiteSpace(path) && AuthenticodeVerifier.IsTrustedSigned(path))
            {
                fusion.Verdict = VerdictClean;
                fusion.Score = 0;
                fusion.ReasonFlags = ScanReasonFlags.TrustedSigner;
                fusion.ReasonText = "trusted-signer";
                return fusion;
            }

            byte[] content = TryReadFile(path, out string readError);
            ScanContext context = new ScanContext
            {
                Path = path ?? string.Empty,
                FileSize = fileSize,
                Content = content
            };

            if (content == null)
            {
                // Could not read (locked / deleted / access denied). Report clean
                // so we do not falsely quarantine; the kernel keeps the file.
                fusion.Verdict = VerdictClean;
                fusion.Score = 0;
                fusion.ReasonText = string.IsNullOrEmpty(readError) ? "unreadable" : readError;
                return fusion;
            }

            int aggregateScore = 0;
            uint reasonFlags = 0;
            List<string> reasons = new List<string>();
            List<string> matchedRules = new List<string>();

            // Content hash (used for reputation correlation and as evidence).
            try
            {
                using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                {
                    fusion.Sha256 = BitConverter.ToString(sha.ComputeHash(content)).Replace("-", string.Empty);
                }
            }
            catch
            {
            }

            IScanEngine[] snapshot;
            lock (syncRoot)
            {
                snapshot = engines.ToArray();
            }

            foreach (IScanEngine engine in snapshot)
            {
                if (!engine.IsAvailable)
                {
                    continue;
                }

                ScanEngineResult result;
                try
                {
                    result = engine.Scan(context);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " scan engine '" + engine.Name + "' error: " + ex.Message);
                    continue;
                }

                if (result == null)
                {
                    continue;
                }

                // Engines contribute additively but the aggregate is capped, so a
                // single high-confidence engine (e.g. a YARA match) can reach the
                // malicious band on its own while weak heuristics accumulate.
                aggregateScore += result.Score;
                reasonFlags |= result.ReasonFlags;
                if (!string.IsNullOrWhiteSpace(result.Reason))
                {
                    reasons.Add(engine.Name + ": " + result.Reason);
                }

                if (result.MatchedRules != null)
                {
                    foreach (string rule in result.MatchedRules)
                    {
                        if (!string.IsNullOrWhiteSpace(rule) && !matchedRules.Contains(rule))
                        {
                            matchedRules.Add(rule);
                        }
                    }
                }
            }

            fusion.MatchedRules = matchedRules.ToArray();

            if (aggregateScore > 100)
            {
                aggregateScore = 100;
            }
            else if (aggregateScore < 0)
            {
                aggregateScore = 0;
            }

            int suspicious;
            int malicious;
            lock (syncRoot)
            {
                suspicious = suspiciousThreshold;
                malicious = maliciousThreshold;
            }

            uint verdict;
            if (aggregateScore >= malicious)
            {
                verdict = VerdictMalicious;
            }
            else if (aggregateScore >= suspicious)
            {
                verdict = VerdictSuspicious;
            }
            else if (aggregateScore > 0)
            {
                verdict = VerdictLowRisk;
            }
            else
            {
                verdict = VerdictClean;
            }

            fusion.Verdict = verdict;
            fusion.Score = aggregateScore;
            fusion.ReasonFlags = reasonFlags;
            fusion.ReasonText = reasons.Count == 0 ? "clean" : string.Join("; ", reasons);
            if (fusion.ReasonText.Length > 250)
            {
                fusion.ReasonText = fusion.ReasonText.Substring(0, 250);
            }

            return fusion;
        }

        private static byte[] TryReadFile(string path, out string error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(path))
            {
                error = "empty path";
                return null;
            }

            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long length = stream.Length;
                    int toRead = length > MaxScanBytes ? MaxScanBytes : (int)length;
                    byte[] buffer = new byte[toRead];
                    int offset = 0;
                    while (offset < toRead)
                    {
                        int read = stream.Read(buffer, offset, toRead - offset);
                        if (read <= 0)
                        {
                            break;
                        }
                        offset += read;
                    }

                    if (offset != toRead)
                    {
                        byte[] trimmed = new byte[offset];
                        Buffer.BlockCopy(buffer, 0, trimmed, 0, offset);
                        return trimmed;
                    }

                    return buffer;
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return null;
            }
        }

        private static string VerdictText(uint verdict)
        {
            switch (verdict)
            {
                case VerdictClean: return "clean";
                case VerdictLowRisk: return "low-risk";
                case VerdictSuspicious: return "suspicious";
                case VerdictMalicious: return "malicious";
                default: return "unknown";
            }
        }

        private sealed class ScanResultFusion
        {
            public uint Verdict;
            public int Score;
            public uint ReasonFlags;
            public string ReasonText = string.Empty;
            public string[] MatchedRules;
            public string Sha256;
        }
    }

    /// <summary>
    /// Public result of an on-demand local file scan.
    /// </summary>
    internal sealed class LocalScanResult
    {
        public string Path { get; set; }
        public ulong FileSize { get; set; }
        public uint Verdict { get; set; }
        public string VerdictText { get; set; }
        public int Score { get; set; }
        public uint ReasonFlags { get; set; }
        public string ReasonText { get; set; }
        public string[] EngineStatus { get; set; }
        public string[] MatchedRules { get; set; }
        public string Sha256 { get; set; }
    }

    /// <summary>
    /// Context handed to each scan engine. Content is the leading bytes of the
    /// file (capped); engines that need more re-read from Path themselves.
    /// </summary>
    internal sealed class ScanContext
    {
        public string Path { get; set; }
        public ulong FileSize { get; set; }
        public byte[] Content { get; set; }
    }

    internal sealed class ScanEngineResult
    {
        /// <summary>0..100 contribution to the aggregate risk score.</summary>
        public int Score { get; set; }

        /// <summary>DP_STATIC_SCAN_REASON_* bit flags.</summary>
        public uint ReasonFlags { get; set; }

        /// <summary>Short human-readable explanation.</summary>
        public string Reason { get; set; }

        /// <summary>Matched detection names (e.g. YARA rule identifiers).</summary>
        public string[] MatchedRules { get; set; }
    }

    /// <summary>
    /// Pluggable scan engine. Implement and register in StaticScanService to add
    /// a new detection technique without any kernel change.
    /// </summary>
    internal interface IScanEngine
    {
        string Name { get; }
        bool IsAvailable { get; }
        ScanEngineResult Scan(ScanContext context);
    }

    // Reason flag bits mirroring DP_STATIC_SCAN_REASON_* in DataProtector.h.
    internal static class ScanReasonFlags
    {
        public const uint ValidPe = 0x00000001u;
        public const uint HighEntropy = 0x00000002u;
        public const uint PackerSection = 0x00000004u;
        public const uint SuspiciousImport = 0x00000008u;
        public const uint SuspiciousString = 0x00000010u;
        public const uint NoImports = 0x00000020u;
        public const uint WxSection = 0x00000040u;
        public const uint TinyImage = 0x00000080u;
        public const uint ScriptDropper = 0x00000100u;
        public const uint DotnetPacked = 0x00000200u;
        public const uint Overlay = 0x00000400u;
        public const uint YaraMatch = 0x00000800u;
        public const uint HashReputation = 0x00001000u;
        public const uint TrustedSigner = 0x00002000u;  // valid Authenticode; kernel skips quarantine
    }

    /// <summary>
    /// Wraps WinVerifyTrust to check whether a file carries a valid Authenticode
    /// signature. A valid signature means the file is trusted and must not be
    /// quarantined regardless of heuristic score.
    /// </summary>
    internal static class AuthenticodeVerifier
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;        // 2 = WTD_UI_NONE
            public uint fdwRevocationChecks; // 0 = WTD_REVOKE_NONE
            public uint dwUnionChoice;     // 1 = WTD_CHOICE_FILE
            public IntPtr pFile;
            public uint dwStateAction;     // 0 = WTD_STATEACTION_IGNORE
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;       // 0x00001010 = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            public uint dwUIContext;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

        private static readonly Guid ActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private const uint ErrorSuccess = 0;

        public static bool IsTrustedSigned(string filePath)
        {
            try
            {
                WinTrustFileInfo fileInfo = new WinTrustFileInfo
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                try
                {
                    Marshal.StructureToPtr(fileInfo, pFile, false);

                    WinTrustData trustData = new WinTrustData
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                        dwUIChoice = 2,
                        fdwRevocationChecks = 0,
                        dwUnionChoice = 1,
                        pFile = pFile,
                        dwStateAction = 0,
                        dwProvFlags = 0x00001010
                    };

                    Guid actionId = ActionGenericVerifyV2;
                    uint result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);
                    return result == ErrorSuccess;
                }
                finally
                {
                    Marshal.FreeHGlobal(pFile);
                }
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Hash reputation engine. Looks up the file SHA-256 in updatable allow /
    /// deny lists shipped from the central server. A deny hit is decisive
    /// (malicious), an allow hit suppresses other noise.
    /// </summary>
    internal sealed class HashReputationScanEngine : IScanEngine
    {
        private readonly string denyListPath;
        private readonly string allowListPath;
        private readonly HashSet<string> denyHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> allowHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private DateTime denyStamp = DateTime.MinValue;
        private DateTime allowStamp = DateTime.MinValue;

        public HashReputationScanEngine(string reputationRoot)
        {
            try
            {
                Directory.CreateDirectory(reputationRoot);
            }
            catch
            {
            }

            denyListPath = Path.Combine(reputationRoot ?? ".", "deny-sha256.txt");
            allowListPath = Path.Combine(reputationRoot ?? ".", "allow-sha256.txt");
        }

        public string Name { get { return "hash-reputation"; } }

        // Always available; empty lists simply produce no hits.
        public bool IsAvailable { get { return true; } }

        public ScanEngineResult Scan(ScanContext context)
        {
            if (context == null || context.Content == null || context.Content.Length == 0)
            {
                return null;
            }

            RefreshLists();

            string hash;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(context.Content);
                hash = BitConverter.ToString(digest).Replace("-", string.Empty);
            }

            if (denyHashes.Contains(hash))
            {
                return new ScanEngineResult
                {
                    Score = 100,
                    ReasonFlags = ScanReasonFlags.HashReputation,
                    Reason = "known-bad hash"
                };
            }

            if (allowHashes.Contains(hash))
            {
                return new ScanEngineResult
                {
                    Score = -100,
                    ReasonFlags = ScanReasonFlags.HashReputation,
                    Reason = "known-good hash"
                };
            }

            return null;
        }

        private void RefreshLists()
        {
            denyStamp = LoadIfChanged(denyListPath, denyHashes, denyStamp);
            allowStamp = LoadIfChanged(allowListPath, allowHashes, allowStamp);
        }

        private static DateTime LoadIfChanged(string path, HashSet<string> target, DateTime lastStamp)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return lastStamp;
                }

                DateTime stamp = File.GetLastWriteTimeUtc(path);
                if (stamp == lastStamp)
                {
                    return lastStamp;
                }

                target.Clear();
                foreach (string raw in File.ReadAllLines(path))
                {
                    string line = raw == null ? string.Empty : raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    target.Add(line);
                }

                return stamp;
            }
            catch
            {
                return lastStamp;
            }
        }
    }
}
