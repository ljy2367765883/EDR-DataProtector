using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;

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
        private const int DefaultSuspiciousThreshold = 40;
        private const int DefaultMaliciousThreshold = 70;

        // Bound the read so a huge file cannot exhaust the agent.
        private const int MaxScanBytes = 16 * 1024 * 1024;

        // Engines never run forever per heartbeat.
        private const int MaxRequestsPerCycle = 16;

        private readonly PolicyBridgeService policyService;
        private readonly List<IScanEngine> engines = new List<IScanEngine>();
        private readonly object syncRoot = new object();
        private int suspiciousThreshold = DefaultSuspiciousThreshold;
        private int maliciousThreshold = DefaultMaliciousThreshold;

        public StaticScanService(PolicyBridgeService policyService, string ruleRoot)
        {
            this.policyService = policyService ?? throw new ArgumentNullException("policyService");

            string baseRoot = string.IsNullOrWhiteSpace(ruleRoot)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataProtector")
                : ruleRoot;
            string scanRoot = Path.Combine(baseRoot, "StaticScan");
            try
            {
                Directory.CreateDirectory(scanRoot);
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
            PolicyBridgeService.StaticScanRequestDto[] requests;
            try
            {
                requests = policyService.QueryStaticScanRequests();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " static scan request drain failed: " + ex.Message);
                return 0;
            }

            if (requests == null || requests.Length == 0)
            {
                return 0;
            }

            int processed = 0;
            foreach (PolicyBridgeService.StaticScanRequestDto request in requests)
            {
                if (processed >= MaxRequestsPerCycle)
                {
                    break;
                }

                try
                {
                    ScanResultFusion fusion = ScanOne(request);
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
                        Console.WriteLine(DateTime.Now.ToString("s") +
                            " static scan verdict=" + VerdictText(fusion.Verdict) +
                            " score=" + fusion.Score.ToString(CultureInfo.InvariantCulture) +
                            " path=" + (request.path ?? string.Empty));
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(DateTime.Now.ToString("s") + " static scan failed for request " +
                        request.requestId.ToString(CultureInfo.InvariantCulture) + ": " + ex.Message);
                }
            }

            return processed;
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
                // Allow-listed: contribute nothing.
                return null;
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
