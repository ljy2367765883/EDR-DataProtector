using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class AiStaticAnalysisService
    {
        private const string StateFileName = "StaticAnalysisState.json";
        private const string SampleDirectoryName = "Samples";
        private const string RunDirectoryName = "Runs";
        private const int MaxSampleBytes = 100 * 1024 * 1024;
        private const int MaxSampleRecords = 1000;
        private readonly object syncRoot = new object();
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly string rootDirectory;
        private readonly string statePath;
        private StaticAnalysisState state;

        public AiStaticAnalysisService(string dataProtectorRoot)
        {
            string baseRoot = string.IsNullOrWhiteSpace(dataProtectorRoot)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataProtector")
                : dataProtectorRoot;
            rootDirectory = Path.Combine(baseRoot, "AiStaticAnalysis");
            statePath = Path.Combine(rootDirectory, StateFileName);
            Directory.CreateDirectory(rootDirectory);
            state = Load();
            EnsureState();
        }

        public StaticAnalysisConfigurationDto QueryConfiguration()
        {
            lock (syncRoot)
            {
                EnsureState();
                return ToConfigurationDto(state.Configuration);
            }
        }

        public PolicyBridgeService.OperationResult SaveConfiguration(StaticAnalysisConfigurationRequest request, string actor)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis configuration body is required.");
            }

            lock (syncRoot)
            {
                EnsureState();
                StaticAnalysisConfiguration current = state.Configuration;
                current.enabled = request.enabled;
                current.aiEnabled = request.aiEnabled;
                current.ghidraRoot = NormalizePathText(request.ghidraRoot);
                current.javaPath = NormalizePathText(request.javaPath);
                current.baseUrl = NormalizeDeviceText(request.baseUrl);
                if (request.clearToken)
                {
                    current.token = string.Empty;
                }
                else if (!string.IsNullOrWhiteSpace(request.token))
                {
                    current.token = request.token.Trim();
                }

                current.model = string.IsNullOrWhiteSpace(request.model) ? "gpt-4.1-mini" : request.model.Trim();
                current.temperature = ClampDouble(request.temperature, 0, 2);
                current.maxFunctions = ClampInt(request.maxFunctions <= 0 ? 220 : request.maxFunctions, 10, 3000);
                current.maxDecompilerChars = ClampInt(request.maxDecompilerChars <= 0 ? 160000 : request.maxDecompilerChars, 20000, 2500000);
                current.timeoutSeconds = ClampInt(request.timeoutSeconds <= 0 ? 900 : request.timeoutSeconds, 60, 7200);
                current.actor = string.IsNullOrWhiteSpace(actor) ? NormalizeDeviceText(request.actor) : actor;
                current.updatedUtc = DateTime.UtcNow.ToString("o");
                Save();
            }

            return Success("AI static analysis configuration saved.");
        }

        public StaticAnalysisRuleDto[] QueryRules()
        {
            lock (syncRoot)
            {
                EnsureState();
                return state.Rules
                    .Select(CloneRule)
                    .OrderByDescending(item => item.enabled)
                    .ThenByDescending(item => item.weight)
                    .ThenBy(item => item.name, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public PolicyBridgeService.OperationResult SaveRules(StaticAnalysisRuleSaveRequest request, string actor)
        {
            if (request == null || request.rules == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis rule list is required.");
            }

            List<StaticAnalysisRuleDto> rules = new List<StaticAnalysisRuleDto>();
            foreach (StaticAnalysisRuleDto rule in request.rules)
            {
                StaticAnalysisRuleDto normalized = NormalizeRule(rule);
                if (string.IsNullOrWhiteSpace(normalized.ruleId))
                {
                    normalized.ruleId = "rule-" + Guid.NewGuid().ToString("N");
                }

                rules.Add(normalized);
            }

            lock (syncRoot)
            {
                state.Rules = rules;
                Save();
            }

            return Success("Static analysis scoring rules saved.");
        }

        public PolicyBridgeService.OperationResult ResetRules(string actor)
        {
            lock (syncRoot)
            {
                state.Rules = DefaultRules();
                Save();
            }

            return Success("Static analysis scoring rules reset.");
        }

        public StaticAnalysisSampleQueryResponse QuerySamples(StaticAnalysisSampleQuery query)
        {
            StaticAnalysisSampleQuery normalized = NormalizeQuery(query);
            lock (syncRoot)
            {
                EnsureState();
                IEnumerable<StaticAnalysisSampleState> rows = state.Samples;
                if (!string.IsNullOrWhiteSpace(normalized.status) &&
                    !string.Equals(normalized.status, "all", StringComparison.OrdinalIgnoreCase))
                {
                    rows = rows.Where(item => string.Equals(item.status, normalized.status, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(normalized.verdict) &&
                    !string.Equals(normalized.verdict, "all", StringComparison.OrdinalIgnoreCase))
                {
                    rows = rows.Where(item => string.Equals(item.verdict, normalized.verdict, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(normalized.search))
                {
                    rows = rows.Where(item => BuildSampleHaystack(item).IndexOf(normalized.search, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                StaticAnalysisSampleDto[] all = rows
                    .OrderByDescending(item => item.submittedUtc, StringComparer.OrdinalIgnoreCase)
                    .Select(ToSampleDto)
                    .ToArray();

                int skip = Math.Max(0, (normalized.page - 1) * normalized.pageSize);
                return new StaticAnalysisSampleQueryResponse
                {
                    page = normalized.page,
                    pageSize = normalized.pageSize,
                    total = all.Length,
                    queuedTotal = all.Count(item => string.Equals(item.status, "queued", StringComparison.OrdinalIgnoreCase)),
                    runningTotal = all.Count(item => string.Equals(item.status, "running", StringComparison.OrdinalIgnoreCase)),
                    completedTotal = all.Count(item => string.Equals(item.status, "completed", StringComparison.OrdinalIgnoreCase)),
                    failedTotal = all.Count(item => string.Equals(item.status, "failed", StringComparison.OrdinalIgnoreCase)),
                    maliciousTotal = all.Count(item => string.Equals(item.verdict, "malicious", StringComparison.OrdinalIgnoreCase)),
                    suspiciousTotal = all.Count(item => string.Equals(item.verdict, "suspicious", StringComparison.OrdinalIgnoreCase)),
                    items = all.Skip(skip).Take(normalized.pageSize).ToArray()
                };
            }
        }

        public StaticAnalysisSampleDto SubmitSample(StaticAnalysisSampleUploadRequest request, string actor)
        {
            StaticAnalysisSampleUploadRequest normalized = NormalizeUpload(request);
            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(normalized.contentBase64);
            }
            catch
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample must be valid base64 content.");
            }

            if (bytes.Length <= 0)
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample is empty.");
            }

            if (bytes.Length > MaxSampleBytes)
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample exceeds the 100 MB server limit.");
            }

            if (!IsExecutableImage(bytes))
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis currently accepts Windows PE executable samples only.");
            }

            string sha256 = string.IsNullOrWhiteSpace(normalized.sha256) ? ComputeSha256Hex(bytes) : normalized.sha256;
            lock (syncRoot)
            {
                EnsureState();
                StaticAnalysisSampleState existing = state.Samples.FirstOrDefault(item => string.Equals(item.sha256, sha256, StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                {
                    existing.lastSubmittedUtc = DateTime.UtcNow.ToString("o");
                    existing.submitCount++;
                    existing.source = string.IsNullOrWhiteSpace(normalized.source) ? existing.source : normalized.source;
                    existing.notes = string.IsNullOrWhiteSpace(normalized.notes) ? existing.notes : normalized.notes;
                    existing.stage = string.IsNullOrWhiteSpace(existing.stage) ? "queued" : existing.stage;
                    existing.stageText = string.IsNullOrWhiteSpace(existing.stageText) ? "等待分析" : existing.stageText;
                    existing.lastProgressUtc = DateTime.UtcNow.ToString("o");
                    existing.logText = AppendAnalysisLog(existing.logText, "样本再次提交，等待静态分析。");
                    Save();
                    return ToSampleDto(existing);
                }

                string sampleId = "st-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 12);
                string storageDirectory = GetSampleDirectory();
                Directory.CreateDirectory(storageDirectory);
                string storagePath = Path.Combine(storageDirectory, sampleId + "-" + SafeStorageFileName(normalized.fileName));
                File.WriteAllBytes(storagePath, bytes);

                StaticAnalysisSampleState sample = new StaticAnalysisSampleState
                {
                    sampleId = sampleId,
                    sha256 = sha256,
                    fileName = normalized.fileName,
                    sizeBytes = bytes.Length,
                    source = string.IsNullOrWhiteSpace(normalized.source) ? "web" : normalized.source,
                    submitter = string.IsNullOrWhiteSpace(actor) ? normalized.actor : actor,
                    notes = normalized.notes,
                    submittedUtc = DateTime.UtcNow.ToString("o"),
                    lastSubmittedUtc = DateTime.UtcNow.ToString("o"),
                    submitCount = 1,
                    status = "queued",
                    stage = "queued",
                    stageText = "等待分析",
                    progress = 0,
                    lastProgressUtc = DateTime.UtcNow.ToString("o"),
                    logText = AppendAnalysisLog(string.Empty, "样本已提交，等待静态分析。"),
                    storagePath = storagePath,
                    architecture = ReadArchitecture(storagePath),
                    signer = TryReadSignerSubject(storagePath),
                    signatureStatus = ReadSignatureStatus(storagePath),
                    productName = ReadVersionInfo(storagePath, "ProductName"),
                    companyName = ReadVersionInfo(storagePath, "CompanyName"),
                    fileDescription = ReadVersionInfo(storagePath, "FileDescription"),
                    fileVersion = ReadVersionInfo(storagePath, "FileVersion")
                };

                state.Samples.Add(sample);
                TrimSamples();
                Save();
                return ToSampleDto(sample);
            }
        }

        public StaticAnalysisSampleDto StartAnalysis(StaticAnalysisAnalyzeRequest request, string actor)
        {
            string sampleId = NormalizeDeviceText(request == null ? string.Empty : request.sampleId);
            if (string.IsNullOrWhiteSpace(sampleId))
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample id is required.");
            }

            StaticAnalysisConfiguration config;
            StaticAnalysisRuleDto[] rules;
            StaticAnalysisSampleState workerSample;
            lock (syncRoot)
            {
                EnsureState();
                StaticAnalysisSampleState sample = state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample == null)
                {
                    throw new PolicyBridgeService.BridgeException(1, "Static analysis sample was not found.");
                }

                if (string.Equals(sample.status, "running", StringComparison.OrdinalIgnoreCase))
                {
                    return ToSampleDto(sample);
                }

                if (!state.Configuration.enabled)
                {
                    throw new PolicyBridgeService.BridgeException(1, "AI static analysis is disabled.");
                }

                if (string.IsNullOrWhiteSpace(sample.storagePath) || !File.Exists(sample.storagePath))
                {
                    sample.status = "failed";
                    sample.stage = "failed";
                    sample.stageText = "样本文件缺失";
                    sample.progress = 100;
                    sample.lastProgressUtc = DateTime.UtcNow.ToString("o");
                    sample.error = "Static analysis sample file is missing from server storage.";
                    sample.logText = AppendAnalysisLog(sample.logText, sample.error);
                    sample.completedUtc = DateTime.UtcNow.ToString("o");
                    Save();
                    return ToSampleDto(sample);
                }

                sample.status = "running";
                sample.startedUtc = DateTime.UtcNow.ToString("o");
                sample.completedUtc = string.Empty;
                sample.error = string.Empty;
                sample.reportJson = string.Empty;
                sample.exitCode = 0;
                sample.score = 0;
                sample.verdict = "queued";
                sample.severity = "info";
                sample.runId = "sa-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 12);
                sample.stage = "queued";
                sample.stageText = "分析任务已创建";
                sample.progress = 2;
                sample.lastProgressUtc = DateTime.UtcNow.ToString("o");
                sample.logText = AppendAnalysisLog(string.Empty, "分析任务已创建。runId=" + sample.runId);
                config = CloneConfiguration(state.Configuration);
                if (request != null)
                {
                    config.maxFunctions = ClampInt(request.maxFunctions <= 0 ? config.maxFunctions : request.maxFunctions, 10, 3000);
                    config.maxDecompilerChars = ClampInt(request.maxDecompilerChars <= 0 ? config.maxDecompilerChars : request.maxDecompilerChars, 20000, 2500000);
                    config.aiEnabled = request.aiEnabled ?? config.aiEnabled;
                }

                rules = state.Rules.Select(CloneRule).ToArray();
                workerSample = CloneSample(sample);
                Save();
            }

            ThreadPool.QueueUserWorkItem(_ => RunAnalysisWorker(workerSample.sampleId, workerSample.runId, config, rules, actor));
            lock (syncRoot)
            {
                StaticAnalysisSampleState refreshed = state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                return ToSampleDto(refreshed);
            }
        }

        public PolicyBridgeService.OperationResult RemoveSample(StaticAnalysisSampleDeleteRequest request)
        {
            string sampleId = NormalizeDeviceText(request == null ? string.Empty : request.sampleId);
            if (string.IsNullOrWhiteSpace(sampleId) && (request == null || !request.all))
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample id is required.");
            }

            lock (syncRoot)
            {
                EnsureState();
                if (request != null && request.all)
                {
                    StaticAnalysisSampleState active = state.Samples.FirstOrDefault(item => IsActiveRunningSample(item));
                    if (active != null)
                    {
                        throw new PolicyBridgeService.BridgeException(1, "Static analysis history cannot be cleared while analysis is running. Active sample: " + active.fileName);
                    }

                    foreach (StaticAnalysisSampleState item in state.Samples.ToArray())
                    {
                        TryDeleteFile(item.storagePath);
                    }
                    DeleteDirectoryContents(GetRunDirectory());
                    DeleteDirectoryContents(GetSampleDirectory());
                    state.Samples.Clear();
                    Save();
                    return Success("Static analysis history cleared.");
                }

                StaticAnalysisSampleState sample = state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample != null)
                {
                    if (IsActiveRunningSample(sample))
                    {
                        throw new PolicyBridgeService.BridgeException(1, "Static analysis sample cannot be removed while analysis is running.");
                    }

                    TryDeleteFile(sample.storagePath);
                    if (!string.IsNullOrWhiteSpace(sample.runId))
                    {
                        TryDeleteDirectory(Path.Combine(GetRunDirectory(), sample.runId));
                    }
                    state.Samples.Remove(sample);
                    Save();
                }
            }

            return Success("Static analysis sample removed.");
        }

        public StaticAnalysisSourceInfo QuerySourceInfo()
        {
            return new StaticAnalysisSourceInfo
            {
                upstream = "https://github.com/NationalSecurityAgency/ghidra",
                upstreamCommit = "94164bd6e90eef1ae6b771a5692c0ca53ea92b81",
                license = "Apache-2.0",
                adapterScript = ResolveAnalyzerScriptPath(),
                extractedPaths = new[]
                {
                    "Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/AnalyzeHeadless.java",
                    "Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat",
                    "Ghidra/Features/Decompiler/ghidra_scripts/ShowCCallsScript.java",
                    "Ghidra/Features/Base/ghidra_scripts/PrintFunctionCallTreesScript.java",
                    "ghidra.program.model.listing.Function / FunctionManager / ReferenceManager / SymbolTable"
                }
            };
        }

        private void RunAnalysisWorker(string sampleId, string runId, StaticAnalysisConfiguration config, StaticAnalysisRuleDto[] rules, string actor)
        {
            StaticAnalysisExecutionResult result;
            try
            {
                StaticAnalysisSampleState sample;
                lock (syncRoot)
                {
                    sample = CloneSample(state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase)));
                }

                UpdateAnalysisProgress(sampleId, "preflight", "准备样本与运行目录", 8, "开始静态分析。样本=" + (sample == null ? sampleId : sample.fileName));
                result = ExecuteAnalysis(sample, runId, config, rules, (stage, stageText, progress, detail) =>
                    UpdateAnalysisProgress(sampleId, stage, stageText, progress, detail));
            }
            catch (Exception ex)
            {
                UpdateAnalysisProgress(sampleId, "failed", "分析异常", 100, ex.Message);
                result = new StaticAnalysisExecutionResult
                {
                    exitCode = 1,
                    error = ex.Message,
                    reportJson = serializer.Serialize(new
                    {
                        schema = "dataprotector.static.report.v1",
                        runId,
                        error = ex.ToString(),
                        generatedUtc = DateTime.UtcNow.ToString("o")
                    })
                };
            }

            lock (syncRoot)
            {
                StaticAnalysisSampleState sample = state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample == null)
                {
                    return;
                }

                sample.completedUtc = DateTime.UtcNow.ToString("o");
                sample.exitCode = result.exitCode;
                sample.error = result.error ?? string.Empty;
                sample.reportJson = Truncate(result.reportJson, 5 * 1024 * 1024);
                sample.status = result.exitCode == 0 ? "completed" : "failed";
                sample.stage = result.exitCode == 0 ? "completed" : "failed";
                sample.stageText = result.exitCode == 0 ? "分析完成" : "分析失败";
                sample.progress = 100;
                sample.lastProgressUtc = DateTime.UtcNow.ToString("o");
                sample.logText = AppendAnalysisLog(sample.logText, result.exitCode == 0 ? "静态分析完成。" : "静态分析失败：" + sample.error);
                sample.score = result.score;
                sample.verdict = string.IsNullOrWhiteSpace(result.verdict) ? (result.exitCode == 0 ? "observed" : "failed") : result.verdict;
                sample.severity = string.IsNullOrWhiteSpace(result.severity) ? (result.exitCode == 0 ? "info" : "warning") : result.severity;
                Save();
            }
        }

        private void UpdateAnalysisProgress(string sampleId, string stage, string stageText, int progress, string detail)
        {
            lock (syncRoot)
            {
                StaticAnalysisSampleState sample = state.Samples.FirstOrDefault(item => string.Equals(item.sampleId, sampleId, StringComparison.OrdinalIgnoreCase));
                if (sample == null)
                {
                    return;
                }

                sample.stage = NormalizeDeviceText(stage);
                sample.stageText = NormalizeDeviceText(stageText);
                sample.progress = ClampInt(progress, 0, 100);
                sample.lastProgressUtc = DateTime.UtcNow.ToString("o");
                if (!string.IsNullOrWhiteSpace(detail))
                {
                    sample.logText = AppendAnalysisLog(sample.logText, detail);
                }
                Save();
            }
        }

        private StaticAnalysisExecutionResult ExecuteAnalysis(
            StaticAnalysisSampleState sample,
            string runId,
            StaticAnalysisConfiguration config,
            StaticAnalysisRuleDto[] rules,
            Action<string, string, int, string> progress)
        {
            if (sample == null)
            {
                throw new InvalidOperationException("Static analysis sample context is missing.");
            }

            string runRoot = Path.Combine(GetRunDirectory(), runId);
            Directory.CreateDirectory(runRoot);
            string ghidraReportPath = Path.Combine(runRoot, "ghidra-report.json");
            string ghidraStdoutPath = Path.Combine(runRoot, "ghidra.stdout.log");
            string ghidraStderrPath = Path.Combine(runRoot, "ghidra.stderr.log");
            PackedSamplePreprocessResult preprocess = PreparePackedSampleForAnalysis(sample, runRoot, progress);
            string analysisInputPath = string.IsNullOrWhiteSpace(preprocess.analysisPath) ? sample.storagePath : preprocess.analysisPath;

            Dictionary<string, object> ghidraReport = null;
            string engineStatus = "not-run";
            string engineMessage = string.Empty;
            int exitCode = 0;

            string headless = ResolveAnalyzeHeadlessPath(config.ghidraRoot);
            if (string.IsNullOrWhiteSpace(headless))
            {
                exitCode = 2;
                engineStatus = "ghidra-not-configured";
                engineMessage = "Ghidra headless analyzer was not found. Configure ghidraRoot to a built Ghidra source checkout or distribution containing support\\analyzeHeadless.bat.";
                progress?.Invoke("failed", "Ghidra 未配置", 100, engineMessage);
                ghidraReport = BuildFallbackReport(sample, engineMessage);
            }
            else
            {
                progress?.Invoke("ghidra", "启动 Ghidra headless", 15, "Ghidra=" + headless);
                ProcessResult process = RunGhidraHeadless(headless, analysisInputPath, runRoot, ghidraReportPath, config, ghidraStdoutPath, ghidraStderrPath, progress);
                exitCode = process.exitCode;
                engineStatus = process.exitCode == 0 && File.Exists(ghidraReportPath) ? "completed" : "failed";
                engineMessage = process.exitCode == 0 ? "Ghidra source-derived analyzer completed." : Truncate(process.stderr + "\n" + process.stdout, 8000);
                progress?.Invoke(engineStatus == "completed" ? "ghidra" : "failed", engineStatus == "completed" ? "Ghidra 分析完成" : "Ghidra 分析失败", engineStatus == "completed" ? 70 : 100, engineMessage);
                GhidraDiagnostics diagnostics = BuildGhidraDiagnostics(process.stdout, process.stderr);
                if (diagnostics.errorCount > 0 || diagnostics.warningCount > 0)
                {
                    progress?.Invoke(
                        diagnostics.errorCount > 0 ? "ghidra-warning" : "ghidra",
                        diagnostics.errorCount > 0 ? "Ghidra 诊断发现解析错误" : "Ghidra 诊断发现警告",
                        72,
                        "errors=" + diagnostics.errorCount.ToString(CultureInfo.InvariantCulture) +
                        "; warnings=" + diagnostics.warningCount.ToString(CultureInfo.InvariantCulture) +
                        "; cliMetadataErrors=" + diagnostics.cliMetadataErrors.ToString(CultureInfo.InvariantCulture) +
                        "; first=" + Truncate(diagnostics.firstDiagnostic, 500));
                }
                if (File.Exists(ghidraReportPath))
                {
                    progress?.Invoke("ghidra", "读取 Ghidra JSON 报告", 74, ghidraReportPath);
                    ghidraReport = TryReadJsonDictionary(ghidraReportPath);
                }
                if (ghidraReport == null)
                {
                    ghidraReport = BuildFallbackReport(sample, engineMessage);
                }
                AttachGhidraDiagnostics(ghidraReport, diagnostics);
            }
            AttachPreprocessingReport(ghidraReport, preprocess);

            progress?.Invoke("scoring", "执行静态规则评分", 80, "规则数=" + (rules == null ? 0 : rules.Length).ToString(CultureInfo.InvariantCulture));
            StaticAnalysisRuleScore ruleScore = EvaluateRules(ghidraReport, rules);
            progress?.Invoke("ai", config.aiEnabled ? "调用 AI 流式判定" : "跳过 AI 判定", config.aiEnabled ? 88 : 94, config.aiEnabled ? NormalizeAiEndpoint(config.baseUrl) : "AI 未启用。");
            StaticAnalysisAiResult aiResult = RunAiAnalysis(config, sample, ghidraReport, ruleScore, progress);
            progress?.Invoke("report", "生成最终报告", 96, "规则分数=" + ruleScore.score.ToString(CultureInfo.InvariantCulture) + "，AI状态=" + aiResult.status + "，AI判定=" + aiResult.verdict);
            Dictionary<string, object> report = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "schema", "dataprotector.static.report.v1" },
                { "runId", runId },
                { "generatedUtc", DateTime.UtcNow.ToString("o") },
                { "sample", BuildSampleReport(sample) },
                { "engine", new Dictionary<string, object>
                    {
                        { "status", engineStatus },
                        { "message", engineMessage },
                        { "ghidraRoot", config.ghidraRoot ?? string.Empty },
                        { "adapterScript", ResolveAnalyzerScriptPath() },
                        { "stdoutPath", ghidraStdoutPath },
                        { "stderrPath", ghidraStderrPath },
                        { "reportPath", ghidraReportPath },
                        { "analysisInputPath", analysisInputPath },
                        { "usedUnpackedSample", preprocess.unpackSucceeded },
                        { "preprocessing", BuildPreprocessingReport(preprocess) },
                        { "diagnostics", GetValue(ghidraReport, "diagnostics") },
                        { "coverage", GetValue(ghidraReport, "coverage") }
                    }
                },
                { "ghidra", ghidraReport },
                { "ruleScore", ruleScore },
                { "ai", aiResult }
            };

            string finalVerdict = ResolveFinalVerdict(ruleScore, aiResult);
            string finalSeverity = ResolveFinalSeverity(ruleScore, aiResult);
            return new StaticAnalysisExecutionResult
            {
                exitCode = exitCode,
                error = exitCode == 0 ? string.Empty : engineMessage,
                reportJson = serializer.Serialize(report),
                score = ruleScore.score,
                verdict = finalVerdict,
                severity = finalSeverity
            };
        }

        private PackedSamplePreprocessResult PreparePackedSampleForAnalysis(
            StaticAnalysisSampleState sample,
            string runRoot,
            Action<string, string, int, string> progress)
        {
            PackedSamplePreprocessResult result = new PackedSamplePreprocessResult
            {
                enabled = true,
                originalPath = sample == null ? string.Empty : sample.storagePath,
                analysisPath = sample == null ? string.Empty : sample.storagePath,
                detected = false,
                packer = string.Empty,
                status = "not-packed",
                message = "No known packer signature was detected.",
                toolPath = string.Empty,
                unpackedPath = string.Empty,
                exitCode = 0,
                stdout = string.Empty,
                stderr = string.Empty
            };

            if (sample == null || string.IsNullOrWhiteSpace(sample.storagePath) || !File.Exists(sample.storagePath))
            {
                result.status = "skipped";
                result.message = "Sample file is missing before packer preprocessing.";
                return result;
            }

            string packer = DetectPackedSample(sample.storagePath);
            if (string.IsNullOrWhiteSpace(packer))
            {
                progress?.Invoke("preflight", "压缩壳预检完成", 10, "未检测到 UPX 等已知压缩壳。");
                return result;
            }

            result.detected = true;
            result.packer = packer;
            progress?.Invoke("preflight", "检测到压缩壳", 10, "packer=" + packer + "; sample=" + sample.fileName);

            if (!string.Equals(packer, "UPX", StringComparison.OrdinalIgnoreCase))
            {
                result.status = "unsupported";
                result.message = "Packed sample detected, but automatic unpacking is not implemented for " + packer + ".";
                progress?.Invoke("preflight", "压缩壳暂不支持自动解包", 11, result.message);
                return result;
            }

            string upxPath = ResolveUpxPath();
            result.toolPath = upxPath;
            if (string.IsNullOrWhiteSpace(upxPath))
            {
                result.status = "tool-missing";
                result.message = "UPX-packed sample detected, but upx.exe was not found. Put upx.exe under server\\static-analyzer\\tools or set DATAPROTECTOR_UPX_PATH.";
                progress?.Invoke("preflight", "UPX 解包工具缺失", 12, result.message);
                return result;
            }

            string unpackRoot = Path.Combine(runRoot, "unpacked");
            Directory.CreateDirectory(unpackRoot);
            string unpackedPath = Path.Combine(unpackRoot, Path.GetFileNameWithoutExtension(sample.storagePath) + ".unpacked.exe");
            TryDeleteFile(unpackedPath);
            File.Copy(sample.storagePath, unpackedPath, true);
            progress?.Invoke("preflight", "开始 UPX 自动解包", 12, "tool=" + upxPath + "; output=" + unpackedPath);

            ProcessResult unpack = RunUpxUnpack(upxPath, unpackedPath);
            result.exitCode = unpack.exitCode;
            result.stdout = Truncate(unpack.stdout, 6000);
            result.stderr = Truncate(unpack.stderr, 6000);
            result.unpackedPath = unpackedPath;
            if (unpack.exitCode == 0 && File.Exists(unpackedPath) && new FileInfo(unpackedPath).Length > 0)
            {
                result.status = "unpacked";
                result.unpackSucceeded = true;
                result.analysisPath = unpackedPath;
                result.message = "UPX unpack succeeded. Ghidra will analyze the unpacked file.";
                progress?.Invoke("preflight", "UPX 自动解包完成", 14, "output=" + unpackedPath + "; size=" + new FileInfo(unpackedPath).Length.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                result.status = "failed";
                result.unpackSucceeded = false;
                result.analysisPath = sample.storagePath;
                result.message = "UPX unpack failed; falling back to the original packed sample.";
                progress?.Invoke("preflight", "UPX 自动解包失败，回退原始样本", 14, "exitCode=" + unpack.exitCode.ToString(CultureInfo.InvariantCulture) + "; stderr=" + Truncate(unpack.stderr, 800));
                TryDeleteFile(unpackedPath);
            }

            return result;
        }

        private ProcessResult RunUpxUnpack(string upxPath, string targetPath)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = upxPath,
                Arguments = "-d -f " + Quote(targetPath),
                WorkingDirectory = Path.GetDirectoryName(targetPath),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                StringBuilder stdout = new StringBuilder();
                StringBuilder stderr = new StringBuilder();
                process.OutputDataReceived += (sender, args) => { if (args.Data != null) stdout.AppendLine(args.Data); };
                process.ErrorDataReceived += (sender, args) => { if (args.Data != null) stderr.AppendLine(args.Data); };
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                bool exited = process.WaitForExit(120000);
                if (!exited)
                {
                    TryKill(process);
                    return new ProcessResult { exitCode = 124, stdout = stdout.ToString(), stderr = stderr + "UPX unpack timed out." };
                }

                process.WaitForExit();
                return new ProcessResult { exitCode = process.ExitCode, stdout = stdout.ToString(), stderr = stderr.ToString() };
            }
        }

        private ProcessResult RunGhidraHeadless(
            string headlessPath,
            string samplePath,
            string runRoot,
            string ghidraReportPath,
            StaticAnalysisConfiguration config,
            string stdoutPath,
            string stderrPath,
            Action<string, string, int, string> progress)
        {
            string scriptPath = Path.GetDirectoryName(ResolveAnalyzerScriptPath());
            string projectDir = Path.Combine(runRoot, "project");
            Directory.CreateDirectory(projectDir);
            string projectName = "DataProtectorStatic-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string args = Quote(projectDir) + " " +
                          Quote(projectName) + " " +
                          "-import " + Quote(samplePath) + " " +
                          "-overwrite " +
                          "-scriptPath " + Quote(scriptPath) + " " +
                          "-postScript DataProtectorGhidraAnalyzer.java " +
                          Quote(ghidraReportPath) + " " +
                          config.maxFunctions.ToString(CultureInfo.InvariantCulture) + " " +
                          config.maxDecompilerChars.ToString(CultureInfo.InvariantCulture) + " " +
                          "-deleteProject";

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = headlessPath,
                Arguments = args,
                WorkingDirectory = Path.GetDirectoryName(headlessPath),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            ApplyJavaPath(startInfo, config.javaPath);
            startInfo.EnvironmentVariables["GHIDRA_HEADLESS_MAXMEM"] = "2G";
            startInfo.EnvironmentVariables["GHIDRA_HEADLESS_JAVA_OPTIONS"] = "-Dfile.encoding=UTF-8";

            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                StringBuilder stdout = new StringBuilder();
                StringBuilder stderr = new StringBuilder();
                DateTime lastProgressUtc = DateTime.MinValue;
                process.OutputDataReceived += (sender, eventArgs) =>
                {
                    if (eventArgs.Data == null)
                    {
                        return;
                    }

                    stdout.AppendLine(eventArgs.Data);
                    MaybeForwardGhidraLine(progress, "stdout", eventArgs.Data, ref lastProgressUtc);
                };
                process.ErrorDataReceived += (sender, eventArgs) =>
                {
                    if (eventArgs.Data == null)
                    {
                        return;
                    }

                    stderr.AppendLine(eventArgs.Data);
                    MaybeForwardGhidraLine(progress, "stderr", eventArgs.Data, ref lastProgressUtc);
                };
                process.Start();
                progress?.Invoke("ghidra", "Ghidra 进程已启动", 20, "PID=" + process.Id.ToString(CultureInfo.InvariantCulture));
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                bool exited = process.WaitForExit(Math.Max(60, config.timeoutSeconds) * 1000);
                if (!exited)
                {
                    TryKill(process);
                    string timeoutMessage = "Ghidra static analysis timed out after " + config.timeoutSeconds.ToString(CultureInfo.InvariantCulture) + " seconds.";
                    progress?.Invoke("failed", "Ghidra 分析超时", 100, timeoutMessage);
                    File.WriteAllText(stdoutPath, stdout.ToString(), Encoding.UTF8);
                    File.WriteAllText(stderrPath, stderr + timeoutMessage, Encoding.UTF8);
                    return new ProcessResult { exitCode = 124, stdout = stdout.ToString(), stderr = stderr + timeoutMessage };
                }

                process.WaitForExit();
                string outText = stdout.ToString();
                string errText = stderr.ToString();
                File.WriteAllText(stdoutPath, outText, Encoding.UTF8);
                File.WriteAllText(stderrPath, errText, Encoding.UTF8);
                progress?.Invoke(process.ExitCode == 0 ? "ghidra" : "failed", "Ghidra 进程已退出", process.ExitCode == 0 ? 68 : 100, "exitCode=" + process.ExitCode.ToString(CultureInfo.InvariantCulture));
                return new ProcessResult { exitCode = process.ExitCode, stdout = outText, stderr = errText };
            }
        }

        private GhidraDiagnostics BuildGhidraDiagnostics(string stdout, string stderr)
        {
            List<string> errors = new List<string>();
            List<string> warnings = new List<string>();
            int cliMetadataErrors = 0;
            foreach (string line in SplitLines((stdout ?? string.Empty) + "\n" + (stderr ?? string.Empty)))
            {
                string trimmed = line == null ? string.Empty : line.Trim();
                if (trimmed.Length == 0)
                {
                    continue;
                }

                bool isError = trimmed.IndexOf("ERROR", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isWarning = trimmed.IndexOf("WARN", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!isError && !isWarning)
                {
                    continue;
                }

                if (trimmed.IndexOf("CliStreamMetadata", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    trimmed.IndexOf("CliStreamBlob", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    trimmed.IndexOf(".NET", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    trimmed.IndexOf("_CorExeMain", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    cliMetadataErrors++;
                }

                if (isError)
                {
                    errors.Add(Truncate(trimmed, 700));
                }
                else
                {
                    warnings.Add(Truncate(trimmed, 700));
                }
            }

            return new GhidraDiagnostics
            {
                errorCount = errors.Count,
                warningCount = warnings.Count,
                cliMetadataErrors = cliMetadataErrors,
                firstDiagnostic = errors.FirstOrDefault() ?? warnings.FirstOrDefault() ?? string.Empty,
                errors = errors.Take(30).ToArray(),
                warnings = warnings.Take(30).ToArray()
            };
        }

        private void AttachGhidraDiagnostics(Dictionary<string, object> ghidraReport, GhidraDiagnostics diagnostics)
        {
            if (ghidraReport == null || diagnostics == null)
            {
                return;
            }

            List<Dictionary<string, object>> functions = EnumerateDictionaries(GetValue(ghidraReport, "functions")).ToList();
            List<Dictionary<string, object>> callGraph = EnumerateDictionaries(GetValue(ghidraReport, "callGraph")).ToList();
            bool managedEntryOnly = functions.Count <= 3 && functions.Any(item =>
                Convert.ToString(GetValue(item, "pseudocode"), CultureInfo.InvariantCulture).IndexOf("_CorExeMain", StringComparison.OrdinalIgnoreCase) >= 0);

            Dictionary<string, object> coverage = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "exportedFunctions", functions.Count },
                { "exportedCallEdges", callGraph.Count },
                { "managedEntryOnly", managedEntryOnly },
                { "lowCoverage", diagnostics.errorCount > 0 || managedEntryOnly || functions.Count <= 1 || callGraph.Count == 0 },
                { "quality", diagnostics.errorCount > 0 || managedEntryOnly ? "low" : callGraph.Count == 0 ? "limited" : "normal" },
                { "reason", diagnostics.cliMetadataErrors > 0 ? "Ghidra reported CLI/.NET metadata markup errors; native call graph coverage is incomplete." :
                    managedEntryOnly ? "Only the managed _CorExeMain entry stub was recovered; use managed-code/decompiler evidence before final verdict." :
                    callGraph.Count == 0 ? "No call graph edges were exported; static evidence is limited." : string.Empty }
            };

            Dictionary<string, object> diag = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "errorCount", diagnostics.errorCount },
                { "warningCount", diagnostics.warningCount },
                { "cliMetadataErrors", diagnostics.cliMetadataErrors },
                { "firstDiagnostic", diagnostics.firstDiagnostic },
                { "errors", diagnostics.errors ?? new string[0] },
                { "warnings", diagnostics.warnings ?? new string[0] }
            };

            ghidraReport["diagnostics"] = diag;
            ghidraReport["coverage"] = coverage;

            Dictionary<string, object> features = GetValue(ghidraReport, "features") as Dictionary<string, object>;
            if (features != null)
            {
                List<object> hits = EnumerateObjects(GetValue(features, "hits")).ToList();
                if (diagnostics.cliMetadataErrors > 0)
                {
                    hits.Add("ghidra-cli-metadata-errors:" + diagnostics.cliMetadataErrors.ToString(CultureInfo.InvariantCulture));
                }
                if (Convert.ToBoolean(coverage["lowCoverage"], CultureInfo.InvariantCulture))
                {
                    hits.Add("static-analysis-low-coverage:" + Convert.ToString(coverage["reason"], CultureInfo.InvariantCulture));
                }
                features["hits"] = hits.Take(900).ToArray();
            }
        }

        private void AttachPreprocessingReport(Dictionary<string, object> ghidraReport, PackedSamplePreprocessResult preprocess)
        {
            if (ghidraReport == null || preprocess == null)
            {
                return;
            }

            ghidraReport["preprocessing"] = BuildPreprocessingReport(preprocess);
            Dictionary<string, object> features = GetValue(ghidraReport, "features") as Dictionary<string, object>;
            if (features == null)
            {
                return;
            }

            List<object> hits = EnumerateObjects(GetValue(features, "hits")).ToList();
            if (preprocess.detected)
            {
                hits.Add("packed-sample:" + preprocess.packer + ":" + preprocess.status);
            }
            if (preprocess.unpackSucceeded)
            {
                hits.Add("packed-sample-unpacked:" + preprocess.packer);
            }
            features["hits"] = hits.Take(900).ToArray();
        }

        private Dictionary<string, object> BuildPreprocessingReport(PackedSamplePreprocessResult preprocess)
        {
            PackedSamplePreprocessResult item = preprocess ?? new PackedSamplePreprocessResult();
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "enabled", item.enabled },
                { "detected", item.detected },
                { "packer", item.packer ?? string.Empty },
                { "status", item.status ?? string.Empty },
                { "message", item.message ?? string.Empty },
                { "originalPath", item.originalPath ?? string.Empty },
                { "analysisPath", item.analysisPath ?? string.Empty },
                { "unpackedPath", item.unpackedPath ?? string.Empty },
                { "unpackSucceeded", item.unpackSucceeded },
                { "toolPath", item.toolPath ?? string.Empty },
                { "exitCode", item.exitCode },
                { "stdout", item.stdout ?? string.Empty },
                { "stderr", item.stderr ?? string.Empty }
            };
        }

        private StaticAnalysisRuleScore EvaluateRules(Dictionary<string, object> ghidraReport, StaticAnalysisRuleDto[] rules)
        {
            StaticAnalysisRuleScore score = new StaticAnalysisRuleScore
            {
                score = 0,
                verdict = "clean",
                severity = "info",
                hits = new List<StaticAnalysisRuleHit>().ToArray()
            };

            List<StaticAnalysisRuleHit> hits = new List<StaticAnalysisRuleHit>();
            foreach (StaticAnalysisRuleDto rule in rules ?? new StaticAnalysisRuleDto[0])
            {
                if (rule == null || !rule.enabled || string.IsNullOrWhiteSpace(rule.pattern))
                {
                    continue;
                }

                List<string> matched = MatchRule(ghidraReport, rule).Take(12).ToList();
                if (matched.Count == 0)
                {
                    continue;
                }

                hits.Add(new StaticAnalysisRuleHit
                {
                    ruleId = rule.ruleId,
                    name = rule.name,
                    target = rule.target,
                    pattern = rule.pattern,
                    weight = rule.weight,
                    severity = rule.severity,
                    verdict = rule.verdict,
                    description = rule.description,
                    evidence = matched.ToArray()
                });
            }

            int total = hits.Sum(item => Math.Max(0, item.weight));
            score.score = ClampInt(total, 0, 100);
            score.hits = hits.OrderByDescending(item => item.weight).ToArray();
            score.verdict = ResolveRuleVerdict(score.score, score.hits);
            score.severity = ResolveRuleSeverity(score.score, score.hits);
            return score;
        }

        private List<string> MatchRule(Dictionary<string, object> report, StaticAnalysisRuleDto rule)
        {
            List<string> candidates = CollectRuleCandidates(report, rule.target);
            List<string> matched = new List<string>();
            Regex regex = null;
            if (rule.regex)
            {
                try
                {
                    regex = new Regex(rule.pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                }
                catch
                {
                    return matched;
                }
            }

            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate))
                {
                    continue;
                }

                bool isMatch = regex != null
                    ? regex.IsMatch(candidate)
                    : candidate.IndexOf(rule.pattern, StringComparison.OrdinalIgnoreCase) >= 0;
                if (isMatch)
                {
                    matched.Add(Truncate(candidate, 500));
                }
            }

            return matched;
        }

        private List<string> CollectRuleCandidates(Dictionary<string, object> report, string target)
        {
            string normalized = NormalizeDeviceText(target).ToLowerInvariant();
            List<string> candidates = new List<string>();
            if (report == null)
            {
                return candidates;
            }

            if (normalized == "import" || normalized == "imports" || normalized == "any")
            {
                foreach (Dictionary<string, object> item in EnumerateDictionaries(GetValue(report, "imports")))
                {
                    candidates.Add(JoinCompact("!", Convert.ToString(GetValue(item, "namespace"), CultureInfo.InvariantCulture), Convert.ToString(GetValue(item, "name"), CultureInfo.InvariantCulture)));
                }
            }

            if (normalized == "string" || normalized == "strings" || normalized == "any")
            {
                foreach (Dictionary<string, object> item in EnumerateDictionaries(GetValue(report, "strings")))
                {
                    candidates.Add(Convert.ToString(GetValue(item, "value"), CultureInfo.InvariantCulture));
                }
            }

            if (normalized == "feature" || normalized == "features" || normalized == "any")
            {
                object features = GetValue(report, "features");
                Dictionary<string, object> featureMap = features as Dictionary<string, object>;
                if (featureMap != null)
                {
                    foreach (object value in EnumerateObjects(GetValue(featureMap, "hits")))
                    {
                        candidates.Add(Convert.ToString(value, CultureInfo.InvariantCulture));
                    }
                }
                foreach (Dictionary<string, object> function in EnumerateDictionaries(GetValue(report, "functions")))
                {
                    foreach (object value in EnumerateObjects(GetValue(function, "featureHits")))
                    {
                        candidates.Add(Convert.ToString(value, CultureInfo.InvariantCulture) + ":" + Convert.ToString(GetValue(function, "name"), CultureInfo.InvariantCulture));
                    }
                }
            }

            if (normalized == "function" || normalized == "pseudocode" || normalized == "any")
            {
                foreach (Dictionary<string, object> function in EnumerateDictionaries(GetValue(report, "functions")))
                {
                    string value = JoinCompact("\n",
                        Convert.ToString(GetValue(function, "name"), CultureInfo.InvariantCulture),
                        Convert.ToString(GetValue(function, "signature"), CultureInfo.InvariantCulture),
                        Convert.ToString(GetValue(function, "called"), CultureInfo.InvariantCulture),
                        Convert.ToString(GetValue(function, "instructions"), CultureInfo.InvariantCulture),
                        normalized == "function" ? string.Empty : Convert.ToString(GetValue(function, "pseudocode"), CultureInfo.InvariantCulture));
                    candidates.Add(value);
                }
            }

            return candidates;
        }

        private StaticAnalysisAiResult RunAiAnalysis(
            StaticAnalysisConfiguration config,
            StaticAnalysisSampleState sample,
            Dictionary<string, object> ghidraReport,
            StaticAnalysisRuleScore ruleScore,
            Action<string, string, int, string> progress)
        {
            StaticAnalysisAiResult result = new StaticAnalysisAiResult
            {
                enabled = config.aiEnabled,
                status = "skipped",
                model = config.model,
                verdict = string.Empty,
                summary = string.Empty,
                raw = string.Empty,
                error = string.Empty,
                endpoint = string.Empty,
                streamed = false,
                httpStatus = 0,
                elapsedMs = 0,
                requestBytes = 0,
                responseBytes = 0,
                contentChars = 0
            };

            if (!config.aiEnabled)
            {
                result.error = "AI analysis is disabled.";
                return result;
            }

            if (string.IsNullOrWhiteSpace(config.baseUrl) || string.IsNullOrWhiteSpace(config.token))
            {
                result.error = "AI baseUrl or token is not configured.";
                return result;
            }

            try
            {
                string endpoint = NormalizeAiEndpoint(config.baseUrl);
                string model = string.IsNullOrWhiteSpace(config.model) ? "gpt-4.1-mini" : config.model;
                string prompt = BuildAiPrompt(sample, ghidraReport, ruleScore);
                Dictionary<string, object> body = new Dictionary<string, object>
                {
                    { "model", model },
                    { "temperature", config.temperature },
                    { "stream", true },
                    { "messages", new object[]
                        {
                            new Dictionary<string, object>
                            {
                                { "role", "system" },
                                { "content", "你是资深恶意代码逆向分析员。像真人分析员一样阅读原始调用关系、反汇编和伪代码证据，快速还原执行路线并判断是否形成恶意闭环。不要机械套模板，不要因为单个导入表或单个字符串就定恶意。输出中文 Markdown，结论必须清楚，判定值只使用 malicious/suspicious/observed/clean 之一。" }
                            },
                            new Dictionary<string, object>
                            {
                                { "role", "user" },
                                { "content", prompt }
                            }
                        }
                    }
                };

                string requestJson = serializer.Serialize(body);
                byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
                result.endpoint = endpoint;
                result.requestBytes = requestBytes.Length;
                progress?.Invoke("ai", "AI 流式请求已发送", 88, "endpoint=" + endpoint + "; model=" + model + "; stream=true; requestBytes=" + requestBytes.Length.ToString(CultureInfo.InvariantCulture) + "; timeoutSeconds=" + Math.Max(30, config.timeoutSeconds).ToString(CultureInfo.InvariantCulture));

                DateTime lastDeltaLogUtc = DateTime.MinValue;
                int deltaCount = 0;
                int streamedChars = 0;
                AiHttpResult response = PostJsonStream(endpoint, config.token, requestJson, config.timeoutSeconds, delta =>
                {
                    if (string.IsNullOrEmpty(delta))
                    {
                        return;
                    }

                    deltaCount++;
                    streamedChars += delta.Length;
                    DateTime now = DateTime.UtcNow;
                    if ((now - lastDeltaLogUtc).TotalSeconds >= 5)
                    {
                        lastDeltaLogUtc = now;
                        progress?.Invoke("ai", "AI 正在流式输出", 90, "chunks=" + deltaCount.ToString(CultureInfo.InvariantCulture) + "; chars=" + streamedChars.ToString(CultureInfo.InvariantCulture));
                    }
                });

                result.raw = Truncate(response.body, 200000);
                result.summary = NormalizeAiMarkdownSummary(string.IsNullOrWhiteSpace(response.content) ? ExtractAiContent(response.body) : response.content);
                result.status = "completed";
                result.verdict = InferAiVerdict(result.summary);
                result.streamed = response.streamed;
                result.httpStatus = response.statusCode;
                result.elapsedMs = response.elapsedMs;
                result.responseBytes = response.responseBytes;
                result.contentChars = string.IsNullOrEmpty(result.summary) ? 0 : result.summary.Length;
                progress?.Invoke("ai", "AI 流式判定完成", 94, "http=" + response.statusCode.ToString(CultureInfo.InvariantCulture) + "; elapsedMs=" + response.elapsedMs.ToString(CultureInfo.InvariantCulture) + "; responseBytes=" + response.responseBytes.ToString(CultureInfo.InvariantCulture) + "; streamed=" + response.streamed.ToString(CultureInfo.InvariantCulture) + "; verdict=" + result.verdict + "; summaryChars=" + result.contentChars.ToString(CultureInfo.InvariantCulture));
            }
            catch (Exception ex)
            {
                result.status = "failed";
                result.error = ex.Message;
                progress?.Invoke("ai", "AI 流式判定失败", 94, ex.Message);
            }

            return result;
        }

        private string BuildAiPrompt(StaticAnalysisSampleState sample, Dictionary<string, object> ghidraReport, StaticAnalysisRuleScore ruleScore)
        {
            Dictionary<string, object> compact = new Dictionary<string, object>
            {
                { "sample", BuildSampleReport(sample) },
                { "operatorRoute", BuildAiAnalysisRoute(ghidraReport) },
                { "ghidraRawEvidence", BuildCompactGhidraSummary(ghidraReport) },
                { "ruleScoreForReferenceOnly", ruleScore }
            };

            return "下面是 Ghidra 导出的原生静态证据。请不要死板套规则，而是按逆向分析的快速路线判断：\n" +
                   "1. 先看入口、调用图、关键函数和伪代码，尝试还原样本主执行路线。\n" +
                   "2. 再看导入表和字符串是否能和调用路线闭环，例如网络接收命令、进程注入、凭据读取、持久化、释放执行、破坏恢复等。\n" +
                   "3. 如果 Ghidra diagnostics/coverage 显示解析错误、CLI/.NET 元数据失败、只有 _CorExeMain 或调用图为空，必须明确说明静态覆盖不足，不能把缺失证据当成恶意证据。\n" +
                   "4. ruleScore 只作为参考，不是最终结论；你可以推翻规则结论。\n" +
                   "5. 输出自然的中文 Markdown：开头给“判定：malicious/suspicious/observed/clean、置信度、原因一句话”，后面按你认为最有效的顺序讲证据链、缺口和下一步。可以用表格，但不要为了表格牺牲判断质量。\n\n" +
                   Truncate(serializer.Serialize(compact), 70000);
        }

        private Dictionary<string, object> BuildCompactGhidraSummary(Dictionary<string, object> report)
        {
            Dictionary<string, object> summary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (report == null)
            {
                return summary;
            }

            summary["program"] = GetValue(report, "program");
            summary["preprocessing"] = GetValue(report, "preprocessing");
            summary["diagnostics"] = GetValue(report, "diagnostics");
            summary["coverage"] = GetValue(report, "coverage");
            summary["features"] = GetValue(report, "features");
            summary["limits"] = GetValue(report, "limits");
            summary["imports"] = EnumerateDictionaries(GetValue(report, "imports")).Take(160).ToArray();
            summary["strings"] = EnumerateDictionaries(GetValue(report, "strings"))
                .OrderByDescending(item => Convert.ToString(GetValue(item, "suspicious"), CultureInfo.InvariantCulture).Equals("True", StringComparison.OrdinalIgnoreCase))
                .Take(180)
                .ToArray();
            summary["functions"] = EnumerateDictionaries(GetValue(report, "functions"))
                .OrderByDescending(item => ScoreFunctionForAi(item))
                .Take(120)
                .Select(item => new Dictionary<string, object>
                {
                    { "name", GetValue(item, "name") },
                    { "entry", GetValue(item, "entry") },
                    { "signature", GetValue(item, "signature") },
                    { "called", GetValue(item, "called") },
                    { "calling", GetValue(item, "calling") },
                    { "featureHits", GetValue(item, "featureHits") },
                    { "instructions", GetValue(item, "instructions") },
                    { "pseudocode", Truncate(Convert.ToString(GetValue(item, "pseudocode"), CultureInfo.InvariantCulture), 4500) }
                })
                .ToArray();
            summary["callGraph"] = EnumerateDictionaries(GetValue(report, "callGraph")).Take(500).ToArray();
            return summary;
        }

        private Dictionary<string, object> BuildAiAnalysisRoute(Dictionary<string, object> report)
        {
            Dictionary<string, object> route = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (report == null)
            {
                return route;
            }

            List<Dictionary<string, object>> functions = EnumerateDictionaries(GetValue(report, "functions")).ToList();
            List<Dictionary<string, object>> edges = EnumerateDictionaries(GetValue(report, "callGraph")).ToList();
            route["preprocessing"] = GetValue(report, "preprocessing");
            route["coverage"] = GetValue(report, "coverage");
            route["diagnostics"] = GetValue(report, "diagnostics");
            route["entryFunctions"] = functions
                .Where(item => Convert.ToString(GetValue(item, "name"), CultureInfo.InvariantCulture).IndexOf("entry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                               Convert.ToString(GetValue(item, "pseudocode"), CultureInfo.InvariantCulture).IndexOf("_CorExeMain", StringComparison.OrdinalIgnoreCase) >= 0)
                .Take(12)
                .ToArray();
            route["highSignalFunctions"] = functions
                .OrderByDescending(item => ScoreFunctionForAi(item))
                .Take(40)
                .ToArray();
            route["callEdges"] = edges.Take(500).ToArray();
            route["dangerousImports"] = EnumerateDictionaries(GetValue(report, "imports"))
                .Where(item => Convert.ToString(GetValue(item, "danger"), CultureInfo.InvariantCulture).Equals("True", StringComparison.OrdinalIgnoreCase))
                .Take(200)
                .ToArray();
            route["strings"] = EnumerateDictionaries(GetValue(report, "strings"))
                .OrderByDescending(item => Convert.ToString(GetValue(item, "suspicious"), CultureInfo.InvariantCulture).Equals("True", StringComparison.OrdinalIgnoreCase))
                .Take(180)
                .ToArray();
            return route;
        }

        private static int ScoreFunctionForAi(Dictionary<string, object> function)
        {
            if (function == null)
            {
                return 0;
            }

            int score = 0;
            score += EnumerateObjects(GetValue(function, "featureHits")).Count() * 100;
            score += EnumerateObjects(GetValue(function, "called")).Count() * 8;
            score += EnumerateObjects(GetValue(function, "calling")).Count() * 3;
            score += Math.Min(80, Convert.ToString(GetValue(function, "pseudocode"), CultureInfo.InvariantCulture).Length / 120);
            score += Math.Min(40, EnumerateObjects(GetValue(function, "instructions")).Count() * 2);
            return score;
        }

        private AiHttpResult PostJsonStream(string endpoint, string token, string body, int timeoutSeconds, Action<string> onDelta)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(endpoint);
            request.Method = "POST";
            request.ContentType = "application/json; charset=utf-8";
            request.Accept = "text/event-stream, application/json";
            request.Timeout = Math.Max(30, timeoutSeconds) * 1000;
            request.ReadWriteTimeout = request.Timeout;
            request.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            request.ContentLength = bytes.Length;

            Stopwatch stopwatch = Stopwatch.StartNew();
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(bytes, 0, bytes.Length);
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                {
                    string contentType = response.ContentType ?? string.Empty;
                    if (contentType.IndexOf("text/event-stream", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return ReadSseResponse(response, reader, stopwatch, onDelta);
                    }

                    string responseBody = reader.ReadToEnd();
                    stopwatch.Stop();
                    string content = ExtractAiContent(responseBody);
                    if (!string.IsNullOrEmpty(content))
                    {
                        onDelta?.Invoke(content);
                    }

                    return new AiHttpResult
                    {
                        statusCode = (int)response.StatusCode,
                        statusDescription = response.StatusDescription ?? string.Empty,
                        body = responseBody,
                        content = content,
                        elapsedMs = stopwatch.ElapsedMilliseconds,
                        responseBytes = Encoding.UTF8.GetByteCount(responseBody ?? string.Empty),
                        streamed = false
                    };
                }
            }
            catch (WebException ex)
            {
                stopwatch.Stop();
                string detail = string.Empty;
                int statusCode = 0;
                if (ex.Response != null)
                {
                    HttpWebResponse errorResponse = ex.Response as HttpWebResponse;
                    if (errorResponse != null)
                    {
                        statusCode = (int)errorResponse.StatusCode;
                    }
                    using (StreamReader reader = new StreamReader(ex.Response.GetResponseStream(), Encoding.UTF8))
                    {
                        detail = reader.ReadToEnd();
                    }
                }
                throw new InvalidOperationException("AI static analysis request failed: http=" + statusCode.ToString(CultureInfo.InvariantCulture) + "; elapsedMs=" + stopwatch.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture) + "; " + ex.Message + "; body=" + Truncate(detail, 1200));
            }
        }

        private AiHttpResult ReadSseResponse(HttpWebResponse response, StreamReader reader, Stopwatch stopwatch, Action<string> onDelta)
        {
            StringBuilder raw = new StringBuilder();
            StringBuilder content = new StringBuilder();
            StringBuilder eventData = new StringBuilder();
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                raw.AppendLine(line);
                if (line.Length == 0)
                {
                    FlushSseEvent(eventData, content, onDelta);
                    continue;
                }

                if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    eventData.AppendLine(line.Substring(5).TrimStart());
                }
            }

            FlushSseEvent(eventData, content, onDelta);
            stopwatch.Stop();
            string rawText = raw.ToString();
            return new AiHttpResult
            {
                statusCode = (int)response.StatusCode,
                statusDescription = response.StatusDescription ?? string.Empty,
                body = rawText,
                content = content.ToString(),
                elapsedMs = stopwatch.ElapsedMilliseconds,
                responseBytes = Encoding.UTF8.GetByteCount(rawText),
                streamed = true
            };
        }

        private void FlushSseEvent(StringBuilder eventData, StringBuilder content, Action<string> onDelta)
        {
            if (eventData == null || eventData.Length == 0)
            {
                return;
            }

            string data = eventData.ToString().Trim();
            eventData.Length = 0;
            if (string.IsNullOrWhiteSpace(data) || string.Equals(data, "[DONE]", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string delta = ExtractStreamingDelta(data);
            if (string.IsNullOrEmpty(delta))
            {
                return;
            }

            content.Append(delta);
            onDelta?.Invoke(delta);
        }

        private string ExtractStreamingDelta(string json)
        {
            try
            {
                Dictionary<string, object> root = serializer.DeserializeObject(json) as Dictionary<string, object>;
                object choicesRaw;
                if (root == null || !root.TryGetValue("choices", out choicesRaw))
                {
                    return string.Empty;
                }

                object[] choices = choicesRaw as object[];
                if (choices == null || choices.Length == 0)
                {
                    return string.Empty;
                }

                Dictionary<string, object> choice = choices[0] as Dictionary<string, object>;
                if (choice == null)
                {
                    return string.Empty;
                }

                Dictionary<string, object> delta = choice.ContainsKey("delta") ? choice["delta"] as Dictionary<string, object> : null;
                if (delta != null && delta.ContainsKey("content"))
                {
                    return Convert.ToString(delta["content"], CultureInfo.InvariantCulture);
                }

                Dictionary<string, object> message = choice.ContainsKey("message") ? choice["message"] as Dictionary<string, object> : null;
                if (message != null && message.ContainsKey("content"))
                {
                    return Convert.ToString(message["content"], CultureInfo.InvariantCulture);
                }

                if (choice.ContainsKey("text"))
                {
                    return Convert.ToString(choice["text"], CultureInfo.InvariantCulture);
                }
            }
            catch
            {
            }

            return string.Empty;
        }

        private string ExtractAiContent(string response)
        {
            try
            {
                Dictionary<string, object> root = serializer.DeserializeObject(response) as Dictionary<string, object>;
                object choicesRaw;
                if (root == null || !root.TryGetValue("choices", out choicesRaw))
                {
                    return Truncate(response, 4000);
                }

                object[] choices = choicesRaw as object[];
                if (choices == null || choices.Length == 0)
                {
                    return Truncate(response, 4000);
                }

                Dictionary<string, object> choice = choices[0] as Dictionary<string, object>;
                Dictionary<string, object> message = choice == null ? null : choice.ContainsKey("message") ? choice["message"] as Dictionary<string, object> : null;
                if (message != null && message.ContainsKey("content"))
                {
                    return Convert.ToString(message["content"], CultureInfo.InvariantCulture);
                }

                if (choice != null && choice.ContainsKey("text"))
                {
                    return Convert.ToString(choice["text"], CultureInfo.InvariantCulture);
                }
            }
            catch
            {
            }

            return Truncate(response, 4000);
        }

        private static string NormalizeAiMarkdownSummary(string text)
        {
            string value = (text ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                return "## 结论\n\n判定：observed\n\n置信度：0.00\n\n原因：AI 接口返回成功但没有正文，需要重新分析。";
            }

            return value;
        }

        private Dictionary<string, object> BuildFallbackReport(StaticAnalysisSampleState sample, string message)
        {
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "schema", "dataprotector.static.ghidra.v1" },
                { "source", "DataProtector fallback PE preflight" },
                { "error", message ?? string.Empty },
                { "program", BuildSampleReport(sample) },
                { "imports", new object[0] },
                { "strings", ExtractAsciiStrings(sample.storagePath).Take(300).Select(value => new Dictionary<string, object>
                    {
                        { "address", "" },
                        { "value", value },
                        { "suspicious", IsSuspiciousString(value) }
                    }).ToArray()
                },
                { "functions", new object[0] },
                { "callGraph", new object[0] },
                { "features", new Dictionary<string, object>
                    {
                        { "hits", new [] { "ghidra-engine-unavailable:" + (message ?? string.Empty) } },
                        { "histogram", new Dictionary<string, object> { { "ghidra-engine-unavailable", 1 } } }
                    }
                },
                { "limits", new Dictionary<string, object> { { "truncated", false } } }
            };
        }

        private Dictionary<string, object> BuildSampleReport(StaticAnalysisSampleState sample)
        {
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "sampleId", sample.sampleId ?? string.Empty },
                { "sha256", sample.sha256 ?? string.Empty },
                { "fileName", sample.fileName ?? string.Empty },
                { "sizeBytes", sample.sizeBytes },
                { "architecture", sample.architecture ?? string.Empty },
                { "signatureStatus", sample.signatureStatus ?? string.Empty },
                { "signer", sample.signer ?? string.Empty },
                { "productName", sample.productName ?? string.Empty },
                { "companyName", sample.companyName ?? string.Empty },
                { "fileDescription", sample.fileDescription ?? string.Empty },
                { "fileVersion", sample.fileVersion ?? string.Empty }
            };
        }

        private Dictionary<string, object> TryReadJsonDictionary(string path)
        {
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                return serializer.DeserializeObject(json) as Dictionary<string, object>;
            }
            catch
            {
                return null;
            }
        }

        private string ResolveAnalyzeHeadlessPath(string configuredRoot)
        {
            List<string> candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(configuredRoot))
            {
                candidates.Add(configuredRoot);
            }

            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            candidates.Add(Path.Combine(baseDirectory, "ghidra"));
            candidates.Add(Path.Combine(baseDirectory, "static-analyzer", "ghidra"));
            candidates.Add(Path.Combine(Directory.GetCurrentDirectory(), "external", "ghidra"));
            candidates.Add(Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "external", "ghidra")));

            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate))
                {
                    continue;
                }

                string full = Path.GetFullPath(candidate);
                string[] possible =
                {
                    Path.Combine(full, "support", "analyzeHeadless.bat"),
                    Path.Combine(full, "Ghidra", "RuntimeScripts", "Windows", "support", "analyzeHeadless.bat"),
                    Path.Combine(full, "ghidraRun.bat")
                };

                foreach (string path in possible)
                {
                    if (File.Exists(path) && Path.GetFileName(path).Equals("analyzeHeadless.bat", StringComparison.OrdinalIgnoreCase))
                    {
                        return path;
                    }
                }
            }

            return string.Empty;
        }

        private string ResolveAnalyzerScriptPath()
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates =
            {
                Path.Combine(baseDirectory, "static-analyzer", "ghidra_scripts", "DataProtectorGhidraAnalyzer.java"),
                Path.Combine(Directory.GetCurrentDirectory(), "DataProtectorStaticAnalyzer", "ghidra_scripts", "DataProtectorGhidraAnalyzer.java"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorStaticAnalyzer", "ghidra_scripts", "DataProtectorGhidraAnalyzer.java"))
            };

            foreach (string candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return candidates[0];
        }

        private StaticAnalysisState Load()
        {
            try
            {
                if (File.Exists(statePath))
                {
                    string json = File.ReadAllText(statePath, Encoding.UTF8);
                    StaticAnalysisState loaded = serializer.Deserialize<StaticAnalysisState>(json);
                    return loaded ?? new StaticAnalysisState();
                }
            }
            catch
            {
            }

            return new StaticAnalysisState();
        }

        private void Save()
        {
            EnsureState();
            Directory.CreateDirectory(rootDirectory);
            File.WriteAllText(statePath, serializer.Serialize(state), Encoding.UTF8);
        }

        private void EnsureState()
        {
            if (state == null)
            {
                state = new StaticAnalysisState();
            }
            if (state.Configuration == null)
            {
                state.Configuration = DefaultConfiguration();
            }
            if (state.Rules == null || state.Rules.Count == 0)
            {
                state.Rules = DefaultRules();
            }
            if (state.Samples == null)
            {
                state.Samples = new List<StaticAnalysisSampleState>();
            }
        }

        private StaticAnalysisConfiguration DefaultConfiguration()
        {
            return new StaticAnalysisConfiguration
            {
                enabled = true,
                aiEnabled = false,
                ghidraRoot = string.Empty,
                javaPath = string.Empty,
                baseUrl = string.Empty,
                token = string.Empty,
                model = "gpt-4.1-mini",
                temperature = 0.1,
                maxFunctions = 220,
                maxDecompilerChars = 160000,
                timeoutSeconds = 900,
                updatedUtc = DateTime.UtcNow.ToString("o")
            };
        }

        private List<StaticAnalysisRuleDto> DefaultRules()
        {
            return new List<StaticAnalysisRuleDto>
            {
                NewRule("inj-primitive", "进程注入原语组合", "feature", "process-injection-primitives", 25, "critical", "malicious", "反编译或调用图中出现远程内存/线程注入关键原语。"),
                NewRule("apc-thread", "APC 或线程上下文执行", "feature", "apc-or-thread-context-execution", 22, "critical", "malicious", "出现 APC、NtTestAlert、线程上下文劫持等执行链迹象。"),
                NewRule("cred-dump", "凭据或转储能力", "feature", "credential-or-dump-primitives", 24, "critical", "malicious", "出现 DPAPI、MiniDumpWriteDump、LSASS 或注册表凭据相关能力。"),
                NewRule("persistence", "持久化能力", "feature", "persistence-primitives", 18, "warning", "suspicious", "出现 Run/RunOnce、服务、计划任务等持久化原语。"),
                NewRule("c2-network", "网络控制通道能力", "feature", "network-command-control-primitives", 14, "warning", "suspicious", "出现 WinHTTP/WinINet/socket 等网络通信能力。"),
                NewRule("impact", "破坏或恢复抑制能力", "feature", "destructive-or-recovery-impact", 20, "critical", "malicious", "出现删除、影子副本或恢复抑制相关能力。"),
                NewRule("dangerous-import", "危险导入表", "import", "WriteProcessMemory", 12, "warning", "suspicious", "导入表出现高风险 API。"),
                NewRule("lolbin-string", "脚本与系统工具链字符串", "string", "powershell", 8, "warning", "suspicious", "样本字符串包含常见脚本执行工具。"),
                NewRule("etw-amsi-bypass", "ETW/AMSI 规避语义", "any", "amsi", 16, "warning", "suspicious", "出现 AMSI/ETW 规避相关语义。")
            };
        }

        private StaticAnalysisRuleDto NewRule(string id, string name, string target, string pattern, int weight, string severity, string verdict, string description)
        {
            return new StaticAnalysisRuleDto
            {
                ruleId = id,
                name = name,
                enabled = true,
                target = target,
                pattern = pattern,
                regex = false,
                weight = weight,
                severity = severity,
                verdict = verdict,
                description = description
            };
        }

        private StaticAnalysisConfiguration CloneConfiguration(StaticAnalysisConfiguration source)
        {
            if (source == null)
            {
                return DefaultConfiguration();
            }

            return new StaticAnalysisConfiguration
            {
                enabled = source.enabled,
                aiEnabled = source.aiEnabled,
                ghidraRoot = source.ghidraRoot,
                javaPath = source.javaPath,
                baseUrl = source.baseUrl,
                token = source.token,
                model = source.model,
                temperature = source.temperature,
                maxFunctions = source.maxFunctions,
                maxDecompilerChars = source.maxDecompilerChars,
                timeoutSeconds = source.timeoutSeconds,
                actor = source.actor,
                updatedUtc = source.updatedUtc
            };
        }

        private StaticAnalysisConfigurationDto ToConfigurationDto(StaticAnalysisConfiguration source)
        {
            StaticAnalysisConfiguration clone = CloneConfiguration(source);
            return new StaticAnalysisConfigurationDto
            {
                enabled = clone.enabled,
                aiEnabled = clone.aiEnabled,
                ghidraRoot = clone.ghidraRoot,
                javaPath = clone.javaPath,
                baseUrl = clone.baseUrl,
                maskedToken = MaskSecret(clone.token),
                tokenConfigured = !string.IsNullOrWhiteSpace(clone.token),
                model = clone.model,
                temperature = clone.temperature,
                maxFunctions = clone.maxFunctions,
                maxDecompilerChars = clone.maxDecompilerChars,
                timeoutSeconds = clone.timeoutSeconds,
                analyzerScript = ResolveAnalyzerScriptPath(),
                ghidraDetected = !string.IsNullOrWhiteSpace(ResolveAnalyzeHeadlessPath(clone.ghidraRoot)),
                updatedUtc = clone.updatedUtc
            };
        }

        private StaticAnalysisRuleDto CloneRule(StaticAnalysisRuleDto rule)
        {
            if (rule == null)
            {
                return new StaticAnalysisRuleDto();
            }

            return new StaticAnalysisRuleDto
            {
                ruleId = rule.ruleId,
                name = rule.name,
                enabled = rule.enabled,
                target = rule.target,
                pattern = rule.pattern,
                regex = rule.regex,
                weight = rule.weight,
                severity = rule.severity,
                verdict = rule.verdict,
                description = rule.description
            };
        }

        private StaticAnalysisRuleDto NormalizeRule(StaticAnalysisRuleDto rule)
        {
            StaticAnalysisRuleDto source = rule ?? new StaticAnalysisRuleDto();
            return new StaticAnalysisRuleDto
            {
                ruleId = NormalizeDeviceText(source.ruleId),
                name = string.IsNullOrWhiteSpace(source.name) ? "未命名静态规则" : NormalizeDeviceText(source.name),
                enabled = source.enabled,
                target = NormalizeRuleTarget(source.target),
                pattern = source.pattern == null ? string.Empty : source.pattern.Trim(),
                regex = source.regex,
                weight = ClampInt(source.weight, 0, 100),
                severity = NormalizeSeverity(source.severity),
                verdict = NormalizeVerdict(source.verdict),
                description = NormalizeDeviceText(source.description)
            };
        }

        private StaticAnalysisSampleState CloneSample(StaticAnalysisSampleState source)
        {
            if (source == null)
            {
                return null;
            }

            return new StaticAnalysisSampleState
            {
                sampleId = source.sampleId,
                sha256 = source.sha256,
                fileName = source.fileName,
                storagePath = source.storagePath,
                sizeBytes = source.sizeBytes,
                source = source.source,
                submitter = source.submitter,
                notes = source.notes,
                submittedUtc = source.submittedUtc,
                lastSubmittedUtc = source.lastSubmittedUtc,
                submitCount = source.submitCount,
                status = source.status,
                startedUtc = source.startedUtc,
                completedUtc = source.completedUtc,
                runId = source.runId,
                exitCode = source.exitCode,
                error = source.error,
                reportJson = source.reportJson,
                stage = source.stage,
                stageText = source.stageText,
                progress = source.progress,
                lastProgressUtc = source.lastProgressUtc,
                logText = source.logText,
                score = source.score,
                verdict = source.verdict,
                severity = source.severity,
                architecture = source.architecture,
                signer = source.signer,
                signatureStatus = source.signatureStatus,
                productName = source.productName,
                companyName = source.companyName,
                fileDescription = source.fileDescription,
                fileVersion = source.fileVersion
            };
        }

        private StaticAnalysisSampleDto ToSampleDto(StaticAnalysisSampleState source)
        {
            if (source == null)
            {
                return new StaticAnalysisSampleDto();
            }

            return new StaticAnalysisSampleDto
            {
                sampleId = source.sampleId,
                sha256 = source.sha256,
                fileName = source.fileName,
                sizeBytes = source.sizeBytes,
                source = source.source,
                submitter = source.submitter,
                notes = source.notes,
                submittedUtc = source.submittedUtc,
                lastSubmittedUtc = source.lastSubmittedUtc,
                submitCount = source.submitCount,
                status = source.status,
                startedUtc = source.startedUtc,
                completedUtc = source.completedUtc,
                runId = source.runId,
                exitCode = source.exitCode,
                error = source.error,
                reportJson = source.reportJson,
                stage = source.stage,
                stageText = source.stageText,
                progress = source.progress,
                lastProgressUtc = source.lastProgressUtc,
                logText = source.logText,
                score = source.score,
                verdict = source.verdict,
                severity = source.severity,
                architecture = source.architecture,
                signer = source.signer,
                signatureStatus = source.signatureStatus,
                productName = source.productName,
                companyName = source.companyName,
                fileDescription = source.fileDescription,
                fileVersion = source.fileVersion
            };
        }

        private StaticAnalysisSampleQuery NormalizeQuery(StaticAnalysisSampleQuery query)
        {
            StaticAnalysisSampleQuery source = query ?? new StaticAnalysisSampleQuery();
            return new StaticAnalysisSampleQuery
            {
                page = ClampInt(source.page <= 0 ? 1 : source.page, 1, 1000000),
                pageSize = ClampInt(source.pageSize <= 0 ? 30 : source.pageSize, 1, 100),
                status = NormalizeDeviceText(source.status),
                verdict = NormalizeDeviceText(source.verdict),
                search = NormalizeDeviceText(source.search)
            };
        }

        private StaticAnalysisSampleUploadRequest NormalizeUpload(StaticAnalysisSampleUploadRequest request)
        {
            if (request == null)
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample upload body is required.");
            }
            if (string.IsNullOrWhiteSpace(request.contentBase64))
            {
                throw new PolicyBridgeService.BridgeException(1, "Static analysis sample payload is required.");
            }

            return new StaticAnalysisSampleUploadRequest
            {
                fileName = NormalizeFileName(request.fileName),
                contentBase64 = request.contentBase64.Trim(),
                sha256 = NormalizeSha256(request.sha256),
                source = string.IsNullOrWhiteSpace(request.source) ? "web" : NormalizeDeviceText(request.source),
                notes = NormalizeDeviceText(request.notes),
                actor = NormalizeDeviceText(request.actor)
            };
        }

        private void TrimSamples()
        {
            if (state.Samples.Count <= MaxSampleRecords)
            {
                return;
            }

            List<StaticAnalysisSampleState> keep = state.Samples
                .OrderByDescending(item => item.submittedUtc, StringComparer.OrdinalIgnoreCase)
                .Take(MaxSampleRecords)
                .ToList();

            foreach (StaticAnalysisSampleState item in state.Samples)
            {
                if (!keep.Contains(item))
                {
                    TryDeleteFile(item.storagePath);
                }
            }

            state.Samples = keep;
        }

        private string GetSampleDirectory()
        {
            return Path.Combine(rootDirectory, SampleDirectoryName);
        }

        private string GetRunDirectory()
        {
            return Path.Combine(rootDirectory, RunDirectoryName);
        }

        private string BuildSampleHaystack(StaticAnalysisSampleState item)
        {
            return JoinCompact("\n",
                item.fileName,
                item.sha256,
                item.source,
                item.submitter,
                item.notes,
                item.status,
                item.verdict,
                item.severity,
                item.signer,
                item.signatureStatus,
                item.productName,
                item.companyName,
                item.fileDescription);
        }

        private static string ResolveFinalVerdict(StaticAnalysisRuleScore ruleScore, StaticAnalysisAiResult aiResult)
        {
            if (aiResult != null && !string.IsNullOrWhiteSpace(aiResult.verdict) &&
                !string.Equals(aiResult.verdict, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                if (ruleScore == null || ruleScore.score < 50)
                {
                    return aiResult.verdict;
                }

                if ((string.Equals(aiResult.verdict, "clean", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(aiResult.verdict, "observed", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(aiResult.verdict, "suspicious", StringComparison.OrdinalIgnoreCase)) &&
                    AiMentionsInsufficientMaliciousEvidence(aiResult.summary))
                {
                    return aiResult.verdict;
                }

                return MoreSevereVerdict(ruleScore.verdict, aiResult.verdict);
            }

            return ruleScore == null ? "observed" : ruleScore.verdict;
        }

        private static string ResolveFinalSeverity(StaticAnalysisRuleScore ruleScore, StaticAnalysisAiResult aiResult)
        {
            if (ruleScore == null)
            {
                return "info";
            }

            return ruleScore.severity;
        }

        private static string MoreSevereVerdict(string a, string b)
        {
            string[] order = { "clean", "observed", "suspicious", "malicious" };
            int ia = Array.FindIndex(order, item => string.Equals(item, a, StringComparison.OrdinalIgnoreCase));
            int ib = Array.FindIndex(order, item => string.Equals(item, b, StringComparison.OrdinalIgnoreCase));
            return order[Math.Max(Math.Max(0, ia), Math.Max(0, ib))];
        }

        private static string ResolveRuleVerdict(int score, StaticAnalysisRuleHit[] hits)
        {
            if (score >= 80 || hits.Any(item => string.Equals(item.verdict, "malicious", StringComparison.OrdinalIgnoreCase) && item.weight >= 24))
            {
                return "malicious";
            }
            if (score >= 45 || hits.Any(item => string.Equals(item.verdict, "suspicious", StringComparison.OrdinalIgnoreCase)))
            {
                return "suspicious";
            }
            if (score > 0)
            {
                return "observed";
            }
            return "clean";
        }

        private static string ResolveRuleSeverity(int score, StaticAnalysisRuleHit[] hits)
        {
            if (score >= 80 || hits.Any(item => string.Equals(item.severity, "critical", StringComparison.OrdinalIgnoreCase)))
            {
                return "critical";
            }
            if (score >= 45 || hits.Any(item => string.Equals(item.severity, "warning", StringComparison.OrdinalIgnoreCase)))
            {
                return "warning";
            }
            return "info";
        }

        private static string InferAiVerdict(string text)
        {
            string raw = text ?? string.Empty;
            string value = raw.ToLowerInvariant();
            Match tableVerdict = Regex.Match(raw, @"\|\s*判定\s*\|\s*([^|\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (tableVerdict.Success)
            {
                string cell = tableVerdict.Groups[1].Value.Trim().ToLowerInvariant();
                string normalized = NormalizeAiVerdictToken(cell);
                if (!string.Equals(normalized, "unknown", StringComparison.OrdinalIgnoreCase))
                {
                    return normalized;
                }
            }

            Match explicitVerdict = Regex.Match(raw, @"(?:判定|安全结论|最终裁定|verdict|conclusion)\s*[:：]\s*([^\r\n|，,。;；]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (explicitVerdict.Success)
            {
                string normalized = NormalizeAiVerdictToken(explicitVerdict.Groups[1].Value);
                if (!string.Equals(normalized, "unknown", StringComparison.OrdinalIgnoreCase))
                {
                    return normalized;
                }
            }

            if (AiMentionsInsufficientMaliciousEvidence(raw) &&
                (value.Contains("可疑") || value.Contains("suspicious") || value.Contains("待确认") || value.Contains("复核")))
            {
                return "suspicious";
            }

            if (HasPositiveVerdict(value, "malicious", "恶意")) return "malicious";
            if (value.Contains("可疑") || value.Contains("suspicious")) return "suspicious";
            if (value.Contains("观察") || value.Contains("observed") || value.Contains("待确认") || value.Contains("复核")) return "observed";
            if (value.Contains("正常") || value.Contains("干净") || value.Contains("良性") || value.Contains("clean") || value.Contains("benign")) return "clean";
            return "unknown";
        }

        private static string NormalizeAiVerdictToken(string token)
        {
            string value = (token ?? string.Empty).Trim().ToLowerInvariant();
            if (value.Contains("malicious") || value.Contains("恶意")) return AiMentionsInsufficientMaliciousEvidence(value) ? "suspicious" : "malicious";
            if (value.Contains("suspicious") || value.Contains("可疑")) return "suspicious";
            if (value.Contains("observed") || value.Contains("观察") || value.Contains("待确认") || value.Contains("复核")) return "observed";
            if (value.Contains("clean") || value.Contains("benign") || value.Contains("正常") || value.Contains("干净") || value.Contains("良性")) return "clean";
            return "unknown";
        }

        private static bool HasPositiveVerdict(string value, string english, string chinese)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            if (AiMentionsInsufficientMaliciousEvidence(value))
            {
                return false;
            }

            return value.Contains("判定：" + chinese) ||
                   value.Contains("判定:" + chinese) ||
                   value.Contains("安全结论：" + chinese) ||
                   value.Contains("安全结论:" + chinese) ||
                   value.Contains("最终裁定：" + chinese) ||
                   value.Contains("最终裁定:" + chinese) ||
                   value.Contains("\"verdict\":\"" + english + "\"") ||
                   value.Contains("| " + english + " ") ||
                   value.Contains("| " + chinese + " ");
        }

        private static bool AiMentionsInsufficientMaliciousEvidence(string text)
        {
            string value = (text ?? string.Empty).ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return Regex.IsMatch(value, "(证据不足|不足以支持|不能|不建议|暂不|无法|未形成|不能闭环|没有看到|缺失|不支持|下调|误报).{0,40}(恶意|malicious)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
                   Regex.IsMatch(value, "(恶意|malicious).{0,40}(证据不足|不足以支持|不能|不建议|暂不|无法|未形成|不能闭环|没有看到|缺失|不支持|下调|误报)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
                   value.Contains("非恶意") ||
                   value.Contains("不是恶意") ||
                   value.Contains("not malicious");
        }

        private static string NormalizeAiEndpoint(string baseUrl)
        {
            string value = (baseUrl ?? string.Empty).Trim().TrimEnd('/');
            if (value.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }
            if (value.EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
            {
                return value + "/chat/completions";
            }
            return value + "/v1/chat/completions";
        }

        private static void ApplyJavaPath(ProcessStartInfo startInfo, string javaPath)
        {
            if (string.IsNullOrWhiteSpace(javaPath))
            {
                return;
            }

            string path = javaPath.Trim();
            if (File.Exists(path))
            {
                string bin = Path.GetDirectoryName(path);
                string home = Directory.GetParent(bin).FullName;
                startInfo.EnvironmentVariables["JAVA_HOME"] = home;
                startInfo.EnvironmentVariables["PATH"] = bin + ";" + startInfo.EnvironmentVariables["PATH"];
            }
            else if (Directory.Exists(path))
            {
                string bin = Path.Combine(path, "bin");
                startInfo.EnvironmentVariables["JAVA_HOME"] = path;
                if (Directory.Exists(bin))
                {
                    startInfo.EnvironmentVariables["PATH"] = bin + ";" + startInfo.EnvironmentVariables["PATH"];
                }
            }
        }

        private static void MaybeForwardGhidraLine(Action<string, string, int, string> progress, string stream, string line, ref DateTime lastProgressUtc)
        {
            if (progress == null || string.IsNullOrWhiteSpace(line))
            {
                return;
            }

            DateTime now = DateTime.UtcNow;
            string trimmed = Truncate(line.Trim(), 700);
            bool isError = stream == "stderr" || trimmed.IndexOf("ERROR", StringComparison.OrdinalIgnoreCase) >= 0;
            bool isWarning = trimmed.IndexOf("WARN", StringComparison.OrdinalIgnoreCase) >= 0;
            if (isError ||
                isWarning ||
                trimmed.IndexOf("DataProtector", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.IndexOf("Analyzing", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.IndexOf("Importing", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.IndexOf("Decompiler", StringComparison.OrdinalIgnoreCase) >= 0 ||
                (now - lastProgressUtc).TotalSeconds >= 3)
            {
                lastProgressUtc = now;
                progress(isError ? "ghidra-warning" : "ghidra", isError ? "Ghidra 输出 ERROR" : isWarning ? "Ghidra 输出 WARN" : "Ghidra 正在分析", 45, "[" + stream + "] " + trimmed);
            }
        }

        private static bool IsActiveRunningSample(StaticAnalysisSampleState sample)
        {
            if (sample == null || !string.Equals(sample.status, "running", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            DateTime lastProgress;
            if (DateTime.TryParse(sample.lastProgressUtc, null, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out lastProgress))
            {
                return (DateTime.UtcNow - lastProgress).TotalMinutes < 30;
            }

            DateTime started;
            if (DateTime.TryParse(sample.startedUtc, null, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out started))
            {
                return (DateTime.UtcNow - started).TotalMinutes < 30;
            }

            return true;
        }

        private static IEnumerable<Dictionary<string, object>> EnumerateDictionaries(object value)
        {
            foreach (object item in EnumerateObjects(value))
            {
                Dictionary<string, object> dictionary = item as Dictionary<string, object>;
                if (dictionary != null)
                {
                    yield return dictionary;
                }
            }
        }

        private static IEnumerable<object> EnumerateObjects(object value)
        {
            object[] array = value as object[];
            if (array != null)
            {
                foreach (object item in array)
                {
                    yield return item;
                }
                yield break;
            }

            IEnumerable<object> enumerable = value as IEnumerable<object>;
            if (enumerable != null && !(value is string))
            {
                foreach (object item in enumerable)
                {
                    yield return item;
                }
            }
        }

        private static IEnumerable<string> SplitLines(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                yield break;
            }

            using (StringReader reader = new StringReader(value))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    yield return line;
                }
            }
        }

        private static object GetValue(Dictionary<string, object> dictionary, string key)
        {
            if (dictionary == null)
            {
                return null;
            }

            object value;
            return dictionary.TryGetValue(key, out value) ? value : null;
        }

        private static IEnumerable<string> ExtractAsciiStrings(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                yield break;
            }

            byte[] bytes = File.ReadAllBytes(path);
            StringBuilder current = new StringBuilder();
            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126)
                {
                    current.Append((char)b);
                    if (current.Length > 800)
                    {
                        yield return current.ToString();
                        current.Length = 0;
                    }
                }
                else
                {
                    if (current.Length >= 5)
                    {
                        yield return current.ToString();
                    }
                    current.Length = 0;
                }
            }
        }

        private static bool IsSuspiciousString(string value)
        {
            string text = (value ?? string.Empty).ToLowerInvariant();
            string[] markers = { "powershell", "cmd.exe", "rundll32", "regsvr32", "lsass", "virtualalloc", "writeprocessmemory", "createremotethread", "http://", "https://", "currentversion\\run", "amsi", "etw" };
            return markers.Any(marker => text.Contains(marker));
        }

        private static string DetectPackedSample(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return string.Empty;
            }

            try
            {
                byte[] bytes = File.ReadAllBytes(path);
                string ascii = Encoding.ASCII.GetString(bytes.Take(Math.Min(bytes.Length, 2 * 1024 * 1024)).ToArray()).ToUpperInvariant();
                if (ascii.Contains("UPX0") || ascii.Contains("UPX1") || ascii.Contains("UPX2") || ascii.Contains("UPX!"))
                {
                    return "UPX";
                }
            }
            catch
            {
            }

            return string.Empty;
        }

        private static string ResolveUpxPath()
        {
            string configured = Environment.GetEnvironmentVariable("DATAPROTECTOR_UPX_PATH");
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            List<string> candidates = new List<string>
            {
                configured,
                Path.Combine(baseDirectory, "static-analyzer", "tools", "upx.exe"),
                Path.Combine(baseDirectory, "tools", "upx.exe"),
                Path.Combine(Directory.GetCurrentDirectory(), "DataProtectorStaticAnalyzer", "tools", "upx.exe"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorStaticAnalyzer", "tools", "upx.exe"))
            };

            foreach (string candidate in candidates)
            {
                if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }

            string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string directory in path.Split(new[] { Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(directory.Trim(), "upx.exe");
                    if (File.Exists(candidate))
                    {
                        return Path.GetFullPath(candidate);
                    }
                }
                catch
                {
                }
            }

            return string.Empty;
        }

        private static bool IsExecutableImage(byte[] bytes)
        {
            return bytes != null && bytes.Length > 0x40 && bytes[0] == 'M' && bytes[1] == 'Z';
        }

        private static string ReadArchitecture(string path)
        {
            try
            {
                using (FileStream stream = File.OpenRead(path))
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    if (reader.ReadUInt16() != 0x5A4D)
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

        private static string ComputeSha256Hex(byte[] bytes)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
            }
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

        private static string NormalizeRuleTarget(string value)
        {
            string normalized = NormalizeDeviceText(value).ToLowerInvariant();
            switch (normalized)
            {
                case "import":
                case "string":
                case "function":
                case "pseudocode":
                case "feature":
                case "any":
                    return normalized;
                default:
                    return "any";
            }
        }

        private static string NormalizeSeverity(string value)
        {
            string normalized = NormalizeDeviceText(value).ToLowerInvariant();
            if (normalized == "critical" || normalized == "warning" || normalized == "info")
            {
                return normalized;
            }
            return "warning";
        }

        private static string NormalizeVerdict(string value)
        {
            string normalized = NormalizeDeviceText(value).ToLowerInvariant();
            if (normalized == "malicious" || normalized == "suspicious" || normalized == "observed" || normalized == "clean")
            {
                return normalized;
            }
            return "suspicious";
        }

        private static string NormalizeDeviceText(string value)
        {
            return (value ?? string.Empty).Trim();
        }

        private static string NormalizePathText(string value)
        {
            return (value ?? string.Empty).Trim().Trim('"');
        }

        private static string MaskSecret(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string secret = value.Trim();
            if (secret.Length <= 8)
            {
                return "****";
            }

            return secret.Substring(0, 4) + "****" + secret.Substring(secret.Length - 4);
        }

        private static int ClampInt(int value, int min, int max)
        {
            return Math.Max(min, Math.Min(max, value));
        }

        private static double ClampDouble(double value, double min, double max)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                return min;
            }
            return Math.Max(min, Math.Min(max, value));
        }

        private static string Quote(string value)
        {
            return "\"" + (value ?? string.Empty).Replace("\"", "\\\"") + "\"";
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, maxLength);
        }

        private static string AppendAnalysisLog(string current, string message)
        {
            string text = NormalizeDeviceText(message);
            if (string.IsNullOrWhiteSpace(text))
            {
                return current ?? string.Empty;
            }

            string line = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + "  " + text.Replace("\r", " ").Replace("\n", " ");
            string merged = string.IsNullOrWhiteSpace(current) ? line : (current.TrimEnd() + Environment.NewLine + line);
            const int maxLogLength = 24000;
            if (merged.Length <= maxLogLength)
            {
                return merged;
            }

            return merged.Substring(merged.Length - maxLogLength);
        }

        private static string JoinCompact(string separator, params string[] values)
        {
            return string.Join(separator, (values ?? new string[0]).Where(item => !string.IsNullOrWhiteSpace(item)));
        }

        private static void TryKill(Process process)
        {
            try
            {
                if (process != null && !process.HasExited)
                {
                    process.Kill();
                }
            }
            catch
            {
            }
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

        private static void DeleteDirectoryContents(string root)
        {
            try
            {
                if (!Directory.Exists(root))
                {
                    return;
                }
                foreach (string file in Directory.GetFiles(root))
                {
                    TryDeleteFile(file);
                }
                foreach (string directory in Directory.GetDirectories(root))
                {
                    TryDeleteDirectory(directory);
                }
            }
            catch
            {
            }
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

        private sealed class StaticAnalysisState
        {
            public StaticAnalysisState()
            {
                Configuration = null;
                Rules = null;
                Samples = new List<StaticAnalysisSampleState>();
            }

            public StaticAnalysisConfiguration Configuration { get; set; }
            public List<StaticAnalysisRuleDto> Rules { get; set; }
            public List<StaticAnalysisSampleState> Samples { get; set; }
        }

        private sealed class StaticAnalysisConfiguration
        {
            public bool enabled { get; set; }
            public bool aiEnabled { get; set; }
            public string ghidraRoot { get; set; }
            public string javaPath { get; set; }
            public string baseUrl { get; set; }
            public string token { get; set; }
            public string model { get; set; }
            public double temperature { get; set; }
            public int maxFunctions { get; set; }
            public int maxDecompilerChars { get; set; }
            public int timeoutSeconds { get; set; }
            public string actor { get; set; }
            public string updatedUtc { get; set; }
        }

        private sealed class StaticAnalysisSampleState
        {
            public string sampleId { get; set; }
            public string sha256 { get; set; }
            public string fileName { get; set; }
            public string storagePath { get; set; }
            public long sizeBytes { get; set; }
            public string source { get; set; }
            public string submitter { get; set; }
            public string notes { get; set; }
            public string submittedUtc { get; set; }
            public string lastSubmittedUtc { get; set; }
            public int submitCount { get; set; }
            public string status { get; set; }
            public string startedUtc { get; set; }
            public string completedUtc { get; set; }
            public string runId { get; set; }
            public int exitCode { get; set; }
            public string error { get; set; }
            public string reportJson { get; set; }
            public string stage { get; set; }
            public string stageText { get; set; }
            public int progress { get; set; }
            public string lastProgressUtc { get; set; }
            public string logText { get; set; }
            public int score { get; set; }
            public string verdict { get; set; }
            public string severity { get; set; }
            public string architecture { get; set; }
            public string signer { get; set; }
            public string signatureStatus { get; set; }
            public string productName { get; set; }
            public string companyName { get; set; }
            public string fileDescription { get; set; }
            public string fileVersion { get; set; }
        }

        private sealed class StaticAnalysisExecutionResult
        {
            public int exitCode { get; set; }
            public string error { get; set; }
            public string reportJson { get; set; }
            public string stage { get; set; }
            public string stageText { get; set; }
            public int progress { get; set; }
            public string lastProgressUtc { get; set; }
            public string logText { get; set; }
            public int score { get; set; }
            public string verdict { get; set; }
            public string severity { get; set; }
        }

        private sealed class ProcessResult
        {
            public int exitCode { get; set; }
            public string stdout { get; set; }
            public string stderr { get; set; }
        }

        private sealed class GhidraDiagnostics
        {
            public int errorCount { get; set; }
            public int warningCount { get; set; }
            public int cliMetadataErrors { get; set; }
            public string firstDiagnostic { get; set; }
            public string[] errors { get; set; }
            public string[] warnings { get; set; }
        }

        private sealed class PackedSamplePreprocessResult
        {
            public bool enabled { get; set; }
            public bool detected { get; set; }
            public string packer { get; set; }
            public string status { get; set; }
            public string message { get; set; }
            public string originalPath { get; set; }
            public string analysisPath { get; set; }
            public string unpackedPath { get; set; }
            public bool unpackSucceeded { get; set; }
            public string toolPath { get; set; }
            public int exitCode { get; set; }
            public string stdout { get; set; }
            public string stderr { get; set; }
        }

        private sealed class AiHttpResult
        {
            public int statusCode { get; set; }
            public string statusDescription { get; set; }
            public string body { get; set; }
            public string content { get; set; }
            public long elapsedMs { get; set; }
            public int responseBytes { get; set; }
            public bool streamed { get; set; }
        }

        public sealed class StaticAnalysisConfigurationDto
        {
            public bool enabled { get; set; }
            public bool aiEnabled { get; set; }
            public string ghidraRoot { get; set; }
            public string javaPath { get; set; }
            public string baseUrl { get; set; }
            public string maskedToken { get; set; }
            public bool tokenConfigured { get; set; }
            public string model { get; set; }
            public double temperature { get; set; }
            public int maxFunctions { get; set; }
            public int maxDecompilerChars { get; set; }
            public int timeoutSeconds { get; set; }
            public string analyzerScript { get; set; }
            public bool ghidraDetected { get; set; }
            public string updatedUtc { get; set; }
        }

        public sealed class StaticAnalysisConfigurationRequest
        {
            public bool enabled { get; set; }
            public bool aiEnabled { get; set; }
            public string ghidraRoot { get; set; }
            public string javaPath { get; set; }
            public string baseUrl { get; set; }
            public string token { get; set; }
            public bool clearToken { get; set; }
            public string model { get; set; }
            public double temperature { get; set; }
            public int maxFunctions { get; set; }
            public int maxDecompilerChars { get; set; }
            public int timeoutSeconds { get; set; }
            public string actor { get; set; }
        }

        public sealed class StaticAnalysisRuleDto
        {
            public string ruleId { get; set; }
            public string name { get; set; }
            public bool enabled { get; set; }
            public string target { get; set; }
            public string pattern { get; set; }
            public bool regex { get; set; }
            public int weight { get; set; }
            public string severity { get; set; }
            public string verdict { get; set; }
            public string description { get; set; }
        }

        public sealed class StaticAnalysisRuleSaveRequest
        {
            public StaticAnalysisRuleDto[] rules { get; set; }
            public string actor { get; set; }
        }

        public sealed class StaticAnalysisSampleQuery
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public string status { get; set; }
            public string verdict { get; set; }
            public string search { get; set; }
        }

        public sealed class StaticAnalysisSampleQueryResponse
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public int total { get; set; }
            public int queuedTotal { get; set; }
            public int runningTotal { get; set; }
            public int completedTotal { get; set; }
            public int failedTotal { get; set; }
            public int maliciousTotal { get; set; }
            public int suspiciousTotal { get; set; }
            public StaticAnalysisSampleDto[] items { get; set; }
        }

        public sealed class StaticAnalysisSampleUploadRequest
        {
            public string fileName { get; set; }
            public string contentBase64 { get; set; }
            public string sha256 { get; set; }
            public string source { get; set; }
            public string notes { get; set; }
            public string actor { get; set; }
        }

        public sealed class StaticAnalysisAnalyzeRequest
        {
            public string sampleId { get; set; }
            public int maxFunctions { get; set; }
            public int maxDecompilerChars { get; set; }
            public bool? aiEnabled { get; set; }
            public string actor { get; set; }
        }

        public sealed class StaticAnalysisSampleDeleteRequest
        {
            public string sampleId { get; set; }
            public bool all { get; set; }
            public string actor { get; set; }
        }

        public sealed class StaticAnalysisSampleDto
        {
            public string sampleId { get; set; }
            public string sha256 { get; set; }
            public string fileName { get; set; }
            public long sizeBytes { get; set; }
            public string source { get; set; }
            public string submitter { get; set; }
            public string notes { get; set; }
            public string submittedUtc { get; set; }
            public string lastSubmittedUtc { get; set; }
            public int submitCount { get; set; }
            public string status { get; set; }
            public string startedUtc { get; set; }
            public string completedUtc { get; set; }
            public string runId { get; set; }
            public int exitCode { get; set; }
            public string error { get; set; }
            public string reportJson { get; set; }
            public string stage { get; set; }
            public string stageText { get; set; }
            public int progress { get; set; }
            public string lastProgressUtc { get; set; }
            public string logText { get; set; }
            public int score { get; set; }
            public string verdict { get; set; }
            public string severity { get; set; }
            public string architecture { get; set; }
            public string signer { get; set; }
            public string signatureStatus { get; set; }
            public string productName { get; set; }
            public string companyName { get; set; }
            public string fileDescription { get; set; }
            public string fileVersion { get; set; }
        }

        public sealed class StaticAnalysisRuleScore
        {
            public int score { get; set; }
            public string verdict { get; set; }
            public string severity { get; set; }
            public StaticAnalysisRuleHit[] hits { get; set; }
        }

        public sealed class StaticAnalysisRuleHit
        {
            public string ruleId { get; set; }
            public string name { get; set; }
            public string target { get; set; }
            public string pattern { get; set; }
            public int weight { get; set; }
            public string severity { get; set; }
            public string verdict { get; set; }
            public string description { get; set; }
            public string[] evidence { get; set; }
        }

        public sealed class StaticAnalysisAiResult
        {
            public bool enabled { get; set; }
            public string status { get; set; }
            public string model { get; set; }
            public string verdict { get; set; }
            public string summary { get; set; }
            public string raw { get; set; }
            public string error { get; set; }
            public string endpoint { get; set; }
            public bool streamed { get; set; }
            public int httpStatus { get; set; }
            public long elapsedMs { get; set; }
            public int requestBytes { get; set; }
            public int responseBytes { get; set; }
            public int contentChars { get; set; }
        }

        public sealed class StaticAnalysisSourceInfo
        {
            public string upstream { get; set; }
            public string upstreamCommit { get; set; }
            public string license { get; set; }
            public string adapterScript { get; set; }
            public string[] extractedPaths { get; set; }
        }
    }
}
