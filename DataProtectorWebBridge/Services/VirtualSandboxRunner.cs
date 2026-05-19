using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class VirtualSandboxRunner
    {
        private const int DefaultTimeoutSeconds = 120;
        private const int MinimumTimeoutSeconds = 15;
        private const int MaximumTimeoutSeconds = 1800;
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();

        public SandboxTaskResult Run(Dictionary<string, object> args)
        {
            if (!Environment.UserInteractive)
            {
                throw new InvalidOperationException("The isolated sandbox requires an interactive Windows session.");
            }

            string samplePath = GetRequiredPath(args, "path", "samplePath");
            samplePath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(samplePath.Trim().Trim('"')));
            if (!File.Exists(samplePath))
            {
                throw new FileNotFoundException("Sandbox sample was not found.", samplePath);
            }

            SandboxAvailability sandboxAvailability = GetWindowsSandboxAvailability();
            if (!sandboxAvailability.IsAvailable)
            {
                throw new InvalidOperationException(sandboxAvailability.Message);
            }

            string sandboxExe = sandboxAvailability.ExecutablePath;
            int timeoutSeconds = Clamp(ParseInt(GetArg(args, "timeoutSeconds", DefaultTimeoutSeconds.ToString(CultureInfo.InvariantCulture)), DefaultTimeoutSeconds), MinimumTimeoutSeconds, MaximumTimeoutSeconds);
            bool networkEnabled = ParseBool(GetArg(args, "networkEnabled", "false"), false);
            bool copyInputDirectory = ParseBool(GetArg(args, "copyInputDirectory", "false"), false);
            bool closeWhenDone = ParseBool(GetArg(args, "closeWhenDone", "true"), true);
            string arguments = GetArg(args, "arguments", string.Empty);

            string runId = DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 12);
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string root = Path.Combine(dataRoot, "DataProtector", "Sandbox", runId);
            string controlHost = Path.Combine(root, "control");
            string reportHost = Path.Combine(root, "report");
            string telemetryHost = Path.Combine(root, "telemetry");
            string configPath = Path.Combine(root, "DataProtectorSandbox.wsb");
            string scriptPath = Path.Combine(controlHost, "run.ps1");
            string reportPath = Path.Combine(reportHost, "report.json");
            string donePath = Path.Combine(reportHost, "report.done");
            string sampleDirectory = Path.GetDirectoryName(samplePath);
            string sampleName = Path.GetFileName(samplePath);
            string sandboxRoot = @"C:\Users\WDAGUtilityAccount\AppData\Local\Temp\WinCache-" + Guid.NewGuid().ToString("N").Substring(0, 10);
            string sandboxInput = sandboxRoot + @"\Input";
            string sandboxControl = sandboxRoot + @"\Control";
            string sandboxReport = sandboxRoot + @"\Report";
            string sandboxTelemetry = sandboxRoot + @"\Telemetry";

            Directory.CreateDirectory(controlHost);
            Directory.CreateDirectory(reportHost);
            Directory.CreateDirectory(telemetryHost);

            string sampleHash = ComputeSha256(samplePath);
            string sampleArchitecture = ReadPeArchitecture(samplePath);
            string signer = TryReadSignerSubject(samplePath);
            PrepareTelemetryPackage(telemetryHost);
            string script = BuildSandboxScript(
                runId,
                sandboxInput,
                sandboxControl,
                sandboxReport,
                sandboxTelemetry,
                sampleName,
                arguments,
                timeoutSeconds,
                networkEnabled,
                copyInputDirectory,
                closeWhenDone,
                sampleHash,
                sampleArchitecture,
                signer);
            File.WriteAllText(scriptPath, script, new UTF8Encoding(false));

            string config = BuildWindowsSandboxConfig(
                sampleDirectory,
                controlHost,
                reportHost,
                telemetryHost,
                sandboxInput,
                sandboxControl,
                sandboxReport,
                sandboxTelemetry,
                networkEnabled);
            File.WriteAllText(configPath, config, new UTF8Encoding(false));

            Stopwatch stopwatch = Stopwatch.StartNew();
            Process sandboxProcess = null;
            try
            {
                sandboxProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = sandboxExe,
                    Arguments = QuoteArgument(configPath),
                    UseShellExecute = false,
                    CreateNoWindow = false,
                    WorkingDirectory = root
                });
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Unable to start Windows Sandbox: " + ex.Message, ex);
            }

            int waitMilliseconds = Math.Min((timeoutSeconds + 240) * 1000, (MaximumTimeoutSeconds + 300) * 1000);
            while (stopwatch.ElapsedMilliseconds < waitMilliseconds)
            {
                if (File.Exists(donePath) && File.Exists(reportPath))
                {
                    string reportJson = File.ReadAllText(reportPath, Encoding.UTF8);
                    return new SandboxTaskResult
                    {
                        ExitCode = 0,
                        Output = EnrichReport(reportJson, runId, root, configPath, samplePath, stopwatch.ElapsedMilliseconds)
                    };
                }

                Thread.Sleep(1000);
            }

            TryTerminateProcess(sandboxProcess);
            string timeoutReport = serializer.Serialize(new
            {
                schema = "dataprotector.sandbox.report.v1",
                isolation = "windows-sandbox",
                runId = runId,
                host = Environment.MachineName,
                startedUtc = DateTime.UtcNow.AddMilliseconds(-stopwatch.ElapsedMilliseconds).ToString("o"),
                completedUtc = DateTime.UtcNow.ToString("o"),
                sample = new
                {
                    hostPath = samplePath,
                    fileName = sampleName,
                    sha256 = sampleHash,
                    architecture = sampleArchitecture,
                    signer = signer
                },
                execution = new
                {
                    timedOut = true,
                    timeoutSeconds = timeoutSeconds,
                    durationMs = stopwatch.ElapsedMilliseconds
                },
                isolationControls = BuildIsolationControlSummary(networkEnabled),
                error = "Windows Sandbox did not return a report before the analysis timeout."
            });

            return new SandboxTaskResult
            {
                ExitCode = 124,
                Output = timeoutReport
            };
        }

        private string EnrichReport(string reportJson, string runId, string root, string configPath, string hostSamplePath, long durationMs)
        {
            try
            {
                Dictionary<string, object> report = serializer.Deserialize<Dictionary<string, object>>(reportJson);
                if (report == null)
                {
                    return reportJson;
                }

                report["host"] = Environment.MachineName;
                report["runId"] = runId;
                report["hostReportRoot"] = root;
                report["hostConfigPath"] = configPath;
                report["hostWaitMs"] = durationMs;
                Dictionary<string, object> sample = report.ContainsKey("sample") ? report["sample"] as Dictionary<string, object> : null;
                if (sample != null)
                {
                    sample["hostPath"] = hostSamplePath;
                }

                return serializer.Serialize(report);
            }
            catch
            {
                return reportJson;
            }
        }

        private static void PrepareTelemetryPackage(string telemetryHost)
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string runnerSource = FindExistingFile(
                Path.Combine(baseDirectory, "DataProtectorSandboxTelemetry.exe"),
                Path.Combine(baseDirectory, "sandbox-telemetry", "DataProtectorSandboxTelemetry.exe"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorSandboxTelemetry", "bin", "x64", "Release", "DataProtectorSandboxTelemetry.exe")),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "DataProtectorSandboxTelemetry", "bin", "x64", "Release", "DataProtectorSandboxTelemetry.exe")));
            if (string.IsNullOrWhiteSpace(runnerSource))
            {
                throw new FileNotFoundException("Sandbox telemetry runner was not found. Build DataProtectorSandboxTelemetry before running server-side sandbox analysis.");
            }

            Directory.CreateDirectory(telemetryHost);
            File.Copy(runnerSource, Path.Combine(telemetryHost, "DataProtectorSandboxTelemetry.exe"), true);
            CopyIfExists(Path.ChangeExtension(runnerSource, ".pdb"), Path.Combine(telemetryHost, "DataProtectorSandboxTelemetry.pdb"));

            string runtimeSource = FindExistingFile(
                Path.Combine(baseDirectory, "DataProtectorUserHookRuntime.dll"),
                Path.Combine(baseDirectory, "x64", "DataProtectorUserHookRuntime.dll"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "x64", "Release", "DataProtectorUserHookRuntime.dll")),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "x64", "Release", "DataProtectorUserHookRuntime.dll")));
            if (string.IsNullOrWhiteSpace(runtimeSource))
            {
                throw new FileNotFoundException("Sandbox hook runtime was not found. Build DataProtectorUserHookRuntime before running server-side sandbox analysis.");
            }

            string x64Directory = Path.Combine(telemetryHost, "x64");
            Directory.CreateDirectory(x64Directory);
            File.Copy(runtimeSource, Path.Combine(x64Directory, "DataProtectorUserHookRuntime.dll"), true);
            CopyIfExists(Path.ChangeExtension(runtimeSource, ".pdb"), Path.Combine(x64Directory, "DataProtectorUserHookRuntime.pdb"));

            PrepareKernelSensorPackage(telemetryHost, baseDirectory);

            string x86RuntimeSource = FindExistingFile(
                Path.Combine(baseDirectory, "x86", "DataProtectorUserHookRuntime.dll"),
                Path.Combine(baseDirectory, "sandbox-telemetry", "x86", "DataProtectorUserHookRuntime.dll"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "Win32", "Release", "DataProtectorUserHookRuntime.dll")),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "Win32", "Release", "DataProtectorUserHookRuntime.dll")));
            if (!string.IsNullOrWhiteSpace(x86RuntimeSource))
            {
                string x86Directory = Path.Combine(telemetryHost, "x86");
                Directory.CreateDirectory(x86Directory);
                File.Copy(x86RuntimeSource, Path.Combine(x86Directory, "DataProtectorUserHookRuntime.dll"), true);
                CopyIfExists(Path.ChangeExtension(x86RuntimeSource, ".pdb"), Path.Combine(x86Directory, "DataProtectorUserHookRuntime.pdb"));
                string x86KernelDirectory = Path.Combine(telemetryHost, "kernel", "x86");
                Directory.CreateDirectory(x86KernelDirectory);

                string x86RunnerSource = FindExistingFile(
                    Path.Combine(baseDirectory, "sandbox-telemetry", "x86", "DataProtectorSandboxTelemetry.exe"),
                    Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorSandboxTelemetry", "bin", "x86", "Release", "DataProtectorSandboxTelemetry.exe")),
                    Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "DataProtectorSandboxTelemetry", "bin", "x86", "Release", "DataProtectorSandboxTelemetry.exe")));
                if (!string.IsNullOrWhiteSpace(x86RunnerSource))
                {
                    File.Copy(x86RunnerSource, Path.Combine(x86Directory, "DataProtectorSandboxTelemetry.exe"), true);
                    CopyIfExists(Path.ChangeExtension(x86RunnerSource, ".pdb"), Path.Combine(x86Directory, "DataProtectorSandboxTelemetry.pdb"));
                }

                string x86PolicyApiSource = FindExistingFile(
                    Path.Combine(baseDirectory, "sandbox-telemetry", "kernel", "x86", "DataProtectorPolicyApi.dll"),
                    Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorPolicyApi", "Win32", "Release", "DataProtectorPolicyApi.dll")),
                    Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "DataProtectorPolicyApi", "Win32", "Release", "DataProtectorPolicyApi.dll")));
                if (!string.IsNullOrWhiteSpace(x86PolicyApiSource))
                {
                    File.Copy(x86PolicyApiSource, Path.Combine(x86KernelDirectory, "DataProtectorPolicyApi.dll"), true);
                    CopyIfExists(Path.ChangeExtension(x86PolicyApiSource, ".pdb"), Path.Combine(x86KernelDirectory, "DataProtectorPolicyApi.pdb"));
                }
            }
        }

        private static void PrepareKernelSensorPackage(string telemetryHost, string baseDirectory)
        {
            string kernelDirectory = Path.Combine(telemetryHost, "kernel");
            Directory.CreateDirectory(kernelDirectory);

            string driverSource = FindExistingFile(
                Path.Combine(baseDirectory, "sandbox-telemetry", "kernel", "DataProtector.sys"),
                Path.Combine(baseDirectory, "driver", "DataProtector.sys"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtector", "x64", "Release", "DataProtector", "DataProtector.sys")),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "DataProtector", "x64", "Release", "DataProtector", "DataProtector.sys")));
            if (!string.IsNullOrWhiteSpace(driverSource))
            {
                File.Copy(driverSource, Path.Combine(kernelDirectory, "DataProtector.sys"), true);
                CopyIfExists(Path.ChangeExtension(driverSource, ".pdb"), Path.Combine(kernelDirectory, "DataProtector.pdb"));
            }

            string policyApiSource = FindExistingFile(
                Path.Combine(baseDirectory, "DataProtectorPolicyApi.dll"),
                Path.Combine(baseDirectory, "sandbox-telemetry", "kernel", "DataProtectorPolicyApi.dll"),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "DataProtectorPolicyApi", "x64", "Release", "DataProtectorPolicyApi.dll")),
                Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "DataProtectorPolicyApi", "x64", "Release", "DataProtectorPolicyApi.dll")));
            if (!string.IsNullOrWhiteSpace(policyApiSource))
            {
                File.Copy(policyApiSource, Path.Combine(kernelDirectory, "DataProtectorPolicyApi.dll"), true);
                CopyIfExists(Path.ChangeExtension(policyApiSource, ".pdb"), Path.Combine(kernelDirectory, "DataProtectorPolicyApi.pdb"));
            }
        }

        private static string FindExistingFile(params string[] paths)
        {
            foreach (string path in paths)
            {
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    return path;
                }
            }

            return string.Empty;
        }

        private static void CopyIfExists(string source, string destination)
        {
            if (!string.IsNullOrWhiteSpace(source) && File.Exists(source))
            {
                File.Copy(source, destination, true);
            }
        }

        private static string BuildWindowsSandboxConfig(
            string inputHost,
            string controlHost,
            string reportHost,
            string telemetryHost,
            string sandboxInput,
            string sandboxControl,
            string sandboxReport,
            string sandboxTelemetry,
            bool networkEnabled)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("<Configuration>");
            builder.AppendLine("  <VGpu>Disable</VGpu>");
            builder.AppendLine("  <Networking>" + (networkEnabled ? "Default" : "Disable") + "</Networking>");
            builder.AppendLine("  <ClipboardRedirection>Disable</ClipboardRedirection>");
            builder.AppendLine("  <PrinterRedirection>Disable</PrinterRedirection>");
            builder.AppendLine("  <AudioInput>Disable</AudioInput>");
            builder.AppendLine("  <VideoInput>Disable</VideoInput>");
            builder.AppendLine("  <MappedFolders>");
            AppendMappedFolder(builder, inputHost, sandboxInput, true);
            AppendMappedFolder(builder, controlHost, sandboxControl, true);
            AppendMappedFolder(builder, reportHost, sandboxReport, false);
            AppendMappedFolder(builder, telemetryHost, sandboxTelemetry, true);
            builder.AppendLine("  </MappedFolders>");
            builder.AppendLine("  <LogonCommand>");
            builder.AppendLine("    <Command>powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File " + XmlEscape(sandboxControl + @"\run.ps1") + "</Command>");
            builder.AppendLine("  </LogonCommand>");
            builder.AppendLine("</Configuration>");
            return builder.ToString();
        }

        private static void AppendMappedFolder(StringBuilder builder, string hostFolder, string sandboxFolder, bool readOnly)
        {
            builder.AppendLine("    <MappedFolder>");
            builder.AppendLine("      <HostFolder>" + XmlEscape(hostFolder) + "</HostFolder>");
            builder.AppendLine("      <SandboxFolder>" + XmlEscape(sandboxFolder) + "</SandboxFolder>");
            builder.AppendLine("      <ReadOnly>" + (readOnly ? "true" : "false") + "</ReadOnly>");
            builder.AppendLine("    </MappedFolder>");
        }

        private static string BuildSandboxScript(
            string runId,
            string sandboxInput,
            string sandboxControl,
            string sandboxReport,
            string sandboxTelemetry,
            string sampleName,
            string arguments,
            int timeoutSeconds,
            bool networkEnabled,
            bool copyInputDirectory,
            bool closeWhenDone,
            string sampleHash,
            string sampleArchitecture,
            string signer)
        {
            string workspaceName = "analysis-" + Guid.NewGuid().ToString("N").Substring(0, 10);
            StringBuilder script = new StringBuilder();
            script.AppendLine("$ErrorActionPreference = 'SilentlyContinue'");
            script.AppendLine("$ProgressPreference = 'SilentlyContinue'");
            script.AppendLine("$runId = '" + PsQuote(runId) + "'");
            script.AppendLine("$inputRoot = '" + PsQuote(sandboxInput) + "'");
            script.AppendLine("$reportRoot = '" + PsQuote(sandboxReport) + "'");
            script.AppendLine("$telemetryRoot = '" + PsQuote(sandboxTelemetry) + "'");
            script.AppendLine("$sampleName = '" + PsQuote(sampleName) + "'");
            script.AppendLine("$sampleArchitecture = '" + PsQuote(sampleArchitecture) + "'");
            script.AppendLine("$argumentText = @'");
            script.AppendLine((arguments ?? string.Empty).Replace("'@", "' @"));
            script.AppendLine("'@");
            script.AppendLine("$timeoutSeconds = " + timeoutSeconds.ToString(CultureInfo.InvariantCulture));
            script.AppendLine("$networkEnabled = $" + (networkEnabled ? "true" : "false"));
            script.AppendLine("$copyInputDirectory = $" + (copyInputDirectory ? "true" : "false"));
            script.AppendLine("$closeWhenDone = $" + (closeWhenDone ? "true" : "false"));
            script.AppendLine("$workspace = Join-Path $env:LOCALAPPDATA '" + PsQuote(workspaceName) + "'");
            script.AppendLine("$reportPath = Join-Path $reportRoot 'report.json'");
            script.AppendLine("$donePath = Join-Path $reportRoot 'report.done'");
            script.AppendLine("New-Item -ItemType Directory -Force -Path $workspace, $reportRoot | Out-Null");
            script.AppendLine("try { if($copyInputDirectory){ Copy-Item -Path (Join-Path $inputRoot '*') -Destination $workspace -Recurse -Force } else { Copy-Item -LiteralPath (Join-Path $inputRoot $sampleName) -Destination (Join-Path $workspace $sampleName) -Force } } catch { [System.IO.File]::WriteAllText($reportPath, '{\"schema\":\"dataprotector.sandbox.report.v2\",\"error\":\"Input copy failed\"}', [System.Text.UTF8Encoding]::new($false)); [System.IO.File]::WriteAllText($donePath, 'done', [System.Text.UTF8Encoding]::new($false)); exit 1 }");
            script.AppendLine("$runPath = Join-Path $workspace $sampleName");
            script.AppendLine("$runner = Join-Path $telemetryRoot 'DataProtectorSandboxTelemetry.exe'");
            script.AppendLine("$runtime = Join-Path $telemetryRoot 'x64\\DataProtectorUserHookRuntime.dll'");
            script.AppendLine("$kernelDriver = Join-Path $telemetryRoot 'kernel\\DataProtector.sys'");
            script.AppendLine("$policyApi = Join-Path $telemetryRoot 'kernel\\DataProtectorPolicyApi.dll'");
            script.AppendLine("if($sampleArchitecture -eq 'x86'){ $runnerCandidate = Join-Path $telemetryRoot 'x86\\DataProtectorSandboxTelemetry.exe'; if(Test-Path -LiteralPath $runnerCandidate){ $runner = $runnerCandidate }; $runtime = Join-Path $telemetryRoot 'x86\\DataProtectorUserHookRuntime.dll'; $policyApiCandidate = Join-Path $telemetryRoot 'kernel\\x86\\DataProtectorPolicyApi.dll'; if(Test-Path -LiteralPath $policyApiCandidate){ $policyApi = $policyApiCandidate } }");
            script.AppendLine("$runnerArgs = @('--run-id', $runId, '--sample', $runPath, '--report', $reportPath, '--runtime', $runtime, '--kernel-driver', $kernelDriver, '--policy-api', $policyApi, '--timeout', ([string]$timeoutSeconds), '--network', ([string]$networkEnabled), '--arguments', $argumentText)");
            script.AppendLine("try { $runnerProcess = Start-Process -FilePath $runner -ArgumentList $runnerArgs -WorkingDirectory $workspace -Wait -PassThru; if(!(Test-Path -LiteralPath $donePath)){ [System.IO.File]::WriteAllText($donePath, 'done', [System.Text.UTF8Encoding]::new($false)) } } catch { [System.IO.File]::WriteAllText($reportPath, '{\"schema\":\"dataprotector.sandbox.report.v2\",\"error\":\"Telemetry runner failed\"}', [System.Text.UTF8Encoding]::new($false)); [System.IO.File]::WriteAllText($donePath, 'done', [System.Text.UTF8Encoding]::new($false)) }");
            script.AppendLine("if($closeWhenDone){ Start-Process -FilePath shutdown.exe -ArgumentList '/s /t 0 /f' -WindowStyle Hidden }");
            return script.ToString();
        }

        private static object BuildIsolationControlSummary(bool networkEnabled)
        {
            return new
            {
                boundary = "Windows Sandbox / Hyper-V",
                hostExecution = "disabled",
                inputMapping = "read-only",
                reportExchange = "empty writable exchange folder",
                clipboard = "disabled",
                printer = "disabled",
                audioInput = "disabled",
                videoInput = "disabled",
                network = networkEnabled ? "enabled" : "disabled",
                profile = "ephemeral"
            };
        }

        private static string FindWindowsSandboxExecutable()
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            List<string> candidates = new List<string>
            {
                Path.Combine(windows, "System32", "WindowsSandbox.exe"),
                Path.Combine(windows, "Sysnative", "WindowsSandbox.exe"),
                FindExecutableInPath("WindowsSandbox.exe")
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

        private static SandboxAvailability GetWindowsSandboxAvailability()
        {
            string sandboxExe = FindWindowsSandboxExecutable();
            string sandboxFeature = GetOptionalFeatureState("Containers-DisposableClientVM");
            string containersFeature = GetOptionalFeatureState("Containers");
            string hyperVFeature = GetOptionalFeatureState("Microsoft-Hyper-V-All");
            string virtualMachinePlatformFeature = GetOptionalFeatureState("VirtualMachinePlatform");
            bool hypervisorPresent = IsHypervisorPresent();
            bool rebootPending = IsWindowsRebootPending();

            List<string> blockers = new List<string>();
            if (!IsFeatureEnabled(sandboxFeature))
            {
                blockers.Add("Windows Sandbox feature Containers-DisposableClientVM is " + sandboxFeature + ".");
            }

            if (!hypervisorPresent)
            {
                blockers.Add("The Windows hypervisor is not active. Reboot after enabling virtualization features and confirm BIOS/UEFI virtualization is enabled.");
            }

            if (string.IsNullOrWhiteSpace(sandboxExe))
            {
                if (rebootPending && IsFeatureEnabled(sandboxFeature))
                {
                    blockers.Add("WindowsSandbox.exe was not found yet, and a Windows component reboot is pending; restart Windows so the Sandbox feature can finish installing.");
                }
                else
                {
                    blockers.Add("WindowsSandbox.exe was not found in System32, Sysnative, or PATH.");
                }
            }

            if (blockers.Count == 0)
            {
                return new SandboxAvailability
                {
                    IsAvailable = true,
                    ExecutablePath = sandboxExe,
                    Message = string.Empty
                };
            }

            string enableCommand = "Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart";
            return new SandboxAvailability
            {
                IsAvailable = false,
                ExecutablePath = sandboxExe,
                Message = "Windows Sandbox is not available on this endpoint. " +
                    string.Join(" ", blockers.ToArray()) +
                    " Current states: Containers-DisposableClientVM=" + sandboxFeature +
                    ", Containers=" + containersFeature +
                    ", Microsoft-Hyper-V-All=" + hyperVFeature +
                    ", VirtualMachinePlatform=" + virtualMachinePlatformFeature +
                    ", HypervisorPresent=" + (hypervisorPresent ? "true" : "false") +
                    ", RebootPending=" + (rebootPending ? "true" : "false") +
                    ". Run PowerShell as administrator: " + enableCommand + ", then restart Windows if requested."
            };
        }

        private static string FindExecutableInPath(string fileName)
        {
            string pathValue = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            string[] directories = pathValue.Split(new[] { Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string directory in directories)
            {
                try
                {
                    string normalized = directory.Trim().Trim('"');
                    if (string.IsNullOrWhiteSpace(normalized))
                    {
                        continue;
                    }

                    string candidate = Path.Combine(Environment.ExpandEnvironmentVariables(normalized), fileName);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
                catch
                {
                }
            }

            return string.Empty;
        }

        private static string GetOptionalFeatureState(string featureName)
        {
            try
            {
                string query = "SELECT InstallState FROM Win32_OptionalFeature WHERE Name='" + featureName.Replace("'", "''") + "'";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2", query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject result in results)
                    {
                        object value = result["InstallState"];
                        if (value == null)
                        {
                            return "Unknown";
                        }

                        return FormatOptionalFeatureState(Convert.ToInt32(value, CultureInfo.InvariantCulture));
                    }
                }

                return "NotFound";
            }
            catch (Exception ex)
            {
                return "Unknown(" + ex.GetType().Name + ")";
            }
        }

        private static string FormatOptionalFeatureState(int installState)
        {
            switch (installState)
            {
                case 1:
                    return "Enabled";
                case 2:
                    return "Disabled";
                case 3:
                    return "Absent";
                case 4:
                    return "Unknown";
                default:
                    return "State" + installState.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static bool IsFeatureEnabled(string state)
        {
            return string.Equals(state, "Enabled", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHypervisorPresent()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2", "SELECT HypervisorPresent FROM Win32_ComputerSystem"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject result in results)
                    {
                        object value = result["HypervisorPresent"];
                        return value != null && Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        private static bool IsWindowsRebootPending()
        {
            try
            {
                if (RegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") ||
                    RegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
                {
                    return true;
                }

                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    if (key == null)
                    {
                        return false;
                    }

                    object pendingRenames = key.GetValue("PendingFileRenameOperations");
                    return pendingRenames != null;
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool RegistryKeyExists(string subKey)
        {
            using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(subKey))
            {
                return key != null;
            }
        }

        private static string ComputeSha256(string path)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha256.ComputeHash(stream);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte item in hash)
                {
                    builder.Append(item.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
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

        private static string GetArg(Dictionary<string, object> args, string key, string fallback)
        {
            object value;
            return args != null && args.TryGetValue(key, out value) && value != null ? Convert.ToString(value, CultureInfo.InvariantCulture) : fallback;
        }

        private static string GetRequiredPath(Dictionary<string, object> args, params string[] keys)
        {
            foreach (string key in keys)
            {
                string value = GetArg(args, key, string.Empty);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            throw new InvalidOperationException("A sandbox sample path is required.");
        }

        private static int ParseInt(string value, int fallback)
        {
            int parsed;
            return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : fallback;
        }

        private static bool ParseBool(string value, bool fallback)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            bool parsed;
            if (bool.TryParse(value, out parsed))
            {
                return parsed;
            }

            return value == "1" ? true : value == "0" ? false : fallback;
        }

        private static int Clamp(int value, int minimum, int maximum)
        {
            return Math.Max(minimum, Math.Min(maximum, value));
        }

        private static string QuoteArgument(string value)
        {
            return "\"" + (value ?? string.Empty).Replace("\"", "\\\"") + "\"";
        }

        private static string XmlEscape(string value)
        {
            return (value ?? string.Empty)
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&apos;");
        }

        private static string PsQuote(string value)
        {
            return (value ?? string.Empty).Replace("'", "''");
        }

        private static void TryTerminateProcess(Process process)
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
            finally
            {
                if (process != null)
                {
                    process.Dispose();
                }
            }
        }

        internal sealed class SandboxTaskResult
        {
            public int ExitCode { get; set; }
            public string Output { get; set; }
        }

        private sealed class SandboxAvailability
        {
            public bool IsAvailable { get; set; }
            public string ExecutablePath { get; set; }
            public string Message { get; set; }
        }
    }
}
