using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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

            string sandboxExe = FindWindowsSandboxExecutable();
            if (string.IsNullOrWhiteSpace(sandboxExe))
            {
                throw new InvalidOperationException("Windows Sandbox is not available on this endpoint. Enable Windows Sandbox/Hyper-V before running isolated analysis.");
            }

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

            Directory.CreateDirectory(controlHost);
            Directory.CreateDirectory(reportHost);

            string sampleHash = ComputeSha256(samplePath);
            string sampleArchitecture = ReadPeArchitecture(samplePath);
            string signer = TryReadSignerSubject(samplePath);
            string script = BuildSandboxScript(
                runId,
                sandboxInput,
                sandboxControl,
                sandboxReport,
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
                sandboxInput,
                sandboxControl,
                sandboxReport,
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

        private static string BuildWindowsSandboxConfig(
            string inputHost,
            string controlHost,
            string reportHost,
            string sandboxInput,
            string sandboxControl,
            string sandboxReport,
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
            script.AppendLine("$controlRoot = '" + PsQuote(sandboxControl) + "'");
            script.AppendLine("$reportRoot = '" + PsQuote(sandboxReport) + "'");
            script.AppendLine("$sampleName = '" + PsQuote(sampleName) + "'");
            script.AppendLine("$sampleSha256 = '" + PsQuote(sampleHash) + "'");
            script.AppendLine("$sampleArchitecture = '" + PsQuote(sampleArchitecture) + "'");
            script.AppendLine("$sampleSigner = '" + PsQuote(signer) + "'");
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
            script.AppendLine("$stdoutPath = Join-Path $reportRoot 'stdout.txt'");
            script.AppendLine("$stderrPath = Join-Path $reportRoot 'stderr.txt'");
            script.AppendLine("New-Item -ItemType Directory -Force -Path $workspace, $reportRoot | Out-Null");
            script.AppendLine("$startedUtc = (Get-Date).ToUniversalTime().ToString('o')");
            script.AppendLine("$behaviors = New-Object System.Collections.ArrayList");
            script.AppendLine("$processRecords = @{}");
            script.AppendLine("$networkRecords = @{}");
            script.AppendLine("$registryRecords = New-Object System.Collections.ArrayList");
            script.AppendLine("$errors = New-Object System.Collections.ArrayList");
            script.AppendLine("function Add-Behavior([string]$type,[string]$severity,[string]$detail,[int]$pid) { [void]$behaviors.Add([ordered]@{ type=$type; severity=$severity; detail=$detail; pid=$pid; timeUtc=(Get-Date).ToUniversalTime().ToString('o') }) }");
            script.AppendLine("function Trunc([string]$value,[int]$max) { if ([string]::IsNullOrEmpty($value)) { return '' }; if ($value.Length -le $max) { return $value }; return $value.Substring(0,$max) + '...' }");
            script.AppendLine("function Read-Text-Limited([string]$path,[int]$max) { try { if (!(Test-Path -LiteralPath $path)) { return '' }; $text = [System.IO.File]::ReadAllText($path); return Trunc $text $max } catch { return '' } }");
            script.AppendLine("function Get-AuthInfo([string]$path) { try { $sig = Get-AuthenticodeSignature -LiteralPath $path; $subject = ''; if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }; return [ordered]@{ status=([string]$sig.Status); signer=$subject } } catch { return [ordered]@{ status='Unknown'; signer='' } } }");
            script.AppendLine("function Snapshot-Autoruns { $paths = @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'); $items=@{}; foreach($p in $paths){ if(Test-Path $p){ $props=(Get-ItemProperty $p).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }; foreach($prop in $props){ $items[($p + '\\' + $prop.Name)] = [string]$prop.Value } } }; return $items }");
            script.AppendLine("function Compare-Autoruns($before,$after){ foreach($key in $after.Keys){ if(!$before.ContainsKey($key) -or $before[$key] -ne $after[$key]){ [void]$registryRecords.Add([ordered]@{ path=$key; value=$after[$key]; change=($(if($before.ContainsKey($key)){'modified'}else{'created'})) }); Add-Behavior 'registry-persistence' 'high' ('Autorun value changed: ' + $key) 0 } } }");
            script.AppendLine("function Get-TreePids([int]$rootPid,$procs){ $set=@{}; if($rootPid -gt 0){ $set[$rootPid]=$true }; $changed=$true; while($changed){ $changed=$false; foreach($p in $procs){ if($p.ParentProcessId -and $set.ContainsKey([int]$p.ParentProcessId) -and !$set.ContainsKey([int]$p.ProcessId)){ $set[[int]$p.ProcessId]=$true; $changed=$true } } }; return $set.Keys }");
            script.AppendLine("function Add-ProcessRecord($p){ $pid=[int]$p.ProcessId; if(!$processRecords.ContainsKey([string]$pid)){ $path=[string]$p.ExecutablePath; $auth=Get-AuthInfo $path; $created=''; try { $created=([System.Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate).ToUniversalTime().ToString('o')) } catch {}; $processRecords[[string]$pid]=[ordered]@{ pid=$pid; parentPid=[int]$p.ParentProcessId; name=[string]$p.Name; path=$path; commandLine=Trunc ([string]$p.CommandLine) 2048; createdUtc=$created; signature=$auth } } }");
            script.AppendLine("function Analyze-Process($p){ $name=([string]$p.Name).ToLowerInvariant(); $cmd=([string]$p.CommandLine).ToLowerInvariant(); $pid=[int]$p.ProcessId; if($name -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$'){ Add-Behavior 'script-or-lolbin-execution' 'medium' ('Interpreter or loader launched: ' + $p.Name) $pid }; if($name -match '^(schtasks|sc|reg|vssadmin|wbadmin|bcdedit|wevtutil|netsh|wmic|bitsadmin|certutil)\\.exe$'){ Add-Behavior 'system-abuse-tool' 'high' ('Administrative tool launched: ' + $p.Name) $pid }; if($cmd.Contains('shadowcopy') -or $cmd.Contains('hklm\\sam') -or $cmd.Contains('hklm\\system') -or $cmd.Contains('encodedcommand') -or $cmd.Contains('downloadstring')){ Add-Behavior 'high-risk-command-line' 'critical' (Trunc ([string]$p.CommandLine) 512) $pid }; if($cmd.Contains('vbox') -or $cmd.Contains('vmware') -or $cmd.Contains('sandbox') -or $cmd.Contains('qemu') -or $cmd.Contains('debug')){ Add-Behavior 'environment-probe' 'medium' (Trunc ([string]$p.CommandLine) 512) $pid } }");
            script.AppendLine("function Add-NetworkRecords($tree){ try { $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $tree -contains [int]$_.OwningProcess -and $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }; foreach($c in $conns){ $key=('{0}:{1}>{2}:{3}/{4}/{5}' -f $c.LocalAddress,$c.LocalPort,$c.RemoteAddress,$c.RemotePort,$c.State,$c.OwningProcess); if(!$networkRecords.ContainsKey($key)){ $networkRecords[$key]=[ordered]@{ pid=[int]$c.OwningProcess; localAddress=[string]$c.LocalAddress; localPort=[int]$c.LocalPort; remoteAddress=[string]$c.RemoteAddress; remotePort=[int]$c.RemotePort; state=[string]$c.State; timeUtc=(Get-Date).ToUniversalTime().ToString('o') }; Add-Behavior 'network-connection' 'medium' ('Remote connection: ' + $c.RemoteAddress + ':' + $c.RemotePort) ([int]$c.OwningProcess) } } } catch {} }");
            script.AppendLine("$autorunsBefore = Snapshot-Autoruns");
            script.AppendLine("try { if($copyInputDirectory){ Copy-Item -Path (Join-Path $inputRoot '*') -Destination $workspace -Recurse -Force } else { Copy-Item -LiteralPath (Join-Path $inputRoot $sampleName) -Destination (Join-Path $workspace $sampleName) -Force } } catch { [void]$errors.Add('Input copy failed: ' + $_.Exception.Message) }");
            script.AppendLine("$runPath = Join-Path $workspace $sampleName");
            script.AppendLine("$exitCode = $null; $timedOut = $false; $rootPid = 0");
            script.AppendLine("try { $proc = Start-Process -FilePath $runPath -ArgumentList $argumentText -WorkingDirectory $workspace -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath; $rootPid = [int]$proc.Id } catch { [void]$errors.Add('Sample start failed: ' + $_.Exception.Message); $proc=$null }");
            script.AppendLine("$deadline = (Get-Date).AddSeconds($timeoutSeconds)");
            script.AppendLine("if($proc -ne $null){ while((Get-Date) -lt $deadline){ $procs = @(Get-CimInstance Win32_Process); $tree = @(Get-TreePids $rootPid $procs); foreach($p in $procs){ if($tree -contains [int]$p.ProcessId){ Add-ProcessRecord $p; Analyze-Process $p } }; Add-NetworkRecords $tree; $liveTree = @(); foreach($pid in $tree){ if(Get-Process -Id $pid -ErrorAction SilentlyContinue){ $liveTree += $pid } }; if($liveTree.Count -eq 0){ break }; Start-Sleep -Milliseconds 500 }; try { $proc.Refresh(); if(!$proc.HasExited -or (Get-Process -Id $rootPid -ErrorAction SilentlyContinue)){ $timedOut = $true; Add-Behavior 'analysis-timeout' 'medium' 'Sample remained active until the sandbox deadline.' $rootPid; $procs = @(Get-CimInstance Win32_Process); $tree = @(Get-TreePids $rootPid $procs); foreach($pid in $tree){ Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } } else { $exitCode = $proc.ExitCode } } catch {} }");
            script.AppendLine("$autorunsAfter = Snapshot-Autoruns");
            script.AppendLine("Compare-Autoruns $autorunsBefore $autorunsAfter");
            script.AppendLine("$artifactList = @(); try { $artifactList = Get-ChildItem -LiteralPath $workspace -Recurse -Force -File | Select-Object -First 256 | ForEach-Object { [ordered]@{ path=$_.FullName.Replace($workspace,'<workspace>'); size=$_.Length; modifiedUtc=$_.LastWriteTimeUtc.ToString('o'); sha256=$(try{(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash}catch{''}) } } } catch { [void]$errors.Add('Artifact enumeration failed: ' + $_.Exception.Message) }");
            script.AppendLine("if($networkRecords.Count -eq 0 -and !$networkEnabled){ Add-Behavior 'network-contained' 'info' 'Sandbox networking was disabled for this run.' 0 }");
            script.AppendLine("$completedUtc = (Get-Date).ToUniversalTime().ToString('o')");
            script.AppendLine("$report = [ordered]@{ schema='dataprotector.sandbox.report.v1'; isolation='windows-sandbox'; runId=$runId; startedUtc=$startedUtc; completedUtc=$completedUtc; sample=[ordered]@{ hostPath=''; fileName=$sampleName; sha256=$sampleSha256; architecture=$sampleArchitecture; signer=$sampleSigner; sandboxPath=$runPath }; execution=[ordered]@{ pid=$rootPid; exitCode=$exitCode; timedOut=$timedOut; timeoutSeconds=$timeoutSeconds }; isolationControls=[ordered]@{ boundary='Windows Sandbox / Hyper-V'; hostExecution='disabled'; inputMapping='read-only'; reportExchange='empty writable exchange folder'; clipboard='disabled'; printer='disabled'; audioInput='disabled'; videoInput='disabled'; network=($(if($networkEnabled){'enabled'}else{'disabled'})); profile='ephemeral' }; analysisHardening=[ordered]@{ localWorkspace='enabled'; randomizedWorkspace='enabled'; hostPathHiddenFromExecution='enabled'; sandboxArtifactsDiscarded='enabled' }; behaviors=@($behaviors); processes=@($processRecords.Values); network=@($networkRecords.Values); registryChanges=@($registryRecords); fileArtifacts=@($artifactList); stdout=(Read-Text-Limited $stdoutPath 32768); stderr=(Read-Text-Limited $stderrPath 32768); errors=@($errors) }");
            script.AppendLine("$json = $report | ConvertTo-Json -Depth 9");
            script.AppendLine("[System.IO.File]::WriteAllText($reportPath, $json, [System.Text.UTF8Encoding]::new($false))");
            script.AppendLine("[System.IO.File]::WriteAllText($donePath, 'done', [System.Text.UTF8Encoding]::new($false))");
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
            string[] candidates =
            {
                Path.Combine(windows, "System32", "WindowsSandbox.exe"),
                Path.Combine(windows, "Sysnative", "WindowsSandbox.exe")
            };

            foreach (string candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return string.Empty;
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
    }
}
