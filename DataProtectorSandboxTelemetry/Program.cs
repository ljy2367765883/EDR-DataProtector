using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DataProtectorSandboxTelemetry
{
    internal static class Program
    {
        private const int DefaultTimeoutSeconds = 120;
        private const int MaxRuntimeEventBytes = 2 * 1024 * 1024;
        private const string RuntimeEventPath = @"C:\ProgramData\DataProtector\UserHookRuntimeEvents.jsonl";
        private const string RuntimePolicyPath = @"C:\ProgramData\DataProtector\UserHookRuntimePolicy.json";
        private const string KernelSensorServiceName = "DataProtector";
        private const string KernelSensorDriverFileName = "DataProtector.sys";
        private const string KernelSensorDriverImagePath = @"\SystemRoot\System32\drivers\DataProtector.sys";
        private static readonly JavaScriptSerializer Serializer = CreateSerializer();

        private static int Main(string[] args)
        {
            Options options = null;
            try
            {
                options = Options.Parse(args);
                return Run(options);
            }
            catch (Exception ex)
            {
                WriteCrashReport(options, ex);
                Console.Error.WriteLine(ex.ToString());
                return 1;
            }
        }

        private static int Run(Options options)
        {
            if (string.IsNullOrWhiteSpace(options.SamplePath) || string.IsNullOrWhiteSpace(options.ReportPath))
            {
                Console.Error.WriteLine("Usage: DataProtectorSandboxTelemetry.exe --sample <path> --report <report.json> [--runtime <DataProtectorUserHookRuntime.dll>] [--timeout 120] [--arguments <args>]");
                return 2;
            }

            DateTime startedUtc = DateTime.UtcNow;
            Stopwatch stopwatch = Stopwatch.StartNew();
            List<BehaviorRecord> behaviors = new List<BehaviorRecord>();
            List<string> errors = new List<string>();
            SuspendedProcess suspendedProcess = null;
            int samplePid = 0;
            int exitCode = -1;
            bool timedOut = false;
            string workspace = Path.GetDirectoryName(options.SamplePath) ?? Environment.CurrentDirectory;

            PrepareRuntimePolicy(errors);
            TryDelete(RuntimeEventPath);

            string sha256 = ComputeSha256(options.SamplePath);
            string architecture = ReadPeArchitecture(options.SamplePath);
            string signer = TryReadSignerSubject(options.SamplePath);
            string runtimePath = ResolveRuntimePath(options.RuntimePath, architecture);
            KernelSensorRecord kernelSensor = InitializeKernelSensor(options.KernelDriverPath, options.PolicyApiPath, runtimePath, behaviors, errors);
            Snapshot before = Snapshot.Capture(errors);
            bool runtimeInjected = false;
            string runtimeStatus = "not-requested";

            try
            {
                suspendedProcess = StartSampleSuspended(options.SamplePath, options.Arguments, workspace);
                samplePid = suspendedProcess.ProcessId;
                if (!string.IsNullOrWhiteSpace(runtimePath) && File.Exists(runtimePath))
                {
                    runtimeInjected = TryInjectDll(samplePid, runtimePath, errors);
                    runtimeStatus = runtimeInjected ? "injected" : "inject-failed";
                }
                else
                {
                    runtimeStatus = "runtime-missing";
                    errors.Add("Hook runtime was not found for sample architecture: " + architecture);
                }

                if (suspendedProcess.MainThreadHandle != IntPtr.Zero)
                {
                    ResumeThread(suspendedProcess.MainThreadHandle);
                }
                ObserveProcess(samplePid, suspendedProcess.ProcessHandle, options.TimeoutSeconds, behaviors, errors, out timedOut, out exitCode);
            }
            catch (Exception ex)
            {
                errors.Add("Sample execution failed: " + ex.Message);
            }
            finally
            {
                if (suspendedProcess != null)
                {
                    if (!timedOut)
                    {
                        suspendedProcess.TerminateIfRunning(errors);
                    }

                    suspendedProcess.Dispose();
                }
            }

            Snapshot after = Snapshot.Capture(errors);
            List<ProcessRecord> processes = CollectProcessRecords(samplePid, before, after);
            List<NetworkRecord> network = CollectNetworkRecords(processes);
            List<RegistryRecord> registry = CompareRegistry(before.Autoruns, after.Autoruns, behaviors);
            List<ServiceRecord> services = CompareServices(before.Services, after.Services, behaviors);
            List<TaskRecord> tasks = CompareTasks(before.Tasks, after.Tasks, behaviors);
            List<FileArtifactRecord> artifacts = EnumerateArtifacts(workspace, behaviors, errors);
            List<RuntimeEventRecord> runtimeEvents = ReadRuntimeEvents(RuntimeEventPath, behaviors, errors);
            List<KernelSensorEventRecord> kernelEvents = DrainKernelSensorEvents(kernelSensor, behaviors, errors);

            RemoveInternalTelemetryNoise(behaviors, processes, network, artifacts, runtimeEvents, kernelEvents, services, tasks);
            AddRuleDetections(processes, network, runtimeEvents, kernelEvents, services, tasks, behaviors);
            RemoveInternalTelemetryNoise(behaviors, processes, network, artifacts, runtimeEvents, kernelEvents, services, tasks);
            Report report = new Report
            {
                schema = "dataprotector.sandbox.report.v2",
                isolation = "windows-sandbox",
                runId = options.RunId,
                startedUtc = startedUtc.ToString("o"),
                completedUtc = DateTime.UtcNow.ToString("o"),
                sample = new SampleRecord
                {
                    hostPath = string.Empty,
                    fileName = Path.GetFileName(options.SamplePath),
                    sha256 = sha256,
                    architecture = architecture,
                    signer = signer,
                    sandboxPath = options.SamplePath
                },
                execution = new ExecutionRecord
                {
                    pid = samplePid,
                    exitCode = exitCode,
                    timedOut = timedOut,
                    timeoutSeconds = options.TimeoutSeconds,
                    durationMs = stopwatch.ElapsedMilliseconds
                },
                telemetry = new TelemetryRecord
                {
                    mode = "commercial-telemetry-v1",
                    runtimeHook = runtimeStatus,
                    runtimePath = runtimePath,
                    runtimeInjected = runtimeInjected,
                    etwProcessProvider = "WMI/CIM fallback",
                    kernelSensor = kernelSensor.status,
                    apiHookProvider = "DataProtectorUserHookRuntime/MinHook",
                    memoryScan = "runtime-private-executable-rwx-manual-map",
                    driverAndServiceDiff = "enabled",
                    taskDiff = "enabled",
                    autorunDiff = "enabled",
                    fileArtifactDiff = "workspace"
                },
                isolationControls = new Dictionary<string, object>
                {
                    { "boundary", "Windows Sandbox / Hyper-V" },
                    { "hostExecution", "disabled" },
                    { "inputMapping", "read-only" },
                    { "reportExchange", "empty writable exchange folder" },
                    { "clipboard", "disabled" },
                    { "printer", "disabled" },
                    { "audioInput", "disabled" },
                    { "videoInput", "disabled" },
                    { "network", options.NetworkEnabled ? "enabled" : "disabled" },
                    { "profile", "ephemeral" }
                },
                analysisHardening = new Dictionary<string, object>
                {
                    { "localWorkspace", "enabled" },
                    { "randomizedWorkspace", "enabled" },
                    { "hostPathHiddenFromExecution", "enabled" },
                    { "sandboxArtifactsDiscarded", "enabled" },
                    { "suspendedLaunchInjection", "enabled" },
                    { "runtimeUnhookDetection", "enabled" },
                    { "syscallBypassHeuristic", "enabled" },
                    { "serviceDriverDiff", "enabled" }
                },
                behaviors = behaviors.Distinct(new BehaviorComparer()).Take(1024).ToList(),
                processes = processes.Take(512).ToList(),
                network = network.Take(512).ToList(),
                registryChanges = registry.Take(512).ToList(),
                services = services.Take(512).ToList(),
                scheduledTasks = tasks.Take(512).ToList(),
                runtimeEvents = runtimeEvents.Take(2048).ToList(),
                kernelSensor = kernelSensor,
                kernelEvents = kernelEvents.Take(2048).ToList(),
                fileArtifacts = artifacts.Take(512).ToList(),
                stdout = string.Empty,
                stderr = string.Empty,
                errors = errors.Distinct().Take(256).ToList()
            };

            Directory.CreateDirectory(Path.GetDirectoryName(options.ReportPath) ?? ".");
            File.WriteAllText(options.ReportPath, Serializer.Serialize(report), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(options.ReportPath) ?? ".", "report.done"), "done", new UTF8Encoding(false));
            return 0;
        }

        private static void WriteCrashReport(Options options, Exception exception)
        {
            try
            {
                string reportPath = options == null ? string.Empty : options.ReportPath;
                if (string.IsNullOrWhiteSpace(reportPath))
                {
                    return;
                }

                string reportDirectory = Path.GetDirectoryName(reportPath) ?? ".";
                Directory.CreateDirectory(reportDirectory);
                Dictionary<string, object> report = new Dictionary<string, object>
                {
                    { "schema", "dataprotector.sandbox.report.v2" },
                    { "error", "Telemetry runner crashed" },
                    { "runId", options.RunId ?? string.Empty },
                    { "samplePath", options.SamplePath ?? string.Empty },
                    { "runtimePath", options.RuntimePath ?? string.Empty },
                    { "kernelDriverPath", options.KernelDriverPath ?? string.Empty },
                    { "policyApiPath", options.PolicyApiPath ?? string.Empty },
                    { "exceptionType", exception.GetType().FullName },
                    { "message", exception.Message },
                    { "stackTrace", exception.ToString() }
                };
                File.WriteAllText(reportPath, Serializer.Serialize(report), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(reportDirectory, "report.done"), "done", new UTF8Encoding(false));
            }
            catch
            {
            }
        }

        private static void ObserveProcess(int processId, IntPtr processHandle, int timeoutSeconds, List<BehaviorRecord> behaviors, List<string> errors, out bool timedOut, out int exitCode)
        {
            timedOut = false;
            exitCode = -1;
            DateTime deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
            HashSet<int> observed = new HashSet<int>();

            while (DateTime.UtcNow < deadline)
            {
                List<ProcessRecord> tree = CollectProcessTree(processId);
                foreach (ProcessRecord record in tree)
                {
                    if (observed.Add(record.pid))
                    {
                        AnalyzeProcess(record, behaviors);
                    }
                }

                uint wait = WaitForSingleObject(processHandle, 0);
                if (wait == 0)
                {
                    uint nativeExitCode;
                    exitCode = GetExitCodeProcess(processHandle, out nativeExitCode) ? unchecked((int)nativeExitCode) : -1;
                    return;
                }

                Thread.Sleep(350);
            }

            timedOut = true;
            AddBehavior(behaviors, "analysis-timeout", "medium", "Sample remained active until the sandbox deadline.", processId);
            if (!TerminateProcess(processHandle, 1))
            {
                errors.Add("Failed to terminate timed-out sample: Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
            }
        }

        private static SuspendedProcess StartSampleSuspended(string samplePath, string arguments, string workspace)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInformation;
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            string commandLine = Quote(samplePath) + (string.IsNullOrWhiteSpace(arguments) ? string.Empty : " " + arguments);
            bool created = CreateProcessW(
                null,
                new StringBuilder(commandLine),
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x00000004,
                IntPtr.Zero,
                workspace,
                ref startupInfo,
                out processInformation);
            if (!created)
            {
                throw new InvalidOperationException("CreateProcessW failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
            }

            return new SuspendedProcess
            {
                ProcessId = (int)processInformation.dwProcessId,
                ProcessHandle = processInformation.hProcess,
                MainThreadHandle = processInformation.hThread
            };
        }

        private static bool TryInjectDll(int processId, string dllPath, List<string> errors)
        {
            IntPtr processHandle = IntPtr.Zero;
            IntPtr remoteMemory = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;
            try
            {
                byte[] bytes = Encoding.Unicode.GetBytes(dllPath + "\0");
                processHandle = OpenProcess(0x001F0FFF, false, processId);
                if (processHandle == IntPtr.Zero)
                {
                    errors.Add("OpenProcess for runtime injection failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                remoteMemory = VirtualAllocEx(processHandle, IntPtr.Zero, (UIntPtr)bytes.Length, 0x3000, 0x04);
                if (remoteMemory == IntPtr.Zero)
                {
                    errors.Add("VirtualAllocEx for runtime injection failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                UIntPtr written;
                if (!WriteProcessMemory(processHandle, remoteMemory, bytes, (UIntPtr)bytes.Length, out written))
                {
                    errors.Add("WriteProcessMemory for runtime injection failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                IntPtr kernel32 = GetModuleHandle("kernel32.dll");
                IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
                if (loadLibrary == IntPtr.Zero)
                {
                    errors.Add("LoadLibraryW address was not found.");
                    return false;
                }

                threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, UIntPtr.Zero, loadLibrary, remoteMemory, 0, IntPtr.Zero);
                if (threadHandle == IntPtr.Zero)
                {
                    errors.Add("CreateRemoteThread for runtime injection failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                WaitForSingleObject(threadHandle, 10000);
                return true;
            }
            finally
            {
                if (threadHandle != IntPtr.Zero) CloseHandle(threadHandle);
                if (remoteMemory != IntPtr.Zero && processHandle != IntPtr.Zero) VirtualFreeEx(processHandle, remoteMemory, UIntPtr.Zero, 0x8000);
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
            }
        }

        private static string ResolveRuntimePath(string requestedPath, string architecture)
        {
            if (!string.IsNullOrWhiteSpace(requestedPath) && File.Exists(requestedPath))
            {
                return requestedPath;
            }

            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string preferred = string.Equals(architecture, "x86", StringComparison.OrdinalIgnoreCase)
                ? Path.Combine(baseDirectory, "x86", "DataProtectorUserHookRuntime.dll")
                : Path.Combine(baseDirectory, "x64", "DataProtectorUserHookRuntime.dll");
            if (File.Exists(preferred))
            {
                return preferred;
            }

            string fallback = Path.Combine(baseDirectory, "DataProtectorUserHookRuntime.dll");
            return File.Exists(fallback) ? fallback : string.Empty;
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

        private static void PrepareRuntimePolicy(List<string> errors)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(RuntimePolicyPath) ?? ".");
                string policy = "{\"enabled\":true,\"auditOnly\":true,\"monitorRuntimeApiBehavior\":true,\"scanExecutableMemory\":true,\"excludedProcessNames\":[],\"excludedProcessDirectories\":[],\"excludedProcessPaths\":[],\"trustedSignerSubjects\":[]}";
                File.WriteAllText(RuntimePolicyPath, policy, new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                errors.Add("Runtime policy preparation failed: " + ex.Message);
            }
        }

        private static KernelSensorRecord InitializeKernelSensor(string driverPackagePath, string policyApiPath, string runtimePath, List<BehaviorRecord> behaviors, List<string> errors)
        {
            KernelSensorRecord sensor = new KernelSensorRecord
            {
                enabled = false,
                status = "disabled",
                serviceName = KernelSensorServiceName,
                driverPath = string.Empty,
                policyApiPath = policyApiPath ?? string.Empty,
                runtimePath = runtimePath ?? string.Empty,
                win32 = 0,
                message = string.Empty
            };

            if (!IsAdministrator())
            {
                sensor.status = "not-admin";
                sensor.message = "Sandbox telemetry is not elevated; kernel sensor loading was skipped.";
                errors.Add(sensor.message);
                return sensor;
            }

            if (!EnablePrivilege("SeLoadDriverPrivilege", errors))
            {
                errors.Add("SeLoadDriverPrivilege could not be enabled; minifilter loading may fail with Win32=1314.");
            }

            string sourceDriver = FindExistingFile(
                driverPackagePath,
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "driver", "DataProtector.sys"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "kernel", "DataProtector.sys"));
            if (string.IsNullOrWhiteSpace(sourceDriver))
            {
                sensor.status = "driver-missing";
                sensor.message = "DataProtector kernel sensor driver was not found in the sandbox telemetry package.";
                errors.Add(sensor.message);
                return sensor;
            }

            try
            {
                string destinationDriver = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32",
                    "drivers",
                    KernelSensorDriverFileName);
                File.Copy(sourceDriver, destinationDriver, true);
                sensor.driverPath = destinationDriver;

                SetMiniFilterInstanceRegistry(sensor.serviceName);
                int win32 = InstallAndStartKernelService(sensor.serviceName, KernelSensorDriverImagePath, errors);
                sensor.win32 = win32;
                if (win32 != 0 && win32 != 1056)
                {
                    sensor.status = "start-failed";
                    sensor.message = "Kernel sensor minifilter load failed with Win32=" + win32.ToString(CultureInfo.InvariantCulture) + ".";
                    errors.Add(sensor.message);
                    return sensor;
                }

                sensor.status = "loaded";
                sensor.enabled = true;
                sensor.message = "Kernel sensor loaded inside Windows Sandbox.";
                AddBehavior(behaviors, "sandbox-kernel-sensor", "info", sensor.message, 0);

                string effectivePolicyApiPath = FindExistingFile(
                    policyApiPath,
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DataProtectorPolicyApi.dll"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "kernel", "DataProtectorPolicyApi.dll"));
                sensor.policyApiPath = effectivePolicyApiPath;
                if (!string.IsNullOrWhiteSpace(effectivePolicyApiPath))
                {
                    uint result = ApplyKernelUserHookPolicy(effectivePolicyApiPath, runtimePath, errors);
                    sensor.policyStatus = "0x" + result.ToString("X8", CultureInfo.InvariantCulture);
                    if (result == 0)
                    {
                        AddBehavior(behaviors, "kernel-early-injection-policy", "info", "Kernel early-injection policy was applied for the sandbox runtime.", 0);
                    }
                    else
                    {
                        errors.Add("Kernel user-hook policy apply failed: 0x" + result.ToString("X8", CultureInfo.InvariantCulture));
                    }
                }
                else
                {
                    sensor.policyStatus = "policy-api-missing";
                    errors.Add("DataProtectorPolicyApi.dll was not found; kernel sensor events will rely on default policy.");
                }
            }
            catch (Exception ex)
            {
                sensor.enabled = false;
                sensor.status = "load-exception";
                sensor.message = ex.Message;
                errors.Add("Kernel sensor initialization failed: " + ex.Message);
            }

            return sensor;
        }

        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static bool EnablePrivilege(string privilegeName, List<string> errors)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token))
                {
                    errors.Add("OpenProcessToken failed while enabling " + privilegeName + ": Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                LUID luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    errors.Add("LookupPrivilegeValue failed for " + privilegeName + ": Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = 0x00000002
                };
                if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    errors.Add("AdjustTokenPrivileges failed for " + privilegeName + ": Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                int win32 = Marshal.GetLastWin32Error();
                if (win32 != 0)
                {
                    errors.Add("AdjustTokenPrivileges did not assign " + privilegeName + ": Win32=" + win32.ToString(CultureInfo.InvariantCulture));
                    return false;
                }

                return true;
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
            }
        }

        private static void SetMiniFilterInstanceRegistry(string serviceName)
        {
            using (Microsoft.Win32.RegistryKey serviceKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName))
            {
                if (serviceKey != null)
                {
                    serviceKey.SetValue("SupportedFeatures", 3, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }

            using (Microsoft.Win32.RegistryKey instancesKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName + @"\Instances"))
            using (Microsoft.Win32.RegistryKey instanceKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName + @"\Instances\DataProtector Sandbox Instance"))
            {
                if (instancesKey != null)
                {
                    instancesKey.SetValue("DefaultInstance", "DataProtector Sandbox Instance", Microsoft.Win32.RegistryValueKind.String);
                }

                if (instanceKey != null)
                {
                    instanceKey.SetValue("Altitude", "141000", Microsoft.Win32.RegistryValueKind.String);
                    instanceKey.SetValue("Flags", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
        }

        private static int InstallAndStartKernelService(string serviceName, string driverImagePath, List<string> errors)
        {
            IntPtr manager = OpenSCManager(null, null, 0xF003F);
            if (manager == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error();
            }

            IntPtr service = IntPtr.Zero;
            try
            {
                service = OpenService(manager, serviceName, 0xF01FF);
                if (service == IntPtr.Zero)
                {
                    service = CreateService(
                        manager,
                        serviceName,
                        serviceName,
                        0xF01FF,
                        2,
                        3,
                        1,
                        driverImagePath,
                        "FSFilter Encryption",
                        IntPtr.Zero,
                        "FltMgr\0",
                        null,
                        null);
                    if (service == IntPtr.Zero)
                    {
                        return Marshal.GetLastWin32Error();
                    }
                }
                else
                {
                    if (!ChangeServiceConfig(service, 2, 3, 1, driverImagePath, "FSFilter Encryption", IntPtr.Zero, "FltMgr\0", null, null, serviceName))
                    {
                        errors.Add("Kernel sensor service config update failed: Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    }
                }

                uint filterLoadResult = FilterLoad(serviceName);
                if (filterLoadResult == 0 || filterLoadResult == 0x80070420)
                {
                    return 0;
                }

                int filterLoadWin32 = HResultToWin32(filterLoadResult);
                errors.Add("Kernel sensor FilterLoad failed: hr=0x" + filterLoadResult.ToString("X8", CultureInfo.InvariantCulture) +
                           " win32=" + filterLoadWin32.ToString(CultureInfo.InvariantCulture) + ". Falling back to SCM StartService.");

                if (StartService(service, 0, null))
                {
                    return 0;
                }

                int error = Marshal.GetLastWin32Error();
                return error == 1056 ? 0 : error;
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                }

                CloseServiceHandle(manager);
            }
        }

        private static int HResultToWin32(uint result)
        {
            const uint FacilityWin32Mask = 0xFFFF0000;
            if ((result & FacilityWin32Mask) == 0x80070000)
            {
                return (int)(result & 0xFFFF);
            }

            return unchecked((int)result);
        }

        private static uint ApplyKernelUserHookPolicy(string policyApiPath, string runtimePath, List<string> errors)
        {
            IntPtr module = IntPtr.Zero;
            IntPtr excludedNames = IntPtr.Zero;
            IntPtr excludedDirectories = IntPtr.Zero;
            IntPtr excludedPaths = IntPtr.Zero;
            IntPtr trustedSigners = IntPtr.Zero;
            IntPtr runtime = IntPtr.Zero;
            try
            {
                module = LoadLibrary(policyApiPath);
                if (module == IntPtr.Zero)
                {
                    errors.Add("LoadLibrary policy API failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return 0xE0010006;
                }

                IntPtr proc = GetProcAddress(module, "DpPolicySetUserHookDefensePolicy");
                if (proc == IntPtr.Zero)
                {
                    errors.Add("DpPolicySetUserHookDefensePolicy export was not found.");
                    return 0xE0010006;
                }

                DpPolicySetUserHookDefensePolicyDelegate setPolicy =
                    (DpPolicySetUserHookDefensePolicyDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(DpPolicySetUserHookDefensePolicyDelegate));
                excludedNames = Marshal.StringToHGlobalUni(string.Empty);
                excludedDirectories = Marshal.StringToHGlobalUni(@"\Windows\System32\");
                excludedPaths = Marshal.StringToHGlobalUni(string.Empty);
                trustedSigners = Marshal.StringToHGlobalUni(string.Empty);
                runtime = Marshal.StringToHGlobalUni(runtimePath ?? string.Empty);
                NativeUserHookDefensePolicy policy = new NativeUserHookDefensePolicy
                {
                    Flags = 0x00000001u | 0x00000002u | 0x00000004u | 0x00000020u | 0x00000080u | 0x00000100u,
                    ExcludedProcessNames = excludedNames,
                    ExcludedProcessDirectories = excludedDirectories,
                    ExcludedProcessPaths = excludedPaths,
                    TrustedSignerSubjects = trustedSigners,
                    RuntimeDllPath = runtime
                };
                return setPolicy(ref policy);
            }
            catch (Exception ex)
            {
                errors.Add("Kernel user-hook policy apply exception: " + ex.Message);
                return 0xE0010006;
            }
            finally
            {
                if (excludedNames != IntPtr.Zero) Marshal.FreeHGlobal(excludedNames);
                if (excludedDirectories != IntPtr.Zero) Marshal.FreeHGlobal(excludedDirectories);
                if (excludedPaths != IntPtr.Zero) Marshal.FreeHGlobal(excludedPaths);
                if (trustedSigners != IntPtr.Zero) Marshal.FreeHGlobal(trustedSigners);
                if (runtime != IntPtr.Zero) Marshal.FreeHGlobal(runtime);
                if (module != IntPtr.Zero) FreeLibrary(module);
            }
        }

        private static List<KernelSensorEventRecord> DrainKernelSensorEvents(KernelSensorRecord sensor, List<BehaviorRecord> behaviors, List<string> errors)
        {
            List<KernelSensorEventRecord> records = new List<KernelSensorEventRecord>();
            if (sensor == null || !sensor.enabled || string.IsNullOrWhiteSpace(sensor.policyApiPath) || !File.Exists(sensor.policyApiPath))
            {
                return records;
            }

            IntPtr module = IntPtr.Zero;
            IntPtr stringBuffer = IntPtr.Zero;
            try
            {
                module = LoadLibrary(sensor.policyApiPath);
                if (module == IntPtr.Zero)
                {
                    errors.Add("LoadLibrary policy API for kernel event drain failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return records;
                }

                IntPtr proc = GetProcAddress(module, "DpPolicyQueryUserHookDefenseEvents");
                if (proc == IntPtr.Zero)
                {
                    errors.Add("DpPolicyQueryUserHookDefenseEvents export was not found.");
                    return records;
                }

                DpPolicyQueryUserHookDefenseEventsDelegate query =
                    (DpPolicyQueryUserHookDefenseEventsDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(DpPolicyQueryUserHookDefenseEventsDelegate));
                uint eventCount;
                uint stringCharsRequired;
                uint result = query(new NativeUserHookDefenseEvent[0], 0, out eventCount, IntPtr.Zero, 0, out stringCharsRequired);
                if (result != 0)
                {
                    errors.Add("Kernel event sizing query failed: 0x" + result.ToString("X8", CultureInfo.InvariantCulture));
                    return records;
                }

                NativeUserHookDefenseEvent[] nativeEvents = new NativeUserHookDefenseEvent[Math.Min((int)eventCount, 2048)];
                int byteCount = checked((int)Math.Max(1u, stringCharsRequired) * sizeof(char));
                stringBuffer = Marshal.AllocHGlobal(byteCount);
                ClearMemory(stringBuffer, byteCount);
                result = query(nativeEvents, (uint)nativeEvents.Length, out eventCount, stringBuffer, Math.Max(1u, stringCharsRequired), out stringCharsRequired);
                if (result != 0)
                {
                    errors.Add("Kernel event query failed: 0x" + result.ToString("X8", CultureInfo.InvariantCulture));
                    return records;
                }

                int count = Math.Min(nativeEvents.Length, (int)eventCount);
                for (int index = 0; index < count; index++)
                {
                    KernelSensorEventRecord record = KernelSensorEventRecord.From(nativeEvents[index]);
                    records.Add(record);
                    AddKernelBehavior(record, behaviors);
                }
            }
            catch (Exception ex)
            {
                errors.Add("Kernel event drain failed: " + ex.Message);
            }
            finally
            {
                if (stringBuffer != IntPtr.Zero) Marshal.FreeHGlobal(stringBuffer);
                if (module != IntPtr.Zero) FreeLibrary(module);
            }

            return records;
        }

        private static void AddKernelBehavior(KernelSensorEventRecord record, List<BehaviorRecord> behaviors)
        {
            if (record == null || IsInternalTelemetryText(record.processImage) || IsInternalTelemetryText(record.target) || IsInternalTelemetryText(record.description))
            {
                return;
            }

            if (IsKernelEvidenceNoise(record))
            {
                return;
            }

            string type = string.Empty;
            string severity = string.Empty;
            if (record.operation == 9 || record.operation == 5)
            {
                type = "kernel-runtime-injection-risk";
                severity = "medium";
            }
            else if (record.operation == 11 || record.operation == 12)
            {
                if (IsCredentialKernelAccess(record))
                {
                    type = "credential-process-access";
                    severity = "high";
                }
                else if (HasCrossProcessInjectionAccess(record))
                {
                    type = "cross-process-injection-evidence";
                    severity = "medium";
                }
            }
            else if (record.operation == 15)
            {
                type = "cross-process-execution";
                severity = IsKnownBenignKernelRelationship(record) ? "medium" : "high";
            }
            else if (record.operation == 13 || record.operation == 14)
            {
                type = "module-reload-evasion";
                severity = "critical";
            }

            if (!string.IsNullOrWhiteSpace(type))
            {
                AddBehavior(behaviors, type, severity, record.description, record.pid);
            }
        }

        private static List<RuntimeEventRecord> ReadRuntimeEvents(string path, List<BehaviorRecord> behaviors, List<string> errors)
        {
            List<RuntimeEventRecord> records = new List<RuntimeEventRecord>();
            try
            {
                if (!File.Exists(path))
                {
                    return records;
                }

                FileInfo info = new FileInfo(path);
                if (info.Length > MaxRuntimeEventBytes)
                {
                    errors.Add("Runtime event log exceeded telemetry limit and was truncated.");
                }

                foreach (string line in File.ReadLines(path).Take(4096))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    try
                    {
                        Dictionary<string, object> item = Serializer.Deserialize<Dictionary<string, object>>(line);
                        RuntimeEventRecord record = RuntimeEventRecord.From(item);
                        records.Add(record);
                        AddRuntimeBehavior(record, behaviors);
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Add("Runtime event read failed: " + ex.Message);
            }

            return records;
        }

        private static void AddRuntimeBehavior(RuntimeEventRecord record, List<BehaviorRecord> behaviors)
        {
            if (record == null ||
                string.IsNullOrWhiteSpace(record.action) ||
                IsInternalTelemetryText(record.action) ||
                IsInternalTelemetryText(record.processImage) ||
                IsInternalTelemetryText(record.target))
            {
                return;
            }

            string severity = "medium";
            string type = "api-hook-event";
            if (record.action.IndexOf("create-hook-failed", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return;
            }

            if (record.action.Contains("blocked"))
            {
                severity = "high";
                type = "blocked-injection-primitive";
            }
            else if (record.action.Contains("unhook") || record.action.Contains("hook-overwrite"))
            {
                severity = "critical";
                type = "hook-tamper";
            }
            else if (record.action.Contains("syscall"))
            {
                severity = "high";
                type = "syscall-bypass-risk";
            }
            else if (record.action.Contains("manual-map") ||
                     record.action.Contains("memory-private-executable") ||
                     record.action.Contains("memory-private-syscall-stub"))
            {
                severity = "high";
                type = "executable-memory";
            }
            else if (record.action.Contains("memory-rwx"))
            {
                return;
            }
            else if (record.action.Contains("network"))
            {
                severity = "medium";
                type = "network-api";
            }
            else if (record.action.Contains("registry"))
            {
                severity = "high";
                type = "registry-write";
            }
            else if (record.action.Contains("load-library"))
            {
                severity = "low";
                type = "module-load";
            }

            AddBehavior(behaviors, type, severity, record.action + ": " + record.target, record.pid);
        }

        private static List<ProcessRecord> CollectProcessRecords(int rootPid, Snapshot before, Snapshot after)
        {
            List<ProcessRecord> tree = CollectProcessTree(rootPid);
            if (tree.Count > 0)
            {
                return tree;
            }

            return after.Processes.Values
                .Where(item => !before.Processes.ContainsKey(item.pid))
                .OrderBy(item => item.createdUtc)
                .Take(512)
                .ToList();
        }

        private static List<ProcessRecord> CollectProcessTree(int rootPid)
        {
            Dictionary<int, ProcessRecord> all = QueryProcesses();
            HashSet<int> tree = new HashSet<int>();
            if (rootPid > 0)
            {
                tree.Add(rootPid);
            }

            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (ProcessRecord record in all.Values)
                {
                    if (tree.Contains(record.parentPid) && tree.Add(record.pid))
                    {
                        changed = true;
                    }
                }
            }

            return all.Values.Where(item => tree.Contains(item.pid)).OrderBy(item => item.createdUtc).ToList();
        }

        private static Dictionary<int, ProcessRecord> QueryProcesses()
        {
            Dictionary<int, ProcessRecord> records = new Dictionary<int, ProcessRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate FROM Win32_Process"))
                {
                    foreach (ManagementObject process in searcher.Get())
                    {
                        int pid = Convert.ToInt32(process["ProcessId"], CultureInfo.InvariantCulture);
                        string path = Convert.ToString(process["ExecutablePath"], CultureInfo.InvariantCulture) ?? string.Empty;
                        records[pid] = new ProcessRecord
                        {
                            pid = pid,
                            parentPid = Convert.ToInt32(process["ParentProcessId"] ?? 0, CultureInfo.InvariantCulture),
                            name = Convert.ToString(process["Name"], CultureInfo.InvariantCulture) ?? string.Empty,
                            path = path,
                            commandLine = Truncate(Convert.ToString(process["CommandLine"], CultureInfo.InvariantCulture) ?? string.Empty, 2048),
                            createdUtc = ConvertWmiTime(process["CreationDate"]),
                            signature = GetSignature(path)
                        };
                    }
                }
            }
            catch
            {
            }

            return records;
        }

        private static List<NetworkRecord> CollectNetworkRecords(List<ProcessRecord> processes)
        {
            HashSet<int> pids = new HashSet<int>(processes.Select(item => item.pid));
            List<NetworkRecord> records = new List<NetworkRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess FROM MSFT_NetTCPConnection"))
                {
                    foreach (ManagementObject connection in searcher.Get())
                    {
                        int pid = Convert.ToInt32(connection["OwningProcess"] ?? 0, CultureInfo.InvariantCulture);
                        if (!pids.Contains(pid))
                        {
                            continue;
                        }

                        string remoteAddress = Convert.ToString(connection["RemoteAddress"], CultureInfo.InvariantCulture) ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(remoteAddress) || remoteAddress == "0.0.0.0" || remoteAddress == "::")
                        {
                            continue;
                        }

                        records.Add(new NetworkRecord
                        {
                            pid = pid,
                            localAddress = Convert.ToString(connection["LocalAddress"], CultureInfo.InvariantCulture) ?? string.Empty,
                            localPort = Convert.ToInt32(connection["LocalPort"] ?? 0, CultureInfo.InvariantCulture),
                            remoteAddress = remoteAddress,
                            remotePort = Convert.ToInt32(connection["RemotePort"] ?? 0, CultureInfo.InvariantCulture),
                            state = Convert.ToString(connection["State"], CultureInfo.InvariantCulture) ?? string.Empty,
                            timeUtc = DateTime.UtcNow.ToString("o")
                        });
                    }
                }
            }
            catch
            {
            }

            return records;
        }

        private static List<FileArtifactRecord> EnumerateArtifacts(string workspace, List<BehaviorRecord> behaviors, List<string> errors)
        {
            List<FileArtifactRecord> records = new List<FileArtifactRecord>();
            try
            {
                foreach (string file in Directory.EnumerateFiles(workspace, "*", SearchOption.AllDirectories).Take(512))
                {
                    FileInfo info = new FileInfo(file);
                    records.Add(new FileArtifactRecord
                    {
                        path = file.Replace(workspace, "<workspace>"),
                        size = info.Length,
                        modifiedUtc = info.LastWriteTimeUtc.ToString("o"),
                        sha256 = info.Length <= 50 * 1024 * 1024 ? ComputeSha256(file) : string.Empty
                    });
                }
            }
            catch (Exception ex)
            {
                errors.Add("Artifact enumeration failed: " + ex.Message);
            }

            if (records.Count > 1)
            {
                AddBehavior(behaviors, "file-artifacts", "medium", "Sample left " + records.Count.ToString(CultureInfo.InvariantCulture) + " file artifact(s) in the workspace.", 0);
            }

            return records;
        }

        private static List<RegistryRecord> CompareRegistry(Dictionary<string, string> before, Dictionary<string, string> after, List<BehaviorRecord> behaviors)
        {
            List<RegistryRecord> records = new List<RegistryRecord>();
            foreach (KeyValuePair<string, string> pair in after)
            {
                string oldValue;
                if (!before.TryGetValue(pair.Key, out oldValue) || oldValue != pair.Value)
                {
                    records.Add(new RegistryRecord { path = pair.Key, value = pair.Value, change = before.ContainsKey(pair.Key) ? "modified" : "created" });
                    AddBehavior(behaviors, "registry-persistence", "high", "Autorun value changed: " + pair.Key, 0);
                }
            }

            return records;
        }

        private static List<ServiceRecord> CompareServices(Dictionary<string, ServiceRecord> before, Dictionary<string, ServiceRecord> after, List<BehaviorRecord> behaviors)
        {
            List<ServiceRecord> records = new List<ServiceRecord>();
            foreach (KeyValuePair<string, ServiceRecord> pair in after)
            {
                ServiceRecord old;
                if (!before.TryGetValue(pair.Key, out old))
                {
                    pair.Value.change = "created";
                    records.Add(pair.Value);
                    AddBehavior(behaviors, pair.Value.serviceType.IndexOf("Kernel", StringComparison.OrdinalIgnoreCase) >= 0 ? "kernel-driver-installed" : "service-installed", "critical", "Service or driver created: " + pair.Value.name, 0);
                }
                else if (!string.Equals(old.pathName, pair.Value.pathName, StringComparison.OrdinalIgnoreCase) || !string.Equals(old.startMode, pair.Value.startMode, StringComparison.OrdinalIgnoreCase))
                {
                    pair.Value.change = "modified";
                    records.Add(pair.Value);
                    AddBehavior(behaviors, "service-modified", "high", "Service modified: " + pair.Value.name, 0);
                }
            }

            return records;
        }

        private static List<TaskRecord> CompareTasks(Dictionary<string, TaskRecord> before, Dictionary<string, TaskRecord> after, List<BehaviorRecord> behaviors)
        {
            List<TaskRecord> records = new List<TaskRecord>();
            foreach (KeyValuePair<string, TaskRecord> pair in after)
            {
                TaskRecord old;
                if (!before.TryGetValue(pair.Key, out old))
                {
                    pair.Value.change = "created";
                    records.Add(pair.Value);
                    AddBehavior(behaviors, "scheduled-task-persistence", "high", "Scheduled task created: " + pair.Value.name, 0);
                }
                else if (!string.Equals(old.command, pair.Value.command, StringComparison.OrdinalIgnoreCase))
                {
                    pair.Value.change = "modified";
                    records.Add(pair.Value);
                    AddBehavior(behaviors, "scheduled-task-modified", "high", "Scheduled task modified: " + pair.Value.name, 0);
                }
            }

            return records;
        }

        private static void AddRuleDetections(List<ProcessRecord> processes, List<NetworkRecord> network, List<RuntimeEventRecord> runtimeEvents, List<KernelSensorEventRecord> kernelEvents, List<ServiceRecord> services, List<TaskRecord> tasks, List<BehaviorRecord> behaviors)
        {
            HashSet<int> sampleTreePids = new HashSet<int>(processes.Where(item => !IsBenignSystemProcessName(item.name)).Select(item => item.pid));
            bool hasMaliciousCommand = processes.Any(IsHighRiskProcessCommand);
            bool hasScriptOrLolbinIntent = processes.Any(IsSuspiciousScriptOrLolbinProcess);
            bool hasCredentialAccess = kernelEvents.Any(item => sampleTreePids.Contains(item.pid) && IsCredentialKernelAccess(item) && !IsKernelEvidenceNoise(item)) ||
                                       processes.Any(HasCredentialCommandIntent);
            bool hasInjectionChain = HasSampleInjectionChain(kernelEvents, runtimeEvents, sampleTreePids);

            foreach (ProcessRecord process in processes)
            {
                AnalyzeProcess(process, behaviors);
            }

            foreach (NetworkRecord connection in network)
            {
                if (sampleTreePids.Contains(connection.pid) && (hasScriptOrLolbinIntent || IsPublicRemoteAddress(connection.remoteAddress)))
                {
                    AddBehavior(behaviors, "network-connection", "medium", "Remote connection: " + connection.remoteAddress + ":" + connection.remotePort.ToString(CultureInfo.InvariantCulture), connection.pid);
                }
            }

            if (runtimeEvents.Any(item => item.action != null &&
                                          (item.action.Contains("unhook") || item.action.Contains("hook-overwrite"))))
            {
                AddBehavior(behaviors, "anti-hook-evasion", "critical", "Runtime hook tampering was observed.", 0);
            }

            if (kernelEvents.Any(item => (item.operation == 13 || item.operation == 14) && !IsKernelEvidenceNoise(item)))
            {
                AddBehavior(behaviors, "native-module-reload-evasion", "critical", "Kernel sensor observed suspicious reload or abnormal path for a sensitive module.", 0);
            }

            if (services.Any(item => item.serviceType.IndexOf("Kernel", StringComparison.OrdinalIgnoreCase) >= 0 && IsSuspiciousPersistenceCommand(item.pathName)))
            {
                AddBehavior(behaviors, "kernel-driver-activity", "critical", "Kernel driver service activity was observed.", 0);
            }

            if (tasks.Any(item => IsSuspiciousPersistenceCommand(item.command)))
            {
                AddBehavior(behaviors, "persistence", "high", "Scheduled task persistence activity was observed.", 0);
            }

            if (hasCredentialAccess)
            {
                AddBehavior(behaviors, "credential-access", "critical", "Credential material or credential process access was observed.", 0);
            }

            if (hasInjectionChain)
            {
                AddBehavior(behaviors, "process-injection-chain", "critical", "Cross-process injection sequence was observed in the sample process tree.", 0);
            }

            if (hasMaliciousCommand)
            {
                AddBehavior(behaviors, "malicious-command-line", "critical", "Sample process tree executed a high-risk command line.", 0);
            }
        }

        private static void AnalyzeProcess(ProcessRecord process, List<BehaviorRecord> behaviors)
        {
            string name = (process.name ?? string.Empty).ToLowerInvariant();
            string cmd = (process.commandLine ?? string.Empty).ToLowerInvariant();
            if (IsSuspiciousScriptOrLolbinProcess(process))
            {
                AddBehavior(behaviors, "script-or-lolbin-execution", "medium", "Interpreter or loader launched: " + process.name, process.pid);
            }

            if (IsAdministrativeToolWithRiskyIntent(name, cmd))
            {
                AddBehavior(behaviors, "system-abuse-tool", "high", "Administrative tool launched: " + process.name, process.pid);
            }

            if (IsHighRiskProcessCommand(process))
            {
                AddBehavior(behaviors, "high-risk-command-line", "critical", Truncate(process.commandLine, 512), process.pid);
            }

            if (cmd.Contains("vbox") || cmd.Contains("vmware") || cmd.Contains("sandbox") || cmd.Contains("qemu") || cmd.Contains("debug") || cmd.Contains("wireshark") || cmd.Contains("procmon"))
            {
                AddBehavior(behaviors, "environment-probe", "medium", Truncate(process.commandLine, 512), process.pid);
            }
        }

        private static void AddBehavior(List<BehaviorRecord> behaviors, string type, string severity, string detail, int pid)
        {
            if (IsInternalTelemetryText(detail))
            {
                return;
            }

            behaviors.Add(new BehaviorRecord
            {
                type = type,
                severity = severity,
                detail = Truncate(detail ?? string.Empty, 1024),
                pid = pid,
                timeUtc = DateTime.UtcNow.ToString("o")
            });
        }

        private static void RemoveInternalTelemetryNoise(
            List<BehaviorRecord> behaviors,
            List<ProcessRecord> processes,
            List<NetworkRecord> network,
            List<FileArtifactRecord> artifacts,
            List<RuntimeEventRecord> runtimeEvents,
            List<KernelSensorEventRecord> kernelEvents,
            List<ServiceRecord> services,
            List<TaskRecord> tasks)
        {
            HashSet<int> internalPids = new HashSet<int>(
                processes.Where(IsInternalProcess).Select(item => item.pid));

            behaviors.RemoveAll(item =>
                item == null ||
                internalPids.Contains(item.pid) ||
                IsBenignBehaviorNoise(item) ||
                IsInternalTelemetryText(item.type) ||
                IsInternalTelemetryText(item.detail));
            network.RemoveAll(item => item == null || internalPids.Contains(item.pid));
            runtimeEvents.RemoveAll(item =>
                item == null ||
                internalPids.Contains(item.pid) ||
                IsInternalTelemetryText(item.processImage) ||
                IsInternalTelemetryText(item.target) ||
                IsInternalTelemetryText(item.action));
            kernelEvents.RemoveAll(item =>
                item == null ||
                internalPids.Contains(item.pid) ||
                IsInternalTelemetryText(item.processImage) ||
                IsInternalTelemetryText(item.target) ||
                IsInternalTelemetryText(item.description));
            artifacts.RemoveAll(item => item == null || IsInternalTelemetryText(item.path));
            services.RemoveAll(item =>
                item == null ||
                IsInternalTelemetryText(item.name) ||
                IsInternalTelemetryText(item.displayName) ||
                IsInternalTelemetryText(item.pathName));
            tasks.RemoveAll(item => item == null || IsInternalTelemetryText(item.command));
            processes.RemoveAll(item => item == null || internalPids.Contains(item.pid) || IsInternalProcess(item));
        }

        private static bool IsBenignBehaviorNoise(BehaviorRecord behavior)
        {
            if (behavior == null)
            {
                return true;
            }

            string type = behavior.type ?? string.Empty;
            string detail = behavior.detail ?? string.Empty;
            return type.Equals("kernel-process-telemetry", StringComparison.OrdinalIgnoreCase) ||
                   type.Equals("kernel-early-injection-queued", StringComparison.OrdinalIgnoreCase) ||
                   IsKnownBenignKernelText(detail);
        }

        private static bool IsInternalProcess(ProcessRecord process)
        {
            if (process == null)
            {
                return false;
            }

            return IsInternalTelemetryText(process.name) ||
                   IsInternalTelemetryText(process.path) ||
                   IsInternalTelemetryText(process.commandLine);
        }

        private static bool IsInternalTelemetryText(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string text = value.ToLowerInvariant();
            return text.Contains("dataprotectorsandboxtelemetry") ||
                   text.Contains("dataprotectorsandbox") ||
                   text.Contains("dataprotectoruserhookruntime") ||
                   text.Contains("dataprotectorpolicyapi") ||
                   text.Contains("dataprotector.sys") ||
                   text.Contains("dataprotectorsandbox.sys") ||
                   text.Contains("dataprotector\\sandbox") ||
                   text.Contains("\\dataprotector\\userhook") ||
                   text.Contains("userhook.observed") ||
                   text.Contains("sandbox-kernel-sensor") ||
                   text.Contains("kernel-early-injection-policy");
        }

        private static bool IsKernelEvidenceNoise(KernelSensorEventRecord record)
        {
            if (record == null)
            {
                return true;
            }

            return IsKnownBenignKernelRelationship(record) ||
                   (IsQueryOnlyProcessAccess(record) && !IsCredentialKernelAccess(record)) ||
                   IsKnownBenignKernelText(record.description);
        }

        private static bool IsKnownBenignKernelRelationship(KernelSensorEventRecord record)
        {
            string source = ExtractKernelField(record == null ? string.Empty : record.description, "source=");
            string target = ExtractKernelField(record == null ? string.Empty : record.description, "target=");
            string sourceName = NormalizeProcessName(source);
            string targetName = NormalizeProcessName(target);

            if (IsInternalTelemetryText(source) || IsInternalTelemetryText(target))
            {
                return true;
            }

            if (IsOneOf(sourceName, "wmiprvse.exe", "wmiadap.exe", "wmiapsrv.exe", "svchost.exe", "explorer.exe", "conhost.exe", "taskhostw.exe", "dllhost.exe"))
            {
                return true;
            }

            if (sourceName == "schtasks.exe" && targetName == "conhost.exe")
            {
                return true;
            }

            if (sourceName == "conhost.exe" && (targetName == "cmd.exe" || targetName == "powershell.exe" || targetName == "schtasks.exe"))
            {
                return true;
            }

            return false;
        }

        private static bool IsKnownBenignKernelText(string value)
        {
            string text = (value ?? string.Empty).ToLowerInvariant();
            return text.Contains("runtime-injection-skipped") ||
                   text.Contains("runtime-injection-queued") ||
                   text.Contains("hook-surface-image-load") ||
                   text.Contains("\\device\\vmsmb\\") ||
                   text.Contains("\\windows\\system32\\ntdll.dll") ||
                   text.Contains("\\windows\\system32\\kernel32.dll") ||
                   text.Contains("\\windows\\system32\\kernelbase.dll");
        }

        private static bool IsQueryOnlyProcessAccess(KernelSensorEventRecord record)
        {
            if (record == null || (record.operation != 11 && record.operation != 12))
            {
                return false;
            }

            int access = ParseHexField(record.description, "access=");
            if (access == 0)
            {
                return false;
            }

            return (access & unchecked((int)0xFFE00000)) == 0 &&
                   (access & unchecked((int)0x001FA3ED)) == 0 &&
                   (access & unchecked((int)0x0000002A)) == 0 &&
                   (access == 0x00001410 || access == 0x00001400 || access == 0x00001000 || access == 0x00000410);
        }

        private static bool HasCrossProcessInjectionAccess(KernelSensorEventRecord record)
        {
            if (record == null || (record.operation != 11 && record.operation != 12))
            {
                return false;
            }

            int access = ParseHexField(record.description, "access=");
            return (access & 0x00000002) != 0 ||
                   (access & 0x00000008) != 0 ||
                   (access & 0x00000020) != 0 ||
                   (access & 0x00000040) != 0 ||
                   (access & 0x00000200) != 0 ||
                   (access & 0x00000400) != 0 ||
                   access == 0x001FFFFF ||
                   access == 0x001F3FFF ||
                   access == 0x001F0FFF;
        }

        private static bool IsCredentialKernelAccess(KernelSensorEventRecord record)
        {
            if (record == null || (record.operation != 11 && record.operation != 12))
            {
                return false;
            }

            string text = (record.description ?? string.Empty).ToLowerInvariant();
            return text.Contains("target=lsass.exe") ||
                   text.Contains("target=sam") ||
                   text.Contains("target=security") ||
                   text.Contains("target=system");
        }

        private static bool HasSampleInjectionChain(List<KernelSensorEventRecord> kernelEvents, List<RuntimeEventRecord> runtimeEvents, HashSet<int> sampleTreePids)
        {
            if (kernelEvents == null || sampleTreePids == null || sampleTreePids.Count == 0)
            {
                return false;
            }

            bool processAccess = kernelEvents.Any(item => sampleTreePids.Contains(item.pid) && HasCrossProcessInjectionAccess(item));
            bool remoteThread = kernelEvents.Any(item => sampleTreePids.Contains(item.pid) && item.operation == 15 && !IsKernelEvidenceNoise(item));
            bool memoryWrite = runtimeEvents != null && runtimeEvents.Any(item => sampleTreePids.Contains(item.pid) &&
                ((item.action ?? string.Empty).IndexOf("write-process-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 (item.action ?? string.Empty).IndexOf("nt-write-virtual-memory", StringComparison.OrdinalIgnoreCase) >= 0));
            bool executableMemory = runtimeEvents != null && runtimeEvents.Any(item => sampleTreePids.Contains(item.pid) &&
                ((item.action ?? string.Empty).IndexOf("remote-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 (item.action ?? string.Empty).IndexOf("nt-allocate-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 (item.action ?? string.Empty).IndexOf("nt-protect-executable-memory", StringComparison.OrdinalIgnoreCase) >= 0));

            return remoteThread && (processAccess || memoryWrite || executableMemory);
        }

        private static bool IsSuspiciousScriptOrLolbinProcess(ProcessRecord process)
        {
            if (process == null)
            {
                return false;
            }

            string name = NormalizeProcessName(process.name);
            string cmd = (process.commandLine ?? string.Empty).ToLowerInvariant();
            if (!IsOneOf(name, "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe"))
            {
                return false;
            }

            return ContainsAny(cmd,
                "-enc", "-encodedcommand", "downloadstring", "frombase64string", "invoke-expression", " iex ",
                "http://", "https://", "javascript:", "vbscript:", "scrobj.dll", "urlcache", "/i:", "shellcode",
                "bypass", "hidden", "regsvr32", "rundll32", "mshta");
        }

        private static bool IsAdministrativeToolWithRiskyIntent(string name, string cmd)
        {
            name = NormalizeProcessName(name);
            cmd = (cmd ?? string.Empty).ToLowerInvariant();
            if (!IsOneOf(name, "schtasks.exe", "sc.exe", "reg.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wevtutil.exe", "wmic.exe", "bitsadmin.exe", "certutil.exe"))
            {
                return false;
            }

            return IsSuspiciousPersistenceCommand(cmd) ||
                   HasCredentialCommandIntent(cmd) ||
                   ContainsAny(cmd, "delete shadows", "shadowcopy delete", "resize shadowstorage", "wbadmin delete", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "cl ", "clear-log", "/create", "process call create", "urlcache", "download");
        }

        private static bool IsHighRiskProcessCommand(ProcessRecord process)
        {
            if (process == null)
            {
                return false;
            }

            string cmd = (process.commandLine ?? string.Empty).ToLowerInvariant();
            return HasCredentialCommandIntent(process) ||
                   ContainsAny(cmd, "shadowcopy delete", "delete shadows", "resize shadowstorage", "wbadmin delete", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "encodedcommand", "downloadstring", "frombase64string", "sekurlsa", "privilege::debug", "lsadump::", "token::", "procdump", "comsvcs.dll", "minidump");
        }

        private static bool HasCredentialCommandIntent(ProcessRecord process)
        {
            return process != null && HasCredentialCommandIntent(process.commandLine);
        }

        private static bool HasCredentialCommandIntent(string commandLine)
        {
            string cmd = (commandLine ?? string.Empty).ToLowerInvariant();
            return ContainsAny(cmd,
                "sekurlsa", "lsadump", "privilege::debug", "token::", "vault::", "kerberos::",
                "hklm\\sam", "hklm\\system", "hklm\\security", "reg save hklm\\sam", "reg save hklm\\system",
                "ntds.dit", "lsass", "comsvcs.dll", "minidump", "procdump");
        }

        private static bool IsSuspiciousPersistenceCommand(string commandLine)
        {
            string cmd = (commandLine ?? string.Empty).ToLowerInvariant();
            return ContainsAny(cmd,
                "currentversion\\run", "\\runonce", "startup", "schtasks /create", "schtasks.exe /create",
                " /create ", "sc create", "new-service", "create service", "start= auto", "autostart",
                "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "appdata", "\\temp\\", "\\users\\public\\");
        }

        private static bool IsBenignSystemProcessName(string name)
        {
            name = NormalizeProcessName(name);
            return IsOneOf(name,
                "wmiprvse.exe", "wmiadap.exe", "wmiapsrv.exe", "svchost.exe", "explorer.exe", "conhost.exe",
                "taskhostw.exe", "dllhost.exe", "runtimebroker.exe", "searchhost.exe", "sihost.exe", "ctfmon.exe",
                "fontdrvhost.exe", "dwm.exe", "spoolsv.exe", "wudfhost.exe", "smartscreen.exe");
        }

        private static bool IsPublicRemoteAddress(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string text = value.Trim().ToLowerInvariant();
            return !(text == "127.0.0.1" ||
                     text == "::1" ||
                     text.StartsWith("10.", StringComparison.Ordinal) ||
                     text.StartsWith("192.168.", StringComparison.Ordinal) ||
                     text.StartsWith("172.16.", StringComparison.Ordinal) ||
                     text.StartsWith("172.17.", StringComparison.Ordinal) ||
                     text.StartsWith("172.18.", StringComparison.Ordinal) ||
                     text.StartsWith("172.19.", StringComparison.Ordinal) ||
                     text.StartsWith("172.2", StringComparison.Ordinal) ||
                     text.StartsWith("172.30.", StringComparison.Ordinal) ||
                     text.StartsWith("172.31.", StringComparison.Ordinal) ||
                     text.StartsWith("fe80:", StringComparison.Ordinal));
        }

        private static bool ContainsAny(string value, params string[] tokens)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return tokens.Any(token => value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static string ExtractKernelField(string text, string prefix)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prefix))
            {
                return string.Empty;
            }

            int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return string.Empty;
            }

            index += prefix.Length;
            int end = text.IndexOf(' ', index);
            if (end < 0)
            {
                end = text.Length;
            }

            return text.Substring(index, end - index).Trim();
        }

        private static int ParseHexField(string text, string prefix)
        {
            string value = ExtractKernelField(text, prefix);
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                value = value.Substring(2);
            }

            int parsed;
            return int.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed) ? parsed : 0;
        }

        private static string NormalizeProcessName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string name = value.Trim().Trim('"').ToLowerInvariant();
            try
            {
                name = Path.GetFileName(name);
            }
            catch
            {
            }

            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && name.IndexOf('.') < 0)
            {
                name += ".exe";
            }

            return name;
        }

        private static SignatureRecord GetSignature(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return new SignatureRecord { status = "Unknown", signer = string.Empty };
            }

            try
            {
                System.Security.Cryptography.X509Certificates.X509Certificate certificate =
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                return new SignatureRecord { status = "Signed", signer = certificate == null ? string.Empty : certificate.Subject };
            }
            catch
            {
                return new SignatureRecord { status = "Unsigned", signer = string.Empty };
            }
        }

        private static string TryReadSignerSubject(string path)
        {
            return GetSignature(path).signer;
        }

        private static string ComputeSha256(string path)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                using (FileStream stream = File.OpenRead(path))
                {
                    return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty).ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
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

        private static bool IsOneOf(string value, params string[] candidates)
        {
            return candidates.Any(item => string.Equals(value, item, StringComparison.OrdinalIgnoreCase));
        }

        private static string ConvertWmiTime(object value)
        {
            try
            {
                string text = Convert.ToString(value, CultureInfo.InvariantCulture);
                return string.IsNullOrWhiteSpace(text) ? string.Empty : ManagementDateTimeConverter.ToDateTime(text).ToUniversalTime().ToString("o");
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, max) + "...";
        }

        private static string Quote(string value)
        {
            return "\"" + (value ?? string.Empty).Replace("\"", "\\\"") + "\"";
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }

        private static JavaScriptSerializer CreateSerializer()
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = 32 * 1024 * 1024;
            serializer.RecursionLimit = 128;
            return serializer;
        }

        private static void ClearMemory(IntPtr destination, int length)
        {
            if (destination == IntPtr.Zero || length <= 0)
            {
                return;
            }

            byte[] zero = new byte[Math.Min(length, 8192)];
            int offset = 0;
            while (offset < length)
            {
                int chunk = Math.Min(zero.Length, length - offset);
                Marshal.Copy(zero, 0, destination + offset, chunk);
                offset += chunk;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr processHandle, IntPtr address, UIntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr processHandle, IntPtr address, UIntPtr size, uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UIntPtr size, out UIntPtr bytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr processHandle, IntPtr threadAttributes, UIntPtr stackSize, IntPtr startAddress, IntPtr parameter, uint creationFlags, IntPtr threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr processHandle, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr processHandle, uint exitCode);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr module);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr serviceControlManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateService(
            IntPtr serviceControlManager,
            string serviceName,
            string displayName,
            uint desiredAccess,
            uint serviceType,
            uint startType,
            uint errorControl,
            string binaryPathName,
            string loadOrderGroup,
            IntPtr tagId,
            string dependencies,
            string serviceStartName,
            string password);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(
            IntPtr service,
            uint serviceType,
            uint startType,
            uint errorControl,
            string binaryPathName,
            string loadOrderGroup,
            IntPtr tagId,
            string dependencies,
            string serviceStartName,
            string password,
            string displayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr service, int argumentCount, string[] arguments);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr serviceControlManagerObject);

        [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
        private static extern uint FilterLoad(string filterName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint DpPolicySetUserHookDefensePolicyDelegate(ref NativeUserHookDefensePolicy policy);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint DpPolicyQueryUserHookDefenseEventsDelegate(
            [Out] NativeUserHookDefenseEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeUserHookDefensePolicy
        {
            public uint Flags;
            public IntPtr ExcludedProcessNames;
            public IntPtr ExcludedProcessDirectories;
            public IntPtr ExcludedProcessPaths;
            public IntPtr TrustedSignerSubjects;
            public IntPtr RuntimeDllPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeUserHookDefenseEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public ulong ParentProcessId;
            public uint Operation;
            public uint Status;
            public uint Flags;
            public IntPtr Target;
            public IntPtr ProcessImage;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private sealed class Options
        {
            public string RunId { get; set; }
            public string SamplePath { get; set; }
            public string ReportPath { get; set; }
            public string RuntimePath { get; set; }
            public string KernelDriverPath { get; set; }
            public string PolicyApiPath { get; set; }
            public string Arguments { get; set; }
            public bool NetworkEnabled { get; set; }
            public int TimeoutSeconds { get; set; }

            public static Options Parse(string[] args)
            {
                Options options = new Options { TimeoutSeconds = DefaultTimeoutSeconds, RunId = Guid.NewGuid().ToString("N") };
                for (int index = 0; index < (args == null ? 0 : args.Length); index++)
                {
                    string name = args[index];
                    string value = index + 1 < args.Length ? args[index + 1] : string.Empty;
                    if (string.Equals(name, "--sample", StringComparison.OrdinalIgnoreCase)) { options.SamplePath = value; index++; }
                    else if (string.Equals(name, "--report", StringComparison.OrdinalIgnoreCase)) { options.ReportPath = value; index++; }
                    else if (string.Equals(name, "--runtime", StringComparison.OrdinalIgnoreCase)) { options.RuntimePath = value; index++; }
                    else if (string.Equals(name, "--kernel-driver", StringComparison.OrdinalIgnoreCase)) { options.KernelDriverPath = value; index++; }
                    else if (string.Equals(name, "--policy-api", StringComparison.OrdinalIgnoreCase)) { options.PolicyApiPath = value; index++; }
                    else if (string.Equals(name, "--arguments", StringComparison.OrdinalIgnoreCase)) { options.Arguments = value; index++; }
                    else if (string.Equals(name, "--run-id", StringComparison.OrdinalIgnoreCase)) { options.RunId = value; index++; }
                    else if (string.Equals(name, "--timeout", StringComparison.OrdinalIgnoreCase)) { int parsed; if (int.TryParse(value, out parsed)) options.TimeoutSeconds = Math.Max(15, Math.Min(parsed, 1800)); index++; }
                    else if (string.Equals(name, "--network", StringComparison.OrdinalIgnoreCase)) { bool parsed; if (bool.TryParse(value, out parsed)) options.NetworkEnabled = parsed; index++; }
                }

                return options;
            }
        }

        private sealed class SuspendedProcess : IDisposable
        {
            public int ProcessId { get; set; }
            public IntPtr ProcessHandle { get; set; }
            public IntPtr MainThreadHandle { get; set; }

            public void TerminateIfRunning(List<string> errors)
            {
                if (ProcessHandle == IntPtr.Zero)
                {
                    return;
                }

                if (WaitForSingleObject(ProcessHandle, 0) == 0)
                {
                    return;
                }

                if (!TerminateProcess(ProcessHandle, 1))
                {
                    errors.Add("Failed to terminate sample during cleanup: Win32=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                }
            }

            public void Dispose()
            {
                if (MainThreadHandle != IntPtr.Zero)
                {
                    CloseHandle(MainThreadHandle);
                    MainThreadHandle = IntPtr.Zero;
                }

                if (ProcessHandle != IntPtr.Zero)
                {
                    CloseHandle(ProcessHandle);
                    ProcessHandle = IntPtr.Zero;
                }
            }
        }

        private sealed class Snapshot
        {
            public Dictionary<int, ProcessRecord> Processes { get; set; }
            public Dictionary<string, string> Autoruns { get; set; }
            public Dictionary<string, ServiceRecord> Services { get; set; }
            public Dictionary<string, TaskRecord> Tasks { get; set; }

            public static Snapshot Capture(List<string> errors)
            {
                return new Snapshot
                {
                    Processes = QueryProcesses(),
                    Autoruns = QueryAutoruns(),
                    Services = QueryServices(errors),
                    Tasks = QueryTasks(errors)
                };
            }

            private static Dictionary<string, string> QueryAutoruns()
            {
                Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string[] roots =
                {
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                foreach (string root in roots)
                {
                    string hive = root.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
                    string subKey = root.Substring(hive.Length + 1);
                    Microsoft.Win32.RegistryKey baseKey = hive == "HKEY_CURRENT_USER" ? Microsoft.Win32.Registry.CurrentUser : Microsoft.Win32.Registry.LocalMachine;
                    try
                    {
                        using (Microsoft.Win32.RegistryKey key = baseKey.OpenSubKey(subKey))
                        {
                            if (key == null) continue;
                            foreach (string name in key.GetValueNames())
                            {
                                values[root + "\\" + name] = Convert.ToString(key.GetValue(name), CultureInfo.InvariantCulture) ?? string.Empty;
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                return values;
            }

            private static Dictionary<string, ServiceRecord> QueryServices(List<string> errors)
            {
                Dictionary<string, ServiceRecord> services = new Dictionary<string, ServiceRecord>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name,DisplayName,PathName,ServiceType,StartMode,State FROM Win32_Service"))
                    {
                        foreach (ManagementObject service in searcher.Get())
                        {
                            string name = Convert.ToString(service["Name"], CultureInfo.InvariantCulture) ?? string.Empty;
                            services[name] = new ServiceRecord
                            {
                                name = name,
                                displayName = Convert.ToString(service["DisplayName"], CultureInfo.InvariantCulture) ?? string.Empty,
                                pathName = Convert.ToString(service["PathName"], CultureInfo.InvariantCulture) ?? string.Empty,
                                serviceType = Convert.ToString(service["ServiceType"], CultureInfo.InvariantCulture) ?? string.Empty,
                                startMode = Convert.ToString(service["StartMode"], CultureInfo.InvariantCulture) ?? string.Empty,
                                state = Convert.ToString(service["State"], CultureInfo.InvariantCulture) ?? string.Empty
                            };
                        }
                    }
                }
                catch (Exception ex)
                {
                    errors.Add("Service WMI snapshot failed: " + ex.Message + ". Using registry fallback.");
                    QueryServicesFromRegistry(services, errors);
                }

                return services;
            }

            private static void QueryServicesFromRegistry(Dictionary<string, ServiceRecord> services, List<string> errors)
            {
                try
                {
                    using (Microsoft.Win32.RegistryKey root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    {
                        if (root == null)
                        {
                            return;
                        }

                        foreach (string name in root.GetSubKeyNames())
                        {
                            using (Microsoft.Win32.RegistryKey key = root.OpenSubKey(name))
                            {
                                if (key == null)
                                {
                                    continue;
                                }

                                int type = Convert.ToInt32(key.GetValue("Type", 0), CultureInfo.InvariantCulture);
                                if ((type & 0x00000001) == 0 && (type & 0x00000002) == 0 && (type & 0x00000010) == 0)
                                {
                                    continue;
                                }

                                services[name] = new ServiceRecord
                                {
                                    name = name,
                                    displayName = Convert.ToString(key.GetValue("DisplayName", name), CultureInfo.InvariantCulture) ?? name,
                                    pathName = Convert.ToString(key.GetValue("ImagePath", string.Empty), CultureInfo.InvariantCulture) ?? string.Empty,
                                    serviceType = ServiceTypeName(type),
                                    startMode = Convert.ToString(key.GetValue("Start", string.Empty), CultureInfo.InvariantCulture) ?? string.Empty,
                                    state = "unknown"
                                };
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    errors.Add("Service registry fallback failed: " + ex.Message);
                }
            }

            private static string ServiceTypeName(int type)
            {
                if ((type & 0x00000001) != 0 || (type & 0x00000002) != 0)
                {
                    return "Kernel Driver";
                }

                if ((type & 0x00000010) != 0)
                {
                    return "Own Process";
                }

                return type.ToString(CultureInfo.InvariantCulture);
            }

            private static Dictionary<string, TaskRecord> QueryTasks(List<string> errors)
            {
                Dictionary<string, TaskRecord> tasks = new Dictionary<string, TaskRecord>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = "/Query /FO CSV /V",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    using (Process process = Process.Start(psi))
                    {
                        string output = process == null ? string.Empty : process.StandardOutput.ReadToEnd();
                        if (process != null) process.WaitForExit(5000);
                        foreach (string line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Skip(1))
                        {
                            string[] cols = ParseCsvLine(line);
                            if (cols.Length < 2) continue;
                            string name = cols[0];
                            string command = cols.Length > 8 ? cols[8] : string.Empty;
                            tasks[name] = new TaskRecord { name = name, command = command, state = cols.Length > 3 ? cols[3] : string.Empty };
                        }
                    }
                }
                catch (Exception ex)
                {
                    errors.Add("Scheduled task snapshot failed: " + ex.Message);
                }

                return tasks;
            }
        }

        private static string[] ParseCsvLine(string line)
        {
            List<string> cols = new List<string>();
            StringBuilder current = new StringBuilder();
            bool quoted = false;
            foreach (char ch in line)
            {
                if (ch == '"')
                {
                    quoted = !quoted;
                    continue;
                }

                if (ch == ',' && !quoted)
                {
                    cols.Add(current.ToString());
                    current.Length = 0;
                    continue;
                }

                current.Append(ch);
            }

            cols.Add(current.ToString());
            return cols.ToArray();
        }

        private sealed class BehaviorComparer : IEqualityComparer<BehaviorRecord>
        {
            public bool Equals(BehaviorRecord x, BehaviorRecord y)
            {
                return x != null && y != null &&
                       string.Equals(x.type, y.type, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(x.detail, y.detail, StringComparison.OrdinalIgnoreCase) &&
                       x.pid == y.pid;
            }

            public int GetHashCode(BehaviorRecord obj)
            {
                return ((obj.type ?? string.Empty) + "|" + (obj.detail ?? string.Empty) + "|" + obj.pid.ToString(CultureInfo.InvariantCulture)).ToLowerInvariant().GetHashCode();
            }
        }

        private sealed class Report
        {
            public string schema { get; set; }
            public string isolation { get; set; }
            public string runId { get; set; }
            public string startedUtc { get; set; }
            public string completedUtc { get; set; }
            public SampleRecord sample { get; set; }
            public ExecutionRecord execution { get; set; }
            public TelemetryRecord telemetry { get; set; }
            public Dictionary<string, object> isolationControls { get; set; }
            public Dictionary<string, object> analysisHardening { get; set; }
            public List<BehaviorRecord> behaviors { get; set; }
            public List<ProcessRecord> processes { get; set; }
            public List<NetworkRecord> network { get; set; }
            public List<RegistryRecord> registryChanges { get; set; }
            public List<ServiceRecord> services { get; set; }
            public List<TaskRecord> scheduledTasks { get; set; }
            public List<RuntimeEventRecord> runtimeEvents { get; set; }
            public KernelSensorRecord kernelSensor { get; set; }
            public List<KernelSensorEventRecord> kernelEvents { get; set; }
            public List<FileArtifactRecord> fileArtifacts { get; set; }
            public string stdout { get; set; }
            public string stderr { get; set; }
            public List<string> errors { get; set; }
        }

        private sealed class SampleRecord
        {
            public string hostPath { get; set; }
            public string fileName { get; set; }
            public string sha256 { get; set; }
            public string architecture { get; set; }
            public string signer { get; set; }
            public string sandboxPath { get; set; }
        }

        private sealed class ExecutionRecord
        {
            public int pid { get; set; }
            public int exitCode { get; set; }
            public bool timedOut { get; set; }
            public int timeoutSeconds { get; set; }
            public long durationMs { get; set; }
        }

        private sealed class TelemetryRecord
        {
            public string mode { get; set; }
            public string runtimeHook { get; set; }
            public string runtimePath { get; set; }
            public bool runtimeInjected { get; set; }
            public string etwProcessProvider { get; set; }
            public string kernelSensor { get; set; }
            public string apiHookProvider { get; set; }
            public string memoryScan { get; set; }
            public string driverAndServiceDiff { get; set; }
            public string taskDiff { get; set; }
            public string autorunDiff { get; set; }
            public string fileArtifactDiff { get; set; }
        }

        private sealed class KernelSensorRecord
        {
            public bool enabled { get; set; }
            public string status { get; set; }
            public string serviceName { get; set; }
            public string driverPath { get; set; }
            public string policyApiPath { get; set; }
            public string runtimePath { get; set; }
            public string policyStatus { get; set; }
            public int win32 { get; set; }
            public string message { get; set; }
        }

        private sealed class BehaviorRecord
        {
            public string type { get; set; }
            public string severity { get; set; }
            public string detail { get; set; }
            public int pid { get; set; }
            public string timeUtc { get; set; }
        }

        private sealed class ProcessRecord
        {
            public int pid { get; set; }
            public int parentPid { get; set; }
            public string name { get; set; }
            public string path { get; set; }
            public string commandLine { get; set; }
            public string createdUtc { get; set; }
            public SignatureRecord signature { get; set; }
        }

        private sealed class SignatureRecord
        {
            public string status { get; set; }
            public string signer { get; set; }
        }

        private sealed class NetworkRecord
        {
            public int pid { get; set; }
            public string localAddress { get; set; }
            public int localPort { get; set; }
            public string remoteAddress { get; set; }
            public int remotePort { get; set; }
            public string state { get; set; }
            public string timeUtc { get; set; }
        }

        private sealed class RegistryRecord
        {
            public string path { get; set; }
            public string value { get; set; }
            public string change { get; set; }
        }

        private sealed class ServiceRecord
        {
            public string name { get; set; }
            public string displayName { get; set; }
            public string pathName { get; set; }
            public string serviceType { get; set; }
            public string startMode { get; set; }
            public string state { get; set; }
            public string change { get; set; }
        }

        private sealed class TaskRecord
        {
            public string name { get; set; }
            public string command { get; set; }
            public string state { get; set; }
            public string change { get; set; }
        }

        private sealed class RuntimeEventRecord
        {
            public string timestampUtc { get; set; }
            public string host { get; set; }
            public int pid { get; set; }
            public string action { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
            public string status { get; set; }
            public bool blocked { get; set; }

            public static RuntimeEventRecord From(Dictionary<string, object> item)
            {
                if (item == null) return new RuntimeEventRecord();
                return new RuntimeEventRecord
                {
                    timestampUtc = Get(item, "timestampUtc"),
                    host = Get(item, "host"),
                    pid = ToInt(Get(item, "pid")),
                    action = Get(item, "action"),
                    target = Get(item, "target"),
                    processImage = Get(item, "processImage"),
                    status = Get(item, "status"),
                    blocked = string.Equals(Get(item, "blocked"), "true", StringComparison.OrdinalIgnoreCase)
                };
            }

            private static string Get(Dictionary<string, object> item, string key)
            {
                object value;
                return item.TryGetValue(key, out value) && value != null ? Convert.ToString(value, CultureInfo.InvariantCulture) : string.Empty;
            }

            private static int ToInt(string value)
            {
                int parsed;
                return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : 0;
            }
        }

        private sealed class KernelSensorEventRecord
        {
            public ulong sequence { get; set; }
            public int pid { get; set; }
            public int parentPid { get; set; }
            public uint operation { get; set; }
            public string operationName { get; set; }
            public string status { get; set; }
            public string flags { get; set; }
            public string target { get; set; }
            public string processImage { get; set; }
            public string description { get; set; }

            public static KernelSensorEventRecord From(NativeUserHookDefenseEvent item)
            {
                string operationName = DescribeKernelOperation(item.Operation);
                string target = Marshal.PtrToStringUni(item.Target) ?? string.Empty;
                string processImage = Marshal.PtrToStringUni(item.ProcessImage) ?? string.Empty;
                return new KernelSensorEventRecord
                {
                    sequence = item.Sequence,
                    pid = unchecked((int)item.ProcessId),
                    parentPid = unchecked((int)item.ParentProcessId),
                    operation = item.Operation,
                    operationName = operationName,
                    status = "0x" + item.Status.ToString("X8", CultureInfo.InvariantCulture),
                    flags = "0x" + item.Flags.ToString("X8", CultureInfo.InvariantCulture),
                    target = target,
                    processImage = processImage,
                    description = operationName + ": " + target
                };
            }

            private static string DescribeKernelOperation(uint operation)
            {
                switch (operation)
                {
                    case 1: return "process-create";
                    case 2: return "hook-surface-image-load";
                    case 3: return "runtime-required";
                    case 4: return "runtime-missing";
                    case 5: return "runtime-rejected";
                    case 6: return "suspicious-hook-attempt";
                    case 7: return "runtime-injection-required";
                    case 8: return "runtime-injection-queued";
                    case 9: return "runtime-injection-failed";
                    case 10: return "runtime-injection-skipped";
                    case 11: return "process-access";
                    case 12: return "thread-access";
                    case 13: return "sensitive-image-reload";
                    case 14: return "sensitive-image-abnormal-path";
                    case 15: return "remote-thread-create";
                    default: return "kernel-event-" + operation.ToString(CultureInfo.InvariantCulture);
                }
            }
        }

        private sealed class FileArtifactRecord
        {
            public string path { get; set; }
            public long size { get; set; }
            public string modifiedUtc { get; set; }
            public string sha256 { get; set; }
        }
    }
}
