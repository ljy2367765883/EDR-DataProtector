using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class RemoteTaskExecutor
    {
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();
        private readonly object terminalSync = new object();
        private readonly Uri serverBaseUri;
        private readonly UsbCryptInitializer usbCryptInitializer = new UsbCryptInitializer();
        private readonly VirtualSandboxRunner virtualSandboxRunner = new VirtualSandboxRunner();
        private Process terminalProcess;
        private StringBuilder terminalBuffer = new StringBuilder();
        private int terminalSequence;

        public RemoteTaskExecutor()
        {
        }

        public RemoteTaskExecutor(Uri serverBaseUri)
        {
            this.serverBaseUri = serverBaseUri;
        }

        public CentralPolicyStore.RemoteTaskResult Execute(CentralPolicyStore.RemoteTaskDto task)
        {
            try
            {
                string output;
                int exitCode = 0;
                string kind = (task.kind ?? string.Empty).Trim();

                switch (kind)
                {
                    case "inventory.installedApps":
                        output = serializer.Serialize(QueryInstalledApps());
                        break;
                    case "inventory.startupItems":
                        output = serializer.Serialize(QueryStartupItems());
                        break;
                    case "process.list":
                        output = serializer.Serialize(QueryProcesses());
                        break;
                    case "process.kill":
                        output = KillProcess(ReadArgs(task.argumentsJson));
                        break;
                    case "file.drives":
                        output = serializer.Serialize(ListDrives());
                        break;
                    case "file.list":
                        output = serializer.Serialize(ListFiles(ReadArgs(task.argumentsJson)));
                        break;
                    case "file.delete":
                        output = DeleteFileSystemEntry(ReadArgs(task.argumentsJson));
                        break;
                    case "file.rename":
                        output = RenameFileSystemEntry(ReadArgs(task.argumentsJson));
                        break;
                    case "desktop.screenshot":
                        output = CaptureScreenshotBase64();
                        break;
                    case "session.lock":
                        output = LockWorkStation() ? "Workstation lock requested." : "LockWorkStation returned false.";
                        exitCode = output.StartsWith("Workstation", StringComparison.Ordinal) ? 0 : 1;
                        break;
                    case "cmd.run":
                        CommandResult command = RunCommand(ReadArgs(task.argumentsJson));
                        output = command.Output;
                        exitCode = command.ExitCode;
                        break;
                    case "terminal.start":
                        output = StartTerminal();
                        break;
                    case "terminal.input":
                        output = WriteTerminalInput(ReadArgs(task.argumentsJson));
                        break;
                    case "terminal.read":
                        output = ReadTerminal();
                        break;
                    case "terminal.stop":
                        output = StopTerminal();
                        break;
                    case "user.changePassword":
                        CommandResult password = ChangePassword(ReadArgs(task.argumentsJson));
                        output = password.Output;
                        exitCode = password.ExitCode;
                        break;
                    case "usbcrypt.initialize":
                        output = serializer.Serialize(InitializeUsbCrypt(task.argumentsJson));
                        break;
                    case "sandbox.run":
                        VirtualSandboxRunner.SandboxTaskResult sandbox = virtualSandboxRunner.Run(ReadArgs(task.argumentsJson));
                        output = sandbox.Output;
                        exitCode = sandbox.ExitCode;
                        break;
                    default:
                        throw new InvalidOperationException("Unsupported remote task kind: " + kind);
                }

                return new CentralPolicyStore.RemoteTaskResult
                {
                    taskId = task.taskId,
                    succeeded = exitCode == 0,
                    exitCode = exitCode,
                    output = output,
                    error = exitCode == 0 ? string.Empty : output
                };
            }
            catch (Exception ex)
            {
                return new CentralPolicyStore.RemoteTaskResult
                {
                    taskId = task.taskId,
                    succeeded = false,
                    exitCode = 1,
                    output = string.Empty,
                    error = ex.Message
                };
            }
        }

        private Dictionary<string, object> ReadArgs(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            }

            Dictionary<string, object> args = serializer.Deserialize<Dictionary<string, object>>(json);
            return args ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }

        private UsbCryptInitializer.UsbCryptInitializationResult InitializeUsbCrypt(string json)
        {
            UsbCryptInitializer.UsbCryptInitializationRequest request = string.IsNullOrWhiteSpace(json)
                ? null
                : serializer.Deserialize<UsbCryptInitializer.UsbCryptInitializationRequest>(json);
            return usbCryptInitializer.Initialize(request, AppDomain.CurrentDomain.BaseDirectory, serverBaseUri);
        }

        private object[] QueryInstalledApps()
        {
            List<InstalledAppInfo> apps = new List<InstalledAppInfo>();
            ReadInstalledApps(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", apps);
            ReadInstalledApps(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", apps);
            ReadInstalledApps(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", apps);
            return apps
                .OrderBy(app => app.displayName, StringComparer.OrdinalIgnoreCase)
                .Take(1000)
                .ToArray();
        }

        private static void ReadInstalledApps(RegistryKey root, string subKeyPath, List<InstalledAppInfo> apps)
        {
            using (RegistryKey uninstall = root.OpenSubKey(subKeyPath))
            {
                if (uninstall == null)
                {
                    return;
                }

                foreach (string name in uninstall.GetSubKeyNames())
                {
                    using (RegistryKey app = uninstall.OpenSubKey(name))
                    {
                        if (app == null)
                        {
                            continue;
                        }

                        string displayName = Convert.ToString(app.GetValue("DisplayName"));
                        if (string.IsNullOrWhiteSpace(displayName))
                        {
                            continue;
                        }

                        string iconPath = Convert.ToString(app.GetValue("DisplayIcon"));
                        apps.Add(new InstalledAppInfo
                        {
                            displayName = displayName,
                            displayVersion = Convert.ToString(app.GetValue("DisplayVersion")),
                            publisher = Convert.ToString(app.GetValue("Publisher")),
                            installLocation = Convert.ToString(app.GetValue("InstallLocation")),
                            uninstallString = Convert.ToString(app.GetValue("UninstallString")),
                            displayIcon = iconPath,
                            iconBase64 = TryReadIcon(iconPath)
                        });
                    }
                }
            }
        }

        private object[] QueryStartupItems()
        {
            List<object> items = new List<object>();
            ReadRunKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", items);
            ReadRunKey(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", items);
            ReadRunKey(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW6432 Run", items);
            ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup Folder", items);
            ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common Startup Folder", items);
            return items.ToArray();
        }

        private object[] QueryProcesses()
        {
            return Process.GetProcesses()
                .Select(process =>
                {
                    string fileName = string.Empty;
                    string userName = string.Empty;
                    DateTime? startTime = null;
                    long memoryBytes = 0;

                    try
                    {
                        fileName = process.MainModule == null ? string.Empty : process.MainModule.FileName;
                    }
                    catch
                    {
                    }

                    try
                    {
                        startTime = process.StartTime.ToUniversalTime();
                    }
                    catch
                    {
                    }

                    try
                    {
                        memoryBytes = process.WorkingSet64;
                    }
                    catch
                    {
                    }

                    return new
                    {
                        pid = process.Id,
                        name = process.ProcessName,
                        path = fileName,
                        user = userName,
                        memoryBytes = memoryBytes,
                        startTimeUtc = startTime.HasValue ? startTime.Value.ToString("o") : string.Empty
                    };
                })
                .OrderBy(process => process.name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(process => process.pid)
                .ToArray();
        }

        private string KillProcess(Dictionary<string, object> args)
        {
            int pid = ParseInt(GetArg(args, "pid", "0"), 0);
            if (pid <= 0)
            {
                throw new InvalidOperationException("A valid process id is required.");
            }

            Process process = Process.GetProcessById(pid);
            string name = process.ProcessName;
            process.Kill();
            process.WaitForExit(5000);
            return "Process terminated: " + name + " (" + pid + ")";
        }

        private object[] ListDrives()
        {
            return DriveInfo.GetDrives()
                .Select(drive =>
                {
                    bool ready = drive.IsReady;
                    return new
                    {
                        name = drive.Name,
                        path = drive.RootDirectory.FullName,
                        driveType = drive.DriveType.ToString(),
                        volumeLabel = ready ? drive.VolumeLabel : string.Empty,
                        fileSystem = ready ? drive.DriveFormat : string.Empty,
                        isReady = ready,
                        totalSize = ready ? drive.TotalSize : 0,
                        freeSpace = ready ? drive.AvailableFreeSpace : 0
                    };
                })
                .OrderBy(drive => drive.name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static void ReadRunKey(RegistryKey root, string subKeyPath, string location, List<object> items)
        {
            using (RegistryKey key = root.OpenSubKey(subKeyPath))
            {
                if (key == null)
                {
                    return;
                }

                foreach (string valueName in key.GetValueNames())
                {
                    items.Add(new
                    {
                        location = location,
                        name = valueName,
                        command = Convert.ToString(key.GetValue(valueName)),
                        enabled = true
                    });
                }
            }
        }

        private static void ReadStartupFolder(string folder, string location, List<object> items)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                return;
            }

            foreach (string file in Directory.GetFiles(folder))
            {
                items.Add(new
                {
                    location = location,
                    name = Path.GetFileName(file),
                    command = file,
                    enabled = true
                });
            }
        }

        private object[] ListFiles(Dictionary<string, object> args)
        {
            string path = GetArg(args, "path", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            int limit = Math.Max(1, Math.Min(ParseInt(GetArg(args, "limit", "200"), 200), 1000));
            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException(path);
            }

            return Directory.GetFileSystemEntries(path)
                .Select(entry =>
                {
                    FileAttributes attributes = File.GetAttributes(entry);
                    bool isDirectory = (attributes & FileAttributes.Directory) == FileAttributes.Directory;
                    long size = 0;
                    if (!isDirectory)
                    {
                        size = new FileInfo(entry).Length;
                    }

                    return new
                    {
                        name = Path.GetFileName(entry),
                        path = entry,
                        isDirectory = isDirectory,
                        size = size,
                        lastWriteUtc = File.GetLastWriteTimeUtc(entry).ToString("o")
                    };
                })
                .OrderByDescending(entry => entry.isDirectory)
                .ThenBy(entry => entry.name, StringComparer.OrdinalIgnoreCase)
                .Take(limit)
                .ToArray();
        }

        private string DeleteFileSystemEntry(Dictionary<string, object> args)
        {
            string path = GetRequiredPath(args, "path");
            if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
                return "Directory deleted: " + path;
            }

            if (File.Exists(path))
            {
                File.Delete(path);
                return "File deleted: " + path;
            }

            throw new FileNotFoundException("Path not found.", path);
        }

        private string RenameFileSystemEntry(Dictionary<string, object> args)
        {
            string path = GetRequiredPath(args, "path");
            string newName = GetArg(args, "newName", string.Empty);
            if (string.IsNullOrWhiteSpace(newName))
            {
                throw new InvalidOperationException("New name is required.");
            }

            if (newName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                throw new InvalidOperationException("New name contains invalid characters.");
            }

            string parent = Path.GetDirectoryName(path);
            if (string.IsNullOrWhiteSpace(parent))
            {
                throw new InvalidOperationException("Root paths cannot be renamed.");
            }

            string target = Path.Combine(parent, newName);
            if (Directory.Exists(path))
            {
                Directory.Move(path, target);
                return "Directory renamed: " + path + " -> " + target;
            }

            if (File.Exists(path))
            {
                File.Move(path, target);
                return "File renamed: " + path + " -> " + target;
            }

            throw new FileNotFoundException("Path not found.", path);
        }

        private string CaptureScreenshotBase64()
        {
            int width = GetSystemMetrics(0);
            int height = GetSystemMetrics(1);
            if (width <= 0 || height <= 0)
            {
                throw new InvalidOperationException("No interactive desktop is available for screenshot capture.");
            }

            using (Bitmap bitmap = new Bitmap(width, height))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (MemoryStream stream = new MemoryStream())
            {
                graphics.CopyFromScreen(0, 0, 0, 0, bitmap.Size);
                bitmap.Save(stream, ImageFormat.Png);
                return Convert.ToBase64String(stream.ToArray());
            }
        }

        private CommandResult RunCommand(Dictionary<string, object> args)
        {
            string command = GetArg(args, "command", string.Empty);
            int timeoutSeconds = Math.Max(1, Math.Min(ParseInt(GetArg(args, "timeoutSeconds", "30"), 30), 300));
            if (string.IsNullOrWhiteSpace(command))
            {
                throw new InvalidOperationException("Command is required.");
            }

            return RunProcess("cmd.exe", "/c " + command, timeoutSeconds);
        }

        private string StartTerminal()
        {
            lock (terminalSync)
            {
                EnsureTerminalStarted();
                return SerializeTerminalSnapshot(true);
            }
        }

        private string WriteTerminalInput(Dictionary<string, object> args)
        {
            string input = GetArg(args, "input", string.Empty);
            if (string.IsNullOrEmpty(input))
            {
                return ReadTerminal();
            }

            lock (terminalSync)
            {
                EnsureTerminalStarted();
                terminalProcess.StandardInput.WriteLine(input);
                AppendTerminalText(input + Environment.NewLine);
                return SerializeTerminalSnapshot(true);
            }
        }

        private string ReadTerminal()
        {
            lock (terminalSync)
            {
                bool running = terminalProcess != null && !terminalProcess.HasExited;
                return SerializeTerminalSnapshot(running);
            }
        }

        private string StopTerminal()
        {
            lock (terminalSync)
            {
                if (terminalProcess == null)
                {
                    return SerializeTerminalSnapshot(false);
                }

                try
                {
                    if (!terminalProcess.HasExited)
                    {
                        terminalProcess.StandardInput.WriteLine("exit");
                        if (!terminalProcess.WaitForExit(1500))
                        {
                            terminalProcess.Kill();
                        }
                    }
                }
                catch
                {
                }
                finally
                {
                    terminalProcess.Dispose();
                    terminalProcess = null;
                    AppendTerminalLine("[terminal stopped]");
                }

                return SerializeTerminalSnapshot(false);
            }
        }

        private void EnsureTerminalStarted()
        {
            if (terminalProcess == null || terminalProcess.HasExited)
            {
                terminalBuffer = new StringBuilder();
                terminalSequence = 0;
                terminalProcess = new Process();
                terminalProcess.StartInfo.FileName = "cmd.exe";
                terminalProcess.StartInfo.Arguments = "/Q /K prompt $P$G";
                terminalProcess.StartInfo.UseShellExecute = false;
                terminalProcess.StartInfo.RedirectStandardInput = true;
                terminalProcess.StartInfo.RedirectStandardOutput = true;
                terminalProcess.StartInfo.RedirectStandardError = true;
                terminalProcess.StartInfo.CreateNoWindow = true;
                terminalProcess.StartInfo.WorkingDirectory = GetTerminalWorkingDirectory();
                terminalProcess.StartInfo.StandardOutputEncoding = Encoding.Default;
                terminalProcess.StartInfo.StandardErrorEncoding = Encoding.Default;
                terminalProcess.Start();
                terminalProcess.StandardInput.AutoFlush = true;
                StartTerminalReader(terminalProcess, terminalProcess.StandardOutput.BaseStream);
                StartTerminalReader(terminalProcess, terminalProcess.StandardError.BaseStream);
            }
        }

        private static string GetTerminalWorkingDirectory()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrWhiteSpace(userProfile) && Directory.Exists(userProfile))
            {
                return userProfile;
            }

            return Environment.SystemDirectory;
        }

        private void StartTerminalReader(Process process, Stream stream)
        {
            System.Threading.ThreadPool.QueueUserWorkItem(state => ReadTerminalStream(process, stream));
        }

        private void ReadTerminalStream(Process process, Stream stream)
        {
            byte[] buffer = new byte[4096];
            while (process != null)
            {
                int read;
                try
                {
                    read = stream.Read(buffer, 0, buffer.Length);
                }
                catch
                {
                    return;
                }

                if (read <= 0)
                {
                    return;
                }

                AppendTerminalText(Encoding.Default.GetString(buffer, 0, read));
            }
        }

        private void AppendTerminalLine(string line)
        {
            if (line == null)
            {
                return;
            }

            AppendTerminalText(line + Environment.NewLine);
        }

        private void AppendTerminalText(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            lock (terminalSync)
            {
                terminalBuffer.Append(text);
                if (terminalBuffer.Length > 65536)
                {
                    terminalBuffer.Remove(0, terminalBuffer.Length - 65536);
                }

                terminalSequence++;
            }
        }

        private string SerializeTerminalSnapshot(bool running)
        {
            return serializer.Serialize(new
            {
                running = running,
                sequence = terminalSequence,
                output = terminalBuffer.ToString()
            });
        }

        private CommandResult ChangePassword(Dictionary<string, object> args)
        {
            string username = GetArg(args, "username", string.Empty);
            string newPassword = GetArg(args, "newPassword", string.Empty);
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(newPassword))
            {
                throw new InvalidOperationException("Username and new password are required.");
            }

            return RunProcess("net.exe", "user \"" + username.Replace("\"", string.Empty) + "\" \"" + newPassword.Replace("\"", string.Empty) + "\"", 30);
        }

        private static CommandResult RunProcess(string fileName, string arguments, int timeoutSeconds)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;

                StringBuilder output = new StringBuilder();
                process.OutputDataReceived += (sender, args) =>
                {
                    if (args.Data != null)
                    {
                        output.AppendLine(args.Data);
                    }
                };
                process.ErrorDataReceived += (sender, args) =>
                {
                    if (args.Data != null)
                    {
                        output.AppendLine(args.Data);
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                if (!process.WaitForExit(timeoutSeconds * 1000))
                {
                    try
                    {
                        process.Kill();
                    }
                    catch
                    {
                    }

                    return new CommandResult { ExitCode = 124, Output = output + "\nCommand timed out." };
                }

                process.WaitForExit();
                return new CommandResult { ExitCode = process.ExitCode, Output = output.ToString() };
            }
        }

        private static string TryReadIcon(string displayIcon)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(displayIcon))
                {
                    return string.Empty;
                }

                string path = displayIcon.Trim().Trim('"');
                int comma = path.LastIndexOf(',');
                if (comma > 2 && File.Exists(path.Substring(0, comma)))
                {
                    path = path.Substring(0, comma);
                }

                if (!File.Exists(path))
                {
                    return string.Empty;
                }

                using (Icon icon = Icon.ExtractAssociatedIcon(path))
                {
                    if (icon == null)
                    {
                        return string.Empty;
                    }

                    using (Bitmap bitmap = icon.ToBitmap())
                    using (MemoryStream stream = new MemoryStream())
                    {
                        bitmap.Save(stream, ImageFormat.Png);
                        return Convert.ToBase64String(stream.ToArray());
                    }
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string GetArg(Dictionary<string, object> args, string key, string fallback)
        {
            object value;
            return args != null && args.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : fallback;
        }

        private static string GetRequiredPath(Dictionary<string, object> args, string key)
        {
            string path = GetArg(args, key, string.Empty);
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new InvalidOperationException("Path is required.");
            }

            return path;
        }

        private static int ParseInt(string value, int fallback)
        {
            int parsed;
            return int.TryParse(value, out parsed) ? parsed : fallback;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool LockWorkStation();

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        private sealed class CommandResult
        {
            public int ExitCode { get; set; }
            public string Output { get; set; }
        }

        private sealed class InstalledAppInfo
        {
            public string displayName { get; set; }
            public string displayVersion { get; set; }
            public string publisher { get; set; }
            public string installLocation { get; set; }
            public string uninstallString { get; set; }
            public string displayIcon { get; set; }
            public string iconBase64 { get; set; }
        }
    }
}
