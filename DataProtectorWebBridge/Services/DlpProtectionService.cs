using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DataProtectorWebBridge.Services
{
    internal sealed class DlpProtectionService : IDisposable
    {
        private const int MaxQueuedEvents = 1000;
        private const int ClipboardRetryCount = 4;
        private const int ClipboardRetryDelayMs = 25;
        private const int DuplicateEventSuppressMs = 1500;
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_CLIPBOARDUPDATE = 0x031D;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int VK_SNAPSHOT = 0x2C;
        private const int VK_SHIFT = 0x10;
        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const int VK_S = 0x53;
        private const int CF_TEXT = 1;
        private const int CF_BITMAP = 2;
        private const int CF_METAFILEPICT = 3;
        private const int CF_OEMTEXT = 7;
        private const int CF_DIB = 8;
        private const int CF_UNICODETEXT = 13;
        private const int CF_ENHMETAFILE = 14;
        private const int CF_HDROP = 15;
        private const int CF_DIBV5 = 17;

        private readonly object syncRoot = new object();
        private readonly Queue<AuditLog.AuditRecord> queuedEvents = new Queue<AuditLog.AuditRecord>();
        private PolicyBridgeService.DlpProtectionPolicyDto policy = PolicyBridgeService.DefaultDlpProtectionPolicy();
        private Thread monitorThread;
        private MonitorForm monitorForm;
        private IntPtr keyboardHook;
        private LowLevelKeyboardProc keyboardProc;
        private bool disposed;
        private DateTime ignoreClipboardUpdatesUntilUtc = DateTime.MinValue;
        private string lastEventFingerprint = string.Empty;
        private DateTime lastEventUtc = DateTime.MinValue;

        public DlpProtectionService()
        {
            keyboardProc = KeyboardHookCallback;
        }

        public PolicyBridgeService.DlpProtectionPolicyDto QueryPolicy()
        {
            lock (syncRoot)
            {
                return PolicyBridgeService.CloneDlpProtectionPolicy(policy);
            }
        }

        public PolicyBridgeService.OperationResult SetPolicy(PolicyBridgeService.DlpProtectionPolicyRequest request)
        {
            PolicyBridgeService.DlpProtectionPolicyDto normalized = PolicyBridgeService.NormalizeDlpProtectionPolicy(request);
            UpdatePolicy(normalized);
            return new PolicyBridgeService.OperationResult
            {
                succeeded = true,
                status = 0,
                statusText = "0x00000000",
                message = "DLP protection policy applied."
            };
        }

        public void UpdatePolicy(PolicyBridgeService.DlpProtectionPolicyDto nextPolicy)
        {
            PolicyBridgeService.DlpProtectionPolicyDto normalized = PolicyBridgeService.CloneDlpProtectionPolicy(nextPolicy);
            lock (syncRoot)
            {
                policy = normalized;
            }

            if (normalized.enabled)
            {
                EnsureMonitorThread();
            }
        }

        public AuditLog.AuditRecord[] DrainAuditRecords()
        {
            lock (syncRoot)
            {
                AuditLog.AuditRecord[] records = queuedEvents.ToArray();
                queuedEvents.Clear();
                return records;
            }
        }

        private void EnsureMonitorThread()
        {
            lock (syncRoot)
            {
                if (disposed)
                {
                    return;
                }

                if (monitorThread != null && monitorThread.IsAlive)
                {
                    return;
                }

                monitorThread = new Thread(MonitorThreadProc)
                {
                    IsBackground = true,
                    Name = "DataProtector-DLP"
                };
                monitorThread.SetApartmentState(ApartmentState.STA);
                monitorThread.Start();
            }
        }

        private void MonitorThreadProc()
        {
            try
            {
                monitorForm = new MonitorForm(this);
                AddClipboardFormatListener(monitorForm.Handle);
                InstallKeyboardHook();
                Application.Run(monitorForm);
            }
            catch (Exception ex)
            {
                QueueEvent("dlp.monitor.failed", "dlp-monitor", string.Empty, false, "0x00000001", ex.Message);
            }
            finally
            {
                try
                {
                    if (monitorForm != null && monitorForm.Handle != IntPtr.Zero)
                    {
                        RemoveClipboardFormatListener(monitorForm.Handle);
                    }
                }
                catch
                {
                }

                UninstallKeyboardHook();
            }
        }

        private void InstallKeyboardHook()
        {
            if (keyboardHook != IntPtr.Zero)
            {
                return;
            }

            IntPtr moduleHandle = IntPtr.Zero;
            try
            {
                using (Process process = Process.GetCurrentProcess())
                using (ProcessModule module = process.MainModule)
                {
                    moduleHandle = GetModuleHandle(module.ModuleName);
                }
            }
            catch
            {
                moduleHandle = IntPtr.Zero;
            }

            keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardProc, moduleHandle, 0);
            if (keyboardHook == IntPtr.Zero)
            {
                QueueEvent("dlp.monitor.keyboard.failed", "keyboard-hook", string.Empty, false, "0x00000001", "Cannot install screenshot hotkey hook.");
            }
        }

        private void UninstallKeyboardHook()
        {
            if (keyboardHook == IntPtr.Zero)
            {
                return;
            }

            UnhookWindowsHookEx(keyboardHook);
            keyboardHook = IntPtr.Zero;
        }

        private IntPtr KeyboardHookCallback(int code, IntPtr wParam, IntPtr lParam)
        {
            if (code >= 0 && (wParam.ToInt32() == WM_KEYDOWN || wParam.ToInt32() == WM_SYSKEYDOWN))
            {
                KbdLlHookStruct data = (KbdLlHookStruct)Marshal.PtrToStructure(lParam, typeof(KbdLlHookStruct));
                if (ShouldBlockScreenshotHotkey((int)data.vkCode))
                {
                    return new IntPtr(1);
                }
            }

            return CallNextHookEx(keyboardHook, code, wParam, lParam);
        }

        private bool ShouldBlockScreenshotHotkey(int virtualKey)
        {
            PolicyBridgeService.DlpProtectionPolicyDto snapshot = QueryPolicy();
            if (!snapshot.enabled || !snapshot.protectScreenshots || !snapshot.blockPrintScreenHotkeys)
            {
                return false;
            }

            bool printScreen = virtualKey == VK_SNAPSHOT;
            bool snippingShortcut = virtualKey == VK_S && IsKeyPressed(VK_SHIFT) && (IsKeyPressed(VK_LWIN) || IsKeyPressed(VK_RWIN));
            if (!printScreen && !snippingShortcut)
            {
                return false;
            }

            ProcessIdentity foreground = GetForegroundProcessIdentity();
            if (IsTrustedProcess(snapshot, foreground))
            {
                return false;
            }

            string hotkey = printScreen ? "PrintScreen" : "Win+Shift+S";
            if (string.Equals(snapshot.screenshotMode, "audit", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(snapshot.screenshotMode, "clear", StringComparison.OrdinalIgnoreCase))
            {
                QueueEvent(
                    "dlp.screenshot.observed.hotkey",
                    hotkey,
                    foreground.path,
                    true,
                    "0x00000000",
                    BuildEventMessage("hotkey", hotkey, foreground, "observed", string.Empty));
                return false;
            }

            QueueEvent(
                "dlp.screenshot.blocked.hotkey",
                hotkey,
                foreground.path,
                false,
                "0xC0000022",
                BuildEventMessage("hotkey", hotkey, foreground, "blocked", string.Empty));
            return true;
        }

        internal void OnClipboardUpdated()
        {
            PolicyBridgeService.DlpProtectionPolicyDto snapshot = QueryPolicy();
            if (!snapshot.enabled || (!snapshot.protectClipboard && !snapshot.protectScreenshots))
            {
                return;
            }

            if (DateTime.UtcNow <= ignoreClipboardUpdatesUntilUtc)
            {
                return;
            }

            ClipboardSnapshot clipboard = ReadClipboardSnapshot();
            if (clipboard == null || clipboard.formats.Length == 0)
            {
                return;
            }

            ProcessIdentity source = GetClipboardOwnerProcessIdentity();
            if (source.processId == 0)
            {
                source = GetForegroundProcessIdentity();
            }

            if (IsTrustedProcess(snapshot, source))
            {
                return;
            }

            string formatSummary = string.Join(",", clipboard.formats);
            bool handled = false;

            if (snapshot.protectScreenshots && clipboard.hasImage)
            {
                handled = true;
                if (string.Equals(snapshot.screenshotMode, "audit", StringComparison.OrdinalIgnoreCase) || !snapshot.clearScreenshotClipboard)
                {
                    QueueEvent(
                        "dlp.screenshot.observed.clipboard-image",
                        "clipboard-image",
                        source.path,
                        true,
                        "0x00000000",
                        BuildEventMessage("clipboard-image", "image", source, "observed", formatSummary));
                }
                else
                {
                    ClearClipboard();
                    QueueEvent(
                        "dlp.screenshot.blocked.clipboard-image",
                        "clipboard-image",
                        source.path,
                        false,
                        "0xC0000022",
                        BuildEventMessage("clipboard-image", "image", source, "cleared", formatSummary));
                }
            }

            if (handled || !snapshot.protectClipboard)
            {
                return;
            }

            bool selected =
                (snapshot.clearClipboardText && clipboard.hasText) ||
                (snapshot.clearClipboardImages && clipboard.hasImage) ||
                (snapshot.clearClipboardFiles && clipboard.hasFiles);

            if (!selected)
            {
                return;
            }

            if (string.Equals(snapshot.clipboardMode, "audit", StringComparison.OrdinalIgnoreCase))
            {
                QueueEvent(
                    "dlp.clipboard.observed",
                    "clipboard",
                    source.path,
                    true,
                    "0x00000000",
                    BuildEventMessage("clipboard", clipboard.kind, source, "observed", formatSummary));
                return;
            }

            ClearClipboard();
            QueueEvent(
                "dlp.clipboard.blocked.clear",
                "clipboard",
                source.path,
                false,
                "0xC0000022",
                BuildEventMessage("clipboard", clipboard.kind, source, "cleared", formatSummary));
        }

        private ClipboardSnapshot ReadClipboardSnapshot()
        {
            for (int attempt = 0; attempt < ClipboardRetryCount; attempt++)
            {
                if (OpenClipboard(IntPtr.Zero))
                {
                    try
                    {
                        List<string> formats = new List<string>();
                        bool hasText = false;
                        bool hasImage = false;
                        bool hasFiles = false;
                        uint format = 0;
                        while ((format = EnumClipboardFormats(format)) != 0)
                        {
                            string name = FormatClipboardFormat(format);
                            formats.Add(name);
                            hasText = hasText || IsTextFormat(format, name);
                            hasImage = hasImage || IsImageFormat(format, name);
                            hasFiles = hasFiles || format == CF_HDROP;
                        }

                        return new ClipboardSnapshot
                        {
                            formats = formats.ToArray(),
                            hasText = hasText,
                            hasImage = hasImage,
                            hasFiles = hasFiles,
                            kind = hasFiles ? "files" : hasImage ? "image" : hasText ? "text" : "data"
                        };
                    }
                    finally
                    {
                        CloseClipboard();
                    }
                }

                Thread.Sleep(ClipboardRetryDelayMs);
            }

            return null;
        }

        private void ClearClipboard()
        {
            ignoreClipboardUpdatesUntilUtc = DateTime.UtcNow.AddMilliseconds(800);
            for (int attempt = 0; attempt < ClipboardRetryCount; attempt++)
            {
                if (OpenClipboard(IntPtr.Zero))
                {
                    try
                    {
                        EmptyClipboard();
                        return;
                    }
                    finally
                    {
                        CloseClipboard();
                    }
                }

                Thread.Sleep(ClipboardRetryDelayMs);
            }
        }

        private void QueueEvent(string action, string target, string extension, bool succeeded, string status, string message)
        {
            string fingerprint = action + "|" + target + "|" + extension + "|" + message;
            DateTime now = DateTime.UtcNow;

            lock (syncRoot)
            {
                if (string.Equals(fingerprint, lastEventFingerprint, StringComparison.OrdinalIgnoreCase) &&
                    (now - lastEventUtc).TotalMilliseconds < DuplicateEventSuppressMs)
                {
                    return;
                }

                lastEventFingerprint = fingerprint;
                lastEventUtc = now;

                if (queuedEvents.Count >= MaxQueuedEvents)
                {
                    queuedEvents.Dequeue();
                }

                queuedEvents.Enqueue(new AuditLog.AuditRecord
                {
                    TimestampUtc = now.ToString("o"),
                    Host = Environment.MachineName,
                    Actor = Environment.UserName,
                    Action = action,
                    Target = target ?? string.Empty,
                    Extension = extension ?? string.Empty,
                    Succeeded = succeeded,
                    Status = status ?? "0x00000000",
                    Message = message ?? string.Empty,
                    SourceHost = Environment.MachineName,
                    SourceUser = Environment.UserName,
                    SourceProcess = ExtractMessageValue(message, "process"),
                    SourcePid = ExtractMessageValue(message, "pid"),
                    ObjectType = InferDlpObjectType(action, target),
                    ObjectName = target ?? string.Empty,
                    ObjectFormat = ExtractMessageValue(message, "formats"),
                    PolicyName = "dlp",
                    Disposition = succeeded ? "observed" : "blocked",
                    Severity = succeeded ? "info" : "critical",
                    EventDetails = message ?? string.Empty
                });
            }
        }

        private static string BuildEventMessage(string channel, string objectKind, ProcessIdentity process, string disposition, string formats)
        {
            return "channel=" + Sanitize(channel) +
                   ";object=" + Sanitize(objectKind) +
                   ";disposition=" + Sanitize(disposition) +
                   ";pid=" + process.processId +
                   ";process=" + Sanitize(process.path) +
                   ";window=" + Sanitize(process.windowTitle) +
                   ";formats=" + Sanitize(formats);
        }

        private static string ExtractMessageValue(string message, string key)
        {
            if (string.IsNullOrWhiteSpace(message) || string.IsNullOrWhiteSpace(key))
            {
                return string.Empty;
            }

            string prefix = key + "=";
            foreach (string part in message.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string item = part.Trim();
                if (item.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return item.Substring(prefix.Length).Trim();
                }
            }

            return string.Empty;
        }

        private static string InferDlpObjectType(string action, string target)
        {
            string text = (action ?? string.Empty) + " " + (target ?? string.Empty);
            if (text.IndexOf("screenshot", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("image", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "screenshot";
            }

            if (text.IndexOf("clipboard", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "clipboard";
            }

            return "dlp";
        }

        private static bool IsTrustedProcess(PolicyBridgeService.DlpProtectionPolicyDto snapshot, ProcessIdentity process)
        {
            if (snapshot == null || process == null || string.IsNullOrWhiteSpace(process.path))
            {
                return false;
            }

            string fileName = Path.GetFileName(process.path);
            string directory = Path.GetDirectoryName(process.path) ?? string.Empty;

            if (snapshot.trustedProcessNames != null && snapshot.trustedProcessNames.Any(name =>
                !string.IsNullOrWhiteSpace(name) &&
                string.Equals(Path.GetFileName(name.Trim()), fileName, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (snapshot.trustedProcessDirectories != null && snapshot.trustedProcessDirectories.Any(dir =>
                IsPathUnderDirectory(directory, dir)))
            {
                return true;
            }

            return false;
        }

        private static bool IsPathUnderDirectory(string path, string directory)
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(directory))
            {
                return false;
            }

            try
            {
                string normalizedPath = NormalizeDirectory(path);
                string normalizedDirectory = NormalizeDirectory(directory);
                return normalizedPath.Equals(normalizedDirectory, StringComparison.OrdinalIgnoreCase) ||
                       normalizedPath.StartsWith(normalizedDirectory + "\\", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeDirectory(string value)
        {
            string full = Path.GetFullPath((value ?? string.Empty).Trim()).TrimEnd('\\');
            return full;
        }

        private static bool IsTextFormat(uint format, string name)
        {
            return format == CF_TEXT ||
                   format == CF_OEMTEXT ||
                   format == CF_UNICODETEXT ||
                   string.Equals(name, "HTML Format", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "Rich Text Format", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsImageFormat(uint format, string name)
        {
            return format == CF_BITMAP ||
                   format == CF_DIB ||
                   format == CF_DIBV5 ||
                   format == CF_METAFILEPICT ||
                   format == CF_ENHMETAFILE ||
                   string.Equals(name, "PNG", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "JFIF", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatClipboardFormat(uint format)
        {
            switch (format)
            {
                case CF_TEXT: return "CF_TEXT";
                case CF_BITMAP: return "CF_BITMAP";
                case CF_METAFILEPICT: return "CF_METAFILEPICT";
                case CF_OEMTEXT: return "CF_OEMTEXT";
                case CF_DIB: return "CF_DIB";
                case CF_UNICODETEXT: return "CF_UNICODETEXT";
                case CF_ENHMETAFILE: return "CF_ENHMETAFILE";
                case CF_HDROP: return "CF_HDROP";
                case CF_DIBV5: return "CF_DIBV5";
            }

            StringBuilder name = new StringBuilder(128);
            if (GetClipboardFormatName(format, name, name.Capacity) > 0)
            {
                return name.ToString();
            }

            return "FORMAT_" + format;
        }

        private static bool IsKeyPressed(int virtualKey)
        {
            return (GetAsyncKeyState(virtualKey) & 0x8000) != 0;
        }

        private static ProcessIdentity GetClipboardOwnerProcessIdentity()
        {
            IntPtr hwnd = GetClipboardOwner();
            return GetProcessIdentityFromWindow(hwnd);
        }

        private static ProcessIdentity GetForegroundProcessIdentity()
        {
            return GetProcessIdentityFromWindow(GetForegroundWindow());
        }

        private static ProcessIdentity GetProcessIdentityFromWindow(IntPtr hwnd)
        {
            ProcessIdentity identity = new ProcessIdentity();
            if (hwnd == IntPtr.Zero)
            {
                return identity;
            }

            try
            {
                uint processId;
                GetWindowThreadProcessId(hwnd, out processId);
                identity.processId = processId;
                identity.windowTitle = GetWindowTitle(hwnd);
                if (processId == 0)
                {
                    return identity;
                }

                using (Process process = Process.GetProcessById(checked((int)processId)))
                {
                    identity.processName = process.ProcessName ?? string.Empty;
                    try
                    {
                        identity.path = process.MainModule == null ? string.Empty : process.MainModule.FileName;
                    }
                    catch
                    {
                        identity.path = identity.processName + ".exe";
                    }
                }
            }
            catch
            {
            }

            return identity;
        }

        private static string GetWindowTitle(IntPtr hwnd)
        {
            try
            {
                int length = GetWindowTextLength(hwnd);
                if (length <= 0)
                {
                    return string.Empty;
                }

                StringBuilder builder = new StringBuilder(length + 1);
                GetWindowText(hwnd, builder, builder.Capacity);
                return builder.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string Sanitize(string value)
        {
            return (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Replace(";", ",").Trim();
        }

        public void Dispose()
        {
            lock (syncRoot)
            {
                if (disposed)
                {
                    return;
                }

                disposed = true;
            }

            try
            {
                MonitorForm form = monitorForm;
                if (form != null && form.IsHandleCreated)
                {
                    form.BeginInvoke((Action)(() => form.Close()));
                }
            }
            catch
            {
            }
        }

        private sealed class MonitorForm : Form
        {
            private readonly DlpProtectionService owner;

            public MonitorForm(DlpProtectionService owner)
            {
                this.owner = owner;
                ShowInTaskbar = false;
                FormBorderStyle = FormBorderStyle.None;
                WindowState = FormWindowState.Minimized;
                StartPosition = FormStartPosition.Manual;
                Location = new System.Drawing.Point(-32000, -32000);
                Size = new System.Drawing.Size(1, 1);
                Opacity = 0;
            }

            protected override void SetVisibleCore(bool value)
            {
                base.SetVisibleCore(false);
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == WM_CLIPBOARDUPDATE)
                {
                    owner.OnClipboardUpdated();
                }

                base.WndProc(ref m);
            }
        }

        private sealed class ClipboardSnapshot
        {
            public string[] formats;
            public bool hasText;
            public bool hasImage;
            public bool hasFiles;
            public string kind;
        }

        private sealed class ProcessIdentity
        {
            public uint processId;
            public string processName = string.Empty;
            public string path = string.Empty;
            public string windowTitle = string.Empty;
        }

        private delegate IntPtr LowLevelKeyboardProc(int code, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct KbdLlHookStruct
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool AddClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hwndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint EnumClipboardFormats(uint format);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetClipboardFormatName(uint format, StringBuilder lpszFormatName, int cchMaxCount);

        [DllImport("user32.dll")]
        private static extern IntPtr GetClipboardOwner();

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hwnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLength(IntPtr hwnd);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int virtualKey);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}
