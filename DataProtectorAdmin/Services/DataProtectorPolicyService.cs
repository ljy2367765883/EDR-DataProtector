using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using DataProtectorAdmin.Infrastructure;
using DataProtectorAdmin.Models;
using DataProtectorAdmin.Native;

namespace DataProtectorAdmin.Services
{
    public sealed class DataProtectorPolicyService : IDataProtectorPolicyService
    {
        private const uint SuccessStatus = 0;
        private const uint BufferTooSmallStatus = 0xE0010005;
        private const uint RuleTypeProcessName = 1;
        private const uint RuleTypeProcessDirectory = 2;
        private const uint RuleTypeExcludedDirectory = 3;
        private const int MessageBufferChars = 512;
        private const int PathBufferChars = 1024;

        private readonly IPolicySettingsStore settingsStore;

        public DataProtectorPolicyService(IPolicySettingsStore settingsStore)
        {
            this.settingsStore = settingsStore;
            Settings = settingsStore.Load();
        }

        public PolicySettings Settings { get; private set; }

        public PolicyOperationResult CheckConnection()
        {
            return InvokeNative(DataProtectorPolicyNative.DpPolicyCheckConnection, "驱动通信正常。");
        }

        public PolicyOperationResult QueryRulesFromDriver()
        {
            try
            {
                AdminDiagnostics.Log("Query process rules from driver: begin.");
                List<PolicyRule> processNameRules = new List<PolicyRule>();
                List<PolicyRule> processDirectoryRules = new List<PolicyRule>();
                List<PolicyRule> excludedDirectoryRules = new List<PolicyRule>();
                uint ruleCount;
                uint stringCharsRequired;
                uint status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                    new DataProtectorPolicyNative.NativePolicyRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    return new PolicyOperationResult(false, status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativePolicyRule[] nativeRules =
                    new DataProtectorPolicyNative.NativePolicyRule[ruleCount];
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int stringBufferBytes = checked((int)Math.Max(1, stringCharsRequired) * 2);
                    stringBuffer = Marshal.AllocHGlobal(stringBufferBytes);
                    ZeroMemory(stringBuffer, stringBufferBytes);

                    status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                        nativeRules,
                        ruleCount,
                        out ruleCount,
                        stringBuffer,
                        stringCharsRequired,
                        out stringCharsRequired);

                    if (status != SuccessStatus)
                    {
                        AdminDiagnostics.Log("Query process rules from driver failed with status 0x" + status.ToString("X8") + ".");
                        return new PolicyOperationResult(false, status, ReadLastErrorMessage());
                    }

                    for (int index = 0; index < nativeRules.Length; index++)
                    {
                        string value = Marshal.PtrToStringUni(nativeRules[index].Value);
                        string extension = NormalizeExtension(Marshal.PtrToStringUni(nativeRules[index].Extension));

                        if (string.IsNullOrWhiteSpace(value))
                        {
                            continue;
                        }

                        if (nativeRules[index].RuleType == RuleTypeProcessName)
                        {
                            AddRuleToList(processNameRules,
                                          new PolicyRule(PolicyRuleKind.ProcessName, value, value, extension));
                        }
                        else if (nativeRules[index].RuleType == RuleTypeProcessDirectory)
                        {
                            AddRuleToList(processDirectoryRules,
                                          new PolicyRule(PolicyRuleKind.ProcessDirectory, value, value, extension));
                        }
                        else if (nativeRules[index].RuleType == RuleTypeExcludedDirectory)
                        {
                            AddRuleToList(excludedDirectoryRules,
                                          new PolicyRule(PolicyRuleKind.ExcludedDirectory, value, value, extension));
                        }
                    }

                    PolicyOperationResult result = CommitLocalChange(
                        "已从驱动读取当前规则。",
                        "已读取驱动规则，但本地配置保存失败：",
                        () =>
                        {
                            Settings.ProcessNameRules.Clear();
                            Settings.ProcessDirectoryRules.Clear();
                            Settings.ExcludedDirectoryRules.Clear();

                            foreach (PolicyRule rule in processNameRules)
                            {
                                Settings.ProcessNameRules.Add(rule);
                            }

                            foreach (PolicyRule rule in processDirectoryRules)
                            {
                                Settings.ProcessDirectoryRules.Add(rule);
                            }

                            foreach (PolicyRule rule in excludedDirectoryRules)
                            {
                                Settings.ExcludedDirectoryRules.Add(rule);
                            }
                        });

                    AdminDiagnostics.Log("Query process rules from driver: " + (result.Succeeded ? "success." : "failed."));
                    return result;
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }
            catch (Exception ex)
            {
                if (IsNativeLoadException(ex))
                {
                    return new PolicyOperationResult(false, 1, BuildNativeLoadError(ex));
                }

                AdminDiagnostics.Log(ex);
                return new PolicyOperationResult(false, 1, "读取驱动规则失败：" + ex.Message);
            }
        }

        public PolicyOperationResult AddProcessNameRule(string processName, string extension)
        {
            string normalized = NormalizeProcessName(processName);
            string normalizedExtension = NormalizeExtension(extension);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return new PolicyOperationResult(false, 1, "请输入进程名，例如 notepad.exe。");
            }

            if (RunOnUiThread(() => Settings.ProcessNameRules.Any(rule => RuleEquals(rule, normalized, normalizedExtension))))
            {
                return PolicyOperationResult.Success("规则已经存在。");
            }

            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyAddProcessNameRuleEx(normalized, normalizedExtension),
                "进程名规则已下发。");

            if (result.Succeeded || IsAlreadyExists(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "驱动中已存在该规则，已补齐本地配置。";

                return CommitLocalChange(message, "规则已下发到驱动，但本地配置保存失败：", () =>
                    Settings.ProcessNameRules.Add(new PolicyRule(PolicyRuleKind.ProcessName, normalized, normalized, normalizedExtension)));
            }

            return result;
        }

        public PolicyOperationResult RemoveProcessNameRule(PolicyRule rule)
        {
            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyRemoveProcessNameRuleEx(rule.DriverValue, rule.Extension),
                "进程名规则已移除。");

            if (result.Succeeded || IsNotFound(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "本地规则已移除，驱动中未找到该规则。";

                return CommitLocalChange(message, "驱动规则已处理，但本地配置保存失败：", () => Settings.ProcessNameRules.Remove(rule));
            }

            return result;
        }

        public PolicyOperationResult AddProcessDirectoryRule(string directoryPath, string extension)
        {
            string trimmed = directoryPath == null ? string.Empty : directoryPath.Trim();
            string normalizedExtension = NormalizeExtension(extension);
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                return new PolicyOperationResult(false, 1, "请选择或输入可信程序目录。");
            }

            DirectoryConversionResult conversion = ConvertDirectoryPath(trimmed);
            if (!conversion.Succeeded || string.IsNullOrWhiteSpace(conversion.DriverValue))
            {
                return new PolicyOperationResult(false, conversion.Status, conversion.Message);
            }

            if (RunOnUiThread(() => Settings.ProcessDirectoryRules.Any(rule => RuleEquals(rule, conversion.DriverValue, normalizedExtension))))
            {
                return PolicyOperationResult.Success("规则已经存在。");
            }

            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyAddProcessDirectoryRuleEx(trimmed, normalizedExtension),
                "文件夹规则已下发。");

            if (result.Succeeded || IsAlreadyExists(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "驱动中已存在该规则，已补齐本地配置。";

                return CommitLocalChange(message, "规则已下发到驱动，但本地配置保存失败：", () =>
                    Settings.ProcessDirectoryRules.Add(new PolicyRule(
                        PolicyRuleKind.ProcessDirectory,
                        trimmed,
                        conversion.DriverValue,
                        normalizedExtension)));
            }

            return result;
        }

        public PolicyOperationResult RemoveProcessDirectoryRule(PolicyRule rule)
        {
            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyRemoveProcessDirectoryRuleEx(rule.DriverValue, rule.Extension),
                "文件夹规则已移除。");

            if (result.Succeeded || IsNotFound(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "本地规则已移除，驱动中未找到该规则。";

                return CommitLocalChange(message, "驱动规则已处理，但本地配置保存失败：", () => Settings.ProcessDirectoryRules.Remove(rule));
            }

            return result;
        }

        public PolicyOperationResult AddExcludedDirectoryRule(string directoryPath, string extension)
        {
            string trimmed = directoryPath == null ? string.Empty : directoryPath.Trim();
            string normalizedExtension = NormalizeExtension(extension);
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                return new PolicyOperationResult(false, 1, "请选择或输入排除目录。");
            }

            DirectoryConversionResult conversion = ConvertDirectoryPath(trimmed);
            if (!conversion.Succeeded || string.IsNullOrWhiteSpace(conversion.DriverValue))
            {
                return new PolicyOperationResult(false, conversion.Status, conversion.Message);
            }

            if (RunOnUiThread(() => Settings.ExcludedDirectoryRules.Any(rule => RuleEquals(rule, conversion.DriverValue, normalizedExtension))))
            {
                return PolicyOperationResult.Success("排除目录规则已经存在。");
            }

            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyAddExcludedDirectoryRuleEx(trimmed, normalizedExtension),
                "排除目录规则已下发。");

            if (result.Succeeded || IsAlreadyExists(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "驱动中已存在该排除目录，已补齐本地配置。";

                return CommitLocalChange(message, "排除目录已下发到驱动，但本地配置保存失败：", () =>
                    Settings.ExcludedDirectoryRules.Add(new PolicyRule(
                        PolicyRuleKind.ExcludedDirectory,
                        trimmed,
                        conversion.DriverValue,
                        normalizedExtension)));
            }

            return result;
        }

        public PolicyOperationResult RemoveExcludedDirectoryRule(PolicyRule rule)
        {
            PolicyOperationResult result = InvokeNative(
                () => DataProtectorPolicyNative.DpPolicyRemoveExcludedDirectoryRuleEx(rule.DriverValue, rule.Extension),
                "排除目录规则已移除。");

            if (result.Succeeded || IsNotFound(result.Status))
            {
                string message = result.Succeeded
                    ? result.Message
                    : "本地排除目录已移除，驱动中未找到该规则。";

                return CommitLocalChange(message, "驱动规则已处理，但本地配置保存失败：", () => Settings.ExcludedDirectoryRules.Remove(rule));
            }

            return result;
        }

        public PolicyOperationResult ClearRules()
        {
            PolicyOperationResult result = InvokeNative(DataProtectorPolicyNative.DpPolicyClearProcessRules, "驱动规则已清空。");
            if (result.Succeeded)
            {
                return CommitLocalChange(result.Message, "驱动规则已清空，但本地配置保存失败：", () =>
                {
                    Settings.ProcessNameRules.Clear();
                    Settings.ProcessDirectoryRules.Clear();
                    Settings.ExcludedDirectoryRules.Clear();
                });
            }

            return result;
        }

        public PolicyOperationResult SynchronizeRules()
        {
            PolicyOperationResult clearResult = InvokeNative(DataProtectorPolicyNative.DpPolicyClearProcessRules, "驱动规则已清空。");
            if (!clearResult.Succeeded)
            {
                return clearResult;
            }

            List<PolicyRule> processNameRules = RunOnUiThread(() => Settings.ProcessNameRules.ToList());
            List<PolicyRule> processDirectoryRules = RunOnUiThread(() => Settings.ProcessDirectoryRules.ToList());
            List<PolicyRule> excludedDirectoryRules = RunOnUiThread(() => Settings.ExcludedDirectoryRules.ToList());

            foreach (PolicyRule rule in processNameRules)
            {
                PolicyOperationResult result = InvokeNative(
                    () => DataProtectorPolicyNative.DpPolicyAddProcessNameRuleEx(rule.DriverValue, rule.Extension),
                    "进程名规则已同步。");

                if (!result.Succeeded)
                {
                    return result;
                }
            }

            foreach (PolicyRule rule in processDirectoryRules)
            {
                PolicyOperationResult result = InvokeNative(
                    () => DataProtectorPolicyNative.DpPolicyAddProcessDirectoryRuleEx(rule.DriverValue, rule.Extension),
                    "文件夹规则已同步。");

                if (!result.Succeeded)
                {
                    return result;
                }
            }

            foreach (PolicyRule rule in excludedDirectoryRules)
            {
                PolicyOperationResult result = InvokeNative(
                    () => DataProtectorPolicyNative.DpPolicyAddExcludedDirectoryRuleEx(rule.DriverValue, rule.Extension),
                    "排除目录规则已同步。");

                if (!result.Succeeded)
                {
                    return result;
                }
            }

            return PolicyOperationResult.Success("所有策略规则已同步到驱动。");
        }

        private static string NormalizeProcessName(string processName)
        {
            string normalized = processName == null ? string.Empty : processName.Trim();
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return string.Empty;
            }

            return normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? normalized
                : normalized + ".exe";
        }

        private static string NormalizeExtension(string extension)
        {
            string normalized = extension == null ? string.Empty : extension.Trim();
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return ".dpf";
            }

            return normalized.StartsWith(".", StringComparison.Ordinal)
                ? normalized
                : "." + normalized;
        }

        private static bool RuleEquals(PolicyRule rule, string driverValue, string extension)
        {
            return string.Equals(rule.DriverValue, driverValue, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(rule.Extension, extension, StringComparison.OrdinalIgnoreCase);
        }

        private static void AddRuleToList(ICollection<PolicyRule> rules, PolicyRule newRule)
        {
            if (!rules.Any(rule => RuleEquals(rule, newRule.DriverValue, newRule.Extension)))
            {
                rules.Add(newRule);
            }
        }

        private static void ZeroMemory(IntPtr buffer, int bytes)
        {
            byte[] zeros = new byte[bytes];
            Marshal.Copy(zeros, 0, buffer, bytes);
        }

        private static DirectoryConversionResult ConvertDirectoryPath(string directoryPath)
        {
            try
            {
                AdminDiagnostics.Log("Convert directory path: begin.");
                StringBuilder buffer = new StringBuilder(PathBufferChars);
                uint status = DataProtectorPolicyNative.DpPolicyConvertDosPathToNtPath(
                    directoryPath,
                    buffer,
                    (uint)buffer.Capacity);

                if (status != SuccessStatus)
                {
                    AdminDiagnostics.Log("Convert directory path failed with status 0x" + status.ToString("X8") + ".");
                    return new DirectoryConversionResult(false, status, string.Empty, ReadLastErrorMessage());
                }

                AdminDiagnostics.Log("Convert directory path: success.");
                return new DirectoryConversionResult(true, status, buffer.ToString(), "路径已转换。");
            }
            catch (Exception ex)
            {
                if (IsNativeLoadException(ex))
                {
                    return new DirectoryConversionResult(false, 1, string.Empty, BuildNativeLoadError(ex));
                }

                AdminDiagnostics.Log(ex);
                return new DirectoryConversionResult(false, 1, string.Empty, "路径转换失败：" + ex.Message);
            }
        }

        private static PolicyOperationResult InvokeNative(Func<uint> operation, string successMessage)
        {
            try
            {
                AdminDiagnostics.Log("Native policy operation begin: " + successMessage);
                uint status = operation();
                if (status == SuccessStatus)
                {
                    AdminDiagnostics.Log("Native policy operation success: " + successMessage);
                    return PolicyOperationResult.Success(successMessage);
                }

                AdminDiagnostics.Log("Native policy operation failed with status 0x" + status.ToString("X8") + ": " + successMessage);
                return new PolicyOperationResult(false, status, ReadLastErrorMessage());
            }
            catch (Exception ex)
            {
                if (IsNativeLoadException(ex))
                {
                    return new PolicyOperationResult(false, 1, BuildNativeLoadError(ex));
                }

                AdminDiagnostics.Log(ex);
                return new PolicyOperationResult(false, 1, "策略操作失败：" + ex.Message);
            }
        }

        private PolicyOperationResult CommitLocalChange(string successMessage, string failurePrefix, Action change)
        {
            try
            {
                PolicySettings snapshot = null;

                RunOnUiThread(() =>
                {
                    if (change != null)
                    {
                        change();
                    }

                    snapshot = CreateSettingsSnapshot();
                });

                settingsStore.Save(snapshot);

                return PolicyOperationResult.Success(successMessage);
            }
            catch (Exception ex)
            {
                AdminDiagnostics.Log(ex);
                return new PolicyOperationResult(false, 1, (failurePrefix ?? "本地配置保存失败：") + ex.Message);
            }
        }

        private PolicySettings CreateSettingsSnapshot()
        {
            PolicySettings snapshot = new PolicySettings();

            foreach (PolicyRule rule in Settings.ProcessNameRules)
            {
                snapshot.ProcessNameRules.Add(rule);
            }

            foreach (PolicyRule rule in Settings.ProcessDirectoryRules)
            {
                snapshot.ProcessDirectoryRules.Add(rule);
            }

            foreach (PolicyRule rule in Settings.ExcludedDirectoryRules)
            {
                snapshot.ExcludedDirectoryRules.Add(rule);
            }

            return snapshot;
        }

        private static void RunOnUiThread(Action action)
        {
            System.Windows.Application application = System.Windows.Application.Current;
            if (application != null &&
                application.Dispatcher != null &&
                !application.Dispatcher.CheckAccess())
            {
                application.Dispatcher.Invoke(action);
                return;
            }

            action();
        }

        private static T RunOnUiThread<T>(Func<T> action)
        {
            System.Windows.Application application = System.Windows.Application.Current;
            if (application != null &&
                application.Dispatcher != null &&
                !application.Dispatcher.CheckAccess())
            {
                return (T)application.Dispatcher.Invoke(action);
            }

            return action();
        }

        private static string ReadLastErrorMessage()
        {
            try
            {
                StringBuilder buffer = new StringBuilder(MessageBufferChars);
                DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(buffer, (uint)buffer.Capacity);
                return buffer.ToString();
            }
            catch
            {
                return "无法读取底层错误信息。";
            }
        }

        private static bool IsNotFound(uint status)
        {
            return status == 0xC0000225 || status == 0x80070002;
        }

        private static bool IsAlreadyExists(uint status)
        {
            return status == 0xC0000035 ||
                   status == 0xD0000035 ||
                   status == 0x800700B7;
        }

        private static bool IsNativeLoadException(Exception exception)
        {
            return exception is DllNotFoundException ||
                   exception is EntryPointNotFoundException ||
                   exception is BadImageFormatException;
        }

        private static string BuildNativeLoadError(Exception exception)
        {
            return "无法加载 DataProtectorPolicyApi.dll：" + exception.Message;
        }

        private sealed class DirectoryConversionResult
        {
            public DirectoryConversionResult(bool succeeded, uint status, string driverValue, string message)
            {
                Succeeded = succeeded;
                Status = status;
                DriverValue = driverValue;
                Message = message;
            }

            public bool Succeeded { get; private set; }

            public uint Status { get; private set; }

            public string DriverValue { get; private set; }

            public string Message { get; private set; }
        }
    }
}
