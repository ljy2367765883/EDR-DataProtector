using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using DataProtectorAgentClient.Models;
using DataProtectorAgentClient.Native;

namespace DataProtectorAgentClient.Services
{
    internal sealed class LocalPolicyReader
    {
        private const uint SuccessStatus = 0;
        private const uint BufferTooSmallStatus = 0xE0010005;
        private const uint RuleTypeProcessName = 1;
        private const uint RuleTypeProcessDirectory = 2;
        private const uint RuleTypeExcludedDirectory = 3;
        private const uint NetworkRuleTypeDomain = 2;
        private const uint NetworkActionAllow = 0;
        private const uint NetworkProtocolIcmp = 1;
        private const uint NetworkProtocolTcp = 6;
        private const uint NetworkProtocolUdp = 17;
        private const uint NetworkDirectionInbound = 0;
        private const uint NetworkDirectionBoth = 2;
        private const uint HashProtectFlagEnabled = 0x00000001;
        private const uint HashProtectFlagLsassHandles = 0x00000002;
        private const uint HashProtectFlagCredentialFiles = 0x00000004;
        private const uint HashProtectFlagRegistryHives = 0x00000008;
        private const uint HashProtectFlagRawExtents = 0x00000010;
        private const uint LateralDefenseFlagEnabled = 0x00000001;
        private const uint LateralDefenseFlagSmbExecutables = 0x00000002;
        private const uint LateralDefenseFlagIpcTasks = 0x00000004;
        private const uint LateralDefenseFlagIpcServices = 0x00000008;
        private const uint LateralDefenseFlagProcessTools = 0x00000010;
        private const uint UserHookDefenseFlagEnabled = 0x00000001;
        private const uint UserHookDefenseFlagEarlyProcessMonitor = 0x00000002;
        private const uint UserHookDefenseFlagImageLoadMonitor = 0x00000004;
        private const uint UserHookDefenseFlagRequireSignedRuntime = 0x00000008;
        private const uint UserHookDefenseFlagBlockUntrustedRuntime = 0x00000010;
        private const uint UserHookDefenseFlagAuditOnly = 0x00000020;
        private const int MessageBufferChars = 512;
        private const int MaxQueryAttempts = 4;

        public DriverStatus ReadStatus()
        {
            try
            {
                uint status = DataProtectorPolicyNative.DpPolicyCheckConnection();
                return new DriverStatus
                {
                    Connected = status == SuccessStatus,
                    StatusText = ToStatusText(status),
                    Message = status == SuccessStatus ? "驱动通信正常" : ReadLastErrorMessage()
                };
            }
            catch (Exception ex)
            {
                return new DriverStatus
                {
                    Connected = false,
                    StatusText = "0x00000001",
                    Message = ex.Message
                };
            }
        }

        public IList<RuleViewItem> ReadRules()
        {
            List<RuleViewItem> rules = new List<RuleViewItem>();
            ReadProcessRules(rules);
            ReadNetworkRules(rules);
            ReadWebShellRules(rules);
            ReadDeviceRules(rules);
            return rules;
        }

        public IList<ProtectionFeatureViewItem> ReadFeatures()
        {
            List<ProtectionFeatureViewItem> features = new List<ProtectionFeatureViewItem>();
            ReadHashProtectFeature(features);
            ReadLateralDefenseFeature(features);
            ReadUserHookDefenseFeature(features);
            return features;
        }

        private void ReadProcessRules(List<RuleViewItem> rules)
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                    new DataProtectorPolicyNative.NativePolicyRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    AddQueryError(rules, "文件防护", status);
                    return;
                }

                DataProtectorPolicyNative.NativePolicyRule[] nativeRules =
                    new DataProtectorPolicyNative.NativePolicyRule[checked((int)ruleCount)];
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryProcessRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            DataProtectorPolicyNative.NativePolicyRule item = nativeRules[index];
                            rules.Add(new RuleViewItem
                            {
                                Category = "文件透明加密",
                                Name = ConvertProcessRuleName(item.RuleType),
                                Target = Marshal.PtrToStringUni(item.Value) ?? string.Empty,
                                Detail = "扩展名 " + (Marshal.PtrToStringUni(item.Extension) ?? ".dpf"),
                                State = "已生效",
                                StateBrushKey = "DpSuccessBrush"
                            });
                        }

                        return;
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        AddQueryError(rules, "文件防护", status);
                        return;
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }
        }

        private void ReadNetworkRules(List<RuleViewItem> rules)
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryNetworkRules(
                    new DataProtectorPolicyNative.NativeNetworkRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    AddQueryError(rules, "网络管控", status);
                    return;
                }

                DataProtectorPolicyNative.NativeNetworkRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeNetworkRule[checked((int)ruleCount)];
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryNetworkRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            DataProtectorPolicyNative.NativeNetworkRule item = nativeRules[index];
                            bool isDomain = item.Kind == NetworkRuleTypeDomain;
                            string target = isDomain
                                ? (Marshal.PtrToStringUni(item.Domain) ?? string.Empty)
                                : FormatAddress(item.RemoteAddress, item.RemoteAddressMask);

                            rules.Add(new RuleViewItem
                            {
                                Category = "网络管控",
                                Name = item.Action == NetworkActionAllow ? "允许规则" : "阻断规则",
                                Target = string.IsNullOrWhiteSpace(target) ? "*" : target,
                                Detail = string.Format(
                                    CultureInfo.InvariantCulture,
                                    "{0} / {1} / 远端端口 {2}",
                                    FromProtocol(item.Protocol).ToUpperInvariant(),
                                    FromDirection(item.Direction),
                                    item.RemotePort == 0 ? "*" : item.RemotePort.ToString(CultureInfo.InvariantCulture)),
                                State = "已生效",
                                StateBrushKey = "DpSuccessBrush"
                            });
                        }

                        return;
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        AddQueryError(rules, "网络管控", status);
                        return;
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }
        }

        private void ReadWebShellRules(List<RuleViewItem> rules)
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryWebShellRules(
                    new DataProtectorPolicyNative.NativeWebShellRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    AddQueryError(rules, "脚本木马防护", status);
                    return;
                }

                DataProtectorPolicyNative.NativeWebShellRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeWebShellRule[checked((int)ruleCount)];
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryWebShellRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(new RuleViewItem
                            {
                                Category = "脚本木马防护",
                                Name = "受保护目录",
                                Target = Marshal.PtrToStringUni(nativeRules[index].Directory) ?? string.Empty,
                                Detail = "脚本写入与高危样本检测",
                                State = "已生效",
                                StateBrushKey = "DpSuccessBrush"
                            });
                        }

                        return;
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        AddQueryError(rules, "脚本木马防护", status);
                        return;
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }
        }

        private void ReadDeviceRules(List<RuleViewItem> rules)
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint ruleCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQueryDeviceRules(
                    new DataProtectorPolicyNative.NativeDeviceRule[0],
                    0,
                    out ruleCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    AddQueryError(rules, "设备管控", status);
                    return;
                }

                DataProtectorPolicyNative.NativeDeviceRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeDeviceRule[checked((int)ruleCount)];
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQueryDeviceRules(
                        nativeRules,
                        (uint)nativeRules.Length,
                        out ruleCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)ruleCount);
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            DataProtectorPolicyNative.NativeDeviceRule item = nativeRules[index];
                            bool allowInsert = item.AllowInsert != 0;
                            bool allowWrite = item.AllowWrite != 0;
                            rules.Add(new RuleViewItem
                            {
                                Category = "设备管控",
                                Name = allowInsert ? (allowWrite ? "允许读写" : "只读授权") : "禁止插入",
                                Target = Marshal.PtrToStringUni(item.DeviceId) ?? string.Empty,
                                Detail = "插入：" + (allowInsert ? "允许" : "阻止") + " / 写入：" + (allowWrite ? "允许" : "阻止"),
                                State = "已生效",
                                StateBrushKey = "DpSuccessBrush"
                            });
                        }

                        return;
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        AddQueryError(rules, "设备管控", status);
                        return;
                    }
                }
                finally
                {
                    if (stringBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(stringBuffer);
                    }
                }
            }
        }

        private void ReadHashProtectFeature(List<ProtectionFeatureViewItem> features)
        {
            try
            {
                DataProtectorPolicyNative.NativeHashProtectPolicy policy;
                uint status = DataProtectorPolicyNative.DpPolicyQueryHashProtectPolicy(out policy);
                if (status != SuccessStatus)
                {
                    features.Add(BuildFeatureError("凭据抓取防护", status));
                    return;
                }

                uint flags = policy.Flags;
                features.Add(new ProtectionFeatureViewItem
                {
                    Name = "凭据抓取防护",
                    Description = BuildHashProtectDescription(flags),
                    State = (flags & HashProtectFlagEnabled) != 0 ? "已开启" : "未开启",
                    AccentBrushKey = (flags & HashProtectFlagEnabled) != 0 ? "DpSuccessBrush" : "DpMutedBrush"
                });
            }
            catch (Exception ex)
            {
                features.Add(BuildFeatureException("凭据抓取防护", ex));
            }
        }

        private void ReadLateralDefenseFeature(List<ProtectionFeatureViewItem> features)
        {
            try
            {
                DataProtectorPolicyNative.NativeLateralDefensePolicy policy;
                uint status = DataProtectorPolicyNative.DpPolicyQueryLateralDefensePolicy(out policy);
                if (status != SuccessStatus)
                {
                    features.Add(BuildFeatureError("横向移动防御", status));
                    return;
                }

                uint flags = policy.Flags;
                features.Add(new ProtectionFeatureViewItem
                {
                    Name = "横向移动防御",
                    Description = BuildLateralDefenseDescription(flags),
                    State = (flags & LateralDefenseFlagEnabled) != 0 ? "已开启" : "未开启",
                    AccentBrushKey = (flags & LateralDefenseFlagEnabled) != 0 ? "DpSuccessBrush" : "DpMutedBrush"
                });
            }
            catch (Exception ex)
            {
                features.Add(BuildFeatureException("横向移动防御", ex));
            }
        }

        private void ReadUserHookDefenseFeature(List<ProtectionFeatureViewItem> features)
        {
            try
            {
                DataProtectorPolicyNative.NativeUserHookDefensePolicy policy;
                uint status = DataProtectorPolicyNative.DpPolicyQueryUserHookDefensePolicy(out policy);
                if (status != SuccessStatus)
                {
                    features.Add(BuildFeatureError("应用 Hook 防御", status));
                    return;
                }

                uint flags = policy.Flags;
                features.Add(new ProtectionFeatureViewItem
                {
                    Name = "应用 Hook 防御",
                    Description = BuildUserHookDefenseDescription(flags),
                    State = (flags & UserHookDefenseFlagEnabled) != 0 ? "已开启" : "未开启",
                    AccentBrushKey = (flags & UserHookDefenseFlagEnabled) != 0 ? "DpSuccessBrush" : "DpMutedBrush"
                });
            }
            catch (Exception ex)
            {
                features.Add(BuildFeatureException("应用 Hook 防御", ex));
            }
        }

        private static ProtectionFeatureViewItem BuildFeatureError(string name, uint status)
        {
            return new ProtectionFeatureViewItem
            {
                Name = name,
                Description = BuildDriverUnavailableSummary(status),
                State = ToStatusText(status),
                AccentBrushKey = "DpWarningBrush"
            };
        }

        private static string BuildHashProtectDescription(uint flags)
        {
            return JoinCapabilities(
                "内存转储防护" + IsEnabled(flags, HashProtectFlagLsassHandles),
                "凭据文件防护" + IsEnabled(flags, HashProtectFlagCredentialFiles),
                "注册表导出防护" + IsEnabled(flags, HashProtectFlagRegistryHives),
                "磁盘原始读取防护" + IsEnabled(flags, HashProtectFlagRawExtents));
        }

        private static string BuildLateralDefenseDescription(uint flags)
        {
            return JoinCapabilities(
                "共享目录投递防护" + IsEnabled(flags, LateralDefenseFlagSmbExecutables),
                "远程计划任务防护" + IsEnabled(flags, LateralDefenseFlagIpcTasks),
                "远程服务创建防护" + IsEnabled(flags, LateralDefenseFlagIpcServices),
                "横向工具调用防护" + IsEnabled(flags, LateralDefenseFlagProcessTools));
        }

        private static string BuildUserHookDefenseDescription(uint flags)
        {
            return JoinCapabilities(
                "早期进程监控" + IsEnabled(flags, UserHookDefenseFlagEarlyProcessMonitor),
                "敏感模块监控" + IsEnabled(flags, UserHookDefenseFlagImageLoadMonitor),
                "签名运行时" + IsEnabled(flags, UserHookDefenseFlagRequireSignedRuntime),
                (flags & UserHookDefenseFlagAuditOnly) != 0
                    ? "仅审计已启用"
                    : "阻断非可信运行时" + IsEnabled(flags, UserHookDefenseFlagBlockUntrustedRuntime));
        }

        private static ProtectionFeatureViewItem BuildFeatureException(string name, Exception ex)
        {
            return new ProtectionFeatureViewItem
            {
                Name = name,
                Description = ex.Message,
                State = "读取失败",
                AccentBrushKey = "DpWarningBrush"
            };
        }

        private static string IsEnabled(uint flags, uint bit)
        {
            return (flags & bit) != 0 ? "已启用" : "未启用";
        }

        private static string JoinCapabilities(params string[] items)
        {
            return string.Join("  ·  ", items);
        }

        private static string ConvertProcessRuleName(uint ruleType)
        {
            if (ruleType == RuleTypeProcessName)
            {
                return "可信进程";
            }

            if (ruleType == RuleTypeProcessDirectory)
            {
                return "可信目录";
            }

            if (ruleType == RuleTypeExcludedDirectory)
            {
                return "排除目录";
            }

            return "未知规则";
        }

        private static void AddQueryError(List<RuleViewItem> rules, string category, uint status)
        {
            rules.Add(new RuleViewItem
            {
                Category = category,
                Name = "读取失败",
                Target = BuildDriverUnavailableSummary(status),
                Detail = ToStatusText(status),
                State = "未读取",
                StateBrushKey = "DpWarningBrush"
            });
        }

        private static string BuildDriverUnavailableSummary(uint status)
        {
            string message = ReadLastErrorMessage();
            if (status == 0x80070002u || message.IndexOf("指定的文件", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "未连接到 DataProtector 驱动，请检查驱动服务或安装状态。";
            }

            if (message.IndexOf("Cannot connect", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "驱动接口不可用：" + message;
            }

            return string.IsNullOrWhiteSpace(message) ? "驱动接口当前不可用。" : message;
        }

        private static string FromProtocol(uint protocol)
        {
            if (protocol == NetworkProtocolIcmp) return "icmp";
            if (protocol == NetworkProtocolTcp) return "tcp";
            if (protocol == NetworkProtocolUdp) return "udp";
            return "any";
        }

        private static string FromDirection(uint direction)
        {
            if (direction == NetworkDirectionInbound) return "入站";
            if (direction == NetworkDirectionBoth) return "双向";
            return "出站";
        }

        private static string FormatAddress(uint address, uint mask)
        {
            if (address == 0 && mask == 0)
            {
                return string.Empty;
            }

            string ip = string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}",
                (address >> 24) & 0xFF,
                (address >> 16) & 0xFF,
                (address >> 8) & 0xFF,
                address & 0xFF);

            if (mask == 0xFFFFFFFFu)
            {
                return ip;
            }

            return ip + "/" + CountPrefix(mask).ToString(CultureInfo.InvariantCulture);
        }

        private static int CountPrefix(uint mask)
        {
            int prefix = 0;
            for (int bit = 31; bit >= 0; bit--)
            {
                if ((mask & (1u << bit)) == 0)
                {
                    break;
                }

                prefix++;
            }

            return prefix;
        }

        private static string ReadLastErrorMessage()
        {
            try
            {
                StringBuilder buffer = new StringBuilder(MessageBufferChars);
                DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(buffer, (uint)buffer.Capacity);
                string message = buffer.ToString();
                return string.IsNullOrWhiteSpace(message) ? "驱动未返回详细错误。" : message;
            }
            catch (Exception ex)
            {
                return "读取原生接口错误失败：" + ex.Message;
            }
        }

        private static void ZeroMemory(IntPtr buffer, int bytes)
        {
            byte[] zeros = new byte[bytes];
            Marshal.Copy(zeros, 0, buffer, bytes);
        }

        private static string ToStatusText(uint status)
        {
            return "0x" + status.ToString("X8", CultureInfo.InvariantCulture);
        }

        internal sealed class DriverStatus
        {
            public bool Connected { get; set; }
            public string StatusText { get; set; }
            public string Message { get; set; }
        }
    }
}
