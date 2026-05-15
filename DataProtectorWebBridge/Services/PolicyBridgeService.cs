using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using DataProtectorWebBridge.Native;

namespace DataProtectorWebBridge.Services
{
    internal sealed class PolicyBridgeService
    {
        private const uint SuccessStatus = 0;
        private const uint BufferTooSmallStatus = 0xE0010005;
        private const uint RuleTypeProcessName = 1;
        private const uint RuleTypeProcessDirectory = 2;
        private const uint RuleTypeExcludedDirectory = 3;
        private const uint NetworkRuleTypeIp = 1;
        private const uint NetworkRuleTypeDomain = 2;
        private const uint NetworkActionAllow = 0;
        private const uint NetworkActionBlock = 1;
        private const uint NetworkProtocolAny = 0;
        private const uint NetworkProtocolIcmp = 1;
        private const uint NetworkProtocolTcp = 6;
        private const uint NetworkProtocolUdp = 17;
        private const uint NetworkDirectionInbound = 0;
        private const uint NetworkDirectionOutbound = 1;
        private const uint NetworkDirectionBoth = 2;
        private const int MessageBufferChars = 512;
        private const int MaxQueryAttempts = 4;

        private readonly AuditLog auditLog;

        public PolicyBridgeService(AuditLog auditLog)
        {
            this.auditLog = auditLog;
        }

        public object GetStatus()
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyCheckConnection);
            return new
            {
                connected = result.succeeded,
                status = result.statusText,
                message = result.message,
                bridgePid = System.Diagnostics.Process.GetCurrentProcess().Id,
                machine = Environment.MachineName,
                user = Environment.UserName,
                auditPath = auditLog.FilePath
            };
        }

        public PolicyRuleDto[] QueryRules()
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
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativePolicyRule[] nativeRules =
                    new DataProtectorPolicyNative.NativePolicyRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
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
                        List<PolicyRuleDto> rules = new List<PolicyRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
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

            throw new BridgeException(BufferTooSmallStatus, "The driver rule set changed while querying. Please retry.");
        }

        public NetworkRuleDto[] QueryNetworkRules()
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
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeNetworkRule[] nativeRules =
                    new DataProtectorPolicyNative.NativeNetworkRule[checked((int)ruleCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
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
                        List<NetworkRuleDto> rules = new List<NetworkRuleDto>();
                        for (int index = 0; index < returned && index < nativeRules.Length; index++)
                        {
                            rules.Add(ConvertNetworkRule(nativeRules[index]));
                        }

                        return rules.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
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

            throw new BridgeException(BufferTooSmallStatus, "The driver network rule set changed while querying. Please retry.");
        }

        public OperationResult AddRule(PolicyRuleRequest request)
        {
            PolicyRuleRequest normalized = NormalizeRequest(request);
            OperationResult result = Invoke(() =>
            {
                if (normalized.Kind == "processName")
                {
                    return DataProtectorPolicyNative.DpPolicyAddProcessNameRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "processDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyAddProcessDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "excludedDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyAddExcludedDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                throw new BridgeException(1, "Unsupported rule kind.");
            });

            auditLog.Append(normalized.Actor, "policy.rule.add." + normalized.Kind, normalized.Value, normalized.Extension, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveRule(PolicyRuleRequest request)
        {
            PolicyRuleRequest normalized = NormalizeRequest(request);
            OperationResult result = Invoke(() =>
            {
                if (normalized.Kind == "processName")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveProcessNameRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "processDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveProcessDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                if (normalized.Kind == "excludedDirectory")
                {
                    return DataProtectorPolicyNative.DpPolicyRemoveExcludedDirectoryRuleEx(normalized.Value, normalized.Extension);
                }

                throw new BridgeException(1, "Unsupported rule kind.");
            });

            auditLog.Append(normalized.Actor, "policy.rule.remove." + normalized.Kind, normalized.Value, normalized.Extension, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearProcessRules);
            auditLog.Append(actor, "policy.rules.clear", "*", "*", result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult AddNetworkRule(NetworkRuleRequest request)
        {
            NetworkRuleDto normalized = NormalizeNetworkRule(request);
            OperationResult result = Invoke(() =>
            {
                DataProtectorPolicyNative.NativeNetworkRule nativeRule = ToNativeNetworkRule(normalized);
                try
                {
                    return DataProtectorPolicyNative.DpPolicyAddNetworkRule(ref nativeRule);
                }
                finally
                {
                    FreeNativeNetworkRule(nativeRule);
                }
            });

            auditLog.Append(normalized.actor, "policy.network.add." + normalized.kind, normalized.displayTarget, string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult RemoveNetworkRule(NetworkRuleRequest request)
        {
            if (request == null || request.ruleId == 0)
            {
                throw new BridgeException(1, "Network rule id is required.");
            }

            OperationResult result = Invoke(() => DataProtectorPolicyNative.DpPolicyRemoveNetworkRule(request.ruleId));
            auditLog.Append(request.actor, "policy.network.remove", request.ruleId.ToString(CultureInfo.InvariantCulture), string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public OperationResult ClearNetworkRules(string actor)
        {
            OperationResult result = Invoke(DataProtectorPolicyNative.DpPolicyClearNetworkRules);
            auditLog.Append(actor, "policy.network.clear", "*", string.Empty, result.succeeded, result.status, result.message);
            return result;
        }

        public SmtpEventDto[] QuerySmtpEvents()
        {
            uint status = SuccessStatus;

            for (int attempt = 0; attempt < MaxQueryAttempts; attempt++)
            {
                uint eventCount;
                uint stringCharsRequired;
                status = DataProtectorPolicyNative.DpPolicyQuerySmtpEvents(
                    new DataProtectorPolicyNative.NativeSmtpEvent[0],
                    0,
                    out eventCount,
                    IntPtr.Zero,
                    0,
                    out stringCharsRequired);

                if (status != SuccessStatus && status != BufferTooSmallStatus)
                {
                    throw new BridgeException(status, ReadLastErrorMessage());
                }

                DataProtectorPolicyNative.NativeSmtpEvent[] nativeEvents =
                    new DataProtectorPolicyNative.NativeSmtpEvent[checked((int)eventCount)];
                uint stringBufferChars = Math.Max(1u, stringCharsRequired);
                IntPtr stringBuffer = IntPtr.Zero;

                try
                {
                    int byteCount = checked((int)stringBufferChars * sizeof(char));
                    stringBuffer = Marshal.AllocHGlobal(byteCount);
                    ZeroMemory(stringBuffer, byteCount);

                    status = DataProtectorPolicyNative.DpPolicyQuerySmtpEvents(
                        nativeEvents,
                        (uint)nativeEvents.Length,
                        out eventCount,
                        stringBuffer,
                        stringBufferChars,
                        out stringCharsRequired);

                    if (status == SuccessStatus)
                    {
                        int returned = checked((int)eventCount);
                        List<SmtpEventDto> events = new List<SmtpEventDto>();
                        for (int index = 0; index < returned && index < nativeEvents.Length; index++)
                        {
                            events.Add(ConvertSmtpEvent(nativeEvents[index]));
                        }

                        return events.ToArray();
                    }

                    if (status != BufferTooSmallStatus)
                    {
                        throw new BridgeException(status, ReadLastErrorMessage());
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

            throw new BridgeException(BufferTooSmallStatus, "The driver SMTP event queue changed while querying. Please retry.");
        }

        public AuditLog.AuditRecord[] DrainSmtpAuditRecords()
        {
            SmtpEventDto[] events = QuerySmtpEvents();
            List<AuditLog.AuditRecord> records = new List<AuditLog.AuditRecord>();

            foreach (SmtpEventDto item in events)
            {
                string endpoint = item.remoteEndpoint;
                string target = item.from + " -> " + item.to;
                string message = "SMTP envelope observed on " + endpoint + " by PID " + item.processId.ToString(CultureInfo.InvariantCulture) + ".";

                auditLog.Append("network-sensor",
                                "network.smtp.send",
                                target,
                                endpoint,
                                true,
                                SuccessStatus,
                                message);

                records.Add(new AuditLog.AuditRecord
                {
                    TimestampUtc = DateTime.UtcNow.ToString("o"),
                    Actor = "network-sensor",
                    Action = "network.smtp.send",
                    Target = target,
                    Extension = endpoint,
                    Succeeded = true,
                    Status = "0x00000000",
                    Message = message
                });
            }

            return records.ToArray();
        }

        private static PolicyRuleRequest NormalizeRequest(PolicyRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Request body is required.");
            }

            string kind = (request.Kind ?? string.Empty).Trim();
            string value = (request.Value ?? string.Empty).Trim();
            string extension = NormalizeExtension(request.Extension);

            if (string.IsNullOrWhiteSpace(kind))
            {
                throw new BridgeException(1, "Rule kind is required.");
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new BridgeException(1, "Rule value is required.");
            }

            if (kind == "processName" && !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                value += ".exe";
            }

            return new PolicyRuleRequest
            {
                Kind = kind,
                Value = value,
                Extension = extension,
                Actor = request.Actor
            };
        }

        private static string NormalizeExtension(string extension)
        {
            string normalized = string.IsNullOrWhiteSpace(extension) ? ".dpf" : extension.Trim();
            return normalized.StartsWith(".", StringComparison.Ordinal) ? normalized : "." + normalized;
        }

        private static NetworkRuleDto NormalizeNetworkRule(NetworkRuleRequest request)
        {
            if (request == null)
            {
                throw new BridgeException(1, "Request body is required.");
            }

            string kind = (request.kind ?? string.Empty).Trim();
            string action = NormalizeNetworkToken(request.action, "block");
            string protocol = NormalizeNetworkToken(request.protocol, "any");
            string direction = NormalizeNetworkToken(request.direction, "outbound");
            string domain = (request.domain ?? string.Empty).Trim().ToLowerInvariant();
            string remoteAddress = (request.remoteAddress ?? string.Empty).Trim();
            string localAddress = (request.localAddress ?? string.Empty).Trim();

            if (request.ruleId == 0)
            {
                throw new BridgeException(1, "Network rule id is required.");
            }

            if (kind != "ip" && kind != "domain")
            {
                throw new BridgeException(1, "Network rule kind must be ip or domain.");
            }

            if (action != "allow" && action != "block")
            {
                throw new BridgeException(1, "Network rule action must be allow or block.");
            }

            if (protocol != "any" && protocol != "icmp" && protocol != "tcp" && protocol != "udp")
            {
                throw new BridgeException(1, "Network protocol must be any, icmp, tcp, or udp.");
            }

            if (direction != "inbound" && direction != "outbound" && direction != "both")
            {
                throw new BridgeException(1, "Network direction must be inbound, outbound, or both.");
            }

            if (kind == "domain" && string.IsNullOrWhiteSpace(domain))
            {
                throw new BridgeException(1, "Domain rule requires a domain.");
            }

            if (kind == "domain" && protocol == "icmp")
            {
                throw new BridgeException(1, "Domain rules do not support ICMP.");
            }

            if (kind == "ip" && string.IsNullOrWhiteSpace(remoteAddress))
            {
                remoteAddress = "*";
            }

            NetworkRuleDto normalized = new NetworkRuleDto
            {
                ruleId = request.ruleId,
                kind = kind,
                action = action,
                protocol = protocol,
                direction = direction,
                localAddress = localAddress,
                localPort = request.localPort,
                remoteAddress = remoteAddress,
                remotePort = request.remotePort,
                domain = domain,
                actor = request.actor
            };

            normalized.displayTarget = kind == "domain" ? domain : remoteAddress;
            return normalized;
        }

        private static string NormalizeNetworkToken(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant();
        }

        private static PolicyRuleDto ConvertRule(DataProtectorPolicyNative.NativePolicyRule nativeRule)
        {
            string kind = "unknown";
            if (nativeRule.RuleType == RuleTypeProcessName)
            {
                kind = "processName";
            }
            else if (nativeRule.RuleType == RuleTypeProcessDirectory)
            {
                kind = "processDirectory";
            }
            else if (nativeRule.RuleType == RuleTypeExcludedDirectory)
            {
                kind = "excludedDirectory";
            }

            return new PolicyRuleDto
            {
                kind = kind,
                value = Marshal.PtrToStringUni(nativeRule.Value) ?? string.Empty,
                extension = Marshal.PtrToStringUni(nativeRule.Extension) ?? ".dpf"
            };
        }

        private static NetworkRuleDto ConvertNetworkRule(DataProtectorPolicyNative.NativeNetworkRule nativeRule)
        {
            return new NetworkRuleDto
            {
                ruleId = nativeRule.RuleId,
                kind = nativeRule.Kind == NetworkRuleTypeDomain ? "domain" : "ip",
                action = nativeRule.Action == NetworkActionAllow ? "allow" : "block",
                protocol = FromProtocol(nativeRule.Protocol),
                direction = FromDirection(nativeRule.Direction),
                localAddress = FormatAddress(nativeRule.LocalAddress, nativeRule.LocalAddressMask),
                localPort = nativeRule.LocalPort,
                remoteAddress = FormatAddress(nativeRule.RemoteAddress, nativeRule.RemoteAddressMask),
                remotePort = nativeRule.RemotePort,
                domain = Marshal.PtrToStringUni(nativeRule.Domain) ?? string.Empty,
                displayTarget = nativeRule.Kind == NetworkRuleTypeDomain
                    ? (Marshal.PtrToStringUni(nativeRule.Domain) ?? string.Empty)
                    : FormatAddress(nativeRule.RemoteAddress, nativeRule.RemoteAddressMask)
            };
        }

        private static SmtpEventDto ConvertSmtpEvent(DataProtectorPolicyNative.NativeSmtpEvent nativeEvent)
        {
            string localEndpoint = FormatEndpoint(nativeEvent.LocalAddress, nativeEvent.LocalPort);
            string remoteEndpoint = FormatEndpoint(nativeEvent.RemoteAddress, nativeEvent.RemotePort);

            return new SmtpEventDto
            {
                sequence = nativeEvent.Sequence,
                processId = nativeEvent.ProcessId,
                localAddress = FormatAddress(nativeEvent.LocalAddress, 0xFFFFFFFFu),
                remoteAddress = FormatAddress(nativeEvent.RemoteAddress, 0xFFFFFFFFu),
                localPort = nativeEvent.LocalPort,
                remotePort = nativeEvent.RemotePort,
                localEndpoint = localEndpoint,
                remoteEndpoint = remoteEndpoint,
                from = Marshal.PtrToStringUni(nativeEvent.From) ?? string.Empty,
                to = Marshal.PtrToStringUni(nativeEvent.To) ?? string.Empty
            };
        }

        private static DataProtectorPolicyNative.NativeNetworkRule ToNativeNetworkRule(NetworkRuleDto rule)
        {
            uint localAddress;
            uint localMask;
            uint remoteAddress;
            uint remoteMask;
            ParseAddress(rule.localAddress, out localAddress, out localMask);
            ParseAddress(rule.remoteAddress, out remoteAddress, out remoteMask);

            return new DataProtectorPolicyNative.NativeNetworkRule
            {
                RuleId = rule.ruleId,
                Kind = rule.kind == "domain" ? NetworkRuleTypeDomain : NetworkRuleTypeIp,
                Action = rule.action == "allow" ? NetworkActionAllow : NetworkActionBlock,
                Protocol = ToProtocol(rule.protocol),
                Direction = ToDirection(rule.direction),
                LocalAddress = localAddress,
                LocalAddressMask = localMask,
                RemoteAddress = remoteAddress,
                RemoteAddressMask = remoteMask,
                LocalPort = rule.localPort,
                RemotePort = rule.kind == "domain" && rule.remotePort == 0 ? (ushort)53 : rule.remotePort,
                Domain = string.IsNullOrWhiteSpace(rule.domain) ? IntPtr.Zero : Marshal.StringToHGlobalUni(rule.domain)
            };
        }

        internal static void FreeNativeNetworkRule(DataProtectorPolicyNative.NativeNetworkRule rule)
        {
            if (rule.Domain != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rule.Domain);
            }
        }

        private static uint ToProtocol(string protocol)
        {
            if (string.Equals(protocol, "icmp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolIcmp;
            if (string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolTcp;
            if (string.Equals(protocol, "udp", StringComparison.OrdinalIgnoreCase)) return NetworkProtocolUdp;
            return NetworkProtocolAny;
        }

        private static string FromProtocol(uint protocol)
        {
            if (protocol == NetworkProtocolIcmp) return "icmp";
            if (protocol == NetworkProtocolTcp) return "tcp";
            if (protocol == NetworkProtocolUdp) return "udp";
            return "any";
        }

        private static uint ToDirection(string direction)
        {
            if (string.Equals(direction, "inbound", StringComparison.OrdinalIgnoreCase)) return NetworkDirectionInbound;
            if (string.Equals(direction, "both", StringComparison.OrdinalIgnoreCase)) return NetworkDirectionBoth;
            return NetworkDirectionOutbound;
        }

        private static string FromDirection(uint direction)
        {
            if (direction == NetworkDirectionInbound) return "inbound";
            if (direction == NetworkDirectionBoth) return "both";
            return "outbound";
        }

        private static void ParseAddress(string value, out uint address, out uint mask)
        {
            address = 0;
            mask = 0;

            if (string.IsNullOrWhiteSpace(value) || value == "*" || value == "0.0.0.0/0")
            {
                return;
            }

            string[] parts = value.Split('/');
            IPAddress ip;
            if (!IPAddress.TryParse(parts[0], out ip))
            {
                throw new BridgeException(1, "Invalid IPv4 address: " + value);
            }

            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length != 4)
            {
                throw new BridgeException(1, "Only IPv4 network rules are supported.");
            }

            address = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            mask = 0xFFFFFFFFu;

            if (parts.Length > 1)
            {
                int prefix;
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > 32)
                {
                    throw new BridgeException(1, "Invalid IPv4 CIDR prefix: " + value);
                }

                mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
            }
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

        private static string FormatEndpoint(uint address, ushort port)
        {
            string ip = FormatAddress(address, 0xFFFFFFFFu);
            return port == 0 ? ip : ip + ":" + port.ToString(CultureInfo.InvariantCulture);
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

        private static OperationResult Invoke(Func<uint> operation)
        {
            try
            {
                uint status = operation();
                bool succeeded = status == SuccessStatus;
                return new OperationResult
                {
                    succeeded = succeeded,
                    status = status,
                    statusText = ToStatusText(status),
                    message = succeeded ? "Success." : ReadLastErrorMessage()
                };
            }
            catch (BridgeException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new OperationResult
                {
                    succeeded = false,
                    status = 1,
                    statusText = ToStatusText(1),
                    message = ex.Message
                };
            }
        }

        private static string ReadLastErrorMessage()
        {
            try
            {
                StringBuilder buffer = new StringBuilder(MessageBufferChars);
                DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(buffer, (uint)buffer.Capacity);
                return buffer.ToString();
            }
            catch (Exception ex)
            {
                return "Cannot read native policy API error: " + ex.Message;
            }
        }

        private static void ZeroMemory(IntPtr buffer, int bytes)
        {
            byte[] zeros = new byte[bytes];
            Marshal.Copy(zeros, 0, buffer, bytes);
        }

        private static string ToStatusText(uint status)
        {
            return "0x" + status.ToString("X8");
        }

        public sealed class PolicyRuleRequest
        {
            public string Kind { get; set; }
            public string Value { get; set; }
            public string Extension { get; set; }
            public string Actor { get; set; }
        }

        public sealed class PolicyRuleDto
        {
            public string kind { get; set; }
            public string value { get; set; }
            public string extension { get; set; }
        }

        public class NetworkRuleRequest
        {
            public uint ruleId { get; set; }
            public string kind { get; set; }
            public string action { get; set; }
            public string protocol { get; set; }
            public string direction { get; set; }
            public string localAddress { get; set; }
            public ushort localPort { get; set; }
            public string remoteAddress { get; set; }
            public ushort remotePort { get; set; }
            public string domain { get; set; }
            public string actor { get; set; }
        }

        public sealed class NetworkRuleDto : NetworkRuleRequest
        {
            public string displayTarget { get; set; }
        }

        public sealed class SmtpEventDto
        {
            public ulong sequence { get; set; }
            public ulong processId { get; set; }
            public string localAddress { get; set; }
            public string remoteAddress { get; set; }
            public ushort localPort { get; set; }
            public ushort remotePort { get; set; }
            public string localEndpoint { get; set; }
            public string remoteEndpoint { get; set; }
            public string from { get; set; }
            public string to { get; set; }
        }

        public sealed class OperationResult
        {
            public bool succeeded { get; set; }
            public uint status { get; set; }
            public string statusText { get; set; }
            public string message { get; set; }
        }

        public sealed class BridgeException : Exception
        {
            public BridgeException(uint status, string message)
                : base(message)
            {
                Status = status;
            }

            public uint Status { get; private set; }
        }
    }
}
