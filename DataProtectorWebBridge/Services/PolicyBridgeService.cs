using System;
using System.Collections.Generic;
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
