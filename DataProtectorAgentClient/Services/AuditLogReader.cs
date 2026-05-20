using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using DataProtectorAgentClient.Models;

namespace DataProtectorAgentClient.Services
{
    internal sealed class AuditLogReader
    {
        private const int MaxLinesToRead = 600;
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        private readonly string auditPath;

        public AuditLogReader(string auditPath)
        {
            this.auditPath = auditPath;
        }

        public IList<SecurityEventViewItem> ReadRecentSecurityEvents(int limit)
        {
            if (string.IsNullOrWhiteSpace(auditPath) || !File.Exists(auditPath))
            {
                return new List<SecurityEventViewItem>();
            }

            List<AuditRecord> records = new List<AuditRecord>();
            foreach (string line in ReadTailLines(auditPath, MaxLinesToRead))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    AuditRecord record = serializer.Deserialize<AuditRecord>(line);
                    if (record != null && IsSecurityEvent(record))
                    {
                        records.Add(record);
                    }
                }
                catch
                {
                }
            }

            return records
                .OrderByDescending(record => ParseUtcOrMin(record.TimestampUtc))
                .Take(Math.Max(1, limit))
                .Select(ConvertEvent)
                .ToList();
        }

        private static IEnumerable<string> ReadTailLines(string path, int maxLines)
        {
            string[] lines = File.ReadAllLines(path, Encoding.UTF8);
            int skip = Math.Max(0, lines.Length - maxLines);
            return lines.Skip(skip);
        }

        private static SecurityEventViewItem ConvertEvent(AuditRecord record)
        {
            string severity = ResolveSeverity(record);
            string disposition = ResolveDisposition(record);
            DateTime timestamp = ParseUtcOrMin(record.TimestampUtc);

            return new SecurityEventViewItem
            {
                TimeText = timestamp == DateTime.MinValue ? string.Empty : timestamp.ToLocalTime().ToString("MM-dd HH:mm:ss", CultureInfo.CurrentCulture),
                Category = TranslateCategory(ClassifyCategory(record)),
                Severity = TranslateSeverity(severity),
                Disposition = TranslateDisposition(disposition),
                Target = ResolveTargetDisplay(record),
                Source = ResolveSourceDisplay(record),
                Message = record.Message ?? string.Empty,
                Status = record.Status ?? string.Empty,
                SeverityBrushKey = SeverityBrushKey(severity, disposition)
            };
        }

        private static string ResolveSourceDisplay(AuditRecord record)
        {
            string process = FirstNonEmpty(record.SourceProcess, record.Extension);
            string pid = string.IsNullOrWhiteSpace(record.SourcePid) ? string.Empty : "PID " + record.SourcePid;
            string user = FirstNonEmpty(record.SourceUser, record.Actor);
            string host = FirstNonEmpty(record.SourceHost, record.Host);
            return JoinCompact(" / ", process, pid, user, host);
        }

        private static string ResolveTargetDisplay(AuditRecord record)
        {
            string target = FirstNonEmpty(record.ObjectName, record.TargetProcess, record.Target);
            string type = record.ObjectType ?? string.Empty;
            string format = record.ObjectFormat ?? string.Empty;
            string pid = string.IsNullOrWhiteSpace(record.TargetPid) ? string.Empty : "PID " + record.TargetPid;
            return JoinCompact(" / ", type, target, format, pid);
        }

        private static string FirstNonEmpty(params string[] values)
        {
            if (values == null)
            {
                return string.Empty;
            }

            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
        }

        private static string JoinCompact(string separator, params string[] values)
        {
            return string.Join(separator, (values ?? new string[0]).Where(value => !string.IsNullOrWhiteSpace(value)).ToArray());
        }

        private static bool IsSecurityEvent(AuditRecord record)
        {
            if (record == null || IsNetworkAwarenessRecord(record))
            {
                return false;
            }

            string category = ClassifyCategory(record);
            if (category == "webshell" ||
                category == "hashdump" ||
                category == "lateral" ||
                category == "userhook" ||
                category == "dlp" ||
                category == "smtp")
            {
                return true;
            }

            string severity = ResolveSeverity(record);
            string disposition = ResolveDisposition(record);
            return severity == "critical" || severity == "warning" || disposition == "blocked";
        }

        private static string ClassifyCategory(AuditRecord record)
        {
            string action = record == null || record.Action == null ? string.Empty : record.Action;

            if (action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".webshell.", StringComparison.OrdinalIgnoreCase) >= 0 ||
                action.EndsWith(".webshell", StringComparison.OrdinalIgnoreCase))
            {
                return "webshell";
            }

            if (action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashprotect.", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".hashdump.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "hashdump";
            }

            if (action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("policy.lateral", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("central.policy.lateral", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".lateral.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "lateral";
            }

            if (action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("policy.userhook", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("central.policy.userhook", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".userhook.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "userhook";
            }

            if (action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("policy.dlp", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("central.policy.dlp", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".dlp.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "dlp";
            }

            if (action.StartsWith("network.smtp", StringComparison.OrdinalIgnoreCase) ||
                action.EndsWith(".smtp", StringComparison.OrdinalIgnoreCase))
            {
                return "smtp";
            }

            return "system";
        }

        private static bool IsNetworkAwarenessRecord(AuditRecord record)
        {
            string action = record == null || record.Action == null ? string.Empty : record.Action;
            return action.StartsWith("network.connection.", StringComparison.OrdinalIgnoreCase);
        }

        private static string ResolveSeverity(AuditRecord record)
        {
            if (record != null && !string.IsNullOrWhiteSpace(record.Severity))
            {
                return record.Severity;
            }

            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string message = record == null || record.Message == null ? string.Empty : record.Message;
            string status = record == null || record.Status == null ? string.Empty : record.Status;

            if (action.StartsWith("webshell.danger", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashdump.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("lateral.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.unhook-detected", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.hook-overwrite-detected", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.syscall-bypass-risk", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-manual-map", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-rwx", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-private-syscall-stub", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("dlp.clipboard.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("dlp.screenshot.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".blocked", StringComparison.OrdinalIgnoreCase) >= 0 ||
                status.Equals("0xC0000022", StringComparison.OrdinalIgnoreCase))
            {
                return "critical";
            }

            if (action.StartsWith("webshell.warning", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("security.audit.drain.failed", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".failed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                message.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "warning";
            }

            if (action.StartsWith("webshell.notice", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("network.smtp", StringComparison.OrdinalIgnoreCase))
            {
                return "info";
            }

            return "operational";
        }

        private static string ResolveDisposition(AuditRecord record)
        {
            if (record != null && !string.IsNullOrWhiteSpace(record.Disposition))
            {
                return record.Disposition;
            }

            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string status = record == null || record.Status == null ? string.Empty : record.Status;
            string message = record == null || record.Message == null ? string.Empty : record.Message;

            if (status.Equals("0xC0000022", StringComparison.OrdinalIgnoreCase) ||
                message.IndexOf("blocked", StringComparison.OrdinalIgnoreCase) >= 0 ||
                message.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "blocked";
            }

            if (record != null && !record.Succeeded)
            {
                return "failed";
            }

            if (action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("network.smtp", StringComparison.OrdinalIgnoreCase))
            {
                return "observed";
            }

            return "completed";
        }

        private static DateTime ParseUtcOrMin(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed)
                ? parsed.ToUniversalTime()
                : DateTime.MinValue;
        }

        private static string TranslateCategory(string category)
        {
            if (category == "webshell") return "脚本木马";
            if (category == "hashdump") return "凭据抓取";
            if (category == "lateral") return "横向移动";
            if (category == "dlp") return "防泄密";
            if (category == "smtp") return "邮件外发";
            return "系统";
        }

        private static string TranslateSeverity(string severity)
        {
            if (severity == "critical") return "紧急";
            if (severity == "warning") return "警告";
            if (severity == "info") return "提示";
            return "运行";
        }

        private static string TranslateDisposition(string disposition)
        {
            if (disposition == "blocked") return "已阻止";
            if (disposition == "failed") return "异常";
            if (disposition == "observed") return "已记录";
            return "完成";
        }

        private static string SeverityBrushKey(string severity, string disposition)
        {
            if (disposition == "blocked" || severity == "critical") return "DpDangerBrush";
            if (severity == "warning") return "DpWarningBrush";
            if (severity == "info") return "DpCommandBrush";
            return "DpMutedBrush";
        }
    }
}
