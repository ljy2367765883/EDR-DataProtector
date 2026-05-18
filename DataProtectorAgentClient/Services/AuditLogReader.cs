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
                Target = record.Target ?? string.Empty,
                Source = string.IsNullOrWhiteSpace(record.Actor) ? (record.Host ?? string.Empty) : record.Actor,
                Message = record.Message ?? string.Empty,
                Status = record.Status ?? string.Empty,
                SeverityBrushKey = SeverityBrushKey(severity, disposition)
            };
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
            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string message = record == null || record.Message == null ? string.Empty : record.Message;
            string status = record == null || record.Status == null ? string.Empty : record.Status;

            if (action.StartsWith("webshell.danger", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashdump.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("lateral.blocked", StringComparison.OrdinalIgnoreCase) ||
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
            if (category == "webshell") return "WebShell";
            if (category == "hashdump") return "反 Dump";
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
