using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal sealed class AuditLog
    {
        private const int DefaultLimit = 200;
        private readonly object syncRoot = new object();
        private readonly JavaScriptSerializer serializer = JsonResponse.CreateSerializer();

        public AuditLog()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            DirectoryPath = Path.Combine(dataRoot, "DataProtector");
            FilePath = Path.Combine(DirectoryPath, "WebAudit.jsonl");
        }

        public string DirectoryPath { get; private set; }

        public string FilePath { get; private set; }

        public static int NormalizeLimit(int limit)
        {
            return limit <= 0 ? DefaultLimit : Math.Min(limit, 1000);
        }

        public static int NormalizePage(int page)
        {
            return page <= 0 ? 1 : Math.Min(page, 1000000);
        }

        public static int NormalizePageSize(int pageSize, int limit)
        {
            return NormalizeLimit(pageSize > 0 ? pageSize : limit);
        }

        public static string ClassifyCategory(AuditRecord record)
        {
            string action = record == null || record.Action == null ? string.Empty : record.Action;

            if (IsNetworkAwarenessRecord(record))
            {
                return "system";
            }

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

            if (action.IndexOf(".network.", StringComparison.OrdinalIgnoreCase) >= 0 ||
                action.StartsWith("policy.network", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("central.policy.network", StringComparison.OrdinalIgnoreCase))
            {
                return "network";
            }

            if (action.StartsWith("remote.", StringComparison.OrdinalIgnoreCase))
            {
                return "remote";
            }

            if (action.StartsWith("agent.", StringComparison.OrdinalIgnoreCase))
            {
                return "agent";
            }

            if (action.StartsWith("policy.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("central.policy.", StringComparison.OrdinalIgnoreCase))
            {
                return "policy";
            }

            return "system";
        }

        public static string ResolveHost(AuditRecord record)
        {
            if (record == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(record.Host))
            {
                return record.Host;
            }

            if (!string.IsNullOrWhiteSpace(record.Actor))
            {
                return record.Actor;
            }

            if (!string.IsNullOrWhiteSpace(record.SourceHost))
            {
                return record.SourceHost;
            }

            return string.Empty;
        }

        public static string ResolveSeverity(AuditRecord record)
        {
            if (record != null && !string.IsNullOrWhiteSpace(record.Severity))
            {
                return record.Severity;
            }

            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string message = record == null || record.Message == null ? string.Empty : record.Message;
            string status = record == null || record.Status == null ? string.Empty : record.Status;

            if (IsUserHookCoverageRecord(record))
            {
                return "warning";
            }

            if (action.StartsWith("webshell.danger", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashdump.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("lateral.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("dlp.clipboard.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("dlp.screenshot.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.IndexOf(".blocked", StringComparison.OrdinalIgnoreCase) >= 0 ||
                status.Equals("0xC0000022", StringComparison.OrdinalIgnoreCase))
            {
                return "critical";
            }

            if (action.StartsWith("webshell.warning", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("security.audit.drain.failed", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.unhook-detected", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.hook-overwrite-detected", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.syscall-bypass-risk", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-manual-map", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-rwx", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-private-syscall-stub", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.runtime.memory-private-executable", StringComparison.OrdinalIgnoreCase) ||
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

        public static string ResolveDisposition(AuditRecord record)
        {
            if (record != null && !string.IsNullOrWhiteSpace(record.Disposition))
            {
                return record.Disposition;
            }

            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string status = record == null || record.Status == null ? string.Empty : record.Status;
            string message = record == null || record.Message == null ? string.Empty : record.Message;

            if (IsUserHookCoverageRecord(record))
            {
                return "observed";
            }

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

        public static bool Matches(AuditRecord record, AuditQueryOptions options)
        {
            if (record == null)
            {
                return false;
            }

            if (IsNetworkAwarenessRecord(record))
            {
                return false;
            }

            if (IsHiddenOperationalRecord(record))
            {
                return false;
            }

            if (options == null)
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(options.Category) &&
                !string.Equals(options.Category, "all", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ClassifyCategory(record), options.Category, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Host) &&
                !string.Equals(options.Host, "all", StringComparison.OrdinalIgnoreCase) &&
                ResolveHost(record).IndexOf(options.Host, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Result))
            {
                if (string.Equals(options.Result, "success", StringComparison.OrdinalIgnoreCase) && !record.Succeeded)
                {
                    return false;
                }

                if (string.Equals(options.Result, "failed", StringComparison.OrdinalIgnoreCase) && record.Succeeded)
                {
                    return false;
                }
            }

            if (!string.IsNullOrWhiteSpace(options.Severity) &&
                !string.Equals(options.Severity, "all", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ResolveSeverity(record), options.Severity, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Disposition) &&
                !string.Equals(options.Disposition, "all", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ResolveDisposition(record), options.Disposition, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            DateTime timestampUtc;
            if (!DateTime.TryParse(record.TimestampUtc, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out timestampUtc))
            {
                timestampUtc = DateTime.MinValue;
            }

            DateTime fromUtc;
            if (TryParseUtc(options.FromUtc, out fromUtc) && timestampUtc < fromUtc)
            {
                return false;
            }

            DateTime toUtc;
            if (TryParseUtc(options.ToUtc, out toUtc) && timestampUtc > toUtc)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Search))
            {
                string haystack = string.Join("\n", new[]
                {
                    record.Actor ?? string.Empty,
                    ResolveHost(record),
                    ResolveSeverity(record),
                    ResolveDisposition(record),
                    ResolveSourceDisplay(record),
                    ResolveTargetDisplay(record),
                    record.SourceProcess ?? string.Empty,
                    record.SourceUser ?? string.Empty,
                    record.SourcePid ?? string.Empty,
                    record.SourceHost ?? string.Empty,
                    record.TargetProcess ?? string.Empty,
                    record.TargetPid ?? string.Empty,
                    record.TargetHost ?? string.Empty,
                    record.ObjectType ?? string.Empty,
                    record.ObjectName ?? string.Empty,
                    record.ObjectFormat ?? string.Empty,
                    record.Action ?? string.Empty,
                    record.Target ?? string.Empty,
                    record.Extension ?? string.Empty,
                    record.Status ?? string.Empty,
                    record.Message ?? string.Empty
                });

                if (haystack.IndexOf(options.Search, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsNetworkAwarenessRecord(AuditRecord record)
        {
            string action = record == null || record.Action == null ? string.Empty : record.Action;
            return action.StartsWith("network.connection.", StringComparison.OrdinalIgnoreCase);
        }

        public void Append(string actor, string action, string target, string extension, bool succeeded, uint status, string message)
        {
            AuditRecord record = new AuditRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Host = Environment.MachineName,
                Actor = string.IsNullOrWhiteSpace(actor) ? Environment.UserName : actor,
                Action = action ?? string.Empty,
                Target = target ?? string.Empty,
                Extension = extension ?? string.Empty,
                Succeeded = succeeded,
                Status = "0x" + status.ToString("X8"),
                Message = message ?? string.Empty
            };

            AppendRecord(record);
        }

        public void AppendRecord(AuditRecord record)
        {
            if (record == null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(record.TimestampUtc))
            {
                record.TimestampUtc = DateTime.UtcNow.ToString("o");
            }

            if (string.IsNullOrWhiteSpace(record.Actor))
            {
                record.Actor = Environment.UserName;
            }

            if (string.IsNullOrWhiteSpace(record.Host))
            {
                record.Host = Environment.MachineName;
            }

            record.Action = record.Action ?? string.Empty;
            record.Target = record.Target ?? string.Empty;
            record.Extension = record.Extension ?? string.Empty;
            record.Status = record.Status ?? "0x00000000";
            record.Message = record.Message ?? string.Empty;
            EnrichRecord(record);

            string line = serializer.Serialize(record);

            lock (syncRoot)
            {
                Directory.CreateDirectory(DirectoryPath);
                File.AppendAllText(FilePath, line + Environment.NewLine, Encoding.UTF8);
            }
        }

        public AuditRecord[] ReadRecent(int limit)
        {
            return Read(new AuditQueryOptions { Limit = limit });
        }

        public AuditRecord[] Read(AuditQueryOptions options)
        {
            return ReadPage(options).items;
        }

        public AuditQueryResponse ReadPage(AuditQueryOptions options)
        {
            AuditQueryOptions query = options ?? new AuditQueryOptions();

            lock (syncRoot)
            {
                if (!File.Exists(FilePath))
                {
                    return BuildQueryResponse(new AuditRecord[0], query);
                }

                List<string> lines = File.ReadAllLines(FilePath, Encoding.UTF8)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .ToList();

                List<AuditRecord> records = new List<AuditRecord>();
                foreach (string line in lines)
                {
                    try
                    {
                        records.Add(serializer.Deserialize<AuditRecord>(line));
                    }
                    catch
                    {
                        records.Add(new AuditRecord
                        {
                            TimestampUtc = DateTime.UtcNow.ToString("o"),
                            Actor = "bridge",
                            Action = "audit.parse.failed",
                            Message = line,
                            Succeeded = false,
                            Status = "0x00000000"
                        });
                    }
                }

                return BuildQueryResponse(records, query);
            }
        }

        public void Clear(string actor)
        {
            lock (syncRoot)
            {
                Directory.CreateDirectory(DirectoryPath);
                File.WriteAllText(FilePath, string.Empty, Encoding.UTF8);
            }

            Append(actor, "audit.events.clear", "*", string.Empty, true, 0, "Audit log cleared.");
        }

        public int Remove(AuditDeleteOptions options)
        {
            if (options == null)
            {
                return 0;
            }

            lock (syncRoot)
            {
                if (!File.Exists(FilePath))
                {
                    return 0;
                }

                List<string> lines = File.ReadAllLines(FilePath, Encoding.UTF8)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .ToList();

                List<AuditRecord> records = new List<AuditRecord>();
                foreach (string line in lines)
                {
                    try
                    {
                        records.Add(serializer.Deserialize<AuditRecord>(line));
                    }
                    catch
                    {
                    }
                }

                int originalCount = records.Count;
                records.RemoveAll(record => IsDeleteMatch(record, options));
                int removed = originalCount - records.Count;
                if (removed <= 0)
                {
                    return 0;
                }

                Directory.CreateDirectory(DirectoryPath);
                File.WriteAllLines(
                    FilePath,
                    records.Select(record => serializer.Serialize(record)).ToArray(),
                    Encoding.UTF8);

                return removed;
            }
        }

        public static AuditQueryResponse BuildQueryResponse(IEnumerable<AuditRecord> records, AuditQueryOptions options)
        {
            AuditQueryOptions query = options ?? new AuditQueryOptions();
            int page = NormalizePage(query.Page);
            int pageSize = NormalizePageSize(query.PageSize, query.Limit);
            int skip = Math.Max(0, (page - 1) * pageSize);
            List<AuditRecord> enrichedRecords = (records ?? Enumerable.Empty<AuditRecord>())
                .Select(record =>
                {
                    EnrichRecord(record);
                    return record;
                })
                .Where(record => record != null)
                .Where(record => !IsHiddenOperationalRecord(record))
                .ToList();

            AuditQueryOptions categoryNeutral = CopyWithoutCategory(query);
            List<AuditRecord> baseMatches = enrichedRecords
                .Where(record => Matches(record, categoryNeutral))
                .ToList();

            IEnumerable<AuditRecord> filtered = baseMatches;
            if (!string.IsNullOrWhiteSpace(query.Category) &&
                !string.Equals(query.Category, "all", StringComparison.OrdinalIgnoreCase))
            {
                filtered = filtered.Where(record => string.Equals(ClassifyCategory(record), query.Category, StringComparison.OrdinalIgnoreCase));
            }

            List<AuditRecord> filteredList = filtered
                .OrderByDescending(record => record == null ? string.Empty : record.TimestampUtc, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new AuditQueryResponse
            {
                page = page,
                pageSize = pageSize,
                total = filteredList.Count,
                criticalTotal = filteredList.Count(record => string.Equals(ResolveSeverity(record), "critical", StringComparison.OrdinalIgnoreCase)),
                warningTotal = filteredList.Count(record => string.Equals(ResolveSeverity(record), "warning", StringComparison.OrdinalIgnoreCase)),
                blockedTotal = filteredList.Count(record => string.Equals(ResolveDisposition(record), "blocked", StringComparison.OrdinalIgnoreCase)),
                categorySummaries = BuildCategorySummaries(baseMatches),
                hostSummaries = BuildHostSummaries(filteredList),
                trendBuckets = BuildTrendBuckets(filteredList),
                items = filteredList
                    .Skip(skip)
                    .Take(pageSize)
                    .ToArray()
            };
        }

        public static void EnrichRecord(AuditRecord record)
        {
            if (record == null)
            {
                return;
            }

            record.Host = record.Host ?? string.Empty;
            record.Actor = record.Actor ?? string.Empty;
            record.Action = record.Action ?? string.Empty;
            record.Target = record.Target ?? string.Empty;
            record.Extension = record.Extension ?? string.Empty;
            record.Status = record.Status ?? "0x00000000";
            record.Message = record.Message ?? string.Empty;

            Dictionary<string, string> fields = ParseAuditFields(record.Message);
            string action = record.Action ?? string.Empty;
            record.Severity = NormalizeAuditSeverity(string.IsNullOrWhiteSpace(record.Severity)
                ? FirstNonEmpty(GetField(fields, "severity"), ResolveSeverity(record))
                : record.Severity);
            record.Disposition = NormalizeAuditDisposition(string.IsNullOrWhiteSpace(record.Disposition)
                ? FirstNonEmpty(GetField(fields, "disposition"), ResolveDisposition(record))
                : record.Disposition);

            if (string.IsNullOrWhiteSpace(record.SourceProcess))
            {
                record.SourceProcess = FirstNonEmpty(
                    GetField(fields, "process"),
                    GetField(fields, "source"),
                    GetField(fields, "sourceProcess"),
                    record.Extension);
            }

            if (string.IsNullOrWhiteSpace(record.SourcePid))
            {
                record.SourcePid = FirstNonEmpty(GetField(fields, "pid"), GetField(fields, "sourcePid"));
            }

            if (string.IsNullOrWhiteSpace(record.SourceUser))
            {
                record.SourceUser = record.Actor;
            }

            if (string.IsNullOrWhiteSpace(record.SourceHost))
            {
                record.SourceHost = ResolveHost(record);
            }

            if (string.IsNullOrWhiteSpace(record.TargetProcess))
            {
                record.TargetProcess = FirstNonEmpty(GetField(fields, "targetProcess"), GetField(fields, "target"));
            }

            if (string.IsNullOrWhiteSpace(record.TargetPid))
            {
                record.TargetPid = GetField(fields, "targetPid");
            }

            if (string.IsNullOrWhiteSpace(record.TargetHost))
            {
                record.TargetHost = GetField(fields, "targetHost");
            }

            if (string.IsNullOrWhiteSpace(record.ObjectType))
            {
                record.ObjectType = InferObjectType(record, fields);
            }

            if (string.IsNullOrWhiteSpace(record.ObjectName))
            {
                record.ObjectName = InferObjectName(record, fields);
            }

            if (string.IsNullOrWhiteSpace(record.ObjectFormat))
            {
                record.ObjectFormat = FirstNonEmpty(GetField(fields, "formats"), GetField(fields, "format"));
            }

            if (string.IsNullOrWhiteSpace(record.PolicyName))
            {
                record.PolicyName = InferPolicyName(action);
            }

            if (string.IsNullOrWhiteSpace(record.EventDetails))
            {
                record.EventDetails = record.Message;
            }

            if (string.IsNullOrWhiteSpace(record.TargetProcess) && LooksLikeProcess(record.Target))
            {
                record.TargetProcess = record.Target;
            }
        }

        public static string ResolveSourceDisplay(AuditRecord record)
        {
            if (record == null)
            {
                return string.Empty;
            }

            EnrichRecord(record);
            string process = FirstNonEmpty(record.SourceProcess, record.Extension);
            string pid = string.IsNullOrWhiteSpace(record.SourcePid) ? string.Empty : "PID " + record.SourcePid;
            string user = record.SourceUser ?? string.Empty;
            string host = record.SourceHost ?? string.Empty;
            return JoinCompact(" / ", process, pid, user, host);
        }

        public static string ResolveTargetDisplay(AuditRecord record)
        {
            if (record == null)
            {
                return string.Empty;
            }

            EnrichRecord(record);
            string target = FirstNonEmpty(record.ObjectName, record.TargetProcess, record.Target);
            string type = record.ObjectType ?? string.Empty;
            string format = record.ObjectFormat ?? string.Empty;
            string pid = string.IsNullOrWhiteSpace(record.TargetPid) ? string.Empty : "PID " + record.TargetPid;
            return JoinCompact(" / ", type, target, format, pid);
        }

        private static Dictionary<string, string> ParseAuditFields(string message)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(message))
            {
                return fields;
            }

            foreach (string part in message.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int index = part.IndexOf('=');
                if (index <= 0)
                {
                    continue;
                }

                string key = part.Substring(0, index).Trim();
                string value = part.Substring(index + 1).Trim();
                if (!string.IsNullOrWhiteSpace(key) && !fields.ContainsKey(key))
                {
                    fields[key] = value;
                }
            }

            ExtractLabeledField(message, fields, "Process", "process");
            ExtractLabeledField(message, fields, "Parent", "parentProcess");
            ExtractLabeledField(message, fields, "Command", "commandLine");
            ExtractLabeledField(message, fields, "TargetPID", "targetPid");
            ExtractPidField(message, fields);
            return fields;
        }

        private static void ExtractLabeledField(string message, Dictionary<string, string> fields, string label, string key)
        {
            if (fields.ContainsKey(key))
            {
                return;
            }

            string prefix = label + ": ";
            int index = message.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return;
            }

            index += prefix.Length;
            int end = FindLabeledFieldEnd(message, index);
            string value = end < 0 ? message.Substring(index) : message.Substring(index, end - index);
            if (!string.IsNullOrWhiteSpace(value))
            {
                fields[key] = value.Trim();
            }
        }

        private static int FindLabeledFieldEnd(string message, int startIndex)
        {
            if (string.IsNullOrEmpty(message) || startIndex < 0 || startIndex >= message.Length)
            {
                return -1;
            }

            for (int index = startIndex; index < message.Length; index++)
            {
                char current = message[index];
                if (current == ';')
                {
                    return index;
                }

                if (current != '.')
                {
                    continue;
                }

                bool nextIsSeparator = index + 1 >= message.Length || char.IsWhiteSpace(message[index + 1]);
                bool previousIsPathOrExtension = index > startIndex && index + 1 < message.Length &&
                    char.IsLetterOrDigit(message[index - 1]) &&
                    char.IsLetterOrDigit(message[index + 1]);
                if (nextIsSeparator && !previousIsPathOrExtension)
                {
                    return index;
                }
            }

            return -1;
        }

        private static void ExtractPidField(string message, Dictionary<string, string> fields)
        {
            if (fields.ContainsKey("pid"))
            {
                return;
            }

            string marker = "PID ";
            int index = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return;
            }

            index += marker.Length;
            int end = index;
            while (end < message.Length && char.IsDigit(message[end]))
            {
                end++;
            }

            if (end > index)
            {
                fields["pid"] = message.Substring(index, end - index);
            }
        }

        private static string GetField(Dictionary<string, string> fields, string key)
        {
            string value;
            return fields != null && fields.TryGetValue(key, out value) ? value : string.Empty;
        }

        private static string InferObjectType(AuditRecord record, Dictionary<string, string> fields)
        {
            string action = record.Action ?? string.Empty;
            string channel = GetField(fields, "channel");
            string objectKind = GetField(fields, "object");

            if (!string.IsNullOrWhiteSpace(channel) || action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase))
            {
                if (action.IndexOf("screenshot", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    channel.IndexOf("image", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "screenshot";
                }

                if (action.IndexOf("clipboard", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    channel.IndexOf("clipboard", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "clipboard";
                }

                return FirstNonEmpty(objectKind, channel, "dlp");
            }

            if (action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase)) return "file";
            if (action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase)) return "credential";
            if (action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase)) return "lateral-target";
            if (action.StartsWith("network.smtp", StringComparison.OrdinalIgnoreCase)) return "smtp";
            if (IsUserHookCoverageRecord(record)) return "sensor-health";
            if (action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("behavior.chain.", StringComparison.OrdinalIgnoreCase)) return "process-behavior";
            return string.Empty;
        }

        private static string InferObjectName(AuditRecord record, Dictionary<string, string> fields)
        {
            string action = record.Action ?? string.Empty;
            string objectKind = GetField(fields, "object");
            string window = GetField(fields, "window");

            if (action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase))
            {
                return JoinCompact(" / ", FirstNonEmpty(objectKind, record.Target), window);
            }

            return record.Target ?? string.Empty;
        }

        private static string InferPolicyName(string action)
        {
            if (string.IsNullOrWhiteSpace(action))
            {
                return string.Empty;
            }

            if (action.StartsWith("dlp.", StringComparison.OrdinalIgnoreCase)) return "dlp";
            if (action.StartsWith("webshell.", StringComparison.OrdinalIgnoreCase)) return "webshell";
            if (action.StartsWith("hashdump.", StringComparison.OrdinalIgnoreCase)) return "hash-protect";
            if (action.StartsWith("lateral.", StringComparison.OrdinalIgnoreCase)) return "lateral-defense";
            if (action.StartsWith("userhook.health.", StringComparison.OrdinalIgnoreCase)) return "process-protection-coverage";
            if (action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase)) return "process-threat-insight";
            return string.Empty;
        }

        public static bool IsUserHookCoverageRecord(AuditRecord record)
        {
            if (record == null)
            {
                return false;
            }

            string action = record.Action ?? string.Empty;
            string objectType = record.ObjectType ?? string.Empty;
            if (string.Equals(objectType, "sensor-health", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("userhook.health.", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!action.StartsWith("userhook.", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string operation = action.Substring("userhook.".Length);
            return string.Equals(operation, "runtime-required", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-missing", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-required", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-queued", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(operation, "runtime-injection-skipped", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHiddenOperationalRecord(AuditRecord record)
        {
            if (record == null)
            {
                return false;
            }

            if (IsUserHookCoverageRecord(record))
            {
                return true;
            }

            string action = record.Action ?? string.Empty;
            return action.StartsWith("userhook.health.", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeAuditSeverity(string value)
        {
            if (string.Equals(value, "critical", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "warning", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "info", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "operational", StringComparison.OrdinalIgnoreCase))
            {
                return value.ToLowerInvariant();
            }

            if (string.Equals(value, "high", StringComparison.OrdinalIgnoreCase))
            {
                return "critical";
            }

            if (string.Equals(value, "medium", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "low", StringComparison.OrdinalIgnoreCase))
            {
                return "warning";
            }

            return string.IsNullOrWhiteSpace(value) ? "operational" : value;
        }

        private static string NormalizeAuditDisposition(string value)
        {
            if (string.Equals(value, "blocked", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "observed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "completed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "failed", StringComparison.OrdinalIgnoreCase))
            {
                return value.ToLowerInvariant();
            }

            if (string.Equals(value, "malicious", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "suspicious", StringComparison.OrdinalIgnoreCase))
            {
                return "observed";
            }

            return string.IsNullOrWhiteSpace(value) ? "completed" : value;
        }

        private static bool LooksLikeProcess(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                   value.IndexOf("\\", StringComparison.OrdinalIgnoreCase) >= 0;
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

        private static bool TryParseUtc(string value, out DateTime timestampUtc)
        {
            if (DateTime.TryParse(value, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out timestampUtc))
            {
                timestampUtc = timestampUtc.ToUniversalTime();
                return true;
            }

            return false;
        }

        private static AuditQueryOptions CopyWithoutCategory(AuditQueryOptions query)
        {
            return new AuditQueryOptions
            {
                Limit = query.Limit,
                Page = query.Page,
                PageSize = query.PageSize,
                Category = "all",
                Host = query.Host,
                Result = query.Result,
                Severity = query.Severity,
                Disposition = query.Disposition,
                FromUtc = query.FromUtc,
                ToUtc = query.ToUtc,
                Search = query.Search
            };
        }

        private static AuditCategorySummary[] BuildCategorySummaries(IEnumerable<AuditRecord> records)
        {
            return (records ?? Enumerable.Empty<AuditRecord>())
                .GroupBy(ClassifyCategory, StringComparer.OrdinalIgnoreCase)
                .Select(group => new AuditCategorySummary
                {
                    category = group.Key,
                    count = group.Count(),
                    critical = group.Count(record => string.Equals(ResolveSeverity(record), "critical", StringComparison.OrdinalIgnoreCase)),
                    warning = group.Count(record => string.Equals(ResolveSeverity(record), "warning", StringComparison.OrdinalIgnoreCase)),
                    blocked = group.Count(record => string.Equals(ResolveDisposition(record), "blocked", StringComparison.OrdinalIgnoreCase))
                })
                .OrderByDescending(item => item.count)
                .ThenBy(item => item.category, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static AuditHostSummary[] BuildHostSummaries(IEnumerable<AuditRecord> records)
        {
            return (records ?? Enumerable.Empty<AuditRecord>())
                .Select(record => new { record, host = ResolveHost(record) })
                .Where(item => !string.IsNullOrWhiteSpace(item.host))
                .GroupBy(item => item.host, StringComparer.OrdinalIgnoreCase)
                .Select(group => new AuditHostSummary
                {
                    host = group.Key,
                    total = group.Count(),
                    critical = group.Count(item => string.Equals(ResolveSeverity(item.record), "critical", StringComparison.OrdinalIgnoreCase)),
                    warning = group.Count(item => string.Equals(ResolveSeverity(item.record), "warning", StringComparison.OrdinalIgnoreCase)),
                    blocked = group.Count(item => string.Equals(ResolveDisposition(item.record), "blocked", StringComparison.OrdinalIgnoreCase))
                })
                .OrderByDescending(item => item.critical)
                .ThenByDescending(item => item.warning)
                .ThenByDescending(item => item.blocked)
                .ThenByDescending(item => item.total)
                .ThenBy(item => item.host, StringComparer.OrdinalIgnoreCase)
                .Take(20)
                .ToArray();
        }

        private static AuditTrendBucket[] BuildTrendBuckets(IEnumerable<AuditRecord> records)
        {
            return (records ?? Enumerable.Empty<AuditRecord>())
                .Select(record => new { record, timestamp = ParseUtcOrMin(record == null ? string.Empty : record.TimestampUtc) })
                .Where(item => item.timestamp != DateTime.MinValue)
                .GroupBy(item => new DateTime(item.timestamp.Year, item.timestamp.Month, item.timestamp.Day, item.timestamp.Hour, 0, 0, DateTimeKind.Utc))
                .OrderBy(group => group.Key)
                .Select(group => new AuditTrendBucket
                {
                    label = group.Key.ToLocalTime().ToString("M/d HH':00'", CultureInfo.InvariantCulture),
                    critical = group.Count(item => string.Equals(ResolveSeverity(item.record), "critical", StringComparison.OrdinalIgnoreCase)),
                    warning = group.Count(item => string.Equals(ResolveSeverity(item.record), "warning", StringComparison.OrdinalIgnoreCase)),
                    total = group.Count()
                })
                .TakeLastCompat(24)
                .ToArray();
        }

        private static DateTime ParseUtcOrMin(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed)
                ? parsed.ToUniversalTime()
                : DateTime.MinValue;
        }

        private static bool IsDeleteMatch(AuditRecord record, AuditDeleteOptions options)
        {
            if (record == null || options == null)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.TimestampUtc) &&
                !string.Equals(record.TimestampUtc, options.TimestampUtc, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Action) &&
                !string.Equals(record.Action, options.Action, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Target) &&
                !string.Equals(record.Target, options.Target, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Status) &&
                !string.Equals(record.Status, options.Status, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(options.Message) &&
                !string.Equals(record.Message, options.Message, StringComparison.Ordinal))
            {
                return false;
            }

            return !string.IsNullOrWhiteSpace(options.TimestampUtc) ||
                   !string.IsNullOrWhiteSpace(options.Action) ||
                   !string.IsNullOrWhiteSpace(options.Target);
        }

        public sealed class AuditQueryOptions
        {
            public int Limit { get; set; }
            public int Page { get; set; }
            public int PageSize { get; set; }
            public string Category { get; set; }
            public string Host { get; set; }
            public string Result { get; set; }
            public string Severity { get; set; }
            public string Disposition { get; set; }
            public string FromUtc { get; set; }
            public string ToUtc { get; set; }
            public string Search { get; set; }
        }

        public sealed class AuditDeleteOptions
        {
            public bool Clear { get; set; }
            public string TimestampUtc { get; set; }
            public string Action { get; set; }
            public string Target { get; set; }
            public string Status { get; set; }
            public string Message { get; set; }
            public string Actor { get; set; }
        }

        public sealed class AuditQueryResponse
        {
            public int page { get; set; }
            public int pageSize { get; set; }
            public int total { get; set; }
            public int criticalTotal { get; set; }
            public int warningTotal { get; set; }
            public int blockedTotal { get; set; }
            public AuditCategorySummary[] categorySummaries { get; set; }
            public AuditHostSummary[] hostSummaries { get; set; }
            public AuditTrendBucket[] trendBuckets { get; set; }
            public AuditRecord[] items { get; set; }
        }

        public sealed class AuditCategorySummary
        {
            public string category { get; set; }
            public int count { get; set; }
            public int critical { get; set; }
            public int warning { get; set; }
            public int blocked { get; set; }
        }

        public sealed class AuditHostSummary
        {
            public string host { get; set; }
            public int total { get; set; }
            public int critical { get; set; }
            public int warning { get; set; }
            public int blocked { get; set; }
        }

        public sealed class AuditTrendBucket
        {
            public string label { get; set; }
            public int critical { get; set; }
            public int warning { get; set; }
            public int total { get; set; }
        }

        public sealed class AuditRecord
        {
            public string TimestampUtc { get; set; }
            public string Host { get; set; }
            public string Actor { get; set; }
            public string Action { get; set; }
            public string Target { get; set; }
            public string Extension { get; set; }
            public bool Succeeded { get; set; }
            public string Status { get; set; }
            public string Message { get; set; }
            public string SourceHost { get; set; }
            public string SourceUser { get; set; }
            public string SourceProcess { get; set; }
            public string SourcePid { get; set; }
            public string TargetHost { get; set; }
            public string TargetProcess { get; set; }
            public string TargetPid { get; set; }
            public string ObjectType { get; set; }
            public string ObjectName { get; set; }
            public string ObjectFormat { get; set; }
            public string PolicyName { get; set; }
            public string Disposition { get; set; }
            public string Severity { get; set; }
            public string EventDetails { get; set; }
        }
    }

    internal static class AuditEnumerableExtensions
    {
        public static IEnumerable<T> TakeLastCompat<T>(this IEnumerable<T> source, int count)
        {
            if (source == null || count <= 0)
            {
                return Enumerable.Empty<T>();
            }

            Queue<T> queue = new Queue<T>();
            foreach (T item in source)
            {
                queue.Enqueue(item);
                if (queue.Count > count)
                {
                    queue.Dequeue();
                }
            }

            return queue.ToArray();
        }
    }
}
