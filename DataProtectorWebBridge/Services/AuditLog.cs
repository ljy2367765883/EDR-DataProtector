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

            return string.Empty;
        }

        public static string ResolveSeverity(AuditRecord record)
        {
            string action = record == null || record.Action == null ? string.Empty : record.Action;
            string message = record == null || record.Message == null ? string.Empty : record.Message;
            string status = record == null || record.Status == null ? string.Empty : record.Status;

            if (action.StartsWith("webshell.danger", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("hashdump.blocked", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("lateral.blocked", StringComparison.OrdinalIgnoreCase) ||
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

        public static string ResolveDisposition(AuditRecord record)
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

            AuditQueryOptions categoryNeutral = CopyWithoutCategory(query);
            List<AuditRecord> baseMatches = (records ?? Enumerable.Empty<AuditRecord>())
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
