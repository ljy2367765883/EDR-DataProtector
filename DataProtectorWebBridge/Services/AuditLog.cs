using System;
using System.Collections.Generic;
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
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();

        public AuditLog()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            DirectoryPath = Path.Combine(dataRoot, "DataProtector");
            FilePath = Path.Combine(DirectoryPath, "WebAudit.jsonl");
        }

        public string DirectoryPath { get; private set; }

        public string FilePath { get; private set; }

        public void Append(string actor, string action, string target, string extension, bool succeeded, uint status, string message)
        {
            AuditRecord record = new AuditRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Actor = string.IsNullOrWhiteSpace(actor) ? Environment.UserName : actor,
                Action = action ?? string.Empty,
                Target = target ?? string.Empty,
                Extension = extension ?? string.Empty,
                Succeeded = succeeded,
                Status = "0x" + status.ToString("X8"),
                Message = message ?? string.Empty
            };

            string line = serializer.Serialize(record);

            lock (syncRoot)
            {
                Directory.CreateDirectory(DirectoryPath);
                File.AppendAllText(FilePath, line + Environment.NewLine, Encoding.UTF8);
            }
        }

        public AuditRecord[] ReadRecent(int limit)
        {
            int take = limit <= 0 ? DefaultLimit : Math.Min(limit, 1000);

            lock (syncRoot)
            {
                if (!File.Exists(FilePath))
                {
                    return new AuditRecord[0];
                }

                List<string> lines = File.ReadAllLines(FilePath, Encoding.UTF8)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Reverse()
                    .Take(take)
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

                return records.ToArray();
            }
        }

        public sealed class AuditRecord
        {
            public string TimestampUtc { get; set; }
            public string Actor { get; set; }
            public string Action { get; set; }
            public string Target { get; set; }
            public string Extension { get; set; }
            public bool Succeeded { get; set; }
            public string Status { get; set; }
            public string Message { get; set; }
        }
    }
}
