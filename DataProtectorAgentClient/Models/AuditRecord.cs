namespace DataProtectorAgentClient.Models
{
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
