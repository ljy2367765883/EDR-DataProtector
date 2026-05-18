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
    }
}
