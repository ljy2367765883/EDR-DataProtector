namespace DataProtectorAgentClient.Models
{
    public sealed class SecurityEventViewItem
    {
        public string TimeText { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string Disposition { get; set; }
        public string Target { get; set; }
        public string Source { get; set; }
        public string Message { get; set; }
        public string Status { get; set; }
        public string SeverityBrushKey { get; set; }
    }
}
