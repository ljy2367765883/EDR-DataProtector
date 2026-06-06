using System.Collections.Generic;

namespace DataProtectorAgentClient.Models
{
    public sealed class AgentClientSnapshot
    {
        public AgentClientSnapshot()
        {
            Rules = new List<RuleViewItem>();
            Events = new List<SecurityEventViewItem>();
            Features = new List<ProtectionFeatureViewItem>();
        }

        public bool DriverConnected { get; set; }
        public string DriverStatus { get; set; }
        public string DriverMessage { get; set; }
        public string MachineName { get; set; }
        public string UserName { get; set; }
        public AgentStateModel AgentState { get; set; }
        public List<RuleViewItem> Rules { get; private set; }
        public List<SecurityEventViewItem> Events { get; private set; }
        public List<ProtectionFeatureViewItem> Features { get; private set; }
        public string AuditPath { get; set; }
        public string StatePath { get; set; }
        public string UsbCryptPolicyPath { get; set; }
        public string DlpPolicySummary { get; set; }
    }
}
