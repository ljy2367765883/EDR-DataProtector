namespace DataProtectorAgentClient.Models
{
    public sealed class AgentStateModel
    {
        public string DeviceId { get; set; }
        public long AppliedPolicyVersion { get; set; }
        public string LastApplyStatus { get; set; }
        public string LastApplyMessage { get; set; }
    }
}
