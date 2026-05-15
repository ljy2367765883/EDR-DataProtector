using System.Collections.ObjectModel;

namespace DataProtectorAdmin.Models
{
    public sealed class PolicySettings
    {
        public PolicySettings()
        {
            ProcessNameRules = new ObservableCollection<PolicyRule>();
            ProcessDirectoryRules = new ObservableCollection<PolicyRule>();
        }

        public ObservableCollection<PolicyRule> ProcessNameRules { get; private set; }

        public ObservableCollection<PolicyRule> ProcessDirectoryRules { get; private set; }
    }
}
