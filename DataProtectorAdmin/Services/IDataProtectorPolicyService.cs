using DataProtectorAdmin.Models;

namespace DataProtectorAdmin.Services
{
    public interface IDataProtectorPolicyService
    {
        PolicySettings Settings { get; }

        PolicyOperationResult CheckConnection();

        PolicyOperationResult QueryRulesFromDriver();

        PolicyOperationResult AddProcessNameRule(string processName, string extension);

        PolicyOperationResult RemoveProcessNameRule(PolicyRule rule);

        PolicyOperationResult AddProcessDirectoryRule(string directoryPath, string extension);

        PolicyOperationResult RemoveProcessDirectoryRule(PolicyRule rule);

        PolicyOperationResult AddExcludedDirectoryRule(string directoryPath, string extension);

        PolicyOperationResult RemoveExcludedDirectoryRule(PolicyRule rule);

        PolicyOperationResult ClearRules();

        PolicyOperationResult SynchronizeRules();
    }
}
