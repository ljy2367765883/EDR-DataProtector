using DataProtectorAdmin.Models;

namespace DataProtectorAdmin.Services
{
    public interface IPolicySettingsStore
    {
        PolicySettings Load();

        void Save(PolicySettings settings);
    }
}
