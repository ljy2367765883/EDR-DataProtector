using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Input;
using DataProtectorAdmin.Infrastructure;
using DataProtectorAdmin.Models;
using DataProtectorAdmin.Services;

namespace DataProtectorAdmin.ViewModels
{
    public sealed class MainViewModel : ObservableObject
    {
        private readonly IDataProtectorPolicyService policyService;
        private readonly RelayCommand checkConnectionCommand;
        private readonly RelayCommand queryRulesCommand;
        private readonly RelayCommand synchronizeRulesCommand;
        private readonly RelayCommand addProcessNameCommand;
        private readonly RelayCommand removeProcessNameCommand;
        private readonly RelayCommand addDirectoryCommand;
        private readonly RelayCommand browseDirectoryCommand;
        private readonly RelayCommand removeDirectoryCommand;
        private readonly RelayCommand addExcludedDirectoryCommand;
        private readonly RelayCommand browseExcludedDirectoryCommand;
        private readonly RelayCommand removeExcludedDirectoryCommand;
        private readonly RelayCommand clearRulesCommand;

        private string newProcessName = string.Empty;
        private string newDirectoryPath = string.Empty;
        private string newExcludedDirectoryPath = string.Empty;
        private string newProcessExtension = ".dpf";
        private string newDirectoryExtension = ".dpf";
        private string newExcludedDirectoryExtension = ".dpf";
        private PolicyRule selectedProcessNameRule;
        private PolicyRule selectedDirectoryRule;
        private PolicyRule selectedExcludedDirectoryRule;
        private bool driverConnected;
        private bool isBusy;
        private string statusMessage = "正在检测驱动状态...";
        private string activePage = "Dashboard";
        private DateTime lastSyncTime;

        public MainViewModel(IDataProtectorPolicyService policyService)
        {
            this.policyService = policyService;

            ProcessNameRules = policyService.Settings.ProcessNameRules;
            ProcessDirectoryRules = policyService.Settings.ProcessDirectoryRules;
            ExcludedDirectoryRules = policyService.Settings.ExcludedDirectoryRules;

            checkConnectionCommand = new RelayCommand(async _ => await CheckConnectionAsync(), _ => !IsBusy);
            queryRulesCommand = new RelayCommand(async _ => await QueryRulesFromDriverAsync(), _ => !IsBusy);
            synchronizeRulesCommand = new RelayCommand(async _ => await SynchronizeRulesAsync(), _ => !IsBusy);
            addProcessNameCommand = new RelayCommand(async _ => await AddProcessNameAsync(), _ => !IsBusy);
            removeProcessNameCommand = new RelayCommand(async _ => await RemoveSelectedProcessNameAsync(), _ => !IsBusy && SelectedProcessNameRule != null);
            addDirectoryCommand = new RelayCommand(async _ => await AddDirectoryAsync(), _ => !IsBusy);
            browseDirectoryCommand = new RelayCommand(_ => BrowseDirectory(), _ => !IsBusy);
            removeDirectoryCommand = new RelayCommand(async _ => await RemoveSelectedDirectoryAsync(), _ => !IsBusy && SelectedDirectoryRule != null);
            addExcludedDirectoryCommand = new RelayCommand(async _ => await AddExcludedDirectoryAsync(), _ => !IsBusy);
            browseExcludedDirectoryCommand = new RelayCommand(_ => BrowseExcludedDirectory(), _ => !IsBusy);
            removeExcludedDirectoryCommand = new RelayCommand(async _ => await RemoveSelectedExcludedDirectoryAsync(), _ => !IsBusy && SelectedExcludedDirectoryRule != null);
            clearRulesCommand = new RelayCommand(async _ => await ClearRulesAsync(), _ => !IsBusy);
            NavigateCommand = new RelayCommand(parameter => ActivePage = parameter == null ? "Dashboard" : parameter.ToString());

            _ = CheckConnectionAsync();
        }

        public ObservableCollection<PolicyRule> ProcessNameRules { get; private set; }

        public ObservableCollection<PolicyRule> ProcessDirectoryRules { get; private set; }

        public ObservableCollection<PolicyRule> ExcludedDirectoryRules { get; private set; }

        public ICommand CheckConnectionCommand
        {
            get { return checkConnectionCommand; }
        }

        public ICommand QueryRulesCommand
        {
            get { return queryRulesCommand; }
        }

        public ICommand SynchronizeRulesCommand
        {
            get { return synchronizeRulesCommand; }
        }

        public ICommand AddProcessNameCommand
        {
            get { return addProcessNameCommand; }
        }

        public ICommand RemoveProcessNameCommand
        {
            get { return removeProcessNameCommand; }
        }

        public ICommand AddDirectoryCommand
        {
            get { return addDirectoryCommand; }
        }

        public ICommand BrowseDirectoryCommand
        {
            get { return browseDirectoryCommand; }
        }

        public ICommand RemoveDirectoryCommand
        {
            get { return removeDirectoryCommand; }
        }

        public ICommand AddExcludedDirectoryCommand
        {
            get { return addExcludedDirectoryCommand; }
        }

        public ICommand BrowseExcludedDirectoryCommand
        {
            get { return browseExcludedDirectoryCommand; }
        }

        public ICommand RemoveExcludedDirectoryCommand
        {
            get { return removeExcludedDirectoryCommand; }
        }

        public ICommand ClearRulesCommand
        {
            get { return clearRulesCommand; }
        }

        public ICommand NavigateCommand { get; private set; }

        public string NewProcessName
        {
            get { return newProcessName; }
            set { SetProperty(ref newProcessName, value); }
        }

        public string NewDirectoryPath
        {
            get { return newDirectoryPath; }
            set { SetProperty(ref newDirectoryPath, value); }
        }

        public string NewExcludedDirectoryPath
        {
            get { return newExcludedDirectoryPath; }
            set { SetProperty(ref newExcludedDirectoryPath, value); }
        }

        public string NewProcessExtension
        {
            get { return newProcessExtension; }
            set { SetProperty(ref newProcessExtension, value); }
        }

        public string NewDirectoryExtension
        {
            get { return newDirectoryExtension; }
            set { SetProperty(ref newDirectoryExtension, value); }
        }

        public string NewExcludedDirectoryExtension
        {
            get { return newExcludedDirectoryExtension; }
            set { SetProperty(ref newExcludedDirectoryExtension, value); }
        }

        public PolicyRule SelectedProcessNameRule
        {
            get { return selectedProcessNameRule; }
            set
            {
                if (SetProperty(ref selectedProcessNameRule, value))
                {
                    removeProcessNameCommand.RaiseCanExecuteChanged();
                }
            }
        }

        public PolicyRule SelectedDirectoryRule
        {
            get { return selectedDirectoryRule; }
            set
            {
                if (SetProperty(ref selectedDirectoryRule, value))
                {
                    removeDirectoryCommand.RaiseCanExecuteChanged();
                }
            }
        }

        public PolicyRule SelectedExcludedDirectoryRule
        {
            get { return selectedExcludedDirectoryRule; }
            set
            {
                if (SetProperty(ref selectedExcludedDirectoryRule, value))
                {
                    removeExcludedDirectoryCommand.RaiseCanExecuteChanged();
                }
            }
        }

        public bool DriverConnected
        {
            get { return driverConnected; }
            private set
            {
                if (SetProperty(ref driverConnected, value))
                {
                    OnPropertyChanged("DriverStatusText");
                    OnPropertyChanged("DriverStatusBrushKey");
                    OnPropertyChanged("DriverStatusCaption");
                }
            }
        }

        public string DriverStatusText
        {
            get { return DriverConnected ? "运行中" : "未连接"; }
        }

        public string DriverStatusCaption
        {
            get { return DriverConnected ? "策略端口可用" : "等待驱动服务启动"; }
        }

        public string DriverStatusBrushKey
        {
            get { return DriverConnected ? "DpSuccessBrush" : "DpDangerBrush"; }
        }

        public string StatusMessage
        {
            get { return statusMessage; }
            private set { SetProperty(ref statusMessage, value); }
        }

        public bool IsBusy
        {
            get { return isBusy; }
            private set
            {
                if (SetProperty(ref isBusy, value))
                {
                    RaiseCommandStatesChanged();
                }
            }
        }

        public string ActivePage
        {
            get { return activePage; }
            set
            {
                if (SetProperty(ref activePage, value))
                {
                    OnPropertyChanged("IsDashboardVisible");
                    OnPropertyChanged("IsTrustedAppsVisible");
                    OnPropertyChanged("IsFoldersVisible");
                    OnPropertyChanged("IsExcludedFoldersVisible");
                    OnPropertyChanged("IsSettingsVisible");
                }
            }
        }

        public bool IsDashboardVisible
        {
            get { return ActivePage == "Dashboard"; }
        }

        public bool IsTrustedAppsVisible
        {
            get { return ActivePage == "TrustedApps"; }
        }

        public bool IsFoldersVisible
        {
            get { return ActivePage == "Folders"; }
        }

        public bool IsExcludedFoldersVisible
        {
            get { return ActivePage == "ExcludedFolders"; }
        }

        public bool IsSettingsVisible
        {
            get { return ActivePage == "Settings"; }
        }

        public int TotalRuleCount
        {
            get { return ProcessNameRules.Count + ProcessDirectoryRules.Count + ExcludedDirectoryRules.Count; }
        }

        public int ProcessRuleCount
        {
            get { return ProcessNameRules.Count; }
        }

        public int DirectoryRuleCount
        {
            get { return ProcessDirectoryRules.Count; }
        }

        public int ExcludedDirectoryRuleCount
        {
            get { return ExcludedDirectoryRules.Count; }
        }

        public string LastSyncText
        {
            get { return lastSyncTime == default(DateTime) ? "尚未同步" : lastSyncTime.ToString("yyyy-MM-dd HH:mm:ss"); }
        }

        private async Task CheckConnectionAsync()
        {
            await RunPolicyOperationAsync(() => policyService.CheckConnection(), null, true);
        }

        private async Task QueryRulesFromDriverAsync()
        {
            await RunPolicyOperationAsync(() => policyService.QueryRulesFromDriver(), RefreshRuleCounters, true);
        }

        private async Task SynchronizeRulesAsync()
        {
            await RunPolicyOperationAsync(
                () => policyService.SynchronizeRules(),
                () =>
                {
                    lastSyncTime = DateTime.Now;
                    OnPropertyChanged("LastSyncText");
                },
                true);
        }

        private async Task AddProcessNameAsync()
        {
            string processName = NewProcessName;
            string extension = NewProcessExtension;

            await RunPolicyOperationAsync(
                () => policyService.AddProcessNameRule(processName, extension),
                () =>
                {
                    NewProcessName = string.Empty;
                    RefreshRuleCounters();
                },
                null);
        }

        private async Task RemoveSelectedProcessNameAsync()
        {
            PolicyRule selectedRule = SelectedProcessNameRule;
            if (selectedRule == null)
            {
                return;
            }

            await RunPolicyOperationAsync(
                () => policyService.RemoveProcessNameRule(selectedRule),
                () =>
                {
                    SelectedProcessNameRule = null;
                    RefreshRuleCounters();
                },
                null);
        }

        private async Task AddDirectoryAsync()
        {
            string directoryPath = NewDirectoryPath;
            string extension = NewDirectoryExtension;

            await RunPolicyOperationAsync(
                () => policyService.AddProcessDirectoryRule(directoryPath, extension),
                () =>
                {
                    NewDirectoryPath = string.Empty;
                    RefreshRuleCounters();
                },
                null);
        }

        private void BrowseDirectory()
        {
            BrowseFolder("选择可信程序所在文件夹", value => NewDirectoryPath = value);
        }

        private async Task AddExcludedDirectoryAsync()
        {
            string directoryPath = NewExcludedDirectoryPath;
            string extension = NewExcludedDirectoryExtension;

            await RunPolicyOperationAsync(
                () => policyService.AddExcludedDirectoryRule(directoryPath, extension),
                () =>
                {
                    NewExcludedDirectoryPath = string.Empty;
                    RefreshRuleCounters();
                },
                null);
        }

        private void BrowseExcludedDirectory()
        {
            BrowseFolder("选择不加解密的排除目录", value => NewExcludedDirectoryPath = value);
        }

        private async Task RemoveSelectedExcludedDirectoryAsync()
        {
            PolicyRule selectedRule = SelectedExcludedDirectoryRule;
            if (selectedRule == null)
            {
                return;
            }

            await RunPolicyOperationAsync(
                () => policyService.RemoveExcludedDirectoryRule(selectedRule),
                () =>
                {
                    SelectedExcludedDirectoryRule = null;
                    RefreshRuleCounters();
                },
                null);
        }

        private void BrowseFolder(string description, Action<string> assign)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = description;
                dialog.ShowNewFolderButton = false;

                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    assign(dialog.SelectedPath);
                }
            }
        }

        private async Task RemoveSelectedDirectoryAsync()
        {
            PolicyRule selectedRule = SelectedDirectoryRule;
            if (selectedRule == null)
            {
                return;
            }

            await RunPolicyOperationAsync(
                () => policyService.RemoveProcessDirectoryRule(selectedRule),
                () =>
                {
                    SelectedDirectoryRule = null;
                    RefreshRuleCounters();
                },
                null);
        }

        private async Task ClearRulesAsync()
        {
            await RunPolicyOperationAsync(() => policyService.ClearRules(), RefreshRuleCounters, null);
        }

        private async Task RunPolicyOperationAsync(
            Func<PolicyOperationResult> operation,
            Action onSuccess,
            bool? updateConnection)
        {
            if (IsBusy)
            {
                return;
            }

            IsBusy = true;

            try
            {
                PolicyOperationResult result = await Task.Run(operation);
                if (result.Succeeded && onSuccess != null)
                {
                    onSuccess();
                }

                ApplyResult(result, updateConnection);
            }
            catch (Exception ex)
            {
                AdminDiagnostics.Log(ex);
                ApplyResult(new PolicyOperationResult(false, 1, "管理端操作失败：" + ex.Message), null);
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void ApplyResult(PolicyOperationResult result, bool? updateConnection)
        {
            StatusMessage = result.Message;

            if (updateConnection.HasValue)
            {
                DriverConnected = result.Succeeded && updateConnection.Value;
            }
            else if (!result.Succeeded &&
                     result.Message != null &&
                     result.Message.IndexOf("connect", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                DriverConnected = false;
            }
        }

        private void RefreshRuleCounters()
        {
            OnPropertyChanged("TotalRuleCount");
            OnPropertyChanged("ProcessRuleCount");
            OnPropertyChanged("DirectoryRuleCount");
            OnPropertyChanged("ExcludedDirectoryRuleCount");
        }

        private void RaiseCommandStatesChanged()
        {
            checkConnectionCommand.RaiseCanExecuteChanged();
            queryRulesCommand.RaiseCanExecuteChanged();
            synchronizeRulesCommand.RaiseCanExecuteChanged();
            addProcessNameCommand.RaiseCanExecuteChanged();
            removeProcessNameCommand.RaiseCanExecuteChanged();
            addDirectoryCommand.RaiseCanExecuteChanged();
            browseDirectoryCommand.RaiseCanExecuteChanged();
            removeDirectoryCommand.RaiseCanExecuteChanged();
            addExcludedDirectoryCommand.RaiseCanExecuteChanged();
            browseExcludedDirectoryCommand.RaiseCanExecuteChanged();
            removeExcludedDirectoryCommand.RaiseCanExecuteChanged();
            clearRulesCommand.RaiseCanExecuteChanged();
        }
    }
}
