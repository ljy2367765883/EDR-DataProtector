using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using DataProtectorAgentClient.Infrastructure;
using DataProtectorAgentClient.Models;
using DataProtectorAgentClient.Services;

namespace DataProtectorAgentClient.ViewModels
{
    public sealed class MainViewModel : ObservableObject
    {
        private readonly AgentClientSnapshotService snapshotService;
        private readonly RelayCommand refreshCommand;
        private string selectedPage = "Overview";
        private bool isRefreshing;
        private bool driverConnected;
        private string driverStatusText = "检测中";
        private string driverStatusCaption = "正在读取本机防护状态";
        private string driverStatusBrushKey = "DpMutedBrush";
        private string statusMessage = "正在加载 DataProtector 终端状态";
        private string lastUpdatedText = string.Empty;
        private string machineText = string.Empty;
        private string userText = string.Empty;
        private string deviceIdText = string.Empty;
        private string policyVersionText = "0";
        private string lastApplyStatusText = string.Empty;
        private string lastApplyMessageText = string.Empty;
        private string lastStateWriteText = string.Empty;
        private string auditPathText = string.Empty;
        private string ruleCountText = "0";
        private string riskEventCountText = "0";
        private string urgentEventCountText = "0";
        private string enabledFeatureCountText = "0";
        private string overviewTitle = "防护状态检测中";
        private string overviewCaption = "正在汇总本机策略、事件和客户端同步状态";

        public MainViewModel(AgentClientSnapshotService snapshotService)
        {
            this.snapshotService = snapshotService ?? throw new ArgumentNullException("snapshotService");
            NavigateCommand = new RelayCommand(parameter => SelectedPage = parameter == null ? "Overview" : parameter.ToString());
            refreshCommand = new RelayCommand(parameter => RefreshAsync(), parameter => !IsRefreshing);
            RefreshCommand = refreshCommand;
            Rules = new ObservableCollection<RuleViewItem>();
            SecurityEvents = new ObservableCollection<SecurityEventViewItem>();
            Features = new ObservableCollection<ProtectionFeatureViewItem>();
            ExtensionCards = new ObservableCollection<ProtectionFeatureViewItem>
            {
                new ProtectionFeatureViewItem
                {
                    Name = "弹窗拦截",
                    Description = "预留本地交互位，后续可接入窗口行为感知、拦截规则和用户确认流。",
                    State = "规划中",
                    AccentBrushKey = "DpCommandBrush"
                },
                new ProtectionFeatureViewItem
                {
                    Name = "终端通知中心",
                    Description = "可扩展为托盘实时通知、安全事件确认和本机处置建议。",
                    State = "规划中",
                    AccentBrushKey = "DpWarningBrush"
                },
                new ProtectionFeatureViewItem
                {
                    Name = "本机自检",
                    Description = "可扩展驱动签名、服务状态、策略完整性和运行环境检查。",
                    State = "规划中",
                    AccentBrushKey = "DpSuccessBrush"
                }
            };
        }

        public RelayCommand NavigateCommand { get; private set; }

        public RelayCommand RefreshCommand { get; private set; }

        public ObservableCollection<RuleViewItem> Rules { get; private set; }

        public ObservableCollection<SecurityEventViewItem> SecurityEvents { get; private set; }

        public ObservableCollection<ProtectionFeatureViewItem> Features { get; private set; }

        public ObservableCollection<ProtectionFeatureViewItem> ExtensionCards { get; private set; }

        public string SelectedPage
        {
            get { return selectedPage; }
            set
            {
                if (SetProperty(ref selectedPage, string.IsNullOrWhiteSpace(value) ? "Overview" : value))
                {
                    OnPropertyChanged("IsOverviewVisible");
                    OnPropertyChanged("IsRulesVisible");
                    OnPropertyChanged("IsEventsVisible");
                    OnPropertyChanged("IsExtensionsVisible");
                }
            }
        }

        public bool IsOverviewVisible { get { return string.Equals(SelectedPage, "Overview", StringComparison.OrdinalIgnoreCase); } }
        public bool IsRulesVisible { get { return string.Equals(SelectedPage, "Rules", StringComparison.OrdinalIgnoreCase); } }
        public bool IsEventsVisible { get { return string.Equals(SelectedPage, "Events", StringComparison.OrdinalIgnoreCase); } }
        public bool IsExtensionsVisible { get { return string.Equals(SelectedPage, "Extensions", StringComparison.OrdinalIgnoreCase); } }

        public bool IsRefreshing
        {
            get { return isRefreshing; }
            private set
            {
                if (SetProperty(ref isRefreshing, value))
                {
                    refreshCommand.RaiseCanExecuteChanged();
                }
            }
        }

        public bool DriverConnected
        {
            get { return driverConnected; }
            private set { SetProperty(ref driverConnected, value); }
        }

        public string DriverStatusText
        {
            get { return driverStatusText; }
            private set { SetProperty(ref driverStatusText, value); }
        }

        public string DriverStatusCaption
        {
            get { return driverStatusCaption; }
            private set { SetProperty(ref driverStatusCaption, value); }
        }

        public string DriverStatusBrushKey
        {
            get { return driverStatusBrushKey; }
            private set { SetProperty(ref driverStatusBrushKey, value); }
        }

        public string StatusMessage
        {
            get { return statusMessage; }
            private set { SetProperty(ref statusMessage, value); }
        }

        public string LastUpdatedText
        {
            get { return lastUpdatedText; }
            private set { SetProperty(ref lastUpdatedText, value); }
        }

        public string MachineText
        {
            get { return machineText; }
            private set { SetProperty(ref machineText, value); }
        }

        public string UserText
        {
            get { return userText; }
            private set { SetProperty(ref userText, value); }
        }

        public string DeviceIdText
        {
            get { return deviceIdText; }
            private set { SetProperty(ref deviceIdText, value); }
        }

        public string PolicyVersionText
        {
            get { return policyVersionText; }
            private set { SetProperty(ref policyVersionText, value); }
        }

        public string LastApplyStatusText
        {
            get { return lastApplyStatusText; }
            private set { SetProperty(ref lastApplyStatusText, value); }
        }

        public string LastApplyMessageText
        {
            get { return lastApplyMessageText; }
            private set { SetProperty(ref lastApplyMessageText, value); }
        }

        public string LastStateWriteText
        {
            get { return lastStateWriteText; }
            private set { SetProperty(ref lastStateWriteText, value); }
        }

        public string AuditPathText
        {
            get { return auditPathText; }
            private set { SetProperty(ref auditPathText, value); }
        }

        public string RuleCountText
        {
            get { return ruleCountText; }
            private set { SetProperty(ref ruleCountText, value); }
        }

        public string RiskEventCountText
        {
            get { return riskEventCountText; }
            private set { SetProperty(ref riskEventCountText, value); }
        }

        public string UrgentEventCountText
        {
            get { return urgentEventCountText; }
            private set { SetProperty(ref urgentEventCountText, value); }
        }

        public string EnabledFeatureCountText
        {
            get { return enabledFeatureCountText; }
            private set { SetProperty(ref enabledFeatureCountText, value); }
        }

        public string OverviewTitle
        {
            get { return overviewTitle; }
            private set { SetProperty(ref overviewTitle, value); }
        }

        public string OverviewCaption
        {
            get { return overviewCaption; }
            private set { SetProperty(ref overviewCaption, value); }
        }

        public void RefreshAsync()
        {
            if (IsRefreshing)
            {
                return;
            }

            IsRefreshing = true;
            StatusMessage = "正在读取本机防护状态...";

            Task.Run(() => snapshotService.ReadSnapshot())
                .ContinueWith(task =>
                {
                    try
                    {
                        if (task.IsFaulted)
                        {
                            Exception exception = task.Exception == null ? null : task.Exception.GetBaseException();
                            StatusMessage = "状态刷新失败：" + (exception == null ? "未知错误" : exception.Message);
                            DriverStatusText = "读取失败";
                            DriverStatusCaption = StatusMessage;
                            DriverStatusBrushKey = "DpDangerBrush";
                            return;
                        }

                        ApplySnapshot(task.Result);
                    }
                    finally
                    {
                        IsRefreshing = false;
                    }
                }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        private void ApplySnapshot(AgentClientSnapshot snapshot)
        {
            if (snapshot == null)
            {
                return;
            }

            DriverConnected = snapshot.DriverConnected;
            DriverStatusText = snapshot.DriverConnected ? "防护运行中" : "驱动未连接";
            DriverStatusCaption = snapshot.DriverConnected ? snapshot.DriverMessage : snapshot.DriverMessage;
            DriverStatusBrushKey = snapshot.DriverConnected ? "DpSuccessBrush" : "DpDangerBrush";
            OverviewTitle = snapshot.DriverConnected ? "终端防护已开启" : "终端防护需要关注";
            OverviewCaption = snapshot.DriverConnected
                ? "本机驱动通信正常，策略与事件已就绪。"
                : "未能连接 DataProtector 驱动，请检查驱动服务或权限。";
            StatusMessage = snapshot.DriverConnected
                ? "已刷新本机只读视图，客户端不会影响事件上报。"
                : "已读取本机状态，但驱动接口当前不可用。";
            LastUpdatedText = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
            MachineText = snapshot.MachineName;
            UserText = snapshot.UserName;
            DeviceIdText = snapshot.AgentState == null ? string.Empty : (snapshot.AgentState.DeviceId ?? string.Empty);
            PolicyVersionText = snapshot.AgentState == null ? "0" : snapshot.AgentState.AppliedPolicyVersion.ToString(CultureInfo.InvariantCulture);
            string rawApplyStatus = snapshot.AgentState == null ? string.Empty : (snapshot.AgentState.LastApplyStatus ?? string.Empty);
            LastApplyStatusText = TranslateApplyStatus(rawApplyStatus);
            LastApplyMessageText = BuildApplySummary(snapshot, rawApplyStatus);
            LastStateWriteText = ResolveLastWriteText(snapshot.StatePath);
            AuditPathText = snapshot.AuditPath ?? string.Empty;

            Rules.Clear();
            foreach (RuleViewItem rule in snapshot.Rules.OrderBy(item => item.Category).ThenBy(item => item.Name).ThenBy(item => item.Target))
            {
                Rules.Add(rule);
            }

            SecurityEvents.Clear();
            foreach (SecurityEventViewItem item in snapshot.Events)
            {
                SecurityEvents.Add(item);
            }

            Features.Clear();
            foreach (ProtectionFeatureViewItem item in snapshot.Features)
            {
                Features.Add(item);
            }

            RuleCountText = Rules.Count.ToString(CultureInfo.InvariantCulture);
            RiskEventCountText = SecurityEvents.Count.ToString(CultureInfo.InvariantCulture);
            UrgentEventCountText = SecurityEvents.Count(item => item.Severity == "紧急" || item.Disposition == "已阻止").ToString(CultureInfo.InvariantCulture);
            EnabledFeatureCountText = Features.Count(item => item.State == "已开启").ToString(CultureInfo.InvariantCulture);
        }

        private static string ResolveLastWriteText(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return "未同步";
                }

                return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
            }
            catch
            {
                return "不可用";
            }
        }

        private static string TranslateApplyStatus(string status)
        {
            if (string.IsNullOrWhiteSpace(status))
            {
                return "未同步";
            }

            if (string.Equals(status, "0x00000000", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(status, "0", StringComparison.OrdinalIgnoreCase))
            {
                return "已应用";
            }

            return "需要关注";
        }

        private static string BuildApplySummary(AgentClientSnapshot snapshot, string status)
        {
            if (snapshot == null || snapshot.AgentState == null)
            {
                return "暂未读取到本机策略同步状态。";
            }

            if (string.Equals(status, "0x00000000", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(status, "0", StringComparison.OrdinalIgnoreCase))
            {
                return string.Format(
                    CultureInfo.CurrentCulture,
                    "最近一次策略已成功应用，当前展示 {0} 条规则、{1} 个防护模块。",
                    snapshot.Rules == null ? 0 : snapshot.Rules.Count,
                    snapshot.Features == null ? 0 : snapshot.Features.Count);
            }

            return "策略应用存在异常，请检查客户端服务、驱动状态或服务器连接。";
        }
    }
}
