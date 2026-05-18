using System;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;
using DataProtectorAgentClient.Models;

namespace DataProtectorAgentClient.Services
{
    public sealed class AgentClientSnapshotService
    {
        private readonly LocalPolicyReader policyReader = new LocalPolicyReader();
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        private readonly string dataDirectory;

        public AgentClientSnapshotService()
        {
            string dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            dataDirectory = Path.Combine(dataRoot, "DataProtector");
        }

        public AgentClientSnapshot ReadSnapshot()
        {
            string statePath = Path.Combine(dataDirectory, "AgentState.json");
            string auditPath = Path.Combine(dataDirectory, "WebAudit.jsonl");
            string usbCryptPolicyPath = Path.Combine(dataDirectory, "UsbCryptPolicy.json");
            LocalPolicyReader.DriverStatus status = policyReader.ReadStatus();

            AgentClientSnapshot snapshot = new AgentClientSnapshot
            {
                DriverConnected = status.Connected,
                DriverStatus = status.StatusText,
                DriverMessage = status.Message,
                MachineName = Environment.MachineName,
                UserName = Environment.UserName,
                AgentState = ReadAgentState(statePath),
                StatePath = statePath,
                AuditPath = auditPath,
                UsbCryptPolicyPath = usbCryptPolicyPath,
                DlpPolicySummary = ResolveDlpPolicySummary()
            };

            foreach (RuleViewItem rule in policyReader.ReadRules())
            {
                snapshot.Rules.Add(rule);
            }

            foreach (ProtectionFeatureViewItem feature in policyReader.ReadFeatures())
            {
                snapshot.Features.Add(feature);
            }

            AddUsbCryptFeature(snapshot, usbCryptPolicyPath);
            AddDlpFeature(snapshot);

            AuditLogReader auditReader = new AuditLogReader(auditPath);
            foreach (SecurityEventViewItem item in auditReader.ReadRecentSecurityEvents(80))
            {
                snapshot.Events.Add(item);
            }

            return snapshot;
        }

        private AgentStateModel ReadAgentState(string statePath)
        {
            try
            {
                if (!File.Exists(statePath))
                {
                    return new AgentStateModel
                    {
                        DeviceId = "未注册",
                        LastApplyStatus = "N/A",
                        LastApplyMessage = "未找到本机 AgentState.json"
                    };
                }

                AgentStateModel state = serializer.Deserialize<AgentStateModel>(File.ReadAllText(statePath, Encoding.UTF8));
                if (state == null)
                {
                    return new AgentStateModel();
                }

                return state;
            }
            catch (Exception ex)
            {
                return new AgentStateModel
                {
                    DeviceId = "读取失败",
                    LastApplyStatus = "0x00000001",
                    LastApplyMessage = ex.Message
                };
            }
        }

        private void AddUsbCryptFeature(AgentClientSnapshot snapshot, string usbCryptPolicyPath)
        {
            UsbCryptPolicyFile policy = ReadUsbCryptPolicy(usbCryptPolicyPath);
            if (policy == null)
            {
                snapshot.Features.Add(new ProtectionFeatureViewItem
                {
                    Name = "U 盘加密",
                    Description = "未读取到本机 USB 加密策略",
                    State = "未配置",
                    AccentBrushKey = "DpMutedBrush"
                });
                return;
            }

            snapshot.Features.Add(new ProtectionFeatureViewItem
            {
                Name = "U 盘加密",
                Description = string.Format(
                    "算法={0}  工具区={1}MB  客户端初始化={2}  硬件授权={3}",
                    string.IsNullOrWhiteSpace(policy.algorithm) ? "rc4" : policy.algorithm,
                    Math.Max(0, policy.publicToolAreaBytes / 1024 / 1024),
                    policy.allowClientProvisioning ? "开" : "关",
                    policy.requireHardwareAuthorization ? "开" : "关"),
                State = policy.enabled ? "已开启" : "未开启",
                AccentBrushKey = policy.enabled ? "DpSuccessBrush" : "DpMutedBrush"
            });
        }

        private void AddDlpFeature(AgentClientSnapshot snapshot)
        {
            string summary = snapshot.DlpPolicySummary;
            bool enabled = summary.IndexOf("enabled=True", StringComparison.OrdinalIgnoreCase) >= 0;
            snapshot.Features.Add(new ProtectionFeatureViewItem
            {
                Name = "截图与剪贴板防泄密",
                Description = string.IsNullOrWhiteSpace(summary) ? "等待 Agent 下发并运行策略" : summary,
                State = enabled ? "已开启" : "未开启",
                AccentBrushKey = enabled ? "DpSuccessBrush" : "DpMutedBrush"
            });
        }

        private string ResolveDlpPolicySummary()
        {
            string statePath = Path.Combine(dataDirectory, "AgentState.json");
            try
            {
                if (!File.Exists(statePath))
                {
                    return string.Empty;
                }

                AgentStateModel state = serializer.Deserialize<AgentStateModel>(File.ReadAllText(statePath, Encoding.UTF8));
                if (state == null || string.IsNullOrWhiteSpace(state.LastApplyMessage))
                {
                    return string.Empty;
                }

                int index = state.LastApplyMessage.IndexOf("DLP:", StringComparison.OrdinalIgnoreCase);
                if (index < 0)
                {
                    return string.Empty;
                }

                return state.LastApplyMessage.Substring(index + 4).Trim();
            }
            catch
            {
                return string.Empty;
            }
        }

        private UsbCryptPolicyFile ReadUsbCryptPolicy(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return null;
                }

                return serializer.Deserialize<UsbCryptPolicyFile>(File.ReadAllText(path, Encoding.UTF8));
            }
            catch
            {
                return null;
            }
        }

        private sealed class UsbCryptPolicyFile
        {
            public bool enabled { get; set; }
            public string algorithm { get; set; }
            public long publicToolAreaBytes { get; set; }
            public bool allowClientProvisioning { get; set; }
            public bool requireHardwareAuthorization { get; set; }
            public string keyMaterialId { get; set; }
        }
    }
}
