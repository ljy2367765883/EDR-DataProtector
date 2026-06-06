# DataProtector

语言：[English](README.md) | **中文**

DataProtector 是一个开源的 Windows 终端数据保护与威胁防护平台。它把基于
内核 minifilter 的透明文件保护、EDR 终端遥测、DLP 审计、集中策略管理、
用户态静态扫描、沙箱辅助分析和安全 U 盘工作流整合在同一个 Visual Studio
2019 + WDK 解决方案中。

> 安全状态：本仓库是用于研究、产品验证和开源协作的严肃工程原型。生产
> 环境落地仍需要补强安装器设计、驱动签名、密钥管理、认证加密、权限模型、
> 兼容性测试、防篡改、安全升级回滚和运维文档。

## 它解决什么问题

现代终端安全既要保护业务数据，也不能破坏正常办公流程。DataProtector 重点
覆盖这些真实业务需求：

- 敏感文档保护：研发文件、合同、图纸、客户资料、财务文件等本地业务数据
  需要继续被可信应用正常使用，同时降低被非授权工具读取、复制或中转的风险。
- 终端威胁可见性：恶意文件落地、可疑进程链、凭据访问、注入、WebShell、
  类勒索批量访问、异常网络行为需要被关联分析，而不是变成互不相干的告警。
- 集中化安全运营：安全团队需要统一管理终端策略、Agent 状态、审计事件、
  攻击链路、网络洞察、沙箱样本、静态分析记录、远程任务和移动存储授权。
- 安全离线交付：外勤、隔离网络、离线交换场景仍然会使用移动介质，因此
  U 盘不能被默认完全信任，也不能简单一刀切禁用。

## 核心能力

| 领域 | 能力 |
| --- | --- |
| 透明保护 | 基于进程感知的文件保护、可信进程规则、受保护扩展名、排除目录、保护标记，以及面向可信应用的明文影子视图。 |
| EDR 遥测 | 进程策略、凭据访问保护、用户态 Hook 防护、横向移动防护、WebShell 检测、FileHunter 敏感读取审计、WFP 网络遥测、SMTP 审计和可执行文件写入检测。 |
| 威胁关联 | 内核侧威胁引擎把传感器信号聚合为进程血缘、风险评分、ATT&CK 风格战术、攻击故事线和分级响应。 |
| 用户态静态扫描 | 内核捕获可执行文件创建、重命名和写入关闭元数据，YARA、哈希信誉、PE 启发式、Ghidra 分析、沙箱遥测和未来引擎都在用户态运行。 |
| 集中控制平面 | 设备资产、策略版本、审计中心、攻击流视图、网络感知、IP 信息增强、沙箱样本中心、静态分析记录、USB Crypt 包和远程任务。 |
| DLP 工作流 | 安全目录审计、剪贴板与截屏控制、敏感文件读取遥测、移动介质暂存可见性和集中策略分发。 |
| 安全 U 盘 | 移动设备资产、集中授权、U 盘布局初始化、公共工具区、受保护私有区、元数据写入和解锁工具。 |
| 操作界面 | 面向集中运营的 WebAdmin、本地策略管理 WPF Admin，以及终端状态 WPF Agent Client。 |

## 典型场景

- 企业文档保护：让可信 Office/WPS、设计、财务或业务系统继续可用，同时减少
  非授权工具直接访问敏感文件。
- 内部攻击检测：把 LSASS 访问、注册表 Hive 访问、远程服务工具、计划任务、
  WMI、PowerShell Remoting、SMB 可执行文件投递、IPC 控制和可疑网络连接
  串成一条攻击故事线。
- 样本研判实验室：结合可执行文件落地检测、YARA 扫描、哈希信誉、Windows
  Sandbox 遥测、用户态 Hook 事件、UPX 脱壳和 Ghidra 静态分析。
- 安全移动介质：为外勤交付、离线交换、隔离网络流程和设备授权测试准备受控
  U 盘。

## 架构

```text
Endpoint
  DataProtector.sys
    Minifilter transparent protection
    Process, credential, web-shell, lateral, file, static-scan sensors
    WFP network filter and SMTP auditing
    ThreatEngine correlation and response
    Kernel policy port: \DataProtectorPolicyPort

  DataProtectorPolicyApi.dll
    Stable native C ABI
    Policy, query, drain, and verdict submission APIs

  DataProtectorWebBridge agent mode
    Central heartbeat
    Policy apply
    Static scan request draining
    DLP service
    Removable device inventory
    Sandbox sample upload
    Remote task execution

Central
  DataProtectorWebBridge server mode
    HTTP API on port 17643
    Device inventory and health
    Central policy versions
    Audit and attack-flow views
    Network awareness
    Sandbox and static-analysis sample centers
    USB Crypt runtime packages
    Remote task queue

Operations
  DataProtectorWebAdmin
  DataProtectorAdmin
  DataProtectorAgentClient
```

## 仓库结构

```text
DataProtector/
  DataProtector/                 Kernel minifilter, sensors, WFP, ThreatEngine
  DataProtectorPolicyApi/        Native C ABI over the driver policy port
  DataProtectorWebBridge/        Local bridge, central server, endpoint agent
  DataProtectorWebAdmin/         Web operator console based on SoybeanAdmin
  DataProtectorAdmin/            WPF local admin console
  DataProtectorAgentClient/      WPF endpoint agent client
  DataProtectorUsbCrypt/         Secure USB runtime driver
  DataProtectorUsbTool/          USB unlock, mount, and initialization tool
  DataProtectorUserHookRuntime/  User-mode runtime hook component
  DataProtectorSandboxTelemetry/ Windows Sandbox telemetry runner
  DataProtectorStaticAnalyzer/   Ghidra/static-analysis tooling
  external/ghidra-release/       Bundled Ghidra distribution assets
  third_party/minhook/           MinHook source used by the hook runtime
  third_party/yara-bin/          Bundled libyara.dll runtime artifact
  third_party/yara-rules/        Bundled third-party YARA rule assets
  UserHookTriggerTest/           Runtime hook test utility
```

## 设计原则

- 重型检测内容放在用户态。内核负责发现事件、捕获元数据并执行用户态返回的
  判定。
- 内核保持轻量、有界、保守。内核缺陷是系统级故障，不是普通异常。
- 终端安全应该形成闭环：本地观察、安全分类、按进程血缘关联、执行策略并
  集中上报。
- 检测引擎必须可扩展。YARA、哈希信誉、启发式规则、沙箱、静态分析、未来
  ML 引擎和云端查询都应该能在用户态接入，而不需要修改内核。
- 在声明生产就绪之前，先把项目作为可用的研究平台和工程原型打磨好。

## 静态扫描模型

DataProtector 明确避免把复杂扫描逻辑放进内核。

- 内核路径：检测可执行文件创建、重命名为可执行文件和写入关闭事件；把请求
  元数据写入有界队列；在策略要求时执行用户态返回的 verdict。
- 用户态路径：通过 `DataProtectorPolicyApi.dll` 拉取待扫描请求，读取文件
  内容，运行扫描引擎管线，再提交 verdict。

这种设计允许 YARA 规则、哈希信誉、PE 启发式、沙箱信号、Ghidra 分析和未来
检测引擎独立演进，而不需要重建或重新加载签名驱动。

## 第三方框架和开源项目

DataProtector 使用并随仓库包含若干第三方组件。重新分发前请务必检查对应上游
许可证，尤其是检测规则、二进制分析工具和运行时二进制文件。

| 组件或项目 | 位置或用途 | 作用 | 许可证或说明 |
| --- | --- | --- | --- |
| Microsoft Windows Driver Kit 和 Windows SDK | `DataProtector`、`DataProtectorPolicyApi`、原生工具 | Minifilter、WFP、Filter Manager IPC、Win32 加密、网络、安装、Shell 和 UI API | Microsoft SDK/WDK 条款。原生项目链接 `fltmgr.lib`、`fwpkclnt.lib`、`ndis.lib`、`FltLib.lib`、`Advapi32.lib`、`Bcrypt.lib`、`Comctl32.lib`、`Setupapi.lib`、`Shell32.lib`、`User32.lib`、`Gdi32.lib`、`Ws2_32.lib`、`Wintrust.lib`、`Crypt32.lib` 等平台库。 |
| .NET Framework 4.7.2、WPF 和 Windows Forms | `DataProtectorWebBridge`、`DataProtectorAdmin`、`DataProtectorAgentClient`、`DataProtectorSandboxTelemetry` | 服务端/Agent 运行时、桌面操作界面和沙箱遥测 | Microsoft .NET Framework 与 Windows 平台条款。 |
| Wpf.Ui 4.3.0 | `DataProtectorAdmin`、`DataProtectorAgentClient` | 现代 WPF 控件和样式 | MIT。 |
| MinHook | `third_party/minhook`、`DataProtectorUserHookRuntime` | 用户态 API Hook 运行时 | BSD-2-Clause。 |
| YARA / libyara v4.5.5 | `third_party/yara-bin/x64/libyara.dll`、`YaraScanEngine` | 用户态静态扫描规则引擎 | 基于官方 `VirusTotal/yara` 源码 tag `v4.5.5` 自行构建；上游 YARA 许可证为 BSD-3-Clause。引擎通过 late binding 加载 `libyara.dll`，缺失时会降级而不是导致服务不可用。 |
| Neo23x0/signature-base | `third_party/yara-rules/signature-base` | 随仓库包含的 YARA 检测规则 | Detection Rule License 1.1。 |
| Yara-Rules/rules | `third_party/yara-rules/yara-rules` | 随仓库包含的社区 YARA 检测规则 | GPL-2.0。 |
| ReversingLabs YARA rules | `third_party/yara-rules/reversinglabs` | 随仓库包含的 YARA 检测规则 | MIT。 |
| Elastic protections-artifacts | `third_party/yara-rules/elastic` | 随仓库包含的 Elastic YARA 检测规则 | Elastic License 2.0。 |
| Ghidra | `external/ghidra-release`、`DataProtectorStaticAnalyzer`、`DataProtectorWebBridge` 静态分析服务 | Headless 导入、反编译、字符串提取、导入表提取、函数图、伪代码和分析脚本集成 | Ghidra 主体为 Apache License 2.0。随仓库的发行目录还包含 `GPL/` 目录，重新分发打包产物前需要单独审查。 |
| UPX | `DataProtectorStaticAnalyzer/tools/upx.exe` | 静态分析前可选的脱壳预处理工具 | UPX 使用 GPL-2.0-or-later 并带 UPX exception。重新分发前请核对上游许可证要求。 |
| SoybeanAdmin | `DataProtectorWebAdmin` | WebAdmin 的基础管理后台结构和约定 | MIT；原 Soybean 许可证保留在 `DataProtectorWebAdmin/LICENSE`。 |
| Vue WebAdmin 技术栈 | `DataProtectorWebAdmin/package.json`、`pnpm-lock.yaml` | 前端应用运行时和构建系统 | 直接依赖包括 Vue 3、Vite 8、TypeScript、pnpm workspace packages、Vue Router、Pinia、Vue I18n、Naive UI、UnoCSS、ECharts、LogicFlow、VueUse、Iconify、Axios、Day.js、NProgress、Better Scroll、clipboard、Tailwind Merge、Sass、ESLint、Oxlint、Oxfmt，以及 Vite/UnoCSS/Iconify 插件。具体许可证请以 npm metadata 和 lockfile 为准。 |
| Star History | README 图表 | 仓库 Star 趋势图 | 仅用于 README 可视化的外部图表服务。 |

这些规则集属于检测内容，不属于内核逻辑。它们由用户态扫描器加载，可以在不修改
签名驱动的情况下替换或更新。更多规则来源和商业分发注意事项请查看
`third_party/yara-rules/README.md`。

## 构建要求

- Windows 10 或 Windows 11 x64。
- Visual Studio 2019。
- 与 Visual Studio 2019 兼容的 Windows Driver Kit。
- .NET Framework 4.7.2 或更高版本。
- WebAdmin 需要 Node.js 20.19.0 或更高版本，以及 pnpm 10.5.0 或更高版本。
- 安装驱动和控制服务需要管理员权限。
- 测试签名环境或有效的驱动签名流程。

本地工程环境使用的 MSBuild 路径为：

```text
D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe
```

如果 Visual Studio 安装路径不同，请同步调整构建脚本。

## 构建

```powershell
.\Build-All.ps1 -Configuration Release -Platform x64
```

直接使用 MSBuild：

```powershell
& 'D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  .\DataProtector.sln `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

在声明改动完成前，至少应构建：

- `DataProtector.vcxproj` `Release|x64`
- `DataProtectorPolicyApi.vcxproj`
- `DataProtectorWebBridge.csproj`
- 完整 `DataProtector.sln` `Release|x64`

## 运行模式

```cmd
DataProtectorWebBridge.exe server [http://+:17643/] [webRoot]
DataProtectorWebBridge.exe agent http://<server-ip>:17643/ [pollSeconds]
DataProtectorWebBridge.exe standalone [http://+:17643/] [webRoot]
```

- `server`：集中 HTTP 服务和 WebAdmin 静态托管。
- `agent`：终端心跳、策略同步、审计上传、扫描请求拉取、沙箱样本上传和远程
  任务执行。
- `standalone`：面向单机直接操作的本地 HTTP bridge。

## Roadmap

- 用认证加密和正式密钥管理替换开发阶段加密方案。
- 增加安装、升级、回滚、签名和安全卸载流程。
- 扩展内核、PolicyApi、WebBridge、WebAdmin 和 Agent 测试。
- 更规范地打包 YARA 规则和扫描器更新。
- 加固 USB Crypt 加密和制备流程。
- 发布更完整的架构、API、部署和运维文档。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ljy2367765883/EDR-DataProtector&type=Date)](https://www.star-history.com/#ljy2367765883/EDR-DataProtector&Date)

## 参与贡献

适合贡献的方向包括 Windows minifilter 稳定性、WFP 和 EDR 传感器覆盖、静态
扫描引擎、YARA 规则打包、沙箱遥测、WebAdmin UX、安全 U 盘流程、构建自动化、
CI、打包和文档。

请保持内核轻量稳定。检测内容应该放在用户态。

## 许可证

本仓库使用 GNU General Public License v3.0 发布。完整文本见 `LICENSE`。
第三方组件和规则集保留其各自上游许可证，具体见上文说明和本地 license 文件。
