# DataProtector

DataProtector is an open-source Windows endpoint data protection and threat
defense platform. It combines transparent file protection, EDR telemetry, DLP
auditing, central policy management, user-mode static scanning, sandbox
analysis, and secure USB workflows in one Visual Studio 2019 + WDK solution.

DataProtector 是一个开源 Windows 终端数据保护与威胁防御平台，覆盖透明
文件保护、终端威胁遥测、DLP 审计、集中策略、用户态静态扫描、沙箱分析
和安全 U 盘工作流。它不是单独的后台页面，而是一套可研究、可二次开发、
可验证安全产品闭环的端点保护工程。

> Security status: this repository is a serious engineering prototype for
> research and product validation. Production deployment still requires stronger
> installer design, driver signing, key management, authenticated encryption,
> permission modeling, compatibility testing, tamper protection, and operations
> documentation.
>
> 安全状态：本仓库适合研究、教学、原型验证和二次开发。若要生产落地，还
> 需要补齐安装升级、驱动签名、密钥管理、认证加密、权限模型、兼容性测试、
> 防篡改和运维文档。

## Business Value / 业务价值

Modern endpoint security has to protect data without breaking daily work.
DataProtector focuses on four business problems that often appear together:

现代终端安全既要保护数据，也不能破坏正常业务。DataProtector 重点覆盖四类
常见但难以同时收口的问题：

- Sensitive document protection: engineering files, contracts, drawings,
  customer records, financial files, and other local business data need to stay
  usable for trusted applications while being harder to read, copy, or stage by
  unauthorized tools.
- 敏感文档保护：研发文档、合同、图纸、客户资料、财务文件等本地业务数据
  需要对可信业务应用保持可用，同时降低非授权工具读取、复制和转存风险。
- Endpoint threat visibility: malware drops, suspicious process chains,
  credential access, injection, web shells, ransomware-like mass access, and
  risky network behavior need to be correlated instead of treated as isolated
  alerts.
- 终端威胁可见性：恶意程序落地、可疑进程链、凭据访问、注入、WebShell、
  类勒索批量访问和异常网络行为，需要被关联分析，而不是散落成孤立告警。
- Centralized policy operations: security teams need a place to manage endpoint
  rules, agent health, audits, network insights, sandbox samples, remote tasks,
  and removable-device authorization.
- 集中策略运营：安全团队需要统一管理终端规则、Agent 健康、审计、网络洞察、
  沙箱样本、远程任务和移动介质授权。
- Secure offline delivery: removable media still appears in field work,
  isolated networks, and offline exchange, so USB storage needs governance
  instead of simply being ignored or fully trusted.
- 安全离线交付：外勤办公、隔离网络和离线资料交换仍会使用 U 盘，所以移动
  介质需要被纳入治理，而不是简单忽略或完全信任。

## What It Provides / 项目能力

| Area | Capability |
| --- | --- |
| Transparent protection | Process-aware file protection, trusted process rules, protected extensions, excluded directories, protection markers, and shadow plaintext views for trusted applications. |
| 透明保护 | 按进程、目录和扩展名建立可信访问策略，结合保护标记和影子明文视图，让可信业务应用可用、非授权访问受限。 |
| EDR telemetry | Process policy, credential access protection, user-hook defense, lateral movement defense, web-shell detection, FileHunter sensitive-read auditing, WFP network telemetry, SMTP auditing, and executable write detection. |
| EDR 遥测 | 进程策略、凭据访问保护、用户态 Hook 防御、横向移动防御、WebShell 检测、FileHunter 敏感读取审计、WFP 网络遥测、SMTP 审计和可执行文件写入检测。 |
| Threat correlation | A kernel-side threat engine aggregates sensor signals into process lineage, risk scores, ATT&CK-style tactics, storylines, and graduated responses. |
| 威胁关联 | 内核威胁引擎将传感器信号聚合到进程谱系中，形成风险评分、ATT&CK 风格战术、攻击故事线和分级响应。 |
| User-mode scanning | The kernel only captures executable create, rename, and write-cleanup metadata. YARA, hash reputation, PE heuristics, and future engines run in user mode and submit verdicts back. |
| 用户态扫描 | 内核只捕获可执行文件创建、重命名和写关闭元数据；YARA、哈希信誉、PE 启发式和未来检测引擎都在用户态运行并回传 verdict。 |
| Central control plane | Device inventory, policy versioning, audit center, attack flow view, network awareness, IP info enrichment, sandbox sample center, static-analysis records, USB Crypt packages, and remote tasks. |
| 中央控制面 | 设备清单、策略版本、审计中心、攻击流程还原、网络感知、IP 信息增强、沙箱样本中心、静态分析记录、USB Crypt 运行包和远程任务。 |
| DLP workflow | Safe-folder auditing, clipboard and screenshot controls, sensitive file read telemetry, removable-media staging visibility, and central policy distribution. |
| DLP 工作流 | 安全目录审计、剪贴板与截图控制、敏感文件读取遥测、移动介质暂存可见性和中央策略下发。 |
| Secure USB | Removable device inventory, central authorization, USB layout initialization, public tool area, protected private area, metadata writing, and unlock tooling. |
| 安全 U 盘 | 可移动设备清点、中央授权、U 盘布局初始化、公开工具区、受保护私有区、元数据写入和解锁工具。 |
| Operator surfaces | WebAdmin for central operations, WPF Admin for local policy, WPF Agent Client for endpoint status, and a standalone bilingual project website. |
| 操作界面 | WebAdmin 集中运营、WPF Admin 本机策略、WPF Agent Client 终端状态展示，以及独立中英双语官网。 |

## Typical Scenarios / 典型场景

- Enterprise document protection: keep trusted Office/WPS, design, finance, or
  business systems usable while reducing direct access by unauthorized tools.
- 企业文档保护：让可信 Office/WPS、设计、财务或业务系统保持可用，同时减少
  非授权工具的直接读取与复制。
- Internal attack detection: connect LSASS access, registry hive access, remote
  service tools, scheduled tasks, WMI, PowerShell remoting, SMB executable
  staging, IPC control, and suspicious network connections.
- 内网攻击检测：将 LSASS 访问、注册表 hive、远程服务工具、计划任务、WMI、
  PowerShell 远程、SMB 可执行文件投递、IPC 控制和异常网络连接串起来分析。
- Sample triage lab: combine executable write detection, YARA scanning,
  hash reputation, Windows Sandbox telemetry, user-mode hook events, and
  Ghidra-based static analysis.
- 样本研判实验：结合可执行文件写入检测、YARA 扫描、哈希信誉、Windows
  Sandbox 遥测、用户态 Hook 事件和基于 Ghidra 的静态分析。
- Secure removable media: prepare controlled USB media for field delivery,
  offline exchange, isolated-network workflows, and device authorization tests.
- 安全移动介质：为外勤交付、离线交换、隔离网络流程和设备授权测试准备受控
  U 盘。

## Architecture / 架构

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
  Website
```

## Components / 组件目录

```text
DataProtector/
  DataProtector/                 Kernel minifilter, sensors, WFP, ThreatEngine
  DataProtectorPolicyApi/        Native C ABI over the driver policy port
  DataProtectorWebBridge/        Local bridge, central server, endpoint agent
  DataProtectorWebAdmin/         Web operator console
  DataProtectorAdmin/            WPF local admin console
  DataProtectorAgentClient/      WPF endpoint agent client
  DataProtectorUsbCrypt/         Secure USB runtime driver
  DataProtectorUsbTool/          USB unlock, mount, and initialization tool
  DataProtectorUserHookRuntime/  User-mode runtime hook component
  DataProtectorSandboxTelemetry/ Windows Sandbox telemetry runner
  DataProtectorStaticAnalyzer/   Ghidra/static-analysis tooling
  UserHookTriggerTest/           Runtime hook test utility
  Website/                       Standalone Chinese/English project website
  third_party/yara-rules/        Bundled YARA rule assets
```

## Standalone Website / 独立官网

`Website/` is a static bilingual project website. It is separate from
`DataProtectorWebAdmin`, which is the product's operator console.

`Website/` 是独立中英双语官网，用来介绍项目业务价值、能力、场景和开源定位；
它不是 `DataProtectorWebAdmin` 管理后台。

```text
Website/index.html?lang=zh
Website/index.html?lang=en
```

## Build Requirements / 构建要求

- Windows 10 or Windows 11 x64.
- Visual Studio 2019.
- Windows Driver Kit compatible with Visual Studio 2019.
- .NET Framework 4.7.2 or newer.
- Administrator privileges for driver installation and service control.
- Test signing or a valid driver signing pipeline.

本地工程记忆中的 MSBuild 路径：

```text
D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe
```

## Build / 构建

```powershell
.\Build-All.ps1 -Configuration Release -Platform x64
```

Direct MSBuild:

```powershell
& 'D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  .\DataProtector.sln `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

Before declaring a change complete, build at least:

- `DataProtector.vcxproj` `Release|x64`
- `DataProtectorPolicyApi.vcxproj`
- `DataProtectorWebBridge.csproj`
- Full `DataProtector.sln` `Release|x64`

## Runtime Modes / 运行模式

```cmd
DataProtectorWebBridge.exe server [http://+:17643/] [webRoot]
DataProtectorWebBridge.exe agent http://<server-ip>:17643/ [pollSeconds]
DataProtectorWebBridge.exe standalone [http://+:17643/] [webRoot]
```

- `server`: central HTTP server and WebAdmin static hosting.
- `agent`: endpoint heartbeat, policy synchronization, audit upload, scan
  request draining, sandbox sample upload, and remote task execution.
- `standalone`: local HTTP bridge for operating one endpoint directly.

- `server`：中央 HTTP 服务和 WebAdmin 静态托管。
- `agent`：终端心跳、策略同步、审计上传、扫描请求 draining、沙箱样本上传和
  远程任务执行。
- `standalone`：本地 HTTP 桥接服务，用于直接操作单台终端。

## Security Principles / 安全原则

- Heavy scanning and detection content must stay in user mode. Kernel code
  detects events, captures metadata, and enforces returned verdicts.
- 复杂扫描和检测内容必须留在用户态。内核只负责发现事件、捕获元数据和执行
  用户态返回的 verdict。
- Kernel code should stay thin, bounded, and conservative. A kernel crash is not
  a normal exception; it is a system-wide failure.
- 内核代码必须保持轻量、有界和保守。内核崩溃不是普通异常，而是整机级故障。
- Current crypto paths are suitable for pipeline validation and research, not
  production data protection without hardening.
- 当前加密路径适合管线验证和研究，未经过生产级密钥管理与认证加密硬化。
- Test in virtual machines or dedicated test hosts before touching real data.
- 请先在虚拟机或专用测试机上验证，不要直接用于真实数据环境。

## Roadmap / 路线图

- Replace development crypto with authenticated encryption and real key
  management.
- 用认证加密和真实密钥管理替换开发验证用加密路径。
- Add installer, upgrade, rollback, signing, and safe-unload workflows.
- 补齐安装、升级、回滚、签名和安全卸载流程。
- Expand kernel, PolicyApi, WebBridge, WebAdmin, and agent tests.
- 扩展内核、PolicyApi、WebBridge、WebAdmin 和 Agent 测试。
- Package YARA rules and scanner updates cleanly.
- 规范化 YARA 规则与扫描器更新包。
- Harden USB Crypt cryptography and provisioning.
- 强化 USB Crypt 密码学和初始化流程。
- Publish deeper architecture, API, deployment, and operations docs.
- 发布更完整的架构、API、部署和运维文档。

## Contributing / 参与贡献

Useful contribution areas include Windows minifilter stability, WFP and EDR
sensor coverage, static scan engines, YARA rule packaging, sandbox telemetry,
WebAdmin UX, secure USB workflows, build automation, CI, packaging, and docs.

欢迎参与 Windows minifilter 稳定性、WFP 与 EDR 传感器覆盖、静态扫描引擎、
YARA 规则包、沙箱遥测、WebAdmin 体验、安全 U 盘流程、构建自动化、CI、打包
和文档建设。

Please keep the kernel thin and stable. Detection content belongs in user mode.

请保持内核轻量稳定，检测内容应放在用户态。

## License / 许可证

No root repository license has been added yet. Choose and add a license before
advertising the project as reusable open-source software.

当前根仓库尚未添加许可证。若要作为可复用开源项目正式发布，请先选择并添加
许可证。
