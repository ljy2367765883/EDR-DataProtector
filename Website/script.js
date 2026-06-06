const translations = {
  zh: {
    metaTitle: "DataProtector | 开源 Windows 终端数据保护平台",
    metaDescription:
      "DataProtector 是一个开源 Windows 终端数据保护与威胁防御平台，覆盖透明文件保护、EDR 遥测、DLP 审计、集中策略、用户态扫描、沙箱分析和安全 U 盘。",
    skip: "跳到正文",
    "brand.sub": "开源终端防护",
    "nav.value": "价值",
    "nav.capabilities": "能力",
    "nav.workflow": "闭环",
    "nav.platform": "平台",
    "nav.opensource": "开源",
    "nav.repo": "查看项目",
    "hero.eyebrow": "开源 Windows 端点安全工程",
    "hero.title": "把数据保护、威胁检测和策略运营放进同一个终端闭环。",
    "hero.lede":
      "DataProtector 面向企业终端、内网数据和安全团队，将透明文件保护、EDR 遥测、DLP 审计、用户态扫描、沙箱分析、中央策略和安全 U 盘工作流整合在一个可开源验证的 Windows 平台里。",
    "hero.primary": "查看项目能力",
    "hero.secondary": "了解开源定位",
    "signal.kicker": "Endpoint Loop",
    "signal.file.k": "Data",
    "signal.file.t": "透明保护",
    "signal.file.d": "可信应用可用，非授权访问受限。",
    "signal.threat.k": "Threat",
    "signal.threat.t": "传感器",
    "signal.threat.d": "凭据、注入、横向移动、WebShell、网络异常。",
    "signal.scan.k": "Scan",
    "signal.scan.t": "用户态判定",
    "signal.scan.d": "YARA、哈希信誉、PE 启发式、沙箱和静态分析。",
    "signal.policy.k": "Policy",
    "signal.policy.t": "中央运营",
    "signal.policy.d": "策略、任务、审计、样本和 USB 授权。",
    "signal.footer.left": "audit / alert / block",
    "signal.footer.right": "isolate / terminate",
    "metric.projects": "解决方案项目",
    "metric.kernel": "内核 C 模块",
    "metric.exports": "PolicyApi 导出",
    "metric.port": "中央 API 端口",
    "value.eyebrow": "业务价值",
    "value.title": "不是后台皮肤，而是端点安全产品的业务闭环。",
    "value.copy":
      "项目把终端文件保护、威胁感知、策略下发、审计取证和移动介质治理放在同一条链路里，适合安全产品原型、企业数据保护研究和 Windows EDR 工程学习。",
    "value.lead.k": "Sensitive Data",
    "value.lead.t": "让可信业务继续工作，让敏感数据不轻易离开终端。",
    "value.lead.d":
      "透明保护模型按进程、目录和扩展名控制访问视图。研发文档、合同、图纸、客户资料和财务文件可以对授权应用保持可用，同时降低普通工具直接读取、复制、缓存和转存风险。",
    "value.1.k": "Threat Visibility",
    "value.1.t": "把攻击行为从单点告警变成可追踪故事线。",
    "value.1.d": "进程、凭据、注入、横向移动、WebShell、文件和网络传感器统一进入威胁评分与攻击流程。",
    "value.2.k": "Policy Operations",
    "value.2.t": "让规则、设备、任务、样本和审计统一运营。",
    "value.2.d": "中央服务维护策略版本，Agent 心跳同步并回传审计、网络连接、沙箱样本和远程任务结果。",
    "value.3.k": "Offline Delivery",
    "value.3.t": "让 U 盘成为受控工作区，而不是盲区。",
    "value.3.d": "设备授权、介质清点、公开工具区、私有数据区和初始化任务共同组成移动介质治理流程。",
    "capability.eyebrow": "核心能力",
    "capability.title": "从文件、进程、网络、样本和介质五个面协同防护。",
    "cap.1.k": "Transparent Protection",
    "cap.1.t": "透明文件保护",
    "cap.1.d": "可信进程规则、受保护扩展名、排除目录、保护标记和影子明文视图，让数据保护不必牺牲业务应用可用性。",
    "cap.2.k": "EDR Sensors",
    "cap.2.t": "终端威胁遥测",
    "cap.2.d": "覆盖 LSASS 访问、注册表 hive、原始磁盘、远程线程、异常镜像加载、ETW 篡改、SMB 投递和 IPC 控制。",
    "cap.3.k": "Threat Engine",
    "cap.3.t": "威胁关联引擎",
    "cap.3.d": "按进程谱系进行评分、衰减、战术映射和故事线记录，支持审计、告警、阻断、网络隔离和终止。",
    "cap.4.k": "User-mode Scan",
    "cap.4.t": "用户态静态扫描",
    "cap.4.d": "内核只捕获可执行文件事件；YARA、哈希信誉、PE 启发式和未来检测引擎在用户态完成判定并回传 verdict。",
    "cap.5.k": "Sandbox",
    "cap.5.t": "沙箱与静态分析",
    "cap.5.d": "Agent 发现可疑 EXE 后上传样本，Server 侧隔离环境运行分析，并结合 Ghidra 与规则评分补充样本上下文。",
    "cap.6.k": "DLP and USB",
    "cap.6.t": "DLP 与安全 U 盘",
    "cap.6.d": "安全目录读取审计、剪贴板与截图控制、可移动介质暂存可见性、USB Crypt 包管理和介质初始化任务构成数据外发治理。",
    "workflow.eyebrow": "工作闭环",
    "workflow.title": "事件在终端发生，判断在用户态演进，策略在中央运营。",
    "workflow.copy": "这个结构让内核保持轻量，检测内容可以持续更新，运营侧也能拿到可解释的审计与攻击流程。",
    "workflow.1.t": "内核捕获事件",
    "workflow.1.d": "minifilter、WFP 和进程回调捕获文件、进程、网络、凭据、横向移动和 WebShell 相关信号。",
    "workflow.2.t": "用户态完成重检测",
    "workflow.2.d": "静态扫描、YARA、沙箱、Ghidra 分析和规则评分都留在用户态，避免把复杂检测内容塞进内核。",
    "workflow.3.t": "ThreatEngine 关联响应",
    "workflow.3.d": "传感器信号进入进程谱系风险评分，形成攻击故事线，并根据策略执行告警、阻断、隔离或终止。",
    "workflow.4.t": "中央策略持续下发",
    "workflow.4.d": "Agent 拉取最新策略并回传审计、网络洞察、样本、设备状态和任务结果，形成运营闭环。",
    "platform.eyebrow": "平台组成",
    "platform.title": "单机能验证，中央能运营，前端能展示。",
    "platform.1.k": "Endpoint",
    "platform.1.t": "驱动、PolicyApi、本地桥接和 Agent",
    "platform.1.d": "终端负责透明保护、传感器采集、策略应用、扫描 verdict 执行、DLP 服务、设备清点和心跳同步。",
    "platform.2.k": "Central",
    "platform.2.t": "中央 HTTP 服务与策略仓库",
    "platform.2.d": "服务端维护设备、策略版本、审计、攻击流程、网络洞察、沙箱样本、静态分析记录、USB 包和任务队列。",
    "platform.3.k": "Operations",
    "platform.3.t": "WebAdmin、WPF Admin 和 Agent Client",
    "platform.3.d": "WebAdmin 服务集中运营，WPF Admin 服务本机策略，Agent Client 服务终端用户可见性。",
    "opensource.eyebrow": "开源定位",
    "opensource.title": "适合研究、教学、原型验证和二次开发。",
    "opensource.1.k": "适合谁",
    "opensource.1.d": "Windows 内核开发者、安全产品工程师、企业安全团队、EDR 研究者、DLP 与透明加密方案评估者。",
    "opensource.2.k": "当前价值",
    "opensource.2.d": "仓库覆盖驱动、原生 ABI、中央服务、Agent、Web 控制台、桌面客户端、沙箱、静态分析和 USB 工具。",
    "opensource.3.k": "生产前需要补齐",
    "opensource.3.d": "安装升级、驱动签名、密钥管理、认证加密、规则包发布、兼容性测试、防篡改、权限模型和运维文档。",
    "entry.eyebrow": "项目入口",
    "entry.title": "从你关心的层开始看。",
    "entry.1": "完整解决方案",
    "entry.2": "终端驱动",
    "entry.3": "中央服务与 Agent",
    "entry.4": "Web 管理控制台",
    "entry.5": "USB Crypt",
    "entry.6": "沙箱遥测",
    "footer.copy": "DataProtector 是一个面向 Windows 终端数据保护与威胁防御的开源项目。",
    "footer.top": "回到顶部"
  },
  en: {
    metaTitle: "DataProtector | Open Windows Endpoint Data Protection",
    metaDescription:
      "DataProtector is an open-source Windows endpoint data protection and threat defense platform for transparent protection, EDR telemetry, DLP auditing, central policy, user-mode scanning, sandbox analysis, and secure USB workflows.",
    skip: "Skip to content",
    "brand.sub": "Open endpoint protection",
    "nav.value": "Value",
    "nav.capabilities": "Capabilities",
    "nav.workflow": "Workflow",
    "nav.platform": "Platform",
    "nav.opensource": "Open source",
    "nav.repo": "View project",
    "hero.eyebrow": "Open Windows endpoint security engineering",
    "hero.title": "Data protection, threat detection, and policy operations in one endpoint loop.",
    "hero.lede":
      "DataProtector is built for enterprise endpoints, internal data, and security teams. It combines transparent file protection, EDR telemetry, DLP auditing, user-mode scanning, sandbox analysis, central policy, and secure USB workflows in one verifiable Windows platform.",
    "hero.primary": "Explore capabilities",
    "hero.secondary": "Open-source position",
    "signal.kicker": "Endpoint Loop",
    "signal.file.k": "Data",
    "signal.file.t": "Transparent protection",
    "signal.file.d": "Trusted apps stay usable while unauthorized access is limited.",
    "signal.threat.k": "Threat",
    "signal.threat.t": "Sensors",
    "signal.threat.d": "Credentials, injection, lateral movement, web shells, network anomalies.",
    "signal.scan.k": "Scan",
    "signal.scan.t": "User-mode verdicts",
    "signal.scan.d": "YARA, hash reputation, PE heuristics, sandboxing, and static analysis.",
    "signal.policy.k": "Policy",
    "signal.policy.t": "Central operations",
    "signal.policy.d": "Policies, tasks, audits, samples, and USB authorization.",
    "signal.footer.left": "audit / alert / block",
    "signal.footer.right": "isolate / terminate",
    "metric.projects": "solution projects",
    "metric.kernel": "kernel C modules",
    "metric.exports": "PolicyApi exports",
    "metric.port": "central API port",
    "value.eyebrow": "Business value",
    "value.title": "Not an admin skin, but a real endpoint-security business loop.",
    "value.copy":
      "The project connects endpoint file protection, threat visibility, policy distribution, audit evidence, and removable-media governance in one chain. It fits security-product prototypes, enterprise data-protection research, and Windows EDR engineering practice.",
    "value.lead.k": "Sensitive Data",
    "value.lead.t": "Keep trusted work running while making sensitive data harder to leave the endpoint.",
    "value.lead.d":
      "The transparent protection model controls access views by process, directory, and extension. Engineering documents, contracts, drawings, customer records, and financial files can remain usable for authorized apps while reducing direct reads, copies, caches, and staging by ordinary tools.",
    "value.1.k": "Threat Visibility",
    "value.1.t": "Turn attack behavior from isolated alerts into traceable storylines.",
    "value.1.d": "Process, credential, injection, lateral, web-shell, file, and network sensors flow into threat scoring and attack reconstruction.",
    "value.2.k": "Policy Operations",
    "value.2.t": "Operate rules, devices, tasks, samples, and audits from one control plane.",
    "value.2.d": "The central service maintains policy versions while agents synchronize heartbeats and report audits, network connections, sandbox samples, and task results.",
    "value.3.k": "Offline Delivery",
    "value.3.t": "Make USB storage a governed workspace instead of a blind spot.",
    "value.3.d": "Device authorization, removable inventory, public tool areas, private data areas, and initialization tasks form a removable-media workflow.",
    "capability.eyebrow": "Core capabilities",
    "capability.title": "Coordinated protection across files, processes, network, samples, and media.",
    "cap.1.k": "Transparent Protection",
    "cap.1.t": "Transparent file protection",
    "cap.1.d": "Trusted process rules, protected extensions, excluded directories, protection markers, and shadow plaintext views protect data without breaking business apps.",
    "cap.2.k": "EDR Sensors",
    "cap.2.t": "Endpoint threat telemetry",
    "cap.2.d": "Cover LSASS access, registry hives, raw disk reads, remote threads, abnormal image loads, ETW tamper, SMB staging, and IPC control.",
    "cap.3.k": "Threat Engine",
    "cap.3.t": "Threat correlation engine",
    "cap.3.d": "Score process lineages, decay risk over time, map tactics, record storylines, and support audit, alert, block, network isolation, and termination.",
    "cap.4.k": "User-mode Scan",
    "cap.4.t": "User-mode static scanning",
    "cap.4.d": "The kernel only captures executable events. YARA, hash reputation, PE heuristics, and future engines classify in user mode and submit verdicts back.",
    "cap.5.k": "Sandbox",
    "cap.5.t": "Sandbox and static analysis",
    "cap.5.d": "Agents upload suspicious executables, the server runs isolated analysis, and Ghidra plus rule scoring adds static context.",
    "cap.6.k": "DLP and USB",
    "cap.6.t": "DLP and secure USB",
    "cap.6.d": "Safe-folder read auditing, clipboard and screenshot controls, removable-media staging visibility, USB Crypt package management, and media initialization govern data movement.",
    "workflow.eyebrow": "Workflow",
    "workflow.title": "Events happen on endpoints, verdicts evolve in user mode, and policy is operated centrally.",
    "workflow.copy": "This keeps the kernel lean, lets detection content evolve, and gives operators explainable audits and attack-flow context.",
    "workflow.1.t": "Kernel captures events",
    "workflow.1.d": "The minifilter, WFP, and process callbacks capture file, process, network, credential, lateral-movement, and web-shell signals.",
    "workflow.2.t": "User mode performs heavy detection",
    "workflow.2.d": "Static scanning, YARA, sandboxing, Ghidra analysis, and rule scoring stay in user mode instead of turning the kernel into a parser.",
    "workflow.3.t": "ThreatEngine correlates and responds",
    "workflow.3.d": "Sensor signals enter process-lineage scoring, form attack storylines, and trigger alerting, blocking, isolation, or termination by policy.",
    "workflow.4.t": "Central policy keeps flowing",
    "workflow.4.d": "Agents pull the latest policy and report audits, network insights, samples, device state, and task results to close the operations loop.",
    "platform.eyebrow": "Platform",
    "platform.title": "Verifiable on one machine, operable centrally, visible through frontends.",
    "platform.1.k": "Endpoint",
    "platform.1.t": "Driver, PolicyApi, local bridge, and agent",
    "platform.1.d": "The endpoint handles transparent protection, sensor collection, policy apply, scan verdict enforcement, DLP service, device inventory, and heartbeat sync.",
    "platform.2.k": "Central",
    "platform.2.t": "Central HTTP service and policy store",
    "platform.2.d": "The server maintains devices, policy versions, audit, attack flows, network insights, sandbox samples, static-analysis records, USB packages, and task queues.",
    "platform.3.k": "Operations",
    "platform.3.t": "WebAdmin, WPF Admin, and Agent Client",
    "platform.3.d": "WebAdmin serves central operations, WPF Admin handles local policy control, and Agent Client gives endpoint-user visibility.",
    "opensource.eyebrow": "Open source",
    "opensource.title": "For research, education, product validation, and extension.",
    "opensource.1.k": "Who it helps",
    "opensource.1.d": "Windows kernel developers, security-product engineers, enterprise security teams, EDR researchers, and DLP or transparent-encryption evaluators.",
    "opensource.2.k": "Current value",
    "opensource.2.d": "The repository spans driver code, native ABI, central service, agent, web console, desktop clients, sandboxing, static analysis, and USB tooling.",
    "opensource.3.k": "Needed before production",
    "opensource.3.d": "Installer and upgrade flows, driver signing, key management, authenticated encryption, rule-pack release, compatibility testing, tamper protection, permission modeling, and operations docs.",
    "entry.eyebrow": "Project entry",
    "entry.title": "Start from the layer you care about.",
    "entry.1": "Full solution",
    "entry.2": "Endpoint driver",
    "entry.3": "Central service and agent",
    "entry.4": "Web admin console",
    "entry.5": "USB Crypt",
    "entry.6": "Sandbox telemetry",
    "footer.copy": "DataProtector is an open Windows project for endpoint data protection and threat defense.",
    "footer.top": "Back to top"
  }
};

const revealItems = Array.from(document.querySelectorAll("[data-reveal]"));
const navLinks = Array.from(document.querySelectorAll(".nav-links a"));
const languageButtons = Array.from(document.querySelectorAll("[data-lang-option]"));
const sections = navLinks
  .map(link => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);

function getInitialLanguage() {
  const requested = new URLSearchParams(window.location.search).get("lang");
  if (requested === "zh" || requested === "en") {
    return requested;
  }

  const saved = window.localStorage.getItem("dataprotector-language");
  if (saved === "zh" || saved === "en") {
    return saved;
  }

  return navigator.language && navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en";
}

function setMetaContent(selector, content) {
  const node = document.querySelector(selector);
  if (node) {
    node.setAttribute("content", content);
  }
}

function applyLanguage(language) {
  const dictionary = translations[language] || translations.en;
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  document.title = dictionary.metaTitle;
  setMetaContent('meta[name="description"]', dictionary.metaDescription);
  setMetaContent('meta[property="og:title"]', dictionary.metaTitle);
  setMetaContent('meta[property="og:description"]', dictionary.metaDescription);

  document.querySelectorAll("[data-i18n]").forEach(node => {
    const key = node.getAttribute("data-i18n");
    if (Object.prototype.hasOwnProperty.call(dictionary, key)) {
      node.textContent = dictionary[key];
    }
  });

  languageButtons.forEach(button => {
    const active = button.getAttribute("data-lang-option") === language;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });

  window.localStorage.setItem("dataprotector-language", language);
}

languageButtons.forEach(button => {
  button.addEventListener("click", () => {
    applyLanguage(button.getAttribute("data-lang-option"));
  });
});

applyLanguage(getInitialLanguage());

if ("IntersectionObserver" in window) {
  const revealObserver = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          revealObserver.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.14 }
  );

  revealItems.forEach(item => revealObserver.observe(item));

  const sectionObserver = new IntersectionObserver(
    entries => {
      const visible = entries
        .filter(entry => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

      if (!visible) {
        return;
      }

      navLinks.forEach(link => {
        link.toggleAttribute("aria-current", link.getAttribute("href") === `#${visible.target.id}`);
      });
    },
    {
      rootMargin: "-30% 0px -56% 0px",
      threshold: [0.08, 0.2, 0.45]
    }
  );

  sections.forEach(section => sectionObserver.observe(section));
} else {
  revealItems.forEach(item => item.classList.add("is-visible"));
}
