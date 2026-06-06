# DataProtector

Language: **English** | [Chinese](README.zh-CN.md)

DataProtector is an open-source Windows endpoint data protection and threat
defense platform. It combines kernel minifilter based transparent protection,
EDR telemetry, DLP auditing, centralized policy operations, user-mode static
scanning, sandbox-assisted triage, and secure USB workflows in one Visual
Studio 2019 + WDK solution.

> Security status: this repository is a serious engineering prototype for
> research, product validation, and open-source collaboration. Production
> deployment still requires stronger installer design, driver signing, key
> management, authenticated encryption, permission modeling, compatibility
> testing, tamper protection, safe upgrade flows, and operations documentation.

## What It Solves

Modern endpoint security has to protect business data without breaking normal
work. DataProtector focuses on these real operational needs:

- Sensitive document protection: engineering files, contracts, drawings,
  customer records, financial files, and other local business data should stay
  usable for trusted applications while becoming harder to read, copy, or stage
  with unauthorized tools.
- Endpoint threat visibility: malware drops, suspicious process chains,
  credential access, injection, web shells, ransomware-like mass access, and
  risky network behavior need to be correlated instead of treated as isolated
  alerts.
- Centralized security operations: teams need one place to manage endpoint
  policy, agent health, audit events, attack flows, network insights, sandbox
  samples, static-analysis records, remote tasks, and removable-device
  authorization.
- Secure offline delivery: removable media is still common in field work,
  isolated networks, and offline exchange, so USB storage needs explicit
  governance instead of being fully trusted or fully blocked.

## Core Capabilities

| Area | Capability |
| --- | --- |
| Transparent protection | Process-aware file protection, trusted process rules, protected extensions, excluded directories, protection markers, and shadow plaintext views for trusted applications. |
| EDR telemetry | Process policy, credential access protection, user-hook defense, lateral movement defense, web-shell detection, FileHunter sensitive-read auditing, WFP network telemetry, SMTP auditing, and executable write detection. |
| Threat correlation | A kernel-side threat engine aggregates sensor signals into process lineage, risk scores, ATT&CK-style tactics, storylines, and graduated responses. |
| User-mode static scanning | The kernel captures executable create, rename, and write-cleanup metadata. YARA, hash reputation, PE heuristics, Ghidra analysis, sandbox telemetry, and future engines run in user mode. |
| Central control plane | Device inventory, policy versioning, audit center, attack-flow view, network awareness, IP enrichment, sandbox sample center, static-analysis records, USB Crypt packages, and remote tasks. |
| DLP workflow | Safe-folder auditing, clipboard and screenshot controls, sensitive file read telemetry, removable-media staging visibility, and central policy distribution. |
| Secure USB | Removable device inventory, central authorization, USB layout initialization, public tool area, protected private area, metadata writing, and unlock tooling. |
| Operator surfaces | WebAdmin for central operations, WPF Admin for local policy, and WPF Agent Client for endpoint status. |

## Typical Scenarios

- Enterprise document protection: keep trusted Office/WPS, design, finance, or
  business systems usable while reducing direct access by unauthorized tools.
- Internal attack detection: connect LSASS access, registry hive access, remote
  service tools, scheduled tasks, WMI, PowerShell remoting, SMB executable
  staging, IPC control, and suspicious network connections into one storyline.
- Sample triage lab: combine executable write detection, YARA scanning, hash
  reputation, Windows Sandbox telemetry, user-mode hook events, UPX unpacking,
  and Ghidra-based static analysis.
- Secure removable media: prepare controlled USB media for field delivery,
  offline exchange, isolated-network workflows, and device authorization tests.

## Architecture

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

## Repository Layout

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

## Design Principles

- Keep heavy detection content in user mode. Kernel code should detect events,
  capture metadata, and enforce returned verdicts.
- Keep the kernel thin, bounded, and conservative. A kernel bug is a system-wide
  failure, not a normal exception.
- Treat endpoint operations as a closed loop: observe locally, classify safely,
  correlate by process lineage, enforce policy, and report centrally.
- Keep detection engines extensible. YARA, hash reputation, heuristic rules,
  sandboxing, static analysis, future ML engines, and cloud lookups should plug
  into user mode without kernel changes.
- Make the product useful as a research platform before claiming production
  readiness.

## Static Scanning Model

DataProtector intentionally keeps complex scanning out of the kernel.

- Kernel path: detect executable create, rename-to-exe, and write-cleanup
  events; capture request metadata into a bounded ring; enforce returned
  verdicts when policy requires action.
- User-mode path: drain pending requests through `DataProtectorPolicyApi.dll`,
  read file content, run the scan engine pipeline, and submit a verdict.

This design allows YARA rules, hash reputation data, PE heuristics, sandbox
signals, Ghidra analysis, and future detection engines to evolve without
rebuilding or reloading the signed driver.

## Third-Party Frameworks and Projects

DataProtector uses and bundles several third-party components. Please review
their upstream licenses before redistribution, especially detection rules,
binary analysis tooling, and bundled runtime artifacts.

| Component or project | Location or usage | Purpose | License or notice |
| --- | --- | --- | --- |
| Microsoft Windows Driver Kit and Windows SDK | `DataProtector`, `DataProtectorPolicyApi`, native tools | Minifilter, WFP, Filter Manager IPC, Win32 crypto, networking, setup, shell, and UI APIs | Microsoft SDK/WDK terms. Native projects link platform libraries such as `fltmgr.lib`, `fwpkclnt.lib`, `ndis.lib`, `FltLib.lib`, `Advapi32.lib`, `Bcrypt.lib`, `Comctl32.lib`, `Setupapi.lib`, `Shell32.lib`, `User32.lib`, `Gdi32.lib`, `Ws2_32.lib`, `Wintrust.lib`, and `Crypt32.lib`. |
| .NET Framework 4.7.2, WPF, and Windows Forms | `DataProtectorWebBridge`, `DataProtectorAdmin`, `DataProtectorAgentClient`, `DataProtectorSandboxTelemetry` | Server/agent runtime, desktop operator UI, and sandbox telemetry | Microsoft .NET Framework and Windows platform terms. |
| Wpf.Ui 4.3.0 | `DataProtectorAdmin`, `DataProtectorAgentClient` | Modern WPF controls and styling | MIT. |
| MinHook | `third_party/minhook`, `DataProtectorUserHookRuntime` | User-mode API hook runtime | BSD-2-Clause. |
| YARA / libyara v4.5.5 | `third_party/yara-bin/x64/libyara.dll`, `YaraScanEngine` | User-mode rule engine for static scanning | Built in-house from official `VirusTotal/yara` source tag `v4.5.5`; upstream YARA license is BSD-3-Clause. The engine late-binds `libyara.dll` and degrades gracefully if it is absent. |
| Neo23x0/signature-base | `third_party/yara-rules/signature-base` | Bundled YARA detection rules | Detection Rule License 1.1. |
| Yara-Rules/rules | `third_party/yara-rules/yara-rules` | Bundled community YARA detection rules | GPL-2.0. |
| ReversingLabs YARA rules | `third_party/yara-rules/reversinglabs` | Bundled YARA detection rules | MIT. |
| Elastic protections-artifacts | `third_party/yara-rules/elastic` | Bundled Elastic YARA detection rules | Elastic License 2.0. |
| Ghidra | `external/ghidra-release`, `DataProtectorStaticAnalyzer`, `DataProtectorWebBridge` static analysis service | Headless import, decompilation, string extraction, import extraction, function graphing, pseudocode, and analyzer script integration | Apache License 2.0 for Ghidra. The bundled distribution also contains a `GPL/` directory; review it before redistributing packaged artifacts. |
| UPX | `DataProtectorStaticAnalyzer/tools/upx.exe` | Optional unpacking preflight before static analysis | UPX is distributed under GPL-2.0-or-later with the UPX exception. Verify upstream license requirements before redistribution. |
| SoybeanAdmin | `DataProtectorWebAdmin` | Base WebAdmin application structure and admin-console conventions | MIT; the original Soybean license is preserved in `DataProtectorWebAdmin/LICENSE`. |
| Vue WebAdmin stack | `DataProtectorWebAdmin/package.json`, `pnpm-lock.yaml` | Frontend application runtime and build system | Direct dependencies include Vue 3, Vite 8, TypeScript, pnpm workspace packages, Vue Router, Pinia, Vue I18n, Naive UI, UnoCSS, ECharts, LogicFlow, VueUse, Iconify, Axios, Day.js, NProgress, Better Scroll, clipboard, Tailwind Merge, Sass, ESLint, Oxlint, Oxfmt, and Vite/UnoCSS/Iconify plugins. Review each package license through npm metadata and the lockfile. |
| Star History | README badges | Repository star trend chart | External chart service used only for README visualization. |

The bundled rule sets are detection content, not kernel logic. They are loaded
by the user-mode scanner and can be replaced or updated without changing the
signed driver. See `third_party/yara-rules/README.md` for the local rule-source
notice and commercial redistribution warning.

## Build Requirements

- Windows 10 or Windows 11 x64.
- Visual Studio 2019.
- Windows Driver Kit compatible with Visual Studio 2019.
- .NET Framework 4.7.2 or newer.
- Node.js 20.19.0 or newer and pnpm 10.5.0 or newer for WebAdmin.
- Administrator privileges for driver installation and service control.
- Test signing or a valid driver signing pipeline.

The local engineering environment uses MSBuild at:

```text
D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe
```

Adjust build scripts if Visual Studio is installed elsewhere.

## Build

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

## Runtime Modes

```cmd
DataProtectorWebBridge.exe server [http://+:17643/] [webRoot]
DataProtectorWebBridge.exe agent http://<server-ip>:17643/ [pollSeconds]
DataProtectorWebBridge.exe standalone [http://+:17643/] [webRoot]
```

- `server`: central HTTP server and WebAdmin static hosting.
- `agent`: endpoint heartbeat, policy synchronization, audit upload, scan
  request draining, sandbox sample upload, and remote task execution.
- `standalone`: local HTTP bridge for operating one endpoint directly.

## Roadmap

- Replace development crypto with authenticated encryption and real key
  management.
- Add installer, upgrade, rollback, signing, and safe-unload workflows.
- Expand kernel, PolicyApi, WebBridge, WebAdmin, and agent tests.
- Package YARA rules and scanner updates cleanly.
- Harden USB Crypt cryptography and provisioning.
- Publish deeper architecture, API, deployment, and operations docs.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ljy2367765883/EDR-DataProtector&type=Date)](https://www.star-history.com/#ljy2367765883/EDR-DataProtector&Date)

## Contributing

Useful contribution areas include Windows minifilter stability, WFP and EDR
sensor coverage, static scan engines, YARA rule packaging, sandbox telemetry,
WebAdmin UX, secure USB workflows, build automation, CI, packaging, and docs.

Please keep the kernel thin and stable. Detection content belongs in user mode.

## License

This repository is released under the GNU General Public License v3.0. See
`LICENSE` for the full license text. Third-party components and rule sets keep
their own upstream licenses as documented above and in their local license
files.
