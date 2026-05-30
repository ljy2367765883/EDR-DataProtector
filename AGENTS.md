# DataProtector — Engineering Memory

This file is durable project memory for AI agents working on DataProtector.
Read it before starting work. Update it when architectural decisions change.

## Product context

- Commercial EDR / transparent-encryption product targeted at large-scale
  deployment (tens of millions of endpoints). Stability and completeness are
  non-negotiable. A kernel bug is a fleet-wide BSOD, not a caught exception.
- Solution builds with Visual Studio 2019 + WDK. MSBuild path:
  `D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe`
- Build the driver project, the PolicyApi DLL, and the WebBridge before
  declaring work done. Full solution: `.\DataProtector.sln` `Release|x64`.
- Components: `DataProtector.sys` (minifilter + EDR sensors), kernel control
  port `\DataProtectorPolicyPort`, `DataProtectorPolicyApi.dll` (stable C ABI),
  `DataProtectorWebBridge` (.NET central server + endpoint agent, HTTP API),
  WPF admin/agent clients.

## CORE ARCHITECTURAL RULE: scanning/detection-content belongs in USER MODE

Decision (owner directive, treat as binding):

> Heavy, rule-driven scanning must NOT run in the kernel. The kernel detects an
> event, captures metadata, and NOTIFIES user mode. A signed user-mode service
> performs the actual scan using YARA or other updatable rule engines and
> returns a verdict. The kernel only enforces the returned verdict.

Rationale:
- Detection content (YARA rules, signatures, ML models, cloud lookups) must be
  updatable WITHOUT shipping/reloading a signed kernel driver.
- Kernel code must stay thin, fast, and provably stable. Complex parsing
  (PE/entropy/string matching/rule evaluation) in kernel = fleet-wide crash
  risk.
- This matches the commercial EDR model: minifilter/callbacks in kernel + a
  signed scanning service in user mode (CrowdStrike, Defender MsMpEng, etc.).
- The design MUST be fully extensible: new rule types / engines must plug in at
  the user-mode service without kernel changes.

Required scanner shape:
- Kernel: on-access detector. On exe create / rename-to-exe / write-cleanup,
  capture {path, pid, operation, size}. Send an ASYNC notification up the
  existing communication port (FltSendMessage to a user-mode-connected port, or
  a dedicated notification port). For pre-execution blocking, the kernel may
  hold the operation pending a verdict with a bounded timeout and a fail-open
  (or policy-configurable fail-closed) default — but never block the kernel
  path indefinitely.
- User mode: a signed scanning service receives notifications, runs YARA / rule
  engines / hash lookups, and returns allow/block. Rules are loaded from a
  rule store that can be updated at runtime and synced from the central server.
- Verdicts/enforcement flow back through the policy channel; the threat engine
  still records the verdict into the per-process score and attack storyline.

### Static scanner design (target, being implemented)

- Transport: POLL/DRAIN over the existing `\DataProtectorPolicyPort`. The whole
  product is poll-based (the agent drains every sensor each heartbeat); the
  scan pipeline matches that, not FltSendMessage push.
- Verdict timing: ASYNC notify + post-hoc quarantine. The kernel never blocks
  the I/O path. On exe create/rename-to-exe/write-cleanup the kernel captures
  {seq, pid, op, size, path, image} into a scan-REQUEST ring. User mode drains
  requests, scans, and submits a VERDICT back; the kernel enforces it
  (records to threat engine; quarantines = truncates the file when policy says
  block).
- `DpStaticScan.c` MUST NOT classify. No PE parsing / entropy / string matching
  in the kernel. It only detects, captures metadata, enqueues requests, and
  enforces returned verdicts.
- User-mode engine: extensible `IScanEngine` pipeline (YARA via libyara P/Invoke,
  hash reputation, heuristic rules, future ML/cloud). Rules are runtime-updatable
  and synced from the central server. libyara.dll is a deployment artifact; if
  absent the YARA engine degrades gracefully (reports unavailable) so the build
  and service still run.
- Existing user-mode assets to build on: `AiStaticAnalysisService` (Ghidra +
  regex rule scoring + AI), `DataProtectorSandboxTelemetry`, and the agent's
  FileSystemWatcher sandbox-upload flow in `AgentSyncClient.cs`.

Control-plane commands for the scanner (kernel + PolicyApi private enum):
  QueryStaticScanRequests (drain), SubmitStaticScanVerdict, plus the existing
  QueryStaticScanEvents / Set+QueryStaticScanPolicy / ClearStaticScanEvents.

## Existing kernel EDR modules (sensors → threat engine)

- `DpThreatEngine.c` — central correlation brain: per-process risk scoring with
  ancestry propagation + time decay, MITRE ATT&CK mapping, graduated response
  (audit/alert/block/network-isolate/terminate), and ATT&CK attack STORYLINE
  (per-lineage ordered incident chain). All sensors report normalized signals
  here via `DpThreatEngineReportSignal`.
- Sensors: `DpProcessPolicy.c` (process notify), `DpUserHookDefense.c`
  (injection/ETW/image), `DpHashProtect.c` (LSASS/credential/registry/raw disk),
  `DpLateralDefense.c`, `DpNetFilter.c` (WFP; consults engine isolation flag),
  `DpWebShell.c`, `DpFileHunter.c`.

## Code conventions (match these exactly)

- Event rings: `LIST_ENTRY` + `KSPIN_LOCK`, sequence counter, dropped counter,
  bounded max with FIFO trim. Two-pass query sizing (header-only sizing call,
  then full copy). See `DpLateralDefense.c` for the canonical pattern.
- Rule lists: `EX_PUSH_LOCK` (FltAcquirePushLock*). Policy structs carry a
  Version + Flags, validate `FlagOn(Flags, ~ALLOWED_FLAGS)`.
- Alloc tags in `DataProtector.h` (`DP_TAG_*`). NonPagedPoolNx for everything.
- Control plane: add a `DpPolicyCommand*` enum value in BOTH `DataProtector.h`
  and `DataProtectorPolicyApi.c` (it keeps a private copy of the structs/enum),
  dispatch in `DpControl.c`, expose via PolicyApi C ABI (+ `.def` export), then
  WebBridge native interop + DTO + HTTP endpoint.
- Editing tip: when inserting C functions near existing ones, DO NOT let the
  edit oldString swallow the following function's signature — several builds
  broke this way. Re-verify the function header after each insert.
- PolicyApi pre-existing C4459 shadow warnings are benign (global helper vars).

## Verification checklist before "done"

1. `DataProtector.vcxproj` Release|x64 builds + signs (catalog generated).
2. `DataProtectorPolicyApi.vcxproj` builds; new exports present (dumpbin).
3. `DataProtectorWebBridge.csproj` builds (C# 7.3 — no static lambdas, etc.).
4. Full `.sln` build: 0 compiler errors.

## Git

- Remote: gitee `origin/master`. Commit messages in English, conventional
  style (`feat:`, `fix:`). Only commit/push when explicitly asked.
