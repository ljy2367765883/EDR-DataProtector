# DataProtector

DataProtector is a Windows transparent file encryption project built around a
kernel-mode minifilter driver, a native user-mode policy API, and a WPF
administration application. It is designed to demonstrate a modular and
extensible transparent encryption pipeline where trusted processes receive
decrypted content and untrusted processes continue to see ciphertext.

The repository is intentionally organized as a full product-style codebase:
kernel I/O interception, policy management, user-mode administration, build
automation, publish packaging, diagnostics, and release artifacts are kept in
separate modules so each part can evolve independently.

> Important: the current cryptographic provider is a test XOR transform used to
> validate the I/O pipeline. It must be replaced with a real authenticated,
> key-managed cryptographic provider before production deployment.

## Table of Contents

- [Project Goals](#project-goals)
- [Repository Layout](#repository-layout)
- [System Architecture](#system-architecture)
- [Core Concepts](#core-concepts)
- [Transparent Encryption Workflow](#transparent-encryption-workflow)
- [Protected File Format](#protected-file-format)
- [Policy Model](#policy-model)
- [Process Trust Workflow](#process-trust-workflow)
- [Kernel Driver Design](#kernel-driver-design)
- [User-Mode API Design](#user-mode-api-design)
- [Administration Application](#administration-application)
- [Build Requirements](#build-requirements)
- [Build Instructions](#build-instructions)
- [Installation and Runtime Workflow](#installation-and-runtime-workflow)
- [Manual Test Matrix](#manual-test-matrix)
- [Diagnostics and Troubleshooting](#diagnostics-and-troubleshooting)
- [Current Limitations](#current-limitations)
- [Production Hardening Roadmap](#production-hardening-roadmap)

## Project Goals

DataProtector focuses on the following engineering goals:

- Provide transparent file encryption for selected file extensions.
- Return plaintext only to trusted processes.
- Return ciphertext to untrusted processes without blocking normal read access.
- Support process trust rules by executable name and executable directory.
- Bind trust rules and exclusion rules to file extensions.
- Support excluded directories where target extensions are left untouched.
- Preserve encrypted files as portable files by storing protection metadata
  inside the main file stream.
- Avoid exposing internal metadata through normal read and file information
  queries.
- Keep the driver, policy API, and UI separately replaceable.
- Keep the implementation understandable enough for kernel debugging and
  productization.

The project does not currently claim to provide production cryptography,
tamper-proof policy storage, enterprise key management, or hardened endpoint
self-defense. Those are explicit roadmap items.

## Repository Layout

```text
DataProtector/
  DataProtector.sln
  Build-All.ps1
  Publish-Admin.ps1
  README.md

  DataProtector/
    DataProtector.c          Driver entry, filter registration, lifecycle
    DataProtector.h          Shared kernel declarations and constants
    DpBuffer.c               Double-buffer allocation helpers
    DpControl.c              User-mode communication port
    DpCrypto.c               Replaceable transform provider
    DpIo.c                   Read, write, query, cleanup, rename callbacks
    DpPolicy.c               File protection metadata and stream contexts
    DpProcessPolicy.c        Trusted process and exclusion rule engine
    DpShadow.c               Trusted mapped-I/O shadow stream workflow
    DpTrace.c                Targeted diagnostic tracing
    DataProtector.inf        Minifilter installation package

  DataProtectorPolicyApi/
    DataProtectorPolicyApi.c Native DLL wrapper around the driver port
    DataProtectorPolicyApi.h Public C ABI for policy management

  DataProtectorAdmin/
    MainWindow.xaml          WPF administration surface
    ViewModels/              UI state and commands
    Services/                Policy service and local settings persistence
    Native/                  P/Invoke bridge to DataProtectorPolicyApi.dll
    Models/                  Policy rule and result models
    Assets/                  Application icon and visual assets
```

## System Architecture

```text
+-----------------------------+
| DataProtectorAdmin.exe       |
| WPF policy administration UI |
+--------------+--------------+
               |
               | P/Invoke
               v
+--------------+--------------+
| DataProtectorPolicyApi.dll   |
| Native C policy client API   |
+--------------+--------------+
               |
               | Filter Manager communication port
               | \DataProtectorPolicyPort
               v
+--------------+--------------+
| DataProtector.sys            |
| Windows minifilter driver    |
+--------------+--------------+
               |
               | IRP_MJ_CREATE / READ / WRITE / QUERY_INFORMATION
               | IRP_MJ_SET_INFORMATION / DIRECTORY_CONTROL / CLEANUP
               v
+--------------+--------------+
| File system                  |
| NTFS / ReFS / FAT / exFAT    |
+-----------------------------+
```

The kernel driver owns all data-path decisions. User mode only configures
policy. This keeps the trusted/untrusted read behavior consistent even when
applications access protected files through different Windows APIs.

## Core Concepts

### Protected Extension

A file is a candidate for protection when its extension matches the configured
policy. The default extension is `.dpf`, and rules may also target formats such
as `.pptx`.

### Trusted Process

A trusted process is allowed to receive plaintext for a protected file. Trust
can be granted by executable image name or by executable directory. Rules are
extension-aware, so a process can be trusted for one file type without being
trusted for every protected extension.

### Untrusted Process

An untrusted process is allowed to read protected files, but it receives the
encrypted bytes from the original stream. It should not receive the private
footer metadata.

### Excluded Directory

An excluded directory rule disables encryption for matching file extensions
under that directory. Files in excluded locations are read and written as normal
files, even if their extension is otherwise protected.

### Logical Size vs Physical Size

Protected files store a private 512-byte metadata footer at the end of the main
data stream. Applications should see the logical file size. The driver uses the
larger physical file size internally.

```text
physical file = encrypted payload bytes + 512-byte DataProtector footer
logical file  = encrypted payload bytes only
```

## Transparent Encryption Workflow

### 1. Creating a New Protected File

1. A trusted application creates or overwrites a file whose path matches a
   protected extension.
2. The driver marks the handle for encryption during cleanup.
3. The application writes plaintext normally.
4. On cleanup, the driver transforms the file content into ciphertext.
5. The driver appends a fixed 512-byte footer containing DataProtector metadata.
6. The stream context and handle context are updated so later opens recognize
   the file as protected.

This deferred workflow is important for compatibility with applications that
create temporary files, write content in multiple phases, and finalize the
document only at close time.

### 2. Opening an Existing Protected File from a Trusted Process

1. The driver detects the protected footer at the end of the file.
2. The driver calculates the logical size from the footer.
3. If the process is trusted for the file extension, reads are redirected
   through the decrypting path.
4. For memory-mapped applications, the driver uses the shadow workflow to avoid
   placing plaintext in the original file cache.
5. The application receives plaintext and can edit the file normally.
6. If the shadow content becomes dirty, cleanup writes the encrypted content
   back to the original file and refreshes the footer.

### 3. Opening an Existing Protected File from an Untrusted Process

1. The driver detects the protected footer.
2. The process is not trusted for that extension.
3. Reads are allowed, but they are clamped to the logical payload range.
4. The caller receives ciphertext bytes.
5. The private footer is never returned as normal file content.

This behavior is the central transparent encryption model: access is not simply
blocked; the caller receives the representation it is allowed to see.

### 4. Reading Past Logical EOF

When a protected file has a 512-byte footer, normal callers must not see that
footer. The read path clamps reads at the logical EOF:

- Reads starting at or beyond logical EOF complete with no payload.
- Reads crossing logical EOF are shortened.
- Trusted reads decrypt only the visible payload range.
- Untrusted reads receive only ciphertext payload bytes.

### 5. Querying File Size

The driver adjusts file information queries for protected streams:

- `FileStandardInformation`
- `FileAllInformation`
- `FileNetworkOpenInformation`
- `FileAllocationInformation`
- `FileEndOfFileInformation`

Directory enumeration is also adjusted for protected files so tools such as
Explorer and `dir` see the logical size rather than the physical size.

### 6. Rename-to-Protected Workflows

Many commercial applications save documents by writing a temporary file first
and then renaming it to the final extension. DataProtector handles this pattern:

1. The driver observes rename information.
2. If the destination path has a protected extension and is not excluded, the
   handle is armed for encryption.
3. After the rename succeeds, final encryption is deferred until cleanup.
4. The final file receives ciphertext content plus the 512-byte footer.

### 7. Excluded Directory Workflow

If a target file is under an excluded directory rule:

1. The protected extension check is bypassed.
2. Reads and writes use the original file stream without transformation.
3. Rename-to-protected behavior is also bypassed when the final target is under
   an excluded directory.

This is useful for caches, staging folders, compatibility directories, or
locations that should remain interoperable with external tooling.

## Protected File Format

DataProtector stores protection metadata in the final 512 bytes of the main
data stream. Alternate data streams are not used for protection metadata.

```text
+------------------------------+------------------------------+
| Encrypted payload             | 512-byte protection footer    |
| Offset 0..LogicalSize-1       | Offset LogicalSize..EOF-1     |
+------------------------------+------------------------------+
```

The footer currently contains:

- Magic value
- Footer format version
- Footer size
- Flags
- Logical file size
- File key length
- File key bytes
- Footer checksum
- Reserved bytes for future format expansion

The driver validates the footer before treating a file as protected. Validation
checks include magic, version, fixed footer size, key length, checksum, and the
relationship between physical EOF and logical EOF.

The fixed-size footer design was chosen because it avoids shifting every
application-visible byte offset. A header-based format would require translating
all caller offsets, which is riskier for complex document formats and memory
mapped I/O.

## Policy Model

Policy rules are maintained by the kernel driver and updated through the
Filter Manager communication port.

Supported rule kinds:

| Rule kind | Meaning |
| --- | --- |
| Process name | Trust an executable name for a specific extension |
| Process directory | Trust all executables under a directory for a specific extension |
| Excluded directory | Disable protection under a directory for a specific extension |

Rules are extension-aware. For example:

```text
notepad.exe      + .dpf   => trusted for .dpf
C:\OfficeTools\  + .pptx  => trusted for .pptx
D:\Exports\      + .pptx  => excluded for .pptx
```

The policy API supports:

- Add process-name trust rule
- Remove process-name trust rule
- Add process-directory trust rule
- Remove process-directory trust rule
- Add excluded-directory rule
- Remove excluded-directory rule
- Clear rules
- Query all rules
- Convert DOS paths to NT paths
- Retrieve the last policy API error message

## Process Trust Workflow

The trust decision happens when a file is opened or when a protected workflow is
armed:

1. Normalize the target file path.
2. Check whether the path has a protected extension.
3. Check whether the path is excluded.
4. Resolve the requestor process identity.
5. Match process-name rules and process-directory rules for the file extension.
6. Store the trust result in a stream-handle context.

The handle context allows later reads, writes, cleanup, and rename handling to
use a stable decision for that open instance.

## Kernel Driver Design

### Driver Registration

`DataProtector.c` registers the minifilter, context types, callbacks, instance
lifecycle, and unload behavior.

The driver currently handles:

- `IRP_MJ_CREATE`
- `IRP_MJ_READ`
- `IRP_MJ_WRITE`
- `IRP_MJ_QUERY_INFORMATION`
- `IRP_MJ_DIRECTORY_CONTROL`
- `IRP_MJ_SET_INFORMATION`
- `IRP_MJ_CLEANUP`
- `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`
- `IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE`

### Double Buffering

The read/write path uses swap buffers so the file system sees ciphertext while
trusted callers see plaintext.

Read path:

1. Allocate a swap buffer.
2. Read ciphertext into the swap buffer.
3. Transform the buffer for trusted callers.
4. Copy plaintext to the original caller buffer.

Write path:

1. Copy caller plaintext into a swap buffer.
2. Transform the swap buffer into ciphertext.
3. Send ciphertext to the file system.
4. Restore the original caller buffer pointers in post-operation cleanup.

### Stream and Handle Contexts

Stream contexts cache file-level state such as protection status and logical
size. Stream-handle contexts cache per-open state such as trust, shadow state,
pending rename target, and cleanup encryption state.

This separation matters because one protected file can be opened by multiple
processes with different trust decisions.

### Shadow Stream Workflow

Some applications, especially Office-style editors, rely heavily on memory
mapped I/O and the system file cache. Returning plaintext directly into the
original protected file cache can compromise the ciphertext-only invariant.

For trusted mapped applications, DataProtector redirects compatible opens to a
plaintext shadow stream:

1. Original ciphertext payload is copied and decrypted into the shadow stream.
2. The trusted application operates on the shadow stream.
3. Dirty shadow content is encrypted back to the original file on cleanup.
4. The original file footer is refreshed.

The shadow stream is an implementation detail for mapped-I/O compatibility. It
is separate from the persistent protection metadata footer.

## User-Mode API Design

`DataProtectorPolicyApi.dll` exposes a stable C ABI for policy operations. The
WPF application calls this DLL through P/Invoke, but the DLL can also be reused
by command-line tools, installers, services, or automated tests.

Public API examples:

```c
DWORD DpPolicyCheckConnection(void);
DWORD DpPolicyAddProcessNameRuleEx(LPCWSTR processName, LPCWSTR extension);
DWORD DpPolicyAddProcessDirectoryRuleEx(LPCWSTR directoryPath, LPCWSTR extension);
DWORD DpPolicyAddExcludedDirectoryRuleEx(LPCWSTR directoryPath, LPCWSTR extension);
DWORD DpPolicyQueryProcessRules(...);
DWORD DpPolicyGetLastErrorMessage(LPWSTR buffer, DWORD bufferChars);
```

The API translates friendly user-mode inputs into the message format expected
by the driver port.

## Administration Application

`DataProtectorAdmin` is a WPF desktop application using the WPF UI package for
a more polished management surface.

The admin app provides:

- Driver connection status
- Process-name trust rule management
- Process-directory trust rule management
- Excluded-directory rule management
- Extension-bound rule editing
- Local settings persistence
- Tray and application icon integration
- Diagnostic logging support

The UI is intentionally separated from policy transport. UI state lives in
view models and services; native driver communication remains in the policy API
layer.

## Build Requirements

Recommended environment:

- Windows 10 or Windows 11 x64
- Visual Studio 2019
- Windows Driver Kit compatible with Visual Studio 2019
- .NET Framework 4.7.2 or newer for the WPF admin app
- Administrator privileges for driver installation and service control
- Test-signing or a valid driver signing workflow for local kernel testing

The included build scripts currently expect MSBuild at:

```text
D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe
```

If Visual Studio is installed elsewhere, update `Build-All.ps1` and
`Publish-Admin.ps1`, or invoke MSBuild directly from your environment.

## Build Instructions

Build the complete solution:

```powershell
.\Build-All.ps1 -Configuration Release -Platform x64
```

Equivalent direct MSBuild command:

```powershell
& 'D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  .\DataProtector.sln `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

Expected key outputs:

```text
x64\Release\DataProtector.sys
x64\Release\DataProtector\dataprotector.cat
DataProtectorPolicyApi\x64\Release\DataProtectorPolicyApi.dll
DataProtectorAdmin\bin\x64\Release\DataProtectorAdmin.exe
```

Publish the admin application package:

```powershell
.\Publish-Admin.ps1
```

Default publish output:

```text
publish\DataProtectorAdmin-x64-Release\
```

## Installation and Runtime Workflow

### 1. Enable a Kernel Test Environment

Use a VM or dedicated test machine. Kernel minifilter development can crash the
system while debugging.

For local test signing, configure Windows appropriately for your environment.
Do not deploy test-signed drivers to production machines.

### 2. Install the Driver Package

Use the generated INF package from the Release output. Installation method may
vary depending on your signing and test environment.

Typical service control commands after installation:

```cmd
sc query DataProtector
net start DataProtector
net stop DataProtector
```

### 3. Launch the Admin Application

Run:

```text
DataProtectorAdmin.exe
```

The admin package must contain:

```text
DataProtectorAdmin.exe
DataProtectorAdmin.exe.config
DataProtectorPolicyApi.dll
Wpf.Ui.dll
```

### 4. Configure Rules

Example policy intent:

```text
Trust notepad.exe for .dpf
Trust C:\Program Files\WPS Office\ for .pptx
Exclude C:\Users\Public\Exports\ for .pptx
```

### 5. Validate Transparent Encryption

Use one trusted process and one untrusted process to read the same protected
file. The trusted process should see plaintext. The untrusted process should
see ciphertext. Both should see the same logical file size.

## Manual Test Matrix

| Scenario | Expected result |
| --- | --- |
| Trusted process creates `.dpf` | File is encrypted on cleanup and receives footer |
| Trusted process reopens `.dpf` | Plaintext is returned |
| Untrusted process reads `.dpf` | Ciphertext payload is returned |
| Read crosses logical EOF | Read is clamped before footer |
| `dir` lists protected file | Logical size is shown, not physical size |
| Explorer lists protected file | Logical size is shown |
| Driver is stopped and file is read | Raw ciphertext file is visible |
| Protected file is copied elsewhere | Footer travels with the file |
| Trusted process opens moved file | File can still be recognized and decrypted |
| File is created with temp extension then renamed to `.pptx` | Encryption is applied after rename/cleanup |
| File is under excluded directory | File remains unencrypted |
| Rule is added in admin app | Driver policy receives the rule |
| Rule is removed in admin app | Driver policy removes the rule |
| Admin app starts without driver | UI should report connection failure cleanly |

## Diagnostics and Troubleshooting

### Driver Does Not Start

Check:

- Driver signing state
- INF installation result
- Minifilter altitude conflicts
- Whether Filter Manager is available
- Event Viewer system logs
- `sc query DataProtector`
- `fltmc filters`

### Admin Cannot Connect

Check:

- `DataProtector.sys` is loaded
- `\DataProtectorPolicyPort` exists
- `DataProtectorPolicyApi.dll` is beside the admin executable
- Admin app bitness is x64
- The process has enough privileges

### Trusted App Still Reads Ciphertext

Check:

- The process-name or process-directory rule matches the actual executable
- The rule extension matches the target file extension
- The target path is not under an excluded directory
- The file has a valid DataProtector footer
- The trusted application is not opening a different temp path

### File Size Looks 512 Bytes Too Large

Check:

- The new driver build is loaded
- Query information callbacks are registered
- Directory enumeration is going through the filter
- The file footer validates successfully

### Office/WPS Save Compatibility

Office-style applications often save through temporary files and final renames.
Use process monitor logs and the targeted PPTX trace switch when investigating
compatibility issues.

The project contains a compile-time PPTX tracing switch:

```c
#define DP_ENABLE_PPTX_OPERATION_TRACE 1
```

Disable this switch for normal builds after investigation.

## Current Limitations

- The current crypto provider is a test XOR transform.
- There is no production key hierarchy or secure key wrapping.
- Policy storage and policy authorization are not hardened.
- The shadow stream workflow still uses an internal alternate stream for mapped
  I/O compatibility.
- The project does not yet include automated kernel integration tests.
- Manual unload is enabled for development convenience and must be revisited for
  production cache safety.
- The default trusted process list is intended for local bring-up only.

## Production Hardening Roadmap

Recommended next engineering milestones:

1. Replace the XOR provider with authenticated encryption.
2. Add per-file data keys protected by a master key or enterprise key service.
3. Add key rotation and footer version migration.
4. Replace development trust defaults with a signed policy service.
5. Persist policy in a protected store with integrity validation.
6. Move shadow storage away from alternate streams if zero-ADS operation is a
   hard product requirement.
7. Add stress tests for rename, overwrite, memory mapping, truncation, and
   concurrent open scenarios.
8. Add crash dump triage documentation and driver verifier profiles.
9. Add installer, upgrade, rollback, and service recovery workflows.
10. Add CI build validation for driver, native API, and WPF admin packaging.

## Design Principles

DataProtector is developed with the following design principles:

- Keep modules small and replaceable.
- Prefer explicit contexts over global state in I/O paths.
- Keep policy decisions separate from cryptographic transformation.
- Hide private metadata from normal application-visible operations.
- Treat Office-style save behavior as a first-class compatibility requirement.
- Build features in a way that supports commercial hardening later.
- Avoid claiming production security until the crypto and policy trust chain are
  actually production-grade.

## Status

The repository currently builds successfully for `Release|x64` with Visual
Studio 2019 and the Windows Driver Kit in the maintained development
environment.

The latest implemented file format stores DataProtector metadata in a fixed
512-byte footer at the end of the main file stream. This makes encrypted files
portable across directories and machines while keeping normal read and query
operations focused on the logical file payload.
