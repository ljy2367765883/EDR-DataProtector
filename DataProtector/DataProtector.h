/*++

Module Name:

    DataProtector.h

Abstract:

    Shared declarations for the DataProtector transparent encryption
    minifilter.

--*/

#pragma once

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#ifndef FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS
#define FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS 0x00000002
#endif

#define DP_TAG_IO_CONTEXT      'cIpD'
#define DP_TAG_IO_BUFFER       'bIpD'
#define DP_TAG_STREAM_CONTEXT  'sCpD'
#define DP_TAG_HANDLE_CONTEXT  'hCpD'
#define DP_TAG_NAME_BUFFER     'nSpD'
#define DP_TAG_SHADOW_BUFFER   'bSpD'
#define DP_TAG_RENAME_CONTEXT  'rCpD'
#define DP_TAG_POLICY_RULE     'rPpD'
#define DP_TAG_PROCESS_ENTRY   'pPpD'
#define DP_TAG_FOOTER_BUFFER   'fPpD'
#define DP_TAG_NET_RULE        'rNpD'
#define DP_TAG_NET_BUFFER      'bNpD'
#define DP_TAG_NET_EVENT       'eNpD'
#define DP_TAG_SMTP_EVENT      'eSpD'
#define DP_TAG_SMTP_FLOW       'fSpD'
#define DP_TAG_WEBSHELL_RULE   'rWpD'
#define DP_TAG_WEBSHELL_EVENT  'eWpD'
#define DP_TAG_WEBSHELL_BUFFER 'bWpD'
#define DP_TAG_FILE_HUNTER_RULE 'rFpD'
#define DP_TAG_FILE_HUNTER_EVENT 'eFpD'
#define DP_TAG_FILE_HUNTER_CONTEXT 'cFpD'
#define DP_TAG_DEVICE_RULE     'rDpD'
#define DP_TAG_HASH_PROTECT    'hHpD'
#define DP_TAG_LATERAL_DEFENSE 'lLpD'
#define DP_TAG_USER_HOOK_DEFENSE 'hUpD'
#define DP_TAG_USB_METADATA    'mUpD'
#define DP_TAG_THREAT_PROCESS  'pTpD'
#define DP_TAG_THREAT_EVENT    'eTpD'
#define DP_TAG_THREAT_RESPONSE 'rTpD'
#define DP_TAG_THREAT_STORY    'yTpD'
#define DP_TAG_STATIC_SCAN     'sSpD'
#define DP_TAG_STATIC_BUFFER   'bSsD'

#define DP_POLICY_MAX_RULE_BYTES (1024 * sizeof(WCHAR))
#define DP_POLICY_MAX_EXTENSION_BYTES (64 * sizeof(WCHAR))
#define DP_POLICY_MAX_NETWORK_RULES 1024
#define DP_POLICY_MAX_DOMAIN_BYTES (260 * sizeof(WCHAR))
#define DP_NETWORK_MAX_CONNECTION_EVENTS 1024
#define DP_NETWORK_EVENT_PROCESS_PATH_CHARS 512
#define DP_NETWORK_EVENT_DOMAIN_CHARS 260
#define DP_POLICY_MAX_SMTP_EVENTS 128
#define DP_SMTP_MAX_ADDRESS_CHARS 256
#define DP_WEBSHELL_MAX_RULES 256
#define DP_WEBSHELL_MAX_PATH_BYTES (1024 * sizeof(WCHAR))
#define DP_WEBSHELL_MAX_EVENTS 256
#define DP_WEBSHELL_MAX_SAMPLE_BYTES 100
#define DP_WEBSHELL_EVENT_PATH_CHARS 512
#define DP_WEBSHELL_EVENT_EXTENSION_CHARS 32
#define DP_FILE_HUNTER_MAX_RULES 256
#define DP_FILE_HUNTER_MAX_EVENTS 512
#define DP_FILE_HUNTER_PATH_CHARS 512
#define DP_FILE_HUNTER_PROCESS_CHARS 64
#define DP_FILE_HUNTER_DEDUP_SLOTS 512
#define DP_FILE_HUNTER_DUPLICATE_WINDOW_100NS (10ll * 1000ll * 10000ll)
#define DP_DEVICE_MAX_RULES 256
#define DP_DEVICE_MAX_ID_CHARS 260
#define DP_DEVICE_MAX_ID_BYTES (DP_DEVICE_MAX_ID_CHARS * sizeof(WCHAR))
#define DP_HASH_PROTECT_MAX_EVENTS 256
#define DP_HASH_PROTECT_TARGET_CHARS 512
#define DP_HASH_PROTECT_PROCESS_CHARS 64
#define DP_LATERAL_DEFENSE_MAX_EVENTS 512
#define DP_LATERAL_DEFENSE_TARGET_CHARS 512
#define DP_LATERAL_DEFENSE_PROCESS_CHARS 64
#define DP_USER_HOOK_DEFENSE_MAX_EVENTS 512
#define DP_USER_HOOK_DEFENSE_TARGET_CHARS 512
#define DP_USER_HOOK_DEFENSE_PROCESS_CHARS 512
#define DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS 2048
#define DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS 512
#define DP_THREAT_MAX_PROCESSES 4096
#define DP_THREAT_MAX_EVENTS 1024
#define DP_THREAT_PROCESS_CHARS 320
#define DP_THREAT_DETAIL_CHARS 384
#define DP_THREAT_HASH_BUCKETS 1024
#define DP_THREAT_MAX_TECHNIQUES_PER_PROC 24
#define DP_THREAT_MAX_STORYLINES 128
#define DP_THREAT_STORY_MAX_STEPS 48
#define DP_THREAT_STORY_DETAIL_CHARS 200
#define DP_STATIC_SCAN_MAX_EVENTS 512
#define DP_STATIC_SCAN_PATH_CHARS 512
#define DP_STATIC_SCAN_PROCESS_CHARS 64
#define DP_STATIC_SCAN_REASON_CHARS 256
#define DP_STATIC_SCAN_SAMPLE_BYTES 4096
#define DP_STATIC_SCAN_MAX_REQUESTS 1024
#define DP_USB_METADATA_BYTES 512
#define DP_USB_METADATA_RESERVED_BYTES (2ull * 1024ull * 1024ull)
#define DP_USB_METADATA_DEFAULT_OFFSET_BYTES (1024ull * 1024ull)
#define DP_USB_PUBLIC_TOOL_BYTES (5ull * 1024ull * 1024ull)
#define DP_USB_DATA_OFFSET_BYTES (DP_USB_METADATA_RESERVED_BYTES + DP_USB_PUBLIC_TOOL_BYTES)
#define DP_USB_METADATA_PATH_CHARS 128
#define DP_USB_METADATA_MESSAGE_VERSION 1
#define DP_USB_METADATA_RESULT_VERSION 1
#define DP_USB_METADATA_MAGIC_V2 0x32535544u
#define DP_USB_METADATA_MAGIC_V1 0x31535544u
#define DP_POLICY_DEFAULT_EXTENSION L".dpf"
#define DP_POLICY_PORT_NAME      L"\\DataProtectorPolicyPort"
#define DP_PROTECTION_MAGIC 0x32465044u
#define DP_PROTECTION_FOOTER_SIZE 512
#define DP_PROTECTION_FOOTER_VERSION 1
#define DP_FILE_KEY_LENGTH 32
#define DP_PROTECTION_FOOTER_RESERVED_SIZE \
    (DP_PROTECTION_FOOTER_SIZE - (sizeof(ULONG) * 6) - sizeof(ULONGLONG) - DP_FILE_KEY_LENGTH)

#define DP_TRACE_ROUTINES      0x00000001
#define DP_TRACE_IO            0x00000002
#define DP_TRACE_POLICY        0x00000004
#define DP_TRACE_SHADOW        0x00000008

//
// Targeted WPS/Office investigation switch. Set to 0 for normal builds.
// When enabled, the driver emits DbgPrintEx lines only for .pptx paths
// and DataProtector internal streams/metadata.
//
#define DP_ENABLE_PPTX_OPERATION_TRACE 0

//
// Targeted WebShell investigation switch. Emits DataProtector77 lines through
// DbgPrintEx while diagnosing policy, event queue, and reporting paths.
//
#define DP_ENABLE_WEBSHELL_OPERATION_TRACE 0

//
// Targeted hash-dump protection diagnostics. Emits only registration failures
// and blocked credential-dump attempts.
//
#define DP_ENABLE_HASH_PROTECT_TRACE 0

//
// Safe-folder file thief hunter diagnostics. Keep this enabled while the
// feature is being validated so DbgView can show policy, path-match, queue,
// and drain activity with the DataProtector[FileHunter] filter.
//
#define DP_ENABLE_FILE_HUNTER_TRACE 1

//
// Blocks well-known built-in hive export tools at process creation time so
// failed reg.exe hive-save attempts still produce a security audit record even
// when the Configuration Manager denies the request before registry callbacks.
//
#define DP_ENABLE_HASH_PROTECT_REG_PROCESS_GUARD 1

//
// Targeted lateral movement defense diagnostics. The module only prints when
// it blocks or queues high-risk IPC/SMB activity.
//
#define DP_ENABLE_LATERAL_DEFENSE_TRACE 0

//
// Application-layer API hook defense diagnostics. Keep this enabled while
// validating kernel-owned startup injection so DbgView can show process-create,
// image-load, export resolution, APC queueing, and skip/failure gates with the
// DataProtector[UserHook] filter.
//
#define DP_ENABLE_USER_HOOK_DEFENSE_TRACE 1

//
// Threat engine diagnostics. The module prints only signal ingestion, score
// escalation, and automated response decisions when enabled.
//
#define DP_ENABLE_THREAT_ENGINE_TRACE 0
//
// Executable static scanner diagnostics. Prints PE classification verdicts and
// block decisions when enabled.
//
#define DP_ENABLE_STATIC_SCAN_TRACE 0
//
// Cached transparent encryption keeps plaintext in the system file cache.
// Manual unload is therefore unsafe unless a separate safe-stop path flushes
// and purges protected streams first.
//
#define DP_ALLOW_MANUAL_UNLOAD 1

//
// Production builds must obtain trust decisions from a signed policy source
// such as a protected user-mode service plus process creation cache. The
// built-in process-name list is only for local bring-up.
//
#define DP_ENABLE_TEST_TRUSTED_PROCESSES 1

//
// The XOR provider is only useful for I/O pipeline validation. Production
// builds must replace DpCrypto.c with an authenticated, key-managed provider.
// When no provider is available, the driver still loads but protected
// plaintext I/O fails closed.
//
#define DP_ENABLE_TEST_CRYPTO_PROVIDER 1

//
// Never enable this in a production isolation model. It exists only as a
// diagnostic switch for studying Cache Manager behavior. The stable design
// redirects trusted memory-mapped applications to a shadow plaintext file.
//
#define DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO 0

extern PFLT_FILTER gDataProtectorFilter;
extern ULONG gDataProtectorTraceFlags;

#define DP_DBG_PRINT(_level, _args)                         \
    (FlagOn(gDataProtectorTraceFlags, (_level)) ?           \
        DbgPrint _args :                                    \
        ((int)0))

typedef enum _DP_IO_OPERATION {
    DpIoRead = 1,
    DpIoWrite = 2
} DP_IO_OPERATION;

typedef struct _DP_IO_CONTEXT {
    DP_IO_OPERATION Operation;
    PFLT_INSTANCE Instance;
    PVOID SwapBuffer;
    ULONG Length;
    ULONG SwapBufferLength;
    PVOID OriginalBuffer;
    PMDL OriginalMdl;
    LARGE_INTEGER ByteOffset;
    struct _DP_HANDLE_CONTEXT *HandleContext;
    ULONG FileKeyLength;
    UCHAR FileKey[DP_FILE_KEY_LENGTH];
    BOOLEAN TransformInPlace;
    BOOLEAN FileHunterAuditOnly;
    struct _DP_FILE_HUNTER_READ_CONTEXT *FileHunterContext;
} DP_IO_CONTEXT, *PDP_IO_CONTEXT;

#pragma pack(push, 1)
typedef struct _DP_PROTECTION_FOOTER {
    ULONG Magic;
    ULONG Version;
    ULONG FooterSize;
    ULONG Flags;
    ULONGLONG LogicalSize;
    ULONG KeyLength;
    UCHAR FileKey[DP_FILE_KEY_LENGTH];
    ULONG Checksum;
    UCHAR Reserved[DP_PROTECTION_FOOTER_RESERVED_SIZE];
} DP_PROTECTION_FOOTER, *PDP_PROTECTION_FOOTER;
#pragma pack(pop)

C_ASSERT(sizeof(DP_PROTECTION_FOOTER) == DP_PROTECTION_FOOTER_SIZE);
C_ASSERT(DP_PROTECTION_FOOTER_RESERVED_SIZE > 0);

typedef struct _DP_STREAM_CONTEXT {
    BOOLEAN IsProtected;
    BOOLEAN PlaintextCacheEnabled;
    LARGE_INTEGER LogicalSize;
    ULONG FileKeyLength;
    UCHAR FileKey[DP_FILE_KEY_LENGTH];
} DP_STREAM_CONTEXT, *PDP_STREAM_CONTEXT;

typedef struct _DP_HANDLE_CONTEXT {
    BOOLEAN IsProtected;
    BOOLEAN IsTrusted;
    BOOLEAN IsShadow;
    BOOLEAN ShadowDirty;
    BOOLEAN EncryptOnCleanup;
    BOOLEAN FooterDirty;
    LARGE_INTEGER LogicalSize;
    ULONG FileKeyLength;
    UCHAR FileKey[DP_FILE_KEY_LENGTH];
    UNICODE_STRING OriginalName;
    UNICODE_STRING ShadowName;
    UNICODE_STRING PendingName;
    BOOLEAN WebShellNewFile;
    BOOLEAN WebShellReported;
    BOOLEAN StaticScanNewFile;
    BOOLEAN StaticScanReported;
} DP_HANDLE_CONTEXT, *PDP_HANDLE_CONTEXT;

typedef struct _DP_CREATE_CONTEXT {
    BOOLEAN IsTrusted;
    BOOLEAN IsShadow;
    BOOLEAN ShadowDirty;
    UNICODE_STRING OriginalName;
    UNICODE_STRING ShadowName;
} DP_CREATE_CONTEXT, *PDP_CREATE_CONTEXT;

typedef struct _DP_FILE_HUNTER_READ_CONTEXT {
    HANDLE ProcessId;
    LARGE_INTEGER ByteOffset;
    ULONG Flags;
    WCHAR Path[DP_FILE_HUNTER_PATH_CHARS];
    ULONG PathLengthBytes;
    WCHAR ProcessImage[DP_FILE_HUNTER_PROCESS_CHARS];
    ULONG ProcessImageLengthBytes;
} DP_FILE_HUNTER_READ_CONTEXT, *PDP_FILE_HUNTER_READ_CONTEXT;

typedef enum _DP_PROCESS_TRUST_RULE_TYPE {
    DpProcessTrustRuleImageName = 1,
    DpProcessTrustRuleImageDirectory = 2,
    DpProcessTrustRuleExcludedDirectory = 3
} DP_PROCESS_TRUST_RULE_TYPE;

typedef enum _DP_POLICY_COMMAND {
    DpPolicyCommandAddProcessNameRule = 1,
    DpPolicyCommandRemoveProcessNameRule = 2,
    DpPolicyCommandAddProcessDirectoryRule = 3,
    DpPolicyCommandRemoveProcessDirectoryRule = 4,
    DpPolicyCommandClearProcessRules = 5,
    DpPolicyCommandQueryProcessRules = 6,
    DpPolicyCommandAddExcludedDirectoryRule = 7,
    DpPolicyCommandRemoveExcludedDirectoryRule = 8,
    DpPolicyCommandAddNetworkRule = 20,
    DpPolicyCommandRemoveNetworkRule = 21,
    DpPolicyCommandClearNetworkRules = 22,
    DpPolicyCommandQueryNetworkRules = 23,
    DpPolicyCommandQuerySmtpEvents = 24,
    DpPolicyCommandQueryNetworkConnectionEvents = 25,
    DpPolicyCommandAddWebShellRule = 40,
    DpPolicyCommandRemoveWebShellRule = 41,
    DpPolicyCommandClearWebShellRules = 42,
    DpPolicyCommandQueryWebShellRules = 43,
    DpPolicyCommandQueryWebShellEvents = 44,
    DpPolicyCommandAddDeviceRule = 60,
    DpPolicyCommandRemoveDeviceRule = 61,
    DpPolicyCommandClearDeviceRules = 62,
    DpPolicyCommandQueryDeviceRules = 63,
    DpPolicyCommandQueryHashProtectEvents = 80,
    DpPolicyCommandSetHashProtectPolicy = 81,
    DpPolicyCommandQueryHashProtectPolicy = 82,
    DpPolicyCommandQueryLateralDefenseEvents = 90,
    DpPolicyCommandSetLateralDefensePolicy = 91,
    DpPolicyCommandQueryLateralDefensePolicy = 92,
    DpPolicyCommandQueryUserHookDefenseEvents = 110,
    DpPolicyCommandSetUserHookDefensePolicy = 111,
    DpPolicyCommandQueryUserHookDefensePolicy = 112,
    DpPolicyCommandAddFileHunterRule = 120,
    DpPolicyCommandRemoveFileHunterRule = 121,
    DpPolicyCommandClearFileHunterRules = 122,
    DpPolicyCommandQueryFileHunterRules = 123,
    DpPolicyCommandQueryFileHunterEvents = 124,
    DpPolicyCommandQueryThreatEvents = 140,
    DpPolicyCommandQueryThreatProcesses = 141,
    DpPolicyCommandSetThreatPolicy = 142,
    DpPolicyCommandQueryThreatPolicy = 143,
    DpPolicyCommandClearThreatEvents = 144,
    DpPolicyCommandRespondThreatProcess = 145,
    DpPolicyCommandQueryThreatStorylines = 146,
    DpPolicyCommandQueryStaticScanEvents = 160,
    DpPolicyCommandSetStaticScanPolicy = 161,
    DpPolicyCommandQueryStaticScanPolicy = 162,
    DpPolicyCommandClearStaticScanEvents = 163,
    DpPolicyCommandQueryStaticScanRequests = 164,
    DpPolicyCommandSubmitStaticScanVerdict = 165,
    DpPolicyCommandWriteUsbMetadata = 100
} DP_POLICY_COMMAND;

typedef struct _DP_POLICY_MESSAGE {
    ULONG Version;
    ULONG Command;
    ULONG ValueLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Data[1];
} DP_POLICY_MESSAGE, *PDP_POLICY_MESSAGE;

#define DP_POLICY_MESSAGE_VERSION 1
#define DP_POLICY_MESSAGE_HEADER_SIZE FIELD_OFFSET(DP_POLICY_MESSAGE, Data)

typedef struct _DP_POLICY_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_POLICY_QUERY_HEADER, *PDP_POLICY_QUERY_HEADER;

typedef struct _DP_POLICY_QUERY_ENTRY {
    ULONG RuleType;
    ULONG ValueLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Data[1];
} DP_POLICY_QUERY_ENTRY, *PDP_POLICY_QUERY_ENTRY;

#define DP_POLICY_QUERY_VERSION 1
#define DP_POLICY_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_POLICY_QUERY_ENTRY, Data)

typedef struct _DP_USB_METADATA_WRITE_MESSAGE {
    ULONG Version;
    ULONG MetadataBytes;
    ULONGLONG OffsetBytes;
    ULONG PhysicalPathLengthBytes;
    ULONG Reserved;
    WCHAR PhysicalPath[DP_USB_METADATA_PATH_CHARS];
    UCHAR Metadata[DP_USB_METADATA_BYTES];
} DP_USB_METADATA_WRITE_MESSAGE, *PDP_USB_METADATA_WRITE_MESSAGE;

typedef struct _DP_USB_METADATA_WRITE_RESULT {
    ULONG Version;
    ULONG Status;
    ULONG PartitionCount;
    ULONG Reserved;
    ULONGLONG OffsetBytes;
    ULONGLONG DiskSizeBytes;
} DP_USB_METADATA_WRITE_RESULT, *PDP_USB_METADATA_WRITE_RESULT;

typedef enum _DP_NETWORK_RULE_KIND {
    DpNetworkRuleIp = 1,
    DpNetworkRuleDomain = 2
} DP_NETWORK_RULE_KIND;

typedef enum _DP_NETWORK_ACTION {
    DpNetworkActionAllow = 0,
    DpNetworkActionBlock = 1
} DP_NETWORK_ACTION;

typedef enum _DP_NETWORK_PROTOCOL {
    DpNetworkProtocolAny = 0,
    DpNetworkProtocolIcmp = 1,
    DpNetworkProtocolTcp = 6,
    DpNetworkProtocolUdp = 17
} DP_NETWORK_PROTOCOL;

typedef enum _DP_NETWORK_DIRECTION {
    DpNetworkDirectionInbound = 0,
    DpNetworkDirectionOutbound = 1,
    DpNetworkDirectionBoth = 2
} DP_NETWORK_DIRECTION;

typedef struct _DP_NETWORK_RULE_MESSAGE {
    ULONG Version;
    ULONG RuleId;
    ULONG Kind;
    ULONG Action;
    ULONG Protocol;
    ULONG Direction;
    ULONG LocalAddress;
    ULONG LocalAddressMask;
    ULONG RemoteAddress;
    ULONG RemoteAddressMask;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG DomainLengthBytes;
    WCHAR Domain[260];
} DP_NETWORK_RULE_MESSAGE, *PDP_NETWORK_RULE_MESSAGE;

typedef struct _DP_NETWORK_RULE_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_NETWORK_RULE_QUERY_HEADER, *PDP_NETWORK_RULE_QUERY_HEADER;

typedef struct _DP_NETWORK_RULE_QUERY_ENTRY {
    ULONG RuleId;
    ULONG Kind;
    ULONG Action;
    ULONG Protocol;
    ULONG Direction;
    ULONG LocalAddress;
    ULONG LocalAddressMask;
    ULONG RemoteAddress;
    ULONG RemoteAddressMask;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG DomainLengthBytes;
    WCHAR Domain[1];
} DP_NETWORK_RULE_QUERY_ENTRY, *PDP_NETWORK_RULE_QUERY_ENTRY;

#define DP_NETWORK_RULE_MESSAGE_VERSION 1
#define DP_NETWORK_RULE_QUERY_VERSION 1
#define DP_NETWORK_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_NETWORK_RULE_QUERY_ENTRY, Domain)

#define DP_NETWORK_EVENT_FLAG_DNS       0x00000001u
#define DP_NETWORK_EVENT_FLAG_QUIC      0x00000002u
#define DP_NETWORK_EVENT_FLAG_HTTP3     0x00000004u
#define DP_NETWORK_EVENT_FLAG_BLOCKED   0x00000008u

typedef struct _DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER, *PDP_NETWORK_CONNECTION_EVENT_QUERY_HEADER;

typedef struct _DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONG Direction;
    ULONG Protocol;
    ULONG LocalAddress;
    ULONG RemoteAddress;
    ULONG Flags;
    ULONG ProcessPathLengthBytes;
    ULONG DomainLengthBytes;
    ULONG Reserved;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG Reserved2;
    WCHAR ProcessPath[DP_NETWORK_EVENT_PROCESS_PATH_CHARS];
    WCHAR Domain[DP_NETWORK_EVENT_DOMAIN_CHARS];
} DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY, *PDP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY;

#define DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION 1

typedef struct _DP_SMTP_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_SMTP_EVENT_QUERY_HEADER, *PDP_SMTP_EVENT_QUERY_HEADER;

typedef struct _DP_SMTP_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONG LocalAddress;
    ULONG RemoteAddress;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG FromLengthBytes;
    ULONG ToLengthBytes;
    ULONG Reserved;
    WCHAR From[DP_SMTP_MAX_ADDRESS_CHARS];
    WCHAR To[DP_SMTP_MAX_ADDRESS_CHARS];
} DP_SMTP_EVENT_QUERY_ENTRY, *PDP_SMTP_EVENT_QUERY_ENTRY;

#define DP_SMTP_EVENT_QUERY_VERSION 1

typedef enum _DP_WEBSHELL_SEVERITY {
    DpWebShellSeverityNotify = 1,
    DpWebShellSeverityWarning = 2,
    DpWebShellSeverityDanger = 3
} DP_WEBSHELL_SEVERITY;

typedef enum _DP_WEBSHELL_OPERATION {
    DpWebShellOperationCreate = 1,
    DpWebShellOperationWrite = 2,
    DpWebShellOperationRename = 3,
    DpWebShellOperationCleanup = 4
} DP_WEBSHELL_OPERATION;

typedef struct _DP_WEBSHELL_RULE_MESSAGE {
    ULONG Version;
    ULONG DirectoryLengthBytes;
    WCHAR Directory[512];
} DP_WEBSHELL_RULE_MESSAGE, *PDP_WEBSHELL_RULE_MESSAGE;

typedef struct _DP_WEBSHELL_RULE_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_WEBSHELL_RULE_QUERY_HEADER, *PDP_WEBSHELL_RULE_QUERY_HEADER;

typedef struct _DP_WEBSHELL_RULE_QUERY_ENTRY {
    ULONG DirectoryLengthBytes;
    WCHAR Directory[1];
} DP_WEBSHELL_RULE_QUERY_ENTRY, *PDP_WEBSHELL_RULE_QUERY_ENTRY;

typedef struct _DP_WEBSHELL_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_WEBSHELL_EVENT_QUERY_HEADER, *PDP_WEBSHELL_EVENT_QUERY_HEADER;

typedef struct _DP_WEBSHELL_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONG Severity;
    ULONG Operation;
    ULONG FileSize;
    ULONG SampleLength;
    ULONG PathLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Path[DP_WEBSHELL_EVENT_PATH_CHARS];
    WCHAR Extension[DP_WEBSHELL_EVENT_EXTENSION_CHARS];
    CHAR Sample[DP_WEBSHELL_MAX_SAMPLE_BYTES];
} DP_WEBSHELL_EVENT_QUERY_ENTRY, *PDP_WEBSHELL_EVENT_QUERY_ENTRY;

#define DP_WEBSHELL_RULE_MESSAGE_VERSION 1
#define DP_WEBSHELL_RULE_QUERY_VERSION 1
#define DP_WEBSHELL_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_WEBSHELL_RULE_QUERY_ENTRY, Directory)
#define DP_WEBSHELL_EVENT_QUERY_VERSION 1

typedef struct _DP_FILE_HUNTER_RULE_MESSAGE {
    ULONG Version;
    ULONG DirectoryLengthBytes;
    WCHAR Directory[512];
} DP_FILE_HUNTER_RULE_MESSAGE, *PDP_FILE_HUNTER_RULE_MESSAGE;

typedef struct _DP_FILE_HUNTER_RULE_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_FILE_HUNTER_RULE_QUERY_HEADER, *PDP_FILE_HUNTER_RULE_QUERY_HEADER;

typedef struct _DP_FILE_HUNTER_RULE_QUERY_ENTRY {
    ULONG DirectoryLengthBytes;
    WCHAR Directory[1];
} DP_FILE_HUNTER_RULE_QUERY_ENTRY, *PDP_FILE_HUNTER_RULE_QUERY_ENTRY;

typedef struct _DP_FILE_HUNTER_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_FILE_HUNTER_EVENT_QUERY_HEADER, *PDP_FILE_HUNTER_EVENT_QUERY_HEADER;

typedef struct _DP_FILE_HUNTER_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONGLONG BytesRead;
    ULONGLONG ByteOffset;
    ULONG Status;
    ULONG Flags;
    ULONG PathLengthBytes;
    ULONG ProcessImageLengthBytes;
    WCHAR Path[DP_FILE_HUNTER_PATH_CHARS];
    WCHAR ProcessImage[DP_FILE_HUNTER_PROCESS_CHARS];
} DP_FILE_HUNTER_EVENT_QUERY_ENTRY, *PDP_FILE_HUNTER_EVENT_QUERY_ENTRY;

#define DP_FILE_HUNTER_RULE_MESSAGE_VERSION 1
#define DP_FILE_HUNTER_RULE_QUERY_VERSION 1
#define DP_FILE_HUNTER_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_FILE_HUNTER_RULE_QUERY_ENTRY, Directory)
#define DP_FILE_HUNTER_EVENT_QUERY_VERSION 1
#define DP_FILE_HUNTER_READ_FLAG_PAGING_IO 0x00000001u
#define DP_FILE_HUNTER_READ_FLAG_CREATE_OPEN 0x00000002u
#define DP_FILE_HUNTER_READ_FLAG_SECTION_MAP 0x00000004u
#define DP_FILE_HUNTER_READ_FLAG_IMAGE_SECTION 0x00000008u
#define DP_FILE_HUNTER_READ_FLAG_EXECUTE_ACCESS 0x00000010u

typedef struct _DP_DEVICE_RULE_MESSAGE {
    ULONG Version;
    ULONG AllowInsert;
    ULONG AllowWrite;
    ULONG DeviceIdLengthBytes;
    WCHAR DeviceId[DP_DEVICE_MAX_ID_CHARS];
} DP_DEVICE_RULE_MESSAGE, *PDP_DEVICE_RULE_MESSAGE;

typedef struct _DP_DEVICE_RULE_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_DEVICE_RULE_QUERY_HEADER, *PDP_DEVICE_RULE_QUERY_HEADER;

typedef struct _DP_DEVICE_RULE_QUERY_ENTRY {
    ULONG AllowInsert;
    ULONG AllowWrite;
    ULONG DeviceIdLengthBytes;
    WCHAR DeviceId[1];
} DP_DEVICE_RULE_QUERY_ENTRY, *PDP_DEVICE_RULE_QUERY_ENTRY;

#define DP_DEVICE_RULE_MESSAGE_VERSION 1
#define DP_DEVICE_RULE_QUERY_VERSION 1
#define DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_DEVICE_RULE_QUERY_ENTRY, DeviceId)

typedef enum _DP_HASH_PROTECT_OPERATION {
    DpHashProtectOperationLsassHandle = 1,
    DpHashProtectOperationCredentialFile = 2,
    DpHashProtectOperationRegistryHive = 3,
    DpHashProtectOperationRawExtent = 4
} DP_HASH_PROTECT_OPERATION;

#define DP_HASH_PROTECT_POLICY_VERSION 1
#define DP_HASH_PROTECT_FLAG_ENABLED          0x00000001
#define DP_HASH_PROTECT_FLAG_LSASS_HANDLES    0x00000002
#define DP_HASH_PROTECT_FLAG_CREDENTIAL_FILES 0x00000004
#define DP_HASH_PROTECT_FLAG_REGISTRY_HIVES   0x00000008
#define DP_HASH_PROTECT_FLAG_RAW_EXTENTS      0x00000010
#define DP_HASH_PROTECT_DEFAULT_FLAGS \
    (DP_HASH_PROTECT_FLAG_ENABLED | \
     DP_HASH_PROTECT_FLAG_LSASS_HANDLES | \
     DP_HASH_PROTECT_FLAG_CREDENTIAL_FILES | \
     DP_HASH_PROTECT_FLAG_REGISTRY_HIVES | \
     DP_HASH_PROTECT_FLAG_RAW_EXTENTS)
#define DP_HASH_PROTECT_ALLOWED_FLAGS DP_HASH_PROTECT_DEFAULT_FLAGS

typedef struct _DP_HASH_PROTECT_POLICY {
    ULONG Version;
    ULONG Flags;
} DP_HASH_PROTECT_POLICY, *PDP_HASH_PROTECT_POLICY;

typedef struct _DP_HASH_PROTECT_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_HASH_PROTECT_EVENT_QUERY_HEADER, *PDP_HASH_PROTECT_EVENT_QUERY_HEADER;

typedef struct _DP_HASH_PROTECT_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONG Operation;
    ULONG Status;
    ULONG DesiredAccess;
    ULONG TargetLengthBytes;
    ULONG ProcessImageLengthBytes;
    WCHAR Target[DP_HASH_PROTECT_TARGET_CHARS];
    WCHAR ProcessImage[DP_HASH_PROTECT_PROCESS_CHARS];
} DP_HASH_PROTECT_EVENT_QUERY_ENTRY, *PDP_HASH_PROTECT_EVENT_QUERY_ENTRY;

#define DP_HASH_PROTECT_EVENT_QUERY_VERSION 1

typedef enum _DP_LATERAL_DEFENSE_OPERATION {
    DpLateralDefenseOperationSmbExecutableCreate = 1,
    DpLateralDefenseOperationSmbExecutableWrite = 2,
    DpLateralDefenseOperationSmbExecutableRename = 3,
    DpLateralDefenseOperationIpcTaskScheduler = 4,
    DpLateralDefenseOperationIpcServiceControl = 5,
    DpLateralDefenseOperationRemoteScheduledTaskTool = 6,
    DpLateralDefenseOperationRemoteServiceTool = 7,
    DpLateralDefenseOperationWmiProcessCreate = 8,
    DpLateralDefenseOperationPowerShellRemoteTask = 9
} DP_LATERAL_DEFENSE_OPERATION;

#define DP_LATERAL_DEFENSE_POLICY_VERSION 1
#define DP_LATERAL_DEFENSE_FLAG_ENABLED            0x00000001
#define DP_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES    0x00000002
#define DP_LATERAL_DEFENSE_FLAG_IPC_TASKS          0x00000004
#define DP_LATERAL_DEFENSE_FLAG_IPC_SERVICES       0x00000008
#define DP_LATERAL_DEFENSE_FLAG_PROCESS_TOOLS      0x00000010
#define DP_LATERAL_DEFENSE_DEFAULT_FLAGS \
    (DP_LATERAL_DEFENSE_FLAG_ENABLED | \
     DP_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES | \
     DP_LATERAL_DEFENSE_FLAG_IPC_TASKS | \
     DP_LATERAL_DEFENSE_FLAG_IPC_SERVICES | \
     DP_LATERAL_DEFENSE_FLAG_PROCESS_TOOLS)
#define DP_LATERAL_DEFENSE_ALLOWED_FLAGS DP_LATERAL_DEFENSE_DEFAULT_FLAGS

typedef struct _DP_LATERAL_DEFENSE_POLICY {
    ULONG Version;
    ULONG Flags;
} DP_LATERAL_DEFENSE_POLICY, *PDP_LATERAL_DEFENSE_POLICY;

typedef struct _DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER, *PDP_LATERAL_DEFENSE_EVENT_QUERY_HEADER;

typedef struct _DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONG Operation;
    ULONG Status;
    ULONG DesiredAccess;
    ULONG Flags;
    ULONG TargetLengthBytes;
    ULONG ProcessImageLengthBytes;
    WCHAR Target[DP_LATERAL_DEFENSE_TARGET_CHARS];
    WCHAR ProcessImage[DP_LATERAL_DEFENSE_PROCESS_CHARS];
} DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY, *PDP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY;

#define DP_LATERAL_DEFENSE_EVENT_QUERY_VERSION 1

typedef enum _DP_USER_HOOK_DEFENSE_OPERATION {
    DpUserHookDefenseOperationProcessCreate = 1,
    DpUserHookDefenseOperationHookSurfaceImageLoad = 2,
    DpUserHookDefenseOperationRuntimeRequired = 3,
    DpUserHookDefenseOperationRuntimeMissing = 4,
    DpUserHookDefenseOperationRuntimeRejected = 5,
    DpUserHookDefenseOperationSuspiciousHookAttempt = 6,
    DpUserHookDefenseOperationRuntimeInjectionRequired = 7,
    DpUserHookDefenseOperationRuntimeInjectionQueued = 8,
    DpUserHookDefenseOperationRuntimeInjectionFailed = 9,
    DpUserHookDefenseOperationRuntimeInjectionSkipped = 10,
    DpUserHookDefenseOperationBehaviorProcessAccess = 11,
    DpUserHookDefenseOperationBehaviorThreadAccess = 12,
    DpUserHookDefenseOperationSensitiveImageReload = 13,
    DpUserHookDefenseOperationSensitiveImageAbnormalPath = 14,
    DpUserHookDefenseOperationBehaviorRemoteThreadCreate = 15
} DP_USER_HOOK_DEFENSE_OPERATION;

#define DP_USER_HOOK_DEFENSE_POLICY_VERSION 4
#define DP_USER_HOOK_DEFENSE_FLAG_ENABLED                 0x00000001
#define DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION 0x00000002
#define DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_MONITOR   DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION
#define DP_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR      0x00000004
#define DP_USER_HOOK_DEFENSE_FLAG_REQUIRE_SIGNED_RUNTIME  0x00000008
#define DP_USER_HOOK_DEFENSE_FLAG_BLOCK_UNTRUSTED_RUNTIME 0x00000010
#define DP_USER_HOOK_DEFENSE_FLAG_AUDIT_ONLY              0x00000020
#define DP_USER_HOOK_DEFENSE_FLAG_MONITOR_SYSTEM_PROCESSES 0x00000040
#define DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_API_BEHAVIOR    0x00000080
#define DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_MEMORY_SCAN     0x00000100
#define DP_USER_HOOK_DEFENSE_FLAG_ETW_TAMPER_MONITOR      0x00000200
#define DP_USER_HOOK_DEFENSE_DEFAULT_FLAGS \
    (DP_USER_HOOK_DEFENSE_FLAG_ENABLED | \
     DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION | \
     DP_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR | \
     DP_USER_HOOK_DEFENSE_FLAG_REQUIRE_SIGNED_RUNTIME | \
     DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_API_BEHAVIOR | \
     DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_MEMORY_SCAN | \
     DP_USER_HOOK_DEFENSE_FLAG_ETW_TAMPER_MONITOR | \
     DP_USER_HOOK_DEFENSE_FLAG_AUDIT_ONLY)
#define DP_USER_HOOK_DEFENSE_DEFAULT_RUNTIME_DLL_PATH \
    L"C:\\ProgramData\\DataProtector\\Runtime\\DataProtectorUserHookRuntime.dll"
#define DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS \
    (DP_USER_HOOK_DEFENSE_FLAG_ENABLED | \
     DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_MONITOR | \
     DP_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR | \
     DP_USER_HOOK_DEFENSE_FLAG_REQUIRE_SIGNED_RUNTIME | \
     DP_USER_HOOK_DEFENSE_FLAG_BLOCK_UNTRUSTED_RUNTIME | \
     DP_USER_HOOK_DEFENSE_FLAG_AUDIT_ONLY | \
     DP_USER_HOOK_DEFENSE_FLAG_MONITOR_SYSTEM_PROCESSES | \
     DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_API_BEHAVIOR | \
     DP_USER_HOOK_DEFENSE_FLAG_RUNTIME_MEMORY_SCAN | \
     DP_USER_HOOK_DEFENSE_FLAG_ETW_TAMPER_MONITOR)

typedef struct _DP_USER_HOOK_DEFENSE_POLICY {
    ULONG Version;
    ULONG Flags;
    ULONG ExcludedProcessNamesLengthBytes;
    ULONG ExcludedProcessDirectoriesLengthBytes;
    ULONG ExcludedProcessPathsLengthBytes;
    ULONG TrustedSignerSubjectsLengthBytes;
    ULONG RuntimeDllPathLengthBytes;
    WCHAR ExcludedProcessNames[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
    WCHAR ExcludedProcessDirectories[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
    WCHAR ExcludedProcessPaths[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
    WCHAR TrustedSignerSubjects[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
    WCHAR RuntimeDllPath[DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS];
} DP_USER_HOOK_DEFENSE_POLICY, *PDP_USER_HOOK_DEFENSE_POLICY;

typedef struct _DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER, *PDP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER;

typedef struct _DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONG Operation;
    ULONG Status;
    ULONG Flags;
    ULONG TargetLengthBytes;
    ULONG ProcessImageLengthBytes;
    WCHAR Target[DP_USER_HOOK_DEFENSE_TARGET_CHARS];
    WCHAR ProcessImage[DP_USER_HOOK_DEFENSE_PROCESS_CHARS];
} DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY, *PDP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY;

#define DP_USER_HOOK_DEFENSE_EVENT_QUERY_VERSION 1

//
// ---------------------------------------------------------------------------
// DataProtector Threat Engine
//
// The threat engine is the cross-module correlation and graduated-response
// brain of the EDR. The individual sensors (process policy, user-hook defense,
// credential-hash protection, lateral-movement defense, network filter,
// web-shell hardening, and file hunter) report normalized behavioral signals.
// The engine maintains a per-process risk model with ancestry-aware score
// propagation, maps each signal to a MITRE ATT&CK technique, applies time
// decay, and orchestrates a graduated automated response as the cumulative
// score crosses configured thresholds.
// ---------------------------------------------------------------------------
//

//
// Normalized behavioral signal identifiers. Each maps to a default weight and
// MITRE ATT&CK technique inside the engine. Sensors stay decoupled from scoring
// policy: they report what they observed, the engine decides what it means.
//
typedef enum _DP_THREAT_SIGNAL {
    DpThreatSignalNone = 0,

    // Execution / process lineage (TA0002, TA0004)
    DpThreatSignalProcessCreated = 1,
    DpThreatSignalSuspiciousParentChild = 2,
    DpThreatSignalLolbinExecuted = 3,
    DpThreatSignalScriptInterpreterSpawned = 4,
    DpThreatSignalOfficeSpawnedChild = 5,

    // Credential access (TA0006)
    DpThreatSignalLsassHandleAccess = 10,
    DpThreatSignalCredentialFileAccess = 11,
    DpThreatSignalRegistryHiveAccess = 12,
    DpThreatSignalRawDiskAccess = 13,

    // Defense evasion / injection / tampering (TA0005)
    DpThreatSignalRemoteThreadInjection = 20,
    DpThreatSignalProcessHandleManipulation = 21,
    DpThreatSignalSuspiciousImageLoad = 22,
    DpThreatSignalEtwTamper = 23,
    DpThreatSignalUnsignedRuntimeRejected = 24,
    DpThreatSignalSecurityToolTamper = 25,

    // Lateral movement (TA0008)
    DpThreatSignalRemoteServiceTool = 30,
    DpThreatSignalRemoteScheduledTask = 31,
    DpThreatSignalRemoteWmiExecution = 32,
    DpThreatSignalRemotePowerShell = 33,
    DpThreatSignalSmbExecutableStaging = 34,
    DpThreatSignalRemoteIpcControl = 35,

    // Command and control / exfiltration (TA0011, TA0010)
    DpThreatSignalBlockedC2Connection = 40,
    DpThreatSignalSuspiciousDnsBeacon = 41,
    DpThreatSignalSmtpExfiltration = 42,

    // Impact / persistence (TA0040, TA0003)
    DpThreatSignalWebShellDropped = 50,
    DpThreatSignalRansomwareMassFileAccess = 51,
    DpThreatSignalSensitiveDataHarvest = 52,
    DpThreatSignalRemovableMediaStaging = 53,

    // Malicious payload on disk (TA0002 / TA0005) - static scanner verdicts
    DpThreatSignalMaliciousExecutableWrite = 60,
    DpThreatSignalSuspiciousExecutableWrite = 61,
    DpThreatSignalPackedExecutableWrite = 62,

    DpThreatSignalMax
} DP_THREAT_SIGNAL;

//
// MITRE ATT&CK tactic identifiers surfaced with each event so the console can
// render an attack storyline.
//
typedef enum _DP_THREAT_TACTIC {
    DpThreatTacticUnknown = 0,
    DpThreatTacticExecution = 1,          // TA0002
    DpThreatTacticPersistence = 2,        // TA0003
    DpThreatTacticPrivilegeEscalation = 3,// TA0004
    DpThreatTacticDefenseEvasion = 4,     // TA0005
    DpThreatTacticCredentialAccess = 5,   // TA0006
    DpThreatTacticDiscovery = 6,          // TA0007
    DpThreatTacticLateralMovement = 7,    // TA0008
    DpThreatTacticCollection = 8,         // TA0009
    DpThreatTacticExfiltration = 9,       // TA0010
    DpThreatTacticCommandAndControl = 10, // TA0011
    DpThreatTacticImpact = 11             // TA0040
} DP_THREAT_TACTIC;

//
// Threat severity bands derived from cumulative process score.
//
typedef enum _DP_THREAT_SEVERITY {
    DpThreatSeverityInformational = 0,
    DpThreatSeverityLow = 1,
    DpThreatSeverityMedium = 2,
    DpThreatSeverityHigh = 3,
    DpThreatSeverityCritical = 4
} DP_THREAT_SEVERITY;

//
// Graduated automated response actions. The engine selects the strongest
// action permitted by policy once a score threshold is crossed.
//
typedef enum _DP_THREAT_RESPONSE_ACTION {
    DpThreatResponseNone = 0,
    DpThreatResponseAudit = 1,        // record only
    DpThreatResponseAlert = 2,        // raise a high-visibility alert
    DpThreatResponseBlock = 3,        // deny the offending operation
    DpThreatResponseIsolateNetwork = 4, // cut the process/host network egress
    DpThreatResponseTerminate = 5     // terminate the offending process tree
} DP_THREAT_RESPONSE_ACTION;

//
// Default per-signal score thresholds that drive graduated response. Scores are
// fixed-point integers (1 point == 1 unit). These are conservative defaults so
// a single benign signal never escalates on its own; correlation across
// signals and ancestry is what produces a high score.
//
#define DP_THREAT_SCORE_THRESHOLD_LOW       30
#define DP_THREAT_SCORE_THRESHOLD_MEDIUM    60
#define DP_THREAT_SCORE_THRESHOLD_HIGH      90
#define DP_THREAT_SCORE_THRESHOLD_CRITICAL  130
#define DP_THREAT_SCORE_MAX                 1000

//
// Score decay: a process loses this many points per decay interval of quiet so
// long-lived benign processes do not accumulate score indefinitely.
//
#define DP_THREAT_DECAY_INTERVAL_100NS  (60ll * 1000ll * 1000ll * 10ll) // 60s
#define DP_THREAT_DECAY_POINTS          5

//
// Fraction (percent) of a child's earned signal score contributed back to its
// parent, so an attack storyline accumulates on the lineage root.
//
#define DP_THREAT_ANCESTRY_PROPAGATION_PCT  50
#define DP_THREAT_ANCESTRY_MAX_DEPTH        8

//
// Engine policy flags.
//
#define DP_THREAT_ENGINE_FLAG_ENABLED              0x00000001
#define DP_THREAT_ENGINE_FLAG_CORRELATION          0x00000002
#define DP_THREAT_ENGINE_FLAG_ANCESTRY_PROPAGATION 0x00000004
#define DP_THREAT_ENGINE_FLAG_AUTO_BLOCK           0x00000008
#define DP_THREAT_ENGINE_FLAG_AUTO_ISOLATE         0x00000010
#define DP_THREAT_ENGINE_FLAG_AUTO_TERMINATE       0x00000020
#define DP_THREAT_ENGINE_FLAG_AUDIT_ONLY           0x00000040

#define DP_THREAT_ENGINE_DEFAULT_FLAGS \
    (DP_THREAT_ENGINE_FLAG_ENABLED | \
     DP_THREAT_ENGINE_FLAG_CORRELATION | \
     DP_THREAT_ENGINE_FLAG_ANCESTRY_PROPAGATION | \
     DP_THREAT_ENGINE_FLAG_AUTO_BLOCK | \
     DP_THREAT_ENGINE_FLAG_AUTO_ISOLATE)

#define DP_THREAT_ENGINE_ALLOWED_FLAGS \
    (DP_THREAT_ENGINE_FLAG_ENABLED | \
     DP_THREAT_ENGINE_FLAG_CORRELATION | \
     DP_THREAT_ENGINE_FLAG_ANCESTRY_PROPAGATION | \
     DP_THREAT_ENGINE_FLAG_AUTO_BLOCK | \
     DP_THREAT_ENGINE_FLAG_AUTO_ISOLATE | \
     DP_THREAT_ENGINE_FLAG_AUTO_TERMINATE | \
     DP_THREAT_ENGINE_FLAG_AUDIT_ONLY)

#define DP_THREAT_ENGINE_POLICY_VERSION 1

typedef struct _DP_THREAT_ENGINE_POLICY {
    ULONG Version;
    ULONG Flags;
    ULONG BlockThreshold;     // score that arms block response (0 = default)
    ULONG IsolateThreshold;   // score that arms network isolation (0 = default)
    ULONG TerminateThreshold; // score that arms termination (0 = default)
    ULONG Reserved;
} DP_THREAT_ENGINE_POLICY, *PDP_THREAT_ENGINE_POLICY;

//
// A single behavioral detection event, queued for the console. Each carries
// the originating process, its lineage root, the normalized signal, mapped
// ATT&CK tactic, the score delta and resulting cumulative score, the chosen
// response, and a human-readable detail string.
//
typedef struct _DP_THREAT_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG TimeStamp;       // KeQuerySystemTime 100ns
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONGLONG LineageRootPid;
    ULONG Signal;              // DP_THREAT_SIGNAL
    ULONG Tactic;              // DP_THREAT_TACTIC
    ULONG TechniqueId;         // numeric ATT&CK technique (e.g. 1003 for T1003)
    ULONG ScoreDelta;
    ULONG CumulativeScore;
    ULONG Severity;            // DP_THREAT_SEVERITY
    ULONG ResponseAction;      // DP_THREAT_RESPONSE_ACTION
    ULONG ResponseStatus;      // NTSTATUS of the response attempt
    ULONG ProcessImageLengthBytes;
    ULONG DetailLengthBytes;
    WCHAR ProcessImage[DP_THREAT_PROCESS_CHARS];
    WCHAR Detail[DP_THREAT_DETAIL_CHARS];
} DP_THREAT_EVENT_QUERY_ENTRY, *PDP_THREAT_EVENT_QUERY_ENTRY;

typedef struct _DP_THREAT_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_THREAT_EVENT_QUERY_HEADER, *PDP_THREAT_EVENT_QUERY_HEADER;

#define DP_THREAT_EVENT_QUERY_VERSION 1

//
// A per-process risk summary, used by the console to render the live
// "processes at risk" board.
//
typedef struct _DP_THREAT_PROCESS_QUERY_ENTRY {
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONGLONG LineageRootPid;
    ULONGLONG FirstSeen;
    ULONGLONG LastActivity;
    ULONG CumulativeScore;
    ULONG Severity;            // DP_THREAT_SEVERITY
    ULONG SignalCount;
    ULONG DistinctTacticMask;  // bitmask of observed DP_THREAT_TACTIC values
    ULONG StrongestResponse;   // DP_THREAT_RESPONSE_ACTION applied so far
    ULONG Flags;
    ULONG ProcessImageLengthBytes;
    WCHAR ProcessImage[DP_THREAT_PROCESS_CHARS];
} DP_THREAT_PROCESS_QUERY_ENTRY, *PDP_THREAT_PROCESS_QUERY_ENTRY;

typedef struct _DP_THREAT_PROCESS_QUERY_HEADER {
    ULONG Version;
    ULONG ProcessCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_THREAT_PROCESS_QUERY_HEADER, *PDP_THREAT_PROCESS_QUERY_HEADER;

#define DP_THREAT_PROCESS_QUERY_VERSION 1

//
// Manual response request issued from the console for a chosen process.
//
typedef struct _DP_THREAT_RESPONSE_REQUEST {
    ULONG Version;
    ULONG Action;              // DP_THREAT_RESPONSE_ACTION
    ULONGLONG ProcessId;
} DP_THREAT_RESPONSE_REQUEST, *PDP_THREAT_RESPONSE_REQUEST;

#define DP_THREAT_RESPONSE_REQUEST_VERSION 1

//
// Attack storyline. When a process lineage crosses the incident threshold the
// engine snapshots its complete, time-ordered chain of behavioral steps so the
// console can render the full attack flow (CrowdStrike-style process tree /
// incident graph). One storyline summarizes one lineage root.
//
typedef struct _DP_THREAT_STORY_STEP {
    ULONGLONG TimeStamp;       // 100ns
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONG Signal;              // DP_THREAT_SIGNAL
    ULONG Tactic;              // DP_THREAT_TACTIC
    ULONG TechniqueId;         // numeric ATT&CK technique
    ULONG ScoreDelta;
    ULONG CumulativeScore;     // lineage score after this step
    ULONG ResponseAction;      // DP_THREAT_RESPONSE_ACTION at this step
    ULONG DetailLengthBytes;
    WCHAR Detail[DP_THREAT_STORY_DETAIL_CHARS];
} DP_THREAT_STORY_STEP, *PDP_THREAT_STORY_STEP;

typedef struct _DP_THREAT_STORY_QUERY_ENTRY {
    ULONGLONG IncidentId;
    ULONGLONG LineageRootPid;
    ULONGLONG OriginProcessId; // process that tripped the incident threshold
    ULONGLONG FirstSeen;
    ULONGLONG LastActivity;
    ULONG PeakScore;
    ULONG Severity;            // DP_THREAT_SEVERITY at peak
    ULONG TacticMask;          // union of tactics across the lineage
    ULONG StrongestResponse;   // DP_THREAT_RESPONSE_ACTION
    ULONG StepCount;           // valid entries in Steps
    ULONG TotalStepsObserved;  // including steps dropped past the cap
    ULONG RootImageLengthBytes;
    ULONG OriginImageLengthBytes;
    WCHAR RootImage[DP_THREAT_PROCESS_CHARS];
    WCHAR OriginImage[DP_THREAT_PROCESS_CHARS];
    DP_THREAT_STORY_STEP Steps[DP_THREAT_STORY_MAX_STEPS];
} DP_THREAT_STORY_QUERY_ENTRY, *PDP_THREAT_STORY_QUERY_ENTRY;

typedef struct _DP_THREAT_STORY_QUERY_HEADER {
    ULONG Version;
    ULONG StorylineCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedStorylines;
} DP_THREAT_STORY_QUERY_HEADER, *PDP_THREAT_STORY_QUERY_HEADER;

#define DP_THREAT_STORY_QUERY_VERSION 1

//
// ---------------------------------------------------------------------------
// Executable static scanner (kernel = thin detector/notifier).
//
// CORE RULE: the kernel does NOT classify. On exe create / rename-to-exe /
// write-cleanup it captures metadata {seq, pid, op, size, path, image} into a
// scan-REQUEST ring. A signed user-mode service drains the requests over the
// policy port, scans with updatable engines (YARA, hash reputation, heuristics,
// ML/cloud), and submits a VERDICT back. The kernel records the verdict event,
// reports it to the threat engine, and enforces quarantine (truncation) when
// policy requires blocking. Detection content stays fully in user mode so it is
// updatable without reloading a signed driver.
// ---------------------------------------------------------------------------
//

typedef enum _DP_STATIC_SCAN_VERDICT {
    DpStaticScanVerdictClean = 0,
    DpStaticScanVerdictLowRisk = 1,
    DpStaticScanVerdictSuspicious = 2,
    DpStaticScanVerdictMalicious = 3
} DP_STATIC_SCAN_VERDICT;

typedef enum _DP_STATIC_SCAN_OPERATION {
    DpStaticScanOperationCreate = 1,
    DpStaticScanOperationWrite = 2,
    DpStaticScanOperationRename = 3,
    DpStaticScanOperationCleanup = 4
} DP_STATIC_SCAN_OPERATION;

//
// Verdict reason bit flags. Produced by the user-mode engine and surfaced with
// each recorded event. The kernel treats these as opaque pass-through bits.
//
#define DP_STATIC_SCAN_REASON_VALID_PE          0x00000001u
#define DP_STATIC_SCAN_REASON_HIGH_ENTROPY      0x00000002u
#define DP_STATIC_SCAN_REASON_PACKER_SECTION    0x00000004u
#define DP_STATIC_SCAN_REASON_SUSPICIOUS_IMPORT 0x00000008u
#define DP_STATIC_SCAN_REASON_SUSPICIOUS_STRING 0x00000010u
#define DP_STATIC_SCAN_REASON_NO_IMPORTS        0x00000020u
#define DP_STATIC_SCAN_REASON_WX_SECTION        0x00000040u
#define DP_STATIC_SCAN_REASON_TINY_IMAGE        0x00000080u
#define DP_STATIC_SCAN_REASON_SCRIPT_DROPPER    0x00000100u
#define DP_STATIC_SCAN_REASON_DOTNET_PACKED     0x00000200u
#define DP_STATIC_SCAN_REASON_OVERLAY           0x00000400u
#define DP_STATIC_SCAN_REASON_YARA_MATCH        0x00000800u
#define DP_STATIC_SCAN_REASON_HASH_REPUTATION   0x00001000u
#define DP_STATIC_SCAN_REASON_TRUSTED_SIGNER    0x00002000u  // valid Authenticode; kernel must not quarantine

#define DP_STATIC_SCAN_POLICY_VERSION 1
#define DP_STATIC_SCAN_FLAG_ENABLED          0x00000001u
#define DP_STATIC_SCAN_FLAG_SCAN_PE          0x00000002u
#define DP_STATIC_SCAN_FLAG_SCAN_SCRIPTS     0x00000004u
#define DP_STATIC_SCAN_FLAG_BLOCK_MALICIOUS  0x00000008u
#define DP_STATIC_SCAN_FLAG_BLOCK_SUSPICIOUS 0x00000010u
#define DP_STATIC_SCAN_FLAG_AUDIT_ONLY       0x00000020u

#define DP_STATIC_SCAN_DEFAULT_FLAGS \
    (DP_STATIC_SCAN_FLAG_ENABLED | \
     DP_STATIC_SCAN_FLAG_SCAN_PE | \
     DP_STATIC_SCAN_FLAG_SCAN_SCRIPTS | \
     DP_STATIC_SCAN_FLAG_BLOCK_MALICIOUS)

#define DP_STATIC_SCAN_ALLOWED_FLAGS \
    (DP_STATIC_SCAN_FLAG_ENABLED | \
     DP_STATIC_SCAN_FLAG_SCAN_PE | \
     DP_STATIC_SCAN_FLAG_SCAN_SCRIPTS | \
     DP_STATIC_SCAN_FLAG_BLOCK_MALICIOUS | \
     DP_STATIC_SCAN_FLAG_BLOCK_SUSPICIOUS | \
     DP_STATIC_SCAN_FLAG_AUDIT_ONLY)

typedef struct _DP_STATIC_SCAN_POLICY {
    ULONG Version;
    ULONG Flags;
    ULONG MaliciousThreshold; // advisory; user mode owns scoring (0 = default)
    ULONG SuspiciousThreshold;// advisory; user mode owns scoring (0 = default)
} DP_STATIC_SCAN_POLICY, *PDP_STATIC_SCAN_POLICY;

//
// Scan REQUEST: kernel -> user mode. The kernel enqueues one per detected
// executable write and the user-mode service drains them. No file content is
// captured in the kernel; the service opens and reads the file itself.
//
typedef struct _DP_STATIC_SCAN_REQUEST_QUERY_HEADER {
    ULONG Version;
    ULONG RequestCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedRequests;
} DP_STATIC_SCAN_REQUEST_QUERY_HEADER, *PDP_STATIC_SCAN_REQUEST_QUERY_HEADER;

typedef struct _DP_STATIC_SCAN_REQUEST_QUERY_ENTRY {
    ULONGLONG RequestId;       // monotonic; echoed back in the verdict
    ULONGLONG TimeStamp;
    ULONGLONG ProcessId;
    ULONGLONG FileSize;
    ULONG Operation;           // DP_STATIC_SCAN_OPERATION
    ULONG PathLengthBytes;
    ULONG ProcessImageLengthBytes;
    ULONG Reserved;
    WCHAR Path[DP_STATIC_SCAN_PATH_CHARS];
    WCHAR ProcessImage[DP_STATIC_SCAN_PROCESS_CHARS];
} DP_STATIC_SCAN_REQUEST_QUERY_ENTRY, *PDP_STATIC_SCAN_REQUEST_QUERY_ENTRY;

#define DP_STATIC_SCAN_REQUEST_QUERY_VERSION 1

//
// Scan VERDICT: user mode -> kernel. The service submits the engine result for
// a given RequestId. The kernel records the event, reports to the threat
// engine, and (if policy says block and the file still resolves) quarantines.
//
typedef struct _DP_STATIC_SCAN_VERDICT_MESSAGE {
    ULONG Version;
    ULONG Verdict;             // DP_STATIC_SCAN_VERDICT
    ULONG Score;               // 0..100, engine-assigned
    ULONG ReasonFlags;
    ULONGLONG RequestId;       // correlates to the drained request
    ULONGLONG ProcessId;
    ULONGLONG FileSize;
    ULONG Operation;           // DP_STATIC_SCAN_OPERATION
    ULONG PathLengthBytes;
    ULONG ReasonTextLengthBytes;
    ULONG Reserved;
    WCHAR Path[DP_STATIC_SCAN_PATH_CHARS];
    WCHAR ReasonText[DP_STATIC_SCAN_REASON_CHARS];
} DP_STATIC_SCAN_VERDICT_MESSAGE, *PDP_STATIC_SCAN_VERDICT_MESSAGE;

#define DP_STATIC_SCAN_VERDICT_MESSAGE_VERSION 1

typedef struct _DP_STATIC_SCAN_EVENT_QUERY_HEADER {
    ULONG Version;
    ULONG EventCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
    ULONGLONG DroppedEvents;
} DP_STATIC_SCAN_EVENT_QUERY_HEADER, *PDP_STATIC_SCAN_EVENT_QUERY_HEADER;

typedef struct _DP_STATIC_SCAN_EVENT_QUERY_ENTRY {
    ULONGLONG Sequence;
    ULONGLONG TimeStamp;
    ULONGLONG ProcessId;
    ULONGLONG FileSize;
    ULONG Verdict;             // DP_STATIC_SCAN_VERDICT
    ULONG Operation;           // DP_STATIC_SCAN_OPERATION
    ULONG Score;
    ULONG ReasonFlags;
    ULONG Status;              // NTSTATUS of resulting action (block/allow)
    ULONG Blocked;
    ULONG PathLengthBytes;
    ULONG ProcessImageLengthBytes;
    ULONG ReasonTextLengthBytes;
    WCHAR Path[DP_STATIC_SCAN_PATH_CHARS];
    WCHAR ProcessImage[DP_STATIC_SCAN_PROCESS_CHARS];
    WCHAR ReasonText[DP_STATIC_SCAN_REASON_CHARS];
} DP_STATIC_SCAN_EVENT_QUERY_ENTRY, *PDP_STATIC_SCAN_EVENT_QUERY_ENTRY;

#define DP_STATIC_SCAN_EVENT_QUERY_VERSION 1

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DataProtectorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
DataProtectorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
DataProtectorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
DataProtectorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
DataProtectorUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
DpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
DpPreFastIoCheckIfPossible(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
DpProcessPolicyIsTrusted(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING FileName
    );

BOOLEAN
DpProcessPolicyNameHasProtectedExtension(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpProcessPolicyNameIsExcluded(
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpProcessPolicyInitialize(
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
DpProcessPolicyUninitialize(
    VOID
    );

NTSTATUS
DpProcessPolicyAddRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    );

NTSTATUS
DpProcessPolicyRemoveRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    );

VOID
DpProcessPolicyClearRules(
    VOID
    );

NTSTATUS
DpProcessPolicyQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpControlInitialize(
    VOID
    );

VOID
DpControlUninitialize(
    VOID
    );

NTSTATUS
DpUsbMetadataWrite(
    _In_ const DP_USB_METADATA_WRITE_MESSAGE *Request,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpNetFilterInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
DpNetFilterUninitialize(
    VOID
    );

NTSTATUS
DpWebShellInitialize(
    VOID
    );

VOID
DpWebShellUninitialize(
    VOID
    );

NTSTATUS
DpDeviceControlInitialize(
    VOID
    );

VOID
DpDeviceControlUninitialize(
    VOID
    );

NTSTATUS
DpHashProtectInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
DpHashProtectUninitialize(
    VOID
    );

NTSTATUS
DpUserHookDefenseInitialize(
    VOID
    );

VOID
DpUserHookDefenseUninitialize(
    VOID
    );

NTSTATUS
DpDeviceControlAddRule(
    _In_ const DP_DEVICE_RULE_MESSAGE *Rule
    );

NTSTATUS
DpDeviceControlRemoveRule(
    _In_ const DP_DEVICE_RULE_MESSAGE *Rule
    );

VOID
DpDeviceControlClearRules(
    VOID
    );

NTSTATUS
DpDeviceControlQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

BOOLEAN
DpDeviceControlShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpHashProtectShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpHashProtectShouldBlockRawVolumeRead(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

VOID
DpHashProtectForgetVolume(
    _In_opt_ PFLT_VOLUME Volume
    );

BOOLEAN
DpHashProtectShouldBlockProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
DpUserHookDefenseObserveProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

NTSTATUS
DpHashProtectQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpHashProtectSetPolicy(
    _In_ const DP_HASH_PROTECT_POLICY *Policy
    );

NTSTATUS
DpHashProtectQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpLateralDefenseInitialize(
    VOID
    );

VOID
DpLateralDefenseUninitialize(
    VOID
    );

BOOLEAN
DpLateralDefenseIsNamedPipeOrMailslot(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpLateralDefenseShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpLateralDefenseShouldBlockWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpLateralDefenseShouldBlockRename(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING TargetName
    );

BOOLEAN
DpLateralDefenseShouldBlockIpcCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpLateralDefenseShouldBlockProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

NTSTATUS
DpLateralDefenseQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpLateralDefenseSetPolicy(
    _In_ const DP_LATERAL_DEFENSE_POLICY *Policy
    );

NTSTATUS
DpLateralDefenseQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpUserHookDefenseQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpUserHookDefenseSetPolicy(
    _In_ const DP_USER_HOOK_DEFENSE_POLICY *Policy
    );

NTSTATUS
DpUserHookDefenseQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

BOOLEAN
DpDeviceControlShouldBlockWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
DpDeviceControlShouldBlockSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpWebShellAddRule(
    _In_ const DP_WEBSHELL_RULE_MESSAGE *Rule
    );

NTSTATUS
DpWebShellRemoveRule(
    _In_ const DP_WEBSHELL_RULE_MESSAGE *Rule
    );

VOID
DpWebShellClearRules(
    VOID
    );

NTSTATUS
DpWebShellQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpWebShellQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

BOOLEAN
DpWebShellIsScriptPath(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ PUNICODE_STRING Extension
    );

BOOLEAN
DpWebShellIsProtectedPath(
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpWebShellInspectWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN NewlyCreated
    );

NTSTATUS
DpWebShellInspectWriteByName(
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _In_ DP_WEBSHELL_OPERATION Operation
    );

NTSTATUS
DpWebShellInspectFileByName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_ DP_WEBSHELL_OPERATION Operation
    );

NTSTATUS
DpWebShellInspectFileBySourceName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING SourceName,
    _In_ PCUNICODE_STRING ReportName,
    _In_ HANDLE ProcessId,
    _In_ DP_WEBSHELL_OPERATION Operation,
    _Out_opt_ PBOOLEAN Inspected
    );

NTSTATUS
DpWebShellInspectFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PCUNICODE_STRING ReportName,
    _In_ HANDLE ProcessId,
    _In_ DP_WEBSHELL_OPERATION Operation
    );

NTSTATUS
DpFileHunterInitialize(
    VOID
    );

VOID
DpFileHunterUninitialize(
    VOID
    );

NTSTATUS
DpFileHunterAddRule(
    _In_ const DP_FILE_HUNTER_RULE_MESSAGE *Rule
    );

NTSTATUS
DpFileHunterRemoveRule(
    _In_ const DP_FILE_HUNTER_RULE_MESSAGE *Rule
    );

VOID
DpFileHunterClearRules(
    VOID
    );

NTSTATUS
DpFileHunterQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpFileHunterQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpFileHunterPrepareReadAudit(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Length,
    _Outptr_result_maybenull_ PDP_FILE_HUNTER_READ_CONTEXT *ReadContext
    );

VOID
DpFileHunterReportReadSuccess(
    _Inout_ PDP_FILE_HUNTER_READ_CONTEXT ReadContext,
    _In_ ULONG Status,
    _In_ ULONG_PTR BytesRead
    );

VOID
DpFileHunterReportReadByName(
    _In_ PCUNICODE_STRING Path,
    _In_opt_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_ ULONG Status,
    _In_ ULONG_PTR BytesRead
    );

VOID
DpFileHunterFreeReadContext(
    _In_opt_ PDP_FILE_HUNTER_READ_CONTEXT ReadContext
    );

NTSTATUS
DpNetFilterAddRule(
    _In_ const DP_NETWORK_RULE_MESSAGE *Rule
    );

NTSTATUS
DpNetFilterRemoveRule(
    _In_ ULONG RuleId
    );

VOID
DpNetFilterClearRules(
    VOID
    );

NTSTATUS
DpNetFilterQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpNetFilterQuerySmtpEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpNetFilterQueryConnectionEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpGetHandleTrust(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected,
    _Out_ PBOOLEAN IsTrusted
    );

NTSTATUS
DpGetHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PDP_HANDLE_CONTEXT *HandleContext
    );

VOID
DpReleaseHandleContext(
    _In_opt_ PDP_HANDLE_CONTEXT HandleContext
    );

PDP_IO_CONTEXT
DpAllocateIoContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ DP_IO_OPERATION Operation,
    _In_ ULONG Length
    );

PDP_IO_CONTEXT
DpAllocateAuditIoContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ DP_IO_OPERATION Operation,
    _In_ ULONG Length
    );

VOID
DpFreeIoContext(
    _In_opt_ PDP_IO_CONTEXT Context
    );

NTSTATUS
DpCryptoInitialize(
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
DpCryptoUninitialize(
    VOID
    );

BOOLEAN
DpCryptoIsReady(
    VOID
    );

VOID
DpCryptoTransformBuffer(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset
    );

VOID
DpCryptoTransformBufferWithKey(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    );

VOID
DpCryptoGetDefaultFileKey(
    _Out_writes_bytes_(DP_FILE_KEY_LENGTH) UCHAR *Key,
    _Out_ PULONG KeyLength
    );

BOOLEAN
DpPolicyNameIsProtected(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpPolicyNameIsExcluded(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpPolicyNameIsShadow(
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpPolicyRefreshStreamContext(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpPolicyFileHasProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicyReadProtectionFooter(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PDP_PROTECTION_FOOTER Footer,
    _Out_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicyGetFileLogicalSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLARGE_INTEGER LogicalSize,
    _Out_opt_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicyWriteProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpPolicyIsProtectedStream(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicySetStreamProtection(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IsProtected
    );

NTSTATUS
DpPolicyEnablePlaintextCache(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpPolicyIsPlaintextCacheEnabled(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN PlaintextCacheEnabled
    );

NTSTATUS
DpShadowPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PDP_CREATE_CONTEXT *CreateContext
    );

NTSTATUS
DpShadowPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PDP_CREATE_CONTEXT CreateContext,
    _Outptr_result_maybenull_ PDP_HANDLE_CONTEXT *HandleContext
    );

NTSTATUS
DpShadowCleanupHandle(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PDP_HANDLE_CONTEXT HandleContext
    );

NTSTATUS
DpShadowMarkHandleDirty(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpShadowEncryptFileObjectInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

NTSTATUS
DpShadowEncryptFileInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING FileName
    );

NTSTATUS
DpShadowTruncateFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

VOID
DpShadowFreeCreateContext(
    _In_opt_ PDP_CREATE_CONTEXT CreateContext
    );

BOOLEAN
DpShadowIsInternalIo(
    VOID
    );

VOID
DpShadowInitialize(
    VOID
    );

VOID
DpShadowUninitialize(
    VOID
    );

VOID
DpStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

VOID
DpHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

#if DP_ENABLE_PPTX_OPERATION_TRACE

BOOLEAN
DpTraceNameIsPptx(
    _In_opt_ PCUNICODE_STRING Name
    );

VOID
DpTracePptxName(
    _In_z_ PCSTR Operation,
    _In_opt_ PCUNICODE_STRING Name,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2,
    _In_ ULONG_PTR Detail3,
    _In_ ULONG_PTR Detail4
    );

VOID
DpTracePptxCallbackData(
    _In_z_ PCSTR Operation,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2,
    _In_ ULONG_PTR Detail3,
    _In_ ULONG_PTR Detail4
    );

#define DP_TRACE_PPTX_NAME(_operation, _name, _status, _detail1, _detail2, _detail3, _detail4) \
    DpTracePptxName((_operation), (_name), (_status), (ULONG_PTR)(_detail1), (ULONG_PTR)(_detail2), (ULONG_PTR)(_detail3), (ULONG_PTR)(_detail4))

#define DP_TRACE_PPTX_DATA(_operation, _data, _fltObjects, _status, _detail1, _detail2, _detail3, _detail4) \
    DpTracePptxCallbackData((_operation), (_data), (_fltObjects), (_status), (ULONG_PTR)(_detail1), (ULONG_PTR)(_detail2), (ULONG_PTR)(_detail3), (ULONG_PTR)(_detail4))

#else

#define DP_TRACE_PPTX_NAME(_operation, _name, _status, _detail1, _detail2, _detail3, _detail4) ((void)0)
#define DP_TRACE_PPTX_DATA(_operation, _data, _fltObjects, _status, _detail1, _detail2, _detail3, _detail4) ((void)0)

#endif

//
// ---------------------------------------------------------------------------
// Threat Engine entry points.
// ---------------------------------------------------------------------------
//

NTSTATUS
DpThreatEngineInitialize(
    VOID
    );

VOID
DpThreatEngineUninitialize(
    VOID
    );

//
// Lifecycle hooks driven from the single process-notify funnel.
//
VOID
DpThreatEngineOnProcessCreate(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    );

VOID
DpThreatEngineOnProcessExit(
    _In_ HANDLE ProcessId
    );

//
// Primary signal ingestion point used by every sensor. ScoreDeltaOverride of 0
// uses the engine's default weight for the signal. Returns the response action
// the engine selected so the caller may enforce it (e.g. deny an operation).
//
DP_THREAT_RESPONSE_ACTION
DpThreatEngineReportSignal(
    _In_ HANDLE ProcessId,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ ULONG ScoreDeltaOverride,
    _In_opt_ PCUNICODE_STRING Detail
    );

//
// Convenience ingestion when the caller only has an ANSI image name (kernel
// callbacks frequently expose PsGetProcessImageFileName output).
//
DP_THREAT_RESPONSE_ACTION
DpThreatEngineReportSignalAnsi(
    _In_ HANDLE ProcessId,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ ULONG ScoreDeltaOverride,
    _In_opt_z_ const CHAR *Detail
    );

//
// Returns TRUE if the engine has placed the given process under network
// isolation. Consulted by the network filter classify path.
//
BOOLEAN
DpThreatEngineIsProcessIsolated(
    _In_ HANDLE ProcessId
    );

NTSTATUS
DpThreatEngineQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpThreatEngineQueryProcesses(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

VOID
DpThreatEngineClearEvents(
    VOID
    );

NTSTATUS
DpThreatEngineSetPolicy(
    _In_ const DP_THREAT_ENGINE_POLICY *Policy
    );

NTSTATUS
DpThreatEngineQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpThreatEngineRespond(
    _In_ const DP_THREAT_RESPONSE_REQUEST *Request
    );

NTSTATUS
DpThreatEngineQueryStorylines(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

//
// ---------------------------------------------------------------------------
// Executable static scanner entry points.
// ---------------------------------------------------------------------------
//

NTSTATUS
DpStaticScanInitialize(
    VOID
    );

VOID
DpStaticScanUninitialize(
    VOID
    );

//
// Returns TRUE if the given name is an executable image the scanner cares
// about (PE extension or known script dropper extension).
//
BOOLEAN
DpStaticScanIsExecutableName(
    _In_ PCUNICODE_STRING Name
    );

//
// Detector entry point. Called from the cleanup path when a handle that
// created/wrote/renamed an executable is closing. Captures metadata and
// enqueues a scan REQUEST for user mode. Does NOT read or classify the file.
//
VOID
DpStaticScanEnqueueRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_ DP_STATIC_SCAN_OPERATION Operation
    );

//
// Drain pending scan requests (kernel -> user mode). Two-pass sizing like the
// other event queues.
//
NTSTATUS
DpStaticScanQueryRequests(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

//
// Submit a user-mode verdict for a previously drained request. Records the
// event, reports to the threat engine, and quarantines (truncates) when the
// verdict is blocking under policy.
//
NTSTATUS
DpStaticScanSubmitVerdict(
    _In_ const DP_STATIC_SCAN_VERDICT_MESSAGE *Verdict
    );

NTSTATUS
DpStaticScanQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpStaticScanSetPolicy(
    _In_ const DP_STATIC_SCAN_POLICY *Policy
    );

NTSTATUS
DpStaticScanQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

VOID
DpStaticScanClearEvents(
    VOID
    );

EXTERN_C_END
