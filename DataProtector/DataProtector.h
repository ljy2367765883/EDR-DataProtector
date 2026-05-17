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
#define DP_TAG_DEVICE_RULE     'rDpD'
#define DP_TAG_HASH_PROTECT    'hHpD'

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
#define DP_DEVICE_MAX_RULES 256
#define DP_DEVICE_MAX_ID_CHARS 260
#define DP_DEVICE_MAX_ID_BYTES (DP_DEVICE_MAX_ID_CHARS * sizeof(WCHAR))
#define DP_HASH_PROTECT_MAX_EVENTS 256
#define DP_HASH_PROTECT_TARGET_CHARS 512
#define DP_HASH_PROTECT_PROCESS_CHARS 64
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
#define DP_ENABLE_PPTX_OPERATION_TRACE 1

//
// Targeted WebShell investigation switch. Emits DataProtector77 lines through
// DbgPrintEx while diagnosing policy, event queue, and reporting paths.
//
#define DP_ENABLE_WEBSHELL_OPERATION_TRACE 1

//
// Targeted hash-dump protection diagnostics. Emits only registration failures
// and blocked credential-dump attempts.
//
#define DP_ENABLE_HASH_PROTECT_TRACE 1

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
} DP_HANDLE_CONTEXT, *PDP_HANDLE_CONTEXT;

typedef struct _DP_CREATE_CONTEXT {
    BOOLEAN IsTrusted;
    BOOLEAN IsShadow;
    BOOLEAN ShadowDirty;
    UNICODE_STRING OriginalName;
    UNICODE_STRING ShadowName;
} DP_CREATE_CONTEXT, *PDP_CREATE_CONTEXT;

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
    DpPolicyCommandQueryHashProtectPolicy = 82
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
    DpHashProtectOperationRegistryHive = 3
} DP_HASH_PROTECT_OPERATION;

#define DP_HASH_PROTECT_POLICY_VERSION 1
#define DP_HASH_PROTECT_FLAG_ENABLED          0x00000001
#define DP_HASH_PROTECT_FLAG_LSASS_HANDLES    0x00000002
#define DP_HASH_PROTECT_FLAG_CREDENTIAL_FILES 0x00000004
#define DP_HASH_PROTECT_FLAG_REGISTRY_HIVES   0x00000008
#define DP_HASH_PROTECT_DEFAULT_FLAGS \
    (DP_HASH_PROTECT_FLAG_ENABLED | \
     DP_HASH_PROTECT_FLAG_LSASS_HANDLES | \
     DP_HASH_PROTECT_FLAG_CREDENTIAL_FILES | \
     DP_HASH_PROTECT_FLAG_REGISTRY_HIVES)
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

EXTERN_C_END
