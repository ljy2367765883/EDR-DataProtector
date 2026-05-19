#define WIN32_LEAN_AND_MEAN

#include "DataProtectorPolicyApi.h"

#include <fltUser.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <wctype.h>

#define DP_POLICY_PORT_NAME L"\\DataProtectorPolicyPort"
#define DP_POLICY_MESSAGE_VERSION 1u
#define DP_POLICY_QUERY_VERSION 1u
#define DP_POLICY_MAX_RULE_BYTES (1024u * sizeof(WCHAR))
#define DP_POLICY_MAX_EXTENSION_BYTES (64u * sizeof(WCHAR))
#define DP_POLICY_MAX_DOMAIN_BYTES (260u * sizeof(WCHAR))
#define DP_NETWORK_EVENT_PROCESS_PATH_CHARS 512u
#define DP_NETWORK_EVENT_DOMAIN_CHARS 260u
#define DP_SMTP_MAX_ADDRESS_CHARS 256u
#define DP_WEBSHELL_MAX_PATH_BYTES (1024u * sizeof(WCHAR))
#define DP_WEBSHELL_EVENT_PATH_CHARS 512u
#define DP_WEBSHELL_EVENT_EXTENSION_CHARS 32u
#define DP_WEBSHELL_MAX_SAMPLE_BYTES 100u
#define DP_DEVICE_MAX_ID_CHARS 260u
#define DP_DEVICE_MAX_ID_BYTES (DP_DEVICE_MAX_ID_CHARS * sizeof(WCHAR))
#define DP_HASH_PROTECT_TARGET_CHARS 512u
#define DP_HASH_PROTECT_PROCESS_CHARS 64u
#define DP_LATERAL_DEFENSE_TARGET_CHARS 512u
#define DP_LATERAL_DEFENSE_PROCESS_CHARS 64u
#define DP_USER_HOOK_DEFENSE_TARGET_CHARS 512u
#define DP_USER_HOOK_DEFENSE_PROCESS_CHARS 512u
#define DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS 2048u
#define DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS 512u
#define DP_USB_METADATA_BYTES 512u
#define DP_USB_METADATA_PATH_CHARS 128u
#define DP_USB_METADATA_MESSAGE_VERSION 1u
#define DP_USB_METADATA_RESULT_VERSION 1u
#define DP_USB_METADATA_DEFAULT_OFFSET_BYTES (1024ull * 1024ull)
#define DP_USB_LAYOUT_PUBLIC_LABEL L"DPUSB"
#define DP_USB_LAYOUT_RESCAN_TRIES 30u
#define DP_USB_LAYOUT_RESCAN_SLEEP_MS 500u
#define DP_USB_LAYOUT_FORMAT_SLEEP_MS 500u
#define DP_USB_LAYOUT_PUBLIC_PARTITION_NUMBER 1u
#define DP_USB_LAYOUT_SECTOR_BYTES 512u
#define DP_USB_LAYOUT_SMALL_PUBLIC_MAX_BYTES (32ull * 1024ull * 1024ull)
#define DP_USB_LAYOUT_FAT_COUNT 2u
#define DP_USB_LAYOUT_FAT16_RESERVED_SECTORS 1u
#define DP_USB_LAYOUT_FAT16_ROOT_ENTRIES 512u
#define DP_USB_LAYOUT_FAT16_MIN_CLUSTERS 4085u
#define DP_USB_LAYOUT_FAT16_MAX_CLUSTERS 65525u
#define DP_SMTP_EVENT_STRING_CHARS (DP_SMTP_MAX_ADDRESS_CHARS * 2u + 2u)
#define DP_NETWORK_CONNECTION_EVENT_STRING_CHARS (DP_NETWORK_EVENT_PROCESS_PATH_CHARS + DP_NETWORK_EVENT_DOMAIN_CHARS + 2u)
#define DP_WEBSHELL_EVENT_STRING_CHARS (DP_WEBSHELL_EVENT_PATH_CHARS + DP_WEBSHELL_EVENT_EXTENSION_CHARS + 2u)
#define DP_HASH_PROTECT_EVENT_STRING_CHARS (DP_HASH_PROTECT_TARGET_CHARS + DP_HASH_PROTECT_PROCESS_CHARS + 2u)
#define DP_LATERAL_DEFENSE_EVENT_STRING_CHARS (DP_LATERAL_DEFENSE_TARGET_CHARS + DP_LATERAL_DEFENSE_PROCESS_CHARS + 2u)
#define DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS (DP_USER_HOOK_DEFENSE_TARGET_CHARS + DP_USER_HOOK_DEFENSE_PROCESS_CHARS + 2u)
#define DP_POLICY_DEFAULT_EXTENSION L".dpf"
#define DP_POLICY_API_ENABLE_FILE_TRACE 1
#define DP_POLICY_API_TRACE_PATH L"C:\\ProgramData\\DataProtector\\PolicyApiTrace.log"

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
    DpPolicyCommandWriteUsbMetadata = 100
} DP_POLICY_COMMAND;

typedef struct _DP_POLICY_MESSAGE {
    ULONG Version;
    ULONG Command;
    ULONG ValueLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Data[1];
} DP_POLICY_MESSAGE, *PDP_POLICY_MESSAGE;

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

typedef struct _DP_USB_METADATA_WRITE_MESSAGE {
    ULONG Version;
    ULONG MetadataBytes;
    ULONGLONG OffsetBytes;
    ULONG PhysicalPathLengthBytes;
    ULONG Reserved;
    WCHAR PhysicalPath[DP_USB_METADATA_PATH_CHARS];
    BYTE Metadata[DP_USB_METADATA_BYTES];
} DP_USB_METADATA_WRITE_MESSAGE, *PDP_USB_METADATA_WRITE_MESSAGE;

typedef struct _DP_USB_METADATA_WRITE_RESULT {
    ULONG Version;
    ULONG Status;
    ULONG PartitionCount;
    ULONG Reserved;
    ULONGLONG OffsetBytes;
    ULONGLONG DiskSizeBytes;
} DP_USB_METADATA_WRITE_RESULT, *PDP_USB_METADATA_WRITE_RESULT;

#pragma pack(push, 1)
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
#pragma pack(pop)

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

typedef struct _DP_HASH_PROTECT_POLICY_MESSAGE {
    ULONG Version;
    ULONG Flags;
} DP_HASH_PROTECT_POLICY_MESSAGE, *PDP_HASH_PROTECT_POLICY_MESSAGE;

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

typedef struct _DP_LATERAL_DEFENSE_POLICY_MESSAGE {
    ULONG Version;
    ULONG Flags;
} DP_LATERAL_DEFENSE_POLICY_MESSAGE, *PDP_LATERAL_DEFENSE_POLICY_MESSAGE;

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

typedef struct _DP_USER_HOOK_DEFENSE_POLICY_MESSAGE {
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
} DP_USER_HOOK_DEFENSE_POLICY_MESSAGE, *PDP_USER_HOOK_DEFENSE_POLICY_MESSAGE;

#define DP_NETWORK_RULE_MESSAGE_VERSION 1u
#define DP_NETWORK_RULE_QUERY_VERSION 1u
#define DP_NETWORK_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_NETWORK_RULE_QUERY_ENTRY, Domain)
#define DP_SMTP_EVENT_QUERY_VERSION 1u
#define DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION 1u
#define DP_WEBSHELL_RULE_MESSAGE_VERSION 1u
#define DP_WEBSHELL_RULE_QUERY_VERSION 1u
#define DP_WEBSHELL_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_WEBSHELL_RULE_QUERY_ENTRY, Directory)
#define DP_WEBSHELL_EVENT_QUERY_VERSION 1u
#define DP_HASH_PROTECT_EVENT_QUERY_VERSION 1u
#define DP_HASH_PROTECT_POLICY_VERSION 1u
#define DP_HASH_PROTECT_ALLOWED_FLAGS \
    (DP_POLICY_API_HASH_PROTECT_FLAG_ENABLED | \
     DP_POLICY_API_HASH_PROTECT_FLAG_LSASS_HANDLES | \
     DP_POLICY_API_HASH_PROTECT_FLAG_CREDENTIAL_FILES | \
     DP_POLICY_API_HASH_PROTECT_FLAG_REGISTRY_HIVES | \
     DP_POLICY_API_HASH_PROTECT_FLAG_RAW_EXTENTS)
#define DP_LATERAL_DEFENSE_EVENT_QUERY_VERSION 1u
#define DP_LATERAL_DEFENSE_POLICY_VERSION 1u
#define DP_LATERAL_DEFENSE_ALLOWED_FLAGS \
    (DP_POLICY_API_LATERAL_DEFENSE_FLAG_ENABLED | \
     DP_POLICY_API_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES | \
     DP_POLICY_API_LATERAL_DEFENSE_FLAG_IPC_TASKS | \
     DP_POLICY_API_LATERAL_DEFENSE_FLAG_IPC_SERVICES | \
     DP_POLICY_API_LATERAL_DEFENSE_FLAG_PROCESS_TOOLS)
#define DP_USER_HOOK_DEFENSE_EVENT_QUERY_VERSION 1u
#define DP_USER_HOOK_DEFENSE_POLICY_VERSION 4u
#define DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS \
    (DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_ENABLED | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_REQUIRE_SIGNED_RUNTIME | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_BLOCK_UNTRUSTED_RUNTIME | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_AUDIT_ONLY | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_MONITOR_SYSTEM_PROCESSES | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_RUNTIME_API_BEHAVIOR | \
     DP_POLICY_API_USER_HOOK_DEFENSE_FLAG_RUNTIME_MEMORY_SCAN)
#define DP_DEVICE_RULE_MESSAGE_VERSION 1u
#define DP_DEVICE_RULE_QUERY_VERSION 1u
#define DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_DEVICE_RULE_QUERY_ENTRY, DeviceId)

C_ASSERT(sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY) == 1232);

static WCHAR gLastErrorMessage[512];
__declspec(thread) static WCHAR gUserHookQueryExcludedProcessNames[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
__declspec(thread) static WCHAR gUserHookQueryExcludedProcessDirectories[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
__declspec(thread) static WCHAR gUserHookQueryExcludedProcessPaths[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
__declspec(thread) static WCHAR gUserHookQueryTrustedSignerSubjects[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
__declspec(thread) static WCHAR gUserHookQueryRuntimeDllPath[DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS];
static volatile LONG gFormatLock = 0;
static volatile LONG gFormatActive = 0;
static volatile LONG gFormatCompleted = 0;
static volatile LONG gFormatSuccess = 0;

typedef enum _DP_FMIFS_PACKET_TYPE {
    DpFmifsProgress = 0,
    DpFmifsDoneWithStructure = 0x0B
} DP_FMIFS_PACKET_TYPE;

typedef BOOLEAN (__stdcall *DP_FMIFS_CALLBACK)(
    _In_ DP_FMIFS_PACKET_TYPE PacketType,
    _In_ ULONG PacketLength,
    _In_opt_ PVOID PacketData
    );

typedef VOID (WINAPI *DP_FORMAT_EX)(
    _In_ PWSTR DriveRoot,
    _In_ ULONG MediaFlag,
    _In_ PWSTR FileSystemName,
    _In_ PWSTR Label,
    _In_ BOOLEAN QuickFormat,
    _In_ ULONG ClusterSize,
    _In_ DP_FMIFS_CALLBACK Callback
    );

typedef struct _DP_PUBLIC_FAT16_LAYOUT {
    DWORD BytesPerSector;
    DWORD SectorsPerCluster;
    DWORD ReservedSectors;
    DWORD FatCount;
    DWORD RootEntryCount;
    DWORD RootDirectorySectors;
    DWORD TotalSectors;
    DWORD FatSectors;
    DWORD DataSectors;
    DWORD ClusterCount;
    DWORD HiddenSectors;
} DP_PUBLIC_FAT16_LAYOUT, *PDP_PUBLIC_FAT16_LAYOUT;

#if DP_POLICY_API_ENABLE_FILE_TRACE
static
VOID
DpPolicyTrace(
    _In_z_ LPCWSTR Format,
    ...
    )
{
    WCHAR line[1024];
    WCHAR timestamp[64];
    SYSTEMTIME systemTime;
    HANDLE fileHandle;
    DWORD bytesWritten;
    int prefixChars;
    int lineChars;
    va_list args;

    if (Format == NULL) {
        return;
    }

    GetSystemTime(&systemTime);
    prefixChars = _snwprintf_s(timestamp,
                               ARRAYSIZE(timestamp),
                               _TRUNCATE,
                               L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu tid=%lu ",
                               systemTime.wYear,
                               systemTime.wMonth,
                               systemTime.wDay,
                               systemTime.wHour,
                               systemTime.wMinute,
                               systemTime.wSecond,
                               systemTime.wMilliseconds,
                               GetCurrentProcessId(),
                               GetCurrentThreadId());

    if (prefixChars < 0) {
        return;
    }

    (VOID)StringCchCopyW(line, ARRAYSIZE(line), timestamp);

    va_start(args, Format);
    (VOID)StringCchVPrintfW(line + prefixChars,
                            ARRAYSIZE(line) - (size_t)prefixChars,
                            Format,
                            args);
    va_end(args);

    (VOID)StringCchCatW(line, ARRAYSIZE(line), L"\r\n");
    lineChars = (int)wcslen(line);

    CreateDirectoryW(L"C:\\ProgramData\\DataProtector", NULL);
    fileHandle = CreateFileW(DP_POLICY_API_TRACE_PATH,
                             FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    (VOID)WriteFile(fileHandle,
                    line,
                    (DWORD)(lineChars * sizeof(WCHAR)),
                    &bytesWritten,
                    NULL);
    CloseHandle(fileHandle);
}
#else
#define DpPolicyTrace(...) ((void)0)
#endif

static
VOID
DpPolicySetLastErrorMessage(
    _In_z_ LPCWSTR Message
    )
{
    (VOID)StringCchCopyW(gLastErrorMessage,
                         ARRAYSIZE(gLastErrorMessage),
                         Message != NULL ? Message : L"Unknown error.");
}

static
VOID
DpPolicySetLastErrorFromCode(
    _In_ DWORD ErrorCode,
    _In_z_ LPCWSTR Prefix
    )
{
    WCHAR systemMessage[256];
    WCHAR formatted[512];
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS |
                  FORMAT_MESSAGE_MAX_WIDTH_MASK;

    systemMessage[0] = L'\0';

    if (FormatMessageW(flags,
                       NULL,
                       ErrorCode,
                       0,
                       systemMessage,
                       ARRAYSIZE(systemMessage),
                       NULL) == 0) {

        (VOID)StringCchPrintfW(systemMessage,
                              ARRAYSIZE(systemMessage),
                              L"Error 0x%08X",
                              ErrorCode);
    }

    (VOID)StringCchPrintfW(formatted,
                          ARRAYSIZE(formatted),
                          L"%s: %s",
                          Prefix != NULL ? Prefix : L"Operation failed",
                          systemMessage);

    DpPolicySetLastErrorMessage(formatted);
}

static
DWORD
DpPolicyTrimCopy(
    _In_z_ LPCWSTR Source,
    _Outptr_result_z_ LPWSTR *Normalized,
    _In_ BOOL TrimTrailingSlash
    )
{
    size_t length;
    LPWSTR value;

    *Normalized = NULL;

    if (Source == NULL) {
        DpPolicySetLastErrorMessage(L"Rule value is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    while (*Source == L' ' || *Source == L'\t' || *Source == L'\r' || *Source == L'\n') {
        Source++;
    }

    length = wcslen(Source);
    while (length > 0) {
        WCHAR character = Source[length - 1];

        if (character != L' ' && character != L'\t' && character != L'\r' && character != L'\n') {
            break;
        }

        length--;
    }

    if (TrimTrailingSlash) {
        while (length > 0 && (Source[length - 1] == L'\\' || Source[length - 1] == L'/')) {
            length--;
        }
    }

    if (length == 0) {
        DpPolicySetLastErrorMessage(L"Rule value is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (length * sizeof(WCHAR) > DP_POLICY_MAX_RULE_BYTES) {
        DpPolicySetLastErrorMessage(L"Rule value is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    value = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (length + 1) * sizeof(WCHAR));
    if (value == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    CopyMemory(value, Source, length * sizeof(WCHAR));
    value[length] = L'\0';

    *Normalized = value;

    return DP_POLICY_API_SUCCESS;
}

static
BOOL
DpPolicyIsNtPath(
    _In_z_ LPCWSTR Path
    )
{
    return Path != NULL &&
           (wcsncmp(Path, L"\\Device\\", 8) == 0 ||
            wcsncmp(Path, L"\\??\\", 4) == 0);
}

static
DWORD
DpPolicyConvertDosPathToNtPathAlloc(
    _In_z_ LPCWSTR DosPath,
    _Outptr_result_z_ LPWSTR *NtPath
    )
{
    WCHAR fullPath[MAX_PATH];
    WCHAR drivePrefix[3];
    WCHAR deviceName[512];
    WCHAR ntPath[1024];
    DWORD fullLength;
    DWORD deviceLength;
    HRESULT hr;

    *NtPath = NULL;

    if (DpPolicyIsNtPath(DosPath)) {
        return DpPolicyTrimCopy(DosPath, NtPath, TRUE);
    }

    fullLength = GetFullPathNameW(DosPath, ARRAYSIZE(fullPath), fullPath, NULL);
    if (fullLength == 0 || fullLength >= ARRAYSIZE(fullPath)) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot normalize directory path");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    if (fullPath[0] == L'\\' && fullPath[1] == L'\\') {
        DpPolicySetLastErrorMessage(L"UNC directory rules are not supported by this driver policy channel.");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    if (fullPath[0] == L'\0' || fullPath[1] != L':') {
        DpPolicySetLastErrorMessage(L"Directory path must be an absolute drive path or an NT path.");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    drivePrefix[0] = fullPath[0];
    drivePrefix[1] = L':';
    drivePrefix[2] = L'\0';

    deviceLength = QueryDosDeviceW(drivePrefix, deviceName, ARRAYSIZE(deviceName));
    if (deviceLength == 0) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot resolve drive device name");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    hr = StringCchPrintfW(ntPath,
                         ARRAYSIZE(ntPath),
                         L"%s%s",
                         deviceName,
                         fullPath + 2);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"Converted NT path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    return DpPolicyTrimCopy(ntPath, NtPath, TRUE);
}

static
DWORD
DpPolicyNormalizeExtensionAlloc(
    _In_z_ LPCWSTR Extension,
    _Outptr_result_z_ LPWSTR *Normalized
    )
{
    DWORD result;
    LPWSTR trimmed = NULL;
    size_t length;
    LPWSTR value;

    result = DpPolicyTrimCopy(Extension, &trimmed, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    length = wcslen(trimmed);
    if (length == 0 || length * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Extension value is empty or too long.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (trimmed[0] == L'.') {
        *Normalized = trimmed;
        return DP_POLICY_API_SUCCESS;
    }

    if ((length + 1) * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Extension value is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    value = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (length + 2) * sizeof(WCHAR));
    if (value == NULL) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    value[0] = L'.';
    CopyMemory(value + 1, trimmed, length * sizeof(WCHAR));
    value[length + 1] = L'\0';

    HeapFree(GetProcessHeap(), 0, trimmed);
    *Normalized = value;

    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicySendMessage(
    _In_ ULONG Command,
    _In_opt_z_ LPCWSTR RuleValue,
    _In_opt_z_ LPCWSTR ExtensionValue,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG BytesReturned
    )
{
    DWORD result = DP_POLICY_API_SUCCESS;
    HRESULT hr;
    HANDLE port = INVALID_HANDLE_VALUE;
    PDP_POLICY_MESSAGE message = NULL;
    ULONG valueLengthBytes = 0;
    ULONG extensionLengthBytes = 0;
    ULONG messageLength;
    ULONG localBytesReturned = 0;
    PULONG bytesReturned = BytesReturned != NULL ? BytesReturned : &localBytesReturned;

    *bytesReturned = 0;

    if (RuleValue != NULL) {
        size_t length = wcslen(RuleValue);

        if (length == 0) {
            DpPolicySetLastErrorMessage(L"Rule value is empty.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        if (length * sizeof(WCHAR) > DP_POLICY_MAX_RULE_BYTES) {
            DpPolicySetLastErrorMessage(L"Rule value is too long.");
            return DP_POLICY_API_ERROR_RULE_TOO_LONG;
        }

        valueLengthBytes = (ULONG)(length * sizeof(WCHAR));
    }

    if (ExtensionValue != NULL) {
        size_t length = wcslen(ExtensionValue);

        if (length == 0) {
            DpPolicySetLastErrorMessage(L"Extension value is empty.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        if (length * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
            DpPolicySetLastErrorMessage(L"Extension value is too long.");
            return DP_POLICY_API_ERROR_RULE_TOO_LONG;
        }

        extensionLengthBytes = (ULONG)(length * sizeof(WCHAR));
    }

    messageLength = (ULONG)FIELD_OFFSET(DP_POLICY_MESSAGE, Data) + valueLengthBytes + extensionLengthBytes;
    message = (PDP_POLICY_MESSAGE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
    if (message == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    message->Version = DP_POLICY_MESSAGE_VERSION;
    message->Command = Command;
    message->ValueLengthBytes = valueLengthBytes;
    message->ExtensionLengthBytes = extensionLengthBytes;

    if (valueLengthBytes != 0) {
        CopyMemory(message->Data, RuleValue, valueLengthBytes);
    }

    if (extensionLengthBytes != 0) {
        CopyMemory((PBYTE)message->Data + valueLengthBytes, ExtensionValue, extensionLengthBytes);
    }

    hr = FilterConnectCommunicationPort(DP_POLICY_PORT_NAME,
                                        0,
                                        NULL,
                                        0,
                                        NULL,
                                        &port);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Cannot connect to DataProtector driver");
        result = (DWORD)hr;
        goto Exit;
    }

    hr = FilterSendMessage(port,
                           message,
                           messageLength,
                           OutputBuffer,
                           OutputBufferLength,
                           bytesReturned);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Driver rejected the policy command");
        result = (DWORD)hr;
        goto Exit;
    }

    DpPolicySetLastErrorMessage(L"Success.");

Exit:
    if (port != INVALID_HANDLE_VALUE) {
        CloseHandle(port);
    }

    if (message != NULL) {
        HeapFree(GetProcessHeap(), 0, message);
    }

    return result;
}

static
DWORD
DpPolicySendRawPolicyMessage(
    _In_ ULONG Command,
    _In_reads_bytes_opt_(PayloadLength) const VOID *Payload,
    _In_ ULONG PayloadLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG BytesReturned
    )
{
    DWORD result = DP_POLICY_API_SUCCESS;
    HRESULT hr;
    HANDLE port = INVALID_HANDLE_VALUE;
    PDP_POLICY_MESSAGE message = NULL;
    ULONG messageLength;
    ULONG localBytesReturned = 0;
    PULONG bytesReturned = BytesReturned != NULL ? BytesReturned : &localBytesReturned;

    *bytesReturned = 0;

    if (PayloadLength != 0 && Payload == NULL) {
        DpPolicySetLastErrorMessage(L"Policy payload is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    messageLength = (ULONG)FIELD_OFFSET(DP_POLICY_MESSAGE, Data) + PayloadLength;
    message = (PDP_POLICY_MESSAGE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
    if (message == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    message->Version = DP_POLICY_MESSAGE_VERSION;
    message->Command = Command;
    message->ValueLengthBytes = PayloadLength;
    message->ExtensionLengthBytes = 0;

    if (PayloadLength != 0) {
        CopyMemory(message->Data, Payload, PayloadLength);
    }

    hr = FilterConnectCommunicationPort(DP_POLICY_PORT_NAME,
                                        0,
                                        NULL,
                                        0,
                                        NULL,
                                        &port);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Cannot connect to DataProtector driver");
        result = (DWORD)hr;
        goto Exit;
    }

    hr = FilterSendMessage(port,
                           message,
                           messageLength,
                           OutputBuffer,
                           OutputBufferLength,
                           bytesReturned);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Driver rejected the policy command");
        result = (DWORD)hr;
        goto Exit;
    }

    DpPolicySetLastErrorMessage(L"Success.");

Exit:
    if (port != INVALID_HANDLE_VALUE) {
        CloseHandle(port);
    }

    if (message != NULL) {
        HeapFree(GetProcessHeap(), 0, message);
    }

    return result;
}

DWORD
DpPolicyCheckConnection(void)
{
    HRESULT hr;
    HANDLE port = INVALID_HANDLE_VALUE;

    hr = FilterConnectCommunicationPort(DP_POLICY_PORT_NAME,
                                        0,
                                        NULL,
                                        0,
                                        NULL,
                                        &port);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Cannot connect to DataProtector driver");
        return (DWORD)hr;
    }

    CloseHandle(port);
    DpPolicySetLastErrorMessage(L"Success.");

    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyAddProcessNameRule(
    _In_z_ LPCWSTR ProcessName
    )
{
    return DpPolicyAddProcessNameRuleEx(ProcessName, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddProcessNameRuleEx(
    _In_z_ LPCWSTR ProcessName,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR normalized = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyTrimCopy(ProcessName, &normalized, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, normalized);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddProcessNameRule,
                                 normalized,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, normalized);

    return result;
}

DWORD
DpPolicyRemoveProcessNameRule(
    _In_z_ LPCWSTR ProcessName
    )
{
    return DpPolicyRemoveProcessNameRuleEx(ProcessName, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveProcessNameRuleEx(
    _In_z_ LPCWSTR ProcessName,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR normalized = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyTrimCopy(ProcessName, &normalized, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, normalized);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveProcessNameRule,
                                 normalized,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, normalized);

    return result;
}

DWORD
DpPolicyAddProcessDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyAddProcessDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddProcessDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddProcessDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyRemoveProcessDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyRemoveProcessDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveProcessDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveProcessDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyAddExcludedDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyAddExcludedDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddExcludedDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);

    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyRemoveExcludedDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyRemoveExcludedDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveExcludedDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);

    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyClearProcessRules(void)
{
    return DpPolicySendMessage(DpPolicyCommandClearProcessRules,
                               NULL,
                               NULL,
                               NULL,
                               0,
                               NULL);
}

DWORD
DpPolicyQueryProcessRules(
    _Out_writes_opt_(RuleCapacity) DP_POLICY_API_RULE *Rules,
    _In_ DWORD RuleCapacity,
    _Out_opt_ DWORD *RuleCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_POLICY_QUERY_HEADER header;
    DP_POLICY_QUERY_HEADER sizingHeader;
    PBYTE cursor;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedRuleCount = 0;
    BOOL sizingOnly = RuleCapacity == 0 && StringBufferChars == 0;

    if (RuleCount != NULL) {
        *RuleCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((RuleCapacity != 0 && Rules == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));

    result = DpPolicySendMessage(DpPolicyCommandQueryProcessRules,
                                 NULL,
                                 NULL,
                                 &sizingHeader,
                                 sizeof(sizingHeader),
                                 &bytesReturned);

    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_POLICY_QUERY_HEADER) ||
        sizingHeader.Version != DP_POLICY_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_POLICY_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid rule snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    bytesRequired = sizingHeader.BytesRequired;

    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendMessage(DpPolicyCommandQueryProcessRules,
                                 NULL,
                                 NULL,
                                 queryBuffer,
                                 bytesRequired,
                                 &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_POLICY_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid rule snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_POLICY_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_POLICY_QUERY_VERSION) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported rule snapshot version.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedRuleCount = header->RuleCount;

    if (RuleCount != NULL) {
        *RuleCount = returnedRuleCount;
    }

    cursor = queryBuffer + sizeof(DP_POLICY_QUERY_HEADER);

    for (index = 0; index < returnedRuleCount; index++) {
        PDP_POLICY_QUERY_ENTRY entry;
        DWORD valueChars;
        DWORD extensionChars;
        DWORD entryBytes;
        LPCWSTR valueSource;
        LPCWSTR extensionSource;

        if ((ULONG_PTR)(cursor - queryBuffer) + sizeof(DP_POLICY_QUERY_ENTRY) > bytesReturned) {
            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned a truncated rule snapshot.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        entry = (PDP_POLICY_QUERY_ENTRY)cursor;
        entryBytes = (DWORD)FIELD_OFFSET(DP_POLICY_QUERY_ENTRY, Data) +
                     entry->ValueLengthBytes +
                     entry->ExtensionLengthBytes;

        if ((ULONG_PTR)(cursor - queryBuffer) + entryBytes > bytesReturned ||
            entry->ValueLengthBytes % sizeof(WCHAR) != 0 ||
            entry->ExtensionLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid rule entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        valueChars = entry->ValueLengthBytes / sizeof(WCHAR);
        extensionChars = entry->ExtensionLengthBytes / sizeof(WCHAR);
        requiredStringChars += valueChars + 1 + extensionChars + 1;

        if (index < RuleCapacity && StringBuffer != NULL &&
            copiedStringChars + valueChars + 1 + extensionChars + 1 <= StringBufferChars) {

            valueSource = entry->Data;
            extensionSource = (LPCWSTR)((PBYTE)entry->Data + entry->ValueLengthBytes);

            Rules[index].RuleType = entry->RuleType;
            Rules[index].Value = StringBuffer + copiedStringChars;
            CopyMemory(StringBuffer + copiedStringChars,
                       valueSource,
                       entry->ValueLengthBytes);
            copiedStringChars += valueChars;
            StringBuffer[copiedStringChars++] = L'\0';

            Rules[index].Extension = StringBuffer + copiedStringChars;
            CopyMemory(StringBuffer + copiedStringChars,
                       extensionSource,
                       entry->ExtensionLengthBytes);
            copiedStringChars += extensionChars;
            StringBuffer[copiedStringChars++] = L'\0';
        }

        cursor += entryBytes;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (RuleCapacity < returnedRuleCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyAddNetworkRule(
    _In_ const DP_POLICY_API_NETWORK_RULE *Rule
    )
{
    DP_NETWORK_RULE_MESSAGE message;
    size_t domainLength = 0;

    if (Rule == NULL ||
        Rule->RuleId == 0 ||
        (Rule->Kind != DP_POLICY_API_NETWORK_RULE_IP && Rule->Kind != DP_POLICY_API_NETWORK_RULE_DOMAIN) ||
        (Rule->Action != DP_POLICY_API_NETWORK_ACTION_ALLOW && Rule->Action != DP_POLICY_API_NETWORK_ACTION_BLOCK) ||
        (Rule->Protocol != DP_POLICY_API_NETWORK_PROTOCOL_ANY &&
         Rule->Protocol != DP_POLICY_API_NETWORK_PROTOCOL_ICMP &&
         Rule->Protocol != DP_POLICY_API_NETWORK_PROTOCOL_TCP &&
         Rule->Protocol != DP_POLICY_API_NETWORK_PROTOCOL_UDP) ||
        (Rule->Direction != DP_POLICY_API_NETWORK_DIRECTION_INBOUND &&
         Rule->Direction != DP_POLICY_API_NETWORK_DIRECTION_OUTBOUND &&
         Rule->Direction != DP_POLICY_API_NETWORK_DIRECTION_BOTH)) {

        DpPolicySetLastErrorMessage(L"Network rule is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&message, sizeof(message));
    message.Version = DP_NETWORK_RULE_MESSAGE_VERSION;
    message.RuleId = Rule->RuleId;
    message.Kind = Rule->Kind;
    message.Action = Rule->Action;
    message.Protocol = Rule->Protocol;
    message.Direction = Rule->Direction;
    message.LocalAddress = Rule->LocalAddress;
    message.LocalAddressMask = Rule->LocalAddressMask;
    message.RemoteAddress = Rule->RemoteAddress;
    message.RemoteAddressMask = Rule->RemoteAddressMask;
    message.LocalPort = Rule->LocalPort;
    message.RemotePort = Rule->RemotePort;

    if (Rule->Domain != NULL) {
        domainLength = wcslen(Rule->Domain);
    }

    if (Rule->Kind == DP_POLICY_API_NETWORK_RULE_DOMAIN && domainLength == 0) {
        DpPolicySetLastErrorMessage(L"Domain network rules require a domain name.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (Rule->Kind == DP_POLICY_API_NETWORK_RULE_DOMAIN &&
        Rule->Protocol == DP_POLICY_API_NETWORK_PROTOCOL_ICMP) {

        DpPolicySetLastErrorMessage(L"Domain network rules do not support ICMP.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (domainLength * sizeof(WCHAR) > DP_POLICY_MAX_DOMAIN_BYTES) {
        DpPolicySetLastErrorMessage(L"Domain value is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    if (domainLength != 0) {
        CopyMemory(message.Domain, Rule->Domain, domainLength * sizeof(WCHAR));
        message.DomainLengthBytes = (ULONG)(domainLength * sizeof(WCHAR));
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandAddNetworkRule,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyRemoveNetworkRule(
    _In_ DWORD RuleId
    )
{
    if (RuleId == 0) {
        DpPolicySetLastErrorMessage(L"Network rule id is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandRemoveNetworkRule,
                                        &RuleId,
                                        sizeof(RuleId),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyClearNetworkRules(void)
{
    return DpPolicySendRawPolicyMessage(DpPolicyCommandClearNetworkRules,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryNetworkRules(
    _Out_writes_opt_(RuleCapacity) DP_POLICY_API_NETWORK_RULE *Rules,
    _In_ DWORD RuleCapacity,
    _Out_opt_ DWORD *RuleCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_NETWORK_RULE_QUERY_HEADER header;
    DP_NETWORK_RULE_QUERY_HEADER sizingHeader;
    PBYTE cursor;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedRuleCount = 0;
    BOOL sizingOnly = RuleCapacity == 0 && StringBufferChars == 0;

    if (RuleCount != NULL) {
        *RuleCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((RuleCapacity != 0 && Rules == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryNetworkRules,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_NETWORK_RULE_QUERY_HEADER) ||
        sizingHeader.Version != DP_NETWORK_RULE_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_NETWORK_RULE_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid network rule snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryNetworkRules,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_NETWORK_RULE_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid network rule snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_NETWORK_RULE_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_NETWORK_RULE_QUERY_VERSION) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported network rule snapshot version.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedRuleCount = header->RuleCount;

    if (RuleCount != NULL) {
        *RuleCount = returnedRuleCount;
    }

    cursor = queryBuffer + sizeof(DP_NETWORK_RULE_QUERY_HEADER);

    for (index = 0; index < returnedRuleCount; index++) {
        PDP_NETWORK_RULE_QUERY_ENTRY entry;
        DWORD domainChars;
        DWORD entryBytes;

        if ((ULONG_PTR)(cursor - queryBuffer) + DP_NETWORK_RULE_QUERY_ENTRY_HEADER_SIZE > bytesReturned) {
            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned a truncated network rule snapshot.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        entry = (PDP_NETWORK_RULE_QUERY_ENTRY)cursor;
        entryBytes = (DWORD)DP_NETWORK_RULE_QUERY_ENTRY_HEADER_SIZE + entry->DomainLengthBytes;
        if ((ULONG_PTR)(cursor - queryBuffer) + entryBytes > bytesReturned ||
            entry->DomainLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid network rule entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        domainChars = entry->DomainLengthBytes / sizeof(WCHAR);
        requiredStringChars += domainChars + 1;

        if (index < RuleCapacity && StringBuffer != NULL && copiedStringChars + domainChars + 1 <= StringBufferChars) {
            Rules[index].RuleId = entry->RuleId;
            Rules[index].Kind = entry->Kind;
            Rules[index].Action = entry->Action;
            Rules[index].Protocol = entry->Protocol;
            Rules[index].Direction = entry->Direction;
            Rules[index].LocalAddress = entry->LocalAddress;
            Rules[index].LocalAddressMask = entry->LocalAddressMask;
            Rules[index].RemoteAddress = entry->RemoteAddress;
            Rules[index].RemoteAddressMask = entry->RemoteAddressMask;
            Rules[index].LocalPort = entry->LocalPort;
            Rules[index].RemotePort = entry->RemotePort;
            Rules[index].Domain = StringBuffer + copiedStringChars;
            if (domainChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry->Domain, entry->DomainLengthBytes);
                copiedStringChars += domainChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }

        cursor += entryBytes;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (RuleCapacity < returnedRuleCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQuerySmtpEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_SMTP_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_SMTP_EVENT_QUERY_HEADER header;
    DP_SMTP_EVENT_QUERY_HEADER sizingHeader;
    PDP_SMTP_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQuerySmtpEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_SMTP_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_SMTP_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_SMTP_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid SMTP event snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_SMTP_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"SMTP event snapshot is too large.");
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired = sizingHeader.EventCount * DP_SMTP_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_SMTP_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"SMTP event snapshot is too large.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired = sizingHeader.EventCount * DP_SMTP_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_SMTP_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"SMTP event snapshot is too large.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars < sizingHeader.EventCount * DP_SMTP_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQuerySmtpEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_SMTP_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid SMTP event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_SMTP_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_SMTP_EVENT_QUERY_VERSION ||
        (header->EventCount > (MAXDWORD - sizeof(DP_SMTP_EVENT_QUERY_HEADER)) / sizeof(DP_SMTP_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_SMTP_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_SMTP_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported SMTP event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;

    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_SMTP_EVENT_QUERY_ENTRY)(queryBuffer + sizeof(DP_SMTP_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD fromChars;
        DWORD toChars;

        if (entry[index].FromLengthBytes > sizeof(entry[index].From) ||
            entry[index].ToLengthBytes > sizeof(entry[index].To) ||
            entry[index].FromLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].ToLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid SMTP event entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        fromChars = entry[index].FromLengthBytes / sizeof(WCHAR);
        toChars = entry[index].ToLengthBytes / sizeof(WCHAR);
        requiredStringChars += fromChars + 1 + toChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + fromChars + 1 + toChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].LocalAddress = entry[index].LocalAddress;
            Events[index].RemoteAddress = entry[index].RemoteAddress;
            Events[index].LocalPort = entry[index].LocalPort;
            Events[index].RemotePort = entry[index].RemotePort;

            Events[index].From = StringBuffer + copiedStringChars;
            if (fromChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].From, entry[index].FromLengthBytes);
                copiedStringChars += fromChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].To = StringBuffer + copiedStringChars;
            if (toChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].To, entry[index].ToLengthBytes);
                copiedStringChars += toChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQueryNetworkConnectionEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_NETWORK_CONNECTION_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_NETWORK_CONNECTION_EVENT_QUERY_HEADER header;
    DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER sizingHeader;
    PDP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryNetworkConnectionEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid network connection event snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_NETWORK_CONNECTION_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"Network connection event snapshot is too large.");
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired =
                sizingHeader.EventCount * DP_NETWORK_CONNECTION_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_NETWORK_CONNECTION_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"Network connection event snapshot is too large.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired =
            sizingHeader.EventCount * DP_NETWORK_CONNECTION_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_NETWORK_CONNECTION_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Network connection event snapshot is too large.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars <
            sizingHeader.EventCount * DP_NETWORK_CONNECTION_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryNetworkConnectionEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid network connection event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION ||
        (header->EventCount >
            (MAXDWORD - sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)) /
                sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported network connection event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;

    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY)
        (queryBuffer + sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD processPathChars;
        DWORD domainChars;

        if (entry[index].ProcessPathLengthBytes > sizeof(entry[index].ProcessPath) ||
            entry[index].DomainLengthBytes > sizeof(entry[index].Domain) ||
            entry[index].ProcessPathLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].DomainLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid network connection event entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        processPathChars = entry[index].ProcessPathLengthBytes / sizeof(WCHAR);
        domainChars = entry[index].DomainLengthBytes / sizeof(WCHAR);
        requiredStringChars += processPathChars + 1 + domainChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + processPathChars + 1 + domainChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].Direction = entry[index].Direction;
            Events[index].Protocol = entry[index].Protocol;
            Events[index].LocalAddress = entry[index].LocalAddress;
            Events[index].RemoteAddress = entry[index].RemoteAddress;
            Events[index].Flags = entry[index].Flags;
            Events[index].LocalPort = entry[index].LocalPort;
            Events[index].RemotePort = entry[index].RemotePort;

            Events[index].ProcessPath = StringBuffer + copiedStringChars;
            if (processPathChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].ProcessPath,
                           entry[index].ProcessPathLengthBytes);
                copiedStringChars += processPathChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].Domain = StringBuffer + copiedStringChars;
            if (domainChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].Domain,
                           entry[index].DomainLengthBytes);
                copiedStringChars += domainChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyBuildWebShellRuleMessage(
    _In_z_ LPCWSTR DirectoryPath,
    _Out_ DP_WEBSHELL_RULE_MESSAGE *Message
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    size_t length;

    if (Message == NULL) {
        DpPolicySetLastErrorMessage(L"WebShell rule message is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(Message, sizeof(*Message));

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    length = wcslen(ntPath);
    if (length == 0 ||
        length * sizeof(WCHAR) > DP_WEBSHELL_MAX_PATH_BYTES ||
        length >= ARRAYSIZE(Message->Directory)) {

        HeapFree(GetProcessHeap(), 0, ntPath);
        DpPolicySetLastErrorMessage(L"Web directory path is empty or too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    Message->Version = DP_WEBSHELL_RULE_MESSAGE_VERSION;
    Message->DirectoryLengthBytes = (ULONG)(length * sizeof(WCHAR));
    CopyMemory(Message->Directory, ntPath, Message->DirectoryLengthBytes);

    HeapFree(GetProcessHeap(), 0, ntPath);
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyAddWebShellRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    DWORD result;
    DP_WEBSHELL_RULE_MESSAGE message;

    result = DpPolicyBuildWebShellRuleMessage(DirectoryPath, &message);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandAddWebShellRule,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyRemoveWebShellRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    DWORD result;
    DP_WEBSHELL_RULE_MESSAGE message;

    result = DpPolicyBuildWebShellRuleMessage(DirectoryPath, &message);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandRemoveWebShellRule,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyClearWebShellRules(void)
{
    return DpPolicySendRawPolicyMessage(DpPolicyCommandClearWebShellRules,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryWebShellRules(
    _Out_writes_opt_(RuleCapacity) DP_POLICY_API_WEBSHELL_RULE *Rules,
    _In_ DWORD RuleCapacity,
    _Out_opt_ DWORD *RuleCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_WEBSHELL_RULE_QUERY_HEADER header;
    DP_WEBSHELL_RULE_QUERY_HEADER sizingHeader;
    PBYTE cursor;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedRuleCount = 0;
    BOOL sizingOnly = RuleCapacity == 0 && StringBufferChars == 0;

    if (RuleCount != NULL) {
        *RuleCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((RuleCapacity != 0 && Rules == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryWebShellRules,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_WEBSHELL_RULE_QUERY_HEADER) ||
        sizingHeader.Version != DP_WEBSHELL_RULE_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_WEBSHELL_RULE_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell rule snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryWebShellRules,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_WEBSHELL_RULE_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell rule snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_WEBSHELL_RULE_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_WEBSHELL_RULE_QUERY_VERSION) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported WebShell rule snapshot version.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedRuleCount = header->RuleCount;

    if (RuleCount != NULL) {
        *RuleCount = returnedRuleCount;
    }

    cursor = queryBuffer + sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);

    for (index = 0; index < returnedRuleCount; index++) {
        PDP_WEBSHELL_RULE_QUERY_ENTRY entry;
        DWORD directoryChars;
        DWORD entryBytes;

        if ((ULONG_PTR)(cursor - queryBuffer) + DP_WEBSHELL_RULE_QUERY_ENTRY_HEADER_SIZE > bytesReturned) {
            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned a truncated WebShell rule snapshot.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        entry = (PDP_WEBSHELL_RULE_QUERY_ENTRY)cursor;
        entryBytes = (DWORD)DP_WEBSHELL_RULE_QUERY_ENTRY_HEADER_SIZE + entry->DirectoryLengthBytes;
        if ((ULONG_PTR)(cursor - queryBuffer) + entryBytes > bytesReturned ||
            entry->DirectoryLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell rule entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        directoryChars = entry->DirectoryLengthBytes / sizeof(WCHAR);
        requiredStringChars += directoryChars + 1;

        if (index < RuleCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + directoryChars + 1 <= StringBufferChars) {

            Rules[index].Directory = StringBuffer + copiedStringChars;
            if (directoryChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry->Directory, entry->DirectoryLengthBytes);
                copiedStringChars += directoryChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }

        cursor += entryBytes;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (RuleCapacity < returnedRuleCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQueryWebShellEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_WEBSHELL_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_WEBSHELL_EVENT_QUERY_HEADER header;
    DP_WEBSHELL_EVENT_QUERY_HEADER sizingHeader;
    PDP_WEBSHELL_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    DpPolicyTrace(L"WebShellEvents enter events=%p capacity=%lu stringBuffer=%p stringChars=%lu sizingOnly=%lu",
                  Events,
                  EventCapacity,
                  StringBuffer,
                  StringBufferChars,
                  sizingOnly);

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        DpPolicyTrace(L"WebShellEvents invalid output buffer events=%p capacity=%lu stringBuffer=%p stringChars=%lu",
                      Events,
                      EventCapacity,
                      StringBuffer,
                      StringBufferChars);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryWebShellEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        DpPolicyTrace(L"WebShellEvents sizing send failed result=0x%08lX last='%s'",
                      result,
                      gLastErrorMessage);
        return result;
    }

    DpPolicyTrace(L"WebShellEvents sizing returned bytes=%lu version=%lu events=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u",
                  bytesReturned,
                  sizingHeader.Version,
                  sizingHeader.EventCount,
                  sizingHeader.BytesRequired,
                  sizingHeader.BytesReturned,
                  sizingHeader.DroppedEvents);

    if (bytesReturned < sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_WEBSHELL_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell event snapshot header.");
        DpPolicyTrace(L"WebShellEvents invalid sizing header bytes=%lu version=%lu bytesRequired=%lu",
                      bytesReturned,
                      sizingHeader.Version,
                      sizingHeader.BytesRequired);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_WEBSHELL_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"WebShell event snapshot is too large.");
                DpPolicyTrace(L"WebShellEvents sizing-only too large events=%lu",
                              sizingHeader.EventCount);
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired = sizingHeader.EventCount * DP_WEBSHELL_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        DpPolicyTrace(L"WebShellEvents sizing-only success eventCount=%lu stringCharsRequired=%lu",
                      EventCount != NULL ? *EventCount : 0,
                      StringBufferCharsRequired != NULL ? *StringBufferCharsRequired : 0);
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_WEBSHELL_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"WebShell event snapshot is too large.");
            DpPolicyTrace(L"WebShellEvents too large before alloc events=%lu",
                          sizingHeader.EventCount);
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired = sizingHeader.EventCount * DP_WEBSHELL_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_WEBSHELL_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"WebShell event snapshot is too large.");
        DpPolicyTrace(L"WebShellEvents too large before capacity check events=%lu",
                      sizingHeader.EventCount);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars < sizingHeader.EventCount * DP_WEBSHELL_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        DpPolicyTrace(L"WebShellEvents buffer too small before drain capacity=%lu neededEvents=%lu stringChars=%lu neededStringChars=%lu",
                      EventCapacity,
                      sizingHeader.EventCount,
                      StringBufferChars,
                      sizingHeader.EventCount * DP_WEBSHELL_EVENT_STRING_CHARS);
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        DpPolicyTrace(L"WebShellEvents alloc failed bytesRequired=%lu",
                      bytesRequired);
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryWebShellEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicyTrace(L"WebShellEvents full send failed result=0x%08lX bytesRequired=%lu last='%s'",
                      result,
                      bytesRequired,
                      gLastErrorMessage);
        return result;
    }

    DpPolicyTrace(L"WebShellEvents full returned bytes=%lu requested=%lu",
                  bytesReturned,
                  bytesRequired);

    if (bytesReturned < sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell event snapshot.");
        DpPolicyTrace(L"WebShellEvents invalid full header bytes=%lu",
                      bytesReturned);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_WEBSHELL_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_WEBSHELL_EVENT_QUERY_VERSION ||
        (header->EventCount > (MAXDWORD - sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER)) / sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported WebShell event snapshot.");
        DpPolicyTrace(L"WebShellEvents unsupported snapshot version=%lu eventCount=%lu bytesReturned=%lu entrySize=%Iu",
                      header->Version,
                      header->EventCount,
                      bytesReturned,
                      sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY));
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;

    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_WEBSHELL_EVENT_QUERY_ENTRY)(queryBuffer + sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD pathChars;
        DWORD extensionChars;

        if (entry[index].PathLengthBytes > sizeof(entry[index].Path) ||
            entry[index].ExtensionLengthBytes > sizeof(entry[index].Extension) ||
            entry[index].SampleLength > sizeof(entry[index].Sample) ||
            entry[index].PathLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].ExtensionLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid WebShell event entry.");
            DpPolicyTrace(L"WebShellEvents invalid entry index=%lu pathBytes=%lu extensionBytes=%lu sample=%lu",
                          index,
                          entry[index].PathLengthBytes,
                          entry[index].ExtensionLengthBytes,
                          entry[index].SampleLength);
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        pathChars = entry[index].PathLengthBytes / sizeof(WCHAR);
        extensionChars = entry[index].ExtensionLengthBytes / sizeof(WCHAR);
        requiredStringChars += pathChars + 1 + extensionChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + pathChars + 1 + extensionChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].Severity = entry[index].Severity;
            Events[index].Operation = entry[index].Operation;
            Events[index].FileSize = entry[index].FileSize;
            Events[index].SampleLength = entry[index].SampleLength;
            CopyMemory(Events[index].Sample, entry[index].Sample, sizeof(Events[index].Sample));

            DpPolicyTrace(L"WebShellEvents copy index=%lu seq=%I64u pid=%I64u severity=%lu op=%lu fileSize=%lu sample=%lu pathBytes=%lu extensionBytes=%lu stringOffset=%lu",
                          index,
                          entry[index].Sequence,
                          entry[index].ProcessId,
                          entry[index].Severity,
                          entry[index].Operation,
                          entry[index].FileSize,
                          entry[index].SampleLength,
                          entry[index].PathLengthBytes,
                          entry[index].ExtensionLengthBytes,
                          copiedStringChars);

            Events[index].Path = StringBuffer + copiedStringChars;
            if (pathChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].Path, entry[index].PathLengthBytes);
                copiedStringChars += pathChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].Extension = StringBuffer + copiedStringChars;
            if (extensionChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].Extension, entry[index].ExtensionLengthBytes);
                copiedStringChars += extensionChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    DpPolicyTrace(L"WebShellEvents post-copy headerEvents=%lu requiredStringChars=%lu copiedStringChars=%lu eventCapacity=%lu stringChars=%lu",
                  returnedEventCount,
                  requiredStringChars,
                  copiedStringChars,
                  EventCapacity,
                  StringBufferChars);

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            DpPolicyTrace(L"WebShellEvents sizing-only post-copy success");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        DpPolicyTrace(L"WebShellEvents buffer too small after copy capacity=%lu eventCount=%lu stringChars=%lu required=%lu",
                      EventCapacity,
                      returnedEventCount,
                      StringBufferChars,
                      requiredStringChars);
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    DpPolicyTrace(L"WebShellEvents success eventCount=%lu stringCharsRequired=%lu",
                  EventCount != NULL ? *EventCount : 0,
                  StringBufferCharsRequired != NULL ? *StringBufferCharsRequired : 0);
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQueryHashProtectEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_HASH_PROTECT_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_HASH_PROTECT_EVENT_QUERY_HEADER header;
    DP_HASH_PROTECT_EVENT_QUERY_HEADER sizingHeader;
    PDP_HASH_PROTECT_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    DpPolicyTrace(L"HashProtectEvents enter events=%p capacity=%lu stringBuffer=%p stringChars=%lu sizingOnly=%lu",
                  Events,
                  EventCapacity,
                  StringBuffer,
                  StringBufferChars,
                  sizingOnly ? 1u : 0u);

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        DpPolicyTrace(L"HashProtectEvents invalid output buffer events=%p capacity=%lu stringBuffer=%p stringChars=%lu",
                      Events,
                      EventCapacity,
                      StringBuffer,
                      StringBufferChars);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryHashProtectEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        DpPolicyTrace(L"HashProtectEvents sizing send failed result=0x%08lX last='%s'",
                      result,
                      gLastErrorMessage);
        return result;
    }

    DpPolicyTrace(L"HashProtectEvents sizing returned bytes=%lu version=%lu events=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u",
                  bytesReturned,
                  sizingHeader.Version,
                  sizingHeader.EventCount,
                  sizingHeader.BytesRequired,
                  sizingHeader.BytesReturned,
                  sizingHeader.DroppedEvents);

    if (bytesReturned < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_HASH_PROTECT_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid hash protection event snapshot header.");
        DpPolicyTrace(L"HashProtectEvents invalid sizing header bytes=%lu version=%lu bytesRequired=%lu",
                      bytesReturned,
                      sizingHeader.Version,
                      sizingHeader.BytesRequired);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_HASH_PROTECT_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"Hash protection event snapshot is too large.");
                DpPolicyTrace(L"HashProtectEvents sizing-only too large events=%lu",
                              sizingHeader.EventCount);
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired = sizingHeader.EventCount * DP_HASH_PROTECT_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        DpPolicyTrace(L"HashProtectEvents sizing-only success eventCount=%lu stringCharsRequired=%lu",
                      EventCount != NULL ? *EventCount : 0,
                      StringBufferCharsRequired != NULL ? *StringBufferCharsRequired : 0);
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_HASH_PROTECT_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"Hash protection event snapshot is too large.");
            DpPolicyTrace(L"HashProtectEvents too large before alloc events=%lu",
                          sizingHeader.EventCount);
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired = sizingHeader.EventCount * DP_HASH_PROTECT_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_HASH_PROTECT_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Hash protection event snapshot is too large.");
        DpPolicyTrace(L"HashProtectEvents too large before capacity check events=%lu",
                      sizingHeader.EventCount);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars < sizingHeader.EventCount * DP_HASH_PROTECT_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        DpPolicyTrace(L"HashProtectEvents buffer too small before drain capacity=%lu neededEvents=%lu stringChars=%lu neededStringChars=%lu",
                      EventCapacity,
                      sizingHeader.EventCount,
                      StringBufferChars,
                      sizingHeader.EventCount * DP_HASH_PROTECT_EVENT_STRING_CHARS);
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        DpPolicyTrace(L"HashProtectEvents alloc failed bytesRequired=%lu",
                      bytesRequired);
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryHashProtectEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicyTrace(L"HashProtectEvents full send failed result=0x%08lX bytesRequired=%lu last='%s'",
                      result,
                      bytesRequired,
                      gLastErrorMessage);
        return result;
    }

    DpPolicyTrace(L"HashProtectEvents full returned bytes=%lu requested=%lu",
                  bytesReturned,
                  bytesRequired);

    if (bytesReturned < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid hash protection event snapshot.");
        DpPolicyTrace(L"HashProtectEvents invalid full header bytes=%lu",
                      bytesReturned);
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_HASH_PROTECT_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_HASH_PROTECT_EVENT_QUERY_VERSION ||
        (header->EventCount > (MAXDWORD - sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER)) / sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported hash protection event snapshot.");
        DpPolicyTrace(L"HashProtectEvents unsupported snapshot version=%lu eventCount=%lu bytesReturned=%lu entrySize=%Iu",
                      header->Version,
                      header->EventCount,
                      bytesReturned,
                      sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY));
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;
    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_HASH_PROTECT_EVENT_QUERY_ENTRY)(queryBuffer + sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD targetChars;
        DWORD processImageChars;

        if (entry[index].TargetLengthBytes > sizeof(entry[index].Target) ||
            entry[index].ProcessImageLengthBytes > sizeof(entry[index].ProcessImage) ||
            entry[index].TargetLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].ProcessImageLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid hash protection event entry.");
            DpPolicyTrace(L"HashProtectEvents invalid entry index=%lu targetBytes=%lu processBytes=%lu",
                          index,
                          entry[index].TargetLengthBytes,
                          entry[index].ProcessImageLengthBytes);
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        targetChars = entry[index].TargetLengthBytes / sizeof(WCHAR);
        processImageChars = entry[index].ProcessImageLengthBytes / sizeof(WCHAR);
        requiredStringChars += targetChars + 1 + processImageChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + targetChars + 1 + processImageChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].Operation = entry[index].Operation;
            Events[index].Status = entry[index].Status;
            Events[index].DesiredAccess = entry[index].DesiredAccess;

            DpPolicyTrace(L"HashProtectEvents copy index=%lu seq=%I64u pid=%I64u op=%lu status=0x%08lX access=0x%08lX targetBytes=%lu processBytes=%lu stringOffset=%lu",
                          index,
                          entry[index].Sequence,
                          entry[index].ProcessId,
                          entry[index].Operation,
                          entry[index].Status,
                          entry[index].DesiredAccess,
                          entry[index].TargetLengthBytes,
                          entry[index].ProcessImageLengthBytes,
                          copiedStringChars);

            Events[index].Target = StringBuffer + copiedStringChars;
            if (targetChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].Target, entry[index].TargetLengthBytes);
                copiedStringChars += targetChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].ProcessImage = StringBuffer + copiedStringChars;
            if (processImageChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars, entry[index].ProcessImage, entry[index].ProcessImageLengthBytes);
                copiedStringChars += processImageChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    DpPolicyTrace(L"HashProtectEvents post-copy headerEvents=%lu requiredStringChars=%lu copiedStringChars=%lu eventCapacity=%lu stringChars=%lu",
                  returnedEventCount,
                  requiredStringChars,
                  copiedStringChars,
                  EventCapacity,
                  StringBufferChars);

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        DpPolicyTrace(L"HashProtectEvents buffer too small after copy capacity=%lu eventCount=%lu stringChars=%lu required=%lu",
                      EventCapacity,
                      returnedEventCount,
                      StringBufferChars,
                      requiredStringChars);
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    DpPolicyTrace(L"HashProtectEvents success eventCount=%lu stringCharsRequired=%lu",
                  EventCount != NULL ? *EventCount : 0,
                  StringBufferCharsRequired != NULL ? *StringBufferCharsRequired : 0);
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicySetHashProtectPolicy(
    _In_ const DP_POLICY_API_HASH_PROTECT_POLICY *Policy
    )
{
    DP_HASH_PROTECT_POLICY_MESSAGE message;

    if (Policy == NULL ||
        (Policy->Flags & ~DP_HASH_PROTECT_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"Hash protection policy is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&message, sizeof(message));
    message.Version = DP_HASH_PROTECT_POLICY_VERSION;
    message.Flags = Policy->Flags;

    return DpPolicySendRawPolicyMessage(DpPolicyCommandSetHashProtectPolicy,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryHashProtectPolicy(
    _Out_ DP_POLICY_API_HASH_PROTECT_POLICY *Policy
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    DP_HASH_PROTECT_POLICY_MESSAGE message;

    if (Policy == NULL) {
        DpPolicySetLastErrorMessage(L"Hash protection policy output is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(Policy, sizeof(*Policy));
    ZeroMemory(&message, sizeof(message));

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryHashProtectPolicy,
                                          NULL,
                                          0,
                                          &message,
                                          sizeof(message),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(message) ||
        message.Version != DP_HASH_PROTECT_POLICY_VERSION ||
        (message.Flags & ~DP_HASH_PROTECT_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid hash protection policy.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    Policy->Flags = message.Flags;
    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQueryLateralDefenseEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_LATERAL_DEFENSE_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_LATERAL_DEFENSE_EVENT_QUERY_HEADER header;
    DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER sizingHeader;
    PDP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryLateralDefenseEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_LATERAL_DEFENSE_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid lateral defense event snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_LATERAL_DEFENSE_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"Lateral defense event snapshot is too large.");
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired =
                sizingHeader.EventCount * DP_LATERAL_DEFENSE_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_LATERAL_DEFENSE_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"Lateral defense event snapshot is too large.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired =
            sizingHeader.EventCount * DP_LATERAL_DEFENSE_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_LATERAL_DEFENSE_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Lateral defense event snapshot is too large.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars <
            sizingHeader.EventCount * DP_LATERAL_DEFENSE_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryLateralDefenseEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid lateral defense event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_LATERAL_DEFENSE_EVENT_QUERY_VERSION ||
        (header->EventCount >
            (MAXDWORD - sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)) /
                sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported lateral defense event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;
    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY)(queryBuffer + sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD targetChars;
        DWORD processImageChars;

        if (entry[index].TargetLengthBytes > sizeof(entry[index].Target) ||
            entry[index].ProcessImageLengthBytes > sizeof(entry[index].ProcessImage) ||
            entry[index].TargetLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].ProcessImageLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid lateral defense event entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        targetChars = entry[index].TargetLengthBytes / sizeof(WCHAR);
        processImageChars = entry[index].ProcessImageLengthBytes / sizeof(WCHAR);
        requiredStringChars += targetChars + 1 + processImageChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + targetChars + 1 + processImageChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].Operation = entry[index].Operation;
            Events[index].Status = entry[index].Status;
            Events[index].DesiredAccess = entry[index].DesiredAccess;
            Events[index].Flags = entry[index].Flags;

            Events[index].Target = StringBuffer + copiedStringChars;
            if (targetChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].Target,
                           entry[index].TargetLengthBytes);
                copiedStringChars += targetChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].ProcessImage = StringBuffer + copiedStringChars;
            if (processImageChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].ProcessImage,
                           entry[index].ProcessImageLengthBytes);
                copiedStringChars += processImageChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicySetLateralDefensePolicy(
    _In_ const DP_POLICY_API_LATERAL_DEFENSE_POLICY *Policy
    )
{
    DP_LATERAL_DEFENSE_POLICY_MESSAGE message;

    if (Policy == NULL ||
        (Policy->Flags & ~DP_LATERAL_DEFENSE_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"Lateral defense policy is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&message, sizeof(message));
    message.Version = DP_LATERAL_DEFENSE_POLICY_VERSION;
    message.Flags = Policy->Flags;

    return DpPolicySendRawPolicyMessage(DpPolicyCommandSetLateralDefensePolicy,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryLateralDefensePolicy(
    _Out_ DP_POLICY_API_LATERAL_DEFENSE_POLICY *Policy
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    DP_LATERAL_DEFENSE_POLICY_MESSAGE message;

    if (Policy == NULL) {
        DpPolicySetLastErrorMessage(L"Lateral defense policy output is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(Policy, sizeof(*Policy));
    ZeroMemory(&message, sizeof(message));

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryLateralDefensePolicy,
                                          NULL,
                                          0,
                                          &message,
                                          sizeof(message),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(message) ||
        message.Version != DP_LATERAL_DEFENSE_POLICY_VERSION ||
        (message.Flags & ~DP_LATERAL_DEFENSE_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid lateral defense policy.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    Policy->Flags = message.Flags;
    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyQueryUserHookDefenseEvents(
    _Out_writes_opt_(EventCapacity) DP_POLICY_API_USER_HOOK_DEFENSE_EVENT *Events,
    _In_ DWORD EventCapacity,
    _Out_opt_ DWORD *EventCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER header;
    DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER sizingHeader;
    PDP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY entry;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedEventCount = 0;
    BOOL sizingOnly = EventCapacity == 0 && StringBufferChars == 0;

    if (EventCount != NULL) {
        *EventCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((EventCapacity != 0 && Events == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryUserHookDefenseEvents,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER) ||
        sizingHeader.Version != DP_USER_HOOK_DEFENSE_EVENT_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid user hook defense event snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (sizingOnly) {
        if (EventCount != NULL) {
            *EventCount = sizingHeader.EventCount;
        }

        if (StringBufferCharsRequired != NULL) {
            if (sizingHeader.EventCount >
                MAXDWORD / DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS) {

                DpPolicySetLastErrorMessage(L"User hook defense event snapshot is too large.");
                return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
            }

            *StringBufferCharsRequired =
                sizingHeader.EventCount * DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS;
        }

        DpPolicySetLastErrorMessage(L"Success.");
        return DP_POLICY_API_SUCCESS;
    }

    if (EventCount != NULL) {
        *EventCount = sizingHeader.EventCount;
    }

    if (StringBufferCharsRequired != NULL) {
        if (sizingHeader.EventCount >
            MAXDWORD / DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS) {

            DpPolicySetLastErrorMessage(L"User hook defense event snapshot is too large.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        *StringBufferCharsRequired =
            sizingHeader.EventCount * DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS;
    }

    if (sizingHeader.EventCount >
        MAXDWORD / DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"User hook defense event snapshot is too large.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (EventCapacity < sizingHeader.EventCount ||
        StringBufferChars <
            sizingHeader.EventCount * DP_USER_HOOK_DEFENSE_EVENT_STRING_CHARS) {

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryUserHookDefenseEvents,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid user hook defense event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_USER_HOOK_DEFENSE_EVENT_QUERY_VERSION ||
        (header->EventCount >
            (MAXDWORD - sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)) /
                sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY)) ||
        bytesReturned < sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER) +
            header->EventCount * sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY)) {

        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported user hook defense event snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedEventCount = header->EventCount;
    if (EventCount != NULL) {
        *EventCount = returnedEventCount;
    }

    entry = (PDP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY)(queryBuffer + sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER));

    for (index = 0; index < returnedEventCount; index++) {
        DWORD targetChars;
        DWORD processImageChars;

        if (entry[index].TargetLengthBytes > sizeof(entry[index].Target) ||
            entry[index].ProcessImageLengthBytes > sizeof(entry[index].ProcessImage) ||
            entry[index].TargetLengthBytes % sizeof(WCHAR) != 0 ||
            entry[index].ProcessImageLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid user hook defense event entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        targetChars = entry[index].TargetLengthBytes / sizeof(WCHAR);
        processImageChars = entry[index].ProcessImageLengthBytes / sizeof(WCHAR);
        requiredStringChars += targetChars + 1 + processImageChars + 1;

        if (index < EventCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + targetChars + 1 + processImageChars + 1 <= StringBufferChars) {

            Events[index].Sequence = entry[index].Sequence;
            Events[index].ProcessId = entry[index].ProcessId;
            Events[index].ParentProcessId = entry[index].ParentProcessId;
            Events[index].Operation = entry[index].Operation;
            Events[index].Status = entry[index].Status;
            Events[index].Flags = entry[index].Flags;

            Events[index].Target = StringBuffer + copiedStringChars;
            if (targetChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].Target,
                           entry[index].TargetLengthBytes);
                copiedStringChars += targetChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';

            Events[index].ProcessImage = StringBuffer + copiedStringChars;
            if (processImageChars != 0) {
                CopyMemory(StringBuffer + copiedStringChars,
                           entry[index].ProcessImage,
                           entry[index].ProcessImageLengthBytes);
                copiedStringChars += processImageChars;
            }
            StringBuffer[copiedStringChars++] = L'\0';
        }
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (EventCapacity < returnedEventCount || StringBufferChars < requiredStringChars) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicySetUserHookDefensePolicy(
    _In_ const DP_POLICY_API_USER_HOOK_DEFENSE_POLICY *Policy
    )
{
    DP_USER_HOOK_DEFENSE_POLICY_MESSAGE message;
    HRESULT hr;

    if (Policy == NULL ||
        (Policy->Flags & ~DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"User hook defense policy is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&message, sizeof(message));
    message.Version = DP_USER_HOOK_DEFENSE_POLICY_VERSION;
    message.Flags = Policy->Flags;

    if (Policy->ExcludedProcessNames != NULL) {
        hr = StringCchCopyW(message.ExcludedProcessNames,
                            ARRAYSIZE(message.ExcludedProcessNames),
                            Policy->ExcludedProcessNames);
        if (FAILED(hr)) {
            DpPolicySetLastErrorMessage(L"User hook excluded process name list is too long.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        message.ExcludedProcessNamesLengthBytes =
            (ULONG)(wcslen(message.ExcludedProcessNames) * sizeof(WCHAR));
    }

    if (Policy->ExcludedProcessDirectories != NULL) {
        hr = StringCchCopyW(message.ExcludedProcessDirectories,
                            ARRAYSIZE(message.ExcludedProcessDirectories),
                            Policy->ExcludedProcessDirectories);
        if (FAILED(hr)) {
            DpPolicySetLastErrorMessage(L"User hook excluded process directory list is too long.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        message.ExcludedProcessDirectoriesLengthBytes =
            (ULONG)(wcslen(message.ExcludedProcessDirectories) * sizeof(WCHAR));
    }

    if (Policy->ExcludedProcessPaths != NULL) {
        hr = StringCchCopyW(message.ExcludedProcessPaths,
                            ARRAYSIZE(message.ExcludedProcessPaths),
                            Policy->ExcludedProcessPaths);
        if (FAILED(hr)) {
            DpPolicySetLastErrorMessage(L"User hook excluded process path list is too long.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        message.ExcludedProcessPathsLengthBytes =
            (ULONG)(wcslen(message.ExcludedProcessPaths) * sizeof(WCHAR));
    }

    if (Policy->TrustedSignerSubjects != NULL) {
        hr = StringCchCopyW(message.TrustedSignerSubjects,
                            ARRAYSIZE(message.TrustedSignerSubjects),
                            Policy->TrustedSignerSubjects);
        if (FAILED(hr)) {
            DpPolicySetLastErrorMessage(L"User hook trusted signer subject list is too long.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        message.TrustedSignerSubjectsLengthBytes =
            (ULONG)(wcslen(message.TrustedSignerSubjects) * sizeof(WCHAR));
    }

    if (Policy->RuntimeDllPath != NULL) {
        hr = StringCchCopyW(message.RuntimeDllPath,
                            ARRAYSIZE(message.RuntimeDllPath),
                            Policy->RuntimeDllPath);
        if (FAILED(hr)) {
            DpPolicySetLastErrorMessage(L"User hook runtime DLL path is too long.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        message.RuntimeDllPathLengthBytes =
            (ULONG)(wcslen(message.RuntimeDllPath) * sizeof(WCHAR));
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandSetUserHookDefensePolicy,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryUserHookDefensePolicy(
    _Out_ DP_POLICY_API_USER_HOOK_DEFENSE_POLICY *Policy
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    DP_USER_HOOK_DEFENSE_POLICY_MESSAGE message;

    if (Policy == NULL) {
        DpPolicySetLastErrorMessage(L"User hook defense policy output is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(Policy, sizeof(*Policy));
    ZeroMemory(&message, sizeof(message));

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryUserHookDefensePolicy,
                                          NULL,
                                          0,
                                          &message,
                                          sizeof(message),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(message) ||
        message.Version != DP_USER_HOOK_DEFENSE_POLICY_VERSION ||
        (message.Flags & ~DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS) != 0) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid user hook defense policy.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(gUserHookQueryExcludedProcessNames, sizeof(gUserHookQueryExcludedProcessNames));
    ZeroMemory(gUserHookQueryExcludedProcessDirectories, sizeof(gUserHookQueryExcludedProcessDirectories));
    ZeroMemory(gUserHookQueryExcludedProcessPaths, sizeof(gUserHookQueryExcludedProcessPaths));
    ZeroMemory(gUserHookQueryTrustedSignerSubjects, sizeof(gUserHookQueryTrustedSignerSubjects));
    ZeroMemory(gUserHookQueryRuntimeDllPath, sizeof(gUserHookQueryRuntimeDllPath));

    if (message.ExcludedProcessNamesLengthBytes >= sizeof(message.ExcludedProcessNames) ||
        message.ExcludedProcessDirectoriesLengthBytes >= sizeof(message.ExcludedProcessDirectories) ||
        message.ExcludedProcessPathsLengthBytes >= sizeof(message.ExcludedProcessPaths) ||
        message.TrustedSignerSubjectsLengthBytes >= sizeof(message.TrustedSignerSubjects) ||
        message.RuntimeDllPathLengthBytes >= sizeof(message.RuntimeDllPath) ||
        message.ExcludedProcessNamesLengthBytes % sizeof(WCHAR) != 0 ||
        message.ExcludedProcessDirectoriesLengthBytes % sizeof(WCHAR) != 0 ||
        message.ExcludedProcessPathsLengthBytes % sizeof(WCHAR) != 0 ||
        message.TrustedSignerSubjectsLengthBytes % sizeof(WCHAR) != 0 ||
        message.RuntimeDllPathLengthBytes % sizeof(WCHAR) != 0) {

        DpPolicySetLastErrorMessage(L"Driver returned invalid user hook defense policy strings.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (message.ExcludedProcessNamesLengthBytes != 0) {
        CopyMemory(gUserHookQueryExcludedProcessNames,
                   message.ExcludedProcessNames,
                   message.ExcludedProcessNamesLengthBytes);
    }

    if (message.ExcludedProcessDirectoriesLengthBytes != 0) {
        CopyMemory(gUserHookQueryExcludedProcessDirectories,
                   message.ExcludedProcessDirectories,
                   message.ExcludedProcessDirectoriesLengthBytes);
    }

    if (message.ExcludedProcessPathsLengthBytes != 0) {
        CopyMemory(gUserHookQueryExcludedProcessPaths,
                   message.ExcludedProcessPaths,
                   message.ExcludedProcessPathsLengthBytes);
    }

    if (message.TrustedSignerSubjectsLengthBytes != 0) {
        CopyMemory(gUserHookQueryTrustedSignerSubjects,
                   message.TrustedSignerSubjects,
                   message.TrustedSignerSubjectsLengthBytes);
    }

    if (message.RuntimeDllPathLengthBytes != 0) {
        CopyMemory(gUserHookQueryRuntimeDllPath,
                   message.RuntimeDllPath,
                   message.RuntimeDllPathLengthBytes);
    }

    Policy->Flags = message.Flags;
    Policy->ExcludedProcessNames = gUserHookQueryExcludedProcessNames;
    Policy->ExcludedProcessDirectories = gUserHookQueryExcludedProcessDirectories;
    Policy->ExcludedProcessPaths = gUserHookQueryExcludedProcessPaths;
    Policy->TrustedSignerSubjects = gUserHookQueryTrustedSignerSubjects;
    Policy->RuntimeDllPath = gUserHookQueryRuntimeDllPath;
    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyConvertDosPathToNtPath(
    _In_z_ LPCWSTR DosPath,
    _Out_writes_(NtPathChars) LPWSTR NtPath,
    _In_ DWORD NtPathChars
    )
{
    DWORD result;
    LPWSTR converted = NULL;
    HRESULT hr;

    if (NtPath == NULL || NtPathChars == 0) {
        DpPolicySetLastErrorMessage(L"Output buffer is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    NtPath[0] = L'\0';

    result = DpPolicyConvertDosPathToNtPathAlloc(DosPath, &converted);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    hr = StringCchCopyW(NtPath, NtPathChars, converted);
    HeapFree(GetProcessHeap(), 0, converted);

    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyBuildDeviceRuleMessage(
    _In_z_ LPCWSTR DeviceId,
    _In_ DWORD AllowInsert,
    _In_ DWORD AllowWrite,
    _Out_ DP_DEVICE_RULE_MESSAGE *Message
    )
{
    size_t length;

    if (DeviceId == NULL || Message == NULL) {
        DpPolicySetLastErrorMessage(L"Device rule is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    length = wcslen(DeviceId);
    if (length == 0 ||
        length >= DP_DEVICE_MAX_ID_CHARS ||
        length * sizeof(WCHAR) > DP_DEVICE_MAX_ID_BYTES) {

        DpPolicySetLastErrorMessage(L"Device id is empty or too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    ZeroMemory(Message, sizeof(*Message));
    Message->Version = DP_DEVICE_RULE_MESSAGE_VERSION;
    Message->AllowInsert = AllowInsert ? 1u : 0u;
    Message->AllowWrite = AllowWrite ? 1u : 0u;
    Message->DeviceIdLengthBytes = (ULONG)(length * sizeof(WCHAR));
    CopyMemory(Message->DeviceId, DeviceId, Message->DeviceIdLengthBytes);

    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyAddDeviceRule(
    _In_ const DP_POLICY_API_DEVICE_RULE *Rule
    )
{
    DWORD result;
    DP_DEVICE_RULE_MESSAGE message;

    if (Rule == NULL) {
        DpPolicySetLastErrorMessage(L"Device rule is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    result = DpPolicyBuildDeviceRuleMessage(Rule->DeviceId,
                                            Rule->AllowInsert,
                                            Rule->AllowWrite,
                                            &message);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandAddDeviceRule,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyRemoveDeviceRule(
    _In_z_ LPCWSTR DeviceId
    )
{
    DWORD result;
    DP_DEVICE_RULE_MESSAGE message;

    result = DpPolicyBuildDeviceRuleMessage(DeviceId, 1u, 1u, &message);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    return DpPolicySendRawPolicyMessage(DpPolicyCommandRemoveDeviceRule,
                                        &message,
                                        sizeof(message),
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyClearDeviceRules(void)
{
    return DpPolicySendRawPolicyMessage(DpPolicyCommandClearDeviceRules,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        NULL);
}

DWORD
DpPolicyQueryDeviceRules(
    _Out_writes_opt_(RuleCapacity) DP_POLICY_API_DEVICE_RULE *Rules,
    _In_ DWORD RuleCapacity,
    _Out_opt_ DWORD *RuleCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_DEVICE_RULE_QUERY_HEADER header;
    DP_DEVICE_RULE_QUERY_HEADER sizingHeader;
    PBYTE cursor;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;
    DWORD returnedRuleCount = 0;
    BOOL sizingOnly = RuleCapacity == 0 && StringBufferChars == 0;

    if (RuleCount != NULL) {
        *RuleCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((RuleCapacity != 0 && Rules == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryDeviceRules,
                                          NULL,
                                          0,
                                          &sizingHeader,
                                          sizeof(sizingHeader),
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_DEVICE_RULE_QUERY_HEADER) ||
        sizingHeader.Version != DP_DEVICE_RULE_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_DEVICE_RULE_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid device rule snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    bytesRequired = sizingHeader.BytesRequired;
    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendRawPolicyMessage(DpPolicyCommandQueryDeviceRules,
                                          NULL,
                                          0,
                                          queryBuffer,
                                          bytesRequired,
                                          &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_DEVICE_RULE_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid device rule snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_DEVICE_RULE_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_DEVICE_RULE_QUERY_VERSION) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported device rule snapshot version.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    returnedRuleCount = header->RuleCount;
    if (RuleCount != NULL) {
        *RuleCount = returnedRuleCount;
    }

    cursor = queryBuffer + sizeof(DP_DEVICE_RULE_QUERY_HEADER);
    for (index = 0; index < returnedRuleCount; index++) {
        PDP_DEVICE_RULE_QUERY_ENTRY entry;
        DWORD deviceIdChars;
        DWORD entryBytes;

        if ((ULONG_PTR)(cursor - queryBuffer) + DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE > bytesReturned) {
            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned a truncated device rule snapshot.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        entry = (PDP_DEVICE_RULE_QUERY_ENTRY)cursor;
        entryBytes = (DWORD)DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE + entry->DeviceIdLengthBytes;
        if ((ULONG_PTR)(cursor - queryBuffer) + entryBytes > bytesReturned ||
            entry->DeviceIdLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid device rule entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        deviceIdChars = entry->DeviceIdLengthBytes / sizeof(WCHAR);
        requiredStringChars += deviceIdChars + 1;

        if (index < RuleCapacity &&
            StringBuffer != NULL &&
            copiedStringChars + deviceIdChars + 1 <= StringBufferChars) {

            Rules[index].DeviceId = StringBuffer + copiedStringChars;
            Rules[index].AllowInsert = entry->AllowInsert;
            Rules[index].AllowWrite = entry->AllowWrite;
            CopyMemory(StringBuffer + copiedStringChars,
                       entry->DeviceId,
                       entry->DeviceIdLengthBytes);
            copiedStringChars += deviceIdChars;
            StringBuffer[copiedStringChars++] = L'\0';
        }

        cursor += entryBytes;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (RuleCapacity < returnedRuleCount || StringBufferChars < requiredStringChars) {
        if (sizingOnly) {
            DpPolicySetLastErrorMessage(L"Success.");
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyNormalizePhysicalDrivePath(
    _In_z_ LPCWSTR PhysicalDrivePath,
    _Out_writes_(DP_USB_METADATA_PATH_CHARS) WCHAR *NtPath,
    _Out_ PULONG NtPathLengthBytes
    )
{
    LPCWSTR source;
    size_t length;
    HRESULT hr;

    if (PhysicalDrivePath == NULL ||
        NtPath == NULL ||
        NtPathLengthBytes == NULL) {

        DpPolicySetLastErrorMessage(L"USB metadata physical drive path is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    source = PhysicalDrivePath;
    if (wcsncmp(source, L"\\\\.\\", 4) == 0) {
        source += 4;
    }

    if (wcsncmp(source, L"\\??\\", 4) == 0) {
        source += 4;
    }

    if (_wcsnicmp(source, L"PhysicalDrive", 13) != 0) {
        DpPolicySetLastErrorMessage(L"USB metadata path must target a PhysicalDrive device.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    length = wcslen(source);
    if (length == 13) {
        DpPolicySetLastErrorMessage(L"USB metadata physical drive number is missing.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (length + 4 >= DP_USB_METADATA_PATH_CHARS) {
        DpPolicySetLastErrorMessage(L"USB metadata physical drive path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    hr = StringCchPrintfW(NtPath,
                         DP_USB_METADATA_PATH_CHARS,
                         L"\\??\\%s",
                         source);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"USB metadata physical drive path conversion failed.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    *NtPathLengthBytes = (ULONG)(wcslen(NtPath) * sizeof(WCHAR));
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyParsePhysicalDriveNumber(
    _In_z_ LPCWSTR PhysicalDrivePath,
    _Out_ DWORD *DiskNumber
    )
{
    LPCWSTR source;
    WCHAR *end = NULL;
    unsigned long value;

    if (PhysicalDrivePath == NULL || DiskNumber == NULL) {
        DpPolicySetLastErrorMessage(L"USB layout physical drive path is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    source = PhysicalDrivePath;
    if (wcsncmp(source, L"\\\\.\\", 4) == 0) {
        source += 4;
    }
    if (wcsncmp(source, L"\\??\\", 4) == 0) {
        source += 4;
    }

    if (_wcsnicmp(source, L"PhysicalDrive", 13) != 0 || source[13] == L'\0') {
        DpPolicySetLastErrorMessage(L"USB layout path must target a PhysicalDrive device.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    value = wcstoul(source + 13, &end, 10);
    if (end == source + 13 || *end != L'\0' || value > 1024ul) {
        DpPolicySetLastErrorMessage(L"USB layout physical drive number is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    *DiskNumber = (DWORD)value;
    return DP_POLICY_API_SUCCESS;
}

static
HANDLE
DpPolicyOpenPhysicalDrive(
    _In_z_ LPCWSTR PhysicalDrivePath
    )
{
    HANDLE handle;

    handle = CreateFileW(PhysicalDrivePath,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot open USB physical drive");
    }

    return handle;
}

static
DWORD
DpPolicyValidateUsbPhysicalDrive(
    _In_ HANDLE DiskHandle,
    _Out_opt_ ULONGLONG *DiskSizeBytes
    )
{
    STORAGE_PROPERTY_QUERY query;
    STORAGE_DEVICE_DESCRIPTOR descriptor;
    DISK_GEOMETRY_EX geometry;
    DWORD bytesReturned = 0;

    ZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.Size = sizeof(descriptor);

    if (!DeviceIoControl(DiskHandle,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         &query,
                         sizeof(query),
                         &descriptor,
                         sizeof(descriptor),
                         &bytesReturned,
                         NULL)) {

        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot query USB physical drive bus type");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    if (descriptor.BusType != BusTypeUsb) {
        DpPolicySetLastErrorMessage(L"Refusing USB layout initialization because the physical disk is not USB.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&geometry, sizeof(geometry));
    bytesReturned = 0;
    if (!DeviceIoControl(DiskHandle,
                         IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                         NULL,
                         0,
                         &geometry,
                         sizeof(geometry),
                         &bytesReturned,
                         NULL)) {

        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot query USB physical drive size");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    if (DiskSizeBytes != NULL) {
        *DiskSizeBytes = (ULONGLONG)geometry.DiskSize.QuadPart;
    }

    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyUpdateDiskProperties(
    _In_ HANDLE DiskHandle
    )
{
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(DiskHandle,
                         IOCTL_DISK_UPDATE_PROPERTIES,
                         NULL,
                         0,
                         NULL,
                         0,
                         &bytesReturned,
                         NULL)) {

        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot refresh USB disk properties");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyLockAndDismountVolume(
    _In_z_ LPCWSTR VolumeName
    )
{
    WCHAR volumePath[MAX_PATH];
    HANDLE volumeHandle;
    DWORD bytesReturned = 0;
    HRESULT hr;

    if (VolumeName == NULL || wcslen(VolumeName) < 4) {
        return DP_POLICY_API_SUCCESS;
    }

    hr = StringCchCopyW(volumePath, ARRAYSIZE(volumePath), VolumeName);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"USB layout volume path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    if (volumePath[wcslen(volumePath) - 1] == L'\\') {
        volumePath[wcslen(volumePath) - 1] = L'\0';
    }

    volumeHandle = CreateFileW(volumePath,
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (volumeHandle == INVALID_HANDLE_VALUE) {
        return DP_POLICY_API_SUCCESS;
    }

    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_LOCK_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesReturned,
                          NULL);
    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_DISMOUNT_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesReturned,
                          NULL);
    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_UNLOCK_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesReturned,
                          NULL);

    CloseHandle(volumeHandle);
    return DP_POLICY_API_SUCCESS;
}

static
VOID
DpPolicyDismountDiskVolumes(
    _In_ DWORD DiskNumber
    )
{
    WCHAR volumeName[MAX_PATH];
    WCHAR deviceName[MAX_PATH];
    WCHAR expectedPrefix[64];
    HANDLE findHandle;
    HRESULT hr;

    hr = StringCchPrintfW(expectedPrefix,
                         ARRAYSIZE(expectedPrefix),
                         L"Harddisk%luPartition",
                         DiskNumber);
    if (FAILED(hr)) {
        return;
    }

    findHandle = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
    if (findHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        WCHAR queryName[MAX_PATH];
        size_t length = wcslen(volumeName);
        if (length == 0 || length >= ARRAYSIZE(queryName)) {
            continue;
        }

        hr = StringCchCopyW(queryName, ARRAYSIZE(queryName), volumeName);
        if (FAILED(hr)) {
            continue;
        }
        if (queryName[length - 1] == L'\\') {
            queryName[length - 1] = L'\0';
        }

        if (QueryDosDeviceW(queryName + 4, deviceName, ARRAYSIZE(deviceName)) != 0 &&
            wcsstr(deviceName, expectedPrefix) != NULL) {

            (VOID)DpPolicyLockAndDismountVolume(volumeName);
        }
    } while (FindNextVolumeW(findHandle, volumeName, ARRAYSIZE(volumeName)));

    FindVolumeClose(findHandle);
}

static
DWORD
DpPolicyCreateUsbPublicLayout(
    _In_ HANDLE DiskHandle,
    _In_ ULONGLONG PublicPartitionOffsetBytes,
    _In_ ULONGLONG PublicPartitionBytes
    )
{
    BYTE layoutBuffer[FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) + sizeof(PARTITION_INFORMATION_EX)];
    CREATE_DISK createDisk;
    PDRIVE_LAYOUT_INFORMATION_EX layout;
    PPARTITION_INFORMATION_EX partition;
    DWORD bytesReturned = 0;
    ULONG signature;

    if ((PublicPartitionOffsetBytes % 512ull) != 0 ||
        (PublicPartitionBytes % 512ull) != 0) {

        DpPolicySetLastErrorMessage(L"USB layout partition range must be sector aligned.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (PublicPartitionOffsetBytes / 512ull > 0xFFFFFFFFull) {
        DpPolicySetLastErrorMessage(L"USB layout public partition offset is not MBR-compatible.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    signature = (ULONG)GetTickCount();
    signature ^= (ULONG)(PublicPartitionOffsetBytes >> 9);
    signature ^= (ULONG)(PublicPartitionBytes >> 9);
    if (signature == 0) {
        signature = 0x44505553u;
    }

    ZeroMemory(&createDisk, sizeof(createDisk));
    createDisk.PartitionStyle = PARTITION_STYLE_MBR;
    createDisk.Mbr.Signature = signature;

    if (!DeviceIoControl(DiskHandle,
                         IOCTL_DISK_CREATE_DISK,
                         &createDisk,
                         sizeof(createDisk),
                         NULL,
                         0,
                         &bytesReturned,
                         NULL)) {

        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot initialize USB disk partition table");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    ZeroMemory(layoutBuffer, sizeof(layoutBuffer));
    layout = (PDRIVE_LAYOUT_INFORMATION_EX)layoutBuffer;
    partition = &layout->PartitionEntry[0];

    layout->PartitionStyle = PARTITION_STYLE_MBR;
    layout->PartitionCount = 1;
    layout->Mbr.Signature = signature;

    partition->PartitionStyle = PARTITION_STYLE_MBR;
    partition->StartingOffset.QuadPart = (LONGLONG)PublicPartitionOffsetBytes;
    partition->PartitionLength.QuadPart = (LONGLONG)PublicPartitionBytes;
    partition->PartitionNumber = DP_USB_LAYOUT_PUBLIC_PARTITION_NUMBER;
    partition->RewritePartition = TRUE;
    partition->Mbr.PartitionType = PublicPartitionBytes <= DP_USB_LAYOUT_SMALL_PUBLIC_MAX_BYTES ?
                                   PARTITION_FAT_16 :
                                   PARTITION_IFS;
    partition->Mbr.BootIndicator = FALSE;
    partition->Mbr.RecognizedPartition = TRUE;
    partition->Mbr.HiddenSectors = (DWORD)(PublicPartitionOffsetBytes / 512ull);

    if (!DeviceIoControl(DiskHandle,
                         IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
                         layout,
                         sizeof(layoutBuffer),
                         NULL,
                         0,
                         &bytesReturned,
                         NULL)) {

        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot write USB disk layout");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    FlushFileBuffers(DiskHandle);
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyAssignDriveLetter(
    _In_z_ LPCWSTR VolumeName,
    _In_opt_z_ LPCWSTR PreferredDriveRoot,
    _Out_writes_(DriveRootChars) LPWSTR DriveRoot,
    _In_ DWORD DriveRootChars
    )
{
    WCHAR root[4];
    WCHAR mountedVolume[MAX_PATH];
    WCHAR letter;
    HRESULT hr;
    DWORD driveType;

    if (DriveRoot == NULL || DriveRootChars < 4) {
        DpPolicySetLastErrorMessage(L"USB layout output drive root buffer is too small.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    DriveRoot[0] = L'\0';

    if (PreferredDriveRoot != NULL &&
        wcslen(PreferredDriveRoot) >= 2 &&
        PreferredDriveRoot[1] == L':') {

        root[0] = (WCHAR)towupper(PreferredDriveRoot[0]);
        root[1] = L':';
        root[2] = L'\\';
        root[3] = L'\0';

        if (GetVolumeNameForVolumeMountPointW(root, mountedVolume, ARRAYSIZE(mountedVolume)) &&
            _wcsicmp(mountedVolume, VolumeName) == 0) {

            hr = StringCchCopyW(DriveRoot, DriveRootChars, root);
            return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
        }

        driveType = GetDriveTypeW(root);
        if (driveType == DRIVE_NO_ROOT_DIR &&
            SetVolumeMountPointW(root, VolumeName)) {

            hr = StringCchCopyW(DriveRoot, DriveRootChars, root);
            return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
        }
    }

    for (letter = L'Z'; letter >= L'F'; letter--) {
        root[0] = letter;
        root[1] = L':';
        root[2] = L'\\';
        root[3] = L'\0';

        if (GetVolumeNameForVolumeMountPointW(root, mountedVolume, ARRAYSIZE(mountedVolume)) &&
            _wcsicmp(mountedVolume, VolumeName) == 0) {

            hr = StringCchCopyW(DriveRoot, DriveRootChars, root);
            return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
        }

        if (GetDriveTypeW(root) != DRIVE_NO_ROOT_DIR) {
            continue;
        }

        if (SetVolumeMountPointW(root, VolumeName)) {
            hr = StringCchCopyW(DriveRoot, DriveRootChars, root);
            return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
        }
    }

    DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot assign a drive letter to USB public partition");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

static
DWORD
DpPolicyIsSupportedPublicFileSystem(
    _In_z_ LPCWSTR FileSystem
    )
{
    if (FileSystem == NULL || FileSystem[0] == L'\0') {
        return FALSE;
    }

    return _wcsicmp(FileSystem, L"FAT") == 0 ||
           _wcsicmp(FileSystem, L"FAT16") == 0 ||
           _wcsicmp(FileSystem, L"FAT32") == 0 ||
           _wcsicmp(FileSystem, L"exFAT") == 0 ||
           _wcsicmp(FileSystem, L"NTFS") == 0;
}

static
DWORD
DpPolicyVerifyPublicToolVolume(
    _In_z_ LPCWSTR DriveRoot
    )
{
    WCHAR fileSystem[32];
    WCHAR label[MAX_PATH + 1];
    DWORD serialNumber;
    DWORD maximumComponentLength;
    DWORD fileSystemFlags;
    DWORD tries;
    DWORD lastError = ERROR_SUCCESS;

    for (tries = 0; tries < DP_USB_LAYOUT_RESCAN_TRIES; tries++) {
        ZeroMemory(fileSystem, sizeof(fileSystem));
        ZeroMemory(label, sizeof(label));
        serialNumber = 0;
        maximumComponentLength = 0;
        fileSystemFlags = 0;

        if (GetVolumeInformationW(DriveRoot,
                                  label,
                                  ARRAYSIZE(label),
                                  &serialNumber,
                                  &maximumComponentLength,
                                  &fileSystemFlags,
                                  fileSystem,
                                  ARRAYSIZE(fileSystem))) {

            if (DpPolicyIsSupportedPublicFileSystem(fileSystem)) {
                if (_wcsicmp(label, DP_USB_LAYOUT_PUBLIC_LABEL) != 0) {
                    (VOID)SetVolumeLabelW(DriveRoot, DP_USB_LAYOUT_PUBLIC_LABEL);
                }

                DpPolicyTrace(L"USB public partition verify success root=%s fs=%s label=%s",
                              DriveRoot,
                              fileSystem,
                              label);
                DpPolicySetLastErrorMessage(L"Success.");
                return DP_POLICY_API_SUCCESS;
            }

            DpPolicyTrace(L"USB public partition verify rejected root=%s fs=%s label=%s",
                          DriveRoot,
                          fileSystem,
                          label);
            DpPolicySetLastErrorMessage(L"USB public partition format verification returned an unsupported file system.");
            return DP_POLICY_API_ERROR_WINDOWS_API;
        }

        lastError = GetLastError();
        Sleep(DP_USB_LAYOUT_RESCAN_SLEEP_MS);
    }

    DpPolicySetLastErrorFromCode(lastError, L"Cannot verify formatted USB public partition");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

static
BOOLEAN __stdcall
DpPolicyFormatCallback(
    _In_ DP_FMIFS_PACKET_TYPE PacketType,
    _In_ ULONG Modifier,
    _In_opt_ PVOID PacketData
    )
{
    UNREFERENCED_PARAMETER(Modifier);

    if (InterlockedCompareExchange(&gFormatActive, 0, 0) != 0 &&
        PacketType == DpFmifsDoneWithStructure) {

        BOOLEAN succeeded = FALSE;
        if (PacketData != NULL) {
            succeeded = *((PBOOLEAN)PacketData);
        }

        InterlockedExchange(&gFormatSuccess, succeeded ? 1 : 0);
        InterlockedExchange(&gFormatCompleted, 1);
    }

    return TRUE;
}

static
DWORD
DpPolicyFormatWithFmifs(
    _In_z_ LPCWSTR DriveRoot,
    _In_z_ LPCWSTR FileSystemName,
    _In_ ULONG ClusterSize
    )
{
    HMODULE module;
    DP_FORMAT_EX formatEx;
    DWORD waitCount = 0;

    while (InterlockedCompareExchange(&gFormatLock, 1, 0) != 0) {
        if (waitCount++ >= DP_USB_LAYOUT_RESCAN_TRIES) {
            DpPolicySetLastErrorMessage(L"Another USB public partition format operation is still running.");
            return DP_POLICY_API_ERROR_WINDOWS_API;
        }

        Sleep(DP_USB_LAYOUT_RESCAN_SLEEP_MS);
    }

    module = LoadLibraryW(L"fmifs.dll");
    if (module == NULL) {
        InterlockedExchange(&gFormatLock, 0);
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot load Windows format library");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    formatEx = (DP_FORMAT_EX)GetProcAddress(module, "FormatEx");
    if (formatEx == NULL) {
        DWORD error = GetLastError();
        FreeLibrary(module);
        InterlockedExchange(&gFormatLock, 0);
        DpPolicySetLastErrorFromCode(error, L"Cannot resolve Windows FormatEx API");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    InterlockedExchange(&gFormatActive, 1);
    InterlockedExchange(&gFormatCompleted, 0);
    InterlockedExchange(&gFormatSuccess, 0);

    DpPolicyTrace(L"USB public partition FormatEx begin root=%s fs=%s cluster=%lu",
                  DriveRoot,
                  FileSystemName,
                  ClusterSize);

    formatEx((PWSTR)DriveRoot,
             0,
             (PWSTR)FileSystemName,
             DP_USB_LAYOUT_PUBLIC_LABEL,
             TRUE,
             ClusterSize,
             DpPolicyFormatCallback);

    InterlockedExchange(&gFormatActive, 0);
    FreeLibrary(module);
    InterlockedExchange(&gFormatLock, 0);
    Sleep(DP_USB_LAYOUT_FORMAT_SLEEP_MS);

    if (InterlockedCompareExchange(&gFormatCompleted, 0, 0) != 0 &&
        InterlockedCompareExchange(&gFormatSuccess, 0, 0) != 0) {

        DpPolicyTrace(L"USB public partition FormatEx success root=%s fs=%s",
                      DriveRoot,
                      FileSystemName);
        return DP_POLICY_API_SUCCESS;
    }

    DpPolicyTrace(L"USB public partition FormatEx failed root=%s fs=%s completed=%ld success=%ld",
                  DriveRoot,
                  FileSystemName,
                  InterlockedCompareExchange(&gFormatCompleted, 0, 0),
                  InterlockedCompareExchange(&gFormatSuccess, 0, 0));

    DpPolicySetLastErrorMessage(L"Windows FormatEx reported that USB public partition formatting failed.");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

static
VOID
DpPolicyWriteLe16(
    _Out_writes_bytes_(2) BYTE *Target,
    _In_ USHORT Value
    )
{
    Target[0] = (BYTE)(Value & 0xFFu);
    Target[1] = (BYTE)((Value >> 8) & 0xFFu);
}

static
VOID
DpPolicyWriteLe32(
    _Out_writes_bytes_(4) BYTE *Target,
    _In_ ULONG Value
    )
{
    Target[0] = (BYTE)(Value & 0xFFu);
    Target[1] = (BYTE)((Value >> 8) & 0xFFu);
    Target[2] = (BYTE)((Value >> 16) & 0xFFu);
    Target[3] = (BYTE)((Value >> 24) & 0xFFu);
}

static
DWORD
DpPolicyCalculateFat16Layout(
    _In_ ULONGLONG VolumeBytes,
    _In_ ULONGLONG PartitionOffsetBytes,
    _Out_ PDP_PUBLIC_FAT16_LAYOUT Layout
    )
{
    DWORD sectorsPerClusterOptions[] = { 1u, 2u, 4u, 8u, 16u, 32u, 64u };
    DWORD totalSectors;
    DWORD index;

    if (Layout == NULL ||
        VolumeBytes < (ULONGLONG)DP_USB_LAYOUT_SECTOR_BYTES * 4096ull ||
        (VolumeBytes % DP_USB_LAYOUT_SECTOR_BYTES) != 0 ||
        VolumeBytes / DP_USB_LAYOUT_SECTOR_BYTES > 0xFFFFu) {

        DpPolicySetLastErrorMessage(L"USB public partition is not suitable for direct FAT16 formatting.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    totalSectors = (DWORD)(VolumeBytes / DP_USB_LAYOUT_SECTOR_BYTES);

    for (index = 0; index < ARRAYSIZE(sectorsPerClusterOptions); index++) {
        DWORD sectorsPerCluster = sectorsPerClusterOptions[index];
        DWORD rootSectors = ((DP_USB_LAYOUT_FAT16_ROOT_ENTRIES * 32u) + (DP_USB_LAYOUT_SECTOR_BYTES - 1u)) / DP_USB_LAYOUT_SECTOR_BYTES;
        DWORD available = totalSectors - DP_USB_LAYOUT_FAT16_RESERVED_SECTORS - rootSectors;
        DWORD fatSectors = 1;
        DWORD clusterCount = 0;
        DWORD iteration;

        for (iteration = 0; iteration < 16; iteration++) {
            DWORD dataSectors;
            DWORD requiredFatSectors;

            if (available <= fatSectors * DP_USB_LAYOUT_FAT_COUNT) {
                break;
            }

            dataSectors = available - (fatSectors * DP_USB_LAYOUT_FAT_COUNT);
            clusterCount = dataSectors / sectorsPerCluster;
            requiredFatSectors = ((clusterCount + 2u) * sizeof(USHORT) + (DP_USB_LAYOUT_SECTOR_BYTES - 1u)) / DP_USB_LAYOUT_SECTOR_BYTES;
            if (requiredFatSectors == fatSectors) {
                break;
            }

            fatSectors = requiredFatSectors;
        }

        if (clusterCount >= DP_USB_LAYOUT_FAT16_MIN_CLUSTERS &&
            clusterCount < DP_USB_LAYOUT_FAT16_MAX_CLUSTERS) {

            ZeroMemory(Layout, sizeof(*Layout));
            Layout->BytesPerSector = DP_USB_LAYOUT_SECTOR_BYTES;
            Layout->SectorsPerCluster = sectorsPerCluster;
            Layout->ReservedSectors = DP_USB_LAYOUT_FAT16_RESERVED_SECTORS;
            Layout->FatCount = DP_USB_LAYOUT_FAT_COUNT;
            Layout->RootEntryCount = DP_USB_LAYOUT_FAT16_ROOT_ENTRIES;
            Layout->RootDirectorySectors = rootSectors;
            Layout->TotalSectors = totalSectors;
            Layout->FatSectors = fatSectors;
            Layout->DataSectors = totalSectors - DP_USB_LAYOUT_FAT16_RESERVED_SECTORS - rootSectors - (fatSectors * DP_USB_LAYOUT_FAT_COUNT);
            Layout->ClusterCount = clusterCount;
            Layout->HiddenSectors = (DWORD)(PartitionOffsetBytes / DP_USB_LAYOUT_SECTOR_BYTES);
            return DP_POLICY_API_SUCCESS;
        }
    }

    DpPolicySetLastErrorMessage(L"Cannot calculate a valid FAT16 layout for the USB public partition.");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

static
VOID
DpPolicyBuildFat16BootSector(
    _In_ const DP_PUBLIC_FAT16_LAYOUT *Layout,
    _Out_writes_bytes_(DP_USB_LAYOUT_SECTOR_BYTES) BYTE *Sector
    )
{
    ZeroMemory(Sector, DP_USB_LAYOUT_SECTOR_BYTES);

    Sector[0] = 0xEB;
    Sector[1] = 0x3C;
    Sector[2] = 0x90;
    CopyMemory(&Sector[3], "MSDOS5.0", 8);
    DpPolicyWriteLe16(&Sector[11], (USHORT)Layout->BytesPerSector);
    Sector[13] = (BYTE)Layout->SectorsPerCluster;
    DpPolicyWriteLe16(&Sector[14], (USHORT)Layout->ReservedSectors);
    Sector[16] = (BYTE)Layout->FatCount;
    DpPolicyWriteLe16(&Sector[17], (USHORT)Layout->RootEntryCount);
    DpPolicyWriteLe16(&Sector[19], (USHORT)Layout->TotalSectors);
    Sector[21] = 0xF8;
    DpPolicyWriteLe16(&Sector[22], (USHORT)Layout->FatSectors);
    DpPolicyWriteLe16(&Sector[24], 32);
    DpPolicyWriteLe16(&Sector[26], 64);
    DpPolicyWriteLe32(&Sector[28], Layout->HiddenSectors);
    DpPolicyWriteLe32(&Sector[32], 0);
    Sector[36] = 0x80;
    Sector[38] = 0x29;
    DpPolicyWriteLe32(&Sector[39], GetTickCount());
    CopyMemory(&Sector[43], "DPUSB      ", 11);
    CopyMemory(&Sector[54], "FAT16   ", 8);
    Sector[510] = 0x55;
    Sector[511] = 0xAA;
}

static
DWORD
DpPolicyWritePublicVolumeSectors(
    _In_z_ LPCWSTR VolumeName,
    _In_ const DP_PUBLIC_FAT16_LAYOUT *Layout
    )
{
    WCHAR volumePath[MAX_PATH];
    HANDLE volumeHandle;
    BYTE sector[DP_USB_LAYOUT_SECTOR_BYTES];
    DWORD bytesTransferred;
    DWORD fatIndex;
    DWORD sectorIndex;
    DWORD result = DP_POLICY_API_SUCCESS;
    DWORD lastError = ERROR_SUCCESS;
    HRESULT hr;
    size_t length;

    hr = StringCchCopyW(volumePath, ARRAYSIZE(volumePath), VolumeName);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"USB public volume path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    length = wcslen(volumePath);
    if (length > 0 && volumePath[length - 1] == L'\\') {
        volumePath[length - 1] = L'\0';
    }

    volumeHandle = CreateFileW(volumePath,
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                               NULL);
    if (volumeHandle == INVALID_HANDLE_VALUE) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot open USB public volume for direct FAT formatting");
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_LOCK_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesTransferred,
                          NULL);
    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_DISMOUNT_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesTransferred,
                          NULL);

    DpPolicyBuildFat16BootSector(Layout, sector);
    if (!WriteFile(volumeHandle, sector, sizeof(sector), &bytesTransferred, NULL) ||
        bytesTransferred != sizeof(sector)) {

        lastError = GetLastError();
        result = DP_POLICY_API_ERROR_WINDOWS_API;
        goto Exit;
    }

    ZeroMemory(sector, sizeof(sector));
    sector[0] = 0xF8;
    sector[1] = 0xFF;
    sector[2] = 0xFF;
    sector[3] = 0xFF;

    for (fatIndex = 0; fatIndex < Layout->FatCount; fatIndex++) {
        LARGE_INTEGER offset;
        offset.QuadPart = ((LONGLONG)Layout->ReservedSectors +
                           ((LONGLONG)fatIndex * (LONGLONG)Layout->FatSectors)) *
                          DP_USB_LAYOUT_SECTOR_BYTES;

        if (!SetFilePointerEx(volumeHandle, offset, NULL, FILE_BEGIN)) {
            lastError = GetLastError();
            result = DP_POLICY_API_ERROR_WINDOWS_API;
            goto Exit;
        }

        for (sectorIndex = 0; sectorIndex < Layout->FatSectors; sectorIndex++) {
            if (!WriteFile(volumeHandle, sector, sizeof(sector), &bytesTransferred, NULL) ||
                bytesTransferred != sizeof(sector)) {

                lastError = GetLastError();
                result = DP_POLICY_API_ERROR_WINDOWS_API;
                goto Exit;
            }

            if (sectorIndex == 0) {
                ZeroMemory(sector, sizeof(sector));
            }
        }
    }

    {
        LARGE_INTEGER rootOffset;
        rootOffset.QuadPart = ((LONGLONG)Layout->ReservedSectors +
                               ((LONGLONG)Layout->FatCount * (LONGLONG)Layout->FatSectors)) *
                              DP_USB_LAYOUT_SECTOR_BYTES;

        if (!SetFilePointerEx(volumeHandle, rootOffset, NULL, FILE_BEGIN)) {
            lastError = GetLastError();
            result = DP_POLICY_API_ERROR_WINDOWS_API;
            goto Exit;
        }
    }

    ZeroMemory(sector, sizeof(sector));
    for (sectorIndex = 0; sectorIndex < Layout->RootDirectorySectors; sectorIndex++) {
        if (!WriteFile(volumeHandle, sector, sizeof(sector), &bytesTransferred, NULL) ||
            bytesTransferred != sizeof(sector)) {

            lastError = GetLastError();
            result = DP_POLICY_API_ERROR_WINDOWS_API;
            goto Exit;
        }
    }

    FlushFileBuffers(volumeHandle);

Exit:
    (VOID)DeviceIoControl(volumeHandle,
                          FSCTL_UNLOCK_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          &bytesTransferred,
                          NULL);
    CloseHandle(volumeHandle);

    if (result != DP_POLICY_API_SUCCESS) {
        DpPolicySetLastErrorFromCode(lastError, L"Cannot write direct FAT metadata to USB public partition");
    }

    return result;
}

static
DWORD
DpPolicyQueryVolumeLength(
    _In_z_ LPCWSTR VolumeName,
    _In_ ULONGLONG FallbackBytes,
    _Out_ ULONGLONG *VolumeBytes
    )
{
    WCHAR volumePath[MAX_PATH];
    HANDLE volumeHandle;
    GET_LENGTH_INFORMATION lengthInfo;
    DWORD bytesReturned = 0;
    HRESULT hr;
    size_t length;

    if (VolumeBytes == NULL) {
        DpPolicySetLastErrorMessage(L"USB public volume length output is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }
    *VolumeBytes = FallbackBytes;

    hr = StringCchCopyW(volumePath, ARRAYSIZE(volumePath), VolumeName);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"USB public volume path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    length = wcslen(volumePath);
    if (length > 0 && volumePath[length - 1] == L'\\') {
        volumePath[length - 1] = L'\0';
    }

    volumeHandle = CreateFileW(volumePath,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (volumeHandle == INVALID_HANDLE_VALUE) {
        DpPolicyTrace(L"USB public partition length query open failed volume=%s error=%lu",
                      VolumeName,
                      GetLastError());
        return DP_POLICY_API_SUCCESS;
    }

    ZeroMemory(&lengthInfo, sizeof(lengthInfo));
    if (DeviceIoControl(volumeHandle,
                        IOCTL_DISK_GET_LENGTH_INFO,
                        NULL,
                        0,
                        &lengthInfo,
                        sizeof(lengthInfo),
                        &bytesReturned,
                        NULL) &&
        lengthInfo.Length.QuadPart > 0) {

        *VolumeBytes = (ULONGLONG)lengthInfo.Length.QuadPart;
    } else {
        DpPolicyTrace(L"USB public partition length query failed volume=%s error=%lu fallback=%I64u",
                      VolumeName,
                      GetLastError(),
                      FallbackBytes);
    }

    CloseHandle(volumeHandle);
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyDirectFormatFat16(
    _In_z_ LPCWSTR VolumeName,
    _In_ ULONGLONG VolumeBytes,
    _In_ ULONGLONG PartitionOffsetBytes
    )
{
    DP_PUBLIC_FAT16_LAYOUT layout;
    ULONGLONG actualBytes = VolumeBytes;
    DWORD result;

    result = DpPolicyQueryVolumeLength(VolumeName,
                                       VolumeBytes,
                                       &actualBytes);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyCalculateFat16Layout(actualBytes,
                                          PartitionOffsetBytes,
                                          &layout);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    DpPolicyTrace(L"USB public partition direct FAT16 begin volume=%s bytes=%I64u spc=%lu fatSectors=%lu clusters=%lu",
                  VolumeName,
                  actualBytes,
                  layout.SectorsPerCluster,
                  layout.FatSectors,
                  layout.ClusterCount);

    result = DpPolicyWritePublicVolumeSectors(VolumeName, &layout);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    DpPolicyTrace(L"USB public partition direct FAT16 success volume=%s", VolumeName);
    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicyFormatPublicToolVolume(
    _In_z_ LPCWSTR DriveRoot,
    _In_z_ LPCWSTR VolumeName,
    _In_ ULONGLONG PublicPartitionOffsetBytes,
    _In_ ULONGLONG PublicPartitionBytes
    )
{
    DWORD result;
    DWORD verifyResult;

    UNREFERENCED_PARAMETER(VolumeName);

    if (PublicPartitionBytes <= DP_USB_LAYOUT_SMALL_PUBLIC_MAX_BYTES) {
        UNREFERENCED_PARAMETER(PublicPartitionOffsetBytes);

        verifyResult = DpPolicyVerifyPublicToolVolume(DriveRoot);
        if (verifyResult == DP_POLICY_API_SUCCESS) {
            return DP_POLICY_API_SUCCESS;
        }

        DpPolicyTrace(L"USB public partition preformatted FAT16 verify failed root=%s", DriveRoot);

        result = DpPolicyFormatWithFmifs(DriveRoot, L"FAT", 0);
        if (result == DP_POLICY_API_SUCCESS) {
            verifyResult = DpPolicyVerifyPublicToolVolume(DriveRoot);
            if (verifyResult == DP_POLICY_API_SUCCESS) {
                return DP_POLICY_API_SUCCESS;
            }
        }
    }

    result = DpPolicyFormatWithFmifs(DriveRoot, L"NTFS", 0);
    if (result == DP_POLICY_API_SUCCESS) {
        verifyResult = DpPolicyVerifyPublicToolVolume(DriveRoot);
        if (verifyResult == DP_POLICY_API_SUCCESS) {
            return DP_POLICY_API_SUCCESS;
        }
    }

    DpPolicySetLastErrorMessage(L"USB public partition formatting failed for all supported file systems.");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

static
DWORD
DpPolicyFindVolumeForDiskPartition(
    _In_ DWORD DiskNumber,
    _In_ ULONGLONG PartitionOffsetBytes,
    _Out_writes_(VolumeNameChars) LPWSTR VolumeName,
    _In_ DWORD VolumeNameChars
    )
{
    WCHAR volumeName[MAX_PATH];
    HANDLE findHandle;
    DWORD tries;
    HRESULT hr;

    if (VolumeName == NULL || VolumeNameChars == 0) {
        DpPolicySetLastErrorMessage(L"USB layout volume output is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }
    VolumeName[0] = L'\0';

    for (tries = 0; tries < DP_USB_LAYOUT_RESCAN_TRIES; tries++) {
        findHandle = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
        if (findHandle != INVALID_HANDLE_VALUE) {
            do {
                WCHAR queryName[MAX_PATH];
                BYTE extentBuffer[FIELD_OFFSET(VOLUME_DISK_EXTENTS, Extents) + sizeof(DISK_EXTENT) * 8];
                PVOLUME_DISK_EXTENTS extents;
                HANDLE volumeHandle;
                size_t length = wcslen(volumeName);
                DWORD bytesReturned = 0;
                DWORD index;
                if (length == 0 || length >= ARRAYSIZE(queryName)) {
                    continue;
                }

                hr = StringCchCopyW(queryName, ARRAYSIZE(queryName), volumeName);
                if (FAILED(hr)) {
                    continue;
                }
                if (queryName[length - 1] == L'\\') {
                    queryName[length - 1] = L'\0';
                }

                volumeHandle = CreateFileW(queryName,
                                           GENERIC_READ,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                                           NULL,
                                           OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL,
                                           NULL);
                if (volumeHandle == INVALID_HANDLE_VALUE) {
                    continue;
                }

                ZeroMemory(extentBuffer, sizeof(extentBuffer));
                if (DeviceIoControl(volumeHandle,
                                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                    NULL,
                                    0,
                                    extentBuffer,
                                    sizeof(extentBuffer),
                                    &bytesReturned,
                                    NULL)) {

                    extents = (PVOLUME_DISK_EXTENTS)extentBuffer;
                    for (index = 0; index < extents->NumberOfDiskExtents && index < 8; index++) {
                        if (extents->Extents[index].DiskNumber == DiskNumber &&
                            (ULONGLONG)extents->Extents[index].StartingOffset.QuadPart == PartitionOffsetBytes) {

                            CloseHandle(volumeHandle);
                            FindVolumeClose(findHandle);
                            hr = StringCchCopyW(VolumeName, VolumeNameChars, volumeName);
                            return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
                        }
                    }
                }

                CloseHandle(volumeHandle);
            } while (FindNextVolumeW(findHandle, volumeName, ARRAYSIZE(volumeName)));

            FindVolumeClose(findHandle);
        }

        Sleep(DP_USB_LAYOUT_RESCAN_SLEEP_MS);
    }

    DpPolicySetLastErrorMessage(L"Cannot find the USB public partition volume after layout initialization.");
    return DP_POLICY_API_ERROR_WINDOWS_API;
}

DWORD
DpPolicyInitializeUsbLayout(
    _In_z_ LPCWSTR PhysicalDrivePath,
    _In_opt_z_ LPCWSTR PreferredDriveRoot,
    _In_ ULONGLONG PublicPartitionOffsetBytes,
    _In_ ULONGLONG PublicPartitionBytes,
    _Out_writes_(DriveRootChars) LPWSTR DriveRoot,
    _In_ DWORD DriveRootChars,
    _Out_opt_ DP_POLICY_API_USB_LAYOUT_RESULT *Result
    )
{
    HANDLE diskHandle = INVALID_HANDLE_VALUE;
    DWORD result;
    DWORD diskNumber = 0;
    ULONGLONG diskSizeBytes = 0;
    WCHAR volumeName[MAX_PATH];

    DpPolicySetLastErrorMessage(L"Success.");

    if (Result != NULL) {
        ZeroMemory(Result, sizeof(*Result));
    }
    if (DriveRoot != NULL && DriveRootChars != 0) {
        DriveRoot[0] = L'\0';
    }

    if (PhysicalDrivePath == NULL ||
        DriveRoot == NULL ||
        DriveRootChars < 4 ||
        PublicPartitionOffsetBytes == 0 ||
        PublicPartitionBytes == 0) {

        DpPolicySetLastErrorMessage(L"USB layout initialization arguments are invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    result = DpPolicyParsePhysicalDriveNumber(PhysicalDrivePath, &diskNumber);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    diskHandle = DpPolicyOpenPhysicalDrive(PhysicalDrivePath);
    if (diskHandle == INVALID_HANDLE_VALUE) {
        return DP_POLICY_API_ERROR_WINDOWS_API;
    }

    result = DpPolicyValidateUsbPhysicalDrive(diskHandle, &diskSizeBytes);
    if (result != DP_POLICY_API_SUCCESS) {
        CloseHandle(diskHandle);
        return result;
    }

    if (diskSizeBytes <= PublicPartitionOffsetBytes + PublicPartitionBytes) {
        CloseHandle(diskHandle);
        DpPolicySetLastErrorMessage(L"USB disk is too small for the requested secure layout.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    DpPolicyDismountDiskVolumes(diskNumber);

    result = DpPolicyCreateUsbPublicLayout(diskHandle,
                                           PublicPartitionOffsetBytes,
                                           PublicPartitionBytes);
    if (result != DP_POLICY_API_SUCCESS) {
        CloseHandle(diskHandle);
        return result;
    }

    result = DpPolicyUpdateDiskProperties(diskHandle);
    CloseHandle(diskHandle);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    ZeroMemory(volumeName, sizeof(volumeName));
    result = DpPolicyFindVolumeForDiskPartition(diskNumber,
                                                PublicPartitionOffsetBytes,
                                                volumeName,
                                                ARRAYSIZE(volumeName));
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (PublicPartitionBytes <= DP_USB_LAYOUT_SMALL_PUBLIC_MAX_BYTES) {
        result = DpPolicyDirectFormatFat16(volumeName,
                                           PublicPartitionBytes,
                                           PublicPartitionOffsetBytes);
        if (result != DP_POLICY_API_SUCCESS) {
            return result;
        }
    }

    result = DpPolicyAssignDriveLetter(volumeName,
                                       PreferredDriveRoot,
                                       DriveRoot,
                                       DriveRootChars);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyFormatPublicToolVolume(DriveRoot,
                                            volumeName,
                                            PublicPartitionOffsetBytes,
                                            PublicPartitionBytes);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (Result != NULL) {
        Result->Status = 0;
        Result->DiskNumber = diskNumber;
        Result->DiskSizeBytes = diskSizeBytes;
        Result->PublicPartitionOffsetBytes = PublicPartitionOffsetBytes;
        Result->PublicPartitionBytes = PublicPartitionBytes;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyWriteUsbMetadata(
    _In_z_ LPCWSTR PhysicalDrivePath,
    _In_ ULONGLONG RequestedOffsetBytes,
    _In_reads_bytes_(DP_POLICY_API_USB_METADATA_BYTES) const BYTE *Metadata,
    _Out_opt_ DP_POLICY_API_USB_METADATA_WRITE_RESULT *Result
    )
{
    DP_USB_METADATA_WRITE_MESSAGE message;
    DP_USB_METADATA_WRITE_RESULT driverResult;
    ULONG bytesReturned = 0;
    ULONG pathLengthBytes = 0;
    DWORD result;
    ULONGLONG offset;

    if (Result != NULL) {
        ZeroMemory(Result, sizeof(*Result));
    }

    if (Metadata == NULL) {
        DpPolicySetLastErrorMessage(L"USB metadata buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&message, sizeof(message));
    result = DpPolicyNormalizePhysicalDrivePath(PhysicalDrivePath,
                                                message.PhysicalPath,
                                                &pathLengthBytes);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    offset = RequestedOffsetBytes == 0 ? DP_USB_METADATA_DEFAULT_OFFSET_BYTES : RequestedOffsetBytes;
    message.Version = DP_USB_METADATA_MESSAGE_VERSION;
    message.MetadataBytes = DP_USB_METADATA_BYTES;
    message.OffsetBytes = offset;
    message.PhysicalPathLengthBytes = pathLengthBytes;
    CopyMemory(message.Metadata, Metadata, DP_USB_METADATA_BYTES);

    ZeroMemory(&driverResult, sizeof(driverResult));
    result = DpPolicySendRawPolicyMessage(DpPolicyCommandWriteUsbMetadata,
                                          &message,
                                          sizeof(message),
                                          &driverResult,
                                          sizeof(driverResult),
                                          &bytesReturned);
    SecureZeroMemory(&message, sizeof(message));

    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(driverResult) ||
        driverResult.Version != DP_USB_METADATA_RESULT_VERSION) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid USB metadata write result.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (Result != NULL) {
        Result->Status = driverResult.Status;
        Result->PartitionCount = driverResult.PartitionCount;
        Result->OffsetBytes = driverResult.OffsetBytes;
        Result->DiskSizeBytes = driverResult.DiskSizeBytes;
    }

    if (driverResult.Status != 0) {
        DpPolicySetLastErrorFromCode(driverResult.Status, L"Driver rejected USB raw metadata write");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyGetLastErrorMessage(
    _Out_writes_(BufferChars) LPWSTR Buffer,
    _In_ DWORD BufferChars
    )
{
    HRESULT hr;

    if (Buffer == NULL || BufferChars == 0) {
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    hr = StringCchCopyW(Buffer, BufferChars, gLastErrorMessage[0] != L'\0' ?
                        gLastErrorMessage :
                        L"No error information is available.");

    return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
}
