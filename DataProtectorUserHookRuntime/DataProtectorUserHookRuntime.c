#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <evntprov.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>
#include <MinHook.h>

#define DP_RUNTIME_EVENT_PATH L"C:\\ProgramData\\DataProtector\\UserHookRuntimeEvents.jsonl"
#define DP_RUNTIME_POLICY_PATH L"C:\\ProgramData\\DataProtector\\UserHookRuntimePolicy.json"
#define DP_RUNTIME_MAX_TEXT 1024
#define DP_RUNTIME_MAX_POLICY_TEXT 32768
#define DP_RUNTIME_STATUS_BLOCKED 0xC0000022u
#define DP_RUNTIME_MAX_HOOKS 96
#define DP_RUNTIME_HOOK_PROBE_BYTES 32
#define DP_RUNTIME_INTEGRITY_INTERVAL_MS 1500
#define DP_RUNTIME_TAMPER_REPORT_INTERVAL_MS 30000
#define DP_RUNTIME_MEMORY_SCAN_INTERVAL_MS 10000
#define DP_RUNTIME_MEMORY_REPORT_INTERVAL_MS 60000
#define DP_RUNTIME_MEMORY_REPORT_CACHE_SIZE 128
#define DP_RUNTIME_MEMORY_SCAN_MAX_REPORTS 16
#define DP_RUNTIME_MEMORY_SAMPLE_BYTES 512

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;

typedef enum _DP_RUNTIME_PROCESS_MATCH_MODE {
    DpRuntimeMatchProcessName = 0,
    DpRuntimeMatchDirectory = 1,
    DpRuntimeMatchExactPath = 2
} DP_RUNTIME_PROCESS_MATCH_MODE;

typedef struct _DP_RUNTIME_HOOK_ENTRY {
    WCHAR ModuleName[32];
    CHAR ApiName[64];
    WCHAR DisplayName[128];
    LPVOID Target;
    LPVOID Detour;
    LPVOID *OriginalSlot;
    BYTE OriginalBytes[DP_RUNTIME_HOOK_PROBE_BYTES];
    BYTE HookBytes[DP_RUNTIME_HOOK_PROBE_BYTES];
    SIZE_T ProbeLength;
    BOOL Created;
    BOOL Enabled;
    BOOL IsNtdllSyscall;
    BOOL IsEtwSurface;
    BOOL HookBytesCaptured;
    BOOL TamperActive;
    BOOL SyscallRiskActive;
    DWORD LastReportTick;
} DP_RUNTIME_HOOK_ENTRY;

typedef enum _DP_RUNTIME_MEMORY_FINDING {
    DpRuntimeMemoryFindingPrivateExecutable = 1,
    DpRuntimeMemoryFindingRwx = 2,
    DpRuntimeMemoryFindingManualMap = 3,
    DpRuntimeMemoryFindingPrivateSyscallStub = 4
} DP_RUNTIME_MEMORY_FINDING;

typedef struct _DP_RUNTIME_MEMORY_REPORT_ENTRY {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD Finding;
    DWORD LastReportTick;
    BOOL Used;
} DP_RUNTIME_MEMORY_REPORT_ENTRY;

typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *PFN_CreateRemoteThreadEx)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
typedef BOOL (WINAPI *PFN_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD (WINAPI *PFN_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef HHOOK (WINAPI *PFN_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HHOOK (WINAPI *PFN_SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef LONG (WINAPI *PFN_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (WINAPI *PFN_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (WINAPI *PFN_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const SECURITY_ATTRIBUTES *, PHKEY, LPDWORD);
typedef LONG (WINAPI *PFN_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const SECURITY_ATTRIBUTES *, PHKEY, LPDWORD);
typedef LONG (WINAPI *PFN_RegDeleteValueW)(HKEY, LPCWSTR);
typedef LONG (WINAPI *PFN_RegDeleteValueA)(HKEY, LPCSTR);
typedef LONG (WINAPI *PFN_RegDeleteKeyW)(HKEY, LPCWSTR);
typedef LONG (WINAPI *PFN_RegDeleteKeyA)(HKEY, LPCSTR);
typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI *PFN_OpenThread)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *PFN_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef SC_HANDLE (WINAPI *PFN_CreateServiceW)(
    SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE (WINAPI *PFN_CreateServiceA)(
    SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef BOOL (WINAPI *PFN_ChangeServiceConfigW)(
    SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL (WINAPI *PFN_ChangeServiceConfigA)(
    SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
typedef BOOL (WINAPI *PFN_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR *);
typedef BOOL (WINAPI *PFN_StartServiceA)(SC_HANDLE, DWORD, LPCSTR *);
typedef BOOL (WINAPI *PFN_MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);
typedef BOOL (WINAPI *PFN_SetThreadContext)(HANDLE, const CONTEXT *);
typedef DWORD (WINAPI *PFN_ResumeThread)(HANDLE);
typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef struct _DP_RUNTIME_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} DP_RUNTIME_CLIENT_ID, *PDP_RUNTIME_CLIENT_ID;
typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PDP_RUNTIME_CLIENT_ID);
typedef NTSTATUS (NTAPI *PFN_NtOpenThread)(PHANDLE, ACCESS_MASK, PVOID, PDP_RUNTIME_CLIENT_ID);
typedef NTSTATUS (NTAPI *PFN_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *PFN_NtQueryKey)(HANDLE, INT, PVOID, ULONG, PULONG);
typedef ULONG (WINAPI *PFN_EventRegister)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
typedef ULONG (WINAPI *PFN_EventUnregister)(REGHANDLE);
typedef ULONG (WINAPI *PFN_EventWrite)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef ULONG (WINAPI *PFN_EventWriteTransfer)(REGHANDLE, PCEVENT_DESCRIPTOR, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef ULONG (WINAPI *PFN_EventWriteString)(REGHANDLE, UCHAR, ULONGLONG, PCWSTR);
typedef NTSTATUS (NTAPI *PFN_EtwEventWrite)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef NTSTATUS (NTAPI *PFN_EtwEventWriteTransfer)(REGHANDLE, PCEVENT_DESCRIPTOR, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *PFN_NtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSuspendProcess)(HANDLE);

static PFN_CreateRemoteThread gRealCreateRemoteThread;
static PFN_CreateRemoteThreadEx gRealCreateRemoteThreadEx;
static PFN_CreateProcessW gRealCreateProcessW;
static PFN_CreateProcessA gRealCreateProcessA;
static PFN_WriteProcessMemory gRealWriteProcessMemory;
static PFN_VirtualAllocEx gRealVirtualAllocEx;
static PFN_VirtualProtectEx gRealVirtualProtectEx;
static PFN_QueueUserAPC gRealQueueUserAPC;
static PFN_SetWindowsHookExW gRealSetWindowsHookExW;
static PFN_SetWindowsHookExA gRealSetWindowsHookExA;
static PFN_LoadLibraryW gRealLoadLibraryW;
static PFN_LoadLibraryA gRealLoadLibraryA;
static PFN_LoadLibraryExW gRealLoadLibraryExW;
static PFN_LoadLibraryExA gRealLoadLibraryExA;
static PFN_RegSetValueExW gRealRegSetValueExW;
static PFN_RegSetValueExA gRealRegSetValueExA;
static PFN_RegCreateKeyExW gRealRegCreateKeyExW;
static PFN_RegCreateKeyExA gRealRegCreateKeyExA;
static PFN_RegDeleteValueW gRealRegDeleteValueW;
static PFN_RegDeleteValueA gRealRegDeleteValueA;
static PFN_RegDeleteKeyW gRealRegDeleteKeyW;
static PFN_RegDeleteKeyA gRealRegDeleteKeyA;
static PFN_OpenProcess gRealOpenProcess;
static PFN_OpenThread gRealOpenThread;
static PFN_DuplicateHandle gRealDuplicateHandle;
static PFN_CreateServiceW gRealCreateServiceW;
static PFN_CreateServiceA gRealCreateServiceA;
static PFN_ChangeServiceConfigW gRealChangeServiceConfigW;
static PFN_ChangeServiceConfigA gRealChangeServiceConfigA;
static PFN_StartServiceW gRealStartServiceW;
static PFN_StartServiceA gRealStartServiceA;
static PFN_MiniDumpWriteDump gRealMiniDumpWriteDump;
static PFN_SetThreadContext gRealSetThreadContext;
static PFN_ResumeThread gRealResumeThread;
static PFN_connect gRealConnect;
static PFN_WSAConnect gRealWSAConnect;
static PFN_NtOpenProcess gRealNtOpenProcess;
static PFN_NtOpenThread gRealNtOpenThread;
static PFN_NtDuplicateObject gRealNtDuplicateObject;
static PFN_NtCreateThreadEx gRealNtCreateThreadEx;
static PFN_NtWriteVirtualMemory gRealNtWriteVirtualMemory;
static PFN_NtAllocateVirtualMemory gRealNtAllocateVirtualMemory;
static PFN_NtProtectVirtualMemory gRealNtProtectVirtualMemory;
static PFN_NtUnmapViewOfSection gRealNtUnmapViewOfSection;
static PFN_EventRegister gRealEventRegister;
static PFN_EventUnregister gRealEventUnregister;
static PFN_EventWrite gRealEventWrite;
static PFN_EventWriteTransfer gRealEventWriteTransfer;
static PFN_EventWriteString gRealEventWriteString;
static PFN_EtwEventWrite gRealEtwEventWrite;
static PFN_EtwEventWriteTransfer gRealEtwEventWriteTransfer;
static PFN_NtMapViewOfSection gRealNtMapViewOfSection;
static PFN_NtQueueApcThread gRealNtQueueApcThread;
static PFN_NtSuspendThread gRealNtSuspendThread;
static PFN_NtSuspendProcess gRealNtSuspendProcess;

static INIT_ONCE gInitializeOnce = INIT_ONCE_STATIC_INIT;
static SRWLOCK gEventLock = SRWLOCK_INIT;
static WCHAR gCurrentProcessPath[MAX_PATH * 2];
static DWORD gCurrentProcessId;
static BOOL gAuditOnly = TRUE;
static BOOL gEnabled = TRUE;
static BOOL gMonitorRuntimeApiBehavior = TRUE;
static BOOL gScanExecutableMemory = TRUE;
static BOOL gMonitorEtwTamper = TRUE;
static BOOL gMinHookInitialized;
static BOOL gHooksEnabled;
static HANDLE gInitThread;
static HANDLE gIntegrityStopEvent;
static HANDLE gIntegrityThread;
static volatile LONG gRuntimeShuttingDown;
static DP_RUNTIME_HOOK_ENTRY gHookEntries[DP_RUNTIME_MAX_HOOKS];
static DWORD gHookEntryCount;
static DP_RUNTIME_MEMORY_REPORT_ENTRY gMemoryReportCache[DP_RUNTIME_MEMORY_REPORT_CACHE_SIZE];
static DWORD gLastMemoryScanTick;
static volatile LONG gEtwUnregisterReports;
static __declspec(thread) LONG gCreateProcessCallDepth;

typedef struct _DP_RUNTIME_KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} DP_RUNTIME_KEY_NAME_INFORMATION;

static VOID
DpRuntimeWriteEvent(
    _In_z_ LPCWSTR Action,
    _In_opt_z_ LPCWSTR Target,
    _In_ DWORD Status,
    _In_ BOOL Blocked
    );

static VOID
DpRuntimeWriteBehaviorEvent(
    _In_z_ LPCWSTR Action,
    _In_opt_z_ LPCWSTR Category,
    _In_opt_z_ LPCWSTR Api,
    _In_opt_z_ LPCWSTR Target,
    _In_ DWORD Status,
    _In_ BOOL Blocked,
    _In_ DWORD TargetPid,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_opt_z_ LPCWSTR CommandLine
    );

static BOOL
DpRuntimeHookApi(
    _In_z_ LPCWSTR ModuleName,
    _In_z_ LPCSTR ApiName,
    _In_ LPVOID Detour,
    _Out_ LPVOID *Original
    );

static VOID
DpRuntimeInstallDynamicModuleHooks(
    _In_opt_z_ LPCWSTR ModuleName
    );

static BOOL
DpRuntimeReadTextFile(
    _In_z_ LPCWSTR Path,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    HANDLE file;
    LARGE_INTEGER fileSize;
    DWORD bytesToRead;
    DWORD bytesRead = 0;
    BYTE *bytes;
    int charsRead;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    file = CreateFileW(Path,
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(file, &fileSize) ||
        fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return FALSE;
    }

    bytesToRead = (DWORD)fileSize.QuadPart;
    bytes = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesToRead + 2);
    if (bytes == NULL) {
        CloseHandle(file);
        return FALSE;
    }

    if (!ReadFile(file, bytes, bytesToRead, &bytesRead, NULL)) {
        HeapFree(GetProcessHeap(), 0, bytes);
        CloseHandle(file);
        return FALSE;
    }

    CloseHandle(file);

    if (bytesRead >= sizeof(WCHAR) && bytes[0] == 0xFF && bytes[1] == 0xFE) {
        DWORD copyBytes = min(bytesRead - sizeof(WCHAR), (BufferChars - 1) * sizeof(WCHAR));
        CopyMemory(Buffer, bytes + sizeof(WCHAR), copyBytes);
        Buffer[copyBytes / sizeof(WCHAR)] = L'\0';
        HeapFree(GetProcessHeap(), 0, bytes);
        return TRUE;
    }

    if (bytesRead >= sizeof(WCHAR) && bytes[0] == 0xFE && bytes[1] == 0xFF) {
        HeapFree(GetProcessHeap(), 0, bytes);
        return FALSE;
    }

    if (bytesRead >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
        MoveMemory(bytes, bytes + 3, bytesRead - 3);
        bytesRead -= 3;
    }

    charsRead = MultiByteToWideChar(CP_UTF8,
                                    MB_ERR_INVALID_CHARS,
                                    (LPCCH)bytes,
                                    (int)bytesRead,
                                    Buffer,
                                    (int)BufferChars - 1);
    if (charsRead <= 0) {
        charsRead = MultiByteToWideChar(CP_ACP,
                                        0,
                                        (LPCCH)bytes,
                                        (int)bytesRead,
                                        Buffer,
                                        (int)BufferChars - 1);
    }

    HeapFree(GetProcessHeap(), 0, bytes);
    if (charsRead <= 0) {
        Buffer[0] = L'\0';
        return FALSE;
    }

    Buffer[charsRead] = L'\0';
    return TRUE;
}

static BOOL
DpRuntimeJsonBool(
    _In_z_ const WCHAR *Json,
    _In_z_ const WCHAR *Key,
    _In_ BOOL Fallback
    )
{
    WCHAR pattern[128];
    WCHAR *cursor;

    if (Json == NULL || Key == NULL) {
        return Fallback;
    }

    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"\"%s\"", Key))) {
        return Fallback;
    }

    cursor = wcsstr(Json, pattern);
    if (cursor == NULL) {
        return Fallback;
    }

    cursor = wcschr(cursor, L':');
    if (cursor == NULL) {
        return Fallback;
    }

    cursor++;
    while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'\r' || *cursor == L'\n') {
        cursor++;
    }

    if (_wcsnicmp(cursor, L"true", 4) == 0) {
        return TRUE;
    }

    if (_wcsnicmp(cursor, L"false", 5) == 0) {
        return FALSE;
    }

    return Fallback;
}

static BOOL
DpRuntimePathHasSuffix(
    _In_z_ const WCHAR *Path,
    _In_z_ const WCHAR *Suffix
    )
{
    size_t pathLength;
    size_t suffixLength;

    if (Path == NULL || Suffix == NULL) {
        return FALSE;
    }

    pathLength = wcslen(Path);
    suffixLength = wcslen(Suffix);
    if (suffixLength == 0 || pathLength < suffixLength) {
        return FALSE;
    }

    return _wcsicmp(Path + pathLength - suffixLength, Suffix) == 0;
}

static int
DpRuntimeHexValue(
    _In_ WCHAR Value
    )
{
    if (Value >= L'0' && Value <= L'9') {
        return (int)(Value - L'0');
    }

    if (Value >= L'a' && Value <= L'f') {
        return (int)(Value - L'a') + 10;
    }

    if (Value >= L'A' && Value <= L'F') {
        return (int)(Value - L'A') + 10;
    }

    return -1;
}

static BOOL
DpRuntimeJsonReadStringToken(
    _In_ WCHAR *StartQuote,
    _In_ WCHAR *ArrayEnd,
    _Out_writes_(TokenChars) WCHAR *Token,
    _In_ DWORD TokenChars,
    _Outptr_result_maybenull_ WCHAR **NextCursor
    )
{
    WCHAR *cursor;
    DWORD written = 0;
    BOOL escaped = FALSE;

    if (NextCursor != NULL) {
        *NextCursor = NULL;
    }

    if (StartQuote == NULL || ArrayEnd == NULL || Token == NULL || TokenChars == 0 || *StartQuote != L'"') {
        return FALSE;
    }

    cursor = StartQuote + 1;
    while (cursor < ArrayEnd) {
        WCHAR ch = *cursor++;

        if (escaped) {
            if (ch == L'n' || ch == L'r' || ch == L't') {
                ch = L' ';
            } else if (ch == L'u' && cursor + 4 <= ArrayEnd) {
                int h0 = DpRuntimeHexValue(cursor[0]);
                int h1 = DpRuntimeHexValue(cursor[1]);
                int h2 = DpRuntimeHexValue(cursor[2]);
                int h3 = DpRuntimeHexValue(cursor[3]);
                if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                    ch = (WCHAR)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                    cursor += 4;
                }
            }

            if (written + 1 < TokenChars) {
                Token[written++] = ch;
            }

            escaped = FALSE;
            continue;
        }

        if (ch == L'\\') {
            escaped = TRUE;
            continue;
        }

        if (ch == L'"') {
            Token[written] = L'\0';
            if (NextCursor != NULL) {
                *NextCursor = cursor;
            }

            return TRUE;
        }

        if (written + 1 < TokenChars) {
            Token[written++] = ch;
        }
    }

    Token[0] = L'\0';
    return FALSE;
}

static BOOL
DpRuntimeStringContainsInsensitive(
    _In_z_ const WCHAR *Value,
    _In_z_ const WCHAR *Needle
    )
{
    size_t valueLength;
    size_t needleLength;
    size_t index;

    if (Value == NULL || Needle == NULL) {
        return FALSE;
    }

    valueLength = wcslen(Value);
    needleLength = wcslen(Needle);
    if (needleLength == 0 || valueLength < needleLength) {
        return FALSE;
    }

    for (index = 0; index <= valueLength - needleLength; index++) {
        if (_wcsnicmp(Value + index, Needle, needleLength) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeJsonArrayContainsProcess(
    _In_z_ const WCHAR *Json,
    _In_z_ const WCHAR *Key,
    _In_z_ const WCHAR *ProcessPath,
    _In_ DP_RUNTIME_PROCESS_MATCH_MODE MatchMode
    )
{
    WCHAR pattern[128];
    WCHAR *cursor;
    WCHAR *arrayEnd;

    if (Json == NULL || Key == NULL || ProcessPath == NULL) {
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"\"%s\"", Key))) {
        return FALSE;
    }

    cursor = wcsstr(Json, pattern);
    if (cursor == NULL) {
        return FALSE;
    }

    cursor = wcschr(cursor, L'[');
    if (cursor == NULL) {
        return FALSE;
    }

    arrayEnd = wcschr(cursor, L']');
    if (arrayEnd == NULL) {
        return FALSE;
    }

    while (cursor < arrayEnd) {
        WCHAR *start = wcschr(cursor, L'"');
        WCHAR token[DP_RUNTIME_MAX_TEXT];
        WCHAR *nextCursor;

        if (start == NULL || start >= arrayEnd) {
            break;
        }

        if (!DpRuntimeJsonReadStringToken(start, arrayEnd, token, ARRAYSIZE(token), &nextCursor) ||
            nextCursor == NULL) {
            break;
        }

        if (token[0] != L'\0') {
            if (MatchMode == DpRuntimeMatchProcessName) {
                if (DpRuntimePathHasSuffix(ProcessPath, token)) {
                    return TRUE;
                }
            } else if (MatchMode == DpRuntimeMatchExactPath) {
                if (_wcsicmp(ProcessPath, token) == 0) {
                    return TRUE;
                }
            } else if (_wcsnicmp(ProcessPath, token, wcslen(token)) == 0) {
                WCHAR next = ProcessPath[wcslen(token)];
                if (next == L'\0' || next == L'\\' || next == L'/') {
                    return TRUE;
                }
            }
        }

        cursor = nextCursor;
    }

    return FALSE;
}

static BOOL
DpRuntimeVerifyFileSignature(
    _In_z_ const WCHAR *Path
    )
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA trustData;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = Path;

    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = WinVerifyTrust(NULL, &action, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &trustData);

    return status == ERROR_SUCCESS;
}

static BOOL
DpRuntimeGetFileSignerSubject(
    _In_z_ const WCHAR *Path,
    _Out_writes_(SubjectChars) WCHAR *Subject,
    _In_ DWORD SubjectChars
    )
{
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    DWORD signerInfoBytes = 0;
    PCMSG_SIGNER_INFO signerInfo = NULL;
    CERT_INFO certInfo;
    PCCERT_CONTEXT certContext = NULL;
    BOOL result = FALSE;

    if (Subject == NULL || SubjectChars == 0) {
        return FALSE;
    }

    Subject[0] = L'\0';

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                          Path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0,
                          NULL,
                          NULL,
                          NULL,
                          &store,
                          &message,
                          NULL)) {
        return FALSE;
    }

    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoBytes) ||
        signerInfoBytes == 0) {
        goto Cleanup;
    }

    signerInfo = (PCMSG_SIGNER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, signerInfoBytes);
    if (signerInfo == NULL) {
        goto Cleanup;
    }

    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoBytes)) {
        goto Cleanup;
    }

    ZeroMemory(&certInfo, sizeof(certInfo));
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;
    certContext = CertFindCertificateInStore(store,
                                             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                             0,
                                             CERT_FIND_SUBJECT_CERT,
                                             &certInfo,
                                             NULL);
    if (certContext == NULL) {
        goto Cleanup;
    }

    if (CertGetNameStringW(certContext,
                           CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           0,
                           NULL,
                           Subject,
                           SubjectChars) > 1) {
        result = TRUE;
    }

Cleanup:
    if (certContext != NULL) {
        CertFreeCertificateContext(certContext);
    }

    if (signerInfo != NULL) {
        HeapFree(GetProcessHeap(), 0, signerInfo);
    }

    if (message != NULL) {
        CryptMsgClose(message);
    }

    if (store != NULL) {
        CertCloseStore(store, 0);
    }

    return result;
}

static BOOL
DpRuntimeJsonArrayContainsText(
    _In_z_ const WCHAR *Json,
    _In_z_ const WCHAR *Key,
    _In_z_ const WCHAR *Value
    )
{
    WCHAR pattern[128];
    WCHAR *cursor;
    WCHAR *arrayEnd;

    if (Json == NULL || Key == NULL || Value == NULL || Value[0] == L'\0') {
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"\"%s\"", Key))) {
        return FALSE;
    }

    cursor = wcsstr(Json, pattern);
    if (cursor == NULL) {
        return FALSE;
    }

    cursor = wcschr(cursor, L'[');
    if (cursor == NULL) {
        return FALSE;
    }

    arrayEnd = wcschr(cursor, L']');
    if (arrayEnd == NULL) {
        return FALSE;
    }

    while (cursor < arrayEnd) {
        WCHAR *start = wcschr(cursor, L'"');
        WCHAR token[DP_RUNTIME_MAX_TEXT];
        WCHAR *nextCursor;

        if (start == NULL || start >= arrayEnd) {
            break;
        }

        if (!DpRuntimeJsonReadStringToken(start, arrayEnd, token, ARRAYSIZE(token), &nextCursor) ||
            nextCursor == NULL) {
            break;
        }

        if (token[0] != L'\0') {
            if (DpRuntimeStringContainsInsensitive(Value, token)) {
                return TRUE;
            }
        }

        cursor = nextCursor;
    }

    return FALSE;
}

static BOOL
DpRuntimeShouldExitBySignerPolicy(
    _In_z_ const WCHAR *Policy
    )
{
    WCHAR subject[DP_RUNTIME_MAX_TEXT];

    if (Policy == NULL ||
        !DpRuntimeGetFileSignerSubject(gCurrentProcessPath, subject, ARRAYSIZE(subject))) {
        return FALSE;
    }

    if (!DpRuntimeJsonArrayContainsText(Policy, L"trustedSignerSubjects", subject)) {
        return FALSE;
    }

    if (!DpRuntimeVerifyFileSignature(gCurrentProcessPath)) {
        DpRuntimeWriteEvent(L"userhook.runtime.policy-signer-untrusted", subject, GetLastError(), FALSE);
        return FALSE;
    }

    DpRuntimeWriteEvent(L"userhook.runtime.policy-signer-excluded", subject, ERROR_SUCCESS, FALSE);
    return TRUE;
}

static BOOL
DpRuntimeShouldExitByPolicy(VOID)
{
    WCHAR policy[DP_RUNTIME_MAX_POLICY_TEXT];

    if (!DpRuntimeReadTextFile(DP_RUNTIME_POLICY_PATH, policy, ARRAYSIZE(policy))) {
        return FALSE;
    }

    gEnabled = DpRuntimeJsonBool(policy, L"enabled", TRUE);
    gAuditOnly = DpRuntimeJsonBool(policy, L"auditOnly", TRUE);
    gMonitorRuntimeApiBehavior = DpRuntimeJsonBool(policy, L"monitorRuntimeApiBehavior", TRUE);
    gScanExecutableMemory = DpRuntimeJsonBool(policy, L"scanExecutableMemory", TRUE);
    gMonitorEtwTamper = DpRuntimeJsonBool(policy, L"monitorEtwTamper", TRUE);

    if (!gEnabled) {
        return TRUE;
    }

    if (DpRuntimeJsonArrayContainsProcess(policy, L"excludedProcessNames", gCurrentProcessPath, DpRuntimeMatchProcessName)) {
        DpRuntimeWriteEvent(L"userhook.runtime.policy-name-excluded", gCurrentProcessPath, ERROR_SUCCESS, FALSE);
        return TRUE;
    }

    if (DpRuntimeJsonArrayContainsProcess(policy, L"excludedProcessDirectories", gCurrentProcessPath, DpRuntimeMatchDirectory)) {
        DpRuntimeWriteEvent(L"userhook.runtime.policy-directory-excluded", gCurrentProcessPath, ERROR_SUCCESS, FALSE);
        return TRUE;
    }

    if (DpRuntimeJsonArrayContainsProcess(policy, L"excludedProcessPaths", gCurrentProcessPath, DpRuntimeMatchExactPath)) {
        DpRuntimeWriteEvent(L"userhook.runtime.policy-path-excluded", gCurrentProcessPath, ERROR_SUCCESS, FALSE);
        return TRUE;
    }

    return DpRuntimeShouldExitBySignerPolicy(policy);
}

static VOID
DpRuntimeEscapeJson(
    _In_opt_z_ LPCWSTR Source,
    _Out_writes_(DestinationChars) WCHAR *Destination,
    _In_ DWORD DestinationChars
    )
{
    DWORD written = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL) {
        return;
    }

    while (*Source != L'\0' && written + 2 < DestinationChars) {
        if (*Source == L'\\' || *Source == L'"') {
            Destination[written++] = L'\\';
            Destination[written++] = *Source++;
            continue;
        }

        if (*Source == L'\r' || *Source == L'\n' || *Source == L'\t') {
            Destination[written++] = L' ';
            Source++;
            continue;
        }

        Destination[written++] = *Source++;
    }

    Destination[written] = L'\0';
}

static VOID
DpRuntimeWriteEvent(
    _In_z_ LPCWSTR Action,
    _In_opt_z_ LPCWSTR Target,
    _In_ DWORD Status,
    _In_ BOOL Blocked
)
{
    DpRuntimeWriteBehaviorEvent(Action, L"behavior", NULL, Target, Status, Blocked, 0, 0, 0, NULL);
}

static VOID
DpRuntimeDebugTrace(
    _In_z_ LPCWSTR Action,
    _In_opt_z_ LPCWSTR Target,
    _In_ DWORD Status
    )
{
    WCHAR message[1024];

    if (Action == NULL) {
        return;
    }

    if (SUCCEEDED(StringCchPrintfW(message,
                                   ARRAYSIZE(message),
                                   L"DataProtector[UserHookRuntime] pid=%lu action=%s status=0x%08X process=%s target=%s\r\n",
                                   gCurrentProcessId,
                                   Action,
                                   Status,
                                   gCurrentProcessPath,
                                   Target == NULL ? L"" : Target))) {
        OutputDebugStringW(message);
    }
}

static VOID
DpRuntimeWriteBehaviorEvent(
    _In_z_ LPCWSTR Action,
    _In_opt_z_ LPCWSTR Category,
    _In_opt_z_ LPCWSTR Api,
    _In_opt_z_ LPCWSTR Target,
    _In_ DWORD Status,
    _In_ BOOL Blocked,
    _In_ DWORD TargetPid,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_opt_z_ LPCWSTR CommandLine
    )
{
    WCHAR directory[MAX_PATH];
    WCHAR processEscaped[DP_RUNTIME_MAX_TEXT * 2];
    WCHAR targetEscaped[DP_RUNTIME_MAX_TEXT * 2];
    WCHAR categoryEscaped[128];
    WCHAR apiEscaped[128];
    WCHAR commandEscaped[DP_RUNTIME_MAX_TEXT * 2];
    WCHAR line[4096];
    CHAR utf8[8192];
    HANDLE file;
    DWORD bytesWritten;
    int utf8Bytes;
    SYSTEMTIME now;

    if (Action == NULL) {
        return;
    }

    if (wcscmp(Action, L"userhook.runtime.loaded") == 0 ||
        wcscmp(Action, L"userhook.runtime.minhook-init-failed") == 0 ||
        wcscmp(Action, L"userhook.runtime.enable-hooks-failed") == 0 ||
        wcscmp(Action, L"userhook.observed.suspended-process-create") == 0 ||
        wcscmp(Action, L"userhook.observed.process-create-result") == 0 ||
        wcsstr(Action, L".blocked.") != NULL) {
        DpRuntimeDebugTrace(Action, Target, Status);
    }

    if (FAILED(StringCchCopyW(directory, ARRAYSIZE(directory), L"C:\\ProgramData\\DataProtector"))) {
        return;
    }

    CreateDirectoryW(directory, NULL);
    DpRuntimeEscapeJson(gCurrentProcessPath, processEscaped, ARRAYSIZE(processEscaped));
    DpRuntimeEscapeJson(Target, targetEscaped, ARRAYSIZE(targetEscaped));
    DpRuntimeEscapeJson(Category == NULL ? L"behavior" : Category, categoryEscaped, ARRAYSIZE(categoryEscaped));
    DpRuntimeEscapeJson(Api, apiEscaped, ARRAYSIZE(apiEscaped));
    DpRuntimeEscapeJson(CommandLine, commandEscaped, ARRAYSIZE(commandEscaped));
    GetSystemTime(&now);

    if (FAILED(StringCchPrintfW(
            line,
            ARRAYSIZE(line),
            L"{\"timestampUtc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"host\":\"%s\",\"pid\":%lu,\"targetPid\":%lu,\"action\":\"%s\",\"category\":\"%s\",\"api\":\"%s\",\"target\":\"%s\",\"processImage\":\"%s\",\"commandLine\":\"%s\",\"status\":\"0x%08X\",\"size\":%Iu,\"flags\":%lu,\"blocked\":%s}\r\n",
            now.wYear,
            now.wMonth,
            now.wDay,
            now.wHour,
            now.wMinute,
            now.wSecond,
            now.wMilliseconds,
            L"",
            gCurrentProcessId,
            TargetPid,
            Action,
            categoryEscaped,
            apiEscaped,
            targetEscaped,
            processEscaped,
            commandEscaped,
            Status,
            Size,
            Flags,
            Blocked ? L"true" : L"false"))) {
        return;
    }

    utf8Bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, ARRAYSIZE(utf8), NULL, NULL);
    if (utf8Bytes <= 1) {
        return;
    }

    AcquireSRWLockExclusive(&gEventLock);
    file = CreateFileW(DP_RUNTIME_EVENT_PATH,
                       FILE_APPEND_DATA,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file != INVALID_HANDLE_VALUE) {
        WriteFile(file, utf8, (DWORD)(utf8Bytes - 1), &bytesWritten, NULL);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&gEventLock);
}

static BOOL
DpRuntimeIsCreateProcessCallActive(VOID)
{
    return gCreateProcessCallDepth > 0;
}

static BOOL
DpRuntimeShouldBlockInjectionPrimitive(
    _In_ HANDLE ProcessHandle
    )
{
    DWORD targetPid;

    if (gAuditOnly ||
        DpRuntimeIsCreateProcessCallActive() ||
        ProcessHandle == NULL ||
        ProcessHandle == GetCurrentProcess()) {
        return FALSE;
    }

    targetPid = GetProcessId(ProcessHandle);
    return targetPid != 0 && targetPid != gCurrentProcessId;
}

static DWORD
DpRuntimeGetTargetProcessId(
    _In_opt_ HANDLE ProcessHandle
    )
{
    if (ProcessHandle == NULL) {
        return 0;
    }

    if (ProcessHandle == GetCurrentProcess()) {
        return gCurrentProcessId;
    }

    return GetProcessId(ProcessHandle);
}

static BOOL
DpRuntimeShouldBlockThreadPrimitive(
    _In_ HANDLE ThreadHandle
    )
{
    DWORD targetPid;

    if (gAuditOnly ||
        DpRuntimeIsCreateProcessCallActive() ||
        ThreadHandle == NULL) {
        return FALSE;
    }

    targetPid = GetProcessIdOfThread(ThreadHandle);
    return targetPid != 0 && targetPid != gCurrentProcessId;
}

static DWORD
DpRuntimeGetTargetThreadProcessId(
    _In_opt_ HANDLE ThreadHandle
    )
{
    if (ThreadHandle == NULL) {
        return 0;
    }

    return GetProcessIdOfThread(ThreadHandle);
}

static VOID
DpRuntimeAnsiToWide(
    _In_opt_z_ LPCSTR Source,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    int chars;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (Source == NULL || Source[0] == '\0') {
        return;
    }

    chars = MultiByteToWideChar(CP_ACP, 0, Source, -1, Buffer, (int)BufferChars);
    if (chars <= 0) {
        Buffer[0] = L'\0';
    } else {
        Buffer[BufferChars - 1] = L'\0';
    }
}

static BOOL
DpRuntimeIsSensitiveProcessAccess(
    _In_ DWORD DesiredAccess
    )
{
    const DWORD mask =
        PROCESS_TERMINATE |
        PROCESS_CREATE_THREAD |
        PROCESS_SET_SESSIONID |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_CREATE_PROCESS |
        PROCESS_SET_QUOTA |
        PROCESS_SET_INFORMATION |
        PROCESS_SUSPEND_RESUME;

    return (DesiredAccess & mask) != 0;
}

static BOOL
DpRuntimeIsSensitiveThreadAccess(
    _In_ DWORD DesiredAccess
    )
{
    const DWORD mask =
        THREAD_TERMINATE |
        THREAD_SUSPEND_RESUME |
        THREAD_SET_CONTEXT |
        THREAD_SET_INFORMATION |
        THREAD_IMPERSONATE |
        THREAD_DIRECT_IMPERSONATION;

    return (DesiredAccess & mask) != 0;
}

static BOOL
DpRuntimeDescribeHandleTarget(
    _In_opt_ HANDLE Handle,
    _Out_writes_(KindChars) WCHAR *Kind,
    _In_ DWORD KindChars,
    _Out_writes_(TargetChars) WCHAR *Target,
    _In_ DWORD TargetChars,
    _Out_opt_ DWORD *TargetPid
    )
{
    DWORD previousError;
    DWORD processId;
    DWORD threadProcessId;
    DWORD threadId;

    if (Kind != NULL && KindChars != 0) {
        Kind[0] = L'\0';
    }

    if (Target != NULL && TargetChars != 0) {
        Target[0] = L'\0';
    }

    if (TargetPid != NULL) {
        *TargetPid = 0;
    }

    if (Handle == NULL || Kind == NULL || KindChars == 0 || Target == NULL || TargetChars == 0) {
        return FALSE;
    }

    previousError = GetLastError();
    processId = GetProcessId(Handle);
    if (processId != 0) {
        (VOID)StringCchCopyW(Kind, KindChars, L"process");
        (VOID)StringCchPrintfW(Target, TargetChars, L"process pid=%lu", processId);
        if (TargetPid != NULL) {
            *TargetPid = processId;
        }

        SetLastError(previousError);
        return TRUE;
    }

    threadProcessId = GetProcessIdOfThread(Handle);
    if (threadProcessId != 0) {
        threadId = GetThreadId(Handle);
        (VOID)StringCchCopyW(Kind, KindChars, L"thread");
        (VOID)StringCchPrintfW(Target, TargetChars, L"thread pid=%lu thread=%lu", threadProcessId, threadId);
        if (TargetPid != NULL) {
            *TargetPid = threadProcessId;
        }

        SetLastError(previousError);
        return TRUE;
    }

    SetLastError(previousError);
    return FALSE;
}

static BOOL
DpRuntimeIsExecutableProtection(
    _In_ DWORD Protection
    )
{
    DWORD baseProtection = Protection & 0xFFu;
    return (baseProtection == PAGE_EXECUTE ||
            baseProtection == PAGE_EXECUTE_READ ||
            baseProtection == PAGE_EXECUTE_READWRITE ||
            baseProtection == PAGE_EXECUTE_WRITECOPY);
}

static BOOL
DpRuntimeIsWritableExecutableProtection(
    _In_ DWORD Protection
    )
{
    DWORD baseProtection = Protection & 0xFFu;
    return baseProtection == PAGE_EXECUTE_READWRITE ||
           baseProtection == PAGE_EXECUTE_WRITECOPY;
}

static WCHAR
DpRuntimeLowerWideChar(
    _In_ WCHAR Value
    )
{
    return (Value >= L'A' && Value <= L'Z') ? (WCHAR)(Value - L'A' + L'a') : Value;
}

static CHAR
DpRuntimeLowerAsciiChar(
    _In_ CHAR Value
    )
{
    return (Value >= 'A' && Value <= 'Z') ? (CHAR)(Value - 'A' + 'a') : Value;
}

static BOOL
DpRuntimeContainsWideInsensitive(
    _In_z_ LPCWSTR Text,
    _In_z_ LPCWSTR Needle
    )
{
    SIZE_T i;
    SIZE_T j;
    SIZE_T textLength;
    SIZE_T needleLength;

    if (Text == NULL || Needle == NULL) {
        return FALSE;
    }

    textLength = wcslen(Text);
    needleLength = wcslen(Needle);
    if (needleLength == 0 || textLength < needleLength) {
        return FALSE;
    }

    for (i = 0; i + needleLength <= textLength; i++) {
        for (j = 0; j < needleLength; j++) {
            if (DpRuntimeLowerWideChar(Text[i + j]) != DpRuntimeLowerWideChar(Needle[j])) {
                break;
            }
        }

        if (j == needleLength) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeContainsAsciiInsensitive(
    _In_z_ const CHAR *Text,
    _In_z_ const CHAR *Needle
    )
{
    SIZE_T i;
    SIZE_T j;
    SIZE_T textLength;
    SIZE_T needleLength;

    if (Text == NULL || Needle == NULL) {
        return FALSE;
    }

    textLength = strlen(Text);
    needleLength = strlen(Needle);
    if (needleLength == 0 || textLength < needleLength) {
        return FALSE;
    }

    for (i = 0; i + needleLength <= textLength; i++) {
        for (j = 0; j < needleLength; j++) {
            if (DpRuntimeLowerAsciiChar(Text[i + j]) != DpRuntimeLowerAsciiChar(Needle[j])) {
                break;
            }
        }

        if (j == needleLength) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeDescribeRemoteWritePayload(
    _In_reads_bytes_opt_(Size) LPCVOID Buffer,
    _In_ SIZE_T Size,
    _Out_writes_(ActionChars) WCHAR *Action,
    _In_ DWORD ActionChars,
    _Out_writes_(TargetChars) WCHAR *Target,
    _In_ DWORD TargetChars
    )
{
    BYTE sample[DP_RUNTIME_MEMORY_SAMPLE_BYTES];
    CHAR ascii[257];
    WCHAR wide[257];
    SIZE_T bytesToCopy;
    SIZE_T i;
    SIZE_T asciiChars;
    SIZE_T wideChars;
    BOOL asciiReadable;

    if (Action == NULL || Target == NULL || ActionChars == 0 || TargetChars == 0) {
        return FALSE;
    }

    Action[0] = L'\0';
    Target[0] = L'\0';
    if (Buffer == NULL || Size < 2) {
        return FALSE;
    }

    bytesToCopy = min(Size, (SIZE_T)sizeof(sample));
    __try {
        CopyMemory(sample, Buffer, bytesToCopy);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (bytesToCopy >= 2 && sample[0] == 'M' && sample[1] == 'Z') {
        if (SUCCEEDED(StringCchCopyW(Action, ActionChars, L"userhook.observed.remote-pe-image-write")) &&
            SUCCEEDED(StringCchCopyW(Target, TargetChars, L"PE image header written to remote process"))) {
            return TRUE;
        }

        return FALSE;
    }

    asciiChars = min(bytesToCopy, (SIZE_T)(ARRAYSIZE(ascii) - 1));
    asciiReadable = FALSE;
    for (i = 0; i < asciiChars; i++) {
        if (sample[i] == 0) {
            break;
        }

        if (sample[i] < 0x20 || sample[i] > 0x7E) {
            break;
        }

        ascii[i] = (CHAR)sample[i];
        asciiReadable = TRUE;
    }

    ascii[i] = '\0';
    if (asciiReadable && DpRuntimeContainsAsciiInsensitive(ascii, ".dll")) {
        if (SUCCEEDED(StringCchCopyW(Action, ActionChars, L"userhook.observed.remote-dll-path-write"))) {
            if (MultiByteToWideChar(CP_ACP, 0, ascii, -1, Target, TargetChars) > 0) {
                return TRUE;
            }

            if (SUCCEEDED(StringCchCopyW(Target, TargetChars, L"DLL path written to remote process"))) {
                return TRUE;
            }
        }

        return FALSE;
    }

    wideChars = min(bytesToCopy / sizeof(WCHAR), (SIZE_T)(ARRAYSIZE(wide) - 1));
    if (wideChars >= 4) {
        CopyMemory(wide, sample, wideChars * sizeof(WCHAR));
        wide[wideChars] = L'\0';
        if (DpRuntimeContainsWideInsensitive(wide, L".dll")) {
            if (SUCCEEDED(StringCchCopyW(Action, ActionChars, L"userhook.observed.remote-dll-path-write")) &&
                SUCCEEDED(StringCchCopyW(Target, TargetChars, wide))) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeQueryRegistryKeyPath(
    _In_ HKEY Key,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    HMODULE ntdll;
    PFN_NtQueryKey ntQueryKey;
    BYTE localBuffer[2048];
    DP_RUNTIME_KEY_NAME_INFORMATION *nameInfo;
    ULONG resultLength = 0;
    NTSTATUS status;
    SIZE_T chars;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (Key == NULL) {
        return FALSE;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return FALSE;
    }

    ntQueryKey = (PFN_NtQueryKey)GetProcAddress(ntdll, "NtQueryKey");
    if (ntQueryKey == NULL) {
        return FALSE;
    }

    status = ntQueryKey((HANDLE)Key, 3, localBuffer, sizeof(localBuffer), &resultLength);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    nameInfo = (DP_RUNTIME_KEY_NAME_INFORMATION *)localBuffer;
    chars = min(nameInfo->NameLength / sizeof(WCHAR), (SIZE_T)(BufferChars - 1));
    CopyMemory(Buffer, nameInfo->Name, chars * sizeof(WCHAR));
    Buffer[chars] = L'\0';
    return TRUE;
}

static VOID
DpRuntimeBuildRegistryValueTarget(
    _In_ HKEY Key,
    _In_opt_z_ LPCWSTR ValueName,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    DWORD length;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (!DpRuntimeQueryRegistryKeyPath(Key, Buffer, BufferChars)) {
        (VOID)StringCchCopyW(Buffer, BufferChars, L"registry");
    }

    if (ValueName != NULL && ValueName[0] != L'\0') {
        length = (DWORD)wcslen(Buffer);
        if (length + 1 < BufferChars) {
            (VOID)StringCchCatW(Buffer, BufferChars, L"\\");
            (VOID)StringCchCatW(Buffer, BufferChars, ValueName);
        }
    }
}

static VOID
DpRuntimeBuildRegistryKeyTarget(
    _In_ HKEY Key,
    _In_opt_z_ LPCWSTR SubKey,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    DWORD length;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (!DpRuntimeQueryRegistryKeyPath(Key, Buffer, BufferChars)) {
        (VOID)StringCchCopyW(Buffer, BufferChars, L"registry");
    }

    if (SubKey != NULL && SubKey[0] != L'\0') {
        length = (DWORD)wcslen(Buffer);
        if (length + 1 < BufferChars) {
            (VOID)StringCchCatW(Buffer, BufferChars, L"\\");
            (VOID)StringCchCatW(Buffer, BufferChars, SubKey);
        }
    }
}

static VOID
DpRuntimeBuildServiceTarget(
    _In_opt_ SC_HANDLE ServiceHandle,
    _In_opt_z_ LPCWSTR ServiceName,
    _In_opt_z_ LPCWSTR BinaryPath,
    _In_ DWORD ServiceType,
    _In_ DWORD StartType,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    BYTE configStorage[4096];
    QUERY_SERVICE_CONFIGW *config;
    DWORD needed = 0;
    WCHAR queriedName[256];
    WCHAR queriedBinary[DP_RUNTIME_MAX_TEXT];
    LPCWSTR name;
    LPCWSTR binary;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    queriedName[0] = L'\0';
    queriedBinary[0] = L'\0';

    name = (ServiceName != NULL && ServiceName[0] != L'\0') ? ServiceName : NULL;
    binary = (BinaryPath != NULL && BinaryPath[0] != L'\0') ? BinaryPath : NULL;

    if (ServiceHandle != NULL && (name == NULL || binary == NULL)) {
        ZeroMemory(configStorage, sizeof(configStorage));
        config = (QUERY_SERVICE_CONFIGW *)configStorage;
        if (QueryServiceConfigW(ServiceHandle, config, sizeof(configStorage), &needed)) {
            if (name == NULL && config->lpDisplayName != NULL && config->lpDisplayName[0] != L'\0') {
                (VOID)StringCchCopyW(queriedName, ARRAYSIZE(queriedName), config->lpDisplayName);
                name = queriedName;
            }

            if (binary == NULL && config->lpBinaryPathName != NULL && config->lpBinaryPathName[0] != L'\0') {
                (VOID)StringCchCopyW(queriedBinary, ARRAYSIZE(queriedBinary), config->lpBinaryPathName);
                binary = queriedBinary;
            }
        }
    }

    if (name == NULL) {
        name = L"service";
    }

    if (binary == NULL) {
        binary = L"";
    }

    if (ServiceType == SERVICE_NO_CHANGE && StartType == SERVICE_NO_CHANGE) {
        (VOID)StringCchPrintfW(Buffer,
                              BufferChars,
                              L"service=%s;bin=%s;service-control",
                              name,
                              binary);
    } else {
        (VOID)StringCchPrintfW(Buffer,
                              BufferChars,
                              L"service=%s;bin=%s;type=0x%08lX;start=0x%08lX",
                              name,
                              binary,
                              ServiceType,
                              StartType);
    }
}

static BOOL
DpRuntimeReadCodeBytes(
    _In_ LPVOID Address,
    _Out_writes_(Length) BYTE *Buffer,
    _In_ SIZE_T Length
    )
{
    __try {
        CopyMemory(Buffer, Address, Length);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ZeroMemory(Buffer, Length);
        return FALSE;
    }
}

static BOOL
DpRuntimeIsLikelySyscallStub(
    _In_reads_(Length) const BYTE *Bytes,
    _In_ SIZE_T Length
    )
{
    SIZE_T i;

    if (Bytes == NULL || Length < 8) {
        return FALSE;
    }

    for (i = 0; i + 2 < Length; i++) {
        if (Bytes[i] == 0x0F && Bytes[i + 1] == 0x05) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeIsLikelyEtwReturnPatch(
    _In_reads_(Length) const BYTE *Bytes,
    _In_ SIZE_T Length
    )
{
    if (Bytes == NULL || Length == 0) {
        return FALSE;
    }

    if (Bytes[0] == 0xC3 || Bytes[0] == 0xC2) {
        return TRUE;
    }

    if (Length >= 3 && Bytes[0] == 0x33 && Bytes[1] == 0xC0 && Bytes[2] == 0xC3) {
        return TRUE;
    }

    if (Length >= 6 &&
        Bytes[0] == 0xB8 &&
        Bytes[1] == 0x00 &&
        Bytes[2] == 0x00 &&
        Bytes[3] == 0x00 &&
        Bytes[4] == 0x00 &&
        Bytes[5] == 0xC3) {
        return TRUE;
    }

    if (Length >= 8 &&
        Bytes[0] == 0x48 &&
        Bytes[1] == 0x31 &&
        Bytes[2] == 0xC0 &&
        Bytes[3] == 0xC3) {
        return TRUE;
    }

    return FALSE;
}

static BOOL
DpRuntimeIsLikelyJumpPatch(
    _In_reads_(Length) const BYTE *Bytes,
    _In_ SIZE_T Length
    )
{
    if (Bytes == NULL || Length == 0) {
        return FALSE;
    }

    if (Bytes[0] == 0xE9 || Bytes[0] == 0xEB) {
        return TRUE;
    }

    if (Length >= 6 &&
        Bytes[0] == 0xFF &&
        Bytes[1] == 0x25) {
        return TRUE;
    }

    return FALSE;
}

static BOOL
DpRuntimeMemoryHasLikelySyscallStub(
    _In_reads_(Length) const BYTE *Bytes,
    _In_ SIZE_T Length
    )
{
    SIZE_T i;

    if (Bytes == NULL || Length < 11) {
        return FALSE;
    }

    for (i = 0; i + 11 <= Length; i++) {
        if (Bytes[i] == 0x4C &&
            Bytes[i + 1] == 0x8B &&
            Bytes[i + 2] == 0xD1 &&
            Bytes[i + 3] == 0xB8 &&
            Bytes[i + 8] == 0x0F &&
            Bytes[i + 9] == 0x05 &&
            Bytes[i + 10] == 0xC3) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeReadMemorySample(
    _In_ PVOID Address,
    _Out_writes_(Length) BYTE *Buffer,
    _In_ SIZE_T Length
    )
{
    SIZE_T bytesRead = 0;

    if (Address == NULL || Buffer == NULL || Length == 0) {
        return FALSE;
    }

    if (ReadProcessMemory(GetCurrentProcess(), Address, Buffer, Length, &bytesRead) &&
        bytesRead == Length) {
        return TRUE;
    }

    __try {
        CopyMemory(Buffer, Address, Length);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ZeroMemory(Buffer, Length);
        return FALSE;
    }
}

static BOOL
DpRuntimeSampleLooksLikePeImage(
    _In_reads_(Length) const BYTE *Bytes,
    _In_ SIZE_T Length
    )
{
    const IMAGE_DOS_HEADER *dosHeader;
    const DWORD *signature;

    if (Bytes == NULL || Length < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    dosHeader = (const IMAGE_DOS_HEADER *)Bytes;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader->e_lfanew <= 0 ||
        (SIZE_T)dosHeader->e_lfanew + sizeof(DWORD) > Length) {
        return FALSE;
    }

    signature = (const DWORD *)(const VOID *)(Bytes + dosHeader->e_lfanew);
    return *signature == IMAGE_NT_SIGNATURE;
}

static DWORD
DpRuntimeMemoryFindingSeverityRank(
    _In_ DWORD Finding
    )
{
    if (Finding == DpRuntimeMemoryFindingManualMap) {
        return 4;
    }

    if (Finding == DpRuntimeMemoryFindingRwx) {
        return 3;
    }

    if (Finding == DpRuntimeMemoryFindingPrivateSyscallStub) {
        return 2;
    }

    return 1;
}

static DWORD
DpRuntimeSelectMemoryFinding(
    _In_ DWORD ExistingFinding,
    _In_ DWORD CandidateFinding
    )
{
    if (ExistingFinding == 0 ||
        DpRuntimeMemoryFindingSeverityRank(CandidateFinding) > DpRuntimeMemoryFindingSeverityRank(ExistingFinding)) {
        return CandidateFinding;
    }

    return ExistingFinding;
}

static LPCWSTR
DpRuntimeMemoryFindingAction(
    _In_ DWORD Finding
    )
{
    if (Finding == DpRuntimeMemoryFindingManualMap) {
        return L"userhook.runtime.memory-manual-map";
    }

    if (Finding == DpRuntimeMemoryFindingRwx) {
        return L"userhook.runtime.memory-rwx";
    }

    if (Finding == DpRuntimeMemoryFindingPrivateSyscallStub) {
        return L"userhook.runtime.memory-private-syscall-stub";
    }

    return L"userhook.runtime.memory-private-executable";
}

static BOOL
DpRuntimeMemoryRegionContainsOwnHookTrampoline(
    _In_ const MEMORY_BASIC_INFORMATION *MemoryInfo
    )
{
    DWORD i;
    BYTE *regionStart;
    BYTE *regionEnd;

    if (MemoryInfo == NULL || MemoryInfo->BaseAddress == NULL || MemoryInfo->RegionSize == 0) {
        return FALSE;
    }

    regionStart = (BYTE *)MemoryInfo->BaseAddress;
    regionEnd = regionStart + MemoryInfo->RegionSize;

    for (i = 0; i < gHookEntryCount; i++) {
        LPVOID trampoline;
        DP_RUNTIME_HOOK_ENTRY *entry = &gHookEntries[i];

        if (!entry->Created || entry->OriginalSlot == NULL || *entry->OriginalSlot == NULL) {
            continue;
        }

        trampoline = *entry->OriginalSlot;
        if ((BYTE *)trampoline >= regionStart && (BYTE *)trampoline < regionEnd) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
DpRuntimeShouldReportMemoryFinding(
    _In_ PVOID BaseAddress,
    _In_ PVOID AllocationBase,
    _In_ DWORD Finding,
    _In_ DWORD NowTick
    )
{
    DWORD i;
    DWORD replacementIndex = 0;
    DWORD oldestTick = 0;

    for (i = 0; i < DP_RUNTIME_MEMORY_REPORT_CACHE_SIZE; i++) {
        DP_RUNTIME_MEMORY_REPORT_ENTRY *entry = &gMemoryReportCache[i];
        if (!entry->Used) {
            replacementIndex = i;
            oldestTick = 0;
            break;
        }

        if (entry->BaseAddress == BaseAddress &&
            entry->AllocationBase == AllocationBase &&
            entry->Finding == Finding) {
            if (NowTick - entry->LastReportTick < DP_RUNTIME_MEMORY_REPORT_INTERVAL_MS) {
                return FALSE;
            }

            entry->LastReportTick = NowTick;
            return TRUE;
        }

        if (oldestTick == 0 || entry->LastReportTick - oldestTick > 0x80000000u) {
            oldestTick = entry->LastReportTick;
            replacementIndex = i;
        }
    }

    gMemoryReportCache[replacementIndex].BaseAddress = BaseAddress;
    gMemoryReportCache[replacementIndex].AllocationBase = AllocationBase;
    gMemoryReportCache[replacementIndex].Finding = Finding;
    gMemoryReportCache[replacementIndex].LastReportTick = NowTick;
    gMemoryReportCache[replacementIndex].Used = TRUE;
    return TRUE;
}

static VOID
DpRuntimeReportMemoryFinding(
    _In_ const MEMORY_BASIC_INFORMATION *MemoryInfo,
    _In_ DWORD Finding,
    _In_ DWORD NowTick
    )
{
    WCHAR target[DP_RUNTIME_MAX_TEXT];
    SIZE_T regionSizeKb;

    if (MemoryInfo == NULL || Finding == 0) {
        return;
    }

    if (!DpRuntimeShouldReportMemoryFinding(MemoryInfo->BaseAddress,
                                            MemoryInfo->AllocationBase,
                                            Finding,
                                            NowTick)) {
        return;
    }

    regionSizeKb = (MemoryInfo->RegionSize + 1023) / 1024;
    if (FAILED(StringCchPrintfW(target,
                                ARRAYSIZE(target),
                                L"base=0x%p allocation=0x%p sizeKb=%Iu protect=0x%08X type=0x%08X state=0x%08X",
                                MemoryInfo->BaseAddress,
                                MemoryInfo->AllocationBase,
                                regionSizeKb,
                                MemoryInfo->Protect,
                                MemoryInfo->Type,
                                MemoryInfo->State))) {
        return;
    }

    DpRuntimeWriteEvent(DpRuntimeMemoryFindingAction(Finding), target, ERROR_SUCCESS, FALSE);
}

static VOID
DpRuntimeScanExecutableMemory(VOID)
{
    SYSTEM_INFO systemInfo;
    BYTE *address;
    BYTE *maximumAddress;
    DWORD nowTick = GetTickCount();
    DWORD reports = 0;

    if (!gScanExecutableMemory) {
        return;
    }

    if (gLastMemoryScanTick != 0 &&
        nowTick - gLastMemoryScanTick < DP_RUNTIME_MEMORY_SCAN_INTERVAL_MS) {
        return;
    }
    gLastMemoryScanTick = nowTick;

    GetNativeSystemInfo(&systemInfo);
    address = (BYTE *)systemInfo.lpMinimumApplicationAddress;
    maximumAddress = (BYTE *)systemInfo.lpMaximumApplicationAddress;

    while (address != NULL && address < maximumAddress) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        SIZE_T queryBytes;
        DWORD finding = 0;

        if (InterlockedCompareExchange(&gRuntimeShuttingDown, 0, 0) != 0 ||
            reports >= DP_RUNTIME_MEMORY_SCAN_MAX_REPORTS) {
            return;
        }

        queryBytes = VirtualQuery(address, &memoryInfo, sizeof(memoryInfo));
        if (queryBytes == 0) {
            address += systemInfo.dwPageSize;
            continue;
        }

        if (memoryInfo.RegionSize == 0 ||
            (BYTE *)memoryInfo.BaseAddress + memoryInfo.RegionSize <= address) {
            address += systemInfo.dwPageSize;
            continue;
        }

        address = (BYTE *)memoryInfo.BaseAddress + memoryInfo.RegionSize;

        if (memoryInfo.State != MEM_COMMIT ||
            (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 ||
            !DpRuntimeIsExecutableProtection(memoryInfo.Protect)) {
            continue;
        }

        if (DpRuntimeMemoryRegionContainsOwnHookTrampoline(&memoryInfo)) {
            continue;
        }

        if (DpRuntimeIsWritableExecutableProtection(memoryInfo.Protect)) {
            finding = DpRuntimeSelectMemoryFinding(finding, DpRuntimeMemoryFindingRwx);
        }

        if (memoryInfo.Type == MEM_PRIVATE) {
            BYTE sample[DP_RUNTIME_MEMORY_SAMPLE_BYTES];
            SIZE_T sampleLength = min((SIZE_T)memoryInfo.RegionSize, (SIZE_T)sizeof(sample));

            finding = DpRuntimeSelectMemoryFinding(finding, DpRuntimeMemoryFindingPrivateExecutable);

            if (DpRuntimeReadMemorySample(memoryInfo.BaseAddress, sample, sampleLength)) {
                if (DpRuntimeSampleLooksLikePeImage(sample, sampleLength)) {
                    finding = DpRuntimeSelectMemoryFinding(finding, DpRuntimeMemoryFindingManualMap);
                } else if (DpRuntimeMemoryHasLikelySyscallStub(sample, sampleLength)) {
                    finding = DpRuntimeSelectMemoryFinding(finding, DpRuntimeMemoryFindingPrivateSyscallStub);
                }
            }
        }

        if (finding != 0) {
            DpRuntimeReportMemoryFinding(&memoryInfo, finding, nowTick);
            reports++;
        }
    }
}

static VOID
DpRuntimeCaptureHookBytes(VOID)
{
    DWORD i;

    for (i = 0; i < gHookEntryCount; i++) {
        DP_RUNTIME_HOOK_ENTRY *entry = &gHookEntries[i];
        if (!entry->Created || entry->Target == NULL) {
            continue;
        }

        if (DpRuntimeReadCodeBytes(entry->Target, entry->HookBytes, entry->ProbeLength)) {
            entry->HookBytesCaptured = TRUE;
            entry->Enabled = TRUE;
        }
    }
}

static BOOL
DpRuntimeShouldReportHookTamper(
    _Inout_ DP_RUNTIME_HOOK_ENTRY *Entry,
    _In_ DWORD NowTick,
    _In_ BOOL IsActiveFlag
    )
{
    if (!IsActiveFlag) {
        return TRUE;
    }

    if (NowTick - Entry->LastReportTick >= DP_RUNTIME_TAMPER_REPORT_INTERVAL_MS) {
        return TRUE;
    }

    return FALSE;
}

static VOID
DpRuntimeTryRestoreHook(
    _Inout_ DP_RUNTIME_HOOK_ENTRY *Entry
    )
{
    MH_STATUS status;
    BYTE restoredBytes[DP_RUNTIME_HOOK_PROBE_BYTES];

    status = MH_DisableHook(Entry->Target);
    if (status != MH_OK && status != MH_ERROR_DISABLED) {
        Entry->Enabled = FALSE;
        DpRuntimeWriteEvent(L"userhook.runtime.unhook-restore-failed", Entry->DisplayName, (DWORD)status, TRUE);
        return;
    }

    status = MH_EnableHook(Entry->Target);
    if (status == MH_OK || status == MH_ERROR_ENABLED) {
        if (DpRuntimeReadCodeBytes(Entry->Target, restoredBytes, Entry->ProbeLength) &&
            memcmp(restoredBytes, Entry->HookBytes, Entry->ProbeLength) == 0) {
            Entry->Enabled = TRUE;
            Entry->TamperActive = FALSE;
            Entry->SyscallRiskActive = FALSE;
            DpRuntimeWriteEvent(L"userhook.runtime.unhook-restored", Entry->DisplayName, ERROR_SUCCESS, FALSE);
            return;
        }

        Entry->Enabled = FALSE;
        DpRuntimeWriteEvent(L"userhook.runtime.unhook-restore-verify-failed", Entry->DisplayName, ERROR_INVALID_DATA, TRUE);
        return;
    }

    Entry->Enabled = FALSE;
    DpRuntimeWriteEvent(L"userhook.runtime.unhook-restore-failed", Entry->DisplayName, (DWORD)status, TRUE);
}

static VOID
DpRuntimeCheckHookIntegrity(VOID)
{
    DWORD i;
    DWORD nowTick = GetTickCount();

    for (i = 0; i < gHookEntryCount; i++) {
        BYTE currentBytes[DP_RUNTIME_HOOK_PROBE_BYTES];
        BOOL matchesHook;
        BOOL matchesOriginal;
        BOOL isSyscallStub;
        BOOL shouldReport;
        DP_RUNTIME_HOOK_ENTRY *entry = &gHookEntries[i];

        if (InterlockedCompareExchange(&gRuntimeShuttingDown, 0, 0) != 0) {
            return;
        }

        if (!entry->Created || !entry->HookBytesCaptured || entry->Target == NULL) {
            continue;
        }

        if (!DpRuntimeReadCodeBytes(entry->Target, currentBytes, entry->ProbeLength)) {
            shouldReport = DpRuntimeShouldReportHookTamper(entry, nowTick, entry->TamperActive);
            entry->TamperActive = TRUE;
            entry->LastReportTick = shouldReport ? nowTick : entry->LastReportTick;
            if (shouldReport) {
                DpRuntimeWriteEvent(L"userhook.runtime.hook-probe-failed", entry->DisplayName, GetLastError(), FALSE);
            }
            continue;
        }

        matchesHook = (memcmp(currentBytes, entry->HookBytes, entry->ProbeLength) == 0);
        if (matchesHook) {
            entry->TamperActive = FALSE;
            entry->SyscallRiskActive = FALSE;
            continue;
        }

        matchesOriginal = (memcmp(currentBytes, entry->OriginalBytes, entry->ProbeLength) == 0);
        isSyscallStub = entry->IsNtdllSyscall && DpRuntimeIsLikelySyscallStub(currentBytes, entry->ProbeLength);

        shouldReport = DpRuntimeShouldReportHookTamper(entry, nowTick, entry->TamperActive);
        entry->TamperActive = TRUE;
        entry->LastReportTick = shouldReport ? nowTick : entry->LastReportTick;
        if (shouldReport) {
            if (entry->IsEtwSurface && DpRuntimeIsLikelyEtwReturnPatch(currentBytes, entry->ProbeLength)) {
                DpRuntimeWriteEvent(L"userhook.runtime.etw-return-patch-detected", entry->DisplayName, ERROR_SUCCESS, FALSE);
            } else if (entry->IsEtwSurface && DpRuntimeIsLikelyJumpPatch(currentBytes, entry->ProbeLength)) {
                DpRuntimeWriteEvent(L"userhook.runtime.etw-jump-patch-detected", entry->DisplayName, ERROR_INVALID_DATA, FALSE);
            } else if (matchesOriginal) {
                DpRuntimeWriteEvent(L"userhook.runtime.unhook-detected", entry->DisplayName, ERROR_SUCCESS, FALSE);
            } else {
                DpRuntimeWriteEvent(L"userhook.runtime.hook-overwrite-detected", entry->DisplayName, ERROR_INVALID_DATA, FALSE);
            }
        }

        if (isSyscallStub && !entry->SyscallRiskActive) {
            entry->SyscallRiskActive = TRUE;
            DpRuntimeWriteEvent(L"userhook.runtime.syscall-bypass-risk", entry->DisplayName, ERROR_SUCCESS, FALSE);
        }

        DpRuntimeTryRestoreHook(entry);
    }
}

static DWORD WINAPI
DpRuntimeIntegrityThreadProc(
    _In_opt_ LPVOID Parameter
    )
{
    UNREFERENCED_PARAMETER(Parameter);

    while (WaitForSingleObject(gIntegrityStopEvent, DP_RUNTIME_INTEGRITY_INTERVAL_MS) == WAIT_TIMEOUT) {
        DpRuntimeCheckHookIntegrity();
        DpRuntimeScanExecutableMemory();
    }

    return ERROR_SUCCESS;
}

static VOID
DpRuntimeStopIntegrityMonitor(VOID)
{
    InterlockedExchange(&gRuntimeShuttingDown, 1);

    if (gIntegrityStopEvent != NULL) {
        SetEvent(gIntegrityStopEvent);
    }

    if (gIntegrityThread != NULL) {
        WaitForSingleObject(gIntegrityThread, 1000);
        CloseHandle(gIntegrityThread);
        gIntegrityThread = NULL;
    }

    if (gIntegrityStopEvent != NULL) {
        CloseHandle(gIntegrityStopEvent);
        gIntegrityStopEvent = NULL;
    }
}

static HANDLE WINAPI
DpHookOpenProcess(
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD processId
    )
{
    HANDLE handle;
    DWORD lastError;

    handle = gRealOpenProcess(desiredAccess, inheritHandle, processId);
    lastError = GetLastError();

    if (DpRuntimeIsSensitiveProcessAccess(desiredAccess)) {
        WCHAR target[160];
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"OpenProcess pid=%lu access=0x%08lX inherit=%lu",
                              processId,
                              desiredAccess,
                              inheritHandle ? 1ul : 0ul);
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.open-process",
                                    L"access",
                                    L"OpenProcess",
                                    target,
                                    handle != NULL ? ERROR_SUCCESS : lastError,
                                    FALSE,
                                    processId,
                                    0,
                                    desiredAccess,
                                    NULL);
    }

    SetLastError(lastError);
    return handle;
}

static HANDLE WINAPI
DpHookOpenThread(
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD threadId
    )
{
    HANDLE handle;
    DWORD lastError;
    DWORD targetPid = 0;

    handle = gRealOpenThread(desiredAccess, inheritHandle, threadId);
    lastError = GetLastError();
    if (handle != NULL) {
        targetPid = DpRuntimeGetTargetThreadProcessId(handle);
    }

    if (DpRuntimeIsSensitiveThreadAccess(desiredAccess)) {
        WCHAR target[160];
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"OpenThread thread=%lu access=0x%08lX inherit=%lu",
                              threadId,
                              desiredAccess,
                              inheritHandle ? 1ul : 0ul);
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.open-thread",
                                    L"access",
                                    L"OpenThread",
                                    target,
                                    handle != NULL ? ERROR_SUCCESS : lastError,
                                    FALSE,
                                    targetPid,
                                    0,
                                    desiredAccess,
                                    NULL);
    }

    SetLastError(lastError);
    return handle;
}

static BOOL WINAPI
DpHookDuplicateHandle(
    HANDLE sourceProcessHandle,
    HANDLE sourceHandle,
    HANDLE targetProcessHandle,
    LPHANDLE targetHandle,
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD options
    )
{
    BOOL ok;
    DWORD lastError;
    BOOL sourceIsCurrent;
    BOOL targetIsCurrent;
    HANDLE inspectHandle = NULL;
    WCHAR kind[16];
    WCHAR targetBase[128];
    DWORD targetPid = 0;

    ok = gRealDuplicateHandle(sourceProcessHandle,
                              sourceHandle,
                              targetProcessHandle,
                              targetHandle,
                              desiredAccess,
                              inheritHandle,
                              options);
    lastError = GetLastError();

    sourceIsCurrent = (sourceProcessHandle == GetCurrentProcess() ||
                       sourceProcessHandle == (HANDLE)(LONG_PTR)-1);
    targetIsCurrent = (targetProcessHandle == GetCurrentProcess() ||
                       targetProcessHandle == (HANDLE)(LONG_PTR)-1);

    if (sourceIsCurrent) {
        inspectHandle = sourceHandle;
    } else if (ok && targetIsCurrent && targetHandle != NULL) {
        inspectHandle = *targetHandle;
    }

    if (DpRuntimeDescribeHandleTarget(inspectHandle,
                                      kind,
                                      ARRAYSIZE(kind),
                                      targetBase,
                                      ARRAYSIZE(targetBase),
                                      &targetPid)) {
        WCHAR target[256];
        LPCWSTR action = (kind[0] == L'p')
            ? L"userhook.observed.duplicate-process-handle"
            : L"userhook.observed.duplicate-thread-handle";
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"DuplicateHandle %s access=0x%08lX options=0x%08lX inherit=%lu",
                              targetBase,
                              desiredAccess,
                              options,
                              inheritHandle ? 1ul : 0ul);
        DpRuntimeWriteBehaviorEvent(action,
                                    L"access",
                                    L"DuplicateHandle",
                                    target,
                                    ok ? ERROR_SUCCESS : lastError,
                                    FALSE,
                                    targetPid,
                                    0,
                                    desiredAccess != 0 ? desiredAccess : options,
                                    NULL);
    }

    SetLastError(lastError);
    return ok;
}

static NTSTATUS NTAPI
DpHookNtOpenProcess(
    PHANDLE processHandle,
    ACCESS_MASK desiredAccess,
    PVOID objectAttributes,
    PDP_RUNTIME_CLIENT_ID clientId
    )
{
    NTSTATUS status;
    DWORD targetPid = 0;

    if (clientId != NULL) {
        __try {
            targetPid = (DWORD)(ULONG_PTR)clientId->UniqueProcess;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            targetPid = 0;
        }
    }

    status = gRealNtOpenProcess(processHandle, desiredAccess, objectAttributes, clientId);
    if (DpRuntimeIsSensitiveProcessAccess(desiredAccess)) {
        WCHAR target[160];
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"NtOpenProcess pid=%lu access=0x%08lX",
                              targetPid,
                              (DWORD)desiredAccess);
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-open-process",
                                    L"access",
                                    L"NtOpenProcess",
                                    target,
                                    NT_SUCCESS(status) ? ERROR_SUCCESS : (DWORD)status,
                                    FALSE,
                                    targetPid,
                                    0,
                                    (DWORD)desiredAccess,
                                    NULL);
    }

    return status;
}

static NTSTATUS NTAPI
DpHookNtOpenThread(
    PHANDLE threadHandle,
    ACCESS_MASK desiredAccess,
    PVOID objectAttributes,
    PDP_RUNTIME_CLIENT_ID clientId
    )
{
    NTSTATUS status;
    DWORD targetPid = 0;
    DWORD threadId = 0;

    if (clientId != NULL) {
        __try {
            targetPid = (DWORD)(ULONG_PTR)clientId->UniqueProcess;
            threadId = (DWORD)(ULONG_PTR)clientId->UniqueThread;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            targetPid = 0;
            threadId = 0;
        }
    }

    status = gRealNtOpenThread(threadHandle, desiredAccess, objectAttributes, clientId);
    if (NT_SUCCESS(status) && targetPid == 0 && threadHandle != NULL && *threadHandle != NULL) {
        targetPid = DpRuntimeGetTargetThreadProcessId(*threadHandle);
    }

    if (DpRuntimeIsSensitiveThreadAccess(desiredAccess)) {
        WCHAR target[160];
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"NtOpenThread thread=%lu access=0x%08lX",
                              threadId,
                              (DWORD)desiredAccess);
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-open-thread",
                                    L"access",
                                    L"NtOpenThread",
                                    target,
                                    NT_SUCCESS(status) ? ERROR_SUCCESS : (DWORD)status,
                                    FALSE,
                                    targetPid,
                                    0,
                                    (DWORD)desiredAccess,
                                    NULL);
    }

    return status;
}

static NTSTATUS NTAPI
DpHookNtDuplicateObject(
    HANDLE sourceProcessHandle,
    HANDLE sourceHandle,
    HANDLE targetProcessHandle,
    PHANDLE targetHandle,
    ACCESS_MASK desiredAccess,
    ULONG handleAttributes,
    ULONG options
    )
{
    NTSTATUS status;
    BOOL sourceIsCurrent;
    BOOL targetIsCurrent;
    HANDLE inspectHandle = NULL;
    WCHAR kind[16];
    WCHAR targetBase[128];
    DWORD targetPid = 0;

    status = gRealNtDuplicateObject(sourceProcessHandle,
                                    sourceHandle,
                                    targetProcessHandle,
                                    targetHandle,
                                    desiredAccess,
                                    handleAttributes,
                                    options);

    sourceIsCurrent = (sourceProcessHandle == GetCurrentProcess() ||
                       sourceProcessHandle == (HANDLE)(LONG_PTR)-1);
    targetIsCurrent = (targetProcessHandle == GetCurrentProcess() ||
                       targetProcessHandle == (HANDLE)(LONG_PTR)-1);

    if (sourceIsCurrent) {
        inspectHandle = sourceHandle;
    } else if (NT_SUCCESS(status) && targetIsCurrent && targetHandle != NULL) {
        __try {
            inspectHandle = *targetHandle;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            inspectHandle = NULL;
        }
    }

    if (DpRuntimeDescribeHandleTarget(inspectHandle,
                                      kind,
                                      ARRAYSIZE(kind),
                                      targetBase,
                                      ARRAYSIZE(targetBase),
                                      &targetPid)) {
        WCHAR target[256];
        LPCWSTR action = (kind[0] == L'p')
            ? L"userhook.observed.nt-duplicate-process-handle"
            : L"userhook.observed.nt-duplicate-thread-handle";
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"NtDuplicateObject %s access=0x%08lX options=0x%08lX",
                              targetBase,
                              (DWORD)desiredAccess,
                              options);
        DpRuntimeWriteBehaviorEvent(action,
                                    L"access",
                                    L"NtDuplicateObject",
                                    target,
                                    NT_SUCCESS(status) ? ERROR_SUCCESS : (DWORD)status,
                                    FALSE,
                                    targetPid,
                                    0,
                                    desiredAccess != 0 ? (DWORD)desiredAccess : options,
                                    NULL);
    }

    return status;
}

static HANDLE WINAPI
DpHookCreateRemoteThread(
    HANDLE processHandle,
    LPSECURITY_ATTRIBUTES threadAttributes,
    SIZE_T stackSize,
    LPTHREAD_START_ROUTINE startAddress,
    LPVOID parameter,
    DWORD creationFlags,
    LPDWORD threadId
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.create-remote-thread", L"injection", L"CreateRemoteThread", L"CreateRemoteThread", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, stackSize, creationFlags, NULL);
        return NULL;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.create-remote-thread", L"injection", L"CreateRemoteThread", L"CreateRemoteThread", ERROR_SUCCESS, FALSE, targetPid, stackSize, creationFlags, NULL);
    return gRealCreateRemoteThread(processHandle, threadAttributes, stackSize, startAddress, parameter, creationFlags, threadId);
}

static HANDLE WINAPI
DpHookCreateRemoteThreadEx(
    HANDLE processHandle,
    LPSECURITY_ATTRIBUTES threadAttributes,
    SIZE_T stackSize,
    LPTHREAD_START_ROUTINE startAddress,
    LPVOID parameter,
    DWORD creationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList,
    LPDWORD threadId
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.create-remote-thread-ex", L"injection", L"CreateRemoteThreadEx", L"CreateRemoteThreadEx", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, stackSize, creationFlags, NULL);
        return NULL;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.create-remote-thread-ex", L"injection", L"CreateRemoteThreadEx", L"CreateRemoteThreadEx", ERROR_SUCCESS, FALSE, targetPid, stackSize, creationFlags, NULL);
    return gRealCreateRemoteThreadEx(processHandle,
                                     threadAttributes,
                                     stackSize,
                                     startAddress,
                                     parameter,
                                     creationFlags,
                                     attributeList,
                                     threadId);
}

static BOOL WINAPI
DpHookWriteProcessMemory(
    HANDLE processHandle,
    LPVOID baseAddress,
    LPCVOID buffer,
    SIZE_T size,
    SIZE_T *bytesWritten
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    WCHAR payloadAction[128];
    WCHAR payloadTarget[DP_RUNTIME_MAX_TEXT];

    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.write-process-memory", L"injection", L"WriteProcessMemory", L"WriteProcessMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, size, 0, NULL);
        return FALSE;
    }

    if (targetPid != 0 &&
        targetPid != gCurrentProcessId &&
        DpRuntimeDescribeRemoteWritePayload(buffer, size, payloadAction, ARRAYSIZE(payloadAction), payloadTarget, ARRAYSIZE(payloadTarget))) {
        DpRuntimeWriteBehaviorEvent(payloadAction, L"injection", L"WriteProcessMemory", payloadTarget, ERROR_SUCCESS, FALSE, targetPid, size, 0, NULL);
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.write-process-memory", L"injection", L"WriteProcessMemory", L"WriteProcessMemory", ERROR_SUCCESS, FALSE, targetPid, size, 0, NULL);
    return gRealWriteProcessMemory(processHandle, baseAddress, buffer, size, bytesWritten);
}

static LPVOID WINAPI
DpHookVirtualAllocEx(
    HANDLE processHandle,
    LPVOID address,
    SIZE_T size,
    DWORD allocationType,
    DWORD protect
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeIsExecutableProtection(protect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            SetLastError(ERROR_ACCESS_DENIED);
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.remote-executable-memory", L"injection", L"VirtualAllocEx", L"VirtualAllocEx", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, size, protect, NULL);
            return NULL;
        }

        DpRuntimeWriteBehaviorEvent(L"userhook.observed.remote-executable-memory", L"injection", L"VirtualAllocEx", L"VirtualAllocEx", ERROR_SUCCESS, FALSE, targetPid, size, protect, NULL);
    }

    return gRealVirtualAllocEx(processHandle, address, size, allocationType, protect);
}

static BOOL WINAPI
DpHookVirtualProtectEx(
    HANDLE processHandle,
    LPVOID address,
    SIZE_T size,
    DWORD newProtect,
    PDWORD oldProtect
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeIsExecutableProtection(newProtect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            SetLastError(ERROR_ACCESS_DENIED);
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.remote-executable-protect", L"injection", L"VirtualProtectEx", L"VirtualProtectEx", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, size, newProtect, NULL);
            return FALSE;
        }

        DpRuntimeWriteBehaviorEvent(L"userhook.observed.remote-executable-protect", L"injection", L"VirtualProtectEx", L"VirtualProtectEx", ERROR_SUCCESS, FALSE, targetPid, size, newProtect, NULL);
    }

    return gRealVirtualProtectEx(processHandle, address, size, newProtect, oldProtect);
}

static DWORD WINAPI
DpHookQueueUserAPC(
    PAPCFUNC apcRoutine,
    HANDLE threadHandle,
    ULONG_PTR data
    )
{
    DWORD targetPid = DpRuntimeGetTargetThreadProcessId(threadHandle);
    if (DpRuntimeShouldBlockThreadPrimitive(threadHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.queue-user-apc", L"injection", L"QueueUserAPC", L"QueueUserAPC", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, 0, 0, NULL);
        return 0;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.queue-user-apc", L"injection", L"QueueUserAPC", L"QueueUserAPC", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    return gRealQueueUserAPC(apcRoutine, threadHandle, data);
}

static HHOOK WINAPI
DpHookSetWindowsHookExW(
    int hookId,
    HOOKPROC hookProc,
    HINSTANCE module,
    DWORD threadId
    )
{
    WCHAR target[64];

    (VOID)StringCchPrintfW(target, ARRAYSIZE(target), L"id=%d;thread=%lu", hookId, threadId);
    if (!gAuditOnly && threadId == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.global-windows-hook", target, DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return NULL;
    }

    DpRuntimeWriteEvent(L"userhook.observed.windows-hook", target, ERROR_SUCCESS, FALSE);
    return gRealSetWindowsHookExW(hookId, hookProc, module, threadId);
}

static HHOOK WINAPI
DpHookSetWindowsHookExA(
    int hookId,
    HOOKPROC hookProc,
    HINSTANCE module,
    DWORD threadId
    )
{
    WCHAR target[64];

    (VOID)StringCchPrintfW(target, ARRAYSIZE(target), L"id=%d;thread=%lu", hookId, threadId);
    if (!gAuditOnly && threadId == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.global-windows-hook", target, DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return NULL;
    }

    DpRuntimeWriteEvent(L"userhook.observed.windows-hook", target, ERROR_SUCCESS, FALSE);
    return gRealSetWindowsHookExA(hookId, hookProc, module, threadId);
}

static BOOL WINAPI
DpHookCreateProcessW(
    LPCWSTR applicationName,
    LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    LPVOID environment,
    LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation
    )
{
    WCHAR target[DP_RUNTIME_MAX_TEXT];
    DWORD lastError;
    DWORD targetPid = 0;
    BOOL ok;

    target[0] = L'\0';
    if (applicationName != NULL) {
        StringCchCopyW(target, ARRAYSIZE(target), applicationName);
    } else if (commandLine != NULL) {
        StringCchCopyW(target, ARRAYSIZE(target), commandLine);
    }

    if ((creationFlags & CREATE_SUSPENDED) != 0) {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.suspended-process-create", L"process", L"CreateProcessW", target, ERROR_SUCCESS, FALSE, 0, 0, creationFlags, commandLine);
    } else {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.process-create", L"process", L"CreateProcessW", target, ERROR_SUCCESS, FALSE, 0, 0, creationFlags, commandLine);
    }

    gCreateProcessCallDepth++;
    ok = gRealCreateProcessW(applicationName,
                             commandLine,
                             processAttributes,
                             threadAttributes,
                             inheritHandles,
                             creationFlags,
                             environment,
                             currentDirectory,
                             startupInfo,
                             processInformation);
    lastError = GetLastError();
    if (gCreateProcessCallDepth > 0) {
        gCreateProcessCallDepth--;
    }

    if (ok && processInformation != NULL) {
        targetPid = processInformation->dwProcessId;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.process-create-result",
                                L"process",
                                L"CreateProcessW",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                targetPid,
                                0,
                                creationFlags,
                                commandLine);
    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookCreateProcessA(
    LPCSTR applicationName,
    LPSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    LPVOID environment,
    LPCSTR currentDirectory,
    LPSTARTUPINFOA startupInfo,
    LPPROCESS_INFORMATION processInformation
    )
{
    WCHAR target[DP_RUNTIME_MAX_TEXT];
    WCHAR command[DP_RUNTIME_MAX_TEXT];
    DWORD lastError;
    DWORD targetPid = 0;
    BOOL ok;

    target[0] = L'\0';
    command[0] = L'\0';
    if (applicationName != NULL) {
        MultiByteToWideChar(CP_ACP, 0, applicationName, -1, target, ARRAYSIZE(target));
    } else if (commandLine != NULL) {
        MultiByteToWideChar(CP_ACP, 0, commandLine, -1, target, ARRAYSIZE(target));
    }

    if (commandLine != NULL) {
        MultiByteToWideChar(CP_ACP, 0, commandLine, -1, command, ARRAYSIZE(command));
    }

    if ((creationFlags & CREATE_SUSPENDED) != 0) {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.suspended-process-create", L"process", L"CreateProcessA", target, ERROR_SUCCESS, FALSE, 0, 0, creationFlags, command);
    } else {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.process-create", L"process", L"CreateProcessA", target, ERROR_SUCCESS, FALSE, 0, 0, creationFlags, command);
    }

    gCreateProcessCallDepth++;
    ok = gRealCreateProcessA(applicationName,
                             commandLine,
                             processAttributes,
                             threadAttributes,
                             inheritHandles,
                             creationFlags,
                             environment,
                             currentDirectory,
                             startupInfo,
                             processInformation);
    lastError = GetLastError();
    if (gCreateProcessCallDepth > 0) {
        gCreateProcessCallDepth--;
    }

    if (ok && processInformation != NULL) {
        targetPid = processInformation->dwProcessId;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.process-create-result",
                                L"process",
                                L"CreateProcessA",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                targetPid,
                                0,
                                creationFlags,
                                command);
    SetLastError(lastError);
    return ok;
}

static HMODULE WINAPI
DpHookLoadLibraryW(
    LPCWSTR fileName
    )
{
    HMODULE module;
    DWORD lastError;

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.load-library", L"module", L"LoadLibraryW", fileName, ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    module = gRealLoadLibraryW(fileName);
    lastError = GetLastError();
    if (module != NULL) {
        DpRuntimeInstallDynamicModuleHooks(fileName);
    }

    SetLastError(lastError);
    return module;
}

static HMODULE WINAPI
DpHookLoadLibraryA(
    LPCSTR fileName
    )
{
    HMODULE module;
    DWORD lastError;
    WCHAR fileNameWide[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(fileName, fileNameWide, ARRAYSIZE(fileNameWide));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.load-library", L"module", L"LoadLibraryA", fileNameWide, ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    module = gRealLoadLibraryA(fileName);
    lastError = GetLastError();
    if (module != NULL) {
        DpRuntimeInstallDynamicModuleHooks(fileNameWide);
    }

    SetLastError(lastError);
    return module;
}

static HMODULE WINAPI
DpHookLoadLibraryExW(
    LPCWSTR fileName,
    HANDLE file,
    DWORD flags
    )
{
    HMODULE module;
    DWORD lastError;

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.load-library-ex", L"module", L"LoadLibraryExW", fileName, ERROR_SUCCESS, FALSE, 0, 0, flags, NULL);
    module = gRealLoadLibraryExW(fileName, file, flags);
    lastError = GetLastError();
    if (module != NULL) {
        DpRuntimeInstallDynamicModuleHooks(fileName);
    }

    SetLastError(lastError);
    return module;
}

static HMODULE WINAPI
DpHookLoadLibraryExA(
    LPCSTR fileName,
    HANDLE file,
    DWORD flags
    )
{
    HMODULE module;
    DWORD lastError;
    WCHAR fileNameWide[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(fileName, fileNameWide, ARRAYSIZE(fileNameWide));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.load-library-ex", L"module", L"LoadLibraryExA", fileNameWide, ERROR_SUCCESS, FALSE, 0, 0, flags, NULL);
    module = gRealLoadLibraryExA(fileName, file, flags);
    lastError = GetLastError();
    if (module != NULL) {
        DpRuntimeInstallDynamicModuleHooks(fileNameWide);
    }

    SetLastError(lastError);
    return module;
}

static LONG WINAPI
DpHookRegSetValueExW(
    HKEY key,
    LPCWSTR valueName,
    DWORD reserved,
    DWORD type,
    const BYTE *data,
    DWORD dataBytes
    )
{
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    UNREFERENCED_PARAMETER(reserved);
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(dataBytes);

    DpRuntimeBuildRegistryValueTarget(key, valueName, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-set-value", L"registry", L"RegSetValueExW", target, ERROR_SUCCESS, FALSE, 0, dataBytes, type, NULL);
    return gRealRegSetValueExW(key, valueName, reserved, type, data, dataBytes);
}

static LONG WINAPI
DpHookRegSetValueExA(
    HKEY key,
    LPCSTR valueName,
    DWORD reserved,
    DWORD type,
    const BYTE *data,
    DWORD dataBytes
    )
{
    WCHAR valueNameWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    UNREFERENCED_PARAMETER(reserved);
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(dataBytes);

    valueNameWide[0] = L'\0';
    if (valueName != NULL) {
        MultiByteToWideChar(CP_ACP, 0, valueName, -1, valueNameWide, ARRAYSIZE(valueNameWide));
    }

    DpRuntimeBuildRegistryValueTarget(key, valueNameWide, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-set-value", L"registry", L"RegSetValueExA", target, ERROR_SUCCESS, FALSE, 0, dataBytes, type, NULL);
    return gRealRegSetValueExA(key, valueName, reserved, type, data, dataBytes);
}

static LONG WINAPI
DpHookRegCreateKeyExW(
    HKEY key,
    LPCWSTR subKey,
    DWORD reserved,
    LPWSTR className,
    DWORD options,
    REGSAM samDesired,
    const SECURITY_ATTRIBUTES *securityAttributes,
    PHKEY result,
    LPDWORD disposition
    )
{
    LONG status;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeBuildRegistryKeyTarget(key, subKey, target, ARRAYSIZE(target));
    status = gRealRegCreateKeyExW(key,
                                  subKey,
                                  reserved,
                                  className,
                                  options,
                                  samDesired,
                                  securityAttributes,
                                  result,
                                  disposition);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-create-key",
                                L"registry",
                                L"RegCreateKeyExW",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                samDesired,
                                NULL);
    return status;
}

static LONG WINAPI
DpHookRegCreateKeyExA(
    HKEY key,
    LPCSTR subKey,
    DWORD reserved,
    LPSTR className,
    DWORD options,
    REGSAM samDesired,
    const SECURITY_ATTRIBUTES *securityAttributes,
    PHKEY result,
    LPDWORD disposition
    )
{
    LONG status;
    WCHAR subKeyWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(subKey, subKeyWide, ARRAYSIZE(subKeyWide));
    DpRuntimeBuildRegistryKeyTarget(key, subKeyWide, target, ARRAYSIZE(target));
    status = gRealRegCreateKeyExA(key,
                                  subKey,
                                  reserved,
                                  className,
                                  options,
                                  samDesired,
                                  securityAttributes,
                                  result,
                                  disposition);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-create-key",
                                L"registry",
                                L"RegCreateKeyExA",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                samDesired,
                                NULL);
    return status;
}

static LONG WINAPI
DpHookRegDeleteValueW(
    HKEY key,
    LPCWSTR valueName
    )
{
    LONG status;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeBuildRegistryValueTarget(key, valueName, target, ARRAYSIZE(target));
    status = gRealRegDeleteValueW(key, valueName);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-delete-value",
                                L"registry",
                                L"RegDeleteValueW",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                0,
                                NULL);
    return status;
}

static LONG WINAPI
DpHookRegDeleteValueA(
    HKEY key,
    LPCSTR valueName
    )
{
    LONG status;
    WCHAR valueNameWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(valueName, valueNameWide, ARRAYSIZE(valueNameWide));
    DpRuntimeBuildRegistryValueTarget(key, valueNameWide, target, ARRAYSIZE(target));
    status = gRealRegDeleteValueA(key, valueName);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-delete-value",
                                L"registry",
                                L"RegDeleteValueA",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                0,
                                NULL);
    return status;
}

static LONG WINAPI
DpHookRegDeleteKeyW(
    HKEY key,
    LPCWSTR subKey
    )
{
    LONG status;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeBuildRegistryKeyTarget(key, subKey, target, ARRAYSIZE(target));
    status = gRealRegDeleteKeyW(key, subKey);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-delete-key",
                                L"registry",
                                L"RegDeleteKeyW",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                0,
                                NULL);
    return status;
}

static LONG WINAPI
DpHookRegDeleteKeyA(
    HKEY key,
    LPCSTR subKey
    )
{
    LONG status;
    WCHAR subKeyWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(subKey, subKeyWide, ARRAYSIZE(subKeyWide));
    DpRuntimeBuildRegistryKeyTarget(key, subKeyWide, target, ARRAYSIZE(target));
    status = gRealRegDeleteKeyA(key, subKey);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.registry-delete-key",
                                L"registry",
                                L"RegDeleteKeyA",
                                target,
                                (DWORD)status,
                                FALSE,
                                0,
                                0,
                                0,
                                NULL);
    return status;
}

static SC_HANDLE WINAPI
DpHookCreateServiceW(
    SC_HANDLE serviceControlManager,
    LPCWSTR serviceName,
    LPCWSTR displayName,
    DWORD desiredAccess,
    DWORD serviceType,
    DWORD startType,
    DWORD errorControl,
    LPCWSTR binaryPathName,
    LPCWSTR loadOrderGroup,
    LPDWORD tagId,
    LPCWSTR dependencies,
    LPCWSTR serviceStartName,
    LPCWSTR password
    )
{
    SC_HANDLE service;
    DWORD lastError;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    service = gRealCreateServiceW(serviceControlManager,
                                  serviceName,
                                  displayName,
                                  desiredAccess,
                                  serviceType,
                                  startType,
                                  errorControl,
                                  binaryPathName,
                                  loadOrderGroup,
                                  tagId,
                                  dependencies,
                                  serviceStartName,
                                  password);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, serviceName, binaryPathName, serviceType, startType, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.create-service",
                                L"service",
                                L"CreateServiceW",
                                target,
                                service != NULL ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                startType,
                                binaryPathName);
    SetLastError(lastError);
    return service;
}

static SC_HANDLE WINAPI
DpHookCreateServiceA(
    SC_HANDLE serviceControlManager,
    LPCSTR serviceName,
    LPCSTR displayName,
    DWORD desiredAccess,
    DWORD serviceType,
    DWORD startType,
    DWORD errorControl,
    LPCSTR binaryPathName,
    LPCSTR loadOrderGroup,
    LPDWORD tagId,
    LPCSTR dependencies,
    LPCSTR serviceStartName,
    LPCSTR password
    )
{
    SC_HANDLE service;
    DWORD lastError;
    WCHAR serviceNameWide[256];
    WCHAR binaryPathWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(serviceName, serviceNameWide, ARRAYSIZE(serviceNameWide));
    DpRuntimeAnsiToWide(binaryPathName, binaryPathWide, ARRAYSIZE(binaryPathWide));
    service = gRealCreateServiceA(serviceControlManager,
                                  serviceName,
                                  displayName,
                                  desiredAccess,
                                  serviceType,
                                  startType,
                                  errorControl,
                                  binaryPathName,
                                  loadOrderGroup,
                                  tagId,
                                  dependencies,
                                  serviceStartName,
                                  password);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, serviceNameWide, binaryPathWide, serviceType, startType, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.create-service",
                                L"service",
                                L"CreateServiceA",
                                target,
                                service != NULL ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                startType,
                                binaryPathWide);
    SetLastError(lastError);
    return service;
}

static BOOL WINAPI
DpHookChangeServiceConfigW(
    SC_HANDLE service,
    DWORD serviceType,
    DWORD startType,
    DWORD errorControl,
    LPCWSTR binaryPathName,
    LPCWSTR loadOrderGroup,
    LPDWORD tagId,
    LPCWSTR dependencies,
    LPCWSTR serviceStartName,
    LPCWSTR password,
    LPCWSTR displayName
    )
{
    BOOL ok;
    DWORD lastError;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    ok = gRealChangeServiceConfigW(service,
                                   serviceType,
                                   startType,
                                   errorControl,
                                   binaryPathName,
                                   loadOrderGroup,
                                   tagId,
                                   dependencies,
                                   serviceStartName,
                                   password,
                                   displayName);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, displayName, binaryPathName, serviceType, startType, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.change-service-config",
                                L"service",
                                L"ChangeServiceConfigW",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                startType,
                                binaryPathName);
    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookChangeServiceConfigA(
    SC_HANDLE service,
    DWORD serviceType,
    DWORD startType,
    DWORD errorControl,
    LPCSTR binaryPathName,
    LPCSTR loadOrderGroup,
    LPDWORD tagId,
    LPCSTR dependencies,
    LPCSTR serviceStartName,
    LPCSTR password,
    LPCSTR displayName
    )
{
    BOOL ok;
    DWORD lastError;
    WCHAR displayNameWide[256];
    WCHAR binaryPathWide[DP_RUNTIME_MAX_TEXT];
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    DpRuntimeAnsiToWide(displayName, displayNameWide, ARRAYSIZE(displayNameWide));
    DpRuntimeAnsiToWide(binaryPathName, binaryPathWide, ARRAYSIZE(binaryPathWide));
    ok = gRealChangeServiceConfigA(service,
                                   serviceType,
                                   startType,
                                   errorControl,
                                   binaryPathName,
                                   loadOrderGroup,
                                   tagId,
                                   dependencies,
                                   serviceStartName,
                                   password,
                                   displayName);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, displayNameWide, binaryPathWide, serviceType, startType, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.change-service-config",
                                L"service",
                                L"ChangeServiceConfigA",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                startType,
                                binaryPathWide);
    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookStartServiceW(
    SC_HANDLE service,
    DWORD argumentCount,
    LPCWSTR *arguments
    )
{
    BOOL ok;
    DWORD lastError;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    ok = gRealStartServiceW(service, argumentCount, arguments);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, NULL, NULL, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.start-service",
                                L"service",
                                L"StartServiceW",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                argumentCount,
                                NULL);
    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookStartServiceA(
    SC_HANDLE service,
    DWORD argumentCount,
    LPCSTR *arguments
    )
{
    BOOL ok;
    DWORD lastError;
    WCHAR target[DP_RUNTIME_MAX_TEXT];

    ok = gRealStartServiceA(service, argumentCount, arguments);
    lastError = GetLastError();
    DpRuntimeBuildServiceTarget(service, NULL, NULL, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.start-service",
                                L"service",
                                L"StartServiceA",
                                target,
                                ok ? ERROR_SUCCESS : lastError,
                                FALSE,
                                0,
                                0,
                                argumentCount,
                                NULL);
    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookMiniDumpWriteDump(
    HANDLE processHandle,
    DWORD processId,
    HANDLE fileHandle,
    DWORD dumpType,
    PVOID exceptionParam,
    PVOID userStreamParam,
    PVOID callbackParam
    )
{
    BOOL ok;
    DWORD lastError;
    DWORD targetPid;

    ok = gRealMiniDumpWriteDump(processHandle,
                                processId,
                                fileHandle,
                                dumpType,
                                exceptionParam,
                                userStreamParam,
                                callbackParam);
    lastError = GetLastError();
    targetPid = processId != 0 ? processId : DpRuntimeGetTargetProcessId(processHandle);

    if (targetPid != 0 && targetPid != gCurrentProcessId) {
        WCHAR target[160];
        (VOID)StringCchPrintfW(target,
                              ARRAYSIZE(target),
                              L"MiniDumpWriteDump pid=%lu dumpType=0x%08lX",
                              targetPid,
                              dumpType);
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.minidump-write",
                                    L"credential",
                                    L"MiniDumpWriteDump",
                                    target,
                                    ok ? ERROR_SUCCESS : lastError,
                                    FALSE,
                                    targetPid,
                                    0,
                                    dumpType,
                                    NULL);
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI
DpHookSetThreadContext(
    HANDLE threadHandle,
    const CONTEXT *context
    )
{
    DWORD targetPid = DpRuntimeGetTargetThreadProcessId(threadHandle);

    UNREFERENCED_PARAMETER(context);
    if (DpRuntimeShouldBlockThreadPrimitive(threadHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.set-thread-context", L"injection", L"SetThreadContext", L"SetThreadContext", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, 0, 0, NULL);
        return FALSE;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.set-thread-context", L"injection", L"SetThreadContext", L"SetThreadContext", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    return gRealSetThreadContext(threadHandle, context);
}

static DWORD WINAPI
DpHookResumeThread(
    HANDLE threadHandle
    )
{
    DWORD targetPid = DpRuntimeGetTargetThreadProcessId(threadHandle);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.resume-thread", L"process", L"ResumeThread", L"ResumeThread", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    return gRealResumeThread(threadHandle);
}

static VOID
DpRuntimeFormatSockaddr(
    _In_opt_ const struct sockaddr *Address,
    _Out_writes_(BufferChars) WCHAR *Buffer,
    _In_ DWORD BufferChars
    )
{
    WCHAR host[NI_MAXHOST];
    WCHAR service[NI_MAXSERV];

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (Address == NULL) {
        return;
    }

    host[0] = L'\0';
    service[0] = L'\0';
    if (GetNameInfoW(Address,
                     Address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                     host,
                     ARRAYSIZE(host),
                     service,
                     ARRAYSIZE(service),
                     NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        StringCchPrintfW(Buffer, BufferChars, L"%s:%s", host, service);
    }
}

static int WSAAPI
DpHookConnect(
    SOCKET socketHandle,
    const struct sockaddr *name,
    int nameLength
    )
{
    WCHAR target[128];

    UNREFERENCED_PARAMETER(nameLength);
    DpRuntimeFormatSockaddr(name, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.network-connect", L"network", L"connect", target, ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    return gRealConnect(socketHandle, name, nameLength);
}

static int WSAAPI
DpHookWSAConnect(
    SOCKET socketHandle,
    const struct sockaddr *name,
    int nameLength,
    LPWSABUF callerData,
    LPWSABUF calleeData,
    LPQOS sqos,
    LPQOS gqos
    )
{
    WCHAR target[128];

    UNREFERENCED_PARAMETER(nameLength);
    DpRuntimeFormatSockaddr(name, target, ARRAYSIZE(target));
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.network-wsaconnect", L"network", L"WSAConnect", target, ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    return gRealWSAConnect(socketHandle, name, nameLength, callerData, calleeData, sqos, gqos);
}

static NTSTATUS NTAPI
DpHookNtCreateThreadEx(
    PHANDLE threadHandle,
    ACCESS_MASK desiredAccess,
    PVOID objectAttributes,
    HANDLE processHandle,
    PVOID startRoutine,
    PVOID argument,
    ULONG createFlags,
    SIZE_T zeroBits,
    SIZE_T stackSize,
    SIZE_T maximumStackSize,
    PVOID attributeList
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-create-thread-ex", L"injection", L"NtCreateThreadEx", L"NtCreateThreadEx", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, stackSize, createFlags, NULL);
        return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-create-thread-ex", L"injection", L"NtCreateThreadEx", L"NtCreateThreadEx", ERROR_SUCCESS, FALSE, targetPid, stackSize, createFlags, NULL);
    return gRealNtCreateThreadEx(threadHandle,
                                 desiredAccess,
                                 objectAttributes,
                                 processHandle,
                                 startRoutine,
                                 argument,
                                 createFlags,
                                 zeroBits,
                                 stackSize,
                                 maximumStackSize,
                                 attributeList);
}

static NTSTATUS NTAPI
DpHookNtWriteVirtualMemory(
    HANDLE processHandle,
    PVOID baseAddress,
    PVOID buffer,
    SIZE_T size,
    PSIZE_T bytesWritten
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    WCHAR payloadAction[128];
    WCHAR payloadTarget[DP_RUNTIME_MAX_TEXT];

    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-write-virtual-memory", L"injection", L"NtWriteVirtualMemory", L"NtWriteVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, size, 0, NULL);
        return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
    }

    if (targetPid != 0 &&
        targetPid != gCurrentProcessId &&
        DpRuntimeDescribeRemoteWritePayload(buffer, size, payloadAction, ARRAYSIZE(payloadAction), payloadTarget, ARRAYSIZE(payloadTarget))) {
        DpRuntimeWriteBehaviorEvent(payloadAction, L"injection", L"NtWriteVirtualMemory", payloadTarget, ERROR_SUCCESS, FALSE, targetPid, size, 0, NULL);
    }

    DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-write-virtual-memory", L"injection", L"NtWriteVirtualMemory", L"NtWriteVirtualMemory", ERROR_SUCCESS, FALSE, targetPid, size, 0, NULL);
    return gRealNtWriteVirtualMemory(processHandle, baseAddress, buffer, size, bytesWritten);
}

static NTSTATUS NTAPI
DpHookNtAllocateVirtualMemory(
    HANDLE processHandle,
    PVOID *baseAddress,
    ULONG_PTR zeroBits,
    PSIZE_T regionSize,
    ULONG allocationType,
    ULONG protect
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeIsExecutableProtection(protect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-allocate-executable-memory", L"injection", L"NtAllocateVirtualMemory", L"NtAllocateVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, regionSize == NULL ? 0 : *regionSize, protect, NULL);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }

        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-allocate-executable-memory", L"injection", L"NtAllocateVirtualMemory", L"NtAllocateVirtualMemory", ERROR_SUCCESS, FALSE, targetPid, regionSize == NULL ? 0 : *regionSize, protect, NULL);
    }

    return gRealNtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);
}

static NTSTATUS NTAPI
DpHookNtProtectVirtualMemory(
    HANDLE processHandle,
    PVOID *baseAddress,
    PSIZE_T numberOfBytesToProtect,
    ULONG newAccessProtection,
    PULONG oldAccessProtection
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (DpRuntimeIsExecutableProtection(newAccessProtection)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-protect-executable-memory", L"injection", L"NtProtectVirtualMemory", L"NtProtectVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, numberOfBytesToProtect == NULL ? 0 : *numberOfBytesToProtect, newAccessProtection, NULL);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }

        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-protect-executable-memory", L"injection", L"NtProtectVirtualMemory", L"NtProtectVirtualMemory", ERROR_SUCCESS, FALSE, targetPid, numberOfBytesToProtect == NULL ? 0 : *numberOfBytesToProtect, newAccessProtection, NULL);
    }

    return gRealNtProtectVirtualMemory(processHandle,
                                       baseAddress,
                                       numberOfBytesToProtect,
                                       newAccessProtection,
                                       oldAccessProtection);
}

static NTSTATUS NTAPI
DpHookNtUnmapViewOfSection(
    HANDLE processHandle,
    PVOID baseAddress
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-unmap-view", L"injection", L"NtUnmapViewOfSection", L"NtUnmapViewOfSection", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    return gRealNtUnmapViewOfSection(processHandle, baseAddress);
}

// NtMapViewOfSection - section-based injection (Cobalt Strike, process hollowing
// variant, PE injection without WriteProcessMemory). Hook reports remote mappings;
// blocks cross-process executable mappings in enforce mode.
static NTSTATUS NTAPI
DpHookNtMapViewOfSection(
    HANDLE sectionHandle,
    HANDLE processHandle,
    PVOID *baseAddress,
    ULONG_PTR zeroBits,
    SIZE_T commitSize,
    PLARGE_INTEGER sectionOffset,
    PSIZE_T viewSize,
    DWORD inheritDisposition,
    ULONG allocationType,
    ULONG win32Protect
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    BOOL isRemote = (processHandle != NULL &&
                     processHandle != GetCurrentProcess() &&
                     targetPid != gCurrentProcessId &&
                     targetPid != 0);

    if (isRemote && DpRuntimeIsExecutableProtection(win32Protect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-map-view-of-section", L"injection", L"NtMapViewOfSection", L"NtMapViewOfSection", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, 0, win32Protect, NULL);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-map-view-of-section", L"injection", L"NtMapViewOfSection", L"NtMapViewOfSection", ERROR_SUCCESS, FALSE, targetPid, 0, win32Protect, NULL);
    }

    return gRealNtMapViewOfSection(sectionHandle, processHandle, baseAddress, zeroBits,
                                   commitSize, sectionOffset, viewSize,
                                   inheritDisposition, allocationType, win32Protect);
}

// NtQueueApcThread - native APC injection bypassing the hooked QueueUserAPC.
// Used by Cobalt Strike, Havoc C2, and common shellcode loaders (early-bird APC,
// NtTestAlert trigger) because it operates directly on the thread handle without
// going through the Win32 layer.
static NTSTATUS NTAPI
DpHookNtQueueApcThread(
    HANDLE threadHandle,
    PVOID apcRoutine,
    PVOID apcArgument1,
    PVOID apcArgument2,
    PVOID apcArgument3
    )
{
    DWORD targetPid = DpRuntimeGetTargetThreadProcessId(threadHandle);
    if (DpRuntimeShouldBlockThreadPrimitive(threadHandle)) {
        DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-queue-apc-thread", L"injection", L"NtQueueApcThread", L"NtQueueApcThread", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, 0, 0, NULL);
        return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
    }
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-queue-apc-thread", L"injection", L"NtQueueApcThread", L"NtQueueApcThread", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    return gRealNtQueueApcThread(threadHandle, apcRoutine, apcArgument1, apcArgument2, apcArgument3);
}

// NtSuspendThread / NtSuspendProcess - used in freeze-and-hollow and thread
// hijacking to stop a target before writing/redirecting its execution.
static NTSTATUS NTAPI
DpHookNtSuspendThread(
    HANDLE threadHandle,
    PULONG previousSuspendCount
    )
{
    DWORD targetPid = DpRuntimeGetTargetThreadProcessId(threadHandle);
    if (targetPid != 0 && targetPid != gCurrentProcessId) {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-suspend-thread", L"injection", L"NtSuspendThread", L"NtSuspendThread", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    }
    return gRealNtSuspendThread(threadHandle, previousSuspendCount);
}

static NTSTATUS NTAPI
DpHookNtSuspendProcess(
    HANDLE processHandle
    )
{
    DWORD targetPid = DpRuntimeGetTargetProcessId(processHandle);
    if (targetPid != 0 && targetPid != gCurrentProcessId) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteBehaviorEvent(L"userhook.blocked.nt-suspend-process", L"injection", L"NtSuspendProcess", L"NtSuspendProcess", DP_RUNTIME_STATUS_BLOCKED, TRUE, targetPid, 0, 0, NULL);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.nt-suspend-process", L"injection", L"NtSuspendProcess", L"NtSuspendProcess", ERROR_SUCCESS, FALSE, targetPid, 0, 0, NULL);
    }
    return gRealNtSuspendProcess(processHandle);
}

static ULONG WINAPI
DpHookEventRegister(
    LPCGUID providerId,
    PENABLECALLBACK enableCallback,
    PVOID callbackContext,
    PREGHANDLE regHandle
    )
{
    DpRuntimeWriteBehaviorEvent(L"userhook.observed.etw-provider-register", L"telemetry", L"EventRegister", L"EventRegister", ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    return gRealEventRegister(providerId, enableCallback, callbackContext, regHandle);
}

static ULONG WINAPI
DpHookEventUnregister(
    REGHANDLE regHandle
    )
{
    if (InterlockedIncrement(&gEtwUnregisterReports) <= 4) {
        DpRuntimeWriteBehaviorEvent(L"userhook.observed.etw-provider-unregister", L"telemetry", L"EventUnregister", L"EventUnregister", ERROR_SUCCESS, FALSE, 0, 0, 0, NULL);
    }

    return gRealEventUnregister(regHandle);
}

static ULONG WINAPI
DpHookEventWrite(
    REGHANDLE regHandle,
    PCEVENT_DESCRIPTOR eventDescriptor,
    ULONG userDataCount,
    PEVENT_DATA_DESCRIPTOR userData
    )
{
    return gRealEventWrite(regHandle, eventDescriptor, userDataCount, userData);
}

static ULONG WINAPI
DpHookEventWriteTransfer(
    REGHANDLE regHandle,
    PCEVENT_DESCRIPTOR eventDescriptor,
    LPCGUID activityId,
    LPCGUID relatedActivityId,
    ULONG userDataCount,
    PEVENT_DATA_DESCRIPTOR userData
    )
{
    return gRealEventWriteTransfer(regHandle, eventDescriptor, activityId, relatedActivityId, userDataCount, userData);
}

static ULONG WINAPI
DpHookEventWriteString(
    REGHANDLE regHandle,
    UCHAR level,
    ULONGLONG keyword,
    PCWSTR string
    )
{
    return gRealEventWriteString(regHandle, level, keyword, string);
}

static NTSTATUS NTAPI
DpHookEtwEventWrite(
    REGHANDLE regHandle,
    PCEVENT_DESCRIPTOR eventDescriptor,
    ULONG userDataCount,
    PEVENT_DATA_DESCRIPTOR userData
    )
{
    return gRealEtwEventWrite(regHandle, eventDescriptor, userDataCount, userData);
}

static NTSTATUS NTAPI
DpHookEtwEventWriteTransfer(
    REGHANDLE regHandle,
    PCEVENT_DESCRIPTOR eventDescriptor,
    LPCGUID activityId,
    LPCGUID relatedActivityId,
    ULONG userDataCount,
    PEVENT_DATA_DESCRIPTOR userData
    )
{
    return gRealEtwEventWriteTransfer(regHandle, eventDescriptor, activityId, relatedActivityId, userDataCount, userData);
}

static BOOL
DpRuntimeHookApi(
    _In_z_ LPCWSTR ModuleName,
    _In_z_ LPCSTR ApiName,
    _In_ LPVOID Detour,
    _Out_ LPVOID *Original
    )
{
    HMODULE module = GetModuleHandleW(ModuleName);
    FARPROC target;
    DP_RUNTIME_HOOK_ENTRY *entry;
    BOOL isNtdllSyscall;

    if (module == NULL) {
        DpRuntimeWriteEvent(L"userhook.runtime.module-not-loaded", ModuleName, ERROR_SUCCESS, FALSE);
        return FALSE;
    }

    target = GetProcAddress(module, ApiName);
    if (target == NULL) {
        return FALSE;
    }

    if (gHookEntryCount >= DP_RUNTIME_MAX_HOOKS) {
        return FALSE;
    }

    entry = &gHookEntries[gHookEntryCount];
    ZeroMemory(entry, sizeof(*entry));
    entry->Target = (LPVOID)target;
    entry->Detour = Detour;
    entry->OriginalSlot = Original;
    entry->ProbeLength = DP_RUNTIME_HOOK_PROBE_BYTES;
    isNtdllSyscall = (_wcsicmp(ModuleName, L"ntdll.dll") == 0 && _strnicmp(ApiName, "Nt", 2) == 0);
    entry->IsNtdllSyscall = isNtdllSyscall;
    entry->IsEtwSurface = (_wcsicmp(ModuleName, L"advapi32.dll") == 0 &&
                           (_strnicmp(ApiName, "Event", 5) == 0 || _strnicmp(ApiName, "Etw", 3) == 0)) ||
                          (_wcsicmp(ModuleName, L"ntdll.dll") == 0 &&
                           _strnicmp(ApiName, "Etw", 3) == 0);
    (VOID)StringCchCopyW(entry->ModuleName, ARRAYSIZE(entry->ModuleName), ModuleName);
    (VOID)StringCchCopyA(entry->ApiName, ARRAYSIZE(entry->ApiName), ApiName);
    (VOID)StringCchPrintfW(entry->DisplayName, ARRAYSIZE(entry->DisplayName), L"%s!%S", ModuleName, ApiName);

    if (!DpRuntimeReadCodeBytes(entry->Target, entry->OriginalBytes, entry->ProbeLength)) {
        DpRuntimeWriteEvent(L"userhook.runtime.hook-baseline-failed", entry->DisplayName, GetLastError(), TRUE);
        return FALSE;
    }

    if (entry->IsEtwSurface && DpRuntimeIsLikelyEtwReturnPatch(entry->OriginalBytes, entry->ProbeLength)) {
        DpRuntimeWriteEvent(L"userhook.runtime.etw-prepatched-detected", entry->DisplayName, ERROR_INVALID_DATA, FALSE);
    }

    if (MH_CreateHook((LPVOID)target, Detour, Original) != MH_OK) {
        DpRuntimeWriteEvent(L"userhook.runtime.create-hook-failed", entry->DisplayName, GetLastError(), FALSE);
        return FALSE;
    }

    entry->Created = TRUE;
    gHookEntryCount++;
    if (gHooksEnabled) {
        MH_STATUS enableStatus = MH_EnableHook((LPVOID)target);
        if (enableStatus == MH_OK || enableStatus == MH_ERROR_ENABLED) {
            if (DpRuntimeReadCodeBytes(entry->Target, entry->HookBytes, entry->ProbeLength)) {
                entry->HookBytesCaptured = TRUE;
                entry->Enabled = TRUE;
            }
        } else {
            DpRuntimeWriteEvent(L"userhook.runtime.enable-hook-failed", entry->DisplayName, (DWORD)enableStatus, FALSE);
        }
    }

    return TRUE;
}

static VOID
DpRuntimeInstallDynamicModuleHooks(
    _In_opt_z_ LPCWSTR ModuleName
    )
{
    if (ModuleName != NULL &&
        ModuleName[0] != L'\0' &&
        !DpRuntimeContainsWideInsensitive(ModuleName, L"dbghelp")) {
        return;
    }

    if (gRealMiniDumpWriteDump == NULL &&
        GetModuleHandleW(L"dbghelp.dll") != NULL) {
        DpRuntimeHookApi(L"dbghelp.dll", "MiniDumpWriteDump", DpHookMiniDumpWriteDump, (LPVOID *)&gRealMiniDumpWriteDump);
    }
}

static BOOL CALLBACK
DpRuntimeInitializeOnce(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context
    )
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    gCurrentProcessId = GetCurrentProcessId();
    GetModuleFileNameW(NULL, gCurrentProcessPath, ARRAYSIZE(gCurrentProcessPath));

    if (DpRuntimeShouldExitByPolicy()) {
        return TRUE;
    }

    if (MH_Initialize() != MH_OK) {
        DpRuntimeWriteEvent(L"userhook.runtime.minhook-init-failed", L"MinHook", GetLastError(), FALSE);
        return TRUE;
    }
    gMinHookInitialized = TRUE;

    if (gMonitorRuntimeApiBehavior) {
        DpRuntimeHookApi(L"kernel32.dll", "OpenProcess", DpHookOpenProcess, (LPVOID *)&gRealOpenProcess);
        DpRuntimeHookApi(L"kernel32.dll", "OpenThread", DpHookOpenThread, (LPVOID *)&gRealOpenThread);
        DpRuntimeHookApi(L"kernel32.dll", "DuplicateHandle", DpHookDuplicateHandle, (LPVOID *)&gRealDuplicateHandle);
        DpRuntimeHookApi(L"kernel32.dll", "CreateRemoteThread", DpHookCreateRemoteThread, (LPVOID *)&gRealCreateRemoteThread);
        DpRuntimeHookApi(L"kernel32.dll", "CreateRemoteThreadEx", DpHookCreateRemoteThreadEx, (LPVOID *)&gRealCreateRemoteThreadEx);
        DpRuntimeHookApi(L"kernel32.dll", "CreateProcessW", DpHookCreateProcessW, (LPVOID *)&gRealCreateProcessW);
        DpRuntimeHookApi(L"kernel32.dll", "CreateProcessA", DpHookCreateProcessA, (LPVOID *)&gRealCreateProcessA);
        DpRuntimeHookApi(L"kernel32.dll", "WriteProcessMemory", DpHookWriteProcessMemory, (LPVOID *)&gRealWriteProcessMemory);
        DpRuntimeHookApi(L"kernel32.dll", "VirtualAllocEx", DpHookVirtualAllocEx, (LPVOID *)&gRealVirtualAllocEx);
        DpRuntimeHookApi(L"kernel32.dll", "VirtualProtectEx", DpHookVirtualProtectEx, (LPVOID *)&gRealVirtualProtectEx);
        DpRuntimeHookApi(L"kernel32.dll", "QueueUserAPC", DpHookQueueUserAPC, (LPVOID *)&gRealQueueUserAPC);
        DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryW", DpHookLoadLibraryW, (LPVOID *)&gRealLoadLibraryW);
        DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryA", DpHookLoadLibraryA, (LPVOID *)&gRealLoadLibraryA);
        DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryExW", DpHookLoadLibraryExW, (LPVOID *)&gRealLoadLibraryExW);
        DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryExA", DpHookLoadLibraryExA, (LPVOID *)&gRealLoadLibraryExA);
        DpRuntimeHookApi(L"kernel32.dll", "SetThreadContext", DpHookSetThreadContext, (LPVOID *)&gRealSetThreadContext);
        DpRuntimeHookApi(L"kernel32.dll", "ResumeThread", DpHookResumeThread, (LPVOID *)&gRealResumeThread);
        DpRuntimeHookApi(L"user32.dll", "SetWindowsHookExW", DpHookSetWindowsHookExW, (LPVOID *)&gRealSetWindowsHookExW);
        DpRuntimeHookApi(L"user32.dll", "SetWindowsHookExA", DpHookSetWindowsHookExA, (LPVOID *)&gRealSetWindowsHookExA);
        DpRuntimeHookApi(L"advapi32.dll", "RegSetValueExW", DpHookRegSetValueExW, (LPVOID *)&gRealRegSetValueExW);
        DpRuntimeHookApi(L"advapi32.dll", "RegSetValueExA", DpHookRegSetValueExA, (LPVOID *)&gRealRegSetValueExA);
        DpRuntimeHookApi(L"advapi32.dll", "RegCreateKeyExW", DpHookRegCreateKeyExW, (LPVOID *)&gRealRegCreateKeyExW);
        DpRuntimeHookApi(L"advapi32.dll", "RegCreateKeyExA", DpHookRegCreateKeyExA, (LPVOID *)&gRealRegCreateKeyExA);
        DpRuntimeHookApi(L"advapi32.dll", "RegDeleteValueW", DpHookRegDeleteValueW, (LPVOID *)&gRealRegDeleteValueW);
        DpRuntimeHookApi(L"advapi32.dll", "RegDeleteValueA", DpHookRegDeleteValueA, (LPVOID *)&gRealRegDeleteValueA);
        DpRuntimeHookApi(L"advapi32.dll", "RegDeleteKeyW", DpHookRegDeleteKeyW, (LPVOID *)&gRealRegDeleteKeyW);
        DpRuntimeHookApi(L"advapi32.dll", "RegDeleteKeyA", DpHookRegDeleteKeyA, (LPVOID *)&gRealRegDeleteKeyA);
        DpRuntimeHookApi(L"advapi32.dll", "CreateServiceW", DpHookCreateServiceW, (LPVOID *)&gRealCreateServiceW);
        DpRuntimeHookApi(L"advapi32.dll", "CreateServiceA", DpHookCreateServiceA, (LPVOID *)&gRealCreateServiceA);
        DpRuntimeHookApi(L"advapi32.dll", "ChangeServiceConfigW", DpHookChangeServiceConfigW, (LPVOID *)&gRealChangeServiceConfigW);
        DpRuntimeHookApi(L"advapi32.dll", "ChangeServiceConfigA", DpHookChangeServiceConfigA, (LPVOID *)&gRealChangeServiceConfigA);
        DpRuntimeHookApi(L"advapi32.dll", "StartServiceW", DpHookStartServiceW, (LPVOID *)&gRealStartServiceW);
        DpRuntimeHookApi(L"advapi32.dll", "StartServiceA", DpHookStartServiceA, (LPVOID *)&gRealStartServiceA);
        DpRuntimeHookApi(L"ws2_32.dll", "connect", DpHookConnect, (LPVOID *)&gRealConnect);
        DpRuntimeHookApi(L"ws2_32.dll", "WSAConnect", DpHookWSAConnect, (LPVOID *)&gRealWSAConnect);
        DpRuntimeHookApi(L"ntdll.dll", "NtOpenProcess", DpHookNtOpenProcess, (LPVOID *)&gRealNtOpenProcess);
        DpRuntimeHookApi(L"ntdll.dll", "NtOpenThread", DpHookNtOpenThread, (LPVOID *)&gRealNtOpenThread);
        DpRuntimeHookApi(L"ntdll.dll", "NtDuplicateObject", DpHookNtDuplicateObject, (LPVOID *)&gRealNtDuplicateObject);
        DpRuntimeHookApi(L"ntdll.dll", "NtCreateThreadEx", DpHookNtCreateThreadEx, (LPVOID *)&gRealNtCreateThreadEx);
        DpRuntimeHookApi(L"ntdll.dll", "NtWriteVirtualMemory", DpHookNtWriteVirtualMemory, (LPVOID *)&gRealNtWriteVirtualMemory);
        DpRuntimeHookApi(L"ntdll.dll", "NtAllocateVirtualMemory", DpHookNtAllocateVirtualMemory, (LPVOID *)&gRealNtAllocateVirtualMemory);
        DpRuntimeHookApi(L"ntdll.dll", "NtProtectVirtualMemory", DpHookNtProtectVirtualMemory, (LPVOID *)&gRealNtProtectVirtualMemory);
        DpRuntimeHookApi(L"ntdll.dll", "NtUnmapViewOfSection", DpHookNtUnmapViewOfSection, (LPVOID *)&gRealNtUnmapViewOfSection);
        DpRuntimeHookApi(L"ntdll.dll", "NtMapViewOfSection", DpHookNtMapViewOfSection, (LPVOID *)&gRealNtMapViewOfSection);
        DpRuntimeHookApi(L"ntdll.dll", "NtQueueApcThread", DpHookNtQueueApcThread, (LPVOID *)&gRealNtQueueApcThread);
        DpRuntimeHookApi(L"ntdll.dll", "NtSuspendThread", DpHookNtSuspendThread, (LPVOID *)&gRealNtSuspendThread);
        DpRuntimeHookApi(L"ntdll.dll", "NtSuspendProcess", DpHookNtSuspendProcess, (LPVOID *)&gRealNtSuspendProcess);

        if (gMonitorEtwTamper) {
            DpRuntimeHookApi(L"advapi32.dll", "EventRegister", DpHookEventRegister, (LPVOID *)&gRealEventRegister);
            DpRuntimeHookApi(L"advapi32.dll", "EventUnregister", DpHookEventUnregister, (LPVOID *)&gRealEventUnregister);
            DpRuntimeHookApi(L"advapi32.dll", "EventWrite", DpHookEventWrite, (LPVOID *)&gRealEventWrite);
            DpRuntimeHookApi(L"advapi32.dll", "EventWriteTransfer", DpHookEventWriteTransfer, (LPVOID *)&gRealEventWriteTransfer);
            DpRuntimeHookApi(L"advapi32.dll", "EventWriteString", DpHookEventWriteString, (LPVOID *)&gRealEventWriteString);
            DpRuntimeHookApi(L"ntdll.dll", "EtwEventWrite", DpHookEtwEventWrite, (LPVOID *)&gRealEtwEventWrite);
            DpRuntimeHookApi(L"ntdll.dll", "EtwEventWriteTransfer", DpHookEtwEventWriteTransfer, (LPVOID *)&gRealEtwEventWriteTransfer);
        } else {
            DpRuntimeWriteEvent(L"userhook.runtime.etw-tamper-monitor-disabled", L"policy", ERROR_SUCCESS, FALSE);
        }

        DpRuntimeInstallDynamicModuleHooks(NULL);

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            DpRuntimeWriteEvent(L"userhook.runtime.enable-hooks-failed", L"MinHook", GetLastError(), FALSE);
            return TRUE;
        }
        gHooksEnabled = TRUE;
        DpRuntimeCaptureHookBytes();
    } else {
        DpRuntimeWriteEvent(L"userhook.runtime.api-monitor-disabled", L"policy", ERROR_SUCCESS, FALSE);
    }

    if (gIntegrityThread == NULL) {
        InterlockedExchange(&gRuntimeShuttingDown, 0);
        gIntegrityStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (gIntegrityStopEvent != NULL) {
            gIntegrityThread = CreateThread(NULL, 0, DpRuntimeIntegrityThreadProc, NULL, 0, NULL);
            if (gIntegrityThread == NULL) {
                CloseHandle(gIntegrityStopEvent);
                gIntegrityStopEvent = NULL;
                DpRuntimeWriteEvent(L"userhook.runtime.integrity-thread-failed", L"CreateThread", GetLastError(), TRUE);
            }
        } else {
            DpRuntimeWriteEvent(L"userhook.runtime.integrity-event-failed", L"CreateEvent", GetLastError(), TRUE);
        }
    }

    DpRuntimeWriteEvent(L"userhook.runtime.loaded", L"DataProtectorUserHookRuntime.dll", ERROR_SUCCESS, FALSE);
    return TRUE;
}

__declspec(dllexport)
BOOL WINAPI
DpUserHookRuntimeInitialize(VOID)
{
    return InitOnceExecuteOnce(&gInitializeOnce, DpRuntimeInitializeOnce, NULL, NULL);
}

static DWORD WINAPI
DpRuntimeInitThreadProc(
    _In_opt_ LPVOID Parameter
    )
{
    UNREFERENCED_PARAMETER(Parameter);
    return DpUserHookRuntimeInitialize() ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

BOOL WINAPI
DllMain(
    HINSTANCE Instance,
    DWORD Reason,
    LPVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Reserved);

    if (Reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(Instance);
        gInitThread = CreateThread(NULL, 0, DpRuntimeInitThreadProc, NULL, 0, NULL);
        if (gInitThread != NULL) {
            CloseHandle(gInitThread);
            gInitThread = NULL;
        }
    } else if (Reason == DLL_PROCESS_DETACH) {
        DpRuntimeStopIntegrityMonitor();
        if (gMinHookInitialized) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            gHooksEnabled = FALSE;
            gMinHookInitialized = FALSE;
        }
    }

    return TRUE;
}
