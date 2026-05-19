#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <strsafe.h>
#include <MinHook.h>

#define DP_RUNTIME_EVENT_PATH L"C:\\ProgramData\\DataProtector\\UserHookRuntimeEvents.jsonl"
#define DP_RUNTIME_POLICY_PATH L"C:\\ProgramData\\DataProtector\\UserHookRuntimePolicy.json"
#define DP_RUNTIME_MAX_TEXT 1024
#define DP_RUNTIME_MAX_POLICY_TEXT 8192
#define DP_RUNTIME_STATUS_BLOCKED 0xC0000022u

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;

typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *PFN_CreateRemoteThreadEx)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
typedef BOOL (WINAPI *PFN_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD (WINAPI *PFN_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef HHOOK (WINAPI *PFN_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HHOOK (WINAPI *PFN_SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef LONG (WINAPI *PFN_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

static PFN_CreateRemoteThread gRealCreateRemoteThread;
static PFN_CreateRemoteThreadEx gRealCreateRemoteThreadEx;
static PFN_CreateProcessW gRealCreateProcessW;
static PFN_WriteProcessMemory gRealWriteProcessMemory;
static PFN_VirtualAllocEx gRealVirtualAllocEx;
static PFN_VirtualProtectEx gRealVirtualProtectEx;
static PFN_QueueUserAPC gRealQueueUserAPC;
static PFN_SetWindowsHookExW gRealSetWindowsHookExW;
static PFN_SetWindowsHookExA gRealSetWindowsHookExA;
static PFN_LoadLibraryW gRealLoadLibraryW;
static PFN_LoadLibraryExW gRealLoadLibraryExW;
static PFN_RegSetValueExW gRealRegSetValueExW;
static PFN_connect gRealConnect;
static PFN_WSAConnect gRealWSAConnect;
static PFN_NtCreateThreadEx gRealNtCreateThreadEx;
static PFN_NtWriteVirtualMemory gRealNtWriteVirtualMemory;
static PFN_NtAllocateVirtualMemory gRealNtAllocateVirtualMemory;
static PFN_NtProtectVirtualMemory gRealNtProtectVirtualMemory;

static INIT_ONCE gInitializeOnce = INIT_ONCE_STATIC_INIT;
static SRWLOCK gEventLock = SRWLOCK_INIT;
static WCHAR gCurrentProcessPath[MAX_PATH * 2];
static DWORD gCurrentProcessId;
static BOOL gAuditOnly = TRUE;
static BOOL gEnabled = TRUE;
static HANDLE gInitThread;

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

static BOOL
DpRuntimeJsonArrayContainsProcess(
    _In_z_ const WCHAR *Json,
    _In_z_ const WCHAR *Key,
    _In_z_ const WCHAR *ProcessPath,
    _In_ BOOL DirectoryMatch
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
        WCHAR *end;
        WCHAR token[DP_RUNTIME_MAX_TEXT];
        size_t chars;

        if (start == NULL || start >= arrayEnd) {
            break;
        }

        end = wcschr(start + 1, L'"');
        if (end == NULL || end > arrayEnd) {
            break;
        }

        chars = (size_t)(end - start - 1);
        if (chars > 0 && chars < ARRAYSIZE(token)) {
            CopyMemory(token, start + 1, chars * sizeof(WCHAR));
            token[chars] = L'\0';

            if (!DirectoryMatch) {
                if (DpRuntimePathHasSuffix(ProcessPath, token)) {
                    return TRUE;
                }
            } else if (_wcsnicmp(ProcessPath, token, wcslen(token)) == 0) {
                WCHAR next = ProcessPath[wcslen(token)];
                if (next == L'\0' || next == L'\\' || next == L'/') {
                    return TRUE;
                }
            }
        }

        cursor = end + 1;
    }

    return FALSE;
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

    if (!gEnabled) {
        return TRUE;
    }

    return DpRuntimeJsonArrayContainsProcess(policy, L"excludedProcessNames", gCurrentProcessPath, FALSE) ||
           DpRuntimeJsonArrayContainsProcess(policy, L"excludedProcessDirectories", gCurrentProcessPath, TRUE);
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
    WCHAR directory[MAX_PATH];
    WCHAR processEscaped[DP_RUNTIME_MAX_TEXT * 2];
    WCHAR targetEscaped[DP_RUNTIME_MAX_TEXT * 2];
    WCHAR line[4096];
    CHAR utf8[8192];
    HANDLE file;
    DWORD bytesWritten;
    int utf8Bytes;
    SYSTEMTIME now;

    if (Action == NULL) {
        return;
    }

    if (FAILED(StringCchCopyW(directory, ARRAYSIZE(directory), L"C:\\ProgramData\\DataProtector"))) {
        return;
    }

    CreateDirectoryW(directory, NULL);
    DpRuntimeEscapeJson(gCurrentProcessPath, processEscaped, ARRAYSIZE(processEscaped));
    DpRuntimeEscapeJson(Target, targetEscaped, ARRAYSIZE(targetEscaped));
    GetSystemTime(&now);

    if (FAILED(StringCchPrintfW(
            line,
            ARRAYSIZE(line),
            L"{\"timestampUtc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"host\":\"%s\",\"pid\":%lu,\"action\":\"%s\",\"target\":\"%s\",\"processImage\":\"%s\",\"status\":\"0x%08X\",\"blocked\":%s}\r\n",
            now.wYear,
            now.wMonth,
            now.wDay,
            now.wHour,
            now.wMinute,
            now.wSecond,
            now.wMilliseconds,
            L"",
            gCurrentProcessId,
            Action,
            targetEscaped,
            processEscaped,
            Status,
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
DpRuntimeShouldBlockInjectionPrimitive(
    _In_ HANDLE ProcessHandle
    )
{
    DWORD targetPid;

    if (gAuditOnly || ProcessHandle == NULL || ProcessHandle == GetCurrentProcess()) {
        return FALSE;
    }

    targetPid = GetProcessId(ProcessHandle);
    return targetPid != 0 && targetPid != gCurrentProcessId;
}

static BOOL
DpRuntimeShouldBlockThreadPrimitive(
    _In_ HANDLE ThreadHandle
    )
{
    DWORD targetPid;

    if (gAuditOnly || ThreadHandle == NULL) {
        return FALSE;
    }

    targetPid = GetProcessIdOfThread(ThreadHandle);
    return targetPid != 0 && targetPid != gCurrentProcessId;
}

static BOOL
DpRuntimeIsExecutableProtection(
    _In_ DWORD Protection
    )
{
    return (Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
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
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.create-remote-thread", L"CreateRemoteThread", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return NULL;
    }

    DpRuntimeWriteEvent(L"userhook.observed.create-remote-thread", L"CreateRemoteThread", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.create-remote-thread-ex", L"CreateRemoteThreadEx", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return NULL;
    }

    DpRuntimeWriteEvent(L"userhook.observed.create-remote-thread-ex", L"CreateRemoteThreadEx", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.write-process-memory", L"WriteProcessMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return FALSE;
    }

    DpRuntimeWriteEvent(L"userhook.observed.write-process-memory", L"WriteProcessMemory", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeIsExecutableProtection(protect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            SetLastError(ERROR_ACCESS_DENIED);
            DpRuntimeWriteEvent(L"userhook.blocked.remote-executable-memory", L"VirtualAllocEx", DP_RUNTIME_STATUS_BLOCKED, TRUE);
            return NULL;
        }

        DpRuntimeWriteEvent(L"userhook.observed.remote-executable-memory", L"VirtualAllocEx", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeIsExecutableProtection(newProtect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            SetLastError(ERROR_ACCESS_DENIED);
            DpRuntimeWriteEvent(L"userhook.blocked.remote-executable-protect", L"VirtualProtectEx", DP_RUNTIME_STATUS_BLOCKED, TRUE);
            return FALSE;
        }

        DpRuntimeWriteEvent(L"userhook.observed.remote-executable-protect", L"VirtualProtectEx", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeShouldBlockThreadPrimitive(threadHandle)) {
        SetLastError(ERROR_ACCESS_DENIED);
        DpRuntimeWriteEvent(L"userhook.blocked.queue-user-apc", L"QueueUserAPC", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return 0;
    }

    DpRuntimeWriteEvent(L"userhook.observed.queue-user-apc", L"QueueUserAPC", ERROR_SUCCESS, FALSE);
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

    target[0] = L'\0';
    if (applicationName != NULL) {
        StringCchCopyW(target, ARRAYSIZE(target), applicationName);
    } else if (commandLine != NULL) {
        StringCchCopyW(target, ARRAYSIZE(target), commandLine);
    }

    if ((creationFlags & CREATE_SUSPENDED) != 0) {
        DpRuntimeWriteEvent(L"userhook.observed.suspended-process-create", target, ERROR_SUCCESS, FALSE);
    } else {
        DpRuntimeWriteEvent(L"userhook.observed.process-create", target, ERROR_SUCCESS, FALSE);
    }

    return gRealCreateProcessW(applicationName,
                               commandLine,
                               processAttributes,
                               threadAttributes,
                               inheritHandles,
                               creationFlags,
                               environment,
                               currentDirectory,
                               startupInfo,
                               processInformation);
}

static HMODULE WINAPI
DpHookLoadLibraryW(
    LPCWSTR fileName
    )
{
    DpRuntimeWriteEvent(L"userhook.observed.load-library", fileName, ERROR_SUCCESS, FALSE);
    return gRealLoadLibraryW(fileName);
}

static HMODULE WINAPI
DpHookLoadLibraryExW(
    LPCWSTR fileName,
    HANDLE file,
    DWORD flags
    )
{
    DpRuntimeWriteEvent(L"userhook.observed.load-library-ex", fileName, ERROR_SUCCESS, FALSE);
    return gRealLoadLibraryExW(fileName, file, flags);
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
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(reserved);
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(dataBytes);

    DpRuntimeWriteEvent(L"userhook.observed.registry-set-value", valueName, ERROR_SUCCESS, FALSE);
    return gRealRegSetValueExW(key, valueName, reserved, type, data, dataBytes);
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
    DpRuntimeWriteEvent(L"userhook.observed.network-connect", target, ERROR_SUCCESS, FALSE);
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
    DpRuntimeWriteEvent(L"userhook.observed.network-wsaconnect", target, ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        DpRuntimeWriteEvent(L"userhook.blocked.nt-create-thread-ex", L"NtCreateThreadEx", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
    }

    DpRuntimeWriteEvent(L"userhook.observed.nt-create-thread-ex", L"NtCreateThreadEx", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
        DpRuntimeWriteEvent(L"userhook.blocked.nt-write-virtual-memory", L"NtWriteVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE);
        return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
    }

    DpRuntimeWriteEvent(L"userhook.observed.nt-write-virtual-memory", L"NtWriteVirtualMemory", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeIsExecutableProtection(protect)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteEvent(L"userhook.blocked.nt-allocate-executable-memory", L"NtAllocateVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }

        DpRuntimeWriteEvent(L"userhook.observed.nt-allocate-executable-memory", L"NtAllocateVirtualMemory", ERROR_SUCCESS, FALSE);
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
    if (DpRuntimeIsExecutableProtection(newAccessProtection)) {
        if (DpRuntimeShouldBlockInjectionPrimitive(processHandle)) {
            DpRuntimeWriteEvent(L"userhook.blocked.nt-protect-executable-memory", L"NtProtectVirtualMemory", DP_RUNTIME_STATUS_BLOCKED, TRUE);
            return (NTSTATUS)DP_RUNTIME_STATUS_BLOCKED;
        }

        DpRuntimeWriteEvent(L"userhook.observed.nt-protect-executable-memory", L"NtProtectVirtualMemory", ERROR_SUCCESS, FALSE);
    }

    return gRealNtProtectVirtualMemory(processHandle,
                                       baseAddress,
                                       numberOfBytesToProtect,
                                       newAccessProtection,
                                       oldAccessProtection);
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

    if (module == NULL) {
        module = LoadLibraryW(ModuleName);
    }

    if (module == NULL) {
        return FALSE;
    }

    target = GetProcAddress(module, ApiName);
    if (target == NULL) {
        return FALSE;
    }

    return MH_CreateHook((LPVOID)target, Detour, Original) == MH_OK;
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

    DpRuntimeHookApi(L"kernel32.dll", "CreateRemoteThread", DpHookCreateRemoteThread, (LPVOID *)&gRealCreateRemoteThread);
    DpRuntimeHookApi(L"kernel32.dll", "CreateRemoteThreadEx", DpHookCreateRemoteThreadEx, (LPVOID *)&gRealCreateRemoteThreadEx);
    DpRuntimeHookApi(L"kernel32.dll", "CreateProcessW", DpHookCreateProcessW, (LPVOID *)&gRealCreateProcessW);
    DpRuntimeHookApi(L"kernel32.dll", "WriteProcessMemory", DpHookWriteProcessMemory, (LPVOID *)&gRealWriteProcessMemory);
    DpRuntimeHookApi(L"kernel32.dll", "VirtualAllocEx", DpHookVirtualAllocEx, (LPVOID *)&gRealVirtualAllocEx);
    DpRuntimeHookApi(L"kernel32.dll", "VirtualProtectEx", DpHookVirtualProtectEx, (LPVOID *)&gRealVirtualProtectEx);
    DpRuntimeHookApi(L"kernel32.dll", "QueueUserAPC", DpHookQueueUserAPC, (LPVOID *)&gRealQueueUserAPC);
    DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryW", DpHookLoadLibraryW, (LPVOID *)&gRealLoadLibraryW);
    DpRuntimeHookApi(L"kernel32.dll", "LoadLibraryExW", DpHookLoadLibraryExW, (LPVOID *)&gRealLoadLibraryExW);
    DpRuntimeHookApi(L"user32.dll", "SetWindowsHookExW", DpHookSetWindowsHookExW, (LPVOID *)&gRealSetWindowsHookExW);
    DpRuntimeHookApi(L"user32.dll", "SetWindowsHookExA", DpHookSetWindowsHookExA, (LPVOID *)&gRealSetWindowsHookExA);
    DpRuntimeHookApi(L"advapi32.dll", "RegSetValueExW", DpHookRegSetValueExW, (LPVOID *)&gRealRegSetValueExW);
    DpRuntimeHookApi(L"ws2_32.dll", "connect", DpHookConnect, (LPVOID *)&gRealConnect);
    DpRuntimeHookApi(L"ws2_32.dll", "WSAConnect", DpHookWSAConnect, (LPVOID *)&gRealWSAConnect);
    DpRuntimeHookApi(L"ntdll.dll", "NtCreateThreadEx", DpHookNtCreateThreadEx, (LPVOID *)&gRealNtCreateThreadEx);
    DpRuntimeHookApi(L"ntdll.dll", "NtWriteVirtualMemory", DpHookNtWriteVirtualMemory, (LPVOID *)&gRealNtWriteVirtualMemory);
    DpRuntimeHookApi(L"ntdll.dll", "NtAllocateVirtualMemory", DpHookNtAllocateVirtualMemory, (LPVOID *)&gRealNtAllocateVirtualMemory);
    DpRuntimeHookApi(L"ntdll.dll", "NtProtectVirtualMemory", DpHookNtProtectVirtualMemory, (LPVOID *)&gRealNtProtectVirtualMemory);

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        DpRuntimeWriteEvent(L"userhook.runtime.enable-hooks-failed", L"MinHook", GetLastError(), FALSE);
        return TRUE;
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
        if (gRealCreateProcessW != NULL) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
    }

    return TRUE;
}
