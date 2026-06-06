#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <strsafe.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif

#ifndef ViewShare
#define ViewShare 1
#endif

typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS (NTAPI *PFN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS (NTAPI *PFN_NtSuspendThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
    );

typedef NTSTATUS (NTAPI *PFN_NtSuspendProcess)(
    HANDLE ProcessHandle
    );

typedef BOOL (WINAPI *PFN_DpUserHookRuntimeInitialize)(VOID);

static const wchar_t *kDefaultTarget = L"%SystemRoot%\\System32\\notepad.exe";
static const wchar_t *kRuntimeDllName = L"DataProtectorUserHookRuntime.dll";
static const wchar_t *kRuntimeEventPath = L"C:\\ProgramData\\DataProtector\\UserHookRuntimeEvents.jsonl";

struct NativeApi
{
    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory;
    PFN_NtWriteVirtualMemory NtWriteVirtualMemory;
    PFN_NtProtectVirtualMemory NtProtectVirtualMemory;
    PFN_NtCreateThreadEx NtCreateThreadEx;
    PFN_NtQueueApcThread NtQueueApcThread;
    PFN_NtUnmapViewOfSection NtUnmapViewOfSection;
    PFN_NtCreateSection NtCreateSection;
    PFN_NtMapViewOfSection NtMapViewOfSection;
    PFN_NtSuspendThread NtSuspendThread;
    PFN_NtSuspendProcess NtSuspendProcess;
};

struct TestContext
{
    PROCESS_INFORMATION ProcessInfo;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    LPVOID RemoteBuffer;
    LPVOID RemoteBuffer2;
    LPVOID RemoteThreadStart;
    LPVOID SectionRemoteBase;
    LPVOID SectionLocalBase;
    HANDLE SectionHandle;
};

static void PrintUsage()
{
    wprintf(L"UserHookTriggerTest - benign trigger program for DataProtector userhook injection defense\n");
    wprintf(L"\n");
    wprintf(L"Usage:\n");
    wprintf(L"  UserHookTriggerTest.exe [--target <exe>] [--no-runtime] [--resume-remote-thread]\n");
    wprintf(L"\n");
    wprintf(L"Default behavior:\n");
    wprintf(L"  Loads DataProtectorUserHookRuntime.dll from the executable directory,\n");
    wprintf(L"  creates a suspended child process, triggers remote memory/write/thread/APC/native\n");
    wprintf(L"  telemetry against that child, then terminates the child process.\n");
    wprintf(L"\n");
    wprintf(L"Event log:\n");
    wprintf(L"  %s\n", kRuntimeEventPath);
}

static bool EqualsArg(const wchar_t *arg, const wchar_t *name)
{
    return arg != NULL && _wcsicmp(arg, name) == 0;
}

static void FormatWin32Error(DWORD error, wchar_t *buffer, DWORD chars)
{
    DWORD written;

    if (buffer == NULL || chars == 0) {
        return;
    }

    buffer[0] = L'\0';
    written = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL,
                             error,
                             0,
                             buffer,
                             chars,
                             NULL);
    if (written == 0) {
        swprintf_s(buffer, chars, L"Win32=%lu", error);
        return;
    }

    while (written > 0 &&
           (buffer[written - 1] == L'\r' ||
            buffer[written - 1] == L'\n' ||
            buffer[written - 1] == L' ')) {
        buffer[written - 1] = L'\0';
        written--;
    }
}

static void PrintWin32Result(const wchar_t *name, BOOL ok)
{
    wchar_t message[256];
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();

    if (ok) {
        wprintf(L"[OK]      %s\n", name);
        return;
    }

    FormatWin32Error(error, message, ARRAYSIZE(message));
    wprintf(L"[BLOCKED] %s failed: %s (0x%08lX)\n", name, message, error);
}

static void PrintNtResult(const wchar_t *name, NTSTATUS status)
{
    if (NT_SUCCESS(status)) {
        wprintf(L"[OK]      %s status=0x%08lX\n", name, (DWORD)status);
    } else {
        wprintf(L"[BLOCKED] %s status=0x%08lX\n", name, (DWORD)status);
    }
}

static bool ExpandPath(const wchar_t *input, wchar_t *output, DWORD chars)
{
    DWORD result;

    if (input == NULL || output == NULL || chars == 0) {
        return false;
    }

    result = ExpandEnvironmentStringsW(input, output, chars);
    return result > 0 && result < chars;
}

static bool GetExecutableDirectory(wchar_t *directory, DWORD chars)
{
    DWORD length;
    wchar_t *slash;

    if (directory == NULL || chars == 0) {
        return false;
    }

    length = GetModuleFileNameW(NULL, directory, chars);
    if (length == 0 || length >= chars) {
        return false;
    }

    slash = wcsrchr(directory, L'\\');
    if (slash == NULL) {
        return false;
    }

    *slash = L'\0';
    return true;
}

static bool LoadRuntimeFromExecutableDirectory()
{
    wchar_t directory[MAX_PATH];
    wchar_t runtimePath[MAX_PATH];
    HMODULE runtime;
    PFN_DpUserHookRuntimeInitialize initializeRuntime;

    if (!GetExecutableDirectory(directory, ARRAYSIZE(directory))) {
        wprintf(L"[WARN]   Cannot locate executable directory; runtime auto-load skipped.\n");
        return false;
    }

    if (FAILED(StringCchPrintfW(runtimePath,
                               ARRAYSIZE(runtimePath),
                               L"%s\\%s",
                               directory,
                               kRuntimeDllName))) {
        wprintf(L"[WARN]   Runtime path is too long; runtime auto-load skipped.\n");
        return false;
    }

    runtime = LoadLibraryW(runtimePath);
    if (runtime == NULL) {
        wchar_t message[256];
        FormatWin32Error(GetLastError(), message, ARRAYSIZE(message));
        wprintf(L"[WARN]   LoadLibrary(%s) failed: %s\n", runtimePath, message);
        return false;
    }

    initializeRuntime = (PFN_DpUserHookRuntimeInitialize)GetProcAddress(runtime, "DpUserHookRuntimeInitialize");
    if (initializeRuntime == NULL) {
        wprintf(L"[WARN]   Runtime loaded, but DpUserHookRuntimeInitialize export was not found.\n");
        return true;
    }

    if (!initializeRuntime()) {
        wprintf(L"[WARN]   DpUserHookRuntimeInitialize returned FALSE.\n");
        return false;
    }

    Sleep(750);
    wprintf(L"[OK]      Runtime loaded: %s\n", runtimePath);
    return true;
}

static bool LoadNativeApi(NativeApi *api)
{
    HMODULE ntdll;

    if (api == NULL) {
        return false;
    }

    ZeroMemory(api, sizeof(*api));
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }

    api->NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    api->NtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    api->NtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    api->NtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    api->NtQueueApcThread = (PFN_NtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
    api->NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    api->NtCreateSection = (PFN_NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    api->NtMapViewOfSection = (PFN_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    api->NtSuspendThread = (PFN_NtSuspendThread)GetProcAddress(ntdll, "NtSuspendThread");
    api->NtSuspendProcess = (PFN_NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");

    return api->NtAllocateVirtualMemory != NULL &&
           api->NtWriteVirtualMemory != NULL &&
           api->NtProtectVirtualMemory != NULL &&
           api->NtCreateThreadEx != NULL &&
           api->NtQueueApcThread != NULL &&
           api->NtUnmapViewOfSection != NULL &&
           api->NtCreateSection != NULL &&
           api->NtMapViewOfSection != NULL &&
           api->NtSuspendThread != NULL &&
           api->NtSuspendProcess != NULL;
}

static bool CreateSuspendedTarget(const wchar_t *target, TestContext *ctx)
{
    wchar_t expanded[MAX_PATH];
    wchar_t commandLine[MAX_PATH + 8];
    STARTUPINFOW startup;
    BOOL ok;

    if (ctx == NULL) {
        return false;
    }

    if (!ExpandPath(target, expanded, ARRAYSIZE(expanded))) {
        wprintf(L"[FAIL]   Could not expand target path: %s\n", target);
        return false;
    }

    swprintf_s(commandLine, ARRAYSIZE(commandLine), L"\"%s\"", expanded);
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&ctx->ProcessInfo, sizeof(ctx->ProcessInfo));

    ok = CreateProcessW(expanded,
                        commandLine,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_SUSPENDED,
                        NULL,
                        NULL,
                        &startup,
                        &ctx->ProcessInfo);
    PrintWin32Result(L"CreateProcessW(CREATE_SUSPENDED)", ok);
    if (!ok) {
        return false;
    }

    wprintf(L"[INFO]    Target PID=%lu TID=%lu image=%s\n",
            ctx->ProcessInfo.dwProcessId,
            ctx->ProcessInfo.dwThreadId,
            expanded);
    return true;
}

static void TriggerKernelHandleAtoms(TestContext *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD |
                                     PROCESS_VM_OPERATION |
                                     PROCESS_VM_WRITE |
                                     PROCESS_VM_READ |
                                     PROCESS_QUERY_INFORMATION |
                                     PROCESS_SUSPEND_RESUME,
                                     FALSE,
                                     ctx->ProcessInfo.dwProcessId);
    PrintWin32Result(L"OpenProcess(injection access)", ctx->ProcessHandle != NULL);
    if (ctx->ProcessHandle == NULL) {
        ctx->ProcessHandle = ctx->ProcessInfo.hProcess;
        wprintf(L"[INFO]    Reusing CreateProcess target handle after OpenProcess was denied.\n");
    }

    ctx->ThreadHandle = OpenThread(THREAD_SET_CONTEXT |
                                   THREAD_GET_CONTEXT |
                                   THREAD_SUSPEND_RESUME |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   ctx->ProcessInfo.dwThreadId);
    PrintWin32Result(L"OpenThread(hijack access)", ctx->ThreadHandle != NULL);
    if (ctx->ThreadHandle == NULL) {
        ctx->ThreadHandle = ctx->ProcessInfo.hThread;
        wprintf(L"[INFO]    Reusing CreateProcess primary thread handle after OpenThread was denied.\n");
    }
}

static void TriggerWin32InjectionAtoms(TestContext *ctx, bool resumeRemoteThread)
{
    const wchar_t dllPath[] = L"C:\\ProgramData\\DataProtector\\BenignUserHookTrigger.dll";
    BYTE mzSample[64];
    SIZE_T bytesWritten = 0;
    DWORD oldProtect = 0;
    DWORD remoteThreadId = 0;
    HANDLE remoteThread;
    BOOL ok;
    SIZE_T pathBytes = sizeof(dllPath);

    if (ctx == NULL || ctx->ProcessHandle == NULL) {
        wprintf(L"[SKIP]   Win32 injection atoms need a process handle.\n");
        return;
    }

    ctx->RemoteBuffer = VirtualAllocEx(ctx->ProcessHandle,
                                       NULL,
                                       4096,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    PrintWin32Result(L"VirtualAllocEx(PAGE_EXECUTE_READWRITE)", ctx->RemoteBuffer != NULL);

    if (ctx->RemoteBuffer != NULL) {
        ok = WriteProcessMemory(ctx->ProcessHandle,
                                ctx->RemoteBuffer,
                                dllPath,
                                pathBytes,
                                &bytesWritten);
        PrintWin32Result(L"WriteProcessMemory(remote DLL path)", ok);

        ZeroMemory(mzSample, sizeof(mzSample));
        mzSample[0] = 'M';
        mzSample[1] = 'Z';
        ok = WriteProcessMemory(ctx->ProcessHandle,
                                (BYTE *)ctx->RemoteBuffer + 512,
                                mzSample,
                                sizeof(mzSample),
                                &bytesWritten);
        PrintWin32Result(L"WriteProcessMemory(MZ sample)", ok);

        ok = VirtualProtectEx(ctx->ProcessHandle,
                              ctx->RemoteBuffer,
                              4096,
                              PAGE_EXECUTE_READ,
                              &oldProtect);
        PrintWin32Result(L"VirtualProtectEx(PAGE_EXECUTE_READ)", ok);
    }

    ctx->RemoteThreadStart = reinterpret_cast<LPVOID>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
    if (ctx->RemoteThreadStart == NULL) {
        wprintf(L"[SKIP]   Cannot resolve kernel32!Sleep for remote thread test.\n");
        return;
    }

    remoteThread = CreateRemoteThread(ctx->ProcessHandle,
                                      NULL,
                                      0,
                                      (LPTHREAD_START_ROUTINE)ctx->RemoteThreadStart,
                                      (LPVOID)(ULONG_PTR)60000,
                                      CREATE_SUSPENDED,
                                      &remoteThreadId);
    PrintWin32Result(L"CreateRemoteThread(CREATE_SUSPENDED)", remoteThread != NULL);
    if (remoteThread != NULL) {
        if (resumeRemoteThread) {
            DWORD previous = ResumeThread(remoteThread);
            PrintWin32Result(L"ResumeThread(remote thread)", previous != (DWORD)-1);
        }
        CloseHandle(remoteThread);
    }

    if (ctx->ThreadHandle != NULL && ctx->RemoteThreadStart != NULL) {
        DWORD queued = QueueUserAPC((PAPCFUNC)ctx->RemoteThreadStart,
                                    ctx->ThreadHandle,
                                    (ULONG_PTR)1000);
        PrintWin32Result(L"QueueUserAPC(primary target thread)", queued != 0);
    }
}

static void TriggerNativeInjectionAtoms(const NativeApi *api, TestContext *ctx)
{
    const wchar_t dllPath[] = L"C:\\ProgramData\\DataProtector\\BenignNativeApcTrigger.dll";
    PVOID base = NULL;
    SIZE_T regionSize = 4096;
    SIZE_T bytesWritten = 0;
    ULONG oldProtect = 0;
    HANDLE nativeThread = NULL;
    NTSTATUS status;

    if (api == NULL || ctx == NULL || ctx->ProcessHandle == NULL) {
        wprintf(L"[SKIP]   Native atoms need ntdll exports and a process handle.\n");
        return;
    }

    status = api->NtAllocateVirtualMemory(ctx->ProcessHandle,
                                          &base,
                                          0,
                                          &regionSize,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    PrintNtResult(L"NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)", status);
    if (NT_SUCCESS(status)) {
        ctx->RemoteBuffer2 = base;

        status = api->NtWriteVirtualMemory(ctx->ProcessHandle,
                                           base,
                                           (PVOID)dllPath,
                                           sizeof(dllPath),
                                           &bytesWritten);
        PrintNtResult(L"NtWriteVirtualMemory(remote DLL path)", status);

        status = api->NtProtectVirtualMemory(ctx->ProcessHandle,
                                             &base,
                                             &regionSize,
                                             PAGE_EXECUTE_READ,
                                             &oldProtect);
        PrintNtResult(L"NtProtectVirtualMemory(PAGE_EXECUTE_READ)", status);
    }

    if (ctx->RemoteThreadStart != NULL) {
        status = api->NtCreateThreadEx(&nativeThread,
                                       THREAD_ALL_ACCESS,
                                       NULL,
                                       ctx->ProcessHandle,
                                       ctx->RemoteThreadStart,
                                       (PVOID)(ULONG_PTR)60000,
                                       0x00000001,
                                       0,
                                       0,
                                       0,
                                       NULL);
        PrintNtResult(L"NtCreateThreadEx(create suspended)", status);
        if (nativeThread != NULL) {
            CloseHandle(nativeThread);
        }
    }

    if (ctx->ThreadHandle != NULL && ctx->RemoteThreadStart != NULL) {
        status = api->NtQueueApcThread(ctx->ThreadHandle,
                                       ctx->RemoteThreadStart,
                                       (PVOID)(ULONG_PTR)1000,
                                       NULL,
                                       NULL);
        PrintNtResult(L"NtQueueApcThread(primary target thread)", status);
    }
}

static void TriggerSectionMapAtoms(const NativeApi *api, TestContext *ctx)
{
    LARGE_INTEGER maximumSize;
    SIZE_T viewSize;
    NTSTATUS status;

    if (api == NULL || ctx == NULL || ctx->ProcessHandle == NULL) {
        wprintf(L"[SKIP]   Section map atoms need ntdll exports and a process handle.\n");
        return;
    }

    maximumSize.QuadPart = 4096;
    status = api->NtCreateSection(&ctx->SectionHandle,
                                  SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                                  NULL,
                                  &maximumSize,
                                  PAGE_EXECUTE_READWRITE,
                                  SEC_COMMIT,
                                  NULL);
    PrintNtResult(L"NtCreateSection(PAGE_EXECUTE_READWRITE)", status);
    if (!NT_SUCCESS(status) || ctx->SectionHandle == NULL) {
        return;
    }

    viewSize = 0;
    status = api->NtMapViewOfSection(ctx->SectionHandle,
                                     GetCurrentProcess(),
                                     &ctx->SectionLocalBase,
                                     0,
                                     0,
                                     NULL,
                                     &viewSize,
                                     ViewShare,
                                     0,
                                     PAGE_READWRITE);
    PrintNtResult(L"NtMapViewOfSection(local write view)", status);
    if (NT_SUCCESS(status) && ctx->SectionLocalBase != NULL) {
        const char marker[] = "DataProtector benign section-map trigger";
        CopyMemory(ctx->SectionLocalBase, marker, sizeof(marker));
    }

    viewSize = 0;
    status = api->NtMapViewOfSection(ctx->SectionHandle,
                                     ctx->ProcessHandle,
                                     &ctx->SectionRemoteBase,
                                     0,
                                     0,
                                     NULL,
                                     &viewSize,
                                     ViewShare,
                                     0,
                                     PAGE_EXECUTE_READ);
    PrintNtResult(L"NtMapViewOfSection(remote executable view)", status);
}

static void TriggerHollowingLikeAtoms(const NativeApi *api, TestContext *ctx, bool resumePrimaryThread)
{
    CONTEXT threadContext;
    BOOL gotContext;
    BOOL setContext;
    NTSTATUS status;
    ULONG previousSuspendCount = 0;

    if (api == NULL || ctx == NULL) {
        return;
    }

    if (ctx->ThreadHandle != NULL) {
        status = api->NtSuspendThread(ctx->ThreadHandle, &previousSuspendCount);
        PrintNtResult(L"NtSuspendThread(primary target thread)", status);
    }

    if (ctx->ProcessHandle != NULL) {
        status = api->NtSuspendProcess(ctx->ProcessHandle);
        PrintNtResult(L"NtSuspendProcess(target process)", status);
    }

    if (ctx->ProcessHandle != NULL) {
        PVOID remotePebLikeAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x10000));
        status = api->NtUnmapViewOfSection(ctx->ProcessHandle, remotePebLikeAddress);
        PrintNtResult(L"NtUnmapViewOfSection(non-critical address)", status);
    }

    if (ctx->ThreadHandle != NULL) {
        ZeroMemory(&threadContext, sizeof(threadContext));
        threadContext.ContextFlags = CONTEXT_CONTROL;
        gotContext = GetThreadContext(ctx->ThreadHandle, &threadContext);
        PrintWin32Result(L"GetThreadContext(primary target thread)", gotContext);

        if (gotContext) {
            setContext = SetThreadContext(ctx->ThreadHandle, &threadContext);
            PrintWin32Result(L"SetThreadContext(no-op primary context)", setContext);
        }

        if (resumePrimaryThread) {
            DWORD previous = ResumeThread(ctx->ThreadHandle);
            PrintWin32Result(L"ResumeThread(primary target thread)", previous != (DWORD)-1);
        } else {
            wprintf(L"[SKIP]   ResumeThread(primary target thread) disabled by default.\n");
        }
    }
}

static void CleanupContext(const NativeApi *api, TestContext *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (api != NULL && ctx->SectionRemoteBase != NULL && ctx->ProcessHandle != NULL) {
        (void)api->NtUnmapViewOfSection(ctx->ProcessHandle, ctx->SectionRemoteBase);
        ctx->SectionRemoteBase = NULL;
    }

    if (api != NULL && ctx->SectionLocalBase != NULL) {
        (void)api->NtUnmapViewOfSection(GetCurrentProcess(), ctx->SectionLocalBase);
        ctx->SectionLocalBase = NULL;
    }

    if (ctx->SectionHandle != NULL) {
        CloseHandle(ctx->SectionHandle);
        ctx->SectionHandle = NULL;
    }

    if (ctx->RemoteBuffer != NULL && ctx->ProcessHandle != NULL) {
        VirtualFreeEx(ctx->ProcessHandle, ctx->RemoteBuffer, 0, MEM_RELEASE);
        ctx->RemoteBuffer = NULL;
    }

    if (api != NULL && ctx->RemoteBuffer2 != NULL && ctx->ProcessHandle != NULL) {
        PVOID base = ctx->RemoteBuffer2;
        VirtualFreeEx(ctx->ProcessHandle, base, 0, MEM_RELEASE);
        ctx->RemoteBuffer2 = NULL;
    }

    if (ctx->ProcessInfo.hProcess != NULL) {
        TerminateProcess(ctx->ProcessInfo.hProcess, 0);
        WaitForSingleObject(ctx->ProcessInfo.hProcess, 3000);
    }

    if (ctx->ProcessHandle != NULL && ctx->ProcessHandle != ctx->ProcessInfo.hProcess) {
        CloseHandle(ctx->ProcessHandle);
        ctx->ProcessHandle = NULL;
    }

    if (ctx->ThreadHandle != NULL && ctx->ThreadHandle != ctx->ProcessInfo.hThread) {
        CloseHandle(ctx->ThreadHandle);
        ctx->ThreadHandle = NULL;
    }

    if (ctx->ProcessInfo.hThread != NULL) {
        CloseHandle(ctx->ProcessInfo.hThread);
        ctx->ProcessInfo.hThread = NULL;
    }

    if (ctx->ProcessInfo.hProcess != NULL) {
        CloseHandle(ctx->ProcessInfo.hProcess);
        ctx->ProcessInfo.hProcess = NULL;
    }
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *target = kDefaultTarget;
    bool loadRuntime = true;
    bool resumeRemoteThread = false;
    bool resumePrimaryThread = false;
    NativeApi api;
    TestContext ctx;
    int i;

    for (i = 1; i < argc; i++) {
        if (EqualsArg(argv[i], L"--help") || EqualsArg(argv[i], L"-h") || EqualsArg(argv[i], L"/?")) {
            PrintUsage();
            return 0;
        }

        if (EqualsArg(argv[i], L"--target")) {
            if (i + 1 >= argc) {
                wprintf(L"[FAIL]   --target requires a path.\n");
                return 2;
            }
            target = argv[++i];
            continue;
        }

        if (EqualsArg(argv[i], L"--no-runtime")) {
            loadRuntime = false;
            continue;
        }

        if (EqualsArg(argv[i], L"--resume-remote-thread")) {
            resumeRemoteThread = true;
            continue;
        }

        if (EqualsArg(argv[i], L"--resume-primary-thread")) {
            resumePrimaryThread = true;
            continue;
        }

        wprintf(L"[FAIL]   Unknown argument: %s\n", argv[i]);
        PrintUsage();
        return 2;
    }

    ZeroMemory(&ctx, sizeof(ctx));

    wprintf(L"[INFO]    DataProtector userhook trigger test starting.\n");
    wprintf(L"[INFO]    This program only targets its own suspended child process.\n");

    if (loadRuntime) {
        (void)LoadRuntimeFromExecutableDirectory();
    } else {
        wprintf(L"[INFO]    Runtime auto-load disabled by --no-runtime.\n");
    }

    if (!LoadNativeApi(&api)) {
        wprintf(L"[FAIL]   Required ntdll exports were not available.\n");
        return 3;
    }

    if (!CreateSuspendedTarget(target, &ctx)) {
        return 4;
    }

    TriggerKernelHandleAtoms(&ctx);
    TriggerWin32InjectionAtoms(&ctx, resumeRemoteThread);
    TriggerNativeInjectionAtoms(&api, &ctx);
    TriggerSectionMapAtoms(&api, &ctx);
    TriggerHollowingLikeAtoms(&api, &ctx, resumePrimaryThread);

    wprintf(L"[INFO]    Trigger pass completed. Check %s and the WebBridge audit page.\n", kRuntimeEventPath);
    CleanupContext(&api, &ctx);
    wprintf(L"[INFO]    Suspended child process cleaned up.\n");
    return 0;
}
