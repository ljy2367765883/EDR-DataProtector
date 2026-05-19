/*++

Module Name:

    DpUserHookDefense.c

Abstract:

    Application-layer API hook defense foundation. The module observes process
    creation and hook-sensitive image loads early from kernel callbacks, queues
    auditable events, and exposes policy plumbing for a signed defensive
    user-mode runtime.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>
#include <ntimage.h>

#if DP_ENABLE_USER_HOOK_DEFENSE_TRACE
#define DP_USER_HOOK_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[UserHook] " _format, __VA_ARGS__)
#else
#define DP_USER_HOOK_TRACE(_format, ...) ((void)0)
#endif

#define DP_USER_HOOK_DEDUP_SLOTS 128
#define DP_USER_HOOK_TARGET_SLOTS 1024
#define DP_USER_HOOK_DEDUP_WINDOW_100NS (10LL * 1000LL * 10000LL)
#define DP_USER_HOOK_MAX_APC_ATTEMPTS 3
#define DP_USER_HOOK_INJECT_STUB_BYTES 128

typedef
VOID
(NTAPI *PKNORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

typedef enum _DP_USER_HOOK_APC_ENVIRONMENT {
    DpUserHookOriginalApcEnvironment,
    DpUserHookAttachedApcEnvironment,
    DpUserHookCurrentApcEnvironment,
    DpUserHookInsertApcEnvironment
} DP_USER_HOOK_APC_ENVIRONMENT;

typedef enum _DP_USER_HOOK_MATCH_MODE {
    DpUserHookMatchProcessName = 0,
    DpUserHookMatchDirectory = 1,
    DpUserHookMatchExactPath = 2
} DP_USER_HOOK_MATCH_MODE;

typedef
VOID
(*DP_USER_HOOK_KERNEL_ROUTINE)(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2
    );

typedef
VOID
(*DP_USER_HOOK_RUNDOWN_ROUTINE)(
    _In_ PRKAPC Apc
    );

EXTERN_C
VOID
NTAPI
KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PRKTHREAD Thread,
    _In_ UCHAR ApcStateIndex,
    _In_ DP_USER_HOOK_KERNEL_ROUTINE KernelRoutine,
    _In_opt_ DP_USER_HOOK_RUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext
    );

EXTERN_C
BOOLEAN
NTAPI
KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
    );

static
VOID
DpUserHookQueueEvent(
    _In_ DP_USER_HOOK_DEFENSE_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_ ULONG Status,
    _In_opt_ PCUNICODE_STRING Target,
    _In_opt_ PCUNICODE_STRING ProcessImage,
    _In_ ULONG Flags
    );

static
BOOLEAN
DpUserHookImageHasSuffix(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_z_ PCWSTR Suffix
    );

typedef enum _DP_USER_HOOK_TARGET_STATE {
    DpUserHookTargetEmpty = 0,
    DpUserHookTargetPending = 1,
    DpUserHookTargetQueued = 2,
    DpUserHookTargetComplete = 3,
    DpUserHookTargetFailed = 4
} DP_USER_HOOK_TARGET_STATE;

typedef struct _DP_USER_HOOK_DEFENSE_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY Event;
} DP_USER_HOOK_DEFENSE_EVENT_ENTRY, *PDP_USER_HOOK_DEFENSE_EVENT_ENTRY;

typedef struct _DP_USER_HOOK_TARGET_ENTRY {
    HANDLE ProcessId;
    ULONG State;
    ULONG AttemptCount;
} DP_USER_HOOK_TARGET_ENTRY, *PDP_USER_HOOK_TARGET_ENTRY;

typedef struct _DP_USER_HOOK_APC_CONTEXT {
    KAPC Apc;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    PVOID RemoteDllPath;
    SIZE_T RemoteDllPathBytes;
    PVOID RemoteStub;
    SIZE_T RemoteStubBytes;
    PVOID LoadLibraryW;
    WCHAR RuntimePath[DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS];
    WCHAR ProcessImage[DP_USER_HOOK_DEFENSE_PROCESS_CHARS];
} DP_USER_HOOK_APC_CONTEXT, *PDP_USER_HOOK_APC_CONTEXT;

typedef struct _DP_USER_HOOK_DEDUP_ENTRY {
    BOOLEAN Valid;
    ULONGLONG ProcessId;
    ULONG Operation;
    ULONG TargetHash;
    LONGLONG LastSeenTime;
} DP_USER_HOOK_DEDUP_ENTRY, *PDP_USER_HOOK_DEDUP_ENTRY;

static LIST_ENTRY gDpUserHookEvents;
static KSPIN_LOCK gDpUserHookEventLock;
static EX_PUSH_LOCK gDpUserHookPolicyLock;
static volatile LONG gDpUserHookPolicyFlags = DP_USER_HOOK_DEFENSE_DEFAULT_FLAGS;
static WCHAR gDpUserHookExcludedProcessNames[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
static WCHAR gDpUserHookExcludedProcessDirectories[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
static WCHAR gDpUserHookExcludedProcessPaths[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
static WCHAR gDpUserHookTrustedSignerSubjects[DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS];
static WCHAR gDpUserHookRuntimeDllPath[DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS];
static ULONG gDpUserHookExcludedProcessNamesLengthBytes = 0;
static ULONG gDpUserHookExcludedProcessDirectoriesLengthBytes = 0;
static ULONG gDpUserHookExcludedProcessPathsLengthBytes = 0;
static ULONG gDpUserHookTrustedSignerSubjectsLengthBytes = 0;
static ULONG gDpUserHookRuntimeDllPathLengthBytes = 0;
static BOOLEAN gDpUserHookInitialized = FALSE;
static BOOLEAN gDpUserHookImageNotifyRegistered = FALSE;
static ULONG gDpUserHookEventCount = 0;
static ULONGLONG gDpUserHookEventSequence = 0;
static ULONGLONG gDpUserHookDroppedEvents = 0;
static DP_USER_HOOK_DEDUP_ENTRY gDpUserHookDedup[DP_USER_HOOK_DEDUP_SLOTS];
static DP_USER_HOOK_TARGET_ENTRY gDpUserHookTargets[DP_USER_HOOK_TARGET_SLOTS];
static KSPIN_LOCK gDpUserHookTargetLock;

static
ULONG
DpUserHookReadPolicyFlags(
    VOID
    )
{
    return (ULONG)gDpUserHookPolicyFlags;
}

static
ULONG
DpUserHookBoundedStringBytes(
    _In_reads_(MaxChars) const WCHAR *Buffer,
    _In_ ULONG MaxChars
    )
{
    ULONG index;

    if (Buffer == NULL || MaxChars == 0) {
        return 0;
    }

    for (index = 0; index < MaxChars; index++) {
        if (Buffer[index] == L'\0') {
            break;
        }
    }

    return index * sizeof(WCHAR);
}

static
BOOLEAN
DpUserHookFeatureEnabled(
    _In_ ULONG FeatureFlag
    )
{
    ULONG flags = DpUserHookReadPolicyFlags();

    return FlagOn(flags, DP_USER_HOOK_DEFENSE_FLAG_ENABLED) &&
           FlagOn(flags, FeatureFlag);
}

static
BOOLEAN
DpUserHookUnicodeEndsWithLiteral(
    _In_opt_ PCUNICODE_STRING Value,
    _In_z_ PCWSTR Suffix
    )
{
    UNICODE_STRING suffixString;

    if (Value == NULL || Value->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&suffixString, Suffix);
    return RtlSuffixUnicodeString(&suffixString, Value, TRUE);
}

static
BOOLEAN
DpUserHookUnicodeContainsLiteral(
    _In_opt_ PCUNICODE_STRING Value,
    _In_z_ PCWSTR Needle
    )
{
    UNICODE_STRING needleString;
    SIZE_T valueChars;
    SIZE_T needleChars;
    SIZE_T index;

    if (Value == NULL || Value->Buffer == NULL || Needle == NULL || Needle[0] == L'\0') {
        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    valueChars = Value->Length / sizeof(WCHAR);
    needleChars = needleString.Length / sizeof(WCHAR);
    if (valueChars < needleChars) {
        return FALSE;
    }

    for (index = 0; index <= valueChars - needleChars; index++) {
        UNICODE_STRING candidate;
        candidate.Buffer = Value->Buffer + index;
        candidate.Length = (USHORT)(needleChars * sizeof(WCHAR));
        candidate.MaximumLength = candidate.Length;

        if (RtlEqualUnicodeString(&candidate, &needleString, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpUserHookMatchListEntry(
    _In_reads_(LengthBytes) const WCHAR *List,
    _In_ ULONG LengthBytes,
    _In_ PCUNICODE_STRING Value,
    _In_ DP_USER_HOOK_MATCH_MODE MatchMode
    )
{
    ULONG chars;
    ULONG index = 0;

    if (List == NULL || LengthBytes == 0 || Value == NULL || Value->Buffer == NULL) {
        return FALSE;
    }

    chars = LengthBytes / sizeof(WCHAR);
    while (index < chars) {
        ULONG start;
        ULONG end;
        UNICODE_STRING token;

        while (index < chars &&
               (List[index] == L'\0' || List[index] == L'\r' || List[index] == L'\n' ||
                List[index] == L';' || List[index] == L',' || List[index] == L'\t' || List[index] == L' ')) {
            index++;
        }

        start = index;
        while (index < chars &&
               List[index] != L'\0' && List[index] != L'\r' && List[index] != L'\n' &&
               List[index] != L';' && List[index] != L',') {
            index++;
        }

        end = index;
        while (end > start && (List[end - 1] == L'\t' || List[end - 1] == L' ' || List[end - 1] == L'\\')) {
            end--;
        }

        if (end > start) {
            token.Buffer = (PWCHAR)&List[start];
            token.Length = (USHORT)((end - start) * sizeof(WCHAR));
            token.MaximumLength = token.Length;

            if (MatchMode == DpUserHookMatchProcessName) {
                if (RtlSuffixUnicodeString(&token, Value, TRUE)) {
                    return TRUE;
                }
            } else if (MatchMode == DpUserHookMatchExactPath) {
                if (RtlEqualUnicodeString(&token, Value, TRUE)) {
                    return TRUE;
                }
            } else if (Value->Length >= token.Length && RtlPrefixUnicodeString(&token, Value, TRUE)) {
                USHORT tokenChars = token.Length / sizeof(WCHAR);
                USHORT valueChars = Value->Length / sizeof(WCHAR);
                if (valueChars == tokenChars ||
                    Value->Buffer[tokenChars] == L'\\' ||
                    Value->Buffer[tokenChars] == L'/') {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static
BOOLEAN
DpUserHookIsBuiltInExcludedImage(
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    static const PCWSTR ExcludedNames[] = {
        L"\\DataProtectorWebBridge.exe",
        L"\\DataProtectorAgentClient.exe",
        L"\\DataProtectorAdmin.exe",
        L"\\DataProtectorUsbTool.exe",
        L"\\MsMpEng.exe",
        L"\\SecurityHealthService.exe",
        L"\\explorer.exe",
        L"\\dwm.exe",
        L"\\SearchIndexer.exe",
        L"\\SearchHost.exe",
        L"\\RuntimeBroker.exe",
        L"\\sihost.exe",
        L"\\StartMenuExperienceHost.exe",
        L"\\ShellExperienceHost.exe",
        L"\\TextInputHost.exe",
        L"\\ctfmon.exe",
        L"\\chrome.exe",
        L"\\msedge.exe",
        L"\\firefox.exe",
        L"\\brave.exe",
        L"\\opera.exe",
        L"\\vivaldi.exe",
        L"\\WINWORD.EXE",
        L"\\EXCEL.EXE",
        L"\\POWERPNT.EXE",
        L"\\OUTLOOK.EXE",
        L"\\Teams.exe",
        L"\\WeChat.exe",
        L"\\Weixin.exe",
        L"\\QQ.exe",
        L"\\DingTalk.exe",
        L"\\Feishu.exe"
    };
    static const PCWSTR ExcludedDirectories[] = {
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\",
        L"\\Windows\\WinSxS\\",
        L"\\Program Files\\DataProtector\\",
        L"\\Program Files (x86)\\DataProtector\\"
    };
    ULONG index;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(ExcludedNames); index++) {
        if (DpUserHookUnicodeEndsWithLiteral(ImagePath, ExcludedNames[index])) {
            return TRUE;
        }
    }

    for (index = 0; index < RTL_NUMBER_OF(ExcludedDirectories); index++) {
        if (DpUserHookUnicodeContainsLiteral(ImagePath, ExcludedDirectories[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpUserHookIsPolicyExcludedImage(
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    BOOLEAN excluded = FALSE;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        return FALSE;
    }

    FltAcquirePushLockShared(&gDpUserHookPolicyLock);

    excluded =
        DpUserHookMatchListEntry(gDpUserHookExcludedProcessNames,
                                 gDpUserHookExcludedProcessNamesLengthBytes,
                                 ImagePath,
                                 DpUserHookMatchProcessName) ||
        DpUserHookMatchListEntry(gDpUserHookExcludedProcessDirectories,
                                 gDpUserHookExcludedProcessDirectoriesLengthBytes,
                                 ImagePath,
                                 DpUserHookMatchDirectory) ||
        DpUserHookMatchListEntry(gDpUserHookExcludedProcessPaths,
                                 gDpUserHookExcludedProcessPathsLengthBytes,
                                 ImagePath,
                                 DpUserHookMatchExactPath);

    FltReleasePushLock(&gDpUserHookPolicyLock);

    return excluded;
}

static
BOOLEAN
DpUserHookShouldInjectProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    ULONG flags = DpUserHookReadPolicyFlags();

    if (!FlagOn(flags, DP_USER_HOOK_DEFENSE_FLAG_ENABLED) ||
        !FlagOn(flags, DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION) ||
        ImagePath == NULL ||
        ImagePath->Buffer == NULL ||
        ImagePath->Length == 0) {
        return FALSE;
    }

    if (!FlagOn(flags, DP_USER_HOOK_DEFENSE_FLAG_MONITOR_SYSTEM_PROCESSES) &&
        (ProcessId == NULL || ProcessId == (HANDLE)(ULONG_PTR)4)) {
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionSkipped,
                             ProcessId,
                             NULL,
                             STATUS_SUCCESS,
                             ImagePath,
                             ImagePath,
                             flags);
        return FALSE;
    }

    if (DpUserHookIsBuiltInExcludedImage(ImagePath) ||
        DpUserHookIsPolicyExcludedImage(ImagePath)) {
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionSkipped,
                             ProcessId,
                             NULL,
                             STATUS_SUCCESS,
                             ImagePath,
                             ImagePath,
                             flags);
        return FALSE;
    }

    return TRUE;
}

static
VOID
DpUserHookTrackTargetProcess(
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG emptyIndex = MAXULONG;

    if (ProcessId == NULL) {
        return;
    }

    KeAcquireSpinLock(&gDpUserHookTargetLock, &oldIrql);

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookTargets); index++) {
        if (gDpUserHookTargets[index].ProcessId == ProcessId) {
            gDpUserHookTargets[index].State = DpUserHookTargetPending;
            gDpUserHookTargets[index].AttemptCount = 0;
            KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
            return;
        }

        if (gDpUserHookTargets[index].ProcessId == NULL && emptyIndex == MAXULONG) {
            emptyIndex = index;
        }
    }

    if (emptyIndex != MAXULONG) {
        gDpUserHookTargets[emptyIndex].ProcessId = ProcessId;
        gDpUserHookTargets[emptyIndex].State = DpUserHookTargetPending;
        gDpUserHookTargets[emptyIndex].AttemptCount = 0;
    } else {
        ULONG replaceIndex = (ULONG)((ULONG_PTR)ProcessId % RTL_NUMBER_OF(gDpUserHookTargets));
        gDpUserHookTargets[replaceIndex].ProcessId = ProcessId;
        gDpUserHookTargets[replaceIndex].State = DpUserHookTargetPending;
        gDpUserHookTargets[replaceIndex].AttemptCount = 0;
    }

    KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
}

static
VOID
DpUserHookUntrackTargetProcess(
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG index;

    if (ProcessId == NULL) {
        return;
    }

    KeAcquireSpinLock(&gDpUserHookTargetLock, &oldIrql);

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookTargets); index++) {
        if (gDpUserHookTargets[index].ProcessId == ProcessId) {
            RtlZeroMemory(&gDpUserHookTargets[index], sizeof(gDpUserHookTargets[index]));
            break;
        }
    }

    KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
}

static
BOOLEAN
DpUserHookIsTrackedTargetProcess(
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG index;
    BOOLEAN found = FALSE;

    if (ProcessId == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(&gDpUserHookTargetLock, &oldIrql);

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookTargets); index++) {
        if (gDpUserHookTargets[index].ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
    return found;
}

static
BOOLEAN
DpUserHookMarkTargetInjectionQueued(
    _In_ HANDLE ProcessId,
    _Out_ PULONG AttemptCount
    )
{
    KIRQL oldIrql;
    ULONG index;
    BOOLEAN shouldQueue = FALSE;

    if (AttemptCount != NULL) {
        *AttemptCount = 0;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(&gDpUserHookTargetLock, &oldIrql);

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookTargets); index++) {
        if (gDpUserHookTargets[index].ProcessId == ProcessId) {
            if (gDpUserHookTargets[index].State == DpUserHookTargetPending ||
                gDpUserHookTargets[index].State == DpUserHookTargetFailed) {

                gDpUserHookTargets[index].State = DpUserHookTargetQueued;
                gDpUserHookTargets[index].AttemptCount++;
                if (AttemptCount != NULL) {
                    *AttemptCount = gDpUserHookTargets[index].AttemptCount;
                }
                shouldQueue = TRUE;
            }
            break;
        }
    }

    KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
    return shouldQueue;
}

static
VOID
DpUserHookMarkTargetInjectionComplete(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Succeeded
    )
{
    KIRQL oldIrql;
    ULONG index;

    if (ProcessId == NULL) {
        return;
    }

    KeAcquireSpinLock(&gDpUserHookTargetLock, &oldIrql);

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookTargets); index++) {
        if (gDpUserHookTargets[index].ProcessId == ProcessId) {
            gDpUserHookTargets[index].State = Succeeded ? DpUserHookTargetComplete : DpUserHookTargetFailed;
            break;
        }
    }

    KeReleaseSpinLock(&gDpUserHookTargetLock, oldIrql);
}

static
VOID
DpUserHookCopyUnicode(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _Out_ PULONG BytesCopied
    )
{
    ULONG bytesToCopy;

    *BytesCopied = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    bytesToCopy = min(Source->Length, (ULONG)((DestinationChars - 1) * sizeof(WCHAR)));
    RtlCopyMemory(Destination, Source->Buffer, bytesToCopy);
    Destination[bytesToCopy / sizeof(WCHAR)] = L'\0';
    *BytesCopied = bytesToCopy;
}

static
ULONG
DpUserHookHashUnicodeBuffer(
    _In_reads_bytes_opt_(LengthBytes) PCWCHAR Buffer,
    _In_ ULONG LengthBytes
    )
{
    ULONG hash = 2166136261u;
    ULONG index;
    ULONG chars = LengthBytes / sizeof(WCHAR);

    if (Buffer == NULL || LengthBytes == 0) {
        return hash;
    }

    for (index = 0; index < chars; index++) {
        WCHAR character = RtlUpcaseUnicodeChar(Buffer[index]);
        hash ^= (ULONG)character;
        hash *= 16777619u;
    }

    return hash;
}

static
BOOLEAN
DpUserHookSuppressDuplicateLocked(
    _In_ const DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY *Event,
    _In_ LONGLONG CurrentTime,
    _In_ ULONG TargetHash
    )
{
    ULONG index;
    ULONG replaceIndex = 0;
    LONGLONG oldestTime = MAXLONGLONG;
    PDP_USER_HOOK_DEDUP_ENTRY slot;

    for (index = 0; index < RTL_NUMBER_OF(gDpUserHookDedup); index++) {
        slot = &gDpUserHookDedup[index];

        if (!slot->Valid) {
            replaceIndex = index;
            oldestTime = MINLONGLONG;
            continue;
        }

        if (slot->LastSeenTime < oldestTime) {
            oldestTime = slot->LastSeenTime;
            replaceIndex = index;
        }

        if (slot->ProcessId == Event->ProcessId &&
            slot->Operation == Event->Operation &&
            slot->TargetHash == TargetHash) {

            if (CurrentTime >= slot->LastSeenTime &&
                CurrentTime - slot->LastSeenTime <= DP_USER_HOOK_DEDUP_WINDOW_100NS) {

                slot->LastSeenTime = CurrentTime;
                return TRUE;
            }

            replaceIndex = index;
            break;
        }
    }

    slot = &gDpUserHookDedup[replaceIndex];
    RtlZeroMemory(slot, sizeof(*slot));
    slot->Valid = TRUE;
    slot->ProcessId = Event->ProcessId;
    slot->Operation = Event->Operation;
    slot->TargetHash = TargetHash;
    slot->LastSeenTime = CurrentTime;

    UNREFERENCED_PARAMETER(oldestTime);

    return FALSE;
}

static
VOID
DpUserHookFreeEvent(
    _In_opt_ PDP_USER_HOOK_DEFENSE_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_USER_HOOK_DEFENSE);
    }
}

static
VOID
DpUserHookClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gDpUserHookInitialized) {
        return;
    }

    KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);
    while (!IsListEmpty(&gDpUserHookEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpUserHookEvents);
        PDP_USER_HOOK_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                                    DP_USER_HOOK_DEFENSE_EVENT_ENTRY,
                                                                    Link);
        gDpUserHookEventCount--;
        KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
        DpUserHookFreeEvent(event);
        KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
}

static
VOID
DpUserHookQueueEvent(
    _In_ DP_USER_HOOK_DEFENSE_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_ ULONG Status,
    _In_opt_ PCUNICODE_STRING Target,
    _In_opt_ PCUNICODE_STRING ProcessImage,
    _In_ ULONG Flags
    )
{
    PDP_USER_HOOK_DEFENSE_EVENT_ENTRY entry;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    ULONG targetHash;
    ULONGLONG sequence;
    ULONG eventCount;
    ULONGLONG droppedEvents;
    UNICODE_STRING targetText;
    UNICODE_STRING processText;

    if (!gDpUserHookInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_USER_HOOK_DEFENSE_EVENT_ENTRY),
                                  DP_TAG_USER_HOOK_DEFENSE);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);
        gDpUserHookDroppedEvents++;
        droppedEvents = gDpUserHookDroppedEvents;
        KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
        DP_USER_HOOK_TRACE("queue alloc failed pid=%p op=%lu dropped=%I64u\n",
                           ProcessId,
                           (ULONG)Operation,
                           droppedEvents);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_USER_HOOK_DEFENSE_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.ParentProcessId = (ULONGLONG)(ULONG_PTR)ParentProcessId;
    entry->Event.Operation = (ULONG)Operation;
    entry->Event.Status = Status;
    entry->Event.Flags = Flags;
    DpUserHookCopyUnicode(entry->Event.Target,
                          RTL_NUMBER_OF(entry->Event.Target),
                          Target,
                          &entry->Event.TargetLengthBytes);
    DpUserHookCopyUnicode(entry->Event.ProcessImage,
                          RTL_NUMBER_OF(entry->Event.ProcessImage),
                          ProcessImage,
                          &entry->Event.ProcessImageLengthBytes);

    targetHash = DpUserHookHashUnicodeBuffer(entry->Event.Target,
                                             entry->Event.TargetLengthBytes);
    KeQuerySystemTime(&currentTime);

    KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);

    if (DpUserHookSuppressDuplicateLocked(&entry->Event,
                                          currentTime.QuadPart,
                                          targetHash)) {
        KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
        DpUserHookFreeEvent(entry);
        return;
    }

    entry->Event.Sequence = ++gDpUserHookEventSequence;
    InsertTailList(&gDpUserHookEvents, &entry->Link);
    gDpUserHookEventCount++;

    while (gDpUserHookEventCount > DP_USER_HOOK_DEFENSE_MAX_EVENTS &&
           !IsListEmpty(&gDpUserHookEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gDpUserHookEvents);
        PDP_USER_HOOK_DEFENSE_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink,
                                                                       DP_USER_HOOK_DEFENSE_EVENT_ENTRY,
                                                                       Link);
        gDpUserHookEventCount--;
        gDpUserHookDroppedEvents++;
        KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
        DpUserHookFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);
    }

    sequence = entry->Event.Sequence;
    eventCount = gDpUserHookEventCount;
    droppedEvents = gDpUserHookDroppedEvents;
    KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);

    targetText.Buffer = entry->Event.Target;
    targetText.Length = (USHORT)entry->Event.TargetLengthBytes;
    targetText.MaximumLength = (USHORT)sizeof(entry->Event.Target);
    processText.Buffer = entry->Event.ProcessImage;
    processText.Length = (USHORT)entry->Event.ProcessImageLengthBytes;
    processText.MaximumLength = (USHORT)sizeof(entry->Event.ProcessImage);

    DP_USER_HOOK_TRACE("queued seq=%I64u count=%lu dropped=%I64u pid=%p parent=%p op=%lu status=0x%08X flags=0x%08X target=%wZ image=%wZ\n",
                       sequence,
                       eventCount,
                       droppedEvents,
                       ProcessId,
                       ParentProcessId,
                       (ULONG)Operation,
                       Status,
                       Flags,
                       &targetText,
                       &processText);
}

static
VOID
DpUserHookGetRuntimeDllPath(
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ ULONG PathChars,
    _Out_ PULONG PathLengthBytes
    )
{
    ULONG bytesToCopy;

    if (PathLengthBytes != NULL) {
        *PathLengthBytes = 0;
    }

    if (Path == NULL || PathChars == 0) {
        return;
    }

    Path[0] = L'\0';

    FltAcquirePushLockShared(&gDpUserHookPolicyLock);
    bytesToCopy = min(gDpUserHookRuntimeDllPathLengthBytes,
                      (ULONG)((PathChars - 1) * sizeof(WCHAR)));
    if (bytesToCopy != 0) {
        RtlCopyMemory(Path, gDpUserHookRuntimeDllPath, bytesToCopy);
        Path[bytesToCopy / sizeof(WCHAR)] = L'\0';
    }
    FltReleasePushLock(&gDpUserHookPolicyLock);

    if (PathLengthBytes != NULL) {
        *PathLengthBytes = DpUserHookBoundedStringBytes(Path, PathChars);
    }
}

static
BOOLEAN
DpUserHookRuntimePathConfigured(
    VOID
    )
{
    BOOLEAN configured;

    FltAcquirePushLockShared(&gDpUserHookPolicyLock);
    configured = gDpUserHookRuntimeDllPathLengthBytes != 0 &&
                 gDpUserHookRuntimeDllPath[0] != L'\0';
    FltReleasePushLock(&gDpUserHookPolicyLock);

    return configured;
}

static
NTSTATUS
DpUserHookFindKernel32LoadLibraryW(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Outptr_ PVOID *LoadLibraryAddress
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    ULONG exportRva;
    ULONG exportSize;
    PIMAGE_EXPORT_DIRECTORY exports;
    PULONG names;
    PUSHORT ordinals;
    PULONG functions;
    ULONG index;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (LoadLibraryAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *LoadLibraryAddress = NULL;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
            dosHeader->e_lfanew <= 0 ||
            (SIZE_T)dosHeader->e_lfanew > ImageSize - sizeof(IMAGE_NT_HEADERS)) {

            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {

            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0 || exportSize < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            exportRva >= ImageSize ||
            exportSize > ImageSize - exportRva) {

            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageBase + exportRva);
        names = (PULONG)((PUCHAR)ImageBase + exports->AddressOfNames);
        ordinals = (PUSHORT)((PUCHAR)ImageBase + exports->AddressOfNameOrdinals);
        functions = (PULONG)((PUCHAR)ImageBase + exports->AddressOfFunctions);

        if (exports->AddressOfNames >= ImageSize ||
            exports->AddressOfNameOrdinals >= ImageSize ||
            exports->AddressOfFunctions >= ImageSize) {

            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        for (index = 0; index < exports->NumberOfNames; index++) {
            const CHAR *name;

            if (names[index] >= ImageSize) {
                continue;
            }

            name = (const CHAR *)((PUCHAR)ImageBase + names[index]);
            if (strcmp(name, "LoadLibraryW") == 0) {
                USHORT ordinal = ordinals[index];
                ULONG functionRva;

                if (ordinal >= exports->NumberOfFunctions) {
                    break;
                }

                functionRva = functions[ordinal];
                if (functionRva == 0 || functionRva >= ImageSize) {
                    break;
                }

                *LoadLibraryAddress = (PUCHAR)ImageBase + functionRva;
                status = STATUS_SUCCESS;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static
VOID
DpUserHookWritePointer(
    _Out_writes_bytes_(sizeof(PVOID)) PUCHAR Destination,
    _In_ PVOID Value
    )
{
    ULONG_PTR encoded = (ULONG_PTR)Value;
    RtlCopyMemory(Destination, &encoded, sizeof(encoded));
}

static
VOID
DpUserHookBuildLoadLibraryStub(
    _Out_writes_bytes_(StubBytes) PUCHAR Stub,
    _In_ SIZE_T StubBytes,
    _In_ PVOID LoadLibraryW,
    _In_ PVOID RemoteDllPath
    )
{
    PUCHAR cursor;

    RtlZeroMemory(Stub, StubBytes);
    cursor = Stub;

    *cursor++ = 0x48; *cursor++ = 0x83; *cursor++ = 0xEC; *cursor++ = 0x28;
    *cursor++ = 0x48; *cursor++ = 0xB9;
    DpUserHookWritePointer(cursor, RemoteDllPath);
    cursor += sizeof(ULONG_PTR);
    *cursor++ = 0x48; *cursor++ = 0xB8;
    DpUserHookWritePointer(cursor, LoadLibraryW);
    cursor += sizeof(ULONG_PTR);
    *cursor++ = 0xFF; *cursor++ = 0xD0;
    *cursor++ = 0x48; *cursor++ = 0x83; *cursor++ = 0xC4; *cursor++ = 0x28;
    *cursor++ = 0xC3;
}

static
VOID
DpUserHookFreeApcContext(
    _In_opt_ PDP_USER_HOOK_APC_CONTEXT Context,
    _In_ BOOLEAN FreeRemoteMemory
    )
{
    if (Context == NULL) {
        return;
    }

    if (FreeRemoteMemory && Context->RemoteDllPath != NULL) {
        SIZE_T regionSize = 0;
        PVOID base = Context->RemoteDllPath;
        (VOID)ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &regionSize, MEM_RELEASE);
        Context->RemoteDllPath = NULL;
    }

    if (FreeRemoteMemory && Context->RemoteStub != NULL) {
        SIZE_T regionSize = 0;
        PVOID base = Context->RemoteStub;
        (VOID)ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &regionSize, MEM_RELEASE);
        Context->RemoteStub = NULL;
    }

    ExFreePoolWithTag(Context, DP_TAG_USER_HOOK_DEFENSE);
}

static
VOID
DpUserHookApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2
    )
{
    PDP_USER_HOOK_APC_CONTEXT context;

    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    context = CONTAINING_RECORD(Apc, DP_USER_HOOK_APC_CONTEXT, Apc);
    if (NormalRoutine == NULL || *NormalRoutine == NULL) {
        DpUserHookMarkTargetInjectionComplete(context->ProcessId, FALSE);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                             context->ProcessId,
                             context->ParentProcessId,
                             (ULONG)STATUS_CANCELLED,
                             NULL,
                             NULL,
                             DpUserHookReadPolicyFlags());
        DpUserHookFreeApcContext(context, TRUE);
        return;
    }

    DpUserHookMarkTargetInjectionComplete(context->ProcessId, TRUE);
    DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionQueued,
                         context->ProcessId,
                         context->ParentProcessId,
                         STATUS_SUCCESS,
                         NULL,
                         NULL,
                         DpUserHookReadPolicyFlags());

    DpUserHookFreeApcContext(context, FALSE);
}

static
VOID
DpUserHookApcRundownRoutine(
    _In_ PRKAPC Apc
    )
{
    PDP_USER_HOOK_APC_CONTEXT context;

    context = CONTAINING_RECORD(Apc, DP_USER_HOOK_APC_CONTEXT, Apc);
    DpUserHookMarkTargetInjectionComplete(context->ProcessId, FALSE);
    DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                         context->ProcessId,
                         context->ParentProcessId,
                         (ULONG)STATUS_CANCELLED,
                         NULL,
                         NULL,
                         DpUserHookReadPolicyFlags());

    DpUserHookFreeApcContext(context, TRUE);
}

static
NTSTATUS
DpUserHookQueueRuntimeApc(
    _In_ PETHREAD Thread,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_ PVOID LoadLibraryW,
    _In_ PCUNICODE_STRING RuntimeDllPath,
    _In_opt_ PCUNICODE_STRING ProcessImage
    )
{
    PDP_USER_HOOK_APC_CONTEXT context;
    SIZE_T pathBytes;
    SIZE_T regionSize;
    NTSTATUS status;
    PUCHAR stub;

    if (Thread == NULL || LoadLibraryW == NULL ||
        RuntimeDllPath == NULL || RuntimeDllPath->Buffer == NULL ||
        RuntimeDllPath->Length == 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if ((SIZE_T)RuntimeDllPath->Length > DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS * sizeof(WCHAR) - sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }

    pathBytes = RuntimeDllPath->Length + sizeof(WCHAR);
    if (pathBytes > DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS * sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }

    context = ExAllocatePoolWithTag(NonPagedPoolNx,
                                    sizeof(DP_USER_HOOK_APC_CONTEXT),
                                    DP_TAG_USER_HOOK_DEFENSE);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->ProcessId = ProcessId;
    context->ParentProcessId = ParentProcessId;
    context->LoadLibraryW = LoadLibraryW;
    RtlCopyMemory(context->RuntimePath, RuntimeDllPath->Buffer, RuntimeDllPath->Length);
    context->RuntimePath[RuntimeDllPath->Length / sizeof(WCHAR)] = L'\0';
    if (ProcessImage != NULL && ProcessImage->Buffer != NULL && ProcessImage->Length != 0) {
        ULONG imageBytes = min(ProcessImage->Length,
                               (ULONG)(sizeof(context->ProcessImage) - sizeof(WCHAR)));
        RtlCopyMemory(context->ProcessImage, ProcessImage->Buffer, imageBytes);
        context->ProcessImage[imageBytes / sizeof(WCHAR)] = L'\0';
    }

    regionSize = pathBytes;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(),
                                     &context->RemoteDllPath,
                                     0,
                                     &regionSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DpUserHookFreeApcContext(context, TRUE);
        return status;
    }

    context->RemoteDllPathBytes = regionSize;
    __try {
        RtlCopyMemory(context->RemoteDllPath, context->RuntimePath, pathBytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        DpUserHookFreeApcContext(context, TRUE);
        return status;
    }

    regionSize = DP_USER_HOOK_INJECT_STUB_BYTES;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(),
                                     &context->RemoteStub,
                                     0,
                                     &regionSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DpUserHookFreeApcContext(context, TRUE);
        return status;
    }

    context->RemoteStubBytes = regionSize;
    stub = ExAllocatePoolWithTag(NonPagedPoolNx,
                                 DP_USER_HOOK_INJECT_STUB_BYTES,
                                 DP_TAG_USER_HOOK_DEFENSE);
    if (stub == NULL) {
        DpUserHookFreeApcContext(context, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DpUserHookBuildLoadLibraryStub(stub,
                                   DP_USER_HOOK_INJECT_STUB_BYTES,
                                   LoadLibraryW,
                                   context->RemoteDllPath);
    __try {
        RtlCopyMemory(context->RemoteStub, stub, DP_USER_HOOK_INJECT_STUB_BYTES);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ExFreePoolWithTag(stub, DP_TAG_USER_HOOK_DEFENSE);
    if (!NT_SUCCESS(status)) {
        DpUserHookFreeApcContext(context, TRUE);
        return status;
    }

    KeInitializeApc(&context->Apc,
                    (PRKTHREAD)Thread,
                    DpUserHookOriginalApcEnvironment,
                    DpUserHookApcKernelRoutine,
                    DpUserHookApcRundownRoutine,
                    (PKNORMAL_ROUTINE)context->RemoteStub,
                    UserMode,
                    NULL);

    if (!KeInsertQueueApc(&context->Apc, NULL, NULL, 0)) {
        DpUserHookFreeApcContext(context, TRUE);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static
VOID
DpUserHookTryQueueRuntimeInjection(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    NTSTATUS status;
    ULONG attemptCount;
    WCHAR runtimePathBuffer[DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS];
    ULONG runtimePathBytes;
    UNICODE_STRING runtimePath;
    PETHREAD currentThread;
    PETHREAD targetThread = NULL;
    PEPROCESS threadProcess;
    PVOID loadLibraryW = NULL;

    if (ImageInfo == NULL ||
        ProcessId == NULL ||
        !DpUserHookFeatureEnabled(DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_INJECTION) ||
        !DpUserHookIsTrackedTargetProcess(ProcessId) ||
        !DpUserHookImageHasSuffix(FullImageName, L"\\kernel32.dll")) {

        return;
    }

    if (!DpUserHookRuntimePathConfigured()) {
        UNICODE_STRING missingTarget;
        RtlInitUnicodeString(&missingTarget, L"DataProtectorUserHookRuntime.dll");
        DpUserHookMarkTargetInjectionComplete(ProcessId, FALSE);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeMissing,
                             ProcessId,
                             NULL,
                             (ULONG)STATUS_OBJECT_NAME_NOT_FOUND,
                             &missingTarget,
                             NULL,
                             DpUserHookReadPolicyFlags());
        return;
    }

    if (!DpUserHookMarkTargetInjectionQueued(ProcessId, &attemptCount)) {
        return;
    }

    if (attemptCount > DP_USER_HOOK_MAX_APC_ATTEMPTS) {
        DpUserHookMarkTargetInjectionComplete(ProcessId, FALSE);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                             ProcessId,
                             NULL,
                             (ULONG)STATUS_RETRY,
                             FullImageName,
                             NULL,
                             DpUserHookReadPolicyFlags());
        return;
    }

    status = DpUserHookFindKernel32LoadLibraryW(ImageInfo->ImageBase,
                                                ImageInfo->ImageSize,
                                                &loadLibraryW);
    if (!NT_SUCCESS(status)) {
        DpUserHookTrackTargetProcess(ProcessId);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                             ProcessId,
                             NULL,
                             (ULONG)status,
                             FullImageName,
                             NULL,
                             DpUserHookReadPolicyFlags());
        return;
    }

    currentThread = PsGetCurrentThread();
    threadProcess = PsGetThreadProcess(currentThread);
    if (threadProcess == NULL || PsGetProcessId(threadProcess) != ProcessId) {
        DpUserHookTrackTargetProcess(ProcessId);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                             ProcessId,
                             NULL,
                             (ULONG)STATUS_NOT_SAME_DEVICE,
                             FullImageName,
                             NULL,
                             DpUserHookReadPolicyFlags());
        return;
    }

    targetThread = currentThread;
    ObReferenceObject(targetThread);

    DpUserHookGetRuntimeDllPath(runtimePathBuffer,
                                RTL_NUMBER_OF(runtimePathBuffer),
                                &runtimePathBytes);
    runtimePath.Buffer = runtimePathBuffer;
    runtimePath.Length = (USHORT)runtimePathBytes;
    runtimePath.MaximumLength = sizeof(runtimePathBuffer);

    status = DpUserHookQueueRuntimeApc(targetThread,
                                       ProcessId,
                                       NULL,
                                       loadLibraryW,
                                       &runtimePath,
                                       NULL);
    ObDereferenceObject(targetThread);

    if (!NT_SUCCESS(status)) {
        DpUserHookTrackTargetProcess(ProcessId);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionFailed,
                             ProcessId,
                             NULL,
                             (ULONG)status,
                             &runtimePath,
                             NULL,
                             DpUserHookReadPolicyFlags());
        return;
    }

    DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionQueued,
                         ProcessId,
                         NULL,
                         (ULONG)STATUS_PENDING,
                         &runtimePath,
                         NULL,
                         DpUserHookReadPolicyFlags());
}

static
BOOLEAN
DpUserHookImageHasSuffix(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_z_ PCWSTR Suffix
    )
{
    UNICODE_STRING suffixString;

    if (FullImageName == NULL || FullImageName->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&suffixString, Suffix);
    return RtlSuffixUnicodeString(&suffixString, FullImageName, TRUE);
}

static
BOOLEAN
DpUserHookIsHookSensitiveImage(
    _In_opt_ PUNICODE_STRING FullImageName
    )
{
    static const PCWSTR HookSensitiveImages[] = {
        L"\\ntdll.dll",
        L"\\kernel32.dll",
        L"\\kernelbase.dll",
        L"\\user32.dll",
        L"\\advapi32.dll",
        L"\\wininet.dll",
        L"\\winhttp.dll",
        L"\\ws2_32.dll",
        L"\\crypt32.dll",
        L"\\bcrypt.dll",
        L"\\amsi.dll",
        L"\\dbghelp.dll",
        L"\\psapi.dll",
        L"\\version.dll"
    };
    ULONG index;

    for (index = 0; index < RTL_NUMBER_OF(HookSensitiveImages); index++) {
        if (DpUserHookImageHasSuffix(FullImageName, HookSensitiveImages[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
DpUserHookLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!DpUserHookIsTrackedTargetProcess(ProcessId)) {
        return;
    }

    DpUserHookTryQueueRuntimeInjection(ProcessId, FullImageName, ImageInfo);

    if (!DpUserHookFeatureEnabled(DP_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR) ||
        !DpUserHookIsHookSensitiveImage(FullImageName)) {

        return;
    }

    DpUserHookQueueEvent(DpUserHookDefenseOperationHookSurfaceImageLoad,
                         ProcessId,
                         NULL,
                         STATUS_SUCCESS,
                         FullImageName,
                         NULL,
                         DpUserHookReadPolicyFlags());
}

VOID
DpUserHookDefenseObserveProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    HANDLE parentProcessId = NULL;
    UNICODE_STRING runtimeTarget;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        DpUserHookUntrackTargetProcess(ProcessId);
        return;
    }

    if (!DpUserHookShouldInjectProcess(ProcessId, CreateInfo->ImageFileName)) {

        return;
    }

    parentProcessId = CreateInfo->ParentProcessId;
    DpUserHookTrackTargetProcess(ProcessId);

    RtlInitUnicodeString(&runtimeTarget, L"DataProtectorUserHookRuntime.dll");

    if (!DpUserHookRuntimePathConfigured()) {
        DpUserHookMarkTargetInjectionComplete(ProcessId, FALSE);
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeMissing,
                             ProcessId,
                             parentProcessId,
                             (ULONG)STATUS_OBJECT_NAME_NOT_FOUND,
                             &runtimeTarget,
                             CreateInfo->ImageFileName,
                             DpUserHookReadPolicyFlags());
        return;
    }

    DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeInjectionRequired,
                         ProcessId,
                         parentProcessId,
                         STATUS_PENDING,
                         &runtimeTarget,
                         CreateInfo->ImageFileName,
                         DpUserHookReadPolicyFlags());
}

NTSTATUS
DpUserHookDefenseInitialize(
    VOID
    )
{
    NTSTATUS status;

    InitializeListHead(&gDpUserHookEvents);
    KeInitializeSpinLock(&gDpUserHookEventLock);
    KeInitializeSpinLock(&gDpUserHookTargetLock);
    FltInitializePushLock(&gDpUserHookPolicyLock);
    InterlockedExchange((volatile LONG *)&gDpUserHookPolicyFlags,
                        (LONG)DP_USER_HOOK_DEFENSE_DEFAULT_FLAGS);
    gDpUserHookEventCount = 0;
    gDpUserHookEventSequence = 0;
    gDpUserHookDroppedEvents = 0;
    RtlZeroMemory(gDpUserHookDedup, sizeof(gDpUserHookDedup));
    RtlZeroMemory(gDpUserHookTargets, sizeof(gDpUserHookTargets));
    RtlZeroMemory(gDpUserHookExcludedProcessNames, sizeof(gDpUserHookExcludedProcessNames));
    RtlZeroMemory(gDpUserHookExcludedProcessDirectories, sizeof(gDpUserHookExcludedProcessDirectories));
    RtlZeroMemory(gDpUserHookExcludedProcessPaths, sizeof(gDpUserHookExcludedProcessPaths));
    RtlZeroMemory(gDpUserHookTrustedSignerSubjects, sizeof(gDpUserHookTrustedSignerSubjects));
    RtlZeroMemory(gDpUserHookRuntimeDllPath, sizeof(gDpUserHookRuntimeDllPath));
    gDpUserHookExcludedProcessNamesLengthBytes = 0;
    gDpUserHookExcludedProcessDirectoriesLengthBytes = 0;
    gDpUserHookExcludedProcessPathsLengthBytes = 0;
    gDpUserHookTrustedSignerSubjectsLengthBytes = 0;
    gDpUserHookRuntimeDllPathLengthBytes = 0;
    gDpUserHookInitialized = TRUE;

    status = PsSetLoadImageNotifyRoutine(DpUserHookLoadImageNotify);
    if (NT_SUCCESS(status)) {
        gDpUserHookImageNotifyRegistered = TRUE;
    } else {
        DP_USER_HOOK_TRACE("PsSetLoadImageNotifyRoutine failed status=0x%08X\n", status);
        DpUserHookDefenseUninitialize();
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
DpUserHookDefenseUninitialize(
    VOID
    )
{
    if (gDpUserHookImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(DpUserHookLoadImageNotify);
        gDpUserHookImageNotifyRegistered = FALSE;
    }

    DpUserHookClearEvents();
    FltDeletePushLock(&gDpUserHookPolicyLock);
    gDpUserHookInitialized = FALSE;
}

NTSTATUS
DpUserHookDefenseSetPolicy(
    _In_ const DP_USER_HOOK_DEFENSE_POLICY *Policy
    )
{
    ULONG flags;
    ULONG namesBytes;
    ULONG directoriesBytes;
    ULONG pathsBytes;
    ULONG signerBytes;
    ULONG runtimeBytes;

    if (Policy == NULL ||
        Policy->Version != DP_USER_HOOK_DEFENSE_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS;

    namesBytes = min(Policy->ExcludedProcessNamesLengthBytes,
                     (ULONG)((DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS - 1) * sizeof(WCHAR)));
    directoriesBytes = min(Policy->ExcludedProcessDirectoriesLengthBytes,
                           (ULONG)((DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS - 1) * sizeof(WCHAR)));
    pathsBytes = min(Policy->ExcludedProcessPathsLengthBytes,
                     (ULONG)((DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS - 1) * sizeof(WCHAR)));
    signerBytes = min(Policy->TrustedSignerSubjectsLengthBytes,
                      (ULONG)((DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS - 1) * sizeof(WCHAR)));
    runtimeBytes = min(Policy->RuntimeDllPathLengthBytes,
                       (ULONG)((DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS - 1) * sizeof(WCHAR)));

    FltAcquirePushLockExclusive(&gDpUserHookPolicyLock);
    RtlZeroMemory(gDpUserHookExcludedProcessNames, sizeof(gDpUserHookExcludedProcessNames));
    RtlZeroMemory(gDpUserHookExcludedProcessDirectories, sizeof(gDpUserHookExcludedProcessDirectories));
    RtlZeroMemory(gDpUserHookExcludedProcessPaths, sizeof(gDpUserHookExcludedProcessPaths));
    RtlZeroMemory(gDpUserHookTrustedSignerSubjects, sizeof(gDpUserHookTrustedSignerSubjects));
    RtlZeroMemory(gDpUserHookRuntimeDllPath, sizeof(gDpUserHookRuntimeDllPath));
    if (namesBytes != 0) {
        RtlCopyMemory(gDpUserHookExcludedProcessNames,
                      Policy->ExcludedProcessNames,
                      namesBytes);
    }
    if (directoriesBytes != 0) {
        RtlCopyMemory(gDpUserHookExcludedProcessDirectories,
                      Policy->ExcludedProcessDirectories,
                      directoriesBytes);
    }
    if (pathsBytes != 0) {
        RtlCopyMemory(gDpUserHookExcludedProcessPaths,
                      Policy->ExcludedProcessPaths,
                      pathsBytes);
    }
    if (signerBytes != 0) {
        RtlCopyMemory(gDpUserHookTrustedSignerSubjects,
                      Policy->TrustedSignerSubjects,
                      signerBytes);
    }
    if (runtimeBytes != 0) {
        RtlCopyMemory(gDpUserHookRuntimeDllPath,
                      Policy->RuntimeDllPath,
                      runtimeBytes);
    }
    gDpUserHookExcludedProcessNamesLengthBytes =
        DpUserHookBoundedStringBytes(gDpUserHookExcludedProcessNames,
                                     DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS);
    gDpUserHookExcludedProcessDirectoriesLengthBytes =
        DpUserHookBoundedStringBytes(gDpUserHookExcludedProcessDirectories,
                                     DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS);
    gDpUserHookExcludedProcessPathsLengthBytes =
        DpUserHookBoundedStringBytes(gDpUserHookExcludedProcessPaths,
                                     DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS);
    gDpUserHookTrustedSignerSubjectsLengthBytes =
        DpUserHookBoundedStringBytes(gDpUserHookTrustedSignerSubjects,
                                     DP_USER_HOOK_DEFENSE_POLICY_TEXT_CHARS);
    gDpUserHookRuntimeDllPathLengthBytes =
        DpUserHookBoundedStringBytes(gDpUserHookRuntimeDllPath,
                                     DP_USER_HOOK_DEFENSE_RUNTIME_PATH_CHARS);
    FltReleasePushLock(&gDpUserHookPolicyLock);

    InterlockedExchange((volatile LONG *)&gDpUserHookPolicyFlags, (LONG)flags);

    DP_USER_HOOK_TRACE("policy updated flags=0x%08X excludedNamesBytes=%lu excludedDirectoriesBytes=%lu excludedPathsBytes=%lu trustedSignersBytes=%lu runtimeBytes=%lu\n",
                       flags,
                       gDpUserHookExcludedProcessNamesLengthBytes,
                       gDpUserHookExcludedProcessDirectoriesLengthBytes,
                       gDpUserHookExcludedProcessPathsLengthBytes,
                       gDpUserHookTrustedSignerSubjectsLengthBytes,
                       gDpUserHookRuntimeDllPathLengthBytes);

    return STATUS_SUCCESS;
}

NTSTATUS
DpUserHookDefenseQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_USER_HOOK_DEFENSE_POLICY policy;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = sizeof(DP_USER_HOOK_DEFENSE_POLICY);

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_USER_HOOK_DEFENSE_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    policy = (PDP_USER_HOOK_DEFENSE_POLICY)OutputBuffer;
    RtlZeroMemory(policy, sizeof(DP_USER_HOOK_DEFENSE_POLICY));
    policy->Version = DP_USER_HOOK_DEFENSE_POLICY_VERSION;
    policy->Flags = DpUserHookReadPolicyFlags();

    FltAcquirePushLockShared(&gDpUserHookPolicyLock);
    policy->ExcludedProcessNamesLengthBytes = gDpUserHookExcludedProcessNamesLengthBytes;
    policy->ExcludedProcessDirectoriesLengthBytes = gDpUserHookExcludedProcessDirectoriesLengthBytes;
    policy->ExcludedProcessPathsLengthBytes = gDpUserHookExcludedProcessPathsLengthBytes;
    policy->TrustedSignerSubjectsLengthBytes = gDpUserHookTrustedSignerSubjectsLengthBytes;
    policy->RuntimeDllPathLengthBytes = gDpUserHookRuntimeDllPathLengthBytes;
    RtlCopyMemory(policy->ExcludedProcessNames,
                  gDpUserHookExcludedProcessNames,
                  sizeof(policy->ExcludedProcessNames));
    RtlCopyMemory(policy->ExcludedProcessDirectories,
                  gDpUserHookExcludedProcessDirectories,
                  sizeof(policy->ExcludedProcessDirectories));
    RtlCopyMemory(policy->ExcludedProcessPaths,
                  gDpUserHookExcludedProcessPaths,
                  sizeof(policy->ExcludedProcessPaths));
    RtlCopyMemory(policy->TrustedSignerSubjects,
                  gDpUserHookTrustedSignerSubjects,
                  sizeof(policy->TrustedSignerSubjects));
    RtlCopyMemory(policy->RuntimeDllPath,
                  gDpUserHookRuntimeDllPath,
                  sizeof(policy->RuntimeDllPath));
    FltReleasePushLock(&gDpUserHookPolicyLock);

    return STATUS_SUCCESS;
}

NTSTATUS
DpUserHookDefenseQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);

    header->Version = DP_USER_HOOK_DEFENSE_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);

    if (!gDpUserHookInitialized) {
        header->BytesRequired = sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);

    header->DroppedEvents = gDpUserHookDroppedEvents;

    for (link = gDpUserHookEvents.Flink; link != &gDpUserHookEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_USER_HOOK_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                                        DP_USER_HOOK_DEFENSE_EVENT_ENTRY,
                                                                        Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpUserHookEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpUserHookEvents);
            PDP_USER_HOOK_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(eventLink,
                                                                        DP_USER_HOOK_DEFENSE_EVENT_ENTRY,
                                                                        Link);
            ULONGLONG sequence = event->Event.Sequence;
            ULONG remainingEvents;

            gDpUserHookEventCount--;
            remainingEvents = gDpUserHookEventCount;
            KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);
            DP_USER_HOOK_TRACE("query drain seq=%I64u remaining=%lu\n",
                               sequence,
                               remainingEvents);
            DpUserHookFreeEvent(event);
            KeAcquireSpinLock(&gDpUserHookEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpUserHookEventLock, oldIrql);

    DP_USER_HOOK_TRACE("query events sizing=%lu events=%lu returned=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u\n",
                       sizingOnly ? 1u : 0u,
                       eventCount,
                       returnedEventCount,
                       bytesRequired,
                       bytesReturned,
                       header->DroppedEvents);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}
