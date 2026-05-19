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

#if DP_ENABLE_USER_HOOK_DEFENSE_TRACE
#define DP_USER_HOOK_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[UserHook] " _format, __VA_ARGS__)
#else
#define DP_USER_HOOK_TRACE(_format, ...) ((void)0)
#endif

#define DP_USER_HOOK_DEDUP_SLOTS 128
#define DP_USER_HOOK_DEDUP_WINDOW_100NS (10LL * 1000LL * 10000LL)

typedef struct _DP_USER_HOOK_DEFENSE_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_USER_HOOK_DEFENSE_EVENT_QUERY_ENTRY Event;
} DP_USER_HOOK_DEFENSE_EVENT_ENTRY, *PDP_USER_HOOK_DEFENSE_EVENT_ENTRY;

typedef struct _DP_USER_HOOK_DEDUP_ENTRY {
    BOOLEAN Valid;
    ULONGLONG ProcessId;
    ULONG Operation;
    ULONG TargetHash;
    LONGLONG LastSeenTime;
} DP_USER_HOOK_DEDUP_ENTRY, *PDP_USER_HOOK_DEDUP_ENTRY;

static LIST_ENTRY gDpUserHookEvents;
static KSPIN_LOCK gDpUserHookEventLock;
static volatile LONG gDpUserHookPolicyFlags = DP_USER_HOOK_DEFENSE_DEFAULT_FLAGS;
static BOOLEAN gDpUserHookInitialized = FALSE;
static BOOLEAN gDpUserHookImageNotifyRegistered = FALSE;
static ULONG gDpUserHookEventCount = 0;
static ULONGLONG gDpUserHookEventSequence = 0;
static ULONGLONG gDpUserHookDroppedEvents = 0;
static DP_USER_HOOK_DEDUP_ENTRY gDpUserHookDedup[DP_USER_HOOK_DEDUP_SLOTS];

static
ULONG
DpUserHookReadPolicyFlags(
    VOID
    )
{
    return (ULONG)gDpUserHookPolicyFlags;
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
DpUserHookShouldSkipProcess(
    _In_opt_ HANDLE ProcessId
    )
{
    ULONG flags = DpUserHookReadPolicyFlags();

    if (FlagOn(flags, DP_USER_HOOK_DEFENSE_FLAG_MONITOR_SYSTEM_PROCESSES)) {
        return FALSE;
    }

    return ProcessId == NULL ||
           ProcessId == (HANDLE)(ULONG_PTR)4;
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

    if (!DpUserHookFeatureEnabled(DP_USER_HOOK_DEFENSE_FLAG_IMAGE_LOAD_MONITOR) ||
        DpUserHookShouldSkipProcess(ProcessId) ||
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

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL ||
        !DpUserHookFeatureEnabled(DP_USER_HOOK_DEFENSE_FLAG_EARLY_PROCESS_MONITOR) ||
        DpUserHookShouldSkipProcess(ProcessId)) {

        return;
    }

    parentProcessId = CreateInfo->ParentProcessId;

    DpUserHookQueueEvent(DpUserHookDefenseOperationProcessCreate,
                         ProcessId,
                         parentProcessId,
                         STATUS_SUCCESS,
                         CreateInfo->CommandLine,
                         CreateInfo->ImageFileName,
                         DpUserHookReadPolicyFlags());

    if (FlagOn(DpUserHookReadPolicyFlags(), DP_USER_HOOK_DEFENSE_FLAG_REQUIRE_SIGNED_RUNTIME)) {
        DpUserHookQueueEvent(DpUserHookDefenseOperationRuntimeRequired,
                             ProcessId,
                             parentProcessId,
                             STATUS_PENDING,
                             CreateInfo->ImageFileName,
                             CreateInfo->ImageFileName,
                             DpUserHookReadPolicyFlags());
    }
}

NTSTATUS
DpUserHookDefenseInitialize(
    VOID
    )
{
    NTSTATUS status;

    InitializeListHead(&gDpUserHookEvents);
    KeInitializeSpinLock(&gDpUserHookEventLock);
    InterlockedExchange((volatile LONG *)&gDpUserHookPolicyFlags,
                        (LONG)DP_USER_HOOK_DEFENSE_DEFAULT_FLAGS);
    gDpUserHookEventCount = 0;
    gDpUserHookEventSequence = 0;
    gDpUserHookDroppedEvents = 0;
    RtlZeroMemory(gDpUserHookDedup, sizeof(gDpUserHookDedup));
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
    gDpUserHookInitialized = FALSE;
}

NTSTATUS
DpUserHookDefenseSetPolicy(
    _In_ const DP_USER_HOOK_DEFENSE_POLICY *Policy
    )
{
    ULONG flags;

    if (Policy == NULL ||
        Policy->Version != DP_USER_HOOK_DEFENSE_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_USER_HOOK_DEFENSE_ALLOWED_FLAGS;
    InterlockedExchange((volatile LONG *)&gDpUserHookPolicyFlags, (LONG)flags);

    DP_USER_HOOK_TRACE("policy updated flags=0x%08X\n", flags);

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
