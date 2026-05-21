/*++

Module Name:

    DpFileHunter.c

Abstract:

    Safe-folder read auditing. This module reports only completed, successful
    IRP_MJ_READ operations under configured directories.

--*/

#include "DataProtector.h"

#if DP_ENABLE_FILE_HUNTER_TRACE
#define DP_FILE_HUNTER_TRACE(_format, ...) \
    DbgPrint("DataProtector[FileHunter] " _format, __VA_ARGS__)
#else
#define DP_FILE_HUNTER_TRACE(_format, ...) ((void)0)
#endif

typedef struct _DP_FILE_HUNTER_RULE_ENTRY {
    LIST_ENTRY Link;
    UNICODE_STRING Directory;
} DP_FILE_HUNTER_RULE_ENTRY, *PDP_FILE_HUNTER_RULE_ENTRY;

typedef struct _DP_FILE_HUNTER_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_FILE_HUNTER_EVENT_QUERY_ENTRY Event;
} DP_FILE_HUNTER_EVENT_ENTRY, *PDP_FILE_HUNTER_EVENT_ENTRY;

typedef struct _DP_FILE_HUNTER_DEDUP_ENTRY {
    BOOLEAN Valid;
    ULONGLONG ProcessId;
    ULONG PathHash;
    ULONG ProcessHash;
    LONGLONG LastSeenTime;
    ULONGLONG SuppressedCount;
} DP_FILE_HUNTER_DEDUP_ENTRY, *PDP_FILE_HUNTER_DEDUP_ENTRY;

static LIST_ENTRY gDpFileHunterRules;
static LIST_ENTRY gDpFileHunterEvents;
static EX_PUSH_LOCK gDpFileHunterRuleLock;
static KSPIN_LOCK gDpFileHunterEventLock;
static BOOLEAN gDpFileHunterInitialized = FALSE;
static ULONG gDpFileHunterRuleCount = 0;
static ULONG gDpFileHunterEventCount = 0;
static ULONGLONG gDpFileHunterEventSequence = 0;
static ULONGLONG gDpFileHunterDroppedEvents = 0;
static volatile LONG gDpFileHunterMissTraceCounter = 0;
static volatile LONG gDpFileHunterSkipTraceCounter = 0;
static DP_FILE_HUNTER_DEDUP_ENTRY gDpFileHunterDedup[DP_FILE_HUNTER_DEDUP_SLOTS];

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static
BOOLEAN
DpFileHunterCanTraceText(
    VOID
    )
{
    return KeGetCurrentIrql() == PASSIVE_LEVEL;
}

static
BOOLEAN
DpFileHunterCanQueueSyntheticEvent(
    VOID
    )
{
    return KeGetCurrentIrql() <= DISPATCH_LEVEL;
}

static
VOID
DpFileHunterTrimTrailingSlash(
    _Inout_ PUNICODE_STRING String
    )
{
    while (String->Length >= sizeof(WCHAR)) {
        WCHAR last = String->Buffer[(String->Length / sizeof(WCHAR)) - 1];

        if (last != L'\\' && last != L'/') {
            break;
        }

        String->Length -= sizeof(WCHAR);
    }
}

static
VOID
DpFileHunterFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, DP_TAG_FILE_HUNTER_RULE);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

static
NTSTATUS
DpFileHunterDuplicateDirectory(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    )
{
    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    if (Source == NULL ||
        Source->Buffer == NULL ||
        Source->Length == 0 ||
        Source->Length > (DP_FILE_HUNTER_PATH_CHARS - 1) * sizeof(WCHAR)) {

        return STATUS_INVALID_PARAMETER;
    }

    Destination->Buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                Source->Length,
                                                DP_TAG_FILE_HUNTER_RULE);
    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;
    Destination->MaximumLength = Source->Length;
    DpFileHunterTrimTrailingSlash(Destination);

    if (Destination->Length == 0) {
        DpFileHunterFreeUnicodeString(Destination);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static
BOOLEAN
DpFileHunterDirectoryMatches(
    _In_ PCUNICODE_STRING Directory,
    _In_ PCUNICODE_STRING Path
    )
{
    if (Directory == NULL ||
        Path == NULL ||
        Directory->Buffer == NULL ||
        Path->Buffer == NULL ||
        Directory->Length == 0 ||
        Path->Length < Directory->Length) {

        return FALSE;
    }

    if (!RtlPrefixUnicodeString(Directory, Path, TRUE)) {
        return FALSE;
    }

    if (Path->Length == Directory->Length) {
        return TRUE;
    }

    return Path->Buffer[Directory->Length / sizeof(WCHAR)] == L'\\' ||
           Path->Buffer[Directory->Length / sizeof(WCHAR)] == L'/';
}

static
BOOLEAN
DpFileHunterRuleExistsLocked(
    _In_ PCUNICODE_STRING Directory
    )
{
    PLIST_ENTRY link;

    for (link = gDpFileHunterRules.Flink; link != &gDpFileHunterRules; link = link->Flink) {
        PDP_FILE_HUNTER_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_FILE_HUNTER_RULE_ENTRY, Link);

        if (RtlEqualUnicodeString(&rule->Directory, Directory, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpFileHunterIsProtectedPath(
    _In_ PCUNICODE_STRING Path
    )
{
    PLIST_ENTRY link;
    BOOLEAN protectedPath = FALSE;

    if (!gDpFileHunterInitialized ||
        Path == NULL ||
        Path->Buffer == NULL ||
        Path->Length == 0) {

        return FALSE;
    }

    FltAcquirePushLockShared(&gDpFileHunterRuleLock);

    for (link = gDpFileHunterRules.Flink; link != &gDpFileHunterRules; link = link->Flink) {
        PDP_FILE_HUNTER_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_FILE_HUNTER_RULE_ENTRY, Link);

        if (DpFileHunterDirectoryMatches(&rule->Directory, Path)) {

            protectedPath = TRUE;
            break;
        }
    }

    FltReleasePushLock(&gDpFileHunterRuleLock);

    return protectedPath;
}

static
VOID
DpFileHunterTraceUnmatchedPath(
    _In_ PCUNICODE_STRING Path,
    _In_ HANDLE ProcessId,
    _In_z_ PCSTR Reason
    )
{
    LONG miss;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return;
    }

    miss = InterlockedIncrement(&gDpFileHunterMissTraceCounter);
    if ((miss & 0x7F) != 1) {
        return;
    }

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("read path miss reason=%s rules=%lu pid=%p sample=%ld path=%wZ\n",
                             Reason,
                             gDpFileHunterRuleCount,
                             ProcessId,
                             miss,
                             Path);
    } else {
        DP_FILE_HUNTER_TRACE("read path miss reason=%s rules=%lu pid=%p sample=%ld pathBytes=%lu\n",
                             Reason,
                             gDpFileHunterRuleCount,
                             ProcessId,
                             miss,
                             Path->Length);
    }
}

static
VOID
DpFileHunterFreeRule(
    _In_opt_ PDP_FILE_HUNTER_RULE_ENTRY Rule
    )
{
    if (Rule == NULL) {
        return;
    }

    DpFileHunterFreeUnicodeString(&Rule->Directory);
    ExFreePoolWithTag(Rule, DP_TAG_FILE_HUNTER_RULE);
}

static
VOID
DpFileHunterClearRulesLocked(
    VOID
    )
{
    while (!IsListEmpty(&gDpFileHunterRules)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpFileHunterRules);
        PDP_FILE_HUNTER_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_FILE_HUNTER_RULE_ENTRY, Link);

        gDpFileHunterRuleCount--;
        DpFileHunterFreeRule(rule);
    }

    gDpFileHunterRuleCount = 0;
}

static
VOID
DpFileHunterFreeEvent(
    _In_opt_ PDP_FILE_HUNTER_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_FILE_HUNTER_EVENT);
    }
}

static
VOID
DpFileHunterClearEvents(
    VOID
    )
{
    LIST_ENTRY localList;
    KIRQL oldIrql;

    if (!gDpFileHunterInitialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);

    while (!IsListEmpty(&gDpFileHunterEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpFileHunterEvents);
        InsertTailList(&localList, link);
    }

    gDpFileHunterEventCount = 0;
    RtlZeroMemory(gDpFileHunterDedup, sizeof(gDpFileHunterDedup));

    KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY link = RemoveHeadList(&localList);
        PDP_FILE_HUNTER_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_FILE_HUNTER_EVENT_ENTRY, Link);
        DpFileHunterFreeEvent(event);
    }
}

static
ULONG
DpFileHunterHashUnicodeBuffer(
    _In_reads_bytes_(LengthBytes) const WCHAR *Buffer,
    _In_ ULONG LengthBytes
    )
{
    ULONG hash = 2166136261u;
    ULONG index;
    ULONG chars = LengthBytes / sizeof(WCHAR);

    if (Buffer == NULL || LengthBytes == 0) {
        return 0;
    }

    for (index = 0; index < chars; index++) {
        WCHAR character = RtlUpcaseUnicodeChar(Buffer[index]);
        hash ^= (ULONG)(character & 0xFF);
        hash *= 16777619u;
        hash ^= (ULONG)((character >> 8) & 0xFF);
        hash *= 16777619u;
    }

    return hash == 0 ? 1 : hash;
}

static
BOOLEAN
DpFileHunterShouldSuppressDuplicateLocked(
    _In_ const DP_FILE_HUNTER_READ_CONTEXT *ReadContext
    )
{
    LARGE_INTEGER now;
    ULONG pathHash;
    ULONG processHash;
    ULONG slot;
    PDP_FILE_HUNTER_DEDUP_ENTRY entry;

    if (ReadContext == NULL) {
        return TRUE;
    }

    KeQuerySystemTime(&now);
    pathHash = DpFileHunterHashUnicodeBuffer(ReadContext->Path,
                                             ReadContext->PathLengthBytes);
    processHash = DpFileHunterHashUnicodeBuffer(ReadContext->ProcessImage,
                                                ReadContext->ProcessImageLengthBytes);
    slot = (pathHash ^ processHash ^ (ULONG)(ULONG_PTR)ReadContext->ProcessId) %
           DP_FILE_HUNTER_DEDUP_SLOTS;
    entry = &gDpFileHunterDedup[slot];

    if (entry->Valid &&
        entry->ProcessId == (ULONGLONG)(ULONG_PTR)ReadContext->ProcessId &&
        entry->PathHash == pathHash &&
        entry->ProcessHash == processHash &&
        now.QuadPart - entry->LastSeenTime < DP_FILE_HUNTER_DUPLICATE_WINDOW_100NS) {

        entry->LastSeenTime = now.QuadPart;
        entry->SuppressedCount++;
        return TRUE;
    }

    entry->Valid = TRUE;
    entry->ProcessId = (ULONGLONG)(ULONG_PTR)ReadContext->ProcessId;
    entry->PathHash = pathHash;
    entry->ProcessHash = processHash;
    entry->LastSeenTime = now.QuadPart;
    entry->SuppressedCount = 0;
    return FALSE;
}

static
VOID
DpFileHunterCopyUnicodeString(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _In_ PCUNICODE_STRING Source,
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
VOID
DpFileHunterCopyProcessImage(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _In_opt_ PEPROCESS Process,
    _Out_ PULONG BytesCopied
    )
{
    const CHAR *imageName;
    SIZE_T index;

    *BytesCopied = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';
    if (Process == NULL) {
        Process = PsGetCurrentProcess();
    }

    imageName = (const CHAR *)PsGetProcessImageFileName(Process);
    if (imageName == NULL) {
        return;
    }

    for (index = 0; index < DestinationChars - 1 && imageName[index] != '\0'; index++) {
        Destination[index] = (WCHAR)(UCHAR)imageName[index];
    }

    Destination[index] = L'\0';
    *BytesCopied = (ULONG)(index * sizeof(WCHAR));
}

NTSTATUS
DpFileHunterInitialize(
    VOID
    )
{
    InitializeListHead(&gDpFileHunterRules);
    InitializeListHead(&gDpFileHunterEvents);
    FltInitializePushLock(&gDpFileHunterRuleLock);
    KeInitializeSpinLock(&gDpFileHunterEventLock);
    gDpFileHunterRuleCount = 0;
    gDpFileHunterEventCount = 0;
    gDpFileHunterEventSequence = 0;
    gDpFileHunterDroppedEvents = 0;
    gDpFileHunterMissTraceCounter = 0;
    gDpFileHunterSkipTraceCounter = 0;
    RtlZeroMemory(gDpFileHunterDedup, sizeof(gDpFileHunterDedup));
    gDpFileHunterInitialized = TRUE;

    DP_FILE_HUNTER_TRACE("initialized maxRules=%lu maxEvents=%lu\n",
                         DP_FILE_HUNTER_MAX_RULES,
                         DP_FILE_HUNTER_MAX_EVENTS);

    return STATUS_SUCCESS;
}

VOID
DpFileHunterUninitialize(
    VOID
    )
{
    if (!gDpFileHunterInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpFileHunterRuleLock);
    DpFileHunterClearRulesLocked();
    FltReleasePushLock(&gDpFileHunterRuleLock);

    DpFileHunterClearEvents();
    FltDeletePushLock(&gDpFileHunterRuleLock);
    gDpFileHunterInitialized = FALSE;

    DP_FILE_HUNTER_TRACE("uninitialized\n", 0);
}

NTSTATUS
DpFileHunterAddRule(
    _In_ const DP_FILE_HUNTER_RULE_MESSAGE *Rule
    )
{
    NTSTATUS status;
    UNICODE_STRING source;
    PDP_FILE_HUNTER_RULE_ENTRY entry;

    if (!gDpFileHunterInitialized ||
        Rule == NULL ||
        Rule->Version != DP_FILE_HUNTER_RULE_MESSAGE_VERSION ||
        Rule->DirectoryLengthBytes == 0 ||
        Rule->DirectoryLengthBytes > sizeof(Rule->Directory) ||
        Rule->DirectoryLengthBytes % sizeof(WCHAR) != 0) {

        DP_FILE_HUNTER_TRACE("add rule rejected invalid initialized=%lu rule=%p\n",
                             gDpFileHunterInitialized ? 1ul : 0ul,
                             Rule);
        return STATUS_INVALID_PARAMETER;
    }

    source.Buffer = (PWCH)Rule->Directory;
    source.Length = (USHORT)Rule->DirectoryLengthBytes;
    source.MaximumLength = source.Length;

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_FILE_HUNTER_RULE_ENTRY),
                                  DP_TAG_FILE_HUNTER_RULE);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(DP_FILE_HUNTER_RULE_ENTRY));
    status = DpFileHunterDuplicateDirectory(&source, &entry->Directory);
    if (!NT_SUCCESS(status)) {
        if (DpFileHunterCanTraceText()) {
            DP_FILE_HUNTER_TRACE("add rule normalize failed status=0x%08X source=%wZ\n",
                                 status,
                                 &source);
        } else {
            DP_FILE_HUNTER_TRACE("add rule normalize failed status=0x%08X sourceLength=%lu\n",
                                 status,
                                 source.Length);
        }
        DpFileHunterFreeRule(entry);
        return status;
    }

    FltAcquirePushLockExclusive(&gDpFileHunterRuleLock);

    if (gDpFileHunterRuleCount >= DP_FILE_HUNTER_MAX_RULES) {
        status = STATUS_QUOTA_EXCEEDED;
    } else if (DpFileHunterRuleExistsLocked(&entry->Directory)) {
        status = STATUS_OBJECT_NAME_COLLISION;
    } else {
        InsertTailList(&gDpFileHunterRules, &entry->Link);
        gDpFileHunterRuleCount++;
        entry = NULL;
        status = STATUS_SUCCESS;
    }

    FltReleasePushLock(&gDpFileHunterRuleLock);

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("add rule status=0x%08X count=%lu directory=%wZ\n",
                             status == STATUS_OBJECT_NAME_COLLISION ? STATUS_SUCCESS : status,
                             gDpFileHunterRuleCount,
                             &source);
    } else {
        DP_FILE_HUNTER_TRACE("add rule status=0x%08X count=%lu directoryBytes=%lu\n",
                             status == STATUS_OBJECT_NAME_COLLISION ? STATUS_SUCCESS : status,
                             gDpFileHunterRuleCount,
                             source.Length);
    }

    DpFileHunterFreeRule(entry);
    return status == STATUS_OBJECT_NAME_COLLISION ? STATUS_SUCCESS : status;
}

NTSTATUS
DpFileHunterRemoveRule(
    _In_ const DP_FILE_HUNTER_RULE_MESSAGE *Rule
    )
{
    NTSTATUS status;
    UNICODE_STRING source;
    UNICODE_STRING normalized;
    PLIST_ENTRY link;
    PDP_FILE_HUNTER_RULE_ENTRY matchedRule = NULL;

    if (!gDpFileHunterInitialized ||
        Rule == NULL ||
        Rule->Version != DP_FILE_HUNTER_RULE_MESSAGE_VERSION ||
        Rule->DirectoryLengthBytes == 0 ||
        Rule->DirectoryLengthBytes > sizeof(Rule->Directory) ||
        Rule->DirectoryLengthBytes % sizeof(WCHAR) != 0) {

        DP_FILE_HUNTER_TRACE("remove rule rejected invalid initialized=%lu rule=%p\n",
                             gDpFileHunterInitialized ? 1ul : 0ul,
                             Rule);
        return STATUS_INVALID_PARAMETER;
    }

    source.Buffer = (PWCH)Rule->Directory;
    source.Length = (USHORT)Rule->DirectoryLengthBytes;
    source.MaximumLength = source.Length;

    status = DpFileHunterDuplicateDirectory(&source, &normalized);
    if (!NT_SUCCESS(status)) {
        if (DpFileHunterCanTraceText()) {
            DP_FILE_HUNTER_TRACE("remove rule normalize failed status=0x%08X source=%wZ\n",
                                 status,
                                 &source);
        } else {
            DP_FILE_HUNTER_TRACE("remove rule normalize failed status=0x%08X sourceLength=%lu\n",
                                 status,
                                 source.Length);
        }
        return status;
    }

    FltAcquirePushLockExclusive(&gDpFileHunterRuleLock);

    for (link = gDpFileHunterRules.Flink; link != &gDpFileHunterRules; link = link->Flink) {
        PDP_FILE_HUNTER_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_FILE_HUNTER_RULE_ENTRY, Link);

        if (RtlEqualUnicodeString(&rule->Directory, &normalized, TRUE)) {
            matchedRule = rule;
            RemoveEntryList(&matchedRule->Link);
            gDpFileHunterRuleCount--;
            break;
        }
    }

    FltReleasePushLock(&gDpFileHunterRuleLock);

    DpFileHunterFreeUnicodeString(&normalized);

    if (matchedRule == NULL) {
        if (DpFileHunterCanTraceText()) {
            DP_FILE_HUNTER_TRACE("remove rule not found count=%lu directory=%wZ\n",
                                 gDpFileHunterRuleCount,
                                 &source);
        } else {
            DP_FILE_HUNTER_TRACE("remove rule not found count=%lu directoryBytes=%lu\n",
                                 gDpFileHunterRuleCount,
                                 source.Length);
        }
        return STATUS_NOT_FOUND;
    }

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("remove rule success count=%lu directory=%wZ\n",
                             gDpFileHunterRuleCount,
                             &source);
    } else {
        DP_FILE_HUNTER_TRACE("remove rule success count=%lu directoryBytes=%lu\n",
                             gDpFileHunterRuleCount,
                             source.Length);
    }

    DpFileHunterFreeRule(matchedRule);
    return STATUS_SUCCESS;
}

VOID
DpFileHunterClearRules(
    VOID
    )
{
    if (!gDpFileHunterInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpFileHunterRuleLock);
    DP_FILE_HUNTER_TRACE("clear rules previous=%lu queuedEvents=%lu\n",
                         gDpFileHunterRuleCount,
                         gDpFileHunterEventCount);
    DpFileHunterClearRulesLocked();
    FltReleasePushLock(&gDpFileHunterRuleLock);
}

NTSTATUS
DpFileHunterQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PLIST_ENTRY link;
    PDP_FILE_HUNTER_RULE_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);
    ULONG ruleCount = 0;
    ULONG returnedRuleCount = 0;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_FILE_HUNTER_RULE_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER));
    header->Version = DP_FILE_HUNTER_RULE_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);

    if (!gDpFileHunterInitialized) {
        header->BytesRequired = sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_FILE_HUNTER_RULE_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    FltAcquirePushLockShared(&gDpFileHunterRuleLock);

    for (link = gDpFileHunterRules.Flink; link != &gDpFileHunterRules; link = link->Flink) {
        PDP_FILE_HUNTER_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_FILE_HUNTER_RULE_ENTRY, Link);
        ULONG entryLength = DP_FILE_HUNTER_RULE_QUERY_ENTRY_HEADER_SIZE + rule->Directory.Length;

        ruleCount++;
        if (bytesRequired > MAXULONG - entryLength) {
            FltReleasePushLock(&gDpFileHunterRuleLock);
            return STATUS_INTEGER_OVERFLOW;
        }

        bytesRequired += entryLength;

        if (bytesReturned <= OutputBufferLength &&
            entryLength <= OutputBufferLength - bytesReturned) {

            PDP_FILE_HUNTER_RULE_QUERY_ENTRY entry = (PDP_FILE_HUNTER_RULE_QUERY_ENTRY)cursor;

            entry->DirectoryLengthBytes = rule->Directory.Length;
            RtlCopyMemory(entry->Directory,
                          rule->Directory.Buffer,
                          rule->Directory.Length);

            cursor += entryLength;
            bytesReturned += entryLength;
            returnedRuleCount++;
        }
    }

    FltReleasePushLock(&gDpFileHunterRuleLock);

    header->RuleCount = ruleCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    DP_FILE_HUNTER_TRACE("query rules sizing=%lu rules=%lu returned=%lu bytesRequired=%lu bytesReturned=%lu\n",
                         sizingOnly ? 1ul : 0ul,
                         ruleCount,
                         returnedRuleCount,
                         bytesRequired,
                         bytesReturned);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedRuleCount != ruleCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpFileHunterQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_FILE_HUNTER_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_FILE_HUNTER_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);

    if (!gDpFileHunterInitialized) {
        header->Version = DP_FILE_HUNTER_EVENT_QUERY_VERSION;
        header->BytesRequired = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
        header->BytesReturned = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);

    header->Version = DP_FILE_HUNTER_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_FILE_HUNTER_EVENT_QUERY_HEADER);
    header->DroppedEvents = gDpFileHunterDroppedEvents;

    for (link = gDpFileHunterEvents.Flink; link != &gDpFileHunterEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_FILE_HUNTER_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_FILE_HUNTER_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_FILE_HUNTER_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_FILE_HUNTER_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_FILE_HUNTER_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_FILE_HUNTER_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_FILE_HUNTER_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpFileHunterEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpFileHunterEvents);
            PDP_FILE_HUNTER_EVENT_ENTRY event = CONTAINING_RECORD(eventLink, DP_FILE_HUNTER_EVENT_ENTRY, Link);
            gDpFileHunterEventCount--;
            DP_FILE_HUNTER_TRACE("query drain seq=%I64u remaining=%lu\n",
                                 event->Event.Sequence,
                                 gDpFileHunterEventCount);
            KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);
            DpFileHunterFreeEvent(event);
            KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);

    DP_FILE_HUNTER_TRACE("query events sizing=%lu events=%lu returned=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u\n",
                         sizingOnly ? 1ul : 0ul,
                         eventCount,
                         returnedEventCount,
                         bytesRequired,
                         bytesReturned,
                         gDpFileHunterDroppedEvents);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpFileHunterPrepareReadAudit(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Length,
    _Outptr_result_maybenull_ PDP_FILE_HUNTER_READ_CONTEXT *ReadContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDP_FILE_HUNTER_READ_CONTEXT context = NULL;
    PEPROCESS requestorProcess = NULL;

    if (ReadContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReadContext = NULL;

    if (!gDpFileHunterInitialized ||
        gDpFileHunterRuleCount == 0 ||
        Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FltObjects->FileObject->FsContext == NULL ||
        Length == 0 ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        if (gDpFileHunterInitialized && gDpFileHunterRuleCount != 0) {
            LONG skip = InterlockedIncrement(&gDpFileHunterSkipTraceCounter);
            if ((skip & 0x3F) == 1) {
                DP_FILE_HUNTER_TRACE("read skip invalid length=%lu data=%p file=%p fsctx=%p flags=0x%08X rules=%lu sample=%ld\n",
                                     Length,
                                     Data,
                                     FltObjects == NULL ? NULL : FltObjects->FileObject,
                                     (FltObjects == NULL || FltObjects->FileObject == NULL) ? NULL : FltObjects->FileObject->FsContext,
                                     (FltObjects == NULL || FltObjects->FileObject == NULL) ? 0ul : FltObjects->FileObject->Flags,
                                     gDpFileHunterRuleCount,
                                     skip);
            }
        }
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        DP_FILE_HUNTER_TRACE("read skip irql=%lu rules=%lu\n",
                             KeGetCurrentIrql(),
                             gDpFileHunterRuleCount);
        return STATUS_SUCCESS;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);
    }

    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        DP_FILE_HUNTER_TRACE("read name query failed status=0x%08X rules=%lu pid=%p\n",
                             status,
                             gDpFileHunterRuleCount,
                             FltGetRequestorProcessIdEx(Data));
        return STATUS_SUCCESS;
    }

    if (!DpFileHunterIsProtectedPath(&nameInfo->Name)) {
        DpFileHunterTraceUnmatchedPath(&nameInfo->Name,
                                       FltGetRequestorProcessIdEx(Data),
                                       "irp-read");
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_SUCCESS;
    }

    context = ExAllocatePoolWithTag(NonPagedPoolNx,
                                    sizeof(DP_FILE_HUNTER_READ_CONTEXT),
                                    DP_TAG_FILE_HUNTER_CONTEXT);
    if (context == NULL) {
        if (DpFileHunterCanTraceText()) {
            DP_FILE_HUNTER_TRACE("read context allocation failed pid=%p path=%wZ\n",
                                 FltGetRequestorProcessIdEx(Data),
                                 &nameInfo->Name);
        } else {
            DP_FILE_HUNTER_TRACE("read context allocation failed pid=%p pathBytes=%lu\n",
                                 FltGetRequestorProcessIdEx(Data),
                                 nameInfo->Name.Length);
        }
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(DP_FILE_HUNTER_READ_CONTEXT));
    context->ProcessId = FltGetRequestorProcessIdEx(Data);
    requestorProcess = FltGetRequestorProcess(Data);
    context->ByteOffset = Data->Iopb->Parameters.Read.ByteOffset;
    context->Flags = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ?
        DP_FILE_HUNTER_READ_FLAG_PAGING_IO :
        0;
    DpFileHunterCopyUnicodeString(context->Path,
                                  RTL_NUMBER_OF(context->Path),
                                  &nameInfo->Name,
                                  &context->PathLengthBytes);
    DpFileHunterCopyProcessImage(context->ProcessImage,
                                 RTL_NUMBER_OF(context->ProcessImage),
                                 requestorProcess,
                                 &context->ProcessImageLengthBytes);

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("read armed pid=%p length=%lu flags=0x%08X path=%wZ process=%ws\n",
                             context->ProcessId,
                             Length,
                             context->Flags,
                             &nameInfo->Name,
                             context->ProcessImage);
    } else {
        DP_FILE_HUNTER_TRACE("read armed pid=%p length=%lu flags=0x%08X pathBytes=%lu process=%ws\n",
                             context->ProcessId,
                             Length,
                             context->Flags,
                             nameInfo->Name.Length,
                             context->ProcessImage);
    }

    FltReleaseFileNameInformation(nameInfo);
    *ReadContext = context;
    return STATUS_SUCCESS;
}

VOID
DpFileHunterReportReadSuccess(
    _Inout_ PDP_FILE_HUNTER_READ_CONTEXT ReadContext,
    _In_ ULONG Status,
    _In_ ULONG_PTR BytesRead
    )
{
    PDP_FILE_HUNTER_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONGLONG queuedSequence;
    ULONG queuedCount;
    ULONGLONG droppedEvents;

    if (!gDpFileHunterInitialized ||
        ReadContext == NULL ||
        BytesRead == 0) {

        if (gDpFileHunterInitialized && ReadContext != NULL) {
            if (DpFileHunterCanTraceText()) {
                DP_FILE_HUNTER_TRACE("read report skipped bytes=%Iu pid=%p path=%ws\n",
                                     BytesRead,
                                     ReadContext->ProcessId,
                                     ReadContext->Path);
            } else {
                DP_FILE_HUNTER_TRACE("read report skipped bytes=%Iu pid=%p pathBytes=%lu\n",
                                     BytesRead,
                                     ReadContext->ProcessId,
                                     ReadContext->PathLengthBytes);
            }
        }
        return;
    }

    KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);
    if (DpFileHunterShouldSuppressDuplicateLocked(ReadContext)) {
        LONG skip = InterlockedIncrement(&gDpFileHunterSkipTraceCounter);
        KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);
        if ((skip & 0x3F) == 1) {
            if (DpFileHunterCanTraceText()) {
                DP_FILE_HUNTER_TRACE("read duplicate suppressed pid=%p bytes=%Iu sample=%ld path=%ws process=%ws\n",
                                     ReadContext->ProcessId,
                                     BytesRead,
                                     skip,
                                     ReadContext->Path,
                                     ReadContext->ProcessImage);
            } else {
                DP_FILE_HUNTER_TRACE("read duplicate suppressed pid=%p bytes=%Iu sample=%ld pathBytes=%lu processBytes=%lu\n",
                                     ReadContext->ProcessId,
                                     BytesRead,
                                     skip,
                                     ReadContext->PathLengthBytes,
                                     ReadContext->ProcessImageLengthBytes);
            }
        }
        return;
    }
    KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_FILE_HUNTER_EVENT_ENTRY),
                                  DP_TAG_FILE_HUNTER_EVENT);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);
        gDpFileHunterDroppedEvents++;
        KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);
        if (DpFileHunterCanTraceText()) {
            DP_FILE_HUNTER_TRACE("read event allocation failed dropped=%I64u pid=%p path=%ws\n",
                                 gDpFileHunterDroppedEvents,
                                 ReadContext->ProcessId,
                                 ReadContext->Path);
        } else {
            DP_FILE_HUNTER_TRACE("read event allocation failed dropped=%I64u pid=%p pathBytes=%lu\n",
                                 gDpFileHunterDroppedEvents,
                                 ReadContext->ProcessId,
                                 ReadContext->PathLengthBytes);
        }
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_FILE_HUNTER_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ReadContext->ProcessId;
    entry->Event.BytesRead = (ULONGLONG)BytesRead;
    entry->Event.ByteOffset = (ULONGLONG)ReadContext->ByteOffset.QuadPart;
    entry->Event.Status = Status;
    entry->Event.Flags = ReadContext->Flags;
    entry->Event.PathLengthBytes = ReadContext->PathLengthBytes;
    entry->Event.ProcessImageLengthBytes = ReadContext->ProcessImageLengthBytes;
    RtlCopyMemory(entry->Event.Path,
                  ReadContext->Path,
                  min(ReadContext->PathLengthBytes, (ULONG)sizeof(entry->Event.Path)));
    RtlCopyMemory(entry->Event.ProcessImage,
                  ReadContext->ProcessImage,
                  min(ReadContext->ProcessImageLengthBytes, (ULONG)sizeof(entry->Event.ProcessImage)));

    KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpFileHunterEventSequence;
    InsertTailList(&gDpFileHunterEvents, &entry->Link);
    gDpFileHunterEventCount++;
    queuedSequence = entry->Event.Sequence;
    queuedCount = gDpFileHunterEventCount;
    droppedEvents = gDpFileHunterDroppedEvents;

    while (gDpFileHunterEventCount > DP_FILE_HUNTER_MAX_EVENTS && !IsListEmpty(&gDpFileHunterEvents)) {
        PLIST_ENTRY oldLink = RemoveHeadList(&gDpFileHunterEvents);
        PDP_FILE_HUNTER_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink, DP_FILE_HUNTER_EVENT_ENTRY, Link);
        gDpFileHunterEventCount--;
        gDpFileHunterDroppedEvents++;
        DP_FILE_HUNTER_TRACE("drop old seq=%I64u count=%lu dropped=%I64u\n",
                             oldEvent->Event.Sequence,
                             gDpFileHunterEventCount,
                             gDpFileHunterDroppedEvents);
        KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);
        DpFileHunterFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpFileHunterEventLock, &oldIrql);
    }

    KeReleaseSpinLock(&gDpFileHunterEventLock, oldIrql);

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("queued seq=%I64u count=%lu dropped=%I64u pid=%I64u bytes=%I64u status=0x%08X path=%ws process=%ws\n",
                             queuedSequence,
                             queuedCount,
                             droppedEvents,
                             (ULONGLONG)(ULONG_PTR)ReadContext->ProcessId,
                             (ULONGLONG)BytesRead,
                             Status,
                             ReadContext->Path,
                             ReadContext->ProcessImage);
    } else {
        DP_FILE_HUNTER_TRACE("queued seq=%I64u count=%lu dropped=%I64u pid=%I64u bytes=%I64u status=0x%08X pathBytes=%lu processBytes=%lu\n",
                             queuedSequence,
                             queuedCount,
                             droppedEvents,
                             (ULONGLONG)(ULONG_PTR)ReadContext->ProcessId,
                             (ULONGLONG)BytesRead,
                             Status,
                             ReadContext->PathLengthBytes,
                             ReadContext->ProcessImageLengthBytes);
    }
}

VOID
DpFileHunterReportReadByName(
    _In_ PCUNICODE_STRING Path,
    _In_opt_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_ ULONG Status,
    _In_ ULONG_PTR BytesRead
    )
{
    DP_FILE_HUNTER_READ_CONTEXT context;

    if (!gDpFileHunterInitialized ||
        gDpFileHunterRuleCount == 0 ||
        Path == NULL ||
        Path->Buffer == NULL ||
        Path->Length == 0 ||
        BytesRead == 0) {

        return;
    }

    if (!DpFileHunterCanQueueSyntheticEvent()) {
        DP_FILE_HUNTER_TRACE("synthetic read skipped irql=%lu flags=0x%08X\n",
                             KeGetCurrentIrql(),
                             Flags);
        return;
    }

    if (!DpFileHunterIsProtectedPath(Path)) {
        DpFileHunterTraceUnmatchedPath(Path, ProcessId, "synthetic");
        return;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.ProcessId = ProcessId == NULL ? PsGetCurrentProcessId() : ProcessId;
    context.ByteOffset.QuadPart = 0;
    context.Flags = Flags;
    DpFileHunterCopyUnicodeString(context.Path,
                                  RTL_NUMBER_OF(context.Path),
                                  Path,
                                  &context.PathLengthBytes);
    DpFileHunterCopyProcessImage(context.ProcessImage,
                                 RTL_NUMBER_OF(context.ProcessImage),
                                 Process,
                                 &context.ProcessImageLengthBytes);

    if (DpFileHunterCanTraceText()) {
        DP_FILE_HUNTER_TRACE("synthetic read matched pid=%p flags=0x%08X bytes=%Iu path=%wZ process=%ws\n",
                             context.ProcessId,
                             Flags,
                             BytesRead,
                             Path,
                             context.ProcessImage);
    } else {
        DP_FILE_HUNTER_TRACE("synthetic read matched pid=%p flags=0x%08X bytes=%Iu pathBytes=%lu process=%ws\n",
                             context.ProcessId,
                             Flags,
                             BytesRead,
                             Path->Length,
                             context.ProcessImage);
    }

    DpFileHunterReportReadSuccess(&context, Status, BytesRead);
}

VOID
DpFileHunterFreeReadContext(
    _In_opt_ PDP_FILE_HUNTER_READ_CONTEXT ReadContext
    )
{
    if (ReadContext != NULL) {
        RtlSecureZeroMemory(ReadContext, sizeof(DP_FILE_HUNTER_READ_CONTEXT));
        ExFreePoolWithTag(ReadContext, DP_TAG_FILE_HUNTER_CONTEXT);
    }
}
