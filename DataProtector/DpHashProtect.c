/*++

Module Name:

    DpHashProtect.c

Abstract:

    Credential hash dump hardening. The module protects LSASS from
    unauthorized process-handle access and blocks direct reads of offline
    credential stores, including Volume Shadow Copy paths.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                 (0x0001)
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD             (0x0002)
#endif

#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID             (0x0004)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION              (0x0008)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                   (0x0010)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                  (0x0020)
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                (0x0040)
#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS            (0x0080)
#endif

#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA                 (0x0100)
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION           (0x0200)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION         (0x0400)
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME            (0x0800)
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif

#if DP_ENABLE_HASH_PROTECT_TRACE
#define DP_HASH_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[HashProtect] " _format, __VA_ARGS__)
#else
#define DP_HASH_TRACE(_format, ...) ((void)0)
#endif

#if !DP_ENABLE_HASH_PROTECT_TRACE
#define DP_HASH_TRACE_VALUE(_value) UNREFERENCED_PARAMETER(_value)
#else
#define DP_HASH_TRACE_VALUE(_value) ((void)0)
#endif

#define DP_HASH_OB_ALTITUDE       L"385201.77"
#define DP_HASH_REG_ALTITUDE      L"385202.77"
#define DP_HASH_LSASS_DEDUP_SLOTS 64
#define DP_HASH_LSASS_DEDUP_WINDOW_100NS (30LL * 1000LL * 10000LL)
#define DP_HASH_RAW_CACHE_TTL_100NS (5LL * 1000LL * 10000LL)
#define DP_HASH_RAW_RETRIEVAL_BUFFER_SIZE (64 * 1024)
#define DP_HASH_RAW_MAX_EXTENTS_PER_VOLUME 8192
#define DP_HASH_RAW_MAX_VOLUMES 64
#define DP_HASH_RAW_TARGET_CHARS 128

typedef struct _DP_HASH_PROTECT_DEDUP_ENTRY {
    BOOLEAN Valid;
    ULONG Operation;
    ULONGLONG ProcessId;
    ULONG Status;
    ACCESS_MASK DesiredAccess;
    ULONG TargetHash;
    ULONG ProcessImageHash;
    LONGLONG LastSeenTime;
    ULONGLONG SuppressedCount;
} DP_HASH_PROTECT_DEDUP_ENTRY, *PDP_HASH_PROTECT_DEDUP_ENTRY;

typedef struct _DP_HASH_RAW_EXTENT_ENTRY {
    LIST_ENTRY Link;
    ULONGLONG Offset;
    ULONGLONG Length;
    ULONG TargetLengthBytes;
    WCHAR Target[DP_HASH_RAW_TARGET_CHARS];
} DP_HASH_RAW_EXTENT_ENTRY, *PDP_HASH_RAW_EXTENT_ENTRY;

typedef struct _DP_HASH_RAW_EXTENT_LIST {
    LIST_ENTRY Extents;
    ULONG ExtentCount;
} DP_HASH_RAW_EXTENT_LIST, *PDP_HASH_RAW_EXTENT_LIST;

typedef struct _DP_HASH_RAW_VOLUME_CACHE {
    LIST_ENTRY Link;
    PFLT_VOLUME Volume;
    LIST_ENTRY Extents;
    LONG ReferenceCount;
    ULONG ExtentCount;
    LARGE_INTEGER LastRefreshTime;
    NTSTATUS LastRefreshStatus;
    BOOLEAN Complete;
} DP_HASH_RAW_VOLUME_CACHE, *PDP_HASH_RAW_VOLUME_CACHE;

typedef struct _DP_HASH_INTERNAL_IO_GUARD {
    PVOID PreviousTopLevelIrp;
} DP_HASH_INTERNAL_IO_GUARD, *PDP_HASH_INTERNAL_IO_GUARD;

static PVOID gDpHashProtectObHandle = NULL;
static LARGE_INTEGER gDpHashProtectRegistryCookie;
static BOOLEAN gDpHashProtectRegistryRegistered = FALSE;
static LIST_ENTRY gDpHashProtectEvents;
static KSPIN_LOCK gDpHashProtectEventLock;
static LIST_ENTRY gDpHashProtectRawVolumes;
static EX_PUSH_LOCK gDpHashProtectRawLock;
static BOOLEAN gDpHashProtectRawLockInitialized = FALSE;
static volatile LONG gDpHashProtectPolicyFlags = DP_HASH_PROTECT_DEFAULT_FLAGS;
static BOOLEAN gDpHashProtectInitialized = FALSE;
static ULONG gDpHashProtectEventCount = 0;
static ULONGLONG gDpHashProtectEventSequence = 0;
static ULONGLONG gDpHashProtectDroppedEvents = 0;
static ULONGLONG gDpHashProtectSuppressedDuplicates = 0;
static ULONG gDpHashProtectRawVolumeCount = 0;
static DP_HASH_PROTECT_DEDUP_ENTRY gDpHashProtectDedup[DP_HASH_LSASS_DEDUP_SLOTS];

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTSTATUS
SeLocateProcessImageName(
    _Inout_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING *pImageFileName
    );

static
ULONG
DpHashProtectReadPolicyFlags(
    VOID
    )
{
    return (ULONG)gDpHashProtectPolicyFlags;
}

static
BOOLEAN
DpHashProtectFeatureEnabled(
    _In_ ULONG FeatureFlag
    )
{
    ULONG flags = DpHashProtectReadPolicyFlags();

    return FlagOn(flags, DP_HASH_PROTECT_FLAG_ENABLED) &&
           FlagOn(flags, FeatureFlag);
}

static
VOID
DpHashProtectBeginInternalIo(
    _Out_ PDP_HASH_INTERNAL_IO_GUARD Guard
    )
{
    Guard->PreviousTopLevelIrp = IoGetTopLevelIrp();
    IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
}

static
VOID
DpHashProtectEndInternalIo(
    _In_ PDP_HASH_INTERNAL_IO_GUARD Guard
    )
{
    IoSetTopLevelIrp((PIRP)Guard->PreviousTopLevelIrp);
}

static
BOOLEAN
DpHashProtectAsciiEqualsInsensitive(
    _In_z_ const CHAR *Left,
    _In_z_ const CHAR *Right
    )
{
    CHAR leftChar;
    CHAR rightChar;

    if (Left == NULL || Right == NULL) {
        return FALSE;
    }

    for (;;) {
        leftChar = *Left++;
        rightChar = *Right++;

        if (leftChar >= 'A' && leftChar <= 'Z') {
            leftChar = (CHAR)(leftChar - 'A' + 'a');
        }

        if (rightChar >= 'A' && rightChar <= 'Z') {
            rightChar = (CHAR)(rightChar - 'A' + 'a');
        }

        if (leftChar != rightChar) {
            return FALSE;
        }

        if (leftChar == '\0') {
            return TRUE;
        }
    }
}

static
BOOLEAN
DpHashProtectIsSystemPid(
    _In_opt_ HANDLE ProcessId
    )
{
    return ProcessId == NULL ||
           ProcessId == (HANDLE)(ULONG_PTR)4;
}

static
BOOLEAN
DpHashProtectUnicodeContainsLiteral(
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
DpHashProtectImagePathIsSystem32Suffix(
    _In_ PCUNICODE_STRING ImagePath,
    _In_z_ PCWSTR FileName
    )
{
    WCHAR suffixBuffer[128];
    UNICODE_STRING suffix;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || FileName == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(RtlStringCchPrintfW(suffixBuffer,
                                        RTL_NUMBER_OF(suffixBuffer),
                                        L"\\Windows\\System32\\%ws",
                                        FileName))) {

        return FALSE;
    }

    RtlInitUnicodeString(&suffix, suffixBuffer);
    return RtlSuffixUnicodeString(&suffix, ImagePath, TRUE);
}

static
BOOLEAN
DpHashProtectIsWindowsImagePath(
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        return FALSE;
    }

    return DpHashProtectUnicodeContainsLiteral(ImagePath, L"\\Windows\\System32\\") ||
           DpHashProtectUnicodeContainsLiteral(ImagePath, L"\\Windows\\SysWOW64\\") ||
           DpHashProtectUnicodeContainsLiteral(ImagePath, L"\\Windows\\WinSxS\\") ||
           DpHashProtectUnicodeContainsLiteral(ImagePath, L"\\Windows\\SystemApps\\") ||
           DpHashProtectUnicodeContainsLiteral(ImagePath, L"\\Windows\\explorer.exe");
}

static
BOOLEAN
DpHashProtectIsWindowsCurrentProcess(
    VOID
    )
{
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN windowsImage = FALSE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &imagePath)) && imagePath != NULL) {
        windowsImage = DpHashProtectIsWindowsImagePath(imagePath);
        ExFreePool(imagePath);
    }

    return windowsImage;
}

static
BOOLEAN
DpHashProtectIsReadQueryProcessAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    const ACCESS_MASK readQueryMask = PROCESS_VM_READ |
                                      PROCESS_QUERY_INFORMATION |
                                      PROCESS_QUERY_LIMITED_INFORMATION |
                                      SYNCHRONIZE |
                                      READ_CONTROL;

    return DesiredAccess != 0 &&
           (DesiredAccess & ~readQueryMask) == 0;
}

static
BOOLEAN
DpHashProtectIsAllowedCurrentProcess(
    VOID
    )
{
    PEPROCESS process;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN allowed = FALSE;
    const CHAR *imageName;

    if (DpHashProtectIsSystemPid(PsGetCurrentProcessId())) {
        return TRUE;
    }

    process = PsGetCurrentProcess();
    imageName = (const CHAR *)PsGetProcessImageFileName(process);

    if (DpHashProtectAsciiEqualsInsensitive(imageName, "lsass.exe")) {
        return TRUE;
    }

    if (NT_SUCCESS(SeLocateProcessImageName(process, &imagePath)) && imagePath != NULL) {
        allowed = DpHashProtectImagePathIsSystem32Suffix(imagePath, L"wininit.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"services.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"csrss.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"smss.exe");
        ExFreePool(imagePath);
    }

    return allowed;
}

typedef struct _DP_HASH_PROTECT_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_HASH_PROTECT_EVENT_QUERY_ENTRY Event;
} DP_HASH_PROTECT_EVENT_ENTRY, *PDP_HASH_PROTECT_EVENT_ENTRY;

static
VOID
DpHashProtectCopyAsciiProcessImage(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ const CHAR *Source,
    _Out_ PULONG BytesCopied
    )
{
    ULONG index;

    *BytesCopied = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Source == NULL) {
        return;
    }

    for (index = 0; index + 1 < DestinationChars && Source[index] != '\0'; index++) {
        Destination[index] = (WCHAR)(UCHAR)Source[index];
    }

    Destination[index] = L'\0';
    *BytesCopied = index * sizeof(WCHAR);
}

static
VOID
DpHashProtectCopyUnicodeTarget(
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
VOID
DpHashProtectFreeEvent(
    _In_opt_ PDP_HASH_PROTECT_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_HASH_PROTECT);
    }
}

static
VOID
DpHashProtectClearRawExtentList(
    _Inout_ PLIST_ENTRY Extents,
    _Inout_ PULONG ExtentCount
    )
{
    if (Extents == NULL || ExtentCount == NULL) {
        return;
    }

    while (!IsListEmpty(Extents)) {
        PLIST_ENTRY link = RemoveHeadList(Extents);
        PDP_HASH_RAW_EXTENT_ENTRY extent = CONTAINING_RECORD(link,
                                                             DP_HASH_RAW_EXTENT_ENTRY,
                                                             Link);
        ExFreePoolWithTag(extent, DP_TAG_HASH_PROTECT);
    }

    *ExtentCount = 0;
}

static
VOID
DpHashProtectClearRawExtentsLocked(
    _Inout_ PDP_HASH_RAW_VOLUME_CACHE Cache
    )
{
    if (Cache == NULL) {
        return;
    }

    DpHashProtectClearRawExtentList(&Cache->Extents, &Cache->ExtentCount);
    Cache->Complete = FALSE;
}

static
VOID
DpHashProtectMoveRawExtentListLocked(
    _Inout_ PLIST_ENTRY Destination,
    _Inout_ PULONG DestinationCount,
    _Inout_ PLIST_ENTRY Source,
    _Inout_ PULONG SourceCount
    )
{
    while (!IsListEmpty(Source)) {
        PLIST_ENTRY link = RemoveHeadList(Source);
        InsertTailList(Destination, link);
    }

    *DestinationCount = *SourceCount;
    *SourceCount = 0;
}

static
VOID
DpHashProtectFreeRawVolumeCache(
    _In_opt_ PDP_HASH_RAW_VOLUME_CACHE Cache
    )
{
    if (Cache == NULL) {
        return;
    }

    DpHashProtectClearRawExtentList(&Cache->Extents, &Cache->ExtentCount);
    Cache->Complete = FALSE;

    if (Cache->Volume != NULL) {
        FltObjectDereference(Cache->Volume);
        Cache->Volume = NULL;
    }

    ExFreePoolWithTag(Cache, DP_TAG_HASH_PROTECT);
}

static
VOID
DpHashProtectReleaseRawVolumeCache(
    _In_opt_ PDP_HASH_RAW_VOLUME_CACHE Cache
    )
{
    if (Cache != NULL &&
        InterlockedDecrement(&Cache->ReferenceCount) == 0) {

        DpHashProtectFreeRawVolumeCache(Cache);
    }
}

static
VOID
DpHashProtectClearRawVolumes(
    VOID
    )
{
    if (!gDpHashProtectRawLockInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpHashProtectRawLock);

    while (!IsListEmpty(&gDpHashProtectRawVolumes)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpHashProtectRawVolumes);
        PDP_HASH_RAW_VOLUME_CACHE cache = CONTAINING_RECORD(link,
                                                            DP_HASH_RAW_VOLUME_CACHE,
                                                            Link);
        if (gDpHashProtectRawVolumeCount != 0) {
            gDpHashProtectRawVolumeCount--;
        }

        DpHashProtectReleaseRawVolumeCache(cache);
    }

    FltReleasePushLock(&gDpHashProtectRawLock);
}

VOID
DpHashProtectForgetVolume(
    _In_opt_ PFLT_VOLUME Volume
    )
{
    PDP_HASH_RAW_VOLUME_CACHE cache = NULL;
    PLIST_ENTRY link;

    if (Volume == NULL || !gDpHashProtectRawLockInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpHashProtectRawLock);

    for (link = gDpHashProtectRawVolumes.Flink;
         link != &gDpHashProtectRawVolumes;
         link = link->Flink) {

        cache = CONTAINING_RECORD(link, DP_HASH_RAW_VOLUME_CACHE, Link);
        if (cache->Volume == Volume) {
            RemoveEntryList(&cache->Link);
            if (gDpHashProtectRawVolumeCount != 0) {
                gDpHashProtectRawVolumeCount--;
            }
            FltReleasePushLock(&gDpHashProtectRawLock);
            DpHashProtectReleaseRawVolumeCache(cache);
            return;
        }
    }

    FltReleasePushLock(&gDpHashProtectRawLock);
}

static
ULONG
DpHashProtectHashUnicodeBuffer(
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
DpHashProtectSuppressDuplicateLocked(
    _In_ const DP_HASH_PROTECT_EVENT_QUERY_ENTRY *Event,
    _In_ LONGLONG CurrentTime,
    _In_ ULONG TargetHash,
    _In_ ULONG ProcessImageHash,
    _Out_ PULONGLONG SuppressedCount
    )
{
    ULONG index;
    ULONG replaceIndex = 0;
    LONGLONG oldestTime = MAXLONGLONG;
    PDP_HASH_PROTECT_DEDUP_ENTRY slot;

    *SuppressedCount = 0;

    if (Event == NULL ||
        Event->Operation != (ULONG)DpHashProtectOperationLsassHandle) {

        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(gDpHashProtectDedup); index++) {
        slot = &gDpHashProtectDedup[index];

        if (!slot->Valid) {
            replaceIndex = index;
            oldestTime = MINLONGLONG;
            continue;
        }

        if (slot->LastSeenTime < oldestTime) {
            oldestTime = slot->LastSeenTime;
            replaceIndex = index;
        }

        if (slot->Operation == Event->Operation &&
            slot->ProcessId == Event->ProcessId &&
            slot->Status == Event->Status &&
            slot->DesiredAccess == Event->DesiredAccess &&
            slot->TargetHash == TargetHash &&
            slot->ProcessImageHash == ProcessImageHash) {

            if (CurrentTime >= slot->LastSeenTime &&
                CurrentTime - slot->LastSeenTime <= DP_HASH_LSASS_DEDUP_WINDOW_100NS) {

                slot->LastSeenTime = CurrentTime;
                slot->SuppressedCount++;
                gDpHashProtectSuppressedDuplicates++;
                *SuppressedCount = slot->SuppressedCount;
                return TRUE;
            }

            replaceIndex = index;
            break;
        }
    }

    slot = &gDpHashProtectDedup[replaceIndex];
    RtlZeroMemory(slot, sizeof(*slot));
    slot->Valid = TRUE;
    slot->Operation = Event->Operation;
    slot->ProcessId = Event->ProcessId;
    slot->Status = Event->Status;
    slot->DesiredAccess = Event->DesiredAccess;
    slot->TargetHash = TargetHash;
    slot->ProcessImageHash = ProcessImageHash;
    slot->LastSeenTime = CurrentTime;

    UNREFERENCED_PARAMETER(oldestTime);

    return FALSE;
}

static
VOID
DpHashProtectClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gDpHashProtectInitialized) {
        return;
    }

    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    while (!IsListEmpty(&gDpHashProtectEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpHashProtectEvents);
        PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_HASH_PROTECT_EVENT_ENTRY, Link);
        gDpHashProtectEventCount--;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DpHashProtectFreeEvent(event);
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
}

static
VOID
DpHashProtectQueueEvent(
    _In_ DP_HASH_PROTECT_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG Status,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCUNICODE_STRING Target,
    _In_opt_z_ const CHAR *ProcessImage
    )
{
    PDP_HASH_PROTECT_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONGLONG sequence;
    ULONG eventCount;
    ULONGLONG droppedEvents;
    UNICODE_STRING targetText;
    UNICODE_STRING processText;
    LARGE_INTEGER currentTime;
    ULONG targetHash;
    ULONG processHash;
    ULONGLONG suppressedCount;

    if (!gDpHashProtectInitialized) {
        DP_HASH_TRACE("queue skipped uninitialized pid=%p op=%lu status=0x%08X\n",
                      ProcessId,
                      (ULONG)Operation,
                      Status);
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_HASH_PROTECT_EVENT_ENTRY),
                                  DP_TAG_HASH_PROTECT);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
        gDpHashProtectDroppedEvents++;
        droppedEvents = gDpHashProtectDroppedEvents;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DP_HASH_TRACE("queue allocation failed pid=%p op=%lu dropped=%I64u\n",
                      ProcessId,
                      (ULONG)Operation,
                      droppedEvents);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_HASH_PROTECT_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.Operation = (ULONG)Operation;
    entry->Event.Status = Status;
    entry->Event.DesiredAccess = DesiredAccess;
    DpHashProtectCopyUnicodeTarget(entry->Event.Target,
                                   RTL_NUMBER_OF(entry->Event.Target),
                                   Target,
                                   &entry->Event.TargetLengthBytes);
    DpHashProtectCopyAsciiProcessImage(entry->Event.ProcessImage,
                                       RTL_NUMBER_OF(entry->Event.ProcessImage),
                                       ProcessImage,
                                       &entry->Event.ProcessImageLengthBytes);

    targetHash = DpHashProtectHashUnicodeBuffer(entry->Event.Target,
                                                entry->Event.TargetLengthBytes);
    processHash = DpHashProtectHashUnicodeBuffer(entry->Event.ProcessImage,
                                                 entry->Event.ProcessImageLengthBytes);
    targetText.Buffer = entry->Event.Target;
    targetText.Length = (USHORT)entry->Event.TargetLengthBytes;
    targetText.MaximumLength = (USHORT)sizeof(entry->Event.Target);
    processText.Buffer = entry->Event.ProcessImage;
    processText.Length = (USHORT)entry->Event.ProcessImageLengthBytes;
    processText.MaximumLength = (USHORT)sizeof(entry->Event.ProcessImage);

    DP_HASH_TRACE("queue event pid=%p op=%lu status=0x%08X access=0x%08X target=%wZ image=%wZ\n",
                  ProcessId,
                  (ULONG)Operation,
                  Status,
                  DesiredAccess,
                  &targetText,
                  &processText);

    KeQuerySystemTimePrecise(&currentTime);
    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);

    if (DpHashProtectSuppressDuplicateLocked(&entry->Event,
                                             currentTime.QuadPart,
                                             targetHash,
                                             processHash,
                                             &suppressedCount)) {

        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DP_HASH_TRACE("dedup suppressed pid=%p op=%lu status=0x%08X access=0x%08X suppressed=%I64u total=%I64u target=%wZ image=%wZ\n",
                      ProcessId,
                      (ULONG)Operation,
                      Status,
                      DesiredAccess,
                      suppressedCount,
                      gDpHashProtectSuppressedDuplicates,
                      &targetText,
                      &processText);
        DpHashProtectFreeEvent(entry);
        return;
    }

    entry->Event.Sequence = ++gDpHashProtectEventSequence;
    InsertTailList(&gDpHashProtectEvents, &entry->Link);
    gDpHashProtectEventCount++;

    while (gDpHashProtectEventCount > DP_HASH_PROTECT_MAX_EVENTS &&
           !IsListEmpty(&gDpHashProtectEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gDpHashProtectEvents);
        PDP_HASH_PROTECT_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink, DP_HASH_PROTECT_EVENT_ENTRY, Link);
        gDpHashProtectEventCount--;
        gDpHashProtectDroppedEvents++;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DpHashProtectFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    }

    sequence = entry->Event.Sequence;
    eventCount = gDpHashProtectEventCount;
    droppedEvents = gDpHashProtectDroppedEvents;
    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);

    DP_HASH_TRACE("queued seq=%I64u count=%lu dropped=%I64u pid=%p op=%lu status=0x%08X access=0x%08X\n",
                  sequence,
                  eventCount,
                  droppedEvents,
                  ProcessId,
                  (ULONG)Operation,
                  Status,
                  DesiredAccess);
}

static
VOID
DpHashProtectQueueEventAsciiTarget(
    _In_ DP_HASH_PROTECT_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG Status,
    _In_ ACCESS_MASK DesiredAccess,
    _In_z_ PCWSTR Target,
    _In_opt_z_ const CHAR *ProcessImage
    )
{
    UNICODE_STRING targetString;

    RtlInitUnicodeString(&targetString, Target);
    DpHashProtectQueueEvent(Operation,
                            ProcessId,
                            Status,
                            DesiredAccess,
                            &targetString,
                            ProcessImage);
}

static
BOOLEAN
DpHashProtectIsLsassProcess(
    _In_ PEPROCESS Process
    )
{
    if (Process == NULL) {
        return FALSE;
    }

    return DpHashProtectAsciiEqualsInsensitive((const CHAR *)PsGetProcessImageFileName(Process),
                                               "lsass.exe");
}

static
ACCESS_MASK
DpHashProtectDangerousProcessAccess(
    VOID
    )
{
    return PROCESS_TERMINATE |
           PROCESS_CREATE_THREAD |
           PROCESS_SET_SESSIONID |
           PROCESS_VM_OPERATION |
           PROCESS_VM_READ |
           PROCESS_VM_WRITE |
           PROCESS_DUP_HANDLE |
           PROCESS_CREATE_PROCESS |
           PROCESS_SET_QUOTA |
           PROCESS_SET_INFORMATION |
           PROCESS_QUERY_INFORMATION |
           PROCESS_SUSPEND_RESUME |
           PROCESS_QUERY_LIMITED_INFORMATION |
           DELETE |
           WRITE_DAC |
           WRITE_OWNER;
}

static
VOID
DpHashProtectFilterLsassAccess(
    _In_ OB_OPERATION Operation,
    _Inout_ POB_PRE_OPERATION_PARAMETERS Parameters
    )
{
    ACCESS_MASK desiredAccess;
    ACCESS_MASK filteredAccess;
    ACCESS_MASK dangerousAccess;
    BOOLEAN suppressReadOnlyWindowsEvent;
    BOOLEAN windowsReadOnlyAccess;

    dangerousAccess = DpHashProtectDangerousProcessAccess();
    suppressReadOnlyWindowsEvent = FALSE;
    windowsReadOnlyAccess = FALSE;

    if (Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = Parameters->CreateHandleInformation.DesiredAccess;
        windowsReadOnlyAccess =
            DpHashProtectIsWindowsCurrentProcess() &&
            DpHashProtectIsReadQueryProcessAccess(desiredAccess);
        filteredAccess = windowsReadOnlyAccess
            ? (desiredAccess & ~PROCESS_VM_READ)
            : (desiredAccess & ~dangerousAccess);

        if (filteredAccess != desiredAccess) {
            suppressReadOnlyWindowsEvent = windowsReadOnlyAccess;
            Parameters->CreateHandleInformation.DesiredAccess = filteredAccess;
            if (!suppressReadOnlyWindowsEvent) {
                DpHashProtectQueueEventAsciiTarget(DpHashProtectOperationLsassHandle,
                                                   PsGetCurrentProcessId(),
                                                   (ULONG)STATUS_ACCESS_DENIED,
                                                   desiredAccess,
                                                   L"lsass.exe",
                                                   (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
            }
            DP_HASH_TRACE("blocked lsass handle create pid=%p access=0x%08X filtered=0x%08X image=%s\n",
                          PsGetCurrentProcessId(),
                          desiredAccess,
                          filteredAccess,
                          PsGetProcessImageFileName(PsGetCurrentProcess()));
        }
    } else if (Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = Parameters->DuplicateHandleInformation.DesiredAccess;
        windowsReadOnlyAccess =
            DpHashProtectIsWindowsCurrentProcess() &&
            DpHashProtectIsReadQueryProcessAccess(desiredAccess);
        filteredAccess = windowsReadOnlyAccess
            ? (desiredAccess & ~PROCESS_VM_READ)
            : (desiredAccess & ~dangerousAccess);

        if (filteredAccess != desiredAccess) {
            suppressReadOnlyWindowsEvent = windowsReadOnlyAccess;
            Parameters->DuplicateHandleInformation.DesiredAccess = filteredAccess;
            if (!suppressReadOnlyWindowsEvent) {
                DpHashProtectQueueEventAsciiTarget(DpHashProtectOperationLsassHandle,
                                                   PsGetCurrentProcessId(),
                                                   (ULONG)STATUS_ACCESS_DENIED,
                                                   desiredAccess,
                                                   L"lsass.exe",
                                                   (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
            }
            DP_HASH_TRACE("blocked lsass handle duplicate pid=%p access=0x%08X filtered=0x%08X image=%s\n",
                          PsGetCurrentProcessId(),
                          desiredAccess,
                          filteredAccess,
                          PsGetProcessImageFileName(PsGetCurrentProcess()));
        }
    }
}

static
OB_PREOP_CALLBACK_STATUS
DpHashProtectPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS targetProcess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!DpHashProtectFeatureEnabled(DP_HASH_PROTECT_FLAG_LSASS_HANDLES)) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation == NULL ||
        OperationInformation->Parameters == NULL ||
        OperationInformation->KernelHandle ||
        OperationInformation->ObjectType != *PsProcessType) {

        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    if (!DpHashProtectIsLsassProcess(targetProcess)) {
        return OB_PREOP_SUCCESS;
    }

    if (PsGetCurrentProcess() == targetProcess ||
        PsGetCurrentProcessId() == PsGetProcessId(targetProcess) ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return OB_PREOP_SUCCESS;
    }

    DpHashProtectFilterLsassAccess(OperationInformation->Operation,
                                   OperationInformation->Parameters);

    return OB_PREOP_SUCCESS;
}

static
BOOLEAN
DpHashProtectSuffix(
    _In_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Suffix
    )
{
    UNICODE_STRING suffixString;

    if (Name == NULL || Name->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&suffixString, Suffix);
    return RtlSuffixUnicodeString(&suffixString, Name, TRUE);
}

static
BOOLEAN
DpHashProtectUnicodeCharEqualsInsensitive(
    _In_ WCHAR Left,
    _In_ WCHAR Right
    )
{
    return RtlUpcaseUnicodeChar(Left) == RtlUpcaseUnicodeChar(Right);
}

static
BOOLEAN
DpHashProtectContainsInsensitive(
    _In_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Needle
    )
{
    USHORT nameChars;
    USHORT needleChars;
    USHORT nameIndex;
    UNICODE_STRING needleString;

    if (Name == NULL || Name->Buffer == NULL || Needle == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    if (needleString.Length == 0 || Name->Length < needleString.Length) {
        return FALSE;
    }

    nameChars = Name->Length / sizeof(WCHAR);
    needleChars = needleString.Length / sizeof(WCHAR);

    for (nameIndex = 0; nameIndex <= nameChars - needleChars; nameIndex++) {
        USHORT needleIndex;
        BOOLEAN matched = TRUE;

        for (needleIndex = 0; needleIndex < needleChars; needleIndex++) {
            if (!DpHashProtectUnicodeCharEqualsInsensitive(Name->Buffer[nameIndex + needleIndex],
                                                           needleString.Buffer[needleIndex])) {
                matched = FALSE;
                break;
            }
        }

        if (matched) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
DpHashProtectCopyTargetSuffix(
    _Out_writes_(DP_HASH_RAW_TARGET_CHARS) PWCHAR Destination,
    _In_z_ PCWSTR Source
    )
{
    size_t sourceChars = 0;
    size_t charsToCopy;

    RtlZeroMemory(Destination, DP_HASH_RAW_TARGET_CHARS * sizeof(WCHAR));

    if (Source == NULL) {
        return;
    }

    while (sourceChars < DP_HASH_RAW_TARGET_CHARS - 1 &&
           Source[sourceChars] != L'\0') {

        sourceChars++;
    }

    charsToCopy = min(sourceChars, (size_t)(DP_HASH_RAW_TARGET_CHARS - 1));
    if (charsToCopy != 0) {
        RtlCopyMemory(Destination, Source, charsToCopy * sizeof(WCHAR));
    }
    Destination[charsToCopy] = L'\0';
}

static
NTSTATUS
DpHashProtectBuildVolumeFileName(
    _In_ PCUNICODE_STRING VolumeName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars,
    _Out_ PUNICODE_STRING Name,
    _In_z_ PCWSTR RelativePath
    )
{
    size_t relativeChars = 0;
    USHORT volumeChars;
    size_t totalChars;

    RtlZeroMemory(Buffer, BufferChars * sizeof(WCHAR));
    RtlInitEmptyUnicodeString(Name,
                              Buffer,
                              (USHORT)(BufferChars * sizeof(WCHAR)));

    if (VolumeName == NULL ||
        VolumeName->Buffer == NULL ||
        VolumeName->Length == 0 ||
        RelativePath == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(RelativePath,
                                        BufferChars,
                                        &relativeChars))) {

        return STATUS_NAME_TOO_LONG;
    }

    volumeChars = VolumeName->Length / sizeof(WCHAR);
    while (volumeChars != 0 && VolumeName->Buffer[volumeChars - 1] == L'\\') {
        volumeChars--;
    }

    totalChars = (size_t)volumeChars + 1 + relativeChars;
    if (totalChars + 1 > BufferChars ||
        totalChars * sizeof(WCHAR) > MAXUSHORT) {

        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(Buffer, VolumeName->Buffer, volumeChars * sizeof(WCHAR));
    Buffer[volumeChars] = L'\\';
    RtlCopyMemory(Buffer + volumeChars + 1,
                  RelativePath,
                  relativeChars * sizeof(WCHAR));
    Buffer[totalChars] = L'\0';
    Name->Length = (USHORT)(totalChars * sizeof(WCHAR));

    return STATUS_SUCCESS;
}

static
BOOLEAN
DpHashProtectIsCredentialStoreName(
    _In_ PCUNICODE_STRING Name
    )
{
    static const PCWSTR SensitiveSuffixes[] = {
        L"\\Windows\\System32\\config\\SAM",
        L"\\Windows\\System32\\config\\SECURITY",
        L"\\Windows\\System32\\config\\SYSTEM",
        L"\\Windows\\System32\\config\\RegBack\\SAM",
        L"\\Windows\\System32\\config\\RegBack\\SECURITY",
        L"\\Windows\\System32\\config\\RegBack\\SYSTEM",
        L"\\Windows\\Repair\\SAM",
        L"\\Windows\\Repair\\SECURITY",
        L"\\Windows\\Repair\\SYSTEM",
        L"\\Windows\\NTDS\\ntds.dit"
    };
    ULONG index;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    for (index = 0; index < ARRAYSIZE(SensitiveSuffixes); index++) {
        if (DpHashProtectSuffix(Name, SensitiveSuffixes[index])) {
            return TRUE;
        }
    }

    if (DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SAM.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SECURITY.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SYSTEM.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\NTDS\\ntds.dit.")) {

        return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
DpHashProtectCreateRequestsDataAccess(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess;
    ULONG createDisposition;
    PFLT_IO_PARAMETER_BLOCK iopb;

    if (Data == NULL || Data->Iopb == NULL) {
        return FALSE;
    }

    iopb = Data->Iopb;
    if (iopb->MajorFunction != IRP_MJ_CREATE ||
        iopb->Parameters.Create.SecurityContext == NULL) {

        return FALSE;
    }

    desiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (FlagOn(desiredAccess,
               FILE_READ_DATA |
               FILE_WRITE_DATA |
               FILE_APPEND_DATA |
               FILE_EXECUTE |
               FILE_DELETE_CHILD |
               DELETE |
               WRITE_DAC |
               WRITE_OWNER |
               GENERIC_READ |
               GENERIC_WRITE |
               GENERIC_EXECUTE |
               GENERIC_ALL)) {

        return TRUE;
    }

    createDisposition = (iopb->Parameters.Create.Options >> 24) & 0xFF;
    switch (createDisposition) {
    case FILE_CREATE:
    case FILE_OPEN_IF:
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF:
    case FILE_SUPERSEDE:
        return TRUE;

    default:
        return FALSE;
    }
}

static
ULONGLONG
DpHashProtectSaturatingAdd(
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right
    )
{
    if (MAXULONGLONG - Left < Right) {
        return MAXULONGLONG;
    }

    return Left + Right;
}

static
BOOLEAN
DpHashProtectRangesOverlap(
    _In_ ULONGLONG FirstOffset,
    _In_ ULONGLONG FirstLength,
    _In_ ULONGLONG SecondOffset,
    _In_ ULONGLONG SecondLength
    )
{
    ULONGLONG firstEnd;
    ULONGLONG secondEnd;

    if (FirstLength == 0 || SecondLength == 0) {
        return FALSE;
    }

    firstEnd = DpHashProtectSaturatingAdd(FirstOffset, FirstLength);
    secondEnd = DpHashProtectSaturatingAdd(SecondOffset, SecondLength);

    return FirstOffset < secondEnd && SecondOffset < firstEnd;
}

static
BOOLEAN
DpHashProtectMultiplyUlonglong(
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right,
    _Out_ PULONGLONG Product
    )
{
    if (Right != 0 && Left > MAXULONGLONG / Right) {
        return FALSE;
    }

    *Product = Left * Right;
    return TRUE;
}

static
NTSTATUS
DpHashProtectQueryClusterSize(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PULONGLONG ClusterSize
    )
{
    FILE_FS_SIZE_INFORMATION sizeInfo;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    *ClusterSize = 0;
    RtlZeroMemory(&sizeInfo, sizeof(sizeInfo));
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));

    status = FltQueryVolumeInformation(Instance,
                                       &ioStatus,
                                       &sizeInfo,
                                       sizeof(sizeInfo),
                                       FileFsSizeInformation);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (sizeInfo.BytesPerSector == 0 ||
        sizeInfo.SectorsPerAllocationUnit == 0) {

        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!DpHashProtectMultiplyUlonglong((ULONGLONG)sizeInfo.BytesPerSector,
                                        (ULONGLONG)sizeInfo.SectorsPerAllocationUnit,
                                        ClusterSize)) {

        return STATUS_INTEGER_OVERFLOW;
    }

    if (*ClusterSize == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpHashProtectOpenRelativeFile(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PHANDLE FileHandle,
    _Outptr_ PFILE_OBJECT *FileObject
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    DP_HASH_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    *FileHandle = NULL;
    *FileObject = NULL;

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    DpHashProtectBeginInternalIo(&guard);

    status = FltCreateFileEx2(gDataProtectorFilter,
                              Instance,
                              FileHandle,
                              FileObject,
                              FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE,
                              &objectAttributes,
                              &ioStatus,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL,
                              0,
                              IO_IGNORE_SHARE_ACCESS_CHECK,
                              NULL);

    DpHashProtectEndInternalIo(&guard);

    if (!NT_SUCCESS(status)) {
        *FileHandle = NULL;
        *FileObject = NULL;
    }

    return status;
}

static
VOID
DpHashProtectCloseRelativeFile(
    _In_opt_ HANDLE FileHandle,
    _In_opt_ PFILE_OBJECT FileObject
    )
{
    if (FileObject != NULL) {
        ObDereferenceObject(FileObject);
    }

    if (FileHandle != NULL) {
        FltClose(FileHandle);
    }
}

static
NTSTATUS
DpHashProtectAppendRawExtent(
    _Inout_ PLIST_ENTRY Extents,
    _Inout_ PULONG ExtentCount,
    _In_ ULONGLONG Offset,
    _In_ ULONGLONG Length,
    _In_z_ PCWSTR TargetSuffix
    )
{
    PDP_HASH_RAW_EXTENT_ENTRY extent;
    size_t targetChars = 0;

    if (Length == 0) {
        return STATUS_SUCCESS;
    }

    if (*ExtentCount >= DP_HASH_RAW_MAX_EXTENTS_PER_VOLUME) {
        return STATUS_BUFFER_OVERFLOW;
    }

    extent = ExAllocatePoolWithTag(NonPagedPoolNx,
                                   sizeof(DP_HASH_RAW_EXTENT_ENTRY),
                                   DP_TAG_HASH_PROTECT);
    if (extent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(extent, sizeof(*extent));
    extent->Offset = Offset;
    extent->Length = Length;
    DpHashProtectCopyTargetSuffix(extent->Target, TargetSuffix);
    if (!NT_SUCCESS(RtlStringCchLengthW(extent->Target,
                                        RTL_NUMBER_OF(extent->Target),
                                        &targetChars))) {
        targetChars = 0;
    }
    extent->TargetLengthBytes = (ULONG)(targetChars * sizeof(WCHAR));

    InsertTailList(Extents, &extent->Link);
    (*ExtentCount)++;
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpHashProtectAppendFileExtents(
    _Inout_ PDP_HASH_RAW_EXTENT_LIST ExtentList,
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName,
    _In_z_ PCWSTR RelativePath,
    _In_ ULONGLONG ClusterSize
    )
{
    WCHAR nameBuffer[512];
    UNICODE_STRING fileName;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    FILE_STANDARD_INFORMATION standardInfo;
    PSTARTING_VCN_INPUT_BUFFER inputBuffer;
    PRETRIEVAL_POINTERS_BUFFER outputBuffer;
    ULONG outputLength = DP_HASH_RAW_RETRIEVAL_BUFFER_SIZE;
    LARGE_INTEGER nextStartingVcn;
    NTSTATUS status;
    NTSTATUS finalStatus = STATUS_SUCCESS;
    DP_HASH_INTERNAL_IO_GUARD guard;

    status = DpHashProtectBuildVolumeFileName(VolumeName,
                                              nameBuffer,
                                              RTL_NUMBER_OF(nameBuffer),
                                              &fileName,
                                              RelativePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpHashProtectOpenRelativeFile(Instance,
                                           &fileName,
                                           &fileHandle,
                                           &fileObject);
    if (!NT_SUCCESS(status)) {
        DP_HASH_TRACE("raw extent open skipped status=0x%08X path=%wZ\n",
                      status,
                      &fileName);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&standardInfo, sizeof(standardInfo));
    status = FltQueryInformationFile(Instance,
                                     fileObject,
                                     &standardInfo,
                                     sizeof(standardInfo),
                                     FileStandardInformation,
                                     NULL);
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        DP_HASH_TRACE("raw extent size query failed status=0x%08X path=%wZ\n",
                      status,
                      &fileName);
        goto Exit;
    }

    if (standardInfo.EndOfFile.QuadPart <= 0) {
        goto Exit;
    }

    inputBuffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                        sizeof(STARTING_VCN_INPUT_BUFFER),
                                        DP_TAG_HASH_PROTECT);
    outputBuffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                         outputLength,
                                         DP_TAG_HASH_PROTECT);
    if (inputBuffer == NULL || outputBuffer == NULL) {
        finalStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitBuffers;
    }

    nextStartingVcn.QuadPart = 0;
    for (;;) {
        ULONG bytesReturned = 0;
        ULONG index;

        RtlZeroMemory(inputBuffer, sizeof(*inputBuffer));
        RtlZeroMemory(outputBuffer, outputLength);
        inputBuffer->StartingVcn = nextStartingVcn;

        DpHashProtectBeginInternalIo(&guard);
        status = FltFsControlFile(Instance,
                                  fileObject,
                                  FSCTL_GET_RETRIEVAL_POINTERS,
                                  inputBuffer,
                                  sizeof(*inputBuffer),
                                  outputBuffer,
                                  outputLength,
                                  &bytesReturned);
        DpHashProtectEndInternalIo(&guard);

        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            if (status == STATUS_END_OF_FILE || status == STATUS_INVALID_PARAMETER) {
                status = STATUS_SUCCESS;
            } else {
                finalStatus = status;
                DP_HASH_TRACE("raw extent fsctl failed status=0x%08X path=%wZ startVcn=%I64d\n",
                              status,
                              &fileName,
                              nextStartingVcn.QuadPart);
            }
            break;
        }

        if (outputBuffer->ExtentCount == 0) {
            break;
        }

        for (index = 0; index < outputBuffer->ExtentCount; index++) {
            LONGLONG startVcn;
            LONGLONG nextVcn;
            LONGLONG lcn;
            ULONGLONG clusterCount;
            ULONGLONG offset;
            ULONGLONG length;

            startVcn = (index == 0) ?
                outputBuffer->StartingVcn.QuadPart :
                outputBuffer->Extents[index - 1].NextVcn.QuadPart;
            nextVcn = outputBuffer->Extents[index].NextVcn.QuadPart;
            lcn = outputBuffer->Extents[index].Lcn.QuadPart;

            if (nextVcn <= startVcn || lcn < 0) {
                continue;
            }

            clusterCount = (ULONGLONG)(nextVcn - startVcn);
            if (!DpHashProtectMultiplyUlonglong((ULONGLONG)lcn,
                                                ClusterSize,
                                                &offset) ||
                !DpHashProtectMultiplyUlonglong(clusterCount,
                                                ClusterSize,
                                                &length)) {

                finalStatus = STATUS_INTEGER_OVERFLOW;
                break;
            }

            status = DpHashProtectAppendRawExtent(&ExtentList->Extents,
                                                  &ExtentList->ExtentCount,
                                                  offset,
                                                  length,
                                                  RelativePath);
            if (!NT_SUCCESS(status)) {
                finalStatus = status;
                break;
            }
        }

        if (!NT_SUCCESS(finalStatus)) {
            break;
        }

        nextStartingVcn = outputBuffer->Extents[outputBuffer->ExtentCount - 1].NextVcn;
        if (status != STATUS_BUFFER_OVERFLOW ||
            nextStartingVcn.QuadPart <= inputBuffer->StartingVcn.QuadPart) {

            break;
        }
    }

ExitBuffers:
    if (outputBuffer != NULL) {
        ExFreePoolWithTag(outputBuffer, DP_TAG_HASH_PROTECT);
    }

    if (inputBuffer != NULL) {
        ExFreePoolWithTag(inputBuffer, DP_TAG_HASH_PROTECT);
    }

Exit:
    DpHashProtectCloseRelativeFile(fileHandle, fileObject);

    return finalStatus == STATUS_BUFFER_OVERFLOW ? STATUS_SUCCESS : finalStatus;
}

static
PDP_HASH_RAW_VOLUME_CACHE
DpHashProtectLookupRawCacheLocked(
    _In_ PFLT_VOLUME Volume
    )
{
    PLIST_ENTRY link;

    for (link = gDpHashProtectRawVolumes.Flink;
         link != &gDpHashProtectRawVolumes;
         link = link->Flink) {

        PDP_HASH_RAW_VOLUME_CACHE cache = CONTAINING_RECORD(link,
                                                            DP_HASH_RAW_VOLUME_CACHE,
                                                            Link);
        if (cache->Volume == Volume) {
            return cache;
        }
    }

    return NULL;
}

static
NTSTATUS
DpHashProtectEnsureRawCache(
    _In_ PFLT_VOLUME Volume,
    _Outptr_ PDP_HASH_RAW_VOLUME_CACHE *Cache
    )
{
    PDP_HASH_RAW_VOLUME_CACHE cache;
    NTSTATUS status;

    *Cache = NULL;

    FltAcquirePushLockExclusive(&gDpHashProtectRawLock);

    cache = DpHashProtectLookupRawCacheLocked(Volume);
    if (cache != NULL) {
        InterlockedIncrement(&cache->ReferenceCount);
        *Cache = cache;
        FltReleasePushLock(&gDpHashProtectRawLock);
        return STATUS_SUCCESS;
    }

    if (gDpHashProtectRawVolumeCount >= DP_HASH_RAW_MAX_VOLUMES) {
        FltReleasePushLock(&gDpHashProtectRawLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cache = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_HASH_RAW_VOLUME_CACHE),
                                  DP_TAG_HASH_PROTECT);
    if (cache == NULL) {
        FltReleasePushLock(&gDpHashProtectRawLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cache, sizeof(*cache));
    InitializeListHead(&cache->Extents);
    cache->ReferenceCount = 2;
    cache->Volume = Volume;
    status = FltObjectReference(Volume);
    if (!NT_SUCCESS(status)) {
        cache->Volume = NULL;
        FltReleasePushLock(&gDpHashProtectRawLock);
        DpHashProtectFreeRawVolumeCache(cache);
        return status;
    }

    InsertTailList(&gDpHashProtectRawVolumes, &cache->Link);
    gDpHashProtectRawVolumeCount++;
    *Cache = cache;

    FltReleasePushLock(&gDpHashProtectRawLock);
    return STATUS_SUCCESS;
}

static
BOOLEAN
DpHashProtectRawCacheNeedsRefresh(
    _In_ const DP_HASH_RAW_VOLUME_CACHE *Cache,
    _In_ LONGLONG CurrentTime
    )
{
    if (Cache == NULL || !Cache->Complete) {
        return TRUE;
    }

    if (CurrentTime < Cache->LastRefreshTime.QuadPart) {
        return TRUE;
    }

    return CurrentTime - Cache->LastRefreshTime.QuadPart > DP_HASH_RAW_CACHE_TTL_100NS;
}

static
NTSTATUS
DpHashProtectRefreshRawCacheIfNeeded(
    _In_ PFLT_INSTANCE Instance,
    _Inout_ PDP_HASH_RAW_VOLUME_CACHE Cache
    )
{
    static const PCWSTR SensitiveRelativePaths[] = {
        L"Windows\\System32\\config\\SAM",
        L"Windows\\System32\\config\\SECURITY",
        L"Windows\\System32\\config\\SYSTEM",
        L"Windows\\System32\\config\\RegBack\\SAM",
        L"Windows\\System32\\config\\RegBack\\SECURITY",
        L"Windows\\System32\\config\\RegBack\\SYSTEM",
        L"Windows\\Repair\\SAM",
        L"Windows\\Repair\\SECURITY",
        L"Windows\\Repair\\SYSTEM",
        L"Windows\\NTDS\\ntds.dit"
    };
    LARGE_INTEGER now;
    WCHAR volumeNameBuffer[512];
    UNICODE_STRING volumeName;
    ULONG volumeNameBytesNeeded = 0;
    ULONGLONG clusterSize = 0;
    NTSTATUS status;
    ULONG index;

    KeQuerySystemTimePrecise(&now);

    FltAcquirePushLockShared(&gDpHashProtectRawLock);
    if (!DpHashProtectRawCacheNeedsRefresh(Cache, now.QuadPart)) {
        FltReleasePushLock(&gDpHashProtectRawLock);
        return STATUS_SUCCESS;
    }
    FltReleasePushLock(&gDpHashProtectRawLock);

    FltAcquirePushLockExclusive(&gDpHashProtectRawLock);
    if (!DpHashProtectRawCacheNeedsRefresh(Cache, now.QuadPart)) {
        FltReleasePushLock(&gDpHashProtectRawLock);
        return STATUS_SUCCESS;
    }

    Cache->LastRefreshTime = now;
    Cache->LastRefreshStatus = STATUS_UNSUCCESSFUL;
    FltReleasePushLock(&gDpHashProtectRawLock);

    status = DpHashProtectQueryClusterSize(Instance, &clusterSize);
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(volumeNameBuffer, sizeof(volumeNameBuffer));
        RtlInitEmptyUnicodeString(&volumeName,
                                  volumeNameBuffer,
                                  sizeof(volumeNameBuffer));
        status = FltGetVolumeName(Cache->Volume,
                                  &volumeName,
                                  &volumeNameBytesNeeded);
    } else {
        RtlInitEmptyUnicodeString(&volumeName,
                                  volumeNameBuffer,
                                  sizeof(volumeNameBuffer));
    }

    {
        DP_HASH_RAW_EXTENT_LIST freshList;

        InitializeListHead(&freshList.Extents);
        freshList.ExtentCount = 0;

        if (NT_SUCCESS(status)) {
            for (index = 0; index < RTL_NUMBER_OF(SensitiveRelativePaths); index++) {
                NTSTATUS pathStatus;

                pathStatus = DpHashProtectAppendFileExtents(&freshList,
                                                            Instance,
                                                            &volumeName,
                                                            SensitiveRelativePaths[index],
                                                            clusterSize);

                if (!NT_SUCCESS(pathStatus)) {
                    status = pathStatus;
                    break;
                }
            }
        }

        FltAcquirePushLockExclusive(&gDpHashProtectRawLock);
        if (NT_SUCCESS(status)) {
            DpHashProtectClearRawExtentsLocked(Cache);
            DpHashProtectMoveRawExtentListLocked(&Cache->Extents,
                                                 &Cache->ExtentCount,
                                                 &freshList.Extents,
                                                 &freshList.ExtentCount);
        }
        FltReleasePushLock(&gDpHashProtectRawLock);

        DpHashProtectClearRawExtentList(&freshList.Extents,
                                        &freshList.ExtentCount);
    }

    KeQuerySystemTimePrecise(&now);
    FltAcquirePushLockExclusive(&gDpHashProtectRawLock);
    Cache->LastRefreshTime = now;
    Cache->LastRefreshStatus = status;
    if (NT_SUCCESS(status)) {
        Cache->Complete = TRUE;
    }
    DP_HASH_TRACE("raw extent cache refresh status=0x%08X extents=%lu cluster=%I64u\n",
                  status,
                  Cache->ExtentCount,
                  clusterSize);
    FltReleasePushLock(&gDpHashProtectRawLock);

    return status;
}

static
BOOLEAN
DpHashProtectFindRawOverlapLocked(
    _In_ PDP_HASH_RAW_VOLUME_CACHE Cache,
    _In_ ULONGLONG Offset,
    _In_ ULONGLONG Length,
    _Out_ PULONGLONG ExtentOffset,
    _Out_ PULONGLONG ExtentLength,
    _Out_writes_(TargetChars) PWCHAR Target,
    _In_ ULONG TargetChars
    )
{
    PLIST_ENTRY link;

    *ExtentOffset = 0;
    *ExtentLength = 0;
    if (Target != NULL && TargetChars != 0) {
        Target[0] = L'\0';
    }

    for (link = Cache->Extents.Flink;
         link != &Cache->Extents;
         link = link->Flink) {

        PDP_HASH_RAW_EXTENT_ENTRY extent = CONTAINING_RECORD(link,
                                                             DP_HASH_RAW_EXTENT_ENTRY,
                                                             Link);
        if (DpHashProtectRangesOverlap(Offset,
                                       Length,
                                       extent->Offset,
                                       extent->Length)) {

            *ExtentOffset = extent->Offset;
            *ExtentLength = extent->Length;
            if (Target != NULL && TargetChars != 0) {
                DpHashProtectCopyTargetSuffix(Target, extent->Target);
            }
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpHashProtectIsProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyName
    )
{
    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0) {
        return FALSE;
    }

    return DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SAM") ||
           DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SECURITY") ||
           DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SYSTEM");
}

static
BOOLEAN
DpHashProtectIsRegToolImage(
    _In_opt_ PCUNICODE_STRING ImageFileName
    )
{
    UNICODE_STRING regExe;

    if (ImageFileName == NULL ||
        ImageFileName->Buffer == NULL ||
        ImageFileName->Length == 0) {

        return FALSE;
    }

    RtlInitUnicodeString(&regExe, L"reg.exe");
    if (RtlEqualUnicodeString(ImageFileName, &regExe, TRUE)) {
        return TRUE;
    }

    return DpHashProtectSuffix(ImageFileName, L"\\reg.exe");
}

static
BOOLEAN
DpHashProtectCommandSeparator(
    _In_ WCHAR Character
    )
{
    return Character == L'\0' ||
           Character == L' ' ||
           Character == L'\t' ||
           Character == L'\r' ||
           Character == L'\n' ||
           Character == L'"' ||
           Character == L'\'' ||
           Character == L',' ||
           Character == L';' ||
           Character == L'=';
}

static
BOOLEAN
DpHashProtectCommandHasToken(
    _In_ PCUNICODE_STRING CommandLine,
    _In_z_ PCWSTR Token
    )
{
    UNICODE_STRING tokenString;
    USHORT commandChars;
    USHORT tokenChars;
    USHORT index;

    if (CommandLine == NULL ||
        CommandLine->Buffer == NULL ||
        CommandLine->Length == 0 ||
        Token == NULL) {

        return FALSE;
    }

    RtlInitUnicodeString(&tokenString, Token);
    if (tokenString.Length == 0 ||
        CommandLine->Length < tokenString.Length) {

        return FALSE;
    }

    commandChars = CommandLine->Length / sizeof(WCHAR);
    tokenChars = tokenString.Length / sizeof(WCHAR);

    for (index = 0; index <= commandChars - tokenChars; index++) {
        USHORT tokenIndex;
        BOOLEAN matched = TRUE;

        if (index != 0 &&
            !DpHashProtectCommandSeparator(CommandLine->Buffer[index - 1])) {

            continue;
        }

        for (tokenIndex = 0; tokenIndex < tokenChars; tokenIndex++) {
            if (!DpHashProtectUnicodeCharEqualsInsensitive(CommandLine->Buffer[index + tokenIndex],
                                                           tokenString.Buffer[tokenIndex])) {
                matched = FALSE;
                break;
            }
        }

        if (matched &&
            (index + tokenChars == commandChars ||
             DpHashProtectCommandSeparator(CommandLine->Buffer[index + tokenChars]))) {

            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpHashProtectCommandTargetsSensitiveHive(
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (CommandLine == NULL ||
        CommandLine->Buffer == NULL ||
        CommandLine->Length == 0) {

        return FALSE;
    }

    return DpHashProtectContainsInsensitive(CommandLine, L"HKLM\\SAM") ||
           DpHashProtectContainsInsensitive(CommandLine, L"HKLM\\SECURITY") ||
           DpHashProtectContainsInsensitive(CommandLine, L"HKLM\\SYSTEM") ||
           DpHashProtectContainsInsensitive(CommandLine, L"HKEY_LOCAL_MACHINE\\SAM") ||
           DpHashProtectContainsInsensitive(CommandLine, L"HKEY_LOCAL_MACHINE\\SECURITY") ||
           DpHashProtectContainsInsensitive(CommandLine, L"HKEY_LOCAL_MACHINE\\SYSTEM") ||
           DpHashProtectContainsInsensitive(CommandLine, L"\\Registry\\Machine\\SAM") ||
           DpHashProtectContainsInsensitive(CommandLine, L"\\Registry\\Machine\\SECURITY") ||
           DpHashProtectContainsInsensitive(CommandLine, L"\\Registry\\Machine\\SYSTEM");
}

static
BOOLEAN
DpHashProtectCommandIsSensitiveHiveExport(
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpHashProtectCommandTargetsSensitiveHive(CommandLine)) {
        return FALSE;
    }

    return DpHashProtectCommandHasToken(CommandLine, L"save") ||
           DpHashProtectCommandHasToken(CommandLine, L"export");
}

BOOLEAN
DpHashProtectShouldBlockProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
#if DP_ENABLE_HASH_PROTECT_REG_PROCESS_GUARD
    PCUNICODE_STRING imageFileName;
    PCUNICODE_STRING commandLine;
    const CHAR *processImage;

    UNREFERENCED_PARAMETER(Process);

    if (!gDpHashProtectInitialized ||
        CreateInfo == NULL ||
        !DpHashProtectFeatureEnabled(DP_HASH_PROTECT_FLAG_REGISTRY_HIVES)) {

        return FALSE;
    }

    imageFileName = CreateInfo->ImageFileName;
    commandLine = CreateInfo->CommandLine;

    if (!DpHashProtectIsRegToolImage(imageFileName) ||
        !DpHashProtectCommandIsSensitiveHiveExport(commandLine) ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return FALSE;
    }

    processImage = imageFileName != NULL ? "reg.exe" : NULL;
    DpHashProtectQueueEvent(DpHashProtectOperationRegistryHive,
                            ProcessId,
                            (ULONG)STATUS_ACCESS_DENIED,
                            0,
                            commandLine,
                            processImage);

    DP_HASH_TRACE("blocked registry hive export process create pid=%p image=%wZ command=%wZ\n",
                  ProcessId,
                  imageFileName,
                  commandLine);

    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    return TRUE;
#else
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
    return FALSE;
#endif
}

static
NTSTATUS
DpHashProtectRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    PVOID object = NULL;
    PCUNICODE_STRING keyName = NULL;
    ULONG_PTR objectId;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!DpHashProtectFeatureEnabled(DP_HASH_PROTECT_FLAG_REGISTRY_HIVES)) {
        return STATUS_SUCCESS;
    }

    if (Argument1 == NULL || Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    switch (notifyClass) {
    case RegNtPreSaveKey:
        object = ((PREG_SAVE_KEY_INFORMATION)Argument2)->Object;
        break;

    case RegNtPreRestoreKey:
        object = ((PREG_RESTORE_KEY_INFORMATION)Argument2)->Object;
        break;

    case RegNtPreReplaceKey:
        object = ((PREG_REPLACE_KEY_INFORMATION)Argument2)->Object;
        break;

    default:
        return STATUS_SUCCESS;
    }

    if (object == NULL ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return STATUS_SUCCESS;
    }

    status = CmCallbackGetKeyObjectID(&gDpHashProtectRegistryCookie,
                                      object,
                                      &objectId,
                                      &keyName);
    if (!NT_SUCCESS(status) || keyName == NULL) {
        return STATUS_SUCCESS;
    }

    if (DpHashProtectIsProtectedRegistryKey(keyName)) {
        DpHashProtectQueueEvent(DpHashProtectOperationRegistryHive,
                                PsGetCurrentProcessId(),
                                (ULONG)STATUS_ACCESS_DENIED,
                                0,
                                keyName,
                                (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
        DP_HASH_TRACE("blocked registry hive export pid=%p class=%lu key=%wZ image=%s\n",
                      PsGetCurrentProcessId(),
                      (ULONG)notifyClass,
                      keyName,
                      PsGetProcessImageFileName(PsGetCurrentProcess()));
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpHashProtectRegisterObCallback(
    VOID
    )
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operationRegistration;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING altitude;

    if (gDpHashProtectObHandle != NULL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&operationRegistration, sizeof(operationRegistration));
    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE |
                                       OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = DpHashProtectPreOperationCallback;
    operationRegistration.PostOperation = NULL;

    RtlInitUnicodeString(&altitude, DP_HASH_OB_ALTITUDE);

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.OperationRegistration = &operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration,
                                 &gDpHashProtectObHandle);
    if (!NT_SUCCESS(status)) {
        gDpHashProtectObHandle = NULL;
        DP_HASH_TRACE("ObRegisterCallbacks failed status=0x%08X\n", status);
    }

    return status;
}

static
NTSTATUS
DpHashProtectRegisterRegistryCallback(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (gDpHashProtectRegistryRegistered) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, DP_HASH_REG_ALTITUDE);
    status = CmRegisterCallbackEx(DpHashProtectRegistryCallback,
                                  &altitude,
                                  DriverObject,
                                  NULL,
                                  &gDpHashProtectRegistryCookie,
                                  NULL);
    if (NT_SUCCESS(status)) {
        gDpHashProtectRegistryRegistered = TRUE;
    } else {
        DP_HASH_TRACE("CmRegisterCallbackEx failed status=0x%08X\n", status);
    }

    return status;
}

NTSTATUS
DpHashProtectInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS obStatus;
    NTSTATUS registryStatus;

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&gDpHashProtectEvents);
    KeInitializeSpinLock(&gDpHashProtectEventLock);
    InitializeListHead(&gDpHashProtectRawVolumes);
    FltInitializePushLock(&gDpHashProtectRawLock);
    gDpHashProtectRawLockInitialized = TRUE;
    InterlockedExchange((volatile LONG *)&gDpHashProtectPolicyFlags,
                        (LONG)DP_HASH_PROTECT_DEFAULT_FLAGS);
    gDpHashProtectEventCount = 0;
    gDpHashProtectEventSequence = 0;
    gDpHashProtectDroppedEvents = 0;
    gDpHashProtectSuppressedDuplicates = 0;
    gDpHashProtectRawVolumeCount = 0;
    RtlZeroMemory(gDpHashProtectDedup, sizeof(gDpHashProtectDedup));
    gDpHashProtectInitialized = TRUE;

    obStatus = DpHashProtectRegisterObCallback();
    registryStatus = DpHashProtectRegisterRegistryCallback(DriverObject);

    if (!NT_SUCCESS(obStatus) || !NT_SUCCESS(registryStatus)) {
        DP_HASH_TRACE("hash protection initialization failed ob=0x%08X registry=0x%08X\n",
                      obStatus,
                      registryStatus);
        DpHashProtectUninitialize();
        return !NT_SUCCESS(obStatus) ? obStatus : registryStatus;
    }

    return STATUS_SUCCESS;
}

VOID
DpHashProtectUninitialize(
    VOID
    )
{
    if (gDpHashProtectRegistryRegistered) {
        CmUnRegisterCallback(gDpHashProtectRegistryCookie);
        gDpHashProtectRegistryRegistered = FALSE;
        gDpHashProtectRegistryCookie.QuadPart = 0;
    }

    if (gDpHashProtectObHandle != NULL) {
        ObUnRegisterCallbacks(gDpHashProtectObHandle);
        gDpHashProtectObHandle = NULL;
    }

    DpHashProtectClearEvents();
    DpHashProtectClearRawVolumes();
    if (gDpHashProtectRawLockInitialized) {
        FltDeletePushLock(&gDpHashProtectRawLock);
        gDpHashProtectRawLockInitialized = FALSE;
    }
    gDpHashProtectInitialized = FALSE;
}

BOOLEAN
DpHashProtectShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN block = FALSE;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE ||
        !DpHashProtectFeatureEnabled(DP_HASH_PROTECT_FLAG_CREDENTIAL_FILES) ||
        Data->RequestorMode == KernelMode ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        DpHashProtectIsAllowedCurrentProcess() ||
        !DpHashProtectCreateRequestsDataAccess(Data)) {

        return FALSE;
    }

    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return FALSE;
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
        return FALSE;
    }

    if (DpHashProtectIsCredentialStoreName(&nameInfo->Name)) {
        block = TRUE;
        DpHashProtectQueueEvent(DpHashProtectOperationCredentialFile,
                                PsGetCurrentProcessId(),
                                (ULONG)STATUS_ACCESS_DENIED,
                                Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                                &nameInfo->Name,
                                (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
        DP_HASH_TRACE("blocked credential store create pid=%p access=0x%08X path=%wZ image=%s\n",
                      PsGetCurrentProcessId(),
                      Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                      &nameInfo->Name,
                      PsGetProcessImageFileName(PsGetCurrentProcess()));
    }

    FltReleaseFileNameInformation(nameInfo);

    return block;
}

BOOLEAN
DpHashProtectShouldBlockRawVolumeRead(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb;
    PFLT_VOLUME volume;
    PDP_HASH_RAW_VOLUME_CACHE cache = NULL;
    LARGE_INTEGER byteOffset;
    ULONGLONG readOffset;
    ULONGLONG readLength;
    ULONGLONG extentOffset;
    ULONGLONG extentLength;
    WCHAR targetBuffer[DP_HASH_RAW_TARGET_CHARS];
    UNICODE_STRING target;
    NTSTATUS status;
    BOOLEAN overlap;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_READ ||
        !DpHashProtectFeatureEnabled(DP_HASH_PROTECT_FLAG_RAW_EXTENTS) ||
        Data->RequestorMode == KernelMode ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        FltObjects->Volume == NULL ||
        !FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return FALSE;
    }

    iopb = Data->Iopb;
    if (iopb->Parameters.Read.Length == 0 ||
        DpShadowIsInternalIo()) {

        return FALSE;
    }

    byteOffset = iopb->Parameters.Read.ByteOffset;
    if (byteOffset.QuadPart < 0 ||
        byteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION) {

        return FALSE;
    }

    readOffset = (ULONGLONG)byteOffset.QuadPart;
    readLength = (ULONGLONG)iopb->Parameters.Read.Length;
    volume = FltObjects->Volume;

    status = DpHashProtectEnsureRawCache(volume, &cache);
    if (!NT_SUCCESS(status) || cache == NULL) {
        DP_HASH_TRACE("raw extent cache unavailable status=0x%08X pid=%p\n",
                      status,
                      PsGetCurrentProcessId());
        return FALSE;
    }

    status = DpHashProtectRefreshRawCacheIfNeeded(FltObjects->Instance, cache);
    if (!NT_SUCCESS(status)) {
        DP_HASH_TRACE("raw extent refresh failed status=0x%08X pid=%p offset=%I64u length=%I64u\n",
                      status,
                      PsGetCurrentProcessId(),
                      readOffset,
                      readLength);
        DpHashProtectReleaseRawVolumeCache(cache);
        return FALSE;
    }

    RtlZeroMemory(targetBuffer, sizeof(targetBuffer));

    FltAcquirePushLockShared(&gDpHashProtectRawLock);
    overlap = DpHashProtectFindRawOverlapLocked(cache,
                                                readOffset,
                                                readLength,
                                                &extentOffset,
                                                &extentLength,
                                                targetBuffer,
                                                RTL_NUMBER_OF(targetBuffer));
    FltReleasePushLock(&gDpHashProtectRawLock);

    if (!overlap) {
        DpHashProtectReleaseRawVolumeCache(cache);
        return FALSE;
    }

    RtlInitUnicodeString(&target, targetBuffer);
    DpHashProtectQueueEvent(DpHashProtectOperationRawExtent,
                            PsGetCurrentProcessId(),
                            (ULONG)STATUS_ACCESS_DENIED,
                            FILE_READ_DATA,
                            &target,
                            (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));

    DP_HASH_TRACE("blocked raw extent read pid=%p offset=%I64u length=%I64u extentOffset=%I64u extentLength=%I64u target=%wZ image=%s\n",
                  PsGetCurrentProcessId(),
                  readOffset,
                  readLength,
                  extentOffset,
                  extentLength,
                  &target,
                  PsGetProcessImageFileName(PsGetCurrentProcess()));

    DpHashProtectReleaseRawVolumeCache(cache);
    return TRUE;
}

NTSTATUS
DpHashProtectSetPolicy(
    _In_ const DP_HASH_PROTECT_POLICY *Policy
    )
{
    ULONG flags;

    if (Policy == NULL ||
        Policy->Version != DP_HASH_PROTECT_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_HASH_PROTECT_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_HASH_PROTECT_ALLOWED_FLAGS;

    InterlockedExchange((volatile LONG *)&gDpHashProtectPolicyFlags, (LONG)flags);

    DP_HASH_TRACE("policy updated flags=0x%08X\n", flags);

    return STATUS_SUCCESS;
}

NTSTATUS
DpHashProtectQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_HASH_PROTECT_POLICY policy;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = sizeof(DP_HASH_PROTECT_POLICY);

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_HASH_PROTECT_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    policy = (PDP_HASH_PROTECT_POLICY)OutputBuffer;
    RtlZeroMemory(policy, sizeof(DP_HASH_PROTECT_POLICY));

    policy->Version = DP_HASH_PROTECT_POLICY_VERSION;
    policy->Flags = DpHashProtectReadPolicyFlags();

    return STATUS_SUCCESS;
}

NTSTATUS
DpHashProtectQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_HASH_PROTECT_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    ULONG traceEventCount = 0;
    ULONG traceReturnedEventCount = 0;
    ULONG traceBytesRequired = 0;
    ULONG traceBytesReturned = 0;
    ULONGLONG traceDroppedEvents = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_HASH_PROTECT_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    header->Version = DP_HASH_PROTECT_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    if (!gDpHashProtectInitialized) {
        header->BytesRequired = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
        DP_HASH_TRACE("query events uninitialized sizing=%lu bytesReturned=%lu\n",
                      sizingOnly ? 1u : 0u,
                      *ReturnOutputBufferLength);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);

    header->DroppedEvents = gDpHashProtectDroppedEvents;

    for (link = gDpHashProtectEvents.Flink; link != &gDpHashProtectEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_HASH_PROTECT_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;
    traceEventCount = eventCount;
    traceReturnedEventCount = returnedEventCount;
    traceBytesRequired = bytesRequired;
    traceBytesReturned = bytesReturned;
    traceDroppedEvents = gDpHashProtectDroppedEvents;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpHashProtectEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpHashProtectEvents);
            PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(eventLink, DP_HASH_PROTECT_EVENT_ENTRY, Link);
            ULONGLONG drainedSequence = event->Event.Sequence;
            ULONG remainingEvents;

            DP_HASH_TRACE_VALUE(drainedSequence);
            gDpHashProtectEventCount--;
            remainingEvents = gDpHashProtectEventCount;
            KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
            DP_HASH_TRACE("query drain seq=%I64u remaining=%lu\n",
                          drainedSequence,
                          remainingEvents);
            DpHashProtectFreeEvent(event);
            KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);

    DP_HASH_TRACE("query events sizing=%lu events=%lu returned=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u\n",
                  sizingOnly ? 1u : 0u,
                  traceEventCount,
                  traceReturnedEventCount,
                  traceBytesRequired,
                  traceBytesReturned,
                  traceDroppedEvents);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}
