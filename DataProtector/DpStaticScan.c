/*++

Module Name:

    DpStaticScan.c

Abstract:

    On-access executable scan DETECTOR / NOTIFIER. This module deliberately does
    NOT classify files. Heavy, rule-driven scanning (YARA, signatures, entropy,
    PE parsing, ML, cloud reputation) belongs in a signed user-mode service so
    detection content is updatable without reloading a signed kernel driver and
    so a parsing bug can never crash the fleet.

    Responsibilities of this kernel module:
      1. Detect: on cleanup of a handle that created / wrote / renamed an
         executable image (PE or script dropper), capture metadata
         {requestId, pid, op, size, path, image}.
      2. Notify: enqueue a scan REQUEST into a bounded ring. The user-mode
         service drains requests over the existing policy port (poll/drain,
         matching every other sensor in this product).
      3. Enforce: when user mode submits a VERDICT, record the result event,
         report it to the threat engine, and - if policy says block and the
         verdict is malicious/suspicious - quarantine the file by truncating it.

    The I/O path is never held waiting for a verdict; detection is async and
    enforcement is post-hoc, which is the safe model for large-scale fleets.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>

#if DP_ENABLE_STATIC_SCAN_TRACE
#define DP_STATIC_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[StaticScan] " _format, __VA_ARGS__)
#else
#define DP_STATIC_TRACE(_format, ...) ((void)0)
#endif

typedef struct _DP_STATIC_SCAN_REQUEST_ENTRY {
    LIST_ENTRY Link;
    DP_STATIC_SCAN_REQUEST_QUERY_ENTRY Request;
} DP_STATIC_SCAN_REQUEST_ENTRY, *PDP_STATIC_SCAN_REQUEST_ENTRY;

typedef struct _DP_STATIC_SCAN_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_STATIC_SCAN_EVENT_QUERY_ENTRY Event;
} DP_STATIC_SCAN_EVENT_ENTRY, *PDP_STATIC_SCAN_EVENT_ENTRY;

//
// Pending requests (kernel -> user mode).
//
static LIST_ENTRY gStaticScanRequests;
static KSPIN_LOCK gStaticScanRequestLock;
static ULONG gStaticScanRequestCount = 0;
static ULONGLONG gStaticScanRequestSequence = 0;
static ULONGLONG gStaticScanDroppedRequests = 0;

//
// Result events (for the console).
//
static LIST_ENTRY gStaticScanEvents;
static KSPIN_LOCK gStaticScanEventLock;
static ULONG gStaticScanEventCount = 0;
static ULONGLONG gStaticScanEventSequence = 0;
static ULONGLONG gStaticScanDroppedEvents = 0;

static BOOLEAN gStaticScanInitialized = FALSE;

static volatile LONG gStaticScanFlags = DP_STATIC_SCAN_DEFAULT_FLAGS;

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static
ULONGLONG
DpStaticNow(
    VOID
    )
{
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);
    return (ULONGLONG)now.QuadPart;
}

static
ULONG
DpStaticReadFlags(
    VOID
    )
{
    return (ULONG)gStaticScanFlags;
}

static
BOOLEAN
DpStaticFeatureEnabled(
    _In_ ULONG FeatureFlag
    )
{
    ULONG flags = DpStaticReadFlags();

    return FlagOn(flags, DP_STATIC_SCAN_FLAG_ENABLED) &&
           FlagOn(flags, FeatureFlag);
}

static
BOOLEAN
DpStaticSuffixInsensitive(
    _In_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Suffix
    )
{
    UNICODE_STRING suffix;
    UNICODE_STRING candidate;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    RtlInitUnicodeString(&suffix, Suffix);
    if (Name->Length < suffix.Length || suffix.Length == 0) {
        return FALSE;
    }

    candidate.Buffer = (PWCH)((PUCHAR)Name->Buffer + Name->Length - suffix.Length);
    candidate.Length = suffix.Length;
    candidate.MaximumLength = suffix.Length;

    return RtlEqualUnicodeString(&candidate, &suffix, TRUE);
}

static
BOOLEAN
DpStaticIsPeName(
    _In_ PCUNICODE_STRING Name
    )
{
    static const PCWSTR PeSuffixes[] = {
        L".exe", L".dll", L".sys", L".scr", L".cpl", L".ocx", L".com", L".efi"
    };
    ULONG index;

    for (index = 0; index < RTL_NUMBER_OF(PeSuffixes); index++) {
        if (DpStaticSuffixInsensitive(Name, PeSuffixes[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpStaticIsScriptDropperName(
    _In_ PCUNICODE_STRING Name
    )
{
    static const PCWSTR ScriptSuffixes[] = {
        L".bat", L".cmd", L".ps1", L".psm1", L".vbs", L".vbe",
        L".js", L".jse", L".wsf", L".hta", L".lnk", L".scf"
    };
    ULONG index;

    for (index = 0; index < RTL_NUMBER_OF(ScriptSuffixes); index++) {
        if (DpStaticSuffixInsensitive(Name, ScriptSuffixes[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
DpStaticScanIsExecutableName(
    _In_ PCUNICODE_STRING Name
    )
{
    return DpStaticIsPeName(Name) || DpStaticIsScriptDropperName(Name);
}

static
VOID
DpStaticFreeRequest(
    _In_opt_ PDP_STATIC_SCAN_REQUEST_ENTRY Request
    )
{
    if (Request != NULL) {
        ExFreePoolWithTag(Request, DP_TAG_STATIC_SCAN);
    }
}

static
VOID
DpStaticFreeEvent(
    _In_opt_ PDP_STATIC_SCAN_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_STATIC_SCAN);
    }
}

//
// Detector. Capture metadata for an executable that a closing handle wrote, and
// enqueue a scan request. No file content is read here; user mode opens and
// reads the file itself. Best-effort: failure to size the file is non-fatal.
//
VOID
DpStaticScanEnqueueRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_ DP_STATIC_SCAN_OPERATION Operation
    )
{
    PDP_STATIC_SCAN_REQUEST_ENTRY entry;
    KIRQL oldIrql;
    ULONGLONG fileSize = 0;
    const CHAR *imageName;
    ULONG i;
    BOOLEAN isPe;
    BOOLEAN isScript;

    UNREFERENCED_PARAMETER(Data);

    if (!gStaticScanInitialized ||
        !DpStaticFeatureEnabled(DP_STATIC_SCAN_FLAG_ENABLED) ||
        Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length == 0) {

        return;
    }

    isPe = DpStaticIsPeName(Name);
    isScript = DpStaticIsScriptDropperName(Name);

    if (isPe && !DpStaticFeatureEnabled(DP_STATIC_SCAN_FLAG_SCAN_PE)) {
        return;
    }
    if (isScript && !isPe && !DpStaticFeatureEnabled(DP_STATIC_SCAN_FLAG_SCAN_SCRIPTS)) {
        return;
    }
    if (!isPe && !isScript) {
        return;
    }

    //
    // Size is metadata only (helps user mode prioritize / cap reads). Failure
    // is tolerated; user mode re-stats the file when it opens it.
    //
    if (FltObjects != NULL &&
        FltObjects->Instance != NULL &&
        FltObjects->FileObject != NULL) {

        FILE_STANDARD_INFORMATION standardInfo;
        NTSTATUS sizeStatus;

        RtlZeroMemory(&standardInfo, sizeof(standardInfo));
        sizeStatus = FltQueryInformationFile(FltObjects->Instance,
                                             FltObjects->FileObject,
                                             &standardInfo,
                                             sizeof(standardInfo),
                                             FileStandardInformation,
                                             NULL);
        if (NT_SUCCESS(sizeStatus)) {
            fileSize = (ULONGLONG)standardInfo.EndOfFile.QuadPart;
        }
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_STATIC_SCAN_REQUEST_ENTRY),
                                  DP_TAG_STATIC_SCAN);
    if (entry == NULL) {
        KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);
        gStaticScanDroppedRequests++;
        KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_STATIC_SCAN_REQUEST_ENTRY));
    entry->Request.TimeStamp = DpStaticNow();
    entry->Request.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Request.FileSize = fileSize;
    entry->Request.Operation = (ULONG)Operation;

    {
        ULONG copyBytes = min((ULONG)Name->Length,
                              (ULONG)((DP_STATIC_SCAN_PATH_CHARS - 1) * sizeof(WCHAR)));
        RtlCopyMemory(entry->Request.Path, Name->Buffer, copyBytes);
        entry->Request.Path[copyBytes / sizeof(WCHAR)] = L'\0';
        entry->Request.PathLengthBytes = copyBytes;
    }

    imageName = (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess());
    if (imageName != NULL) {
        for (i = 0;
             i + 1 < DP_STATIC_SCAN_PROCESS_CHARS && imageName[i] != '\0';
             i++) {

            entry->Request.ProcessImage[i] = (WCHAR)(UCHAR)imageName[i];
        }
        entry->Request.ProcessImage[i] = L'\0';
        entry->Request.ProcessImageLengthBytes = i * sizeof(WCHAR);
    }

    KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);

    entry->Request.RequestId = ++gStaticScanRequestSequence;
    InsertTailList(&gStaticScanRequests, &entry->Link);
    gStaticScanRequestCount++;

    while (gStaticScanRequestCount > DP_STATIC_SCAN_MAX_REQUESTS &&
           !IsListEmpty(&gStaticScanRequests)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gStaticScanRequests);
        PDP_STATIC_SCAN_REQUEST_ENTRY oldRequest = CONTAINING_RECORD(oldLink,
                                                                     DP_STATIC_SCAN_REQUEST_ENTRY,
                                                                     Link);
        gStaticScanRequestCount--;
        gStaticScanDroppedRequests++;
        KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);
        DpStaticFreeRequest(oldRequest);
        KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);
    }

    KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);

    DP_STATIC_TRACE("request queued id=%I64u pid=%p op=%lu size=%I64u path=%wZ\n",
                    entry->Request.RequestId,
                    ProcessId,
                    (ULONG)Operation,
                    fileSize,
                    Name);
}

NTSTATUS
DpStaticScanQueryRequests(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_STATIC_SCAN_REQUEST_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);
    ULONG requestCount = 0;
    ULONG returnedCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_STATIC_SCAN_REQUEST_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);

    header->Version = DP_STATIC_SCAN_REQUEST_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);

    if (!gStaticScanInitialized) {
        header->BytesRequired = sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_STATIC_SCAN_REQUEST_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);

    header->DroppedRequests = gStaticScanDroppedRequests;

    for (link = gStaticScanRequests.Flink; link != &gStaticScanRequests; link = link->Flink) {
        bytesRequired += sizeof(DP_STATIC_SCAN_REQUEST_QUERY_ENTRY);
        requestCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_STATIC_SCAN_REQUEST_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_STATIC_SCAN_REQUEST_ENTRY request = CONTAINING_RECORD(link,
                                                                      DP_STATIC_SCAN_REQUEST_ENTRY,
                                                                      Link);
            RtlCopyMemory(cursor, &request->Request, sizeof(DP_STATIC_SCAN_REQUEST_QUERY_ENTRY));
            cursor += sizeof(DP_STATIC_SCAN_REQUEST_QUERY_ENTRY);
            bytesReturned += sizeof(DP_STATIC_SCAN_REQUEST_QUERY_ENTRY);
            returnedCount++;
        }
    }

    header->RequestCount = requestCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    //
    // Drain only when the caller took everything (two-pass: a sizing-only call
    // never drains).
    //
    if (!sizingOnly && returnedCount == requestCount) {
        while (!IsListEmpty(&gStaticScanRequests)) {
            PLIST_ENTRY drainLink = RemoveHeadList(&gStaticScanRequests);
            PDP_STATIC_SCAN_REQUEST_ENTRY request = CONTAINING_RECORD(drainLink,
                                                                      DP_STATIC_SCAN_REQUEST_ENTRY,
                                                                      Link);
            gStaticScanRequestCount--;
            KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);
            DpStaticFreeRequest(request);
            KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedCount != requestCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

//
// Quarantine: open the file by name and truncate it to zero length so a
// malicious payload cannot be executed. Runs at PASSIVE_LEVEL on the verdict
// submission path.
//
static
NTSTATUS
DpStaticQuarantineByName(
    _In_ PCUNICODE_STRING Name
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;

    if (gDataProtectorFilter == NULL ||
        Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length == 0 ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {

        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = FltCreateFileEx2(gDataProtectorFilter,
                              NULL,
                              &fileHandle,
                              &fileObject,
                              FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
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
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpShadowTruncateFileObject(NULL, fileObject);

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    if (fileHandle != NULL) {
        FltClose(fileHandle);
    }

    return status;
}

static
VOID
DpStaticQueueEvent(
    _In_ const DP_STATIC_SCAN_VERDICT_MESSAGE *Verdict,
    _In_ NTSTATUS ActionStatus,
    _In_ BOOLEAN Blocked
    )
{
    PDP_STATIC_SCAN_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONG copyBytes;

    if (!gStaticScanInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_STATIC_SCAN_EVENT_ENTRY),
                                  DP_TAG_STATIC_SCAN);
    if (entry == NULL) {
        KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
        gStaticScanDroppedEvents++;
        KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_STATIC_SCAN_EVENT_ENTRY));
    entry->Event.TimeStamp = DpStaticNow();
    entry->Event.ProcessId = Verdict->ProcessId;
    entry->Event.FileSize = Verdict->FileSize;
    entry->Event.Verdict = Verdict->Verdict;
    entry->Event.Operation = Verdict->Operation;
    entry->Event.Score = Verdict->Score;
    entry->Event.ReasonFlags = Verdict->ReasonFlags;
    entry->Event.Status = (ULONG)ActionStatus;
    entry->Event.Blocked = Blocked ? 1u : 0u;

    copyBytes = min(Verdict->PathLengthBytes,
                    (ULONG)((DP_STATIC_SCAN_PATH_CHARS - 1) * sizeof(WCHAR)));
    if (copyBytes != 0) {
        RtlCopyMemory(entry->Event.Path, Verdict->Path, copyBytes);
    }
    entry->Event.Path[copyBytes / sizeof(WCHAR)] = L'\0';
    entry->Event.PathLengthBytes = copyBytes;

    copyBytes = min(Verdict->ReasonTextLengthBytes,
                    (ULONG)((DP_STATIC_SCAN_REASON_CHARS - 1) * sizeof(WCHAR)));
    if (copyBytes != 0) {
        RtlCopyMemory(entry->Event.ReasonText, Verdict->ReasonText, copyBytes);
    }
    entry->Event.ReasonText[copyBytes / sizeof(WCHAR)] = L'\0';
    entry->Event.ReasonTextLengthBytes = copyBytes;

    KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);

    entry->Event.Sequence = ++gStaticScanEventSequence;
    InsertTailList(&gStaticScanEvents, &entry->Link);
    gStaticScanEventCount++;

    while (gStaticScanEventCount > DP_STATIC_SCAN_MAX_EVENTS &&
           !IsListEmpty(&gStaticScanEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gStaticScanEvents);
        PDP_STATIC_SCAN_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink,
                                                                 DP_STATIC_SCAN_EVENT_ENTRY,
                                                                 Link);
        gStaticScanEventCount--;
        gStaticScanDroppedEvents++;
        KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
        DpStaticFreeEvent(oldEvent);
        KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
    }

    KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
}

//
// Map a user-mode verdict to a threat-engine signal so the disk verdict folds
// into the owning process's storyline and risk score.
//
static
VOID
DpStaticReportToThreatEngine(
    _In_ const DP_STATIC_SCAN_VERDICT_MESSAGE *Verdict
    )
{
    DP_THREAT_SIGNAL signal;
    HANDLE processId = (HANDLE)(ULONG_PTR)Verdict->ProcessId;
    UNICODE_STRING path;

    if (processId == NULL) {
        return;
    }

    switch (Verdict->Verdict) {
    case DpStaticScanVerdictMalicious:
        signal = DpThreatSignalMaliciousExecutableWrite;
        break;
    case DpStaticScanVerdictSuspicious:
        if (FlagOn(Verdict->ReasonFlags, DP_STATIC_SCAN_REASON_PACKER_SECTION) ||
            FlagOn(Verdict->ReasonFlags, DP_STATIC_SCAN_REASON_HIGH_ENTROPY)) {

            signal = DpThreatSignalPackedExecutableWrite;
        } else {
            signal = DpThreatSignalSuspiciousExecutableWrite;
        }
        break;
    default:
        return;
    }

    path.Buffer = (PWCH)Verdict->Path;
    path.Length = (USHORT)min(Verdict->PathLengthBytes,
                              (ULONG)((DP_STATIC_SCAN_PATH_CHARS - 1) * sizeof(WCHAR)));
    path.MaximumLength = path.Length;

    (VOID)DpThreatEngineReportSignal(processId,
                                     signal,
                                     0,
                                     (path.Length != 0) ? &path : NULL);
}

static
BOOLEAN
DpStaticVerdictShouldBlock(
    _In_ DP_STATIC_SCAN_VERDICT Verdict
    )
{
    ULONG flags = DpStaticReadFlags();

    if (!FlagOn(flags, DP_STATIC_SCAN_FLAG_ENABLED) ||
        FlagOn(flags, DP_STATIC_SCAN_FLAG_AUDIT_ONLY)) {

        return FALSE;
    }

    if (Verdict == DpStaticScanVerdictMalicious &&
        FlagOn(flags, DP_STATIC_SCAN_FLAG_BLOCK_MALICIOUS)) {

        return TRUE;
    }

    if (Verdict == DpStaticScanVerdictSuspicious &&
        FlagOn(flags, DP_STATIC_SCAN_FLAG_BLOCK_SUSPICIOUS)) {

        return TRUE;
    }

    return FALSE;
}

NTSTATUS
DpStaticScanSubmitVerdict(
    _In_ const DP_STATIC_SCAN_VERDICT_MESSAGE *Verdict
    )
{
    NTSTATUS actionStatus = STATUS_SUCCESS;
    BOOLEAN blocked = FALSE;
    DP_STATIC_SCAN_VERDICT verdictKind;

    if (Verdict == NULL ||
        Verdict->Version != DP_STATIC_SCAN_VERDICT_MESSAGE_VERSION ||
        Verdict->PathLengthBytes > (DP_STATIC_SCAN_PATH_CHARS - 1) * sizeof(WCHAR) ||
        Verdict->ReasonTextLengthBytes > (DP_STATIC_SCAN_REASON_CHARS - 1) * sizeof(WCHAR) ||
        (Verdict->PathLengthBytes % sizeof(WCHAR)) != 0 ||
        (Verdict->ReasonTextLengthBytes % sizeof(WCHAR)) != 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if (!gStaticScanInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    verdictKind = (DP_STATIC_SCAN_VERDICT)Verdict->Verdict;
    if (verdictKind > DpStaticScanVerdictMalicious) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Enforce quarantine when policy says block. The original handle is long
    // gone, so we re-open by name and truncate.
    //
    if (DpStaticVerdictShouldBlock(verdictKind) &&
        Verdict->PathLengthBytes != 0) {

        UNICODE_STRING path;

        path.Buffer = (PWCH)Verdict->Path;
        path.Length = (USHORT)Verdict->PathLengthBytes;
        path.MaximumLength = (USHORT)Verdict->PathLengthBytes;

        actionStatus = DpStaticQuarantineByName(&path);
        blocked = NT_SUCCESS(actionStatus);

        DP_STATIC_TRACE("quarantine verdict=%lu status=0x%08X path=%wZ\n",
                        (ULONG)verdictKind,
                        actionStatus,
                        &path);
    }

    //
    // Record the result and fold it into the threat engine. Clean verdicts are
    // not recorded as events (they are the common case and would flood the
    // console), but suspicious/malicious always are.
    //
    if (verdictKind != DpStaticScanVerdictClean) {
        DpStaticQueueEvent(Verdict, actionStatus, blocked);
        DpStaticReportToThreatEngine(Verdict);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpStaticScanQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_STATIC_SCAN_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_STATIC_SCAN_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);

    header->Version = DP_STATIC_SCAN_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);

    if (!gStaticScanInitialized) {
        header->BytesRequired = sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_STATIC_SCAN_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);

    header->DroppedEvents = gStaticScanDroppedEvents;

    for (link = gStaticScanEvents.Flink; link != &gStaticScanEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_STATIC_SCAN_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_STATIC_SCAN_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_STATIC_SCAN_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                                  DP_STATIC_SCAN_EVENT_ENTRY,
                                                                  Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_STATIC_SCAN_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_STATIC_SCAN_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_STATIC_SCAN_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gStaticScanEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gStaticScanEvents);
            PDP_STATIC_SCAN_EVENT_ENTRY event = CONTAINING_RECORD(eventLink,
                                                                  DP_STATIC_SCAN_EVENT_ENTRY,
                                                                  Link);
            gStaticScanEventCount--;
            KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
            DpStaticFreeEvent(event);
            KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpStaticScanSetPolicy(
    _In_ const DP_STATIC_SCAN_POLICY *Policy
    )
{
    ULONG flags;

    if (Policy == NULL ||
        Policy->Version != DP_STATIC_SCAN_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_STATIC_SCAN_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_STATIC_SCAN_ALLOWED_FLAGS;
    InterlockedExchange(&gStaticScanFlags, (LONG)flags);

    DP_STATIC_TRACE("policy updated flags=0x%08X\n", flags);

    return STATUS_SUCCESS;
}

NTSTATUS
DpStaticScanQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_STATIC_SCAN_POLICY policy;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = sizeof(DP_STATIC_SCAN_POLICY);

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_STATIC_SCAN_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    policy = (PDP_STATIC_SCAN_POLICY)OutputBuffer;
    RtlZeroMemory(policy, sizeof(DP_STATIC_SCAN_POLICY));
    policy->Version = DP_STATIC_SCAN_POLICY_VERSION;
    policy->Flags = DpStaticReadFlags();

    return STATUS_SUCCESS;
}

VOID
DpStaticScanClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gStaticScanInitialized) {
        return;
    }

    KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
    while (!IsListEmpty(&gStaticScanEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gStaticScanEvents);
        PDP_STATIC_SCAN_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                              DP_STATIC_SCAN_EVENT_ENTRY,
                                                              Link);
        gStaticScanEventCount--;
        KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
        DpStaticFreeEvent(event);
        KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
}

NTSTATUS
DpStaticScanInitialize(
    VOID
    )
{
    InitializeListHead(&gStaticScanRequests);
    InitializeListHead(&gStaticScanEvents);
    KeInitializeSpinLock(&gStaticScanRequestLock);
    KeInitializeSpinLock(&gStaticScanEventLock);
    InterlockedExchange(&gStaticScanFlags, (LONG)DP_STATIC_SCAN_DEFAULT_FLAGS);
    gStaticScanRequestCount = 0;
    gStaticScanRequestSequence = 0;
    gStaticScanDroppedRequests = 0;
    gStaticScanEventCount = 0;
    gStaticScanEventSequence = 0;
    gStaticScanDroppedEvents = 0;
    gStaticScanInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
DpStaticScanUninitialize(
    VOID
    )
{
    KIRQL oldIrql;

    gStaticScanInitialized = FALSE;

    KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);
    while (!IsListEmpty(&gStaticScanRequests)) {
        PLIST_ENTRY link = RemoveHeadList(&gStaticScanRequests);
        PDP_STATIC_SCAN_REQUEST_ENTRY request = CONTAINING_RECORD(link,
                                                                  DP_STATIC_SCAN_REQUEST_ENTRY,
                                                                  Link);
        gStaticScanRequestCount--;
        KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);
        DpStaticFreeRequest(request);
        KeAcquireSpinLock(&gStaticScanRequestLock, &oldIrql);
    }
    KeReleaseSpinLock(&gStaticScanRequestLock, oldIrql);

    KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
    while (!IsListEmpty(&gStaticScanEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gStaticScanEvents);
        PDP_STATIC_SCAN_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                              DP_STATIC_SCAN_EVENT_ENTRY,
                                                              Link);
        gStaticScanEventCount--;
        KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
        DpStaticFreeEvent(event);
        KeAcquireSpinLock(&gStaticScanEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gStaticScanEventLock, oldIrql);
}
