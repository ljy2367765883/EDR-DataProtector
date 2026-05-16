/*++

Module Name:

    DpWebShell.c

Abstract:

    Web directory hardening policy. The module detects newly created web
    script files under protected web roots and classifies short one-liner
    style payloads before the write or rename is allowed to complete.

--*/

#include "DataProtector.h"

typedef struct _DP_WEBSHELL_RULE_ENTRY {
    LIST_ENTRY Link;
    UNICODE_STRING Directory;
} DP_WEBSHELL_RULE_ENTRY, *PDP_WEBSHELL_RULE_ENTRY;

typedef struct _DP_WEBSHELL_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_WEBSHELL_EVENT_QUERY_ENTRY Event;
} DP_WEBSHELL_EVENT_ENTRY, *PDP_WEBSHELL_EVENT_ENTRY;

static LIST_ENTRY gDpWebShellRules;
static LIST_ENTRY gDpWebShellEvents;
static EX_PUSH_LOCK gDpWebShellRuleLock;
static KSPIN_LOCK gDpWebShellEventLock;
static BOOLEAN gDpWebShellInitialized = FALSE;
static ULONG gDpWebShellRuleCount = 0;
static ULONG gDpWebShellEventCount = 0;
static ULONGLONG gDpWebShellEventSequence = 0;
static ULONGLONG gDpWebShellDroppedEvents = 0;

static
VOID
DpWebShellFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, DP_TAG_WEBSHELL_RULE);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

static
VOID
DpWebShellTrimTrailingSlash(
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
NTSTATUS
DpWebShellDuplicateDirectory(
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
        Source->Length > DP_WEBSHELL_MAX_PATH_BYTES) {

        return STATUS_INVALID_PARAMETER;
    }

    Destination->Buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                Source->Length,
                                                DP_TAG_WEBSHELL_RULE);

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;
    Destination->MaximumLength = Source->Length;
    DpWebShellTrimTrailingSlash(Destination);

    if (Destination->Length == 0) {
        DpWebShellFreeUnicodeString(Destination);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static
BOOLEAN
DpWebShellDirectoryMatches(
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
DpWebShellRuleExistsLocked(
    _In_ PCUNICODE_STRING Directory
    )
{
    PLIST_ENTRY link;

    for (link = gDpWebShellRules.Flink; link != &gDpWebShellRules; link = link->Flink) {
        PDP_WEBSHELL_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_WEBSHELL_RULE_ENTRY, Link);

        if (RtlEqualUnicodeString(&rule->Directory, Directory, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
DpWebShellFreeRule(
    _In_opt_ PDP_WEBSHELL_RULE_ENTRY Rule
    )
{
    if (Rule == NULL) {
        return;
    }

    DpWebShellFreeUnicodeString(&Rule->Directory);
    ExFreePoolWithTag(Rule, DP_TAG_WEBSHELL_RULE);
}

static
VOID
DpWebShellClearRulesLocked(
    VOID
    )
{
    while (!IsListEmpty(&gDpWebShellRules)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpWebShellRules);
        PDP_WEBSHELL_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_WEBSHELL_RULE_ENTRY, Link);

        gDpWebShellRuleCount--;
        DpWebShellFreeRule(rule);
    }

    gDpWebShellRuleCount = 0;
}

static
VOID
DpWebShellFreeEvent(
    _In_opt_ PDP_WEBSHELL_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_WEBSHELL_EVENT);
    }
}

static
VOID
DpWebShellClearEvents(
    VOID
    )
{
    LIST_ENTRY localList;
    KIRQL oldIrql;

    if (!gDpWebShellInitialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);

    while (!IsListEmpty(&gDpWebShellEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpWebShellEvents);
        InsertTailList(&localList, link);
    }

    gDpWebShellEventCount = 0;

    KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY link = RemoveHeadList(&localList);
        PDP_WEBSHELL_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_WEBSHELL_EVENT_ENTRY, Link);
        DpWebShellFreeEvent(event);
    }
}

static
CHAR
DpWebShellLowerAscii(
    _In_ CHAR Character
    )
{
    if (Character >= 'A' && Character <= 'Z') {
        return (CHAR)(Character + ('a' - 'A'));
    }

    return Character;
}

static
BOOLEAN
DpWebShellAsciiContainsInsensitive(
    _In_reads_bytes_(BufferLength) const CHAR *Buffer,
    _In_ SIZE_T BufferLength,
    _In_z_ const CHAR *Needle
    )
{
    SIZE_T index;
    SIZE_T needleLength = 0;

    if (Buffer == NULL || Needle == NULL) {
        return FALSE;
    }

    while (Needle[needleLength] != '\0') {
        needleLength++;
    }

    if (needleLength == 0 || BufferLength < needleLength) {
        return FALSE;
    }

    for (index = 0; index <= BufferLength - needleLength; index++) {
        SIZE_T subIndex;
        BOOLEAN matched = TRUE;

        for (subIndex = 0; subIndex < needleLength; subIndex++) {
            if (DpWebShellLowerAscii(Buffer[index + subIndex]) !=
                DpWebShellLowerAscii(Needle[subIndex])) {

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
ULONG
DpWebShellBuildAsciiView(
    _In_reads_bytes_(Length) const CHAR *Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(OutputLength) CHAR *Output,
    _In_ ULONG OutputLength
    )
{
    ULONG inputIndex;
    ULONG outputIndex = 0;

    if (Output == NULL || OutputLength == 0) {
        return 0;
    }

    Output[0] = '\0';

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    for (inputIndex = 0; inputIndex < Length && outputIndex < OutputLength - 1; inputIndex++) {
        UCHAR character = (UCHAR)Buffer[inputIndex];

        if (character == 0) {
            continue;
        }

        if (character == '\r' || character == '\n' || character == '\t' ||
            (character >= 0x20 && character <= 0x7E)) {

            Output[outputIndex++] = (CHAR)character;
        }
    }

    Output[outputIndex] = '\0';
    return outputIndex;
}

static
BOOLEAN
DpWebShellLooksLikeOneLiner(
    _In_reads_bytes_(Length) const CHAR *Buffer,
    _In_ ULONG Length
    )
{
    CHAR asciiView[DP_WEBSHELL_MAX_SAMPLE_BYTES + 1];
    ULONG viewLength;

    if (Buffer == NULL || Length == 0 || Length > DP_WEBSHELL_MAX_SAMPLE_BYTES) {
        return FALSE;
    }

    viewLength = DpWebShellBuildAsciiView(Buffer,
                                          Length,
                                          asciiView,
                                          sizeof(asciiView));

    if (viewLength == 0) {
        return FALSE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "<?") &&
         (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "eval") ||
          DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "assert") ||
          DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "system") ||
          DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "shell_exec") ||
          DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "passthru"))) ||
        DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "$_post") ||
        DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "$_get") ||
        DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "$_request")) {

        return TRUE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "<%") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "request(") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "request.form") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "request.querystring")) &&
        (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "eval") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "execute") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "wscript.shell") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "server.createobject"))) {

        return TRUE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "runtime.getruntime") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "processbuilder") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "getparameter")) &&
        (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "exec") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "start"))) {

        return TRUE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "subprocess") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "os.system") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "popen")) &&
        (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "request") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "input"))) {

        return TRUE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "child_process") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "require(") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "eval(")) &&
        (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "exec") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "spawn") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "req."))) {

        return TRUE;
    }

    if ((DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "cmd.exe") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "/bin/sh") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "powershell")) &&
        (DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "eval") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "exec") ||
         DpWebShellAsciiContainsInsensitive(asciiView, viewLength, "system"))) {

        return TRUE;
    }

    return FALSE;
}

static
VOID
DpWebShellCopyPath(
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
DpWebShellQueueEvent(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING Extension,
    _In_ ULONG FileSize,
    _In_reads_bytes_opt_(SampleLength) const CHAR *Sample,
    _In_ ULONG SampleLength,
    _In_ DP_WEBSHELL_SEVERITY Severity,
    _In_ DP_WEBSHELL_OPERATION Operation
    )
{
    PDP_WEBSHELL_EVENT_ENTRY entry;
    KIRQL oldIrql;

    if (!gDpWebShellInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_WEBSHELL_EVENT_ENTRY),
                                  DP_TAG_WEBSHELL_EVENT);

    if (entry == NULL) {
        KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);
        gDpWebShellDroppedEvents++;
        KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_WEBSHELL_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.Severity = (ULONG)Severity;
    entry->Event.Operation = (ULONG)Operation;
    entry->Event.FileSize = FileSize;
    DpWebShellCopyPath(entry->Event.Path,
                       RTL_NUMBER_OF(entry->Event.Path),
                       Path,
                       &entry->Event.PathLengthBytes);
    DpWebShellCopyPath(entry->Event.Extension,
                       RTL_NUMBER_OF(entry->Event.Extension),
                       Extension,
                       &entry->Event.ExtensionLengthBytes);

    entry->Event.SampleLength = min(SampleLength, (ULONG)sizeof(entry->Event.Sample));
    if (Sample != NULL && entry->Event.SampleLength != 0) {
        RtlCopyMemory(entry->Event.Sample, Sample, entry->Event.SampleLength);
    }

    KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpWebShellEventSequence;
    InsertTailList(&gDpWebShellEvents, &entry->Link);
    gDpWebShellEventCount++;

    while (gDpWebShellEventCount > DP_WEBSHELL_MAX_EVENTS && !IsListEmpty(&gDpWebShellEvents)) {
        PLIST_ENTRY oldLink = RemoveHeadList(&gDpWebShellEvents);
        PDP_WEBSHELL_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink, DP_WEBSHELL_EVENT_ENTRY, Link);
        gDpWebShellEventCount--;
        gDpWebShellDroppedEvents++;
        KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);
        DpWebShellFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);
    }

    KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);
}

static
NTSTATUS
DpWebShellClassifyAndReport(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG FileSize,
    _In_reads_bytes_opt_(SampleLength) const CHAR *Sample,
    _In_ ULONG SampleLength,
    _In_ DP_WEBSHELL_OPERATION Operation
    )
{
    UNICODE_STRING extension;
    DP_WEBSHELL_SEVERITY severity;
    BOOLEAN oneLiner;

    if (!DpWebShellIsProtectedPath(Path) ||
        !DpWebShellIsScriptPath(Path, &extension)) {

        return STATUS_SUCCESS;
    }

    oneLiner = FileSize <= DP_WEBSHELL_MAX_SAMPLE_BYTES &&
               SampleLength != 0 &&
               DpWebShellLooksLikeOneLiner(Sample, min(SampleLength, (ULONG)DP_WEBSHELL_MAX_SAMPLE_BYTES));

    if (oneLiner) {
        severity = DpWebShellSeverityDanger;
    } else if (FileSize <= DP_WEBSHELL_MAX_SAMPLE_BYTES) {
        severity = DpWebShellSeverityWarning;
    } else {
        severity = DpWebShellSeverityNotify;
    }

    DpWebShellQueueEvent(ProcessId,
                         Path,
                         &extension,
                         FileSize,
                         Sample,
                         min(SampleLength, (ULONG)DP_WEBSHELL_MAX_SAMPLE_BYTES),
                         severity,
                         Operation);

    if (severity == DpWebShellSeverityDanger) {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

BOOLEAN
DpWebShellIsScriptPath(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ PUNICODE_STRING Extension
    )
{
    static const WCHAR *extensions[] = {
        L".asp", L".aspx", L".ashx", L".asmx", L".asa", L".cer", L".cdx",
        L".php", L".php3", L".php4", L".php5", L".phtml",
        L".jsp", L".jspx", L".jsw", L".jsv", L".jhtml",
        L".cfm", L".cfml", L".pl", L".cgi", L".py", L".rb",
        L".js", L".mjs", L".vbs", L".shtml"
    };
    ULONG extensionIndex;

    if (Extension != NULL) {
        RtlZeroMemory(Extension, sizeof(*Extension));
    }

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    for (extensionIndex = 0; extensionIndex < RTL_NUMBER_OF(extensions); extensionIndex++) {
        UNICODE_STRING suffix;
        UNICODE_STRING candidate;

        RtlInitUnicodeString(&candidate, extensions[extensionIndex]);
        if (Name->Length < candidate.Length) {
            continue;
        }

        suffix.Buffer = (PWCH)((PUCHAR)Name->Buffer + Name->Length - candidate.Length);
        suffix.Length = candidate.Length;
        suffix.MaximumLength = candidate.Length;

        if (RtlEqualUnicodeString(&suffix, &candidate, TRUE)) {
            if (Extension != NULL) {
                *Extension = suffix;
            }

            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
DpWebShellIsProtectedPath(
    _In_ PCUNICODE_STRING Name
    )
{
    PLIST_ENTRY link;
    BOOLEAN protectedPath = FALSE;

    if (!gDpWebShellInitialized ||
        Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length == 0) {

        return FALSE;
    }

    FltAcquirePushLockShared(&gDpWebShellRuleLock);

    for (link = gDpWebShellRules.Flink; link != &gDpWebShellRules; link = link->Flink) {
        PDP_WEBSHELL_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_WEBSHELL_RULE_ENTRY, Link);

        if (DpWebShellDirectoryMatches(&rule->Directory, Name)) {
            protectedPath = TRUE;
            break;
        }
    }

    FltReleasePushLock(&gDpWebShellRuleLock);

    return protectedPath;
}

NTSTATUS
DpWebShellInspectWriteByName(
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _In_ DP_WEBSHELL_OPERATION Operation
    )
{
    if (!gDpWebShellInitialized ||
        Name == NULL ||
        Name->Buffer == NULL ||
        Buffer == NULL ||
        Length == 0) {

        return STATUS_SUCCESS;
    }

    return DpWebShellClassifyAndReport(ProcessId,
                                       Name,
                                       Length,
                                       (const CHAR *)Buffer,
                                       min(Length, (ULONG)DP_WEBSHELL_MAX_SAMPLE_BYTES),
                                       Operation);
}

NTSTATUS
DpWebShellInspectWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN NewlyCreated
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG sampleLength;

    if (!gDpWebShellInitialized ||
        !NewlyCreated ||
        Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        Buffer == NULL ||
        Length == 0) {

        return STATUS_SUCCESS;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    sampleLength = min(Length, (ULONG)DP_WEBSHELL_MAX_SAMPLE_BYTES);
    status = DpWebShellClassifyAndReport(FltGetRequestorProcessIdEx(Data),
                                         &nameInfo->Name,
                                         Length,
                                         (const CHAR *)Buffer,
                                         sampleLength,
                                         DpWebShellOperationWrite);

    FltReleaseFileNameInformation(nameInfo);

    return status;
}

NTSTATUS
DpWebShellInspectFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PCUNICODE_STRING ReportName,
    _In_ HANDLE ProcessId,
    _In_ DP_WEBSHELL_OPERATION Operation
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION standardInfo;
    CHAR sample[DP_WEBSHELL_MAX_SAMPLE_BYTES];
    ULONG bytesRead = 0;
    LARGE_INTEGER byteOffset;
    ULONG fileSize;

    if (!gDpWebShellInitialized ||
        Instance == NULL ||
        FileObject == NULL ||
        ReportName == NULL ||
        ReportName->Buffer == NULL ||
        !DpWebShellIsProtectedPath(ReportName) ||
        !DpWebShellIsScriptPath(ReportName, NULL)) {

        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&standardInfo, sizeof(standardInfo));
    status = FltQueryInformationFile(Instance,
                                     FileObject,
                                     &standardInfo,
                                     sizeof(standardInfo),
                                     FileStandardInformation,
                                     NULL);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    fileSize = standardInfo.EndOfFile.QuadPart > MAXULONG ?
        MAXULONG :
        (ULONG)standardInfo.EndOfFile.QuadPart;

    RtlZeroMemory(sample, sizeof(sample));
    byteOffset.QuadPart = 0;
    if (fileSize != 0) {
        (VOID)FltReadFile(Instance,
                          FileObject,
                          &byteOffset,
                          min(fileSize, (ULONG)sizeof(sample)),
                          sample,
                          0,
                          &bytesRead,
                          NULL,
                          NULL);
    }

    return DpWebShellClassifyAndReport(ProcessId,
                                       ReportName,
                                       fileSize,
                                       sample,
                                       bytesRead,
                                       Operation);
}

NTSTATUS
DpWebShellInspectFileByName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _In_ HANDLE ProcessId,
    _In_ DP_WEBSHELL_OPERATION Operation
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    FILE_STANDARD_INFORMATION standardInfo;
    CHAR sample[DP_WEBSHELL_MAX_SAMPLE_BYTES];
    ULONG bytesRead = 0;
    LARGE_INTEGER byteOffset;
    ULONG fileSize;

    if (!gDpWebShellInitialized ||
        Instance == NULL ||
        Name == NULL ||
        Name->Buffer == NULL ||
        !DpWebShellIsProtectedPath(Name) ||
        !DpWebShellIsScriptPath(Name, NULL)) {

        return STATUS_SUCCESS;
    }

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = FltCreateFileEx2(gDataProtectorFilter,
                              Instance,
                              &fileHandle,
                              &fileObject,
                              FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                              &objectAttributes,
                              &ioStatus,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL,
                              0,
                              0,
                              NULL);

    if (!NT_SUCCESS(status)) {
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
        goto Exit;
    }

    fileSize = standardInfo.EndOfFile.QuadPart > MAXULONG ?
        MAXULONG :
        (ULONG)standardInfo.EndOfFile.QuadPart;

    RtlZeroMemory(sample, sizeof(sample));
    byteOffset.QuadPart = 0;
    if (fileSize != 0) {
        (VOID)FltReadFile(Instance,
                          fileObject,
                          &byteOffset,
                          min(fileSize, (ULONG)sizeof(sample)),
                          sample,
                          0,
                          &bytesRead,
                          NULL,
                          NULL);
    }

    status = DpWebShellClassifyAndReport(ProcessId,
                                         Name,
                                         fileSize,
                                         sample,
                                         bytesRead,
                                         Operation);

Exit:
    if (fileHandle != NULL) {
        FltClose(fileHandle);
    }

    return status;
}

NTSTATUS
DpWebShellInitialize(
    VOID
    )
{
    InitializeListHead(&gDpWebShellRules);
    InitializeListHead(&gDpWebShellEvents);
    FltInitializePushLock(&gDpWebShellRuleLock);
    KeInitializeSpinLock(&gDpWebShellEventLock);
    gDpWebShellRuleCount = 0;
    gDpWebShellEventCount = 0;
    gDpWebShellEventSequence = 0;
    gDpWebShellDroppedEvents = 0;
    gDpWebShellInitialized = TRUE;

    return STATUS_SUCCESS;
}

VOID
DpWebShellUninitialize(
    VOID
    )
{
    if (!gDpWebShellInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpWebShellRuleLock);
    DpWebShellClearRulesLocked();
    FltReleasePushLock(&gDpWebShellRuleLock);

    DpWebShellClearEvents();
    FltDeletePushLock(&gDpWebShellRuleLock);
    gDpWebShellInitialized = FALSE;
}

NTSTATUS
DpWebShellAddRule(
    _In_ const DP_WEBSHELL_RULE_MESSAGE *Rule
    )
{
    NTSTATUS status;
    UNICODE_STRING source;
    PDP_WEBSHELL_RULE_ENTRY entry;

    if (!gDpWebShellInitialized ||
        Rule == NULL ||
        Rule->Version != DP_WEBSHELL_RULE_MESSAGE_VERSION ||
        Rule->DirectoryLengthBytes == 0 ||
        Rule->DirectoryLengthBytes > DP_WEBSHELL_MAX_PATH_BYTES ||
        Rule->DirectoryLengthBytes > sizeof(Rule->Directory)) {

        return STATUS_INVALID_PARAMETER;
    }

    source.Buffer = (PWCH)Rule->Directory;
    source.Length = (USHORT)Rule->DirectoryLengthBytes;
    source.MaximumLength = source.Length;

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_WEBSHELL_RULE_ENTRY),
                                  DP_TAG_WEBSHELL_RULE);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(DP_WEBSHELL_RULE_ENTRY));
    status = DpWebShellDuplicateDirectory(&source, &entry->Directory);
    if (!NT_SUCCESS(status)) {
        DpWebShellFreeRule(entry);
        return status;
    }

    FltAcquirePushLockExclusive(&gDpWebShellRuleLock);

    if (gDpWebShellRuleCount >= DP_WEBSHELL_MAX_RULES) {
        status = STATUS_QUOTA_EXCEEDED;
    } else if (DpWebShellRuleExistsLocked(&entry->Directory)) {
        status = STATUS_OBJECT_NAME_COLLISION;
    } else {
        InsertTailList(&gDpWebShellRules, &entry->Link);
        gDpWebShellRuleCount++;
        entry = NULL;
        status = STATUS_SUCCESS;
    }

    FltReleasePushLock(&gDpWebShellRuleLock);

    DpWebShellFreeRule(entry);

    return status;
}

NTSTATUS
DpWebShellRemoveRule(
    _In_ const DP_WEBSHELL_RULE_MESSAGE *Rule
    )
{
    NTSTATUS status;
    UNICODE_STRING source;
    UNICODE_STRING normalized;
    PLIST_ENTRY link;
    PDP_WEBSHELL_RULE_ENTRY matchedRule = NULL;

    if (!gDpWebShellInitialized ||
        Rule == NULL ||
        Rule->Version != DP_WEBSHELL_RULE_MESSAGE_VERSION ||
        Rule->DirectoryLengthBytes == 0 ||
        Rule->DirectoryLengthBytes > DP_WEBSHELL_MAX_PATH_BYTES ||
        Rule->DirectoryLengthBytes > sizeof(Rule->Directory)) {

        return STATUS_INVALID_PARAMETER;
    }

    source.Buffer = (PWCH)Rule->Directory;
    source.Length = (USHORT)Rule->DirectoryLengthBytes;
    source.MaximumLength = source.Length;

    status = DpWebShellDuplicateDirectory(&source, &normalized);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    FltAcquirePushLockExclusive(&gDpWebShellRuleLock);

    for (link = gDpWebShellRules.Flink; link != &gDpWebShellRules; link = link->Flink) {
        PDP_WEBSHELL_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_WEBSHELL_RULE_ENTRY, Link);

        if (RtlEqualUnicodeString(&rule->Directory, &normalized, TRUE)) {
            matchedRule = rule;
            RemoveEntryList(&matchedRule->Link);
            gDpWebShellRuleCount--;
            break;
        }
    }

    FltReleasePushLock(&gDpWebShellRuleLock);

    DpWebShellFreeUnicodeString(&normalized);

    if (matchedRule == NULL) {
        return STATUS_NOT_FOUND;
    }

    DpWebShellFreeRule(matchedRule);
    return STATUS_SUCCESS;
}

VOID
DpWebShellClearRules(
    VOID
    )
{
    if (!gDpWebShellInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpWebShellRuleLock);
    DpWebShellClearRulesLocked();
    FltReleasePushLock(&gDpWebShellRuleLock);
}

NTSTATUS
DpWebShellQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PLIST_ENTRY link;
    PDP_WEBSHELL_RULE_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);
    ULONG ruleCount = 0;
    ULONG returnedRuleCount = 0;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_WEBSHELL_RULE_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_WEBSHELL_RULE_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_WEBSHELL_RULE_QUERY_HEADER));
    header->Version = DP_WEBSHELL_RULE_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);

    if (!gDpWebShellInitialized) {
        header->BytesRequired = sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_WEBSHELL_RULE_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    FltAcquirePushLockShared(&gDpWebShellRuleLock);

    for (link = gDpWebShellRules.Flink; link != &gDpWebShellRules; link = link->Flink) {
        PDP_WEBSHELL_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_WEBSHELL_RULE_ENTRY, Link);
        ULONG entryLength = DP_WEBSHELL_RULE_QUERY_ENTRY_HEADER_SIZE + rule->Directory.Length;

        ruleCount++;

        if (bytesRequired > MAXULONG - entryLength) {
            FltReleasePushLock(&gDpWebShellRuleLock);
            return STATUS_INTEGER_OVERFLOW;
        }

        bytesRequired += entryLength;

        if (bytesReturned <= OutputBufferLength &&
            entryLength <= OutputBufferLength - bytesReturned) {

            PDP_WEBSHELL_RULE_QUERY_ENTRY entry = (PDP_WEBSHELL_RULE_QUERY_ENTRY)cursor;

            entry->DirectoryLengthBytes = rule->Directory.Length;
            RtlCopyMemory(entry->Directory,
                          rule->Directory.Buffer,
                          rule->Directory.Length);

            cursor += entryLength;
            bytesReturned += entryLength;
            returnedRuleCount++;
        }
    }

    FltReleasePushLock(&gDpWebShellRuleLock);

    header->RuleCount = ruleCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedRuleCount != ruleCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpWebShellQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_WEBSHELL_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_WEBSHELL_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);

    if (!gDpWebShellInitialized) {
        header->Version = DP_WEBSHELL_EVENT_QUERY_VERSION;
        header->BytesRequired = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
        header->BytesReturned = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);

    header->Version = DP_WEBSHELL_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_WEBSHELL_EVENT_QUERY_HEADER);
    header->DroppedEvents = gDpWebShellDroppedEvents;

    for (link = gDpWebShellEvents.Flink; link != &gDpWebShellEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_WEBSHELL_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_WEBSHELL_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_WEBSHELL_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpWebShellEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpWebShellEvents);
            PDP_WEBSHELL_EVENT_ENTRY event = CONTAINING_RECORD(eventLink, DP_WEBSHELL_EVENT_ENTRY, Link);
            gDpWebShellEventCount--;
            KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);
            DpWebShellFreeEvent(event);
            KeAcquireSpinLock(&gDpWebShellEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpWebShellEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}
