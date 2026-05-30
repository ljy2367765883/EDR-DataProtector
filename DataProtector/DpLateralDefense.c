/*++

Module Name:

    DpLateralDefense.c

Abstract:

    Intranet lateral movement defense for IPC, SMB executable staging, and
    remote scheduled-task / service-creation tooling.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>

#if DP_ENABLE_LATERAL_DEFENSE_TRACE
#define DP_LATERAL_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[Lateral] " _format, __VA_ARGS__)
#else
#define DP_LATERAL_TRACE(_format, ...) ((void)0)
#endif

#if !DP_ENABLE_LATERAL_DEFENSE_TRACE
#define DP_LATERAL_TRACE_VALUE(_value) UNREFERENCED_PARAMETER(_value)
#else
#define DP_LATERAL_TRACE_VALUE(_value) ((void)0)
#endif

typedef struct _DP_LATERAL_DEFENSE_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY Event;
} DP_LATERAL_DEFENSE_EVENT_ENTRY, *PDP_LATERAL_DEFENSE_EVENT_ENTRY;

static LIST_ENTRY gDpLateralEvents;
static KSPIN_LOCK gDpLateralEventLock;
static volatile LONG gDpLateralPolicyFlags = DP_LATERAL_DEFENSE_DEFAULT_FLAGS;
static BOOLEAN gDpLateralInitialized = FALSE;
static ULONG gDpLateralEventCount = 0;
static ULONGLONG gDpLateralEventSequence = 0;
static ULONGLONG gDpLateralDroppedEvents = 0;

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static
ULONG
DpLateralReadPolicyFlags(
    VOID
    )
{
    return (ULONG)gDpLateralPolicyFlags;
}

static
BOOLEAN
DpLateralFeatureEnabled(
    _In_ ULONG FeatureFlag
    )
{
    ULONG flags = DpLateralReadPolicyFlags();

    return FlagOn(flags, DP_LATERAL_DEFENSE_FLAG_ENABLED) &&
           FlagOn(flags, FeatureFlag);
}

static
BOOLEAN
DpLateralAsciiEqualsInsensitive(
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
DpLateralIsSystemPid(
    _In_opt_ HANDLE ProcessId
    )
{
    return ProcessId == NULL ||
           ProcessId == (HANDLE)(ULONG_PTR)4;
}

static
WCHAR
DpLateralUpcase(
    _In_ WCHAR Character
    )
{
    return RtlUpcaseUnicodeChar(Character);
}

static
BOOLEAN
DpLateralUnicodeCharEqualsInsensitive(
    _In_ WCHAR Left,
    _In_ WCHAR Right
    )
{
    return DpLateralUpcase(Left) == DpLateralUpcase(Right);
}

static
BOOLEAN
DpLateralSuffix(
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
DpLateralContainsInsensitive(
    _In_opt_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Needle
    )
{
    USHORT nameChars;
    USHORT needleChars;
    USHORT nameIndex;
    UNICODE_STRING needleString;

    if (Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length == 0 ||
        Needle == NULL) {

        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    if (needleString.Length == 0 ||
        Name->Length < needleString.Length) {

        return FALSE;
    }

    nameChars = Name->Length / sizeof(WCHAR);
    needleChars = needleString.Length / sizeof(WCHAR);

    for (nameIndex = 0; nameIndex <= nameChars - needleChars; nameIndex++) {
        USHORT needleIndex;
        BOOLEAN matched = TRUE;

        for (needleIndex = 0; needleIndex < needleChars; needleIndex++) {
            if (!DpLateralUnicodeCharEqualsInsensitive(Name->Buffer[nameIndex + needleIndex],
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
BOOLEAN
DpLateralCommandSeparator(
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
           Character == L':' ||
           Character == L'=';
}

static
BOOLEAN
DpLateralCommandHasToken(
    _In_opt_ PCUNICODE_STRING CommandLine,
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
            !DpLateralCommandSeparator(CommandLine->Buffer[index - 1])) {

            continue;
        }

        for (tokenIndex = 0; tokenIndex < tokenChars; tokenIndex++) {
            if (!DpLateralUnicodeCharEqualsInsensitive(CommandLine->Buffer[index + tokenIndex],
                                                       tokenString.Buffer[tokenIndex])) {
                matched = FALSE;
                break;
            }
        }

        if (matched &&
            (index + tokenChars == commandChars ||
             DpLateralCommandSeparator(CommandLine->Buffer[index + tokenChars]))) {

            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpLateralCommandHasSwitchPrefix(
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_z_ PCWSTR SwitchPrefix
    )
{
    UNICODE_STRING switchString;
    USHORT commandChars;
    USHORT switchChars;
    USHORT index;

    if (CommandLine == NULL ||
        CommandLine->Buffer == NULL ||
        CommandLine->Length == 0 ||
        SwitchPrefix == NULL) {

        return FALSE;
    }

    RtlInitUnicodeString(&switchString, SwitchPrefix);
    if (switchString.Length == 0 ||
        CommandLine->Length < switchString.Length) {

        return FALSE;
    }

    commandChars = CommandLine->Length / sizeof(WCHAR);
    switchChars = switchString.Length / sizeof(WCHAR);

    for (index = 0; index <= commandChars - switchChars; index++) {
        USHORT switchIndex;
        BOOLEAN matched = TRUE;

        if (index != 0 &&
            !DpLateralCommandSeparator(CommandLine->Buffer[index - 1])) {

            continue;
        }

        for (switchIndex = 0; switchIndex < switchChars; switchIndex++) {
            if (!DpLateralUnicodeCharEqualsInsensitive(CommandLine->Buffer[index + switchIndex],
                                                       switchString.Buffer[switchIndex])) {
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
BOOLEAN
DpLateralCommandHasUnc(
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    return DpLateralContainsInsensitive(CommandLine, L"\\\\");
}

static
BOOLEAN
DpLateralIsKnownSmbServerProcess(
    VOID
    )
{
    const CHAR *imageName;

    if (DpLateralIsSystemPid(PsGetCurrentProcessId())) {
        return TRUE;
    }

    imageName = (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess());
    return DpLateralAsciiEqualsInsensitive(imageName, "system") ||
           DpLateralAsciiEqualsInsensitive(imageName, "svchost.exe");
}

static
BOOLEAN
DpLateralLooksRemoteFileOperation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return FALSE;
    }

    if (FlagOn(FltObjects->FileObject->Flags, FO_REMOTE_ORIGIN)) {
        return TRUE;
    }

    return Data != NULL &&
           Data->RequestorMode != KernelMode &&
           DpLateralIsKnownSmbServerProcess();
}

static
BOOLEAN
DpLateralLooksRemoteIpcOperation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess;

    if (Data == NULL) {
        return FALSE;
    }

    if (Data->Iopb == NULL ||
        Data->Iopb->Parameters.Create.SecurityContext == NULL) {

        return FALSE;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (FlagOn(desiredAccess, FILE_CREATE_PIPE_INSTANCE)) {
        return FALSE;
    }

    return DpLateralIsKnownSmbServerProcess();
}

static
BOOLEAN
DpLateralIsExecutableStagingPath(
    _In_ PCUNICODE_STRING Name
    )
{
    static const PCWSTR ExecutableSuffixes[] = {
        L".exe",
        L".dll",
        L".scr",
        L".com",
        L".bat",
        L".cmd",
        L".ps1",
        L".psm1",
        L".vbs",
        L".vbe",
        L".js",
        L".jse",
        L".hta",
        L".msi",
        L".msp",
        L".cpl",
        L".lnk"
    };
    ULONG index;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    for (index = 0; index < ARRAYSIZE(ExecutableSuffixes); index++) {
        if (DpLateralSuffix(Name, ExecutableSuffixes[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpLateralCreateRequestsWriteAccess(
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
               FILE_WRITE_DATA |
               FILE_APPEND_DATA |
               FILE_WRITE_EA |
               FILE_WRITE_ATTRIBUTES |
               FILE_DELETE_CHILD |
               DELETE |
               WRITE_DAC |
               WRITE_OWNER |
               GENERIC_WRITE |
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
VOID
DpLateralCopyAsciiProcessImage(
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
DpLateralCopyUnicodeTarget(
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
DpLateralFreeEvent(
    _In_opt_ PDP_LATERAL_DEFENSE_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_LATERAL_DEFENSE);
    }
}

static
VOID
DpLateralClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gDpLateralInitialized) {
        return;
    }

    KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);
    while (!IsListEmpty(&gDpLateralEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpLateralEvents);
        PDP_LATERAL_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                                  DP_LATERAL_DEFENSE_EVENT_ENTRY,
                                                                  Link);
        gDpLateralEventCount--;
        KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);
        DpLateralFreeEvent(event);
        KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);
}

static
VOID
DpLateralQueueEvent(
    _In_ DP_LATERAL_DEFENSE_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG Status,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCUNICODE_STRING Target,
    _In_opt_z_ const CHAR *ProcessImage,
    _In_ ULONG Flags
    )
{
    PDP_LATERAL_DEFENSE_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONGLONG sequence;
    ULONG eventCount;
    ULONGLONG droppedEvents;
    UNICODE_STRING targetText;
    UNICODE_STRING processText;

    if (!gDpLateralInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_LATERAL_DEFENSE_EVENT_ENTRY),
                                  DP_TAG_LATERAL_DEFENSE);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);
        gDpLateralDroppedEvents++;
        droppedEvents = gDpLateralDroppedEvents;
        KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);
        DP_LATERAL_TRACE("queue alloc failed pid=%p op=%lu dropped=%I64u\n",
                         ProcessId,
                         (ULONG)Operation,
                         droppedEvents);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_LATERAL_DEFENSE_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.Operation = (ULONG)Operation;
    entry->Event.Status = Status;
    entry->Event.DesiredAccess = DesiredAccess;
    entry->Event.Flags = Flags;
    DpLateralCopyUnicodeTarget(entry->Event.Target,
                               RTL_NUMBER_OF(entry->Event.Target),
                               Target,
                               &entry->Event.TargetLengthBytes);
    DpLateralCopyAsciiProcessImage(entry->Event.ProcessImage,
                                   RTL_NUMBER_OF(entry->Event.ProcessImage),
                                   ProcessImage,
                                   &entry->Event.ProcessImageLengthBytes);

    KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpLateralEventSequence;
    InsertTailList(&gDpLateralEvents, &entry->Link);
    gDpLateralEventCount++;

    while (gDpLateralEventCount > DP_LATERAL_DEFENSE_MAX_EVENTS &&
           !IsListEmpty(&gDpLateralEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gDpLateralEvents);
        PDP_LATERAL_DEFENSE_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink,
                                                                     DP_LATERAL_DEFENSE_EVENT_ENTRY,
                                                                     Link);
        gDpLateralEventCount--;
        gDpLateralDroppedEvents++;
        KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);
        DpLateralFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);
    }

    sequence = entry->Event.Sequence;
    eventCount = gDpLateralEventCount;
    droppedEvents = gDpLateralDroppedEvents;
    KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);

    targetText.Buffer = entry->Event.Target;
    targetText.Length = (USHORT)entry->Event.TargetLengthBytes;
    targetText.MaximumLength = (USHORT)sizeof(entry->Event.Target);
    processText.Buffer = entry->Event.ProcessImage;
    processText.Length = (USHORT)entry->Event.ProcessImageLengthBytes;
    processText.MaximumLength = (USHORT)sizeof(entry->Event.ProcessImage);

    DP_LATERAL_TRACE("queued seq=%I64u count=%lu dropped=%I64u pid=%p op=%lu status=0x%08X access=0x%08X target=%wZ image=%wZ\n",
                     sequence,
                     eventCount,
                     droppedEvents,
                     ProcessId,
                     (ULONG)Operation,
                     Status,
                     DesiredAccess,
                     &targetText,
                     &processText);
}

static
BOOLEAN
DpLateralGetCurrentFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION *NameInfo
    )
{
    NTSTATUS status;

    *NameInfo = NULL;

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       NameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           NameInfo);
    }

    if (!NT_SUCCESS(status) || *NameInfo == NULL) {
        *NameInfo = NULL;
        return FALSE;
    }

    status = FltParseFileNameInformation(*NameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(*NameInfo);
        *NameInfo = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
DpLateralDefenseIsNamedPipeOrMailslot(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    FLT_FILESYSTEM_TYPE fileSystemType;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return FALSE;
    }

    if (FlagOn(FltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT)) {
        return TRUE;
    }

    if (FltObjects->Volume == NULL) {
        return FALSE;
    }

    status = FltGetFileSystemType(FltObjects->Volume, &fileSystemType);
    return NT_SUCCESS(status) &&
           (fileSystemType == FLT_FSTYPE_NPFS ||
            fileSystemType == FLT_FSTYPE_MSFS);
}

static
BOOLEAN
DpLateralPipeNameIsTaskScheduler(
    _In_ PCUNICODE_STRING Name
    )
{
    return DpLateralSuffix(Name, L"\\atsvc") ||
           DpLateralSuffix(Name, L"\\schedsvc") ||
           DpLateralSuffix(Name, L"\\scheduler") ||
           DpLateralContainsInsensitive(Name, L"\\atsvc") ||
           DpLateralContainsInsensitive(Name, L"\\schedsvc");
}

static
BOOLEAN
DpLateralPipeNameIsServiceControl(
    _In_ PCUNICODE_STRING Name
    )
{
    return DpLateralSuffix(Name, L"\\svcctl") ||
           DpLateralContainsInsensitive(Name, L"\\svcctl");
}

BOOLEAN
DpLateralDefenseShouldBlockIpcCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ACCESS_MASK desiredAccess = 0;
    DP_LATERAL_DEFENSE_OPERATION operation;
    ULONG featureFlag;
    BOOLEAN shouldBlock = FALSE;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE ||
        !DpLateralDefenseIsNamedPipeOrMailslot(FltObjects) ||
        Data->Iopb->Parameters.Create.SecurityContext == NULL ||
        !DpLateralLooksRemoteIpcOperation(Data)) {

        return FALSE;
    }

    if (!DpLateralGetCurrentFileName(Data, &nameInfo)) {
        return FALSE;
    }

    if (DpLateralPipeNameIsTaskScheduler(&nameInfo->Name)) {
        operation = DpLateralDefenseOperationIpcTaskScheduler;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_TASKS;
    } else if (DpLateralPipeNameIsServiceControl(&nameInfo->Name)) {
        operation = DpLateralDefenseOperationIpcServiceControl;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_SERVICES;
    } else {
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    if (DpLateralFeatureEnabled(featureFlag)) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        DpLateralQueueEvent(operation,
                            PsGetCurrentProcessId(),
                            (ULONG)STATUS_ACCESS_DENIED,
                            desiredAccess,
                            &nameInfo->Name,
                            (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()),
                            0);
        (VOID)DpThreatEngineReportSignal(PsGetCurrentProcessId(),
                                         DpThreatSignalRemoteIpcControl,
                                         0,
                                         &nameInfo->Name);
        shouldBlock = TRUE;
        DP_LATERAL_TRACE("blocked ipc pipe create pid=%p access=0x%08X path=%wZ image=%s\n",
                         PsGetCurrentProcessId(),
                         desiredAccess,
                         &nameInfo->Name,
                         PsGetProcessImageFileName(PsGetCurrentProcess()));
    }

    FltReleaseFileNameInformation(nameInfo);
    return shouldBlock;
}

BOOLEAN
DpLateralDefenseShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ACCESS_MASK desiredAccess = 0;
    BOOLEAN shouldBlock = FALSE;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE ||
        !DpLateralFeatureEnabled(DP_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES) ||
        DpLateralDefenseIsNamedPipeOrMailslot(FltObjects) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
        !DpLateralLooksRemoteFileOperation(Data, FltObjects) ||
        !DpLateralCreateRequestsWriteAccess(Data)) {

        return FALSE;
    }

    if (!DpLateralGetCurrentFileName(Data, &nameInfo)) {
        return FALSE;
    }

    if (DpLateralIsExecutableStagingPath(&nameInfo->Name)) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        DpLateralQueueEvent(DpLateralDefenseOperationSmbExecutableCreate,
                            PsGetCurrentProcessId(),
                            (ULONG)STATUS_ACCESS_DENIED,
                            desiredAccess,
                            &nameInfo->Name,
                            (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()),
                            FltObjects->FileObject->Flags);
        (VOID)DpThreatEngineReportSignal(PsGetCurrentProcessId(),
                                         DpThreatSignalSmbExecutableStaging,
                                         0,
                                         &nameInfo->Name);
        shouldBlock = TRUE;
        DP_LATERAL_TRACE("blocked smb executable create pid=%p access=0x%08X path=%wZ flags=0x%08X image=%s\n",
                         PsGetCurrentProcessId(),
                         desiredAccess,
                         &nameInfo->Name,
                         FltObjects->FileObject->Flags,
                         PsGetProcessImageFileName(PsGetCurrentProcess()));
    }

    FltReleaseFileNameInformation(nameInfo);
    return shouldBlock;
}

BOOLEAN
DpLateralDefenseShouldBlockWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN shouldBlock = FALSE;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_WRITE ||
        !DpLateralFeatureEnabled(DP_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES) ||
        DpLateralDefenseIsNamedPipeOrMailslot(FltObjects) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
        Data->Iopb->Parameters.Write.Length == 0 ||
        !DpLateralLooksRemoteFileOperation(Data, FltObjects)) {

        return FALSE;
    }

    if (!DpLateralGetCurrentFileName(Data, &nameInfo)) {
        return FALSE;
    }

    if (DpLateralIsExecutableStagingPath(&nameInfo->Name)) {
        DpLateralQueueEvent(DpLateralDefenseOperationSmbExecutableWrite,
                            PsGetCurrentProcessId(),
                            (ULONG)STATUS_ACCESS_DENIED,
                            FILE_WRITE_DATA,
                            &nameInfo->Name,
                            (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()),
                            FltObjects->FileObject->Flags);
        (VOID)DpThreatEngineReportSignal(PsGetCurrentProcessId(),
                                         DpThreatSignalSmbExecutableStaging,
                                         0,
                                         &nameInfo->Name);
        shouldBlock = TRUE;
        DP_LATERAL_TRACE("blocked smb executable write pid=%p length=%lu path=%wZ flags=0x%08X image=%s\n",
                         PsGetCurrentProcessId(),
                         Data->Iopb->Parameters.Write.Length,
                         &nameInfo->Name,
                         FltObjects->FileObject->Flags,
                         PsGetProcessImageFileName(PsGetCurrentProcess()));
    }

    FltReleaseFileNameInformation(nameInfo);
    return shouldBlock;
}

BOOLEAN
DpLateralDefenseShouldBlockRename(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING TargetName
    )
{
    if (Data == NULL ||
        !DpLateralFeatureEnabled(DP_LATERAL_DEFENSE_FLAG_SMB_EXECUTABLES) ||
        DpLateralDefenseIsNamedPipeOrMailslot(FltObjects) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
        !DpLateralLooksRemoteFileOperation(Data, FltObjects) ||
        !DpLateralIsExecutableStagingPath(TargetName)) {

        return FALSE;
    }

    DpLateralQueueEvent(DpLateralDefenseOperationSmbExecutableRename,
                        PsGetCurrentProcessId(),
                        (ULONG)STATUS_ACCESS_DENIED,
                        DELETE,
                        TargetName,
                        (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()),
                        FltObjects->FileObject->Flags);

    (VOID)DpThreatEngineReportSignal(PsGetCurrentProcessId(),
                                     DpThreatSignalSmbExecutableStaging,
                                     0,
                                     TargetName);

    DP_LATERAL_TRACE("blocked smb executable rename pid=%p target=%wZ flags=0x%08X image=%s\n",
                     PsGetCurrentProcessId(),
                     TargetName,
                     FltObjects->FileObject->Flags,
                     PsGetProcessImageFileName(PsGetCurrentProcess()));

    return TRUE;
}

static
BOOLEAN
DpLateralIsImageSuffix(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_z_ PCWSTR FileName
    )
{
    UNICODE_STRING fileNameString;

    if (ImageFileName == NULL ||
        ImageFileName->Buffer == NULL ||
        ImageFileName->Length == 0 ||
        FileName == NULL) {

        return FALSE;
    }

    RtlInitUnicodeString(&fileNameString, FileName);
    if (RtlEqualUnicodeString(ImageFileName, &fileNameString, TRUE)) {
        return TRUE;
    }

    return DpLateralSuffix(ImageFileName, FileName);
}

static
BOOLEAN
DpLateralIsRemoteScheduledTaskCommand(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpLateralIsImageSuffix(ImageFileName, L"\\schtasks.exe")) {
        return FALSE;
    }

    return DpLateralCommandHasSwitchPrefix(CommandLine, L"/s") &&
           (DpLateralCommandHasSwitchPrefix(CommandLine, L"/create") ||
            DpLateralCommandHasSwitchPrefix(CommandLine, L"/change") ||
            DpLateralCommandHasSwitchPrefix(CommandLine, L"/run"));
}

static
BOOLEAN
DpLateralIsRemoteAtCommand(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpLateralIsImageSuffix(ImageFileName, L"\\at.exe")) {
        return FALSE;
    }

    return DpLateralCommandHasUnc(CommandLine);
}

static
BOOLEAN
DpLateralIsRemoteServiceCommand(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpLateralIsImageSuffix(ImageFileName, L"\\sc.exe")) {
        return FALSE;
    }

    return DpLateralCommandHasUnc(CommandLine) &&
           (DpLateralCommandHasToken(CommandLine, L"create") ||
            DpLateralCommandHasToken(CommandLine, L"config") ||
            DpLateralCommandHasToken(CommandLine, L"start"));
}

static
BOOLEAN
DpLateralIsRemoteWmiCommand(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpLateralIsImageSuffix(ImageFileName, L"\\wmic.exe")) {
        return FALSE;
    }

    return DpLateralCommandHasSwitchPrefix(CommandLine, L"/node") &&
           DpLateralCommandHasToken(CommandLine, L"process") &&
           DpLateralCommandHasToken(CommandLine, L"create");
}

static
BOOLEAN
DpLateralIsPowerShellLateralCommand(
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    if (!DpLateralIsImageSuffix(ImageFileName, L"\\powershell.exe") &&
        !DpLateralIsImageSuffix(ImageFileName, L"\\pwsh.exe")) {

        return FALSE;
    }

    return DpLateralCommandHasToken(CommandLine, L"Invoke-Command") ||
           DpLateralCommandHasToken(CommandLine, L"Enter-PSSession") ||
           DpLateralCommandHasToken(CommandLine, L"New-PSSession") ||
           DpLateralContainsInsensitive(CommandLine, L"-ComputerName") ||
           DpLateralContainsInsensitive(CommandLine, L"-ConnectionUri");
}

BOOLEAN
DpLateralDefenseShouldBlockProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    PCUNICODE_STRING imageFileName;
    PCUNICODE_STRING commandLine;
    const CHAR *processImage = NULL;
    DP_LATERAL_DEFENSE_OPERATION operation;
    ULONG featureFlag;
    DP_THREAT_SIGNAL threatSignal;

    if (!gDpLateralInitialized ||
        CreateInfo == NULL ||
        !DpLateralFeatureEnabled(DP_LATERAL_DEFENSE_FLAG_PROCESS_TOOLS)) {

        return FALSE;
    }

    imageFileName = CreateInfo->ImageFileName;
    commandLine = CreateInfo->CommandLine;

    if (DpLateralIsRemoteScheduledTaskCommand(imageFileName, commandLine) ||
        DpLateralIsRemoteAtCommand(imageFileName, commandLine)) {

        operation = DpLateralDefenseOperationRemoteScheduledTaskTool;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_TASKS;
        threatSignal = DpThreatSignalRemoteScheduledTask;
    } else if (DpLateralIsRemoteServiceCommand(imageFileName, commandLine)) {
        operation = DpLateralDefenseOperationRemoteServiceTool;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_SERVICES;
        threatSignal = DpThreatSignalRemoteServiceTool;
    } else if (DpLateralIsRemoteWmiCommand(imageFileName, commandLine)) {
        operation = DpLateralDefenseOperationWmiProcessCreate;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_SERVICES;
        threatSignal = DpThreatSignalRemoteWmiExecution;
    } else if (DpLateralIsPowerShellLateralCommand(imageFileName, commandLine)) {
        operation = DpLateralDefenseOperationPowerShellRemoteTask;
        featureFlag = DP_LATERAL_DEFENSE_FLAG_IPC_TASKS;
        threatSignal = DpThreatSignalRemotePowerShell;
    } else {
        return FALSE;
    }

    if (!DpLateralFeatureEnabled(featureFlag)) {
        return FALSE;
    }

    if (Process != NULL) {
        processImage = (const CHAR *)PsGetProcessImageFileName(Process);
    }

    DpLateralQueueEvent(operation,
                        ProcessId,
                        (ULONG)STATUS_ACCESS_DENIED,
                        0,
                        commandLine,
                        processImage,
                        0);

    (VOID)DpThreatEngineReportSignal(ProcessId,
                                     threatSignal,
                                     0,
                                     commandLine);

    DP_LATERAL_TRACE("blocked process create pid=%p op=%lu image=%wZ command=%wZ\n",
                     ProcessId,
                     (ULONG)operation,
                     imageFileName,
                     commandLine);

    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    return TRUE;
}

NTSTATUS
DpLateralDefenseInitialize(
    VOID
    )
{
    InitializeListHead(&gDpLateralEvents);
    KeInitializeSpinLock(&gDpLateralEventLock);
    InterlockedExchange((volatile LONG *)&gDpLateralPolicyFlags,
                        (LONG)DP_LATERAL_DEFENSE_DEFAULT_FLAGS);
    gDpLateralEventCount = 0;
    gDpLateralEventSequence = 0;
    gDpLateralDroppedEvents = 0;
    gDpLateralInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
DpLateralDefenseUninitialize(
    VOID
    )
{
    DpLateralClearEvents();
    gDpLateralInitialized = FALSE;
}

NTSTATUS
DpLateralDefenseSetPolicy(
    _In_ const DP_LATERAL_DEFENSE_POLICY *Policy
    )
{
    ULONG flags;

    if (Policy == NULL ||
        Policy->Version != DP_LATERAL_DEFENSE_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_LATERAL_DEFENSE_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_LATERAL_DEFENSE_ALLOWED_FLAGS;
    InterlockedExchange((volatile LONG *)&gDpLateralPolicyFlags, (LONG)flags);

    DP_LATERAL_TRACE("policy updated flags=0x%08X\n", flags);

    return STATUS_SUCCESS;
}

NTSTATUS
DpLateralDefenseQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_LATERAL_DEFENSE_POLICY policy;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = sizeof(DP_LATERAL_DEFENSE_POLICY);

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_LATERAL_DEFENSE_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    policy = (PDP_LATERAL_DEFENSE_POLICY)OutputBuffer;
    RtlZeroMemory(policy, sizeof(DP_LATERAL_DEFENSE_POLICY));
    policy->Version = DP_LATERAL_DEFENSE_POLICY_VERSION;
    policy->Flags = DpLateralReadPolicyFlags();

    return STATUS_SUCCESS;
}

NTSTATUS
DpLateralDefenseQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_LATERAL_DEFENSE_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_LATERAL_DEFENSE_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);

    header->Version = DP_LATERAL_DEFENSE_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);

    if (!gDpLateralInitialized) {
        header->BytesRequired = sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);

    header->DroppedEvents = gDpLateralDroppedEvents;

    for (link = gDpLateralEvents.Flink; link != &gDpLateralEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_LATERAL_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                                      DP_LATERAL_DEFENSE_EVENT_ENTRY,
                                                                      Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_LATERAL_DEFENSE_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpLateralEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpLateralEvents);
            PDP_LATERAL_DEFENSE_EVENT_ENTRY event = CONTAINING_RECORD(eventLink,
                                                                      DP_LATERAL_DEFENSE_EVENT_ENTRY,
                                                                      Link);
            ULONGLONG sequence = event->Event.Sequence;
            ULONG remainingEvents;

            DP_LATERAL_TRACE_VALUE(sequence);
            gDpLateralEventCount--;
            remainingEvents = gDpLateralEventCount;
            KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);
            DP_LATERAL_TRACE("query drain seq=%I64u remaining=%lu\n",
                             sequence,
                             remainingEvents);
            DpLateralFreeEvent(event);
            KeAcquireSpinLock(&gDpLateralEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpLateralEventLock, oldIrql);

    DP_LATERAL_TRACE("query events sizing=%lu events=%lu returned=%lu bytesRequired=%lu bytesReturned=%lu dropped=%I64u\n",
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
