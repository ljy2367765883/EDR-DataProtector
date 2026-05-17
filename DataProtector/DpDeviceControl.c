/*++

Module Name:

    DpDeviceControl.c

Abstract:

    Removable storage device access and write policy enforcement.

--*/

#include "DataProtector.h"

typedef struct _DP_DEVICE_RULE_ENTRY {
    LIST_ENTRY Link;
    BOOLEAN AllowInsert;
    BOOLEAN AllowWrite;
    UNICODE_STRING DeviceId;
    WCHAR DeviceIdBuffer[DP_DEVICE_MAX_ID_CHARS];
} DP_DEVICE_RULE_ENTRY, *PDP_DEVICE_RULE_ENTRY;

static LIST_ENTRY gDpDeviceRules;
static EX_PUSH_LOCK gDpDeviceRuleLock;
static BOOLEAN gDpDeviceRuleLockInitialized = FALSE;
static ULONG gDpDeviceRuleCount = 0;

static
VOID
DpDeviceNormalizeId(
    _Inout_ PUNICODE_STRING DeviceId
    )
{
    USHORT index;

    if (DeviceId == NULL || DeviceId->Buffer == NULL) {
        return;
    }

    while (DeviceId->Length >= sizeof(WCHAR) &&
           DeviceId->Buffer[(DeviceId->Length / sizeof(WCHAR)) - 1] == L'\\') {

        DeviceId->Length -= sizeof(WCHAR);
    }

    for (index = 0; index < DeviceId->Length / sizeof(WCHAR); index++) {
        DeviceId->Buffer[index] = RtlUpcaseUnicodeChar(DeviceId->Buffer[index]);
    }
}

static
BOOLEAN
DpDeviceIsWildcardId(
    _In_ PCUNICODE_STRING DeviceId
    )
{
    return DeviceId != NULL &&
           DeviceId->Length == sizeof(WCHAR) &&
           DeviceId->Buffer != NULL &&
           DeviceId->Buffer[0] == L'*';
}

static
BOOLEAN
DpDeviceRuleMatchesLocked(
    _In_ const DP_DEVICE_RULE_ENTRY *Rule,
    _In_ PCUNICODE_STRING DeviceId
    )
{
    if (Rule == NULL || DeviceId == NULL) {
        return FALSE;
    }

    if (DpDeviceIsWildcardId(&Rule->DeviceId)) {
        return TRUE;
    }

    return RtlEqualUnicodeString(&Rule->DeviceId, DeviceId, TRUE);
}

static
VOID
DpDeviceClearRulesLocked(
    VOID
    )
{
    while (!IsListEmpty(&gDpDeviceRules)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpDeviceRules);
        PDP_DEVICE_RULE_ENTRY entry = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
        ExFreePoolWithTag(entry, DP_TAG_DEVICE_RULE);
    }

    gDpDeviceRuleCount = 0;
}

static
NTSTATUS
DpDeviceBuildVolumeId(
    _In_ PFLT_VOLUME Volume,
    _Out_writes_(DP_DEVICE_MAX_ID_CHARS) PWCHAR Buffer,
    _Out_ PUNICODE_STRING DeviceId
    )
{
    NTSTATUS status;
    ULONG lengthNeeded = 0;

    RtlZeroMemory(Buffer, DP_DEVICE_MAX_ID_BYTES);
    RtlInitEmptyUnicodeString(DeviceId, Buffer, DP_DEVICE_MAX_ID_BYTES);

    status = FltGetVolumeGuidName(Volume, DeviceId, &lengthNeeded);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        DeviceId->Length = 0;
        status = FltGetVolumeGuidName(Volume, DeviceId, &lengthNeeded);
    }

    if (NT_SUCCESS(status) && DeviceId->Length != 0) {
        DpDeviceNormalizeId(DeviceId);
        return STATUS_SUCCESS;
    }

    DeviceId->Length = 0;
    lengthNeeded = 0;
    status = FltGetVolumeName(Volume, DeviceId, &lengthNeeded);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        DeviceId->Length = 0;
        status = FltGetVolumeName(Volume, DeviceId, &lengthNeeded);
    }

    if (!NT_SUCCESS(status) || DeviceId->Length == 0) {
        return status;
    }

    DpDeviceNormalizeId(DeviceId);
    return STATUS_SUCCESS;
}

static
BOOLEAN
DpDeviceIsRemovableVolume(
    _In_ PFLT_VOLUME Volume
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT diskDeviceObject = NULL;
    BOOLEAN removable = FALSE;

    status = FltGetDiskDeviceObject(Volume, &diskDeviceObject);
    if (!NT_SUCCESS(status) || diskDeviceObject == NULL) {
        return FALSE;
    }

    removable = BooleanFlagOn(diskDeviceObject->Characteristics, FILE_REMOVABLE_MEDIA);
    ObDereferenceObject(diskDeviceObject);

    return removable;
}

static
BOOLEAN
DpDeviceCreateRequestsWriteAccess(
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
BOOLEAN
DpDeviceSetInformationChangesMedia(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    switch (InformationClass) {
    case FileBasicInformation:
    case FileRenameInformation:
    case FileLinkInformation:
    case FileAllocationInformation:
    case FileEndOfFileInformation:
    case FileDispositionInformation:
    case FileValidDataLengthInformation:
    case FileShortNameInformation:
    case FileLinkInformationBypassAccessCheck:
    case FileDispositionInformationEx:
    case FileRenameInformationEx:
    case FileRenameInformationExBypassAccessCheck:
    case FileLinkInformationEx:
    case FileLinkInformationExBypassAccessCheck:
        return TRUE;

    default:
        return FALSE;
    }
}

static
BOOLEAN
DpDeviceLookupDecision(
    _In_ PCUNICODE_STRING DeviceId,
    _Out_ PBOOLEAN AllowInsert,
    _Out_ PBOOLEAN AllowWrite,
    _Out_opt_ PBOOLEAN MatchedWildcard
    )
{
    PLIST_ENTRY link;
    BOOLEAN found = FALSE;
    BOOLEAN wildcardFound = FALSE;
    BOOLEAN wildcardAllowInsert = TRUE;
    BOOLEAN wildcardAllowWrite = TRUE;

    *AllowInsert = TRUE;
    *AllowWrite = TRUE;
    if (MatchedWildcard != NULL) {
        *MatchedWildcard = FALSE;
    }

    FltAcquirePushLockShared(&gDpDeviceRuleLock);
    for (link = gDpDeviceRules.Flink; link != &gDpDeviceRules; link = link->Flink) {
        PDP_DEVICE_RULE_ENTRY entry = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
        if (DpDeviceIsWildcardId(&entry->DeviceId)) {
            wildcardAllowInsert = entry->AllowInsert;
            wildcardAllowWrite = entry->AllowWrite;
            wildcardFound = TRUE;
            continue;
        }

        if (DpDeviceRuleMatchesLocked(entry, DeviceId)) {
            *AllowInsert = entry->AllowInsert;
            *AllowWrite = entry->AllowWrite;
            found = TRUE;
            break;
        }
    }

    if (!found && wildcardFound) {
        *AllowInsert = wildcardAllowInsert;
        *AllowWrite = wildcardAllowWrite;
        if (MatchedWildcard != NULL) {
            *MatchedWildcard = TRUE;
        }
        found = TRUE;
    }

    FltReleasePushLock(&gDpDeviceRuleLock);

    return found;
}

static
BOOLEAN
DpDeviceShouldBlock(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN ForWrite
    )
{
    NTSTATUS status;
    PFLT_VOLUME volume = NULL;
    WCHAR deviceIdBuffer[DP_DEVICE_MAX_ID_CHARS];
    UNICODE_STRING deviceId;
    BOOLEAN allowInsert = TRUE;
    BOOLEAN allowWrite = TRUE;
    BOOLEAN found;
    BOOLEAN matchedWildcard = FALSE;
    BOOLEAN block = FALSE;

    if (Data == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->Instance == NULL) {

        return FALSE;
    }

    if (!ForWrite && Data->RequestorMode == KernelMode) {
        return FALSE;
    }

    status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
    if (!NT_SUCCESS(status) || volume == NULL) {
        return FALSE;
    }

    status = DpDeviceBuildVolumeId(volume, deviceIdBuffer, &deviceId);
    if (!NT_SUCCESS(status)) {
        FltObjectDereference(volume);
        return FALSE;
    }

    found = DpDeviceLookupDecision(&deviceId,
                                   &allowInsert,
                                   &allowWrite,
                                   &matchedWildcard);
    if (!found) {
        FltObjectDereference(volume);
        return FALSE;
    }

    if (matchedWildcard && !DpDeviceIsRemovableVolume(volume)) {
        FltObjectDereference(volume);
        return FALSE;
    }

    if (!allowInsert) {
        block = TRUE;
    } else if (ForWrite) {
        block = !allowWrite;
    } else if (!allowWrite && DpDeviceCreateRequestsWriteAccess(Data)) {
        block = TRUE;
    }

    FltObjectDereference(volume);

    return block;
}

NTSTATUS
DpDeviceControlInitialize(
    VOID
    )
{
    InitializeListHead(&gDpDeviceRules);
    FltInitializePushLock(&gDpDeviceRuleLock);
    gDpDeviceRuleLockInitialized = TRUE;
    gDpDeviceRuleCount = 0;
    return STATUS_SUCCESS;
}

VOID
DpDeviceControlUninitialize(
    VOID
    )
{
    if (!gDpDeviceRuleLockInitialized) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpDeviceRuleLock);
    DpDeviceClearRulesLocked();
    FltReleasePushLock(&gDpDeviceRuleLock);
    FltDeletePushLock(&gDpDeviceRuleLock);
    gDpDeviceRuleLockInitialized = FALSE;
}

NTSTATUS
DpDeviceControlAddRule(
    _In_ const DP_DEVICE_RULE_MESSAGE *Rule
    )
{
    PDP_DEVICE_RULE_ENTRY entry = NULL;
    PLIST_ENTRY link;
    NTSTATUS status = STATUS_SUCCESS;

    if (Rule == NULL ||
        Rule->Version != DP_DEVICE_RULE_MESSAGE_VERSION ||
        Rule->DeviceIdLengthBytes == 0 ||
        Rule->DeviceIdLengthBytes > DP_DEVICE_MAX_ID_BYTES ||
        Rule->DeviceIdLengthBytes % sizeof(WCHAR) != 0 ||
        Rule->DeviceIdLengthBytes / sizeof(WCHAR) >= DP_DEVICE_MAX_ID_CHARS) {

        return STATUS_INVALID_PARAMETER;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_DEVICE_RULE_ENTRY),
                                  DP_TAG_DEVICE_RULE);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    RtlCopyMemory(entry->DeviceIdBuffer,
                  Rule->DeviceId,
                  Rule->DeviceIdLengthBytes);
    RtlInitUnicodeString(&entry->DeviceId, entry->DeviceIdBuffer);
    entry->DeviceId.Length = (USHORT)Rule->DeviceIdLengthBytes;
    entry->DeviceId.MaximumLength = sizeof(entry->DeviceIdBuffer);
    DpDeviceNormalizeId(&entry->DeviceId);
    entry->AllowInsert = Rule->AllowInsert ? TRUE : FALSE;
    entry->AllowWrite = Rule->AllowWrite ? TRUE : FALSE;

    FltAcquirePushLockExclusive(&gDpDeviceRuleLock);

    if (gDpDeviceRuleCount >= DP_DEVICE_MAX_RULES) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        for (link = gDpDeviceRules.Flink; link != &gDpDeviceRules; link = link->Flink) {
            PDP_DEVICE_RULE_ENTRY existing = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
            if (RtlEqualUnicodeString(&existing->DeviceId, &entry->DeviceId, TRUE)) {
                existing->AllowInsert = entry->AllowInsert;
                existing->AllowWrite = entry->AllowWrite;
                status = STATUS_OBJECT_NAME_EXISTS;
                break;
            }
        }

        if (NT_SUCCESS(status)) {
            InsertTailList(&gDpDeviceRules, &entry->Link);
            gDpDeviceRuleCount++;
            entry = NULL;
        } else if (status == STATUS_OBJECT_NAME_EXISTS) {
            status = STATUS_SUCCESS;
        }
    }

    FltReleasePushLock(&gDpDeviceRuleLock);

    if (entry != NULL) {
        ExFreePoolWithTag(entry, DP_TAG_DEVICE_RULE);
    }

    return status;
}

NTSTATUS
DpDeviceControlRemoveRule(
    _In_ const DP_DEVICE_RULE_MESSAGE *Rule
    )
{
    UNICODE_STRING deviceId;
    WCHAR buffer[DP_DEVICE_MAX_ID_CHARS];
    PLIST_ENTRY link;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Rule == NULL ||
        Rule->Version != DP_DEVICE_RULE_MESSAGE_VERSION ||
        Rule->DeviceIdLengthBytes == 0 ||
        Rule->DeviceIdLengthBytes > DP_DEVICE_MAX_ID_BYTES ||
        Rule->DeviceIdLengthBytes % sizeof(WCHAR) != 0 ||
        Rule->DeviceIdLengthBytes / sizeof(WCHAR) >= DP_DEVICE_MAX_ID_CHARS) {

        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(buffer, sizeof(buffer));
    RtlCopyMemory(buffer, Rule->DeviceId, Rule->DeviceIdLengthBytes);
    RtlInitUnicodeString(&deviceId, buffer);
    deviceId.Length = (USHORT)Rule->DeviceIdLengthBytes;
    deviceId.MaximumLength = sizeof(buffer);
    DpDeviceNormalizeId(&deviceId);

    FltAcquirePushLockExclusive(&gDpDeviceRuleLock);
    for (link = gDpDeviceRules.Flink; link != &gDpDeviceRules; link = link->Flink) {
        PDP_DEVICE_RULE_ENTRY entry = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
        if (RtlEqualUnicodeString(&entry->DeviceId, &deviceId, TRUE)) {
            RemoveEntryList(&entry->Link);
            gDpDeviceRuleCount--;
            ExFreePoolWithTag(entry, DP_TAG_DEVICE_RULE);
            status = STATUS_SUCCESS;
            break;
        }
    }
    FltReleasePushLock(&gDpDeviceRuleLock);

    return status;
}

VOID
DpDeviceControlClearRules(
    VOID
    )
{
    FltAcquirePushLockExclusive(&gDpDeviceRuleLock);
    DpDeviceClearRulesLocked();
    FltReleasePushLock(&gDpDeviceRuleLock);
}

NTSTATUS
DpDeviceControlQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_DEVICE_RULE_QUERY_HEADER header = (PDP_DEVICE_RULE_QUERY_HEADER)OutputBuffer;
    PLIST_ENTRY link;
    ULONG bytesRequired = sizeof(DP_DEVICE_RULE_QUERY_HEADER);
    ULONG bytesWritten = sizeof(DP_DEVICE_RULE_QUERY_HEADER);
    ULONG count = 0;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    FltAcquirePushLockShared(&gDpDeviceRuleLock);
    for (link = gDpDeviceRules.Flink; link != &gDpDeviceRules; link = link->Flink) {
        PDP_DEVICE_RULE_ENTRY entry = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
        bytesRequired += DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE + entry->DeviceId.Length;
        count++;
    }

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_DEVICE_RULE_QUERY_HEADER)) {
        FltReleasePushLock(&gDpDeviceRuleLock);
        *ReturnOutputBufferLength = sizeof(DP_DEVICE_RULE_QUERY_HEADER);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    header->Version = DP_DEVICE_RULE_QUERY_VERSION;
    header->RuleCount = count;
    header->BytesRequired = bytesRequired;

    if (OutputBufferLength < bytesRequired) {
        header->BytesReturned = sizeof(DP_DEVICE_RULE_QUERY_HEADER);
        FltReleasePushLock(&gDpDeviceRuleLock);
        *ReturnOutputBufferLength = sizeof(DP_DEVICE_RULE_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    for (link = gDpDeviceRules.Flink; link != &gDpDeviceRules; link = link->Flink) {
        PDP_DEVICE_RULE_ENTRY entry = CONTAINING_RECORD(link, DP_DEVICE_RULE_ENTRY, Link);
        PDP_DEVICE_RULE_QUERY_ENTRY queryEntry = (PDP_DEVICE_RULE_QUERY_ENTRY)((PUCHAR)OutputBuffer + bytesWritten);

        queryEntry->AllowInsert = entry->AllowInsert ? 1 : 0;
        queryEntry->AllowWrite = entry->AllowWrite ? 1 : 0;
        queryEntry->DeviceIdLengthBytes = entry->DeviceId.Length;
        RtlCopyMemory(queryEntry->DeviceId,
                      entry->DeviceId.Buffer,
                      entry->DeviceId.Length);
        bytesWritten += DP_DEVICE_RULE_QUERY_ENTRY_HEADER_SIZE + entry->DeviceId.Length;
    }

    header->BytesReturned = bytesWritten;
    FltReleasePushLock(&gDpDeviceRuleLock);

    *ReturnOutputBufferLength = bytesWritten;
    return STATUS_SUCCESS;
}

BOOLEAN
DpDeviceControlShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    return DpDeviceShouldBlock(Data, FltObjects, FALSE);
}

BOOLEAN
DpDeviceControlShouldBlockWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    return DpDeviceShouldBlock(Data, FltObjects, TRUE);
}

BOOLEAN
DpDeviceControlShouldBlockSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    if (Data == NULL ||
        Data->Iopb == NULL ||
        !DpDeviceSetInformationChangesMedia(Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {

        return FALSE;
    }

    return DpDeviceShouldBlock(Data, FltObjects, TRUE);
}
