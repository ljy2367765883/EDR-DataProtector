#include "DataProtectorUsbCrypt.h"

typedef struct _DPUSB_SESSION_STATE {
    EX_PUSH_LOCK Lock;
    BOOLEAN LockInitialized;
    BOOLEAN SessionOpen;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    ULONG KeyLength;
    WCHAR PhysicalDrivePath[128];
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_SESSION_STATE, *PDPUSB_SESSION_STATE;

static PDEVICE_OBJECT gDpUsbDeviceObject = NULL;
static UNICODE_STRING gDpUsbDosName;
static DPUSB_SESSION_STATE gDpUsbSession;

typedef struct _DPUSB_SESSION_SNAPSHOT {
    BOOLEAN SessionOpen;
    ULONG Algorithm;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    ULONG KeyLength;
    WCHAR PhysicalDrivePath[128];
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
} DPUSB_SESSION_SNAPSHOT, *PDPUSB_SESSION_SNAPSHOT;

static
VOID
DpUsbComplete(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static
NTSTATUS
DpUsbNormalizePhysicalPath(
    _In_z_ PCWSTR Source,
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ ULONG PathChars
    )
{
    PCWSTR suffix;

    if (Source == NULL || Path == NULL || PathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    suffix = Source;
    if (wcsncmp(suffix, L"\\\\.\\", 4) == 0) {
        suffix += 4;
    } else if (wcsncmp(suffix, L"\\??\\", 4) == 0) {
        suffix += 4;
    }

    if (_wcsnicmp(suffix, L"PhysicalDrive", 13) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return RtlStringCchPrintfW(Path, PathChars, L"\\??\\%s", suffix);
}

static
NTSTATUS
DpUsbOpenSession(
    _In_ PDPUSB_OPEN_SESSION Request
    )
{
    WCHAR normalizedPath[128];
    NTSTATUS status;

    if (Request == NULL ||
        Request->Version != 1 ||
        Request->Algorithm != DPUSB_ALGORITHM_RC4 ||
        Request->KeyLength == 0 ||
        Request->KeyLength > DPUSB_MAX_KEY_BYTES ||
        Request->ToolAreaBytes != DPUSB_MIN_TOOL_BYTES ||
        Request->DataOffsetBytes < DPUSB_DATA_OFFSET_BYTES ||
        Request->PhysicalDrivePath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbNormalizePhysicalPath(Request->PhysicalDrivePath,
                                        normalizedPath,
                                        RTL_NUMBER_OF(normalizedPath));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquirePushLockExclusive(&gDpUsbSession.Lock);
    gDpUsbSession.SessionOpen = TRUE;
    gDpUsbSession.Algorithm = Request->Algorithm;
    gDpUsbSession.ToolAreaBytes = Request->ToolAreaBytes;
    gDpUsbSession.DataOffsetBytes = Request->DataOffsetBytes;
    gDpUsbSession.DataLengthBytes = Request->DataLengthBytes;
    gDpUsbSession.KeyLength = Request->KeyLength;
    RtlStringCchCopyW(gDpUsbSession.PhysicalDrivePath,
                      RTL_NUMBER_OF(gDpUsbSession.PhysicalDrivePath),
                      normalizedPath);
    RtlCopyMemory(gDpUsbSession.Key, Request->Key, Request->KeyLength);
    RtlStringCchCopyW(gDpUsbSession.DeviceId,
                      RTL_NUMBER_OF(gDpUsbSession.DeviceId),
                      Request->DeviceId);
    ExReleasePushLockExclusive(&gDpUsbSession.Lock);

    return STATUS_SUCCESS;
}

static
VOID
DpUsbCloseSession(
    VOID
    )
{
    ExAcquirePushLockExclusive(&gDpUsbSession.Lock);
    RtlSecureZeroMemory(gDpUsbSession.Key, sizeof(gDpUsbSession.Key));
    gDpUsbSession.SessionOpen = FALSE;
    gDpUsbSession.Algorithm = 0;
    gDpUsbSession.ToolAreaBytes = 0;
    gDpUsbSession.DataOffsetBytes = 0;
    gDpUsbSession.DataLengthBytes = 0;
    gDpUsbSession.KeyLength = 0;
    RtlZeroMemory(gDpUsbSession.PhysicalDrivePath, sizeof(gDpUsbSession.PhysicalDrivePath));
    RtlZeroMemory(gDpUsbSession.DeviceId, sizeof(gDpUsbSession.DeviceId));
    ExReleasePushLockExclusive(&gDpUsbSession.Lock);
}

static
NTSTATUS
DpUsbQueryStatus(
    _Out_ PDPUSB_STATUS Status,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    if (Status == NULL || OutputLength < sizeof(DPUSB_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(Status, sizeof(*Status));
    Status->Version = 1;

    ExAcquirePushLockShared(&gDpUsbSession.Lock);
    Status->SessionOpen = gDpUsbSession.SessionOpen;
    Status->Algorithm = gDpUsbSession.Algorithm;
    Status->ToolAreaBytes = gDpUsbSession.ToolAreaBytes;
    Status->DataOffsetBytes = gDpUsbSession.DataOffsetBytes;
    Status->DataLengthBytes = gDpUsbSession.DataLengthBytes;
    RtlStringCchCopyW(Status->PhysicalDrivePath,
                      RTL_NUMBER_OF(Status->PhysicalDrivePath),
                      gDpUsbSession.PhysicalDrivePath);
    RtlStringCchCopyW(Status->DeviceId,
                      RTL_NUMBER_OF(Status->DeviceId),
                      gDpUsbSession.DeviceId);
    ExReleasePushLockShared(&gDpUsbSession.Lock);

    *BytesReturned = sizeof(*Status);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryLengthValue(
    _Out_ PULONGLONG LengthBytes
    )
{
    if (LengthBytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockShared(&gDpUsbSession.Lock);
    *LengthBytes = gDpUsbSession.SessionOpen ? gDpUsbSession.DataLengthBytes : 0;
    ExReleasePushLockShared(&gDpUsbSession.Lock);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryDiskLength(
    _Out_ PGET_LENGTH_INFORMATION Length,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;

    if (Length == NULL || BytesReturned == NULL || OutputLength < sizeof(GET_LENGTH_INFORMATION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(Length, sizeof(*Length));
    DpUsbQueryLengthValue(&lengthBytes);
    Length->Length.QuadPart = (LONGLONG)lengthBytes;

    *BytesReturned = sizeof(*Length);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbBuildGeometry(
    _In_ ULONGLONG LengthBytes,
    _Out_ PDISK_GEOMETRY Geometry
    )
{
    ULONGLONG cylinders;

    if (Geometry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    cylinders = LengthBytes / (255ull * 63ull * 512ull);
    if (cylinders == 0) {
        cylinders = 1;
    }

    RtlZeroMemory(Geometry, sizeof(*Geometry));
    Geometry->Cylinders.QuadPart = (LONGLONG)cylinders;
    Geometry->MediaType = FixedMedia;
    Geometry->TracksPerCylinder = 255;
    Geometry->SectorsPerTrack = 63;
    Geometry->BytesPerSector = 512;

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryDriveGeometry(
    _Out_ PDISK_GEOMETRY Geometry,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;

    if (Geometry == NULL || BytesReturned == NULL || OutputLength < sizeof(DISK_GEOMETRY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    DpUsbBuildGeometry(lengthBytes, Geometry);

    *BytesReturned = sizeof(*Geometry);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbBuildPartitionInfo(
    _In_ ULONGLONG LengthBytes,
    _Out_ PPARTITION_INFORMATION_EX Partition
    )
{
    if (Partition == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Partition, sizeof(*Partition));
    Partition->PartitionStyle = PARTITION_STYLE_MBR;
    Partition->StartingOffset.QuadPart = 0;
    Partition->PartitionLength.QuadPart = (LONGLONG)LengthBytes;
    Partition->PartitionNumber = 1;
    Partition->RewritePartition = FALSE;
    Partition->Mbr.PartitionType = PARTITION_IFS;
    Partition->Mbr.BootIndicator = FALSE;
    Partition->Mbr.RecognizedPartition = TRUE;

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryPartitionInfo(
    _Out_ PPARTITION_INFORMATION_EX Partition,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;

    if (Partition == NULL || BytesReturned == NULL || OutputLength < sizeof(PARTITION_INFORMATION_EX)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    DpUsbBuildPartitionInfo(lengthBytes, Partition);

    *BytesReturned = sizeof(*Partition);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryMediaTypes(
    _Out_ PDISK_GEOMETRY Geometry,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    return DpUsbQueryDriveGeometry(Geometry, OutputLength, BytesReturned);
}

static
NTSTATUS
DpUsbQueryWritable(
    _Out_ PULONG BytesReturned
    )
{
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryDeviceNumber(
    _Out_ PSTORAGE_DEVICE_NUMBER DeviceNumber,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    if (DeviceNumber == NULL || BytesReturned == NULL || OutputLength < sizeof(STORAGE_DEVICE_NUMBER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(DeviceNumber, sizeof(*DeviceNumber));
    DeviceNumber->DeviceType = FILE_DEVICE_DISK;
    DeviceNumber->DeviceNumber = 0x44505543;
    DeviceNumber->PartitionNumber = 1;
    *BytesReturned = sizeof(*DeviceNumber);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryHotplugInfo(
    _Out_ PSTORAGE_HOTPLUG_INFO HotplugInfo,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    if (HotplugInfo == NULL || BytesReturned == NULL || OutputLength < sizeof(STORAGE_HOTPLUG_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(HotplugInfo, sizeof(*HotplugInfo));
    HotplugInfo->Size = sizeof(*HotplugInfo);
    HotplugInfo->MediaRemovable = TRUE;
    HotplugInfo->MediaHotplug = TRUE;
    HotplugInfo->DeviceHotplug = TRUE;
    HotplugInfo->WriteCacheEnableOverride = FALSE;
    *BytesReturned = sizeof(*HotplugInfo);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryDriveLayout(
    _Out_ PDRIVE_LAYOUT_INFORMATION_EX Layout,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;

    if (Layout == NULL ||
        BytesReturned == NULL ||
        OutputLength < (ULONG)FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) + sizeof(PARTITION_INFORMATION_EX)) {

        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    RtlZeroMemory(Layout, OutputLength);
    Layout->PartitionStyle = PARTITION_STYLE_MBR;
    Layout->PartitionCount = 1;
    Layout->Mbr.Signature = 0x44505543;
    DpUsbBuildPartitionInfo(lengthBytes, &Layout->PartitionEntry[0]);
    *BytesReturned = (ULONG)FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) + sizeof(PARTITION_INFORMATION_EX);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryStorageMediaTypes(
    _Out_ PGET_MEDIA_TYPES MediaTypes,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;
    DISK_GEOMETRY geometry;

    if (MediaTypes == NULL || BytesReturned == NULL || OutputLength < sizeof(GET_MEDIA_TYPES)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    DpUsbBuildGeometry(lengthBytes, &geometry);
    RtlZeroMemory(MediaTypes, OutputLength);
    MediaTypes->DeviceType = FILE_DEVICE_DISK;
    MediaTypes->MediaInfoCount = 1;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.Cylinders = geometry.Cylinders;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.MediaType = RemovableMedia;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.TracksPerCylinder = geometry.TracksPerCylinder;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.SectorsPerTrack = geometry.SectorsPerTrack;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.BytesPerSector = geometry.BytesPerSector;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.NumberMediaSides = 1;
    MediaTypes->MediaInfo[0].DeviceSpecific.DiskInfo.MediaCharacteristics = MEDIA_CURRENTLY_MOUNTED;
    *BytesReturned = sizeof(GET_MEDIA_TYPES);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryStorageProperty(
    _In_reads_bytes_(InputLength) const VOID *InputBuffer,
    _In_ ULONG InputLength,
    _Out_writes_bytes_(OutputLength) VOID *OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    const STORAGE_PROPERTY_QUERY *query;

    if (InputBuffer == NULL ||
        InputLength < sizeof(STORAGE_PROPERTY_QUERY) - sizeof(UCHAR) ||
        OutputBuffer == NULL ||
        BytesReturned == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    query = (const STORAGE_PROPERTY_QUERY *)InputBuffer;
    if (query->QueryType != PropertyStandardQuery &&
        query->QueryType != PropertyExistsQuery) {

        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (query->PropertyId == StorageDeviceProperty) {
        STORAGE_DEVICE_DESCRIPTOR *descriptor;

        if (OutputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        descriptor = (STORAGE_DEVICE_DESCRIPTOR *)OutputBuffer;
        RtlZeroMemory(OutputBuffer, OutputLength);
        descriptor->Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        descriptor->Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        descriptor->DeviceType = DIRECT_ACCESS_DEVICE;
        descriptor->RemovableMedia = TRUE;
        descriptor->CommandQueueing = FALSE;
        descriptor->BusType = BusTypeVirtual;
        descriptor->RawPropertiesLength = 0;
        *BytesReturned = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        return STATUS_SUCCESS;
    }

    if (query->PropertyId == StorageDeviceSeekPenaltyProperty) {
        DEVICE_SEEK_PENALTY_DESCRIPTOR *descriptor;

        if (OutputLength < sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        descriptor = (DEVICE_SEEK_PENALTY_DESCRIPTOR *)OutputBuffer;
        RtlZeroMemory(descriptor, sizeof(*descriptor));
        descriptor->Version = sizeof(*descriptor);
        descriptor->Size = sizeof(*descriptor);
        descriptor->IncursSeekPenalty = FALSE;
        *BytesReturned = sizeof(*descriptor);
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
DpUsbCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DpUsbComplete(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
DpUsbUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DpUsbComplete(Irp, STATUS_NOT_SUPPORTED, 0);
    return STATUS_NOT_SUPPORTED;
}

static
BOOLEAN
DpUsbAddUlonglong(
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right,
    _Out_ PULONGLONG Result
    )
{
    if (Result == NULL || Left > MAXULONGLONG - Right) {
        return FALSE;
    }

    *Result = Left + Right;
    return TRUE;
}

static
NTSTATUS
DpUsbCaptureSession(
    _Out_ PDPUSB_SESSION_SNAPSHOT Snapshot
    )
{
    if (Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    ExAcquirePushLockShared(&gDpUsbSession.Lock);
    if (!gDpUsbSession.SessionOpen ||
        gDpUsbSession.Algorithm != DPUSB_ALGORITHM_RC4 ||
        gDpUsbSession.KeyLength == 0 ||
        gDpUsbSession.KeyLength > DPUSB_MAX_KEY_BYTES ||
        gDpUsbSession.PhysicalDrivePath[0] == L'\0') {

        ExReleasePushLockShared(&gDpUsbSession.Lock);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    Snapshot->SessionOpen = gDpUsbSession.SessionOpen;
    Snapshot->Algorithm = gDpUsbSession.Algorithm;
    Snapshot->DataOffsetBytes = gDpUsbSession.DataOffsetBytes;
    Snapshot->DataLengthBytes = gDpUsbSession.DataLengthBytes;
    Snapshot->KeyLength = gDpUsbSession.KeyLength;
    RtlCopyMemory(Snapshot->Key, gDpUsbSession.Key, gDpUsbSession.KeyLength);
    RtlStringCchCopyW(Snapshot->PhysicalDrivePath,
                      RTL_NUMBER_OF(Snapshot->PhysicalDrivePath),
                      gDpUsbSession.PhysicalDrivePath);
    ExReleasePushLockShared(&gDpUsbSession.Lock);

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbOpenBackingDisk(
    _In_ const DPUSB_SESSION_SNAPSHOT *Snapshot,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DiskHandle
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    if (Snapshot == NULL || DiskHandle == NULL || Snapshot->PhysicalDrivePath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&path, Snapshot->PhysicalDrivePath);
    InitializeObjectAttributes(&objectAttributes,
                               &path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    return ZwCreateFile(DiskHandle,
                        DesiredAccess | SYNCHRONIZE,
                        &objectAttributes,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);
}

static
NTSTATUS
DpUsbValidateRange(
    _In_ const DPUSB_SESSION_SNAPSHOT *Snapshot,
    _In_ ULONGLONG LogicalOffset,
    _In_ ULONG Length,
    _Out_ PULONGLONG PhysicalOffset
    )
{
    ULONGLONG logicalEnd;

    if (Snapshot == NULL || PhysicalOffset == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!DpUsbAddUlonglong(LogicalOffset, Length, &logicalEnd)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    if (Snapshot->DataLengthBytes != 0 && logicalEnd > Snapshot->DataLengthBytes) {
        return STATUS_END_OF_FILE;
    }

    if (!DpUsbAddUlonglong(Snapshot->DataOffsetBytes, LogicalOffset, PhysicalOffset)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpUsbFlushBuffers(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DpUsbComplete(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
DpUsbReadWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    BOOLEAN isWrite;
    ULONG length;
    ULONGLONG logicalOffset;
    ULONGLONG physicalOffset;
    DPUSB_SESSION_SNAPSHOT snapshot;
    HANDLE diskHandle = NULL;
    PVOID systemAddress;
    UCHAR *ioBuffer = NULL;
    LARGE_INTEGER byteOffset;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    isWrite = stack->MajorFunction == IRP_MJ_WRITE;
    length = isWrite ? stack->Parameters.Write.Length : stack->Parameters.Read.Length;
    logicalOffset = (ULONGLONG)(isWrite ?
        stack->Parameters.Write.ByteOffset.QuadPart :
        stack->Parameters.Read.ByteOffset.QuadPart);

    if (length == 0) {
        DpUsbComplete(Irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    status = DpUsbCaptureSession(&snapshot);
    if (!NT_SUCCESS(status)) {
        DpUsbComplete(Irp, status, 0);
        return status;
    }

    status = DpUsbValidateRange(&snapshot,
                                logicalOffset,
                                length,
                                &physicalOffset);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
        DpUsbComplete(Irp, status, 0);
        return status;
    }

    systemAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    if (systemAddress == NULL) {
        RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ioBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, length, DPUSB_TAG_IO);
    if (ioBuffer == NULL) {
        RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (isWrite) {
        RtlCopyMemory(ioBuffer, systemAddress, length);
        DpUsbRc4CryptAtOffset(snapshot.Key,
                              snapshot.KeyLength,
                              logicalOffset,
                              ioBuffer,
                              length);
    } else {
        RtlZeroMemory(ioBuffer, length);
    }

    status = DpUsbOpenBackingDisk(&snapshot,
                                  isWrite ? GENERIC_WRITE : GENERIC_READ,
                                  &diskHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    byteOffset.QuadPart = (LONGLONG)physicalOffset;
    if (isWrite) {
        status = ZwWriteFile(diskHandle,
                             NULL,
                             NULL,
                             NULL,
                             &ioStatus,
                             ioBuffer,
                             length,
                             &byteOffset,
                             NULL);
    } else {
        status = ZwReadFile(diskHandle,
                            NULL,
                            NULL,
                            NULL,
                            &ioStatus,
                            ioBuffer,
                            length,
                            &byteOffset,
                            NULL);
        if (NT_SUCCESS(status) && ioStatus.Information != 0) {
            DpUsbRc4CryptAtOffset(snapshot.Key,
                                  snapshot.KeyLength,
                                  logicalOffset,
                                  ioBuffer,
                                  (ULONG)ioStatus.Information);
            RtlCopyMemory(systemAddress, ioBuffer, (SIZE_T)ioStatus.Information);
        }
    }

    if (NT_SUCCESS(status)) {
        information = ioStatus.Information;
    }

Exit:
    if (diskHandle != NULL) {
        ZwClose(diskHandle);
    }

    if (ioBuffer != NULL) {
        RtlSecureZeroMemory(ioBuffer, length);
        ExFreePoolWithTag(ioBuffer, DPUSB_TAG_IO);
    }

    RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
    DpUsbComplete(Irp, status, information);
    return status;
}

NTSTATUS
DpUsbDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    ULONG controlCode;
    ULONG inputLength;
    ULONG outputLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesReturned = 0;
    PVOID buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (controlCode) {
    case IOCTL_DPUSB_QUERY_STATUS:
        status = DpUsbQueryStatus((PDPUSB_STATUS)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_LENGTH_INFO:
        status = DpUsbQueryDiskLength((PGET_LENGTH_INFORMATION)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
        status = DpUsbQueryDriveGeometry((PDISK_GEOMETRY)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_PARTITION_INFO_EX:
        status = DpUsbQueryPartitionInfo((PPARTITION_INFORMATION_EX)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_MEDIA_TYPES:
        status = DpUsbQueryMediaTypes((PDISK_GEOMETRY)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
    case IOCTL_DISK_UPDATE_PROPERTIES:
    case IOCTL_DISK_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_DISK_VERIFY:
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_DISK_IS_WRITABLE:
        status = DpUsbQueryWritable(&bytesReturned);
        break;

    case IOCTL_STORAGE_GET_DEVICE_NUMBER:
        status = DpUsbQueryDeviceNumber((PSTORAGE_DEVICE_NUMBER)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_STORAGE_GET_HOTPLUG_INFO:
        status = DpUsbQueryHotplugInfo((PSTORAGE_HOTPLUG_INFO)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
        status = DpUsbQueryDriveLayout((PDRIVE_LAYOUT_INFORMATION_EX)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_STORAGE_GET_MEDIA_TYPES_EX:
        status = DpUsbQueryStorageMediaTypes((PGET_MEDIA_TYPES)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_STORAGE_QUERY_PROPERTY:
        status = DpUsbQueryStorageProperty(buffer,
                                           inputLength,
                                           buffer,
                                           outputLength,
                                           &bytesReturned);
        break;

    case IOCTL_DPUSB_OPEN_SESSION:
        if (inputLength < sizeof(DPUSB_OPEN_SESSION)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = DpUsbOpenSession((PDPUSB_OPEN_SESSION)buffer);
        break;

    case IOCTL_DPUSB_CLOSE_SESSION:
        DpUsbCloseSession();
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    DpUsbComplete(Irp, status, bytesReturned);
    return status;
}

VOID
DpUsbUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    DpUsbCloseSession();
    IoDeleteSymbolicLink(&gDpUsbDosName);

    if (gDpUsbDeviceObject != NULL) {
        IoDeleteDevice(gDpUsbDeviceObject);
        gDpUsbDeviceObject = NULL;
    }

    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    ULONG index;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&gDpUsbSession, sizeof(gDpUsbSession));
    ExInitializePushLock(&gDpUsbSession.Lock);
    gDpUsbSession.LockInitialized = TRUE;

    RtlInitUnicodeString(&deviceName, DPUSB_DEVICE_NAME);
    RtlInitUnicodeString(&gDpUsbDosName, DPUSB_DOS_DEVICE_NAME);

    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_DISK,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &gDpUsbDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&gDpUsbDosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDpUsbDeviceObject);
        gDpUsbDeviceObject = NULL;
        return status;
    }

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; index++) {
        DriverObject->MajorFunction[index] = DpUsbUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DpUsbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DpUsbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DpUsbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = DpUsbFlushBuffers;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DpUsbDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = DpUsbReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DpUsbReadWrite;
    DriverObject->DriverUnload = DpUsbUnload;

    gDpUsbDeviceObject->Flags |= DO_DIRECT_IO;
    gDpUsbDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
