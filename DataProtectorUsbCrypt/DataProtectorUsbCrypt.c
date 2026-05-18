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

#if DPUSB_TRACE_ENABLED
#define DPUSB_TRACE(_area, _format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtectorUsbCrypt77[" _area "] " _format, __VA_ARGS__)
#else
#define DPUSB_TRACE(_area, _format, ...) ((void)0)
#endif

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
PCSTR
DpUsbMajorName(
    _In_ UCHAR MajorFunction
    )
{
    switch (MajorFunction) {
    case IRP_MJ_CREATE:
        return "CREATE";
    case IRP_MJ_CLOSE:
        return "CLOSE";
    case IRP_MJ_CLEANUP:
        return "CLEANUP";
    case IRP_MJ_READ:
        return "READ";
    case IRP_MJ_WRITE:
        return "WRITE";
    case IRP_MJ_FLUSH_BUFFERS:
        return "FLUSH";
    case IRP_MJ_DEVICE_CONTROL:
        return "DEVICE_CONTROL";
    case IRP_MJ_QUERY_INFORMATION:
        return "QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION:
        return "SET_INFORMATION";
    case IRP_MJ_DIRECTORY_CONTROL:
        return "DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return "FILE_SYSTEM_CONTROL";
    case IRP_MJ_PNP:
        return "PNP";
    case IRP_MJ_POWER:
        return "POWER";
    default:
        return "OTHER";
    }
}

static
PCSTR
DpUsbIoctlName(
    _In_ ULONG ControlCode
    )
{
    switch (ControlCode) {
    case IOCTL_DPUSB_QUERY_STATUS:
        return "IOCTL_DPUSB_QUERY_STATUS";
    case IOCTL_DPUSB_OPEN_SESSION:
        return "IOCTL_DPUSB_OPEN_SESSION";
    case IOCTL_DPUSB_CLOSE_SESSION:
        return "IOCTL_DPUSB_CLOSE_SESSION";
    case IOCTL_DISK_GET_LENGTH_INFO:
        return "IOCTL_DISK_GET_LENGTH_INFO";
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
        return "IOCTL_DISK_GET_DRIVE_GEOMETRY";
    case IOCTL_DISK_GET_PARTITION_INFO_EX:
        return "IOCTL_DISK_GET_PARTITION_INFO_EX";
    case IOCTL_DISK_GET_MEDIA_TYPES:
        return "IOCTL_DISK_GET_MEDIA_TYPES";
    case IOCTL_DISK_CHECK_VERIFY:
        return "IOCTL_DISK_CHECK_VERIFY";
    case IOCTL_STORAGE_CHECK_VERIFY:
        return "IOCTL_STORAGE_CHECK_VERIFY";
    case IOCTL_STORAGE_CHECK_VERIFY2:
        return "IOCTL_STORAGE_CHECK_VERIFY2";
    case IOCTL_DISK_UPDATE_PROPERTIES:
        return "IOCTL_DISK_UPDATE_PROPERTIES";
    case IOCTL_DISK_MEDIA_REMOVAL:
        return "IOCTL_DISK_MEDIA_REMOVAL";
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        return "IOCTL_STORAGE_MEDIA_REMOVAL";
    case IOCTL_DISK_VERIFY:
        return "IOCTL_DISK_VERIFY";
    case IOCTL_DISK_IS_WRITABLE:
        return "IOCTL_DISK_IS_WRITABLE";
    case IOCTL_STORAGE_GET_DEVICE_NUMBER:
        return "IOCTL_STORAGE_GET_DEVICE_NUMBER";
    case IOCTL_STORAGE_GET_HOTPLUG_INFO:
        return "IOCTL_STORAGE_GET_HOTPLUG_INFO";
    case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
        return "IOCTL_DISK_GET_DRIVE_LAYOUT_EX";
    case IOCTL_STORAGE_GET_MEDIA_TYPES_EX:
        return "IOCTL_STORAGE_GET_MEDIA_TYPES_EX";
    case IOCTL_STORAGE_QUERY_PROPERTY:
        return "IOCTL_STORAGE_QUERY_PROPERTY";
    default:
        return "UNKNOWN_IOCTL";
    }
}

static
VOID
DpUsbComplete(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    PIO_STACK_LOCATION stack;

    stack = IoGetCurrentIrpStackLocation(Irp);
    DPUSB_TRACE("Complete",
                "irp=%p major=%s status=0x%08X information=%Iu pid=%p\n",
                Irp,
                DpUsbMajorName(stack->MajorFunction),
                Status,
                Information,
                PsGetCurrentProcessId());

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
        DPUSB_TRACE("Session",
                    "open invalid request=%p version=%lu algorithm=%lu keyLength=%lu tool=%I64u dataOffset=%I64u pathFirst=0x%04X\n",
                    Request,
                    Request != NULL ? Request->Version : 0,
                    Request != NULL ? Request->Algorithm : 0,
                    Request != NULL ? Request->KeyLength : 0,
                    Request != NULL ? Request->ToolAreaBytes : 0,
                    Request != NULL ? Request->DataOffsetBytes : 0,
                    Request != NULL ? Request->PhysicalDrivePath[0] : 0);
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbNormalizePhysicalPath(Request->PhysicalDrivePath,
                                        normalizedPath,
                                        RTL_NUMBER_OF(normalizedPath));
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("Session",
                    "normalize failed status=0x%08X path=%ws\n",
                    status,
                    Request->PhysicalDrivePath);
        return status;
    }

    DPUSB_TRACE("Session",
                "open begin deviceId=%ws physical=%ws normalized=%ws dataOffset=%I64u dataLength=%I64u keyLength=%lu\n",
                Request->DeviceId,
                Request->PhysicalDrivePath,
                normalizedPath,
                Request->DataOffsetBytes,
                Request->DataLengthBytes,
                Request->KeyLength);

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

    DPUSB_TRACE("Session", "open complete deviceId=%ws\n", Request->DeviceId);
    return STATUS_SUCCESS;
}

static
VOID
DpUsbCloseSession(
    VOID
    )
{
    DPUSB_TRACE("Session", "close begin\n");
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
    DPUSB_TRACE("Session", "close complete\n");
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

    DPUSB_TRACE("Query",
                "status session=%u dataOffset=%I64u dataLength=%I64u physical=%ws deviceId=%ws\n",
                Status->SessionOpen,
                Status->DataOffsetBytes,
                Status->DataLengthBytes,
                Status->PhysicalDrivePath,
                Status->DeviceId);

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

    DPUSB_TRACE("Query", "length bytes=%I64u\n", lengthBytes);
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

    DPUSB_TRACE("Query",
                "geometry length=%I64u cylinders=%I64d tracks=%lu sectors=%lu bytesPerSector=%lu\n",
                lengthBytes,
                Geometry->Cylinders.QuadPart,
                Geometry->TracksPerCylinder,
                Geometry->SectorsPerTrack,
                Geometry->BytesPerSector);
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

    DPUSB_TRACE("Query", "partition length=%I64u number=%lu\n", lengthBytes, Partition->PartitionNumber);
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
    DPUSB_TRACE("Query",
                "device number type=%lu number=0x%08X partition=%lu\n",
                DeviceNumber->DeviceType,
                DeviceNumber->DeviceNumber,
                DeviceNumber->PartitionNumber);
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
    DPUSB_TRACE("Query", "hotplug mediaRemovable=%u mediaHotplug=%u deviceHotplug=%u\n", TRUE, TRUE, TRUE);
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
    DPUSB_TRACE("Query", "layout partitions=%lu length=%I64u\n", Layout->PartitionCount, lengthBytes);
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
        DPUSB_TRACE("Query", "storage property device descriptor output=%lu\n", OutputLength);
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
        DPUSB_TRACE("Query", "storage property seek penalty output=%lu\n", OutputLength);
        *BytesReturned = sizeof(*descriptor);
        return STATUS_SUCCESS;
    }

    DPUSB_TRACE("Query",
                "storage property unsupported id=%lu type=%lu input=%lu output=%lu\n",
                query->PropertyId,
                query->QueryType,
                InputLength,
                OutputLength);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
DpUsbCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    DPUSB_TRACE("Dispatch",
                "enter irp=%p major=%s pid=%p file=%p\n",
                Irp,
                DpUsbMajorName(stack->MajorFunction),
                PsGetCurrentProcessId(),
                stack->FileObject);
    DpUsbComplete(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
DpUsbUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    DPUSB_TRACE("Unsupported",
                "irp=%p major=0x%02X(%s) minor=0x%02X pid=%p file=%p\n",
                Irp,
                stack->MajorFunction,
                DpUsbMajorName(stack->MajorFunction),
                stack->MinorFunction,
                PsGetCurrentProcessId(),
                stack->FileObject);
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

        DPUSB_TRACE("Session",
                    "capture failed open=%u algorithm=%lu keyLength=%lu pathFirst=0x%04X\n",
                    gDpUsbSession.SessionOpen,
                    gDpUsbSession.Algorithm,
                    gDpUsbSession.KeyLength,
                    gDpUsbSession.PhysicalDrivePath[0]);
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

    DPUSB_TRACE("Session",
                "capture ok physical=%ws dataOffset=%I64u dataLength=%I64u keyLength=%lu\n",
                Snapshot->PhysicalDrivePath,
                Snapshot->DataOffsetBytes,
                Snapshot->DataLengthBytes,
                Snapshot->KeyLength);
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

    DPUSB_TRACE("Backing",
                "open begin desired=0x%08X path=%ws\n",
                DesiredAccess,
                Snapshot->PhysicalDrivePath);

    {
        NTSTATUS status;
        status = ZwCreateFile(DiskHandle,
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
        DPUSB_TRACE("Backing",
                    "open end status=0x%08X information=%Iu handle=%p path=%ws\n",
                    status,
                    ioStatus.Information,
                    NT_SUCCESS(status) ? *DiskHandle : NULL,
                    Snapshot->PhysicalDrivePath);
        return status;
    }
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
        DPUSB_TRACE("Range", "overflow logical=%I64u length=%lu\n", LogicalOffset, Length);
        return STATUS_INTEGER_OVERFLOW;
    }

    if (Snapshot->DataLengthBytes != 0 && logicalEnd > Snapshot->DataLengthBytes) {
        DPUSB_TRACE("Range",
                    "eof logical=%I64u end=%I64u length=%lu dataLength=%I64u\n",
                    LogicalOffset,
                    logicalEnd,
                    Length,
                    Snapshot->DataLengthBytes);
        return STATUS_END_OF_FILE;
    }

    if (!DpUsbAddUlonglong(Snapshot->DataOffsetBytes, LogicalOffset, PhysicalOffset)) {
        DPUSB_TRACE("Range",
                    "physical overflow dataOffset=%I64u logical=%I64u\n",
                    Snapshot->DataOffsetBytes,
                    LogicalOffset);
        return STATUS_INTEGER_OVERFLOW;
    }

    DPUSB_TRACE("Range",
                "mapped logical=%I64u length=%lu physical=%I64u\n",
                LogicalOffset,
                Length,
                *PhysicalOffset);
    return STATUS_SUCCESS;
}

NTSTATUS
DpUsbFlushBuffers(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DPUSB_TRACE("Dispatch", "flush irp=%p pid=%p\n", Irp, PsGetCurrentProcessId());
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

    DPUSB_TRACE("ReadWrite",
                "enter irp=%p op=%s length=%lu logical=%I64u mdl=%p flags=0x%08X pid=%p\n",
                Irp,
                isWrite ? "WRITE" : "READ",
                length,
                logicalOffset,
                Irp->MdlAddress,
                Irp->Flags,
                PsGetCurrentProcessId());

    if (length == 0) {
        DPUSB_TRACE("ReadWrite", "zero length irp=%p op=%s\n", Irp, isWrite ? "WRITE" : "READ");
        DpUsbComplete(Irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    if (Irp->MdlAddress == NULL) {
        DPUSB_TRACE("ReadWrite",
                    "missing mdl irp=%p op=%s length=%lu flags=0x%08X systemBuffer=%p userBuffer=%p\n",
                    Irp,
                    isWrite ? "WRITE" : "READ",
                    length,
                    Irp->Flags,
                    Irp->AssociatedIrp.SystemBuffer,
                    Irp->UserBuffer);
        DpUsbComplete(Irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbCaptureSession(&snapshot);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("ReadWrite", "capture failed irp=%p status=0x%08X\n", Irp, status);
        DpUsbComplete(Irp, status, 0);
        return status;
    }

    status = DpUsbValidateRange(&snapshot,
                                logicalOffset,
                                length,
                                &physicalOffset);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("ReadWrite", "range failed irp=%p status=0x%08X\n", Irp, status);
        RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
        DpUsbComplete(Irp, status, 0);
        return status;
    }

    systemAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    if (systemAddress == NULL) {
        DPUSB_TRACE("ReadWrite", "mdl mapping failed irp=%p mdl=%p\n", Irp, Irp->MdlAddress);
        RtlSecureZeroMemory(&snapshot, sizeof(snapshot));
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ioBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, length, DPUSB_TAG_IO);
    if (ioBuffer == NULL) {
        DPUSB_TRACE("ReadWrite", "alloc failed irp=%p length=%lu\n", Irp, length);
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
        DPUSB_TRACE("ReadWrite", "backing open failed irp=%p status=0x%08X\n", Irp, status);
        goto Exit;
    }

    byteOffset.QuadPart = (LONGLONG)physicalOffset;
    if (isWrite) {
        DPUSB_TRACE("ReadWrite",
                    "ZwWrite begin irp=%p handle=%p physical=%I64u length=%lu\n",
                    Irp,
                    diskHandle,
                    physicalOffset,
                    length);
        status = ZwWriteFile(diskHandle,
                             NULL,
                             NULL,
                             NULL,
                             &ioStatus,
                             ioBuffer,
                             length,
                             &byteOffset,
                             NULL);
        DPUSB_TRACE("ReadWrite",
                    "ZwWrite end irp=%p status=0x%08X information=%Iu\n",
                    Irp,
                    status,
                    ioStatus.Information);
    } else {
        DPUSB_TRACE("ReadWrite",
                    "ZwRead begin irp=%p handle=%p physical=%I64u length=%lu\n",
                    Irp,
                    diskHandle,
                    physicalOffset,
                    length);
        status = ZwReadFile(diskHandle,
                            NULL,
                            NULL,
                            NULL,
                            &ioStatus,
                            ioBuffer,
                            length,
                            &byteOffset,
                            NULL);
        DPUSB_TRACE("ReadWrite",
                    "ZwRead end irp=%p status=0x%08X information=%Iu\n",
                    Irp,
                    status,
                    ioStatus.Information);
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
    DPUSB_TRACE("ReadWrite",
                "leave irp=%p op=%s status=0x%08X information=%Iu\n",
                Irp,
                isWrite ? "WRITE" : "READ",
                status,
                information);
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

    DPUSB_TRACE("Ioctl",
                "enter irp=%p code=0x%08X(%s) input=%lu output=%lu buffer=%p pid=%p file=%p\n",
                Irp,
                controlCode,
                DpUsbIoctlName(controlCode),
                inputLength,
                outputLength,
                buffer,
                PsGetCurrentProcessId(),
                stack->FileObject);

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
        DPUSB_TRACE("Ioctl",
                    "unsupported irp=%p code=0x%08X input=%lu output=%lu\n",
                    Irp,
                    controlCode,
                    inputLength,
                    outputLength);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    DPUSB_TRACE("Ioctl",
                "leave irp=%p code=0x%08X(%s) status=0x%08X bytes=%lu\n",
                Irp,
                controlCode,
                DpUsbIoctlName(controlCode),
                status,
                bytesReturned);
    DpUsbComplete(Irp, status, bytesReturned);
    return status;
}

VOID
DpUsbUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    DPUSB_TRACE("Driver", "unload begin driver=%p device=%p\n", DriverObject, gDpUsbDeviceObject);
    DpUsbCloseSession();
    IoDeleteSymbolicLink(&gDpUsbDosName);

    if (gDpUsbDeviceObject != NULL) {
        IoDeleteDevice(gDpUsbDeviceObject);
        gDpUsbDeviceObject = NULL;
    }

    UNREFERENCED_PARAMETER(DriverObject);
    DPUSB_TRACE("Driver", "unload complete\n");
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

    DPUSB_TRACE("Driver", "entry begin driver=%p registry=%wZ\n", DriverObject, RegistryPath);
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
        DPUSB_TRACE("Driver", "IoCreateDevice failed status=0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&gDpUsbDosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("Driver", "IoCreateSymbolicLink failed status=0x%08X\n", status);
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
    DPUSB_TRACE("Driver",
                "entry complete device=%p flags=0x%08X trace=%u\n",
                gDpUsbDeviceObject,
                gDpUsbDeviceObject->Flags,
                DPUSB_TRACE_ENABLED);
    return STATUS_SUCCESS;
}
