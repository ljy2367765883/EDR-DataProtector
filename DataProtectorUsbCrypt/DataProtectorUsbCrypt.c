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
    HANDLE BackingHandle;
    PFILE_OBJECT BackingFileObject;
    PDEVICE_OBJECT BackingDeviceObject;
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_SESSION_STATE, *PDPUSB_SESSION_STATE;

static PDEVICE_OBJECT gDpUsbDeviceObject = NULL;
static PDEVICE_OBJECT gDpUsbVolumeDeviceObject = NULL;
static UNICODE_STRING gDpUsbDosName;
static DPUSB_SESSION_STATE gDpUsbSession;
static volatile LONG gDpUsbUnloading = 0;
static volatile LONG gDpUsbActiveWorkers = 0;
static KEVENT gDpUsbNoActiveWorkers;

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
    PFILE_OBJECT BackingFileObject;
    PDEVICE_OBJECT BackingDeviceObject;
    ULONG BackingAlignment;
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
} DPUSB_SESSION_SNAPSHOT, *PDPUSB_SESSION_SNAPSHOT;

typedef struct _DPUSB_IO_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    PIRP Irp;
    BOOLEAN IsWrite;
} DPUSB_IO_WORK_ITEM, *PDPUSB_IO_WORK_ITEM;

static
ULONG
DpUsbGetDeviceAlignment(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    ULONG alignment = DPUSB_SECTOR_BYTES;

    if (DeviceObject != NULL && DeviceObject->AlignmentRequirement != 0) {
        ULONG deviceAlignment = DeviceObject->AlignmentRequirement + 1;
        if (deviceAlignment > alignment) {
            alignment = deviceAlignment;
        }
    }

    if ((alignment & (alignment - 1)) != 0) {
        ULONG rounded = DPUSB_SECTOR_BYTES;
        while (rounded < alignment && rounded < (64 * 1024)) {
            rounded <<= 1;
        }
        alignment = rounded;
    }

    return alignment;
}

static
PVOID
DpUsbAlignPointer(
    _In_ PVOID Buffer,
    _In_ ULONG Alignment
    )
{
    ULONG_PTR mask = (ULONG_PTR)Alignment - 1;
    return (PVOID)(((ULONG_PTR)Buffer + mask) & ~mask);
}

static
BOOLEAN
DpUsbIsVolumeDevice(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    return DeviceObject != NULL && DeviceObject == gDpUsbVolumeDeviceObject;
}

static
BOOLEAN
DpUsbIsControlDevice(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    return DeviceObject != NULL && DeviceObject == gDpUsbDeviceObject;
}

static
VOID
DpUsbReadWriteWorker(
    _In_ PVOID Context
    );

static
NTSTATUS
DpUsbWriteAlignedBuffer(
    _In_ ULONGLONG LogicalOffset,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    );

static
VOID
DpUsbFinishReadWriteWorker(
    _In_ PDPUSB_IO_WORK_ITEM WorkItem
    )
{
    ExFreePoolWithTag(WorkItem, DPUSB_TAG_WORK);
    if (InterlockedDecrement(&gDpUsbActiveWorkers) == 0) {
        KeSetEvent(&gDpUsbNoActiveWorkers, IO_NO_INCREMENT, FALSE);
    }
}

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
    case IOCTL_DPUSB_MOUNT_DRIVE:
        return "IOCTL_DPUSB_MOUNT_DRIVE";
    case IOCTL_DPUSB_UNMOUNT_DRIVE:
        return "IOCTL_DPUSB_UNMOUNT_DRIVE";
    case IOCTL_DPUSB_RAW_WRITE_ALIGNED:
        return "IOCTL_DPUSB_RAW_WRITE_ALIGNED";
    case IOCTL_DISK_GET_LENGTH_INFO:
        return "IOCTL_DISK_GET_LENGTH_INFO";
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
        return "IOCTL_DISK_GET_DRIVE_GEOMETRY";
    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
        return "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX";
    case IOCTL_DISK_GET_PARTITION_INFO:
        return "IOCTL_DISK_GET_PARTITION_INFO";
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
    case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
        return "IOCTL_MOUNTDEV_QUERY_UNIQUE_ID";
    case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
        return "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME";
    case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
        return "IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME";
    case IOCTL_MOUNTDEV_LINK_CREATED:
        return "IOCTL_MOUNTDEV_LINK_CREATED";
    case IOCTL_MOUNTDEV_LINK_DELETED:
        return "IOCTL_MOUNTDEV_LINK_DELETED";
    case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
        return "IOCTL_MOUNTDEV_QUERY_STABLE_GUID";
    case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
        return "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS";
    case IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE:
        return "IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE";
    case IOCTL_VOLUME_IS_OFFLINE:
        return "IOCTL_VOLUME_IS_OFFLINE";
    case IOCTL_VOLUME_IS_IO_CAPABLE:
        return "IOCTL_VOLUME_IS_IO_CAPABLE";
    case IOCTL_VOLUME_QUERY_VOLUME_NUMBER:
        return "IOCTL_VOLUME_QUERY_VOLUME_NUMBER";
    case IOCTL_VOLUME_IS_PARTITION:
        return "IOCTL_VOLUME_IS_PARTITION";
    case IOCTL_VOLUME_IS_DYNAMIC:
        return "IOCTL_VOLUME_IS_DYNAMIC";
    case IOCTL_VOLUME_UPDATE_PROPERTIES:
        return "IOCTL_VOLUME_UPDATE_PROPERTIES";
    case IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER:
        return "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER";
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
DpUsbOpenBackingDiskByPath(
    _In_z_ PCWSTR PhysicalDrivePath,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DiskHandle,
    _Outptr_ PFILE_OBJECT *FileObject,
    _Outptr_ PDEVICE_OBJECT *DeviceObject
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE handle = NULL;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    if (PhysicalDrivePath == NULL ||
        PhysicalDrivePath[0] == L'\0' ||
        DiskHandle == NULL ||
        FileObject == NULL ||
        DeviceObject == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    *DiskHandle = NULL;
    *FileObject = NULL;
    *DeviceObject = NULL;

    RtlInitUnicodeString(&path, PhysicalDrivePath);
    InitializeObjectAttributes(&objectAttributes,
                               &path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    DPUSB_TRACE("Backing",
                "session open begin desired=0x%08X path=%ws\n",
                DesiredAccess,
                PhysicalDrivePath);

    status = ZwCreateFile(&handle,
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
                "session open file status=0x%08X information=%Iu handle=%p path=%ws\n",
                status,
                ioStatus.Information,
                NT_SUCCESS(status) ? handle : NULL,
                PhysicalDrivePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(handle,
                                       DesiredAccess,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&fileObject,
                                       NULL);
    DPUSB_TRACE("Backing",
                "session reference status=0x%08X fileObject=%p\n",
                status,
                fileObject);
    if (!NT_SUCCESS(status)) {
        ZwClose(handle);
        return status;
    }

    deviceObject = IoGetRelatedDeviceObject(fileObject);
    if (deviceObject == NULL) {
        ObDereferenceObject(fileObject);
        ZwClose(handle);
        return STATUS_INVALID_DEVICE_STATE;
    }
    ObReferenceObject(deviceObject);

    *DiskHandle = handle;
    *FileObject = fileObject;
    *DeviceObject = deviceObject;
    DPUSB_TRACE("Backing",
                "session open complete handle=%p fileObject=%p deviceObject=%p flags=0x%08X alignment=%lu\n",
                handle,
                fileObject,
                deviceObject,
                deviceObject->Flags,
                DpUsbGetDeviceAlignment(deviceObject));
    return STATUS_SUCCESS;
}

static
VOID
DpUsbReleaseBackingLocked(
    VOID
    )
{
    HANDLE backingHandle;
    PFILE_OBJECT backingFileObject;
    PDEVICE_OBJECT backingDeviceObject;

    backingHandle = gDpUsbSession.BackingHandle;
    backingFileObject = gDpUsbSession.BackingFileObject;
    backingDeviceObject = gDpUsbSession.BackingDeviceObject;
    gDpUsbSession.BackingHandle = NULL;
    gDpUsbSession.BackingFileObject = NULL;
    gDpUsbSession.BackingDeviceObject = NULL;

    if (backingFileObject != NULL) {
        ObDereferenceObject(backingFileObject);
    }

    if (backingDeviceObject != NULL) {
        ObDereferenceObject(backingDeviceObject);
    }

    if (backingHandle != NULL) {
        ZwClose(backingHandle);
    }
}

static
NTSTATUS
DpUsbOpenSession(
    _In_ PDPUSB_OPEN_SESSION Request
    )
{
    WCHAR normalizedPath[128];
    HANDLE backingHandle = NULL;
    PFILE_OBJECT backingFileObject = NULL;
    PDEVICE_OBJECT backingDeviceObject = NULL;
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

    status = DpUsbOpenBackingDiskByPath(normalizedPath,
                                        GENERIC_READ | GENERIC_WRITE,
                                        &backingHandle,
                                        &backingFileObject,
                                        &backingDeviceObject);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("Session",
                    "backing open failed status=0x%08X path=%ws\n",
                    status,
                    normalizedPath);
        return status;
    }

    ExAcquirePushLockExclusive(&gDpUsbSession.Lock);
    DpUsbReleaseBackingLocked();
    gDpUsbSession.SessionOpen = TRUE;
    gDpUsbSession.Algorithm = Request->Algorithm;
    gDpUsbSession.ToolAreaBytes = Request->ToolAreaBytes;
    gDpUsbSession.DataOffsetBytes = Request->DataOffsetBytes;
    gDpUsbSession.DataLengthBytes = Request->DataLengthBytes;
    gDpUsbSession.KeyLength = Request->KeyLength;
    RtlStringCchCopyW(gDpUsbSession.PhysicalDrivePath,
                      RTL_NUMBER_OF(gDpUsbSession.PhysicalDrivePath),
                      normalizedPath);
    gDpUsbSession.BackingHandle = backingHandle;
    gDpUsbSession.BackingFileObject = backingFileObject;
    gDpUsbSession.BackingDeviceObject = backingDeviceObject;
    RtlCopyMemory(gDpUsbSession.Key, Request->Key, Request->KeyLength);
    RtlStringCchCopyW(gDpUsbSession.DeviceId,
                      RTL_NUMBER_OF(gDpUsbSession.DeviceId),
                      Request->DeviceId);
    ExReleasePushLockExclusive(&gDpUsbSession.Lock);

    DPUSB_TRACE("Session",
                "open complete deviceId=%ws backingHandle=%p fileObject=%p deviceObject=%p\n",
                Request->DeviceId,
                backingHandle,
                backingFileObject,
                backingDeviceObject);
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
    DpUsbReleaseBackingLocked();
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
DpUsbQueryDriveGeometryEx(
    _Out_writes_bytes_(OutputLength) PDISK_GEOMETRY_EX Geometry,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;
    ULONG requiredBytes;

    if (Geometry == NULL || BytesReturned == NULL || OutputLength < sizeof(DISK_GEOMETRY_EX)) {
        if (BytesReturned != NULL) {
            *BytesReturned = sizeof(DISK_GEOMETRY_EX);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    requiredBytes = sizeof(DISK_GEOMETRY_EX);
    DpUsbQueryLengthValue(&lengthBytes);
    RtlZeroMemory(Geometry, OutputLength);
    DpUsbBuildGeometry(lengthBytes, &Geometry->Geometry);
    Geometry->DiskSize.QuadPart = (LONGLONG)lengthBytes;
    Geometry->Data[0] = 0;
    DPUSB_TRACE("Query",
                "geometry ex length=%I64u cylinders=%I64d bytesReturned=%lu\n",
                lengthBytes,
                Geometry->Geometry.Cylinders.QuadPart,
                requiredBytes);
    *BytesReturned = requiredBytes;
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
    Partition->Mbr.PartitionType = PARTITION_FAT32;
    Partition->Mbr.BootIndicator = FALSE;
    Partition->Mbr.RecognizedPartition = TRUE;

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryPartitionInfoLegacy(
    _Out_ PPARTITION_INFORMATION Partition,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;

    if (Partition == NULL || BytesReturned == NULL || OutputLength < sizeof(PARTITION_INFORMATION)) {
        if (BytesReturned != NULL) {
            *BytesReturned = sizeof(PARTITION_INFORMATION);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    RtlZeroMemory(Partition, sizeof(*Partition));
    Partition->StartingOffset.QuadPart = 0;
    Partition->PartitionLength.QuadPart = (LONGLONG)lengthBytes;
    Partition->HiddenSectors = 0;
    Partition->PartitionNumber = 1;
    Partition->PartitionType = PARTITION_FAT32;
    Partition->BootIndicator = FALSE;
    Partition->RecognizedPartition = TRUE;
    Partition->RewritePartition = FALSE;
    DPUSB_TRACE("Query",
                "partition legacy length=%I64u type=0x%02X number=%lu\n",
                lengthBytes,
                Partition->PartitionType,
                Partition->PartitionNumber);
    *BytesReturned = sizeof(*Partition);
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
DpUsbQueryVolumeNumber(
    _Out_ PVOLUME_NUMBER VolumeNumber,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    if (VolumeNumber == NULL || BytesReturned == NULL || OutputLength < sizeof(VOLUME_NUMBER)) {
        if (BytesReturned != NULL) {
            *BytesReturned = sizeof(VOLUME_NUMBER);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(VolumeNumber, sizeof(*VolumeNumber));
    VolumeNumber->VolumeNumber = 0x44505543;
    RtlCopyMemory(VolumeNumber->VolumeManagerName, L"DPUSB   ", sizeof(VolumeNumber->VolumeManagerName));
    *BytesReturned = sizeof(*VolumeNumber);
    DPUSB_TRACE("Query", "volume number=0x%08X manager=DPUSB\n", VolumeNumber->VolumeNumber);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryMediaSerialNumber(
    _Out_writes_bytes_(OutputLength) PSTORAGE_MEDIA_SERIAL_NUMBER_DATA SerialNumber,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    static const UCHAR serial[] = "DataProtectorUsbCrypt";
    ULONG requiredBytes;

    if (SerialNumber == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    requiredBytes = (ULONG)FIELD_OFFSET(STORAGE_MEDIA_SERIAL_NUMBER_DATA, SerialNumber) + sizeof(serial) - 1;
    *BytesReturned = requiredBytes;
    if (OutputLength < requiredBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(SerialNumber, OutputLength);
    SerialNumber->SerialNumberLength = sizeof(serial) - 1;
    RtlCopyMemory(SerialNumber->SerialNumber, serial, sizeof(serial) - 1);
    DPUSB_TRACE("Query", "media serial bytes=%lu\n", requiredBytes);
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

static
NTSTATUS
DpUsbQueryMountDeviceName(
    _Out_writes_bytes_(OutputLength) PMOUNTDEV_NAME MountName,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    USHORT nameBytes;
    ULONG requiredBytes;
    UNICODE_STRING deviceName;

    if (MountName == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&deviceName, DPUSB_VOLUME_DEVICE_NAME);
    nameBytes = deviceName.Length;
    requiredBytes = (ULONG)FIELD_OFFSET(MOUNTDEV_NAME, Name) + nameBytes;
    *BytesReturned = requiredBytes;

    if (OutputLength < requiredBytes) {
        if (OutputLength >= sizeof(MOUNTDEV_NAME)) {
            MountName->NameLength = nameBytes;
        }
        DPUSB_TRACE("Query",
                    "mountdev name too small output=%lu required=%lu\n",
                    OutputLength,
                    requiredBytes);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(MountName, OutputLength);
    MountName->NameLength = nameBytes;
    RtlCopyMemory(MountName->Name, deviceName.Buffer, nameBytes);
    DPUSB_TRACE("Query", "mountdev name=%wZ bytes=%lu\n", &deviceName, requiredBytes);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbBuildUniqueIdString(
    _Out_writes_(IdChars) PWCHAR Id,
    _In_ ULONG IdChars
    )
{
    DPUSB_STATUS status;
    ULONG bytesReturned;
    NTSTATUS queryStatus;

    if (Id == NULL || IdChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Id, IdChars * sizeof(WCHAR));
    queryStatus = DpUsbQueryStatus(&status, sizeof(status), &bytesReturned);
    if (NT_SUCCESS(queryStatus) && status.DeviceId[0] != L'\0') {
        return RtlStringCchPrintfW(Id, IdChars, L"DataProtectorUsbCrypt-%ws", status.DeviceId);
    }

    return RtlStringCchCopyW(Id, IdChars, L"DataProtectorUsbCrypt-locked");
}

static
NTSTATUS
DpUsbQueryMountUniqueId(
    _Out_writes_bytes_(OutputLength) PMOUNTDEV_UNIQUE_ID UniqueId,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    WCHAR uniqueText[DPUSB_MAX_DEVICE_ID_CHARS + 32];
    USHORT uniqueBytes;
    ULONG requiredBytes;
    NTSTATUS status;

    if (UniqueId == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbBuildUniqueIdString(uniqueText, RTL_NUMBER_OF(uniqueText));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    uniqueBytes = (USHORT)(wcslen(uniqueText) * sizeof(WCHAR));
    requiredBytes = (ULONG)FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId) + uniqueBytes;
    *BytesReturned = requiredBytes;

    if (OutputLength < requiredBytes) {
        if (OutputLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
            UniqueId->UniqueIdLength = uniqueBytes;
        }
        DPUSB_TRACE("Query",
                    "mountdev unique id too small output=%lu required=%lu\n",
                    OutputLength,
                    requiredBytes);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(UniqueId, OutputLength);
    UniqueId->UniqueIdLength = uniqueBytes;
    RtlCopyMemory(UniqueId->UniqueId, uniqueText, uniqueBytes);
    DPUSB_TRACE("Query", "mountdev unique id bytes=%lu text=%ws\n", requiredBytes, uniqueText);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryMountSuggestedLinkName(
    _Out_writes_bytes_(OutputLength) PMOUNTDEV_SUGGESTED_LINK_NAME LinkName,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    static const WCHAR suggestedName[] = L"\\DosDevices\\Z:";
    USHORT nameBytes;
    ULONG requiredBytes;

    if (LinkName == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    nameBytes = (USHORT)((RTL_NUMBER_OF(suggestedName) - 1) * sizeof(WCHAR));
    requiredBytes = (ULONG)FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME, Name) + nameBytes;
    *BytesReturned = requiredBytes;

    if (OutputLength < requiredBytes) {
        if (OutputLength >= sizeof(MOUNTDEV_SUGGESTED_LINK_NAME)) {
            LinkName->NameLength = nameBytes;
        }
        DPUSB_TRACE("Query",
                    "mountdev suggested link too small output=%lu required=%lu\n",
                    OutputLength,
                    requiredBytes);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(LinkName, OutputLength);
    LinkName->UseOnlyIfThereAreNoOtherLinks = TRUE;
    LinkName->NameLength = nameBytes;
    RtlCopyMemory(LinkName->Name, suggestedName, nameBytes);
    DPUSB_TRACE("Query", "mountdev suggested link=%ws bytes=%lu\n", suggestedName, requiredBytes);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryMountStableGuid(
    _Out_writes_bytes_(OutputLength) PMOUNTDEV_STABLE_GUID StableGuid,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    WCHAR uniqueText[DPUSB_MAX_DEVICE_ID_CHARS + 32];
    const UCHAR *bytes;
    ULONG byteCount;
    ULONG hash = 2166136261UL;
    ULONG index;

    if (StableGuid == NULL || BytesReturned == NULL || OutputLength < sizeof(MOUNTDEV_STABLE_GUID)) {
        if (BytesReturned != NULL) {
            *BytesReturned = sizeof(MOUNTDEV_STABLE_GUID);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!NT_SUCCESS(DpUsbBuildUniqueIdString(uniqueText, RTL_NUMBER_OF(uniqueText)))) {
        RtlStringCchCopyW(uniqueText, RTL_NUMBER_OF(uniqueText), L"DataProtectorUsbCrypt-locked");
    }

    bytes = (const UCHAR *)uniqueText;
    byteCount = (ULONG)(wcslen(uniqueText) * sizeof(WCHAR));
    for (index = 0; index < byteCount; index++) {
        hash ^= bytes[index];
        hash *= 16777619UL;
    }

    RtlZeroMemory(StableGuid, sizeof(*StableGuid));
    StableGuid->StableGuid.Data1 = hash;
    StableGuid->StableGuid.Data2 = (USHORT)((hash >> 16) ^ 0x5553);
    StableGuid->StableGuid.Data3 = (USHORT)((hash & 0xFFFF) ^ 0x4243);
    StableGuid->StableGuid.Data4[0] = 0x90;
    StableGuid->StableGuid.Data4[1] = 0x00;
    StableGuid->StableGuid.Data4[2] = 0x44;
    StableGuid->StableGuid.Data4[3] = 0x50;
    StableGuid->StableGuid.Data4[4] = 0x55;
    StableGuid->StableGuid.Data4[5] = 0x53;
    StableGuid->StableGuid.Data4[6] = 0x42;
    StableGuid->StableGuid.Data4[7] = (UCHAR)(hash & 0xFF);
    *BytesReturned = sizeof(*StableGuid);
    DPUSB_TRACE("Query", "mountdev stable guid bytes=%lu hash=0x%08X id=%ws\n", *BytesReturned, hash, uniqueText);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbQueryVolumeDiskExtents(
    _Out_writes_bytes_(OutputLength) PVOLUME_DISK_EXTENTS Extents,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned
    )
{
    ULONGLONG lengthBytes;
    ULONG requiredBytes;

    if (Extents == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    requiredBytes = (ULONG)FIELD_OFFSET(VOLUME_DISK_EXTENTS, Extents) + sizeof(DISK_EXTENT);
    *BytesReturned = requiredBytes;

    if (OutputLength < requiredBytes) {
        DPUSB_TRACE("Query",
                    "volume extents too small output=%lu required=%lu\n",
                    OutputLength,
                    requiredBytes);
        return STATUS_BUFFER_TOO_SMALL;
    }

    DpUsbQueryLengthValue(&lengthBytes);
    RtlZeroMemory(Extents, OutputLength);
    Extents->NumberOfDiskExtents = 1;
    Extents->Extents[0].DiskNumber = 0x44505543;
    Extents->Extents[0].StartingOffset.QuadPart = 0;
    Extents->Extents[0].ExtentLength.QuadPart = (LONGLONG)lengthBytes;
    DPUSB_TRACE("Query",
                "volume extents disk=0x%08X length=%I64u\n",
                Extents->Extents[0].DiskNumber,
                lengthBytes);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbBuildGlobalDriveName(
    _In_ WCHAR DriveLetter,
    _Out_ PUNICODE_STRING DriveName,
    _Out_writes_(DriveNameChars) PWCHAR DriveNameBuffer,
    _In_ ULONG DriveNameChars
    )
{
    NTSTATUS status;
    WCHAR letter;

    if (DriveName == NULL || DriveNameBuffer == NULL || DriveNameChars < 24) {
        return STATUS_INVALID_PARAMETER;
    }

    letter = DriveLetter;
    if (letter >= L'a' && letter <= L'z') {
        letter = (WCHAR)(letter - L'a' + L'A');
    }

    if (letter < L'A' || letter > L'Z') {
        return STATUS_INVALID_PARAMETER;
    }

    status = RtlStringCchPrintfW(DriveNameBuffer,
                                 DriveNameChars,
                                 L"\\DosDevices\\Global\\%wc:",
                                 letter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(DriveName, DriveNameBuffer);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbMountDriveLetter(
    _In_ PDPUSB_DRIVE_MOUNT Request,
    _In_ ULONG InputLength
    )
{
    WCHAR driveNameBuffer[32];
    UNICODE_STRING driveName;
    UNICODE_STRING deviceName;
    NTSTATUS status;
    NTSTATUS deleteStatus;

    if (Request == NULL || InputLength < sizeof(DPUSB_DRIVE_MOUNT) || Request->Version != 1) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbBuildGlobalDriveName(Request->DriveLetter,
                                       &driveName,
                                       driveNameBuffer,
                                       RTL_NUMBER_OF(driveNameBuffer));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&deviceName, DPUSB_VOLUME_DEVICE_NAME);
    deleteStatus = IoDeleteSymbolicLink(&driveName);
    status = IoCreateSymbolicLink(&driveName, &deviceName);
    DPUSB_TRACE("Mount",
                "mount drive=%wZ target=%wZ delete=0x%08X create=0x%08X\n",
                &driveName,
                &deviceName,
                deleteStatus,
                status);
    return status;
}

static
NTSTATUS
DpUsbUnmountDriveLetter(
    _In_ PDPUSB_DRIVE_MOUNT Request,
    _In_ ULONG InputLength
    )
{
    WCHAR driveNameBuffer[32];
    UNICODE_STRING driveName;
    NTSTATUS status;

    if (Request == NULL || InputLength < sizeof(DPUSB_DRIVE_MOUNT) || Request->Version != 1) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpUsbBuildGlobalDriveName(Request->DriveLetter,
                                       &driveName,
                                       driveNameBuffer,
                                       RTL_NUMBER_OF(driveNameBuffer));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoDeleteSymbolicLink(&driveName);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
        status = STATUS_SUCCESS;
    }

    DPUSB_TRACE("Mount", "unmount drive=%wZ status=0x%08X\n", &driveName, status);
    return status;
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
DpUsbQueryInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    FILE_INFORMATION_CLASS informationClass;
    ULONG outputLength;
    PVOID buffer;
    ULONG_PTR information = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG lengthBytes = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    informationClass = stack->Parameters.QueryFile.FileInformationClass;
    outputLength = stack->Parameters.QueryFile.Length;
    buffer = Irp->AssociatedIrp.SystemBuffer;
    DpUsbQueryLengthValue(&lengthBytes);

    DPUSB_TRACE("Information",
                "query irp=%p class=%lu length=%lu buffer=%p file=%p current=%I64d dataLength=%I64u pid=%p\n",
                Irp,
                (ULONG)informationClass,
                outputLength,
                buffer,
                stack->FileObject,
                stack->FileObject != NULL ? stack->FileObject->CurrentByteOffset.QuadPart : 0,
                lengthBytes,
                PsGetCurrentProcessId());

    switch (informationClass) {
    case FilePositionInformation:
        if (buffer == NULL || outputLength < sizeof(FILE_POSITION_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(FILE_POSITION_INFORMATION);
            break;
        }

        ((PFILE_POSITION_INFORMATION)buffer)->CurrentByteOffset =
            stack->FileObject != NULL ? stack->FileObject->CurrentByteOffset : RtlConvertLongToLargeInteger(0);
        information = sizeof(FILE_POSITION_INFORMATION);
        break;

    case FileStandardInformation:
        if (buffer == NULL || outputLength < sizeof(FILE_STANDARD_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(FILE_STANDARD_INFORMATION);
            break;
        }

        RtlZeroMemory(buffer, sizeof(FILE_STANDARD_INFORMATION));
        ((PFILE_STANDARD_INFORMATION)buffer)->AllocationSize.QuadPart = (LONGLONG)lengthBytes;
        ((PFILE_STANDARD_INFORMATION)buffer)->EndOfFile.QuadPart = (LONGLONG)lengthBytes;
        ((PFILE_STANDARD_INFORMATION)buffer)->NumberOfLinks = 1;
        ((PFILE_STANDARD_INFORMATION)buffer)->DeletePending = FALSE;
        ((PFILE_STANDARD_INFORMATION)buffer)->Directory = FALSE;
        information = sizeof(FILE_STANDARD_INFORMATION);
        break;

    default:
        DPUSB_TRACE("Information",
                    "query unsupported irp=%p class=%lu length=%lu\n",
                    Irp,
                    (ULONG)informationClass,
                    outputLength);
        status = STATUS_INVALID_INFO_CLASS;
        information = 0;
        break;
    }

    DpUsbComplete(Irp, status, information);
    return status;
}

NTSTATUS
DpUsbSetInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    FILE_INFORMATION_CLASS informationClass;
    ULONG inputLength;
    PVOID buffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    ULONGLONG lengthBytes = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    informationClass = stack->Parameters.SetFile.FileInformationClass;
    inputLength = stack->Parameters.SetFile.Length;
    buffer = Irp->AssociatedIrp.SystemBuffer;
    DpUsbQueryLengthValue(&lengthBytes);

    DPUSB_TRACE("Information",
                "set irp=%p class=%lu length=%lu buffer=%p file=%p current=%I64d dataLength=%I64u pid=%p\n",
                Irp,
                (ULONG)informationClass,
                inputLength,
                buffer,
                stack->FileObject,
                stack->FileObject != NULL ? stack->FileObject->CurrentByteOffset.QuadPart : 0,
                lengthBytes,
                PsGetCurrentProcessId());

    switch (informationClass) {
    case FilePositionInformation:
        if (buffer == NULL || inputLength < sizeof(FILE_POSITION_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (((PFILE_POSITION_INFORMATION)buffer)->CurrentByteOffset.QuadPart < 0 ||
            (ULONGLONG)((PFILE_POSITION_INFORMATION)buffer)->CurrentByteOffset.QuadPart > lengthBytes) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (stack->FileObject != NULL) {
            stack->FileObject->CurrentByteOffset =
                ((PFILE_POSITION_INFORMATION)buffer)->CurrentByteOffset;
        }
        status = STATUS_SUCCESS;
        break;

    default:
        DPUSB_TRACE("Information",
                    "set unsupported irp=%p class=%lu length=%lu\n",
                    Irp,
                    (ULONG)informationClass,
                    inputLength);
        status = STATUS_INVALID_INFO_CLASS;
        break;
    }

    DpUsbComplete(Irp, status, information);
    return status;
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
        gDpUsbSession.PhysicalDrivePath[0] == L'\0' ||
        gDpUsbSession.BackingFileObject == NULL ||
        gDpUsbSession.BackingDeviceObject == NULL) {

        DPUSB_TRACE("Session",
                    "capture failed open=%u algorithm=%lu keyLength=%lu pathFirst=0x%04X fileObject=%p deviceObject=%p\n",
                    gDpUsbSession.SessionOpen,
                    gDpUsbSession.Algorithm,
                    gDpUsbSession.KeyLength,
                    gDpUsbSession.PhysicalDrivePath[0],
                    gDpUsbSession.BackingFileObject,
                    gDpUsbSession.BackingDeviceObject);
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
    Snapshot->BackingFileObject = gDpUsbSession.BackingFileObject;
    Snapshot->BackingDeviceObject = gDpUsbSession.BackingDeviceObject;
    Snapshot->BackingAlignment = DpUsbGetDeviceAlignment(gDpUsbSession.BackingDeviceObject);
    ObReferenceObject(Snapshot->BackingFileObject);
    ObReferenceObject(Snapshot->BackingDeviceObject);
    ExReleasePushLockShared(&gDpUsbSession.Lock);

    DPUSB_TRACE("Session",
                "capture ok physical=%ws dataOffset=%I64u dataLength=%I64u keyLength=%lu fileObject=%p deviceObject=%p alignment=%lu\n",
                Snapshot->PhysicalDrivePath,
                Snapshot->DataOffsetBytes,
                Snapshot->DataLengthBytes,
                Snapshot->KeyLength,
                Snapshot->BackingFileObject,
                Snapshot->BackingDeviceObject,
                Snapshot->BackingAlignment);
    return STATUS_SUCCESS;
}

static
VOID
DpUsbReleaseSessionSnapshot(
    _Inout_ PDPUSB_SESSION_SNAPSHOT Snapshot
    )
{
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT deviceObject;

    if (Snapshot == NULL) {
        return;
    }

    fileObject = Snapshot->BackingFileObject;
    deviceObject = Snapshot->BackingDeviceObject;
    Snapshot->BackingFileObject = NULL;
    Snapshot->BackingDeviceObject = NULL;

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }

    if (deviceObject != NULL) {
        ObDereferenceObject(deviceObject);
    }

    RtlSecureZeroMemory(Snapshot, sizeof(*Snapshot));
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

static
NTSTATUS
DpUsbForwardBackingReadWrite(
    _In_ const DPUSB_SESSION_SNAPSHOT *Snapshot,
    _In_ BOOLEAN IsWrite,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ ULONGLONG PhysicalOffset,
    _Out_ PULONG_PTR Information
    )
{
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER byteOffset;
    HANDLE handle = NULL;
    ULONG alignment;
    ULONG allocationLength;
    UCHAR *allocation = NULL;
    UCHAR *ioBuffer = NULL;
    NTSTATUS status;

    if (Information != NULL) {
        *Information = 0;
    }

    if (Snapshot == NULL ||
        Snapshot->BackingFileObject == NULL ||
        Snapshot->BackingDeviceObject == NULL ||
        Buffer == NULL ||
        Length == 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if ((PhysicalOffset % DPUSB_SECTOR_BYTES) != 0 || (Length % DPUSB_SECTOR_BYTES) != 0) {
        DPUSB_TRACE("Backing",
                    "%s rejected unaligned physical=%I64u length=%lu sector=%lu\n",
                    IsWrite ? "write" : "read",
                    PhysicalOffset,
                    Length,
                    DPUSB_SECTOR_BYTES);
        return STATUS_INVALID_PARAMETER;
    }

    alignment = Snapshot->BackingAlignment != 0 ? Snapshot->BackingAlignment : DPUSB_SECTOR_BYTES;
    allocationLength = Length + alignment - 1;
    allocation = (UCHAR *)ExAllocatePoolWithTag(NonPagedPoolNx, allocationLength, DPUSB_TAG_IO);
    if (allocation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ioBuffer = (UCHAR *)DpUsbAlignPointer(allocation, alignment);
    if (IsWrite) {
        RtlCopyMemory(ioBuffer, Buffer, Length);
    } else {
        RtlZeroMemory(ioBuffer, Length);
    }

    ExAcquirePushLockShared(&gDpUsbSession.Lock);
    if (!gDpUsbSession.SessionOpen ||
        gDpUsbSession.BackingHandle == NULL ||
        gDpUsbSession.BackingFileObject != Snapshot->BackingFileObject) {

        status = STATUS_DEVICE_NOT_READY;
        DPUSB_TRACE("Backing",
                    "%s session changed open=%u handle=%p liveFile=%p snapshotFile=%p\n",
                    IsWrite ? "write" : "read",
                    gDpUsbSession.SessionOpen,
                    gDpUsbSession.BackingHandle,
                    gDpUsbSession.BackingFileObject,
                    Snapshot->BackingFileObject);
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        RtlSecureZeroMemory(allocation, allocationLength);
        ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
        return status;
    }

    handle = gDpUsbSession.BackingHandle;
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    byteOffset.QuadPart = (LONGLONG)PhysicalOffset;

    DPUSB_TRACE("Backing",
                "%s zw begin handle=%p file=%p device=%p physical=%I64u length=%lu align=%lu buffer=%p\n",
                IsWrite ? "write" : "read",
                handle,
                Snapshot->BackingFileObject,
                Snapshot->BackingDeviceObject,
                PhysicalOffset,
                Length,
                alignment,
                ioBuffer);
    if (IsWrite) {
        status = ZwWriteFile(handle,
                             NULL,
                             NULL,
                             NULL,
                             &ioStatus,
                             ioBuffer,
                             Length,
                             &byteOffset,
                             NULL);
    } else {
        status = ZwReadFile(handle,
                            NULL,
                            NULL,
                            NULL,
                            &ioStatus,
                            ioBuffer,
                            Length,
                            &byteOffset,
                            NULL);
    }
    if (NT_SUCCESS(status)) {
        status = ioStatus.Status;
    }
    DPUSB_TRACE("Backing",
                "%s zw end status=0x%08X iosb=0x%08X information=%Iu physical=%I64u length=%lu\n",
                IsWrite ? "write" : "read",
                status,
                ioStatus.Status,
                ioStatus.Information,
                PhysicalOffset,
                Length);
    ExReleasePushLockShared(&gDpUsbSession.Lock);

    if (NT_SUCCESS(status) && Information != NULL) {
        *Information = ioStatus.Information;
    }

    if (NT_SUCCESS(status) && !IsWrite && ioStatus.Information != 0) {
        RtlCopyMemory(Buffer, ioBuffer, (SIZE_T)ioStatus.Information);
    }

    RtlSecureZeroMemory(allocation, allocationLength);
    ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
    return status;
}

static
NTSTATUS
DpUsbWriteAlignedBuffer(
    _In_ ULONGLONG LogicalOffset,
    _In_reads_bytes_(Length) const VOID *Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    ULONGLONG physicalOffset;
    UCHAR *allocation = NULL;
    UCHAR *ioBuffer;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER byteOffset;
    ULONG alignment = DPUSB_SECTOR_BYTES;
    ULONG allocationLength;
    NTSTATUS status;

    if (Information != NULL) {
        *Information = 0;
    }

    if (Buffer == NULL || Length == 0 || Length > DPUSB_RAW_WRITE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((LogicalOffset % DPUSB_SECTOR_BYTES) != 0 || (Length % DPUSB_SECTOR_BYTES) != 0) {
        DPUSB_TRACE("RawWrite",
                    "unaligned request logical=%I64u length=%lu sector=%lu\n",
                    LogicalOffset,
                    Length,
                    DPUSB_SECTOR_BYTES);
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockShared(&gDpUsbSession.Lock);
    if (!gDpUsbSession.SessionOpen || gDpUsbSession.BackingHandle == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        DPUSB_TRACE("RawWrite",
                    "session unavailable logical=%I64u length=%lu open=%u handle=%p\n",
                    LogicalOffset,
                    Length,
                    gDpUsbSession.SessionOpen,
                    gDpUsbSession.BackingHandle);
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        return status;
    }

    alignment = DpUsbGetDeviceAlignment(gDpUsbSession.BackingDeviceObject);
    allocationLength = Length + alignment - 1;
    allocation = (UCHAR *)ExAllocatePoolWithTag(NonPagedPoolNx,
                                               allocationLength,
                                               DPUSB_TAG_IO);
    if (allocation == NULL) {
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ioBuffer = (UCHAR *)DpUsbAlignPointer(allocation, alignment);
    RtlCopyMemory(ioBuffer, Buffer, Length);

    if (!DpUsbAddUlonglong(LogicalOffset, Length, &physicalOffset) ||
        (gDpUsbSession.DataLengthBytes != 0 && physicalOffset > gDpUsbSession.DataLengthBytes)) {

        status = STATUS_END_OF_FILE;
        DPUSB_TRACE("RawWrite",
                    "logical range invalid logical=%I64u length=%lu dataLength=%I64u\n",
                    LogicalOffset,
                    Length,
                    gDpUsbSession.DataLengthBytes);
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        RtlSecureZeroMemory(allocation, allocationLength);
        ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
        return status;
    }

    if (!DpUsbAddUlonglong(gDpUsbSession.DataOffsetBytes, LogicalOffset, &physicalOffset)) {
        status = STATUS_INTEGER_OVERFLOW;
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        RtlSecureZeroMemory(allocation, allocationLength);
        ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
        return status;
    }

    if ((physicalOffset % DPUSB_SECTOR_BYTES) != 0) {
        status = STATUS_INVALID_PARAMETER;
        DPUSB_TRACE("RawWrite",
                    "physical offset unaligned logical=%I64u physical=%I64u length=%lu\n",
                    LogicalOffset,
                    physicalOffset,
                    Length);
        ExReleasePushLockShared(&gDpUsbSession.Lock);
        RtlSecureZeroMemory(allocation, allocationLength);
        ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
        return status;
    }

    DpUsbRc4CryptAtOffset(gDpUsbSession.Key,
                          gDpUsbSession.KeyLength,
                          LogicalOffset,
                          ioBuffer,
                          Length);

    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    byteOffset.QuadPart = (LONGLONG)physicalOffset;
    DPUSB_TRACE("RawWrite",
                "aligned zw write begin handle=%p logical=%I64u physical=%I64u length=%lu align=%lu buffer=%p\n",
                gDpUsbSession.BackingHandle,
                LogicalOffset,
                physicalOffset,
                Length,
                alignment,
                ioBuffer);
    status = ZwWriteFile(gDpUsbSession.BackingHandle,
                         NULL,
                         NULL,
                         NULL,
                         &ioStatus,
                         ioBuffer,
                         Length,
                         &byteOffset,
                         NULL);
    if (NT_SUCCESS(status)) {
        status = ioStatus.Status;
    }
    DPUSB_TRACE("RawWrite",
                "aligned zw write end status=0x%08X iosb=0x%08X information=%Iu logical=%I64u physical=%I64u length=%lu\n",
                status,
                ioStatus.Status,
                ioStatus.Information,
                LogicalOffset,
                physicalOffset,
                Length);

    ExReleasePushLockShared(&gDpUsbSession.Lock);

    if (NT_SUCCESS(status) && ioStatus.Information != Length) {
        status = STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(status) && Information != NULL) {
        *Information = Length;
    }

    RtlSecureZeroMemory(allocation, allocationLength);
    ExFreePoolWithTag(allocation, DPUSB_TAG_IO);
    return status;
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
    PDPUSB_IO_WORK_ITEM workItem;
    PIO_STACK_LOCATION stack;
    BOOLEAN isWrite;
    ULONG length;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    isWrite = stack->MajorFunction == IRP_MJ_WRITE;
    length = isWrite ? stack->Parameters.Write.Length : stack->Parameters.Read.Length;

    DPUSB_TRACE("ReadWrite",
                "queue enter irp=%p op=%s length=%lu logical=%I64d mdl=%p flags=0x%08X irql=%lu pid=%p\n",
                Irp,
                isWrite ? "WRITE" : "READ",
                length,
                isWrite ? stack->Parameters.Write.ByteOffset.QuadPart : stack->Parameters.Read.ByteOffset.QuadPart,
                Irp->MdlAddress,
                Irp->Flags,
                (ULONG)KeGetCurrentIrql(),
                PsGetCurrentProcessId());

    if (!DpUsbIsVolumeDevice(DeviceObject)) {
        DPUSB_TRACE("ReadWrite",
                    "reject non-volume device irp=%p device=%p op=%s\n",
                    Irp,
                    DeviceObject,
                    isWrite ? "WRITE" : "READ");
        DpUsbComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (length == 0) {
        DPUSB_TRACE("ReadWrite", "zero length irp=%p op=%s\n", Irp, isWrite ? "WRITE" : "READ");
        DpUsbComplete(Irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    if (InterlockedCompareExchange(&gDpUsbUnloading, 0, 0) != 0) {
        DPUSB_TRACE("ReadWrite", "reject during unload irp=%p op=%s\n", Irp, isWrite ? "WRITE" : "READ");
        DpUsbComplete(Irp, STATUS_DELETE_PENDING, 0);
        return STATUS_DELETE_PENDING;
    }

    workItem = (PDPUSB_IO_WORK_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*workItem), DPUSB_TAG_WORK);
    if (workItem == NULL) {
        DPUSB_TRACE("ReadWrite", "work item alloc failed irp=%p length=%lu\n", Irp, length);
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (InterlockedIncrement(&gDpUsbActiveWorkers) == 1) {
        KeClearEvent(&gDpUsbNoActiveWorkers);
    }

    if (InterlockedCompareExchange(&gDpUsbUnloading, 0, 0) != 0) {
        if (InterlockedDecrement(&gDpUsbActiveWorkers) == 0) {
            KeSetEvent(&gDpUsbNoActiveWorkers, IO_NO_INCREMENT, FALSE);
        }
        ExFreePoolWithTag(workItem, DPUSB_TAG_WORK);
        DPUSB_TRACE("ReadWrite", "reject after worker reserve during unload irp=%p\n", Irp);
        DpUsbComplete(Irp, STATUS_DELETE_PENDING, 0);
        return STATUS_DELETE_PENDING;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->Irp = Irp;
    workItem->IsWrite = isWrite;
    IoMarkIrpPending(Irp);
    ExInitializeWorkItem(&workItem->WorkItem, DpUsbReadWriteWorker, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
    DPUSB_TRACE("ReadWrite", "queued worker irp=%p work=%p\n", Irp, workItem);
    return STATUS_PENDING;
}

static
VOID
DpUsbReadWriteWorker(
    _In_ PVOID Context
    )
{
    PDPUSB_IO_WORK_ITEM workItem;
    PIRP Irp;
    PIO_STACK_LOCATION stack;
    BOOLEAN isWrite;
    ULONG length;
    ULONGLONG logicalOffset;
    ULONGLONG physicalOffset;
    DPUSB_SESSION_SNAPSHOT snapshot;
    PVOID systemAddress;
    UCHAR *ioBuffer = NULL;
    NTSTATUS status;
    ULONG_PTR information = 0;

    workItem = (PDPUSB_IO_WORK_ITEM)Context;
    if (workItem == NULL || workItem->Irp == NULL) {
        if (workItem != NULL) {
            DpUsbFinishReadWriteWorker(workItem);
        } else if (InterlockedDecrement(&gDpUsbActiveWorkers) == 0) {
            KeSetEvent(&gDpUsbNoActiveWorkers, IO_NO_INCREMENT, FALSE);
        }
        return;
    }

    Irp = workItem->Irp;
    stack = IoGetCurrentIrpStackLocation(Irp);
    isWrite = workItem->IsWrite;
    length = isWrite ? stack->Parameters.Write.Length : stack->Parameters.Read.Length;
    logicalOffset = (ULONGLONG)(isWrite ?
        stack->Parameters.Write.ByteOffset.QuadPart :
        stack->Parameters.Read.ByteOffset.QuadPart);

    DPUSB_TRACE("ReadWrite",
                "worker enter irp=%p work=%p op=%s length=%lu logical=%I64u mdl=%p flags=0x%08X irql=%lu pid=%p\n",
                Irp,
                workItem,
                isWrite ? "WRITE" : "READ",
                length,
                logicalOffset,
                Irp->MdlAddress,
                Irp->Flags,
                (ULONG)KeGetCurrentIrql(),
                PsGetCurrentProcessId());

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
        DpUsbFinishReadWriteWorker(workItem);
        return;
    }

    status = DpUsbCaptureSession(&snapshot);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("ReadWrite", "capture failed irp=%p status=0x%08X\n", Irp, status);
        DpUsbComplete(Irp, status, 0);
        DpUsbFinishReadWriteWorker(workItem);
        return;
    }

    status = DpUsbValidateRange(&snapshot,
                                logicalOffset,
                                length,
                                &physicalOffset);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("ReadWrite", "range failed irp=%p status=0x%08X\n", Irp, status);
        DpUsbReleaseSessionSnapshot(&snapshot);
        DpUsbComplete(Irp, status, 0);
        DpUsbFinishReadWriteWorker(workItem);
        return;
    }

    systemAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    if (systemAddress == NULL) {
        DPUSB_TRACE("ReadWrite", "mdl mapping failed irp=%p mdl=%p\n", Irp, Irp->MdlAddress);
        DpUsbReleaseSessionSnapshot(&snapshot);
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        DpUsbFinishReadWriteWorker(workItem);
        return;
    }

    ioBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, length, DPUSB_TAG_IO);
    if (ioBuffer == NULL) {
        DPUSB_TRACE("ReadWrite", "alloc failed irp=%p length=%lu\n", Irp, length);
        DpUsbReleaseSessionSnapshot(&snapshot);
        DpUsbComplete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        DpUsbFinishReadWriteWorker(workItem);
        return;
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

    if (isWrite) {
        DPUSB_TRACE("ReadWrite",
                    "forward write begin irp=%p physical=%I64u length=%lu\n",
                    Irp,
                    physicalOffset,
                    length);
        status = DpUsbForwardBackingReadWrite(&snapshot,
                                              TRUE,
                                              ioBuffer,
                                              length,
                                              physicalOffset,
                                              &information);
        DPUSB_TRACE("ReadWrite",
                    "forward write end irp=%p status=0x%08X information=%Iu\n",
                    Irp,
                    status,
                    information);
    } else {
        DPUSB_TRACE("ReadWrite",
                    "forward read begin irp=%p physical=%I64u length=%lu\n",
                    Irp,
                    physicalOffset,
                    length);
        status = DpUsbForwardBackingReadWrite(&snapshot,
                                              FALSE,
                                              ioBuffer,
                                              length,
                                              physicalOffset,
                                              &information);
        DPUSB_TRACE("ReadWrite",
                    "forward read end irp=%p status=0x%08X information=%Iu\n",
                    Irp,
                    status,
                    information);
        if (NT_SUCCESS(status) && information != 0) {
            DpUsbRc4CryptAtOffset(snapshot.Key,
                                  snapshot.KeyLength,
                                  logicalOffset,
                                  ioBuffer,
                                  (ULONG)information);
            RtlCopyMemory(systemAddress, ioBuffer, (SIZE_T)information);
        }
    }

    if (ioBuffer != NULL) {
        RtlSecureZeroMemory(ioBuffer, length);
        ExFreePoolWithTag(ioBuffer, DPUSB_TAG_IO);
    }

    DpUsbReleaseSessionSnapshot(&snapshot);
    DPUSB_TRACE("ReadWrite",
                "worker leave irp=%p work=%p op=%s status=0x%08X information=%Iu\n",
                Irp,
                workItem,
                isWrite ? "WRITE" : "READ",
                status,
                information);
    DpUsbComplete(Irp, status, information);
    DpUsbFinishReadWriteWorker(workItem);
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

    if (DpUsbIsControlDevice(DeviceObject)) {
        switch (controlCode) {
        case IOCTL_DPUSB_QUERY_STATUS:
            status = DpUsbQueryStatus((PDPUSB_STATUS)buffer, outputLength, &bytesReturned);
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

        case IOCTL_DPUSB_MOUNT_DRIVE:
            status = DpUsbMountDriveLetter((PDPUSB_DRIVE_MOUNT)buffer, inputLength);
            bytesReturned = 0;
            break;

        case IOCTL_DPUSB_UNMOUNT_DRIVE:
            status = DpUsbUnmountDriveLetter((PDPUSB_DRIVE_MOUNT)buffer, inputLength);
            bytesReturned = 0;
            break;

        case IOCTL_DPUSB_RAW_WRITE_ALIGNED:
            if (buffer == NULL ||
                inputLength < (ULONG)FIELD_OFFSET(DPUSB_RAW_WRITE_REQUEST, Data) ||
                ((PDPUSB_RAW_WRITE_REQUEST)buffer)->Version != 1 ||
                ((PDPUSB_RAW_WRITE_REQUEST)buffer)->DataLength > DPUSB_RAW_WRITE_MAX_BYTES ||
                inputLength < (ULONG)FIELD_OFFSET(DPUSB_RAW_WRITE_REQUEST, Data) + ((PDPUSB_RAW_WRITE_REQUEST)buffer)->DataLength) {

                status = STATUS_INVALID_PARAMETER;
                bytesReturned = 0;
                break;
            }

            status = DpUsbWriteAlignedBuffer(((PDPUSB_RAW_WRITE_REQUEST)buffer)->LogicalOffset,
                                             ((PDPUSB_RAW_WRITE_REQUEST)buffer)->Data,
                                             ((PDPUSB_RAW_WRITE_REQUEST)buffer)->DataLength,
                                             NULL);
            bytesReturned = 0;
            break;

        default:
            DPUSB_TRACE("Ioctl",
                        "control unsupported irp=%p code=0x%08X input=%lu output=%lu\n",
                        Irp,
                        controlCode,
                        inputLength,
                        outputLength);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        DPUSB_TRACE("Ioctl",
                    "leave control irp=%p code=0x%08X(%s) status=0x%08X bytes=%lu\n",
                    Irp,
                    controlCode,
                    DpUsbIoctlName(controlCode),
                    status,
                    bytesReturned);
        DpUsbComplete(Irp, status, bytesReturned);
        return status;
    }

    if (!DpUsbIsVolumeDevice(DeviceObject)) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DPUSB_TRACE("Ioctl",
                    "unknown device irp=%p device=%p code=0x%08X(%s)\n",
                    Irp,
                    DeviceObject,
                    controlCode,
                    DpUsbIoctlName(controlCode));
        DpUsbComplete(Irp, status, 0);
        return status;
    }

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

    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
        status = DpUsbQueryDriveGeometryEx((PDISK_GEOMETRY_EX)buffer, outputLength, &bytesReturned);
        break;

    case IOCTL_DISK_GET_PARTITION_INFO:
        status = DpUsbQueryPartitionInfoLegacy((PPARTITION_INFORMATION)buffer, outputLength, &bytesReturned);
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
    case IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE:
    case IOCTL_VOLUME_IS_IO_CAPABLE:
    case IOCTL_VOLUME_UPDATE_PROPERTIES:
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_VOLUME_IS_OFFLINE:
    case IOCTL_VOLUME_IS_DYNAMIC:
        bytesReturned = 0;
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case IOCTL_VOLUME_IS_PARTITION:
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_VOLUME_QUERY_VOLUME_NUMBER:
        status = DpUsbQueryVolumeNumber((PVOLUME_NUMBER)buffer, outputLength, &bytesReturned);
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

    case IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER:
        status = DpUsbQueryMediaSerialNumber((PSTORAGE_MEDIA_SERIAL_NUMBER_DATA)buffer, outputLength, &bytesReturned);
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

    case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
        status = DpUsbQueryMountUniqueId((PMOUNTDEV_UNIQUE_ID)buffer,
                                         outputLength,
                                         &bytesReturned);
        break;

    case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
        status = DpUsbQueryMountDeviceName((PMOUNTDEV_NAME)buffer,
                                           outputLength,
                                           &bytesReturned);
        break;

    case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
        status = DpUsbQueryMountSuggestedLinkName((PMOUNTDEV_SUGGESTED_LINK_NAME)buffer,
                                                  outputLength,
                                                  &bytesReturned);
        break;

    case IOCTL_MOUNTDEV_LINK_CREATED:
    case IOCTL_MOUNTDEV_LINK_DELETED:
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
        status = DpUsbQueryMountStableGuid((PMOUNTDEV_STABLE_GUID)buffer,
                                           outputLength,
                                           &bytesReturned);
        break;

    case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
        status = DpUsbQueryVolumeDiskExtents((PVOLUME_DISK_EXTENTS)buffer,
                                             outputLength,
                                             &bytesReturned);
        break;

    default:
        DPUSB_TRACE("Ioctl",
                    "volume unsupported irp=%p code=0x%08X input=%lu output=%lu\n",
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

NTSTATUS
DpUsbFileSystemControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    ULONG controlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    controlCode = stack->Parameters.FileSystemControl.FsControlCode;

    DPUSB_TRACE("Fsctl",
                "enter irp=%p code=0x%08X pid=%p file=%p\n",
                Irp,
                controlCode,
                PsGetCurrentProcessId(),
                stack->FileObject);

    switch (controlCode) {
    case FSCTL_LOCK_VOLUME:
    case FSCTL_UNLOCK_VOLUME:
    case FSCTL_DISMOUNT_VOLUME:
    case FSCTL_IS_VOLUME_MOUNTED:
    case FSCTL_ALLOW_EXTENDED_DASD_IO:
        status = STATUS_SUCCESS;
        break;

    default:
        DPUSB_TRACE("Fsctl",
                    "unsupported irp=%p code=0x%08X\n",
                    Irp,
                    controlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    DPUSB_TRACE("Fsctl",
                "leave irp=%p code=0x%08X status=0x%08X\n",
                Irp,
                controlCode,
                status);
    DpUsbComplete(Irp, status, 0);
    return status;
}

VOID
DpUsbUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    DPUSB_TRACE("Driver", "unload begin driver=%p device=%p\n", DriverObject, gDpUsbDeviceObject);
    InterlockedExchange(&gDpUsbUnloading, 1);
    if (InterlockedCompareExchange(&gDpUsbActiveWorkers, 0, 0) != 0) {
        DPUSB_TRACE("Driver",
                    "unload waiting activeWorkers=%ld\n",
                    InterlockedCompareExchange(&gDpUsbActiveWorkers, 0, 0));
        KeWaitForSingleObject(&gDpUsbNoActiveWorkers, Executive, KernelMode, FALSE, NULL);
    }
    DpUsbCloseSession();
    IoDeleteSymbolicLink(&gDpUsbDosName);

    if (gDpUsbVolumeDeviceObject != NULL) {
        IoDeleteDevice(gDpUsbVolumeDeviceObject);
        gDpUsbVolumeDeviceObject = NULL;
    }

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
    UNICODE_STRING volumeDeviceName;
    ULONG index;

    UNREFERENCED_PARAMETER(RegistryPath);

    DPUSB_TRACE("Driver", "entry begin driver=%p registry=%wZ\n", DriverObject, RegistryPath);
    RtlZeroMemory(&gDpUsbSession, sizeof(gDpUsbSession));
    ExInitializePushLock(&gDpUsbSession.Lock);
    gDpUsbSession.LockInitialized = TRUE;
    InterlockedExchange(&gDpUsbUnloading, 0);
    InterlockedExchange(&gDpUsbActiveWorkers, 0);
    KeInitializeEvent(&gDpUsbNoActiveWorkers, NotificationEvent, TRUE);

    RtlInitUnicodeString(&deviceName, DPUSB_DEVICE_NAME);
    RtlInitUnicodeString(&volumeDeviceName, DPUSB_VOLUME_DEVICE_NAME);
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

    status = IoCreateDevice(DriverObject,
                            0,
                            &volumeDeviceName,
                            FILE_DEVICE_DISK,
                            FILE_REMOVABLE_MEDIA | FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &gDpUsbVolumeDeviceObject);
    if (!NT_SUCCESS(status)) {
        DPUSB_TRACE("Driver", "IoCreateDevice volume failed status=0x%08X\n", status);
        IoDeleteSymbolicLink(&gDpUsbDosName);
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
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = DpUsbQueryInformation;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = DpUsbSetInformation;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = DpUsbFlushBuffers;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DpUsbDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = DpUsbFileSystemControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = DpUsbReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DpUsbReadWrite;
    DriverObject->DriverUnload = DpUsbUnload;

    gDpUsbDeviceObject->Flags |= DO_DIRECT_IO;
    gDpUsbDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    gDpUsbVolumeDeviceObject->Flags |= DO_DIRECT_IO;
    gDpUsbVolumeDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DPUSB_TRACE("Driver",
                "entry complete control=%p controlFlags=0x%08X volume=%p volumeFlags=0x%08X trace=%u\n",
                gDpUsbDeviceObject,
                gDpUsbDeviceObject->Flags,
                gDpUsbVolumeDeviceObject,
                gDpUsbVolumeDeviceObject->Flags,
                DPUSB_TRACE_ENABLED);
    return STATUS_SUCCESS;
}
