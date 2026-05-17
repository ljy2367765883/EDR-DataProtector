/*++

Module Name:

    DpUsbMetadata.c

Abstract:

    Kernel-side raw USB metadata writer used by centrally managed Secure USB
    initialization. User mode supplies the signed policy decision and metadata
    block; the driver performs the final disk-boundary validation and write.

--*/

#include "DataProtector.h"

#include <ntdddisk.h>

#define DP_USB_METADATA_MAX_LAYOUT_BYTES (64 * 1024)
#define DP_USB_METADATA_SECTOR_BYTES 512
static
BOOLEAN
DpUsbMetadataIsZeroBlock(
    _In_reads_bytes_(DP_USB_METADATA_BYTES) const UCHAR *Buffer
    )
{
    ULONG index;

    for (index = 0; index < DP_USB_METADATA_BYTES; index++) {
        if (Buffer[index] != 0) {
            return FALSE;
        }
    }

    return TRUE;
}

static
BOOLEAN
DpUsbMetadataHasKnownMagic(
    _In_reads_bytes_(DP_USB_METADATA_BYTES) const UCHAR *Buffer
    )
{
    ULONG magic;

    RtlCopyMemory(&magic, Buffer, sizeof(magic));
    return magic == DP_USB_METADATA_MAGIC_V2 || magic == DP_USB_METADATA_MAGIC_V1;
}

static
BOOLEAN
DpUsbMetadataAddUlonglong(
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
BOOLEAN
DpUsbMetadataRangeIntersects(
    _In_ ULONGLONG LeftOffset,
    _In_ ULONGLONG LeftLength,
    _In_ ULONGLONG RightOffset,
    _In_ ULONGLONG RightLength
    )
{
    ULONGLONG leftEnd;
    ULONGLONG rightEnd;

    if (LeftLength == 0 || RightLength == 0 ||
        !DpUsbMetadataAddUlonglong(LeftOffset, LeftLength, &leftEnd) ||
        !DpUsbMetadataAddUlonglong(RightOffset, RightLength, &rightEnd)) {

        return TRUE;
    }

    return LeftOffset < rightEnd && RightOffset < leftEnd;
}

static
NTSTATUS
DpUsbMetadataBuildPath(
    _In_ const DP_USB_METADATA_WRITE_MESSAGE *Request,
    _Out_ PUNICODE_STRING Path
    )
{
    USHORT lengthBytes;

    if (Request->PhysicalPathLengthBytes == 0 ||
        Request->PhysicalPathLengthBytes > (DP_USB_METADATA_PATH_CHARS - 1) * sizeof(WCHAR) ||
        (Request->PhysicalPathLengthBytes % sizeof(WCHAR)) != 0) {

        return STATUS_INVALID_PARAMETER;
    }

    lengthBytes = (USHORT)Request->PhysicalPathLengthBytes;
    if (Request->PhysicalPath[lengthBytes / sizeof(WCHAR)] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    Path->Buffer = (PWCH)Request->PhysicalPath;
    Path->Length = lengthBytes;
    Path->MaximumLength = lengthBytes + sizeof(WCHAR);

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbMetadataOpenDisk(
    _In_ PUNICODE_STRING PhysicalPath,
    _Out_ PHANDLE DiskHandle
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    InitializeObjectAttributes(&objectAttributes,
                               PhysicalPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    return ZwCreateFile(DiskHandle,
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
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
DpUsbMetadataQueryLayout(
    _In_ HANDLE DiskHandle,
    _Outptr_result_bytebuffer_(*LayoutBytes) PDRIVE_LAYOUT_INFORMATION_EX *Layout,
    _Out_ PULONG LayoutBytes
    )
{
    PDRIVE_LAYOUT_INFORMATION_EX layout;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    ULONG bytes;

    if (Layout == NULL || LayoutBytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Layout = NULL;
    *LayoutBytes = 0;
    bytes = DP_USB_METADATA_MAX_LAYOUT_BYTES;

    layout = ExAllocatePoolWithTag(NonPagedPoolNx, bytes, DP_TAG_USB_METADATA);
    if (layout == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(layout, bytes);
    status = ZwDeviceIoControlFile(DiskHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &ioStatus,
                                   IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                   NULL,
                                   0,
                                   layout,
                                   bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(layout, DP_TAG_USB_METADATA);
        return status;
    }

    *Layout = layout;
    *LayoutBytes = bytes;
    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbMetadataQueryLength(
    _In_ HANDLE DiskHandle,
    _Out_ PULONGLONG DiskSizeBytes
    )
{
    GET_LENGTH_INFORMATION lengthInfo;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (DiskSizeBytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DiskSizeBytes = 0;
    RtlZeroMemory(&lengthInfo, sizeof(lengthInfo));
    status = ZwDeviceIoControlFile(DiskHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &ioStatus,
                                   IOCTL_DISK_GET_LENGTH_INFO,
                                   NULL,
                                   0,
                                   &lengthInfo,
                                   sizeof(lengthInfo));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (lengthInfo.Length.QuadPart <= 0) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    *DiskSizeBytes = (ULONGLONG)lengthInfo.Length.QuadPart;
    return STATUS_SUCCESS;
}

static
ULONG
DpUsbMetadataSafePartitionCount(
    _In_opt_ const DRIVE_LAYOUT_INFORMATION_EX *Layout,
    _In_ ULONG LayoutBytes
    )
{
    ULONG maxCount;

    if (Layout == NULL ||
        LayoutBytes < (ULONG)FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) {

        return 0;
    }

    maxCount = (LayoutBytes - (ULONG)FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) /
               sizeof(PARTITION_INFORMATION_EX);

    return Layout->PartitionCount < maxCount ? Layout->PartitionCount : maxCount;
}

static
NTSTATUS
DpUsbMetadataValidateTarget(
    _In_ const DP_USB_METADATA_WRITE_MESSAGE *Request,
    _In_opt_ const DRIVE_LAYOUT_INFORMATION_EX *Layout,
    _In_ ULONG LayoutBytes,
    _In_ ULONGLONG DiskSizeBytes,
    _Out_ PULONG PartitionCount
    )
{
    ULONGLONG metadataEnd;
    ULONG index;
    ULONG partitionCount = 0;

    if (Request->MetadataBytes != DP_USB_METADATA_BYTES ||
        Request->OffsetBytes >= DP_USB_METADATA_RESERVED_BYTES ||
        (Request->OffsetBytes % DP_USB_METADATA_SECTOR_BYTES) != 0 ||
        !DpUsbMetadataAddUlonglong(Request->OffsetBytes, DP_USB_METADATA_BYTES, &metadataEnd) ||
        metadataEnd > DP_USB_METADATA_RESERVED_BYTES ||
        metadataEnd > DiskSizeBytes) {

        return STATUS_INVALID_PARAMETER;
    }

    if (Layout != NULL) {
        partitionCount = DpUsbMetadataSafePartitionCount(Layout, LayoutBytes);
        for (index = 0; index < partitionCount; index++) {
            const PARTITION_INFORMATION_EX *partition = &Layout->PartitionEntry[index];
            ULONGLONG offset;
            ULONGLONG length;

            if (partition->PartitionLength.QuadPart <= 0) {
                continue;
            }

            offset = (ULONGLONG)partition->StartingOffset.QuadPart;
            length = (ULONGLONG)partition->PartitionLength.QuadPart;

            if (DpUsbMetadataRangeIntersects(Request->OffsetBytes,
                                             DP_USB_METADATA_BYTES,
                                             offset,
                                             length)) {

                return STATUS_CONFLICTING_ADDRESSES;
            }
        }
    }

    if (PartitionCount != NULL) {
        *PartitionCount = partitionCount;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpUsbMetadataReadExisting(
    _In_ HANDLE DiskHandle,
    _In_ ULONGLONG OffsetBytes,
    _Out_writes_bytes_(DP_USB_METADATA_BYTES) UCHAR *Buffer
    )
{
    LARGE_INTEGER byteOffset;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    byteOffset.QuadPart = (LONGLONG)OffsetBytes;
    RtlZeroMemory(Buffer, DP_USB_METADATA_BYTES);
    status = ZwReadFile(DiskHandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatus,
                        Buffer,
                        DP_USB_METADATA_BYTES,
                        &byteOffset,
                        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return ioStatus.Information == DP_USB_METADATA_BYTES ? STATUS_SUCCESS : STATUS_END_OF_FILE;
}

static
NTSTATUS
DpUsbMetadataWriteBlock(
    _In_ HANDLE DiskHandle,
    _In_ ULONGLONG OffsetBytes,
    _In_reads_bytes_(DP_USB_METADATA_BYTES) const UCHAR *Metadata
    )
{
    LARGE_INTEGER byteOffset;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    byteOffset.QuadPart = (LONGLONG)OffsetBytes;
    status = ZwWriteFile(DiskHandle,
                         NULL,
                         NULL,
                         NULL,
                         &ioStatus,
                         (PVOID)Metadata,
                         DP_USB_METADATA_BYTES,
                         &byteOffset,
                         NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return ioStatus.Information == DP_USB_METADATA_BYTES ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
DpUsbMetadataWrite(
    _In_ const DP_USB_METADATA_WRITE_MESSAGE *Request,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    UNICODE_STRING physicalPath;
    HANDLE diskHandle = NULL;
    PDRIVE_LAYOUT_INFORMATION_EX layout = NULL;
    ULONG layoutBytes = 0;
    ULONG partitionCount = 0;
    ULONGLONG diskSizeBytes = 0;
    UCHAR existing[DP_USB_METADATA_BYTES];
    NTSTATUS status;
    DP_USB_METADATA_WRITE_RESULT result;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;
    RtlZeroMemory(&result, sizeof(result));
    result.Version = DP_USB_METADATA_RESULT_VERSION;
    result.Status = (ULONG)STATUS_UNSUCCESSFUL;

    if (Request == NULL ||
        Request->Version != DP_USB_METADATA_MESSAGE_VERSION ||
        Request->MetadataBytes != DP_USB_METADATA_BYTES ||
        Request->Metadata[0] == 0) {

        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = DpUsbMetadataBuildPath(Request, &physicalPath);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpUsbMetadataOpenDisk(&physicalPath, &diskHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpUsbMetadataQueryLength(diskHandle, &diskSizeBytes);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpUsbMetadataQueryLayout(diskHandle, &layout, &layoutBytes);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpUsbMetadataValidateTarget(Request,
                                         layout,
                                         layoutBytes,
                                         diskSizeBytes,
                                         &partitionCount);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpUsbMetadataReadExisting(diskHandle,
                                       Request->OffsetBytes,
                                       existing);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (!DpUsbMetadataIsZeroBlock(existing) &&
        !DpUsbMetadataHasKnownMagic(existing)) {

        status = STATUS_OBJECT_NAME_COLLISION;
        goto Exit;
    }

    status = DpUsbMetadataWriteBlock(diskHandle,
                                     Request->OffsetBytes,
                                     Request->Metadata);

Exit:
    result.Status = (ULONG)status;
    result.PartitionCount = partitionCount;
    result.OffsetBytes = Request != NULL ? Request->OffsetBytes : 0;
    result.DiskSizeBytes = diskSizeBytes;

    if (layout != NULL) {
        ExFreePoolWithTag(layout, DP_TAG_USB_METADATA);
    }

    if (diskHandle != NULL) {
        ZwClose(diskHandle);
    }

    if (OutputBuffer != NULL && OutputBufferLength >= sizeof(result)) {
        RtlCopyMemory(OutputBuffer, &result, sizeof(result));
        *ReturnOutputBufferLength = sizeof(result);
    }

    return OutputBuffer != NULL && OutputBufferLength >= sizeof(result) ? STATUS_SUCCESS : status;
}
