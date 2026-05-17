#pragma once

#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <ntddstor.h>
#include <ntstrsafe.h>

#define DPUSB_DEVICE_NAME L"\\Device\\DataProtectorUsbCrypt"
#define DPUSB_DOS_DEVICE_NAME L"\\DosDevices\\DataProtectorUsbCrypt"

#define DPUSB_TAG_STATE 'sUpD'
#define DPUSB_TAG_TEXT  'tUpD'
#define DPUSB_TAG_IO    'iUpD'

#define DPUSB_IOCTL_INDEX 0x900
#define IOCTL_DPUSB_QUERY_STATUS CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DPUSB_OPEN_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DPUSB_CLOSE_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 2, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define DPUSB_MAX_DEVICE_ID_CHARS 260
#define DPUSB_MAX_KEY_BYTES 64
#define DPUSB_ALGORITHM_RC4 1
#define DPUSB_METADATA_RESERVED_BYTES (2ull * 1024ull * 1024ull)
#define DPUSB_MIN_TOOL_BYTES (5ull * 1024ull * 1024ull)
#define DPUSB_DATA_OFFSET_BYTES (DPUSB_METADATA_RESERVED_BYTES + DPUSB_MIN_TOOL_BYTES)
#define DPUSB_HEADER_SIGNATURE 'CPUDP001'

typedef struct _DPUSB_OPEN_SESSION {
    ULONG Version;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    ULONG KeyLength;
    WCHAR PhysicalDrivePath[128];
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_OPEN_SESSION, *PDPUSB_OPEN_SESSION;

typedef struct _DPUSB_STATUS {
    ULONG Version;
    BOOLEAN SessionOpen;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    WCHAR PhysicalDrivePath[128];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_STATUS, *PDPUSB_STATUS;

typedef struct _DPUSB_RC4_STATE {
    UCHAR S[256];
    UCHAR I;
    UCHAR J;
} DPUSB_RC4_STATE, *PDPUSB_RC4_STATE;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DpUsbUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH DpUsbCreateClose;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DpUsbCreateClose;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH DpUsbCreateClose;

_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS)
DRIVER_DISPATCH DpUsbFlushBuffers;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DpUsbDeviceControl;

_Dispatch_type_(IRP_MJ_READ)
DRIVER_DISPATCH DpUsbReadWrite;

_Dispatch_type_(IRP_MJ_WRITE)
DRIVER_DISPATCH DpUsbReadWrite;

VOID
DpUsbRc4Initialize(
    _Out_ PDPUSB_RC4_STATE State,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    );

VOID
DpUsbRc4Apply(
    _Inout_ PDPUSB_RC4_STATE State,
    _Inout_updates_bytes_(Length) UCHAR *Buffer,
    _In_ ULONG Length
    );

VOID
DpUsbRc4CryptAtOffset(
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR *Buffer,
    _In_ ULONG Length
    );
