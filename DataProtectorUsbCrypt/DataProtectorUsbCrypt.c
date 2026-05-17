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
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_SESSION_STATE, *PDPUSB_SESSION_STATE;

static PDEVICE_OBJECT gDpUsbDeviceObject = NULL;
static UNICODE_STRING gDpUsbDosName;
static DPUSB_SESSION_STATE gDpUsbSession;

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
DpUsbOpenSession(
    _In_ PDPUSB_OPEN_SESSION Request
    )
{
    if (Request == NULL ||
        Request->Version != 1 ||
        Request->Algorithm != DPUSB_ALGORITHM_RC4 ||
        Request->KeyLength == 0 ||
        Request->KeyLength > DPUSB_MAX_KEY_BYTES ||
        Request->ToolAreaBytes < DPUSB_MIN_TOOL_BYTES ||
        Request->DataOffsetBytes < Request->ToolAreaBytes) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&gDpUsbSession.Lock);
    gDpUsbSession.SessionOpen = TRUE;
    gDpUsbSession.Algorithm = Request->Algorithm;
    gDpUsbSession.ToolAreaBytes = Request->ToolAreaBytes;
    gDpUsbSession.DataOffsetBytes = Request->DataOffsetBytes;
    gDpUsbSession.DataLengthBytes = Request->DataLengthBytes;
    gDpUsbSession.KeyLength = Request->KeyLength;
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
    RtlStringCchCopyW(Status->DeviceId,
                      RTL_NUMBER_OF(Status->DeviceId),
                      gDpUsbSession.DeviceId);
    ExReleasePushLockShared(&gDpUsbSession.Lock);

    *BytesReturned = sizeof(*Status);
    return STATUS_SUCCESS;
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
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DpUsbDeviceControl;
    DriverObject->DriverUnload = DpUsbUnload;

    gDpUsbDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
