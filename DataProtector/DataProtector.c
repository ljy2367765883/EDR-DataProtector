/*++

Module Name:

    DataProtector.c

Abstract:

    Driver entry, filter registration and instance lifecycle for the
    DataProtector transparent encryption minifilter.

--*/

#include "DataProtector.h"

PFLT_FILTER gDataProtectorFilter = NULL;
ULONG gDataProtectorTraceFlags = 0;

CONST FLT_CONTEXT_REGISTRATION Contexts[] = {

    { FLT_STREAM_CONTEXT,
      0,
      DpStreamContextCleanup,
      sizeof(DP_STREAM_CONTEXT),
      DP_TAG_STREAM_CONTEXT,
      NULL,
      NULL,
      NULL },

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      DpHandleContextCleanup,
      sizeof(DP_HANDLE_CONTEXT),
      DP_TAG_HANDLE_CONTEXT,
      NULL,
      NULL,
      NULL },

    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      DpPreCreate,
      DpPostCreate },

    { IRP_MJ_READ,
      0,
      DpPreRead,
      DpPostRead },

    { IRP_MJ_WRITE,
      0,
      DpPreWrite,
      DpPostWrite },

    { IRP_MJ_SET_INFORMATION,
      0,
      DpPreSetInformation,
      DpPostSetInformation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      DpPreQueryInformation,
      DpPostQueryInformation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      DpPreDirectoryControl,
      DpPostDirectoryControl },

    { IRP_MJ_CLEANUP,
      0,
      DpPreCleanup,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      DpPreAcquireForSectionSynchronization,
      NULL },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      DpPreFastIoCheckIfPossible,
      NULL },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,

    Contexts,
    Callbacks,

#if DP_ALLOW_MANUAL_UNLOAD
    DataProtectorUnload,
#else
    NULL,
#endif

    DataProtectorInstanceSetup,
    DataProtectorInstanceQueryTeardown,
    DataProtectorInstanceTeardownStart,
    DataProtectorInstanceTeardownComplete,

    NULL,
    NULL,
    NULL,
    NULL
};

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DataProtectorUnload)
#pragma alloc_text(PAGE, DataProtectorInstanceQueryTeardown)
#pragma alloc_text(PAGE, DataProtectorInstanceSetup)
#pragma alloc_text(PAGE, DataProtectorInstanceTeardownStart)
#pragma alloc_text(PAGE, DataProtectorInstanceTeardownComplete)
#endif

NTSTATUS
DataProtectorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    switch (VolumeFilesystemType) {
    case FLT_FSTYPE_NPFS:
    case FLT_FSTYPE_MSFS:
        return STATUS_SUCCESS;

    default:
        break;
    }

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        VolumeDeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM) {

        return STATUS_FLT_DO_NOT_ATTACH;
    }

    switch (VolumeFilesystemType) {
    case FLT_FSTYPE_NTFS:
    case FLT_FSTYPE_REFS:
    case FLT_FSTYPE_FAT:
    case FLT_FSTYPE_EXFAT:
        return STATUS_SUCCESS;

    default:
        return STATUS_FLT_DO_NOT_ATTACH;
    }
}

NTSTATUS
DataProtectorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    return STATUS_SUCCESS;
}

VOID
DataProtectorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();
}

VOID
DataProtectorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    if (FltObjects != NULL) {
        DpHashProtectForgetVolume(FltObjects->Volume);
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    DpShadowInitialize();

    status = DpThreatEngineInitialize();
    if (!NT_SUCCESS(status)) {
        DpShadowUninitialize();
        return status;
    }

    status = DpProcessPolicyInitialize(RegistryPath);
    if (!NT_SUCCESS(status)) {
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpCryptoInitialize(RegistryPath);
    if (!NT_SUCCESS(status)) {
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpWebShellInitialize();
    if (!NT_SUCCESS(status)) {
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpFileHunterInitialize();
    if (!NT_SUCCESS(status)) {
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpDeviceControlInitialize();
    if (!NT_SUCCESS(status)) {
        DpFileHunterUninitialize();
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpLateralDefenseInitialize();
    if (!NT_SUCCESS(status)) {
        DpDeviceControlUninitialize();
        DpFileHunterUninitialize();
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpHashProtectInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DpLateralDefenseUninitialize();
        DpDeviceControlUninitialize();
        DpFileHunterUninitialize();
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = DpUserHookDefenseInitialize();
    if (!NT_SUCCESS(status)) {
        DpHashProtectUninitialize();
        DpLateralDefenseUninitialize();
        DpDeviceControlUninitialize();
        DpFileHunterUninitialize();
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
        return status;
    }

    status = FltRegisterFilter(DriverObject,
                               &FilterRegistration,
                               &gDataProtectorFilter);

    if (NT_SUCCESS(status)) {

        status = FltStartFiltering(gDataProtectorFilter);

        if (!NT_SUCCESS(status)) {
            FltUnregisterFilter(gDataProtectorFilter);
            gDataProtectorFilter = NULL;
        }
    }

    if (NT_SUCCESS(status)) {
        status = DpControlInitialize();
        if (!NT_SUCCESS(status)) {
            FltUnregisterFilter(gDataProtectorFilter);
            gDataProtectorFilter = NULL;
        }
    }

    if (NT_SUCCESS(status)) {
        NTSTATUS netStatus = DpNetFilterInitialize(DriverObject);
        if (!NT_SUCCESS(netStatus)) {
            DP_DBG_PRINT(DP_TRACE_POLICY,
                         ("DataProtector!DriverEntry: network filter initialization failed 0x%08X\n",
                          netStatus));
        }
    }

    if (!NT_SUCCESS(status)) {
        DpUserHookDefenseUninitialize();
        DpHashProtectUninitialize();
        DpLateralDefenseUninitialize();
        DpDeviceControlUninitialize();
        DpFileHunterUninitialize();
        DpWebShellUninitialize();
        DpCryptoUninitialize();
        DpProcessPolicyUninitialize();
        DpThreatEngineUninitialize();
        DpShadowUninitialize();
    }

    return status;
}

NTSTATUS
DataProtectorUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DpNetFilterUninitialize();

    DpControlUninitialize();

    DpUserHookDefenseUninitialize();

    DpHashProtectUninitialize();

    DpLateralDefenseUninitialize();

    DpDeviceControlUninitialize();

    DpFileHunterUninitialize();

    DpWebShellUninitialize();

    if (gDataProtectorFilter != NULL) {
        FltUnregisterFilter(gDataProtectorFilter);
        gDataProtectorFilter = NULL;
    }

    DpCryptoUninitialize();
    DpProcessPolicyUninitialize();
    DpThreatEngineUninitialize();
    DpShadowUninitialize();

    return STATUS_SUCCESS;
}
