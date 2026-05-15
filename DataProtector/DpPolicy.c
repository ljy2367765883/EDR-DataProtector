/*++

Module Name:

    DpPolicy.c

Abstract:

    File protection policy and stream context management.

--*/

#include "DataProtector.h"

#define DP_SHADOW_SUFFIX       L":DataProtectorShadow"
#define DP_PROTECTION_MARKER   L":DataProtectorMeta"
#define DP_PROTECTION_MAGIC    0x50445044u

typedef struct _DP_POLICY_INTERNAL_IO_GUARD {
    PVOID PreviousTopLevelIrp;
} DP_POLICY_INTERNAL_IO_GUARD, *PDP_POLICY_INTERNAL_IO_GUARD;

static
VOID
DpPolicyBeginInternalIo(
    _Out_ PDP_POLICY_INTERNAL_IO_GUARD Guard
    )
{
    Guard->PreviousTopLevelIrp = IoGetTopLevelIrp();
    IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
}

static
VOID
DpPolicyEndInternalIo(
    _In_ PDP_POLICY_INTERNAL_IO_GUARD Guard
    )
{
    IoSetTopLevelIrp((PIRP)Guard->PreviousTopLevelIrp);
}

BOOLEAN
DpPolicyNameIsProtected(
    _In_ PCUNICODE_STRING Name
    )
{
    return DpProcessPolicyNameHasProtectedExtension(Name);
}

BOOLEAN
DpPolicyNameIsShadow(
    _In_ PCUNICODE_STRING Name
    )
{
    UNICODE_STRING shadowSuffix;
    UNICODE_STRING suffix;

    if (Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length < sizeof(DP_SHADOW_SUFFIX) - sizeof(WCHAR)) {

        return FALSE;
    }

    RtlInitUnicodeString(&shadowSuffix, DP_SHADOW_SUFFIX);

    suffix.Buffer = (PWCH)((PUCHAR)Name->Buffer + Name->Length - shadowSuffix.Length);
    suffix.Length = shadowSuffix.Length;
    suffix.MaximumLength = shadowSuffix.Length;

    return RtlEqualUnicodeString(&suffix, &shadowSuffix, TRUE);
}

static
NTSTATUS
DpPolicyBuildMarkerName(
    _In_ PCUNICODE_STRING Name,
    _Out_ PUNICODE_STRING MarkerName
    )
{
    UNICODE_STRING suffix;

    MarkerName->Buffer = NULL;
    MarkerName->Length = 0;
    MarkerName->MaximumLength = 0;

    if (Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length == 0 ||
        Name->Length > MAXUSHORT - (sizeof(DP_PROTECTION_MARKER) - sizeof(WCHAR))) {

        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&suffix, DP_PROTECTION_MARKER);

    MarkerName->Length = Name->Length + suffix.Length;
    MarkerName->MaximumLength = MarkerName->Length;
    MarkerName->Buffer = ExAllocatePoolWithTag(PagedPool,
                                               MarkerName->MaximumLength,
                                               DP_TAG_NAME_BUFFER);

    if (MarkerName->Buffer == NULL) {
        MarkerName->Length = 0;
        MarkerName->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(MarkerName->Buffer, Name->Buffer, Name->Length);
    RtlCopyMemory((PUCHAR)MarkerName->Buffer + Name->Length,
                  suffix.Buffer,
                  suffix.Length);

    return STATUS_SUCCESS;
}

static
VOID
DpPolicyFreeMarkerName(
    _Inout_ PUNICODE_STRING MarkerName
    )
{
    if (MarkerName->Buffer != NULL) {
        ExFreePoolWithTag(MarkerName->Buffer, DP_TAG_NAME_BUFFER);
        MarkerName->Buffer = NULL;
    }

    MarkerName->Length = 0;
    MarkerName->MaximumLength = 0;
}

static
NTSTATUS
DpPolicyOpenFileByName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _Out_ PHANDLE FileHandle,
    _Outptr_result_maybenull_ PFILE_OBJECT *FileObject,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    *FileHandle = NULL;
    *FileObject = NULL;

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    DpPolicyBeginInternalIo(&guard);

    status = FltCreateFileEx2(gDataProtectorFilter,
                              Instance,
                              FileHandle,
                              FileObject,
                              DesiredAccess,
                              &objectAttributes,
                              IoStatusBlock,
                              NULL,
                              FileAttributes,
                              ShareAccess,
                              CreateDisposition,
                              CreateOptions,
                              NULL,
                              0,
                              IO_IGNORE_SHARE_ACCESS_CHECK,
                              NULL);

    DpPolicyEndInternalIo(&guard);

    return status;
}

static
VOID
DpPolicyCloseFile(
    _In_opt_ HANDLE FileHandle,
    _In_opt_ PFILE_OBJECT FileObject
    )
{
    if (FileObject != NULL) {
        ObDereferenceObject(FileObject);
    }

    if (FileHandle != NULL) {
        FltClose(FileHandle);
    }
}

NTSTATUS
DpPolicyFileHasProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PBOOLEAN IsProtected
    )
{
    UNICODE_STRING markerName;
    HANDLE markerHandle = NULL;
    PFILE_OBJECT markerFileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    ULONG magic = 0;
    ULONG bytesRead = 0;
    LARGE_INTEGER offset;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    *IsProtected = FALSE;

    if (Instance == NULL || Name == NULL || Name->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpPolicyBuildMarkerName(Name, &markerName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpPolicyOpenFileByName(Instance,
                                    &markerName,
                                    FILE_READ_DATA | SYNCHRONIZE,
                                    FILE_ATTRIBUTE_NORMAL,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    FILE_OPEN,
                                    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                    &markerHandle,
                                    &markerFileObject,
                                    &ioStatus);

    if (!NT_SUCCESS(status)) {
        DpPolicyFreeMarkerName(&markerName);

        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_NO_SUCH_FILE ||
            status == STATUS_NOT_FOUND) {

            return STATUS_SUCCESS;
        }

        return status;
    }

    offset.QuadPart = 0;
    DpPolicyBeginInternalIo(&guard);

    status = FltReadFile(Instance,
                         markerFileObject,
                         &offset,
                         sizeof(magic),
                         &magic,
                         FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                         &bytesRead,
                         NULL,
                         NULL);

    DpPolicyEndInternalIo(&guard);

    if (NT_SUCCESS(status) && bytesRead == sizeof(magic) && magic == DP_PROTECTION_MAGIC) {
        *IsProtected = TRUE;
    }

    DpPolicyCloseFile(markerHandle, markerFileObject);
    DpPolicyFreeMarkerName(&markerName);

    return status;
}

NTSTATUS
DpPolicyWriteProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name
    )
{
    UNICODE_STRING markerName;
    HANDLE markerHandle = NULL;
    PFILE_OBJECT markerFileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    ULONG magic = DP_PROTECTION_MAGIC;
    ULONG bytesWritten = 0;
    LARGE_INTEGER offset;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    if (Instance == NULL || Name == NULL || Name->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpPolicyBuildMarkerName(Name, &markerName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpPolicyOpenFileByName(Instance,
                                    &markerName,
                                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    FILE_OVERWRITE_IF,
                                    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                    &markerHandle,
                                    &markerFileObject,
                                    &ioStatus);

    if (!NT_SUCCESS(status)) {
        DpPolicyFreeMarkerName(&markerName);
        return status;
    }

    offset.QuadPart = 0;
    DpPolicyBeginInternalIo(&guard);

    status = FltWriteFile(Instance,
                          markerFileObject,
                          &offset,
                          sizeof(magic),
                          &magic,
                          FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                          &bytesWritten,
                          NULL,
                          NULL);

    DpPolicyEndInternalIo(&guard);

    if (NT_SUCCESS(status) && bytesWritten != sizeof(magic)) {
        status = STATUS_DISK_FULL;
    }

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, markerFileObject);
    }

    DpPolicyCloseFile(markerHandle, markerFileObject);
    DpPolicyFreeMarkerName(&markerName);

    return status;
}

NTSTATUS
DpPolicyRefreshStreamContext(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDP_STREAM_CONTEXT streamContext = NULL;
    PFLT_CONTEXT oldContext = NULL;
    BOOLEAN isProtected = FALSE;
    BOOLEAN markerPresent = FALSE;

    PAGED_CODE();

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (DpPolicyNameIsProtected(&nameInfo->Name) &&
        !DpPolicyNameIsShadow(&nameInfo->Name)) {

        status = DpPolicyFileHasProtectionMarker(FltObjects->Instance,
                                                 &nameInfo->Name,
                                                 &markerPresent);
        if (NT_SUCCESS(status)) {
            isProtected = markerPresent;
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    status = FltAllocateContext(gDataProtectorFilter,
                                FLT_STREAM_CONTEXT,
                                sizeof(DP_STREAM_CONTEXT),
                                NonPagedPoolNx,
                                &streamContext);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(streamContext, sizeof(DP_STREAM_CONTEXT));
    streamContext->IsProtected = isProtected;
    streamContext->PlaintextCacheEnabled = FALSE;

    status = FltSetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                 streamContext,
                                 &oldContext);

    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
    }

    FltReleaseContext(streamContext);

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        status = STATUS_SUCCESS;
    }

    return status;
}

NTSTATUS
DpPolicyEnablePlaintextCache(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
#if DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO
    NTSTATUS status;
    PDP_STREAM_CONTEXT streamContext = NULL;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 &streamContext);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    streamContext->PlaintextCacheEnabled = TRUE;

    FltReleaseContext(streamContext);

    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(FltObjects);

    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS
DpPolicyIsPlaintextCacheEnabled(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN PlaintextCacheEnabled
    )
{
    *PlaintextCacheEnabled = FALSE;

#if !DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO
    UNREFERENCED_PARAMETER(FltObjects);

    return STATUS_SUCCESS;
#else
    NTSTATUS status;
    PDP_STREAM_CONTEXT streamContext = NULL;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 &streamContext);

    if (NT_SUCCESS(status)) {
        *PlaintextCacheEnabled = streamContext->PlaintextCacheEnabled;
        FltReleaseContext(streamContext);
        return STATUS_SUCCESS;
    }

    if (status == STATUS_NOT_FOUND) {
        return STATUS_SUCCESS;
    }

    return status;
#endif
}

NTSTATUS
DpPolicyIsProtectedStream(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected
    )
{
    NTSTATUS status;
    PDP_STREAM_CONTEXT streamContext = NULL;

    *IsProtected = FALSE;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 &streamContext);

    if (NT_SUCCESS(status)) {
        *IsProtected = streamContext->IsProtected;
        FltReleaseContext(streamContext);
        return STATUS_SUCCESS;
    }

    if (status == STATUS_NOT_FOUND) {
        return STATUS_SUCCESS;
    }

    return status;
}

NTSTATUS
DpPolicySetStreamProtection(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IsProtected
    )
{
    NTSTATUS status;
    PDP_STREAM_CONTEXT streamContext = NULL;
    PFLT_CONTEXT oldContext = NULL;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltAllocateContext(gDataProtectorFilter,
                                FLT_STREAM_CONTEXT,
                                sizeof(DP_STREAM_CONTEXT),
                                NonPagedPoolNx,
                                &streamContext);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(streamContext, sizeof(DP_STREAM_CONTEXT));
    streamContext->IsProtected = IsProtected;
    streamContext->PlaintextCacheEnabled = FALSE;

    status = FltSetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                 streamContext,
                                 &oldContext);

    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
    }

    FltReleaseContext(streamContext);

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        status = STATUS_SUCCESS;
    }

    return status;
}

VOID
DpStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

VOID
DpHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    PDP_HANDLE_CONTEXT handleContext = (PDP_HANDLE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (handleContext->OriginalName.Buffer != NULL) {
        ExFreePoolWithTag(handleContext->OriginalName.Buffer, DP_TAG_NAME_BUFFER);
        handleContext->OriginalName.Buffer = NULL;
        handleContext->OriginalName.Length = 0;
        handleContext->OriginalName.MaximumLength = 0;
    }

    if (handleContext->ShadowName.Buffer != NULL) {
        ExFreePoolWithTag(handleContext->ShadowName.Buffer, DP_TAG_NAME_BUFFER);
        handleContext->ShadowName.Buffer = NULL;
        handleContext->ShadowName.Length = 0;
        handleContext->ShadowName.MaximumLength = 0;
    }

    if (handleContext->PendingName.Buffer != NULL) {
        ExFreePoolWithTag(handleContext->PendingName.Buffer, DP_TAG_NAME_BUFFER);
        handleContext->PendingName.Buffer = NULL;
        handleContext->PendingName.Length = 0;
        handleContext->PendingName.MaximumLength = 0;
    }
}

NTSTATUS
DpGetHandleTrust(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected,
    _Out_ PBOOLEAN IsTrusted
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;

    *IsProtected = FALSE;
    *IsTrusted = FALSE;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetStreamHandleContext(FltObjects->Instance,
                                       FltObjects->FileObject,
                                       &handleContext);

    if (NT_SUCCESS(status)) {
        *IsProtected = handleContext->IsProtected;
        *IsTrusted = handleContext->IsTrusted;
        FltReleaseContext(handleContext);
        return STATUS_SUCCESS;
    }

    if (status == STATUS_NOT_FOUND) {
        return DpPolicyIsProtectedStream(FltObjects, IsProtected);
    }

    return status;
}

NTSTATUS
DpGetHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PDP_HANDLE_CONTEXT *HandleContext
    )
{
    if (HandleContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HandleContext = NULL;

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return FltGetStreamHandleContext(FltObjects->Instance,
                                     FltObjects->FileObject,
                                     HandleContext);
}

VOID
DpReleaseHandleContext(
    _In_opt_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    if (HandleContext != NULL) {
        FltReleaseContext(HandleContext);
    }
}
