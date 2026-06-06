/*++

Module Name:

    DpPolicy.c

Abstract:

    File protection policy and stream context management.

--*/

#include "DataProtector.h"

#define DP_SHADOW_SUFFIX       L":DataProtectorShadow"

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
    return DpProcessPolicyNameHasProtectedExtension(Name) &&
           !DpProcessPolicyNameIsExcluded(Name);
}

BOOLEAN
DpPolicyNameIsExcluded(
    _In_ PCUNICODE_STRING Name
    )
{
    return DpProcessPolicyNameIsExcluded(Name);
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
ULONG
DpPolicyFooterChecksum(
    _In_ const DP_PROTECTION_FOOTER *Footer
    )
{
    const UCHAR *bytes;
    ULONG checksum = 0;
    ULONG index;
    ULONG checksumOffset;

    if (Footer == NULL) {
        return 0;
    }

    bytes = (const UCHAR *)Footer;
    checksumOffset = FIELD_OFFSET(DP_PROTECTION_FOOTER, Checksum);

    for (index = 0; index < sizeof(DP_PROTECTION_FOOTER); index++) {
        if (index >= checksumOffset &&
            index < checksumOffset + sizeof(Footer->Checksum)) {
            continue;
        }

        checksum = ((checksum << 5) | (checksum >> 27)) + bytes[index];
    }

    return checksum == 0 ? DP_PROTECTION_MAGIC : checksum;
}

static
VOID
DpPolicyInitializeFooter(
    _Out_ PDP_PROTECTION_FOOTER Footer,
    _In_ LARGE_INTEGER LogicalSize
    )
{
    RtlZeroMemory(Footer, sizeof(*Footer));

    Footer->Magic = DP_PROTECTION_MAGIC;
    Footer->Version = DP_PROTECTION_FOOTER_VERSION;
    Footer->FooterSize = DP_PROTECTION_FOOTER_SIZE;
    Footer->LogicalSize = (ULONGLONG)LogicalSize.QuadPart;

    DpCryptoGetDefaultFileKey(Footer->FileKey, &Footer->KeyLength);
    Footer->Checksum = DpPolicyFooterChecksum(Footer);
}

static
BOOLEAN
DpPolicyValidateFooter(
    _In_ const DP_PROTECTION_FOOTER *Footer,
    _In_ LARGE_INTEGER PhysicalSize
    )
{
    LARGE_INTEGER maximumLogicalSize;

    if (Footer == NULL ||
        PhysicalSize.QuadPart < DP_PROTECTION_FOOTER_SIZE) {

        return FALSE;
    }

    if (Footer->Magic != DP_PROTECTION_MAGIC ||
        Footer->Version != DP_PROTECTION_FOOTER_VERSION ||
        Footer->FooterSize != DP_PROTECTION_FOOTER_SIZE ||
        Footer->KeyLength == 0 ||
        Footer->KeyLength > DP_FILE_KEY_LENGTH ||
        Footer->Checksum != DpPolicyFooterChecksum(Footer)) {

        return FALSE;
    }

    maximumLogicalSize.QuadPart = PhysicalSize.QuadPart - DP_PROTECTION_FOOTER_SIZE;

    if (Footer->LogicalSize != (ULONGLONG)maximumLogicalSize.QuadPart) {
        return FALSE;
    }

    return TRUE;
}

static
NTSTATUS
DpPolicyQueryFileSizeByObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLARGE_INTEGER EndOfFile
    )
{
    FILE_STANDARD_INFORMATION standardInfo;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    DpPolicyBeginInternalIo(&guard);

    status = FltQueryInformationFile(Instance,
                                     FileObject,
                                     &standardInfo,
                                     sizeof(standardInfo),
                                     FileStandardInformation,
                                     NULL);

    DpPolicyEndInternalIo(&guard);

    if (NT_SUCCESS(status)) {
        *EndOfFile = standardInfo.EndOfFile;
    }

    return status;
}

static
NTSTATUS
DpPolicySetFileSizeByObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ LARGE_INTEGER EndOfFile
    )
{
    FILE_END_OF_FILE_INFORMATION eofInfo;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    eofInfo.EndOfFile = EndOfFile;

    DpPolicyBeginInternalIo(&guard);

    status = FltSetInformationFile(Instance,
                                   FileObject,
                                   &eofInfo,
                                   sizeof(eofInfo),
                                   FileEndOfFileInformation);

    DpPolicyEndInternalIo(&guard);

    return status;
}

static
NTSTATUS
DpPolicyReadFooterByObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PDP_PROTECTION_FOOTER Footer,
    _Out_ PBOOLEAN IsProtected,
    _Out_opt_ PLARGE_INTEGER PhysicalSize
    )
{
    LARGE_INTEGER fileSize;
    LARGE_INTEGER offset;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    ULONG bytesRead = 0;
    NTSTATUS status;

    *IsProtected = FALSE;
    RtlZeroMemory(Footer, sizeof(*Footer));

    status = DpPolicyQueryFileSizeByObject(Instance, FileObject, &fileSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (PhysicalSize != NULL) {
        *PhysicalSize = fileSize;
    }

    if (fileSize.QuadPart < DP_PROTECTION_FOOTER_SIZE) {
        return STATUS_SUCCESS;
    }

    offset.QuadPart = fileSize.QuadPart - DP_PROTECTION_FOOTER_SIZE;

    DpPolicyBeginInternalIo(&guard);

    status = FltReadFile(Instance,
                         FileObject,
                         &offset,
                         sizeof(*Footer),
                         Footer,
                         FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                         &bytesRead,
                         NULL,
                         NULL);

    DpPolicyEndInternalIo(&guard);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (bytesRead == sizeof(*Footer) &&
        DpPolicyValidateFooter(Footer, fileSize)) {

        *IsProtected = TRUE;
    } else {
        RtlZeroMemory(Footer, sizeof(*Footer));
    }

    return STATUS_SUCCESS;
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
    DP_PROTECTION_FOOTER footer;

    return DpPolicyReadProtectionFooter(Instance, Name, &footer, IsProtected);
}

NTSTATUS
DpPolicyReadProtectionFooter(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PDP_PROTECTION_FOOTER Footer,
    _Out_ PBOOLEAN IsProtected
    )
{
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER physicalSize;
    NTSTATUS status;

    physicalSize.QuadPart = 0;

    if (Instance == NULL ||
        Name == NULL ||
        Name->Buffer == NULL ||
        Footer == NULL ||
        IsProtected == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    *IsProtected = FALSE;
    RtlZeroMemory(Footer, sizeof(*Footer));

    status = DpPolicyOpenFileByName(Instance,
                                    Name,
                                    FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                    FILE_ATTRIBUTE_NORMAL,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    FILE_OPEN,
                                    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                    &fileHandle,
                                    &fileObject,
                                    &ioStatus);

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_NO_SUCH_FILE ||
            status == STATUS_NOT_FOUND) {

            DP_TRACE_PPTX_NAME("FooterMissing",
                               Name,
                               status,
                               0,
                               0,
                               0,
                               0);
            return STATUS_SUCCESS;
        }

        DP_TRACE_PPTX_NAME("FooterOpenFailed",
                           Name,
                           status,
                           0,
                           0,
                           0,
                           0);
        return status;
    }

    status = DpPolicyReadFooterByObject(Instance,
                                        fileObject,
                                        Footer,
                                        IsProtected,
                                        &physicalSize);

    DP_TRACE_PPTX_NAME("FooterRead",
                       Name,
                       status,
                       *IsProtected,
                       physicalSize.QuadPart,
                       Footer->LogicalSize,
                       Footer->KeyLength);

    DpPolicyCloseFile(fileHandle, fileObject);

    return status;
}

NTSTATUS
DpPolicyWriteProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name
    )
{
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    DP_PROTECTION_FOOTER existingFooter;
    DP_PROTECTION_FOOTER footer;
    BOOLEAN isProtected = FALSE;
    LARGE_INTEGER physicalSize;
    LARGE_INTEGER logicalSize;
    LARGE_INTEGER footerOffset;
    LARGE_INTEGER finalSize;
    ULONG bytesWritten = 0;
    DP_POLICY_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    if (Instance == NULL || Name == NULL || Name->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpPolicyOpenFileByName(Instance,
                                    Name,
                                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                    FILE_ATTRIBUTE_NORMAL,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    FILE_OPEN,
                                    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                    &fileHandle,
                                    &fileObject,
                                    &ioStatus);

    if (!NT_SUCCESS(status)) {
        DP_TRACE_PPTX_NAME("FooterWriteOpenFailed",
                           Name,
                           status,
                           0,
                           0,
                           0,
                           0);
        return status;
    }

    status = DpPolicyReadFooterByObject(Instance,
                                        fileObject,
                                        &existingFooter,
                                        &isProtected,
                                        &physicalSize);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (isProtected) {
        logicalSize.QuadPart = (LONGLONG)existingFooter.LogicalSize;
        footerOffset = logicalSize;
    } else {
        logicalSize = physicalSize;
        footerOffset = physicalSize;
    }

    DpPolicyInitializeFooter(&footer, logicalSize);

    DpPolicyBeginInternalIo(&guard);

    status = FltWriteFile(Instance,
                          fileObject,
                          &footerOffset,
                          sizeof(footer),
                          &footer,
                          FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                          &bytesWritten,
                          NULL,
                          NULL);

    DpPolicyEndInternalIo(&guard);

    if (NT_SUCCESS(status) && bytesWritten != sizeof(footer)) {
        status = STATUS_DISK_FULL;
    }

    if (NT_SUCCESS(status)) {
        finalSize.QuadPart = logicalSize.QuadPart + DP_PROTECTION_FOOTER_SIZE;
        status = DpPolicySetFileSizeByObject(Instance, fileObject, finalSize);
    }

    DP_TRACE_PPTX_NAME("FooterWrite",
                       Name,
                       status,
                       logicalSize.QuadPart,
                       bytesWritten,
                       isProtected,
                       footer.KeyLength);

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, fileObject);
    }

Exit:
    DpPolicyCloseFile(fileHandle, fileObject);

    return status;
}

NTSTATUS
DpPolicyGetFileLogicalSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLARGE_INTEGER LogicalSize,
    _Out_opt_ PBOOLEAN IsProtected
    )
{
    DP_PROTECTION_FOOTER footer;
    LARGE_INTEGER physicalSize;
    BOOLEAN isProtected = FALSE;
    NTSTATUS status;

    if (LogicalSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    LogicalSize->QuadPart = 0;
    if (IsProtected != NULL) {
        *IsProtected = FALSE;
    }

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpPolicyReadFooterByObject(Instance,
                                        FileObject,
                                        &footer,
                                        &isProtected,
                                        &physicalSize);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (isProtected) {
        LogicalSize->QuadPart = (LONGLONG)footer.LogicalSize;
    } else {
        *LogicalSize = physicalSize;
    }

    if (IsProtected != NULL) {
        *IsProtected = isProtected;
    }

    return STATUS_SUCCESS;
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
    DP_PROTECTION_FOOTER footer;
    BOOLEAN isProtected = FALSE;
    BOOLEAN markerPresent = FALSE;
    LARGE_INTEGER logicalSize;

    PAGED_CODE();

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&footer, sizeof(footer));
    logicalSize.QuadPart = 0;

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (DpPolicyNameIsProtected(&nameInfo->Name) &&
        !DpPolicyNameIsShadow(&nameInfo->Name)) {

        status = DpPolicyReadProtectionFooter(FltObjects->Instance,
                                              &nameInfo->Name,
                                              &footer,
                                              &markerPresent);
        if (NT_SUCCESS(status)) {
            isProtected = markerPresent;
            if (markerPresent) {
                logicalSize.QuadPart = (LONGLONG)footer.LogicalSize;
            }
        }
    }

    DP_TRACE_PPTX_NAME("RefreshStream",
                       &nameInfo->Name,
                       status,
                       isProtected,
                       markerPresent,
                       0,
                       0);

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
    if (isProtected && markerPresent) {
        streamContext->LogicalSize = logicalSize;
        streamContext->FileKeyLength = footer.KeyLength;
        RtlCopyMemory(streamContext->FileKey,
                      footer.FileKey,
                      min(footer.KeyLength, (ULONG)DP_FILE_KEY_LENGTH));
    } else {
        DpCryptoGetDefaultFileKey(streamContext->FileKey,
                                  &streamContext->FileKeyLength);
    }

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
    DpCryptoGetDefaultFileKey(streamContext->FileKey,
                              &streamContext->FileKeyLength);

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
