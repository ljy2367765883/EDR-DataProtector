/*++

Module Name:

    DpIo.c

Abstract:

    Transparent read/write encryption callbacks. Protected streams use a
    swap buffer so the file system sees ciphertext while callers see
    plaintext.

--*/

#include "DataProtector.h"

static
BOOLEAN
DpIsPagingIo(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    return BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO);
}

static
BOOLEAN
DpCanProcessOperation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Length
    )
{
    UNREFERENCED_PARAMETER(Data);

    if (Length == 0 ||
        FltObjects->FileObject == NULL ||
        FltObjects->FileObject->FsContext == NULL) {

        return FALSE;
    }

    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return FALSE;
    }

    return TRUE;
}

static
PVOID
DpGetSystemBufferAddress(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PMDL MdlAddress,
    _In_opt_ PVOID Buffer
    )
{
    if (MdlAddress != NULL) {
        return MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    }

    if (Buffer == NULL) {
        return NULL;
    }

    if (Data->RequestorMode == KernelMode) {
        return Buffer;
    }

    return NULL;
}

typedef struct _DP_RENAME_CONTEXT {
    BOOLEAN EncryptAfterRename;
    PFLT_FILE_NAME_INFORMATION TargetNameInfo;
} DP_RENAME_CONTEXT, *PDP_RENAME_CONTEXT;

static
NTSTATUS
DpDuplicateName(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    )
{
    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination->Buffer = ExAllocatePoolWithTag(PagedPool,
                                                Source->Length,
                                                DP_TAG_NAME_BUFFER);

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;
    Destination->MaximumLength = Source->Length;

    return STATUS_SUCCESS;
}

static
VOID
DpFreeName(
    _Inout_ PUNICODE_STRING Name
    )
{
    if (Name->Buffer != NULL) {
        ExFreePoolWithTag(Name->Buffer, DP_TAG_NAME_BUFFER);
        Name->Buffer = NULL;
    }

    Name->Length = 0;
    Name->MaximumLength = 0;
}

static
BOOLEAN
DpCreateDispositionWillReplaceFile(
    _In_ ULONG CreateDisposition
    )
{
    return CreateDisposition == FILE_CREATE ||
           CreateDisposition == FILE_OVERWRITE ||
           CreateDisposition == FILE_OVERWRITE_IF ||
           CreateDisposition == FILE_SUPERSEDE;
}

static
NTSTATUS
DpMarkHandleEncryptOnCleanup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PCUNICODE_STRING PendingName,
    _In_ BOOLEAN IsTrusted,
    _In_ BOOLEAN CreateContextIfMissing
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PFLT_CONTEXT oldContext = NULL;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (status == STATUS_NOT_FOUND) {
        if (!CreateContextIfMissing) {
            return STATUS_SUCCESS;
        }

        status = FltAllocateContext(gDataProtectorFilter,
                                    FLT_STREAMHANDLE_CONTEXT,
                                    sizeof(DP_HANDLE_CONTEXT),
                                    NonPagedPoolNx,
                                    &handleContext);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlZeroMemory(handleContext, sizeof(DP_HANDLE_CONTEXT));

        status = FltSetStreamHandleContext(FltObjects->Instance,
                                           FltObjects->FileObject,
                                           FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                           handleContext,
                                           &oldContext);

        if (oldContext != NULL) {
            FltReleaseContext(oldContext);
        }

        if (!NT_SUCCESS(status)) {
            FltReleaseContext(handleContext);
            return status == STATUS_FLT_CONTEXT_ALREADY_DEFINED ? STATUS_SUCCESS : status;
        }
    } else if (!NT_SUCCESS(status) || handleContext == NULL) {
        return status;
    }

    if (handleContext->IsShadow) {
        DpReleaseHandleContext(handleContext);
        return STATUS_SUCCESS;
    }

    handleContext->EncryptOnCleanup = TRUE;
    handleContext->IsTrusted = IsTrusted;

    if (PendingName != NULL && PendingName->Buffer != NULL) {
        DpFreeName(&handleContext->PendingName);
        status = DpDuplicateName(PendingName, &handleContext->PendingName);
    } else {
        status = STATUS_SUCCESS;
    }

    DpReleaseHandleContext(handleContext);

    return status;
}

static
NTSTATUS
DpFinalizeEncryptOnCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    NTSTATUS status;
    NTSTATUS markerStatus;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PCUNICODE_STRING finalName = NULL;

    if (HandleContext == NULL || !HandleContext->EncryptOnCleanup) {
        return STATUS_SUCCESS;
    }

    if (FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (HandleContext->PendingName.Buffer != NULL) {
        finalName = &HandleContext->PendingName;
    } else {
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        finalName = &nameInfo->Name;
    }

    if (!DpPolicyNameIsProtected(finalName) || DpPolicyNameIsShadow(finalName)) {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    (VOID)FltFlushBuffers(FltObjects->Instance, FltObjects->FileObject);

    status = DpShadowEncryptFileObjectInPlace(FltObjects->Instance,
                                              FltObjects->FileObject);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    markerStatus = DpPolicyWriteProtectionMarker(FltObjects->Instance,
                                                 finalName);
    if (!NT_SUCCESS(markerStatus)) {
        status = markerStatus;
        goto Exit;
    }

    (VOID)DpPolicySetStreamProtection(FltObjects, TRUE);
    HandleContext->IsProtected = TRUE;
    HandleContext->EncryptOnCleanup = FALSE;

Exit:
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    return status;
}

static
BOOLEAN
DpIsRenameInformationClass(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    switch (InformationClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileRenameInformationBypassAccessCheck:
    case FileRenameInformationExBypassAccessCheck:
        return TRUE;

    default:
        return FALSE;
    }
}

static
NTSTATUS
DpGetRenameTargetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION *TargetNameInfo
    )
{
    NTSTATUS status;
    PFILE_RENAME_INFORMATION renameInfo;
    HANDLE rootDirectory;

    *TargetNameInfo = NULL;

    if (FltObjects->FileObject == NULL ||
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
        Data->Iopb->Parameters.SetFileInformation.Length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) {

        return STATUS_INVALID_PARAMETER;
    }

    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (renameInfo->FileNameLength == 0 ||
        renameInfo->FileNameLength >
            Data->Iopb->Parameters.SetFileInformation.Length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) {

        return STATUS_INVALID_PARAMETER;
    }

    rootDirectory = renameInfo->RootDirectory;

    status = FltGetDestinationFileNameInformation(FltObjects->Instance,
                                                  FltObjects->FileObject,
                                                  rootDirectory,
                                                  renameInfo->FileName,
                                                  renameInfo->FileNameLength,
                                                  FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                                  TargetNameInfo);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(*TargetNameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(*TargetNameInfo);
        *TargetNameInfo = NULL;
    }

    return status;
}

static
VOID
DpFreeRenameContext(
    _In_opt_ PDP_RENAME_CONTEXT RenameContext
    )
{
    if (RenameContext != NULL) {
        if (RenameContext->TargetNameInfo != NULL) {
            FltReleaseFileNameInformation(RenameContext->TargetNameInfo);
            RenameContext->TargetNameInfo = NULL;
        }

        ExFreePoolWithTag(RenameContext, DP_TAG_RENAME_CONTEXT);
    }
}

static
BOOLEAN
DpRenameTargetRemainsProtected(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PDP_RENAME_CONTEXT RenameContext,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION *EffectiveNameInfo
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION tunneledNameInfo = NULL;
    BOOLEAN isProtected = FALSE;

    *EffectiveNameInfo = NULL;

    if (RenameContext == NULL || RenameContext->TargetNameInfo == NULL) {
        return FALSE;
    }

    status = FltGetTunneledName(Data,
                                RenameContext->TargetNameInfo,
                                &tunneledNameInfo);

    if (NT_SUCCESS(status) && tunneledNameInfo != NULL) {
        status = FltParseFileNameInformation(tunneledNameInfo);
        if (NT_SUCCESS(status)) {
            isProtected = DpPolicyNameIsProtected(&tunneledNameInfo->Name) &&
                          !DpPolicyNameIsShadow(&tunneledNameInfo->Name);
        }

        if (isProtected) {
            *EffectiveNameInfo = tunneledNameInfo;
        } else {
            FltReleaseFileNameInformation(tunneledNameInfo);
        }

        return isProtected;
    }

    isProtected = DpPolicyNameIsProtected(&RenameContext->TargetNameInfo->Name) &&
                  !DpPolicyNameIsShadow(&RenameContext->TargetNameInfo->Name);

    if (isProtected) {
        FltReferenceFileNameInformation(RenameContext->TargetNameInfo);
        *EffectiveNameInfo = RenameContext->TargetNameInfo;
    }

    return isProtected;
}

static
FLT_POSTOP_CALLBACK_STATUS
DpPostSetInformationWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    PDP_RENAME_CONTEXT renameContext = (PDP_RENAME_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION effectiveNameInfo = NULL;
    BOOLEAN trusted;

    if (renameContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) &&
        NT_SUCCESS(Data->IoStatus.Status) &&
        renameContext->EncryptAfterRename &&
        DpRenameTargetRemainsProtected(Data, renameContext, &effectiveNameInfo) &&
        FltObjects->FileObject != NULL) {

        trusted = DpProcessPolicyIsTrusted(Data, &effectiveNameInfo->Name);
        if (!trusted) {
            goto Exit;
        }

        status = DpMarkHandleEncryptOnCleanup(FltObjects,
                                              &effectiveNameInfo->Name,
                                              TRUE,
                                              TRUE);
        if (!NT_SUCCESS(status)) {
            DP_DBG_PRINT(DP_TRACE_IO,
                         ("DataProtector!DpPostSetInformationWhenSafe: failed to arm deferred encryption 0x%08X\n",
                          status));
        }
    }

Exit:
    if (effectiveNameInfo != NULL) {
        FltReleaseFileNameInformation(effectiveNameInfo);
    }

    DpFreeRenameContext(renameContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PDP_CREATE_CONTEXT createContext = NULL;

    *CompletionContext = NULL;

    status = DpShadowPreCreate(Data, FltObjects, &createContext);
    if (status == STATUS_REPARSE) {
        DpShadowFreeCreateContext(createContext);
        return FLT_PREOP_COMPLETE;
    }

    if (!NT_SUCCESS(status)) {
        DpShadowFreeCreateContext(createContext);
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    *CompletionContext = createContext;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    BOOLEAN isProtected = FALSE;
    BOOLEAN markerPresent = FALSE;
    BOOLEAN pathProtected = FALSE;
    BOOLEAN createdOrReplaced = FALSE;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PDP_CREATE_CONTEXT createContext = (PDP_CREATE_CONTEXT)CompletionContext;
    PFLT_CONTEXT oldContext = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG createDisposition;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        DpShadowFreeCreateContext(createContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (NT_SUCCESS(Data->IoStatus.Status) &&
        FltObjects->FileObject != NULL &&
        !FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        if (createContext != NULL && createContext->IsShadow) {
            status = DpShadowPostCreate(Data,
                                        FltObjects,
                                        createContext,
                                        &handleContext);

            if (NT_SUCCESS(status) && handleContext != NULL) {
                status = FltSetStreamHandleContext(FltObjects->Instance,
                                                   FltObjects->FileObject,
                                                   FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                                   handleContext,
                                                   &oldContext);

                if (oldContext != NULL) {
                    FltReleaseContext(oldContext);
                }

                FltReleaseContext(handleContext);
            }

            DpShadowFreeCreateContext(createContext);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if (!DpShadowIsInternalIo()) {
            (VOID)DpPolicyRefreshStreamContext(Data, FltObjects);
        }

        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);

        if (NT_SUCCESS(status)) {
            pathProtected = DpPolicyNameIsProtected(&nameInfo->Name) &&
                            !DpPolicyNameIsShadow(&nameInfo->Name);

            if (pathProtected) {
                (VOID)DpPolicyFileHasProtectionMarker(FltObjects->Instance,
                                                      &nameInfo->Name,
                                                      &markerPresent);

                isProtected = markerPresent;
            }
        }

        if (pathProtected) {

            status = FltAllocateContext(gDataProtectorFilter,
                                        FLT_STREAMHANDLE_CONTEXT,
                                        sizeof(DP_HANDLE_CONTEXT),
                                        NonPagedPoolNx,
                                        &handleContext);

            if (NT_SUCCESS(status)) {
                RtlZeroMemory(handleContext, sizeof(DP_HANDLE_CONTEXT));
                handleContext->IsProtected = isProtected;
                handleContext->IsTrusted = FALSE;

                if (nameInfo != NULL) {
                    handleContext->IsTrusted = DpProcessPolicyIsTrusted(Data, &nameInfo->Name);

                    createDisposition = Data->Iopb->Parameters.Create.Options >> 24;
                    createdOrReplaced = Data->IoStatus.Information == FILE_CREATED ||
                                        Data->IoStatus.Information == FILE_OVERWRITTEN ||
                                        Data->IoStatus.Information == FILE_SUPERSEDED ||
                                        DpCreateDispositionWillReplaceFile(createDisposition);

                    if (!markerPresent &&
                        createdOrReplaced &&
                        handleContext->IsTrusted) {

                        handleContext->EncryptOnCleanup = TRUE;
                        (VOID)DpDuplicateName(&nameInfo->Name,
                                              &handleContext->PendingName);
                    }
                }

                status = FltSetStreamHandleContext(FltObjects->Instance,
                                                   FltObjects->FileObject,
                                                   FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                                   handleContext,
                                                   &oldContext);

                if (oldContext != NULL) {
                    FltReleaseContext(oldContext);
                }

                FltReleaseContext(handleContext);
            }
        }

        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    DpShadowFreeCreateContext(createContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DpPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    BOOLEAN isProtected;
    BOOLEAN isTrusted;
    BOOLEAN plaintextCacheEnabled;
    NTSTATUS status;
    ULONG length;
    PDP_IO_CONTEXT ioContext;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    *CompletionContext = NULL;

    length = iopb->Parameters.Read.Length;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpCanProcessOperation(Data, FltObjects, length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status) || !isProtected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

#if DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO
    status = DpPolicyIsPlaintextCacheEnabled(FltObjects, &plaintextCacheEnabled);
    if (!NT_SUCCESS(status)) {
        plaintextCacheEnabled = FALSE;
    }
#else
    plaintextCacheEnabled = FALSE;
#endif

    if (!isTrusted && !plaintextCacheEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpIsPagingIo(Data) && isTrusted && plaintextCacheEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpIsPagingIo(Data) && !plaintextCacheEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpCryptoIsReady()) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpIsPagingIo(Data)) {
        ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoRead, 1);
        if (ioContext == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        ioContext->OriginalBuffer = iopb->Parameters.Read.ReadBuffer;
        ioContext->OriginalMdl = iopb->Parameters.Read.MdlAddress;
        ioContext->ByteOffset = iopb->Parameters.Read.ByteOffset;
        ioContext->Length = length;
        ioContext->TransformInPlace = TRUE;
        *CompletionContext = ioContext;

        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoRead, length);
    if (ioContext == NULL) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext->OriginalBuffer = iopb->Parameters.Read.ReadBuffer;
    ioContext->OriginalMdl = iopb->Parameters.Read.MdlAddress;
    ioContext->ByteOffset = iopb->Parameters.Read.ByteOffset;

    if (ioContext->OriginalMdl == NULL && Data->RequestorMode != KernelMode) {
        status = FltLockUserBuffer(Data);
        if (!NT_SUCCESS(status)) {
            DpFreeIoContext(ioContext);
            Data->IoStatus.Status = status;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        ioContext->OriginalMdl = iopb->Parameters.Read.MdlAddress;
    }

    iopb->Parameters.Read.ReadBuffer = ioContext->SwapBuffer;
    iopb->Parameters.Read.MdlAddress = NULL;

    FLT_SET_CALLBACK_DATA_DIRTY(Data);

    *CompletionContext = ioContext;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PDP_IO_CONTEXT ioContext = (PDP_IO_CONTEXT)CompletionContext;
    ULONG bytesRead;
    PVOID destination;

    UNREFERENCED_PARAMETER(FltObjects);

    if (ioContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        DpFreeIoContext(ioContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
        bytesRead = (ULONG)min(Data->IoStatus.Information, ioContext->Length);

        if (ioContext->TransformInPlace) {
            destination = DpGetSystemBufferAddress(Data,
                                                   ioContext->OriginalMdl,
                                                   ioContext->OriginalBuffer);

            if (destination == NULL) {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
            } else {
                DpCryptoTransformBuffer((PUCHAR)destination,
                                        bytesRead,
                                        ioContext->ByteOffset);
            }

            DpFreeIoContext(ioContext);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        DpCryptoTransformBuffer((PUCHAR)ioContext->SwapBuffer,
                                bytesRead,
                                ioContext->ByteOffset);

        destination = DpGetSystemBufferAddress(Data,
                                               ioContext->OriginalMdl,
                                               ioContext->OriginalBuffer);

        if (destination == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        } else {
            RtlCopyMemory(destination, ioContext->SwapBuffer, bytesRead);
        }
    }

    Data->Iopb->Parameters.Read.ReadBuffer = ioContext->OriginalBuffer;
    Data->Iopb->Parameters.Read.MdlAddress = ioContext->OriginalMdl;
    FLT_SET_CALLBACK_DATA_DIRTY(Data);

    DpFreeIoContext(ioContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    BOOLEAN isProtected;
    BOOLEAN isTrusted;
    BOOLEAN plaintextCacheEnabled;
    NTSTATUS status;
    ULONG length;
    PVOID source;
    PDP_IO_CONTEXT ioContext;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    *CompletionContext = NULL;

    length = iopb->Parameters.Write.Length;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpCanProcessOperation(Data, FltObjects, length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    (VOID)DpShadowMarkHandleDirty(FltObjects);

    if (!isProtected && isTrusted) {
        (VOID)DpMarkHandleEncryptOnCleanup(FltObjects,
                                           NULL,
                                           TRUE,
                                           FALSE);
    }

    if (!isProtected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

#if DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO
    status = DpPolicyIsPlaintextCacheEnabled(FltObjects, &plaintextCacheEnabled);
    if (!NT_SUCCESS(status)) {
        plaintextCacheEnabled = FALSE;
    }
#else
    plaintextCacheEnabled = FALSE;
#endif

    if (!isTrusted) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (!DpIsPagingIo(Data) && plaintextCacheEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpIsPagingIo(Data) && !plaintextCacheEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpCryptoIsReady()) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoWrite, length);
    if (ioContext == NULL) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext->OriginalBuffer = iopb->Parameters.Write.WriteBuffer;
    ioContext->OriginalMdl = iopb->Parameters.Write.MdlAddress;
    ioContext->ByteOffset = iopb->Parameters.Write.ByteOffset;

    source = DpGetSystemBufferAddress(Data,
                                      iopb->Parameters.Write.MdlAddress,
                                      iopb->Parameters.Write.WriteBuffer);

    if (source == NULL &&
        iopb->Parameters.Write.MdlAddress == NULL &&
        Data->RequestorMode != KernelMode) {

        status = FltLockUserBuffer(Data);
        if (NT_SUCCESS(status)) {
            ioContext->OriginalMdl = iopb->Parameters.Write.MdlAddress;
            source = DpGetSystemBufferAddress(Data,
                                              ioContext->OriginalMdl,
                                              ioContext->OriginalBuffer);
        }
    }

    if (source == NULL) {
        DpFreeIoContext(ioContext);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    RtlCopyMemory(ioContext->SwapBuffer, source, length);
    DpCryptoTransformBuffer((PUCHAR)ioContext->SwapBuffer,
                            length,
                            ioContext->ByteOffset);

    iopb->Parameters.Write.WriteBuffer = ioContext->SwapBuffer;
    iopb->Parameters.Write.MdlAddress = NULL;

    FLT_SET_CALLBACK_DATA_DIRTY(Data);

    *CompletionContext = ioContext;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PDP_IO_CONTEXT ioContext = (PDP_IO_CONTEXT)CompletionContext;

    UNREFERENCED_PARAMETER(FltObjects);

    if (ioContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        Data->Iopb->Parameters.Write.WriteBuffer = ioContext->OriginalBuffer;
        Data->Iopb->Parameters.Write.MdlAddress = ioContext->OriginalMdl;
        FLT_SET_CALLBACK_DATA_DIRTY(Data);
    }

    DpFreeIoContext(ioContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;

    UNREFERENCED_PARAMETER(Data);

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        status = DpFinalizeEncryptOnCleanup(Data, FltObjects, handleContext);
        if (!NT_SUCCESS(status)) {
            DP_DBG_PRINT(DP_TRACE_IO,
                         ("DataProtector!DpPreCleanup: finalize encryption failed 0x%08X\n",
                          status));
        } else {
            (VOID)DpShadowCleanupHandle(FltObjects, handleContext);
        }

        DpReleaseHandleContext(handleContext);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
DpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    FILE_INFORMATION_CLASS informationClass;
    BOOLEAN isProtected = FALSE;
    BOOLEAN isTrusted = FALSE;
    PFLT_FILE_NAME_INFORMATION targetNameInfo = NULL;
    PDP_RENAME_CONTEXT renameContext = NULL;

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (DpIsRenameInformationClass(informationClass)) {
        (VOID)DpShadowMarkHandleDirty(FltObjects);

        status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
        if (!NT_SUCCESS(status) || isProtected) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = DpGetRenameTargetInformation(Data,
                                              FltObjects,
                                              &targetNameInfo);

        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (DpPolicyNameIsProtected(&targetNameInfo->Name) &&
            !DpPolicyNameIsShadow(&targetNameInfo->Name)) {

            renameContext = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                  sizeof(DP_RENAME_CONTEXT),
                                                  DP_TAG_RENAME_CONTEXT);

            if (renameContext != NULL) {
                RtlZeroMemory(renameContext, sizeof(DP_RENAME_CONTEXT));
                renameContext->EncryptAfterRename = TRUE;
                FltReferenceFileNameInformation(targetNameInfo);
                renameContext->TargetNameInfo = targetNameInfo;
                *CompletionContext = renameContext;
            }
        }

        FltReleaseFileNameInformation(targetNameInfo);

        if (renameContext != NULL) {
            return FLT_PREOP_SYNCHRONIZE;
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    switch (informationClass) {
    case FileEndOfFileInformation:
    case FileAllocationInformation:
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        (VOID)DpShadowMarkHandleDirty(FltObjects);
        break;

    default:
        break;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PDP_RENAME_CONTEXT renameContext = (PDP_RENAME_CONTEXT)CompletionContext;
    FLT_POSTOP_CALLBACK_STATUS callbackStatus;

    if (renameContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        DpFreeRenameContext(renameContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FltDoCompletionProcessingWhenSafe(Data,
                                          FltObjects,
                                          CompletionContext,
                                          Flags,
                                          DpPostSetInformationWhenSafe,
                                          &callbackStatus)) {

        return callbackStatus;
    }

    DpFreeRenameContext(renameContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DpPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    BOOLEAN isProtected;
    BOOLEAN isTrusted;
    NTSTATUS status;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    ULONG writeMask;

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects->FileObject == NULL ||
        FltObjects->FileObject->FsContext == NULL ||
        iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    writeMask = PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    if (FlagOn(iopb->Parameters.AcquireForSectionSynchronization.PageProtection, writeMask)) {
        (VOID)DpShadowMarkHandleDirty(FltObjects);
    }

#if !DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(isProtected);
    UNREFERENCED_PARAMETER(isTrusted);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
#else

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status) || !isProtected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (isTrusted) {
        (VOID)DpPolicyEnablePlaintextCache(FltObjects);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
#endif
}

FLT_PREOP_CALLBACK_STATUS
DpPreFastIoCheckIfPossible(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    BOOLEAN isProtected;
    BOOLEAN isTrusted;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Data);

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status) || !isProtected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(isTrusted);

    return FLT_PREOP_DISALLOW_FASTIO;
}
