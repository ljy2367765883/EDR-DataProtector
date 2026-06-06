/*++

Module Name:

    DpIo.c

Abstract:

    Transparent read/write encryption callbacks. Protected streams use a
    swap buffer so the file system sees ciphertext while callers see
    plaintext.

--*/

#include "DataProtector.h"

#if DP_ENABLE_WEBSHELL_OPERATION_TRACE
#define DP_WEBSHELL_IO_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector77[WebShellIo] " _format, __VA_ARGS__)
#else
#define DP_WEBSHELL_IO_TRACE(_format, ...) ((void)0)
#endif

#if DP_ENABLE_FILE_HUNTER_TRACE
#define DP_FILE_HUNTER_IO_TRACE(_format, ...) \
    DbgPrint("DataProtector[FileHunter] " _format, __VA_ARGS__)
#else
#define DP_FILE_HUNTER_IO_TRACE(_format, ...) ((void)0)
#endif

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
BOOLEAN
DpFileHunterCreateGrantsReadIntent(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    ACCESS_MASK readMask = FILE_READ_DATA |
                           FILE_EXECUTE |
                           GENERIC_READ |
                           GENERIC_EXECUTE |
                           MAXIMUM_ALLOWED;

    return (DesiredAccess & readMask) != 0;
}

static
ULONG
DpFileHunterFlagsFromCreateAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    ULONG flags = DP_FILE_HUNTER_READ_FLAG_CREATE_OPEN;

    if ((DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) != 0) {
        flags |= DP_FILE_HUNTER_READ_FLAG_EXECUTE_ACCESS;
    }

    return flags;
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

static
FLT_PREOP_CALLBACK_STATUS
DpArmFileHunterAuditRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Length,
    _Inout_ PDP_FILE_HUNTER_READ_CONTEXT *FileHunterContext,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PDP_IO_CONTEXT ioContext;

    if (FileHunterContext == NULL ||
        *FileHunterContext == NULL ||
        CompletionContext == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ioContext = DpAllocateAuditIoContext(FltObjects->Instance, DpIoRead, Length);
    if (ioContext == NULL) {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            DP_FILE_HUNTER_IO_TRACE("audit context allocation failed length=%lu path=%ws process=%ws\n",
                                    Length,
                                    (*FileHunterContext)->Path,
                                    (*FileHunterContext)->ProcessImage);
        } else {
            DP_FILE_HUNTER_IO_TRACE("audit context allocation failed length=%lu pathBytes=%lu processBytes=%lu\n",
                                    Length,
                                    (*FileHunterContext)->PathLengthBytes,
                                    (*FileHunterContext)->ProcessImageLengthBytes);
        }
        DpFileHunterFreeReadContext(*FileHunterContext);
        *FileHunterContext = NULL;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ioContext->OriginalBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
    ioContext->OriginalMdl = Data->Iopb->Parameters.Read.MdlAddress;
    ioContext->ByteOffset = Data->Iopb->Parameters.Read.ByteOffset;
    ioContext->FileHunterContext = *FileHunterContext;
    *FileHunterContext = NULL;
    *CompletionContext = ioContext;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        DP_FILE_HUNTER_IO_TRACE("audit callback armed length=%lu path=%ws process=%ws\n",
                                Length,
                                ioContext->FileHunterContext->Path,
                                ioContext->FileHunterContext->ProcessImage);
    } else {
        DP_FILE_HUNTER_IO_TRACE("audit callback armed length=%lu pathBytes=%lu processBytes=%lu\n",
                                Length,
                                ioContext->FileHunterContext->PathLengthBytes,
                                ioContext->FileHunterContext->ProcessImageLengthBytes);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

typedef struct _DP_RENAME_CONTEXT {
    BOOLEAN EncryptAfterRename;
    BOOLEAN InspectWebShellAfterRename;
    BOOLEAN WebShellAlreadyInspected;
    PFLT_FILE_NAME_INFORMATION TargetNameInfo;
} DP_RENAME_CONTEXT, *PDP_RENAME_CONTEXT;

typedef struct _DP_DIRECTORY_CONTEXT {
    UNICODE_STRING DirectoryName;
} DP_DIRECTORY_CONTEXT, *PDP_DIRECTORY_CONTEXT;

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
VOID
DpFreeDirectoryContext(
    _In_opt_ PDP_DIRECTORY_CONTEXT DirectoryContext
    )
{
    if (DirectoryContext == NULL) {
        return;
    }

    DpFreeName(&DirectoryContext->DirectoryName);
    ExFreePoolWithTag(DirectoryContext, DP_TAG_NAME_BUFFER);
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
VOID
DpApplyDefaultFileKeyToHandle(
    _Inout_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    if (HandleContext == NULL || HandleContext->FileKeyLength != 0) {
        return;
    }

    DpCryptoGetDefaultFileKey(HandleContext->FileKey,
                              &HandleContext->FileKeyLength);
}

static
VOID
DpApplyFooterToHandle(
    _Inout_ PDP_HANDLE_CONTEXT HandleContext,
    _In_ const DP_PROTECTION_FOOTER *Footer
    )
{
    if (HandleContext == NULL || Footer == NULL) {
        return;
    }

    HandleContext->LogicalSize.QuadPart = (LONGLONG)Footer->LogicalSize;
    HandleContext->FileKeyLength = Footer->KeyLength;
    RtlZeroMemory(HandleContext->FileKey, sizeof(HandleContext->FileKey));
    RtlCopyMemory(HandleContext->FileKey,
                  Footer->FileKey,
                  min(Footer->KeyLength, (ULONG)DP_FILE_KEY_LENGTH));
}

static
NTSTATUS
DpGetLogicalSizeForHandle(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER LogicalSize,
    _Out_opt_ PDP_HANDLE_CONTEXT *ReferencedHandleContext
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    BOOLEAN protectedByFooter = FALSE;

    if (ReferencedHandleContext != NULL) {
        *ReferencedHandleContext = NULL;
    }

    LogicalSize->QuadPart = 0;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        if (handleContext->IsProtected && handleContext->LogicalSize.QuadPart >= 0) {
            *LogicalSize = handleContext->LogicalSize;

            if (ReferencedHandleContext != NULL) {
                *ReferencedHandleContext = handleContext;
            } else {
                DpReleaseHandleContext(handleContext);
            }

            return STATUS_SUCCESS;
        }

        DpReleaseHandleContext(handleContext);
    }

    status = DpPolicyGetFileLogicalSize(FltObjects->Instance,
                                        FltObjects->FileObject,
                                        LogicalSize,
                                        &protectedByFooter);

    UNREFERENCED_PARAMETER(protectedByFooter);

    return status;
}

static
VOID
DpUpdateReferencedHandleLogicalSizeAfterWrite(
    _Inout_ PDP_HANDLE_CONTEXT HandleContext,
    _In_ LARGE_INTEGER ByteOffset,
    _In_ ULONG_PTR BytesWritten
    )
{
    LARGE_INTEGER endOffset;

    if (HandleContext == NULL) {
        return;
    }

    if (BytesWritten == 0 ||
        ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION ||
        ByteOffset.LowPart == FILE_WRITE_TO_END_OF_FILE) {

        return;
    }

    endOffset.QuadPart = ByteOffset.QuadPart + (LONGLONG)BytesWritten;

    if (endOffset.QuadPart > HandleContext->LogicalSize.QuadPart) {
        HandleContext->LogicalSize = endOffset;
        HandleContext->FooterDirty = TRUE;
    }
}

static
BOOLEAN
DpInformationClassHasVisibleSize(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    switch (InformationClass) {
    case FileStandardInformation:
    case FileAllInformation:
    case FileNetworkOpenInformation:
    case FileAllocationInformation:
    case FileEndOfFileInformation:
        return TRUE;

    default:
        return FALSE;
    }
}

static
VOID
DpHideFooterInAllocationSize(
    _Inout_ PLARGE_INTEGER AllocationSize,
    _In_ LARGE_INTEGER LogicalSize
    )
{
    if (AllocationSize->QuadPart >= DP_PROTECTION_FOOTER_SIZE) {
        AllocationSize->QuadPart -= DP_PROTECTION_FOOTER_SIZE;
    }

    if (AllocationSize->QuadPart < LogicalSize.QuadPart) {
        *AllocationSize = LogicalSize;
    }
}

static
VOID
DpAdjustInformationSizeBuffer(
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS InformationClass,
    _In_ LARGE_INTEGER LogicalSize
    )
{
    if (Buffer == NULL) {
        return;
    }

    switch (InformationClass) {
    case FileStandardInformation:
        if (Length >= sizeof(FILE_STANDARD_INFORMATION)) {
            PFILE_STANDARD_INFORMATION standardInfo = (PFILE_STANDARD_INFORMATION)Buffer;
            standardInfo->EndOfFile = LogicalSize;
            DpHideFooterInAllocationSize(&standardInfo->AllocationSize, LogicalSize);
        }
        break;

    case FileAllInformation:
        if (Length >= (ULONG)FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation)) {
            PFILE_ALL_INFORMATION allInfo = (PFILE_ALL_INFORMATION)Buffer;
            allInfo->StandardInformation.EndOfFile = LogicalSize;
            DpHideFooterInAllocationSize(&allInfo->StandardInformation.AllocationSize, LogicalSize);
        }
        break;

    case FileNetworkOpenInformation:
        if (Length >= sizeof(FILE_NETWORK_OPEN_INFORMATION)) {
            PFILE_NETWORK_OPEN_INFORMATION networkInfo = (PFILE_NETWORK_OPEN_INFORMATION)Buffer;
            networkInfo->EndOfFile = LogicalSize;
            DpHideFooterInAllocationSize(&networkInfo->AllocationSize, LogicalSize);
        }
        break;

    case FileAllocationInformation:
        if (Length >= sizeof(FILE_ALLOCATION_INFORMATION)) {
            PFILE_ALLOCATION_INFORMATION allocationInfo = (PFILE_ALLOCATION_INFORMATION)Buffer;
            DpHideFooterInAllocationSize(&allocationInfo->AllocationSize, LogicalSize);
        }
        break;

    case FileEndOfFileInformation:
        if (Length >= sizeof(FILE_END_OF_FILE_INFORMATION)) {
            ((PFILE_END_OF_FILE_INFORMATION)Buffer)->EndOfFile = LogicalSize;
        }
        break;

    default:
        break;
    }
}

static
VOID
DpAdjustDirectoryEntrySize(
    _Inout_ PVOID Entry,
    _In_ FILE_INFORMATION_CLASS InformationClass,
    _In_ LARGE_INTEGER LogicalSize
    )
{
    switch (InformationClass) {
    case FileDirectoryInformation:
        ((PFILE_DIRECTORY_INFORMATION)Entry)->EndOfFile = LogicalSize;
        DpHideFooterInAllocationSize(&((PFILE_DIRECTORY_INFORMATION)Entry)->AllocationSize, LogicalSize);
        break;

    case FileFullDirectoryInformation:
        ((PFILE_FULL_DIR_INFORMATION)Entry)->EndOfFile = LogicalSize;
        DpHideFooterInAllocationSize(&((PFILE_FULL_DIR_INFORMATION)Entry)->AllocationSize, LogicalSize);
        break;

    case FileBothDirectoryInformation:
        ((PFILE_BOTH_DIR_INFORMATION)Entry)->EndOfFile = LogicalSize;
        DpHideFooterInAllocationSize(&((PFILE_BOTH_DIR_INFORMATION)Entry)->AllocationSize, LogicalSize);
        break;

    case FileIdFullDirectoryInformation:
        ((PFILE_ID_FULL_DIR_INFORMATION)Entry)->EndOfFile = LogicalSize;
        DpHideFooterInAllocationSize(&((PFILE_ID_FULL_DIR_INFORMATION)Entry)->AllocationSize, LogicalSize);
        break;

    case FileIdBothDirectoryInformation:
        ((PFILE_ID_BOTH_DIR_INFORMATION)Entry)->EndOfFile = LogicalSize;
        DpHideFooterInAllocationSize(&((PFILE_ID_BOTH_DIR_INFORMATION)Entry)->AllocationSize, LogicalSize);
        break;

    default:
        break;
    }
}

static
BOOLEAN
DpDirectoryClassHasVisibleSize(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    switch (InformationClass) {
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileIdBothDirectoryInformation:
        return TRUE;

    default:
        return FALSE;
    }
}

static
ULONG
DpGetDirectoryEntryNextOffset(
    _In_ PVOID Entry,
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    switch (InformationClass) {
    case FileDirectoryInformation:
        return ((PFILE_DIRECTORY_INFORMATION)Entry)->NextEntryOffset;

    case FileFullDirectoryInformation:
        return ((PFILE_FULL_DIR_INFORMATION)Entry)->NextEntryOffset;

    case FileBothDirectoryInformation:
        return ((PFILE_BOTH_DIR_INFORMATION)Entry)->NextEntryOffset;

    case FileIdFullDirectoryInformation:
        return ((PFILE_ID_FULL_DIR_INFORMATION)Entry)->NextEntryOffset;

    case FileIdBothDirectoryInformation:
        return ((PFILE_ID_BOTH_DIR_INFORMATION)Entry)->NextEntryOffset;

    default:
        return 0;
    }
}

static
VOID
DpGetDirectoryEntryFileName(
    _In_ PVOID Entry,
    _In_ FILE_INFORMATION_CLASS InformationClass,
    _Out_ PUNICODE_STRING FileName
    )
{
    FileName->Buffer = NULL;
    FileName->Length = 0;
    FileName->MaximumLength = 0;

    switch (InformationClass) {
    case FileDirectoryInformation:
        FileName->Buffer = ((PFILE_DIRECTORY_INFORMATION)Entry)->FileName;
        FileName->Length = (USHORT)min(((PFILE_DIRECTORY_INFORMATION)Entry)->FileNameLength, (ULONG)MAXUSHORT);
        break;

    case FileFullDirectoryInformation:
        FileName->Buffer = ((PFILE_FULL_DIR_INFORMATION)Entry)->FileName;
        FileName->Length = (USHORT)min(((PFILE_FULL_DIR_INFORMATION)Entry)->FileNameLength, (ULONG)MAXUSHORT);
        break;

    case FileBothDirectoryInformation:
        FileName->Buffer = ((PFILE_BOTH_DIR_INFORMATION)Entry)->FileName;
        FileName->Length = (USHORT)min(((PFILE_BOTH_DIR_INFORMATION)Entry)->FileNameLength, (ULONG)MAXUSHORT);
        break;

    case FileIdFullDirectoryInformation:
        FileName->Buffer = ((PFILE_ID_FULL_DIR_INFORMATION)Entry)->FileName;
        FileName->Length = (USHORT)min(((PFILE_ID_FULL_DIR_INFORMATION)Entry)->FileNameLength, (ULONG)MAXUSHORT);
        break;

    case FileIdBothDirectoryInformation:
        FileName->Buffer = ((PFILE_ID_BOTH_DIR_INFORMATION)Entry)->FileName;
        FileName->Length = (USHORT)min(((PFILE_ID_BOTH_DIR_INFORMATION)Entry)->FileNameLength, (ULONG)MAXUSHORT);
        break;

    default:
        break;
    }

    FileName->MaximumLength = FileName->Length;
}

static
NTSTATUS
DpBuildDirectoryChildName(
    _In_ PCUNICODE_STRING DirectoryName,
    _In_ PCUNICODE_STRING FileName,
    _Out_ PUNICODE_STRING ChildName
    )
{
    USHORT separatorLength;

    ChildName->Buffer = NULL;
    ChildName->Length = 0;
    ChildName->MaximumLength = 0;

    if (DirectoryName == NULL ||
        DirectoryName->Buffer == NULL ||
        FileName == NULL ||
        FileName->Buffer == NULL ||
        FileName->Length == 0) {

        return STATUS_INVALID_PARAMETER;
    }

    separatorLength =
        DirectoryName->Length >= sizeof(WCHAR) &&
        DirectoryName->Buffer[(DirectoryName->Length / sizeof(WCHAR)) - 1] == L'\\' ?
        0 :
        sizeof(WCHAR);

    if (DirectoryName->Length > MAXUSHORT - separatorLength ||
        FileName->Length > MAXUSHORT - DirectoryName->Length - separatorLength) {

        return STATUS_NAME_TOO_LONG;
    }

    ChildName->Length = DirectoryName->Length + separatorLength + FileName->Length;
    ChildName->MaximumLength = ChildName->Length;
    ChildName->Buffer = ExAllocatePoolWithTag(PagedPool,
                                              ChildName->MaximumLength,
                                              DP_TAG_NAME_BUFFER);

    if (ChildName->Buffer == NULL) {
        ChildName->Length = 0;
        ChildName->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(ChildName->Buffer,
                  DirectoryName->Buffer,
                  DirectoryName->Length);

    if (separatorLength != 0) {
        *(PWCHAR)((PUCHAR)ChildName->Buffer + DirectoryName->Length) = L'\\';
    }

    RtlCopyMemory((PUCHAR)ChildName->Buffer + DirectoryName->Length + separatorLength,
                  FileName->Buffer,
                  FileName->Length);

    return STATUS_SUCCESS;
}

static
VOID
DpFreeDirectoryChildName(
    _Inout_ PUNICODE_STRING ChildName
    )
{
    if (ChildName->Buffer != NULL) {
        ExFreePoolWithTag(ChildName->Buffer, DP_TAG_NAME_BUFFER);
        ChildName->Buffer = NULL;
    }

    ChildName->Length = 0;
    ChildName->MaximumLength = 0;
}

static
VOID
DpAdjustDirectoryBufferSizes(
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS InformationClass,
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING DirectoryName
    )
{
    PUCHAR entry;
    ULONG offset = 0;
    ULONG nextOffset;
    UNICODE_STRING fileName;
    UNICODE_STRING childName;
    DP_PROTECTION_FOOTER footer;
    BOOLEAN isProtected;
    NTSTATUS status;

    if (Buffer == NULL ||
        Length == 0 ||
        Instance == NULL ||
        DirectoryName == NULL ||
        DirectoryName->Buffer == NULL ||
        !DpDirectoryClassHasVisibleSize(InformationClass)) {

        return;
    }

    entry = (PUCHAR)Buffer;

    for (;;) {
        if (offset >= Length) {
            break;
        }

        DpGetDirectoryEntryFileName(entry, InformationClass, &fileName);
        status = DpBuildDirectoryChildName(DirectoryName, &fileName, &childName);
        if (NT_SUCCESS(status)) {
            status = DpPolicyReadProtectionFooter(Instance,
                                                  &childName,
                                                  &footer,
                                                  &isProtected);
            if (NT_SUCCESS(status) && isProtected) {
                LARGE_INTEGER logicalSize;

                logicalSize.QuadPart = (LONGLONG)footer.LogicalSize;
                DpAdjustDirectoryEntrySize(entry,
                                           InformationClass,
                                           logicalSize);
            }

            DpFreeDirectoryChildName(&childName);
        }

        nextOffset = DpGetDirectoryEntryNextOffset(entry, InformationClass);
        if (nextOffset == 0) {
            break;
        }

        if (nextOffset > Length - offset) {
            break;
        }

        offset += nextOffset;
        entry = (PUCHAR)Buffer + offset;
    }
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
                                           FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                           handleContext,
                                           &oldContext);

        if (oldContext != NULL) {
            FltReleaseContext(oldContext);
        }

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            FltReleaseContext(handleContext);

            status = DpGetHandleContext(FltObjects, &handleContext);
            if (!NT_SUCCESS(status) || handleContext == NULL) {
                return status;
            }
        } else if (!NT_SUCCESS(status)) {
            FltReleaseContext(handleContext);
            return status;
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
    DpApplyDefaultFileKeyToHandle(handleContext);

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
DpEnsureWebShellHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN NewlyCreated
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PFLT_CONTEXT oldContext = NULL;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (status == STATUS_NOT_FOUND) {
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
                                           FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                           handleContext,
                                           &oldContext);

        if (oldContext != NULL) {
            FltReleaseContext(oldContext);
        }

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            FltReleaseContext(handleContext);

            status = DpGetHandleContext(FltObjects, &handleContext);
            if (!NT_SUCCESS(status) || handleContext == NULL) {
                return status;
            }
        } else if (!NT_SUCCESS(status)) {
            FltReleaseContext(handleContext);
            return status;
        }
    } else if (!NT_SUCCESS(status) || handleContext == NULL) {
        return status;
    }

    handleContext->WebShellNewFile = NewlyCreated;
    handleContext->WebShellReported = FALSE;
    DpReleaseHandleContext(handleContext);

    return STATUS_SUCCESS;
}

static
VOID
DpMarkHandleWebShellReported(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        handleContext->WebShellReported = TRUE;
        DpReleaseHandleContext(handleContext);
    }
}

static
BOOLEAN
DpHandleNeedsWebShellInspection(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    BOOLEAN inspect = FALSE;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        inspect = handleContext->WebShellNewFile && !handleContext->WebShellReported;
        DpReleaseHandleContext(handleContext);
    }

    return inspect;
}

static
BOOLEAN
DpHandleWebShellInspectionCompleted(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    BOOLEAN completed = FALSE;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        completed = handleContext->WebShellReported;
        DpReleaseHandleContext(handleContext);
    }

    return completed;
}

static
NTSTATUS
DpMarkWebShellCandidateIfNeeded(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING Name,
    _In_ BOOLEAN NewlyCreated
    )
{
    if (Name == NULL ||
        Name->Buffer == NULL ||
        !DpWebShellIsProtectedPath(Name) ||
        !DpWebShellIsScriptPath(Name, NULL)) {

        return STATUS_SUCCESS;
    }

    return DpEnsureWebShellHandleContext(FltObjects, NewlyCreated);
}

static
BOOLEAN
DpArmWebShellWriteInspectionIfTargeted(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    if (DpHandleNeedsWebShellInspection(FltObjects)) {
        return TRUE;
    }

    if (DpHandleWebShellInspectionCompleted(FltObjects)) {
        return FALSE;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = DpMarkWebShellCandidateIfNeeded(FltObjects,
                                             &nameInfo->Name,
                                             TRUE);
    FltReleaseFileNameInformation(nameInfo);

    return NT_SUCCESS(status) && DpHandleNeedsWebShellInspection(FltObjects);
}

static
BOOLEAN
DpInspectWebShellWriteByCurrentName(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Length,
    _Out_ PNTSTATUS InspectionStatus
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PFLT_IO_PARAMETER_BLOCK iopb;
    PVOID source;

    *InspectionStatus = STATUS_SUCCESS;

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        Length == 0) {

        DP_WEBSHELL_IO_TRACE("write skip invalid length=%lu\n", Length);
        return FALSE;
    }

    if (DpHandleWebShellInspectionCompleted(FltObjects)) {
        DP_WEBSHELL_IO_TRACE("write skip completed length=%lu\n", Length);
        return FALSE;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        DP_WEBSHELL_IO_TRACE("write name failed status=0x%08X length=%lu\n",
                             status,
                             Length);
        return FALSE;
    }

    if (!DpWebShellIsProtectedPath(&nameInfo->Name) ||
        !DpWebShellIsScriptPath(&nameInfo->Name, NULL)) {

        DP_WEBSHELL_IO_TRACE("write bypass length=%lu path=%wZ\n",
                             Length,
                             &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    (VOID)DpEnsureWebShellHandleContext(FltObjects, TRUE);
    DP_WEBSHELL_IO_TRACE("write targeted pid=%p length=%lu path=%wZ\n",
                         FltGetRequestorProcessIdEx(Data),
                         Length,
                         &nameInfo->Name);

    iopb = Data->Iopb;
    source = DpGetSystemBufferAddress(Data,
                                      iopb->Parameters.Write.MdlAddress,
                                      iopb->Parameters.Write.WriteBuffer);

    if (source == NULL &&
        iopb->Parameters.Write.MdlAddress == NULL &&
        Data->RequestorMode != KernelMode) {

        status = FltLockUserBuffer(Data);
        if (NT_SUCCESS(status)) {
            source = DpGetSystemBufferAddress(Data,
                                              iopb->Parameters.Write.MdlAddress,
                                              iopb->Parameters.Write.WriteBuffer);
        }
    }

    if (source == NULL) {
        DP_WEBSHELL_IO_TRACE("write buffer unavailable length=%lu path=%wZ\n",
                             Length,
                             &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    status = DpWebShellInspectWriteByName(&nameInfo->Name,
                                          FltGetRequestorProcessIdEx(Data),
                                          source,
                                          Length,
                                          DpWebShellOperationWrite);
    if (!NT_SUCCESS(status)) {
        DpMarkHandleWebShellReported(FltObjects);
    }

    *InspectionStatus = status;

    DP_WEBSHELL_IO_TRACE("write inspected status=0x%08X length=%lu path=%wZ\n",
                         status,
                         Length,
                         &nameInfo->Name);

    FltReleaseFileNameInformation(nameInfo);

    return TRUE;
}

static
NTSTATUS
DpInspectWebShellOnCleanup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_opt_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN shouldInspect = FALSE;

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        return STATUS_SUCCESS;
    }

    if (HandleContext != NULL) {
        shouldInspect = HandleContext->WebShellNewFile && !HandleContext->WebShellReported;
    }

    if (!shouldInspect &&
        !FlagOn(FltObjects->FileObject->Flags, FO_FILE_MODIFIED | FO_FILE_SIZE_CHANGED)) {

        return STATUS_SUCCESS;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    if (!shouldInspect) {
        shouldInspect = DpWebShellIsProtectedPath(&nameInfo->Name) &&
                        DpWebShellIsScriptPath(&nameInfo->Name, NULL);
    }

    if (!shouldInspect) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_SUCCESS;
    }

    status = DpWebShellInspectFileObject(FltObjects->Instance,
                                         FltObjects->FileObject,
                                         &nameInfo->Name,
                                         FltGetRequestorProcessIdEx(Data),
                                         DpWebShellOperationCleanup);

    if (HandleContext != NULL) {
        HandleContext->WebShellReported = TRUE;
    } else {
        DpMarkHandleWebShellReported(FltObjects);
    }

    if (status == STATUS_ACCESS_DENIED) {
        NTSTATUS truncateStatus;

        truncateStatus = DpShadowTruncateFileObject(FltObjects->Instance,
                                                    FltObjects->FileObject);
        DP_DBG_PRINT(DP_TRACE_IO,
                     ("DataProtector!DpInspectWebShellOnCleanup: dangerous web script neutralized status=0x%08X path=%wZ\n",
                      truncateStatus,
                      &nameInfo->Name));
    }

    FltReleaseFileNameInformation(nameInfo);

    return status;
}

//
// Static executable scan detector on cleanup. When a handle that modified the
// file is closing and the target is an executable image (or script dropper),
// capture its metadata and enqueue a scan REQUEST for the signed user-mode
// service. The kernel performs NO classification and NO file read here; user
// mode drains the request, scans with YARA / updatable engines, and submits a
// verdict that the kernel enforces asynchronously.
//
static
VOID
DpInspectStaticScanOnCleanup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_opt_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN modified;

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        return;
    }

    if (HandleContext != NULL && HandleContext->StaticScanReported) {
        return;
    }

    //
    // Only notify when this handle actually wrote/created the file.
    //
    modified = (HandleContext != NULL && HandleContext->StaticScanNewFile) ||
               FlagOn(FltObjects->FileObject->Flags, FO_FILE_MODIFIED | FO_FILE_SIZE_CHANGED);

    if (!modified) {
        return;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return;
    }

    if (!DpStaticScanIsExecutableName(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    DpStaticScanEnqueueRequest(Data,
                               FltObjects,
                               &nameInfo->Name,
                               FltGetRequestorProcessIdEx(Data),
                               DpStaticScanOperationCleanup);

    if (HandleContext != NULL) {
        HandleContext->StaticScanReported = TRUE;
    }

    FltReleaseFileNameInformation(nameInfo);
}

static
NTSTATUS
DpInspectWebShellRenameSource(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING TargetName
    )
{
    NTSTATUS status;
    NTSTATUS sourceStatus;
    PFLT_FILE_NAME_INFORMATION sourceNameInfo = NULL;
    BOOLEAN sourceInspected = FALSE;

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        TargetName == NULL ||
        TargetName->Buffer == NULL ||
        TargetName->Length == 0) {

        DP_WEBSHELL_IO_TRACE("rename skip invalid target\n");
        return STATUS_SUCCESS;
    }

    if (!DpWebShellIsProtectedPath(TargetName) ||
        !DpWebShellIsScriptPath(TargetName, NULL)) {

        DP_WEBSHELL_IO_TRACE("rename skip unprotected target=%wZ\n",
                             TargetName);
        return STATUS_SUCCESS;
    }

    DP_WEBSHELL_IO_TRACE("rename targeted pid=%p target=%wZ\n",
                         FltGetRequestorProcessIdEx(Data),
                         TargetName);

    sourceStatus = FltGetFileNameInformation(Data,
                                             FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                             &sourceNameInfo);
    if (NT_SUCCESS(sourceStatus) && sourceNameInfo != NULL) {
        DP_WEBSHELL_IO_TRACE("rename source name=%wZ target=%wZ\n",
                             &sourceNameInfo->Name,
                             TargetName);
        sourceStatus = DpWebShellInspectFileBySourceName(FltObjects->Instance,
                                                         &sourceNameInfo->Name,
                                                         TargetName,
                                                         FltGetRequestorProcessIdEx(Data),
                                                         DpWebShellOperationRename,
                                                         &sourceInspected);
        FltReleaseFileNameInformation(sourceNameInfo);
        if (!NT_SUCCESS(sourceStatus)) {
            DP_WEBSHELL_IO_TRACE("rename denied from source status=0x%08X target=%wZ\n",
                                 sourceStatus,
                                 TargetName);
            return sourceStatus;
        }
    } else {
        DP_WEBSHELL_IO_TRACE("rename source name failed status=0x%08X target=%wZ\n",
                             sourceStatus,
                             TargetName);
    }

    if (sourceInspected) {
        DP_WEBSHELL_IO_TRACE("rename source inspected status=0x%08X target=%wZ\n",
                             sourceStatus,
                             TargetName);
        return sourceStatus;
    }

    status = DpWebShellInspectFileObject(FltObjects->Instance,
                                         FltObjects->FileObject,
                                         TargetName,
                                         FltGetRequestorProcessIdEx(Data),
                                         DpWebShellOperationRename);

    DP_WEBSHELL_IO_TRACE("rename fallback fileobject status=0x%08X target=%wZ\n",
                         status,
                         TargetName);

    return status;
}

static
NTSTATUS
DpTruncateWebShellFileByName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;

    if (Instance == NULL || Name == NULL || Name->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = FltCreateFileEx2(gDataProtectorFilter,
                              Instance,
                              &fileHandle,
                              &fileObject,
                              FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                              &objectAttributes,
                              &ioStatus,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL,
                              0,
                              IO_IGNORE_SHARE_ACCESS_CHECK,
                              NULL);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpShadowTruncateFileObject(Instance, fileObject);

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }

    if (fileHandle != NULL) {
        FltClose(fileHandle);
    }

    return status;
}

static
NTSTATUS
DpArmTrustedPathEncryptOnCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_z_ PCSTR Operation,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN pathProtected = FALSE;
    BOOLEAN trusted = FALSE;

#if !DP_ENABLE_PPTX_DATA_TRACE
    UNREFERENCED_PARAMETER(Operation);
    UNREFERENCED_PARAMETER(Detail1);
    UNREFERENCED_PARAMETER(Detail2);
#endif

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        FltObjects->FileObject->FsContext == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        DP_TRACE_PPTX_DATA(Operation,
                           Data,
                           FltObjects,
                           status,
                           0,
                           0,
                           Detail1,
                           Detail2);
        return status;
    }

    pathProtected = DpPolicyNameIsProtected(&nameInfo->Name) &&
                    !DpPolicyNameIsShadow(&nameInfo->Name);

    if (pathProtected) {
        trusted = DpProcessPolicyIsTrusted(Data, &nameInfo->Name);
    }

    if (pathProtected && trusted) {
        status = DpMarkHandleEncryptOnCleanup(FltObjects,
                                              &nameInfo->Name,
                                              TRUE,
                                              TRUE);
    } else {
        status = STATUS_SUCCESS;
    }

    DP_TRACE_PPTX_NAME(Operation,
                       &nameInfo->Name,
                       status,
                       pathProtected,
                       trusted,
                       Detail1,
                       Detail2);

    FltReleaseFileNameInformation(nameInfo);

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
        DP_TRACE_PPTX_NAME("CleanupSkipEncrypt",
                           finalName,
                           STATUS_SUCCESS,
                           HandleContext->IsProtected,
                           HandleContext->IsTrusted,
                           HandleContext->IsShadow,
                           HandleContext->EncryptOnCleanup);
        status = STATUS_SUCCESS;
        goto Exit;
    }

    DP_TRACE_PPTX_NAME("CleanupEncryptBegin",
                       finalName,
                       STATUS_SUCCESS,
                       HandleContext->IsProtected,
                       HandleContext->IsTrusted,
                       HandleContext->IsShadow,
                       HandleContext->EncryptOnCleanup);

    (VOID)FltFlushBuffers(FltObjects->Instance, FltObjects->FileObject);

    status = DpShadowEncryptFileObjectInPlace(FltObjects->Instance,
                                              FltObjects->FileObject);

    if (!NT_SUCCESS(status)) {
        DP_TRACE_PPTX_NAME("CleanupEncryptFailed",
                           finalName,
                           status,
                           HandleContext->IsProtected,
                           HandleContext->IsTrusted,
                           HandleContext->IsShadow,
                           HandleContext->EncryptOnCleanup);
        goto Exit;
    }

    markerStatus = DpPolicyWriteProtectionMarker(FltObjects->Instance,
                                                 finalName);
    if (!NT_SUCCESS(markerStatus)) {
        status = markerStatus;
        DP_TRACE_PPTX_NAME("CleanupMarkerFailed",
                           finalName,
                           status,
                           HandleContext->IsProtected,
                           HandleContext->IsTrusted,
                           HandleContext->IsShadow,
                           HandleContext->EncryptOnCleanup);
        goto Exit;
    }

    (VOID)DpPolicySetStreamProtection(FltObjects, TRUE);
    HandleContext->IsProtected = TRUE;
    HandleContext->LogicalSize.QuadPart = 0;
    (VOID)DpPolicyGetFileLogicalSize(FltObjects->Instance,
                                     FltObjects->FileObject,
                                     &HandleContext->LogicalSize,
                                     NULL);
    DpApplyDefaultFileKeyToHandle(HandleContext);
    HandleContext->EncryptOnCleanup = FALSE;

    DP_TRACE_PPTX_NAME("CleanupEncryptDone",
                       finalName,
                       STATUS_SUCCESS,
                       HandleContext->IsProtected,
                       HandleContext->IsTrusted,
                       HandleContext->IsShadow,
                       HandleContext->EncryptOnCleanup);

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
            DP_TRACE_PPTX_NAME("RenameTunneledNotProtected",
                               &tunneledNameInfo->Name,
                               status,
                               isProtected,
                               0,
                               0,
                               0);
            FltReleaseFileNameInformation(tunneledNameInfo);
        }

        return isProtected;
    }

    isProtected = DpPolicyNameIsProtected(&RenameContext->TargetNameInfo->Name) &&
                  !DpPolicyNameIsShadow(&RenameContext->TargetNameInfo->Name);

    if (isProtected) {
        FltReferenceFileNameInformation(RenameContext->TargetNameInfo);
        *EffectiveNameInfo = RenameContext->TargetNameInfo;
    } else {
        DP_TRACE_PPTX_NAME("RenameTargetNotProtected",
                           &RenameContext->TargetNameInfo->Name,
                           STATUS_SUCCESS,
                           isProtected,
                           0,
                           0,
                           0);
    }

    return isProtected;
}

static
BOOLEAN
DpRenameTargetRemainsWebShellProtected(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PDP_RENAME_CONTEXT RenameContext,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION *EffectiveNameInfo
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION tunneledNameInfo = NULL;
    BOOLEAN protectedPath = FALSE;

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
            protectedPath = DpWebShellIsProtectedPath(&tunneledNameInfo->Name) &&
                            DpWebShellIsScriptPath(&tunneledNameInfo->Name, NULL);
        }

        if (protectedPath) {
            *EffectiveNameInfo = tunneledNameInfo;
        } else {
            FltReleaseFileNameInformation(tunneledNameInfo);
        }

        return protectedPath;
    }

    protectedPath = DpWebShellIsProtectedPath(&RenameContext->TargetNameInfo->Name) &&
                    DpWebShellIsScriptPath(&RenameContext->TargetNameInfo->Name, NULL);

    if (protectedPath) {
        FltReferenceFileNameInformation(RenameContext->TargetNameInfo);
        *EffectiveNameInfo = RenameContext->TargetNameInfo;
    }

    return protectedPath;
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
    PFLT_FILE_NAME_INFORMATION webShellNameInfo = NULL;
    BOOLEAN trusted = FALSE;

    if (renameContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) &&
        NT_SUCCESS(Data->IoStatus.Status) &&
        FltObjects->FileObject != NULL) {

        if (renameContext->InspectWebShellAfterRename &&
            !renameContext->WebShellAlreadyInspected &&
            DpRenameTargetRemainsWebShellProtected(Data, renameContext, &webShellNameInfo)) {

            status = DpWebShellInspectFileByName(FltObjects->Instance,
                                                 &webShellNameInfo->Name,
                                                 FltGetRequestorProcessIdEx(Data),
                                                 DpWebShellOperationRename);
            (VOID)DpMarkWebShellCandidateIfNeeded(FltObjects,
                                                  &webShellNameInfo->Name,
                                                  TRUE);
            DpMarkHandleWebShellReported(FltObjects);
            if (status == STATUS_ACCESS_DENIED) {
                status = DpTruncateWebShellFileByName(FltObjects->Instance,
                                                      &webShellNameInfo->Name);
                if (!NT_SUCCESS(status)) {
                    (VOID)DpShadowTruncateFileObject(FltObjects->Instance,
                                                     FltObjects->FileObject);
                }
            }
        }

        if (renameContext->EncryptAfterRename &&
            DpRenameTargetRemainsProtected(Data, renameContext, &effectiveNameInfo)) {

            trusted = DpProcessPolicyIsTrusted(Data, &effectiveNameInfo->Name);
            DP_TRACE_PPTX_NAME("RenamePostTarget",
                               &effectiveNameInfo->Name,
                               Data->IoStatus.Status,
                               trusted,
                               renameContext->EncryptAfterRename,
                               0,
                               0);
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
                DP_TRACE_PPTX_NAME("RenameArmEncryptFailed",
                                   &effectiveNameInfo->Name,
                                   status,
                                   trusted,
                                   renameContext->EncryptAfterRename,
                                   0,
                                   0);
            } else {
                DP_TRACE_PPTX_NAME("RenameArmEncryptDone",
                                   &effectiveNameInfo->Name,
                                   status,
                                   trusted,
                                   renameContext->EncryptAfterRename,
                                   0,
                                   0);
            }
        }
    }

Exit:
    if (webShellNameInfo != NULL) {
        FltReleaseFileNameInformation(webShellNameInfo);
    }

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

    if (DpLateralDefenseShouldBlockIpcCreate(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpLateralDefenseIsNamedPipeOrMailslot(FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpLateralDefenseShouldBlockCreate(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpDeviceControlShouldBlockCreate(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpHashProtectShouldBlockCreate(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    status = DpShadowPreCreate(Data, FltObjects, &createContext);
    if (status == STATUS_REPARSE) {
        DP_TRACE_PPTX_DATA("PreCreateShadowReparse",
                           Data,
                           FltObjects,
                           status,
                           0,
                           0,
                           0,
                           0);
        DpShadowFreeCreateContext(createContext);
        return FLT_PREOP_COMPLETE;
    }

    if (!NT_SUCCESS(status)) {
        DP_TRACE_PPTX_DATA("PreCreateDenied",
                           Data,
                           FltObjects,
                           status,
                           0,
                           0,
                           0,
                           0);
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
    DP_PROTECTION_FOOTER footer;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PDP_CREATE_CONTEXT createContext = (PDP_CREATE_CONTEXT)CompletionContext;
    PFLT_CONTEXT oldContext = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG createDisposition;
    ACCESS_MASK desiredAccess = 0;
    BOOLEAN hunterReadIntent = FALSE;
    ULONG hunterFlags = DP_FILE_HUNTER_READ_FLAG_CREATE_OPEN;

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
            DP_TRACE_PPTX_NAME("PostCreateShadowHandle",
                               &createContext->OriginalName,
                               status,
                               createContext->IsTrusted,
                               createContext->IsShadow,
                               createContext->ShadowDirty,
                               Data->IoStatus.Information);

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

        if (!NT_SUCCESS(status)) {
            status = FltGetFileNameInformation(Data,
                                               FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                               &nameInfo);
        }

        if (NT_SUCCESS(status)) {
            createDisposition = Data->Iopb->Parameters.Create.Options >> 24;
            createdOrReplaced = Data->IoStatus.Information == FILE_CREATED ||
                                Data->IoStatus.Information == FILE_OVERWRITTEN ||
                                Data->IoStatus.Information == FILE_SUPERSEDED ||
                                DpCreateDispositionWillReplaceFile(createDisposition);

            if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
                desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                hunterReadIntent = !createdOrReplaced &&
                                   DpFileHunterCreateGrantsReadIntent(desiredAccess);
                hunterFlags = DpFileHunterFlagsFromCreateAccess(desiredAccess);
            }

            if (hunterReadIntent) {
                DpFileHunterReportReadByName(&nameInfo->Name,
                                             FltGetRequestorProcess(Data),
                                             FltGetRequestorProcessIdEx(Data),
                                             hunterFlags,
                                             (ULONG)Data->IoStatus.Status,
                                             1);
            }

            pathProtected = DpPolicyNameIsProtected(&nameInfo->Name) &&
                            !DpPolicyNameIsShadow(&nameInfo->Name);

            if (pathProtected) {
                RtlZeroMemory(&footer, sizeof(footer));
                (VOID)DpPolicyReadProtectionFooter(FltObjects->Instance,
                                                  &nameInfo->Name,
                                                  &footer,
                                                  &markerPresent);

                isProtected = markerPresent;
            }

            DP_TRACE_PPTX_NAME("PostCreatePolicy",
                               &nameInfo->Name,
                               Data->IoStatus.Status,
                               pathProtected,
                               markerPresent,
                               isProtected,
                               Data->IoStatus.Information);
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
                DpApplyDefaultFileKeyToHandle(handleContext);
                if (isProtected && markerPresent) {
                    DpApplyFooterToHandle(handleContext, &footer);
                }

                if (nameInfo != NULL) {
                    handleContext->IsTrusted = DpProcessPolicyIsTrusted(Data, &nameInfo->Name);

                    if (createdOrReplaced &&
                        DpWebShellIsProtectedPath(&nameInfo->Name) &&
                        DpWebShellIsScriptPath(&nameInfo->Name, NULL)) {

                        handleContext->WebShellNewFile = TRUE;
                        handleContext->WebShellReported = FALSE;
                    }

                    if (!markerPresent &&
                        createdOrReplaced &&
                        handleContext->IsTrusted) {

                        handleContext->EncryptOnCleanup = TRUE;
                        (VOID)DpDuplicateName(&nameInfo->Name,
                                              &handleContext->PendingName);
                        handleContext->LogicalSize.QuadPart = 0;
                    }

                    DP_TRACE_PPTX_NAME("PostCreateHandle",
                                       &nameInfo->Name,
                                       status,
                                       handleContext->IsProtected,
                                       handleContext->IsTrusted,
                                       handleContext->EncryptOnCleanup,
                                       createdOrReplaced);
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

        if (!pathProtected && nameInfo != NULL) {
            createDisposition = Data->Iopb->Parameters.Create.Options >> 24;
            createdOrReplaced = Data->IoStatus.Information == FILE_CREATED ||
                                Data->IoStatus.Information == FILE_OVERWRITTEN ||
                                Data->IoStatus.Information == FILE_SUPERSEDED ||
                                DpCreateDispositionWillReplaceFile(createDisposition);

            if (createdOrReplaced) {
                (VOID)DpMarkWebShellCandidateIfNeeded(FltObjects,
                                                      &nameInfo->Name,
                                                      TRUE);
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
    BOOLEAN isProtected = FALSE;
    BOOLEAN isTrusted = FALSE;
    BOOLEAN plaintextCacheEnabled;
    NTSTATUS status;
    ULONG length;
    ULONG originalLength;
    LARGE_INTEGER logicalSize;
    LONGLONG readOffset;
    PDP_IO_CONTEXT ioContext;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PDP_FILE_HUNTER_READ_CONTEXT fileHunterContext = NULL;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    *CompletionContext = NULL;

    length = iopb->Parameters.Read.Length;
    originalLength = length;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpHashProtectShouldBlockRawVolumeRead(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (!DpCanProcessOperation(Data, FltObjects, length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpFileHunterPrepareReadAudit(Data,
                                          FltObjects,
                                          length,
                                          &fileHunterContext);
    if (!NT_SUCCESS(status)) {
        fileHunterContext = NULL;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status) || !isProtected) {
        DP_TRACE_PPTX_DATA("PreReadBypass",
                           Data,
                           FltObjects,
                           status,
                           isProtected,
                           isTrusted,
                           length,
                           DpIsPagingIo(Data));
        return DpArmFileHunterAuditRead(Data,
                                        FltObjects,
                                        length,
                                        &fileHunterContext,
                                        CompletionContext);
    }

    status = DpGetLogicalSizeForHandle(FltObjects,
                                       &logicalSize,
                                       &handleContext);

    if (NT_SUCCESS(status)) {
        readOffset = iopb->Parameters.Read.ByteOffset.QuadPart;

        if (readOffset < 0 || readOffset >= logicalSize.QuadPart) {
            DpReleaseHandleContext(handleContext);
            DpFileHunterFreeReadContext(fileHunterContext);
            Data->IoStatus.Status = STATUS_END_OF_FILE;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        if ((ULONGLONG)length > (ULONGLONG)(logicalSize.QuadPart - readOffset)) {
            length = (ULONG)(logicalSize.QuadPart - readOffset);
            iopb->Parameters.Read.Length = length;
            FLT_SET_CALLBACK_DATA_DIRTY(Data);
        }
    } else {
        DpReleaseHandleContext(handleContext);
        handleContext = NULL;
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
        DpReleaseHandleContext(handleContext);
        DP_TRACE_PPTX_DATA("PreReadCiphertext",
                           Data,
                           FltObjects,
                           STATUS_SUCCESS,
                           isProtected,
                           isTrusted,
                           originalLength,
                           DpIsPagingIo(Data));
        return DpArmFileHunterAuditRead(Data,
                                        FltObjects,
                                        length,
                                        &fileHunterContext,
                                        CompletionContext);
    }

    if (!DpIsPagingIo(Data) && isTrusted && plaintextCacheEnabled) {
        DpReleaseHandleContext(handleContext);
        return DpArmFileHunterAuditRead(Data,
                                        FltObjects,
                                        length,
                                        &fileHunterContext,
                                        CompletionContext);
    }

    if (DpIsPagingIo(Data) && !plaintextCacheEnabled) {
        DpReleaseHandleContext(handleContext);
        DP_TRACE_PPTX_DATA("PreReadPagingBypass",
                           Data,
                           FltObjects,
                           STATUS_SUCCESS,
                           isProtected,
                           isTrusted,
                           originalLength,
                           plaintextCacheEnabled);
        return DpArmFileHunterAuditRead(Data,
                                        FltObjects,
                                        length,
                                        &fileHunterContext,
                                        CompletionContext);
    }

    if (!DpCryptoIsReady()) {
        DP_TRACE_PPTX_DATA("PreReadCryptoNotReady",
                           Data,
                           FltObjects,
                           STATUS_ACCESS_DENIED,
                           isProtected,
                           isTrusted,
                           originalLength,
                           DpIsPagingIo(Data));
        DpReleaseHandleContext(handleContext);
        DpFileHunterFreeReadContext(fileHunterContext);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpIsPagingIo(Data)) {
        ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoRead, 1);
        if (ioContext == NULL) {
            DpReleaseHandleContext(handleContext);
            DpFileHunterFreeReadContext(fileHunterContext);
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        ioContext->OriginalBuffer = iopb->Parameters.Read.ReadBuffer;
        ioContext->OriginalMdl = iopb->Parameters.Read.MdlAddress;
        ioContext->ByteOffset = iopb->Parameters.Read.ByteOffset;
        ioContext->Length = length;
        ioContext->FileHunterContext = fileHunterContext;
        fileHunterContext = NULL;
        if (handleContext != NULL && handleContext->FileKeyLength != 0) {
            ioContext->FileKeyLength = handleContext->FileKeyLength;
            RtlCopyMemory(ioContext->FileKey,
                          handleContext->FileKey,
                          min(handleContext->FileKeyLength, (ULONG)DP_FILE_KEY_LENGTH));
        }
        ioContext->TransformInPlace = TRUE;
        *CompletionContext = ioContext;
        DpReleaseHandleContext(handleContext);
        DP_TRACE_PPTX_DATA("PreReadTransformPaging",
                           Data,
                           FltObjects,
                           STATUS_SUCCESS,
                           isProtected,
                           isTrusted,
                           originalLength,
                           ioContext->ByteOffset.QuadPart);

        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoRead, length);
    if (ioContext == NULL) {
        DpReleaseHandleContext(handleContext);
        DpFileHunterFreeReadContext(fileHunterContext);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext->OriginalBuffer = iopb->Parameters.Read.ReadBuffer;
    ioContext->OriginalMdl = iopb->Parameters.Read.MdlAddress;
    ioContext->ByteOffset = iopb->Parameters.Read.ByteOffset;
    ioContext->FileHunterContext = fileHunterContext;
    fileHunterContext = NULL;
    if (handleContext != NULL && handleContext->FileKeyLength != 0) {
        ioContext->FileKeyLength = handleContext->FileKeyLength;
        RtlCopyMemory(ioContext->FileKey,
                      handleContext->FileKey,
                      min(handleContext->FileKeyLength, (ULONG)DP_FILE_KEY_LENGTH));
    }
    ioContext->HandleContext = handleContext;
    handleContext = NULL;

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

    DP_TRACE_PPTX_DATA("PreReadTransform",
                       Data,
                       FltObjects,
                       STATUS_SUCCESS,
                       isProtected,
                       isTrusted,
                       originalLength,
                       ioContext->ByteOffset.QuadPart);

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

        if (ioContext->FileHunterContext != NULL) {
            DpFileHunterReportReadSuccess(ioContext->FileHunterContext,
                                          (ULONG)Data->IoStatus.Status,
                                          Data->IoStatus.Information);
        }

        if (ioContext->FileHunterAuditOnly) {
            DpFreeIoContext(ioContext);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        DP_TRACE_PPTX_DATA("PostReadTransform",
                           Data,
                           FltObjects,
                           Data->IoStatus.Status,
                           bytesRead,
                           ioContext->Length,
                           ioContext->TransformInPlace,
                           ioContext->ByteOffset.QuadPart);

        if (ioContext->TransformInPlace) {
            destination = DpGetSystemBufferAddress(Data,
                                                   ioContext->OriginalMdl,
                                                   ioContext->OriginalBuffer);

            if (destination == NULL) {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
            } else {
                DpCryptoTransformBufferWithKey((PUCHAR)destination,
                                               bytesRead,
                                               ioContext->ByteOffset,
                                               ioContext->FileKey,
                                               ioContext->FileKeyLength);
            }

            DpFreeIoContext(ioContext);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        DpCryptoTransformBufferWithKey((PUCHAR)ioContext->SwapBuffer,
                                       bytesRead,
                                       ioContext->ByteOffset,
                                       ioContext->FileKey,
                                       ioContext->FileKeyLength);

        destination = DpGetSystemBufferAddress(Data,
                                               ioContext->OriginalMdl,
                                               ioContext->OriginalBuffer);

        if (destination == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        } else {
            RtlCopyMemory(destination, ioContext->SwapBuffer, bytesRead);
        }
    } else if (ioContext->FileHunterAuditOnly) {
        DpFreeIoContext(ioContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
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
    BOOLEAN isProtected = FALSE;
    BOOLEAN isTrusted = FALSE;
    BOOLEAN plaintextCacheEnabled;
    NTSTATUS status;
    NTSTATUS webShellStatus;
    ULONG length;
    LARGE_INTEGER logicalSize;
    PVOID source;
    PDP_IO_CONTEXT ioContext;
    PDP_HANDLE_CONTEXT handleContext = NULL;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    *CompletionContext = NULL;

    length = iopb->Parameters.Write.Length;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpLateralDefenseShouldBlockWrite(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (DpLateralDefenseIsNamedPipeOrMailslot(FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpDeviceControlShouldBlockWrite(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (!DpCanProcessOperation(Data, FltObjects, length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    (VOID)DpArmWebShellWriteInspectionIfTargeted(Data, FltObjects);

    if (DpInspectWebShellWriteByCurrentName(Data,
                                            FltObjects,
                                            length,
                                            &webShellStatus) &&
        !NT_SUCCESS(webShellStatus)) {

        DP_WEBSHELL_IO_TRACE("prewrite complete deny status=0x%08X length=%lu\n",
                             webShellStatus,
                             length);
        Data->IoStatus.Status = webShellStatus;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status)) {
        DP_TRACE_PPTX_DATA("PreWriteNoContext",
                           Data,
                           FltObjects,
                           status,
                           isProtected,
                           isTrusted,
                           length,
                           DpIsPagingIo(Data));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    (VOID)DpShadowMarkHandleDirty(FltObjects);

    if (!isProtected) {
        if (DpHandleNeedsWebShellInspection(FltObjects)) {
            source = DpGetSystemBufferAddress(Data,
                                              iopb->Parameters.Write.MdlAddress,
                                              iopb->Parameters.Write.WriteBuffer);

            if (source == NULL &&
                iopb->Parameters.Write.MdlAddress == NULL &&
                Data->RequestorMode != KernelMode) {

                status = FltLockUserBuffer(Data);
                if (NT_SUCCESS(status)) {
                    source = DpGetSystemBufferAddress(Data,
                                                      iopb->Parameters.Write.MdlAddress,
                                                      iopb->Parameters.Write.WriteBuffer);
                }
            }

            if (source != NULL) {
                status = DpWebShellInspectWrite(Data,
                                                FltObjects,
                                                source,
                                                length,
                                                TRUE);
                DpMarkHandleWebShellReported(FltObjects);

                if (!NT_SUCCESS(status)) {
                    Data->IoStatus.Status = status;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }
            }
        }

        status = DpArmTrustedPathEncryptOnCleanup(Data,
                                                  FltObjects,
                                                  "PreWriteArmPath",
                                                  length,
                                                  DpIsPagingIo(Data));
        DP_TRACE_PPTX_DATA("PreWritePlainBypass",
                           Data,
                           FltObjects,
                           status,
                           isProtected,
                           isTrusted,
                           length,
                           DpIsPagingIo(Data));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpHandleNeedsWebShellInspection(FltObjects)) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

        source = DpGetSystemBufferAddress(Data,
                                          iopb->Parameters.Write.MdlAddress,
                                          iopb->Parameters.Write.WriteBuffer);

        if (source == NULL &&
            iopb->Parameters.Write.MdlAddress == NULL &&
            Data->RequestorMode != KernelMode) {

            status = FltLockUserBuffer(Data);
            if (NT_SUCCESS(status)) {
                source = DpGetSystemBufferAddress(Data,
                                                  iopb->Parameters.Write.MdlAddress,
                                                  iopb->Parameters.Write.WriteBuffer);
            }
        }

        if (source != NULL) {
            status = FltGetFileNameInformation(Data,
                                               FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                               &nameInfo);
            if (NT_SUCCESS(status)) {
                status = DpWebShellInspectWriteByName(&nameInfo->Name,
                                                      FltGetRequestorProcessIdEx(Data),
                                                      source,
                                                      length,
                                                      DpWebShellOperationWrite);
                FltReleaseFileNameInformation(nameInfo);
            } else {
                status = STATUS_SUCCESS;
            }

            DpMarkHandleWebShellReported(FltObjects);

            if (!NT_SUCCESS(status)) {
                if (handleContext != NULL) {
                    DpReleaseHandleContext(handleContext);
                }
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
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
        DP_TRACE_PPTX_DATA("PreWriteDeniedUntrusted",
                           Data,
                           FltObjects,
                           STATUS_ACCESS_DENIED,
                           isProtected,
                           isTrusted,
                           length,
                           DpIsPagingIo(Data));
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    status = DpGetLogicalSizeForHandle(FltObjects,
                                       &logicalSize,
                                       &handleContext);
    if (handleContext == NULL) {
        status = STATUS_NOT_FOUND;
    }

    if (NT_SUCCESS(status) &&
        iopb->Parameters.Write.ByteOffset.LowPart != FILE_USE_FILE_POINTER_POSITION &&
        iopb->Parameters.Write.ByteOffset.LowPart != FILE_WRITE_TO_END_OF_FILE) {

        if (iopb->Parameters.Write.ByteOffset.QuadPart > logicalSize.QuadPart) {
            if (handleContext != NULL && !handleContext->IsShadow) {
                DpReleaseHandleContext(handleContext);
                Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
    }

    if (!DpIsPagingIo(Data) && plaintextCacheEnabled) {
        DpReleaseHandleContext(handleContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpIsPagingIo(Data) && !plaintextCacheEnabled) {
        DpReleaseHandleContext(handleContext);
        DP_TRACE_PPTX_DATA("PreWritePagingBypass",
                           Data,
                           FltObjects,
                           STATUS_SUCCESS,
                           isProtected,
                           isTrusted,
                           length,
                           plaintextCacheEnabled);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!DpCryptoIsReady()) {
        DpReleaseHandleContext(handleContext);
        DP_TRACE_PPTX_DATA("PreWriteCryptoNotReady",
                           Data,
                           FltObjects,
                           STATUS_ACCESS_DENIED,
                           isProtected,
                           isTrusted,
                           length,
                           DpIsPagingIo(Data));
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext = DpAllocateIoContext(FltObjects->Instance, DpIoWrite, length);
    if (ioContext == NULL) {
        DpReleaseHandleContext(handleContext);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ioContext->OriginalBuffer = iopb->Parameters.Write.WriteBuffer;
    ioContext->OriginalMdl = iopb->Parameters.Write.MdlAddress;
    ioContext->ByteOffset = iopb->Parameters.Write.ByteOffset;
    if (handleContext != NULL && handleContext->FileKeyLength != 0) {
        ioContext->FileKeyLength = handleContext->FileKeyLength;
        RtlCopyMemory(ioContext->FileKey,
                      handleContext->FileKey,
                      min(handleContext->FileKeyLength, (ULONG)DP_FILE_KEY_LENGTH));
    }
    ioContext->HandleContext = handleContext;
    handleContext = NULL;

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
    DpCryptoTransformBufferWithKey((PUCHAR)ioContext->SwapBuffer,
                                   length,
                                   ioContext->ByteOffset,
                                   ioContext->FileKey,
                                   ioContext->FileKeyLength);

    iopb->Parameters.Write.WriteBuffer = ioContext->SwapBuffer;
    iopb->Parameters.Write.MdlAddress = NULL;

    FLT_SET_CALLBACK_DATA_DIRTY(Data);

    *CompletionContext = ioContext;

    DP_TRACE_PPTX_DATA("PreWriteTransform",
                       Data,
                       FltObjects,
                       STATUS_SUCCESS,
                       isProtected,
                       isTrusted,
                       length,
                       ioContext->ByteOffset.QuadPart);

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
        DP_TRACE_PPTX_DATA("PostWriteRestore",
                           Data,
                           FltObjects,
                           Data->IoStatus.Status,
                           Data->IoStatus.Information,
                           ioContext->Length,
                           ioContext->ByteOffset.QuadPart,
                           0);
        if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
            DpUpdateReferencedHandleLogicalSizeAfterWrite(ioContext->HandleContext,
                                                          ioContext->ByteOffset,
                                                          Data->IoStatus.Information);
        }

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

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        (VOID)DpInspectWebShellOnCleanup(Data, FltObjects, handleContext);
        (VOID)DpInspectStaticScanOnCleanup(Data, FltObjects, handleContext);

        DP_TRACE_PPTX_DATA("PreCleanupHandle",
                           Data,
                           FltObjects,
                           status,
                           handleContext->IsProtected,
                           handleContext->IsTrusted,
                           handleContext->IsShadow,
                           handleContext->EncryptOnCleanup);
        status = DpFinalizeEncryptOnCleanup(Data, FltObjects, handleContext);
        if (!NT_SUCCESS(status)) {
            DP_DBG_PRINT(DP_TRACE_IO,
                         ("DataProtector!DpPreCleanup: finalize encryption failed 0x%08X\n",
                          status));
        } else {
            status = DpShadowCleanupHandle(FltObjects, handleContext);
            DP_TRACE_PPTX_DATA("PreCleanupShadow",
                               Data,
                               FltObjects,
                               status,
                               handleContext->IsProtected,
                               handleContext->IsTrusted,
                               handleContext->IsShadow,
                               handleContext->ShadowDirty);
        }

        DpReleaseHandleContext(handleContext);
    } else {
        (VOID)DpInspectWebShellOnCleanup(Data, FltObjects, NULL);
        (VOID)DpInspectStaticScanOnCleanup(Data, FltObjects, NULL);
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

    if (DpLateralDefenseIsNamedPipeOrMailslot(FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (DpDeviceControlShouldBlockSetInformation(Data, FltObjects)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (DpIsRenameInformationClass(informationClass)) {
        (VOID)DpShadowMarkHandleDirty(FltObjects);

        status = DpGetRenameTargetInformation(Data,
                                              FltObjects,
                                              &targetNameInfo);

        if (!NT_SUCCESS(status)) {
            DP_TRACE_PPTX_DATA("PreRenameNoTarget",
                               Data,
                               FltObjects,
                               status,
                               isProtected,
                               isTrusted,
                               informationClass,
                               0);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (DpLateralDefenseShouldBlockRename(Data,
                                              FltObjects,
                                              &targetNameInfo->Name)) {
            FltReleaseFileNameInformation(targetNameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
        if (!NT_SUCCESS(status)) {
            isProtected = FALSE;
            isTrusted = FALSE;
        }

        DP_TRACE_PPTX_NAME("PreRenameTarget",
                           &targetNameInfo->Name,
                           status,
                           isProtected,
                           isTrusted,
                           informationClass,
                           0);

        if (!isProtected &&
            DpPolicyNameIsProtected(&targetNameInfo->Name) &&
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

        if (DpWebShellIsProtectedPath(&targetNameInfo->Name) &&
            DpWebShellIsScriptPath(&targetNameInfo->Name, NULL)) {

            status = DpInspectWebShellRenameSource(Data,
                                                   FltObjects,
                                                   &targetNameInfo->Name);
            if (!NT_SUCCESS(status)) {
                DP_WEBSHELL_IO_TRACE("prerename complete deny status=0x%08X target=%wZ\n",
                                     status,
                                     &targetNameInfo->Name);
                FltReleaseFileNameInformation(targetNameInfo);
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }

            if (renameContext == NULL) {
                renameContext = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                      sizeof(DP_RENAME_CONTEXT),
                                                      DP_TAG_RENAME_CONTEXT);
                if (renameContext != NULL) {
                    RtlZeroMemory(renameContext, sizeof(DP_RENAME_CONTEXT));
                    FltReferenceFileNameInformation(targetNameInfo);
                    renameContext->TargetNameInfo = targetNameInfo;
                    *CompletionContext = renameContext;
                }
            }

            if (renameContext != NULL) {
                renameContext->InspectWebShellAfterRename = TRUE;
                renameContext->WebShellAlreadyInspected = TRUE;
            }
        }

        DP_TRACE_PPTX_NAME("PreRenameDecision",
                           &targetNameInfo->Name,
                           STATUS_SUCCESS,
                           renameContext != NULL,
                           isProtected,
                           isTrusted,
                           informationClass);

        FltReleaseFileNameInformation(targetNameInfo);

        if (renameContext != NULL) {
            return FLT_PREOP_SYNCHRONIZE;
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    switch (informationClass) {
    case FileEndOfFileInformation:
    case FileAllocationInformation:
        (VOID)DpShadowMarkHandleDirty(FltObjects);
        status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
        if (NT_SUCCESS(status) && !isProtected) {
            (VOID)DpArmTrustedPathEncryptOnCleanup(Data,
                                                   FltObjects,
                                                   "PreSetInfoArmPath",
                                                   informationClass,
                                                   0);
        } else if (NT_SUCCESS(status) && isProtected) {
            PDP_HANDLE_CONTEXT handleContext = NULL;

            status = DpGetHandleContext(FltObjects, &handleContext);
            if (NT_SUCCESS(status) && handleContext != NULL) {
                if (informationClass == FileEndOfFileInformation &&
                    Data->Iopb->Parameters.SetFileInformation.InfoBuffer != NULL &&
                    Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_END_OF_FILE_INFORMATION)) {

                    handleContext->LogicalSize =
                        ((PFILE_END_OF_FILE_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile;
                    handleContext->FooterDirty = TRUE;
                } else if (informationClass == FileAllocationInformation &&
                           Data->Iopb->Parameters.SetFileInformation.InfoBuffer != NULL &&
                           Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_ALLOCATION_INFORMATION)) {

                    if (((PFILE_ALLOCATION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->AllocationSize.QuadPart <
                        handleContext->LogicalSize.QuadPart) {
                        handleContext->LogicalSize =
                            ((PFILE_ALLOCATION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->AllocationSize;
                        handleContext->FooterDirty = TRUE;
                    }
                }

                DpReleaseHandleContext(handleContext);
            }
        }
        break;

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
DpPreQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    BOOLEAN isProtected = FALSE;
    BOOLEAN isTrusted = FALSE;
    NTSTATUS status;
    FILE_INFORMATION_CLASS informationClass;

    UNREFERENCED_PARAMETER(isTrusted);

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo() ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    if (!DpInformationClassHasVisibleSize(informationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DpGetHandleTrust(FltObjects, &isProtected, &isTrusted);
    if (!NT_SUCCESS(status) || !isProtected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SYNCHRONIZE;
}

FLT_PREOP_CALLBACK_STATUS
DpPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    FILE_INFORMATION_CLASS informationClass;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDP_DIRECTORY_CONTEXT directoryContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);

    *CompletionContext = NULL;

    if (DpShadowIsInternalIo() ||
        Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    if (!DpDirectoryClassHasVisibleSize(informationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    directoryContext = ExAllocatePoolWithTag(PagedPool,
                                             sizeof(DP_DIRECTORY_CONTEXT),
                                             DP_TAG_NAME_BUFFER);
    if (directoryContext == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(directoryContext, sizeof(DP_DIRECTORY_CONTEXT));
    status = DpDuplicateName(&nameInfo->Name,
                             &directoryContext->DirectoryName);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(status)) {
        DpFreeDirectoryContext(directoryContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = directoryContext;

    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PDP_DIRECTORY_CONTEXT directoryContext = (PDP_DIRECTORY_CONTEXT)CompletionContext;
    FILE_INFORMATION_CLASS informationClass;
    PVOID buffer;
    ULONG length;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {

        DpFreeDirectoryContext(directoryContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Information == 0) {

        DpFreeDirectoryContext(directoryContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (directoryContext == NULL ||
        directoryContext->DirectoryName.Buffer == NULL) {

        DpFreeDirectoryContext(directoryContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    informationClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    length = (ULONG)min(Data->IoStatus.Information,
                       Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length);
    buffer = FltGetNewSystemBufferAddress(Data);
    if (buffer == NULL) {
        buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    }

    DpAdjustDirectoryBufferSizes(buffer,
                                 length,
                                 informationClass,
                                 FltObjects->Instance,
                                 &directoryContext->DirectoryName);
    FLT_SET_CALLBACK_DATA_DIRTY(Data);
    DpFreeDirectoryContext(directoryContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
DpPostQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    LARGE_INTEGER logicalSize;
    FILE_INFORMATION_CLASS informationClass;
    PVOID buffer;
    ULONG length;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Information == 0) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    informationClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    length = Data->Iopb->Parameters.QueryFileInformation.Length;
    buffer = FltGetNewSystemBufferAddress(Data);
    if (buffer == NULL) {
        buffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
    }

    status = DpGetLogicalSizeForHandle(FltObjects,
                                       &logicalSize,
                                       NULL);

    if (NT_SUCCESS(status)) {
        DpAdjustInformationSizeBuffer(buffer,
                                      length,
                                      informationClass,
                                      logicalSize);

        FLT_SET_CALLBACK_DATA_DIRTY(Data);
    }

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
    ULONG hunterFlags;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

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

    if (!FlagOn(iopb->Parameters.AcquireForSectionSynchronization.PageProtection, writeMask) &&
        KeGetCurrentIrql() <= APC_LEVEL) {

        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);
        if (!NT_SUCCESS(status)) {
            status = FltGetFileNameInformation(Data,
                                               FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                               &nameInfo);
        }

        if (NT_SUCCESS(status) && nameInfo != NULL) {
            hunterFlags = DP_FILE_HUNTER_READ_FLAG_SECTION_MAP;
            if (iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection) {
                if (FlagOn(iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
                           PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    hunterFlags |= DP_FILE_HUNTER_READ_FLAG_IMAGE_SECTION |
                                   DP_FILE_HUNTER_READ_FLAG_EXECUTE_ACCESS;
                }
            }

            DpFileHunterReportReadByName(&nameInfo->Name,
                                         FltGetRequestorProcess(Data),
                                         FltGetRequestorProcessIdEx(Data),
                                         hunterFlags,
                                         STATUS_SUCCESS,
                                         1);

            FltReleaseFileNameInformation(nameInfo);
        }
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
