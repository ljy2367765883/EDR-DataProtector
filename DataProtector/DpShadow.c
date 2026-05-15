/*++

Module Name:

    DpShadow.c

Abstract:

    Shadow-file virtualization for protected files. Trusted applications are
    redirected to a plaintext shadow stream so cached and mapped I/O never
    places plaintext in the original protected file cache.

--*/

#include "DataProtector.h"

#define DP_SHADOW_SUFFIX L":DataProtectorShadow"
#define DP_SHADOW_COPY_CHUNK (64 * 1024)

static ERESOURCE gDpShadowResource;

typedef struct _DP_INTERNAL_IO_GUARD {
    PVOID PreviousTopLevelIrp;
} DP_INTERNAL_IO_GUARD, *PDP_INTERNAL_IO_GUARD;

static
VOID
DpShadowBeginInternalIo(
    _Out_ PDP_INTERNAL_IO_GUARD Guard
    )
{
    Guard->PreviousTopLevelIrp = IoGetTopLevelIrp();
    IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
}

static
VOID
DpShadowEndInternalIo(
    _In_ PDP_INTERNAL_IO_GUARD Guard
    )
{
    IoSetTopLevelIrp((PIRP)Guard->PreviousTopLevelIrp);
}

BOOLEAN
DpShadowIsInternalIo(
    VOID
    )
{
    return IoGetTopLevelIrp() == (PIRP)FSRTL_FSP_TOP_LEVEL_IRP;
}

VOID
DpShadowInitialize(
    VOID
    )
{
    ExInitializeResourceLite(&gDpShadowResource);
}

VOID
DpShadowUninitialize(
    VOID
    )
{
    ExDeleteResourceLite(&gDpShadowResource);
}

static
NTSTATUS
DpShadowDuplicateName(
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
NTSTATUS
DpShadowBuildShadowName(
    _In_ PCUNICODE_STRING OriginalName,
    _Out_ PUNICODE_STRING ShadowName
    )
{
    UNICODE_STRING suffix;

    ShadowName->Buffer = NULL;
    ShadowName->Length = 0;
    ShadowName->MaximumLength = 0;

    if (OriginalName == NULL ||
        OriginalName->Buffer == NULL ||
        OriginalName->Length == 0 ||
        OriginalName->Length > MAXUSHORT - (sizeof(DP_SHADOW_SUFFIX) - sizeof(WCHAR))) {

        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&suffix, DP_SHADOW_SUFFIX);

    ShadowName->Length = OriginalName->Length + suffix.Length;
    ShadowName->MaximumLength = ShadowName->Length;
    ShadowName->Buffer = ExAllocatePoolWithTag(PagedPool,
                                               ShadowName->MaximumLength,
                                               DP_TAG_NAME_BUFFER);

    if (ShadowName->Buffer == NULL) {
        ShadowName->Length = 0;
        ShadowName->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(ShadowName->Buffer,
                  OriginalName->Buffer,
                  OriginalName->Length);

    RtlCopyMemory((PUCHAR)ShadowName->Buffer + OriginalName->Length,
                  suffix.Buffer,
                  suffix.Length);

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpShadowBuildOriginalNameFromShadow(
    _In_ PCUNICODE_STRING ShadowName,
    _Out_ PUNICODE_STRING OriginalName
    )
{
    UNICODE_STRING suffix;
    UNICODE_STRING original;

    OriginalName->Buffer = NULL;
    OriginalName->Length = 0;
    OriginalName->MaximumLength = 0;

    if (!DpPolicyNameIsShadow(ShadowName)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&suffix, DP_SHADOW_SUFFIX);

    original.Buffer = ShadowName->Buffer;
    original.Length = ShadowName->Length - suffix.Length;
    original.MaximumLength = original.Length;

    return DpShadowDuplicateName(&original, OriginalName);
}

static
VOID
DpShadowFreeName(
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
NTSTATUS
DpShadowOpenFile(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ ULONG Flags,
    _Out_ PHANDLE FileHandle,
    _Outptr_ PFILE_OBJECT *FileObject,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    DP_INTERNAL_IO_GUARD guard;

    InitializeObjectAttributes(&objectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    DpShadowBeginInternalIo(&guard);

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
                              Flags,
                              NULL);

    DpShadowEndInternalIo(&guard);

    return status;
}

static
VOID
DpShadowCloseFile(
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

static
NTSTATUS
DpShadowSetFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ LARGE_INTEGER EndOfFile
    )
{
    FILE_END_OF_FILE_INFORMATION endOfFileInfo;
    DP_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    endOfFileInfo.EndOfFile = EndOfFile;

    DpShadowBeginInternalIo(&guard);

    status = FltSetInformationFile(Instance,
                                   FileObject,
                                   &endOfFileInfo,
                                   sizeof(endOfFileInfo),
                                   FileEndOfFileInformation);

    DpShadowEndInternalIo(&guard);

    return status;
}

static
NTSTATUS
DpShadowQueryFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLARGE_INTEGER EndOfFile
    )
{
    FILE_STANDARD_INFORMATION standardInfo;
    DP_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    DpShadowBeginInternalIo(&guard);

    status = FltQueryInformationFile(Instance,
                                     FileObject,
                                     &standardInfo,
                                     sizeof(standardInfo),
                                     FileStandardInformation,
                                     NULL);

    DpShadowEndInternalIo(&guard);

    if (NT_SUCCESS(status)) {
        *EndOfFile = standardInfo.EndOfFile;
    }

    return status;
}

static
NTSTATUS
DpShadowReadRaw(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _Out_ PULONG BytesRead
    )
{
    DP_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    DpShadowBeginInternalIo(&guard);

    status = FltReadFile(Instance,
                         FileObject,
                         ByteOffset,
                         Length,
                         Buffer,
                         FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                         BytesRead,
                         NULL,
                         NULL);

    DpShadowEndInternalIo(&guard);

    return status;
}

static
NTSTATUS
DpShadowWriteRaw(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _In_reads_bytes_(Length) PVOID Buffer,
    _Out_ PULONG BytesWritten
    )
{
    DP_INTERNAL_IO_GUARD guard;
    NTSTATUS status;

    DpShadowBeginInternalIo(&guard);

    status = FltWriteFile(Instance,
                          FileObject,
                          ByteOffset,
                          Length,
                          Buffer,
                          FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                          BytesWritten,
                          NULL,
                          NULL);

    DpShadowEndInternalIo(&guard);

    return status;
}

static
NTSTATUS
DpShadowCopyTransformed(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT SourceFileObject,
    _In_ PFILE_OBJECT DestinationFileObject,
    _In_ BOOLEAN Transform,
    _In_ LARGE_INTEGER SourceSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR buffer;
    LARGE_INTEGER offset;
    ULONG toCopy;
    ULONG bytesRead;
    ULONG bytesWritten;

    buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                   DP_SHADOW_COPY_CHUNK,
                                   DP_TAG_SHADOW_BUFFER);

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    offset.QuadPart = 0;

    while (offset.QuadPart < SourceSize.QuadPart) {
        toCopy = (ULONG)min((LONGLONG)DP_SHADOW_COPY_CHUNK,
                            SourceSize.QuadPart - offset.QuadPart);

        status = DpShadowReadRaw(Instance,
                                 SourceFileObject,
                                 &offset,
                                 toCopy,
                                 buffer,
                                 &bytesRead);

        if (!NT_SUCCESS(status)) {
            break;
        }

        if (bytesRead == 0) {
            break;
        }

        if (Transform) {
            DpCryptoTransformBuffer(buffer, bytesRead, offset);
        }

        status = DpShadowWriteRaw(Instance,
                                  DestinationFileObject,
                                  &offset,
                                  bytesRead,
                                  buffer,
                                  &bytesWritten);

        if (!NT_SUCCESS(status)) {
            break;
        }

        if (bytesWritten != bytesRead) {
            status = STATUS_DISK_FULL;
            break;
        }

        offset.QuadPart += bytesRead;
    }

    RtlSecureZeroMemory(buffer, DP_SHADOW_COPY_CHUNK);
    ExFreePoolWithTag(buffer, DP_TAG_SHADOW_BUFFER);

    return status;
}

static
NTSTATUS
DpShadowSyncOriginalToShadow(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING ShadowName,
    _In_ ULONG CreateDisposition,
    _Out_ PBOOLEAN ShadowDirty
    )
{
    HANDLE originalHandle = NULL;
    HANDLE shadowHandle = NULL;
    PFILE_OBJECT originalFileObject = NULL;
    PFILE_OBJECT shadowFileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER originalSize;
    NTSTATUS status;
    BOOLEAN copyOriginal = TRUE;
    ACCESS_MASK originalAccess = FILE_READ_DATA | SYNCHRONIZE;
    ULONG originalDisposition = FILE_OPEN;

    *ShadowDirty = FALSE;
    originalSize.QuadPart = 0;

    if (!DpCryptoIsReady()) {
        return STATUS_ACCESS_DENIED;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(&gDpShadowResource);

    switch (CreateDisposition) {
    case FILE_CREATE:
        originalAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        originalDisposition = FILE_CREATE;
        copyOriginal = FALSE;
        *ShadowDirty = TRUE;
        break;

    case FILE_OPEN_IF:
        originalAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        originalDisposition = FILE_OPEN_IF;
        break;

    case FILE_OVERWRITE:
        originalAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        originalDisposition = FILE_OVERWRITE;
        copyOriginal = FALSE;
        *ShadowDirty = TRUE;
        break;

    case FILE_OVERWRITE_IF:
        originalAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        originalDisposition = FILE_OVERWRITE_IF;
        copyOriginal = FALSE;
        *ShadowDirty = TRUE;
        break;

    case FILE_SUPERSEDE:
        originalAccess = DELETE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        originalDisposition = FILE_SUPERSEDE;
        copyOriginal = FALSE;
        *ShadowDirty = TRUE;
        break;

    default:
        originalAccess = FILE_READ_DATA | SYNCHRONIZE;
        originalDisposition = FILE_OPEN;
        break;
    }

    status = DpShadowOpenFile(Instance,
                              OriginalName,
                              originalAccess,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              originalDisposition,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              0,
                              &originalHandle,
                              &originalFileObject,
                              &ioStatus);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (ioStatus.Information == FILE_CREATED) {
        copyOriginal = FALSE;
        *ShadowDirty = TRUE;
        goto CreateShadow;
    }

    if (CreateDisposition == FILE_OPEN_IF && ioStatus.Information == FILE_OPENED) {
        *ShadowDirty = FALSE;
    }

    status = DpShadowOpenFile(Instance,
                              ShadowName,
                              FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                              FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OVERWRITE_IF,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              0,
                              &shadowHandle,
                              &shadowFileObject,
                              &ioStatus);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

CreateShadow:
    if (shadowFileObject == NULL) {
        status = DpShadowOpenFile(Instance,
                                  ShadowName,
                                  FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                  FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  FILE_OVERWRITE_IF,
                                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                  0,
                                  &shadowHandle,
                                  &shadowFileObject,
                                  &ioStatus);

        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    if (copyOriginal) {
        status = DpShadowQueryFileSize(Instance,
                                       originalFileObject,
                                       &originalSize);

        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    status = DpShadowSetFileSize(Instance,
                                 shadowFileObject,
                                 originalSize);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (copyOriginal) {
        status = DpShadowCopyTransformed(Instance,
                                         originalFileObject,
                                         shadowFileObject,
                                         TRUE,
                                         originalSize);
    }

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, shadowFileObject);
    }

Exit:
    DpShadowCloseFile(shadowHandle, shadowFileObject);
    DpShadowCloseFile(originalHandle, originalFileObject);
    ExReleaseResourceAndLeaveCriticalRegion(&gDpShadowResource);

    return status;
}

static
NTSTATUS
DpShadowSyncShadowToOriginal(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING ShadowName
    )
{
    HANDLE originalHandle = NULL;
    HANDLE shadowHandle = NULL;
    PFILE_OBJECT originalFileObject = NULL;
    PFILE_OBJECT shadowFileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER shadowSize;
    NTSTATUS status;

    if (!DpCryptoIsReady()) {
        return STATUS_ACCESS_DENIED;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(&gDpShadowResource);

    status = DpShadowOpenFile(Instance,
                              ShadowName,
                              FILE_READ_DATA | SYNCHRONIZE,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              0,
                              &shadowHandle,
                              &shadowFileObject,
                              &ioStatus);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpShadowOpenFile(Instance,
                              OriginalName,
                              FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OVERWRITE_IF,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              0,
                              &originalHandle,
                              &originalFileObject,
                              &ioStatus);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpShadowQueryFileSize(Instance,
                                   shadowFileObject,
                                   &shadowSize);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpShadowSetFileSize(Instance,
                                 originalFileObject,
                                 shadowSize);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpShadowCopyTransformed(Instance,
                                     shadowFileObject,
                                     originalFileObject,
                                     TRUE,
                                     shadowSize);

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, originalFileObject);
    }

Exit:
    DpShadowCloseFile(originalHandle, originalFileObject);
    DpShadowCloseFile(shadowHandle, shadowFileObject);
    ExReleaseResourceAndLeaveCriticalRegion(&gDpShadowResource);

    return status;
}

NTSTATUS
DpShadowEncryptFileObjectInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    )
{
    NTSTATUS status;
    LARGE_INTEGER fileSize;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!DpCryptoIsReady()) {
        return STATUS_ACCESS_DENIED;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(&gDpShadowResource);

    status = DpShadowQueryFileSize(Instance,
                                   FileObject,
                                   &fileSize);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = DpShadowCopyTransformed(Instance,
                                     FileObject,
                                     FileObject,
                                     TRUE,
                                     fileSize);

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, FileObject);
    }

Exit:
    ExReleaseResourceAndLeaveCriticalRegion(&gDpShadowResource);

    return status;
}

NTSTATUS
DpShadowEncryptFileInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING FileName
    )
{
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (Instance == NULL || FileName == NULL || FileName->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DpShadowOpenFile(Instance,
                              FileName,
                              FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                              IO_IGNORE_SHARE_ACCESS_CHECK,
                              &fileHandle,
                              &fileObject,
                              &ioStatus);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpShadowEncryptFileObjectInPlace(Instance, fileObject);

    DpShadowCloseFile(fileHandle, fileObject);

    return status;
}

NTSTATUS
DpShadowTruncateFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    )
{
    LARGE_INTEGER endOfFile;
    NTSTATUS status;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    endOfFile.QuadPart = 0;

    ExEnterCriticalRegionAndAcquireResourceExclusive(&gDpShadowResource);

    status = DpShadowSetFileSize(Instance,
                                 FileObject,
                                 endOfFile);

    if (NT_SUCCESS(status)) {
        (VOID)FltFlushBuffers(Instance, FileObject);
    }

    ExReleaseResourceAndLeaveCriticalRegion(&gDpShadowResource);

    return status;
}

VOID
DpShadowFreeCreateContext(
    _In_opt_ PDP_CREATE_CONTEXT CreateContext
    )
{
    if (CreateContext == NULL) {
        return;
    }

    DpShadowFreeName(&CreateContext->OriginalName);
    DpShadowFreeName(&CreateContext->ShadowName);

    ExFreePoolWithTag(CreateContext, DP_TAG_HANDLE_CONTEXT);
}

NTSTATUS
DpShadowPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PDP_CREATE_CONTEXT *CreateContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDP_CREATE_CONTEXT createContext = NULL;
    BOOLEAN trusted;
    BOOLEAN markerPresent = FALSE;

    *CreateContext = NULL;

    if (DpShadowIsInternalIo() ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        return STATUS_SUCCESS;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    if (DpPolicyNameIsShadow(&nameInfo->Name)) {
        createContext = ExAllocatePoolWithTag(PagedPool,
                                              sizeof(DP_CREATE_CONTEXT),
                                              DP_TAG_HANDLE_CONTEXT);

        if (createContext == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlZeroMemory(createContext, sizeof(DP_CREATE_CONTEXT));

        status = DpShadowDuplicateName(&nameInfo->Name,
                                       &createContext->ShadowName);

        if (!NT_SUCCESS(status)) {
            DpShadowFreeCreateContext(createContext);
            createContext = NULL;
            goto Exit;
        }

        status = DpShadowBuildOriginalNameFromShadow(&createContext->ShadowName,
                                                     &createContext->OriginalName);

        if (!NT_SUCCESS(status)) {
            DpShadowFreeCreateContext(createContext);
            createContext = NULL;
            goto Exit;
        }

        trusted = DpProcessPolicyIsTrusted(Data, &createContext->OriginalName);
        if (!trusted) {
            DpShadowFreeCreateContext(createContext);
            createContext = NULL;
            status = STATUS_ACCESS_DENIED;
            goto Exit;
        }

        createContext->IsTrusted = TRUE;
        createContext->IsShadow = TRUE;
        *CreateContext = createContext;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    if (!DpPolicyNameIsProtected(&nameInfo->Name)) {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    status = DpPolicyFileHasProtectionMarker(FltObjects->Instance,
                                             &nameInfo->Name,
                                             &markerPresent);
    if (!NT_SUCCESS(status) || !markerPresent) {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    trusted = DpProcessPolicyIsTrusted(Data, &nameInfo->Name);
    if (!trusted) {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    createContext = ExAllocatePoolWithTag(PagedPool,
                                          sizeof(DP_CREATE_CONTEXT),
                                          DP_TAG_HANDLE_CONTEXT);

    if (createContext == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(createContext, sizeof(DP_CREATE_CONTEXT));

    status = DpShadowDuplicateName(&nameInfo->Name,
                                   &createContext->OriginalName);

    if (!NT_SUCCESS(status)) {
        DpShadowFreeCreateContext(createContext);
        createContext = NULL;
        goto Exit;
    }

    status = DpShadowBuildShadowName(&createContext->OriginalName,
                                     &createContext->ShadowName);

    if (!NT_SUCCESS(status)) {
        DpShadowFreeCreateContext(createContext);
        createContext = NULL;
        goto Exit;
    }

    status = DpShadowSyncOriginalToShadow(FltObjects->Instance,
                                          &createContext->OriginalName,
                                          &createContext->ShadowName,
                                          Data->Iopb->Parameters.Create.Options >> 24,
                                          &createContext->ShadowDirty);

    if (!NT_SUCCESS(status)) {
        DP_DBG_PRINT(DP_TRACE_SHADOW,
                     ("DataProtector!DpShadowPreCreate: sync original to shadow failed 0x%08X\n",
                      status));
        DpShadowFreeCreateContext(createContext);
        createContext = NULL;
        goto Exit;
    }

    status = IoReplaceFileObjectName(FltObjects->FileObject,
                                     createContext->ShadowName.Buffer,
                                     createContext->ShadowName.Length);

    if (!NT_SUCCESS(status)) {
        DpShadowFreeCreateContext(createContext);
        createContext = NULL;
        goto Exit;
    }

    Data->Iopb->Parameters.Create.Options =
        (Data->Iopb->Parameters.Create.Options & 0x00FFFFFF) |
        (FILE_OPEN_IF << 24);
    FLT_SET_CALLBACK_DATA_DIRTY(Data);

    createContext->IsTrusted = TRUE;
    createContext->IsShadow = TRUE;
    *CreateContext = createContext;
    Data->IoStatus.Status = STATUS_REPARSE;
    Data->IoStatus.Information = IO_REPARSE;
    DP_DBG_PRINT(DP_TRACE_SHADOW,
                 ("DataProtector!DpShadowPreCreate: redirected trusted create to shadow stream\n"));
    status = STATUS_REPARSE;

Exit:
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    return status;
}

NTSTATUS
DpShadowPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PDP_CREATE_CONTEXT CreateContext,
    _Outptr_result_maybenull_ PDP_HANDLE_CONTEXT *HandleContext
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;

    UNREFERENCED_PARAMETER(FltObjects);

    *HandleContext = NULL;

    if (CreateContext == NULL || !CreateContext->IsShadow) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return Data->IoStatus.Status;
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

    handleContext->IsProtected = FALSE;
    handleContext->IsTrusted = CreateContext->IsTrusted;
    handleContext->IsShadow = TRUE;
    handleContext->ShadowDirty = CreateContext->ShadowDirty;

    if (CreateContext->OriginalName.Buffer != NULL) {
        status = DpShadowDuplicateName(&CreateContext->OriginalName,
                                       &handleContext->OriginalName);

        if (!NT_SUCCESS(status)) {
            FltReleaseContext(handleContext);
            return status;
        }
    }

    if (CreateContext->ShadowName.Buffer != NULL) {
        status = DpShadowDuplicateName(&CreateContext->ShadowName,
                                       &handleContext->ShadowName);

        if (!NT_SUCCESS(status)) {
            FltReleaseContext(handleContext);
            return status;
        }
    }

    *HandleContext = handleContext;

    return STATUS_SUCCESS;
}

NTSTATUS
DpShadowCleanupHandle(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PDP_HANDLE_CONTEXT HandleContext
    )
{
    NTSTATUS status;

    if (HandleContext == NULL || !HandleContext->IsShadow || !HandleContext->ShadowDirty) {
        return STATUS_SUCCESS;
    }

    if (HandleContext->OriginalName.Buffer == NULL ||
        HandleContext->ShadowName.Buffer == NULL) {

        return STATUS_SUCCESS;
    }

    status = DpShadowSyncShadowToOriginal(FltObjects->Instance,
                                          &HandleContext->OriginalName,
                                          &HandleContext->ShadowName);

    DP_DBG_PRINT(DP_TRACE_SHADOW,
                 ("DataProtector!DpShadowCleanupHandle: writeback status 0x%08X\n",
                  status));

    return status;
}

NTSTATUS
DpShadowMarkHandleDirty(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PDP_HANDLE_CONTEXT handleContext = NULL;

    status = DpGetHandleContext(FltObjects, &handleContext);
    if (NT_SUCCESS(status) && handleContext != NULL) {
        if (handleContext->IsShadow) {
            handleContext->ShadowDirty = TRUE;
        }

        DpReleaseHandleContext(handleContext);
        return STATUS_SUCCESS;
    }

    if (status == STATUS_NOT_FOUND) {
        return STATUS_SUCCESS;
    }

    return status;
}
