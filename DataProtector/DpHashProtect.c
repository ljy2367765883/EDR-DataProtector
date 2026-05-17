/*++

Module Name:

    DpHashProtect.c

Abstract:

    Credential hash dump hardening. The module protects LSASS from
    unauthorized process-handle access and blocks direct reads of offline
    credential stores, including Volume Shadow Copy paths.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                 (0x0001)
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD             (0x0002)
#endif

#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID             (0x0004)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION              (0x0008)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                   (0x0010)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                  (0x0020)
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                (0x0040)
#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS            (0x0080)
#endif

#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA                 (0x0100)
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION           (0x0200)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION         (0x0400)
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME            (0x0800)
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif

#if DP_ENABLE_HASH_PROTECT_TRACE
#define DP_HASH_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[HashProtect] " _format, __VA_ARGS__)
#else
#define DP_HASH_TRACE(_format, ...) ((void)0)
#endif

#define DP_HASH_OB_ALTITUDE       L"385201.77"
#define DP_HASH_REG_ALTITUDE      L"385202.77"

static PVOID gDpHashProtectObHandle = NULL;
static LARGE_INTEGER gDpHashProtectRegistryCookie;
static BOOLEAN gDpHashProtectRegistryRegistered = FALSE;
static LIST_ENTRY gDpHashProtectEvents;
static KSPIN_LOCK gDpHashProtectEventLock;
static BOOLEAN gDpHashProtectInitialized = FALSE;
static ULONG gDpHashProtectEventCount = 0;
static ULONGLONG gDpHashProtectEventSequence = 0;
static ULONGLONG gDpHashProtectDroppedEvents = 0;

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTSTATUS
SeLocateProcessImageName(
    _Inout_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING *pImageFileName
    );

static
BOOLEAN
DpHashProtectAsciiEqualsInsensitive(
    _In_z_ const CHAR *Left,
    _In_z_ const CHAR *Right
    )
{
    CHAR leftChar;
    CHAR rightChar;

    if (Left == NULL || Right == NULL) {
        return FALSE;
    }

    for (;;) {
        leftChar = *Left++;
        rightChar = *Right++;

        if (leftChar >= 'A' && leftChar <= 'Z') {
            leftChar = (CHAR)(leftChar - 'A' + 'a');
        }

        if (rightChar >= 'A' && rightChar <= 'Z') {
            rightChar = (CHAR)(rightChar - 'A' + 'a');
        }

        if (leftChar != rightChar) {
            return FALSE;
        }

        if (leftChar == '\0') {
            return TRUE;
        }
    }
}

static
BOOLEAN
DpHashProtectIsSystemPid(
    _In_opt_ HANDLE ProcessId
    )
{
    return ProcessId == NULL ||
           ProcessId == (HANDLE)(ULONG_PTR)4;
}

static
BOOLEAN
DpHashProtectImagePathIsSystem32Suffix(
    _In_ PCUNICODE_STRING ImagePath,
    _In_z_ PCWSTR FileName
    )
{
    WCHAR suffixBuffer[128];
    UNICODE_STRING suffix;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || FileName == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(RtlStringCchPrintfW(suffixBuffer,
                                        RTL_NUMBER_OF(suffixBuffer),
                                        L"\\Windows\\System32\\%ws",
                                        FileName))) {

        return FALSE;
    }

    RtlInitUnicodeString(&suffix, suffixBuffer);
    return RtlSuffixUnicodeString(&suffix, ImagePath, TRUE);
}

static
BOOLEAN
DpHashProtectIsAllowedCurrentProcess(
    VOID
    )
{
    PEPROCESS process;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN allowed = FALSE;
    const CHAR *imageName;

    if (DpHashProtectIsSystemPid(PsGetCurrentProcessId())) {
        return TRUE;
    }

    process = PsGetCurrentProcess();
    imageName = (const CHAR *)PsGetProcessImageFileName(process);

    if (DpHashProtectAsciiEqualsInsensitive(imageName, "lsass.exe")) {
        return TRUE;
    }

    if (NT_SUCCESS(SeLocateProcessImageName(process, &imagePath)) && imagePath != NULL) {
        allowed = DpHashProtectImagePathIsSystem32Suffix(imagePath, L"wininit.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"services.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"csrss.exe") ||
                  DpHashProtectImagePathIsSystem32Suffix(imagePath, L"smss.exe");
        ExFreePool(imagePath);
    }

    return allowed;
}

typedef struct _DP_HASH_PROTECT_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_HASH_PROTECT_EVENT_QUERY_ENTRY Event;
} DP_HASH_PROTECT_EVENT_ENTRY, *PDP_HASH_PROTECT_EVENT_ENTRY;

static
VOID
DpHashProtectCopyAsciiProcessImage(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ const CHAR *Source,
    _Out_ PULONG BytesCopied
    )
{
    ULONG index;

    *BytesCopied = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Source == NULL) {
        return;
    }

    for (index = 0; index + 1 < DestinationChars && Source[index] != '\0'; index++) {
        Destination[index] = (WCHAR)(UCHAR)Source[index];
    }

    Destination[index] = L'\0';
    *BytesCopied = index * sizeof(WCHAR);
}

static
VOID
DpHashProtectCopyUnicodeTarget(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _Out_ PULONG BytesCopied
    )
{
    ULONG bytesToCopy;

    *BytesCopied = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    bytesToCopy = min(Source->Length, (ULONG)((DestinationChars - 1) * sizeof(WCHAR)));
    RtlCopyMemory(Destination, Source->Buffer, bytesToCopy);
    Destination[bytesToCopy / sizeof(WCHAR)] = L'\0';
    *BytesCopied = bytesToCopy;
}

static
VOID
DpHashProtectFreeEvent(
    _In_opt_ PDP_HASH_PROTECT_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_HASH_PROTECT);
    }
}

static
VOID
DpHashProtectClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gDpHashProtectInitialized) {
        return;
    }

    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    while (!IsListEmpty(&gDpHashProtectEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpHashProtectEvents);
        PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_HASH_PROTECT_EVENT_ENTRY, Link);
        gDpHashProtectEventCount--;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DpHashProtectFreeEvent(event);
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
}

static
VOID
DpHashProtectQueueEvent(
    _In_ DP_HASH_PROTECT_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG Status,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCUNICODE_STRING Target,
    _In_opt_z_ const CHAR *ProcessImage
    )
{
    PDP_HASH_PROTECT_EVENT_ENTRY entry;
    KIRQL oldIrql;

    if (!gDpHashProtectInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_HASH_PROTECT_EVENT_ENTRY),
                                  DP_TAG_HASH_PROTECT);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
        gDpHashProtectDroppedEvents++;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_HASH_PROTECT_EVENT_ENTRY));
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.Operation = (ULONG)Operation;
    entry->Event.Status = Status;
    entry->Event.DesiredAccess = DesiredAccess;
    DpHashProtectCopyUnicodeTarget(entry->Event.Target,
                                   RTL_NUMBER_OF(entry->Event.Target),
                                   Target,
                                   &entry->Event.TargetLengthBytes);
    DpHashProtectCopyAsciiProcessImage(entry->Event.ProcessImage,
                                       RTL_NUMBER_OF(entry->Event.ProcessImage),
                                       ProcessImage,
                                       &entry->Event.ProcessImageLengthBytes);

    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpHashProtectEventSequence;
    InsertTailList(&gDpHashProtectEvents, &entry->Link);
    gDpHashProtectEventCount++;

    while (gDpHashProtectEventCount > DP_HASH_PROTECT_MAX_EVENTS &&
           !IsListEmpty(&gDpHashProtectEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gDpHashProtectEvents);
        PDP_HASH_PROTECT_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink, DP_HASH_PROTECT_EVENT_ENTRY, Link);
        gDpHashProtectEventCount--;
        gDpHashProtectDroppedEvents++;
        KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
        DpHashProtectFreeEvent(oldEvent);
        KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
    }

    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
}

static
VOID
DpHashProtectQueueEventAsciiTarget(
    _In_ DP_HASH_PROTECT_OPERATION Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG Status,
    _In_ ACCESS_MASK DesiredAccess,
    _In_z_ PCWSTR Target,
    _In_opt_z_ const CHAR *ProcessImage
    )
{
    UNICODE_STRING targetString;

    RtlInitUnicodeString(&targetString, Target);
    DpHashProtectQueueEvent(Operation,
                            ProcessId,
                            Status,
                            DesiredAccess,
                            &targetString,
                            ProcessImage);
}

static
BOOLEAN
DpHashProtectIsLsassProcess(
    _In_ PEPROCESS Process
    )
{
    if (Process == NULL) {
        return FALSE;
    }

    return DpHashProtectAsciiEqualsInsensitive((const CHAR *)PsGetProcessImageFileName(Process),
                                               "lsass.exe");
}

static
ACCESS_MASK
DpHashProtectDangerousProcessAccess(
    VOID
    )
{
    return PROCESS_TERMINATE |
           PROCESS_CREATE_THREAD |
           PROCESS_SET_SESSIONID |
           PROCESS_VM_OPERATION |
           PROCESS_VM_READ |
           PROCESS_VM_WRITE |
           PROCESS_DUP_HANDLE |
           PROCESS_CREATE_PROCESS |
           PROCESS_SET_QUOTA |
           PROCESS_SET_INFORMATION |
           PROCESS_QUERY_INFORMATION |
           PROCESS_SUSPEND_RESUME |
           PROCESS_QUERY_LIMITED_INFORMATION |
           DELETE |
           WRITE_DAC |
           WRITE_OWNER;
}

static
VOID
DpHashProtectFilterLsassAccess(
    _In_ OB_OPERATION Operation,
    _Inout_ POB_PRE_OPERATION_PARAMETERS Parameters
    )
{
    ACCESS_MASK desiredAccess;
    ACCESS_MASK filteredAccess;
    ACCESS_MASK dangerousAccess;

    dangerousAccess = DpHashProtectDangerousProcessAccess();

    if (Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = Parameters->CreateHandleInformation.DesiredAccess;
        filteredAccess = desiredAccess & ~dangerousAccess;

        if (filteredAccess != desiredAccess) {
            Parameters->CreateHandleInformation.DesiredAccess = filteredAccess;
            DpHashProtectQueueEventAsciiTarget(DpHashProtectOperationLsassHandle,
                                               PsGetCurrentProcessId(),
                                               (ULONG)STATUS_ACCESS_DENIED,
                                               desiredAccess,
                                               L"lsass.exe",
                                               (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
            DP_HASH_TRACE("blocked lsass handle create pid=%p access=0x%08X filtered=0x%08X image=%s\n",
                          PsGetCurrentProcessId(),
                          desiredAccess,
                          filteredAccess,
                          PsGetProcessImageFileName(PsGetCurrentProcess()));
        }
    } else if (Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = Parameters->DuplicateHandleInformation.DesiredAccess;
        filteredAccess = desiredAccess & ~dangerousAccess;

        if (filteredAccess != desiredAccess) {
            Parameters->DuplicateHandleInformation.DesiredAccess = filteredAccess;
            DpHashProtectQueueEventAsciiTarget(DpHashProtectOperationLsassHandle,
                                               PsGetCurrentProcessId(),
                                               (ULONG)STATUS_ACCESS_DENIED,
                                               desiredAccess,
                                               L"lsass.exe",
                                               (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
            DP_HASH_TRACE("blocked lsass handle duplicate pid=%p access=0x%08X filtered=0x%08X image=%s\n",
                          PsGetCurrentProcessId(),
                          desiredAccess,
                          filteredAccess,
                          PsGetProcessImageFileName(PsGetCurrentProcess()));
        }
    }
}

static
OB_PREOP_CALLBACK_STATUS
DpHashProtectPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS targetProcess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL ||
        OperationInformation->Parameters == NULL ||
        OperationInformation->KernelHandle ||
        OperationInformation->ObjectType != *PsProcessType) {

        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    if (!DpHashProtectIsLsassProcess(targetProcess)) {
        return OB_PREOP_SUCCESS;
    }

    if (PsGetCurrentProcess() == targetProcess ||
        PsGetCurrentProcessId() == PsGetProcessId(targetProcess) ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return OB_PREOP_SUCCESS;
    }

    DpHashProtectFilterLsassAccess(OperationInformation->Operation,
                                   OperationInformation->Parameters);

    return OB_PREOP_SUCCESS;
}

static
BOOLEAN
DpHashProtectSuffix(
    _In_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Suffix
    )
{
    UNICODE_STRING suffixString;

    if (Name == NULL || Name->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&suffixString, Suffix);
    return RtlSuffixUnicodeString(&suffixString, Name, TRUE);
}

static
BOOLEAN
DpHashProtectUnicodeCharEqualsInsensitive(
    _In_ WCHAR Left,
    _In_ WCHAR Right
    )
{
    return RtlUpcaseUnicodeChar(Left) == RtlUpcaseUnicodeChar(Right);
}

static
BOOLEAN
DpHashProtectContainsInsensitive(
    _In_ PCUNICODE_STRING Name,
    _In_z_ PCWSTR Needle
    )
{
    USHORT nameChars;
    USHORT needleChars;
    USHORT nameIndex;
    UNICODE_STRING needleString;

    if (Name == NULL || Name->Buffer == NULL || Needle == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    if (needleString.Length == 0 || Name->Length < needleString.Length) {
        return FALSE;
    }

    nameChars = Name->Length / sizeof(WCHAR);
    needleChars = needleString.Length / sizeof(WCHAR);

    for (nameIndex = 0; nameIndex <= nameChars - needleChars; nameIndex++) {
        USHORT needleIndex;
        BOOLEAN matched = TRUE;

        for (needleIndex = 0; needleIndex < needleChars; needleIndex++) {
            if (!DpHashProtectUnicodeCharEqualsInsensitive(Name->Buffer[nameIndex + needleIndex],
                                                           needleString.Buffer[needleIndex])) {
                matched = FALSE;
                break;
            }
        }

        if (matched) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpHashProtectIsCredentialStoreName(
    _In_ PCUNICODE_STRING Name
    )
{
    static const PCWSTR SensitiveSuffixes[] = {
        L"\\Windows\\System32\\config\\SAM",
        L"\\Windows\\System32\\config\\SECURITY",
        L"\\Windows\\System32\\config\\SYSTEM",
        L"\\Windows\\System32\\config\\RegBack\\SAM",
        L"\\Windows\\System32\\config\\RegBack\\SECURITY",
        L"\\Windows\\System32\\config\\RegBack\\SYSTEM",
        L"\\Windows\\Repair\\SAM",
        L"\\Windows\\Repair\\SECURITY",
        L"\\Windows\\Repair\\SYSTEM",
        L"\\Windows\\NTDS\\ntds.dit"
    };
    ULONG index;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    for (index = 0; index < ARRAYSIZE(SensitiveSuffixes); index++) {
        if (DpHashProtectSuffix(Name, SensitiveSuffixes[index])) {
            return TRUE;
        }
    }

    if (DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SAM.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SECURITY.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\System32\\config\\SYSTEM.") ||
        DpHashProtectContainsInsensitive(Name, L"\\Windows\\NTDS\\ntds.dit.")) {

        return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
DpHashProtectCreateRequestsDataAccess(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess;
    ULONG createDisposition;
    PFLT_IO_PARAMETER_BLOCK iopb;

    if (Data == NULL || Data->Iopb == NULL) {
        return FALSE;
    }

    iopb = Data->Iopb;
    if (iopb->MajorFunction != IRP_MJ_CREATE ||
        iopb->Parameters.Create.SecurityContext == NULL) {

        return FALSE;
    }

    desiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (FlagOn(desiredAccess,
               FILE_READ_DATA |
               FILE_WRITE_DATA |
               FILE_APPEND_DATA |
               FILE_EXECUTE |
               FILE_DELETE_CHILD |
               DELETE |
               WRITE_DAC |
               WRITE_OWNER |
               GENERIC_READ |
               GENERIC_WRITE |
               GENERIC_EXECUTE |
               GENERIC_ALL)) {

        return TRUE;
    }

    createDisposition = (iopb->Parameters.Create.Options >> 24) & 0xFF;
    switch (createDisposition) {
    case FILE_CREATE:
    case FILE_OPEN_IF:
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF:
    case FILE_SUPERSEDE:
        return TRUE;

    default:
        return FALSE;
    }
}

static
BOOLEAN
DpHashProtectIsProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyName
    )
{
    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0) {
        return FALSE;
    }

    return DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SAM") ||
           DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SECURITY") ||
           DpHashProtectSuffix(KeyName, L"\\Registry\\Machine\\SYSTEM");
}

static
NTSTATUS
DpHashProtectRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    PVOID object = NULL;
    PCUNICODE_STRING keyName = NULL;
    ULONG_PTR objectId;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL || Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    switch (notifyClass) {
    case RegNtPreSaveKey:
        object = ((PREG_SAVE_KEY_INFORMATION)Argument2)->Object;
        break;

    case RegNtPreRestoreKey:
        object = ((PREG_RESTORE_KEY_INFORMATION)Argument2)->Object;
        break;

    case RegNtPreReplaceKey:
        object = ((PREG_REPLACE_KEY_INFORMATION)Argument2)->Object;
        break;

    default:
        return STATUS_SUCCESS;
    }

    if (object == NULL ||
        DpHashProtectIsAllowedCurrentProcess()) {

        return STATUS_SUCCESS;
    }

    status = CmCallbackGetKeyObjectID(&gDpHashProtectRegistryCookie,
                                      object,
                                      &objectId,
                                      &keyName);
    if (!NT_SUCCESS(status) || keyName == NULL) {
        return STATUS_SUCCESS;
    }

    if (DpHashProtectIsProtectedRegistryKey(keyName)) {
        DpHashProtectQueueEvent(DpHashProtectOperationRegistryHive,
                                PsGetCurrentProcessId(),
                                (ULONG)STATUS_ACCESS_DENIED,
                                0,
                                keyName,
                                (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
        DP_HASH_TRACE("blocked registry hive export pid=%p class=%lu key=%wZ image=%s\n",
                      PsGetCurrentProcessId(),
                      (ULONG)notifyClass,
                      keyName,
                      PsGetProcessImageFileName(PsGetCurrentProcess()));
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpHashProtectRegisterObCallback(
    VOID
    )
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operationRegistration;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING altitude;

    if (gDpHashProtectObHandle != NULL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&operationRegistration, sizeof(operationRegistration));
    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE |
                                       OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = DpHashProtectPreOperationCallback;
    operationRegistration.PostOperation = NULL;

    RtlInitUnicodeString(&altitude, DP_HASH_OB_ALTITUDE);

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.OperationRegistration = &operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration,
                                 &gDpHashProtectObHandle);
    if (!NT_SUCCESS(status)) {
        gDpHashProtectObHandle = NULL;
        DP_HASH_TRACE("ObRegisterCallbacks failed status=0x%08X\n", status);
    }

    return status;
}

static
NTSTATUS
DpHashProtectRegisterRegistryCallback(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (gDpHashProtectRegistryRegistered) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, DP_HASH_REG_ALTITUDE);
    status = CmRegisterCallbackEx(DpHashProtectRegistryCallback,
                                  &altitude,
                                  DriverObject,
                                  NULL,
                                  &gDpHashProtectRegistryCookie,
                                  NULL);
    if (NT_SUCCESS(status)) {
        gDpHashProtectRegistryRegistered = TRUE;
    } else {
        DP_HASH_TRACE("CmRegisterCallbackEx failed status=0x%08X\n", status);
    }

    return status;
}

NTSTATUS
DpHashProtectInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS obStatus;
    NTSTATUS registryStatus;

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&gDpHashProtectEvents);
    KeInitializeSpinLock(&gDpHashProtectEventLock);
    gDpHashProtectEventCount = 0;
    gDpHashProtectEventSequence = 0;
    gDpHashProtectDroppedEvents = 0;
    gDpHashProtectInitialized = TRUE;

    obStatus = DpHashProtectRegisterObCallback();
    registryStatus = DpHashProtectRegisterRegistryCallback(DriverObject);

    if (!NT_SUCCESS(obStatus) && !NT_SUCCESS(registryStatus)) {
        DP_HASH_TRACE("hash protection running degraded ob=0x%08X registry=0x%08X\n",
                      obStatus,
                      registryStatus);
    }

    return STATUS_SUCCESS;
}

VOID
DpHashProtectUninitialize(
    VOID
    )
{
    if (gDpHashProtectRegistryRegistered) {
        CmUnRegisterCallback(gDpHashProtectRegistryCookie);
        gDpHashProtectRegistryRegistered = FALSE;
        gDpHashProtectRegistryCookie.QuadPart = 0;
    }

    if (gDpHashProtectObHandle != NULL) {
        ObUnRegisterCallbacks(gDpHashProtectObHandle);
        gDpHashProtectObHandle = NULL;
    }

    DpHashProtectClearEvents();
    gDpHashProtectInitialized = FALSE;
}

BOOLEAN
DpHashProtectShouldBlockCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN block = FALSE;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE ||
        Data->RequestorMode == KernelMode ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL ||
        DpHashProtectIsAllowedCurrentProcess() ||
        !DpHashProtectCreateRequestsDataAccess(Data)) {

        return FALSE;
    }

    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return FALSE;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);
    }

    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FALSE;
    }

    if (DpHashProtectIsCredentialStoreName(&nameInfo->Name)) {
        block = TRUE;
        DpHashProtectQueueEvent(DpHashProtectOperationCredentialFile,
                                PsGetCurrentProcessId(),
                                (ULONG)STATUS_ACCESS_DENIED,
                                Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                                &nameInfo->Name,
                                (const CHAR *)PsGetProcessImageFileName(PsGetCurrentProcess()));
        DP_HASH_TRACE("blocked credential store create pid=%p access=0x%08X path=%wZ image=%s\n",
                      PsGetCurrentProcessId(),
                      Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                      &nameInfo->Name,
                      PsGetProcessImageFileName(PsGetCurrentProcess()));
    }

    FltReleaseFileNameInformation(nameInfo);

    return block;
}

NTSTATUS
DpHashProtectQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_HASH_PROTECT_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_HASH_PROTECT_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    header->Version = DP_HASH_PROTECT_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);

    if (!gDpHashProtectInitialized) {
        header->BytesRequired = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_HASH_PROTECT_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);

    header->DroppedEvents = gDpHashProtectDroppedEvents;

    for (link = gDpHashProtectEvents.Flink; link != &gDpHashProtectEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_HASH_PROTECT_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_HASH_PROTECT_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpHashProtectEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpHashProtectEvents);
            PDP_HASH_PROTECT_EVENT_ENTRY event = CONTAINING_RECORD(eventLink, DP_HASH_PROTECT_EVENT_ENTRY, Link);
            gDpHashProtectEventCount--;
            KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);
            DpHashProtectFreeEvent(event);
            KeAcquireSpinLock(&gDpHashProtectEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpHashProtectEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}
