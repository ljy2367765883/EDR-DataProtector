/*++

Module Name:

    DpProcessPolicy.c

Abstract:

    Dynamic requestor process trust policy. A trust rule is scoped by both a
    requestor identity and a protected file extension. This prevents a trusted
    process from becoming globally trusted for every protected file class.

--*/

#include "DataProtector.h"

#define DP_TRUSTED_PROCESS_NAMES_VALUE L"TrustedProcessNames"
#define DP_TRUSTED_PROCESS_DIRS_VALUE  L"TrustedProcessDirectories"

typedef struct _DP_PROCESS_RULE {
    LIST_ENTRY Link;
    DP_PROCESS_TRUST_RULE_TYPE Type;
    UNICODE_STRING Value;
    UNICODE_STRING Extension;
} DP_PROCESS_RULE, *PDP_PROCESS_RULE;

typedef struct _DP_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    UNICODE_STRING ImagePath;
    UNICODE_STRING ImageName;
    UNICODE_STRING ImageDirectory;
} DP_PROCESS_ENTRY, *PDP_PROCESS_ENTRY;

static LIST_ENTRY gDpProcessRules;
static LIST_ENTRY gDpProcessEntries;
static EX_PUSH_LOCK gDpProcessPolicyLock;
static BOOLEAN gDpProcessNotifyRegistered = FALSE;

extern
UCHAR *
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static
VOID
DpProcessPolicyFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, DP_TAG_POLICY_RULE);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

static
NTSTATUS
DpProcessPolicyDuplicateString(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    )
{
    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    if (Source == NULL ||
        Source->Buffer == NULL ||
        Source->Length == 0 ||
        Source->Length > DP_POLICY_MAX_RULE_BYTES) {

        return STATUS_INVALID_PARAMETER;
    }

    Destination->Buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                Source->Length,
                                                DP_TAG_POLICY_RULE);

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
DpProcessPolicyTrimTrailingSlash(
    _Inout_ PUNICODE_STRING String
    )
{
    while (String->Length >= sizeof(WCHAR)) {
        WCHAR last = String->Buffer[(String->Length / sizeof(WCHAR)) - 1];

        if (last != L'\\' && last != L'/') {
            break;
        }

        String->Length -= sizeof(WCHAR);
    }
}

static
NTSTATUS
DpProcessPolicyNormalizeRuleValue(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _Out_ PUNICODE_STRING NormalizedValue
    )
{
    NTSTATUS status;

    status = DpProcessPolicyDuplicateString(Value, NormalizedValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (RuleType == DpProcessTrustRuleImageDirectory) {
        DpProcessPolicyTrimTrailingSlash(NormalizedValue);
        if (NormalizedValue->Length == 0) {
            DpProcessPolicyFreeUnicodeString(NormalizedValue);
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
DpProcessPolicyNormalizeExtension(
    _In_ PCUNICODE_STRING Extension,
    _Out_ PUNICODE_STRING NormalizedExtension
    )
{
    NTSTATUS status;

    NormalizedExtension->Buffer = NULL;
    NormalizedExtension->Length = 0;
    NormalizedExtension->MaximumLength = 0;

    if (Extension == NULL ||
        Extension->Buffer == NULL ||
        Extension->Length == 0 ||
        Extension->Length > DP_POLICY_MAX_EXTENSION_BYTES) {

        return STATUS_INVALID_PARAMETER;
    }

    status = DpProcessPolicyDuplicateString(Extension, NormalizedExtension);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (NormalizedExtension->Buffer[0] != L'.') {
        PWCH buffer;

        if (NormalizedExtension->Length > DP_POLICY_MAX_EXTENSION_BYTES - sizeof(WCHAR)) {
            DpProcessPolicyFreeUnicodeString(NormalizedExtension);
            return STATUS_INVALID_PARAMETER;
        }

        buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                       NormalizedExtension->Length + sizeof(WCHAR),
                                       DP_TAG_POLICY_RULE);
        if (buffer == NULL) {
            DpProcessPolicyFreeUnicodeString(NormalizedExtension);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        buffer[0] = L'.';
        RtlCopyMemory(buffer + 1,
                      NormalizedExtension->Buffer,
                      NormalizedExtension->Length);

        ExFreePoolWithTag(NormalizedExtension->Buffer, DP_TAG_POLICY_RULE);
        NormalizedExtension->Buffer = buffer;
        NormalizedExtension->Length += sizeof(WCHAR);
        NormalizedExtension->MaximumLength = NormalizedExtension->Length;
    }

    return STATUS_SUCCESS;
}

static
VOID
DpProcessPolicyDeriveImageParts(
    _Inout_ PDP_PROCESS_ENTRY Entry
    )
{
    USHORT offset;
    USHORT lastSlash = 0;
    BOOLEAN foundSlash = FALSE;

    Entry->ImageName.Buffer = Entry->ImagePath.Buffer;
    Entry->ImageName.Length = Entry->ImagePath.Length;
    Entry->ImageName.MaximumLength = Entry->ImagePath.Length;
    Entry->ImageDirectory.Buffer = Entry->ImagePath.Buffer;
    Entry->ImageDirectory.Length = 0;
    Entry->ImageDirectory.MaximumLength = 0;

    for (offset = 0; offset < Entry->ImagePath.Length; offset += sizeof(WCHAR)) {
        WCHAR character = Entry->ImagePath.Buffer[offset / sizeof(WCHAR)];

        if (character == L'\\' || character == L'/') {
            lastSlash = offset;
            foundSlash = TRUE;
        }
    }

    if (foundSlash) {
        Entry->ImageDirectory.Length = lastSlash;
        Entry->ImageDirectory.MaximumLength = Entry->ImageDirectory.Length;
        Entry->ImageName.Buffer = (PWCH)((PUCHAR)Entry->ImagePath.Buffer + lastSlash + sizeof(WCHAR));
        Entry->ImageName.Length = Entry->ImagePath.Length - lastSlash - sizeof(WCHAR);
        Entry->ImageName.MaximumLength = Entry->ImageName.Length;
    }
}

static
VOID
DpProcessPolicyFreeRule(
    _In_ PDP_PROCESS_RULE Rule
    )
{
    if (Rule == NULL) {
        return;
    }

    DpProcessPolicyFreeUnicodeString(&Rule->Value);
    DpProcessPolicyFreeUnicodeString(&Rule->Extension);
    ExFreePoolWithTag(Rule, DP_TAG_POLICY_RULE);
}

static
VOID
DpProcessPolicyFreeProcessEntry(
    _In_ PDP_PROCESS_ENTRY Entry
    )
{
    if (Entry == NULL) {
        return;
    }

    DpProcessPolicyFreeUnicodeString(&Entry->ImagePath);
    ExFreePoolWithTag(Entry, DP_TAG_PROCESS_ENTRY);
}

static
BOOLEAN
DpProcessPolicyRuleExistsLocked(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    )
{
    PLIST_ENTRY link;

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        if (rule->Type == RuleType &&
            RtlEqualUnicodeString(&rule->Value, Value, TRUE) &&
            RtlEqualUnicodeString(&rule->Extension, Extension, TRUE)) {

            return TRUE;
        }
    }

    return FALSE;
}

static
CHAR
DpProcessPolicyToLowerAscii(
    _In_ CHAR Character
    )
{
    if (Character >= 'A' && Character <= 'Z') {
        return (CHAR)(Character - 'A' + 'a');
    }

    return Character;
}

static
BOOLEAN
DpProcessPolicyImageNameMatchesRule(
    _In_ PCUNICODE_STRING RuleName,
    _In_z_ const CHAR *ImageName
    )
{
    USHORT ruleIndex;
    USHORT ruleChars;

    if (RuleName->Buffer == NULL || ImageName == NULL) {
        return FALSE;
    }

    ruleChars = RuleName->Length / sizeof(WCHAR);

    for (ruleIndex = 0; ruleIndex < ruleChars; ruleIndex++) {
        WCHAR ruleChar = RuleName->Buffer[ruleIndex];
        CHAR imageChar = ImageName[ruleIndex];

        if (imageChar == '\0' || ruleChar > 0x7F) {
            return FALSE;
        }

        if (DpProcessPolicyToLowerAscii((CHAR)ruleChar) !=
            DpProcessPolicyToLowerAscii(imageChar)) {

            return FALSE;
        }
    }

    return ImageName[ruleChars] == '\0';
}

static
BOOLEAN
DpProcessPolicyNameHasExtension(
    _In_ PCUNICODE_STRING Name,
    _In_ PCUNICODE_STRING Extension
    )
{
    UNICODE_STRING suffix;

    if (Name == NULL ||
        Name->Buffer == NULL ||
        Extension == NULL ||
        Extension->Buffer == NULL ||
        Extension->Length == 0 ||
        Name->Length < Extension->Length) {

        return FALSE;
    }

    suffix.Buffer = (PWCH)((PUCHAR)Name->Buffer + Name->Length - Extension->Length);
    suffix.Length = Extension->Length;
    suffix.MaximumLength = Extension->Length;

    return RtlEqualUnicodeString(&suffix, Extension, TRUE);
}

static
BOOLEAN
DpProcessPolicyImageNameTrustedLocked(
    _In_z_ const CHAR *ImageName,
    _In_ PCUNICODE_STRING FileName
    )
{
    PLIST_ENTRY link;

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        if (rule->Type == DpProcessTrustRuleImageName &&
            DpProcessPolicyNameHasExtension(FileName, &rule->Extension) &&
            DpProcessPolicyImageNameMatchesRule(&rule->Value, ImageName)) {

            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DpProcessPolicyDirectoryMatches(
    _In_ PCUNICODE_STRING RuleDirectory,
    _In_ PCUNICODE_STRING ImagePath
    )
{
    if (RuleDirectory->Length == 0 ||
        ImagePath->Length < RuleDirectory->Length) {

        return FALSE;
    }

    if (!RtlPrefixUnicodeString(RuleDirectory, ImagePath, TRUE)) {
        return FALSE;
    }

    if (ImagePath->Length == RuleDirectory->Length) {
        return TRUE;
    }

    return ImagePath->Buffer[RuleDirectory->Length / sizeof(WCHAR)] == L'\\' ||
           ImagePath->Buffer[RuleDirectory->Length / sizeof(WCHAR)] == L'/';
}

static
BOOLEAN
DpProcessPolicyEntryTrustedLocked(
    _In_ PDP_PROCESS_ENTRY Entry,
    _In_ PCUNICODE_STRING FileName
    )
{
    PLIST_ENTRY link;

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        if (!DpProcessPolicyNameHasExtension(FileName, &rule->Extension)) {
            continue;
        }

        if (rule->Type == DpProcessTrustRuleImageName &&
            RtlEqualUnicodeString(&rule->Value, &Entry->ImageName, TRUE)) {

            return TRUE;
        }

        if (rule->Type == DpProcessTrustRuleImageDirectory &&
            DpProcessPolicyDirectoryMatches(&rule->Value, &Entry->ImagePath)) {

            return TRUE;
        }
    }

    return FALSE;
}

static
PDP_PROCESS_ENTRY
DpProcessPolicyFindEntryLocked(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY link;

    for (link = gDpProcessEntries.Flink; link != &gDpProcessEntries; link = link->Flink) {
        PDP_PROCESS_ENTRY entry = CONTAINING_RECORD(link, DP_PROCESS_ENTRY, Link);

        if (entry->ProcessId == ProcessId) {
            return entry;
        }
    }

    return NULL;
}

static
NTSTATUS
DpProcessPolicyCreateEntry(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _Outptr_ PDP_PROCESS_ENTRY *Entry
    )
{
    NTSTATUS status;
    PDP_PROCESS_ENTRY entry;
    PUNICODE_STRING locatedImageName = NULL;
    PCUNICODE_STRING sourceName = ImageFileName;
    ANSI_STRING fallbackAnsi;

    *Entry = NULL;

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_PROCESS_ENTRY),
                                  DP_TAG_PROCESS_ENTRY);

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(DP_PROCESS_ENTRY));
    entry->ProcessId = ProcessId;

    if (sourceName == NULL || sourceName->Buffer == NULL || sourceName->Length == 0) {
        status = SeLocateProcessImageName(Process, &locatedImageName);
        if (NT_SUCCESS(status)) {
            sourceName = locatedImageName;
        }
    }

    if (sourceName != NULL && sourceName->Buffer != NULL && sourceName->Length != 0) {
        status = DpProcessPolicyDuplicateString(sourceName, &entry->ImagePath);
    } else {
        RtlInitAnsiString(&fallbackAnsi, (PCSZ)PsGetProcessImageFileName(Process));
        status = RtlAnsiStringToUnicodeString(&entry->ImagePath, &fallbackAnsi, TRUE);
        if (NT_SUCCESS(status)) {
            USHORT imageLength;
            PWCH newBuffer;

            imageLength = entry->ImagePath.Length;
            newBuffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                              imageLength,
                                              DP_TAG_POLICY_RULE);

            if (newBuffer != NULL) {
                RtlCopyMemory(newBuffer,
                              entry->ImagePath.Buffer,
                              imageLength);
            }

            RtlFreeUnicodeString(&entry->ImagePath);

            if (newBuffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                entry->ImagePath.Buffer = newBuffer;
                entry->ImagePath.Length = imageLength;
                entry->ImagePath.MaximumLength = imageLength;
            }
        }
    }

    if (locatedImageName != NULL) {
        ExFreePool(locatedImageName);
    }

    if (!NT_SUCCESS(status)) {
        DpProcessPolicyFreeProcessEntry(entry);
        return status;
    }

    DpProcessPolicyDeriveImageParts(entry);

    *Entry = entry;

    return STATUS_SUCCESS;
}

static
VOID
DpProcessPolicyRemoveProcessEntry(
    _In_ HANDLE ProcessId
    )
{
    PDP_PROCESS_ENTRY entry;

    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);

    entry = DpProcessPolicyFindEntryLocked(ProcessId);
    if (entry != NULL) {
        RemoveEntryList(&entry->Link);
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    DpProcessPolicyFreeProcessEntry(entry);
}

static
VOID
DpProcessPolicyCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS status;
    PDP_PROCESS_ENTRY entry;

    if (CreateInfo == NULL) {
        DpProcessPolicyRemoveProcessEntry(ProcessId);
        return;
    }

    status = DpProcessPolicyCreateEntry(ProcessId,
                                        Process,
                                        CreateInfo->ImageFileName,
                                        &entry);

    if (!NT_SUCCESS(status)) {
        return;
    }

    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);

    {
        PDP_PROCESS_ENTRY oldEntry = DpProcessPolicyFindEntryLocked(ProcessId);
        if (oldEntry != NULL) {
            RemoveEntryList(&oldEntry->Link);
            DpProcessPolicyFreeProcessEntry(oldEntry);
        }
    }

    InsertTailList(&gDpProcessEntries, &entry->Link);
    FltReleasePushLock(&gDpProcessPolicyLock);
}

static
VOID
DpProcessPolicyClearRulesLocked(
    VOID
    )
{
    while (!IsListEmpty(&gDpProcessRules)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpProcessRules);
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        DpProcessPolicyFreeRule(rule);
    }
}

static
VOID
DpProcessPolicyClearEntriesLocked(
    VOID
    )
{
    while (!IsListEmpty(&gDpProcessEntries)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpProcessEntries);
        PDP_PROCESS_ENTRY entry = CONTAINING_RECORD(link, DP_PROCESS_ENTRY, Link);

        DpProcessPolicyFreeProcessEntry(entry);
    }
}

static
NTSTATUS
DpProcessPolicyRegistryCallback(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext
    )
{
    UNICODE_STRING value;
    UNICODE_STRING extension;
    DP_PROCESS_TRUST_RULE_TYPE ruleType;

    UNREFERENCED_PARAMETER(ValueName);
    UNREFERENCED_PARAMETER(Context);

    if (ValueType != REG_SZ || ValueData == NULL || ValueLength < sizeof(WCHAR)) {
        return STATUS_SUCCESS;
    }

    ruleType = (DP_PROCESS_TRUST_RULE_TYPE)(ULONG_PTR)EntryContext;

    value.Buffer = (PWCH)ValueData;
    value.Length = (USHORT)(ValueLength - sizeof(WCHAR));
    value.MaximumLength = value.Length;

    while (value.Length >= sizeof(WCHAR) &&
           value.Buffer[(value.Length / sizeof(WCHAR)) - 1] == UNICODE_NULL) {

        value.Length -= sizeof(WCHAR);
    }

    if (value.Length == 0) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&extension, DP_POLICY_DEFAULT_EXTENSION);
    (VOID)DpProcessPolicyAddRule(ruleType, &value, &extension);

    return STATUS_SUCCESS;
}

static
VOID
DpProcessPolicyLoadRulesFromRegistry(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    RTL_QUERY_REGISTRY_TABLE queryTable[3];

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return;
    }

    RtlZeroMemory(queryTable, sizeof(queryTable));

    queryTable[0].QueryRoutine = DpProcessPolicyRegistryCallback;
    queryTable[0].Name = DP_TRUSTED_PROCESS_NAMES_VALUE;
    queryTable[0].EntryContext = (PVOID)(ULONG_PTR)DpProcessTrustRuleImageName;

    queryTable[1].QueryRoutine = DpProcessPolicyRegistryCallback;
    queryTable[1].Name = DP_TRUSTED_PROCESS_DIRS_VALUE;
    queryTable[1].EntryContext = (PVOID)(ULONG_PTR)DpProcessTrustRuleImageDirectory;

    (VOID)RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                 RegistryPath->Buffer,
                                 queryTable,
                                 NULL,
                                 NULL);
}

NTSTATUS
DpProcessPolicyAddRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    )
{
    NTSTATUS status;
    PDP_PROCESS_RULE rule;
    UNICODE_STRING normalizedValue;
    UNICODE_STRING normalizedExtension;

    if (RuleType != DpProcessTrustRuleImageName &&
        RuleType != DpProcessTrustRuleImageDirectory) {

        return STATUS_INVALID_PARAMETER;
    }

    status = DpProcessPolicyNormalizeRuleValue(RuleType, Value, &normalizedValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpProcessPolicyNormalizeExtension(Extension, &normalizedExtension);
    if (!NT_SUCCESS(status)) {
        DpProcessPolicyFreeUnicodeString(&normalizedValue);
        return status;
    }

    rule = ExAllocatePoolWithTag(NonPagedPoolNx,
                                 sizeof(DP_PROCESS_RULE),
                                 DP_TAG_POLICY_RULE);

    if (rule == NULL) {
        DpProcessPolicyFreeUnicodeString(&normalizedValue);
        DpProcessPolicyFreeUnicodeString(&normalizedExtension);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(rule, sizeof(DP_PROCESS_RULE));
    rule->Type = RuleType;
    rule->Value = normalizedValue;
    rule->Extension = normalizedExtension;

    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);

    if (DpProcessPolicyRuleExistsLocked(RuleType, &rule->Value, &rule->Extension)) {
        status = STATUS_OBJECT_NAME_COLLISION;
    } else {
        InsertTailList(&gDpProcessRules, &rule->Link);
        rule = NULL;
        status = STATUS_SUCCESS;
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    DpProcessPolicyFreeRule(rule);

    return status;
}

NTSTATUS
DpProcessPolicyRemoveRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    )
{
    NTSTATUS status;
    PLIST_ENTRY link;
    PDP_PROCESS_RULE matchedRule = NULL;
    UNICODE_STRING normalizedValue;
    UNICODE_STRING normalizedExtension;

    if (RuleType != DpProcessTrustRuleImageName &&
        RuleType != DpProcessTrustRuleImageDirectory) {

        return STATUS_INVALID_PARAMETER;
    }

    status = DpProcessPolicyNormalizeRuleValue(RuleType, Value, &normalizedValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpProcessPolicyNormalizeExtension(Extension, &normalizedExtension);
    if (!NT_SUCCESS(status)) {
        DpProcessPolicyFreeUnicodeString(&normalizedValue);
        return status;
    }

    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        if (rule->Type == RuleType &&
            RtlEqualUnicodeString(&rule->Value, &normalizedValue, TRUE) &&
            RtlEqualUnicodeString(&rule->Extension, &normalizedExtension, TRUE)) {

            matchedRule = rule;
            RemoveEntryList(&matchedRule->Link);
            break;
        }
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    DpProcessPolicyFreeUnicodeString(&normalizedValue);
    DpProcessPolicyFreeUnicodeString(&normalizedExtension);

    if (matchedRule == NULL) {
        return STATUS_NOT_FOUND;
    }

    DpProcessPolicyFreeRule(matchedRule);

    return STATUS_SUCCESS;
}

VOID
DpProcessPolicyClearRules(
    VOID
    )
{
    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);
    DpProcessPolicyClearRulesLocked();
    FltReleasePushLock(&gDpProcessPolicyLock);
}

NTSTATUS
DpProcessPolicyQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PLIST_ENTRY link;
    PDP_POLICY_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_POLICY_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_POLICY_QUERY_HEADER);
    ULONG ruleCount = 0;
    ULONG returnedRuleCount = 0;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_POLICY_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_POLICY_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_POLICY_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_POLICY_QUERY_HEADER));
    header->Version = DP_POLICY_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_POLICY_QUERY_HEADER);

    cursor = (PUCHAR)OutputBuffer + sizeof(DP_POLICY_QUERY_HEADER);

    FltAcquirePushLockShared(&gDpProcessPolicyLock);

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);
        ULONG entryLength = DP_POLICY_QUERY_ENTRY_HEADER_SIZE +
                            rule->Value.Length +
                            rule->Extension.Length;

        ruleCount++;

        if (bytesRequired > MAXULONG - entryLength) {
            FltReleasePushLock(&gDpProcessPolicyLock);
            return STATUS_INTEGER_OVERFLOW;
        }

        bytesRequired += entryLength;

        if (bytesReturned <= OutputBufferLength &&
            entryLength <= OutputBufferLength - bytesReturned) {
            PDP_POLICY_QUERY_ENTRY entry = (PDP_POLICY_QUERY_ENTRY)cursor;

            entry->RuleType = (ULONG)rule->Type;
            entry->ValueLengthBytes = rule->Value.Length;
            entry->ExtensionLengthBytes = rule->Extension.Length;

            RtlCopyMemory(entry->Data,
                          rule->Value.Buffer,
                          rule->Value.Length);
            RtlCopyMemory((PUCHAR)entry->Data + rule->Value.Length,
                          rule->Extension.Buffer,
                          rule->Extension.Length);

            cursor += entryLength;
            bytesReturned += entryLength;
            returnedRuleCount++;
        }
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    header->RuleCount = ruleCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedRuleCount != ruleCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

BOOLEAN
DpProcessPolicyNameHasProtectedExtension(
    _In_ PCUNICODE_STRING Name
    )
{
    PLIST_ENTRY link;
    BOOLEAN protectedExtension = FALSE;

    FltAcquirePushLockShared(&gDpProcessPolicyLock);

    for (link = gDpProcessRules.Flink; link != &gDpProcessRules; link = link->Flink) {
        PDP_PROCESS_RULE rule = CONTAINING_RECORD(link, DP_PROCESS_RULE, Link);

        if (DpProcessPolicyNameHasExtension(Name, &rule->Extension)) {
            protectedExtension = TRUE;
            break;
        }
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    return protectedExtension;
}

BOOLEAN
DpProcessPolicyIsTrusted(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING FileName
    )
{
    BOOLEAN trusted = FALSE;
    HANDLE processId;
    PDP_PROCESS_ENTRY entry;
    PEPROCESS process;
    const CHAR *fallbackImageName;
    DP_PROCESS_ENTRY fallbackEntry;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    processId = FltGetRequestorProcessIdEx(Data);
    if (processId == NULL) {
        return FALSE;
    }

    FltAcquirePushLockShared(&gDpProcessPolicyLock);

    entry = DpProcessPolicyFindEntryLocked(processId);
    if (entry != NULL) {
        trusted = DpProcessPolicyEntryTrustedLocked(entry, FileName);
    }

    FltReleasePushLock(&gDpProcessPolicyLock);

    if (entry != NULL) {
        return trusted;
    }

    process = FltGetRequestorProcess(Data);
    if (process == NULL) {
        return FALSE;
    }

    fallbackImageName = (const CHAR *)PsGetProcessImageFileName(process);
    if (fallbackImageName != NULL) {
        FltAcquirePushLockShared(&gDpProcessPolicyLock);
        trusted = DpProcessPolicyImageNameTrustedLocked(fallbackImageName, FileName);
        FltReleasePushLock(&gDpProcessPolicyLock);
    }

    if (trusted || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return trusted;
    }

    if (gDpProcessNotifyRegistered) {
        return FALSE;
    }

    RtlZeroMemory(&fallbackEntry, sizeof(fallbackEntry));
    if (NT_SUCCESS(DpProcessPolicyCreateEntry(processId, process, NULL, &entry))) {
        fallbackEntry = *entry;

        FltAcquirePushLockShared(&gDpProcessPolicyLock);
        trusted = DpProcessPolicyEntryTrustedLocked(&fallbackEntry, FileName);
        FltReleasePushLock(&gDpProcessPolicyLock);

        DpProcessPolicyFreeProcessEntry(entry);
    }

    return trusted;
}

NTSTATUS
DpProcessPolicyInitialize(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    InitializeListHead(&gDpProcessRules);
    InitializeListHead(&gDpProcessEntries);
    FltInitializePushLock(&gDpProcessPolicyLock);

    DpProcessPolicyLoadRulesFromRegistry(RegistryPath);

    status = PsSetCreateProcessNotifyRoutineEx(DpProcessPolicyCreateProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        gDpProcessNotifyRegistered = TRUE;
    } else {
        DP_DBG_PRINT(DP_TRACE_POLICY,
                     ("DataProtector!DpProcessPolicyInitialize: process notify registration failed 0x%08X, using on-demand image lookup\n",
                      status));
        status = STATUS_SUCCESS;
    }

#if DP_ENABLE_TEST_TRUSTED_PROCESSES
    {
        UNICODE_STRING rule;
        UNICODE_STRING extension;

        RtlInitUnicodeString(&extension, DP_POLICY_DEFAULT_EXTENSION);

        RtlInitUnicodeString(&rule, L"cmd.exe");
        (VOID)DpProcessPolicyAddRule(DpProcessTrustRuleImageName, &rule, &extension);

        RtlInitUnicodeString(&rule, L"powershell.exe");
        (VOID)DpProcessPolicyAddRule(DpProcessTrustRuleImageName, &rule, &extension);

        RtlInitUnicodeString(&rule, L"notepad.exe");
        (VOID)DpProcessPolicyAddRule(DpProcessTrustRuleImageName, &rule, &extension);

        RtlInitUnicodeString(&rule, L"wpp.exe");
        (VOID)DpProcessPolicyAddRule(DpProcessTrustRuleImageName, &rule, &extension);
    }
#endif

    return status;
}

VOID
DpProcessPolicyUninitialize(
    VOID
    )
{
    if (gDpProcessNotifyRegistered) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(DpProcessPolicyCreateProcessNotify,
                                                TRUE);
        gDpProcessNotifyRegistered = FALSE;
    }

    FltAcquirePushLockExclusive(&gDpProcessPolicyLock);
    DpProcessPolicyClearRulesLocked();
    DpProcessPolicyClearEntriesLocked();
    FltReleasePushLock(&gDpProcessPolicyLock);

    FltDeletePushLock(&gDpProcessPolicyLock);
}
