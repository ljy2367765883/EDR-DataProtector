#define WIN32_LEAN_AND_MEAN

#include "DataProtectorPolicyApi.h"

#include <fltUser.h>
#include <strsafe.h>

#define DP_POLICY_PORT_NAME L"\\DataProtectorPolicyPort"
#define DP_POLICY_MESSAGE_VERSION 1u
#define DP_POLICY_QUERY_VERSION 1u
#define DP_POLICY_MAX_RULE_BYTES (1024u * sizeof(WCHAR))
#define DP_POLICY_MAX_EXTENSION_BYTES (64u * sizeof(WCHAR))
#define DP_POLICY_DEFAULT_EXTENSION L".dpf"

typedef enum _DP_POLICY_COMMAND {
    DpPolicyCommandAddProcessNameRule = 1,
    DpPolicyCommandRemoveProcessNameRule = 2,
    DpPolicyCommandAddProcessDirectoryRule = 3,
    DpPolicyCommandRemoveProcessDirectoryRule = 4,
    DpPolicyCommandClearProcessRules = 5,
    DpPolicyCommandQueryProcessRules = 6,
    DpPolicyCommandAddExcludedDirectoryRule = 7,
    DpPolicyCommandRemoveExcludedDirectoryRule = 8
} DP_POLICY_COMMAND;

typedef struct _DP_POLICY_MESSAGE {
    ULONG Version;
    ULONG Command;
    ULONG ValueLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Data[1];
} DP_POLICY_MESSAGE, *PDP_POLICY_MESSAGE;

typedef struct _DP_POLICY_QUERY_HEADER {
    ULONG Version;
    ULONG RuleCount;
    ULONG BytesRequired;
    ULONG BytesReturned;
} DP_POLICY_QUERY_HEADER, *PDP_POLICY_QUERY_HEADER;

typedef struct _DP_POLICY_QUERY_ENTRY {
    ULONG RuleType;
    ULONG ValueLengthBytes;
    ULONG ExtensionLengthBytes;
    WCHAR Data[1];
} DP_POLICY_QUERY_ENTRY, *PDP_POLICY_QUERY_ENTRY;

static WCHAR gLastErrorMessage[512];

static
VOID
DpPolicySetLastErrorMessage(
    _In_z_ LPCWSTR Message
    )
{
    (VOID)StringCchCopyW(gLastErrorMessage,
                         ARRAYSIZE(gLastErrorMessage),
                         Message != NULL ? Message : L"Unknown error.");
}

static
VOID
DpPolicySetLastErrorFromCode(
    _In_ DWORD ErrorCode,
    _In_z_ LPCWSTR Prefix
    )
{
    WCHAR systemMessage[256];
    WCHAR formatted[512];
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS |
                  FORMAT_MESSAGE_MAX_WIDTH_MASK;

    systemMessage[0] = L'\0';

    if (FormatMessageW(flags,
                       NULL,
                       ErrorCode,
                       0,
                       systemMessage,
                       ARRAYSIZE(systemMessage),
                       NULL) == 0) {

        (VOID)StringCchPrintfW(systemMessage,
                              ARRAYSIZE(systemMessage),
                              L"Error 0x%08X",
                              ErrorCode);
    }

    (VOID)StringCchPrintfW(formatted,
                          ARRAYSIZE(formatted),
                          L"%s: %s",
                          Prefix != NULL ? Prefix : L"Operation failed",
                          systemMessage);

    DpPolicySetLastErrorMessage(formatted);
}

static
DWORD
DpPolicyTrimCopy(
    _In_z_ LPCWSTR Source,
    _Outptr_result_z_ LPWSTR *Normalized,
    _In_ BOOL TrimTrailingSlash
    )
{
    size_t length;
    LPWSTR value;

    *Normalized = NULL;

    if (Source == NULL) {
        DpPolicySetLastErrorMessage(L"Rule value is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    while (*Source == L' ' || *Source == L'\t' || *Source == L'\r' || *Source == L'\n') {
        Source++;
    }

    length = wcslen(Source);
    while (length > 0) {
        WCHAR character = Source[length - 1];

        if (character != L' ' && character != L'\t' && character != L'\r' && character != L'\n') {
            break;
        }

        length--;
    }

    if (TrimTrailingSlash) {
        while (length > 0 && (Source[length - 1] == L'\\' || Source[length - 1] == L'/')) {
            length--;
        }
    }

    if (length == 0) {
        DpPolicySetLastErrorMessage(L"Rule value is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (length * sizeof(WCHAR) > DP_POLICY_MAX_RULE_BYTES) {
        DpPolicySetLastErrorMessage(L"Rule value is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    value = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (length + 1) * sizeof(WCHAR));
    if (value == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    CopyMemory(value, Source, length * sizeof(WCHAR));
    value[length] = L'\0';

    *Normalized = value;

    return DP_POLICY_API_SUCCESS;
}

static
BOOL
DpPolicyIsNtPath(
    _In_z_ LPCWSTR Path
    )
{
    return Path != NULL &&
           (wcsncmp(Path, L"\\Device\\", 8) == 0 ||
            wcsncmp(Path, L"\\??\\", 4) == 0);
}

static
DWORD
DpPolicyConvertDosPathToNtPathAlloc(
    _In_z_ LPCWSTR DosPath,
    _Outptr_result_z_ LPWSTR *NtPath
    )
{
    WCHAR fullPath[MAX_PATH];
    WCHAR drivePrefix[3];
    WCHAR deviceName[512];
    WCHAR ntPath[1024];
    DWORD fullLength;
    DWORD deviceLength;
    HRESULT hr;

    *NtPath = NULL;

    if (DpPolicyIsNtPath(DosPath)) {
        return DpPolicyTrimCopy(DosPath, NtPath, TRUE);
    }

    fullLength = GetFullPathNameW(DosPath, ARRAYSIZE(fullPath), fullPath, NULL);
    if (fullLength == 0 || fullLength >= ARRAYSIZE(fullPath)) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot normalize directory path");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    if (fullPath[0] == L'\\' && fullPath[1] == L'\\') {
        DpPolicySetLastErrorMessage(L"UNC directory rules are not supported by this driver policy channel.");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    if (fullPath[0] == L'\0' || fullPath[1] != L':') {
        DpPolicySetLastErrorMessage(L"Directory path must be an absolute drive path or an NT path.");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    drivePrefix[0] = fullPath[0];
    drivePrefix[1] = L':';
    drivePrefix[2] = L'\0';

    deviceLength = QueryDosDeviceW(drivePrefix, deviceName, ARRAYSIZE(deviceName));
    if (deviceLength == 0) {
        DpPolicySetLastErrorFromCode(GetLastError(), L"Cannot resolve drive device name");
        return DP_POLICY_API_ERROR_PATH_CONVERSION;
    }

    hr = StringCchPrintfW(ntPath,
                         ARRAYSIZE(ntPath),
                         L"%s%s",
                         deviceName,
                         fullPath + 2);
    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"Converted NT path is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    return DpPolicyTrimCopy(ntPath, NtPath, TRUE);
}

static
DWORD
DpPolicyNormalizeExtensionAlloc(
    _In_z_ LPCWSTR Extension,
    _Outptr_result_z_ LPWSTR *Normalized
    )
{
    DWORD result;
    LPWSTR trimmed = NULL;
    size_t length;
    LPWSTR value;

    result = DpPolicyTrimCopy(Extension, &trimmed, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    length = wcslen(trimmed);
    if (length == 0 || length * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Extension value is empty or too long.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (trimmed[0] == L'.') {
        *Normalized = trimmed;
        return DP_POLICY_API_SUCCESS;
    }

    if ((length + 1) * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Extension value is too long.");
        return DP_POLICY_API_ERROR_RULE_TOO_LONG;
    }

    value = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (length + 2) * sizeof(WCHAR));
    if (value == NULL) {
        HeapFree(GetProcessHeap(), 0, trimmed);
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    value[0] = L'.';
    CopyMemory(value + 1, trimmed, length * sizeof(WCHAR));
    value[length + 1] = L'\0';

    HeapFree(GetProcessHeap(), 0, trimmed);
    *Normalized = value;

    return DP_POLICY_API_SUCCESS;
}

static
DWORD
DpPolicySendMessage(
    _In_ ULONG Command,
    _In_opt_z_ LPCWSTR RuleValue,
    _In_opt_z_ LPCWSTR ExtensionValue,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG BytesReturned
    )
{
    DWORD result = DP_POLICY_API_SUCCESS;
    HRESULT hr;
    HANDLE port = INVALID_HANDLE_VALUE;
    PDP_POLICY_MESSAGE message = NULL;
    ULONG valueLengthBytes = 0;
    ULONG extensionLengthBytes = 0;
    ULONG messageLength;
    ULONG localBytesReturned = 0;
    PULONG bytesReturned = BytesReturned != NULL ? BytesReturned : &localBytesReturned;

    *bytesReturned = 0;

    if (RuleValue != NULL) {
        size_t length = wcslen(RuleValue);

        if (length == 0) {
            DpPolicySetLastErrorMessage(L"Rule value is empty.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        if (length * sizeof(WCHAR) > DP_POLICY_MAX_RULE_BYTES) {
            DpPolicySetLastErrorMessage(L"Rule value is too long.");
            return DP_POLICY_API_ERROR_RULE_TOO_LONG;
        }

        valueLengthBytes = (ULONG)(length * sizeof(WCHAR));
    }

    if (ExtensionValue != NULL) {
        size_t length = wcslen(ExtensionValue);

        if (length == 0) {
            DpPolicySetLastErrorMessage(L"Extension value is empty.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        if (length * sizeof(WCHAR) > DP_POLICY_MAX_EXTENSION_BYTES) {
            DpPolicySetLastErrorMessage(L"Extension value is too long.");
            return DP_POLICY_API_ERROR_RULE_TOO_LONG;
        }

        extensionLengthBytes = (ULONG)(length * sizeof(WCHAR));
    }

    messageLength = (ULONG)FIELD_OFFSET(DP_POLICY_MESSAGE, Data) + valueLengthBytes + extensionLengthBytes;
    message = (PDP_POLICY_MESSAGE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
    if (message == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    message->Version = DP_POLICY_MESSAGE_VERSION;
    message->Command = Command;
    message->ValueLengthBytes = valueLengthBytes;
    message->ExtensionLengthBytes = extensionLengthBytes;

    if (valueLengthBytes != 0) {
        CopyMemory(message->Data, RuleValue, valueLengthBytes);
    }

    if (extensionLengthBytes != 0) {
        CopyMemory((PBYTE)message->Data + valueLengthBytes, ExtensionValue, extensionLengthBytes);
    }

    hr = FilterConnectCommunicationPort(DP_POLICY_PORT_NAME,
                                        0,
                                        NULL,
                                        0,
                                        NULL,
                                        &port);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Cannot connect to DataProtector driver");
        result = (DWORD)hr;
        goto Exit;
    }

    hr = FilterSendMessage(port,
                           message,
                           messageLength,
                           OutputBuffer,
                           OutputBufferLength,
                           bytesReturned);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Driver rejected the policy command");
        result = (DWORD)hr;
        goto Exit;
    }

    DpPolicySetLastErrorMessage(L"Success.");

Exit:
    if (port != INVALID_HANDLE_VALUE) {
        CloseHandle(port);
    }

    if (message != NULL) {
        HeapFree(GetProcessHeap(), 0, message);
    }

    return result;
}

DWORD
DpPolicyCheckConnection(void)
{
    HRESULT hr;
    HANDLE port = INVALID_HANDLE_VALUE;

    hr = FilterConnectCommunicationPort(DP_POLICY_PORT_NAME,
                                        0,
                                        NULL,
                                        0,
                                        NULL,
                                        &port);
    if (FAILED(hr)) {
        DpPolicySetLastErrorFromCode((DWORD)hr, L"Cannot connect to DataProtector driver");
        return (DWORD)hr;
    }

    CloseHandle(port);
    DpPolicySetLastErrorMessage(L"Success.");

    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyAddProcessNameRule(
    _In_z_ LPCWSTR ProcessName
    )
{
    return DpPolicyAddProcessNameRuleEx(ProcessName, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddProcessNameRuleEx(
    _In_z_ LPCWSTR ProcessName,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR normalized = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyTrimCopy(ProcessName, &normalized, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, normalized);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddProcessNameRule,
                                 normalized,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, normalized);

    return result;
}

DWORD
DpPolicyRemoveProcessNameRule(
    _In_z_ LPCWSTR ProcessName
    )
{
    return DpPolicyRemoveProcessNameRuleEx(ProcessName, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveProcessNameRuleEx(
    _In_z_ LPCWSTR ProcessName,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR normalized = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyTrimCopy(ProcessName, &normalized, FALSE);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, normalized);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveProcessNameRule,
                                 normalized,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, normalized);

    return result;
}

DWORD
DpPolicyAddProcessDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyAddProcessDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddProcessDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddProcessDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyRemoveProcessDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyRemoveProcessDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveProcessDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveProcessDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);
    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyAddExcludedDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyAddExcludedDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyAddExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandAddExcludedDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);

    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyRemoveExcludedDirectoryRule(
    _In_z_ LPCWSTR DirectoryPath
    )
{
    return DpPolicyRemoveExcludedDirectoryRuleEx(DirectoryPath, DP_POLICY_DEFAULT_EXTENSION);
}

DWORD
DpPolicyRemoveExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR DirectoryPath,
    _In_z_ LPCWSTR Extension
    )
{
    DWORD result;
    LPWSTR ntPath = NULL;
    LPWSTR normalizedExtension = NULL;

    result = DpPolicyConvertDosPathToNtPathAlloc(DirectoryPath, &ntPath);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    result = DpPolicyNormalizeExtensionAlloc(Extension, &normalizedExtension);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ntPath);
        return result;
    }

    result = DpPolicySendMessage(DpPolicyCommandRemoveExcludedDirectoryRule,
                                 ntPath,
                                 normalizedExtension,
                                 NULL,
                                 0,
                                 NULL);

    HeapFree(GetProcessHeap(), 0, normalizedExtension);
    HeapFree(GetProcessHeap(), 0, ntPath);

    return result;
}

DWORD
DpPolicyClearProcessRules(void)
{
    return DpPolicySendMessage(DpPolicyCommandClearProcessRules,
                               NULL,
                               NULL,
                               NULL,
                               0,
                               NULL);
}

DWORD
DpPolicyQueryProcessRules(
    _Out_writes_opt_(RuleCapacity) DP_POLICY_API_RULE *Rules,
    _In_ DWORD RuleCapacity,
    _Out_opt_ DWORD *RuleCount,
    _Out_writes_opt_(StringBufferChars) LPWSTR StringBuffer,
    _In_ DWORD StringBufferChars,
    _Out_opt_ DWORD *StringBufferCharsRequired
    )
{
    DWORD result;
    ULONG bytesReturned = 0;
    ULONG bytesRequired;
    PBYTE queryBuffer = NULL;
    PDP_POLICY_QUERY_HEADER header;
    DP_POLICY_QUERY_HEADER sizingHeader;
    PBYTE cursor;
    DWORD index;
    DWORD requiredStringChars = 0;
    DWORD copiedStringChars = 0;

    if (RuleCount != NULL) {
        *RuleCount = 0;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = 0;
    }

    if ((RuleCapacity != 0 && Rules == NULL) ||
        (StringBufferChars != 0 && StringBuffer == NULL)) {

        DpPolicySetLastErrorMessage(L"Output buffer is invalid.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    ZeroMemory(&sizingHeader, sizeof(sizingHeader));

    result = DpPolicySendMessage(DpPolicyCommandQueryProcessRules,
                                 NULL,
                                 NULL,
                                 &sizingHeader,
                                 sizeof(sizingHeader),
                                 &bytesReturned);

    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    if (bytesReturned < sizeof(DP_POLICY_QUERY_HEADER) ||
        sizingHeader.Version != DP_POLICY_QUERY_VERSION ||
        sizingHeader.BytesRequired < sizeof(DP_POLICY_QUERY_HEADER)) {

        DpPolicySetLastErrorMessage(L"Driver returned an invalid rule snapshot header.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    bytesRequired = sizingHeader.BytesRequired;

    queryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesRequired);
    if (queryBuffer == NULL) {
        DpPolicySetLastErrorMessage(L"Out of memory.");
        return DP_POLICY_API_ERROR_OUT_OF_MEMORY;
    }

    result = DpPolicySendMessage(DpPolicyCommandQueryProcessRules,
                                 NULL,
                                 NULL,
                                 queryBuffer,
                                 bytesRequired,
                                 &bytesReturned);
    if (result != DP_POLICY_API_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        return result;
    }

    if (bytesReturned < sizeof(DP_POLICY_QUERY_HEADER)) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an invalid rule snapshot.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    header = (PDP_POLICY_QUERY_HEADER)queryBuffer;
    if (header->Version != DP_POLICY_QUERY_VERSION) {
        HeapFree(GetProcessHeap(), 0, queryBuffer);
        DpPolicySetLastErrorMessage(L"Driver returned an unsupported rule snapshot version.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    if (RuleCount != NULL) {
        *RuleCount = header->RuleCount;
    }

    cursor = queryBuffer + sizeof(DP_POLICY_QUERY_HEADER);

    for (index = 0; index < header->RuleCount; index++) {
        PDP_POLICY_QUERY_ENTRY entry;
        DWORD valueChars;
        DWORD extensionChars;
        DWORD entryBytes;
        LPCWSTR valueSource;
        LPCWSTR extensionSource;

        if ((ULONG_PTR)(cursor - queryBuffer) + sizeof(DP_POLICY_QUERY_ENTRY) > bytesReturned) {
            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned a truncated rule snapshot.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        entry = (PDP_POLICY_QUERY_ENTRY)cursor;
        entryBytes = (DWORD)FIELD_OFFSET(DP_POLICY_QUERY_ENTRY, Data) +
                     entry->ValueLengthBytes +
                     entry->ExtensionLengthBytes;

        if ((ULONG_PTR)(cursor - queryBuffer) + entryBytes > bytesReturned ||
            entry->ValueLengthBytes % sizeof(WCHAR) != 0 ||
            entry->ExtensionLengthBytes % sizeof(WCHAR) != 0) {

            HeapFree(GetProcessHeap(), 0, queryBuffer);
            DpPolicySetLastErrorMessage(L"Driver returned an invalid rule entry.");
            return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
        }

        valueChars = entry->ValueLengthBytes / sizeof(WCHAR);
        extensionChars = entry->ExtensionLengthBytes / sizeof(WCHAR);
        requiredStringChars += valueChars + 1 + extensionChars + 1;

        if (index < RuleCapacity && StringBuffer != NULL &&
            copiedStringChars + valueChars + 1 + extensionChars + 1 <= StringBufferChars) {

            valueSource = entry->Data;
            extensionSource = (LPCWSTR)((PBYTE)entry->Data + entry->ValueLengthBytes);

            Rules[index].RuleType = entry->RuleType;
            Rules[index].Value = StringBuffer + copiedStringChars;
            CopyMemory(StringBuffer + copiedStringChars,
                       valueSource,
                       entry->ValueLengthBytes);
            copiedStringChars += valueChars;
            StringBuffer[copiedStringChars++] = L'\0';

            Rules[index].Extension = StringBuffer + copiedStringChars;
            CopyMemory(StringBuffer + copiedStringChars,
                       extensionSource,
                       entry->ExtensionLengthBytes);
            copiedStringChars += extensionChars;
            StringBuffer[copiedStringChars++] = L'\0';
        }

        cursor += entryBytes;
    }

    if (StringBufferCharsRequired != NULL) {
        *StringBufferCharsRequired = requiredStringChars;
    }

    HeapFree(GetProcessHeap(), 0, queryBuffer);

    if (RuleCapacity < header->RuleCount || StringBufferChars < requiredStringChars) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyConvertDosPathToNtPath(
    _In_z_ LPCWSTR DosPath,
    _Out_writes_(NtPathChars) LPWSTR NtPath,
    _In_ DWORD NtPathChars
    )
{
    DWORD result;
    LPWSTR converted = NULL;
    HRESULT hr;

    if (NtPath == NULL || NtPathChars == 0) {
        DpPolicySetLastErrorMessage(L"Output buffer is empty.");
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    NtPath[0] = L'\0';

    result = DpPolicyConvertDosPathToNtPathAlloc(DosPath, &converted);
    if (result != DP_POLICY_API_SUCCESS) {
        return result;
    }

    hr = StringCchCopyW(NtPath, NtPathChars, converted);
    HeapFree(GetProcessHeap(), 0, converted);

    if (FAILED(hr)) {
        DpPolicySetLastErrorMessage(L"Output buffer is too small.");
        return DP_POLICY_API_ERROR_BUFFER_TOO_SMALL;
    }

    DpPolicySetLastErrorMessage(L"Success.");
    return DP_POLICY_API_SUCCESS;
}

DWORD
DpPolicyGetLastErrorMessage(
    _Out_writes_(BufferChars) LPWSTR Buffer,
    _In_ DWORD BufferChars
    )
{
    HRESULT hr;

    if (Buffer == NULL || BufferChars == 0) {
        return DP_POLICY_API_ERROR_INVALID_ARGUMENT;
    }

    hr = StringCchCopyW(Buffer, BufferChars, gLastErrorMessage[0] != L'\0' ?
                        gLastErrorMessage :
                        L"No error information is available.");

    return FAILED(hr) ? DP_POLICY_API_ERROR_BUFFER_TOO_SMALL : DP_POLICY_API_SUCCESS;
}
