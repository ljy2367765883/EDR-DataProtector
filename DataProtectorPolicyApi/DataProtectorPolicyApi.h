#pragma once

#include <windows.h>

#ifdef DATAPROTECTORPOLICYAPI_EXPORTS
#define DP_POLICY_API __declspec(dllexport)
#else
#define DP_POLICY_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DP_POLICY_API_SUCCESS                   0x00000000u
#define DP_POLICY_API_ERROR_INVALID_ARGUMENT    0xE0010001u
#define DP_POLICY_API_ERROR_OUT_OF_MEMORY       0xE0010002u
#define DP_POLICY_API_ERROR_RULE_TOO_LONG       0xE0010003u
#define DP_POLICY_API_ERROR_PATH_CONVERSION     0xE0010004u
#define DP_POLICY_API_ERROR_BUFFER_TOO_SMALL    0xE0010005u

#define DP_POLICY_API_RULE_PROCESS_NAME         1u
#define DP_POLICY_API_RULE_PROCESS_DIRECTORY    2u
#define DP_POLICY_API_RULE_EXCLUDED_DIRECTORY   3u

#define DP_POLICY_API_NETWORK_RULE_IP           1u
#define DP_POLICY_API_NETWORK_RULE_DOMAIN       2u

#define DP_POLICY_API_NETWORK_ACTION_ALLOW      0u
#define DP_POLICY_API_NETWORK_ACTION_BLOCK      1u

#define DP_POLICY_API_NETWORK_PROTOCOL_ANY      0u
#define DP_POLICY_API_NETWORK_PROTOCOL_ICMP     1u
#define DP_POLICY_API_NETWORK_PROTOCOL_TCP      6u
#define DP_POLICY_API_NETWORK_PROTOCOL_UDP      17u

#define DP_POLICY_API_NETWORK_DIRECTION_INBOUND  0u
#define DP_POLICY_API_NETWORK_DIRECTION_OUTBOUND 1u
#define DP_POLICY_API_NETWORK_DIRECTION_BOTH     2u

#define DP_POLICY_API_WEBSHELL_SEVERITY_NOTIFY   1u
#define DP_POLICY_API_WEBSHELL_SEVERITY_WARNING  2u
#define DP_POLICY_API_WEBSHELL_SEVERITY_DANGER   3u

#define DP_POLICY_API_WEBSHELL_OPERATION_CREATE  1u
#define DP_POLICY_API_WEBSHELL_OPERATION_WRITE   2u
#define DP_POLICY_API_WEBSHELL_OPERATION_RENAME  3u

#define DP_POLICY_API_WEBSHELL_SAMPLE_BYTES      100u
#define DP_POLICY_API_DEVICE_ID_CHARS            260u

#define DP_POLICY_API_HASH_OPERATION_LSASS_HANDLE     1u
#define DP_POLICY_API_HASH_OPERATION_CREDENTIAL_FILE  2u
#define DP_POLICY_API_HASH_OPERATION_REGISTRY_HIVE    3u
#define DP_POLICY_API_HASH_OPERATION_RAW_EXTENT       4u

#define DP_POLICY_API_HASH_PROTECT_FLAG_ENABLED          0x00000001u
#define DP_POLICY_API_HASH_PROTECT_FLAG_LSASS_HANDLES    0x00000002u
#define DP_POLICY_API_HASH_PROTECT_FLAG_CREDENTIAL_FILES 0x00000004u
#define DP_POLICY_API_HASH_PROTECT_FLAG_REGISTRY_HIVES   0x00000008u
#define DP_POLICY_API_HASH_PROTECT_FLAG_RAW_EXTENTS      0x00000010u

#define DP_POLICY_API_NETWORK_EVENT_FLAG_DNS       0x00000001u
#define DP_POLICY_API_NETWORK_EVENT_FLAG_QUIC      0x00000002u
#define DP_POLICY_API_NETWORK_EVENT_FLAG_HTTP3     0x00000004u
#define DP_POLICY_API_NETWORK_EVENT_FLAG_BLOCKED   0x00000008u

typedef struct _DP_POLICY_API_RULE {
    DWORD RuleType;
    LPCWSTR Value;
    LPCWSTR Extension;
} DP_POLICY_API_RULE, *PDP_POLICY_API_RULE;

typedef struct _DP_POLICY_API_NETWORK_RULE {
    DWORD RuleId;
    DWORD Kind;
    DWORD Action;
    DWORD Protocol;
    DWORD Direction;
    DWORD LocalAddress;
    DWORD LocalAddressMask;
    DWORD RemoteAddress;
    DWORD RemoteAddressMask;
    WORD LocalPort;
    WORD RemotePort;
    LPCWSTR Domain;
} DP_POLICY_API_NETWORK_RULE, *PDP_POLICY_API_NETWORK_RULE;

typedef struct _DP_POLICY_API_SMTP_EVENT {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    DWORD LocalAddress;
    DWORD RemoteAddress;
    WORD LocalPort;
    WORD RemotePort;
    LPCWSTR From;
    LPCWSTR To;
} DP_POLICY_API_SMTP_EVENT, *PDP_POLICY_API_SMTP_EVENT;

typedef struct _DP_POLICY_API_NETWORK_CONNECTION_EVENT {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    DWORD Direction;
    DWORD Protocol;
    DWORD LocalAddress;
    DWORD RemoteAddress;
    DWORD Flags;
    WORD LocalPort;
    WORD RemotePort;
    LPCWSTR ProcessPath;
    LPCWSTR Domain;
} DP_POLICY_API_NETWORK_CONNECTION_EVENT, *PDP_POLICY_API_NETWORK_CONNECTION_EVENT;

typedef struct _DP_POLICY_API_WEBSHELL_RULE {
    LPCWSTR Directory;
} DP_POLICY_API_WEBSHELL_RULE, *PDP_POLICY_API_WEBSHELL_RULE;

typedef struct _DP_POLICY_API_DEVICE_RULE {
    LPCWSTR DeviceId;
    DWORD AllowInsert;
    DWORD AllowWrite;
} DP_POLICY_API_DEVICE_RULE, *PDP_POLICY_API_DEVICE_RULE;

typedef struct _DP_POLICY_API_WEBSHELL_EVENT {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    DWORD Severity;
    DWORD Operation;
    DWORD FileSize;
    DWORD SampleLength;
    LPCWSTR Path;
    LPCWSTR Extension;
    BYTE Sample[DP_POLICY_API_WEBSHELL_SAMPLE_BYTES];
} DP_POLICY_API_WEBSHELL_EVENT, *PDP_POLICY_API_WEBSHELL_EVENT;

typedef struct _DP_POLICY_API_HASH_PROTECT_EVENT {
    ULONGLONG Sequence;
    ULONGLONG ProcessId;
    DWORD Operation;
    DWORD Status;
    DWORD DesiredAccess;
    LPCWSTR Target;
    LPCWSTR ProcessImage;
} DP_POLICY_API_HASH_PROTECT_EVENT, *PDP_POLICY_API_HASH_PROTECT_EVENT;

typedef struct _DP_POLICY_API_HASH_PROTECT_POLICY {
    DWORD Flags;
} DP_POLICY_API_HASH_PROTECT_POLICY, *PDP_POLICY_API_HASH_PROTECT_POLICY;

DP_POLICY_API
DWORD
DpPolicyCheckConnection(void);

DP_POLICY_API
DWORD
DpPolicyAddProcessNameRule(
    _In_z_ LPCWSTR processName
    );

DP_POLICY_API
DWORD
DpPolicyAddProcessNameRuleEx(
    _In_z_ LPCWSTR processName,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyRemoveProcessNameRule(
    _In_z_ LPCWSTR processName
    );

DP_POLICY_API
DWORD
DpPolicyRemoveProcessNameRuleEx(
    _In_z_ LPCWSTR processName,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyAddProcessDirectoryRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyAddProcessDirectoryRuleEx(
    _In_z_ LPCWSTR directoryPath,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyRemoveProcessDirectoryRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyRemoveProcessDirectoryRuleEx(
    _In_z_ LPCWSTR directoryPath,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyAddExcludedDirectoryRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyAddExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR directoryPath,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyRemoveExcludedDirectoryRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyRemoveExcludedDirectoryRuleEx(
    _In_z_ LPCWSTR directoryPath,
    _In_z_ LPCWSTR extension
    );

DP_POLICY_API
DWORD
DpPolicyClearProcessRules(void);

DP_POLICY_API
DWORD
DpPolicyQueryProcessRules(
    _Out_writes_opt_(ruleCapacity) DP_POLICY_API_RULE *rules,
    _In_ DWORD ruleCapacity,
    _Out_opt_ DWORD *ruleCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyAddNetworkRule(
    _In_ const DP_POLICY_API_NETWORK_RULE *rule
    );

DP_POLICY_API
DWORD
DpPolicyRemoveNetworkRule(
    _In_ DWORD ruleId
    );

DP_POLICY_API
DWORD
DpPolicyClearNetworkRules(void);

DP_POLICY_API
DWORD
DpPolicyQueryNetworkRules(
    _Out_writes_opt_(ruleCapacity) DP_POLICY_API_NETWORK_RULE *rules,
    _In_ DWORD ruleCapacity,
    _Out_opt_ DWORD *ruleCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyQuerySmtpEvents(
    _Out_writes_opt_(eventCapacity) DP_POLICY_API_SMTP_EVENT *events,
    _In_ DWORD eventCapacity,
    _Out_opt_ DWORD *eventCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyQueryNetworkConnectionEvents(
    _Out_writes_opt_(eventCapacity) DP_POLICY_API_NETWORK_CONNECTION_EVENT *events,
    _In_ DWORD eventCapacity,
    _Out_opt_ DWORD *eventCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyAddWebShellRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyRemoveWebShellRule(
    _In_z_ LPCWSTR directoryPath
    );

DP_POLICY_API
DWORD
DpPolicyClearWebShellRules(void);

DP_POLICY_API
DWORD
DpPolicyQueryWebShellRules(
    _Out_writes_opt_(ruleCapacity) DP_POLICY_API_WEBSHELL_RULE *rules,
    _In_ DWORD ruleCapacity,
    _Out_opt_ DWORD *ruleCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyQueryWebShellEvents(
    _Out_writes_opt_(eventCapacity) DP_POLICY_API_WEBSHELL_EVENT *events,
    _In_ DWORD eventCapacity,
    _Out_opt_ DWORD *eventCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyQueryHashProtectEvents(
    _Out_writes_opt_(eventCapacity) DP_POLICY_API_HASH_PROTECT_EVENT *events,
    _In_ DWORD eventCapacity,
    _Out_opt_ DWORD *eventCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicySetHashProtectPolicy(
    _In_ const DP_POLICY_API_HASH_PROTECT_POLICY *policy
    );

DP_POLICY_API
DWORD
DpPolicyQueryHashProtectPolicy(
    _Out_ DP_POLICY_API_HASH_PROTECT_POLICY *policy
    );

DP_POLICY_API
DWORD
DpPolicyAddDeviceRule(
    _In_ const DP_POLICY_API_DEVICE_RULE *rule
    );

DP_POLICY_API
DWORD
DpPolicyRemoveDeviceRule(
    _In_z_ LPCWSTR deviceId
    );

DP_POLICY_API
DWORD
DpPolicyClearDeviceRules(void);

DP_POLICY_API
DWORD
DpPolicyQueryDeviceRules(
    _Out_writes_opt_(ruleCapacity) DP_POLICY_API_DEVICE_RULE *rules,
    _In_ DWORD ruleCapacity,
    _Out_opt_ DWORD *ruleCount,
    _Out_writes_opt_(stringBufferChars) LPWSTR stringBuffer,
    _In_ DWORD stringBufferChars,
    _Out_opt_ DWORD *stringBufferCharsRequired
    );

DP_POLICY_API
DWORD
DpPolicyConvertDosPathToNtPath(
    _In_z_ LPCWSTR dosPath,
    _Out_writes_(ntPathChars) LPWSTR ntPath,
    _In_ DWORD ntPathChars
    );

DP_POLICY_API
DWORD
DpPolicyGetLastErrorMessage(
    _Out_writes_(bufferChars) LPWSTR buffer,
    _In_ DWORD bufferChars
    );

#ifdef __cplusplus
}
#endif
