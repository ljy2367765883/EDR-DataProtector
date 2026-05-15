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

typedef struct _DP_POLICY_API_RULE {
    DWORD RuleType;
    LPCWSTR Value;
    LPCWSTR Extension;
} DP_POLICY_API_RULE, *PDP_POLICY_API_RULE;

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
