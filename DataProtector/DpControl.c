/*++

Module Name:

    DpControl.c

Abstract:

    Filter Manager communication port used by the policy service to update
    process trust rules.

--*/

#include "DataProtector.h"

static PFLT_PORT gDpControlServerPort = NULL;

static
NTSTATUS
FLTAPI
DpControlConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (ClientPort == NULL || ConnectionPortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ConnectionPortCookie = ClientPort;

    return STATUS_SUCCESS;
}

static
VOID
FLTAPI
DpControlDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PFLT_PORT clientPort = (PFLT_PORT)ConnectionCookie;

    if (clientPort != NULL && gDataProtectorFilter != NULL) {
        FltCloseClientPort(gDataProtectorFilter, &clientPort);
    }
}

static
NTSTATUS
FLTAPI
DpControlMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PDP_POLICY_MESSAGE message = (PDP_POLICY_MESSAGE)InputBuffer;
    UNICODE_STRING value;
    UNICODE_STRING extension;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL ||
        InputBufferLength < (ULONG)DP_POLICY_MESSAGE_HEADER_SIZE ||
        message->Version != DP_POLICY_MESSAGE_VERSION) {

        return STATUS_INVALID_PARAMETER;
    }

    if (message->Command == DpPolicyCommandQueryProcessRules) {
        return DpProcessPolicyQueryRules(OutputBuffer,
                                         OutputBufferLength,
                                         ReturnOutputBufferLength);
    }

    if (message->Command == DpPolicyCommandQueryNetworkRules) {
        return DpNetFilterQueryRules(OutputBuffer,
                                     OutputBufferLength,
                                     ReturnOutputBufferLength);
    }

    if (message->Command == DpPolicyCommandQuerySmtpEvents) {
        return DpNetFilterQuerySmtpEvents(OutputBuffer,
                                          OutputBufferLength,
                                          ReturnOutputBufferLength);
    }

    if (message->Command == DpPolicyCommandQueryWebShellRules) {
        return DpWebShellQueryRules(OutputBuffer,
                                    OutputBufferLength,
                                    ReturnOutputBufferLength);
    }

    if (message->Command == DpPolicyCommandQueryWebShellEvents) {
        return DpWebShellQueryEvents(OutputBuffer,
                                     OutputBufferLength,
                                     ReturnOutputBufferLength);
    }

    if (message->Command == DpPolicyCommandAddNetworkRule) {
        PDP_NETWORK_RULE_MESSAGE rule;

        if (message->ValueLengthBytes != sizeof(DP_NETWORK_RULE_MESSAGE) ||
            InputBufferLength < (ULONG)DP_POLICY_MESSAGE_HEADER_SIZE + sizeof(DP_NETWORK_RULE_MESSAGE)) {

            return STATUS_INVALID_PARAMETER;
        }

        rule = (PDP_NETWORK_RULE_MESSAGE)message->Data;
        return DpNetFilterAddRule(rule);
    }

    if (message->Command == DpPolicyCommandRemoveNetworkRule) {
        PULONG ruleId = (PULONG)message->Data;

        if (message->ValueLengthBytes != sizeof(ULONG) ||
            InputBufferLength < (ULONG)DP_POLICY_MESSAGE_HEADER_SIZE + sizeof(ULONG)) {

            return STATUS_INVALID_PARAMETER;
        }

        return DpNetFilterRemoveRule(*ruleId);
    }

    if (message->Command == DpPolicyCommandClearNetworkRules) {
        DpNetFilterClearRules();
        return STATUS_SUCCESS;
    }

    if (message->Command == DpPolicyCommandAddWebShellRule ||
        message->Command == DpPolicyCommandRemoveWebShellRule) {

        PDP_WEBSHELL_RULE_MESSAGE rule;

        if (message->ValueLengthBytes != sizeof(DP_WEBSHELL_RULE_MESSAGE) ||
            InputBufferLength < (ULONG)DP_POLICY_MESSAGE_HEADER_SIZE + sizeof(DP_WEBSHELL_RULE_MESSAGE)) {

            return STATUS_INVALID_PARAMETER;
        }

        rule = (PDP_WEBSHELL_RULE_MESSAGE)message->Data;
        if (message->Command == DpPolicyCommandAddWebShellRule) {
            return DpWebShellAddRule(rule);
        }

        return DpWebShellRemoveRule(rule);
    }

    if (message->Command == DpPolicyCommandClearWebShellRules) {
        DpWebShellClearRules();
        return STATUS_SUCCESS;
    }

    if (message->Command != DpPolicyCommandClearProcessRules) {
        if (message->ValueLengthBytes == 0 ||
            message->ValueLengthBytes > DP_POLICY_MAX_RULE_BYTES ||
            message->ExtensionLengthBytes == 0 ||
            message->ExtensionLengthBytes > DP_POLICY_MAX_EXTENSION_BYTES ||
            InputBufferLength < (ULONG)DP_POLICY_MESSAGE_HEADER_SIZE +
                message->ValueLengthBytes +
                message->ExtensionLengthBytes) {

            return STATUS_INVALID_PARAMETER;
        }

        value.Buffer = message->Data;
        value.Length = (USHORT)message->ValueLengthBytes;
        value.MaximumLength = value.Length;

        extension.Buffer = (PWCH)((PUCHAR)message->Data + message->ValueLengthBytes);
        extension.Length = (USHORT)message->ExtensionLengthBytes;
        extension.MaximumLength = extension.Length;
    } else {
        RtlZeroMemory(&value, sizeof(value));
        RtlZeroMemory(&extension, sizeof(extension));
    }

    switch (message->Command) {
    case DpPolicyCommandAddProcessNameRule:
        status = DpProcessPolicyAddRule(DpProcessTrustRuleImageName, &value, &extension);
        break;

    case DpPolicyCommandRemoveProcessNameRule:
        status = DpProcessPolicyRemoveRule(DpProcessTrustRuleImageName, &value, &extension);
        break;

    case DpPolicyCommandAddProcessDirectoryRule:
        status = DpProcessPolicyAddRule(DpProcessTrustRuleImageDirectory, &value, &extension);
        break;

    case DpPolicyCommandRemoveProcessDirectoryRule:
        status = DpProcessPolicyRemoveRule(DpProcessTrustRuleImageDirectory, &value, &extension);
        break;

    case DpPolicyCommandAddExcludedDirectoryRule:
        status = DpProcessPolicyAddRule(DpProcessTrustRuleExcludedDirectory, &value, &extension);
        break;

    case DpPolicyCommandRemoveExcludedDirectoryRule:
        status = DpProcessPolicyRemoveRule(DpProcessTrustRuleExcludedDirectory, &value, &extension);
        break;

    case DpPolicyCommandClearProcessRules:
        DpProcessPolicyClearRules();
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

NTSTATUS
DpControlInitialize(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objectAttributes;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    RtlInitUnicodeString(&portName, DP_POLICY_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor,
                                               FLT_PORT_ALL_ACCESS);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&objectAttributes,
                               &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               securityDescriptor);

    status = FltCreateCommunicationPort(gDataProtectorFilter,
                                        &gDpControlServerPort,
                                        &objectAttributes,
                                        NULL,
                                        DpControlConnectNotify,
                                        DpControlDisconnectNotify,
                                        DpControlMessageNotify,
                                        1);

    FltFreeSecurityDescriptor(securityDescriptor);

    return status;
}

VOID
DpControlUninitialize(
    VOID
    )
{
    if (gDpControlServerPort != NULL) {
        FltCloseCommunicationPort(gDpControlServerPort);
        gDpControlServerPort = NULL;
    }
}
