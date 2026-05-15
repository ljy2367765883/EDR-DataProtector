/*++

Module Name:

    DpNetFilter.c

Abstract:

    Windows Filtering Platform network protection module for DataProtector.
    The first production integration supports IPv4 outbound IP rules and
    outbound UDP/53 DNS domain rules through the existing policy channel.

--*/

#ifndef NDIS630
#define NDIS630 1
#endif
#ifndef NDIS_WDM
#define NDIS_WDM 1
#endif

#include "DataProtector.h"
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

DEFINE_GUID(
    DP_WFP_SUBLAYER_GUID,
    0x8c5d1d24, 0x23b7, 0x4d97, 0x9b, 0x3d, 0xaa, 0x46, 0x30, 0x91, 0x10, 0x71);

DEFINE_GUID(
    DP_WFP_ALE_CONNECT_V4_CALLOUT_GUID,
    0x6a49fc75, 0x1736, 0x4e9b, 0x96, 0xaa, 0x17, 0x60, 0x97, 0x3f, 0x10, 0x4b);

DEFINE_GUID(
    DP_WFP_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
    0x6377bd40, 0x8c40, 0x45dc, 0xa1, 0x6e, 0x22, 0xec, 0xf8, 0xb8, 0x44, 0x55);

DEFINE_GUID(
    DP_WFP_DNS_DATAGRAM_V4_CALLOUT_GUID,
    0x499d0624, 0x7b6f, 0x46c9, 0xa9, 0xc2, 0x3d, 0xb7, 0x76, 0x92, 0x21, 0xe4);

typedef struct _DP_NETWORK_RULE_ENTRY {
    LIST_ENTRY Link;
    ULONG RuleId;
    DP_NETWORK_RULE_KIND Kind;
    DP_NETWORK_ACTION Action;
    DP_NETWORK_PROTOCOL Protocol;
    DP_NETWORK_DIRECTION Direction;
    ULONG LocalAddress;
    ULONG LocalAddressMask;
    ULONG RemoteAddress;
    ULONG RemoteAddressMask;
    USHORT LocalPort;
    USHORT RemotePort;
    UNICODE_STRING Domain;
} DP_NETWORK_RULE_ENTRY, *PDP_NETWORK_RULE_ENTRY;

static LIST_ENTRY gDpNetworkRules;
static KSPIN_LOCK gDpNetworkRuleLock;
static PDEVICE_OBJECT gDpNetDeviceObject = NULL;
static HANDLE gDpWfpEngineHandle = NULL;
static UINT32 gDpAleConnectV4CalloutId = 0;
static UINT32 gDpAleRecvAcceptV4CalloutId = 0;
static UINT32 gDpDnsDatagramV4CalloutId = 0;
static BOOLEAN gDpNetFilterInitialized = FALSE;
static BOOLEAN gDpNetworkRuleLockInitialized = FALSE;

static
VOID
DpNetFilterFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, DP_TAG_NET_RULE);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

static
VOID
DpNetFilterFreeRule(
    _In_ PDP_NETWORK_RULE_ENTRY Rule
    )
{
    if (Rule != NULL) {
        DpNetFilterFreeUnicodeString(&Rule->Domain);
        ExFreePoolWithTag(Rule, DP_TAG_NET_RULE);
    }
}

static
WCHAR
DpNetFilterLowerWide(
    _In_ WCHAR Character
    )
{
    if (Character >= L'A' && Character <= L'Z') {
        return Character + (L'a' - L'A');
    }

    return Character;
}

static
BOOLEAN
DpNetFilterEqualDomain(
    _In_ PCUNICODE_STRING RuleDomain,
    _In_ PCWSTR Domain
    )
{
    SIZE_T domainLength = 0;
    SIZE_T ruleLength;
    SIZE_T index;

    if (RuleDomain == NULL ||
        RuleDomain->Buffer == NULL ||
        RuleDomain->Length == 0 ||
        Domain == NULL ||
        Domain[0] == L'\0') {

        return FALSE;
    }

    while (Domain[domainLength] != L'\0') {
        domainLength++;
    }

    ruleLength = RuleDomain->Length / sizeof(WCHAR);

    if (ruleLength > 1 && RuleDomain->Buffer[0] == L'*') {
        PCWSTR suffix = RuleDomain->Buffer + 1;
        SIZE_T suffixLength = ruleLength - 1;

        if (domainLength < suffixLength) {
            return FALSE;
        }

        for (index = 0; index < suffixLength; index++) {
            if (DpNetFilterLowerWide(suffix[index]) !=
                DpNetFilterLowerWide(Domain[domainLength - suffixLength + index])) {

                return FALSE;
            }
        }

        return TRUE;
    }

    if (domainLength != ruleLength) {
        return FALSE;
    }

    for (index = 0; index < ruleLength; index++) {
        if (DpNetFilterLowerWide(RuleDomain->Buffer[index]) !=
            DpNetFilterLowerWide(Domain[index])) {

            return FALSE;
        }
    }

    return TRUE;
}

static
BOOLEAN
DpNetFilterDirectionMatches(
    _In_ DP_NETWORK_DIRECTION RuleDirection,
    _In_ DP_NETWORK_DIRECTION Direction
    )
{
    return RuleDirection == DpNetworkDirectionBoth || RuleDirection == Direction;
}

static
BOOLEAN
DpNetFilterProtocolMatches(
    _In_ DP_NETWORK_PROTOCOL RuleProtocol,
    _In_ DP_NETWORK_PROTOCOL Protocol
    )
{
    return RuleProtocol == DpNetworkProtocolAny || RuleProtocol == Protocol;
}

static
BOOLEAN
DpNetFilterAddressMatches(
    _In_ ULONG RuleAddress,
    _In_ ULONG RuleMask,
    _In_ ULONG Address
    )
{
    if (RuleMask != 0) {
        return (Address & RuleMask) == (RuleAddress & RuleMask);
    }

    return RuleAddress == 0 || RuleAddress == Address;
}

static
BOOLEAN
DpNetFilterRuleMatches(
    _In_ PDP_NETWORK_RULE_ENTRY Rule,
    _In_ DP_NETWORK_DIRECTION Direction,
    _In_ DP_NETWORK_PROTOCOL Protocol,
    _In_ ULONG LocalAddress,
    _In_ USHORT LocalPort,
    _In_ ULONG RemoteAddress,
    _In_ USHORT RemotePort,
    _In_opt_ PCWSTR Domain
    )
{
    if (!DpNetFilterDirectionMatches(Rule->Direction, Direction) ||
        !DpNetFilterProtocolMatches(Rule->Protocol, Protocol)) {

        return FALSE;
    }

    if (Rule->LocalPort != 0 && Rule->LocalPort != LocalPort) {
        return FALSE;
    }

    if (Rule->RemotePort != 0 && Rule->RemotePort != RemotePort) {
        return FALSE;
    }

    if (!DpNetFilterAddressMatches(Rule->LocalAddress, Rule->LocalAddressMask, LocalAddress) ||
        !DpNetFilterAddressMatches(Rule->RemoteAddress, Rule->RemoteAddressMask, RemoteAddress)) {

        return FALSE;
    }

    if (Rule->Kind == DpNetworkRuleDomain) {
        return DpNetFilterEqualDomain(&Rule->Domain, Domain);
    }

    return TRUE;
}

static
DP_NETWORK_ACTION
DpNetFilterFindAction(
    _In_ DP_NETWORK_DIRECTION Direction,
    _In_ DP_NETWORK_PROTOCOL Protocol,
    _In_ ULONG LocalAddress,
    _In_ USHORT LocalPort,
    _In_ ULONG RemoteAddress,
    _In_ USHORT RemotePort,
    _In_opt_ PCWSTR Domain
    )
{
    PLIST_ENTRY link;
    DP_NETWORK_ACTION action = DpNetworkActionAllow;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gDpNetworkRuleLock, &oldIrql);

    for (link = gDpNetworkRules.Flink; link != &gDpNetworkRules; link = link->Flink) {
        PDP_NETWORK_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_NETWORK_RULE_ENTRY, Link);

        if (DpNetFilterRuleMatches(rule,
                                   Direction,
                                   Protocol,
                                   LocalAddress,
                                   LocalPort,
                                   RemoteAddress,
                                   RemotePort,
                                   Domain)) {

            action = rule->Action;
            break;
        }
    }

    KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);

    return action;
}

static
PDP_NETWORK_RULE_ENTRY
DpNetFilterRemoveRuleLocked(
    _In_ ULONG RuleId
    )
{
    PLIST_ENTRY link;

    for (link = gDpNetworkRules.Flink; link != &gDpNetworkRules; link = link->Flink) {
        PDP_NETWORK_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_NETWORK_RULE_ENTRY, Link);

        if (rule->RuleId == RuleId) {
            RemoveEntryList(&rule->Link);
            return rule;
        }
    }

    return NULL;
}

static
VOID
NTAPI
DpNetFilterAleClassify(
    _In_ const FWPS_INCOMING_VALUES0 *InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *InMetaValues,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER1 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *ClassifyOut
    )
{
    ULONG localAddress;
    ULONG remoteAddress;
    USHORT localPort;
    USHORT remotePort;
    UCHAR protocol;
    DP_NETWORK_DIRECTION direction;
    DP_NETWORK_ACTION action;

    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (InFixedValues == NULL ||
        ClassifyOut == NULL ||
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {

        return;
    }

    if (!gDpNetFilterInitialized) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        direction = DpNetworkDirectionOutbound;
        localAddress = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddress = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    } else if (InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        direction = DpNetworkDirectionInbound;
        localAddress = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddress = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    action = DpNetFilterFindAction(direction,
                                   (DP_NETWORK_PROTOCOL)protocol,
                                   localAddress,
                                   localPort,
                                   remoteAddress,
                                   remotePort,
                                   NULL);

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static
BOOLEAN
DpNetFilterParseDnsQuery(
    _In_ const VOID *LayerData,
    _In_ ULONG TransportHeaderSize,
    _Out_writes_(DomainBufferChars) PWCHAR DomainBuffer,
    _In_ SIZE_T DomainBufferChars
    )
{
    PNET_BUFFER_LIST netBufferList;
    PNET_BUFFER netBuffer;
    ULONG dataLength;
    PUCHAR copyBuffer = NULL;
    PVOID dataBuffer;
    PUCHAR dnsHeader;
    PUCHAR dnsQuery;
    ULONG remainingLength;
    SIZE_T queryIndex = 0;
    SIZE_T outputIndex = 0;

    if (LayerData == NULL ||
        DomainBuffer == NULL ||
        DomainBufferChars == 0 ||
        TransportHeaderSize == 0) {

        return FALSE;
    }

    DomainBuffer[0] = L'\0';
    netBufferList = (PNET_BUFFER_LIST)LayerData;
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    if (netBuffer == NULL) {
        return FALSE;
    }

    dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    if (dataLength < TransportHeaderSize + 12) {
        return FALSE;
    }

    copyBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, DP_TAG_NET_BUFFER);
    if (copyBuffer == NULL) {
        return FALSE;
    }

    dataBuffer = NdisGetDataBuffer(netBuffer, dataLength, copyBuffer, 1, 0);
    if (dataBuffer == NULL) {
        ExFreePoolWithTag(copyBuffer, DP_TAG_NET_BUFFER);
        return FALSE;
    }

    dnsHeader = (PUCHAR)dataBuffer + TransportHeaderSize;
    if ((dnsHeader[2] & 0x80) != 0) {
        ExFreePoolWithTag(copyBuffer, DP_TAG_NET_BUFFER);
        return FALSE;
    }

    dnsQuery = dnsHeader + 12;
    remainingLength = dataLength - TransportHeaderSize - 12;

    while (queryIndex < remainingLength && outputIndex < DomainBufferChars - 1) {
        UCHAR labelLength = dnsQuery[queryIndex++];
        UCHAR index;

        if (labelLength == 0) {
            break;
        }

        if ((labelLength & 0xC0) == 0xC0 ||
            labelLength > 63 ||
            queryIndex + labelLength > remainingLength) {

            break;
        }

        if (outputIndex > 0) {
            DomainBuffer[outputIndex++] = L'.';
        }

        for (index = 0; index < labelLength && outputIndex < DomainBufferChars - 1; index++) {
            UCHAR character = dnsQuery[queryIndex++];

            if (character < 0x20 || character > 0x7E) {
                ExFreePoolWithTag(copyBuffer, DP_TAG_NET_BUFFER);
                return FALSE;
            }

            if (character >= 'A' && character <= 'Z') {
                character += ('a' - 'A');
            }

            DomainBuffer[outputIndex++] = (WCHAR)character;
        }
    }

    DomainBuffer[outputIndex] = L'\0';
    ExFreePoolWithTag(copyBuffer, DP_TAG_NET_BUFFER);

    return outputIndex > 0;
}

static
VOID
NTAPI
DpNetFilterDnsClassify(
    _In_ const FWPS_INCOMING_VALUES0 *InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *InMetaValues,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER1 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *ClassifyOut
    )
{
    ULONG localAddress;
    ULONG remoteAddress;
    USHORT localPort;
    USHORT remotePort;
    UCHAR protocol;
    ULONG directionValue;
    ULONG transportHeaderSize = 0;
    WCHAR domain[260];
    DP_NETWORK_ACTION action;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (InFixedValues == NULL ||
        ClassifyOut == NULL ||
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {

        return;
    }

    if (!gDpNetFilterInitialized) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    directionValue = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32;
    if (directionValue != FWP_DIRECTION_OUTBOUND) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    protocol = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
    remotePort = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    if (protocol != IPPROTO_UDP) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    localAddress = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
    remoteAddress = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
    localPort = InFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;

    action = DpNetFilterFindAction(DpNetworkDirectionOutbound,
                                   DpNetworkProtocolUdp,
                                   localAddress,
                                   localPort,
                                   remoteAddress,
                                   remotePort,
                                   NULL);

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    if (remotePort != 53) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (InMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE)) {

        transportHeaderSize = InMetaValues->transportHeaderSize;
    }

    if (!DpNetFilterParseDnsQuery(LayerData,
                                  transportHeaderSize,
                                  domain,
                                  RTL_NUMBER_OF(domain))) {

        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    action = DpNetFilterFindAction(DpNetworkDirectionOutbound,
                                   DpNetworkProtocolUdp,
                                   localAddress,
                                   localPort,
                                   remoteAddress,
                                   remotePort,
                                   domain);

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static
NTSTATUS
NTAPI
DpNetFilterNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID *FilterKey,
    _Inout_ FWPS_FILTER1 *Filter
    )
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

static
VOID
NTAPI
DpNetFilterFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    )
{
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);
    UNREFERENCED_PARAMETER(FlowContext);
}

static
NTSTATUS
DpNetFilterRegisterCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ const GUID *CalloutGuid,
    _In_ const GUID *LayerGuid,
    _In_ FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFn,
    _In_z_ PWSTR Name,
    _Out_ UINT32 *CalloutId
    )
{
    NTSTATUS status;
    FWPS_CALLOUT1 callout;
    FWPM_CALLOUT0 managementCallout;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutGuid;
    callout.classifyFn = ClassifyFn;
    callout.notifyFn = DpNetFilterNotify;
    callout.flowDeleteFn = DpNetFilterFlowDelete;

    status = FwpsCalloutRegister1(DeviceObject, &callout, CalloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&managementCallout, sizeof(managementCallout));
    managementCallout.calloutKey = *CalloutGuid;
    managementCallout.displayData.name = Name;
    managementCallout.displayData.description = L"DataProtector network defense callout";
    managementCallout.applicableLayer = *LayerGuid;

    status = FwpmCalloutAdd0(gDpWfpEngineHandle, &managementCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(*CalloutId);
        *CalloutId = 0;
    }

    return status == STATUS_FWP_ALREADY_EXISTS ? STATUS_SUCCESS : status;
}

static
NTSTATUS
DpNetFilterAddManagementFilter(
    _In_ const GUID *LayerGuid,
    _In_ const GUID *CalloutGuid,
    _In_z_ PWSTR Name,
    _In_opt_ FWPM_FILTER_CONDITION0 *Conditions,
    _In_ UINT32 ConditionCount
    )
{
    FWPM_FILTER0 filter;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = *LayerGuid;
    filter.displayData.name = Name;
    filter.displayData.description = L"DataProtector network defense filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *CalloutGuid;
    filter.subLayerKey = DP_WFP_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.filterCondition = Conditions;
    filter.numFilterConditions = ConditionCount;

    return FwpmFilterAdd0(gDpWfpEngineHandle, &filter, NULL, NULL);
}

static
VOID
DpNetFilterInitializeProtocolCondition(
    _Out_ FWPM_FILTER_CONDITION0 *Condition,
    _In_ UCHAR Protocol
    )
{
    RtlZeroMemory(Condition, sizeof(FWPM_FILTER_CONDITION0));
    Condition->fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    Condition->matchType = FWP_MATCH_EQUAL;
    Condition->conditionValue.type = FWP_UINT8;
    Condition->conditionValue.uint8 = Protocol;
}

NTSTATUS
DpNetFilterInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 subLayer;
    FWPM_FILTER_CONDITION0 tcpCondition;
    FWPM_FILTER_CONDITION0 aleUdpCondition;
    FWPM_FILTER_CONDITION0 udpConditions[2];

    InitializeListHead(&gDpNetworkRules);
    KeInitializeSpinLock(&gDpNetworkRuleLock);
    gDpNetworkRuleLockInitialized = TRUE;

    status = IoCreateDevice(DriverObject,
                            0,
                            NULL,
                            FILE_DEVICE_NETWORK,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &gDpNetDeviceObject);
    if (!NT_SUCCESS(status)) {
        DpNetFilterUninitialize();
        return status;
    }

    gDpNetDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL,
                             RPC_C_AUTHN_WINNT,
                             NULL,
                             &session,
                             &gDpWfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DpNetFilterUninitialize();
        return status;
    }

    status = FwpmTransactionBegin0(gDpWfpEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(gDpWfpEngineHandle);
        gDpWfpEngineHandle = NULL;
        DpNetFilterUninitialize();
        return status;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = DP_WFP_SUBLAYER_GUID;
    subLayer.displayData.name = L"DataProtector Network Defense";
    subLayer.displayData.description = L"DataProtector WFP network defense sublayer";
    subLayer.weight = 0xFFFF;

    status = FwpmSubLayerAdd0(gDpWfpEngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    status = DpNetFilterRegisterCallout(gDpNetDeviceObject,
                                        &DP_WFP_ALE_CONNECT_V4_CALLOUT_GUID,
                                        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                        DpNetFilterAleClassify,
                                        L"DataProtector ALE Connect V4",
                                        &gDpAleConnectV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    status = DpNetFilterRegisterCallout(gDpNetDeviceObject,
                                        &DP_WFP_DNS_DATAGRAM_V4_CALLOUT_GUID,
                                        &FWPM_LAYER_DATAGRAM_DATA_V4,
                                        DpNetFilterDnsClassify,
                                        L"DataProtector DNS Datagram V4",
                                        &gDpDnsDatagramV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    status = DpNetFilterRegisterCallout(gDpNetDeviceObject,
                                        &DP_WFP_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
                                        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                        DpNetFilterAleClassify,
                                        L"DataProtector ALE Recv Accept V4",
                                        &gDpAleRecvAcceptV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    DpNetFilterInitializeProtocolCondition(&tcpCondition, IPPROTO_TCP);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                            &DP_WFP_ALE_CONNECT_V4_CALLOUT_GUID,
                                            L"DataProtector outbound TCP defense",
                                            &tcpCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializeProtocolCondition(&aleUdpCondition, IPPROTO_UDP);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                            &DP_WFP_ALE_CONNECT_V4_CALLOUT_GUID,
                                            L"DataProtector outbound UDP connect defense",
                                            &aleUdpCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializeProtocolCondition(&tcpCondition, IPPROTO_TCP);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                            &DP_WFP_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
                                            L"DataProtector inbound TCP defense",
                                            &tcpCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializeProtocolCondition(&aleUdpCondition, IPPROTO_UDP);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                            &DP_WFP_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
                                            L"DataProtector inbound UDP defense",
                                            &aleUdpCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    RtlZeroMemory(udpConditions, sizeof(udpConditions));
    udpConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    udpConditions[0].matchType = FWP_MATCH_EQUAL;
    udpConditions[0].conditionValue.type = FWP_UINT8;
    udpConditions[0].conditionValue.uint8 = IPPROTO_UDP;
    udpConditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
    udpConditions[1].matchType = FWP_MATCH_EQUAL;
    udpConditions[1].conditionValue.type = FWP_UINT32;
    udpConditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;

    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_DATAGRAM_DATA_V4,
                                            &DP_WFP_DNS_DATAGRAM_V4_CALLOUT_GUID,
                                            L"DataProtector outbound UDP defense",
                                            udpConditions,
                                            RTL_NUMBER_OF(udpConditions));
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    status = FwpmTransactionCommit0(gDpWfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    gDpNetFilterInitialized = TRUE;
    return STATUS_SUCCESS;

Abort:
    FwpmTransactionAbort0(gDpWfpEngineHandle);

Cleanup:
    DpNetFilterUninitialize();
    return status;
}

VOID
DpNetFilterUninitialize(
    VOID
    )
{
    gDpNetFilterInitialized = FALSE;

    if (gDpDnsDatagramV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(gDpDnsDatagramV4CalloutId);
        gDpDnsDatagramV4CalloutId = 0;
    }

    if (gDpAleRecvAcceptV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(gDpAleRecvAcceptV4CalloutId);
        gDpAleRecvAcceptV4CalloutId = 0;
    }

    if (gDpAleConnectV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(gDpAleConnectV4CalloutId);
        gDpAleConnectV4CalloutId = 0;
    }

    if (gDpWfpEngineHandle != NULL) {
        FwpmEngineClose0(gDpWfpEngineHandle);
        gDpWfpEngineHandle = NULL;
    }

    if (gDpNetDeviceObject != NULL) {
        IoDeleteDevice(gDpNetDeviceObject);
        gDpNetDeviceObject = NULL;
    }

    if (gDpNetworkRuleLockInitialized) {
        DpNetFilterClearRules();
        gDpNetworkRuleLockInitialized = FALSE;
    }
}

NTSTATUS
DpNetFilterAddRule(
    _In_ const DP_NETWORK_RULE_MESSAGE *Rule
    )
{
    PDP_NETWORK_RULE_ENTRY entry;
    KIRQL oldIrql;
    PDP_NETWORK_RULE_ENTRY oldRule = NULL;

    if (Rule == NULL ||
        Rule->Version != DP_NETWORK_RULE_MESSAGE_VERSION ||
        Rule->RuleId == 0 ||
        (Rule->Kind != DpNetworkRuleIp && Rule->Kind != DpNetworkRuleDomain) ||
        (Rule->Action != DpNetworkActionAllow && Rule->Action != DpNetworkActionBlock) ||
        (Rule->DomainLengthBytes > DP_POLICY_MAX_DOMAIN_BYTES) ||
        (Rule->DomainLengthBytes % sizeof(WCHAR)) != 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->Kind == DpNetworkRuleDomain && Rule->DomainLengthBytes == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_NETWORK_RULE_ENTRY),
                                  DP_TAG_NET_RULE);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(DP_NETWORK_RULE_ENTRY));
    entry->RuleId = Rule->RuleId;
    entry->Kind = (DP_NETWORK_RULE_KIND)Rule->Kind;
    entry->Action = (DP_NETWORK_ACTION)Rule->Action;
    entry->Protocol = (DP_NETWORK_PROTOCOL)Rule->Protocol;
    entry->Direction = (DP_NETWORK_DIRECTION)Rule->Direction;
    entry->LocalAddress = Rule->LocalAddress;
    entry->LocalAddressMask = Rule->LocalAddressMask;
    entry->RemoteAddress = Rule->RemoteAddress;
    entry->RemoteAddressMask = Rule->RemoteAddressMask;
    entry->LocalPort = Rule->LocalPort;
    entry->RemotePort = Rule->RemotePort;
    InitializeListHead(&entry->Link);

    if (Rule->DomainLengthBytes != 0) {
        entry->Domain.Buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                     Rule->DomainLengthBytes,
                                                     DP_TAG_NET_RULE);
        if (entry->Domain.Buffer == NULL) {
            DpNetFilterFreeRule(entry);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(entry->Domain.Buffer, Rule->Domain, Rule->DomainLengthBytes);
        entry->Domain.Length = (USHORT)Rule->DomainLengthBytes;
        entry->Domain.MaximumLength = entry->Domain.Length;
    }

    KeAcquireSpinLock(&gDpNetworkRuleLock, &oldIrql);
    oldRule = DpNetFilterRemoveRuleLocked(Rule->RuleId);
    InsertTailList(&gDpNetworkRules, &entry->Link);
    KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);

    if (oldRule != NULL) {
        DpNetFilterFreeRule(oldRule);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpNetFilterRemoveRule(
    _In_ ULONG RuleId
    )
{
    PDP_NETWORK_RULE_ENTRY matched = NULL;
    KIRQL oldIrql;

    if (RuleId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&gDpNetworkRuleLock, &oldIrql);

    matched = DpNetFilterRemoveRuleLocked(RuleId);

    KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);

    if (matched == NULL) {
        return STATUS_NOT_FOUND;
    }

    DpNetFilterFreeRule(matched);
    return STATUS_SUCCESS;
}

VOID
DpNetFilterClearRules(
    VOID
    )
{
    LIST_ENTRY localList;
    KIRQL oldIrql;

    InitializeListHead(&localList);

    KeAcquireSpinLock(&gDpNetworkRuleLock, &oldIrql);

    while (!IsListEmpty(&gDpNetworkRules)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpNetworkRules);
        InsertTailList(&localList, link);
    }

    KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY link = RemoveHeadList(&localList);
        PDP_NETWORK_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_NETWORK_RULE_ENTRY, Link);
        DpNetFilterFreeRule(rule);
    }
}

NTSTATUS
DpNetFilterQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_NETWORK_RULE_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_NETWORK_RULE_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_NETWORK_RULE_QUERY_HEADER);
    ULONG ruleCount = 0;
    ULONG returnedRuleCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_NETWORK_RULE_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_NETWORK_RULE_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_NETWORK_RULE_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_NETWORK_RULE_QUERY_HEADER));
    header->Version = DP_NETWORK_RULE_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_NETWORK_RULE_QUERY_HEADER);

    cursor = (PUCHAR)OutputBuffer + sizeof(DP_NETWORK_RULE_QUERY_HEADER);

    KeAcquireSpinLock(&gDpNetworkRuleLock, &oldIrql);

    for (link = gDpNetworkRules.Flink; link != &gDpNetworkRules; link = link->Flink) {
        PDP_NETWORK_RULE_ENTRY rule = CONTAINING_RECORD(link, DP_NETWORK_RULE_ENTRY, Link);
        ULONG entryBytes = DP_NETWORK_RULE_QUERY_ENTRY_HEADER_SIZE + rule->Domain.Length;

        if (bytesRequired > MAXULONG - entryBytes) {
            KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);
            return STATUS_INTEGER_OVERFLOW;
        }

        bytesRequired += entryBytes;
        ruleCount++;

        if (bytesReturned <= OutputBufferLength &&
            entryBytes <= OutputBufferLength - bytesReturned) {
            PDP_NETWORK_RULE_QUERY_ENTRY outputEntry;

            outputEntry = (PDP_NETWORK_RULE_QUERY_ENTRY)cursor;
            RtlZeroMemory(outputEntry, entryBytes);
            outputEntry->RuleId = rule->RuleId;
            outputEntry->Kind = rule->Kind;
            outputEntry->Action = rule->Action;
            outputEntry->Protocol = rule->Protocol;
            outputEntry->Direction = rule->Direction;
            outputEntry->LocalAddress = rule->LocalAddress;
            outputEntry->LocalAddressMask = rule->LocalAddressMask;
            outputEntry->RemoteAddress = rule->RemoteAddress;
            outputEntry->RemoteAddressMask = rule->RemoteAddressMask;
            outputEntry->LocalPort = rule->LocalPort;
            outputEntry->RemotePort = rule->RemotePort;
            outputEntry->DomainLengthBytes = rule->Domain.Length;
            if (rule->Domain.Length != 0) {
                RtlCopyMemory(outputEntry->Domain,
                              rule->Domain.Buffer,
                              rule->Domain.Length);
            }

            cursor += entryBytes;
            bytesReturned += entryBytes;
            returnedRuleCount++;
        }
    }

    KeReleaseSpinLock(&gDpNetworkRuleLock, oldIrql);

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
