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
#include <ntstrsafe.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

#define DP_UDP_HEADER_SIZE 8
#define DP_SMTP_CAPTURE_BYTES 4096
#define DP_SMTP_MAX_LINE_BYTES 1024

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

DEFINE_GUID(
    DP_WFP_INBOUND_TRANSPORT_V4_CALLOUT_GUID,
    0x7f115b67, 0x2a1f, 0x4dd0, 0x8b, 0x9c, 0x39, 0x48, 0xc6, 0x6c, 0x95, 0x90);

DEFINE_GUID(
    DP_WFP_SMTP_STREAM_V4_CALLOUT_GUID,
    0x28778b42, 0x1d77, 0x49e5, 0xb5, 0xa7, 0x48, 0x6c, 0x4c, 0xfa, 0x95, 0x32);

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

typedef struct _DP_SMTP_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_SMTP_EVENT_QUERY_ENTRY Event;
} DP_SMTP_EVENT_ENTRY, *PDP_SMTP_EVENT_ENTRY;

typedef struct _DP_NETWORK_CONNECTION_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY Event;
} DP_NETWORK_CONNECTION_EVENT_ENTRY, *PDP_NETWORK_CONNECTION_EVENT_ENTRY;

typedef struct _DP_SMTP_FLOW_CONTEXT {
    ULONG LocalAddress;
    ULONG RemoteAddress;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONGLONG ProcessId;
    BOOLEAN HasFrom;
    WCHAR From[DP_SMTP_MAX_ADDRESS_CHARS];
    CHAR PendingLine[DP_SMTP_MAX_LINE_BYTES];
    ULONG PendingLength;
} DP_SMTP_FLOW_CONTEXT, *PDP_SMTP_FLOW_CONTEXT;

static LIST_ENTRY gDpNetworkRules;
static LIST_ENTRY gDpNetworkConnectionEvents;
static LIST_ENTRY gDpSmtpEvents;
static KSPIN_LOCK gDpNetworkRuleLock;
static KSPIN_LOCK gDpNetworkConnectionEventLock;
static KSPIN_LOCK gDpSmtpEventLock;
static PDEVICE_OBJECT gDpNetDeviceObject = NULL;
static HANDLE gDpWfpEngineHandle = NULL;
static UINT32 gDpAleConnectV4CalloutId = 0;
static UINT32 gDpAleRecvAcceptV4CalloutId = 0;
static UINT32 gDpDnsDatagramV4CalloutId = 0;
static UINT32 gDpInboundTransportV4CalloutId = 0;
static UINT32 gDpSmtpStreamV4CalloutId = 0;
static BOOLEAN gDpNetFilterInitialized = FALSE;
static BOOLEAN gDpNetworkRuleLockInitialized = FALSE;
static BOOLEAN gDpNetworkConnectionEventLockInitialized = FALSE;
static BOOLEAN gDpSmtpEventLockInitialized = FALSE;
static ULONG gDpNetworkConnectionEventCount = 0;
static ULONGLONG gDpNetworkConnectionEventSequence = 0;
static ULONGLONG gDpNetworkConnectionDroppedEvents = 0;
static ULONG gDpSmtpEventCount = 0;
static ULONGLONG gDpSmtpEventSequence = 0;
static ULONGLONG gDpSmtpDroppedEvents = 0;

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
VOID
DpNetFilterFreeSmtpEvent(
    _In_ PDP_SMTP_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_SMTP_EVENT);
    }
}

static
VOID
DpNetFilterFreeConnectionEvent(
    _In_ PDP_NETWORK_CONNECTION_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_NET_EVENT);
    }
}

static
VOID
DpNetFilterClearConnectionEvents(
    VOID
    )
{
    LIST_ENTRY localList;
    KIRQL oldIrql;

    if (!gDpNetworkConnectionEventLockInitialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&gDpNetworkConnectionEventLock, &oldIrql);

    while (!IsListEmpty(&gDpNetworkConnectionEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpNetworkConnectionEvents);
        InsertTailList(&localList, link);
    }

    gDpNetworkConnectionEventCount = 0;

    KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY link = RemoveHeadList(&localList);
        PDP_NETWORK_CONNECTION_EVENT_ENTRY event =
            CONTAINING_RECORD(link, DP_NETWORK_CONNECTION_EVENT_ENTRY, Link);
        DpNetFilterFreeConnectionEvent(event);
    }
}

static
VOID
DpNetFilterClearSmtpEvents(
    VOID
    )
{
    LIST_ENTRY localList;
    KIRQL oldIrql;

    if (!gDpSmtpEventLockInitialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&gDpSmtpEventLock, &oldIrql);

    while (!IsListEmpty(&gDpSmtpEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gDpSmtpEvents);
        InsertTailList(&localList, link);
    }

    gDpSmtpEventCount = 0;

    KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY link = RemoveHeadList(&localList);
        PDP_SMTP_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_SMTP_EVENT_ENTRY, Link);
        DpNetFilterFreeSmtpEvent(event);
    }
}

static
CHAR
DpNetFilterLowerAscii(
    _In_ CHAR Character
    )
{
    if (Character >= 'A' && Character <= 'Z') {
        return (CHAR)(Character + ('a' - 'A'));
    }

    return Character;
}

static
BOOLEAN
DpNetFilterAsciiStartsWithInsensitive(
    _In_reads_bytes_(Length) const CHAR *Buffer,
    _In_ SIZE_T Length,
    _In_z_ const CHAR *Prefix
    )
{
    SIZE_T index;

    if (Buffer == NULL || Prefix == NULL) {
        return FALSE;
    }

    for (index = 0; Prefix[index] != '\0'; index++) {
        if (index >= Length ||
            DpNetFilterLowerAscii(Buffer[index]) != DpNetFilterLowerAscii(Prefix[index])) {

            return FALSE;
        }
    }

    return TRUE;
}

static
SIZE_T
DpNetFilterAsciiStringLength(
    _In_z_ const CHAR *Value
    )
{
    SIZE_T length = 0;

    if (Value == NULL) {
        return 0;
    }

    while (Value[length] != '\0') {
        length++;
    }

    return length;
}

static
VOID
DpNetFilterCopyAsciiAddressToWide(
    _In_reads_bytes_(Length) const CHAR *Source,
    _In_ SIZE_T Length,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars
    )
{
    SIZE_T index;
    SIZE_T start = 0;
    SIZE_T end = Length;
    SIZE_T outputIndex = 0;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Source == NULL || Length == 0) {
        return;
    }

    while (start < end &&
           (Source[start] == ' ' || Source[start] == '\t' ||
            Source[start] == '<' || Source[start] == '"')) {

        start++;
    }

    while (end > start &&
           (Source[end - 1] == ' ' || Source[end - 1] == '\t' ||
            Source[end - 1] == '\r' || Source[end - 1] == '\n' ||
            Source[end - 1] == '>' || Source[end - 1] == '"')) {

        end--;
    }

    for (index = start; index < end && outputIndex < DestinationChars - 1; index++) {
        UCHAR character = (UCHAR)Source[index];

        if (character < 0x20 || character > 0x7E) {
            break;
        }

        Destination[outputIndex++] = (WCHAR)character;
    }

    Destination[outputIndex] = L'\0';
}

static
BOOLEAN
DpNetFilterExtractSmtpAddress(
    _In_reads_bytes_(LineLength) const CHAR *Line,
    _In_ SIZE_T LineLength,
    _In_z_ const CHAR *CommandPrefix,
    _Out_writes_(AddressChars) PWCHAR Address,
    _In_ SIZE_T AddressChars
    )
{
    SIZE_T prefixLength;
    SIZE_T index;
    SIZE_T valueStart;
    SIZE_T valueEnd;

    if (Address == NULL || AddressChars == 0) {
        return FALSE;
    }

    Address[0] = L'\0';

    if (!DpNetFilterAsciiStartsWithInsensitive(Line, LineLength, CommandPrefix)) {
        return FALSE;
    }

    prefixLength = DpNetFilterAsciiStringLength(CommandPrefix);
    index = prefixLength;

    if (index < LineLength &&
        Line[index] != ':' &&
        Line[index] != ' ' &&
        Line[index] != '\t') {

        return FALSE;
    }

    while (index < LineLength && (Line[index] == ' ' || Line[index] == '\t')) {
        index++;
    }

    if (index < LineLength && Line[index] == ':') {
        index++;
    }

    while (index < LineLength && (Line[index] == ' ' || Line[index] == '\t')) {
        index++;
    }

    valueStart = index;
    valueEnd = LineLength;

    while (valueEnd > valueStart &&
           (Line[valueEnd - 1] == '\r' || Line[valueEnd - 1] == '\n' ||
            Line[valueEnd - 1] == ' ' || Line[valueEnd - 1] == '\t')) {

        valueEnd--;
    }

    if (valueEnd <= valueStart) {
        return FALSE;
    }

    for (index = valueStart; index < valueEnd; index++) {
        if (Line[index] == '>') {
            valueEnd = index + 1;
            break;
        }
    }

    DpNetFilterCopyAsciiAddressToWide(Line + valueStart,
                                      valueEnd - valueStart,
                                      Address,
                                      AddressChars);

    return Address[0] != L'\0';
}

static
ULONG
DpNetFilterWideStringLengthBytes(
    _In_reads_(MaxChars) const WCHAR *Value,
    _In_ SIZE_T MaxChars
    )
{
    SIZE_T chars = 0;

    if (Value == NULL) {
        return 0;
    }

    while (chars < MaxChars && Value[chars] != L'\0') {
        chars++;
    }

    return (ULONG)(chars * sizeof(WCHAR));
}

static
VOID
DpNetFilterCopyProcessPath(
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0 *InMetaValues,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _Out_ PULONG LengthBytes
    )
{
    SIZE_T copyBytes;

    if (LengthBytes != NULL) {
        *LengthBytes = 0;
    }

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (InMetaValues == NULL ||
        !FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH) ||
        InMetaValues->processPath == NULL ||
        InMetaValues->processPath->data == NULL ||
        InMetaValues->processPath->size == 0) {

        return;
    }

    copyBytes = InMetaValues->processPath->size;
    if (copyBytes > (DestinationChars - 1) * sizeof(WCHAR)) {
        copyBytes = (DestinationChars - 1) * sizeof(WCHAR);
    }

    copyBytes -= copyBytes % sizeof(WCHAR);
    if (copyBytes == 0) {
        return;
    }

    RtlCopyMemory(Destination, InMetaValues->processPath->data, copyBytes);
    Destination[copyBytes / sizeof(WCHAR)] = L'\0';

    if (LengthBytes != NULL) {
        *LengthBytes = DpNetFilterWideStringLengthBytes(Destination, DestinationChars);
    }
}

static
VOID
DpNetFilterCopyDomain(
    _In_opt_z_ PCWSTR Domain,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _Out_ PULONG LengthBytes
    )
{
    SIZE_T index = 0;

    if (LengthBytes != NULL) {
        *LengthBytes = 0;
    }

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = L'\0';

    if (Domain == NULL || Domain[0] == L'\0') {
        return;
    }

    while (index < DestinationChars - 1 && Domain[index] != L'\0') {
        Destination[index] = Domain[index];
        index++;
    }

    Destination[index] = L'\0';

    if (LengthBytes != NULL) {
        *LengthBytes = (ULONG)(index * sizeof(WCHAR));
    }
}

static
WCHAR
DpNetFilterLowerWide(
    _In_ WCHAR Character
    );

static
BOOLEAN
DpNetFilterPathEndsWithInsensitive(
    _In_reads_(ValueChars) PCWSTR Value,
    _In_ SIZE_T ValueChars,
    _In_z_ PCWSTR Suffix
    )
{
    SIZE_T suffixChars = 0;
    SIZE_T index;

    if (Value == NULL || Suffix == NULL) {
        return FALSE;
    }

    while (Suffix[suffixChars] != L'\0') {
        suffixChars++;
    }

    if (suffixChars == 0 || suffixChars > ValueChars) {
        return FALSE;
    }

    for (index = 0; index < suffixChars; index++) {
        WCHAR left = Value[ValueChars - suffixChars + index];
        WCHAR right = Suffix[index];

        if (DpNetFilterLowerWide(left) != DpNetFilterLowerWide(right)) {
            return FALSE;
        }
    }

    return TRUE;
}

static
BOOLEAN
DpNetFilterProcessPathIsIgnored(
    _In_reads_(PathChars) PCWSTR Path,
    _In_ SIZE_T PathChars
    )
{
    static PCWSTR ignoredNames[] = {
        L"\\chrome.exe", L"\\msedge.exe", L"\\firefox.exe", L"\\iexplore.exe",
        L"\\msedgewebview2.exe", L"\\chromium.exe", L"\\opera.exe", L"\\opera_gx.exe",
        L"\\brave.exe", L"\\vivaldi.exe", L"\\safari.exe", L"\\ucbrowser.exe",
        L"\\browser.exe", L"\\qqbrowser.exe", L"\\sogouexplorer.exe",
        L"\\360se.exe", L"\\360chrome.exe", L"\\liebao.exe", L"\\maxthon.exe",
        L"\\2345explorer.exe", L"\\baidubrowser.exe", L"\\theworld.exe",
        L"\\wechat.exe", L"\\weixin.exe", L"\\wechatappex.exe", L"\\wxwork.exe",
        L"\\enterprisewechat.exe", L"\\wecom.exe", L"\\qq.exe", L"\\tim.exe",
        L"\\dingtalk.exe", L"\\feishu.exe", L"\\lark.exe", L"\\teams.exe",
        L"\\slack.exe", L"\\telegram.exe", L"\\discord.exe", L"\\skype.exe",
        L"\\zoom.exe", L"\\tencentmeeting.exe", L"\\wemeetapp.exe",
        L"\\outlook.exe", L"\\thunderbird.exe", L"\\foxmail.exe",
        L"\\whatsapp.exe", L"\\signal.exe", L"\\line.exe", L"\\viber.exe",
        L"\\mattermost.exe"
    };
    ULONG index;

    if (Path == NULL || PathChars == 0) {
        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(ignoredNames); index++) {
        if (DpNetFilterPathEndsWithInsensitive(Path, PathChars, ignoredNames[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static
ULONG
DpNetFilterDetectProtocolFlags(
    _In_opt_z_ PCWSTR Domain,
    _In_ ULONG BaseFlags
    )
{
    ULONG flags = BaseFlags;

    if (Domain != NULL) {
        SIZE_T index = 0;
        while (Domain[index] != L'\0') {
            if ((Domain[index] == L'h' || Domain[index] == L'H') &&
                (Domain[index + 1] == L'3') &&
                (Domain[index + 2] == L'\0' || Domain[index + 2] == L'.' || Domain[index + 2] == L'-')) {

                flags |= DP_NETWORK_EVENT_FLAG_QUIC | DP_NETWORK_EVENT_FLAG_HTTP3;
                break;
            }

            index++;
        }
    }

    return flags;
}

static
VOID
DpNetFilterQueueConnectionEvent(
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0 *InMetaValues,
    _In_ DP_NETWORK_DIRECTION Direction,
    _In_ UCHAR Protocol,
    _In_ ULONG LocalAddress,
    _In_ USHORT LocalPort,
    _In_ ULONG RemoteAddress,
    _In_ USHORT RemotePort,
    _In_opt_z_ PCWSTR Domain,
    _In_ ULONG Flags
    )
{
    PDP_NETWORK_CONNECTION_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONGLONG processId = 0;

    if (!gDpNetworkConnectionEventLockInitialized) {
        return;
    }

    if (InMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {

        processId = InMetaValues->processId;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_NETWORK_CONNECTION_EVENT_ENTRY),
                                  DP_TAG_NET_EVENT);
    if (entry == NULL) {
        KeAcquireSpinLock(&gDpNetworkConnectionEventLock, &oldIrql);
        gDpNetworkConnectionDroppedEvents++;
        KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_NETWORK_CONNECTION_EVENT_ENTRY));
    InitializeListHead(&entry->Link);

    entry->Event.ProcessId = processId;
    entry->Event.Direction = Direction;
    entry->Event.Protocol = Protocol;
    entry->Event.LocalAddress = LocalAddress;
    entry->Event.RemoteAddress = RemoteAddress;
    entry->Event.LocalPort = LocalPort;
    entry->Event.RemotePort = RemotePort;
    entry->Event.Flags = DpNetFilterDetectProtocolFlags(Domain, Flags);

    DpNetFilterCopyProcessPath(InMetaValues,
                               entry->Event.ProcessPath,
                               RTL_NUMBER_OF(entry->Event.ProcessPath),
                               &entry->Event.ProcessPathLengthBytes);

    if (DpNetFilterProcessPathIsIgnored(entry->Event.ProcessPath,
                                        entry->Event.ProcessPathLengthBytes / sizeof(WCHAR))) {

        ExFreePoolWithTag(entry, DP_TAG_NET_EVENT);
        return;
    }

    DpNetFilterCopyDomain(Domain,
                          entry->Event.Domain,
                          RTL_NUMBER_OF(entry->Event.Domain),
                          &entry->Event.DomainLengthBytes);

    KeAcquireSpinLock(&gDpNetworkConnectionEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpNetworkConnectionEventSequence;
    InsertTailList(&gDpNetworkConnectionEvents, &entry->Link);
    gDpNetworkConnectionEventCount++;

    if (gDpNetworkConnectionEventCount > DP_NETWORK_MAX_CONNECTION_EVENTS) {
        LIST_ENTRY trimList;

        InitializeListHead(&trimList);

        while (gDpNetworkConnectionEventCount > DP_NETWORK_MAX_CONNECTION_EVENTS &&
               !IsListEmpty(&gDpNetworkConnectionEvents)) {

            PLIST_ENTRY oldLink = RemoveHeadList(&gDpNetworkConnectionEvents);
            InsertTailList(&trimList, oldLink);
            gDpNetworkConnectionEventCount--;
            gDpNetworkConnectionDroppedEvents++;
        }

        KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);

        while (!IsListEmpty(&trimList)) {
            PLIST_ENTRY oldLink = RemoveHeadList(&trimList);
            PDP_NETWORK_CONNECTION_EVENT_ENTRY oldEvent =
                CONTAINING_RECORD(oldLink, DP_NETWORK_CONNECTION_EVENT_ENTRY, Link);
            DpNetFilterFreeConnectionEvent(oldEvent);
        }

        return;
    }

    KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);
}

static
VOID
DpNetFilterQueueSmtpEvent(
    _In_ PDP_SMTP_FLOW_CONTEXT FlowContext,
    _In_reads_(DP_SMTP_MAX_ADDRESS_CHARS) const WCHAR *Recipient
    )
{
    PDP_SMTP_EVENT_ENTRY entry;
    KIRQL oldIrql;

    if (FlowContext == NULL || !FlowContext->HasFrom ||
        Recipient == NULL || Recipient[0] == L'\0') {

        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_SMTP_EVENT_ENTRY),
                                  DP_TAG_SMTP_EVENT);
    if (entry == NULL) {
        if (gDpSmtpEventLockInitialized) {
            KeAcquireSpinLock(&gDpSmtpEventLock, &oldIrql);
            gDpSmtpDroppedEvents++;
            KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);
        }
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_SMTP_EVENT_ENTRY));
    InitializeListHead(&entry->Link);
    entry->Event.ProcessId = FlowContext->ProcessId;
    entry->Event.LocalAddress = FlowContext->LocalAddress;
    entry->Event.RemoteAddress = FlowContext->RemoteAddress;
    entry->Event.LocalPort = FlowContext->LocalPort;
    entry->Event.RemotePort = FlowContext->RemotePort;
    RtlStringCchCopyW(entry->Event.From,
                      RTL_NUMBER_OF(entry->Event.From),
                      FlowContext->From);
    RtlStringCchCopyW(entry->Event.To,
                      RTL_NUMBER_OF(entry->Event.To),
                      Recipient);
    entry->Event.FromLengthBytes =
        DpNetFilterWideStringLengthBytes(entry->Event.From, RTL_NUMBER_OF(entry->Event.From));
    entry->Event.ToLengthBytes =
        DpNetFilterWideStringLengthBytes(entry->Event.To, RTL_NUMBER_OF(entry->Event.To));

    KeAcquireSpinLock(&gDpSmtpEventLock, &oldIrql);

    entry->Event.Sequence = ++gDpSmtpEventSequence;
    InsertTailList(&gDpSmtpEvents, &entry->Link);
    gDpSmtpEventCount++;

    if (gDpSmtpEventCount > DP_POLICY_MAX_SMTP_EVENTS) {
        LIST_ENTRY trimList;

        InitializeListHead(&trimList);

        while (gDpSmtpEventCount > DP_POLICY_MAX_SMTP_EVENTS && !IsListEmpty(&gDpSmtpEvents)) {
            PLIST_ENTRY oldLink = RemoveHeadList(&gDpSmtpEvents);
            InsertTailList(&trimList, oldLink);
            gDpSmtpEventCount--;
            gDpSmtpDroppedEvents++;
        }

        KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);

        while (!IsListEmpty(&trimList)) {
            PLIST_ENTRY oldLink = RemoveHeadList(&trimList);
            PDP_SMTP_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink, DP_SMTP_EVENT_ENTRY, Link);
            DpNetFilterFreeSmtpEvent(oldEvent);
        }

        return;
    }

    KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);
}

static
VOID
DpNetFilterInspectSmtpLine(
    _Inout_ PDP_SMTP_FLOW_CONTEXT FlowContext,
    _In_reads_bytes_(LineLength) const CHAR *Line,
    _In_ SIZE_T LineLength
    )
{
    WCHAR address[DP_SMTP_MAX_ADDRESS_CHARS];

    if (FlowContext == NULL || Line == NULL || LineLength == 0) {
        return;
    }

    RtlZeroMemory(address, sizeof(address));

    if (DpNetFilterExtractSmtpAddress(Line,
                                      LineLength,
                                      "MAIL FROM",
                                      address,
                                      RTL_NUMBER_OF(address))) {

        RtlStringCchCopyW(FlowContext->From,
                          RTL_NUMBER_OF(FlowContext->From),
                          address);
        FlowContext->HasFrom = TRUE;
        return;
    }

    if (DpNetFilterExtractSmtpAddress(Line,
                                      LineLength,
                                      "RCPT TO",
                                      address,
                                      RTL_NUMBER_OF(address))) {

        DpNetFilterQueueSmtpEvent(FlowContext, address);
    }
}

static
VOID
DpNetFilterInspectSmtpBuffer(
    _Inout_ PDP_SMTP_FLOW_CONTEXT FlowContext,
    _In_reads_bytes_(Length) const CHAR *Buffer,
    _In_ SIZE_T Length
    )
{
    SIZE_T offset = 0;

    if (FlowContext == NULL || Buffer == NULL || Length == 0) {
        return;
    }

    while (offset < Length) {
        SIZE_T lineStart = offset;
        SIZE_T lineEnd = offset;

        while (lineEnd < Length && Buffer[lineEnd] != '\n') {
            lineEnd++;
        }

        if (FlowContext->PendingLength != 0) {
            SIZE_T lineBytes = lineEnd - lineStart;
            SIZE_T copyBytes = lineBytes;

            if (copyBytes > RTL_NUMBER_OF(FlowContext->PendingLine) - FlowContext->PendingLength) {
                copyBytes = RTL_NUMBER_OF(FlowContext->PendingLine) - FlowContext->PendingLength;
            }

            if (copyBytes != 0) {
                RtlCopyMemory(FlowContext->PendingLine + FlowContext->PendingLength,
                              Buffer + lineStart,
                              copyBytes);
                FlowContext->PendingLength += (ULONG)copyBytes;
            }

            if (lineEnd < Length) {
                DpNetFilterInspectSmtpLine(FlowContext,
                                           FlowContext->PendingLine,
                                           FlowContext->PendingLength);
                FlowContext->PendingLength = 0;
                RtlZeroMemory(FlowContext->PendingLine, sizeof(FlowContext->PendingLine));
            } else if (FlowContext->PendingLength >= RTL_NUMBER_OF(FlowContext->PendingLine)) {
                FlowContext->PendingLength = 0;
                RtlZeroMemory(FlowContext->PendingLine, sizeof(FlowContext->PendingLine));
            }
        } else if (lineEnd < Length) {
            DpNetFilterInspectSmtpLine(FlowContext,
                                       Buffer + lineStart,
                                       lineEnd - lineStart);
        } else {
            SIZE_T lineBytes = lineEnd - lineStart;

            if (lineBytes >= RTL_NUMBER_OF(FlowContext->PendingLine)) {
                FlowContext->PendingLength = 0;
                RtlZeroMemory(FlowContext->PendingLine, sizeof(FlowContext->PendingLine));
            } else if (lineBytes != 0) {
                RtlCopyMemory(FlowContext->PendingLine,
                              Buffer + lineStart,
                              lineBytes);
                FlowContext->PendingLength = (ULONG)lineBytes;
            }
        }

        offset = lineEnd < Length ? lineEnd + 1 : Length;
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
DpNetFilterDomainPatternMatches(
    _In_reads_(PatternLength) PCWSTR Pattern,
    _In_ SIZE_T PatternLength,
    _In_ PCWSTR Domain,
    _In_ SIZE_T DomainLength
    )
{
    SIZE_T patternIndex = 0;
    SIZE_T domainIndex = 0;
    SIZE_T starIndex = (SIZE_T)-1;
    SIZE_T retryDomainIndex = 0;

    while (domainIndex < DomainLength) {
        if (patternIndex < PatternLength && Pattern[patternIndex] == L'*') {
            starIndex = patternIndex++;
            retryDomainIndex = domainIndex;
            continue;
        }

        if (patternIndex < PatternLength &&
            (Pattern[patternIndex] == L'?' ||
             DpNetFilterLowerWide(Pattern[patternIndex]) ==
                DpNetFilterLowerWide(Domain[domainIndex]))) {

            patternIndex++;
            domainIndex++;
            continue;
        }

        if (starIndex != (SIZE_T)-1) {
            patternIndex = starIndex + 1;
            retryDomainIndex++;
            domainIndex = retryDomainIndex;
            continue;
        }

        return FALSE;
    }

    while (patternIndex < PatternLength && Pattern[patternIndex] == L'*') {
        patternIndex++;
    }

    return patternIndex == PatternLength;
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

    return DpNetFilterDomainPatternMatches(RuleDomain->Buffer,
                                           ruleLength,
                                           Domain,
                                           domainLength);
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
        if (Protocol == DpNetworkProtocolIcmp) {
            return FALSE;
        }

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

    if (protocol != IPPROTO_TCP &&
        protocol != IPPROTO_UDP &&
        protocol != IPPROTO_ICMP) {

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

    if (protocol != IPPROTO_UDP ||
        direction == DpNetworkDirectionInbound ||
        action == DpNetworkActionBlock) {

        DpNetFilterQueueConnectionEvent(InMetaValues,
                                        direction,
                                        protocol,
                                        localAddress,
                                        localPort,
                                        remoteAddress,
                                        remotePort,
                                        NULL,
                                        action == DpNetworkActionBlock ? DP_NETWORK_EVENT_FLAG_BLOCKED : 0);
    }

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static
BOOLEAN
DpNetFilterLooksLikeQuicDatagram(
    _In_opt_ const VOID *LayerData,
    _In_ ULONG TransportHeaderSize,
    _In_ USHORT RemotePort
    )
{
    PNET_BUFFER_LIST netBufferList;
    PNET_BUFFER netBuffer;
    ULONG dataLength;
    PUCHAR copyBuffer = NULL;
    PVOID dataBuffer;
    PUCHAR payload;
    UCHAR firstByte;
    ULONG version;
    BOOLEAN result = FALSE;

    if (RemotePort != 443 ||
        LayerData == NULL ||
        TransportHeaderSize == 0) {

        return FALSE;
    }

    netBufferList = (PNET_BUFFER_LIST)LayerData;
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    if (netBuffer == NULL) {
        return FALSE;
    }

    dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    if (dataLength <= TransportHeaderSize) {
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

    payload = (PUCHAR)dataBuffer + TransportHeaderSize;
    firstByte = payload[0];

    if ((firstByte & 0x80) != 0) {
        if (dataLength >= TransportHeaderSize + 7 &&
            (firstByte & 0x40) != 0) {

            version = ((ULONG)payload[1] << 24) |
                      ((ULONG)payload[2] << 16) |
                      ((ULONG)payload[3] << 8) |
                      (ULONG)payload[4];
            result = version != 0;
        }
    } else {
        result = (firstByte & 0x40) != 0;
    }

    ExFreePoolWithTag(copyBuffer, DP_TAG_NET_BUFFER);
    return result;
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
    ULONG transportHeaderSize = DP_UDP_HEADER_SIZE;
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
        DpNetFilterQueueConnectionEvent(InMetaValues,
                                        DpNetworkDirectionOutbound,
                                        protocol,
                                        localAddress,
                                        localPort,
                                        remoteAddress,
                                        remotePort,
                                        NULL,
                                        DP_NETWORK_EVENT_FLAG_BLOCKED);
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    if (remotePort != 53) {
        ULONG eventFlags = DpNetFilterLooksLikeQuicDatagram(LayerData,
                                                            transportHeaderSize,
                                                            remotePort)
            ? DP_NETWORK_EVENT_FLAG_QUIC
            : 0;

        DpNetFilterQueueConnectionEvent(InMetaValues,
                                        DpNetworkDirectionOutbound,
                                        protocol,
                                        localAddress,
                                        localPort,
                                        remoteAddress,
                                        remotePort,
                                        NULL,
                                        eventFlags);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (InMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE) &&
        InMetaValues->transportHeaderSize != 0) {

        transportHeaderSize = InMetaValues->transportHeaderSize;
    }

    if (!DpNetFilterParseDnsQuery(LayerData,
                                  transportHeaderSize,
                                  domain,
                                  RTL_NUMBER_OF(domain))) {

        DpNetFilterQueueConnectionEvent(InMetaValues,
                                        DpNetworkDirectionOutbound,
                                        protocol,
                                        localAddress,
                                        localPort,
                                        remoteAddress,
                                        remotePort,
                                        NULL,
                                        remotePort == 53 ? DP_NETWORK_EVENT_FLAG_DNS : 0);
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

    DpNetFilterQueueConnectionEvent(InMetaValues,
                                    DpNetworkDirectionOutbound,
                                    protocol,
                                    localAddress,
                                    localPort,
                                    remoteAddress,
                                    remotePort,
                                    domain,
                                    DP_NETWORK_EVENT_FLAG_DNS |
                                        (action == DpNetworkActionBlock ? DP_NETWORK_EVENT_FLAG_BLOCKED : 0));

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static
VOID
NTAPI
DpNetFilterInboundTransportClassify(
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
    DP_NETWORK_ACTION action;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (InFixedValues == NULL ||
        ClassifyOut == NULL ||
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {

        return;
    }

    if (!gDpNetFilterInitialized ||
        InFixedValues->layerId != FWPS_LAYER_INBOUND_TRANSPORT_V4) {

        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    protocol = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
    if (protocol != IPPROTO_ICMP) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    localAddress = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
    remoteAddress = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
    localPort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
    remotePort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

    action = DpNetFilterFindAction(DpNetworkDirectionInbound,
                                   DpNetworkProtocolIcmp,
                                   localAddress,
                                   localPort,
                                   remoteAddress,
                                   remotePort,
                                   NULL);

    DpNetFilterQueueConnectionEvent(InMetaValues,
                                    DpNetworkDirectionInbound,
                                    protocol,
                                    localAddress,
                                    localPort,
                                    remoteAddress,
                                    remotePort,
                                    NULL,
                                    action == DpNetworkActionBlock ? DP_NETWORK_EVENT_FLAG_BLOCKED : 0);

    if (action == DpNetworkActionBlock) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static
VOID
NTAPI
DpNetFilterSmtpClassify(
    _In_ const FWPS_INCOMING_VALUES0 *InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *InMetaValues,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER1 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *ClassifyOut
    )
{
    FWPS_STREAM_CALLOUT_IO_PACKET0 *ioPacket;
    FWPS_STREAM_DATA0 *streamData;
    PDP_SMTP_FLOW_CONTEXT flowContext = (PDP_SMTP_FLOW_CONTEXT)(ULONG_PTR)FlowContext;
    PCHAR captureBuffer = NULL;
    SIZE_T bytesToCopy;
    SIZE_T bytesCopied = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    if (ClassifyOut != NULL && (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }

    ioPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0 *)LayerData;
    if (InFixedValues == NULL ||
        InMetaValues == NULL ||
        ioPacket == NULL ||
        ioPacket->streamData == NULL) {

        return;
    }

    ioPacket->streamAction = FWPS_STREAM_ACTION_NONE;
    ioPacket->countBytesRequired = 0;
    ioPacket->countBytesEnforced = 0;

    streamData = ioPacket->streamData;
    if ((streamData->flags & FWPS_STREAM_FLAG_SEND) == 0 ||
        streamData->dataLength == 0) {

        return;
    }

    if (flowContext == NULL) {
        if (!FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE) ||
            InMetaValues->flowHandle == 0 ||
            gDpSmtpStreamV4CalloutId == 0) {

            return;
        }

        flowContext = ExAllocatePoolWithTag(NonPagedPoolNx,
                                            sizeof(DP_SMTP_FLOW_CONTEXT),
                                            DP_TAG_SMTP_FLOW);
        if (flowContext == NULL) {
            return;
        }

        RtlZeroMemory(flowContext, sizeof(DP_SMTP_FLOW_CONTEXT));
        flowContext->LocalAddress = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;
        flowContext->RemoteAddress = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
        flowContext->LocalPort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;
        flowContext->RemotePort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;

        if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            flowContext->ProcessId = InMetaValues->processId;
        }

        status = FwpsFlowAssociateContext0(InMetaValues->flowHandle,
                                           FWPS_LAYER_STREAM_V4,
                                           gDpSmtpStreamV4CalloutId,
                                           (UINT64)(ULONG_PTR)flowContext);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(flowContext, DP_TAG_SMTP_FLOW);
            return;
        }
    }

    bytesToCopy = streamData->dataLength;
    if (bytesToCopy > DP_SMTP_CAPTURE_BYTES) {
        bytesToCopy = DP_SMTP_CAPTURE_BYTES;
    }

    captureBuffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                          DP_SMTP_CAPTURE_BYTES,
                                          DP_TAG_NET_BUFFER);
    if (captureBuffer == NULL) {
        return;
    }

    RtlZeroMemory(captureBuffer, DP_SMTP_CAPTURE_BYTES);
    FwpsCopyStreamDataToBuffer0(streamData,
                                captureBuffer,
                                bytesToCopy,
                                &bytesCopied);

    if (bytesCopied != 0) {
        DpNetFilterInspectSmtpBuffer(flowContext, captureBuffer, bytesCopied);
    }

    ExFreePoolWithTag(captureBuffer, DP_TAG_NET_BUFFER);
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

    if (CalloutId == gDpSmtpStreamV4CalloutId && FlowContext != 0) {
        PDP_SMTP_FLOW_CONTEXT flowContext = (PDP_SMTP_FLOW_CONTEXT)(ULONG_PTR)FlowContext;
        ExFreePoolWithTag(flowContext, DP_TAG_SMTP_FLOW);
    }
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

static
VOID
DpNetFilterInitializePortCondition(
    _Out_ FWPM_FILTER_CONDITION0 *Condition,
    _In_ USHORT Port
    )
{
    RtlZeroMemory(Condition, sizeof(FWPM_FILTER_CONDITION0));
    Condition->fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    Condition->matchType = FWP_MATCH_EQUAL;
    Condition->conditionValue.type = FWP_UINT16;
    Condition->conditionValue.uint16 = Port;
}

static
VOID
DpNetFilterInitializeIcmpTypeCondition(
    _Out_ FWPM_FILTER_CONDITION0 *Condition,
    _In_ UCHAR Type
    )
{
    RtlZeroMemory(Condition, sizeof(FWPM_FILTER_CONDITION0));
    Condition->fieldKey = FWPM_CONDITION_ICMP_TYPE;
    Condition->matchType = FWP_MATCH_EQUAL;
    Condition->conditionValue.type = FWP_UINT16;
    Condition->conditionValue.uint16 = Type;
}

static
NTSTATUS
DpNetFilterAddAleProtocolFilters(
    _In_ const GUID *LayerGuid,
    _In_ const GUID *CalloutGuid,
    _In_z_ PWSTR TcpName,
    _In_z_ PWSTR UdpName,
    _In_z_ PWSTR IcmpName
    )
{
    NTSTATUS status;
    FWPM_FILTER_CONDITION0 condition;

    DpNetFilterInitializeProtocolCondition(&condition, IPPROTO_TCP);
    status = DpNetFilterAddManagementFilter(LayerGuid,
                                            CalloutGuid,
                                            TcpName,
                                            &condition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        return status;
    }

    DpNetFilterInitializeProtocolCondition(&condition, IPPROTO_UDP);
    status = DpNetFilterAddManagementFilter(LayerGuid,
                                            CalloutGuid,
                                            UdpName,
                                            &condition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        return status;
    }

    DpNetFilterInitializeProtocolCondition(&condition, IPPROTO_ICMP);
    status = DpNetFilterAddManagementFilter(LayerGuid,
                                            CalloutGuid,
                                            IcmpName,
                                            &condition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpNetFilterInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 subLayer;
    FWPM_FILTER_CONDITION0 udpConditions[2];
    FWPM_FILTER_CONDITION0 smtpPortCondition;
    FWPM_FILTER_CONDITION0 inboundIcmpConditions[2];

    InitializeListHead(&gDpNetworkRules);
    InitializeListHead(&gDpNetworkConnectionEvents);
    InitializeListHead(&gDpSmtpEvents);
    KeInitializeSpinLock(&gDpNetworkRuleLock);
    KeInitializeSpinLock(&gDpNetworkConnectionEventLock);
    KeInitializeSpinLock(&gDpSmtpEventLock);
    gDpNetworkRuleLockInitialized = TRUE;
    gDpNetworkConnectionEventLockInitialized = TRUE;
    gDpSmtpEventLockInitialized = TRUE;
    gDpNetworkConnectionEventCount = 0;
    gDpNetworkConnectionEventSequence = 0;
    gDpNetworkConnectionDroppedEvents = 0;
    gDpSmtpEventCount = 0;
    gDpSmtpEventSequence = 0;
    gDpSmtpDroppedEvents = 0;

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

    status = DpNetFilterRegisterCallout(gDpNetDeviceObject,
                                        &DP_WFP_INBOUND_TRANSPORT_V4_CALLOUT_GUID,
                                        &FWPM_LAYER_INBOUND_TRANSPORT_V4,
                                        DpNetFilterInboundTransportClassify,
                                        L"DataProtector Inbound Transport V4",
                                        &gDpInboundTransportV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    status = DpNetFilterRegisterCallout(gDpNetDeviceObject,
                                        &DP_WFP_SMTP_STREAM_V4_CALLOUT_GUID,
                                        &FWPM_LAYER_STREAM_V4,
                                        DpNetFilterSmtpClassify,
                                        L"DataProtector SMTP Stream V4",
                                        &gDpSmtpStreamV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    status = DpNetFilterAddAleProtocolFilters(&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                              &DP_WFP_ALE_CONNECT_V4_CALLOUT_GUID,
                                              L"DataProtector outbound TCP defense",
                                              L"DataProtector outbound UDP connect defense",
                                              L"DataProtector outbound ICMP defense");
    if (!NT_SUCCESS(status)) {
        goto Abort;
    }

    status = DpNetFilterAddAleProtocolFilters(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                              &DP_WFP_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
                                              L"DataProtector inbound TCP defense",
                                              L"DataProtector inbound UDP defense",
                                              L"DataProtector inbound ICMP defense");
    if (!NT_SUCCESS(status)) {
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

    RtlZeroMemory(inboundIcmpConditions, sizeof(inboundIcmpConditions));
    DpNetFilterInitializeProtocolCondition(&inboundIcmpConditions[0], IPPROTO_ICMP);
    DpNetFilterInitializeIcmpTypeCondition(&inboundIcmpConditions[1], 8);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_INBOUND_TRANSPORT_V4,
                                            &DP_WFP_INBOUND_TRANSPORT_V4_CALLOUT_GUID,
                                            L"DataProtector inbound ICMP echo request defense",
                                            inboundIcmpConditions,
                                            RTL_NUMBER_OF(inboundIcmpConditions));
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializePortCondition(&smtpPortCondition, 25);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_STREAM_V4,
                                            &DP_WFP_SMTP_STREAM_V4_CALLOUT_GUID,
                                            L"DataProtector SMTP stream audit 25",
                                            &smtpPortCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializePortCondition(&smtpPortCondition, 465);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_STREAM_V4,
                                            &DP_WFP_SMTP_STREAM_V4_CALLOUT_GUID,
                                            L"DataProtector SMTP stream audit 465",
                                            &smtpPortCondition,
                                            1);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto Abort;
    }

    DpNetFilterInitializePortCondition(&smtpPortCondition, 587);
    status = DpNetFilterAddManagementFilter(&FWPM_LAYER_STREAM_V4,
                                            &DP_WFP_SMTP_STREAM_V4_CALLOUT_GUID,
                                            L"DataProtector SMTP stream audit 587",
                                            &smtpPortCondition,
                                            1);
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

    if (gDpSmtpStreamV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(gDpSmtpStreamV4CalloutId);
        gDpSmtpStreamV4CalloutId = 0;
    }

    if (gDpInboundTransportV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(gDpInboundTransportV4CalloutId);
        gDpInboundTransportV4CalloutId = 0;
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

    if (gDpNetworkConnectionEventLockInitialized) {
        DpNetFilterClearConnectionEvents();
        gDpNetworkConnectionEventLockInitialized = FALSE;
    }

    if (gDpSmtpEventLockInitialized) {
        DpNetFilterClearSmtpEvents();
        gDpSmtpEventLockInitialized = FALSE;
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
        (Rule->Protocol != DpNetworkProtocolAny &&
         Rule->Protocol != DpNetworkProtocolIcmp &&
         Rule->Protocol != DpNetworkProtocolTcp &&
         Rule->Protocol != DpNetworkProtocolUdp) ||
        (Rule->Direction != DpNetworkDirectionInbound &&
         Rule->Direction != DpNetworkDirectionOutbound &&
         Rule->Direction != DpNetworkDirectionBoth) ||
        (Rule->DomainLengthBytes > DP_POLICY_MAX_DOMAIN_BYTES) ||
        (Rule->DomainLengthBytes % sizeof(WCHAR)) != 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->Kind == DpNetworkRuleDomain && Rule->DomainLengthBytes == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->Kind == DpNetworkRuleDomain &&
        Rule->Protocol == DpNetworkProtocolIcmp) {

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

NTSTATUS
DpNetFilterQueryConnectionEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_NETWORK_CONNECTION_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)) {

        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_NETWORK_CONNECTION_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);

    if (!gDpNetworkConnectionEventLockInitialized) {
        header->Version = DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION;
        header->BytesRequired = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
        header->BytesReturned = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpNetworkConnectionEventLock, &oldIrql);

    header->Version = DP_NETWORK_CONNECTION_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_HEADER);
    header->DroppedEvents = gDpNetworkConnectionDroppedEvents;

    for (link = gDpNetworkConnectionEvents.Flink;
         link != &gDpNetworkConnectionEvents;
         link = link->Flink) {

        bytesRequired += sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_NETWORK_CONNECTION_EVENT_ENTRY event =
                CONTAINING_RECORD(link, DP_NETWORK_CONNECTION_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor,
                          &event->Event,
                          sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_NETWORK_CONNECTION_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        LIST_ENTRY localList;

        InitializeListHead(&localList);

        while (!IsListEmpty(&gDpNetworkConnectionEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpNetworkConnectionEvents);
            InsertTailList(&localList, eventLink);
            gDpNetworkConnectionEventCount--;
        }

        KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);

        while (!IsListEmpty(&localList)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&localList);
            PDP_NETWORK_CONNECTION_EVENT_ENTRY event =
                CONTAINING_RECORD(eventLink, DP_NETWORK_CONNECTION_EVENT_ENTRY, Link);
            DpNetFilterFreeConnectionEvent(event);
        }

        return STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&gDpNetworkConnectionEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpNetFilterQuerySmtpEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_SMTP_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_SMTP_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_SMTP_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_SMTP_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_SMTP_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_SMTP_EVENT_QUERY_HEADER);

    if (!gDpSmtpEventLockInitialized) {
        header->Version = DP_SMTP_EVENT_QUERY_VERSION;
        header->BytesRequired = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
        header->BytesReturned = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gDpSmtpEventLock, &oldIrql);

    header->Version = DP_SMTP_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_SMTP_EVENT_QUERY_HEADER);
    header->DroppedEvents = gDpSmtpDroppedEvents;

    for (link = gDpSmtpEvents.Flink; link != &gDpSmtpEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_SMTP_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_SMTP_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_SMTP_EVENT_ENTRY event = CONTAINING_RECORD(link, DP_SMTP_EVENT_ENTRY, Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_SMTP_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_SMTP_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_SMTP_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gDpSmtpEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gDpSmtpEvents);
            PDP_SMTP_EVENT_ENTRY event = CONTAINING_RECORD(eventLink, DP_SMTP_EVENT_ENTRY, Link);
            gDpSmtpEventCount--;
            KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);
            DpNetFilterFreeSmtpEvent(event);
            KeAcquireSpinLock(&gDpSmtpEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gDpSmtpEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}
