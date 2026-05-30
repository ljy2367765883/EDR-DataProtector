/*++

Module Name:

    DpThreatEngine.c

Abstract:

    Cross-module threat correlation and graduated-response engine. This module
    is the analytic brain of the DataProtector EDR. The individual kernel
    sensors (process policy, user-hook defense, credential-hash protection,
    lateral-movement defense, network filter, web-shell hardening, and file
    hunter) report normalized behavioral signals here instead of acting in
    isolation.

    The engine maintains a per-process risk model:

      * Each tracked process carries a cumulative, time-decayed risk score.
      * Every signal maps to a weight and a MITRE ATT&CK tactic / technique.
      * Observing a new distinct tactic in a process lineage applies a
        correlation bonus, so multi-stage kill chains escalate quickly while a
        single benign signal does not.
      * Score earned by a child propagates up the process ancestry, letting a
        malicious lineage root (a dropper, a macro host, a remote shell) be
        scored and contained together with its children.
      * As the score crosses configured thresholds, the engine selects the
        strongest permitted response: audit, alert, block, network isolation,
        or process-tree termination.

    Active enforcement that requires PASSIVE_LEVEL (process termination) is
    handed to a dedicated worker thread. Network isolation is published as a
    per-process flag consulted by the network filter classify path, which runs
    at DISPATCH_LEVEL; the process table is therefore guarded by a spin lock so
    it can be queried safely from any IRQL.

--*/

#include "DataProtector.h"

#include <ntstrsafe.h>

#if DP_ENABLE_THREAT_ENGINE_TRACE
#define DP_THREAT_TRACE(_format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DataProtector[Threat] " _format, __VA_ARGS__)
#else
#define DP_THREAT_TRACE(_format, ...) ((void)0)
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

extern POBJECT_TYPE *PsProcessType;

//
// Per-process node flags.
//
#define DP_THREAT_PROC_FLAG_ISOLATED      0x00000001
#define DP_THREAT_PROC_FLAG_TERMINATED    0x00000002
#define DP_THREAT_PROC_FLAG_TERMINATE_REQ 0x00000004

//
// Correlation bonus applied for each additional distinct ATT&CK tactic seen in
// a process lineage. Breadth across the kill chain is the strongest indicator
// of a genuine intrusion.
//
#define DP_THREAT_CORRELATION_BONUS 12

//
// Bounded worker request ring for active responses.
//
#define DP_THREAT_RESPONSE_QUEUE_DEPTH 256

typedef struct _DP_THREAT_TECHNIQUE_SLOT {
    ULONG TechniqueId;
    ULONG Tactic;
    ULONG Hits;
} DP_THREAT_TECHNIQUE_SLOT, *PDP_THREAT_TECHNIQUE_SLOT;

typedef struct _DP_THREAT_PROCESS_NODE {
    LIST_ENTRY BucketLink;
    LIST_ENTRY OrderLink;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    HANDLE LineageRootPid;
    ULONG CumulativeScore;
    ULONG SignalCount;
    ULONG DistinctTacticMask;
    ULONG StrongestResponse;
    ULONG Flags;
    ULONGLONG FirstSeen;
    ULONGLONG LastActivity;
    ULONGLONG LastDecay;
    ULONG ImageLengthBytes;
    WCHAR Image[DP_THREAT_PROCESS_CHARS];
    ULONG TechniqueCount;
    DP_THREAT_TECHNIQUE_SLOT Techniques[DP_THREAT_MAX_TECHNIQUES_PER_PROC];
} DP_THREAT_PROCESS_NODE, *PDP_THREAT_PROCESS_NODE;

typedef struct _DP_THREAT_EVENT_ENTRY {
    LIST_ENTRY Link;
    DP_THREAT_EVENT_QUERY_ENTRY Event;
} DP_THREAT_EVENT_ENTRY, *PDP_THREAT_EVENT_ENTRY;

typedef struct _DP_THREAT_RESPONSE_SLOT {
    HANDLE ProcessId;
    ULONG Action;
} DP_THREAT_RESPONSE_SLOT, *PDP_THREAT_RESPONSE_SLOT;

//
// Attack storyline. One record per process lineage root. It accumulates a
// time-ordered ring of behavioral steps so the console can reconstruct the
// full attack flow once the lineage trips the incident threshold.
//
typedef struct _DP_THREAT_STORYLINE {
    LIST_ENTRY Link;
    HANDLE LineageRootPid;
    HANDLE OriginProcessId;     // process that first crossed the incident bar
    ULONGLONG IncidentId;       // assigned when the lineage becomes an incident
    ULONGLONG FirstSeen;
    ULONGLONG LastActivity;
    ULONG PeakScore;
    ULONG Severity;
    ULONG TacticMask;
    ULONG StrongestResponse;
    ULONG StepCount;            // valid entries in Steps (capped)
    ULONG TotalStepsObserved;
    ULONG NextStep;             // ring write cursor
    BOOLEAN IsIncident;
    ULONG RootImageLengthBytes;
    ULONG OriginImageLengthBytes;
    WCHAR RootImage[DP_THREAT_PROCESS_CHARS];
    WCHAR OriginImage[DP_THREAT_PROCESS_CHARS];
    DP_THREAT_STORY_STEP Steps[DP_THREAT_STORY_MAX_STEPS];
} DP_THREAT_STORYLINE, *PDP_THREAT_STORYLINE;

//
// Signal metadata: default weight, mapped tactic, ATT&CK technique number.
//
typedef struct _DP_THREAT_SIGNAL_INFO {
    ULONG Weight;
    DP_THREAT_TACTIC Tactic;
    ULONG TechniqueId;
} DP_THREAT_SIGNAL_INFO, *PDP_THREAT_SIGNAL_INFO;

//
// The lineage score at which a storyline is promoted to a tracked incident.
//
#define DP_THREAT_INCIDENT_THRESHOLD DP_THREAT_SCORE_THRESHOLD_HIGH

//
// Process table.
//
static LIST_ENTRY gThreatBuckets[DP_THREAT_HASH_BUCKETS];
static LIST_ENTRY gThreatProcessOrder;
static KSPIN_LOCK gThreatProcessLock;
static ULONG gThreatProcessCount = 0;

//
// Event ring for the console.
//
static LIST_ENTRY gThreatEvents;
static KSPIN_LOCK gThreatEventLock;
static ULONG gThreatEventCount = 0;
static ULONGLONG gThreatEventSequence = 0;
static ULONGLONG gThreatDroppedEvents = 0;

//
// Attack storyline table, keyed by lineage root.
//
static LIST_ENTRY gThreatStorylines;
static KSPIN_LOCK gThreatStoryLock;
static ULONG gThreatStorylineCount = 0;
static ULONGLONG gThreatIncidentSequence = 0;
static ULONGLONG gThreatDroppedStorylines = 0;

//
// Policy.
//
static volatile LONG gThreatEngineFlags = DP_THREAT_ENGINE_DEFAULT_FLAGS;
static volatile LONG gThreatBlockThreshold = DP_THREAT_SCORE_THRESHOLD_MEDIUM;
static volatile LONG gThreatIsolateThreshold = DP_THREAT_SCORE_THRESHOLD_HIGH;
static volatile LONG gThreatTerminateThreshold = DP_THREAT_SCORE_THRESHOLD_CRITICAL;

static BOOLEAN gThreatInitialized = FALSE;

//
// Active-response worker.
//
static KSPIN_LOCK gThreatResponseLock;
static DP_THREAT_RESPONSE_SLOT gThreatResponseQueue[DP_THREAT_RESPONSE_QUEUE_DEPTH];
static ULONG gThreatResponseHead = 0;
static ULONG gThreatResponseTail = 0;
static ULONG gThreatResponseCount = 0;
static KSEMAPHORE gThreatResponseSemaphore;
static volatile LONG gThreatWorkerStop = 0;
static PVOID gThreatWorkerThread = NULL;

static
ULONGLONG
DpThreatNow(
    VOID
    )
{
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);
    return (ULONGLONG)now.QuadPart;
}

static
ULONG
DpThreatReadFlags(
    VOID
    )
{
    return (ULONG)gThreatEngineFlags;
}

static
BOOLEAN
DpThreatFeatureEnabled(
    _In_ ULONG FeatureFlag
    )
{
    ULONG flags = DpThreatReadFlags();

    return FlagOn(flags, DP_THREAT_ENGINE_FLAG_ENABLED) &&
           FlagOn(flags, FeatureFlag);
}

static
ULONG
DpThreatBucketIndex(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR raw = (ULONG_PTR)ProcessId;

    //
    // PIDs are allocated in multiples of four; fold the value to spread it
    // across the bucket array.
    //
    return (ULONG)((raw / 4) % DP_THREAT_HASH_BUCKETS);
}

static
const DP_THREAT_SIGNAL_INFO *
DpThreatLookupSignal(
    _In_ DP_THREAT_SIGNAL Signal
    )
{
    static const DP_THREAT_SIGNAL_INFO Unknown = { 5, DpThreatTacticUnknown, 0 };

    static const DP_THREAT_SIGNAL_INFO ProcessCreated = { 1, DpThreatTacticExecution, 0 };
    static const DP_THREAT_SIGNAL_INFO SuspiciousParentChild = { 18, DpThreatTacticExecution, 1059 };
    static const DP_THREAT_SIGNAL_INFO LolbinExecuted = { 20, DpThreatTacticDefenseEvasion, 1218 };
    static const DP_THREAT_SIGNAL_INFO ScriptInterpreterSpawned = { 12, DpThreatTacticExecution, 1059 };
    static const DP_THREAT_SIGNAL_INFO OfficeSpawnedChild = { 28, DpThreatTacticExecution, 1204 };

    static const DP_THREAT_SIGNAL_INFO LsassHandleAccess = { 48, DpThreatTacticCredentialAccess, 1003 };
    static const DP_THREAT_SIGNAL_INFO CredentialFileAccess = { 42, DpThreatTacticCredentialAccess, 1003 };
    static const DP_THREAT_SIGNAL_INFO RegistryHiveAccess = { 38, DpThreatTacticCredentialAccess, 1003 };
    static const DP_THREAT_SIGNAL_INFO RawDiskAccess = { 44, DpThreatTacticCredentialAccess, 1006 };

    static const DP_THREAT_SIGNAL_INFO RemoteThreadInjection = { 50, DpThreatTacticDefenseEvasion, 1055 };
    static const DP_THREAT_SIGNAL_INFO ProcessHandleManipulation = { 30, DpThreatTacticDefenseEvasion, 1055 };
    static const DP_THREAT_SIGNAL_INFO SuspiciousImageLoad = { 24, DpThreatTacticDefenseEvasion, 1574 };
    static const DP_THREAT_SIGNAL_INFO EtwTamper = { 42, DpThreatTacticDefenseEvasion, 1562 };
    static const DP_THREAT_SIGNAL_INFO UnsignedRuntimeRejected = { 20, DpThreatTacticDefenseEvasion, 1562 };
    static const DP_THREAT_SIGNAL_INFO SecurityToolTamper = { 58, DpThreatTacticDefenseEvasion, 1562 };

    static const DP_THREAT_SIGNAL_INFO RemoteServiceTool = { 45, DpThreatTacticLateralMovement, 1021 };
    static const DP_THREAT_SIGNAL_INFO RemoteScheduledTask = { 42, DpThreatTacticLateralMovement, 1053 };
    static const DP_THREAT_SIGNAL_INFO RemoteWmiExecution = { 45, DpThreatTacticLateralMovement, 1047 };
    static const DP_THREAT_SIGNAL_INFO RemotePowerShell = { 40, DpThreatTacticLateralMovement, 1021 };
    static const DP_THREAT_SIGNAL_INFO SmbExecutableStaging = { 38, DpThreatTacticLateralMovement, 1021 };
    static const DP_THREAT_SIGNAL_INFO RemoteIpcControl = { 35, DpThreatTacticLateralMovement, 1021 };

    static const DP_THREAT_SIGNAL_INFO BlockedC2Connection = { 36, DpThreatTacticCommandAndControl, 1071 };
    static const DP_THREAT_SIGNAL_INFO SuspiciousDnsBeacon = { 28, DpThreatTacticCommandAndControl, 1071 };
    static const DP_THREAT_SIGNAL_INFO SmtpExfiltration = { 40, DpThreatTacticExfiltration, 1048 };

    static const DP_THREAT_SIGNAL_INFO WebShellDropped = { 52, DpThreatTacticPersistence, 1505 };
    static const DP_THREAT_SIGNAL_INFO RansomwareMassFileAccess = { 60, DpThreatTacticImpact, 1486 };
    static const DP_THREAT_SIGNAL_INFO SensitiveDataHarvest = { 22, DpThreatTacticCollection, 1005 };
    static const DP_THREAT_SIGNAL_INFO RemovableMediaStaging = { 24, DpThreatTacticCollection, 1052 };

    static const DP_THREAT_SIGNAL_INFO MaliciousExecutableWrite = { 55, DpThreatTacticExecution, 1204 };
    static const DP_THREAT_SIGNAL_INFO SuspiciousExecutableWrite = { 30, DpThreatTacticExecution, 1204 };
    static const DP_THREAT_SIGNAL_INFO PackedExecutableWrite = { 34, DpThreatTacticDefenseEvasion, 1027 };

    switch (Signal) {
    case DpThreatSignalProcessCreated: return &ProcessCreated;
    case DpThreatSignalSuspiciousParentChild: return &SuspiciousParentChild;
    case DpThreatSignalLolbinExecuted: return &LolbinExecuted;
    case DpThreatSignalScriptInterpreterSpawned: return &ScriptInterpreterSpawned;
    case DpThreatSignalOfficeSpawnedChild: return &OfficeSpawnedChild;

    case DpThreatSignalLsassHandleAccess: return &LsassHandleAccess;
    case DpThreatSignalCredentialFileAccess: return &CredentialFileAccess;
    case DpThreatSignalRegistryHiveAccess: return &RegistryHiveAccess;
    case DpThreatSignalRawDiskAccess: return &RawDiskAccess;

    case DpThreatSignalRemoteThreadInjection: return &RemoteThreadInjection;
    case DpThreatSignalProcessHandleManipulation: return &ProcessHandleManipulation;
    case DpThreatSignalSuspiciousImageLoad: return &SuspiciousImageLoad;
    case DpThreatSignalEtwTamper: return &EtwTamper;
    case DpThreatSignalUnsignedRuntimeRejected: return &UnsignedRuntimeRejected;
    case DpThreatSignalSecurityToolTamper: return &SecurityToolTamper;

    case DpThreatSignalRemoteServiceTool: return &RemoteServiceTool;
    case DpThreatSignalRemoteScheduledTask: return &RemoteScheduledTask;
    case DpThreatSignalRemoteWmiExecution: return &RemoteWmiExecution;
    case DpThreatSignalRemotePowerShell: return &RemotePowerShell;
    case DpThreatSignalSmbExecutableStaging: return &SmbExecutableStaging;
    case DpThreatSignalRemoteIpcControl: return &RemoteIpcControl;

    case DpThreatSignalBlockedC2Connection: return &BlockedC2Connection;
    case DpThreatSignalSuspiciousDnsBeacon: return &SuspiciousDnsBeacon;
    case DpThreatSignalSmtpExfiltration: return &SmtpExfiltration;

    case DpThreatSignalWebShellDropped: return &WebShellDropped;
    case DpThreatSignalRansomwareMassFileAccess: return &RansomwareMassFileAccess;
    case DpThreatSignalSensitiveDataHarvest: return &SensitiveDataHarvest;
    case DpThreatSignalRemovableMediaStaging: return &RemovableMediaStaging;

    case DpThreatSignalMaliciousExecutableWrite: return &MaliciousExecutableWrite;
    case DpThreatSignalSuspiciousExecutableWrite: return &SuspiciousExecutableWrite;
    case DpThreatSignalPackedExecutableWrite: return &PackedExecutableWrite;

    default:
        return &Unknown;
    }
}

static
DP_THREAT_SEVERITY
DpThreatSeverityFromScore(
    _In_ ULONG Score
    )
{
    if (Score >= DP_THREAT_SCORE_THRESHOLD_CRITICAL) {
        return DpThreatSeverityCritical;
    }
    if (Score >= DP_THREAT_SCORE_THRESHOLD_HIGH) {
        return DpThreatSeverityHigh;
    }
    if (Score >= DP_THREAT_SCORE_THRESHOLD_MEDIUM) {
        return DpThreatSeverityMedium;
    }
    if (Score >= DP_THREAT_SCORE_THRESHOLD_LOW) {
        return DpThreatSeverityLow;
    }
    return DpThreatSeverityInformational;
}

//
// Translate a cumulative score into the strongest response permitted by the
// current policy.
//
static
DP_THREAT_RESPONSE_ACTION
DpThreatActionForScore(
    _In_ ULONG Score
    )
{
    ULONG flags = DpThreatReadFlags();
    ULONG blockThreshold = (ULONG)gThreatBlockThreshold;
    ULONG isolateThreshold = (ULONG)gThreatIsolateThreshold;
    ULONG terminateThreshold = (ULONG)gThreatTerminateThreshold;

    if (!FlagOn(flags, DP_THREAT_ENGINE_FLAG_ENABLED)) {
        return DpThreatResponseNone;
    }

    //
    // Audit-only mode never enforces; it caps escalation at an alert so the
    // console still sees the full storyline.
    //
    if (FlagOn(flags, DP_THREAT_ENGINE_FLAG_AUDIT_ONLY)) {
        if (Score >= DP_THREAT_SCORE_THRESHOLD_LOW) {
            return DpThreatResponseAlert;
        }
        return DpThreatResponseAudit;
    }

    if (FlagOn(flags, DP_THREAT_ENGINE_FLAG_AUTO_TERMINATE) &&
        Score >= terminateThreshold) {
        return DpThreatResponseTerminate;
    }

    if (FlagOn(flags, DP_THREAT_ENGINE_FLAG_AUTO_ISOLATE) &&
        Score >= isolateThreshold) {
        return DpThreatResponseIsolateNetwork;
    }

    if (FlagOn(flags, DP_THREAT_ENGINE_FLAG_AUTO_BLOCK) &&
        Score >= blockThreshold) {
        return DpThreatResponseBlock;
    }

    if (Score >= DP_THREAT_SCORE_THRESHOLD_LOW) {
        return DpThreatResponseAlert;
    }

    return DpThreatResponseAudit;
}

//
// Must be called with gThreatProcessLock held.
//
static
PDP_THREAT_PROCESS_NODE
DpThreatFindNodeLocked(
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket = DpThreatBucketIndex(ProcessId);
    PLIST_ENTRY link;

    for (link = gThreatBuckets[bucket].Flink;
         link != &gThreatBuckets[bucket];
         link = link->Flink) {

        PDP_THREAT_PROCESS_NODE node = CONTAINING_RECORD(link,
                                                         DP_THREAT_PROCESS_NODE,
                                                         BucketLink);
        if (node->ProcessId == ProcessId) {
            return node;
        }
    }

    return NULL;
}

//
// Must be called with gThreatProcessLock held. Removes and frees the oldest
// tracked process so the table stays bounded.
//
static
VOID
DpThreatEvictOldestLocked(
    VOID
    )
{
    PLIST_ENTRY orderLink;
    PDP_THREAT_PROCESS_NODE node;

    if (IsListEmpty(&gThreatProcessOrder)) {
        return;
    }

    orderLink = RemoveHeadList(&gThreatProcessOrder);
    node = CONTAINING_RECORD(orderLink, DP_THREAT_PROCESS_NODE, OrderLink);
    RemoveEntryList(&node->BucketLink);
    gThreatProcessCount--;
    ExFreePoolWithTag(node, DP_TAG_THREAT_PROCESS);
}

//
// Must be called with gThreatProcessLock held. Inserts a freshly allocated
// node into both the bucket chain and the FIFO order list.
//
static
VOID
DpThreatInsertNodeLocked(
    _In_ PDP_THREAT_PROCESS_NODE Node
    )
{
    ULONG bucket = DpThreatBucketIndex(Node->ProcessId);

    while (gThreatProcessCount >= DP_THREAT_MAX_PROCESSES) {
        DpThreatEvictOldestLocked();
    }

    InsertTailList(&gThreatBuckets[bucket], &Node->BucketLink);
    InsertTailList(&gThreatProcessOrder, &Node->OrderLink);
    gThreatProcessCount++;
}

static
PDP_THREAT_PROCESS_NODE
DpThreatAllocateNode(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId
    )
{
    PDP_THREAT_PROCESS_NODE node;
    ULONGLONG now = DpThreatNow();

    node = ExAllocatePoolWithTag(NonPagedPoolNx,
                                 sizeof(DP_THREAT_PROCESS_NODE),
                                 DP_TAG_THREAT_PROCESS);
    if (node == NULL) {
        return NULL;
    }

    RtlZeroMemory(node, sizeof(DP_THREAT_PROCESS_NODE));
    node->ProcessId = ProcessId;
    node->ParentProcessId = ParentProcessId;
    node->LineageRootPid = ProcessId;
    node->FirstSeen = now;
    node->LastActivity = now;
    node->LastDecay = now;
    return node;
}

//
// Must be called with gThreatProcessLock held. Applies elapsed time decay so a
// quiet process bleeds risk back toward zero.
//
static
VOID
DpThreatApplyDecayLocked(
    _Inout_ PDP_THREAT_PROCESS_NODE Node,
    _In_ ULONGLONG Now
    )
{
    ULONGLONG elapsed;
    ULONGLONG intervals;
    ULONG decay;

    if (Node->CumulativeScore == 0) {
        Node->LastDecay = Now;
        return;
    }

    if (Now <= Node->LastDecay) {
        return;
    }

    elapsed = Now - Node->LastDecay;
    intervals = elapsed / (ULONGLONG)DP_THREAT_DECAY_INTERVAL_100NS;
    if (intervals == 0) {
        return;
    }

    if (intervals > (ULONGLONG)(Node->CumulativeScore / DP_THREAT_DECAY_POINTS) + 1) {
        decay = Node->CumulativeScore;
    } else {
        decay = (ULONG)(intervals * DP_THREAT_DECAY_POINTS);
    }

    if (decay >= Node->CumulativeScore) {
        Node->CumulativeScore = 0;
    } else {
        Node->CumulativeScore -= decay;
    }

    Node->LastDecay += intervals * (ULONGLONG)DP_THREAT_DECAY_INTERVAL_100NS;
}

//
// Must be called with gThreatProcessLock held. Records the ATT&CK technique on
// the node and reports whether the tactic is newly observed for this process.
//
static
BOOLEAN
DpThreatRecordTechniqueLocked(
    _Inout_ PDP_THREAT_PROCESS_NODE Node,
    _In_ ULONG TechniqueId,
    _In_ DP_THREAT_TACTIC Tactic
    )
{
    ULONG index;
    BOOLEAN newTactic;
    ULONG tacticBit = (Tactic < 32) ? (1u << (ULONG)Tactic) : 0;

    newTactic = (tacticBit != 0) && !FlagOn(Node->DistinctTacticMask, tacticBit);
    if (tacticBit != 0) {
        Node->DistinctTacticMask |= tacticBit;
    }

    for (index = 0; index < Node->TechniqueCount; index++) {
        if (Node->Techniques[index].TechniqueId == TechniqueId &&
            Node->Techniques[index].Tactic == (ULONG)Tactic) {

            Node->Techniques[index].Hits++;
            return newTactic;
        }
    }

    if (Node->TechniqueCount < DP_THREAT_MAX_TECHNIQUES_PER_PROC) {
        Node->Techniques[Node->TechniqueCount].TechniqueId = TechniqueId;
        Node->Techniques[Node->TechniqueCount].Tactic = (ULONG)Tactic;
        Node->Techniques[Node->TechniqueCount].Hits = 1;
        Node->TechniqueCount++;
    }

    return newTactic;
}

static
ULONG
DpThreatPopCount(
    _In_ ULONG Value
    )
{
    ULONG count = 0;

    while (Value != 0) {
        Value &= (Value - 1);
        count++;
    }

    return count;
}

//
// Case-insensitive test for whether an image path ends with the given file
// name (handles both bare names and full paths).
//
static
BOOLEAN
DpThreatImageNameMatches(
    _In_ PCUNICODE_STRING ImagePath,
    _In_z_ PCWSTR FileName
    )
{
    UNICODE_STRING fileName;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        return FALSE;
    }

    RtlInitUnicodeString(&fileName, FileName);
    if (fileName.Length == 0 || ImagePath->Length < fileName.Length) {
        return FALSE;
    }

    if (RtlEqualUnicodeString(ImagePath, &fileName, TRUE)) {
        return TRUE;
    }

    //
    // Suffix match, requiring a path separator immediately before the name so
    // "notepad.exe" does not match "evilnotepad.exe".
    //
    {
        USHORT imageChars = ImagePath->Length / sizeof(WCHAR);
        USHORT nameChars = fileName.Length / sizeof(WCHAR);
        USHORT offset = imageChars - nameChars;
        USHORT i;
        WCHAR precedingChar;

        if (offset > 0) {
            precedingChar = ImagePath->Buffer[offset - 1];
            if (precedingChar != L'\\' && precedingChar != L'/') {
                return FALSE;
            }
        }

        for (i = 0; i < nameChars; i++) {
            if (RtlUpcaseUnicodeChar(ImagePath->Buffer[offset + i]) !=
                RtlUpcaseUnicodeChar(fileName.Buffer[i])) {

                return FALSE;
            }
        }

        return TRUE;
    }
}

static
VOID
DpThreatFreeEvent(
    _In_opt_ PDP_THREAT_EVENT_ENTRY Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, DP_TAG_THREAT_EVENT);
    }
}

static
VOID
DpThreatQueueEvent(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE LineageRootPid,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ const DP_THREAT_SIGNAL_INFO *Info,
    _In_ ULONG ScoreDelta,
    _In_ ULONG CumulativeScore,
    _In_ DP_THREAT_SEVERITY Severity,
    _In_ DP_THREAT_RESPONSE_ACTION Action,
    _In_ NTSTATUS ResponseStatus,
    _In_reads_(ImageChars) const WCHAR *Image,
    _In_ ULONG ImageChars,
    _In_opt_ PCUNICODE_STRING Detail
    )
{
    PDP_THREAT_EVENT_ENTRY entry;
    KIRQL oldIrql;
    ULONG imageBytes;

    if (!gThreatInitialized) {
        return;
    }

    entry = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_THREAT_EVENT_ENTRY),
                                  DP_TAG_THREAT_EVENT);
    if (entry == NULL) {
        KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
        gThreatDroppedEvents++;
        KeReleaseSpinLock(&gThreatEventLock, oldIrql);
        return;
    }

    RtlZeroMemory(entry, sizeof(DP_THREAT_EVENT_ENTRY));
    entry->Event.TimeStamp = DpThreatNow();
    entry->Event.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    entry->Event.ParentProcessId = (ULONGLONG)(ULONG_PTR)ParentProcessId;
    entry->Event.LineageRootPid = (ULONGLONG)(ULONG_PTR)LineageRootPid;
    entry->Event.Signal = (ULONG)Signal;
    entry->Event.Tactic = (ULONG)Info->Tactic;
    entry->Event.TechniqueId = Info->TechniqueId;
    entry->Event.ScoreDelta = ScoreDelta;
    entry->Event.CumulativeScore = CumulativeScore;
    entry->Event.Severity = (ULONG)Severity;
    entry->Event.ResponseAction = (ULONG)Action;
    entry->Event.ResponseStatus = (ULONG)ResponseStatus;

    if (Image != NULL && ImageChars > 0) {
        ULONG copyChars = min(ImageChars, (ULONG)RTL_NUMBER_OF(entry->Event.ProcessImage) - 1);
        RtlCopyMemory(entry->Event.ProcessImage, Image, copyChars * sizeof(WCHAR));
        entry->Event.ProcessImage[copyChars] = L'\0';
        entry->Event.ProcessImageLengthBytes = copyChars * sizeof(WCHAR);
    }

    if (Detail != NULL && Detail->Buffer != NULL && Detail->Length > 0) {
        imageBytes = min((ULONG)Detail->Length,
                         (ULONG)((RTL_NUMBER_OF(entry->Event.Detail) - 1) * sizeof(WCHAR)));
        RtlCopyMemory(entry->Event.Detail, Detail->Buffer, imageBytes);
        entry->Event.Detail[imageBytes / sizeof(WCHAR)] = L'\0';
        entry->Event.DetailLengthBytes = imageBytes;
    }

    KeAcquireSpinLock(&gThreatEventLock, &oldIrql);

    entry->Event.Sequence = ++gThreatEventSequence;
    InsertTailList(&gThreatEvents, &entry->Link);
    gThreatEventCount++;

    while (gThreatEventCount > DP_THREAT_MAX_EVENTS &&
           !IsListEmpty(&gThreatEvents)) {

        PLIST_ENTRY oldLink = RemoveHeadList(&gThreatEvents);
        PDP_THREAT_EVENT_ENTRY oldEvent = CONTAINING_RECORD(oldLink,
                                                            DP_THREAT_EVENT_ENTRY,
                                                            Link);
        gThreatEventCount--;
        gThreatDroppedEvents++;
        KeReleaseSpinLock(&gThreatEventLock, oldIrql);
        DpThreatFreeEvent(oldEvent);
        KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
    }

    KeReleaseSpinLock(&gThreatEventLock, oldIrql);

    DP_THREAT_TRACE("event seq=%I64u pid=%p signal=%lu delta=%lu score=%lu sev=%lu action=%lu\n",
                    entry->Event.Sequence,
                    ProcessId,
                    (ULONG)Signal,
                    ScoreDelta,
                    CumulativeScore,
                    (ULONG)Severity,
                    (ULONG)Action);
}

//
// Must be called with gThreatStoryLock held. Find or create the storyline for
// a lineage root, evicting the lowest-value record when at capacity.
//
static
PDP_THREAT_STORYLINE
DpThreatFindOrCreateStorylineLocked(
    _In_ HANDLE LineageRootPid,
    _In_ ULONGLONG Now
    )
{
    PLIST_ENTRY link;
    PDP_THREAT_STORYLINE story;
    PDP_THREAT_STORYLINE weakest = NULL;

    for (link = gThreatStorylines.Flink; link != &gThreatStorylines; link = link->Flink) {
        story = CONTAINING_RECORD(link, DP_THREAT_STORYLINE, Link);
        if (story->LineageRootPid == LineageRootPid) {
            return story;
        }

        if (weakest == NULL ||
            story->PeakScore < weakest->PeakScore ||
            (story->PeakScore == weakest->PeakScore &&
             story->LastActivity < weakest->LastActivity)) {

            weakest = story;
        }
    }

    if (gThreatStorylineCount >= DP_THREAT_MAX_STORYLINES) {
        //
        // At capacity: never evict a confirmed incident in favor of a fresh,
        // unscored lineage. If the weakest is an incident, skip recording.
        //
        if (weakest == NULL || weakest->IsIncident) {
            return NULL;
        }

        RemoveEntryList(&weakest->Link);
        gThreatStorylineCount--;
        gThreatDroppedStorylines++;
        ExFreePoolWithTag(weakest, DP_TAG_THREAT_STORY);
    }

    story = ExAllocatePoolWithTag(NonPagedPoolNx,
                                  sizeof(DP_THREAT_STORYLINE),
                                  DP_TAG_THREAT_STORY);
    if (story == NULL) {
        return NULL;
    }

    RtlZeroMemory(story, sizeof(DP_THREAT_STORYLINE));
    story->LineageRootPid = LineageRootPid;
    story->FirstSeen = Now;
    story->LastActivity = Now;
    InsertTailList(&gThreatStorylines, &story->Link);
    gThreatStorylineCount++;
    return story;
}

//
// Append one ordered step to a lineage storyline and promote it to a tracked
// incident once the lineage score crosses the incident threshold. Runs under
// its own lock so it never nests inside the process-table lock.
//
static
VOID
DpThreatRecordStoryStep(
    _In_ HANDLE LineageRootPid,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ const DP_THREAT_SIGNAL_INFO *Info,
    _In_ ULONG ScoreDelta,
    _In_ ULONG CumulativeScore,
    _In_ DP_THREAT_SEVERITY Severity,
    _In_ DP_THREAT_RESPONSE_ACTION Action,
    _In_reads_(ImageChars) const WCHAR *Image,
    _In_ ULONG ImageChars,
    _In_opt_ PCUNICODE_STRING Detail
    )
{
    PDP_THREAT_STORYLINE story;
    PDP_THREAT_STORY_STEP step;
    KIRQL oldIrql;
    ULONGLONG now;
    ULONG slot;
    ULONG tacticBit;

    if (!gThreatInitialized || LineageRootPid == NULL) {
        return;
    }

    now = DpThreatNow();

    KeAcquireSpinLock(&gThreatStoryLock, &oldIrql);

    story = DpThreatFindOrCreateStorylineLocked(LineageRootPid, now);
    if (story == NULL) {
        KeReleaseSpinLock(&gThreatStoryLock, oldIrql);
        return;
    }

    story->LastActivity = now;
    story->TotalStepsObserved++;

    tacticBit = ((ULONG)Info->Tactic < 32) ? (1u << (ULONG)Info->Tactic) : 0;
    story->TacticMask |= tacticBit;

    if (CumulativeScore > story->PeakScore) {
        story->PeakScore = CumulativeScore;
        story->Severity = (ULONG)Severity;
    }

    if ((ULONG)Action > story->StrongestResponse) {
        story->StrongestResponse = (ULONG)Action;
    }

    //
    // Capture the lineage root image once (the first step whose process is the
    // root supplies it; otherwise we keep the most recent root-side image).
    //
    if (story->RootImageLengthBytes == 0 && ProcessId == LineageRootPid &&
        Image != NULL && ImageChars != 0) {

        ULONG copyChars = min(ImageChars, (ULONG)DP_THREAT_PROCESS_CHARS - 1);
        RtlCopyMemory(story->RootImage, Image, copyChars * sizeof(WCHAR));
        story->RootImage[copyChars] = L'\0';
        story->RootImageLengthBytes = copyChars * sizeof(WCHAR);
    }

    //
    // Ring-buffer the step. When full, advance the window but keep counting so
    // the console can show "N of M steps".
    //
    if (story->StepCount < DP_THREAT_STORY_MAX_STEPS) {
        slot = story->StepCount;
        story->StepCount++;
    } else {
        slot = story->NextStep;
        story->NextStep = (story->NextStep + 1) % DP_THREAT_STORY_MAX_STEPS;
    }

    step = &story->Steps[slot];
    RtlZeroMemory(step, sizeof(*step));
    step->TimeStamp = now;
    step->ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    step->ParentProcessId = (ULONGLONG)(ULONG_PTR)ParentProcessId;
    step->Signal = (ULONG)Signal;
    step->Tactic = (ULONG)Info->Tactic;
    step->TechniqueId = Info->TechniqueId;
    step->ScoreDelta = ScoreDelta;
    step->CumulativeScore = CumulativeScore;
    step->ResponseAction = (ULONG)Action;

    if (Detail != NULL && Detail->Buffer != NULL && Detail->Length > 0) {
        ULONG copyBytes = min((ULONG)Detail->Length,
                              (ULONG)((DP_THREAT_STORY_DETAIL_CHARS - 1) * sizeof(WCHAR)));
        RtlCopyMemory(step->Detail, Detail->Buffer, copyBytes);
        step->Detail[copyBytes / sizeof(WCHAR)] = L'\0';
        step->DetailLengthBytes = copyBytes;
    }

    //
    // Promote to a tracked incident the first time the lineage crosses the
    // incident threshold, recording the originating process and image.
    //
    if (!story->IsIncident && CumulativeScore >= DP_THREAT_INCIDENT_THRESHOLD) {
        story->IsIncident = TRUE;
        story->IncidentId = ++gThreatIncidentSequence;
        story->OriginProcessId = ProcessId;
        if (Image != NULL && ImageChars != 0) {
            ULONG copyChars = min(ImageChars, (ULONG)DP_THREAT_PROCESS_CHARS - 1);
            RtlCopyMemory(story->OriginImage, Image, copyChars * sizeof(WCHAR));
            story->OriginImage[copyChars] = L'\0';
            story->OriginImageLengthBytes = copyChars * sizeof(WCHAR);
        }
    }

    KeReleaseSpinLock(&gThreatStoryLock, oldIrql);
}

//
// Enqueue an active response for the worker thread. Network isolation is a
// passive flag already published on the node, so only termination is queued
// here.
//
static
VOID
DpThreatEnqueueResponse(
    _In_ HANDLE ProcessId,
    _In_ DP_THREAT_RESPONSE_ACTION Action
    )
{
    KIRQL oldIrql;
    BOOLEAN queued = FALSE;

    if (gThreatWorkerStop != 0 || gThreatWorkerThread == NULL) {
        return;
    }

    KeAcquireSpinLock(&gThreatResponseLock, &oldIrql);
    if (gThreatResponseCount < DP_THREAT_RESPONSE_QUEUE_DEPTH) {
        gThreatResponseQueue[gThreatResponseTail].ProcessId = ProcessId;
        gThreatResponseQueue[gThreatResponseTail].Action = (ULONG)Action;
        gThreatResponseTail = (gThreatResponseTail + 1) % DP_THREAT_RESPONSE_QUEUE_DEPTH;
        gThreatResponseCount++;
        queued = TRUE;
    }
    KeReleaseSpinLock(&gThreatResponseLock, oldIrql);

    if (queued) {
        KeReleaseSemaphore(&gThreatResponseSemaphore, IO_NO_INCREMENT, 1, FALSE);
    }
}

static
NTSTATUS
DpThreatTerminateProcessById(
    _In_ HANDLE ProcessId
    )
{
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(process,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   PROCESS_TERMINATE,
                                   *PsProcessType,
                                   KernelMode,
                                   &processHandle);
    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
        ZwClose(processHandle);
    }

    ObDereferenceObject(process);
    return status;
}

static
VOID
DpThreatResponseWorker(
    _In_ PVOID StartContext
    )
{
    UNREFERENCED_PARAMETER(StartContext);

    for (;;) {
        DP_THREAT_RESPONSE_SLOT slot = { 0 };
        KIRQL oldIrql;
        BOOLEAN haveWork = FALSE;

        KeWaitForSingleObject(&gThreatResponseSemaphore,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);

        if (gThreatWorkerStop != 0) {
            break;
        }

        KeAcquireSpinLock(&gThreatResponseLock, &oldIrql);
        if (gThreatResponseCount > 0) {
            slot = gThreatResponseQueue[gThreatResponseHead];
            gThreatResponseHead = (gThreatResponseHead + 1) % DP_THREAT_RESPONSE_QUEUE_DEPTH;
            gThreatResponseCount--;
            haveWork = TRUE;
        }
        KeReleaseSpinLock(&gThreatResponseLock, oldIrql);

        if (!haveWork) {
            continue;
        }

        if (slot.Action == (ULONG)DpThreatResponseTerminate) {
            NTSTATUS status = DpThreatTerminateProcessById(slot.ProcessId);

            DP_THREAT_TRACE("terminate pid=%p status=0x%08X\n",
                            slot.ProcessId,
                            status);

            if (NT_SUCCESS(status)) {
                PDP_THREAT_PROCESS_NODE node;

                KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
                node = DpThreatFindNodeLocked(slot.ProcessId);
                if (node != NULL) {
                    node->Flags |= DP_THREAT_PROC_FLAG_TERMINATED;
                }
                KeReleaseSpinLock(&gThreatProcessLock, oldIrql);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID
DpThreatEngineOnProcessCreate(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    PDP_THREAT_PROCESS_NODE node;
    PDP_THREAT_PROCESS_NODE parent;
    KIRQL oldIrql;
    WCHAR parentImage[DP_THREAT_PROCESS_CHARS];
    ULONG parentImageChars = 0;
    DP_THREAT_SIGNAL lineageSignal = DpThreatSignalNone;

    UNREFERENCED_PARAMETER(CommandLine);

    parentImage[0] = L'\0';

    if (!gThreatInitialized || !DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_ENABLED)) {
        return;
    }

    node = DpThreatAllocateNode(ProcessId, ParentProcessId);
    if (node == NULL) {
        return;
    }

    if (ImageFileName != NULL &&
        ImageFileName->Buffer != NULL &&
        ImageFileName->Length > 0) {

        ULONG copyBytes = min((ULONG)ImageFileName->Length,
                              (ULONG)((DP_THREAT_PROCESS_CHARS - 1) * sizeof(WCHAR)));
        RtlCopyMemory(node->Image, ImageFileName->Buffer, copyBytes);
        node->Image[copyBytes / sizeof(WCHAR)] = L'\0';
        node->ImageLengthBytes = copyBytes;
    }

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);

    {
        PDP_THREAT_PROCESS_NODE existing = DpThreatFindNodeLocked(ProcessId);
        if (existing != NULL) {
            RemoveEntryList(&existing->BucketLink);
            RemoveEntryList(&existing->OrderLink);
            gThreatProcessCount--;
            ExFreePoolWithTag(existing, DP_TAG_THREAT_PROCESS);
        }
    }

    //
    // Inherit the lineage root from the parent so an entire attack tree shares
    // a storyline identity, and snapshot the parent image for spawn analysis.
    //
    if (ParentProcessId != NULL) {
        parent = DpThreatFindNodeLocked(ParentProcessId);
        if (parent != NULL) {
            node->LineageRootPid = parent->LineageRootPid;
            if (parent->ImageLengthBytes > 0) {
                parentImageChars = parent->ImageLengthBytes / sizeof(WCHAR);
                RtlCopyMemory(parentImage, parent->Image, parent->ImageLengthBytes);
                parentImage[parentImageChars] = L'\0';
            }
        } else {
            node->LineageRootPid = ParentProcessId;
        }
    }

    DpThreatInsertNodeLocked(node);

    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    //
    // Spawn-lineage heuristics (evaluated outside the lock; the report path
    // re-acquires it). A document or script host spawning a command shell is a
    // classic phishing/macro execution chain (T1204/T1059).
    //
    if (DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_CORRELATION) &&
        parentImageChars > 0 &&
        ImageFileName != NULL) {

        UNICODE_STRING parentName;
        UNICODE_STRING childName;
        BOOLEAN parentIsOffice;
        BOOLEAN parentIsScript;
        BOOLEAN childIsShell;
        BOOLEAN childIsScript;

        parentName.Buffer = parentImage;
        parentName.Length = (USHORT)(parentImageChars * sizeof(WCHAR));
        parentName.MaximumLength = (USHORT)sizeof(parentImage);
        childName = *ImageFileName;

        parentIsOffice =
            DpThreatImageNameMatches(&parentName, L"winword.exe") ||
            DpThreatImageNameMatches(&parentName, L"excel.exe") ||
            DpThreatImageNameMatches(&parentName, L"powerpnt.exe") ||
            DpThreatImageNameMatches(&parentName, L"outlook.exe") ||
            DpThreatImageNameMatches(&parentName, L"wps.exe") ||
            DpThreatImageNameMatches(&parentName, L"et.exe") ||
            DpThreatImageNameMatches(&parentName, L"wpp.exe");

        parentIsScript =
            DpThreatImageNameMatches(&parentName, L"wscript.exe") ||
            DpThreatImageNameMatches(&parentName, L"cscript.exe") ||
            DpThreatImageNameMatches(&parentName, L"mshta.exe");

        childIsShell =
            DpThreatImageNameMatches(&childName, L"cmd.exe") ||
            DpThreatImageNameMatches(&childName, L"powershell.exe") ||
            DpThreatImageNameMatches(&childName, L"pwsh.exe");

        childIsScript =
            DpThreatImageNameMatches(&childName, L"wscript.exe") ||
            DpThreatImageNameMatches(&childName, L"cscript.exe") ||
            DpThreatImageNameMatches(&childName, L"mshta.exe") ||
            DpThreatImageNameMatches(&childName, L"rundll32.exe") ||
            DpThreatImageNameMatches(&childName, L"regsvr32.exe");

        if (parentIsOffice && (childIsShell || childIsScript)) {
            lineageSignal = DpThreatSignalOfficeSpawnedChild;
        } else if (parentIsScript && childIsShell) {
            lineageSignal = DpThreatSignalSuspiciousParentChild;
        }

        if (lineageSignal != DpThreatSignalNone) {
            (VOID)DpThreatEngineReportSignal(ProcessId, lineageSignal, 0, ImageFileName);
        }
    }
}

VOID
DpThreatEngineOnProcessExit(
    _In_ HANDLE ProcessId
    )
{
    PDP_THREAT_PROCESS_NODE node = NULL;
    KIRQL oldIrql;

    if (!gThreatInitialized) {
        return;
    }

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
    node = DpThreatFindNodeLocked(ProcessId);
    if (node != NULL) {
        RemoveEntryList(&node->BucketLink);
        RemoveEntryList(&node->OrderLink);
        gThreatProcessCount--;
    }
    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    if (node != NULL) {
        ExFreePoolWithTag(node, DP_TAG_THREAT_PROCESS);
    }
}

DP_THREAT_RESPONSE_ACTION
DpThreatEngineReportSignal(
    _In_ HANDLE ProcessId,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ ULONG ScoreDeltaOverride,
    _In_opt_ PCUNICODE_STRING Detail
    )
{
    const DP_THREAT_SIGNAL_INFO *info;
    PDP_THREAT_PROCESS_NODE node;
    PDP_THREAT_PROCESS_NODE preAllocated = NULL;
    KIRQL oldIrql;
    ULONGLONG now;
    ULONG delta;
    ULONG cumulativeScore;
    BOOLEAN newTactic;
    DP_THREAT_SEVERITY severity;
    DP_THREAT_RESPONSE_ACTION action;
    HANDLE parentPid = NULL;
    HANDLE lineageRoot = ProcessId;
    WCHAR imageSnapshot[DP_THREAT_PROCESS_CHARS];
    ULONG imageChars = 0;
    HANDLE terminateTargets[DP_THREAT_ANCESTRY_MAX_DEPTH + 1];
    ULONG terminateCount = 0;
    ULONG i;

    if (!gThreatInitialized ||
        !DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_ENABLED) ||
        Signal == DpThreatSignalNone ||
        Signal >= DpThreatSignalMax) {

        return DpThreatResponseNone;
    }

    info = DpThreatLookupSignal(Signal);
    now = DpThreatNow();
    imageSnapshot[0] = L'\0';

    //
    // Pre-allocate a node outside the lock in case this signal targets a
    // process the engine has not seen yet (e.g. one created before load).
    //
    preAllocated = DpThreatAllocateNode(ProcessId, NULL);

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);

    node = DpThreatFindNodeLocked(ProcessId);
    if (node == NULL) {
        if (preAllocated == NULL) {
            KeReleaseSpinLock(&gThreatProcessLock, oldIrql);
            return DpThreatResponseNone;
        }
        node = preAllocated;
        preAllocated = NULL;
        DpThreatInsertNodeLocked(node);
    }

    DpThreatApplyDecayLocked(node, now);

    newTactic = FALSE;
    if (DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_CORRELATION)) {
        newTactic = DpThreatRecordTechniqueLocked(node, info->TechniqueId, info->Tactic);
    } else {
        (VOID)DpThreatRecordTechniqueLocked(node, info->TechniqueId, info->Tactic);
    }

    delta = (ScoreDeltaOverride != 0) ? ScoreDeltaOverride : info->Weight;

    //
    // Correlation: reward kill-chain breadth. The more distinct tactics already
    // observed in this process, the more a new tactic matters.
    //
    if (newTactic) {
        ULONG distinctTactics = DpThreatPopCount(node->DistinctTacticMask);
        if (distinctTactics > 1) {
            delta += DP_THREAT_CORRELATION_BONUS * (distinctTactics - 1);
        }
    }

    if (node->CumulativeScore + delta > DP_THREAT_SCORE_MAX) {
        node->CumulativeScore = DP_THREAT_SCORE_MAX;
    } else {
        node->CumulativeScore += delta;
    }

    node->SignalCount++;
    node->LastActivity = now;

    cumulativeScore = node->CumulativeScore;
    severity = DpThreatSeverityFromScore(cumulativeScore);
    action = DpThreatActionForScore(cumulativeScore);

    if ((ULONG)action > node->StrongestResponse) {
        node->StrongestResponse = (ULONG)action;
    }

    if (action == DpThreatResponseIsolateNetwork ||
        action == DpThreatResponseTerminate) {
        node->Flags |= DP_THREAT_PROC_FLAG_ISOLATED;
    }

    if (action == DpThreatResponseTerminate &&
        !FlagOn(node->Flags, DP_THREAT_PROC_FLAG_TERMINATE_REQ)) {

        node->Flags |= DP_THREAT_PROC_FLAG_TERMINATE_REQ;
        if (terminateCount < RTL_NUMBER_OF(terminateTargets)) {
            terminateTargets[terminateCount++] = ProcessId;
        }
    }

    parentPid = node->ParentProcessId;
    lineageRoot = node->LineageRootPid;
    if (node->ImageLengthBytes > 0) {
        imageChars = node->ImageLengthBytes / sizeof(WCHAR);
        RtlCopyMemory(imageSnapshot, node->Image, node->ImageLengthBytes);
        imageSnapshot[imageChars] = L'\0';
    }

    //
    // Propagate a fraction of the earned score up the ancestry so the lineage
    // root accumulates the storyline and the whole tree can be contained.
    //
    if (DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_ANCESTRY_PROPAGATION) &&
        delta > 0) {

        HANDLE ancestorPid = node->ParentProcessId;
        ULONG propagated = delta;
        ULONG depth;

        for (depth = 0; depth < DP_THREAT_ANCESTRY_MAX_DEPTH && ancestorPid != NULL; depth++) {
            PDP_THREAT_PROCESS_NODE ancestor = DpThreatFindNodeLocked(ancestorPid);
            DP_THREAT_RESPONSE_ACTION ancestorAction;

            propagated = (propagated * DP_THREAT_ANCESTRY_PROPAGATION_PCT) / 100;
            if (propagated == 0 || ancestor == NULL) {
                break;
            }

            DpThreatApplyDecayLocked(ancestor, now);

            if (ancestor->CumulativeScore + propagated > DP_THREAT_SCORE_MAX) {
                ancestor->CumulativeScore = DP_THREAT_SCORE_MAX;
            } else {
                ancestor->CumulativeScore += propagated;
            }
            ancestor->LastActivity = now;

            ancestorAction = DpThreatActionForScore(ancestor->CumulativeScore);
            if ((ULONG)ancestorAction > ancestor->StrongestResponse) {
                ancestor->StrongestResponse = (ULONG)ancestorAction;
            }

            if (ancestorAction == DpThreatResponseIsolateNetwork ||
                ancestorAction == DpThreatResponseTerminate) {
                ancestor->Flags |= DP_THREAT_PROC_FLAG_ISOLATED;
            }

            if (ancestorAction == DpThreatResponseTerminate &&
                !FlagOn(ancestor->Flags, DP_THREAT_PROC_FLAG_TERMINATE_REQ)) {

                ancestor->Flags |= DP_THREAT_PROC_FLAG_TERMINATE_REQ;
                if (terminateCount < RTL_NUMBER_OF(terminateTargets)) {
                    terminateTargets[terminateCount++] = ancestorPid;
                }
            }

            ancestorPid = ancestor->ParentProcessId;
        }
    }

    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    if (preAllocated != NULL) {
        ExFreePoolWithTag(preAllocated, DP_TAG_THREAT_PROCESS);
    }

    //
    // Enqueue active termination requests outside the lock.
    //
    for (i = 0; i < terminateCount; i++) {
        DpThreatEnqueueResponse(terminateTargets[i], DpThreatResponseTerminate);
    }

    DpThreatQueueEvent(ProcessId,
                       parentPid,
                       lineageRoot,
                       Signal,
                       info,
                       delta,
                       cumulativeScore,
                       severity,
                       action,
                       STATUS_SUCCESS,
                       imageSnapshot,
                       imageChars,
                       Detail);

    //
    // Record the step into the lineage attack storyline so the complete attack
    // flow is preserved for incident review.
    //
    DpThreatRecordStoryStep(lineageRoot,
                            ProcessId,
                            parentPid,
                            Signal,
                            info,
                            delta,
                            cumulativeScore,
                            severity,
                            action,
                            imageSnapshot,
                            imageChars,
                            Detail);

    return action;
}

DP_THREAT_RESPONSE_ACTION
DpThreatEngineReportSignalAnsi(
    _In_ HANDLE ProcessId,
    _In_ DP_THREAT_SIGNAL Signal,
    _In_ ULONG ScoreDeltaOverride,
    _In_opt_z_ const CHAR *Detail
    )
{
    WCHAR buffer[DP_THREAT_DETAIL_CHARS];
    UNICODE_STRING detail;
    ULONG index = 0;

    if (Detail != NULL) {
        for (index = 0;
             index + 1 < RTL_NUMBER_OF(buffer) && Detail[index] != '\0';
             index++) {

            buffer[index] = (WCHAR)(UCHAR)Detail[index];
        }
    }
    buffer[index] = L'\0';

    detail.Buffer = buffer;
    detail.Length = (USHORT)(index * sizeof(WCHAR));
    detail.MaximumLength = (USHORT)sizeof(buffer);

    return DpThreatEngineReportSignal(ProcessId,
                                      Signal,
                                      ScoreDeltaOverride,
                                      (Detail != NULL) ? &detail : NULL);
}

BOOLEAN
DpThreatEngineIsProcessIsolated(
    _In_ HANDLE ProcessId
    )
{
    PDP_THREAT_PROCESS_NODE node;
    KIRQL oldIrql;
    BOOLEAN isolated = FALSE;

    if (!gThreatInitialized ||
        !DpThreatFeatureEnabled(DP_THREAT_ENGINE_FLAG_AUTO_ISOLATE)) {

        return FALSE;
    }

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
    node = DpThreatFindNodeLocked(ProcessId);
    if (node != NULL) {
        isolated = FlagOn(node->Flags, DP_THREAT_PROC_FLAG_ISOLATED) ? TRUE : FALSE;
    }
    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    return isolated;
}

NTSTATUS
DpThreatEngineQueryEvents(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_THREAT_EVENT_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_THREAT_EVENT_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_THREAT_EVENT_QUERY_HEADER);
    ULONG eventCount = 0;
    ULONG returnedEventCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN sizingOnly;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_THREAT_EVENT_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_THREAT_EVENT_QUERY_HEADER)OutputBuffer;
    sizingOnly = OutputBufferLength == sizeof(DP_THREAT_EVENT_QUERY_HEADER);

    RtlZeroMemory(header, sizeof(DP_THREAT_EVENT_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_THREAT_EVENT_QUERY_HEADER);

    header->Version = DP_THREAT_EVENT_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_THREAT_EVENT_QUERY_HEADER);

    if (!gThreatInitialized) {
        header->BytesRequired = sizeof(DP_THREAT_EVENT_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_THREAT_EVENT_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gThreatEventLock, &oldIrql);

    header->DroppedEvents = gThreatDroppedEvents;

    for (link = gThreatEvents.Flink; link != &gThreatEvents; link = link->Flink) {
        bytesRequired += sizeof(DP_THREAT_EVENT_QUERY_ENTRY);
        eventCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_THREAT_EVENT_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_THREAT_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                             DP_THREAT_EVENT_ENTRY,
                                                             Link);
            RtlCopyMemory(cursor, &event->Event, sizeof(DP_THREAT_EVENT_QUERY_ENTRY));
            cursor += sizeof(DP_THREAT_EVENT_QUERY_ENTRY);
            bytesReturned += sizeof(DP_THREAT_EVENT_QUERY_ENTRY);
            returnedEventCount++;
        }
    }

    header->EventCount = eventCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (!sizingOnly && returnedEventCount == eventCount) {
        while (!IsListEmpty(&gThreatEvents)) {
            PLIST_ENTRY eventLink = RemoveHeadList(&gThreatEvents);
            PDP_THREAT_EVENT_ENTRY event = CONTAINING_RECORD(eventLink,
                                                             DP_THREAT_EVENT_ENTRY,
                                                             Link);
            gThreatEventCount--;
            KeReleaseSpinLock(&gThreatEventLock, oldIrql);
            DpThreatFreeEvent(event);
            KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&gThreatEventLock, oldIrql);

    if (sizingOnly) {
        return STATUS_SUCCESS;
    }

    if (returnedEventCount != eventCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpThreatEngineQueryProcesses(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_THREAT_PROCESS_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_THREAT_PROCESS_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_THREAT_PROCESS_QUERY_HEADER);
    ULONG processCount = 0;
    ULONG returnedCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_THREAT_PROCESS_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_THREAT_PROCESS_QUERY_HEADER)OutputBuffer;
    RtlZeroMemory(header, sizeof(DP_THREAT_PROCESS_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_THREAT_PROCESS_QUERY_HEADER);

    header->Version = DP_THREAT_PROCESS_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_THREAT_PROCESS_QUERY_HEADER);

    if (!gThreatInitialized) {
        header->BytesRequired = sizeof(DP_THREAT_PROCESS_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_THREAT_PROCESS_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);

    for (link = gThreatProcessOrder.Flink;
         link != &gThreatProcessOrder;
         link = link->Flink) {

        PDP_THREAT_PROCESS_NODE node = CONTAINING_RECORD(link,
                                                         DP_THREAT_PROCESS_NODE,
                                                         OrderLink);

        //
        // Only surface processes that actually carry risk so the board stays
        // focused on what matters.
        //
        if (node->CumulativeScore == 0) {
            continue;
        }

        bytesRequired += sizeof(DP_THREAT_PROCESS_QUERY_ENTRY);
        processCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_THREAT_PROCESS_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_THREAT_PROCESS_QUERY_ENTRY entry = (PDP_THREAT_PROCESS_QUERY_ENTRY)cursor;

            RtlZeroMemory(entry, sizeof(DP_THREAT_PROCESS_QUERY_ENTRY));
            entry->ProcessId = (ULONGLONG)(ULONG_PTR)node->ProcessId;
            entry->ParentProcessId = (ULONGLONG)(ULONG_PTR)node->ParentProcessId;
            entry->LineageRootPid = (ULONGLONG)(ULONG_PTR)node->LineageRootPid;
            entry->FirstSeen = node->FirstSeen;
            entry->LastActivity = node->LastActivity;
            entry->CumulativeScore = node->CumulativeScore;
            entry->Severity = (ULONG)DpThreatSeverityFromScore(node->CumulativeScore);
            entry->SignalCount = node->SignalCount;
            entry->DistinctTacticMask = node->DistinctTacticMask;
            entry->StrongestResponse = node->StrongestResponse;
            entry->Flags = node->Flags;

            if (node->ImageLengthBytes > 0) {
                ULONG copyBytes = min(node->ImageLengthBytes,
                                      (ULONG)((RTL_NUMBER_OF(entry->ProcessImage) - 1) * sizeof(WCHAR)));
                RtlCopyMemory(entry->ProcessImage, node->Image, copyBytes);
                entry->ProcessImage[copyBytes / sizeof(WCHAR)] = L'\0';
                entry->ProcessImageLengthBytes = copyBytes;
            }

            cursor += sizeof(DP_THREAT_PROCESS_QUERY_ENTRY);
            bytesReturned += sizeof(DP_THREAT_PROCESS_QUERY_ENTRY);
            returnedCount++;
        }
    }

    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    header->ProcessCount = processCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (returnedCount != processCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DpThreatEngineQueryStorylines(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_THREAT_STORY_QUERY_HEADER header;
    PUCHAR cursor;
    ULONG bytesRequired = sizeof(DP_THREAT_STORY_QUERY_HEADER);
    ULONG bytesReturned = sizeof(DP_THREAT_STORY_QUERY_HEADER);
    ULONG storyCount = 0;
    ULONG returnedCount = 0;
    PLIST_ENTRY link;
    KIRQL oldIrql;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_THREAT_STORY_QUERY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PDP_THREAT_STORY_QUERY_HEADER)OutputBuffer;
    RtlZeroMemory(header, sizeof(DP_THREAT_STORY_QUERY_HEADER));
    cursor = (PUCHAR)OutputBuffer + sizeof(DP_THREAT_STORY_QUERY_HEADER);

    header->Version = DP_THREAT_STORY_QUERY_VERSION;
    header->BytesReturned = sizeof(DP_THREAT_STORY_QUERY_HEADER);

    if (!gThreatInitialized) {
        header->BytesRequired = sizeof(DP_THREAT_STORY_QUERY_HEADER);
        *ReturnOutputBufferLength = sizeof(DP_THREAT_STORY_QUERY_HEADER);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&gThreatStoryLock, &oldIrql);

    header->DroppedStorylines = gThreatDroppedStorylines;

    for (link = gThreatStorylines.Flink; link != &gThreatStorylines; link = link->Flink) {
        PDP_THREAT_STORYLINE story = CONTAINING_RECORD(link, DP_THREAT_STORYLINE, Link);

        //
        // Only surface confirmed incidents; in-progress low-score lineages are
        // not yet a storyline worth presenting.
        //
        if (!story->IsIncident) {
            continue;
        }

        bytesRequired += sizeof(DP_THREAT_STORY_QUERY_ENTRY);
        storyCount++;

        if (bytesReturned <= OutputBufferLength &&
            sizeof(DP_THREAT_STORY_QUERY_ENTRY) <= OutputBufferLength - bytesReturned) {

            PDP_THREAT_STORY_QUERY_ENTRY entry = (PDP_THREAT_STORY_QUERY_ENTRY)cursor;
            ULONG i;
            ULONG ordered;

            RtlZeroMemory(entry, sizeof(DP_THREAT_STORY_QUERY_ENTRY));
            entry->IncidentId = story->IncidentId;
            entry->LineageRootPid = (ULONGLONG)(ULONG_PTR)story->LineageRootPid;
            entry->OriginProcessId = (ULONGLONG)(ULONG_PTR)story->OriginProcessId;
            entry->FirstSeen = story->FirstSeen;
            entry->LastActivity = story->LastActivity;
            entry->PeakScore = story->PeakScore;
            entry->Severity = story->Severity;
            entry->TacticMask = story->TacticMask;
            entry->StrongestResponse = story->StrongestResponse;
            entry->StepCount = story->StepCount;
            entry->TotalStepsObserved = story->TotalStepsObserved;

            if (story->RootImageLengthBytes != 0) {
                ULONG copyBytes = min(story->RootImageLengthBytes,
                                      (ULONG)((RTL_NUMBER_OF(entry->RootImage) - 1) * sizeof(WCHAR)));
                RtlCopyMemory(entry->RootImage, story->RootImage, copyBytes);
                entry->RootImage[copyBytes / sizeof(WCHAR)] = L'\0';
                entry->RootImageLengthBytes = copyBytes;
            }

            if (story->OriginImageLengthBytes != 0) {
                ULONG copyBytes = min(story->OriginImageLengthBytes,
                                      (ULONG)((RTL_NUMBER_OF(entry->OriginImage) - 1) * sizeof(WCHAR)));
                RtlCopyMemory(entry->OriginImage, story->OriginImage, copyBytes);
                entry->OriginImage[copyBytes / sizeof(WCHAR)] = L'\0';
                entry->OriginImageLengthBytes = copyBytes;
            }

            //
            // Emit steps in chronological order. When the ring has wrapped,
            // NextStep points at the oldest entry.
            //
            for (i = 0; i < story->StepCount; i++) {
                if (story->StepCount < DP_THREAT_STORY_MAX_STEPS) {
                    ordered = i;
                } else {
                    ordered = (story->NextStep + i) % DP_THREAT_STORY_MAX_STEPS;
                }
                entry->Steps[i] = story->Steps[ordered];
            }

            cursor += sizeof(DP_THREAT_STORY_QUERY_ENTRY);
            bytesReturned += sizeof(DP_THREAT_STORY_QUERY_ENTRY);
            returnedCount++;
        }
    }

    KeReleaseSpinLock(&gThreatStoryLock, oldIrql);

    header->StorylineCount = storyCount;
    header->BytesRequired = bytesRequired;
    header->BytesReturned = bytesReturned;
    *ReturnOutputBufferLength = bytesReturned;

    if (returnedCount != storyCount) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

VOID
DpThreatEngineClearEvents(
    VOID
    )
{
    KIRQL oldIrql;

    if (!gThreatInitialized) {
        return;
    }

    KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
    while (!IsListEmpty(&gThreatEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gThreatEvents);
        PDP_THREAT_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                         DP_THREAT_EVENT_ENTRY,
                                                         Link);
        gThreatEventCount--;
        KeReleaseSpinLock(&gThreatEventLock, oldIrql);
        DpThreatFreeEvent(event);
        KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gThreatEventLock, oldIrql);
}

NTSTATUS
DpThreatEngineSetPolicy(
    _In_ const DP_THREAT_ENGINE_POLICY *Policy
    )
{
    ULONG flags;

    if (Policy == NULL ||
        Policy->Version != DP_THREAT_ENGINE_POLICY_VERSION ||
        FlagOn(Policy->Flags, ~DP_THREAT_ENGINE_ALLOWED_FLAGS)) {

        return STATUS_INVALID_PARAMETER;
    }

    flags = Policy->Flags & DP_THREAT_ENGINE_ALLOWED_FLAGS;
    InterlockedExchange(&gThreatEngineFlags, (LONG)flags);

    if (Policy->BlockThreshold != 0) {
        InterlockedExchange(&gThreatBlockThreshold, (LONG)Policy->BlockThreshold);
    } else {
        InterlockedExchange(&gThreatBlockThreshold, DP_THREAT_SCORE_THRESHOLD_MEDIUM);
    }

    if (Policy->IsolateThreshold != 0) {
        InterlockedExchange(&gThreatIsolateThreshold, (LONG)Policy->IsolateThreshold);
    } else {
        InterlockedExchange(&gThreatIsolateThreshold, DP_THREAT_SCORE_THRESHOLD_HIGH);
    }

    if (Policy->TerminateThreshold != 0) {
        InterlockedExchange(&gThreatTerminateThreshold, (LONG)Policy->TerminateThreshold);
    } else {
        InterlockedExchange(&gThreatTerminateThreshold, DP_THREAT_SCORE_THRESHOLD_CRITICAL);
    }

    DP_THREAT_TRACE("policy updated flags=0x%08X block=%ld isolate=%ld terminate=%ld\n",
                    flags,
                    gThreatBlockThreshold,
                    gThreatIsolateThreshold,
                    gThreatTerminateThreshold);

    return STATUS_SUCCESS;
}

NTSTATUS
DpThreatEngineQueryPolicy(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PDP_THREAT_ENGINE_POLICY policy;

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = sizeof(DP_THREAT_ENGINE_POLICY);

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DP_THREAT_ENGINE_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    policy = (PDP_THREAT_ENGINE_POLICY)OutputBuffer;
    RtlZeroMemory(policy, sizeof(DP_THREAT_ENGINE_POLICY));
    policy->Version = DP_THREAT_ENGINE_POLICY_VERSION;
    policy->Flags = DpThreatReadFlags();
    policy->BlockThreshold = (ULONG)gThreatBlockThreshold;
    policy->IsolateThreshold = (ULONG)gThreatIsolateThreshold;
    policy->TerminateThreshold = (ULONG)gThreatTerminateThreshold;

    return STATUS_SUCCESS;
}

NTSTATUS
DpThreatEngineRespond(
    _In_ const DP_THREAT_RESPONSE_REQUEST *Request
    )
{
    PDP_THREAT_PROCESS_NODE node;
    KIRQL oldIrql;
    HANDLE targetPid;
    DP_THREAT_RESPONSE_ACTION action;
    BOOLEAN found = FALSE;

    if (Request == NULL ||
        Request->Version != DP_THREAT_RESPONSE_REQUEST_VERSION ||
        Request->ProcessId == 0) {

        return STATUS_INVALID_PARAMETER;
    }

    if (!gThreatInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    targetPid = (HANDLE)(ULONG_PTR)Request->ProcessId;
    action = (DP_THREAT_RESPONSE_ACTION)Request->Action;

    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
    node = DpThreatFindNodeLocked(targetPid);
    if (node != NULL) {
        found = TRUE;

        switch (action) {
        case DpThreatResponseIsolateNetwork:
            node->Flags |= DP_THREAT_PROC_FLAG_ISOLATED;
            if ((ULONG)action > node->StrongestResponse) {
                node->StrongestResponse = (ULONG)action;
            }
            break;

        case DpThreatResponseTerminate:
            node->Flags |= DP_THREAT_PROC_FLAG_ISOLATED;
            node->Flags |= DP_THREAT_PROC_FLAG_TERMINATE_REQ;
            if ((ULONG)action > node->StrongestResponse) {
                node->StrongestResponse = (ULONG)action;
            }
            break;

        case DpThreatResponseNone:
            //
            // Clearing isolation lets an operator release a process that was
            // contained on a false positive.
            //
            node->Flags &= ~(DP_THREAT_PROC_FLAG_ISOLATED | DP_THREAT_PROC_FLAG_TERMINATE_REQ);
            break;

        default:
            break;
        }
    }
    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);

    if (!found) {
        return STATUS_NOT_FOUND;
    }

    if (action == DpThreatResponseTerminate) {
        DpThreatEnqueueResponse(targetPid, DpThreatResponseTerminate);
    }

    DP_THREAT_TRACE("manual response pid=%p action=%lu\n",
                    targetPid,
                    (ULONG)action);

    return STATUS_SUCCESS;
}

NTSTATUS
DpThreatEngineInitialize(
    VOID
    )
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    ULONG i;

    for (i = 0; i < DP_THREAT_HASH_BUCKETS; i++) {
        InitializeListHead(&gThreatBuckets[i]);
    }

    InitializeListHead(&gThreatProcessOrder);
    InitializeListHead(&gThreatEvents);
    InitializeListHead(&gThreatStorylines);
    KeInitializeSpinLock(&gThreatProcessLock);
    KeInitializeSpinLock(&gThreatEventLock);
    KeInitializeSpinLock(&gThreatStoryLock);
    KeInitializeSpinLock(&gThreatResponseLock);
    KeInitializeSemaphore(&gThreatResponseSemaphore, 0, MAXLONG);

    gThreatProcessCount = 0;
    gThreatEventCount = 0;
    gThreatEventSequence = 0;
    gThreatDroppedEvents = 0;
    gThreatStorylineCount = 0;
    gThreatIncidentSequence = 0;
    gThreatDroppedStorylines = 0;
    gThreatResponseHead = 0;
    gThreatResponseTail = 0;
    gThreatResponseCount = 0;
    gThreatWorkerStop = 0;
    gThreatWorkerThread = NULL;

    InterlockedExchange(&gThreatEngineFlags, (LONG)DP_THREAT_ENGINE_DEFAULT_FLAGS);
    InterlockedExchange(&gThreatBlockThreshold, DP_THREAT_SCORE_THRESHOLD_MEDIUM);
    InterlockedExchange(&gThreatIsolateThreshold, DP_THREAT_SCORE_THRESHOLD_HIGH);
    InterlockedExchange(&gThreatTerminateThreshold, DP_THREAT_SCORE_THRESHOLD_CRITICAL);

    status = PsCreateSystemThread(&threadHandle,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL,
                                  NULL,
                                  DpThreatResponseWorker,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(threadHandle,
                                       THREAD_ALL_ACCESS,
                                       *PsThreadType,
                                       KernelMode,
                                       &gThreatWorkerThread,
                                       NULL);
    ZwClose(threadHandle);

    if (!NT_SUCCESS(status)) {
        //
        // The worker thread is running but we could not obtain a reference to
        // synchronize teardown. Signal it to stop and fail initialization.
        //
        InterlockedExchange(&gThreatWorkerStop, 1);
        KeReleaseSemaphore(&gThreatResponseSemaphore, IO_NO_INCREMENT, 1, FALSE);
        gThreatWorkerThread = NULL;
        return status;
    }

    gThreatInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
DpThreatEngineUninitialize(
    VOID
    )
{
    KIRQL oldIrql;
    ULONG i;

    gThreatInitialized = FALSE;

    //
    // Stop the response worker first so no termination work runs during
    // teardown.
    //
    if (gThreatWorkerThread != NULL) {
        InterlockedExchange(&gThreatWorkerStop, 1);
        KeReleaseSemaphore(&gThreatResponseSemaphore, IO_NO_INCREMENT, 1, FALSE);
        KeWaitForSingleObject(gThreatWorkerThread,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        ObDereferenceObject(gThreatWorkerThread);
        gThreatWorkerThread = NULL;
    }

    //
    // Drain events.
    //
    KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
    while (!IsListEmpty(&gThreatEvents)) {
        PLIST_ENTRY link = RemoveHeadList(&gThreatEvents);
        PDP_THREAT_EVENT_ENTRY event = CONTAINING_RECORD(link,
                                                         DP_THREAT_EVENT_ENTRY,
                                                         Link);
        gThreatEventCount--;
        KeReleaseSpinLock(&gThreatEventLock, oldIrql);
        DpThreatFreeEvent(event);
        KeAcquireSpinLock(&gThreatEventLock, &oldIrql);
    }
    KeReleaseSpinLock(&gThreatEventLock, oldIrql);

    //
    // Drain storylines.
    //
    KeAcquireSpinLock(&gThreatStoryLock, &oldIrql);
    while (!IsListEmpty(&gThreatStorylines)) {
        PLIST_ENTRY link = RemoveHeadList(&gThreatStorylines);
        PDP_THREAT_STORYLINE story = CONTAINING_RECORD(link,
                                                       DP_THREAT_STORYLINE,
                                                       Link);
        gThreatStorylineCount--;
        KeReleaseSpinLock(&gThreatStoryLock, oldIrql);
        ExFreePoolWithTag(story, DP_TAG_THREAT_STORY);
        KeAcquireSpinLock(&gThreatStoryLock, &oldIrql);
    }
    KeReleaseSpinLock(&gThreatStoryLock, oldIrql);

    //
    // Drain the process table.
    //
    KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
    while (!IsListEmpty(&gThreatProcessOrder)) {
        PLIST_ENTRY link = RemoveHeadList(&gThreatProcessOrder);
        PDP_THREAT_PROCESS_NODE node = CONTAINING_RECORD(link,
                                                         DP_THREAT_PROCESS_NODE,
                                                         OrderLink);
        RemoveEntryList(&node->BucketLink);
        gThreatProcessCount--;
        KeReleaseSpinLock(&gThreatProcessLock, oldIrql);
        ExFreePoolWithTag(node, DP_TAG_THREAT_PROCESS);
        KeAcquireSpinLock(&gThreatProcessLock, &oldIrql);
    }

    for (i = 0; i < DP_THREAT_HASH_BUCKETS; i++) {
        InitializeListHead(&gThreatBuckets[i]);
    }

    KeReleaseSpinLock(&gThreatProcessLock, oldIrql);
}
