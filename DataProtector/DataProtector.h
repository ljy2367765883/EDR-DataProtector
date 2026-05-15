/*++

Module Name:

    DataProtector.h

Abstract:

    Shared declarations for the DataProtector transparent encryption
    minifilter.

--*/

#pragma once

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define DP_TAG_IO_CONTEXT      'cIpD'
#define DP_TAG_IO_BUFFER       'bIpD'
#define DP_TAG_STREAM_CONTEXT  'sCpD'
#define DP_TAG_HANDLE_CONTEXT  'hCpD'
#define DP_TAG_NAME_BUFFER     'nSpD'
#define DP_TAG_SHADOW_BUFFER   'bSpD'
#define DP_TAG_RENAME_CONTEXT  'rCpD'
#define DP_TAG_POLICY_RULE     'rPpD'
#define DP_TAG_PROCESS_ENTRY   'pPpD'

#define DP_POLICY_MAX_RULE_BYTES (1024 * sizeof(WCHAR))
#define DP_POLICY_MAX_EXTENSION_BYTES (64 * sizeof(WCHAR))
#define DP_POLICY_DEFAULT_EXTENSION L".dpf"
#define DP_POLICY_PORT_NAME      L"\\DataProtectorPolicyPort"

#define DP_TRACE_ROUTINES      0x00000001
#define DP_TRACE_IO            0x00000002
#define DP_TRACE_POLICY        0x00000004
#define DP_TRACE_SHADOW        0x00000008

//
// Targeted WPS/Office investigation switch. Set to 0 for normal builds.
// When enabled, the driver emits DbgPrintEx lines only for .pptx paths
// and their DataProtector ADS streams.
//
#define DP_ENABLE_PPTX_OPERATION_TRACE 1

//
// Cached transparent encryption keeps plaintext in the system file cache.
// Manual unload is therefore unsafe unless a separate safe-stop path flushes
// and purges protected streams first.
//
#define DP_ALLOW_MANUAL_UNLOAD 1

//
// Production builds must obtain trust decisions from a signed policy source
// such as a protected user-mode service plus process creation cache. The
// built-in process-name list is only for local bring-up.
//
#define DP_ENABLE_TEST_TRUSTED_PROCESSES 1

//
// The XOR provider is only useful for I/O pipeline validation. Production
// builds must replace DpCrypto.c with an authenticated, key-managed provider.
// When no provider is available, the driver still loads but protected
// plaintext I/O fails closed.
//
#define DP_ENABLE_TEST_CRYPTO_PROVIDER 1

//
// Never enable this in a production isolation model. It exists only as a
// diagnostic switch for studying Cache Manager behavior. The stable design
// redirects trusted memory-mapped applications to a shadow plaintext file.
//
#define DP_ENABLE_UNSAFE_PLAINTEXT_CACHE_FOR_MAPPED_IO 0

extern PFLT_FILTER gDataProtectorFilter;
extern ULONG gDataProtectorTraceFlags;

#define DP_DBG_PRINT(_level, _args)                         \
    (FlagOn(gDataProtectorTraceFlags, (_level)) ?           \
        DbgPrint _args :                                    \
        ((int)0))

typedef enum _DP_IO_OPERATION {
    DpIoRead = 1,
    DpIoWrite = 2
} DP_IO_OPERATION;

typedef struct _DP_IO_CONTEXT {
    DP_IO_OPERATION Operation;
    PFLT_INSTANCE Instance;
    PVOID SwapBuffer;
    ULONG Length;
    ULONG SwapBufferLength;
    PVOID OriginalBuffer;
    PMDL OriginalMdl;
    LARGE_INTEGER ByteOffset;
    BOOLEAN TransformInPlace;
} DP_IO_CONTEXT, *PDP_IO_CONTEXT;

typedef struct _DP_STREAM_CONTEXT {
    BOOLEAN IsProtected;
    BOOLEAN PlaintextCacheEnabled;
} DP_STREAM_CONTEXT, *PDP_STREAM_CONTEXT;

typedef struct _DP_HANDLE_CONTEXT {
    BOOLEAN IsProtected;
    BOOLEAN IsTrusted;
    BOOLEAN IsShadow;
    BOOLEAN ShadowDirty;
    BOOLEAN EncryptOnCleanup;
    UNICODE_STRING OriginalName;
    UNICODE_STRING ShadowName;
    UNICODE_STRING PendingName;
} DP_HANDLE_CONTEXT, *PDP_HANDLE_CONTEXT;

typedef struct _DP_CREATE_CONTEXT {
    BOOLEAN IsTrusted;
    BOOLEAN IsShadow;
    BOOLEAN ShadowDirty;
    UNICODE_STRING OriginalName;
    UNICODE_STRING ShadowName;
} DP_CREATE_CONTEXT, *PDP_CREATE_CONTEXT;

typedef enum _DP_PROCESS_TRUST_RULE_TYPE {
    DpProcessTrustRuleImageName = 1,
    DpProcessTrustRuleImageDirectory = 2,
    DpProcessTrustRuleExcludedDirectory = 3
} DP_PROCESS_TRUST_RULE_TYPE;

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

#define DP_POLICY_MESSAGE_VERSION 1
#define DP_POLICY_MESSAGE_HEADER_SIZE FIELD_OFFSET(DP_POLICY_MESSAGE, Data)

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

#define DP_POLICY_QUERY_VERSION 1
#define DP_POLICY_QUERY_ENTRY_HEADER_SIZE FIELD_OFFSET(DP_POLICY_QUERY_ENTRY, Data)

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DataProtectorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
DataProtectorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
DataProtectorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
DataProtectorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
DataProtectorUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
DpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
DpPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DpPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
DpPreFastIoCheckIfPossible(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
DpProcessPolicyIsTrusted(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING FileName
    );

BOOLEAN
DpProcessPolicyNameHasProtectedExtension(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpProcessPolicyNameIsExcluded(
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpProcessPolicyInitialize(
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
DpProcessPolicyUninitialize(
    VOID
    );

NTSTATUS
DpProcessPolicyAddRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    );

NTSTATUS
DpProcessPolicyRemoveRule(
    _In_ DP_PROCESS_TRUST_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Extension
    );

VOID
DpProcessPolicyClearRules(
    VOID
    );

NTSTATUS
DpProcessPolicyQueryRules(
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
DpControlInitialize(
    VOID
    );

VOID
DpControlUninitialize(
    VOID
    );

NTSTATUS
DpGetHandleTrust(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected,
    _Out_ PBOOLEAN IsTrusted
    );

NTSTATUS
DpGetHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PDP_HANDLE_CONTEXT *HandleContext
    );

VOID
DpReleaseHandleContext(
    _In_opt_ PDP_HANDLE_CONTEXT HandleContext
    );

PDP_IO_CONTEXT
DpAllocateIoContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ DP_IO_OPERATION Operation,
    _In_ ULONG Length
    );

VOID
DpFreeIoContext(
    _In_opt_ PDP_IO_CONTEXT Context
    );

NTSTATUS
DpCryptoInitialize(
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
DpCryptoUninitialize(
    VOID
    );

BOOLEAN
DpCryptoIsReady(
    VOID
    );

VOID
DpCryptoTransformBuffer(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset
    );

BOOLEAN
DpPolicyNameIsProtected(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpPolicyNameIsExcluded(
    _In_ PCUNICODE_STRING Name
    );

BOOLEAN
DpPolicyNameIsShadow(
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpPolicyRefreshStreamContext(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpPolicyFileHasProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name,
    _Out_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicyWriteProtectionMarker(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name
    );

NTSTATUS
DpPolicyIsProtectedStream(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsProtected
    );

NTSTATUS
DpPolicySetStreamProtection(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IsProtected
    );

NTSTATUS
DpPolicyEnablePlaintextCache(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpPolicyIsPlaintextCacheEnabled(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN PlaintextCacheEnabled
    );

NTSTATUS
DpShadowPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PDP_CREATE_CONTEXT *CreateContext
    );

NTSTATUS
DpShadowPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PDP_CREATE_CONTEXT CreateContext,
    _Outptr_result_maybenull_ PDP_HANDLE_CONTEXT *HandleContext
    );

NTSTATUS
DpShadowCleanupHandle(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PDP_HANDLE_CONTEXT HandleContext
    );

NTSTATUS
DpShadowMarkHandleDirty(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
DpShadowEncryptFileObjectInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

NTSTATUS
DpShadowEncryptFileInPlace(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING FileName
    );

NTSTATUS
DpShadowTruncateFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

VOID
DpShadowFreeCreateContext(
    _In_opt_ PDP_CREATE_CONTEXT CreateContext
    );

BOOLEAN
DpShadowIsInternalIo(
    VOID
    );

VOID
DpShadowInitialize(
    VOID
    );

VOID
DpShadowUninitialize(
    VOID
    );

VOID
DpStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

VOID
DpHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

#if DP_ENABLE_PPTX_OPERATION_TRACE

BOOLEAN
DpTraceNameIsPptx(
    _In_opt_ PCUNICODE_STRING Name
    );

VOID
DpTracePptxName(
    _In_z_ PCSTR Operation,
    _In_opt_ PCUNICODE_STRING Name,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2,
    _In_ ULONG_PTR Detail3,
    _In_ ULONG_PTR Detail4
    );

VOID
DpTracePptxCallbackData(
    _In_z_ PCSTR Operation,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2,
    _In_ ULONG_PTR Detail3,
    _In_ ULONG_PTR Detail4
    );

#define DP_TRACE_PPTX_NAME(_operation, _name, _status, _detail1, _detail2, _detail3, _detail4) \
    DpTracePptxName((_operation), (_name), (_status), (ULONG_PTR)(_detail1), (ULONG_PTR)(_detail2), (ULONG_PTR)(_detail3), (ULONG_PTR)(_detail4))

#define DP_TRACE_PPTX_DATA(_operation, _data, _fltObjects, _status, _detail1, _detail2, _detail3, _detail4) \
    DpTracePptxCallbackData((_operation), (_data), (_fltObjects), (_status), (ULONG_PTR)(_detail1), (ULONG_PTR)(_detail2), (ULONG_PTR)(_detail3), (ULONG_PTR)(_detail4))

#else

#define DP_TRACE_PPTX_NAME(_operation, _name, _status, _detail1, _detail2, _detail3, _detail4) ((void)0)
#define DP_TRACE_PPTX_DATA(_operation, _data, _fltObjects, _status, _detail1, _detail2, _detail3, _detail4) ((void)0)

#endif

EXTERN_C_END
