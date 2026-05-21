/*++

Module Name:

    DpBuffer.c

Abstract:

    Double-buffer allocation helpers for the transparent encryption path.

--*/

#include "DataProtector.h"

PDP_IO_CONTEXT
DpAllocateIoContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ DP_IO_OPERATION Operation,
    _In_ ULONG Length
    )
{
    PDP_IO_CONTEXT context;

    context = ExAllocatePoolWithTag(NonPagedPoolNx,
                                    sizeof(DP_IO_CONTEXT),
                                    DP_TAG_IO_CONTEXT);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DP_IO_CONTEXT));

    context->SwapBuffer = FltAllocatePoolAlignedWithTag(Instance,
                                                        NonPagedPoolNx,
                                                        Length,
                                                        DP_TAG_IO_BUFFER);

    if (context->SwapBuffer == NULL) {
        ExFreePoolWithTag(context, DP_TAG_IO_CONTEXT);
        return NULL;
    }

    RtlZeroMemory(context->SwapBuffer, Length);
    context->Instance = Instance;
    context->Operation = Operation;
    context->Length = Length;
    context->SwapBufferLength = Length;
    DpCryptoGetDefaultFileKey(context->FileKey, &context->FileKeyLength);

    return context;
}

PDP_IO_CONTEXT
DpAllocateAuditIoContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ DP_IO_OPERATION Operation,
    _In_ ULONG Length
    )
{
    PDP_IO_CONTEXT context;

    context = ExAllocatePoolWithTag(NonPagedPoolNx,
                                    sizeof(DP_IO_CONTEXT),
                                    DP_TAG_IO_CONTEXT);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DP_IO_CONTEXT));
    context->Instance = Instance;
    context->Operation = Operation;
    context->Length = Length;
    context->FileHunterAuditOnly = TRUE;

    return context;
}

VOID
DpFreeIoContext(
    _In_opt_ PDP_IO_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (Context->SwapBuffer != NULL) {
        RtlSecureZeroMemory(Context->SwapBuffer, Context->SwapBufferLength);
        FltFreePoolAlignedWithTag(Context->Instance,
                                  Context->SwapBuffer,
                                  DP_TAG_IO_BUFFER);
        Context->SwapBuffer = NULL;
    }

    if (Context->HandleContext != NULL) {
        FltReleaseContext(Context->HandleContext);
        Context->HandleContext = NULL;
    }

    if (Context->FileHunterContext != NULL) {
        DpFileHunterFreeReadContext(Context->FileHunterContext);
        Context->FileHunterContext = NULL;
    }

    ExFreePoolWithTag(Context, DP_TAG_IO_CONTEXT);
}
