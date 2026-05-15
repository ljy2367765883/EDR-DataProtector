/*++

Module Name:

    DpTrace.c

Abstract:

    Targeted diagnostic logging helpers.

--*/

#include "DataProtector.h"

#if DP_ENABLE_PPTX_OPERATION_TRACE

static
WCHAR
DpTraceLowerWide(
    _In_ WCHAR Character
    )
{
    if (Character >= L'A' && Character <= L'Z') {
        return (WCHAR)(Character - L'A' + L'a');
    }

    return Character;
}

static
BOOLEAN
DpTracePptxSuffixAt(
    _In_reads_(CharacterCount) const WCHAR *Buffer,
    _In_ USHORT CharacterCount,
    _In_ USHORT Index
    )
{
    static const WCHAR extension[] = L".pptx";
    USHORT extensionIndex;
    USHORT extensionChars = RTL_NUMBER_OF(extension) - 1;
    USHORT nextIndex;

    if (Index > CharacterCount ||
        CharacterCount - Index < extensionChars) {

        return FALSE;
    }

    for (extensionIndex = 0; extensionIndex < extensionChars; extensionIndex++) {
        if (DpTraceLowerWide(Buffer[Index + extensionIndex]) != extension[extensionIndex]) {
            return FALSE;
        }
    }

    nextIndex = Index + extensionChars;
    if (nextIndex == CharacterCount) {
        return TRUE;
    }

    return Buffer[nextIndex] == L':';
}

BOOLEAN
DpTraceNameIsPptx(
    _In_opt_ PCUNICODE_STRING Name
    )
{
    USHORT index;
    USHORT characters;

    if (Name == NULL ||
        Name->Buffer == NULL ||
        Name->Length < sizeof(L".pptx") - sizeof(WCHAR)) {

        return FALSE;
    }

    characters = Name->Length / sizeof(WCHAR);
    for (index = 0; index < characters; index++) {
        if (DpTraceLowerWide(Name->Buffer[index]) == L'.' &&
            DpTracePptxSuffixAt(Name->Buffer, characters, index)) {

            return TRUE;
        }
    }

    return FALSE;
}

VOID
DpTracePptxName(
    _In_z_ PCSTR Operation,
    _In_opt_ PCUNICODE_STRING Name,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Detail1,
    _In_ ULONG_PTR Detail2,
    _In_ ULONG_PTR Detail3,
    _In_ ULONG_PTR Detail4
    )
{
    if (!DpTraceNameIsPptx(Name)) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "DataProtector[PPTX] op=%s pid=%p status=0x%08X d1=%Iu d2=%Iu d3=%Iu d4=%Iu name=%wZ\n",
               Operation,
               PsGetCurrentProcessId(),
               Status,
               Detail1,
               Detail2,
               Detail3,
               Detail4,
               Name);
}

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
    )
{
    NTSTATUS nameStatus;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    if (Data == NULL ||
        FltObjects == NULL ||
        FltObjects->FileObject == NULL) {

        return;
    }

    nameStatus = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);

    if (!NT_SUCCESS(nameStatus)) {
        return;
    }

    if (DpTraceNameIsPptx(&nameInfo->Name)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "DataProtector[PPTX] op=%s pid=%p major=0x%02X minor=0x%02X status=0x%08X d1=%Iu d2=%Iu d3=%Iu d4=%Iu name=%wZ\n",
                   Operation,
                   PsGetCurrentProcessId(),
                   Data->Iopb != NULL ? Data->Iopb->MajorFunction : 0,
                   Data->Iopb != NULL ? Data->Iopb->MinorFunction : 0,
                   Status,
                   Detail1,
                   Detail2,
                   Detail3,
                   Detail4,
                   &nameInfo->Name);
    }

    FltReleaseFileNameInformation(nameInfo);
}

#endif
