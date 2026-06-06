/*++

Module Name:

    DpCrypto.c

Abstract:

    Replaceable stream transformation provider used by the transparent
    encryption I/O path.

--*/

#include "DataProtector.h"

#if DP_ENABLE_TEST_CRYPTO_PROVIDER

#define DP_DEFAULT_KEY_SEED 0xA7u

static UCHAR gDpKeyStream[32];

static
UCHAR
DpCryptoKeyByte(
    _In_ ULONGLONG Position,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    )
{
    return Key[Position % KeyLength];
}

#endif // DP_ENABLE_TEST_CRYPTO_PROVIDER

NTSTATUS
DpCryptoInitialize(
    _In_ PUNICODE_STRING RegistryPath
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    ULONG index;
#endif

    UNREFERENCED_PARAMETER(RegistryPath);

#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    for (index = 0; index < RTL_NUMBER_OF(gDpKeyStream); index++) {
        gDpKeyStream[index] = (UCHAR)(DP_DEFAULT_KEY_SEED + (index * 37u));
    }

    return STATUS_SUCCESS;
#else
    return STATUS_SUCCESS;
#endif
}

VOID
DpCryptoUninitialize(
    VOID
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    RtlSecureZeroMemory(gDpKeyStream, sizeof(gDpKeyStream));
#endif
}

BOOLEAN
DpCryptoIsReady(
    VOID
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    return TRUE;
#else
    return FALSE;
#endif
}

VOID
DpCryptoTransformBufferWithKey(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    ULONG index;
    ULONGLONG baseOffset;

    if (Buffer == NULL || Length == 0 || Key == NULL || KeyLength == 0) {
        return;
    }

    baseOffset = (ULONGLONG)ByteOffset.QuadPart;

    for (index = 0; index < Length; index++) {
        Buffer[index] ^= DpCryptoKeyByte(baseOffset + index, Key, KeyLength);
    }
#else
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ByteOffset);
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeyLength);
#endif
}

VOID
DpCryptoTransformBuffer(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    DpCryptoTransformBufferWithKey(Buffer,
                                   Length,
                                   ByteOffset,
                                   gDpKeyStream,
                                   RTL_NUMBER_OF(gDpKeyStream));
#else
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ByteOffset);
#endif
}

VOID
DpCryptoGetDefaultFileKey(
    _Out_writes_bytes_(DP_FILE_KEY_LENGTH) UCHAR *Key,
    _Out_ PULONG KeyLength
    )
{
    if (KeyLength != NULL) {
        *KeyLength = 0;
    }

    if (Key == NULL || KeyLength == NULL) {
        return;
    }

#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    RtlZeroMemory(Key, DP_FILE_KEY_LENGTH);
    RtlCopyMemory(Key, gDpKeyStream, min((ULONG)sizeof(gDpKeyStream), (ULONG)DP_FILE_KEY_LENGTH));
    *KeyLength = min((ULONG)sizeof(gDpKeyStream), (ULONG)DP_FILE_KEY_LENGTH);
#else
    RtlZeroMemory(Key, DP_FILE_KEY_LENGTH);
#endif
}
