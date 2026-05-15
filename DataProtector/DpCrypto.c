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
    _In_ ULONGLONG Position
    )
{
    return gDpKeyStream[Position % RTL_NUMBER_OF(gDpKeyStream)];
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
DpCryptoTransformBuffer(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset
    )
{
#if DP_ENABLE_TEST_CRYPTO_PROVIDER
    ULONG index;
    ULONGLONG baseOffset;

    if (Buffer == NULL || Length == 0) {
        return;
    }

    baseOffset = (ULONGLONG)ByteOffset.QuadPart;

    for (index = 0; index < Length; index++) {
        Buffer[index] ^= DpCryptoKeyByte(baseOffset + index);
    }
#else
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ByteOffset);
#endif
}
