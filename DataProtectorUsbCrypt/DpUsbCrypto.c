#include "DataProtectorUsbCrypt.h"

VOID
DpUsbRc4Initialize(
    _Out_ PDPUSB_RC4_STATE State,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    )
{
    ULONG index;
    UCHAR j = 0;

    RtlZeroMemory(State, sizeof(*State));
    if (Key == NULL || KeyLength == 0) {
        return;
    }

    for (index = 0; index < 256; index++) {
        State->S[index] = (UCHAR)index;
    }

    for (index = 0; index < 256; index++) {
        UCHAR swap;
        j = (UCHAR)(j + State->S[index] + Key[index % KeyLength]);
        swap = State->S[index];
        State->S[index] = State->S[j];
        State->S[j] = swap;
    }

    State->I = 0;
    State->J = 0;
}

VOID
DpUsbRc4Apply(
    _Inout_ PDPUSB_RC4_STATE State,
    _Inout_updates_bytes_(Length) UCHAR *Buffer,
    _In_ ULONG Length
    )
{
    ULONG index;

    if (State == NULL || Buffer == NULL || Length == 0) {
        return;
    }

    for (index = 0; index < Length; index++) {
        UCHAR swap;
        UCHAR keyByte;

        State->I = (UCHAR)(State->I + 1);
        State->J = (UCHAR)(State->J + State->S[State->I]);

        swap = State->S[State->I];
        State->S[State->I] = State->S[State->J];
        State->S[State->J] = swap;

        keyByte = State->S[(UCHAR)(State->S[State->I] + State->S[State->J])];
        Buffer[index] ^= keyByte;
    }
}

VOID
DpUsbRc4CryptAtOffsetLegacy(
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR *Buffer,
    _In_ ULONG Length
    )
{
    DPUSB_RC4_STATE state;
    UCHAR discard[256];
    ULONGLONG remaining;

    if (Key == NULL || KeyLength == 0 || Buffer == NULL || Length == 0) {
        return;
    }

    DpUsbRc4Initialize(&state, Key, KeyLength);

    remaining = Offset;
    while (remaining != 0) {
        ULONG chunk = remaining > sizeof(discard) ? (ULONG)sizeof(discard) : (ULONG)remaining;
        RtlZeroMemory(discard, chunk);
        DpUsbRc4Apply(&state, discard, chunk);
        remaining -= chunk;
    }

    DpUsbRc4Apply(&state, Buffer, Length);
    RtlSecureZeroMemory(discard, sizeof(discard));
    RtlSecureZeroMemory(&state, sizeof(state));
}

VOID
DpUsbRc4CryptAtOffset(
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR *Buffer,
    _In_ ULONG Length
    )
{
    DPUSB_RC4_STATE state;
    UCHAR blockKey[DPUSB_MAX_KEY_BYTES + sizeof(ULONGLONG)];
    UCHAR discard[256];
    ULONGLONG blockIndex;
    ULONG blockOffset;
    ULONG remaining;

    if (Key == NULL || KeyLength == 0 || Buffer == NULL || Length == 0) {
        return;
    }

    if (KeyLength > DPUSB_MAX_KEY_BYTES) {
        return;
    }

    remaining = Length;
    while (remaining != 0) {
        ULONG chunk;

        blockIndex = Offset / DPUSB_CRYPTO_BLOCK_BYTES;
        blockOffset = (ULONG)(Offset % DPUSB_CRYPTO_BLOCK_BYTES);
        chunk = DPUSB_CRYPTO_BLOCK_BYTES - blockOffset;
        if (chunk > remaining) {
            chunk = remaining;
        }

        RtlCopyMemory(blockKey, Key, KeyLength);
        RtlCopyMemory(blockKey + KeyLength, &blockIndex, sizeof(blockIndex));
        DpUsbRc4Initialize(&state, blockKey, KeyLength + (ULONG)sizeof(blockIndex));

        if (blockOffset != 0) {
            ULONG discardRemaining = blockOffset;
            while (discardRemaining != 0) {
                ULONG discardChunk = discardRemaining > sizeof(discard) ?
                    (ULONG)sizeof(discard) :
                    discardRemaining;
                RtlZeroMemory(discard, discardChunk);
                DpUsbRc4Apply(&state, discard, discardChunk);
                discardRemaining -= discardChunk;
            }
        }

        DpUsbRc4Apply(&state, Buffer, chunk);
        Buffer += chunk;
        Offset += chunk;
        remaining -= chunk;
    }

    RtlSecureZeroMemory(blockKey, sizeof(blockKey));
    RtlSecureZeroMemory(discard, sizeof(discard));
    RtlSecureZeroMemory(&state, sizeof(state));
}
