namespace Glacier.Codec.Cryptography.AesGcmSiv;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Hardware;

/// <summary>
/// RFC 8452 Section 3 POLYVAL universal hash over GF(2^128), implemented via the
/// Appendix A byte-reversal equivalence to hardware-accelerated PCLMULQDQ / scalar GHASH.
/// </summary>
internal static class PolyvalKernel
{
    private const ulong GhashPolyR = 0xE100000000000000UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ByteReverse16(ReadOnlySpan<byte> src, Span<byte> dst)
    {
        ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(src.Slice(0, 8));
        ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(src.Slice(8, 8));
        BinaryPrimitives.WriteUInt64LittleEndian(dst.Slice(0, 8), BinaryPrimitives.ReverseEndianness(hi));
        BinaryPrimitives.WriteUInt64LittleEndian(dst.Slice(8, 8), BinaryPrimitives.ReverseEndianness(lo));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MulX_Ghash(ref ulong hi, ref ulong lo)
    {
        ulong lsbMask = (ulong)-(long)(lo & 1UL);
        lo = (lo >> 1) | (hi << 63);
        hi = (hi >> 1) ^ (GhashPolyR & lsbMask);
    }

    /// <summary>
    /// Computes POLYVAL(authKey, aad, plaintext, le64(aadBits) || le64(ptBits)) for AES-GCM-SIV,
    /// or raw POLYVAL over blocks when <paramref name="includeLengthBlock"/> is false.
    /// </summary>
    public static void ComputePolyval(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        bool includeLengthBlock = true)
    {
        // RFC 8452 Appendix A:
        // POLYVAL(H, X_1, ..., X_n) = ByteReverse16(GHASH(mulX_GHASH(ByteReverse16(H)), ByteReverse16(X_1), ..., ByteReverse16(X_n)))
        Span<byte> hRev = stackalloc byte[16];
        ByteReverse16(authKey.Slice(0, 16), hRev);

        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hRev.Slice(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hRev.Slice(8, 8));
        MulX_Ghash(ref hHi, ref hLo);

        ulong yHi = 0;
        ulong yLo = 0;
        Span<byte> padded = stackalloc byte[16];
        Span<byte> revBlock = stackalloc byte[16];

        if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasPclmulqdq)
        {
            Vector128<ulong> h1 = Vector128.Create(hLo, hHi);

            FeedPaddedBlocksPclmul(aad, ref yHi, ref yLo, h1, padded, revBlock);
            FeedPaddedBlocksPclmul(plaintext, ref yHi, ref yLo, h1, padded, revBlock);

            if (includeLengthBlock)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(padded.Slice(0, 8), (ulong)aad.Length * 8UL);
                BinaryPrimitives.WriteUInt64LittleEndian(padded.Slice(8, 8), (ulong)plaintext.Length * 8UL);
                ByteReverse16(padded, revBlock);
                AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, revBlock, h1);
            }
        }
        else
        {
            FeedPaddedBlocksScalar(aad, ref yHi, ref yLo, hHi, hLo, padded, revBlock);
            FeedPaddedBlocksScalar(plaintext, ref yHi, ref yLo, hHi, hLo, padded, revBlock);

            if (includeLengthBlock)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(padded.Slice(0, 8), (ulong)aad.Length * 8UL);
                BinaryPrimitives.WriteUInt64LittleEndian(padded.Slice(8, 8), (ulong)plaintext.Length * 8UL);
                ByteReverse16(padded, revBlock);
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, revBlock, hHi, hLo);
            }
        }

        // Write GHASH state as big-endian 16 bytes into padded, then ByteReverse16 into destination
        BinaryPrimitives.WriteUInt64BigEndian(padded.Slice(0, 8), yHi);
        BinaryPrimitives.WriteUInt64BigEndian(padded.Slice(8, 8), yLo);
        ByteReverse16(padded, destination);
    }

    private static void FeedPaddedBlocksPclmul(
        ReadOnlySpan<byte> data,
        ref ulong yHi,
        ref ulong yLo,
        Vector128<ulong> h1,
        Span<byte> padded,
        Span<byte> revBlock)
    {
        int offset = 0;
        while (offset + 16 <= data.Length)
        {
            ByteReverse16(data.Slice(offset, 16), revBlock);
            AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, revBlock, h1);
            offset += 16;
        }

        if (offset < data.Length)
        {
            padded.Clear();
            data.Slice(offset).CopyTo(padded);
            ByteReverse16(padded, revBlock);
            AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, revBlock, h1);
        }
    }

    private static void FeedPaddedBlocksScalar(
        ReadOnlySpan<byte> data,
        ref ulong yHi,
        ref ulong yLo,
        ulong hHi,
        ulong hLo,
        Span<byte> padded,
        Span<byte> revBlock)
    {
        int offset = 0;
        while (offset + 16 <= data.Length)
        {
            ByteReverse16(data.Slice(offset, 16), revBlock);
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, revBlock, hHi, hLo);
            offset += 16;
        }

        if (offset < data.Length)
        {
            padded.Clear();
            data.Slice(offset).CopyTo(padded);
            ByteReverse16(padded, revBlock);
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, revBlock, hHi, hLo);
        }
    }
}
