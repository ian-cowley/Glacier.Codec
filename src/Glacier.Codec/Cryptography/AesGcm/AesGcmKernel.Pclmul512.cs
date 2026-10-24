namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Hardware-accelerated multi-block parallel carryless multiplication GHASH using 512-bit VPCLMULQDQ.
/// Aggregates 8 independent blocks (128 bytes) per step with single amortized reduction.
/// </summary>
internal static unsafe class AesGcmKernelPclmul512
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<ulong> Fold512(Vector512<ulong> v)
    {
        Vector256<ulong> v256 = v.GetLower() ^ v.GetUpper();
        return v256.GetLower() ^ v256.GetUpper();
    }

    private static readonly Vector512<byte> ByteReverseMask512 = Vector512.Create(
        (byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Ghash8Blocks(
        ref ulong yHi,
        ref ulong yLo,
        byte* pBlocks,
        Vector512<ulong> h8to5,
        Vector512<ulong> h4to1)
    {
        Vector512<ulong> xA = Avx512BW.Shuffle(Vector512.Load(pBlocks), ByteReverseMask512).AsUInt64();
        Vector512<ulong> xB = Avx512BW.Shuffle(Vector512.Load(pBlocks + 64), ByteReverseMask512).AsUInt64();

        Vector512<ulong> yInit = Vector512.Create(yLo, yHi, 0, 0, 0, 0, 0, 0);
        xA ^= yInit;

        Vector512<ulong> z0_512 = Pclmulqdq.V512.CarrylessMultiply(xA, h8to5, 0x00) ^
                                  Pclmulqdq.V512.CarrylessMultiply(xB, h4to1, 0x00);

        Vector512<ulong> z1_512 = (Pclmulqdq.V512.CarrylessMultiply(xA, h8to5, 0x01) ^
                                   Pclmulqdq.V512.CarrylessMultiply(xA, h8to5, 0x10)) ^
                                  (Pclmulqdq.V512.CarrylessMultiply(xB, h4to1, 0x01) ^
                                   Pclmulqdq.V512.CarrylessMultiply(xB, h4to1, 0x10));

        Vector512<ulong> z2_512 = Pclmulqdq.V512.CarrylessMultiply(xA, h8to5, 0x11) ^
                                  Pclmulqdq.V512.CarrylessMultiply(xB, h4to1, 0x11);

        Vector128<ulong> z0 = Fold512(z0_512);
        Vector128<ulong> z1 = Fold512(z1_512);
        Vector128<ulong> z2 = Fold512(z2_512);

        AesGcmKernelPclmul.Reduce(z0, z1, z2, out yHi, out yLo);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Ghash4Blocks(
        ref ulong yHi,
        ref ulong yLo,
        byte* pBlocks,
        Vector512<ulong> h4to1)
    {
        Vector512<ulong> x = Avx512BW.Shuffle(Vector512.Load(pBlocks), ByteReverseMask512).AsUInt64();
        Vector512<ulong> yInit = Vector512.Create(yLo, yHi, 0, 0, 0, 0, 0, 0);
        x ^= yInit;

        Vector512<ulong> z0_512 = Pclmulqdq.V512.CarrylessMultiply(x, h4to1, 0x00);
        Vector512<ulong> z1_512 = Pclmulqdq.V512.CarrylessMultiply(x, h4to1, 0x01) ^
                                  Pclmulqdq.V512.CarrylessMultiply(x, h4to1, 0x10);
        Vector512<ulong> z2_512 = Pclmulqdq.V512.CarrylessMultiply(x, h4to1, 0x11);

        Vector128<ulong> z0 = Fold512(z0_512);
        Vector128<ulong> z1 = Fold512(z1_512);
        Vector128<ulong> z2 = Fold512(z2_512);

        AesGcmKernelPclmul.Reduce(z0, z1, z2, out yHi, out yLo);
    }

    public static void ProcessBlocks(
        ref ulong yHi,
        ref ulong yLo,
        ReadOnlySpan<byte> data,
        Vector512<ulong> h8to5,
        Vector512<ulong> h4to1,
        Vector128<ulong> h1,
        Vector128<ulong> h2,
        Vector128<ulong> h3,
        Vector128<ulong> h4)
    {
        int offset = 0;
        int length = data.Length;

        fixed (byte* pData = data)
        {
            while (offset + 128 <= length)
            {
                Ghash8Blocks(ref yHi, ref yLo, pData + offset, h8to5, h4to1);
                offset += 128;
            }

            if (offset + 64 <= length)
            {
                Ghash4Blocks(ref yHi, ref yLo, pData + offset, h4to1);
                offset += 64;
            }

            while (offset + 16 <= length)
            {
                AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, pData + offset, h1);
                offset += 16;
            }
        }

        if (offset < length)
        {
            Span<byte> pad = stackalloc byte[16];
            data.Slice(offset).CopyTo(pad);
            fixed (byte* pPad = pad)
            {
                AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, pPad, h1);
            }
        }
    }
}
