namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Hardware-accelerated carryless multiplication GHASH using 128-bit PCLMULQDQ.
/// Evaluates GF(2^128) polynomial multiplication modulo f(x) = x^128 + x^7 + x^2 + x + 1.
/// </summary>
internal static unsafe class AesGcmKernelPclmul
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Reduce(
        Vector128<ulong> z0,
        Vector128<ulong> z1,
        Vector128<ulong> z2,
        out ulong rHi,
        out ulong rLo)
    {
        z0 = Sse2.Xor(z0, Sse2.ShiftLeftLogical128BitLane(z1, 8));
        z2 = Sse2.Xor(z2, Sse2.ShiftRightLogical128BitLane(z1, 8));

        ulong t3 = z0.GetElement(0);
        ulong t2 = z0.GetElement(1);
        ulong t1 = z2.GetElement(0);
        ulong t0 = z2.GetElement(1);

        t1 ^= t3 ^ (t3 >> 1) ^ (t3 >> 2) ^ (t3 >> 7);
        t2 ^= (t3 << 63) ^ (t3 << 62) ^ (t3 << 57);

        ulong w0 = (t0 << 1) | (t1 >> 63);
        ulong w1 = (t1 << 1) | (t2 >> 63);
        ulong w2 = (t2 << 1);

        w0 ^= w2 ^ (w2 >> 1) ^ (w2 >> 2) ^ (w2 >> 7);
        w1 ^= (t2 << 63) ^ (t2 << 58);

        rHi = w0;
        rLo = w1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MulExt(
        Vector128<ulong> x,
        Vector128<ulong> y,
        ref Vector128<ulong> acc0,
        ref Vector128<ulong> acc1,
        ref Vector128<ulong> acc2)
    {
        acc0 = Sse2.Xor(acc0, Pclmulqdq.CarrylessMultiply(x, y, 0x00));
        Vector128<ulong> m1 = Pclmulqdq.CarrylessMultiply(x, y, 0x01);
        Vector128<ulong> m2 = Pclmulqdq.CarrylessMultiply(x, y, 0x10);
        acc1 = Sse2.Xor(acc1, Sse2.Xor(m1, m2));
        acc2 = Sse2.Xor(acc2, Pclmulqdq.CarrylessMultiply(x, y, 0x11));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<ulong> MulOne(Vector128<ulong> x, Vector128<ulong> y)
    {
        Vector128<ulong> z0 = Vector128<ulong>.Zero;
        Vector128<ulong> z1 = Vector128<ulong>.Zero;
        Vector128<ulong> z2 = Vector128<ulong>.Zero;
        MulExt(x, y, ref z0, ref z1, ref z2);
        Reduce(z0, z1, z2, out ulong rHi, out ulong rLo);
        return Vector128.Create(rLo, rHi);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void GhashBlock(
        ref ulong yHi,
        ref ulong yLo,
        byte* pBlock,
        Vector128<ulong> h1)
    {
        ulong* u = (ulong*)pBlock;
        ulong bHi = BinaryPrimitives.ReverseEndianness(u[0]);
        ulong bLo = BinaryPrimitives.ReverseEndianness(u[1]);
        Vector128<ulong> x = Vector128.Create(yLo ^ bLo, yHi ^ bHi);

        Vector128<ulong> z0 = Vector128<ulong>.Zero;
        Vector128<ulong> z1 = Vector128<ulong>.Zero;
        Vector128<ulong> z2 = Vector128<ulong>.Zero;
        MulExt(x, h1, ref z0, ref z1, ref z2);
        Reduce(z0, z1, z2, out yHi, out yLo);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void GhashBlock(
        ref ulong yHi,
        ref ulong yLo,
        ReadOnlySpan<byte> block,
        Vector128<ulong> h1)
    {
        fixed (byte* pBlock = block)
        {
            GhashBlock(ref yHi, ref yLo, pBlock, h1);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Ghash4Blocks(
        ref ulong yHi,
        ref ulong yLo,
        byte* pBlocks,
        Vector128<ulong> h1,
        Vector128<ulong> h2,
        Vector128<ulong> h3,
        Vector128<ulong> h4)
    {
        ulong* u = (ulong*)pBlocks;
        ulong b0Hi = BinaryPrimitives.ReverseEndianness(u[0]);
        ulong b0Lo = BinaryPrimitives.ReverseEndianness(u[1]);
        ulong b1Hi = BinaryPrimitives.ReverseEndianness(u[2]);
        ulong b1Lo = BinaryPrimitives.ReverseEndianness(u[3]);
        ulong b2Hi = BinaryPrimitives.ReverseEndianness(u[4]);
        ulong b2Lo = BinaryPrimitives.ReverseEndianness(u[5]);
        ulong b3Hi = BinaryPrimitives.ReverseEndianness(u[6]);
        ulong b3Lo = BinaryPrimitives.ReverseEndianness(u[7]);

        Vector128<ulong> x0 = Vector128.Create(yLo ^ b0Lo, yHi ^ b0Hi);
        Vector128<ulong> x1 = Vector128.Create(b1Lo, b1Hi);
        Vector128<ulong> x2 = Vector128.Create(b2Lo, b2Hi);
        Vector128<ulong> x3 = Vector128.Create(b3Lo, b3Hi);

        Vector128<ulong> z0 = Vector128<ulong>.Zero;
        Vector128<ulong> z1 = Vector128<ulong>.Zero;
        Vector128<ulong> z2 = Vector128<ulong>.Zero;

        MulExt(x0, h4, ref z0, ref z1, ref z2);
        MulExt(x1, h3, ref z0, ref z1, ref z2);
        MulExt(x2, h2, ref z0, ref z1, ref z2);
        MulExt(x3, h1, ref z0, ref z1, ref z2);

        Reduce(z0, z1, z2, out yHi, out yLo);
    }

    public static void ProcessBlocks(
        ref ulong yHi,
        ref ulong yLo,
        ReadOnlySpan<byte> data,
        Vector128<ulong> h1,
        Vector128<ulong> h2,
        Vector128<ulong> h3,
        Vector128<ulong> h4)
    {
        int offset = 0;
        int length = data.Length;

        fixed (byte* pData = data)
        {
            while (offset + 64 <= length)
            {
                Ghash4Blocks(ref yHi, ref yLo, pData + offset, h1, h2, h3, h4);
                offset += 64;
            }

            while (offset + 16 <= length)
            {
                GhashBlock(ref yHi, ref yLo, pData + offset, h1);
                offset += 16;
            }
        }

        if (offset < length)
        {
            Span<byte> pad = stackalloc byte[16];
            data.Slice(offset).CopyTo(pad);
            fixed (byte* pPad = pad)
            {
                GhashBlock(ref yHi, ref yLo, pPad, h1);
            }
        }
    }
}
