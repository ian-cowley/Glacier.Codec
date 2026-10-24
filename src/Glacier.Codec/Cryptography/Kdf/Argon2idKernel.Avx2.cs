namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX2 256-bit SIMD implementation of Argon2id block compression function G (RFC 9106).
/// Operates on 4 64-bit lanes simultaneously with zero heap allocations.
/// </summary>
internal static class Argon2idKernelAvx2
{
    private const byte Perm1230 = 0b00_11_10_01; // [1, 2, 3, 0]
    private const byte Perm2301 = 0b01_00_11_10; // [2, 3, 0, 1]
    private const byte Perm3012 = 0b10_01_00_11; // [3, 0, 1, 2]

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> RotR(Vector256<ulong> x, int shift)
    {
        return Vector256.ShiftRightLogical(x, shift) | Vector256.ShiftLeft(x, 64 - shift);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> RotR32(Vector256<ulong> x)
    {
        return Avx2.Shuffle(x.AsUInt32(), 0b10_11_00_01).AsUInt64();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GB_Avx2(
        ref Vector256<ulong> a,
        ref Vector256<ulong> b,
        ref Vector256<ulong> c,
        ref Vector256<ulong> d)
    {
        Vector256<ulong> prod = Avx2.Multiply(a.AsUInt32(), b.AsUInt32()).AsUInt64();
        a = a + b + prod + prod;
        d = RotR32(d ^ a);

        prod = Avx2.Multiply(c.AsUInt32(), d.AsUInt32()).AsUInt64();
        c = c + d + prod + prod;
        b = RotR(b ^ c, 24);

        prod = Avx2.Multiply(a.AsUInt32(), b.AsUInt32()).AsUInt64();
        a = a + b + prod + prod;
        d = RotR(d ^ a, 16);

        prod = Avx2.Multiply(c.AsUInt32(), d.AsUInt32()).AsUInt64();
        c = c + d + prod + prod;
        b = RotR(b ^ c, 63);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void P_Avx2(
        ref Vector256<ulong> va,
        ref Vector256<ulong> vb,
        ref Vector256<ulong> vc,
        ref Vector256<ulong> vd)
    {
        // 1. Column GB rounds
        GB_Avx2(ref va, ref vb, ref vc, ref vd);

        // 2. Diagonal permutations
        vb = Avx2.Permute4x64(vb, Perm1230);
        vc = Avx2.Permute4x64(vc, Perm2301);
        vd = Avx2.Permute4x64(vd, Perm3012);

        // 3. Diagonal GB rounds
        GB_Avx2(ref va, ref vb, ref vc, ref vd);

        // 4. Reverse diagonal permutations
        vb = Avx2.Permute4x64(vb, Perm3012);
        vc = Avx2.Permute4x64(vc, Perm2301);
        vd = Avx2.Permute4x64(vd, Perm1230);
    }

    /// <summary>
    /// AVX2 accelerated block compression: dest = G(x, y).
    /// </summary>
    public static unsafe void MixBlock(ulong* dest, ulong* x, ulong* y)
    {
        ulong* r = stackalloc ulong[128];
        Vector256<ulong>* rVec = (Vector256<ulong>*)r;
        Vector256<ulong>* xVec = (Vector256<ulong>*)x;
        Vector256<ulong>* yVec = (Vector256<ulong>*)y;

        // 1. R = X ^ Y (32 vectors of 256 bits = 1024 bytes)
        for (int i = 0; i < 32; i++)
        {
            rVec[i] = xVec[i] ^ yVec[i];
        }

        // 2. Row-wise passes: 8 rows of 16 ulongs (4 Vector256<ulong> each)
        for (int row = 0; row < 8; row++)
        {
            int baseIdx = row * 4;
            P_Avx2(
                ref rVec[baseIdx + 0],
                ref rVec[baseIdx + 1],
                ref rVec[baseIdx + 2],
                ref rVec[baseIdx + 3]);
        }

        // 3. Column-wise passes: 8 columns of 16 ulongs
        // In row format: register R_{8*k + j} is located at row k, col j
        // We unpack column pairs or transpose to run column P rounds:
        // For column pairs (c, c+1) where c in {0, 2, 4, 6}:
        for (int col = 0; col < 8; col++)
        {
            int c0 = 16 * 0 + 2 * col;
            int c1 = 16 * 1 + 2 * col;
            int c2 = 16 * 2 + 2 * col;
            int c3 = 16 * 3 + 2 * col;
            int c4 = 16 * 4 + 2 * col;
            int c5 = 16 * 5 + 2 * col;
            int c6 = 16 * 6 + 2 * col;
            int c7 = 16 * 7 + 2 * col;

            Argon2idKernelScalar.P(
                ref r[c0], ref r[c0 + 1], ref r[c1], ref r[c1 + 1],
                ref r[c2], ref r[c2 + 1], ref r[c3], ref r[c3 + 1],
                ref r[c4], ref r[c4 + 1], ref r[c5], ref r[c5 + 1],
                ref r[c6], ref r[c6 + 1], ref r[c7], ref r[c7 + 1]);
        }

        // 4. Output: dest = Z ^ R
        Vector256<ulong>* destVec = (Vector256<ulong>*)dest;
        for (int i = 0; i < 32; i++)
        {
            destVec[i] = rVec[i] ^ (xVec[i] ^ yVec[i]);
        }
    }

    /// <summary>
    /// AVX2 accelerated block compression with accumulation: dest ^= G(x, y).
    /// </summary>
    public static unsafe void MixBlockXor(ulong* dest, ulong* x, ulong* y)
    {
        ulong* r = stackalloc ulong[128];
        Vector256<ulong>* rVec = (Vector256<ulong>*)r;
        Vector256<ulong>* xVec = (Vector256<ulong>*)x;
        Vector256<ulong>* yVec = (Vector256<ulong>*)y;

        for (int i = 0; i < 32; i++)
        {
            rVec[i] = xVec[i] ^ yVec[i];
        }

        for (int row = 0; row < 8; row++)
        {
            int baseIdx = row * 4;
            P_Avx2(
                ref rVec[baseIdx + 0],
                ref rVec[baseIdx + 1],
                ref rVec[baseIdx + 2],
                ref rVec[baseIdx + 3]);
        }

        for (int col = 0; col < 8; col++)
        {
            int c0 = 16 * 0 + 2 * col;
            int c1 = 16 * 1 + 2 * col;
            int c2 = 16 * 2 + 2 * col;
            int c3 = 16 * 3 + 2 * col;
            int c4 = 16 * 4 + 2 * col;
            int c5 = 16 * 5 + 2 * col;
            int c6 = 16 * 6 + 2 * col;
            int c7 = 16 * 7 + 2 * col;

            Argon2idKernelScalar.P(
                ref r[c0], ref r[c0 + 1], ref r[c1], ref r[c1 + 1],
                ref r[c2], ref r[c2 + 1], ref r[c3], ref r[c3 + 1],
                ref r[c4], ref r[c4 + 1], ref r[c5], ref r[c5 + 1],
                ref r[c6], ref r[c6 + 1], ref r[c7], ref r[c7 + 1]);
        }

        Vector256<ulong>* destVec = (Vector256<ulong>*)dest;
        for (int i = 0; i < 32; i++)
        {
            destVec[i] ^= rVec[i] ^ (xVec[i] ^ yVec[i]);
        }
    }
}
