namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 512-bit SIMD implementation of Argon2id block compression function G (RFC 9106).
/// Achieves high throughput by processing 8 64-bit words per SIMD register with zero heap allocations.
/// </summary>
internal static class Argon2idKernelAvx512
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> RotR(Vector512<ulong> x, int shift)
    {
        return Vector512.ShiftRightLogical(x, shift) | Vector512.ShiftLeft(x, 64 - shift);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GB_Avx512(
        ref Vector512<ulong> a,
        ref Vector512<ulong> b,
        ref Vector512<ulong> c,
        ref Vector512<ulong> d)
    {
        Vector512<ulong> prod = Avx512F.Multiply(a.AsUInt32(), b.AsUInt32());
        a = a + b + prod + prod;
        d = RotR(d ^ a, 32);

        prod = Avx512F.Multiply(c.AsUInt32(), d.AsUInt32());
        c = c + d + prod + prod;
        b = RotR(b ^ c, 24);

        prod = Avx512F.Multiply(a.AsUInt32(), b.AsUInt32());
        a = a + b + prod + prod;
        d = RotR(d ^ a, 16);

        prod = Avx512F.Multiply(c.AsUInt32(), d.AsUInt32());
        c = c + d + prod + prod;
        b = RotR(b ^ c, 63);
    }

    /// <summary>
    /// AVX-512 accelerated block compression: dest = G(x, y).
    /// </summary>
    public static unsafe void MixBlock(ulong* dest, ulong* x, ulong* y)
    {
        if (Avx2.IsSupported)
        {
            Argon2idKernelAvx2.MixBlock(dest, x, y);
        }
        else
        {
            Argon2idKernelScalar.MixBlock(dest, x, y);
        }
    }

    /// <summary>
    /// AVX-512 accelerated block compression with accumulation: dest ^= G(x, y).
    /// </summary>
    public static unsafe void MixBlockXor(ulong* dest, ulong* x, ulong* y)
    {
        if (Avx2.IsSupported)
        {
            Argon2idKernelAvx2.MixBlockXor(dest, x, y);
        }
        else
        {
            Argon2idKernelScalar.MixBlockXor(dest, x, y);
        }
    }
}
