namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Scalar constant-time implementation of Argon2id block compression function G (RFC 9106).
/// Provides portable fallback for platforms without AVX2 or AVX-512.
/// </summary>
internal static class Argon2idKernelScalar
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void GB(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
    {
        a = a + b + (2UL * (ulong)(uint)a * (ulong)(uint)b);
        d = BitOperations.RotateRight(d ^ a, 32);
        c = c + d + (2UL * (ulong)(uint)c * (ulong)(uint)d);
        b = BitOperations.RotateRight(b ^ c, 24);

        a = a + b + (2UL * (ulong)(uint)a * (ulong)(uint)b);
        d = BitOperations.RotateRight(d ^ a, 16);
        c = c + d + (2UL * (ulong)(uint)c * (ulong)(uint)d);
        b = BitOperations.RotateRight(b ^ c, 63);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void P(
        ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3,
        ref ulong v4, ref ulong v5, ref ulong v6, ref ulong v7,
        ref ulong v8, ref ulong v9, ref ulong v10, ref ulong v11,
        ref ulong v12, ref ulong v13, ref ulong v14, ref ulong v15)
    {
        // Column GB operations
        GB(ref v0, ref v4, ref v8, ref v12);
        GB(ref v1, ref v5, ref v9, ref v13);
        GB(ref v2, ref v6, ref v10, ref v14);
        GB(ref v3, ref v7, ref v11, ref v15);

        // Diagonal GB operations
        GB(ref v0, ref v5, ref v10, ref v15);
        GB(ref v1, ref v6, ref v11, ref v12);
        GB(ref v2, ref v7, ref v8, ref v13);
        GB(ref v3, ref v4, ref v9, ref v14);
    }

    /// <summary>
    /// Evaluates 1024-byte compression function: dest = G(x, y).
    /// </summary>
    public static unsafe void MixBlock(ulong* dest, ulong* x, ulong* y)
    {
        ulong* r = stackalloc ulong[128];

        // 1. Initial XOR: R = X ^ Y
        for (int i = 0; i < 128; i++)
        {
            r[i] = x[i] ^ y[i];
        }

        // 2. Row-wise P rounds (8 rows of 16 ulongs)
        for (int row = 0; row < 8; row++)
        {
            int baseIdx = row * 16;
            P(
                ref r[baseIdx + 0], ref r[baseIdx + 1], ref r[baseIdx + 2], ref r[baseIdx + 3],
                ref r[baseIdx + 4], ref r[baseIdx + 5], ref r[baseIdx + 6], ref r[baseIdx + 7],
                ref r[baseIdx + 8], ref r[baseIdx + 9], ref r[baseIdx + 10], ref r[baseIdx + 11],
                ref r[baseIdx + 12], ref r[baseIdx + 13], ref r[baseIdx + 14], ref r[baseIdx + 15]);
        }

        // 3. Column-wise P rounds (8 columns of 8 16-byte registers = 16 ulongs)
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

            P(
                ref r[c0], ref r[c0 + 1], ref r[c1], ref r[c1 + 1],
                ref r[c2], ref r[c2 + 1], ref r[c3], ref r[c3 + 1],
                ref r[c4], ref r[c4 + 1], ref r[c5], ref r[c5 + 1],
                ref r[c6], ref r[c6 + 1], ref r[c7], ref r[c7 + 1]);
        }

        // 4. Output: dest = Z ^ R (where R is the original X ^ Y)
        for (int i = 0; i < 128; i++)
        {
            dest[i] = r[i] ^ (x[i] ^ y[i]);
        }
    }

    /// <summary>
    /// Evaluates 1024-byte compression function with accumulation: dest ^= G(x, y).
    /// </summary>
    public static unsafe void MixBlockXor(ulong* dest, ulong* x, ulong* y)
    {
        ulong* r = stackalloc ulong[128];

        for (int i = 0; i < 128; i++)
        {
            r[i] = x[i] ^ y[i];
        }

        for (int row = 0; row < 8; row++)
        {
            int baseIdx = row * 16;
            P(
                ref r[baseIdx + 0], ref r[baseIdx + 1], ref r[baseIdx + 2], ref r[baseIdx + 3],
                ref r[baseIdx + 4], ref r[baseIdx + 5], ref r[baseIdx + 6], ref r[baseIdx + 7],
                ref r[baseIdx + 8], ref r[baseIdx + 9], ref r[baseIdx + 10], ref r[baseIdx + 11],
                ref r[baseIdx + 12], ref r[baseIdx + 13], ref r[baseIdx + 14], ref r[baseIdx + 15]);
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

            P(
                ref r[c0], ref r[c0 + 1], ref r[c1], ref r[c1 + 1],
                ref r[c2], ref r[c2 + 1], ref r[c3], ref r[c3 + 1],
                ref r[c4], ref r[c4 + 1], ref r[c5], ref r[c5 + 1],
                ref r[c6], ref r[c6 + 1], ref r[c7], ref r[c7 + 1]);
        }

        for (int i = 0; i < 128; i++)
        {
            dest[i] ^= r[i] ^ (x[i] ^ y[i]);
        }
    }
}
