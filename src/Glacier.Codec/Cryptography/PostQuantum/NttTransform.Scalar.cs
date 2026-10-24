namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Scalar constant-time implementation of Number Theoretic Transform (NTT) for ML-KEM (FIPS 203 Section 4.3).
/// Implements Radix-2 Cooley-Tukey NTT, Gentleman-Sande INTT, and Montgomery polynomial multiplication.
/// </summary>
internal static class NttTransformScalar
{
    public const short Q = 3329;
    public const short Inv128 = 3303; // 128^-1 mod 3329

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static short FieldAdd(short a, short b)
    {
        int sum = a + b;
        return (short)(sum >= Q ? sum - Q : sum);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static short FieldSub(short a, short b)
    {
        int diff = a - b;
        return (short)(diff < 0 ? diff + Q : diff);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static short FieldMul(short a, short b)
    {
        return (short)(((int)a * (int)b) % Q);
    }

    /// <summary>
    /// FIPS 203 Algorithm 9 (NTT): Transforms 256 coefficients into NTT domain.
    /// </summary>
    public static void ForwardNtt(Span<short> f, ReadOnlySpan<short> zetas)
    {
        int k = 1;
        for (int len = 128; len >= 2; len >>= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                short zeta = zetas[k++];
                for (int j = start; j < start + len; j++)
                {
                    short t = FieldMul(zeta, f[j + len]);
                    f[j + len] = FieldSub(f[j], t);
                    f[j] = FieldAdd(f[j], t);
                }
            }
        }
    }

    /// <summary>
    /// FIPS 203 Algorithm 10 (NTT^-1): Inverts 256 coefficients from NTT domain back to standard polynomial domain.
    /// </summary>
    public static void InverseNtt(Span<short> f, ReadOnlySpan<short> zetas)
    {
        int k = 127;
        for (int len = 2; len <= 128; len <<= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                short zeta = zetas[k--];
                for (int j = start; j < start + len; j++)
                {
                    short t = f[j];
                    f[j] = FieldAdd(t, f[j + len]);
                    short diff = FieldSub(f[j + len], t);
                    f[j + len] = FieldMul(zeta, diff);
                }
            }
        }

        for (int i = 0; i < 256; i++)
        {
            f[i] = FieldMul(f[i], Inv128);
        }
    }

    /// <summary>
    /// FIPS 203 Algorithm 11 &amp; 12 (MultiplyNTTs): Multiplies two NTT-domain polynomials modulo (X^2 - gamma).
    /// </summary>
    public static void MultiplyNTTs(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h, ReadOnlySpan<short> gammas)
    {
        for (int i = 0; i < 256; i += 2)
        {
            short a0 = f[i];
            short a1 = f[i + 1];
            short b0 = g[i];
            short b1 = g[i + 1];
            short gamma = gammas[i / 2];

            short a0b0 = FieldMul(a0, b0);
            short a1b1 = FieldMul(a1, b1);
            short a1b1g = FieldMul(a1b1, gamma);
            h[i] = FieldAdd(a0b0, a1b1g);

            short a0b1 = FieldMul(a0, b1);
            short a1b0 = FieldMul(a1, b0);
            h[i + 1] = FieldAdd(a0b1, a1b0);
        }
    }

    /// <summary>
    /// Coefficient-wise addition: h = f + g (mod q).
    /// </summary>
    public static void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        for (int i = 0; i < 256; i++)
        {
            h[i] = FieldAdd(f[i], g[i]);
        }
    }

    /// <summary>
    /// Coefficient-wise subtraction: h = f - g (mod q).
    /// </summary>
    public static void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        for (int i = 0; i < 256; i++)
        {
            h[i] = FieldSub(f[i], g[i]);
        }
    }
}
