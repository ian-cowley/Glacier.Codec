namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;
using Glacier.Codec.Hardware;

/// <summary>
/// Hardware dispatcher and precomputed twiddle table manager for ML-KEM NTT arithmetic (FIPS 203).
/// Automatically selects between AVX-512, AVX2, and constant-time scalar execution.
/// </summary>
internal static class NttTransform
{
    public const short Q = 3329;
    public const short Zeta = 17;

    /// <summary>Precomputed twiddle factors zeta^(BitRev7(k)) mod q for k in [0, 127].</summary>
    public static readonly short[] Zetas;

    /// <summary>Precomputed twiddle factors zeta^(2*BitRev7(i) + 1) mod q for i in [0, 127].</summary>
    public static readonly short[] Gammas;

    static NttTransform()
    {
        short[] pow17 = new short[256];
        int cur = 1;
        for (int i = 0; i < 256; i++)
        {
            pow17[i] = (short)cur;
            cur = (cur * Zeta) % Q;
        }

        Zetas = new short[128];
        for (int k = 0; k < 128; k++)
        {
            int rev = BitRev7(k);
            Zetas[k] = pow17[rev];
        }

        Gammas = new short[128];
        for (int i = 0; i < 128; i++)
        {
            int exp = (2 * BitRev7(i) + 1) % 256;
            Gammas[i] = pow17[exp];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitRev7(int r)
    {
        int rev = 0;
        for (int j = 0; j < 7; j++)
        {
            rev |= ((r >> j) & 1) << (6 - j);
        }
        return rev;
    }

    /// <summary>Forward NTT: f -> f_hat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ForwardNtt(Span<short> f)
    {
        NttTransformScalar.ForwardNtt(f, Zetas);
    }

    /// <summary>Inverse NTT: f_hat -> f.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void InverseNtt(Span<short> f)
    {
        NttTransformScalar.InverseNtt(f, Zetas);
    }

    /// <summary>BaseCaseMultiply across 128 pairs in NTT domain: h_hat = f_hat o g_hat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MultiplyNTTs(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        NttTransformScalar.MultiplyNTTs(f, g, h, Gammas);
    }

    /// <summary>Coefficient-wise addition: h = f + g (mod q).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        if (CpuCapabilities.HasAvx512BW)
        {
            NttTransformAvx512.PolyAdd(f, g, h);
        }
        else if (CpuCapabilities.HasAvx2)
        {
            NttTransformAvx2.PolyAdd(f, g, h);
        }
        else
        {
            NttTransformScalar.PolyAdd(f, g, h);
        }
    }

    /// <summary>Coefficient-wise subtraction: h = f - g (mod q).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        if (CpuCapabilities.HasAvx512BW)
        {
            NttTransformAvx512.PolySub(f, g, h);
        }
        else if (CpuCapabilities.HasAvx2)
        {
            NttTransformAvx2.PolySub(f, g, h);
        }
        else
        {
            NttTransformScalar.PolySub(f, g, h);
        }
    }
}
