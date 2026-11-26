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
    public const short QInv = -3327;       // Q * QInv ≡ 1 (mod 2^16)
    public const short BarrettV = 20159;   // round(2^26 / 3329)
    public const short R2ModQ = 1353;      // (2^16)^2 mod 3329

    /// <summary>Precomputed twiddle factors zeta^(BitRev7(k)) mod q for k in [0, 127].</summary>
    public static readonly short[] Zetas;

    /// <summary>Precomputed twiddle factors zeta^(2*BitRev7(i) + 1) mod q for i in [0, 127].</summary>
    public static readonly short[] Gammas;

    /// <summary>Signed Montgomery-domain twiddle factors zeta^(BitRev7(k)) * 2^16 mod+- q.</summary>
    public static readonly short[] ZetasMont;

    /// <summary>Signed Montgomery-domain twiddle factors gamma[i] * 2^16 mod+- q.</summary>
    public static readonly short[] GammasMont;

    /// <summary>Signed Montgomery-domain 128^-1 * 2^16 mod+- q.</summary>
    public static readonly short Inv128Mont;

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
        ZetasMont = new short[128];
        for (int k = 0; k < 128; k++)
        {
            int rev = BitRev7(k);
            Zetas[k] = pow17[rev];
            ZetasMont[k] = ToSignedModQ((Zetas[k] * 65536L) % Q);
        }

        Gammas = new short[128];
        GammasMont = new short[128];
        for (int i = 0; i < 128; i++)
        {
            int exp = (2 * BitRev7(i) + 1) % 256;
            Gammas[i] = pow17[exp];
            GammasMont[i] = ToSignedModQ((Gammas[i] * 65536L) % Q);
        }

        Inv128Mont = ToSignedModQ((NttTransformScalar.Inv128 * 65536L) % Q);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static short ToSignedModQ(long value)
    {
        int v = (int)(value % Q);
        if (v > (Q >> 1)) v -= Q;
        return (short)v;
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
        if (CpuCapabilities.HasAvx512BW && CpuCapabilities.HasVector512)
        {
            NttTransformAvx512.ForwardNtt(f, ZetasMont);
        }
        else if (CpuCapabilities.HasAvx2)
        {
            NttTransformAvx2.ForwardNtt(f, ZetasMont);
        }
        else
        {
            NttTransformScalar.ForwardNtt(f, Zetas);
        }
    }

    /// <summary>Inverse NTT: f_hat -> f.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void InverseNtt(Span<short> f)
    {
        if (CpuCapabilities.HasAvx512BW && CpuCapabilities.HasVector512)
        {
            NttTransformAvx512.InverseNtt(f, ZetasMont, Inv128Mont);
        }
        else if (CpuCapabilities.HasAvx2)
        {
            NttTransformAvx2.InverseNtt(f, ZetasMont, Inv128Mont);
        }
        else
        {
            NttTransformScalar.InverseNtt(f, Zetas);
        }
    }

    /// <summary>BaseCaseMultiply across 128 pairs in NTT domain: h_hat = f_hat o g_hat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MultiplyNTTs(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        if (CpuCapabilities.HasAvx512BW && CpuCapabilities.HasVector512)
        {
            NttTransformAvx512.MultiplyNTTs(f, g, h, GammasMont);
        }
        else if (CpuCapabilities.HasAvx2)
        {
            NttTransformAvx2.MultiplyNTTs(f, g, h, GammasMont);
        }
        else
        {
            NttTransformScalar.MultiplyNTTs(f, g, h, Gammas);
        }
    }

    /// <summary>Coefficient-wise addition: h = f + g (mod q).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        if (CpuCapabilities.HasAvx512BW && CpuCapabilities.HasVector512)
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
        if (CpuCapabilities.HasAvx512BW && CpuCapabilities.HasVector512)
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
