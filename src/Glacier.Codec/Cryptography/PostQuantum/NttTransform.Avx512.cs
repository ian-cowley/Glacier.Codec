namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 512-bit SIMD implementation of polynomial arithmetic, Montgomery NTT/INTT, and
/// BaseCaseMultiply for ML-KEM. Processes 32 16-bit coefficients per 512-bit vector register.
/// </summary>
internal static unsafe class NttTransformAvx512
{
    private static readonly Vector512<short> s_vQ = Vector512.Create(NttTransform.Q);
    private static readonly Vector512<short> s_vQInv = Vector512.Create(NttTransform.QInv);
    private static readonly Vector512<short> s_vBarrettV = Vector512.Create(NttTransform.BarrettV);
    private static readonly Vector512<short> s_v512 = Vector512.Create((short)512);
    private static readonly Vector512<short> s_vR2 = Vector512.Create(NttTransform.R2ModQ);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector512<short> MontMul512(Vector512<short> a, Vector512<short> b)
    {
        Vector512<short> lo = Avx512BW.MultiplyLow(a, b);
        Vector512<short> hi = Avx512BW.MultiplyHigh(a, b);
        Vector512<short> t = Avx512BW.MultiplyLow(lo, s_vQInv);
        Vector512<short> u = Avx512BW.MultiplyHigh(t, s_vQ);
        return Avx512BW.Subtract(hi, u);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector512<short> BarrettReduce512(Vector512<short> v)
    {
        Vector512<short> t = Avx512BW.ShiftRightArithmetic(Avx512BW.Add(Avx512BW.MultiplyHigh(v, s_vBarrettV), s_v512), 10);
        return Avx512BW.Subtract(v, Avx512BW.MultiplyLow(t, s_vQ));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector512<short> Canonicalize512(Vector512<short> v)
    {
        v = BarrettReduce512(v);
        Vector512<short> negMask = Vector512.LessThan(v, Vector512<short>.Zero);
        return Avx512BW.Add(v, negMask & s_vQ);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector512<short> PolyAdd512(Vector512<short> a, Vector512<short> b)
    {
        Vector512<short> sum = a + b;
        Vector512<short> mask = Vector512.GreaterThanOrEqual(sum, s_vQ);
        return sum - (mask & s_vQ);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector512<short> PolySub512(Vector512<short> a, Vector512<short> b)
    {
        Vector512<short> diff = a - b;
        Vector512<short> mask = Vector512.LessThan(diff, Vector512<short>.Zero);
        return diff + (mask & s_vQ);
    }

    public static void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector512<short>* vf = (Vector512<short>*)pf;
            Vector512<short>* vg = (Vector512<short>*)pg;
            Vector512<short>* vh = (Vector512<short>*)ph;

            for (int i = 0; i < 8; i++)
            {
                vh[i] = PolyAdd512(vf[i], vg[i]);
            }
        }
    }

    public static void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector512<short>* vf = (Vector512<short>*)pf;
            Vector512<short>* vg = (Vector512<short>*)pg;
            Vector512<short>* vh = (Vector512<short>*)ph;

            for (int i = 0; i < 8; i++)
            {
                vh[i] = PolySub512(vf[i], vg[i]);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void ForwardNtt(Span<short> f, ReadOnlySpan<short> zetasMont)
    {
        fixed (short* pf = f)
        fixed (short* pz = zetasMont)
        {
            int k = 1;
            for (int len = 128; len >= 32; len >>= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    Vector512<short> vZeta = Vector512.Create(pz[k++]);
                    for (int j = start; j < start + len; j += 32)
                    {
                        Vector512<short> a = Vector512.Load(pf + j);
                        Vector512<short> b = Vector512.Load(pf + j + len);
                        Vector512<short> t = MontMul512(vZeta, b);
                        BarrettReduce512(Avx512BW.Subtract(a, t)).Store(pf + j + len);
                        BarrettReduce512(Avx512BW.Add(a, t)).Store(pf + j);
                    }
                }
            }

            // len = 16 (AVX2)
            for (int start = 0; start < 256; start += 32)
            {
                Vector256<short> vZeta = Vector256.Create(pz[k++]);
                Vector256<short> a = Vector256.Load(pf + start);
                Vector256<short> b = Vector256.Load(pf + start + 16);
                Vector256<short> t = NttTransformAvx2.MontMul256(vZeta, b);
                Avx2.Store(pf + start + 16, NttTransformAvx2.BarrettReduce256(Avx2.Subtract(a, t)));
                Avx2.Store(pf + start, NttTransformAvx2.BarrettReduce256(Avx2.Add(a, t)));
            }

            // len = 8, 4, 2
            NttTransformAvx2.ForwardNttSmallLayers(pf, pz, k);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void InverseNtt(Span<short> f, ReadOnlySpan<short> zetasMont, short inv128Mont)
    {
        fixed (short* pf = f)
        fixed (short* pz = zetasMont)
        {
            int k = NttTransformAvx2.InverseNttSmallLayers(pf, pz, 127);

            // len = 16 (AVX2)
            for (int start = 0; start < 256; start += 32)
            {
                Vector256<short> vZeta = Vector256.Create(pz[k--]);
                Vector256<short> a = Vector256.Load(pf + start);
                Vector256<short> b = Vector256.Load(pf + start + 16);
                Avx2.Store(pf + start, NttTransformAvx2.BarrettReduce256(Avx2.Add(a, b)));
                Avx2.Store(pf + start + 16, NttTransformAvx2.MontMul256(vZeta, Avx2.Subtract(b, a)));
            }

            // len = 32, 64, 128 (AVX-512)
            for (int len = 32; len <= 128; len <<= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    Vector512<short> vZeta = Vector512.Create(pz[k--]);
                    for (int j = start; j < start + len; j += 32)
                    {
                        Vector512<short> a = Vector512.Load(pf + j);
                        Vector512<short> b = Vector512.Load(pf + j + len);
                        BarrettReduce512(Avx512BW.Add(a, b)).Store(pf + j);
                        MontMul512(vZeta, Avx512BW.Subtract(b, a)).Store(pf + j + len);
                    }
                }
            }

            Vector512<short> vInv128 = Vector512.Create(inv128Mont);
            for (int i = 0; i < 256; i += 32)
            {
                Vector512<short> v = Vector512.Load(pf + i);
                Canonicalize512(MontMul512(v, vInv128)).Store(pf + i);
            }
        }
    }

    private static readonly Vector512<short> s_evenIdx = Vector512.Create(
        (short)0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
        32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62);

    private static readonly Vector512<short> s_oddIdx = Vector512.Create(
        (short)1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
        33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63);

    private static readonly Vector512<short> s_reinterleaveLoIdx = Vector512.Create(
        (short)0, 32, 1, 33, 2, 34, 3, 35, 4, 36, 5, 37, 6, 38, 7, 39,
        8, 40, 9, 41, 10, 42, 11, 43, 12, 44, 13, 45, 14, 46, 15, 47);

    private static readonly Vector512<short> s_reinterleaveHiIdx = Vector512.Create(
        (short)16, 48, 17, 49, 18, 50, 19, 51, 20, 52, 21, 53, 22, 54, 23, 55,
        24, 56, 25, 57, 26, 58, 27, 59, 28, 60, 29, 61, 30, 62, 31, 63);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void MultiplyNTTs(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h, ReadOnlySpan<short> gammasMont)
    {
        fixed (short* pf = f, pg = g, ph = h, pgam = gammasMont)
        {
            for (int i = 0; i < 256; i += 64)
            {
                Vector512<short> f0 = Vector512.Load(pf + i);
                Vector512<short> f1 = Vector512.Load(pf + i + 32);
                Vector512<short> g0 = Vector512.Load(pg + i);
                Vector512<short> g1 = Vector512.Load(pg + i + 32);

                Vector512<short> a0 = Avx512BW.PermuteVar32x16x2(f0, s_evenIdx, f1);
                Vector512<short> a1 = Avx512BW.PermuteVar32x16x2(f0, s_oddIdx, f1);
                Vector512<short> b0 = Avx512BW.PermuteVar32x16x2(g0, s_evenIdx, g1);
                Vector512<short> b1 = Avx512BW.PermuteVar32x16x2(g0, s_oddIdx, g1);

                Vector512<short> vGamma = Vector512.Load(pgam + (i / 2));

                Vector512<short> r0 = Avx512BW.Add(MontMul512(a0, b0), MontMul512(MontMul512(a1, b1), vGamma));
                Vector512<short> r1 = Avx512BW.Add(MontMul512(a0, b1), MontMul512(a1, b0));

                Vector512<short> h0 = Canonicalize512(MontMul512(r0, s_vR2));
                Vector512<short> h1 = Canonicalize512(MontMul512(r1, s_vR2));

                Avx512BW.PermuteVar32x16x2(h0, s_reinterleaveLoIdx, h1).Store(ph + i);
                Avx512BW.PermuteVar32x16x2(h0, s_reinterleaveHiIdx, h1).Store(ph + i + 32);
            }
        }
    }
}
