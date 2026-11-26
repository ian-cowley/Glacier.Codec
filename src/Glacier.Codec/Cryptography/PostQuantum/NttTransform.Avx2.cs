namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX2 256-bit SIMD implementation of polynomial arithmetic, Montgomery NTT/INTT, and
/// BaseCaseMultiply for ML-KEM. Processes 16 16-bit coefficients per vector register.
/// </summary>
internal static unsafe class NttTransformAvx2
{
    private static readonly Vector256<short> s_vQ = Vector256.Create(NttTransform.Q);
    private static readonly Vector256<short> s_vQInv = Vector256.Create(NttTransform.QInv);
    private static readonly Vector256<short> s_vBarrettV = Vector256.Create(NttTransform.BarrettV);
    private static readonly Vector256<short> s_v512 = Vector256.Create((short)512);
    private static readonly Vector256<short> s_vR2 = Vector256.Create(NttTransform.R2ModQ);

    private static readonly Vector128<short> s_v128Q = Vector128.Create(NttTransform.Q);
    private static readonly Vector128<short> s_v128QInv = Vector128.Create(NttTransform.QInv);
    private static readonly Vector128<short> s_v128BarrettV = Vector128.Create(NttTransform.BarrettV);
    private static readonly Vector128<short> s_v128_512 = Vector128.Create((short)512);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<short> MontMul256(Vector256<short> a, Vector256<short> b)
    {
        Vector256<short> lo = Avx2.MultiplyLow(a, b);
        Vector256<short> hi = Avx2.MultiplyHigh(a, b);
        Vector256<short> t = Avx2.MultiplyLow(lo, s_vQInv);
        Vector256<short> u = Avx2.MultiplyHigh(t, s_vQ);
        return Avx2.Subtract(hi, u);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<short> MontMul128(Vector128<short> a, Vector128<short> b)
    {
        Vector128<short> lo = Sse2.MultiplyLow(a, b);
        Vector128<short> hi = Sse2.MultiplyHigh(a, b);
        Vector128<short> t = Sse2.MultiplyLow(lo, s_v128QInv);
        Vector128<short> u = Sse2.MultiplyHigh(t, s_v128Q);
        return Sse2.Subtract(hi, u);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<short> BarrettReduce256(Vector256<short> v)
    {
        Vector256<short> t = Avx2.ShiftRightArithmetic(Avx2.Add(Avx2.MultiplyHigh(v, s_vBarrettV), s_v512), 10);
        return Avx2.Subtract(v, Avx2.MultiplyLow(t, s_vQ));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<short> BarrettReduce128(Vector128<short> v)
    {
        Vector128<short> t = Sse2.ShiftRightArithmetic(Sse2.Add(Sse2.MultiplyHigh(v, s_v128BarrettV), s_v128_512), 10);
        return Sse2.Subtract(v, Sse2.MultiplyLow(t, s_v128Q));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<short> Canonicalize256(Vector256<short> v)
    {
        v = BarrettReduce256(v);
        Vector256<short> negMask = Vector256.LessThan(v, Vector256<short>.Zero);
        return Avx2.Add(v, Avx2.And(negMask, s_vQ));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<short> PolyAdd256(Vector256<short> a, Vector256<short> b)
    {
        Vector256<short> sum = a + b;
        Vector256<short> mask = Vector256.GreaterThanOrEqual(sum, s_vQ);
        return sum - (mask & s_vQ);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<short> PolySub256(Vector256<short> a, Vector256<short> b)
    {
        Vector256<short> diff = a - b;
        Vector256<short> mask = Vector256.LessThan(diff, Vector256<short>.Zero);
        return diff + (mask & s_vQ);
    }

    public static void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector256<short>* vf = (Vector256<short>*)pf;
            Vector256<short>* vg = (Vector256<short>*)pg;
            Vector256<short>* vh = (Vector256<short>*)ph;

            for (int i = 0; i < 16; i++)
            {
                vh[i] = PolyAdd256(vf[i], vg[i]);
            }
        }
    }

    public static void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector256<short>* vf = (Vector256<short>*)pf;
            Vector256<short>* vg = (Vector256<short>*)pg;
            Vector256<short>* vh = (Vector256<short>*)ph;

            for (int i = 0; i < 16; i++)
            {
                vh[i] = PolySub256(vf[i], vg[i]);
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
            for (int len = 128; len >= 16; len >>= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    Vector256<short> vZeta = Vector256.Create(pz[k++]);
                    for (int j = start; j < start + len; j += 16)
                    {
                        Vector256<short> a = Vector256.Load(pf + j);
                        Vector256<short> b = Vector256.Load(pf + j + len);
                        Vector256<short> t = MontMul256(vZeta, b);
                        Avx2.Store(pf + j + len, BarrettReduce256(Avx2.Subtract(a, t)));
                        Avx2.Store(pf + j, BarrettReduce256(Avx2.Add(a, t)));
                    }
                }
            }

            ForwardNttSmallLayers(pf, pz, k);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void ForwardNttSmallLayers(short* pf, short* pz, int k)
    {
        // len = 8: 16 groups of (8 left, 8 right)
        for (int start = 0; start < 256; start += 16)
        {
            Vector128<short> vZeta = Vector128.Create(pz[k++]);
            Vector128<short> a = Vector128.Load(pf + start);
            Vector128<short> b = Vector128.Load(pf + start + 8);
            Vector128<short> t = MontMul128(vZeta, b);
            Sse2.Store(pf + start + 8, BarrettReduce128(Sse2.Subtract(a, t)));
            Sse2.Store(pf + start, BarrettReduce128(Sse2.Add(a, t)));
        }

        // len = 4: 32 groups of (4 left, 4 right), processed 2 groups per 256-bit pair (4 groups across v0, v1)
        for (int start = 0; start < 256; start += 32)
        {
            Vector256<short> v0 = Vector256.Load(pf + start);
            Vector256<short> v1 = Vector256.Load(pf + start + 16);

            Vector256<short> a = Avx2.UnpackLow(v0.AsInt64(), v1.AsInt64()).AsInt16();  // [L0, L2, L1, L3]
            Vector256<short> b = Avx2.UnpackHigh(v0.AsInt64(), v1.AsInt64()).AsInt16(); // [R0, R2, R1, R3]

            Vector256<short> vZeta = Vector256.Create(
                Vector128.Create(pz[k], pz[k], pz[k], pz[k], pz[k + 2], pz[k + 2], pz[k + 2], pz[k + 2]),
                Vector128.Create(pz[k + 1], pz[k + 1], pz[k + 1], pz[k + 1], pz[k + 3], pz[k + 3], pz[k + 3], pz[k + 3]));
            k += 4;

            Vector256<short> t = MontMul256(vZeta, b);
            Vector256<short> outL = BarrettReduce256(Avx2.Add(a, t));
            Vector256<short> outR = BarrettReduce256(Avx2.Subtract(a, t));

            Avx2.Store(pf + start, Avx2.UnpackLow(outL.AsInt64(), outR.AsInt64()).AsInt16());
            Avx2.Store(pf + start + 16, Avx2.UnpackHigh(outL.AsInt64(), outR.AsInt64()).AsInt16());
        }

        // len = 2: 64 groups of (2 left, 2 right), processed 8 groups across v0, v1
        for (int start = 0; start < 256; start += 32)
        {
            Vector256<int> v0 = Avx2.Shuffle(Vector256.Load(pf + start).AsInt32(), 0xD8);      // [L0, L1, R0, R1 | L2, L3, R2, R3]
            Vector256<int> v1 = Avx2.Shuffle(Vector256.Load(pf + start + 16).AsInt32(), 0xD8); // [L4, L5, R4, R5 | L6, L7, R6, R7]

            Vector256<short> a = Avx2.UnpackLow(v0.AsInt64(), v1.AsInt64()).AsInt16();  // [L0, L1, L4, L5 | L2, L3, L6, L7]
            Vector256<short> b = Avx2.UnpackHigh(v0.AsInt64(), v1.AsInt64()).AsInt16(); // [R0, R1, R4, R5 | R2, R3, R6, R7]

            Vector256<short> vZeta = Vector256.Create(
                Vector128.Create(pz[k], pz[k], pz[k + 1], pz[k + 1], pz[k + 4], pz[k + 4], pz[k + 5], pz[k + 5]),
                Vector128.Create(pz[k + 2], pz[k + 2], pz[k + 3], pz[k + 3], pz[k + 6], pz[k + 6], pz[k + 7], pz[k + 7]));
            k += 8;

            Vector256<short> t = MontMul256(vZeta, b);
            Vector256<short> outL = Canonicalize256(Avx2.Add(a, t));
            Vector256<short> outR = Canonicalize256(Avx2.Subtract(a, t));

            Vector256<int> u0 = Avx2.UnpackLow(outL.AsInt64(), outR.AsInt64()).AsInt32();
            Vector256<int> u1 = Avx2.UnpackHigh(outL.AsInt64(), outR.AsInt64()).AsInt32();

            Avx2.Store(pf + start, Avx2.Shuffle(u0, 0xD8).AsInt16());
            Avx2.Store(pf + start + 16, Avx2.Shuffle(u1, 0xD8).AsInt16());
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void InverseNtt(Span<short> f, ReadOnlySpan<short> zetasMont, short inv128Mont)
    {
        fixed (short* pf = f)
        fixed (short* pz = zetasMont)
        {
            int k = InverseNttSmallLayers(pf, pz, 127);

            for (int len = 16; len <= 128; len <<= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    Vector256<short> vZeta = Vector256.Create(pz[k--]);
                    for (int j = start; j < start + len; j += 16)
                    {
                        Vector256<short> a = Vector256.Load(pf + j);
                        Vector256<short> b = Vector256.Load(pf + j + len);
                        Avx2.Store(pf + j, BarrettReduce256(Avx2.Add(a, b)));
                        Avx2.Store(pf + j + len, MontMul256(vZeta, Avx2.Subtract(b, a)));
                    }
                }
            }

            Vector256<short> vInv128 = Vector256.Create(inv128Mont);
            for (int i = 0; i < 256; i += 16)
            {
                Vector256<short> v = Vector256.Load(pf + i);
                Avx2.Store(pf + i, Canonicalize256(MontMul256(v, vInv128)));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int InverseNttSmallLayers(short* pf, short* pz, int k)
    {
        // len = 2
        for (int start = 0; start < 256; start += 32)
        {
            Vector256<int> v0 = Avx2.Shuffle(Vector256.Load(pf + start).AsInt32(), 0xD8);
            Vector256<int> v1 = Avx2.Shuffle(Vector256.Load(pf + start + 16).AsInt32(), 0xD8);

            Vector256<short> a = Avx2.UnpackLow(v0.AsInt64(), v1.AsInt64()).AsInt16();
            Vector256<short> b = Avx2.UnpackHigh(v0.AsInt64(), v1.AsInt64()).AsInt16();

            Vector256<short> vZeta = Vector256.Create(
                Vector128.Create(pz[k], pz[k], pz[k - 1], pz[k - 1], pz[k - 4], pz[k - 4], pz[k - 5], pz[k - 5]),
                Vector128.Create(pz[k - 2], pz[k - 2], pz[k - 3], pz[k - 3], pz[k - 6], pz[k - 6], pz[k - 7], pz[k - 7]));
            k -= 8;

            Vector256<short> outL = BarrettReduce256(Avx2.Add(a, b));
            Vector256<short> outR = MontMul256(vZeta, Avx2.Subtract(b, a));

            Vector256<int> u0 = Avx2.UnpackLow(outL.AsInt64(), outR.AsInt64()).AsInt32();
            Vector256<int> u1 = Avx2.UnpackHigh(outL.AsInt64(), outR.AsInt64()).AsInt32();

            Avx2.Store(pf + start, Avx2.Shuffle(u0, 0xD8).AsInt16());
            Avx2.Store(pf + start + 16, Avx2.Shuffle(u1, 0xD8).AsInt16());
        }

        // len = 4
        for (int start = 0; start < 256; start += 32)
        {
            Vector256<short> v0 = Vector256.Load(pf + start);
            Vector256<short> v1 = Vector256.Load(pf + start + 16);

            Vector256<short> a = Avx2.UnpackLow(v0.AsInt64(), v1.AsInt64()).AsInt16();
            Vector256<short> b = Avx2.UnpackHigh(v0.AsInt64(), v1.AsInt64()).AsInt16();

            Vector256<short> vZeta = Vector256.Create(
                Vector128.Create(pz[k], pz[k], pz[k], pz[k], pz[k - 2], pz[k - 2], pz[k - 2], pz[k - 2]),
                Vector128.Create(pz[k - 1], pz[k - 1], pz[k - 1], pz[k - 1], pz[k - 3], pz[k - 3], pz[k - 3], pz[k - 3]));
            k -= 4;

            Vector256<short> outL = BarrettReduce256(Avx2.Add(a, b));
            Vector256<short> outR = MontMul256(vZeta, Avx2.Subtract(b, a));

            Avx2.Store(pf + start, Avx2.UnpackLow(outL.AsInt64(), outR.AsInt64()).AsInt16());
            Avx2.Store(pf + start + 16, Avx2.UnpackHigh(outL.AsInt64(), outR.AsInt64()).AsInt16());
        }

        // len = 8
        for (int start = 0; start < 256; start += 16)
        {
            Vector128<short> vZeta = Vector128.Create(pz[k--]);
            Vector128<short> a = Vector128.Load(pf + start);
            Vector128<short> b = Vector128.Load(pf + start + 8);
            Sse2.Store(pf + start, BarrettReduce128(Sse2.Add(a, b)));
            Sse2.Store(pf + start + 8, MontMul128(vZeta, Sse2.Subtract(b, a)));
        }

        return k;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Deinterleave16Pairs(
        Vector256<short> v0,
        Vector256<short> v1,
        out Vector256<short> evens,
        out Vector256<short> odds)
    {
        v0 = Avx2.Shuffle(Avx2.ShuffleHigh(Avx2.ShuffleLow(v0, 0xD8), 0xD8).AsInt32(), 0xD8).AsInt16();
        v1 = Avx2.Shuffle(Avx2.ShuffleHigh(Avx2.ShuffleLow(v1, 0xD8), 0xD8).AsInt32(), 0xD8).AsInt16();
        evens = Avx2.UnpackLow(v0.AsInt64(), v1.AsInt64()).AsInt16();
        odds = Avx2.UnpackHigh(v0.AsInt64(), v1.AsInt64()).AsInt16();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Reinterleave16Pairs(
        Vector256<short> evens,
        Vector256<short> odds,
        out Vector256<short> v0,
        out Vector256<short> v1)
    {
        Vector256<int> u0 = Avx2.Shuffle(Avx2.UnpackLow(evens.AsInt64(), odds.AsInt64()).AsInt32(), 0xD8);
        Vector256<int> u1 = Avx2.Shuffle(Avx2.UnpackHigh(evens.AsInt64(), odds.AsInt64()).AsInt32(), 0xD8);
        v0 = Avx2.ShuffleHigh(Avx2.ShuffleLow(u0.AsInt16(), 0xD8), 0xD8);
        v1 = Avx2.ShuffleHigh(Avx2.ShuffleLow(u1.AsInt16(), 0xD8), 0xD8);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void MultiplyNTTs(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h, ReadOnlySpan<short> gammasMont)
    {
        fixed (short* pf = f, pg = g, ph = h, pgam = gammasMont)
        {
            for (int i = 0; i < 256; i += 32)
            {
                Deinterleave16Pairs(Vector256.Load(pf + i), Vector256.Load(pf + i + 16), out Vector256<short> a0, out Vector256<short> a1);
                Deinterleave16Pairs(Vector256.Load(pg + i), Vector256.Load(pg + i + 16), out Vector256<short> b0, out Vector256<short> b1);

                // Match deinterleaved lane order: [0, 1, 2, 3, 8, 9, 10, 11 | 4, 5, 6, 7, 12, 13, 14, 15]
                int gi = i / 2;
                Vector256<short> vGamma = Vector256.Create(
                    Vector128.Create(pgam[gi + 0], pgam[gi + 1], pgam[gi + 2], pgam[gi + 3], pgam[gi + 8], pgam[gi + 9], pgam[gi + 10], pgam[gi + 11]),
                    Vector128.Create(pgam[gi + 4], pgam[gi + 5], pgam[gi + 6], pgam[gi + 7], pgam[gi + 12], pgam[gi + 13], pgam[gi + 14], pgam[gi + 15]));

                Vector256<short> r0 = Avx2.Add(MontMul256(a0, b0), MontMul256(MontMul256(a1, b1), vGamma));
                Vector256<short> r1 = Avx2.Add(MontMul256(a0, b1), MontMul256(a1, b0));

                Vector256<short> h0 = Canonicalize256(MontMul256(r0, s_vR2));
                Vector256<short> h1 = Canonicalize256(MontMul256(r1, s_vR2));

                Reinterleave16Pairs(h0, h1, out Vector256<short> out0, out Vector256<short> out1);
                Avx2.Store(ph + i, out0);
                Avx2.Store(ph + i + 16, out1);
            }
        }
    }
}
