namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX2 256-bit SIMD implementation of polynomial arithmetic and Montgomery reductions for ML-KEM.
/// Processes 16 16-bit coefficients simultaneously per vector register with zero heap allocations.
/// </summary>
internal static class NttTransformAvx2
{
    private static readonly Vector256<short> s_vQ = Vector256.Create(NttTransformScalar.Q);

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

    public static unsafe void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector256<short>* vf = (Vector256<short>*)pf;
            Vector256<short>* vg = (Vector256<short>*)pg;
            Vector256<short>* vh = (Vector256<short>*)ph;

            for (int i = 0; i < 16; i++) // 16 * 16 = 256 coefficients
            {
                vh[i] = PolyAdd256(vf[i], vg[i]);
            }
        }
    }

    public static unsafe void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
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
}
