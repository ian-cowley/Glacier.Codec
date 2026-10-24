namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 512-bit SIMD implementation of polynomial arithmetic for ML-KEM.
/// Processes 32 16-bit coefficients simultaneously per vector register with zero heap allocations.
/// </summary>
internal static class NttTransformAvx512
{
    private static readonly Vector512<short> s_vQ = Vector512.Create(NttTransformScalar.Q);

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

    public static unsafe void PolyAdd(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
    {
        fixed (short* pf = f, pg = g, ph = h)
        {
            Vector512<short>* vf = (Vector512<short>*)pf;
            Vector512<short>* vg = (Vector512<short>*)pg;
            Vector512<short>* vh = (Vector512<short>*)ph;

            for (int i = 0; i < 8; i++) // 8 * 32 = 256 coefficients
            {
                vh[i] = PolyAdd512(vf[i], vg[i]);
            }
        }
    }

    public static unsafe void PolySub(ReadOnlySpan<short> f, ReadOnlySpan<short> g, Span<short> h)
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
}
