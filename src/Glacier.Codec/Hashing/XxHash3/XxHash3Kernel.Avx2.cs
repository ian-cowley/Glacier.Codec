namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX2 256-bit SIMD kernel for xxHash3 64-byte stripe accumulation and accumulator scrambling.
/// </summary>
internal static unsafe class XxHash3KernelAvx2
{
    private static readonly Vector256<ulong> s_scramblePrime = Vector256.Create((ulong)XxHash3Constants.Prime32_1);

    public static bool IsSupported => Avx2.IsSupported;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AccumulateStripe(ulong* accumulators, byte* source, byte* secret)
    {
        // Low 4 lanes (0..3)
        Vector256<ulong> acc0 = Vector256.Load(accumulators);
        Vector256<uint> data0 = Vector256.Load((uint*)source);
        Vector256<uint> key0 = Vector256.Load((uint*)secret);
        Vector256<uint> dataKey0 = data0 ^ key0;

        Vector256<uint> shifted0 = Avx2.ShiftRightLogical(dataKey0.AsUInt64(), 32).AsUInt32();
        Vector256<ulong> prod0 = Avx2.Multiply(dataKey0, shifted0);
        Vector256<ulong> swap0 = Avx2.Permute4x64(data0.AsUInt64(), 0xB1);
        acc0 = acc0 + swap0 + prod0;
        acc0.Store(accumulators);

        // High 4 lanes (4..7)
        Vector256<ulong> acc1 = Vector256.Load(accumulators + 4);
        Vector256<uint> data1 = Vector256.Load((uint*)(source + 32));
        Vector256<uint> key1 = Vector256.Load((uint*)(secret + 32));
        Vector256<uint> dataKey1 = data1 ^ key1;

        Vector256<uint> shifted1 = Avx2.ShiftRightLogical(dataKey1.AsUInt64(), 32).AsUInt32();
        Vector256<ulong> prod1 = Avx2.Multiply(dataKey1, shifted1);
        Vector256<ulong> swap1 = Avx2.Permute4x64(data1.AsUInt64(), 0xB1);
        acc1 = acc1 + swap1 + prod1;
        acc1.Store(accumulators + 4);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Scramble(ulong* accumulators, byte* secret)
    {
        Vector256<ulong> acc0 = Vector256.Load(accumulators);
        Vector256<ulong> key0 = Vector256.Load((ulong*)secret);
        Vector256<ulong> xorShift0 = acc0 ^ Vector256.ShiftRightLogical(acc0, 47);
        acc0 = (xorShift0 ^ key0) * s_scramblePrime;
        acc0.Store(accumulators);

        Vector256<ulong> acc1 = Vector256.Load(accumulators + 4);
        Vector256<ulong> key1 = Vector256.Load((ulong*)(secret + 32));
        Vector256<ulong> xorShift1 = acc1 ^ Vector256.ShiftRightLogical(acc1, 47);
        acc1 = (xorShift1 ^ key1) * s_scramblePrime;
        acc1.Store(accumulators + 4);
    }
}
