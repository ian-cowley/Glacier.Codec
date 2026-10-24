namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 512-bit SIMD kernel for xxHash3 64-byte stripe accumulation and accumulator scrambling.
/// </summary>
internal static unsafe class XxHash3KernelAvx512
{
    private static readonly Vector512<ulong> s_swapMask = Vector512.Create(1UL, 0, 3, 2, 5, 4, 7, 6);
    private static readonly Vector512<ulong> s_scramblePrime = Vector512.Create((ulong)XxHash3Constants.Prime32_1);

    public static bool IsSupported => Avx512F.IsSupported;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AccumulateStripe(ulong* accumulators, byte* source, byte* secret)
    {
        Vector512<ulong> acc = Vector512.Load(accumulators);
        Vector512<ulong> data = Vector512.Load((ulong*)source);
        Vector512<ulong> key = Vector512.Load((ulong*)secret);
        Vector512<ulong> dataKey = data ^ key;

        // 32x32 -> 64 product of low and high halves
        Vector512<ulong> shifted = Vector512.ShiftRightLogical(dataKey, 32);
        Vector512<ulong> product = Avx512F.Multiply(dataKey.AsUInt32(), shifted.AsUInt32()).AsUInt64();

        // Adjacent lane swap: 0<->1, 2<->3, 4<->5, 6<->7
        Vector512<ulong> swapped = Vector512.Shuffle(data, s_swapMask);

        acc = acc + swapped + product;
        acc.Store(accumulators);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Scramble(ulong* accumulators, byte* secret)
    {
        Vector512<ulong> acc = Vector512.Load(accumulators);
        Vector512<ulong> key = Vector512.Load((ulong*)secret);
        Vector512<ulong> xorShift = acc ^ Vector512.ShiftRightLogical(acc, 47);
        acc = (xorShift ^ key) * s_scramblePrime;
        acc.Store(accumulators);
    }
}
