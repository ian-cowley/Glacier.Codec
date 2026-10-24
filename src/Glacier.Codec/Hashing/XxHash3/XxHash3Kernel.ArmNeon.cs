namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

/// <summary>
/// ARM NEON 128-bit SIMD kernel for xxHash3 64-byte stripe accumulation and accumulator scrambling.
/// </summary>
internal static unsafe class XxHash3KernelArmNeon
{
    private static readonly Vector128<ulong> s_scramblePrime = Vector128.Create((ulong)XxHash3Constants.Prime32_1);
    private static readonly Vector128<ulong> s_swapMask = Vector128.Create(1UL, 0);

    public static bool IsSupported => AdvSimd.IsSupported;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AccumulateStripe(ulong* accumulators, byte* source, byte* secret)
    {
        for (int i = 0; i < 4; i++)
        {
            Vector128<ulong> acc = Vector128.Load(accumulators + (i * 2));
            Vector128<uint> data = Vector128.Load((uint*)(source + (i * 16)));
            Vector128<uint> key = Vector128.Load((uint*)(secret + (i * 16)));
            Vector128<uint> dataKey = data ^ key;

            Vector64<uint> evens = Vector128.Shuffle(dataKey, Vector128.Create(0u, 2, 0, 0)).GetLower();
            Vector64<uint> odds = Vector128.Shuffle(dataKey, Vector128.Create(1u, 3, 0, 0)).GetLower();
            Vector128<ulong> product = AdvSimd.MultiplyWideningLower(evens, odds);

            Vector128<ulong> swapped = Vector128.Shuffle(data.AsUInt64(), s_swapMask);
            acc = acc + swapped + product;
            acc.Store(accumulators + (i * 2));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Scramble(ulong* accumulators, byte* secret)
    {
        for (int i = 0; i < 4; i++)
        {
            Vector128<ulong> acc = Vector128.Load(accumulators + (i * 2));
            Vector128<ulong> key = Vector128.Load((ulong*)(secret + (i * 16)));
            Vector128<ulong> xorShift = acc ^ Vector128.ShiftRightLogical(acc, 47);
            acc = (xorShift ^ key) * s_scramblePrime;
            acc.Store(accumulators + (i * 2));
        }
    }
}
