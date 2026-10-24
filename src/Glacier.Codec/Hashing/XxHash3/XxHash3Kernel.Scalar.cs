namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Portable 64-bit scalar execution kernel for xxHash3 64-byte stripe accumulation and accumulator scrambling.
/// </summary>
internal static unsafe class XxHash3KernelScalar
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AccumulateStripe(ulong* accumulators, byte* source, byte* secret)
    {
        for (int i = 0; i < 8; i++)
        {
            ulong sourceVal = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(source + (8 * i), 8));
            ulong sourceKey = sourceVal ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + (8 * i), 8));

            accumulators[i ^ 1] += sourceVal;
            accumulators[i] += (ulong)(uint)sourceKey * (uint)(sourceKey >> 32);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Scramble(ulong* accumulators, byte* secret)
    {
        for (int i = 0; i < 8; i++)
        {
            ulong xorShift = accumulators[i] ^ (accumulators[i] >> 47);
            ulong key = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + (8 * i), 8));
            accumulators[i] = (xorShift ^ key) * XxHash3Constants.Prime32_1;
        }
    }
}
