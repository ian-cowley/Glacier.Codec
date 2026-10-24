namespace Glacier.Codec.Compression.Lz4;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

/// <summary>
/// Hardware-accelerated match finder and forward match extension engine for LZ4 compression.
/// Utilizes SIMD Vector256/Vector128, 64-bit difference scanning, and multiplicative Fibonacci hashing.
/// </summary>
public static unsafe class Lz4MatchFinder
{
    /// <summary>
    /// Computes the 14-bit hash table index from 4 bytes of input.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ComputeHash(uint value)
    {
        return (int)((value * Lz4Constants.KnuthFactor) >> (32 - Lz4Constants.HashLog));
    }

    /// <summary>
    /// Computes the 14-bit hash table index directly from a memory pointer.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ComputeHash(byte* ptr)
    {
        uint val = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(ptr, 4));
        return ComputeHash(val);
    }

    /// <summary>
    /// Extends a match forward from the current positions using vectorized SIMD and 64-bit diff operations.
    /// </summary>
    /// <param name="ip">Pointer to current input position after initial 4-byte match.</param>
    /// <param name="match">Pointer to candidate match position after initial 4-byte match.</param>
    /// <param name="matchLimit">Upper boundary limit pointer for input stream.</param>
    /// <returns>Number of additional matching bytes beyond initial 4 bytes.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ExtendMatch(byte* ip, byte* match, byte* matchLimit)
    {
        byte* pIn = ip;
        byte* pMatch = match;

        // 1. Vector256 32-byte SIMD chunk comparison if hardware accelerated
        if (Vector256.IsHardwareAccelerated)
        {
            while (pIn + 32 <= matchLimit)
            {
                Vector256<byte> v1 = Vector256.Load(pIn);
                Vector256<byte> v2 = Vector256.Load(pMatch);
                Vector256<byte> eq = Vector256.Equals(v1, v2);
                uint mask = eq.ExtractMostSignificantBits();
                if (mask != 0xFFFFFFFF)
                {
                    int matchCount = BitOperations.TrailingZeroCount(~mask);
                    return (int)(pIn - ip) + matchCount;
                }
                pIn += 32;
                pMatch += 32;
            }
        }

        // 2. Vector128 16-byte SIMD chunk comparison
        if (Vector128.IsHardwareAccelerated)
        {
            while (pIn + 16 <= matchLimit)
            {
                Vector128<byte> v1 = Vector128.Load(pIn);
                Vector128<byte> v2 = Vector128.Load(pMatch);
                Vector128<byte> eq = Vector128.Equals(v1, v2);
                uint mask = eq.ExtractMostSignificantBits();
                if (mask != 0xFFFF)
                {
                    int matchCount = BitOperations.TrailingZeroCount(~mask);
                    return (int)(pIn - ip) + matchCount;
                }
                pIn += 16;
                pMatch += 16;
            }
        }

        // 3. 64-bit word XOR difference comparison
        while (pIn + 8 <= matchLimit)
        {
            ulong diff = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(pIn, 8)) ^
                         BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(pMatch, 8));
            if (diff == 0)
            {
                pIn += 8;
                pMatch += 8;
            }
            else
            {
                int matchCount = BitOperations.TrailingZeroCount(diff) >> 3;
                return (int)(pIn - ip) + matchCount;
            }
        }

        // 4. Scalar fallback for trailing bytes
        while (pIn < matchLimit && *pIn == *pMatch)
        {
            pIn++;
            pMatch++;
        }

        return (int)(pIn - ip);
    }
}
