namespace Glacier.Codec.Hashing.XxHash32;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Standalone, clean-room, zero-allocation implementation of xxHash32 and xxHash64 non-cryptographic checksum algorithms.
/// Used for LZ4 frame descriptors, LZ4 content checksums, and Zstandard (RFC 8878) frame checksums.
/// </summary>
public static unsafe class XxHash32
{
    public const uint Prime32_1 = 2654435761U; // 0x9E3779B1
    public const uint Prime32_2 = 2246822519U; // 0x85EBCA77
    public const uint Prime32_3 = 3266489917U; // 0xC2B2AE3D
    public const uint Prime32_4 = 668265263U;  // 0x27D4EB2F
    public const uint Prime32_5 = 374761393U;  // 0x165667B1

    public const ulong Prime64_1 = 11400714785074694791UL; // 0x9E3779B185EBCA87
    public const ulong Prime64_2 = 14029467366897019727UL; // 0xC2B2AE3D27D4EB4F
    public const ulong Prime64_3 = 1609587929392839161UL;  // 0x165667B19E3779F9
    public const ulong Prime64_4 = 9650029242287828579UL;  // 0x85EBCA77C2B2AE63
    public const ulong Prime64_5 = 2870177450012600261UL;  // 0x27D4EB2F165667C5

    /// <summary>
    /// Computes the 32-bit xxHash of the input data using the specified seed.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(ReadOnlySpan<byte> source, uint seed = 0)
    {
        uint h32;
        int length = source.Length;

        fixed (byte* pSource = source)
        {
            byte* p = pSource;
            byte* bEnd = p + length;

            if (length >= 16)
            {
                byte* limit = bEnd - 16;
                uint v1 = seed + Prime32_1 + Prime32_2;
                uint v2 = seed + Prime32_2;
                uint v3 = seed + 0;
                uint v4 = seed - Prime32_1;

                do
                {
                    v1 = BitOperations.RotateLeft(v1 + BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p, 4)) * Prime32_2, 13) * Prime32_1;
                    v2 = BitOperations.RotateLeft(v2 + BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p + 4, 4)) * Prime32_2, 13) * Prime32_1;
                    v3 = BitOperations.RotateLeft(v3 + BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p + 8, 4)) * Prime32_2, 13) * Prime32_1;
                    v4 = BitOperations.RotateLeft(v4 + BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p + 12, 4)) * Prime32_2, 13) * Prime32_1;
                    p += 16;
                }
                while (p <= limit);

                h32 = BitOperations.RotateLeft(v1, 1) +
                      BitOperations.RotateLeft(v2, 7) +
                      BitOperations.RotateLeft(v3, 12) +
                      BitOperations.RotateLeft(v4, 18);
            }
            else
            {
                h32 = seed + Prime32_5;
            }

            h32 += (uint)length;

            while (p + 4 <= bEnd)
            {
                h32 = BitOperations.RotateLeft(h32 + BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p, 4)) * Prime32_3, 17) * Prime32_4;
                p += 4;
            }

            while (p < bEnd)
            {
                h32 = BitOperations.RotateLeft(h32 + (uint)(*p) * Prime32_5, 11) * Prime32_1;
                p++;
            }
        }

        h32 ^= h32 >> 15;
        h32 *= Prime32_2;
        h32 ^= h32 >> 13;
        h32 *= Prime32_3;
        h32 ^= h32 >> 16;

        return h32;
    }

    /// <summary>
    /// Computes the 64-bit xxHash of the input data using the specified seed.
    /// Conforms to RFC 8878 Zstandard content checksum specification.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<byte> source, ulong seed = 0)
    {
        ulong h64;
        int length = source.Length;

        fixed (byte* pSource = source)
        {
            byte* p = pSource;
            byte* bEnd = p + length;

            if (length >= 32)
            {
                byte* limit = bEnd - 32;
                ulong v1 = seed + Prime64_1 + Prime64_2;
                ulong v2 = seed + Prime64_2;
                ulong v3 = seed + 0;
                ulong v4 = seed - Prime64_1;

                do
                {
                    v1 = BitOperations.RotateLeft(v1 + BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(p, 8)) * Prime64_2, 31) * Prime64_1;
                    v2 = BitOperations.RotateLeft(v2 + BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(p + 8, 8)) * Prime64_2, 31) * Prime64_1;
                    v3 = BitOperations.RotateLeft(v3 + BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(p + 16, 8)) * Prime64_2, 31) * Prime64_1;
                    v4 = BitOperations.RotateLeft(v4 + BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(p + 24, 8)) * Prime64_2, 31) * Prime64_1;
                    p += 32;
                }
                while (p <= limit);

                h64 = BitOperations.RotateLeft(v1, 1) +
                      BitOperations.RotateLeft(v2, 7) +
                      BitOperations.RotateLeft(v3, 12) +
                      BitOperations.RotateLeft(v4, 18);

                h64 = MergeRound64(h64, v1);
                h64 = MergeRound64(h64, v2);
                h64 = MergeRound64(h64, v3);
                h64 = MergeRound64(h64, v4);
            }
            else
            {
                h64 = seed + Prime64_5;
            }

            h64 += (ulong)length;

            while (p + 8 <= bEnd)
            {
                ulong k1 = BitOperations.RotateLeft(BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(p, 8)) * Prime64_2, 31) * Prime64_1;
                h64 = BitOperations.RotateLeft(h64 ^ k1, 27) * Prime64_1 + Prime64_4;
                p += 8;
            }

            if (p + 4 <= bEnd)
            {
                h64 = BitOperations.RotateLeft(h64 ^ ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p, 4)) * Prime64_1), 23) * Prime64_2 + Prime64_3;
                p += 4;
            }

            while (p < bEnd)
            {
                h64 = BitOperations.RotateLeft(h64 ^ ((ulong)(*p) * Prime64_5), 11) * Prime64_1;
                p++;
            }
        }

        h64 ^= h64 >> 33;
        h64 *= Prime64_2;
        h64 ^= h64 >> 29;
        h64 *= Prime64_3;
        h64 ^= h64 >> 32;

        return h64;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MergeRound64(ulong acc, ulong val)
    {
        val = BitOperations.RotateLeft(val * Prime64_2, 31) * Prime64_1;
        acc ^= val;
        acc = acc * Prime64_1 + Prime64_4;
        return acc;
    }
}
