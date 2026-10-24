namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Portable 32-bit scalar implementation of ChaCha20 quarter-rounds and block generation (RFC 8439).
/// </summary>
internal static class ChaCha20KernelScalar
{
    private const uint C0 = 0x61707865;
    private const uint C1 = 0x3320646e;
    private const uint C2 = 0x79622d32;
    private const uint C3 = 0x6b206574;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d = BitOperations.RotateLeft(d ^ a, 16);
        c += d; b = BitOperations.RotateLeft(b ^ c, 12);
        a += b; d = BitOperations.RotateLeft(d ^ a, 8);
        c += d; b = BitOperations.RotateLeft(b ^ c, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void GenerateBlock(
        ReadOnlySpan<byte> key,
        uint counter,
        ReadOnlySpan<byte> nonce,
        Span<byte> destination)
    {
        uint k0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
        uint k1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
        uint k2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
        uint k3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
        uint k4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
        uint k5 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
        uint k6 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
        uint k7 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));

        uint n0 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
        uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
        uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));

        uint s0 = C0, s1 = C1, s2 = C2, s3 = C3;
        uint s4 = k0, s5 = k1, s6 = k2, s7 = k3;
        uint s8 = k4, s9 = k5, s10 = k6, s11 = k7;
        uint s12 = counter, s13 = n0, s14 = n1, s15 = n2;

        for (int r = 0; r < 10; r++)
        {
            // Column round
            QuarterRound(ref s0, ref s4, ref s8, ref s12);
            QuarterRound(ref s1, ref s5, ref s9, ref s13);
            QuarterRound(ref s2, ref s6, ref s10, ref s14);
            QuarterRound(ref s3, ref s7, ref s11, ref s15);

            // Diagonal round
            QuarterRound(ref s0, ref s5, ref s10, ref s15);
            QuarterRound(ref s1, ref s6, ref s11, ref s12);
            QuarterRound(ref s2, ref s7, ref s8, ref s13);
            QuarterRound(ref s3, ref s4, ref s9, ref s14);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(0, 4), s0 + C0);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4, 4), s1 + C1);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8, 4), s2 + C2);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12, 4), s3 + C3);

        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(16, 4), s4 + k0);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(20, 4), s5 + k1);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(24, 4), s6 + k2);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(28, 4), s7 + k3);

        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(32, 4), s8 + k4);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(36, 4), s9 + k5);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(40, 4), s10 + k6);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(44, 4), s11 + k7);

        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(48, 4), s12 + counter);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(52, 4), s13 + n0);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(56, 4), s14 + n1);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(60, 4), s15 + n2);
    }
}
