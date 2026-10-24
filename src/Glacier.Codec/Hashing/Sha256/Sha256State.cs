namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// 256-bit SHA-256 internal working state registers (H0..H7).
/// </summary>
public struct Sha256State
{
    public uint H0;
    public uint H1;
    public uint H2;
    public uint H3;
    public uint H4;
    public uint H5;
    public uint H6;
    public uint H7;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Sha256State CreateInitial() => new()
    {
        H0 = 0x6a09e667,
        H1 = 0xbb67ae85,
        H2 = 0x3c6ef372,
        H3 = 0xa54ff53a,
        H4 = 0x510e527f,
        H5 = 0x9b05688c,
        H6 = 0x1f83d9ab,
        H7 = 0x5be0cd19
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteDigest(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(0, 4), H0);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4, 4), H1);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8, 4), H2);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12, 4), H3);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16, 4), H4);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(20, 4), H5);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(24, 4), H6);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(28, 4), H7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Zeroize()
    {
        H0 = H1 = H2 = H3 = H4 = H5 = H6 = H7 = 0;
    }
}
