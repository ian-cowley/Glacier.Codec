namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Unified xxHash3 streaming hasher and static facade compatible with both high-throughput one-shot
/// methods and <see cref="Glacier.Codec.Hashing.IStreamingHasher"/> streaming workflows.
/// </summary>
public sealed class XxHash3Hasher : XxHash3Stream
{
    public XxHash3Hasher(ulong seed = 0) : base(8, seed) { }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<byte> source, ulong seed = 0) =>
        XxHash3.Hash64(source, seed);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128 Hash128(ReadOnlySpan<byte> source, ulong seed = 0) =>
        XxHash3.Hash128(source, seed);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Hash64(ReadOnlySpan<byte> source, Span<byte> destination, ulong seed = 0)
    {
        if (destination.Length < 8)
        {
            throw new ArgumentException("Destination span must be at least 8 bytes.", nameof(destination));
        }
        ulong hash = XxHash3.Hash64(source, seed);
        BinaryPrimitives.WriteUInt64LittleEndian(destination, hash);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Hash128(ReadOnlySpan<byte> source, Span<byte> destination, ulong seed = 0)
    {
        if (destination.Length < 16)
        {
            throw new ArgumentException("Destination span must be at least 16 bytes.", nameof(destination));
        }
        UInt128 hash = XxHash3.Hash128(source, seed);
        BinaryPrimitives.WriteUInt64LittleEndian(destination, (ulong)(hash & ulong.MaxValue));
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), (ulong)(hash >> 64));
    }
}
