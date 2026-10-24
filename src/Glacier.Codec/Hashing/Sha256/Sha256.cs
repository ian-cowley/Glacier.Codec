namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// Static, pure first-party zero-allocation cryptographic SHA-256 hash engine conforming to NIST FIPS 180-4.
/// Executes hardware-accelerated block compression (SHA-NI / ARMv8 Crypto / unrolled scalar) via <see cref="Sha256Kernel"/>.
/// </summary>
public static class Sha256
{
    public const int HashSizeInBytes = 32;
    public const int BlockSizeInBytes = 64;

    /// <summary>
    /// Computes the SHA-256 hash of <paramref name="source"/> into <paramref name="destination"/> with zero heap allocations.
    /// Routes block compression through the first-party <see cref="Sha256Kernel"/> hardware dispatch pipeline.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Hash(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (destination.Length < HashSizeInBytes)
        {
            throw new ArgumentException($"Destination span must be at least {HashSizeInBytes} bytes.", nameof(destination));
        }

        ComputeHashCore(source, destination.Slice(0, HashSizeInBytes));
    }

    /// <summary>
    /// Attempts to compute the SHA-256 hash into <paramref name="destination"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryHash(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length < HashSizeInBytes)
        {
            bytesWritten = 0;
            return false;
        }

        Hash(source, destination);
        bytesWritten = HashSizeInBytes;
        return true;
    }

    /// <summary>
    /// Compares a computed SHA-256 hash against an expected digest in constant time to prevent timing side channels.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool VerifyHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> expectedDigest)
    {
        if (expectedDigest.Length != HashSizeInBytes)
        {
            return false;
        }

        Span<byte> actualDigest = stackalloc byte[HashSizeInBytes];
        Hash(source, actualDigest);
        return CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void ComputeHashCore(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Sha256State state = Sha256State.CreateInitial();
        int fullBlocks = source.Length / BlockSizeInBytes;
        int processedBytes = fullBlocks * BlockSizeInBytes;

        if (fullBlocks > 0)
        {
            Sha256Kernel.CompressBlocks(ref state, source.Slice(0, processedBytes));
        }

        ReadOnlySpan<byte> remainder = source.Slice(processedBytes);
        Span<byte> padBuffer = stackalloc byte[128];
        remainder.CopyTo(padBuffer);
        int padLen = remainder.Length;

        padBuffer[padLen++] = 0x80;

        int totalBlocks;
        if (padLen <= 56)
        {
            padBuffer.Slice(padLen, 56 - padLen).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(padBuffer.Slice(56, 8), (ulong)source.Length * 8UL);
            totalBlocks = 1;
        }
        else
        {
            padBuffer.Slice(padLen, 64 - padLen).Clear();
            padBuffer.Slice(64, 56).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(padBuffer.Slice(120, 8), (ulong)source.Length * 8UL);
            totalBlocks = 2;
        }

        Sha256Kernel.CompressBlocks(ref state, padBuffer.Slice(0, totalBlocks * BlockSizeInBytes));
        state.WriteDigest(destination);
        CryptographicOperations.ZeroMemory(padBuffer);
    }
}
