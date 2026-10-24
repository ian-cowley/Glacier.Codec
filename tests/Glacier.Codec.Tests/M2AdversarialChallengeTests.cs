namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Glacier.Codec.Hardware;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;

/// <summary>
/// Adversarial stress tests for Milestone M2:
/// - Unaligned memory span loads (offsets 1..7) across critical boundary sizes.
/// - Streaming single-byte ingestion across 64B, 240B, and 1024B boundaries.
/// - Bit-exact parity between one-shot and streaming hashers.
/// - Verification of zero GC heap allocations on hot hashing paths.
/// </summary>
public unsafe class M2AdversarialChallengeTests
{
    private static readonly int[] BoundarySizes =
    [
        0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33,
        63, 64, 65, 127, 128, 129, 239, 240, 241, 255, 256,
        1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097
    ];

    // =========================================================================
    // 1. UNALIGNED MEMORY LOAD SAFETY (Offsets 1..7)
    // =========================================================================

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    public void XxHash3_UnalignedMemoryOffsets_DoNotFaultAndMatchExpected(int offset)
    {
        foreach (int size in BoundarySizes)
        {
            byte[] backing = new byte[size + offset + 64];
            for (int i = 0; i < backing.Length; i++) backing[i] = (byte)(i * 37 + 11);

            ReadOnlySpan<byte> unalignedSpan = backing.AsSpan(offset, size);
            byte[] alignedCopy = unalignedSpan.ToArray();

            ulong expected64 = System.IO.Hashing.XxHash3.HashToUInt64(alignedCopy);
            ulong actual64 = XxHash3Hasher.Hash64(unalignedSpan);
            Assert.Equal(expected64, actual64);

            UInt128 hash128Unaligned = XxHash3Hasher.Hash128(unalignedSpan);
            UInt128 hash128Aligned = XxHash3Hasher.Hash128(alignedCopy);
            Assert.Equal(hash128Aligned, hash128Unaligned);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    public void Blake3_UnalignedMemoryOffsets_DoNotFaultAndMatchAligned(int offset)
    {
        Span<byte> hUnaligned = stackalloc byte[32];
        Span<byte> hAligned = stackalloc byte[32];

        foreach (int size in BoundarySizes)
        {
            byte[] backing = new byte[size + offset + 64];
            for (int i = 0; i < backing.Length; i++) backing[i] = (byte)(i * 41 + 13);

            ReadOnlySpan<byte> unalignedSpan = backing.AsSpan(offset, size);
            byte[] alignedCopy = unalignedSpan.ToArray();

            Blake3Hasher.Hash(unalignedSpan, hUnaligned);
            Blake3Hasher.Hash(alignedCopy, hAligned);

            Assert.True(hAligned.SequenceEqual(hUnaligned), $"Blake3 unaligned mismatch at size={size}, offset={offset}");
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    public void Sha256_UnalignedMemoryOffsets_DoNotFaultAndMatchAligned(int offset)
    {
        Span<byte> hUnaligned = stackalloc byte[32];
        Span<byte> hAligned = stackalloc byte[32];

        foreach (int size in BoundarySizes)
        {
            byte[] backing = new byte[size + offset + 64];
            for (int i = 0; i < backing.Length; i++) backing[i] = (byte)(i * 43 + 17);

            ReadOnlySpan<byte> unalignedSpan = backing.AsSpan(offset, size);
            byte[] alignedCopy = unalignedSpan.ToArray();

            Sha256Hasher.Hash(unalignedSpan, hUnaligned);
            Sha256Hasher.Hash(alignedCopy, hAligned);

            Assert.True(hAligned.SequenceEqual(hUnaligned), $"Sha256 unaligned mismatch at size={size}, offset={offset}");
        }
    }

    // =========================================================================
    // 2. PATHOLOGICAL 1-BYTE-AT-A-TIME STREAMING
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(239)]
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(2050)]
    public void XxHash3_StreamingByteByByte_MatchesOneShot(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < length; i++) payload[i] = (byte)(i * 29 + 3);

        ulong expected = XxHash3Hasher.Hash64(payload);

        using var streamHasher = new XxHash3Hasher();
        for (int i = 0; i < length; i++)
        {
            streamHasher.Append(payload.AsSpan(i, 1));
        }

        Span<byte> digest = stackalloc byte[8];
        streamHasher.Finalize(digest);
        ulong actual = BinaryPrimitives.ReadUInt64LittleEndian(digest);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(2048)]
    public void Blake3_StreamingByteByByte_MatchesOneShot(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < length; i++) payload[i] = (byte)(i * 31 + 5);

        Span<byte> expected = stackalloc byte[32];
        Blake3Hasher.Hash(payload, expected);

        using var streamHasher = new Blake3Hasher();
        for (int i = 0; i < length; i++)
        {
            streamHasher.Append(payload.AsSpan(i, 1));
        }

        Span<byte> actual = stackalloc byte[32];
        streamHasher.Finalize(actual);

        Assert.True(expected.SequenceEqual(actual), $"Blake3 byte-by-byte mismatch at length={length}");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    public void Sha256_StreamingByteByByte_MatchesOneShot(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < length; i++) payload[i] = (byte)(i * 33 + 7);

        Span<byte> expected = stackalloc byte[32];
        Sha256Hasher.Hash(payload, expected);

        using var streamHasher = new Sha256Hasher();
        for (int i = 0; i < length; i++)
        {
            streamHasher.Append(payload.AsSpan(i, 1));
        }

        Span<byte> actual = stackalloc byte[32];
        streamHasher.Finalize(actual);

        Assert.True(expected.SequenceEqual(actual), $"Sha256 byte-by-byte mismatch at length={length}");
    }

    // =========================================================================
    // 3. ZERO HEAP ALLOCATIONS ON HOT PATH
    // =========================================================================

    [Fact]
    public void XxHash3_ZeroAllocations_OneShotAndStreaming()
    {
        byte[] data = new byte[2048];
        Array.Fill(data, (byte)0x55);
        Span<byte> dest = stackalloc byte[8];

        // Warmup
        XxHash3Hasher.Hash64(data, dest);
        using var stream = new XxHash3Hasher();
        stream.Append(data);
        stream.Finalize(dest);

        // One-shot test
        long beforeOneShot = GC.GetAllocatedBytesForCurrentThread();
        XxHash3Hasher.Hash64(data, dest);
        long afterOneShot = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, afterOneShot - beforeOneShot);

        // Streaming test
        stream.Reset();
        long beforeStream = GC.GetAllocatedBytesForCurrentThread();
        stream.Append(data.AsSpan(0, 1024));
        stream.Append(data.AsSpan(1024, 1024));
        stream.Finalize(dest);
        long afterStream = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, afterStream - beforeStream);
    }

    [Fact]
    public void Blake3_ZeroAllocations_OneShotAndStreaming()
    {
        byte[] data = new byte[2048];
        Array.Fill(data, (byte)0x77);
        Span<byte> dest = stackalloc byte[32];

        // Warmup JIT with exact call pattern
        for (int w = 0; w < 5; w++)
        {
            Blake3Hasher.Hash(data, dest);
            using var streamWarm = new Blake3Hasher();
            streamWarm.Append(data.AsSpan(0, 1024));
            streamWarm.Append(data.AsSpan(1024, 1024));
            streamWarm.Finalize(dest);
        }

        // One-shot test: Verifies zero heap allocation on remediated one-shot Hash
        long beforeOneShot = GC.GetAllocatedBytesForCurrentThread();
        Blake3Hasher.Hash(data, dest);
        long afterOneShot = GC.GetAllocatedBytesForCurrentThread();
        long oneShotAlloc = afterOneShot - beforeOneShot;
        Assert.Equal(0, oneShotAlloc);

        // Streaming test: Reusing an already allocated instance allocates 0 bytes during Append/Finalize
        using var stream = new Blake3Hasher();
        long beforeStream = GC.GetAllocatedBytesForCurrentThread();
        stream.Append(data.AsSpan(0, 1024));
        stream.Append(data.AsSpan(1024, 1024));
        stream.Finalize(dest);
        long afterStream = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, afterStream - beforeStream);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(240)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(8192)]
    [InlineData(65536)]
    public void Blake3_OneShot_ZeroAllocations_VaryingSizesAndKeyed(int size)
    {
        byte[] data = new byte[size];
        Random.Shared.NextBytes(data);
        byte[] key = new byte[32];
        Random.Shared.NextBytes(key);
        Span<byte> dest = stackalloc byte[32];

        // Warmup JIT
        for (int i = 0; i < 5; i++)
        {
            Blake3Hasher.Hash(data, dest);
            Blake3Hasher.HashKeyed(data, key, dest);
        }

        // Test one-shot Hash
        long before = GC.GetAllocatedBytesForCurrentThread();
        Blake3Hasher.Hash(data, dest);
        long after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);

        // Test one-shot HashKeyed
        before = GC.GetAllocatedBytesForCurrentThread();
        Blake3Hasher.HashKeyed(data, key, dest);
        after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);
    }

    [Fact]
    public void Blake3_CreateKeyDerivation_AllocatesHeapMemory_ViolationDetected()
    {
        // This test documents whether CreateKeyDerivation violates zero-heap allocation rule
        string context = "AdversarialContextString";

        // Warmup
        using var kdfWarm = Blake3Hasher.CreateKeyDerivation(context);

        long before = GC.GetAllocatedBytesForCurrentThread();
        using var kdf = Blake3Hasher.CreateKeyDerivation(context);
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocatedBytes = after - before;
        // Encoding.UTF8.GetBytes(context) allocates a byte[] array on the heap!
        // We assert this finding empirically:
        Assert.True(allocatedBytes > 0, "Blake3Hasher.CreateKeyDerivation allocated bytes on heap due to Encoding.UTF8.GetBytes(context)");
    }
}
