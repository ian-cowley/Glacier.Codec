namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;
using Xunit;

/// <summary>
/// Tier 5 Adversarial Test Suite for Hashing & Digest Engine.
/// Probes BLAKE3 odd chunk count foldings, parallel reduction parity, XOF seeks past 4GB/1TB,
/// SHA-256 padding schedule boundaries, and xxHash3 240-byte mid-size transitions.
/// </summary>
public sealed class Tier5AdversarialHashingTests
{
    // =========================================================================
    // 1. BLAKE3 Merkle Tree Foldings Across Odd, Prime & Extreme Chunk Counts
    // =========================================================================

    [Theory]
    [InlineData(1)]     // 1,024 B - single leaf root
    [InlineData(2)]     // 2,048 B - balanced 2-leaf tree
    [InlineData(3)]     // 3,072 B - subtree (0,1) + leaf 2
    [InlineData(5)]     // 5,120 B - subtree (0..3) + leaf 4
    [InlineData(7)]     // 7,168 B - subtree (0..3) + subtree (4..5) + leaf 6
    [InlineData(9)]     // 9,216 B - crosses AVX2 8-way boundary (0..7) + leaf 8
    [InlineData(15)]    // 15,360 B - (0..7) + (8..11) + (12..13) + leaf 14
    [InlineData(17)]    // 17,408 B - crosses AVX-512 16-way boundary (0..15) + leaf 16
    [InlineData(33)]    // 33,792 B - (0..31) + leaf 32
    [InlineData(65)]    // 66,560 B - (0..63) + leaf 64
    public void Blake3_OddAndExtremeChunkCounts_MerkleFoldingParity(int chunkCount)
    {
        int byteCount = chunkCount * Blake3Constants.ChunkSize;
        byte[] payload = new byte[byteCount];
        RandomNumberGenerator.Fill(payload);

        byte[] oneShotHash = new byte[32];
        byte[] streamingHash = new byte[32];

        Blake3Hasher.Hash(payload, oneShotHash);

        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.Finalize(streamingHash);
        }

        Assert.Equal(oneShotHash, streamingHash);
    }

    [Theory]
    [InlineData(1025)] // 1,049,600 B (just over 1 MB parallel threshold)
    [InlineData(1027)] // 1,051,648 B
    [InlineData(1049)] // 1,074,176 B (prime chunk count)
    [InlineData(2047)] // 2,096,128 B
    [InlineData(2049)] // 2,098,176 B
    public void Blake3_ParallelVsSequentialStreaming_ExactParity(int chunkCount)
    {
        int byteCount = chunkCount * Blake3Constants.ChunkSize;
        byte[] payload = new byte[byteCount];
        RandomNumberGenerator.Fill(payload);

        byte[] parallelHash = new byte[32];
        byte[] streamingHash = new byte[32];

        // One-shot triggers parallel reduction on workloads >= 1MB
        Blake3Hasher.Hash(payload, parallelHash);

        // Streaming always evaluates via sequential incremental state
        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.Finalize(streamingHash);
        }

        Assert.Equal(streamingHash, parallelHash);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1023)]
    public void Blake3_ParallelFractionalTails_ExactParity(int extraBytes)
    {
        int byteCount = (1025 * Blake3Constants.ChunkSize) + extraBytes;
        byte[] payload = new byte[byteCount];
        RandomNumberGenerator.Fill(payload);

        byte[] parallelHash = new byte[32];
        byte[] streamingHash = new byte[32];

        Blake3Hasher.Hash(payload, parallelHash);

        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.Finalize(streamingHash);
        }

        Assert.Equal(streamingHash, parallelHash);
    }

    // =========================================================================
    // 2. BLAKE3 Arbitrary-Length XOF Seeks (Past 4 GB & 1 TB)
    // =========================================================================

    [Fact]
    public void Blake3_Xof_SequentialVsSeekOffset_Parity()
    {
        byte[] payload = "Glacier.Codec Tier 5 Adversarial XOF Verification Stream"u8.ToArray();

        // 1. Generate 256 bytes continuously from offset 0
        byte[] longStream = new byte[256];
        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.FinalizeSeek(0, longStream);
        }

        // 2. Seek at offset 31 for 33 bytes (straddling block boundary 64)
        byte[] straddleBlock = new byte[33];
        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.FinalizeSeek(31, straddleBlock);
        }

        Assert.Equal(longStream.AsSpan(31, 33).ToArray(), straddleBlock);

        // 3. Seek at offset 64 for 64 bytes (exact second block)
        byte[] secondBlock = new byte[64];
        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.FinalizeSeek(64, secondBlock);
        }

        Assert.Equal(longStream.AsSpan(64, 64).ToArray(), secondBlock);
    }

    [Fact]
    public void Blake3_Xof_SeekPast4GB_CounterOverflow_Deterministic()
    {
        byte[] payload = "High-offset XOF seek test beyond 32-bit counter limits"u8.ToArray();

        // 4 GB seek (2^32 bytes)
        ulong seek4Gb = 4_294_967_296UL;
        byte[] outA = new byte[64];
        byte[] outB = new byte[64];

        using (var hasher1 = new Blake3Hasher())
        {
            hasher1.Append(payload);
            hasher1.FinalizeSeek(seek4Gb, outA);
        }

        using (var hasher2 = new Blake3Hasher())
        {
            hasher2.Append(payload);
            hasher2.FinalizeSeek(seek4Gb, outB);
        }

        Assert.Equal(outA, outB);
        Assert.False(outA.AsSpan().SequenceEqual(new byte[64])); // Not all zeros
    }

    [Fact]
    public void Blake3_Xof_Seek1Terabyte_Deterministic()
    {
        byte[] payload = "Terabyte-scale XOF seek test"u8.ToArray();
        ulong seek1Tb = 1_000_000_000_000UL;

        byte[] out1 = new byte[32];
        byte[] out2 = new byte[32];

        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.FinalizeSeek(seek1Tb, out1);
        }

        using (var hasher = new Blake3Hasher())
        {
            hasher.Append(payload);
            hasher.FinalizeSeek(seek1Tb, out2);
        }

        Assert.Equal(out1, out2);
        Assert.False(out1.AsSpan().SequenceEqual(new byte[32]));
    }

    // =========================================================================
    // 3. SHA-256 Message Schedule Padding Boundaries & Fragmented Streaming
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]  // Exactly fits in single 64-byte block with 8-byte length
    [InlineData(56)]  // Spills into double block (128 bytes)
    [InlineData(63)]  // Last byte of first block
    [InlineData(64)]  // Exact 1-block message, spills into second block
    [InlineData(119)] // Exactly fits in 2 blocks (128 bytes)
    [InlineData(120)] // Spills into 3 blocks (192 bytes)
    public void Sha256_PaddingSchedule_ExactBlockTransitions(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        RandomNumberGenerator.Fill(payload);

        byte[] expected = System.Security.Cryptography.SHA256.HashData(payload);
        byte[] actual = new byte[32];

        Sha256.Hash(payload, actual);
        Assert.Equal(expected, actual);

        // Verify streaming parity
        byte[] streamActual = new byte[32];
        using (var hasher = new Sha256Hasher())
        {
            hasher.Append(payload);
            hasher.Finalize(streamActual);
        }
        Assert.Equal(expected, streamActual);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    public void Sha256_FragmentedStreaming_MatchesOneShot(int fragmentSize)
    {
        byte[] payload = new byte[1000];
        RandomNumberGenerator.Fill(payload);

        byte[] expected = System.Security.Cryptography.SHA256.HashData(payload);
        byte[] actual = new byte[32];

        using var hasher = new Sha256Hasher();
        int offset = 0;
        while (offset < payload.Length)
        {
            int len = Math.Min(fragmentSize, payload.Length - offset);
            hasher.Append(payload.AsSpan(offset, len));
            offset += len;
        }

        hasher.Finalize(actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Sha256_NonMutating_GetCurrentHash_DuringIngestion()
    {
        byte[] payload = new byte[200];
        RandomNumberGenerator.Fill(payload);

        using var hasher = new Sha256Hasher();
        byte[] intermediate = new byte[32];
        byte[] golden = new byte[32];

        for (int i = 1; i <= payload.Length; i++)
        {
            hasher.Append(payload.AsSpan(i - 1, 1));
            hasher.GetCurrentHash(intermediate);

            golden = System.Security.Cryptography.SHA256.HashData(payload.AsSpan(0, i).ToArray());
            Assert.Equal(golden, intermediate);
        }

        byte[] finalDigest = new byte[32];
        hasher.Finalize(finalDigest);
        Assert.Equal(golden, finalDigest);
    }

    // =========================================================================
    // 4. xxHash3 240-Byte Mid-Size Threshold Transitions & Streaming
    // =========================================================================

    [Theory]
    [InlineData(230)]
    [InlineData(238)]
    [InlineData(239)] // MidSizeMax - 1
    [InlineData(240)] // Exact MidSizeMax boundary
    [InlineData(241)] // MidSizeMax + 1 (transitions to 64-byte stripe accumulation)
    [InlineData(242)]
    [InlineData(250)]
    public void XxHash3_240Byte_Threshold_Transition_Unseeded(int length)
    {
        byte[] payload = new byte[length];
        RandomNumberGenerator.Fill(payload);

        ulong h64 = XxHash3.Hash64(payload);
        UInt128 h128 = XxHash3.Hash128(payload);

        Assert.NotEqual(0UL, h64);
        Assert.NotEqual(UInt128.Zero, h128);

        // Parity with 64-bit stream
        using (var stream64 = new XxHash3Stream(hashSize: 8))
        {
            stream64.Append(payload);
            Span<byte> dest64 = stackalloc byte[8];
            stream64.GetCurrentHash(dest64);
            Assert.Equal(h64, BinaryPrimitives.ReadUInt64LittleEndian(dest64));
        }

        // Parity with 128-bit stream
        using (var stream128 = new XxHash3Stream(hashSize: 16))
        {
            stream128.Append(payload);
            Span<byte> dest128 = stackalloc byte[16];
            stream128.GetCurrentHash(dest128);
            ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(dest128);
            ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(dest128.Slice(8));
            UInt128 streamVal = ((UInt128)hi << 64) | lo;
            Assert.Equal(h128, streamVal);
        }
    }

    [Theory]
    [InlineData(239)]
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(242)]
    public void XxHash3_240Byte_Threshold_Transition_Seeded(int length)
    {
        byte[] payload = new byte[length];
        RandomNumberGenerator.Fill(payload);
        const ulong seed = 0x123456789ABCDEF0UL;

        ulong h64 = XxHash3.Hash64(payload, seed);
        UInt128 h128 = XxHash3.Hash128(payload, seed);

        Assert.NotEqual(0UL, h64);
        Assert.NotEqual(UInt128.Zero, h128);

        using (var stream64 = new XxHash3Stream(hashSize: 8, seed: seed))
        {
            stream64.Append(payload);
            Span<byte> dest64 = stackalloc byte[8];
            stream64.GetCurrentHash(dest64);
            Assert.Equal(h64, BinaryPrimitives.ReadUInt64LittleEndian(dest64));
        }

        using (var stream128 = new XxHash3Stream(hashSize: 16, seed: seed))
        {
            stream128.Append(payload);
            Span<byte> dest128 = stackalloc byte[16];
            stream128.GetCurrentHash(dest128);
            ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(dest128);
            ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(dest128.Slice(8));
            UInt128 streamVal = ((UInt128)hi << 64) | lo;
            Assert.Equal(h128, streamVal);
        }
    }

    [Fact]
    public void XxHash3Stream_SingleByteAppend_UpTo300Bytes_Parity()
    {
        byte[] payload = new byte[300];
        RandomNumberGenerator.Fill(payload);

        using var stream = new XxHash3Stream(hashSize: 8);
        Span<byte> dest = stackalloc byte[8];

        for (int i = 1; i <= payload.Length; i++)
        {
            stream.Append(payload.AsSpan(i - 1, 1));

            ulong expected64 = XxHash3.Hash64(payload.AsSpan(0, i));
            stream.GetCurrentHash(dest);
            Assert.Equal(expected64, BinaryPrimitives.ReadUInt64LittleEndian(dest));
        }
    }
}
