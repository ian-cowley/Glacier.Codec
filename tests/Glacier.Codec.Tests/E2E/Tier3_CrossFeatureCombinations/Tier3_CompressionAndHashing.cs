using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.XxHash3;

namespace Glacier.Codec.Tests.E2E.Tier3_CrossFeatureCombinations;

public class Tier3_CompressionAndHashing
{
    [Fact]
    public void Pairwise_Lz4Compression_WithBlake3Checksum_IntegrityVerified()
    {
        byte[] payload = new byte[8192];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 127);

        // 1. Compress via LZ4
        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(payload.Length)];
        int compLen = Lz4Codec.Compress(payload, compressed);

        // 2. Compute BLAKE3 tree hash over compressed buffer
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(compressed.AsSpan(0, compLen), hash);

        // 3. Verify hash is repeatable
        Span<byte> verifyHash = stackalloc byte[32];
        Blake3Hasher.Hash(compressed.AsSpan(0, compLen), verifyHash);
        Assert.True(hash.SequenceEqual(verifyHash));

        // 4. Decompress and verify content roundtrip
        byte[] decompressed = new byte[payload.Length];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), decompressed);
        Assert.Equal(payload.Length, decompLen);
        Assert.Equal(payload, decompressed);
    }

    [Fact]
    public void Pairwise_ZstdCompression_WithXxHash3IntegrityDigest()
    {
        string text = "High-throughput data storage block with Zstandard compression and xxHash3 indexing.";
        byte[] input = Encoding.UTF8.GetBytes(text);

        // 1. Compress with Zstd
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int compLen = ZstdCodec.Compress(input, compressed);

        // 2. Hash with xxHash3 64-bit
        ulong originalHash = XxHash3Hasher.Hash64(input);
        ulong compressedHash = XxHash3Hasher.Hash64(compressed.AsSpan(0, compLen));
        Assert.NotEqual(originalHash, compressedHash);

        // 3. Decompress and verify hash matches original
        byte[] decompressed = new byte[input.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);
        Assert.Equal(input.Length, decompLen);

        ulong roundtripHash = XxHash3Hasher.Hash64(decompressed);
        Assert.Equal(originalHash, roundtripHash);
    }

    [Fact]
    public void Pairwise_CorruptedCompressedStream_DetectedByHashBeforeDecompress()
    {
        byte[] payload = new byte[1024];
        RandomNumberGenerator.Fill(payload);

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(payload.Length)];
        int compLen = Lz4Codec.Compress(payload, compressed);

        Span<byte> expectedHash = stackalloc byte[32];
        Blake3Hasher.Hash(compressed.AsSpan(0, compLen), expectedHash);

        // Tamper with compressed bitstream
        compressed[compLen / 2] ^= 0xAA;

        Span<byte> actualHash = stackalloc byte[32];
        Blake3Hasher.Hash(compressed.AsSpan(0, compLen), actualHash);

        // Integrity check detects tampering before invoking decompressor
        Assert.False(expectedHash.SequenceEqual(actualHash));
    }
}
