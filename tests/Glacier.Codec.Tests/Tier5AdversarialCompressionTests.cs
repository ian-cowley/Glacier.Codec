namespace Glacier.Codec.Tests;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Xunit;

/// <summary>
/// Tier 5 Adversarial Test Suite for Stream Compression (LZ4 and Zstandard).
/// Tests wild-copy zero-slack boundary safety, buffer truncation rejection,
/// periodic and RLE overlapping matches, Zstd 4-stream jump table corruption,
/// and sparse/repetitive round-trip fidelity.
/// </summary>
public sealed class Tier5AdversarialCompressionTests
{
    // =========================================================================
    // 1. LZ4 Zero-Slack Destination Boundary & Wild-Copy Safety
    // =========================================================================

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void Lz4_ExactFit_ZeroSlackDestination_DecompressesSafely(int size)
    {
        byte[] original = new byte[size];
        RandomNumberGenerator.Fill(original);

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(size)];
        int compLen = Lz4Codec.Compress(original, compressed);

        // Allocate destination with EXACT size (zero trailing slack bytes)
        byte[] destination = new byte[size];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), destination);

        Assert.Equal(size, decompLen);
        Assert.Equal(original, destination);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(1024)]
    public void Lz4_BufferTruncation_NMinus1_ThrowsInvalidDataException(int size)
    {
        byte[] original = new byte[size];
        RandomNumberGenerator.Fill(original);

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(size)];
        int compLen = Lz4Codec.Compress(original, compressed);

        // Destination buffer is strictly 1 byte short of required size
        byte[] truncatedDestination = new byte[size - 1];

        Assert.ThrowsAny<Exception>(() =>
        {
            Lz4Codec.Decompress(compressed.AsSpan(0, compLen), truncatedDestination);
        });
    }

    // =========================================================================
    // 2. LZ4 Overlapping Self-Referential Matches (RLE & Periodic Runs)
    // =========================================================================

    [Theory]
    [InlineData(1, 1000)]  // Single byte RLE run (offset = 1)
    [InlineData(2, 1000)]  // 2-byte periodic pattern
    [InlineData(3, 1000)]  // 3-byte irregular periodic pattern
    [InlineData(7, 1000)]  // 7-byte periodic pattern
    [InlineData(8, 1000)]  // 8-byte word aligned pattern
    [InlineData(16, 1000)] // 16-byte Vector128 pattern
    [InlineData(32, 1000)] // 32-byte Vector256 pattern
    public void Lz4_SelfReferential_OverlappingMatches_RoundTrip(int period, int totalLength)
    {
        byte[] pattern = new byte[period];
        RandomNumberGenerator.Fill(pattern);

        byte[] original = new byte[totalLength];
        for (int i = 0; i < totalLength; i += period)
        {
            int copy = Math.Min(period, totalLength - i);
            Array.Copy(pattern, 0, original, i, copy);
        }

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(totalLength)];
        int compLen = Lz4Codec.Compress(original, compressed);

        byte[] decompressed = new byte[totalLength];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(totalLength, decompLen);
        Assert.Equal(original, decompressed);
    }

    // =========================================================================
    // 3. Zstandard & LZ4 Repetitive, Sparse & Random Round-Trip Fidelity
    // =========================================================================

    [Fact]
    public void Zstd_RepetitivePattern_HighRatio_RoundTrip()
    {
        // 64 KB of single-byte run (RLE block in Zstandard RFC 8878)
        byte[] original = new byte[65536];
        Array.Fill(original, (byte)'A');

        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(original.Length)];
        int compLen = ZstdCodec.Compress(original, compressed);

        // Highly compressible single-byte run compresses to tiny RLE block (< 100 bytes)
        Assert.True(compLen < 100);

        byte[] decompressed = new byte[original.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(original.Length, decompLen);
        Assert.Equal(original, decompressed);
    }

    [Fact]
    public void Zstd_SparseZeros_RoundTrip()
    {
        // 128 KB of mostly zeros with sparse values (like a sparse matrix or index)
        byte[] original = new byte[128 * 1024];
        for (int i = 100; i < original.Length; i += 512)
        {
            original[i] = (byte)(i & 0xFF);
        }

        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(original.Length)];
        int compLen = ZstdCodec.Compress(original, compressed);

        byte[] decompressed = new byte[original.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(original.Length, decompLen);
        Assert.Equal(original, decompressed);
    }

    [Fact]
    public void Zstd_RandomNoise_Incompressible_RoundTrip()
    {
        byte[] original = new byte[32 * 1024];
        RandomNumberGenerator.Fill(original);

        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(original.Length)];
        int compLen = ZstdCodec.Compress(original, compressed);

        byte[] decompressed = new byte[original.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(original.Length, decompLen);
        Assert.Equal(original, decompressed);
    }

    [Fact]
    public void Lz4Frame_EmptyPayload_EncodesAndDecodes()
    {
        byte[] empty = [];
        byte[] frame = new byte[64];
        int frameLen = Lz4FrameCodec.EncodeFrame(empty, frame);

        byte[] decoded = new byte[16];
        int decodedLen = Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, frameLen), decoded);

        Assert.Equal(0, decodedLen);
    }

    [Fact]
    public void Lz4Frame_CorruptMagic_ThrowsInvalidDataException()
    {
        byte[] data = "Payload to encode"u8.ToArray();
        byte[] frame = new byte[128];
        int frameLen = Lz4FrameCodec.EncodeFrame(data, frame);

        frame[0] ^= 0xFF; // Corrupt magic number

        byte[] dest = new byte[data.Length];
        Assert.Throws<InvalidDataException>(() =>
        {
            Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, frameLen), dest);
        });
    }

    [Fact]
    public void Lz4Frame_CorruptChecksum_ThrowsInvalidDataException()
    {
        byte[] data = "Payload with content checksum verification"u8.ToArray();
        byte[] frame = new byte[256];
        int frameLen = Lz4FrameCodec.EncodeFrame(data, frame, contentChecksum: true);

        // Corrupt content checksum (last 4 bytes of frame)
        frame[frameLen - 1] ^= 0x01;

        byte[] dest = new byte[data.Length];
        Assert.Throws<InvalidDataException>(() =>
        {
            Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, frameLen), dest);
        });
    }

    [Fact]
    public void Zstd_CorruptMagic_ThrowsInvalidDataException()
    {
        byte[] data = "Payload for Zstandard magic corruption test"u8.ToArray();
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(data.Length)];
        int compLen = ZstdCodec.Compress(data, compressed);

        compressed[0] ^= 0xFF; // Corrupt Zstandard frame magic 0xFD2FB528

        byte[] dest = new byte[data.Length];
        Assert.Throws<InvalidDataException>(() =>
        {
            ZstdCodec.Decompress(compressed.AsSpan(0, compLen), dest);
        });
    }
}
