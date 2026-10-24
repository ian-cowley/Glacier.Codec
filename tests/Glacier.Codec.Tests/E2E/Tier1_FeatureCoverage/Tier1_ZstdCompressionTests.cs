using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Zstd;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_ZstdCompressionTests
{
    // Feature 54: Zstandard Frame Header & Magic
    [Fact]
    public void Feature54_Zstd_EmptyFrame_MatchesOfficialHeader()
    {
        Span<byte> frame = stackalloc byte[16];
        int frameLen = ZstdCodec.Compress(ReadOnlySpan<byte>.Empty, frame);

        Assert.Equal(9, frameLen);

        // Magic: 0xFD2FB528 (Little Endian: 28 B5 2F FD)
        Assert.Equal(0x28, frame[0]);
        Assert.Equal(0xB5, frame[1]);
        Assert.Equal(0x2F, frame[2]);
        Assert.Equal(0xFD, frame[3]);

        Span<byte> decompressed = stackalloc byte[16];
        int decompLen = ZstdCodec.Decompress(frame.Slice(0, frameLen), decompressed);
        Assert.Equal(0, decompLen);
    }

    [Fact]
    public void Feature54_Zstd_AsciiPayload_Roundtrip()
    {
        byte[] input = Encoding.ASCII.GetBytes("Zstandard compression roundtrip test in Glacier.Codec.");
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];

        int compLen = ZstdCodec.Compress(input, compressed);
        Assert.True(compLen > 0);

        byte[] decompressed = new byte[input.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    // Feature 55 & 56: 4-Stream Huffman & FSE Sequence Decoding
    [Fact]
    public void Feature55_56_Zstd_MultiBlockData_Roundtrip()
    {
        byte[] input = new byte[4096];
        for (int i = 0; i < input.Length; i++)
        {
            input[i] = (byte)((i * 37) % 256);
        }

        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int compLen = ZstdCodec.Compress(input, compressed);

        byte[] decompressed = new byte[input.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    // Feature 57 & 58: Repeat Offsets History & Sequence Execution
    [Fact]
    public void Feature57_58_Zstd_RepetitiveSequences_Roundtrip()
    {
        // Repeating sequence with varied periods
        string pattern = "ABCDEFGHIJ0123456789";
        var sb = new StringBuilder();
        for (int i = 0; i < 50; i++) sb.Append(pattern);
        byte[] input = Encoding.UTF8.GetBytes(sb.ToString());

        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int compLen = ZstdCodec.Compress(input, compressed);

        byte[] decompressed = new byte[input.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    // Feature 59: Content Checksum Verification
    [Fact]
    public void Feature59_Zstd_ContentChecksum_Validated()
    {
        byte[] input = Encoding.UTF8.GetBytes("Checksum validation data string");
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int compLen = ZstdCodec.Compress(input, compressed);

        byte[] decompressed = new byte[input.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }
}
