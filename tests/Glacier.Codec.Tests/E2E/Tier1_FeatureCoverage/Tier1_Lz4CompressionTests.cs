using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Lz4;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_Lz4CompressionTests
{
    // Feature 50: LZ4 Block Parser
    [Fact]
    public void Feature50_Lz4Block_EmptyBuffer_EncodesSingleZeroToken()
    {
        Span<byte> compressed = stackalloc byte[16];
        int compLen = Lz4Codec.Compress(ReadOnlySpan<byte>.Empty, compressed);

        Assert.Equal(1, compLen);
        Assert.Equal(0x00, compressed[0]);

        Span<byte> decompressed = stackalloc byte[16];
        int decompLen = Lz4Codec.Decompress(compressed.Slice(0, compLen), decompressed);
        Assert.Equal(0, decompLen);
    }

    [Fact]
    public void Feature50_Lz4Block_ShortAscii_Roundtrip()
    {
        byte[] input = Encoding.ASCII.GetBytes("Glacier.Codec.LZ4.HighThroughput.Test");
        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];

        int compLen = Lz4Codec.Compress(input, compressed);
        Assert.True(compLen > 0);

        byte[] decompressed = new byte[input.Length];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    // Feature 51: SIMD Match Finder
    [Fact]
    public void Feature51_Lz4Block_RepetitivePattern_HighCompressionRatio()
    {
        byte[] input = new byte[1000];
        Array.Fill(input, (byte)'A');

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int compLen = Lz4Codec.Compress(input, compressed);

        // Repetitive 1000 'A's should compress down significantly
        Assert.True(compLen < 50, $"Expected high compression for repetitive data, got {compLen} bytes.");

        byte[] decompressed = new byte[input.Length];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    // Feature 52: LZ4 Overlapping Match RLE
    [Fact]
    public void Feature52_Lz4Block_OverlappingMatch_RleExpansion()
    {
        // "ABCABCABCABCABCABC" - offset is 3, match length is 15
        string str = "ABCABCABCABCABCABCABCABCABCABC";
        byte[] input = Encoding.ASCII.GetBytes(str);

        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int compLen = Lz4Codec.Compress(input, compressed);

        byte[] decompressed = new byte[input.Length];
        int decompLen = Lz4Codec.Decompress(compressed.AsSpan(0, compLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(str, Encoding.ASCII.GetString(decompressed));
    }

    // Feature 53: LZ4 Frame Codec
    [Fact]
    public void Feature53_Lz4Frame_MagicAndDescriptorValidation()
    {
        byte[] input = Encoding.UTF8.GetBytes("LZ4 Frame framing format verification test.");
        byte[] frameBuffer = new byte[input.Length + 64];

        int frameLen = Lz4FrameCodec.EncodeFrame(input, frameBuffer, contentChecksum: true);
        Assert.True(frameLen > 7);

        // Verify magic number 0x184D2204
        uint magic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(frameBuffer.AsSpan(0, 4));
        Assert.Equal(Lz4FrameCodec.MagicNumber, magic);

        byte[] decompressed = new byte[input.Length];
        int decompLen = Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameLen), decompressed);

        Assert.Equal(input.Length, decompLen);
        Assert.Equal(input, decompressed);
    }

    [Fact]
    public void Feature53_Lz4Frame_EmptyInput_ProducesValid11ByteOrCheckedFrame()
    {
        byte[] frameBuffer = new byte[32];
        int frameLen = Lz4FrameCodec.EncodeFrame(ReadOnlySpan<byte>.Empty, frameBuffer, contentChecksum: false);

        Assert.Equal(11, frameLen);

        byte[] decompressed = new byte[16];
        int decompLen = Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameLen), decompressed);
        Assert.Equal(0, decompLen);
    }
}
