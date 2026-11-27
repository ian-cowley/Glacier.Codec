using System;
using System.IO;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;

namespace Glacier.Codec.Tests.E2E.Tier2_BoundaryCases;

public class Tier2_CompressionBoundaries
{
    // LZ4 Block Boundaries
    [Fact]
    public void Boundary_Lz4Block_EmptyInput_Emits0x00()
    {
        Span<byte> comp = stackalloc byte[16];
        int len = Lz4Codec.Compress(ReadOnlySpan<byte>.Empty, comp);
        Assert.Equal(1, len);
        Assert.Equal(0x00, comp[0]);

        Span<byte> decomp = stackalloc byte[16];
        int dLen = Lz4Codec.Decompress(comp.Slice(0, len), decomp);
        Assert.Equal(0, dLen);
    }

    [Fact]
    public void Boundary_Lz4Block_SingleByteInput_Roundtrip()
    {
        byte[] input = [(byte)'Z'];
        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(1)];
        int compLen = Lz4Codec.Compress(input, comp);

        byte[] decomp = new byte[1];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, compLen), decomp);
        Assert.Equal(1, dLen);
        Assert.Equal((byte)'Z', decomp[0]);
    }

    [Fact]
    public void Boundary_Lz4Block_IncompressibleHighEntropyData_Roundtrip()
    {
        byte[] randomData = new byte[2048];
        RandomNumberGenerator.Fill(randomData);

        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(randomData.Length)];
        int compLen = Lz4Codec.Compress(randomData, comp);

        byte[] decomp = new byte[randomData.Length];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, compLen), decomp);
        Assert.Equal(randomData.Length, dLen);
        Assert.Equal(randomData, decomp);
    }

    [Fact]
    public void Boundary_Lz4Block_TruncatedLiteralsStream_ThrowsInvalidDataException()
    {
        // Token specifies 10 literals, but stream ends immediately
        byte[] corrupted = [(byte)0xA0, (byte)'A', (byte)'B'];
        byte[] dest = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corrupted, dest));
    }

    // LZ4 Frame Boundaries
    [Fact]
    public void Boundary_Lz4Frame_InvalidMagic_ThrowsInvalidDataException()
    {
        byte[] corruptMagic = [0x00, 0x00, 0x00, 0x00, 0x60, 0x40, 0x82];
        byte[] dest = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(corruptMagic, dest));
    }

    [Fact]
    public void Boundary_Lz4Frame_TruncatedFrame_ThrowsInvalidDataException()
    {
        byte[] truncated = [0x04, 0x22, 0x4D]; // Less than 7 bytes
        byte[] dest = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(truncated, dest));
    }

    // Zstandard Frame Boundaries
    [Fact]
    public void Boundary_Zstd_InvalidMagic_ThrowsInvalidDataException()
    {
        byte[] corruptMagic = [0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0x00, 0x01, 0x00, 0x00];
        byte[] dest = new byte[32];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(corruptMagic, dest));
    }

    [Fact]
    public void Boundary_Zstd_SingleByteInput_Roundtrip()
    {
        byte[] input = [(byte)'Q'];
        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(1)];
        int compLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[1];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, compLen), decomp);
        Assert.Equal(1, dLen);
        Assert.Equal((byte)'Q', decomp[0]);
    }

    [Fact]
    public void Boundary_Zstd_IncompressibleRandomData_Roundtrip()
    {
        byte[] randomData = new byte[4096];
        RandomNumberGenerator.Fill(randomData);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(randomData.Length)];
        int compLen = ZstdCodec.Compress(randomData, comp);

        byte[] decomp = new byte[randomData.Length];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, compLen), decomp);
        Assert.Equal(randomData.Length, dLen);
        Assert.Equal(randomData, decomp);
    }

    [Fact]
    public void Boundary_Zstd_OversizedWindowFcsMismatchAndBadHuffmanWeight_ThrowInvalidDataException()
    {
        // Zstd frame with singleSegment=0 and exp=31 (window > 128 MB cap)
        byte[] oversizedWindow = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xF8, 0x01, 0x00, 0x00];
        byte[] dest = new byte[64];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(oversizedWindow, dest));

        // Zstd singleSegment=1 with FCS=10 but 1-byte raw last block (len=1 != 10)
        // FHD: 0x20 (singleSegment=1, fcsFlag=0 => 1-byte FCS=10), LastBlock Raw size=1: header = (1<<3)|1 = 9
        byte[] fcsMismatch = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x0A, 0x09, 0x00, 0x00, (byte)'A'];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(fcsMismatch, dest));

        // Huffman direct header (0x81 => 2 symbols), weight bytes have weight=15 (>11 max)
        byte[] badHuff = [0x81, 0xFF];
        Span<HuffmanTableEntry> tbl = stackalloc HuffmanTableEntry[2048];
        bool threw = false;
        try
        {
            HuffmanDecoder.BuildTable(badHuff, tbl, out _);
        }
        catch (InvalidDataException)
        {
            threw = true;
        }
        Assert.True(threw);
    }
}
