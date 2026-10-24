using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Glacier.Codec.Compression;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Hashing.XxHash32;

/// <summary>
/// Comprehensive unit tests for Milestone M5: High-Throughput Stream Compression (LZ4 and Zstandard RFC 8878).
/// Validates zero-allocation invariants, SIMD match extensions, RLE overlap expansion,
/// frame containers, descriptors, xxHash32/xxHash64 checksums, and adversarial edge cases.
/// </summary>
public class CompressionTests
{
    // =========================================================================
    // 1. xxHash32 and xxHash64 Core Tests
    // =========================================================================

    [Fact]
    public void XxHash32_EmptyBuffer_MatchesStandardReference()
    {
        uint hash = XxHash32.Hash(ReadOnlySpan<byte>.Empty, seed: 0);
        Assert.Equal(0x02CC5D05U, hash);
    }

    [Fact]
    public void XxHash32_KnownInputs_ProduceConsistentDigests()
    {
        byte[] input1 = Encoding.ASCII.GetBytes("hello world");
        uint hash1 = XxHash32.Hash(input1, seed: 0);
        Assert.NotEqual(0U, hash1);

        uint hash2 = XxHash32.Hash(input1, seed: 0);
        Assert.Equal(hash1, hash2);

        uint hashSeeded = XxHash32.Hash(input1, seed: 12345);
        Assert.NotEqual(hash1, hashSeeded);
    }

    [Fact]
    public void XxHash32_StripeBoundaries_CorrectlyAccumulates()
    {
        // Test lengths spanning 0..64 bytes to exercise all remainder branches
        for (int len = 0; len <= 64; len++)
        {
            byte[] buf = new byte[len];
            for (int i = 0; i < len; i++) buf[i] = (byte)(i * 31);
            uint h = XxHash32.Hash(buf, seed: 0);
            Assert.True(h != 0 || len == 0);
        }
    }

    [Fact]
    public void XxHash64_EmptyBuffer_MatchesReference()
    {
        ulong hash = XxHash32.Hash64(ReadOnlySpan<byte>.Empty, seed: 0);
        Assert.Equal(0xEF46DB3751D8E999UL, hash);
    }

    // =========================================================================
    // 2. LZ4 Block Compression & Decompression Tests
    // =========================================================================

    [Fact]
    public void Lz4Block_EmptyBuffer_Roundtrip()
    {
        Span<byte> comp = stackalloc byte[16];
        int cLen = Lz4Codec.Compress(ReadOnlySpan<byte>.Empty, comp);
        Assert.Equal(1, cLen);
        Assert.Equal(0x00, comp[0]);

        Span<byte> decomp = stackalloc byte[16];
        int dLen = Lz4Codec.Decompress(comp.Slice(0, cLen), decomp);
        Assert.Equal(0, dLen);
    }

    [Fact]
    public void Lz4Block_SingleByte_Roundtrip()
    {
        byte[] input = [(byte)'X'];
        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(1)];
        int cLen = Lz4Codec.Compress(input, comp);

        byte[] decomp = new byte[1];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(1, dLen);
        Assert.Equal(input[0], decomp[0]);
    }

    [Fact]
    public void Lz4Block_ShortInputsUnderMfLimit_Roundtrip()
    {
        for (int len = 1; len <= 12; len++)
        {
            byte[] input = new byte[len];
            for (int i = 0; i < len; i++) input[i] = (byte)(i + 1);

            byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(len)];
            int cLen = Lz4Codec.Compress(input, comp);

            byte[] decomp = new byte[len];
            int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
            Assert.Equal(len, dLen);
            Assert.Equal(input, decomp);
        }
    }

    [Fact]
    public void Lz4Block_SingleByteRle_Offset1_ExtremeCompression()
    {
        byte[] input = new byte[10_000];
        Array.Fill(input, (byte)'K');

        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int cLen = Lz4Codec.Compress(input, comp);

        // 10,000 identical bytes must compress to under 60 bytes
        Assert.True(cLen < 60, $"Compressed size was {cLen}, expected < 60");

        byte[] decomp = new byte[input.Length];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Lz4Block_TwoBytePattern_Offset2_Roundtrip()
    {
        byte[] input = new byte[2000];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 2 == 0 ? 0xAB : 0xCD);

        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int cLen = Lz4Codec.Compress(input, comp);
        Assert.True(cLen < 50);

        byte[] decomp = new byte[input.Length];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Lz4Block_IrregularOffsets_3_to_7_Roundtrip()
    {
        foreach (int period in new[] { 3, 4, 5, 6, 7 })
        {
            byte[] input = new byte[3000];
            for (int i = 0; i < input.Length; i++) input[i] = (byte)((i % period) + 65);

            byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
            int cLen = Lz4Codec.Compress(input, comp);

            byte[] decomp = new byte[input.Length];
            int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
            Assert.Equal(input.Length, dLen);
            Assert.Equal(input, decomp);
        }
    }

    [Fact]
    public void Lz4Block_IncompressibleRandomData_Roundtrip()
    {
        byte[] input = new byte[4096];
        RandomNumberGenerator.Fill(input);

        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int cLen = Lz4Codec.Compress(input, comp);

        byte[] decomp = new byte[input.Length];
        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Lz4Block_TruncatedLiteralStream_ThrowsInvalidDataException()
    {
        // Token has 8 literals, but only 2 bytes follow
        byte[] corrupt = [0x80, 0x01, 0x02];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corrupt, decomp));
    }

    [Fact]
    public void Lz4Block_OffsetZero_ThrowsInvalidDataException()
    {
        // 1 literal 'A', offset 0, match 4
        byte[] corrupt = [0x10, (byte)'A', 0x00, 0x00];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corrupt, decomp));
    }

    [Fact]
    public void Lz4Block_OffsetBeforeBuffer_ThrowsInvalidDataException()
    {
        // 1 literal 'A', offset 10 (points before start), match 4
        byte[] corrupt = [0x10, (byte)'A', 0x0A, 0x00];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corrupt, decomp));
    }

    // =========================================================================
    // 3. LZ4 Frame Codec Tests
    // =========================================================================

    [Fact]
    public void Lz4Frame_LargeMultiBlock_Roundtrip()
    {
        // 200 KB payload spanning 4 x 64 KB blocks
        byte[] input = new byte[200 * 1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 17);

        byte[] frame = new byte[input.Length + 1024];
        int frameLen = Lz4FrameCodec.EncodeFrame(input, frame, contentChecksum: true, blockChecksum: true);

        byte[] decomp = new byte[input.Length];
        int dLen = Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, frameLen), decomp);

        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Lz4Frame_TamperedHeaderChecksum_ThrowsInvalidDataException()
    {
        byte[] input = Encoding.UTF8.GetBytes("Frame header tampering test");
        byte[] frame = new byte[input.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(input, frame, contentChecksum: false);

        // Header checksum is at index 6
        frame[6] ^= 0xFF;

        byte[] decomp = new byte[input.Length];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, fLen), decomp));
    }

    [Fact]
    public void Lz4Frame_TamperedContentChecksum_ThrowsInvalidDataException()
    {
        byte[] input = Encoding.UTF8.GetBytes("Content checksum tampering test");
        byte[] frame = new byte[input.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(input, frame, contentChecksum: true);

        // Tamper with content checksum (last 4 bytes)
        frame[fLen - 1] ^= 0x01;

        byte[] decomp = new byte[input.Length];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, fLen), decomp));
    }

    [Fact]
    public void Lz4Frame_SkippableFrame_IgnoredCleanly()
    {
        // Skippable frame: Magic 0x184D2A50, UserDataSize 8, 8 bytes data
        byte[] skippable = [0x50, 0x2A, 0x4D, 0x18, 0x08, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        byte[] decomp = new byte[16];
        int dLen = Lz4FrameCodec.DecodeFrame(skippable, decomp);
        Assert.Equal(0, dLen);
    }

    // =========================================================================
    // 4. Zstandard RFC 8878 Codec Tests
    // =========================================================================

    [Fact]
    public void Zstd_EmptyFrame_MatchesRfcSpecification()
    {
        Span<byte> frame = stackalloc byte[16];
        int frameLen = ZstdCodec.Compress(ReadOnlySpan<byte>.Empty, frame);
        Assert.Equal(9, frameLen);

        // Magic 0xFD2FB528
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(0, 4));
        Assert.Equal(ZstdCodec.MagicNumber, magic);

        Span<byte> decomp = stackalloc byte[16];
        int dLen = ZstdCodec.Decompress(frame.Slice(0, frameLen), decomp);
        Assert.Equal(0, dLen);
    }

    [Fact]
    public void Zstd_SingleByte_Roundtrip()
    {
        byte[] input = [(byte)'M'];
        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(1)];
        int cLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[1];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(1, dLen);
        Assert.Equal((byte)'M', decomp[0]);
    }

    [Fact]
    public void Zstd_LargeRepetitiveRleBlock_Roundtrip()
    {
        byte[] input = new byte[64 * 1024];
        Array.Fill(input, (byte)0x7E);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int cLen = ZstdCodec.Compress(input, comp);

        // 64 KB of identical bytes must compress to under 25 bytes
        Assert.True(cLen < 25, $"Zstd RLE block size was {cLen}");

        byte[] decomp = new byte[input.Length];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Zstd_RawBlock_Roundtrip()
    {
        byte[] input = new byte[1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i ^ 0x55);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int cLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[input.Length];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Zstd_ContentChecksum_Verification()
    {
        byte[] input = Encoding.UTF8.GetBytes("High-throughput RFC 8878 Zstandard content checksum test payload.");
        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int cLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[input.Length];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(input.Length, dLen);
        Assert.Equal(input, decomp);
    }

    [Fact]
    public void Zstd_TamperedContentChecksum_ThrowsInvalidDataException()
    {
        byte[] input = Encoding.UTF8.GetBytes("Data to be tampered at checksum");
        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int cLen = ZstdCodec.Compress(input, comp);

        // Tamper with trailing 4-byte checksum
        comp[cLen - 1] ^= 0xFF;

        byte[] decomp = new byte[input.Length];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp));
    }

    [Fact]
    public void Zstd_InvalidMagic_ThrowsInvalidDataException()
    {
        byte[] corrupt = [0x11, 0x22, 0x33, 0x44, 0x20, 0x00, 0x01, 0x00, 0x00];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(corrupt, decomp));
    }

    [Fact]
    public void Zstd_EmptyInput_ThrowsInvalidDataException()
    {
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(ReadOnlySpan<byte>.Empty, decomp));
    }

    [Fact]
    public void Zstd_ReservedFhdBitsNonZero_ThrowsInvalidDataException()
    {
        // Magic + FHD with reserved bit 3 set (0x28)
        byte[] corrupt = [0x28, 0xB5, 0x2F, 0xFD, 0x28, 0x00, 0x01, 0x00, 0x00];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(corrupt, decomp));
    }

    [Fact]
    public void Zstd_ReservedBlockType3_ThrowsInvalidDataException()
    {
        // Block header with Type = 3 (0b0110 in bits 2-1)
        byte[] corrupt = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x07, 0x00, 0x00];
        byte[] decomp = new byte[32];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(corrupt, decomp));
    }

    [Fact]
    public void Zstd_ExactMaxBlockSize128KB_Roundtrip()
    {
        int size = ZstdConstants.MaxBlockSize;
        byte[] input = new byte[size];
        for (int i = 0; i < size; i++) input[i] = (byte)(i * 17);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(size)];
        int cLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[size];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(size, dLen);
        Assert.True(input.AsSpan().SequenceEqual(decomp));
    }

    [Fact]
    public void Zstd_MaxBlockSizePlusOneByte_TwoBlocksRoundtrip()
    {
        int size = ZstdConstants.MaxBlockSize + 1;
        byte[] input = new byte[size];
        for (int i = 0; i < size; i++) input[i] = (byte)(i * 31);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(size)];
        int cLen = ZstdCodec.Compress(input, comp);

        byte[] decomp = new byte[size];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(size, dLen);
        Assert.True(input.AsSpan().SequenceEqual(decomp));
    }

    [Fact]
    public void Zstd_1MB_RleMultiBlock_MassiveCompressionAndExactRoundtrip()
    {
        int size = 1024 * 1024;
        byte[] input = new byte[size];
        Array.Fill(input, (byte)0x42);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(size)];
        int cLen = ZstdCodec.Compress(input, comp);

        // 1 MB RLE must compress to < 60 bytes (8 blocks of 4 bytes + headers)
        Assert.True(cLen < 60, $"Compressed size was {cLen}; expected < 60 bytes.");

        byte[] decomp = new byte[size];
        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        Assert.Equal(size, dLen);
        Assert.True(input.AsSpan().SequenceEqual(decomp));
    }

    // =========================================================================
    // 5. Streaming Compressor & Decompressor Contract Tests
    // =========================================================================

    [Fact]
    public void StreamingCompressor_Lz4_CompressAndDecompressChunks()
    {
        using var compressor = new Lz4StreamCompressor();
        using var decompressor = new Lz4StreamDecompressor();

        byte[] chunk1 = Encoding.UTF8.GetBytes("First streaming chunk of data.");
        byte[] chunk2 = Encoding.UTF8.GetBytes("Second streaming chunk of data with more text.");

        byte[] comp1 = new byte[compressor.GetMaxCompressedChunkSize(chunk1.Length)];
        int c1Len = compressor.CompressChunk(chunk1, comp1, isFinalChunk: false);

        byte[] comp2 = new byte[compressor.GetMaxCompressedChunkSize(chunk2.Length)];
        int c2Len = compressor.CompressChunk(chunk2, comp2, isFinalChunk: true);

        byte[] decomp1 = new byte[chunk1.Length];
        int d1Len = decompressor.DecompressChunk(comp1.AsSpan(0, c1Len), decomp1, out int consumed1);
        Assert.Equal(chunk1.Length, d1Len);
        Assert.Equal(c1Len, consumed1);
        Assert.Equal(chunk1, decomp1);

        byte[] decomp2 = new byte[chunk2.Length];
        int d2Len = decompressor.DecompressChunk(comp2.AsSpan(0, c2Len), decomp2, out int consumed2);
        Assert.Equal(chunk2.Length, d2Len);
        Assert.Equal(c2Len, consumed2);
        Assert.Equal(chunk2, decomp2);

        compressor.Reset();
        decompressor.Reset();
    }

    [Fact]
    public void StreamingCompressor_Zstd_CompressAndDecompressChunks()
    {
        using var compressor = new ZstdStreamCompressor();
        using var decompressor = new ZstdStreamDecompressor();

        byte[] chunk1 = Encoding.UTF8.GetBytes("Zstd streaming chunk 1.");
        byte[] comp1 = new byte[compressor.GetMaxCompressedChunkSize(chunk1.Length)];
        int c1Len = compressor.CompressChunk(chunk1, comp1, isFinalChunk: true);

        byte[] decomp1 = new byte[chunk1.Length];
        int d1Len = decompressor.DecompressChunk(comp1.AsSpan(0, c1Len), decomp1, out int consumed1);
        Assert.Equal(chunk1.Length, d1Len);
        Assert.Equal(c1Len, consumed1);
        Assert.Equal(chunk1, decomp1);
    }

    // =========================================================================
    // 6. Zero GC Allocation Invariant Tests
    // =========================================================================

    [Fact]
    public void Lz4_SteadyStateBlock_ZeroHeapAllocations()
    {
        byte[] data = new byte[4096];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 128);

        byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(data.Length)];
        int cLen = Lz4Codec.Compress(data, comp);
        byte[] decomp = new byte[data.Length];

        // Warm up slab pool
        for (int w = 0; w < 5; w++)
        {
            Lz4Codec.Compress(data, comp);
            Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 20; i++)
        {
            Lz4Codec.Compress(data, comp);
            Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();

        long diff = allocatedAfter - allocatedBefore;
        Assert.Equal(0L, diff);
    }

    [Fact]
    public void Zstd_SteadyStateBlock_ZeroHeapAllocations()
    {
        byte[] data = new byte[4096];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 64);

        byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(data.Length)];
        int cLen = ZstdCodec.Compress(data, comp);
        byte[] decomp = new byte[data.Length];

        // Warm up
        for (int w = 0; w < 5; w++)
        {
            ZstdCodec.Compress(data, comp);
            ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 20; i++)
        {
            ZstdCodec.Compress(data, comp);
            ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();

        long diff = allocatedAfter - allocatedBefore;
        Assert.Equal(0L, diff);
    }
}
