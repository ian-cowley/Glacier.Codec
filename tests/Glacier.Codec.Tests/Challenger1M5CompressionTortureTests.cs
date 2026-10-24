namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;

/// <summary>
/// Empirical challenge and torture test suite for Milestone M5: High-Throughput Stream Compression (LZ4 and Zstandard RFC 8878).
/// Verifies compression ratios across diverse topologies, boundary buffer sizes, corrupt frame & bit-tampering rejection,
/// and 1,000 randomized roundtrip cycles with bit-exact restoration.
/// </summary>
public sealed class Challenger1M5CompressionTortureTests
{
    // =========================================================================
    // 1. Diverse Data Topologies & Compression Ratios
    // =========================================================================

    [Fact]
    public void Topology_Rle1000Bytes_MassiveCompressionAndExactRoundtrip()
    {
        byte[] input = new byte[1000];
        Array.Fill(input, (byte)0xA5);

        // LZ4 Block
        byte[] lz4Comp = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
        int lz4Len = Lz4Codec.Compress(input, lz4Comp);
        Assert.True(lz4Len <= 25, $"LZ4 1000B RLE compressed to {lz4Len} bytes; expected <= 25 bytes.");
        byte[] lz4Decomp = new byte[input.Length];
        int lz4DecompLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
        Assert.Equal(input.Length, lz4DecompLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));

        // LZ4 Frame
        byte[] lz4Frame = new byte[input.Length + 1024];
        int lz4FrameLen = Lz4FrameCodec.EncodeFrame(input, lz4Frame, contentChecksum: true, blockChecksum: true);
        Assert.True(lz4FrameLen <= 45, $"LZ4 Frame 1000B RLE was {lz4FrameLen} bytes; expected <= 45 bytes.");
        byte[] lz4FrameDecomp = new byte[input.Length];
        int lz4FrameDecompLen = Lz4FrameCodec.DecodeFrame(lz4Frame.AsSpan(0, lz4FrameLen), lz4FrameDecomp);
        Assert.Equal(input.Length, lz4FrameDecompLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4FrameDecomp));

        // Zstandard Frame
        byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(input.Length)];
        int zstdLen = ZstdCodec.Compress(input, zstdComp);
        Assert.True(zstdLen <= 20, $"Zstd 1000B RLE was {zstdLen} bytes; expected <= 20 bytes.");
        byte[] zstdDecomp = new byte[input.Length];
        int zstdDecompLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
        Assert.Equal(input.Length, zstdDecompLen);
        Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(16)]
    public void Topology_ShortRepeatingPatterns_PeriodsAndExactRoundtrip(int period)
    {
        int length = 2048;
        byte[] input = new byte[length];
        for (int i = 0; i < length; i++)
        {
            input[i] = (byte)((i % period) * 17 + 3);
        }

        // LZ4 Block
        byte[] lz4Comp = new byte[Lz4Codec.MaximumCompressedSize(length)];
        int lz4Len = Lz4Codec.Compress(input, lz4Comp);
        Assert.True(lz4Len < length / 4, $"LZ4 period {period} compressed to {lz4Len}; expected < {length / 4}");
        byte[] lz4Decomp = new byte[length];
        int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
        Assert.Equal(length, lz4DLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));

        // Zstd Frame
        byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(length)];
        int zstdLen = ZstdCodec.Compress(input, zstdComp);
        byte[] zstdDecomp = new byte[length];
        int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
        Assert.Equal(length, zstdDLen);
        Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
    }

    [Fact]
    public void Topology_HighEntropyRandom_ExpansionBoundsAndIntegrity()
    {
        int length = 16384;
        byte[] input = new byte[length];
        RandomNumberGenerator.Fill(input);

        // LZ4 Block expansion bound: MaximumCompressedSize
        int maxLz4 = Lz4Codec.MaximumCompressedSize(length);
        byte[] lz4Comp = new byte[maxLz4];
        int lz4Len = Lz4Codec.Compress(input, lz4Comp);
        Assert.True(lz4Len <= maxLz4, $"LZ4 length {lz4Len} exceeded max bound {maxLz4}");

        byte[] lz4Decomp = new byte[length];
        int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
        Assert.Equal(length, lz4DLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));

        // Zstd Frame expansion bound
        int maxZstd = ZstdCodec.MaximumCompressedSize(length);
        byte[] zstdComp = new byte[maxZstd];
        int zstdLen = ZstdCodec.Compress(input, zstdComp);
        Assert.True(zstdLen <= maxZstd, $"Zstd length {zstdLen} exceeded max bound {maxZstd}");

        byte[] zstdDecomp = new byte[length];
        int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
        Assert.Equal(length, zstdDLen);
        Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
    }

    [Fact]
    public void Topology_RealWorldStructuredData_JsonAndCsv()
    {
        // 1. Tabular CSV
        var sbCsv = new StringBuilder();
        sbCsv.AppendLine("id,metric_name,device_uuid,timestamp_utc,temperature_c,status_code");
        for (int i = 1; i <= 60; i++)
        {
            sbCsv.AppendLine($"{i},sensor_ambient_thermal,550e8400-e29b-41d4-a716-446655440000,2026-10-24T10:00:{i:D2}Z,23.456,OK");
        }
        byte[] csvBytes = Encoding.UTF8.GetBytes(sbCsv.ToString());

        // 2. Structured JSON
        var sbJson = new StringBuilder();
        sbJson.Append("{\"events\":[");
        for (int i = 1; i <= 60; i++)
        {
            if (i > 1) sbJson.Append(',');
            sbJson.Append($"{{\"eventId\":{i},\"type\":\"telemetry_event\",\"cluster\":\"us-east-1\",\"active\":true,\"load\":0.74}}");
        }
        sbJson.Append("]}");
        byte[] jsonBytes = Encoding.UTF8.GetBytes(sbJson.ToString());

        foreach (byte[] payload in new[] { csvBytes, jsonBytes })
        {
            // LZ4 Block
            byte[] lz4Comp = new byte[Lz4Codec.MaximumCompressedSize(payload.Length)];
            int lz4Len = Lz4Codec.Compress(payload, lz4Comp);
            Assert.True(lz4Len < payload.Length / 2, $"LZ4 structured compression ratio < 2.0x (orig {payload.Length}, comp {lz4Len})");

            byte[] lz4Decomp = new byte[payload.Length];
            int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
            Assert.Equal(payload.Length, lz4DLen);
            Assert.True(payload.AsSpan().SequenceEqual(lz4Decomp));

            // Zstd Frame
            byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(payload.Length)];
            int zstdLen = ZstdCodec.Compress(payload, zstdComp);
            byte[] zstdDecomp = new byte[payload.Length];
            int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
            Assert.Equal(payload.Length, zstdDLen);
            Assert.True(payload.AsSpan().SequenceEqual(zstdDecomp));
        }
    }

    // =========================================================================
    // 2. Extreme Boundary Buffer Sizes
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(65536)]
    public void BoundarySizes_ExtremeDimensions_BitExactRestoration(int size)
    {
        byte[] input = new byte[size];
        for (int i = 0; i < size; i++)
        {
            input[i] = (byte)(i * 37 + (i >> 8));
        }

        // Test A: LZ4 Block
        byte[] lz4Comp = new byte[Lz4Codec.MaximumCompressedSize(size)];
        int lz4Len = Lz4Codec.Compress(input, lz4Comp);
        byte[] lz4Decomp = new byte[size];
        int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
        Assert.Equal(size, lz4DLen);
        if (size > 0)
        {
            Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));
        }

        // Test B: LZ4 Frame (with content and block checksums)
        byte[] lz4Frame = new byte[size + (size / 10) + 2048];
        int lz4FrameLen = Lz4FrameCodec.EncodeFrame(input, lz4Frame, contentChecksum: true, blockChecksum: true);
        byte[] lz4FrameDecomp = new byte[size];
        int lz4FrameDLen = Lz4FrameCodec.DecodeFrame(lz4Frame.AsSpan(0, lz4FrameLen), lz4FrameDecomp);
        Assert.Equal(size, lz4FrameDLen);
        if (size > 0)
        {
            Assert.True(input.AsSpan().SequenceEqual(lz4FrameDecomp));
        }

        // Test C: Zstandard Frame
        byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(size)];
        int zstdLen = ZstdCodec.Compress(input, zstdComp);
        byte[] zstdDecomp = new byte[size];
        int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
        Assert.Equal(size, zstdDLen);
        if (size > 0)
        {
            Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
        }
    }

    [Fact]
    public void BoundarySizes_Lz4_1MB_ExtremeDimension_BitExactRestoration()
    {
        int size = 1048576; // 1 MB
        byte[] input = new byte[size];
        for (int i = 0; i < size; i++) input[i] = (byte)(i * 37 + (i >> 8));

        // LZ4 Block 1MB
        byte[] lz4Comp = new byte[Lz4Codec.MaximumCompressedSize(size)];
        int lz4Len = Lz4Codec.Compress(input, lz4Comp);
        byte[] lz4Decomp = new byte[size];
        int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
        Assert.Equal(size, lz4DLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));

        // LZ4 Frame 1MB
        byte[] lz4Frame = new byte[size + (size / 10) + 2048];
        int lz4FrameLen = Lz4FrameCodec.EncodeFrame(input, lz4Frame, contentChecksum: true, blockChecksum: true);
        byte[] lz4FrameDecomp = new byte[size];
        int lz4FrameDLen = Lz4FrameCodec.DecodeFrame(lz4Frame.AsSpan(0, lz4FrameLen), lz4FrameDecomp);
        Assert.Equal(size, lz4FrameDLen);
        Assert.True(input.AsSpan().SequenceEqual(lz4FrameDecomp));
    }

    [Fact]
    public void BoundarySizes_Zstd_1MB_ExtremeDimension_BitExactRestoration()
    {
        int size = 1048576; // 1 MB
        byte[] input = new byte[size];
        for (int i = 0; i < size; i++) input[i] = (byte)(i * 37 + (i >> 8));

        // Zstandard Frame 1MB
        byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(size)];
        int zstdLen = ZstdCodec.Compress(input, zstdComp);
        byte[] zstdDecomp = new byte[size];
        int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
        Assert.Equal(size, zstdDLen);
        Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(131072)]        // 128 KB (exact MaxBlockSize)
    [InlineData(131073)]        // 128 KB + 1 byte (spans 2 blocks)
    [InlineData(262144)]        // 256 KB (spans 2 full blocks)
    [InlineData(1048576)]       // 1 MB (spans 8 full blocks)
    [InlineData(4194304)]       // 4 MB (spans 32 full blocks)
    public void BoundarySizes_RequiredPayloadDimensions_ZstdAndLz4_BitExactRestoration(int size)
    {
        // 1. Structured Pattern
        byte[] structured = new byte[size];
        for (int i = 0; i < size; i++) structured[i] = (byte)(i * 37 + (i >> 8));

        // 2. Repetitive RLE Pattern
        byte[] rle = new byte[size];
        Array.Fill(rle, (byte)0x5A);

        // 3. High Entropy Pattern
        byte[] highEntropy = new byte[size];
        var rng = new Random(size ^ 0x55AA);
        rng.NextBytes(highEntropy);

        foreach (byte[] input in new[] { structured, rle, highEntropy })
        {
            // Zstandard Frame Codec
            byte[] zstdComp = new byte[ZstdCodec.MaximumCompressedSize(size)];
            int zstdLen = ZstdCodec.Compress(input, zstdComp);
            byte[] zstdDecomp = new byte[size];
            int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
            Assert.Equal(size, zstdDLen);
            if (size > 0)
            {
                Assert.True(input.AsSpan().SequenceEqual(zstdDecomp));
            }

            // LZ4 Frame Codec
            byte[] lz4Frame = new byte[size + (size / 8) + 2048];
            int lz4Len = Lz4FrameCodec.EncodeFrame(input, lz4Frame, contentChecksum: true, blockChecksum: true);
            byte[] lz4Decomp = new byte[size];
            int lz4DLen = Lz4FrameCodec.DecodeFrame(lz4Frame.AsSpan(0, lz4Len), lz4Decomp);
            Assert.Equal(size, lz4DLen);
            if (size > 0)
            {
                Assert.True(input.AsSpan().SequenceEqual(lz4Decomp));
            }
        }
    }

    // =========================================================================
    // 3. Corrupt Frame & Bit-Tampering Rejection
    // =========================================================================

    [Theory]
    [InlineData(0x00000000U)]
    [InlineData(0xFFFFFFFFU)]
    [InlineData(0x184D2203U)]
    [InlineData(0x184D2205U)]
    [InlineData(0x04224D18U)] // reversed endianness
    [InlineData(0x12345678U)]
    public void Corrupt_Lz4Frame_InvalidMagics_RejectedSafely(uint invalidMagic)
    {
        byte[] payload = Encoding.UTF8.GetBytes("Testing LZ4 frame magic rejection.");
        byte[] frame = new byte[payload.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(payload, frame);

        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(0, 4), invalidMagic);
        byte[] decomp = new byte[payload.Length];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, fLen), decomp));
    }

    [Theory]
    [InlineData(0x00000000U)]
    [InlineData(0xFFFFFFFFU)]
    [InlineData(0xFD2FB527U)]
    [InlineData(0xFD2FB529U)]
    [InlineData(0x28B52FFDU)] // reversed endianness
    [InlineData(0xDEADBEEFU)]
    public void Corrupt_ZstdFrame_InvalidMagics_RejectedSafely(uint invalidMagic)
    {
        byte[] payload = Encoding.UTF8.GetBytes("Testing Zstd frame magic rejection.");
        byte[] frame = new byte[ZstdCodec.MaximumCompressedSize(payload.Length)];
        int fLen = ZstdCodec.Compress(payload, frame);

        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(0, 4), invalidMagic);
        byte[] decomp = new byte[payload.Length];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame.AsSpan(0, fLen), decomp));
    }

    [Fact]
    public void Corrupt_Lz4Frame_TruncatedHeadersAndPayloads_ThrowsInvalidDataException()
    {
        byte[] payload = new byte[128];
        RandomNumberGenerator.Fill(payload);
        byte[] frame = new byte[payload.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(payload, frame, contentChecksum: true, blockChecksum: true);

        // Test every truncation point from 0 to fLen - 1
        byte[] decomp = new byte[payload.Length];
        for (int trunc = 0; trunc < fLen; trunc++)
        {
            Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, trunc), decomp));
        }
    }

    [Fact]
    public void Corrupt_ZstdFrame_TruncatedHeadersAndPayloads_ThrowsInvalidDataException()
    {
        byte[] payload = new byte[128];
        RandomNumberGenerator.Fill(payload);
        byte[] frame = new byte[ZstdCodec.MaximumCompressedSize(payload.Length)];
        int fLen = ZstdCodec.Compress(payload, frame);

        // Test every truncation point from 0 to fLen - 1
        byte[] decomp = new byte[payload.Length];
        for (int trunc = 0; trunc < fLen; trunc++)
        {
            Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame.AsSpan(0, trunc), decomp));
        }
    }

    [Fact]
    public void Corrupt_Lz4Block_InvalidOffsets_ThrowsInvalidDataException()
    {
        byte[] decomp = new byte[64];

        // Case 1: Match offset == 0
        byte[] corruptOffset0 = [0x10, (byte)'A', 0x00, 0x00];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corruptOffset0, decomp));

        // Case 2: Match offset pointing before start of destination (offset = 5, but currentDst = 2)
        byte[] corruptOffsetBeforeStart = [0x20, (byte)'A', (byte)'B', 0x05, 0x00];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(corruptOffsetBeforeStart, decomp));

        // Case 3: Truncated match offset (token has match, but only 1 byte offset given)
        byte[] truncatedOffset = [0x10, (byte)'A', 0x01];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(truncatedOffset, decomp));
    }

    [Fact]
    public void Corrupt_Zstd_InvalidOffsets_ThrowsInvalidDataException()
    {
        var seqExec = new SequenceExecutor();
        // Initial state: R1=1, R2=4, R3=8
        // offsetCode = 3 with LL == 0 triggers: offset = _r1 - 1 = 1 - 1 = 0 -> throws InvalidDataException
        Assert.Throws<InvalidDataException>(() => seqExec.ResolveOffset(offsetCode: 3, literalLength: 0));

        // Match offset exceeding decoded history window boundary
        byte[] lits = [(byte)'X'];
        byte[] dst = new byte[32];
        int litIdx = 0;
        int dstIdx = 2; // only 2 bytes written
        // Attempt match copy with offset 10 (exceeds window 2)
        Assert.Throws<InvalidDataException>(() => seqExec.Execute(lits, ref litIdx, literalLength: 0, matchLength: 4, offset: 10, dst, ref dstIdx));
    }

    [Fact]
    public void Corrupt_Lz4Frame_CorruptBlockLengths_ThrowsInvalidDataException()
    {
        byte[] payload = Encoding.UTF8.GetBytes("Block length corruption test");
        byte[] frame = new byte[payload.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(payload, frame);

        // Block size header is at index 7 (after 4-byte magic, 1-byte flg, 1-byte bd, 1-byte hc)
        // Set block size to 0x70000000 (exceeds frame length)
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(7, 4), 0x70000000U);

        byte[] decomp = new byte[payload.Length];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame.AsSpan(0, fLen), decomp));
    }

    [Fact]
    public void Corrupt_ZstdFrame_BlockSizeExceedsLimitOrReservedType_ThrowsInvalidDataException()
    {
        byte[] decomp = new byte[64];

        // Case 1: Block size exceeds MaxBlockSize (128 KB = 131072)
        // 24-bit header: Last=1 (bit 0), Type=0 (bits 2-1), Size=140000 (bits 23-3)
        uint badSizeHeader = 1U | (0U << 1) | (140000U << 3);
        byte[] badSizeFrame = [
            0x28, 0xB5, 0x2F, 0xFD, // Magic
            0x20, 0x00,             // FHD: Single_Segment=1, FCS=0
            (byte)(badSizeHeader & 0xFF),
            (byte)((badSizeHeader >> 8) & 0xFF),
            (byte)((badSizeHeader >> 16) & 0xFF)
        ];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(badSizeFrame, decomp));

        // Case 2: Reserved block type (3)
        // 24-bit header: Last=1, Type=3 (bits 2-1 = 0b11), Size=10
        uint reservedTypeHeader = 1U | (3U << 1) | (10U << 3);
        byte[] reservedTypeFrame = [
            0x28, 0xB5, 0x2F, 0xFD,
            0x20, 0x00,
            (byte)(reservedTypeHeader & 0xFF),
            (byte)((reservedTypeHeader >> 8) & 0xFF),
            (byte)((reservedTypeHeader >> 16) & 0xFF)
        ];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(reservedTypeFrame, decomp));
    }

    [Fact]
    public void Corrupt_Lz4Frame_BitFlipsInChecksums_ThrowsInvalidDataException()
    {
        byte[] payload = Encoding.UTF8.GetBytes("Frame checksum bit tampering verification payload.");
        byte[] frame = new byte[payload.Length + 64];
        int fLen = Lz4FrameCodec.EncodeFrame(payload, frame, contentChecksum: true, blockChecksum: true);

        byte[] decomp = new byte[payload.Length];

        // 1. Bit flip in Header Checksum (index 6)
        byte[] corruptHc = (byte[])frame.Clone();
        corruptHc[6] ^= 0x40;
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(corruptHc.AsSpan(0, fLen), decomp));

        // 2. Bit flip in Content Checksum (last 4 bytes)
        byte[] corruptCc = (byte[])frame.Clone();
        corruptCc[fLen - 2] ^= 0x80;
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(corruptCc.AsSpan(0, fLen), decomp));
    }

    [Fact]
    public void Corrupt_ZstdFrame_BitFlipsInContentChecksum_ThrowsInvalidDataException()
    {
        byte[] payload = Encoding.UTF8.GetBytes("Zstd content checksum tampering challenge payload.");
        byte[] frame = new byte[ZstdCodec.MaximumCompressedSize(payload.Length)];
        int fLen = ZstdCodec.Compress(payload, frame);

        byte[] decomp = new byte[payload.Length];

        // Tamper each of the last 4 checksum bytes
        for (int b = 1; b <= 4; b++)
        {
            byte[] corrupt = (byte[])frame.Clone();
            corrupt[fLen - b] ^= 0x01;
            Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(corrupt.AsSpan(0, fLen), decomp));
        }
    }

    [Fact]
    public void Corrupt_FseDecoder_InvalidAccuracyLogAndCorruptProbabilities_ThrowsInvalidDataException()
    {
        // Case 1: AccuracyLog exceeds maxAccuracyLog
        // First 4 bits = 15 => accuracyLog = 15 + 5 = 20 (> maxAccuracyLog = 9)
        byte[] badAccuracyHeader = [0x0F, 0x00, 0x00];
        Assert.Throws<InvalidDataException>(() =>
        {
            var localTable = new FseTableEntry[64];
            FseDecoder.ReadTable(badAccuracyHeader, maxSymbol: 35, maxAccuracyLog: 9, localTable, out _);
        });

        // Case 2: Remaining probability sum does not resolve to 0
        byte[] badSumHeader = [0x00, 0x00, 0x00]; // accuracyLog = 5 (tableSize = 32), all zero probabilities
        Assert.Throws<InvalidDataException>(() =>
        {
            var localTable = new FseTableEntry[64];
            FseDecoder.ReadTable(badSumHeader, maxSymbol: 5, maxAccuracyLog: 9, localTable, out _);
        });
    }

    [Fact]
    public void Corrupt_HuffmanDecoder_CorruptWeights_ThrowsInvalidDataException()
    {
        // Case 1: Empty description
        Assert.Throws<InvalidDataException>(() =>
        {
            var localTable = new HuffmanTableEntry[2048];
            HuffmanDecoder.BuildTable(ReadOnlySpan<byte>.Empty, localTable, out _);
        });

        // Case 2: Direct representation with 0 symbols (header = 127) -> not direct (> 127)
        // header = 128 (numSymbols = 1), but zero weight bytes provided
        byte[] truncatedDirect = [128];
        Assert.Throws<InvalidDataException>(() =>
        {
            var localTable = new HuffmanTableEntry[2048];
            HuffmanDecoder.BuildTable(truncatedDirect, localTable, out _);
        });

        // Case 3: Weight sum is zero
        byte[] zeroWeights = [129, 0x00]; // numSymbols = 2, weights = [0, 0]
        Assert.Throws<InvalidDataException>(() =>
        {
            var localTable = new HuffmanTableEntry[2048];
            HuffmanDecoder.BuildTable(zeroWeights, localTable, out _);
        });
    }

    // =========================================================================
    // 4. 1,000 Randomized Roundtrip Cycles
    // =========================================================================

    [Fact]
    public void Randomized_1000Cycles_ExactRestoration()
    {
        var rng = new Random(42); // deterministic seed for reproducibility

        for (int cycle = 0; cycle < 1000; cycle++)
        {
            // Pick size: mix of edge boundaries and diverse buffer lengths
            int size;
            int sizeClass = rng.Next(6);
            if (sizeClass == 0)
            {
                size = rng.Next(0, 16); // boundary sizes 0..15
            }
            else if (sizeClass == 1)
            {
                size = rng.Next(16, 256); // small sizes
            }
            else if (sizeClass == 2)
            {
                size = rng.Next(256, 4096); // medium sizes
            }
            else if (sizeClass == 3)
            {
                size = rng.Next(4096, 32768); // large sizes
            }
            else if (sizeClass == 4)
            {
                // Exact powers of 2 or close to 64KB
                int[] powers = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65535, 65536];
                size = powers[rng.Next(powers.Length)];
            }
            else
            {
                size = rng.Next(100, 2000);
            }

            byte[] input = new byte[size];

            // Pick topology
            int topology = rng.Next(5);
            if (topology == 0)
            {
                // RLE run
                byte rleVal = (byte)rng.Next(256);
                Array.Fill(input, rleVal);
            }
            else if (topology == 1)
            {
                // Short repeating pattern (period 2..31)
                int period = rng.Next(2, 32);
                for (int i = 0; i < size; i++) input[i] = (byte)((i % period) ^ (period * 7));
            }
            else if (topology == 2)
            {
                // High entropy pseudorandom
                rng.NextBytes(input);
            }
            else if (topology == 3)
            {
                // ASCII text
                for (int i = 0; i < size; i++) input[i] = (byte)rng.Next(32, 127);
            }
            else
            {
                // Mixed blocks: RLE chunks followed by random chunks
                int p = 0;
                while (p < size)
                {
                    int chunkSize = Math.Min(size - p, rng.Next(8, 64));
                    if (rng.Next(2) == 0)
                    {
                        byte b = (byte)rng.Next(256);
                        Array.Fill(input, b, p, chunkSize);
                    }
                    else
                    {
                        for (int k = 0; k < chunkSize; k++) input[p + k] = (byte)rng.Next(256);
                    }
                    p += chunkSize;
                }
            }

            // Test 1: LZ4 Block Codec
            int maxLz4 = Lz4Codec.MaximumCompressedSize(size);
            byte[] lz4Comp = new byte[maxLz4];
            int lz4Len = Lz4Codec.Compress(input, lz4Comp);
            byte[] lz4Decomp = new byte[size];
            int lz4DLen = Lz4Codec.Decompress(lz4Comp.AsSpan(0, lz4Len), lz4Decomp);
            Assert.Equal(size, lz4DLen);
            if (size > 0)
            {
                Assert.True(input.AsSpan().SequenceEqual(lz4Decomp), $"Cycle {cycle}: LZ4 block bit-exact restoration failed for size {size}.");
            }

            // Test 2: LZ4 Frame Codec
            bool contentCsum = (cycle % 2) == 0;
            bool blockCsum = (cycle % 3) == 0;
            byte[] lz4Frame = new byte[size + (size / 10) + 1024];
            int frameLen = Lz4FrameCodec.EncodeFrame(input, lz4Frame, contentCsum, blockCsum);
            byte[] frameDecomp = new byte[size];
            int frameDLen = Lz4FrameCodec.DecodeFrame(lz4Frame.AsSpan(0, frameLen), frameDecomp);
            Assert.Equal(size, frameDLen);
            if (size > 0)
            {
                Assert.True(input.AsSpan().SequenceEqual(frameDecomp), $"Cycle {cycle}: LZ4 frame bit-exact restoration failed for size {size}.");
            }

            // Test 3: Zstd Frame Codec
            int maxZstd = ZstdCodec.MaximumCompressedSize(size);
            byte[] zstdComp = new byte[maxZstd];
            int zstdLen = ZstdCodec.Compress(input, zstdComp);
            byte[] zstdDecomp = new byte[size];
            int zstdDLen = ZstdCodec.Decompress(zstdComp.AsSpan(0, zstdLen), zstdDecomp);
            Assert.Equal(size, zstdDLen);
            if (size > 0)
            {
                Assert.True(input.AsSpan().SequenceEqual(zstdDecomp), $"Cycle {cycle}: Zstd frame bit-exact restoration failed for size {size}.");
            }
        }
    }
}
