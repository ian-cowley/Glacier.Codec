using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Hashing.XxHash3;

namespace Glacier.Codec.Tests.E2E.Tier4_RealWorldScenarios;

public class Tier4_ColumnarChunkPipeline
{
    private record RowGroupMetadata(int RowCount, ulong IndexHash, int CompressedBytes);

    [Fact]
    public void Scenario_ColumnarDataFrame_ChunkCompressionAndXxHash3Indexing()
    {
        const int totalRows = 10_000;
        const int rowsPerRowGroup = 2_000;
        int rowGroupCount = totalRows / rowsPerRowGroup;

        // Generate synthetic columnar series: int64 timestamps and float64 metrics
        long[] timestamps = new long[totalRows];
        double[] metrics = new double[totalRows];
        long baseTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        for (int i = 0; i < totalRows; i++)
        {
            timestamps[i] = baseTime + (i * 100);
            metrics[i] = Math.Sin(i * 0.05) * 100.0;
        }

        var catalog = new List<RowGroupMetadata>();
        var compressedRowGroups = new List<byte[]>();

        // 1. Process and compress row groups
        for (int rg = 0; rg < rowGroupCount; rg++)
        {
            int startIdx = rg * rowsPerRowGroup;
            int count = rowsPerRowGroup;

            // Serialize timestamps column chunk to bytes (LE)
            byte[] rawBytes = new byte[count * sizeof(long)];
            for (int r = 0; r < count; r++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(rawBytes.AsSpan(r * sizeof(long), sizeof(long)), timestamps[startIdx + r]);
            }

            // Index column chunk using xxHash3 64-bit
            ulong indexHash = XxHash3Hasher.Hash64(rawBytes);

            // Compress chunk with LZ4
            byte[] compBuffer = new byte[Lz4Codec.MaximumCompressedSize(rawBytes.Length)];
            int compLen = Lz4Codec.Compress(rawBytes, compBuffer);

            byte[] finalChunk = new byte[compLen];
            Array.Copy(compBuffer, finalChunk, compLen);

            compressedRowGroups.Add(finalChunk);
            catalog.Add(new RowGroupMetadata(count, indexHash, compLen));
        }

        Assert.Equal(rowGroupCount, catalog.Count);

        // 2. Query engine execution: Scan row group 2, decompress and verify index
        int targetRg = 2;
        var meta = catalog[targetRg];
        byte[] compData = compressedRowGroups[targetRg];

        byte[] decompBuffer = new byte[meta.RowCount * sizeof(long)];
        int decompLen = Lz4Codec.Decompress(compData, decompBuffer);

        Assert.Equal(decompBuffer.Length, decompLen);

        // Verify xxHash3 index matches
        ulong verifyHash = XxHash3Hasher.Hash64(decompBuffer);
        Assert.Equal(meta.IndexHash, verifyHash);

        // Verify deserialized values
        for (int r = 0; r < meta.RowCount; r++)
        {
            long val = BinaryPrimitives.ReadInt64LittleEndian(decompBuffer.AsSpan(r * sizeof(long), sizeof(long)));
            Assert.Equal(timestamps[(targetRg * rowsPerRowGroup) + r], val);
        }
    }
}
