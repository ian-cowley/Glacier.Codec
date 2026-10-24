using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Memory;

namespace Glacier.Codec.Tests.E2E.Tier4_RealWorldScenarios;

public class Tier4_SecureStorageWalPipeline
{
    private const uint WalMagic = 0x57414C31; // "WAL1"

    [Fact]
    public void Scenario_SecureStorageWriteAheadLog_WithZstdAndBlake3()
    {
        using var walStream = new MemoryStream();
        using var pool = new UnmanagedSlabPool();

        const int recordCount = 5;
        const int recordDataSize = 64 * 1024; // 64 KB log record

        Span<byte> checksum = stackalloc byte[32];
        Span<byte> header = stackalloc byte[52];

        // 1. Write WAL entries
        for (ulong lsn = 1; lsn <= recordCount; lsn++)
        {
            IntPtr slab = pool.Rent(recordDataSize, out int actualSize);
            try
            {
                unsafe
                {
                    // Synthesize log entry
                    var recordSpan = new Span<byte>((void*)slab, recordDataSize);
                    recordSpan.Fill((byte)(lsn & 0xFF));

                    // Compress record with Zstandard
                    int maxComp = ZstdCodec.MaximumCompressedSize(recordDataSize);
                    byte[] compBuf = new byte[maxComp];
                    int compLen = ZstdCodec.Compress(recordSpan, compBuf);

                    // Compute BLAKE3 checksum over compressed body
                    Blake3Hasher.Hash(compBuf.AsSpan(0, compLen), checksum);

                    // Record Frame layout:
                    // [Magic (4B)] [LSN (8B)] [CompLength (4B)] [RawLength (4B)] [Checksum (32B)] [Payload]
                    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(0, 4), WalMagic);
                    BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(4, 8), lsn);
                    BinaryPrimitives.WriteInt32LittleEndian(header.Slice(12, 4), compLen);
                    BinaryPrimitives.WriteInt32LittleEndian(header.Slice(16, 4), recordDataSize);
                    checksum.CopyTo(header.Slice(20, 32));

                    walStream.Write(header);
                    walStream.Write(compBuf, 0, compLen);
                }
            }
            finally
            {
                pool.Return(slab, actualSize);
            }
        }

        // 2. Simulate partial / corrupted write at tail
        long validCommitOffset = walStream.Position;
        walStream.Write(new byte[] { 0x31, 0x4C, 0x41, 0x57, 0x06 }); // Incomplete header trailing crash

        // 3. Crash Recovery Engine: Scan WAL, verify BLAKE3 checksums, truncate tail corrupt record
        walStream.Position = 0;
        ulong recoveredLsn = 0;
        Span<byte> actualChecksum = stackalloc byte[32];

        while (walStream.Position + 52 <= walStream.Length)
        {
            walStream.ReadExactly(header);

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(0, 4));
            if (magic != WalMagic)
            {
                // Crash point reached: truncate corrupted record
                walStream.SetLength(walStream.Position - 52);
                break;
            }

            ulong lsn = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(4, 8));
            int compLen = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(12, 4));
            int rawLen = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(16, 4));
            ReadOnlySpan<byte> expectedChecksum = header.Slice(20, 32);

            if (walStream.Position + compLen > walStream.Length)
            {
                // Truncated body: crash recovery
                walStream.SetLength(walStream.Position - 52);
                break;
            }

            byte[] compPayload = new byte[compLen];
            walStream.ReadExactly(compPayload);

            // Verify BLAKE3 checksum
            Blake3Hasher.Hash(compPayload, actualChecksum);

            if (!CryptographicOperations.FixedTimeEquals(expectedChecksum, actualChecksum))
            {
                // Corrupted record detected
                walStream.SetLength(walStream.Position - 52 - compLen);
                break;
            }

            // Decompress and verify
            byte[] decomp = new byte[rawLen];
            int dLen = ZstdCodec.Decompress(compPayload, decomp);
            Assert.Equal(rawLen, dLen);
            Assert.Equal((byte)(lsn & 0xFF), decomp[0]);

            recoveredLsn = lsn;
        }

        // Truncate any incomplete/uncommitted trailing crash bytes after the last valid record
        walStream.SetLength(walStream.Position);

        Assert.Equal((ulong)recordCount, recoveredLsn);
        Assert.Equal(validCommitOffset, walStream.Length);
    }
}
