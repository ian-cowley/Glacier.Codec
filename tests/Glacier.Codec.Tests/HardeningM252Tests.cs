namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Cryptography.PostQuantum;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.XxHash32;
using Glacier.Codec.Memory;
using Xunit;

public class HardeningM252Tests
{
    private static byte[] BuildZstdSingleSeqFrame(byte[] litPayload, byte modes, byte[] seqData, int outputLen = 16)
    {
        using var ms = new MemoryStream();
        // Zstd magic
        Span<byte> magic = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(magic, ZstdCodec.MagicNumber);
        ms.Write(magic);

        // FHD: singleSegment=1 (0x20), 1-byte FCS
        ms.WriteByte(0x20);
        ms.WriteByte((byte)outputLen);

        // Build compressed block payload
        using var blk = new MemoryStream();
        // Raw literals (sizeFormat=0 -> 1 byte header: (len << 3) | 0)
        blk.WriteByte((byte)(litPayload.Length << 3));
        blk.Write(litPayload);
        // 1 sequence
        blk.WriteByte(1);
        blk.WriteByte(modes);
        blk.Write(seqData);

        byte[] blockBytes = blk.ToArray();
        uint header24 = 1u | (2u << 1) | ((uint)blockBytes.Length << 3);
        ms.WriteByte((byte)(header24 & 0xFF));
        ms.WriteByte((byte)((header24 >> 8) & 0xFF));
        ms.WriteByte((byte)((header24 >> 16) & 0xFF));
        ms.Write(blockBytes);
        return ms.ToArray();
    }

    [Theory]
    [InlineData(36)]
    [InlineData(255)]
    public void Zstd_RleLiteralLengthSymbol_OutOfBounds_ThrowsInvalidDataException(byte invalidLlSym)
    {
        // llMode = 1 (RLE), ofMode = 0, mlMode = 0 => modes = 0x40
        byte[] frame = BuildZstdSingleSeqFrame("ABCD"u8.ToArray(), 0x40, [invalidLlSym, 0x00, 0x00, 0x01]);
        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame, dst));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(255)]
    public void Zstd_RleOffsetSymbol_OutOfBounds_ThrowsInvalidDataException(byte invalidOfSym)
    {
        // llMode = 0, ofMode = 1 (RLE), mlMode = 0 => modes = 0x10
        byte[] frame = BuildZstdSingleSeqFrame("ABCD"u8.ToArray(), 0x10, [invalidOfSym, 0x00, 0x00, 0x00, 0x00, 0x01]);
        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame, dst));
    }

    [Theory]
    [InlineData(53)]
    [InlineData(255)]
    public void Zstd_RleMatchLengthSymbol_OutOfBounds_ThrowsInvalidDataException(byte invalidMlSym)
    {
        // llMode = 0, ofMode = 0, mlMode = 1 (RLE) => modes = 0x04
        byte[] frame = BuildZstdSingleSeqFrame("ABCD"u8.ToArray(), 0x04, [invalidMlSym, 0x00, 0x00, 0x01]);
        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame, dst));
    }

    [Fact]
    public void Zstd_FseOffsetCode31_ThrowsInvalidDataException()
    {
        // Craft FSE-compressed OF table (ofMode = 2 -> modes = 0x20) with accuracyLog = 5 (32 states)
        // where symbols 0..30 have probability 0 and symbol 31 has probability 32.
        // Forward bitstream (LSB-first):
        // 4 bits: 0 (accuracyLog = 5)
        // 5 bits: 1 (prob=0 for sym 0), 2 bits: 3 (3 zeros), ..., 10 repeats of 3 => sym 0..30 = 0 (remaining=32)
        // 6 bits: 63 (val & 31 = 31 >= threshold 30 => val = 63 - 30 = 33 => prob = 32 for sym 31)
        ulong bits = 0;
        int bitCount = 0;
        void PushBits(uint val, int count)
        {
            bits |= ((ulong)val & ((1UL << count) - 1UL)) << bitCount;
            bitCount += count;
        }

        PushBits(0, 4); // accuracyLog - 5 = 0
        PushBits(1, 5); // sym 0: prob = 0
        for (int i = 0; i < 10; i++) PushBits(3, 2); // 30 zeros -> s reaches 31
        PushBits(63, 6); // sym 31: prob = 32 -> remaining = 0

        int fseBytesLen = (bitCount + 7) / 8;
        byte[] seqData = new byte[fseBytesLen + 8];
        for (int i = 0; i < fseBytesLen; i++)
        {
            seqData[i] = (byte)((bits >> (i * 8)) & 0xFF);
        }
        // Backward sequence bitstream with enough bits + sentinel '1' bit
        seqData[^1] = 0x80;

        byte[] frame = BuildZstdSingleSeqFrame("ABCD"u8.ToArray(), 0x20, seqData);
        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame, dst));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void Huffman_Decode4Streams_SmallTotalLits_ThrowsInvalidDataException(int totalLits)
    {
        var table = new HuffmanTableEntry[2];
        table[0] = new HuffmanTableEntry { Symbol = (byte)'A', NumBits = 1 };
        table[1] = new HuffmanTableEntry { Symbol = (byte)'B', NumBits = 1 };

        // Valid 6-byte jump table + 4 minimal 1-byte backward streams
        byte[] payload = [1, 0, 1, 0, 1, 0, 0x02, 0x02, 0x02, 0x02];
        byte[] dst = new byte[totalLits];

        Assert.Throws<InvalidDataException>(() =>
            HuffmanDecoder.Decode4Streams(payload, table, maxBits: 1, dst));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public void Zstd_4StreamCompressedLiterals_SmallRegSize_ThrowsInvalidDataException(int regSize)
    {
        // Build Zstd frame with compressed 4-stream literals (litType = 2, sizeFormat = 1)
        // Direct Huffman table with 2 symbols ('A' weight 1, 'B' weight 1): headerByte = 128 (2-1+127=128? No: numSymbols-1? Wait: numSymbols = headerByte - 127 => headerByte=128 means 1 explicit symbol, 2nd deduced!)
        // headerByte = 128, weight0 = 0x10 => sym0='A' w=1, rest=1 => sym1=1 w=1. treeBytes = 2.
        // 4 streams payload: 6-byte jump table [1,0, 1,0, 1,0] + 4 bytes [0x02, 0x02, 0x02, 0x02] => compSize = 2 + 10 = 12.
        int compSize = 12;
        uint litHeader24 = 2u | (1u << 2) | ((uint)regSize << 4) | ((uint)compSize << 14);
        byte[] blockBytes = new byte[3 + compSize];
        blockBytes[0] = (byte)(litHeader24 & 0xFF);
        blockBytes[1] = (byte)((litHeader24 >> 8) & 0xFF);
        blockBytes[2] = (byte)((litHeader24 >> 16) & 0xFF);
        blockBytes[3] = 128; // direct weights, numSymbols=1 explicit
        blockBytes[4] = 0x10; // w[0] = 1
        // Jump table: s1=1, s2=1, s3=1
        blockBytes[5] = 1; blockBytes[6] = 0;
        blockBytes[7] = 1; blockBytes[8] = 0;
        blockBytes[9] = 1; blockBytes[10] = 0;
        blockBytes[11] = 0x02; blockBytes[12] = 0x02; blockBytes[13] = 0x02; blockBytes[14] = 0x02;

        using var ms = new MemoryStream();
        Span<byte> magic = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(magic, ZstdCodec.MagicNumber);
        ms.Write(magic);
        ms.WriteByte(0x20);
        ms.WriteByte((byte)regSize);

        uint header24 = 1u | (2u << 1) | ((uint)blockBytes.Length << 3);
        ms.WriteByte((byte)(header24 & 0xFF));
        ms.WriteByte((byte)((header24 >> 8) & 0xFF));
        ms.WriteByte((byte)((header24 >> 16) & 0xFF));
        ms.Write(blockBytes);

        byte[] dst = new byte[regSize];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(ms.ToArray(), dst));
    }

    [Fact]
    public void Huffman_Decode4Streams_SixBytes_RoundtripsCleanly()
    {
        Span<HuffmanTableEntry> table = stackalloc HuffmanTableEntry[2];
        table[0] = new HuffmanTableEntry { Symbol = (byte)'A', NumBits = 1 }; // code 0
        table[1] = new HuffmanTableEntry { Symbol = (byte)'B', NumBits = 1 }; // code 1

        // totalLits = 6 => seg = 2, reg1=2, reg2=2, reg3=2, reg4=0
        // Backward bitstream encoding 2 bits (MSB-first to peek): 00 + sentinel 1 => 0b100 = 0x04
        // 01 + sentinel 1 => 0b101 = 0x05, 10 + sentinel 1 => 0b110 = 0x06
        byte[] payload = [1, 0, 1, 0, 1, 0, 0x04, 0x05, 0x06];
        byte[] dst = new byte[6];
        HuffmanDecoder.Decode4Streams(payload, table, maxBits: 1, dst);

        Assert.Equal("AAABBA"u8.ToArray(), dst);
    }

    private static byte[] BuildDependentLz4Frame(byte[] block1Raw, byte[] block2Compressed, ReadOnlySpan<byte> expectedPlaintext)
    {
        using var ms = new MemoryStream();
        Span<byte> tmp4 = stackalloc byte[4];

        BinaryPrimitives.WriteUInt32LittleEndian(tmp4, Lz4FrameCodec.MagicNumber);
        ms.Write(tmp4);

        // FLG = 0x44 (Version=01, BlockIndependence=0, ContentChecksum=1), BD = 0x40 (64 KB)
        Span<byte> desc = [0x44, 0x40];
        ms.Write(desc);
        byte hc = (byte)((XxHash32.Hash(desc, 0) >> 8) & 0xFF);
        ms.WriteByte(hc);

        // Block 1: uncompressed
        BinaryPrimitives.WriteUInt32LittleEndian(tmp4, 0x80000000U | (uint)block1Raw.Length);
        ms.Write(tmp4);
        ms.Write(block1Raw);

        // Block 2: compressed referencing block 1
        BinaryPrimitives.WriteUInt32LittleEndian(tmp4, (uint)block2Compressed.Length);
        ms.Write(tmp4);
        ms.Write(block2Compressed);

        // EndMark
        BinaryPrimitives.WriteUInt32LittleEndian(tmp4, 0u);
        ms.Write(tmp4);

        // Content Checksum
        uint csum = XxHash32.Hash(expectedPlaintext, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(tmp4, csum);
        ms.Write(tmp4);

        return ms.ToArray();
    }

    [Fact]
    public void Lz4Frame_DependentBlocks_RoundtripsCrossBlockBackReferences()
    {
        byte[] block1 = new byte[100];
        for (int i = 0; i < block1.Length; i++) block1[i] = (byte)(i + 1);

        // Block 2: 0 literals, match length 20 (token 0x0F + ext 0x01) at offset 80 (from block1[20..39]) + 5 trailing literals
        byte[] block2Comp =
        [
            0x0F,       // litLen=0, matchToken=15
            0x50, 0x00, // offset = 80 LE
            0x01,       // matchLen = 15 + 4 + 1 = 20
            0x50,       // trailing litLen = 5
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE
        ];

        byte[] expected = new byte[125];
        block1.CopyTo(expected, 0);
        block1.AsSpan(20, 20).CopyTo(expected.AsSpan(100, 20));
        new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE }.CopyTo(expected, 120);

        byte[] frame = BuildDependentLz4Frame(block1, block2Comp, expected);
        byte[] decoded = new byte[125];
        int written = Lz4FrameCodec.DecodeFrame(frame, decoded);

        Assert.Equal(125, written);
        Assert.Equal(expected, decoded);
    }

    [Fact]
    public void Lz4Frame_DependentBlocks_OffsetBeforeFrameStart_ThrowsInvalidDataException()
    {
        byte[] block1 = new byte[20];
        byte[] block2Comp =
        [
            0x00,       // litLen=0, matchLen=4
            0x19, 0x00, // offset = 25 > 20 bytes in block 1!
            0x50, 1, 2, 3, 4, 5
        ];

        byte[] frame = BuildDependentLz4Frame(block1, block2Comp, ReadOnlySpan<byte>.Empty);
        byte[] decoded = new byte[64];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame, decoded));
    }

    [Fact]
    public void Lz4Codec_DecompressFromOffset_EnforcesHistoryStartWindow()
    {
        byte[] buffer = new byte[256];
        for (int i = 0; i < 100; i++) buffer[i] = (byte)(i ^ 0x5A);

        // Block at outputOffset=100, historyStartOffset=80 (only 20 bytes lookback allowed), offset=30 -> invalid!
        byte[] invalidBlock = [0x00, 30, 0, 0x50, 1, 2, 3, 4, 5];
        Assert.Throws<InvalidDataException>(() =>
            Lz4Codec.DecompressFromOffset(invalidBlock, buffer, outputOffset: 100, historyStartOffset: 80));

        // Offset=20 exactly at historyStartOffset=80 -> valid!
        byte[] validBlock = [0x00, 20, 0, 0x50, 1, 2, 3, 4, 5];
        int written = Lz4Codec.DecompressFromOffset(validBlock, buffer, outputOffset: 100, historyStartOffset: 80);
        Assert.Equal(9, written);
        Assert.Equal(buffer.AsSpan(80, 4).ToArray(), buffer.AsSpan(100, 4).ToArray());
    }

    [Fact]
    public void Argon2id_GeometryAndConstructor_HandleLargeParametersWithoutIntOverflow()
    {
        // 8 * (int.MaxValue / 4) overflows signed int; constructor must compare in long and throw ArgumentOutOfRangeException
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new Argon2id(iterations: 1, memoryKb: 1024, parallelism: int.MaxValue / 4));

        // 2 GiB (2_097_152 KiB) overflows int32 totalBytes if computed in int, must be positive 2 GiB in long
        var (mPrime, q, s, totalBytes) = Argon2id.ComputeMatrixGeometry(memoryKb: 2_097_152, parallelism: 4);
        Assert.Equal(2_097_152L, mPrime);
        Assert.Equal(524_288L, q);
        Assert.Equal(131_072L, s);
        Assert.Equal(2_147_483_648L, totalBytes);
        Assert.True(totalBytes > int.MaxValue);
    }

    [Theory]
    [InlineData(2, 1024)]
    [InlineData(4, 1024)]
    [InlineData(8, 2048)]
    public void Argon2id_ParallelSlices_DeterministicUnderConcurrency(int parallelism, int memoryKb)
    {
        byte[] pwd = Encoding.UTF8.GetBytes("ParallelArgon2idSecret");
        byte[] salt = Encoding.UTF8.GetBytes("ParallelSalt1234");

        byte[] expected = new byte[32];
        Argon2id.DeriveKey(pwd, salt, expected, iterations: 1, memoryKb: memoryKb, parallelism: parallelism);

        Parallel.For(0, 8, _ =>
        {
            Span<byte> actual = stackalloc byte[32];
            Argon2id.DeriveKey(pwd, salt, actual, iterations: 1, memoryKb: memoryKb, parallelism: parallelism);
            Assert.True(actual.SequenceEqual(expected));
        });
    }

    [Fact]
    public void Argon2id_ParallelSlices_ZeroSteadyStateAllocations()
    {
        byte[] pwd = Encoding.UTF8.GetBytes("ParallelZeroAllocPwd");
        byte[] salt = Encoding.UTF8.GetBytes("ParallelZeroAllocSalt");
        using var kdf = new Argon2id(iterations: 1, memoryKb: 2048, parallelism: 4); // s = 128 >= 64 -> parallel path

        Span<byte> tag = stackalloc byte[32];
        kdf.DeriveKey(pwd, salt, tag); // Warm up pool & JIT

        long before = GC.GetAllocatedBytesForCurrentThread();
        kdf.DeriveKey(pwd, salt, tag);
        long after = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, after - before);
    }

    [Fact]
    public void KeccakSponge_ResetAndDispose_ZeroesStateAndByteIndex()
    {
        Span<byte> secretInput = stackalloc byte[64];
        for (int i = 0; i < secretInput.Length; i++) secretInput[i] = (byte)(i + 1);

        Span<byte> digest1 = stackalloc byte[32];
        Span<byte> digest2 = stackalloc byte[32];
        Span<byte> freshDigest = stackalloc byte[32];

        var sponge = new KeccakSponge(rateInBytes: 136);
        sponge.Absorb(secretInput);
        Assert.True(sponge.ByteIndex > 0);
        sponge.Pad(0x06);
        sponge.Squeeze(digest1);

        bool anyNonZeroBeforeReset = false;
        for (int i = 0; i < 25; i++)
        {
            if (sponge.GetStateWord(i) != 0) anyNonZeroBeforeReset = true;
        }
        Assert.True(anyNonZeroBeforeReset);

        sponge.Reset();
        Assert.Equal(0, sponge.ByteIndex);
        for (int i = 0; i < 25; i++)
        {
            Assert.Equal(0UL, sponge.GetStateWord(i));
        }

        // Verify reused sponge produces identical output to a fresh sponge
        byte[] secondMsg = Encoding.UTF8.GetBytes("second-message-after-reset");
        sponge.Absorb(secondMsg);
        sponge.Pad(0x06);
        sponge.Squeeze(digest2);
        KeccakSponge.Sha3_256(secondMsg, freshDigest);
        Assert.True(digest2.SequenceEqual(freshDigest));

        // Verify Dispose scrubs all 25 state words and ByteIndex
        sponge.Dispose();
        Assert.Equal(0, sponge.ByteIndex);
        for (int i = 0; i < 25; i++)
        {
            Assert.Equal(0UL, sponge.GetStateWord(i));
        }
    }

    [Fact]
    public void UnmanagedSlabPool_RawRent_Exceeds512Entries_ScalesAndRemainsZeroAlloc()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 64, maxLargeSlabs: 8, maxHugeSlabs: 4);
        const int liveCount = 700;
        var ptrs = new IntPtr[liveCount];
        var sizes = new int[liveCount];
        var seen = new System.Collections.Generic.HashSet<IntPtr>(liveCount);

        for (int i = 0; i < liveCount; i++)
        {
            ptrs[i] = pool.Rent(64, out sizes[i]);
            Assert.NotEqual(IntPtr.Zero, ptrs[i]);
            Assert.Equal(0L, (long)ptrs[i] & 63L);
            Assert.True(seen.Add(ptrs[i]), $"Duplicate pointer returned at index {i}");
        }

        for (int i = 0; i < liveCount; i++)
        {
            pool.Return(ptrs[i], sizes[i]);
            // Duplicate return must remain safely idempotent
            pool.Return(ptrs[i], sizes[i]);
        }

        // Warm up one steady-state rent/return cycle
        IntPtr warmPtr = pool.Rent(64, out int warmSize);
        pool.Return(warmPtr, warmSize);

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 16; i++)
        {
            IntPtr p = pool.Rent(64, out int s);
            pool.Return(p, s);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);
    }

    [Fact]
    public unsafe void UnmanagedSlabPool_ZeroMemoryChunked_ZeroesNonEmptyRegions()
    {
        byte[] buf = new byte[4096];
        buf.AsSpan().Fill(0xA5);
        fixed (byte* p = buf)
        {
            UnmanagedSlabPool.ZeroMemoryChunked(p, (nuint)buf.Length);
        }
        Assert.All(buf, b => Assert.Equal(0, b));
    }

    [Fact]
    public void ParallelEngines_HighContention_24Threads_ZeroAllocAndCorrect()
    {
        const int threadsCount = 24;
        const int payloadSize = 512 * 1024;
        var errors = new ConcurrentBag<Exception>();
        var ready = new CountdownEvent(threadsCount);
        var go = new ManualResetEventSlim(false);
        var barrier = new Barrier(threadsCount);

        byte[] blakeInput = new byte[2 * 1024 * 1024];
        for (int i = 0; i < blakeInput.Length; i++) blakeInput[i] = (byte)(i * 13 + 7);
        byte[] expectedBlake = new byte[32];
        Blake3Hasher.Hash(blakeInput, expectedBlake);

        byte[] aesKey = new byte[32];
        RandomNumberGenerator.Fill(aesKey);

        var threads = new Thread[threadsCount];
        for (int t = 0; t < threadsCount; t++)
        {
            int tid = t;
            threads[t] = new Thread(() =>
            {
                try
                {
                    using var cipher = new Aes256GcmCipher(aesKey);
                    byte[] plain = new byte[payloadSize];
                    for (int i = 0; i < plain.Length; i++) plain[i] = (byte)(i + tid);
                    byte[] cipherBuf = new byte[payloadSize];
                    byte[] decBuf = new byte[payloadSize];
                    byte[] tag = new byte[16];
                    byte[] nonce = new byte[12];
                    BinaryPrimitives.WriteInt32LittleEndian(nonce, tid);
                    byte[] aad = new byte[16];
                    byte[] blakeOut = new byte[32];

                    ready.Signal();
                    go.Wait();

                    // Warmup
                    cipher.Encrypt(plain, aad, nonce, cipherBuf, tag);
                    Assert.True(cipher.Decrypt(cipherBuf, aad, nonce, tag, decBuf));
                    Blake3Hasher.Hash(blakeInput, blakeOut);
                    Assert.True(blakeOut.AsSpan().SequenceEqual(expectedBlake));

                    barrier.SignalAndWait();

                    for (int iter = 0; iter < 5; iter++)
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);
                        long b = GC.GetAllocatedBytesForCurrentThread();
                        cipher.Encrypt(plain, aad, nonce, cipherBuf, tag);
                        bool ok = cipher.Decrypt(cipherBuf, aad, nonce, tag, decBuf);
                        Blake3Hasher.Hash(blakeInput, blakeOut);
                        long a = GC.GetAllocatedBytesForCurrentThread();

                        if (a - b != 0)
                            throw new InvalidOperationException($"Thread {tid} allocated {a - b} bytes.");
                        if (!ok || !plain.AsSpan().SequenceEqual(decBuf))
                            throw new InvalidOperationException($"AES-GCM mismatch on thread {tid}.");
                        if (!blakeOut.AsSpan().SequenceEqual(expectedBlake))
                            throw new InvalidOperationException($"BLAKE3 mismatch on thread {tid}.");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }) { IsBackground = true };
            threads[t].Start();
        }

        ready.Wait();
        go.Set();
        foreach (var th in threads) th.Join();

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(0x7FFFFFFFU)]
    [InlineData(0xFFFFFFFFU)]
    public void Lz4Frame_BlockSizeIntOverflow_ThrowsInvalidDataException(uint blockSize)
    {
        byte[] frame = new byte[15];
        frame[0] = 0x04; frame[1] = 0x22; frame[2] = 0x4D; frame[3] = 0x18; // LZ4 frame magic
        frame[4] = 0x60; frame[5] = 0x40; frame[6] = 0x82;                   // FLG=0x60, BD=0x40, HC=0x82
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(7, 4), blockSize);
        // bytes 11..14 remain 0

        byte[] dst = new byte[64];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame, dst));
    }

    [Theory]
    [InlineData(0xFFFFFFF8U)]
    [InlineData(0xFFFFFFF9U)]
    [InlineData(0xFFFFFFFAU)]
    [InlineData(0xFFFFFFFBU)]
    [InlineData(0xFFFFFFFCU)]
    [InlineData(0xFFFFFFFDU)]
    [InlineData(0xFFFFFFFEU)]
    [InlineData(0xFFFFFFFFU)]
    public void Lz4Frame_SkippableFrameUIntWraparound_ThrowsInvalidDataException(uint skipSize)
    {
        byte[] frame = new byte[8];
        frame[0] = 0x50; frame[1] = 0x2A; frame[2] = 0x4D; frame[3] = 0x18;
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4, 4), skipSize);

        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(frame, dst));
    }

    [Theory]
    [InlineData(0xFFFFFFF8U)]
    [InlineData(0xFFFFFFF9U)]
    [InlineData(0xFFFFFFFAU)]
    [InlineData(0xFFFFFFFBU)]
    [InlineData(0xFFFFFFFCU)]
    [InlineData(0xFFFFFFFDU)]
    [InlineData(0xFFFFFFFEU)]
    [InlineData(0xFFFFFFFFU)]
    public void Zstd_SkippableFrameUIntWraparound_ThrowsInvalidDataException(uint skipSize)
    {
        byte[] frame = new byte[8];
        frame[0] = 0x50; frame[1] = 0x2A; frame[2] = 0x4D; frame[3] = 0x18;
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4, 4), skipSize);

        byte[] dst = new byte[16];
        Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(frame, dst));
    }

    [Fact]
    public void Zstd_SkippableFrame_ExactZeroSkipSize_ReturnsZero()
    {
        byte[] frame = [0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
        byte[] dst = new byte[16];
        Assert.Equal(0, ZstdCodec.Decompress(frame, dst));
    }

    [Fact]
    public void Argon2id_ParallelSlices_ZeroAllocUnderHeavyContention()
    {
        const int threadsCount = 12;
        byte[] pwd = Encoding.UTF8.GetBytes("ContentionZeroAllocPwd");
        byte[] salt = Encoding.UTF8.GetBytes("ContentionZeroAllocSalt");
        byte[] expected = new byte[32];
        Argon2id.DeriveKey(pwd, salt, expected, iterations: 2, memoryKb: 4096, parallelism: 4);

        var errors = new ConcurrentBag<Exception>();
        var barrier = new Barrier(threadsCount);
        var threads = new Thread[threadsCount];

        for (int t = 0; t < threadsCount; t++)
        {
            threads[t] = new Thread(() =>
            {
                try
                {
                    using var kdf = new Argon2id(iterations: 2, memoryKb: 4096, parallelism: 4);
                    Span<byte> tag = stackalloc byte[32];

                    // Warmup JIT & thread-local buffers
                    kdf.DeriveKey(pwd, salt, tag);
                    if (!tag.SequenceEqual(expected))
                        throw new InvalidOperationException("Warmup Argon2id mismatch.");

                    // Synchronized contention warmup so ThreadPool global queue segments reach steady-state capacity
                    barrier.SignalAndWait();
                    kdf.DeriveKey(pwd, salt, tag);
                    barrier.SignalAndWait();

                    for (int iter = 0; iter < 5; iter++)
                    {
                        long before = GC.GetAllocatedBytesForCurrentThread();
                        kdf.DeriveKey(pwd, salt, tag);
                        long after = GC.GetAllocatedBytesForCurrentThread();

                        if (after - before != 0)
                            throw new InvalidOperationException($"Allocated {after - before} bytes under contention on iter {iter}.");
                        if (!tag.SequenceEqual(expected))
                            throw new InvalidOperationException("Argon2id mismatch under contention.");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }) { IsBackground = true };
            threads[t].Start();
        }

        foreach (var th in threads) th.Join();
        Assert.Empty(errors);
    }
}
