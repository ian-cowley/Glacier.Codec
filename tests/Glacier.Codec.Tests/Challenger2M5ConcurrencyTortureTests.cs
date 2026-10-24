namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Compression;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Hashing.XxHash32;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Concurrency Torture, High-Throughput Memory Streaming, and Zero-Allocation Stress Suite for Milestone M5.
/// Authored by Empirical Challenger 2 (challenger_m5_2).
/// Validates:
/// 1. 32-thread massive concurrent streaming compression/decompression stress via Parallel.For.
/// 2. High-throughput streaming data: sustained 64 MB / 128 MB streaming data passing through Lz4Codec, Lz4FrameCodec, and ZstdCodec.
/// 3. Strict steady-state zero-allocation assertions: verify that steady-state hot paths allocate strictly 0 bytes.
/// 4. Adversarial concurrent corruption and thread-isolation resilience without memory leaks.
/// </summary>
public class Challenger2M5ConcurrencyTortureTests
{
    private const int ConcurrencyLevel32 = 32;

    // =========================================================================
    // SECTION 1: MASSIVE CONCURRENCY TORTURE (32 CONCURRENT THREADS)
    // =========================================================================

    [Fact]
    public void Concurrency_32Threads_Lz4Codec_DistinctPayloads_NoRaceConditions()
    {
        const int iterationsPerThread = 12;
        var exceptions = new ConcurrentBag<Exception>();
        byte[][] threadInputs = new byte[ConcurrencyLevel32][];
        for (int t = 0; t < ConcurrencyLevel32; t++)
        {
            int len = 4096 + (t * 512);
            threadInputs[t] = new byte[len];
            for (int i = 0; i < len; i++) threadInputs[t][i] = (byte)((t * 17) ^ (i % 64 == 0 ? 0xAA : (i & 0x7F)));
        }

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] input = threadInputs[threadId];
                byte[] compBuffer = new byte[Lz4Codec.MaximumCompressedSize(input.Length)];
                byte[] decompBuffer = new byte[input.Length];

                for (int iter = 0; iter < iterationsPerThread; iter++)
                {
                    int compLen = Lz4Codec.Compress(input, compBuffer);
                    Assert.True(compLen > 0 && compLen <= compBuffer.Length);

                    decompBuffer.AsSpan().Clear();
                    int decompLen = Lz4Codec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
                    Assert.Equal(input.Length, decompLen);
                    Assert.True(input.AsSpan().SequenceEqual(decompBuffer));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_Lz4Codec_SharedInstance_ThreadSafe()
    {
        ICompressionCodec sharedCodec = new Lz4Codec();
        const int iterations = 10;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] input = new byte[2048];
                for (int i = 0; i < input.Length; i++) input[i] = (byte)((threadId * 31 + i) & 0xFF);
                byte[] compBuffer = new byte[sharedCodec.GetMaxCompressedSize(input.Length)];
                byte[] decompBuffer = new byte[input.Length];

                for (int iter = 0; iter < iterations; iter++)
                {
                    int compLen = sharedCodec.CompressBlock(input, compBuffer);
                    int decompLen = sharedCodec.DecompressBlock(compBuffer.AsSpan(0, compLen), decompBuffer);
                    Assert.Equal(input.Length, decompLen);
                    Assert.True(input.AsSpan().SequenceEqual(decompBuffer));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_Lz4FrameCodec_EncodeDecode_ChecksumIntegrity()
    {
        const int iterations = 8;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                int size = 16384 + (threadId * 1024);
                byte[] input = new byte[size];
                for (int i = 0; i < size; i++) input[i] = (byte)((threadId * 7 + i * 3) & 0xFF);
                byte[] frameBuffer = new byte[Lz4Codec.MaximumCompressedSize(size) + 64];
                byte[] decompBuffer = new byte[size];

                for (int iter = 0; iter < iterations; iter++)
                {
                    bool blockCsum = (threadId & 1) == 0;
                    bool contentCsum = (iter & 1) == 0;
                    int frameLen = Lz4FrameCodec.EncodeFrame(input, frameBuffer, contentChecksum: contentCsum, blockChecksum: blockCsum);
                    Assert.True(frameLen > 0);

                    decompBuffer.AsSpan().Clear();
                    int decompLen = Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameLen), decompBuffer);
                    Assert.Equal(size, decompLen);
                    Assert.True(input.AsSpan().SequenceEqual(decompBuffer));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_ZstdCodec_RleAndRawBlocks_NoDataCorruption()
    {
        const int iterations = 10;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                int len = 1024 + (threadId * 256);
                byte[] rleInput = new byte[len];
                Array.Fill(rleInput, (byte)(threadId * 9 + 1));
                byte[] rawInput = new byte[len];
                for (int i = 0; i < len; i++) rawInput[i] = (byte)((threadId * 13 + i * 19) & 0xFF);

                byte[] compBuffer = new byte[ZstdCodec.MaximumCompressedSize(len)];
                byte[] decompBuffer = new byte[len];

                for (int iter = 0; iter < iterations; iter++)
                {
                    int cLenRle = ZstdCodec.Compress(rleInput, compBuffer);
                    int dLenRle = ZstdCodec.Decompress(compBuffer.AsSpan(0, cLenRle), decompBuffer);
                    Assert.Equal(len, dLenRle);
                    Assert.True(rleInput.AsSpan().SequenceEqual(decompBuffer));

                    int cLenRaw = ZstdCodec.Compress(rawInput, compBuffer);
                    int dLenRaw = ZstdCodec.Decompress(compBuffer.AsSpan(0, cLenRaw), decompBuffer);
                    Assert.Equal(len, dLenRaw);
                    Assert.True(rawInput.AsSpan().SequenceEqual(decompBuffer));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_ZstdCodec_SharedInstance_ThreadSafe()
    {
        ICompressionCodec sharedCodec = new ZstdCodec();
        const int iterations = 10;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] input = new byte[2048];
                for (int i = 0; i < input.Length; i++) input[i] = (byte)((threadId * 23 + i) & 0xFF);
                byte[] comp = new byte[sharedCodec.GetMaxCompressedSize(input.Length)];
                byte[] decomp = new byte[input.Length];

                for (int iter = 0; iter < iterations; iter++)
                {
                    int cLen = sharedCodec.CompressBlock(input, comp);
                    int dLen = sharedCodec.DecompressBlock(comp.AsSpan(0, cLen), decomp);
                    Assert.Equal(input.Length, dLen);
                    Assert.True(input.AsSpan().SequenceEqual(decomp));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_StreamingCompressors_SimultaneousChunkPipelines()
    {
        const int chunksPerThread = 6;
        const int chunkSize = 4096;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                using var lz4Comp = new Lz4StreamCompressor();
                using var lz4Decomp = new Lz4StreamDecompressor();
                using var zstdComp = new ZstdStreamCompressor();
                using var zstdDecomp = new ZstdStreamDecompressor();

                byte[] chunk = new byte[chunkSize];
                byte[] compBuf = new byte[lz4Comp.GetMaxCompressedChunkSize(chunkSize) + 128];
                byte[] decompBuf = new byte[chunkSize];

                for (int c = 0; c < chunksPerThread; c++)
                {
                    for (int i = 0; i < chunkSize; i++) chunk[i] = (byte)((threadId * 11 + c * 7 + i) & 0xFF);
                    bool isFinal = (c == chunksPerThread - 1);

                    int lz4CLen = lz4Comp.CompressChunk(chunk, compBuf, isFinal);
                    int lz4DLen = lz4Decomp.DecompressChunk(compBuf.AsSpan(0, lz4CLen), decompBuf, out int lz4Consumed);
                    Assert.Equal(lz4CLen, lz4Consumed);
                    Assert.Equal(chunkSize, lz4DLen);
                    Assert.True(chunk.AsSpan().SequenceEqual(decompBuf));

                    int zstdCLen = zstdComp.CompressChunk(chunk, compBuf, isFinal);
                    int zstdDLen = zstdDecomp.DecompressChunk(compBuf.AsSpan(0, zstdCLen), decompBuf, out int zstdConsumed);
                    Assert.Equal(zstdCLen, zstdConsumed);
                    Assert.Equal(chunkSize, zstdDLen);
                    Assert.True(chunk.AsSpan().SequenceEqual(decompBuf));
                }

                lz4Comp.Reset();
                lz4Decomp.Reset();
                zstdComp.Reset();
                zstdDecomp.Reset();
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_UnmanagedSlabPool_StressLeasingUnderCompression()
    {
        const int iterations = 25;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] data = new byte[8192];
                for (int i = 0; i < data.Length; i++) data[i] = (byte)((threadId + i) & 0x7F);

                for (int i = 0; i < iterations; i++)
                {
                    using var lease1 = UnmanagedSlabPool.Shared.Rent(65536);
                    using var lease2 = UnmanagedSlabPool.Shared.Rent(16384);
                    int cLen = Lz4Codec.Compress(data, lease1.Span);
                    int dLen = Lz4Codec.Decompress(lease1.Span.Slice(0, cLen), lease2.Span);

                    Assert.Equal(data.Length, dLen);
                    Assert.True(data.AsSpan().SequenceEqual(lease2.Span.Slice(0, dLen)));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    // =========================================================================
    // SECTION 2: HIGH-THROUGHPUT STREAMING DATA (64 MB & 128 MB SUSTAINED STREAMS)
    // =========================================================================

    [Fact]
    public void HighThroughput_64MB_Lz4FrameCodec_SustainedStream_RoundtripVerification()
    {
        const int dataSize64M = 64 * 1024 * 1024;
        byte[] source = new byte[dataSize64M];

        for (int i = 0; i < dataSize64M; i += 4096)
        {
            int blockIdx = i / 4096;
            BinaryPrimitives.WriteInt32LittleEndian(source.AsSpan(i, 4), blockIdx);
            for (int j = 4; j < 4096; j++) source[i + j] = (byte)((j * 17) & 0x7F);
        }

        byte[] frameBuffer = new byte[Lz4Codec.MaximumCompressedSize(dataSize64M) + 4096];
        byte[] decompBuffer = new byte[dataSize64M];

        int frameSize = Lz4FrameCodec.EncodeFrame(source, frameBuffer, contentChecksum: true, blockChecksum: true);
        Assert.True(frameSize > 0 && frameSize < dataSize64M);

        int decompSize = Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameSize), decompBuffer);
        Assert.Equal(dataSize64M, decompSize);

        uint origCsum = XxHash32.Hash(source, 0);
        uint decompCsum = XxHash32.Hash(decompBuffer, 0);
        Assert.Equal(origCsum, decompCsum);
        Assert.True(source.AsSpan().SequenceEqual(decompBuffer));
    }

    [Fact]
    public void HighThroughput_128MB_Lz4FrameCodec_SustainedStream_RoundtripVerification()
    {
        const int dataSize128M = 128 * 1024 * 1024;
        byte[] source = new byte[dataSize128M];

        for (int i = 0; i < dataSize128M; i += 8192)
        {
            int chunkIdx = i / 8192;
            BinaryPrimitives.WriteInt32LittleEndian(source.AsSpan(i, 4), chunkIdx);
            for (int j = 4; j < 8192; j++) source[i + j] = (byte)((chunkIdx + (j % 128)) & 0xFF);
        }

        byte[] frameBuffer = new byte[Lz4Codec.MaximumCompressedSize(dataSize128M) + 8192];
        byte[] decompBuffer = new byte[dataSize128M];

        int frameSize = Lz4FrameCodec.EncodeFrame(source, frameBuffer, contentChecksum: true, blockChecksum: false);
        Assert.True(frameSize > 0);

        int decompSize = Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameSize), decompBuffer);
        Assert.Equal(dataSize128M, decompSize);

        uint origHash = XxHash32.Hash(source, 0);
        uint decompHash = XxHash32.Hash(decompBuffer, 0);
        Assert.Equal(origHash, decompHash);
    }

    [Fact]
    public void HighThroughput_64MB_Lz4Stream_ChunkedPipeline_ExactRoundtrip()
    {
        const int totalBytes = 64 * 1024 * 1024;
        const int chunkSize = 64 * 1024;
        int chunkCount = totalBytes / chunkSize;

        using var compressor = new Lz4StreamCompressor();
        using var decompressor = new Lz4StreamDecompressor();

        byte[] chunkSource = new byte[chunkSize];
        byte[] chunkComp = new byte[compressor.GetMaxCompressedChunkSize(chunkSize)];
        byte[] chunkDecomp = new byte[chunkSize];

        ulong originalDigestAccum = 0;
        ulong decompDigestAccum = 0;

        for (int c = 0; c < chunkCount; c++)
        {
            for (int i = 0; i < chunkSize; i++) chunkSource[i] = (byte)((c * 37 + i * 5) & 0xFF);
            originalDigestAccum ^= XxHash32.Hash64(chunkSource, (ulong)c);

            bool isFinal = (c == chunkCount - 1);
            int compLen = compressor.CompressChunk(chunkSource, chunkComp, isFinal);
            int decompLen = decompressor.DecompressChunk(chunkComp.AsSpan(0, compLen), chunkDecomp, out int consumed);

            Assert.Equal(compLen, consumed);
            Assert.Equal(chunkSize, decompLen);
            decompDigestAccum ^= XxHash32.Hash64(chunkDecomp, (ulong)c);
        }

        Assert.Equal(originalDigestAccum, decompDigestAccum);
    }

    [Fact]
    public void HighThroughput_128MB_Lz4Stream_ChunkedPipeline_ExactRoundtrip()
    {
        const int totalBytes = 128 * 1024 * 1024;
        const int chunkSize = 128 * 1024;
        int chunkCount = totalBytes / chunkSize;

        using var compressor = new Lz4StreamCompressor();
        using var decompressor = new Lz4StreamDecompressor();

        byte[] chunkSource = new byte[chunkSize];
        byte[] chunkComp = new byte[compressor.GetMaxCompressedChunkSize(chunkSize)];
        byte[] chunkDecomp = new byte[chunkSize];

        ulong originalDigestAccum = 0;
        ulong decompDigestAccum = 0;

        for (int c = 0; c < chunkCount; c++)
        {
            for (int i = 0; i < chunkSize; i++) chunkSource[i] = (byte)((c * 19 + (i % 256)) & 0xFF);
            originalDigestAccum ^= XxHash32.Hash64(chunkSource, (ulong)c);

            bool isFinal = (c == chunkCount - 1);
            int compLen = compressor.CompressChunk(chunkSource, chunkComp, isFinal);
            int decompLen = decompressor.DecompressChunk(chunkComp.AsSpan(0, compLen), chunkDecomp, out int consumed);

            Assert.Equal(compLen, consumed);
            Assert.Equal(chunkSize, decompLen);
            decompDigestAccum ^= XxHash32.Hash64(chunkDecomp, (ulong)c);
        }

        Assert.Equal(originalDigestAccum, decompDigestAccum);
    }

    [Fact]
    public void HighThroughput_64MB_ZstdStream_ChunkedPipeline_ExactRoundtrip()
    {
        const int totalBytes = 64 * 1024 * 1024;
        const int chunkSize = 64 * 1024;
        int chunkCount = totalBytes / chunkSize;

        using var compressor = new ZstdStreamCompressor();
        using var decompressor = new ZstdStreamDecompressor();

        byte[] chunkSource = new byte[chunkSize];
        byte[] chunkComp = new byte[compressor.GetMaxCompressedChunkSize(chunkSize)];
        byte[] chunkDecomp = new byte[chunkSize];

        ulong origChecksum = 0;
        ulong decompChecksum = 0;

        for (int c = 0; c < chunkCount; c++)
        {
            if ((c & 3) == 0) Array.Fill(chunkSource, (byte)(c & 0xFF));
            else for (int i = 0; i < chunkSize; i++) chunkSource[i] = (byte)((c * 23 + i) & 0xFF);

            origChecksum ^= XxHash32.Hash64(chunkSource, (ulong)c);

            bool isFinal = (c == chunkCount - 1);
            int compLen = compressor.CompressChunk(chunkSource, chunkComp, isFinal);
            int decompLen = decompressor.DecompressChunk(chunkComp.AsSpan(0, compLen), chunkDecomp, out int consumed);

            Assert.Equal(compLen, consumed);
            Assert.Equal(chunkSize, decompLen);
            decompChecksum ^= XxHash32.Hash64(chunkDecomp, (ulong)c);
        }

        Assert.Equal(origChecksum, decompChecksum);
    }

    [Fact]
    public void HighThroughput_128MB_ZstdStream_ChunkedPipeline_ExactRoundtrip()
    {
        const int totalBytes = 128 * 1024 * 1024;
        const int chunkSize = 64 * 1024;
        int chunkCount = totalBytes / chunkSize;

        using var compressor = new ZstdStreamCompressor();
        using var decompressor = new ZstdStreamDecompressor();

        byte[] chunkSource = new byte[chunkSize];
        byte[] chunkComp = new byte[compressor.GetMaxCompressedChunkSize(chunkSize)];
        byte[] chunkDecomp = new byte[chunkSize];

        ulong origDigest = 0;
        ulong decompDigest = 0;

        for (int c = 0; c < chunkCount; c++)
        {
            for (int i = 0; i < chunkSize; i++) chunkSource[i] = (byte)((c * 41 + i * 3) & 0xFF);
            origDigest ^= XxHash32.Hash64(chunkSource, (ulong)c);

            bool isFinal = (c == chunkCount - 1);
            int compLen = compressor.CompressChunk(chunkSource, chunkComp, isFinal);
            int decompLen = decompressor.DecompressChunk(chunkComp.AsSpan(0, compLen), chunkDecomp, out int consumed);

            Assert.Equal(compLen, consumed);
            Assert.Equal(chunkSize, decompLen);
            decompDigest ^= XxHash32.Hash64(chunkDecomp, (ulong)c);
        }

        Assert.Equal(origDigest, decompDigest);
    }

    [Fact]
    public void HighThroughput_32MB_Lz4Codec_LargeSingleBlock_ExactRoundtrip()
    {
        const int size32M = 32 * 1024 * 1024;
        byte[] source = new byte[size32M];
        for (int i = 0; i < size32M; i += 2048)
        {
            for (int j = 0; j < 2048; j++) source[i + j] = (byte)((j % 64 == 0 ? 0xEE : (j & 0x7F)));
        }

        byte[] compBuffer = new byte[Lz4Codec.MaximumCompressedSize(size32M)];
        byte[] decompBuffer = new byte[size32M];

        int compLen = Lz4Codec.Compress(source, compBuffer);
        Assert.True(compLen > 0);

        int decompLen = Lz4Codec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
        Assert.Equal(size32M, decompLen);

        uint hashOrig = XxHash32.Hash(source, 0);
        uint hashDecomp = XxHash32.Hash(decompBuffer, 0);
        Assert.Equal(hashOrig, hashDecomp);
    }

    // =========================================================================
    // SECTION 3: STRICT STEADY-STATE ZERO-ALLOCATION ASSERTIONS
    // =========================================================================

    [Fact]
    public void ZeroAlloc_Lz4Codec_Block_ZeroBytesAllocated()
    {
        byte[] source = new byte[8192];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)(i % 128);
        byte[] compBuffer = new byte[Lz4Codec.MaximumCompressedSize(source.Length)];
        byte[] decompBuffer = new byte[source.Length];
        int compLen = Lz4Codec.Compress(source, compBuffer);

        for (int w = 0; w < 10; w++)
        {
            Lz4Codec.Compress(source, compBuffer);
            Lz4Codec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 50; i++)
        {
            Lz4Codec.Compress(source, compBuffer);
            Lz4Codec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    [Fact]
    public void ZeroAlloc_Lz4FrameCodec_EncodeAndDecodeFrame_ZeroBytesAllocated()
    {
        byte[] source = new byte[8192];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)((i * 3) & 0xFF);
        byte[] frameBuffer = new byte[Lz4Codec.MaximumCompressedSize(source.Length) + 64];
        byte[] decompBuffer = new byte[source.Length];
        int frameLen = Lz4FrameCodec.EncodeFrame(source, frameBuffer, contentChecksum: true, blockChecksum: false);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        for (int w = 0; w < 25; w++)
        {
            Lz4FrameCodec.EncodeFrame(source, frameBuffer, contentChecksum: true, blockChecksum: false);
            Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameLen), decompBuffer);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 25; i++)
        {
            Lz4FrameCodec.EncodeFrame(source, frameBuffer, contentChecksum: true, blockChecksum: false);
            Lz4FrameCodec.DecodeFrame(frameBuffer.AsSpan(0, frameLen), decompBuffer);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    [Fact]
    public void ZeroAlloc_ZstdCodec_Frame_ZeroBytesAllocated()
    {
        byte[] source = new byte[4096];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)(i % 64);
        byte[] compBuffer = new byte[ZstdCodec.MaximumCompressedSize(source.Length)];
        byte[] decompBuffer = new byte[source.Length];
        int compLen = ZstdCodec.Compress(source, compBuffer);

        for (int w = 0; w < 10; w++)
        {
            ZstdCodec.Compress(source, compBuffer);
            ZstdCodec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 50; i++)
        {
            ZstdCodec.Compress(source, compBuffer);
            ZstdCodec.Decompress(compBuffer.AsSpan(0, compLen), decompBuffer);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    [Fact]
    public void ZeroAlloc_Lz4Streaming_ChunkCompression_ZeroBytesAllocated()
    {
        using var compressor = new Lz4StreamCompressor();
        using var decompressor = new Lz4StreamDecompressor();
        byte[] source = new byte[4096];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)((i * 7) & 0xFF);
        byte[] compBuffer = new byte[compressor.GetMaxCompressedChunkSize(source.Length)];
        byte[] decompBuffer = new byte[source.Length];
        int compLen = compressor.CompressChunk(source, compBuffer, isFinalChunk: false);

        for (int w = 0; w < 10; w++)
        {
            compressor.CompressChunk(source, compBuffer, isFinalChunk: false);
            decompressor.DecompressChunk(compBuffer.AsSpan(0, compLen), decompBuffer, out _);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 50; i++)
        {
            compressor.CompressChunk(source, compBuffer, isFinalChunk: false);
            decompressor.DecompressChunk(compBuffer.AsSpan(0, compLen), decompBuffer, out _);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    [Fact]
    public void ZeroAlloc_ZstdStreaming_ChunkCompression_ZeroBytesAllocated()
    {
        using var compressor = new ZstdStreamCompressor();
        using var decompressor = new ZstdStreamDecompressor();
        byte[] source = new byte[4096];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)((i * 11) & 0xFF);
        byte[] compBuffer = new byte[compressor.GetMaxCompressedChunkSize(source.Length)];
        byte[] decompBuffer = new byte[source.Length];
        int compLen = compressor.CompressChunk(source, compBuffer, isFinalChunk: false);

        for (int w = 0; w < 10; w++)
        {
            compressor.CompressChunk(source, compBuffer, isFinalChunk: false);
            decompressor.DecompressChunk(compBuffer.AsSpan(0, compLen), decompBuffer, out _);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 50; i++)
        {
            compressor.CompressChunk(source, compBuffer, isFinalChunk: false);
            decompressor.DecompressChunk(compBuffer.AsSpan(0, compLen), decompBuffer, out _);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    [Fact]
    public void ZeroAlloc_XxHash32_And_XxHash64_ZeroBytesAllocated()
    {
        byte[] source = new byte[4096];
        for (int i = 0; i < source.Length; i++) source[i] = (byte)(i & 0xFF);

        for (int w = 0; w < 10; w++)
        {
            _ = XxHash32.Hash(source, 0);
            _ = XxHash32.Hash64(source, 0);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            _ = XxHash32.Hash(source, 0);
            _ = XxHash32.Hash64(source, 0);
        }
        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0L, allocatedAfter - allocatedBefore);
    }

    // =========================================================================
    // SECTION 4: ADVERSARIAL CONCURRENCY & MEMORY TORTURE
    // =========================================================================

    [Fact]
    public void Torture_ConcurrentCorruptedFrames_AllThreadsThrowSafely()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] badMagicFrame = [0x99, 0x88, 0x77, 0x66, 0x60, 0x40, 0x00];
                byte[] outBuf = new byte[128];
                Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(badMagicFrame, outBuf));

                byte[] badZstdMagic = [0x11, 0x22, 0x33, 0x44, 0x20, 0x00, 0x01, 0x00, 0x00];
                Assert.Throws<InvalidDataException>(() => ZstdCodec.Decompress(badZstdMagic, outBuf));

                byte[] truncatedLz4Block = [0x10];
                Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(truncatedLz4Block, outBuf));
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Torture_ConcurrentRepeatedResetAndDispose_NoObjectDisposedLeaks()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                for (int i = 0; i < 50; i++)
                {
                    using var lz4 = new Lz4StreamCompressor();
                    using var zstd = new ZstdStreamCompressor();
                    lz4.Reset();
                    zstd.Reset();
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }

    [Fact]
    public void Torture_ConcurrentExtremeVariableLengthSlices_ZeroBufferOverrun()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte[] bigBuf = new byte[512];
                for (int i = 0; i < bigBuf.Length; i++) bigBuf[i] = (byte)(i + threadId);
                byte[] compBuf = new byte[1024];
                byte[] decompBuf = new byte[512];

                for (int len = 0; len <= 256; len++)
                {
                    ReadOnlySpan<byte> slice = bigBuf.AsSpan(0, len);
                    int cLen = Lz4Codec.Compress(slice, compBuf);
                    int dLen = Lz4Codec.Decompress(compBuf.AsSpan(0, cLen), decompBuf);
                    Assert.Equal(len, dLen);
                    Assert.True(slice.SequenceEqual(decompBuf.AsSpan(0, dLen)));

                    int zcLen = ZstdCodec.Compress(slice, compBuf);
                    int zdLen = ZstdCodec.Decompress(compBuf.AsSpan(0, zcLen), decompBuf);
                    Assert.Equal(len, zdLen);
                    Assert.True(slice.SequenceEqual(decompBuf.AsSpan(0, zdLen)));
                }
            }
            catch (Exception ex) { exceptions.Add(ex); }
        });
        Assert.Empty(exceptions);
    }
}
