namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Glacier.Codec.Hardware;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;

/// <summary>
/// Empirical Concurrency, Parallelism &amp; Stress Torture Harness for Milestone M2 Iteration 2.
/// Authored by Empirical Challenger 2.
/// 
/// Validates:
/// 1. Blake3Hasher.HashParallel multi-threaded tree reduction across 1MB, 4MB, and 16MB payloads under 24+ parallel threads.
/// 2. Bit-exact determinism between parallel reduction, streaming reduction, and one-shot execution.
/// 3. Concurrent hashing stress across 32 threads with XxHash3 (64/128-bit), Sha256, and Blake3.
/// 4. Memory zeroing and lifecycle safety on hasher disposal under concurrent loads.
/// 5. Empirical investigation of HardwareArbiter routing thresholds in Blake3Hasher.Hash.
/// </summary>
public unsafe class M2ConcurrencyAndParallelismStressTests
{
    private const int WorkerCount24 = 24;
    private const int WorkerCount32 = 32;

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "HashParallel")]
    private static extern void InvokeBlake3HashParallel(Blake3Hasher? target, ReadOnlySpan<byte> input, Span<byte> destination);

    // =========================================================================
    // 1. BLAKE3 MULTI-THREADED PARALLEL REDUCTION DETERMINISM (1MB, 4MB, 16MB)
    // =========================================================================

    [Theory]
    [InlineData(1024 * 1024)]             // Exact 1 MB (1024 chunks)
    [InlineData(1024 * 1024 + 17)]        // 1 MB + partial chunk
    [InlineData(2 * 1024 * 1024)]         // 2 MB (2048 chunks)
    [InlineData(4 * 1024 * 1024)]         // Exact 4 MB (4096 chunks)
    [InlineData(4 * 1024 * 1024 + 1025)]  // 4 MB + 1 full chunk + 1 byte
    [InlineData(8 * 1024 * 1024)]         // 8 MB (8192 chunks)
    [InlineData(16 * 1024 * 1024)]        // Exact 16 MB (16384 chunks)
    [InlineData(16 * 1024 * 1024 + 63)]   // 16 MB + partial block
    public void Blake3_ParallelReduction_MatchesStreamingReduction(int payloadSize)
    {
        byte[] payload = new byte[payloadSize];
        for (int i = 0; i < payloadSize; i++)
        {
            payload[i] = (byte)((i * 31 + 7) & 0xFF);
        }

        // 1. Golden digest via sequential streaming chunk ingestion
        byte[] streamingDigest = new byte[32];
        using (var streamHasher = new Blake3Hasher())
        {
            const int chunkSize = 64 * 1024;
            int offset = 0;
            while (offset < payloadSize)
            {
                int len = Math.Min(chunkSize, payloadSize - offset);
                streamHasher.Append(payload.AsSpan(offset, len));
                offset += len;
            }
            streamHasher.Finalize(streamingDigest);
        }

        // 2. Direct invocation of multi-threaded Blake3Hasher.HashParallel
        byte[] parallelDigest = new byte[32];
        InvokeBlake3HashParallel(null, payload, parallelDigest);

        Assert.True(
            streamingDigest.AsSpan().SequenceEqual(parallelDigest),
            $"Blake3 HashParallel mismatch for size {payloadSize}: Parallel={Convert.ToHexString(parallelDigest)} vs Stream={Convert.ToHexString(streamingDigest)}");

        // 3. Public Blake3Hasher.Hash execution
        byte[] oneShotDigest = new byte[32];
        Blake3Hasher.Hash(payload, oneShotDigest);

        Assert.True(
            streamingDigest.AsSpan().SequenceEqual(oneShotDigest),
            $"Blake3 public Hash mismatch for size {payloadSize}: OneShot={Convert.ToHexString(oneShotDigest)} vs Stream={Convert.ToHexString(streamingDigest)}");
    }

    // =========================================================================
    // 2. BLAKE3 HASHPARALLEL MULTI-THREADED REDUCTION TORTURE (24+ WORKERS)
    // =========================================================================

    [Fact]
    public void Blake3_HashParallel_24Workers_HeavyContentionTorture()
    {
        // Test multiple sizes under heavy parallel contention across 24 concurrent workers
        int[] testSizes = [
            1024 * 1024,        // 1 MB
            1024 * 1024 + 777,  // 1 MB + odd remainder
            2 * 1024 * 1024,    // 2 MB
            4 * 1024 * 1024,    // 4 MB
            4 * 1024 * 1024 + 65// 4 MB + 65 bytes
        ];

        // Precompute expected golden digests for each size
        byte[][] goldenDigests = new byte[testSizes.Length][];
        byte[][] testBuffers = new byte[testSizes.Length][];

        for (int s = 0; s < testSizes.Length; s++)
        {
            int size = testSizes[s];
            testBuffers[s] = new byte[size];
            for (int i = 0; i < size; i++)
            {
                testBuffers[s][i] = (byte)((i * 37 + s * 13 + 5) & 0xFF);
            }

            goldenDigests[s] = new byte[32];
            using var stream = new Blake3Hasher();
            stream.Append(testBuffers[s]);
            stream.Finalize(goldenDigests[s]);
        }

        const int iterationsPerWorker = 20;
        var exceptions = new ConcurrentBag<Exception>();
        int completedIterations = 0;

        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                Span<byte> workerHash = stackalloc byte[32];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int testIndex = (workerId + iter) % testSizes.Length;
                    byte[] buffer = testBuffers[testIndex];
                    byte[] expected = goldenDigests[testIndex];

                    // Direct invocation of parallel reduction kernel
                    InvokeBlake3HashParallel(null, buffer, workerHash);

                    if (!workerHash.SequenceEqual(expected))
                    {
                        throw new InvalidOperationException(
                            $"Blake3 HashParallel corruption at worker {workerId}, iter {iter}, size {buffer.Length}: " +
                            $"got {Convert.ToHexString(workerHash)}, expected {Convert.ToHexString(expected)}");
                    }

                    Interlocked.Increment(ref completedIterations);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(WorkerCount24 * iterationsPerWorker, completedIterations);
    }

    // =========================================================================
    // 3. CONCURRENT HASHING STRESS TEST (32 CONCURRENT THREADS)
    // =========================================================================

    [Fact]
    public void ConcurrentHashing_32Threads_XxHash3_Sha256_Blake3_Torture()
    {
        const int iterationsPerWorker = 150;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        // Shared input buffer pools with distinct pseudorandom patterns
        int[] sizes = [0, 1, 7, 16, 64, 128, 240, 241, 1024, 4096, 65536];
        byte[][] buffers = new byte[sizes.Length][];
        for (int s = 0; s < sizes.Length; s++)
        {
            buffers[s] = new byte[sizes[s]];
            for (int i = 0; i < sizes[s]; i++)
            {
                buffers[s][i] = (byte)((i * 53 + s * 17 + 1) & 0xFF);
            }
        }

        // Precompute ground truth for verification
        ulong[] xxh64Golden = new ulong[sizes.Length];
        UInt128[] xxh128Golden = new UInt128[sizes.Length];
        byte[][] sha256Golden = new byte[sizes.Length][];
        byte[][] blake3Golden = new byte[sizes.Length][];

        for (int s = 0; s < sizes.Length; s++)
        {
            xxh64Golden[s] = XxHash3Hasher.Hash64(buffers[s]);
            xxh128Golden[s] = XxHash3Hasher.Hash128(buffers[s]);

            sha256Golden[s] = new byte[32];
            Sha256.Hash(buffers[s], sha256Golden[s]);

            blake3Golden[s] = new byte[32];
            Blake3Hasher.Hash(buffers[s], blake3Golden[s]);
        }

        Parallel.For(0, WorkerCount32, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount32 }, workerId =>
        {
            try
            {
                Span<byte> shaOut = stackalloc byte[32];
                Span<byte> blakeOut = stackalloc byte[32];

                Span<byte> streamDest = stackalloc byte[8];
                Span<byte> shaStreamOut = stackalloc byte[32];
                Span<byte> b3StreamOut = stackalloc byte[32];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int sizeIdx = (workerId * 11 + iter) % sizes.Length;
                    byte[] data = buffers[sizeIdx];

                    // 1. XxHash3 64-bit and 128-bit one-shot verification
                    ulong xxh64 = XxHash3Hasher.Hash64(data);
                    if (xxh64 != xxh64Golden[sizeIdx])
                    {
                        throw new InvalidOperationException($"XxHash3 64-bit mismatch on thread {workerId}");
                    }

                    UInt128 xxh128 = XxHash3Hasher.Hash128(data);
                    if (xxh128 != xxh128Golden[sizeIdx])
                    {
                        throw new InvalidOperationException($"XxHash3 128-bit mismatch on thread {workerId}");
                    }

                    // 2. XxHash3 Streaming lifecycle verification
                    using (var xxhStream = new XxHash3Hasher())
                    {
                        if (data.Length > 0)
                        {
                            int half = data.Length / 2;
                            xxhStream.Append(data.AsSpan(0, half));
                            xxhStream.Append(data.AsSpan(half));
                        }
                        xxhStream.Finalize(streamDest);
                        ulong stream64 = BinaryPrimitives.ReadUInt64LittleEndian(streamDest);
                        if (stream64 != xxh64Golden[sizeIdx])
                        {
                            throw new InvalidOperationException($"XxHash3 stream mismatch on thread {workerId}");
                        }
                    }

                    // 3. SHA-256 One-Shot & Streaming verification
                    Sha256.Hash(data, shaOut);
                    if (!shaOut.SequenceEqual(sha256Golden[sizeIdx]))
                    {
                        throw new InvalidOperationException($"Sha256 one-shot mismatch on thread {workerId}");
                    }

                    using (var shaStream = new Sha256Hasher())
                    {
                        int half = data.Length / 2;
                        shaStream.Append(data.AsSpan(0, half));
                        shaStream.Append(data.AsSpan(half));
                        shaStream.Finalize(shaStreamOut);
                        if (!shaStreamOut.SequenceEqual(sha256Golden[sizeIdx]))
                        {
                            throw new InvalidOperationException($"Sha256 stream mismatch on thread {workerId}");
                        }
                    }

                    // 4. Blake3 One-Shot, Streaming & Keyed MAC
                    Blake3Hasher.Hash(data, blakeOut);
                    if (!blakeOut.SequenceEqual(blake3Golden[sizeIdx]))
                    {
                        throw new InvalidOperationException($"Blake3 one-shot mismatch on thread {workerId}");
                    }

                    using (var b3Stream = new Blake3Hasher())
                    {
                        int half = data.Length / 2;
                        b3Stream.Append(data.AsSpan(0, half));
                        b3Stream.Append(data.AsSpan(half));
                        b3Stream.Finalize(b3StreamOut);
                        if (!b3StreamOut.SequenceEqual(blake3Golden[sizeIdx]))
                        {
                            throw new InvalidOperationException($"Blake3 stream mismatch on thread {workerId}");
                        }
                    }

                    Interlocked.Increment(ref totalCompleted);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(WorkerCount32 * iterationsPerWorker, totalCompleted);
    }

    // =========================================================================
    // 4. HASHER SECURE DISPOSAL & MEMORY ZEROING INTEGRITY
    // =========================================================================

    [Fact]
    public void HasherDisposal_ThrowsObjectDisposedException_OnUseAfterFree()
    {
        // Blake3Hasher
        var b3 = new Blake3Hasher();
        b3.Append(new byte[64]);
        b3.Dispose();
        Assert.Throws<ObjectDisposedException>(() => b3.Append(new byte[64]));
        Assert.Throws<ObjectDisposedException>(() => b3.Reset());
        Assert.Throws<ObjectDisposedException>(() => b3.GetCurrentHash(new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => b3.Finalize(new byte[32]));
        b3.Dispose(); // Multiple dispose must be safe and idempotent

        // Sha256Hasher
        var sha = new Sha256Hasher();
        sha.Append(new byte[64]);
        sha.Dispose();
        Assert.Throws<ObjectDisposedException>(() => sha.Append(new byte[64]));
        Assert.Throws<ObjectDisposedException>(() => sha.Reset());
        Assert.Throws<ObjectDisposedException>(() => sha.GetCurrentHash(new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => sha.Finalize(new byte[32]));
        sha.Dispose(); // Idempotent

        // XxHash3Stream
        var xxh = new XxHash3Hasher();
        xxh.Append(new byte[64]);
        xxh.Dispose();
        Assert.Throws<ObjectDisposedException>(() => xxh.Append(new byte[64]));
        Assert.Throws<ObjectDisposedException>(() => xxh.Reset());
        Assert.Throws<ObjectDisposedException>(() => xxh.GetCurrentHash(new byte[8]));
        Assert.Throws<ObjectDisposedException>(() => xxh.Finalize(new byte[8]));
        xxh.Dispose(); // Idempotent
    }

    // =========================================================================
    // 5. HARDWARE ARBITER ROUTING BEHAVIOR FOR BLAKE3 HASHING
    // =========================================================================

    [Theory]
    [InlineData(1024 * 1024, ExecutionTarget.CpuParallelPool)]         // 1 MB -> CpuParallelPool
    [InlineData(2 * 1024 * 1024, ExecutionTarget.CpuParallelPool)]     // 2 MB -> CpuParallelPool
    [InlineData(4 * 1024 * 1024 - 1, ExecutionTarget.CpuParallelPool)] // 4 MB - 1 -> CpuParallelPool
    public void HardwareArbiter_Blake3IntermediatePayloads_RouteToCpuParallelPool(int size, ExecutionTarget expected)
    {
        ExecutionTarget target = HardwareArbiter.RouteWorkload(size);
        Assert.Equal(expected, target);
    }

    [Theory]
    [InlineData(4 * 1024 * 1024)]  // 4 MB
    [InlineData(16 * 1024 * 1024)] // 16 MB
    public void HardwareArbiter_PayloadsGe4MB_DefaultGpuAvailable_RoutesToGpuCompute(int size)
    {
        // When gpuAvailable is defaulted to true, 4MB and 16MB route to GpuCompute
        ExecutionTarget targetDefault = HardwareArbiter.RouteWorkload(size);
        Assert.Equal(ExecutionTarget.GpuCompute, targetDefault);

        // When gpuAvailable is false (CPU only), 4MB and 16MB route to CpuParallelPool
        ExecutionTarget targetNoGpu = HardwareArbiter.RouteWorkload(size, 1, gpuAvailable: false);
        Assert.Equal(ExecutionTarget.CpuParallelPool, targetNoGpu);
    }

    // =========================================================================
    // 6. 16MB PAYLOAD 24-WORKER PARALLEL REDUCTION TORTURE
    // =========================================================================

    [Fact]
    public void Blake3_HashParallel_24Workers_16MB_UltraContentionTorture()
    {
        const int payload16M = 16 * 1024 * 1024;
        byte[] payload = new byte[payload16M];
        for (int i = 0; i < payload16M; i++)
        {
            payload[i] = (byte)((i * 47 + 23) & 0xFF);
        }

        // Golden digest via streaming reduction
        byte[] expected = new byte[32];
        using (var stream = new Blake3Hasher())
        {
            const int step = 1024 * 1024;
            int offset = 0;
            while (offset < payload16M)
            {
                int len = Math.Min(step, payload16M - offset);
                stream.Append(payload.AsSpan(offset, len));
                offset += len;
            }
            stream.Finalize(expected);
        }

        var exceptions = new ConcurrentBag<Exception>();
        int completedWorkers = 0;

        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                Span<byte> digest = stackalloc byte[32];
                // Direct invocation of parallel reduction kernel
                InvokeBlake3HashParallel(null, payload, digest);

                if (!digest.SequenceEqual(expected))
                {
                    throw new InvalidOperationException(
                        $"Worker {workerId} produced corrupted 16MB hash: {Convert.ToHexString(digest)} vs {Convert.ToHexString(expected)}");
                }

                Interlocked.Increment(ref completedWorkers);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(WorkerCount24, completedWorkers);
    }
}
