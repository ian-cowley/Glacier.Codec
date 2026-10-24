namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;
using Xunit;

/// <summary>
/// Empirical Adversarial Challenge Test Suite for Milestone M2 (High-Throughput Hashing & Digest Engine).
/// Authored by Empirical Challenger 2.
/// 
/// Stress-tests:
/// 1. Concurrency & Thread-Safety Torture under 24 to 32 parallel threads for XxHash3, Sha256, and Blake3Hasher.
/// 2. Zero Heap Allocation verification in steady-state one-shot hashing via GC.GetAllocatedBytesForCurrentThread().
/// 3. Key Material Erasure / ZeroMemory upon Dispose() for keyed hashers (Blake3Hasher and XxHash3Stream).
/// 4. Boundary robustness, state bleed immunity, and double-disposal idempotency.
/// </summary>
public unsafe class Challenger2M2HashingTortureTests
{
    private const int WorkerCount24 = 24;
    private const int WorkerCount32 = 32;

    // =========================================================================
    // SECTION 1: CONCURRENCY & THREAD-SAFETY TORTURE (24+ PARALLEL WORKERS)
    // =========================================================================

    /// <summary>
    /// EMPIRICAL TORTURE 1A: 24+ concurrent workers executing XxHash3.Hash64 and XxHash3.Hash128
    /// simultaneously across varying buffer lengths (0B to 8192B) and varying seeds.
    /// Asserts 100% deterministic outputs, zero state bleed, and zero race conditions under thread contention.
    /// </summary>
    [Fact]
    public void ConcurrencyTorture_24Workers_XxHash3_Hash64And128_ZeroRaceConditions()
    {
        const int iterationsPerWorker = 1000;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        int[] testLengths = [0, 1, 3, 4, 8, 9, 16, 17, 32, 64, 128, 240, 241, 512, 1024, 2048, 8192];
        ulong[] testSeeds = [0, 1, 1234567UL, 0x9E3779B97F4A7C15UL, 0xFFFFFFFFFFFFFFFFUL];

        // Precompute expected golden values single-threaded to verify determinism
        var expected64 = new ulong[testLengths.Length, testSeeds.Length];
        var expected128 = new UInt128[testLengths.Length, testSeeds.Length];
        byte[][] buffers = new byte[testLengths.Length][];

        for (int l = 0; l < testLengths.Length; l++)
        {
            buffers[l] = new byte[testLengths[l]];
            for (int b = 0; b < testLengths[l]; b++)
            {
                buffers[l][b] = (byte)((b * 37 + l * 19 + 7) & 0xFF);
            }

            for (int s = 0; s < testSeeds.Length; s++)
            {
                expected64[l, s] = XxHash3.Hash64(buffers[l], testSeeds[s]);
                expected128[l, s] = XxHash3.Hash128(buffers[l], testSeeds[s]);
            }
        }

        // Parallel torture across 24 concurrent workers
        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                Span<byte> dest8 = stackalloc byte[8];
                Span<byte> dest16 = stackalloc byte[16];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int lIdx = (workerId * 7 + iter) % testLengths.Length;
                    int sIdx = (workerId * 13 + iter) % testSeeds.Length;

                    byte[] input = buffers[lIdx];
                    ulong seed = testSeeds[sIdx];

                    // 1. Verify 64-bit hash under contention
                    ulong actual64 = XxHash3.Hash64(input, seed);
                    if (actual64 != expected64[lIdx, sIdx])
                    {
                        throw new InvalidOperationException(
                            $"[XxHash3.Hash64 RACE] Worker {workerId} iter {iter} len {input.Length} seed {seed}: " +
                            $"expected 0x{expected64[lIdx, sIdx]:X16}, got 0x{actual64:X16}");
                    }

                    // 2. Verify 128-bit hash under contention
                    UInt128 actual128 = XxHash3.Hash128(input, seed);
                    if (actual128 != expected128[lIdx, sIdx])
                    {
                        throw new InvalidOperationException(
                            $"[XxHash3.Hash128 RACE] Worker {workerId} iter {iter} len {input.Length} seed {seed}: " +
                            $"expected {expected128[lIdx, sIdx]}, got {actual128}");
                    }

                    // 3. Verify span-writing facade overload
                    XxHash3Hasher.Hash64(input, dest8, seed);
                    ulong written64 = BinaryPrimitives.ReadUInt64LittleEndian(dest8);
                    if (written64 != expected64[lIdx, sIdx])
                    {
                        throw new InvalidOperationException($"[XxHash3Hasher.Hash64 Facade RACE] Worker {workerId}");
                    }

                    XxHash3Hasher.Hash128(input, dest16, seed);
                    ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(dest16);
                    ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(dest16.Slice(8));
                    UInt128 written128 = new UInt128(hi, lo);
                    if (written128 != expected128[lIdx, sIdx])
                    {
                        throw new InvalidOperationException($"[XxHash3Hasher.Hash128 Facade RACE] Worker {workerId}");
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
        Assert.Equal(WorkerCount24 * iterationsPerWorker, totalCompleted);
    }

    /// <summary>
    /// EMPIRICAL TORTURE 1B: 24+ concurrent workers executing Sha256.Hash and Sha256.VerifyHash
    /// across varying buffer sizes (0B, 3B, 56B, 64B, 112B, 1024B, 8192B) simultaneously.
    /// Asserts SHA-NI / hardware acceleration thread-safety and zero digest corruption.
    /// </summary>
    [Fact]
    public void ConcurrencyTorture_24Workers_Sha256_ZeroDigestCorruption()
    {
        const int iterationsPerWorker = 800;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        int[] lengths = [0, 3, 56, 64, 112, 256, 1024, 4096, 8192];
        byte[][] buffers = new byte[lengths.Length][];
        byte[][] expectedDigests = new byte[lengths.Length][];

        for (int i = 0; i < lengths.Length; i++)
        {
            buffers[i] = new byte[lengths[i]];
            for (int b = 0; b < lengths[i]; b++)
            {
                buffers[i][b] = (byte)((b * 41 + i * 17 + 3) & 0xFF);
            }
            expectedDigests[i] = System.Security.Cryptography.SHA256.HashData(buffers[i]);
        }

        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                Span<byte> digest = stackalloc byte[32];
                Span<byte> tryDigest = stackalloc byte[32];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int idx = (workerId * 5 + iter) % lengths.Length;
                    byte[] input = buffers[idx];
                    byte[] expected = expectedDigests[idx];

                    // 1. One-shot Hash
                    Sha256.Hash(input, digest);
                    if (!digest.SequenceEqual(expected))
                    {
                        throw new InvalidOperationException(
                            $"[Sha256.Hash RACE] Worker {workerId} iter {iter} len {input.Length} digest mismatch!");
                    }

                    // 2. TryHash
                    if (!Sha256.TryHash(input, tryDigest, out int written) || written != 32 || !tryDigest.SequenceEqual(expected))
                    {
                        throw new InvalidOperationException($"[Sha256.TryHash RACE] Worker {workerId} iter {iter}");
                    }

                    // 3. VerifyHash constant-time check
                    if (!Sha256.VerifyHash(input, expected))
                    {
                        throw new InvalidOperationException($"[Sha256.VerifyHash RACE] Worker {workerId} iter {iter}");
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
        Assert.Equal(WorkerCount24 * iterationsPerWorker, totalCompleted);
    }

    /// <summary>
    /// EMPIRICAL TORTURE 1C: 24+ concurrent workers creating and running independent Blake3Hasher instances
    /// in both standard, keyed MAC, and KDF modes with irregular chunk appends and root tree reduction.
    /// Asserts Merkle tree state machine thread-safety, zero state bleed, and deterministic multi-chunk hashing.
    /// </summary>
    [Fact]
    public void ConcurrencyTorture_24Workers_Blake3Hasher_IndependentStateIntegrity()
    {
        const int iterationsPerWorker = 300;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        int[] lengths = [0, 1, 64, 65, 1024, 2048, 4096, 7000];
        byte[][] payloads = new byte[lengths.Length][];
        byte[][] expectedStandard = new byte[lengths.Length][];
        byte[][] expectedKeyed = new byte[lengths.Length][];

        byte[] masterKey = new byte[32];
        for (int i = 0; i < 32; i++) masterKey[i] = (byte)(i * 7 + 11);

        for (int i = 0; i < lengths.Length; i++)
        {
            payloads[i] = new byte[lengths[i]];
            for (int b = 0; b < lengths[i]; b++)
            {
                payloads[i][b] = (byte)((b * 53 + i * 29) & 0xFF);
            }

            expectedStandard[i] = new byte[32];
            Blake3Hasher.Hash(payloads[i], expectedStandard[i]);

            expectedKeyed[i] = new byte[32];
            Blake3Hasher.HashKeyed(payloads[i], masterKey, expectedKeyed[i]);
        }

        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                Span<byte> actualDigest = stackalloc byte[32];
                Span<byte> streamDigest = stackalloc byte[32];
                Span<byte> keyedDigest = stackalloc byte[32];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int pIdx = (workerId * 3 + iter) % lengths.Length;
                    byte[] payload = payloads[pIdx];

                    // 1. One-shot standard hashing
                    Blake3Hasher.Hash(payload, actualDigest);
                    if (!actualDigest.SequenceEqual(expectedStandard[pIdx]))
                    {
                        throw new InvalidOperationException($"[Blake3 OneShot Standard RACE] Worker {workerId} len {payload.Length}");
                    }

                    // 2. Incremental streaming with irregular chunk slices
                    using (var streamHasher = new Blake3Hasher())
                    {
                        int offset = 0;
                        int sliceSize = (workerId % 7) * 50 + 23; // Variable slice per worker
                        while (offset < payload.Length)
                        {
                            int take = Math.Min(sliceSize, payload.Length - offset);
                            streamHasher.Append(payload.AsSpan(offset, take));
                            offset += take;
                        }

                        streamHasher.Finalize(streamDigest);

                        if (!streamDigest.SequenceEqual(expectedStandard[pIdx]))
                        {
                            throw new InvalidOperationException($"[Blake3 Streaming Standard RACE] Worker {workerId} len {payload.Length}");
                        }
                    }

                    // 3. One-shot keyed MAC hashing
                    Blake3Hasher.HashKeyed(payload, masterKey, actualDigest);
                    if (!actualDigest.SequenceEqual(expectedKeyed[pIdx]))
                    {
                        throw new InvalidOperationException($"[Blake3 OneShot Keyed RACE] Worker {workerId} len {payload.Length}");
                    }

                    // 4. Keyed streaming hasher with SetKey
                    using (var keyedHasher = new Blake3Hasher())
                    {
                        keyedHasher.SetKey(masterKey);
                        keyedHasher.Append(payload);
                        keyedHasher.Finalize(keyedDigest);

                        if (!keyedDigest.SequenceEqual(expectedKeyed[pIdx]))
                        {
                            throw new InvalidOperationException($"[Blake3 Streaming Keyed RACE] Worker {workerId} len {payload.Length}");
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
        Assert.Equal(WorkerCount24 * iterationsPerWorker, totalCompleted);
    }

    /// <summary>
    /// EMPIRICAL TORTURE 1D: Mixed concurrent storm across 32 parallel threads simultaneously executing
    /// XxHash3.Hash64, XxHash3.Hash128, Sha256.Hash, Blake3Hasher.Hash, and XxHash3Stream.Append.
    /// Asserts zero memory corruption, zero race conditions, and complete determinism across all algorithms.
    /// </summary>
    [Fact]
    public void ConcurrencyTorture_32Workers_MixedHashStorm_ZeroContentionFailures()
    {
        const int iterationsPerWorker = 300;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        byte[] sharedInput = new byte[2048];
        for (int i = 0; i < sharedInput.Length; i++) sharedInput[i] = (byte)(i ^ 0x5C);

        ulong expectedXxh64 = XxHash3.Hash64(sharedInput);
        UInt128 expectedXxh128 = XxHash3.Hash128(sharedInput);

        byte[] expectedSha = new byte[32];
        Sha256.Hash(sharedInput, expectedSha);

        byte[] expectedBlake = new byte[32];
        Blake3Hasher.Hash(sharedInput, expectedBlake);

        Parallel.For(0, WorkerCount32, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount32 }, workerId =>
        {
            try
            {
                Span<byte> shaDigest = stackalloc byte[32];
                Span<byte> b3Digest = stackalloc byte[32];
                Span<byte> out64 = stackalloc byte[8];

                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int mode = (workerId + iter) % 5;
                    switch (mode)
                    {
                        case 0:
                            ulong h64 = XxHash3.Hash64(sharedInput);
                            Assert.Equal(expectedXxh64, h64);
                            break;
                        case 1:
                            UInt128 h128 = XxHash3.Hash128(sharedInput);
                            Assert.Equal(expectedXxh128, h128);
                            break;
                        case 2:
                            Sha256.Hash(sharedInput, shaDigest);
                            Assert.True(shaDigest.SequenceEqual(expectedSha));
                            break;
                        case 3:
                            Blake3Hasher.Hash(sharedInput, b3Digest);
                            Assert.True(b3Digest.SequenceEqual(expectedBlake));
                            break;
                        case 4:
                            using (var xxhStream = new XxHash3Stream(8, 0))
                            {
                                xxhStream.Append(sharedInput.AsSpan(0, 512));
                                xxhStream.Append(sharedInput.AsSpan(512, 1536));
                                xxhStream.Finalize(out64);
                                ulong s64 = BinaryPrimitives.ReadUInt64LittleEndian(out64);
                                Assert.Equal(expectedXxh64, s64);
                            }
                            break;
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
    // SECTION 2: ZERO HEAP ALLOCATION VERIFICATION
    // =========================================================================

    /// <summary>
    /// EMPIRICAL PROOF 2A: ZERO HEAP ALLOCATIONS IN XxHash3.Hash64 (STEADY-STATE).
    /// Asserts GC.GetAllocatedBytesForCurrentThread() delta is exactly 0 B across all size tiers:
    /// 0B, 4B, 16B, 64B, 128B, 240B, 241B, 1024B, 4096B with default seed and custom seed.
    /// </summary>
    [Theory]
    [InlineData(0, 0UL)]
    [InlineData(4, 0UL)]
    [InlineData(16, 0UL)]
    [InlineData(64, 0UL)]
    [InlineData(128, 0UL)]
    [InlineData(240, 0UL)]
    [InlineData(241, 0UL)]
    [InlineData(1024, 0UL)]
    [InlineData(4096, 0UL)]
    [InlineData(16, 1234567UL)]
    [InlineData(240, 1234567UL)]
    [InlineData(1024, 1234567UL)]
    [InlineData(4096, 1234567UL)]
    public void ZeroAllocations_XxHash3_Hash64_SteadyStateZeroBytesAllocated(int length, ulong seed)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);
        ReadOnlySpan<byte> span = buffer;

        // Warm up JIT to avoid one-time JIT compilation allocations
        for (int i = 0; i < 100; i++)
        {
            _ = XxHash3.Hash64(span, seed);
        }

        // Measure steady state allocation across 100 sequential operations
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            _ = XxHash3.Hash64(span, seed);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocated = after - before;
        Assert.Equal(0, allocated);
    }

    /// <summary>
    /// EMPIRICAL PROOF 2B: ZERO HEAP ALLOCATIONS IN XxHash3.Hash128 (STEADY-STATE).
    /// Asserts GC.GetAllocatedBytesForCurrentThread() delta is exactly 0 B across all size tiers.
    /// </summary>
    [Theory]
    [InlineData(0, 0UL)]
    [InlineData(16, 0UL)]
    [InlineData(64, 0UL)]
    [InlineData(240, 0UL)]
    [InlineData(241, 0UL)]
    [InlineData(1024, 0UL)]
    [InlineData(4096, 0UL)]
    [InlineData(64, 987654321UL)]
    [InlineData(1024, 987654321UL)]
    public void ZeroAllocations_XxHash3_Hash128_SteadyStateZeroBytesAllocated(int length, ulong seed)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);
        ReadOnlySpan<byte> span = buffer;

        // Warm up JIT
        for (int i = 0; i < 100; i++)
        {
            _ = XxHash3.Hash128(span, seed);
        }

        // Measure steady state allocation
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            _ = XxHash3.Hash128(span, seed);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocated = after - before;
        Assert.Equal(0, allocated);
    }

    /// <summary>
    /// EMPIRICAL PROOF 2C: ZERO HEAP ALLOCATIONS IN Sha256.Hash (STEADY-STATE).
    /// Asserts GC.GetAllocatedBytesForCurrentThread() delta is exactly 0 B across diverse message lengths.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(32)]
    [InlineData(56)]
    [InlineData(64)]
    [InlineData(112)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void ZeroAllocations_Sha256_Hash_SteadyStateZeroBytesAllocated(int length)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);
        ReadOnlySpan<byte> span = buffer;
        Span<byte> destination = stackalloc byte[32];

        // Warm up JIT
        for (int i = 0; i < 100; i++)
        {
            Sha256.Hash(span, destination);
        }

        // Steady-state measurement
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            Sha256.Hash(span, destination);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocated = after - before;
        Assert.Equal(0, allocated);
    }

    /// <summary>
    /// EMPIRICAL PROOF 2D: ZERO HEAP ALLOCATIONS IN XxHash3Hasher FACADE OVERLOADS.
    /// Asserts writing directly into Span&lt;byte&gt; performs zero heap allocations.
    /// </summary>
    [Fact]
    public void ZeroAllocations_XxHash3Hasher_SpanFacades_ZeroBytesAllocated()
    {
        byte[] buffer = new byte[512];
        Random.Shared.NextBytes(buffer);
        ReadOnlySpan<byte> span = buffer;
        Span<byte> dest8 = stackalloc byte[8];
        Span<byte> dest16 = stackalloc byte[16];

        for (int i = 0; i < 50; i++)
        {
            XxHash3Hasher.Hash64(span, dest8);
            XxHash3Hasher.Hash128(span, dest16);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            XxHash3Hasher.Hash64(span, dest8);
            XxHash3Hasher.Hash128(span, dest16);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, after - before);
    }

    // =========================================================================
    // SECTION 3: KEY MATERIAL ERASURE / ZEROMEMORY ON DISPOSAL
    // =========================================================================

    /// <summary>
    /// EMPIRICAL PROOF 3A: KEY MATERIAL ERASURE IN Blake3Hasher (KEYED MODE).
    /// In keyed mode, Blake3Hasher stores key material in _key and intermediate CV in _chunkCv.
    /// Inspects that before Dispose() these contain non-zero key bytes, and upon Dispose(),
    /// CryptographicOperations.ZeroMemory scrubs _key, _chunkCv, _blockBuffer, and _cvStack strictly to 0x00.
    /// </summary>
    [Fact]
    public void KeyErasure_Blake3Hasher_KeyedMode_ScrubsKeyMaterialOnDispose()
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < 32; i++) keyBytes[i] = (byte)(i + 1);

        var hasher = new Blake3Hasher(keyBytes);
        byte[] input = [0xAA, 0xBB, 0xCC, 0xDD];
        hasher.Append(input);

        // 1. Inspect _key field before disposal: must contain key material
        byte[] keyBefore = ExtractFixedBufferBytes(hasher, "_key");
        Assert.Equal(32, keyBefore.Length);
        Assert.True(keyBefore.AsSpan().SequenceEqual(keyBytes), "Key material must be present in _key prior to disposal.");

        // 2. Inspect _chunkCv before disposal: must contain non-zero initial CV
        byte[] cvBefore = ExtractFixedBufferBytes(hasher, "_chunkCv");
        Assert.Contains(cvBefore, b => b != 0);

        // 3. Trigger Dispose()
        hasher.Dispose();

        // 4. Assert _key is completely zeroed out
        byte[] keyAfter = ExtractFixedBufferBytes(hasher, "_key");
        Assert.Equal(32, keyAfter.Length);
        Assert.All(keyAfter, b => Assert.Equal(0, b));

        // 5. Assert _chunkCv is completely zeroed out
        byte[] cvAfter = ExtractFixedBufferBytes(hasher, "_chunkCv");
        Assert.Equal(32, cvAfter.Length);
        Assert.All(cvAfter, b => Assert.Equal(0, b));

        // 6. Assert _blockBuffer is completely zeroed out
        byte[] bufAfter = ExtractFixedBufferBytes(hasher, "_blockBuffer");
        Assert.Equal(64, bufAfter.Length);
        Assert.All(bufAfter, b => Assert.Equal(0, b));

        // 7. Assert _cvStack is completely zeroed out
        byte[] stackAfter = ExtractFixedBufferBytes(hasher, "_cvStack");
        Assert.Equal(Blake3Constants.MaxTreeDepth * 8 * 4, stackAfter.Length);
        Assert.All(stackAfter, b => Assert.Equal(0, b));

        // 8. Assert subsequent calls throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => hasher.Append(new byte[1]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Reset());
        Assert.Throws<ObjectDisposedException>(() => hasher.GetCurrentHash(new byte[32]));

        // 9. Assert double disposal is safe and idempotent
        hasher.Dispose();
    }

    /// <summary>
    /// EMPIRICAL PROOF 3B: KEY MATERIAL ERASURE IN XxHash3Stream (CUSTOM SECRET MODE).
    /// When configured with a custom secret, XxHash3Stream stores the secret in _secret (192 bytes)
    /// and accumulates state in _acc (64 bytes) and _buffer (256 bytes).
    /// Inspects that before Dispose() these contain non-zero secret material, and upon Dispose(),
    /// CryptographicOperations.ZeroMemory scrubs _secret, _acc, and _buffer strictly to 0x00.
    /// </summary>
    [Fact]
    public void KeyErasure_XxHash3Stream_CustomSecret_ScrubsSecretAndStateOnDispose()
    {
        var stream = new XxHash3Stream(8, 0);

        // Supply custom 192-byte high-entropy secret
        byte[] customSecret = new byte[XxHash3Constants.SecretLengthBytes];
        for (int i = 0; i < customSecret.Length; i++) customSecret[i] = (byte)((i * 3 + 17) & 0xFF);
        stream.SetKey(customSecret);

        byte[] input = new byte[300];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i + 1);
        stream.Append(input);

        // 1. Inspect _secret before disposal: must match customSecret
        byte[] secretBefore = ExtractFixedBufferBytes(stream, "_secret");
        Assert.Equal(XxHash3Constants.SecretLengthBytes, secretBefore.Length);
        Assert.True(secretBefore.AsSpan().SequenceEqual(customSecret), "Secret must be present before disposal.");

        // 2. Inspect _buffer and _acc before disposal: must contain active data
        byte[] bufBefore = ExtractFixedBufferBytes(stream, "_buffer");
        Assert.Contains(bufBefore, b => b != 0);

        byte[] accBefore = ExtractFixedBufferBytes(stream, "_acc");
        Assert.Contains(accBefore, b => b != 0);

        // 3. Trigger Dispose()
        stream.Dispose();

        // 4. Assert _secret is strictly zeroed out
        byte[] secretAfter = ExtractFixedBufferBytes(stream, "_secret");
        Assert.Equal(XxHash3Constants.SecretLengthBytes, secretAfter.Length);
        Assert.All(secretAfter, b => Assert.Equal(0, b));

        // 5. Assert _buffer is strictly zeroed out
        byte[] bufAfter = ExtractFixedBufferBytes(stream, "_buffer");
        Assert.Equal(XxHash3Constants.InternalBufferLengthBytes, bufAfter.Length);
        Assert.All(bufAfter, b => Assert.Equal(0, b));

        // 6. Assert _acc accumulators are strictly zeroed out
        byte[] accAfter = ExtractFixedBufferBytes(stream, "_acc");
        Assert.Equal(XxHash3Constants.AccumulatorCount * sizeof(ulong), accAfter.Length);
        Assert.All(accAfter, b => Assert.Equal(0, b));

        // 7. Subsequent operations must throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => stream.Append(new byte[10]));
        Assert.Throws<ObjectDisposedException>(() => stream.Reset());
        Assert.Throws<ObjectDisposedException>(() => stream.GetCurrentHash(new byte[8]));

        // 8. Double disposal is safe and idempotent
        stream.Dispose();
    }

    /// <summary>
    /// EMPIRICAL PROOF 3C: KEY MATERIAL ERASURE IN Sha256Hasher.
    /// Inspects that Sha256Hasher zeros out its intermediate 64-byte staging buffer and state registers on Dispose().
    /// </summary>
    [Fact]
    public void KeyErasure_Sha256Hasher_ScrubsStagingBufferAndStateOnDispose()
    {
        var hasher = new Sha256Hasher();
        byte[] partialBlock = new byte[37];
        Array.Fill(partialBlock, (byte)0xEE);
        hasher.Append(partialBlock);

        // Staging buffer before disposal contains 0xEE bytes
        byte[] bufBefore = ExtractFixedBufferBytes(hasher, "_buffer");
        Assert.Contains(bufBefore, b => b == 0xEE);

        hasher.Dispose();

        // Staging buffer after disposal must be 100% zeroed
        byte[] bufAfter = ExtractFixedBufferBytes(hasher, "_buffer");
        Assert.Equal(64, bufAfter.Length);
        Assert.All(bufAfter, b => Assert.Equal(0, b));

        // State after disposal must throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => hasher.Append(new byte[10]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Reset());
        Assert.Throws<ObjectDisposedException>(() => hasher.GetCurrentHash(new byte[32]));

        // Double dispose is safe
        hasher.Dispose();
    }

    // =========================================================================
    // SECTION 4: BOUNDARY AND CORRUPTION CHALLENGES
    // =========================================================================

    /// <summary>
    /// EMPIRICAL CHALLENGE 4A: XxHash3 destination span too small throws ArgumentException.
    /// </summary>
    [Fact]
    public void Boundary_XxHash3Hasher_DestinationTooSmall_ThrowsArgumentException()
    {
        byte[] input = new byte[10];
        byte[] tooSmall64 = new byte[7];
        byte[] tooSmall128 = new byte[15];

        Assert.Throws<ArgumentException>(() => XxHash3Hasher.Hash64(input, tooSmall64));
        Assert.Throws<ArgumentException>(() => XxHash3Hasher.Hash128(input, tooSmall128));
    }

    /// <summary>
    /// EMPIRICAL CHALLENGE 4B: Sha256 destination span too small throws ArgumentException.
    /// </summary>
    [Fact]
    public void Boundary_Sha256_DestinationTooSmall_ThrowsArgumentException()
    {
        byte[] input = new byte[10];
        byte[] tooSmall = new byte[31];
        Assert.Throws<ArgumentException>(() => Sha256.Hash(input, tooSmall));
    }

    /// <summary>
    /// EMPIRICAL CHALLENGE 4C: Blake3Hasher destination span too small throws ArgumentException.
    /// </summary>
    [Fact]
    public void Boundary_Blake3Hasher_DestinationTooSmall_ThrowsArgumentException()
    {
        byte[] input = new byte[10];
        byte[] key = new byte[32];
        byte[] tooSmall = new byte[31];
        Assert.Throws<ArgumentException>(() => Blake3Hasher.Hash(input, tooSmall));
        Assert.Throws<ArgumentException>(() => Blake3Hasher.HashKeyed(input, key, tooSmall));
    }

    // =========================================================================
    // HELPER: REFLECTION FIXED BUFFER MEMORY EXTRACTOR
    // =========================================================================

    private static byte[] ExtractFixedBufferBytes(object target, string fieldName)
    {
        FieldInfo field = target.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Field '{fieldName}' not found on type '{target.GetType().Name}'.");

        object structBox = field.GetValue(target)
            ?? throw new InvalidOperationException($"Field '{fieldName}' returned null.");

        FieldInfo dataField = structBox.GetType().GetField("Data")
            ?? throw new InvalidOperationException($"Fixed buffer field 'Data' not found on struct '{structBox.GetType().Name}'.");

        object dataBox = dataField.GetValue(structBox)
            ?? throw new InvalidOperationException("Fixed buffer value returned null.");

        int size = Marshal.SizeOf(dataBox.GetType());
        byte[] buffer = new byte[size];
        IntPtr hGlobal = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(dataBox, hGlobal, false);
            Marshal.Copy(hGlobal, buffer, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(hGlobal);
        }

        return buffer;
    }
}
