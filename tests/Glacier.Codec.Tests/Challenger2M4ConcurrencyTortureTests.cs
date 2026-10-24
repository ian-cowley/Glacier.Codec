namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Cryptography.PostQuantum;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Concurrency Torture, Memory Allocation, and Stress Testing Suite for Milestone M4.
/// Authored by Empirical Challenger 2 (challenger_m4_2).
///
/// Rigorously validates:
/// 1. Massive Concurrency Stress: 32 concurrent threads executing Argon2id and ML-KEM (768 & 1024).
/// 2. Large Memory Configuration Stress: Sustained Argon2id execution with m=64MB (65536 KB), p=4 lanes,
///    verifying slab leasing, unmanaged buffer recycling, and zero memory leaks.
/// 3. Strict Zero-Allocation Verification: Steady-state execution allocates exactly 0 bytes on hot paths.
/// 4. Boundary & High-Parallelism Edge Cases: Extreme lane counts and minimal valid memory constraints.
/// </summary>
public class Challenger2M4ConcurrencyTortureTests
{
    private const int ThreadCount32 = 32;

    // =========================================================================
    // SECTION 1: MASSIVE CONCURRENCY TORTURE (32 CONCURRENT THREADS)
    // =========================================================================

    [Fact]
    public void Concurrency_32Threads_Argon2id_DistinctInputs_NoMemoryCorruptionOrRaces()
    {
        // 32 concurrent threads each derive keys with unique pwdBytes and salts
        const int iterationsPerThread = 6;
        var exceptions = new ConcurrentBag<Exception>();

        // Pre-compute golden references sequentially to verify that concurrent execution
        // suffers zero buffer collisions, race conditions, or memory corruption.
        byte[][] goldenTags = new byte[ThreadCount32][];
        for (int t = 0; t < ThreadCount32; t++)
        {
            byte[] pwdBytes = new byte[32];
            byte[] saltBytes = new byte[16];
            for (int i = 0; i < 32; i++) pwdBytes[i] = (byte)((t * 13 + i * 7) & 0xFF);
            for (int i = 0; i < 16; i++) saltBytes[i] = (byte)((t * 29 + i * 11) & 0xFF);

            goldenTags[t] = new byte[32];
            using var kdf = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 2);
            kdf.DeriveKey(pwdBytes, saltBytes, goldenTags[t]);
        }

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                byte[] pwdBytes = new byte[32];
                byte[] saltBytes = new byte[16];
                for (int i = 0; i < 32; i++) pwdBytes[i] = (byte)((threadId * 13 + i * 7) & 0xFF);
                for (int i = 0; i < 16; i++) saltBytes[i] = (byte)((threadId * 29 + i * 11) & 0xFF);

                Span<byte> tag = stackalloc byte[32];
                using var threadKdf = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 2);

                for (int iter = 0; iter < iterationsPerThread; iter++)
                {
                    tag.Clear();
                    threadKdf.DeriveKey(pwdBytes, saltBytes, tag);

                    if (!tag.SequenceEqual(goldenTags[threadId]))
                    {
                        throw new InvalidOperationException(
                            $"Thread {threadId} iteration {iter} produced corrupted tag! " +
                            $"Expected: {Convert.ToHexString(goldenTags[threadId])}, " +
                            $"Actual: {Convert.ToHexString(tag)}");
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_Argon2id_SharedInstance_SameInputs_AllMatch()
    {
        // 32 concurrent threads executing against a single shared Argon2id instance
        using var sharedKdf = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 4);

        byte[] pwdBytes = new byte[32];
        byte[] saltBytes = new byte[16];
        pwdBytes.AsSpan().Fill(0x5A);
        saltBytes.AsSpan().Fill(0xA5);

        byte[] referenceTag = new byte[32];
        sharedKdf.DeriveKey(pwdBytes, saltBytes, referenceTag);

        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                Span<byte> localTag = stackalloc byte[32];
                for (int i = 0; i < 8; i++)
                {
                    localTag.Clear();
                    sharedKdf.DeriveKey(pwdBytes, saltBytes, localTag);

                    if (!localTag.SequenceEqual(referenceTag))
                    {
                        throw new InvalidOperationException(
                            $"Shared instance thread {threadId} run {i} produced tag mismatch!");
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_MlKem768_MassiveKeyGenEncapsDecaps_AllSucceed()
    {
        var kem = MlKemEngine.MlKem768;
        const int roundsPerThread = 8;
        var exceptions = new ConcurrentBag<Exception>();
        int totalSuccessfulCycles = 0;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                byte[] pk = new byte[kem.PublicKeySizeInBytes];
                byte[] sk = new byte[kem.SecretKeySizeInBytes];
                byte[] ct = new byte[kem.CiphertextSizeInBytes];
                byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
                byte[] ssB = new byte[kem.SharedSecretSizeInBytes];

                for (int r = 0; r < roundsPerThread; r++)
                {
                    kem.GenerateKeyPair(pk, sk);
                    kem.Encapsulate(pk, ct, ssA);

                    bool decapsOk = kem.Decapsulate(sk, ct, ssB);
                    if (!decapsOk)
                    {
                        throw new InvalidOperationException($"Thread {threadId} round {r}: Decapsulate returned false!");
                    }

                    if (!ssA.AsSpan().SequenceEqual(ssB))
                    {
                        throw new InvalidOperationException(
                            $"Thread {threadId} round {r}: Shared secret mismatch! " +
                            $"ssA={Convert.ToHexString(ssA)}, ssB={Convert.ToHexString(ssB)}");
                    }

                    Interlocked.Increment(ref totalSuccessfulCycles);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ThreadCount32 * roundsPerThread, totalSuccessfulCycles);
    }

    [Fact]
    public void Concurrency_32Threads_MlKem1024_MassiveKeyGenEncapsDecaps_AllSucceed()
    {
        var kem = MlKemEngine.MlKem1024;
        const int roundsPerThread = 8;
        var exceptions = new ConcurrentBag<Exception>();
        int totalSuccessfulCycles = 0;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                byte[] pk = new byte[kem.PublicKeySizeInBytes];
                byte[] sk = new byte[kem.SecretKeySizeInBytes];
                byte[] ct = new byte[kem.CiphertextSizeInBytes];
                byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
                byte[] ssB = new byte[kem.SharedSecretSizeInBytes];

                for (int r = 0; r < roundsPerThread; r++)
                {
                    kem.GenerateKeyPair(pk, sk);
                    kem.Encapsulate(pk, ct, ssA);

                    bool decapsOk = kem.Decapsulate(sk, ct, ssB);
                    if (!decapsOk)
                    {
                        throw new InvalidOperationException($"Thread {threadId} round {r}: Decapsulate returned false!");
                    }

                    if (!ssA.AsSpan().SequenceEqual(ssB))
                    {
                        throw new InvalidOperationException(
                            $"Thread {threadId} round {r}: Shared secret mismatch! " +
                            $"ssA={Convert.ToHexString(ssA)}, ssB={Convert.ToHexString(ssB)}");
                    }

                    Interlocked.Increment(ref totalSuccessfulCycles);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ThreadCount32 * roundsPerThread, totalSuccessfulCycles);
    }

    [Fact]
    public void Concurrency_32Threads_Interleaved_MlKem768_And_MlKem1024_WithRejection()
    {
        // 32 threads interleaving ML-KEM-768 and ML-KEM-1024 with legitimate and tampered decapsulations
        var exceptions = new ConcurrentBag<Exception>();
        int rejectionCount = 0;
        int acceptanceCount = 0;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                bool use768 = (threadId % 2 == 0);
                MlKemEngine kem = use768 ? MlKemEngine.MlKem768 : MlKemEngine.MlKem1024;

                byte[] pk = new byte[kem.PublicKeySizeInBytes];
                byte[] sk = new byte[kem.SecretKeySizeInBytes];
                byte[] ct = new byte[kem.CiphertextSizeInBytes];
                byte[] ssA = new byte[32];
                byte[] ssB = new byte[32];

                for (int i = 0; i < 6; i++)
                {
                    kem.GenerateKeyPair(pk, sk);
                    kem.Encapsulate(pk, ct, ssA);

                    if (i % 2 == 0)
                    {
                        // Normal roundtrip
                        bool ok = kem.Decapsulate(sk, ct, ssB);
                        if (!ok || !ssA.AsSpan().SequenceEqual(ssB))
                        {
                            throw new InvalidOperationException($"Acceptance failure in thread {threadId}");
                        }
                        Interlocked.Increment(ref acceptanceCount);
                    }
                    else
                    {
                        // Tampered round: flip a bit in ciphertext
                        ct[i % ct.Length] ^= 0x80;
                        bool ok = kem.Decapsulate(sk, ct, ssB);
                        if (ok)
                        {
                            throw new InvalidOperationException($"Tampered ciphertext was unexpectedly accepted in thread {threadId}!");
                        }
                        if (ssA.AsSpan().SequenceEqual(ssB))
                        {
                            throw new InvalidOperationException($"Implicit rejection produced real key in thread {threadId}!");
                        }
                        Interlocked.Increment(ref rejectionCount);
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ThreadCount32 * 3, acceptanceCount);
        Assert.Equal(ThreadCount32 * 3, rejectionCount);
    }

    // =========================================================================
    // SECTION 2: LARGE MEMORY CONFIGURATION STRESS (64MB, p=4) & SLAB RECYCLING
    // =========================================================================

    [Fact]
    public void LargeMemoryStress_Argon2id_64MB_p4_SustainedExecution_Deterministic()
    {
        // RFC 9106 recommended memory size: m = 64 MB (65536 KiB) with p = 4 lanes, t = 1
        const int mem64Mb = 65536;
        const int lanes = 4;
        const int passes = 1;

        byte[] pwdBytes = new byte[32];
        byte[] saltBytes = new byte[16];
        pwdBytes.AsSpan().Fill(0x42);
        saltBytes.AsSpan().Fill(0x24);

        using var argon64 = new Argon2id(iterations: passes, memoryKb: mem64Mb, parallelism: lanes);

        byte[] tagRun1 = new byte[32];
        byte[] tagRun2 = new byte[32];
        byte[] tagRun3 = new byte[32];

        // Sustained execution: verify that 64MB buffer can be rented, computed, and recycled repeatedly
        argon64.DeriveKey(pwdBytes, saltBytes, tagRun1);
        argon64.DeriveKey(pwdBytes, saltBytes, tagRun2);
        argon64.DeriveKey(pwdBytes, saltBytes, tagRun3);

        // Verify bit-exact determinism across all runs
        Assert.True(tagRun1.AsSpan().SequenceEqual(tagRun2), "Run 1 and Run 2 produced different tags!");
        Assert.True(tagRun2.AsSpan().SequenceEqual(tagRun3), "Run 2 and Run 3 produced different tags!");
        Assert.False(tagRun1.AsSpan().SequenceEqual(new byte[32]), "Derived key is all zeroes!");
    }

    [Fact]
    public void LargeMemoryStress_Argon2id_64MB_MemoryRecycling_ZeroLeaks()
    {
        const int mem64Mb = 65536;
        using var argon = new Argon2id(iterations: 1, memoryKb: mem64Mb, parallelism: 4);

        byte[] pwdBytes = new byte[32];
        byte[] saltBytes = new byte[16];
        Span<byte> tag = stackalloc byte[32];

        // Warm up and trigger initial allocations
        argon.DeriveKey(pwdBytes, saltBytes, tag);

        // Execute multiple 64MB passes: verify 64MB matrix is strictly unmanaged (at most 48-byte wrapper)
        for (int i = 0; i < 3; i++)
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            argon.DeriveKey(pwdBytes, saltBytes, tag);
            long after = GC.GetAllocatedBytesForCurrentThread();

            long allocated = after - before;
            Assert.True(allocated <= 48, $"Allocated {allocated} bytes on managed heap; 64MB matrix must be unmanaged!");
        }

        // Verify unmanaged 64MB slab leasing and disposal cycle
        using (SlabLease lease = UnmanagedSlabPool.Shared.Rent(mem64Mb * 1024))
        {
            Assert.True(lease.Length >= mem64Mb * 1024);
            lease.Span[0] = 0xAA;
            lease.Span[mem64Mb * 1024 - 1] = 0xBB;
        }
    }

    [Fact]
    public unsafe void SlabPool_StressLeasingAndRecycling_UnderConcurrency()
    {
        // Stress test the underlying UnmanagedSlabPool directly across 32 threads
        var pool = UnmanagedSlabPool.Shared;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                for (int iter = 0; iter < 50; iter++)
                {
                    // Alternating small (64KB), large (1MB), and oversized (2MB) slabs
                    int reqSize = (iter % 3) switch
                    {
                        0 => UnmanagedSlabPool.SmallSlabSize,
                        1 => UnmanagedSlabPool.LargeSlabSize,
                        _ => 2 * 1024 * 1024
                    };

                    using (SlabLease lease = pool.Rent(reqSize))
                    {
                        Assert.True(lease.Length >= reqSize);
                        Assert.True((nint)lease.Pointer != 0);

                        // Verify 64-byte alignment
                        Assert.Equal(0, (nint)lease.Pointer % 64);

                        // Write touch memory
                        lease.Span[0] = (byte)(threadId & 0xFF);
                        lease.Span[reqSize - 1] = (byte)(iter & 0xFF);
                    }

                    // Also test raw IntPtr rental and return
                    IntPtr rawPtr = pool.Rent(reqSize, out int actualSize);
                    Assert.True(actualSize >= reqSize);
                    Assert.True(rawPtr != IntPtr.Zero);
                    pool.Return(rawPtr, actualSize);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    // =========================================================================
    // SECTION 3: STRICT ZERO-ALLOCATION VERIFICATION (STEADY STATE)
    // =========================================================================

    [Fact]
    public void ZeroAllocation_Argon2id_SteadyStateLoop_AllocatesZeroBytes()
    {
        byte[] pwdBytes = new byte[32];
        byte[] saltBytes = new byte[16];
        pwdBytes.AsSpan().Fill(0x33);
        saltBytes.AsSpan().Fill(0x44);

        using var kdf = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 2);
        Span<byte> tag = stackalloc byte[32];

        // Warm up JIT and slab pool
        for (int i = 0; i < 3; i++)
        {
            kdf.DeriveKey(pwdBytes, saltBytes, tag);
        }

        // Run 20 consecutive steady-state iterations and assert 0 bytes allocated per iteration
        for (int iter = 0; iter < 20; iter++)
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            kdf.DeriveKey(pwdBytes, saltBytes, tag);
            long after = GC.GetAllocatedBytesForCurrentThread();

            long allocated = after - before;
            Assert.Equal(0, allocated);
        }
    }

    [Fact]
    public void ZeroAllocation_MlKem768_DerandOperations_AllocatesZeroBytes()
    {
        var kem = MlKemEngine.MlKem768;

        byte[] d = new byte[32];
        byte[] z = new byte[32];
        byte[] m = new byte[32];
        d.AsSpan().Fill(0x11);
        z.AsSpan().Fill(0x22);
        m.AsSpan().Fill(0x33);

        Span<byte> pk = stackalloc byte[kem.PublicKeySizeInBytes];
        Span<byte> sk = stackalloc byte[kem.SecretKeySizeInBytes];
        Span<byte> ct = stackalloc byte[kem.CiphertextSizeInBytes];
        Span<byte> ssA = stackalloc byte[kem.SharedSecretSizeInBytes];
        Span<byte> ssB = stackalloc byte[kem.SharedSecretSizeInBytes];

        // Warm up JIT
        for (int i = 0; i < 3; i++)
        {
            kem.GenerateKeyPairDerand(d, z, pk, sk);
            kem.EncapsulateDerand(pk, m, ct, ssA);
            kem.Decapsulate(sk, ct, ssB);
        }

        // Test 15 iterations each of KeyGenDerand, EncapsulateDerand, and Decapsulate
        for (int iter = 0; iter < 15; iter++)
        {
            long b1 = GC.GetAllocatedBytesForCurrentThread();
            kem.GenerateKeyPairDerand(d, z, pk, sk);
            long a1 = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(0, a1 - b1);

            long b2 = GC.GetAllocatedBytesForCurrentThread();
            kem.EncapsulateDerand(pk, m, ct, ssA);
            long a2 = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(0, a2 - b2);

            long b3 = GC.GetAllocatedBytesForCurrentThread();
            bool ok = kem.Decapsulate(sk, ct, ssB);
            long a3 = GC.GetAllocatedBytesForCurrentThread();
            Assert.True(ok);
            Assert.Equal(0, a3 - b3);
        }
    }

    [Fact]
    public void ZeroAllocation_MlKem1024_DerandOperations_AllocatesZeroBytes()
    {
        var kem = MlKemEngine.MlKem1024;

        byte[] d = new byte[32];
        byte[] z = new byte[32];
        byte[] m = new byte[32];
        d.AsSpan().Fill(0x44);
        z.AsSpan().Fill(0x55);
        m.AsSpan().Fill(0x66);

        Span<byte> pk = stackalloc byte[kem.PublicKeySizeInBytes];
        Span<byte> sk = stackalloc byte[kem.SecretKeySizeInBytes];
        Span<byte> ct = stackalloc byte[kem.CiphertextSizeInBytes];
        Span<byte> ssA = stackalloc byte[kem.SharedSecretSizeInBytes];
        Span<byte> ssB = stackalloc byte[kem.SharedSecretSizeInBytes];

        // Warm up JIT
        for (int i = 0; i < 3; i++)
        {
            kem.GenerateKeyPairDerand(d, z, pk, sk);
            kem.EncapsulateDerand(pk, m, ct, ssA);
            kem.Decapsulate(sk, ct, ssB);
        }

        // Test 15 iterations each
        for (int iter = 0; iter < 15; iter++)
        {
            long b1 = GC.GetAllocatedBytesForCurrentThread();
            kem.GenerateKeyPairDerand(d, z, pk, sk);
            long a1 = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(0, a1 - b1);

            long b2 = GC.GetAllocatedBytesForCurrentThread();
            kem.EncapsulateDerand(pk, m, ct, ssA);
            long a2 = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(0, a2 - b2);

            long b3 = GC.GetAllocatedBytesForCurrentThread();
            bool ok = kem.Decapsulate(sk, ct, ssB);
            long a3 = GC.GetAllocatedBytesForCurrentThread();
            Assert.True(ok);
            Assert.Equal(0, a3 - b3);
        }
    }

    [Fact]
    public void ZeroAllocation_MlKem_ImplicitRejection_AllocatesZeroBytes()
    {
        var kem768 = MlKemEngine.MlKem768;
        var kem1024 = MlKemEngine.MlKem1024;

        byte[] pk768 = new byte[kem768.PublicKeySizeInBytes];
        byte[] sk768 = new byte[kem768.SecretKeySizeInBytes];
        byte[] ct768 = new byte[kem768.CiphertextSizeInBytes];
        byte[] ss768 = new byte[32];

        kem768.GenerateKeyPair(pk768, sk768);
        kem768.Encapsulate(pk768, ct768, ss768);
        ct768[0] ^= 0xEE; // Invalidate ciphertext

        byte[] pk1024 = new byte[kem1024.PublicKeySizeInBytes];
        byte[] sk1024 = new byte[kem1024.SecretKeySizeInBytes];
        byte[] ct1024 = new byte[kem1024.CiphertextSizeInBytes];
        byte[] ss1024 = new byte[32];

        kem1024.GenerateKeyPair(pk1024, sk1024);
        kem1024.Encapsulate(pk1024, ct1024, ss1024);
        ct1024[0] ^= 0xEE; // Invalidate ciphertext

        // Warm up rejection paths and let Tiered compilation settle
        Span<byte> rejectSs = stackalloc byte[32];
        for (int w = 0; w < 50; w++)
        {
            kem768.Decapsulate(sk768, ct768, rejectSs);
            kem1024.Decapsulate(sk1024, ct1024, rejectSs);
        }

        for (int iter = 0; iter < 10; iter++)
        {
            long b768 = GC.GetAllocatedBytesForCurrentThread();
            bool ok768 = kem768.Decapsulate(sk768, ct768, rejectSs);
            long a768 = GC.GetAllocatedBytesForCurrentThread();
            Assert.False(ok768);
            Assert.Equal(0, a768 - b768);

            long b1024 = GC.GetAllocatedBytesForCurrentThread();
            bool ok1024 = kem1024.Decapsulate(sk1024, ct1024, rejectSs);
            long a1024 = GC.GetAllocatedBytesForCurrentThread();
            Assert.False(ok1024);
            Assert.Equal(0, a1024 - b1024);
        }
    }

    // =========================================================================
    // SECTION 4: BOUNDARY & HIGH-PARALLELISM EDGE CASES
    // =========================================================================

    [Theory]
    [InlineData(1, 8)]     // p=1, m=8
    [InlineData(2, 16)]    // p=2, m=16
    [InlineData(4, 32)]    // p=4, m=32
    [InlineData(8, 64)]    // p=8, m=64
    [InlineData(16, 128)]  // p=16, m=128
    public void BoundaryStress_Argon2id_MinimalValidMemory_And_HighParallelism(int parallelism, int minMemoryKb)
    {
        byte[] pwdBytes = new byte[16];
        byte[] saltBytes = new byte[16];
        pwdBytes.AsSpan().Fill(0x77);
        saltBytes.AsSpan().Fill(0x88);

        Span<byte> tag1 = stackalloc byte[32];
        Span<byte> tag2 = stackalloc byte[32];

        using var kdf = new Argon2id(iterations: 1, memoryKb: minMemoryKb, parallelism: parallelism);
        kdf.DeriveKey(pwdBytes, saltBytes, tag1);
        kdf.DeriveKey(pwdBytes, saltBytes, tag2);

        Assert.True(tag1.SequenceEqual(tag2));
        Assert.False(tag1.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void BoundaryStress_MlKem_UnalignedBufferSlices_RoundtripValid()
    {
        // Allocate larger buffers and slice with unaligned odd byte offsets
        var kem = MlKemEngine.MlKem768;
        byte[] largeBuffer = new byte[8192];
        RandomNumberGenerator.Fill(largeBuffer);

        // Offsets with odd alignments
        int pkOffset = 13;
        int skOffset = 1201;
        int ctOffset = 3605;
        int ssAOffset = 4701;
        int ssBOffset = 4753;

        Span<byte> pk = largeBuffer.AsSpan(pkOffset, kem.PublicKeySizeInBytes);
        Span<byte> sk = largeBuffer.AsSpan(skOffset, kem.SecretKeySizeInBytes);
        Span<byte> ct = largeBuffer.AsSpan(ctOffset, kem.CiphertextSizeInBytes);
        Span<byte> ssA = largeBuffer.AsSpan(ssAOffset, kem.SharedSecretSizeInBytes);
        Span<byte> ssB = largeBuffer.AsSpan(ssBOffset, kem.SharedSecretSizeInBytes);

        kem.GenerateKeyPair(pk, sk);
        kem.Encapsulate(pk, ct, ssA);
        bool ok = kem.Decapsulate(sk, ct, ssB);

        Assert.True(ok);
        Assert.True(ssA.SequenceEqual(ssB));
    }

    [Fact]
    public void Concurrency_8Threads_Argon2id_64MB_SimultaneousExecution()
    {
        // 8 concurrent threads simultaneously renting 64MB unmanaged slabs (512MB active memory)
        const int threadCount8 = 8;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, threadCount8, new ParallelOptions { MaxDegreeOfParallelism = threadCount8 }, threadId =>
        {
            try
            {
                byte[] pwdBytes = new byte[32];
                byte[] saltBytes = new byte[16];
                for (int i = 0; i < 32; i++) pwdBytes[i] = (byte)((threadId * 17 + i) & 0xFF);
                for (int i = 0; i < 16; i++) saltBytes[i] = (byte)((threadId * 31 + i) & 0xFF);

                using var argon = new Argon2id(iterations: 1, memoryKb: 65536, parallelism: 4);
                Span<byte> tag1 = stackalloc byte[32];
                Span<byte> tag2 = stackalloc byte[32];

                argon.DeriveKey(pwdBytes, saltBytes, tag1);
                argon.DeriveKey(pwdBytes, saltBytes, tag2);

                if (!tag1.SequenceEqual(tag2))
                {
                    throw new InvalidOperationException($"Thread {threadId} failed determinism across runs!");
                }
                if (tag1.SequenceEqual(new byte[32]))
                {
                    throw new InvalidOperationException($"Thread {threadId} produced all zeroes!");
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_32Threads_MlKemKeyPair_LifecycleAndZeroMemory()
    {
        // 32 threads creating and disposing managed MlKemKeyPair containers backed by SecureMemory
        var kem = MlKemEngine.MlKem768;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                for (int iter = 0; iter < 10; iter++)
                {
                    using (MlKemKeyPair keyPair = kem.CreateKeyPair())
                    {
                        byte[] ct = new byte[kem.CiphertextSizeInBytes];
                        byte[] ssA = new byte[32];
                        byte[] ssB = new byte[32];

                        keyPair.Encapsulate(ct, ssA);
                        bool ok = keyPair.Decapsulate(ct, ssB);

                        if (!ok || !ssA.AsSpan().SequenceEqual(ssB))
                        {
                            throw new InvalidOperationException($"Thread {threadId} iter {iter} failed shared secret agreement!");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void CorruptedSecretKey_TriggersImplicitRejection_Deterministically()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssReal = new byte[32];
        kem.Encapsulate(pk, ct, ssReal);

        // Corrupt dk_PKE at sk[0] so decryption produces incorrect m', causing re-encryption c' != c
        sk[0] ^= 0xAA;

        byte[] ssReject1 = new byte[32];
        byte[] ssReject2 = new byte[32];

        bool ok1 = kem.Decapsulate(sk, ct, ssReject1);
        bool ok2 = kem.Decapsulate(sk, ct, ssReject2);

        Assert.False(ok1);
        Assert.False(ok2);
        Assert.False(ssReal.AsSpan().SequenceEqual(ssReject1));
        Assert.True(ssReject1.AsSpan().SequenceEqual(ssReject2));
    }
}
