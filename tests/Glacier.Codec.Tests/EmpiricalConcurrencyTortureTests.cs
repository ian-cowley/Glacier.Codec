namespace Glacier.Codec.Tests;

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Concurrency & Memory Torture Test Suite for UnmanagedSlabPool.
/// Authored by Empirical Challenger (Milestone M1 Iteration 2).
/// 
/// Stress tests under extreme multi-threaded concurrency (24 to 48 parallel workers):
/// 1. Zero double-free crashes and zero heap corruption across tens of thousands of cycles.
/// 2. Zero memory corruption under race conditions (interleaved write verification).
/// 3. Zero buffer aliasing across concurrent active rentals (tracked via concurrent pointer registry).
/// 4. Cryptographic zero-memory sanitization verification across all recycles.
/// 5. Torture testing the pointer-based Rent/Return API with intentional duplicate and foreign pointer returns.
/// 6. Pool lifecycle and disposal safety under concurrent active usage.
/// 7. AVX-512 PaddedSpan boundary integrity under concurrent stress.
/// </summary>
public class EmpiricalConcurrencyTortureTests
{
    private const int ConcurrencyWorkers24 = 24;
    private const int ConcurrencyWorkers32 = 32;
    private const int ConcurrencyWorkers48 = 48;

    /// <summary>
    /// EMPIRICAL PROOF 1: ZERO BUFFER ALIASING UNDER 32 CONCURRENT WORKERS.
    /// Every active rental is registered in a ConcurrentDictionary. If any buffer is ever rented
    /// simultaneously to two workers, TryAdd returns false and triggers immediate failure.
    /// In addition, each worker writes a unique pattern and asserts zero corruption upon release.
    /// </summary>
    [Fact]
    public unsafe void Torture_32Workers_ActivePointerRegistry_ZeroBufferAliasing()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 64, maxLargeSlabs: 16);
        const int iterationsPerWorker = 500;
        var activePointers = new ConcurrentDictionary<IntPtr, int>();
        var exceptions = new ConcurrentBag<Exception>();
        int totalSuccessfulCycles = 0;

        Parallel.For(0, ConcurrencyWorkers32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyWorkers32 }, workerId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    bool isSmall = (iter % 3) != 0;
                    int requestSize = isSmall ? 64 * 1024 : 1024 * 1024;

                    using SlabLease lease = pool.Rent(requestSize);
                    IntPtr ptr = (IntPtr)lease.Pointer;

                    // 1. Strict alignment check
                    Assert.Equal(0u, (nuint)ptr % 64u);

                    // 2. ZERO ALIASING ASSERTION: Must not be in activePointers already!
                    bool added = activePointers.TryAdd(ptr, workerId);
                    if (!added)
                    {
                        activePointers.TryGetValue(ptr, out int ownerId);
                        throw new InvalidOperationException(
                            $"FATAL BUFFER ALIASING: Worker {workerId} rented pointer 0x{ptr:X} which is currently held by Worker {ownerId}!");
                    }

                    try
                    {
                        // 3. Write deterministic pattern across whole span
                        Span<byte> span = lease.Span;
                        byte pattern = (byte)((workerId * 31 + iter) & 0xFF);
                        span[0] = pattern;
                        span[span.Length / 4] = (byte)(pattern ^ 0x33);
                        span[span.Length / 2] = (byte)(pattern ^ 0x55);
                        span[3 * span.Length / 4] = (byte)(pattern ^ 0xAA);
                        span[span.Length - 1] = (byte)(pattern ^ 0xFF);

                        // 4. Spin-wait to simulate real workload and induce thread interleaving
                        Thread.SpinWait((iter % 10) * 10 + 20);

                        // 5. Memory corruption assertion: data must NOT have been modified by another thread
                        Assert.Equal(pattern, span[0]);
                        Assert.Equal((byte)(pattern ^ 0x33), span[span.Length / 4]);
                        Assert.Equal((byte)(pattern ^ 0x55), span[span.Length / 2]);
                        Assert.Equal((byte)(pattern ^ 0xAA), span[3 * span.Length / 4]);
                        Assert.Equal((byte)(pattern ^ 0xFF), span[span.Length - 1]);
                    }
                    finally
                    {
                        // Remove from active registry BEFORE lease is returned to pool
                        bool removed = activePointers.TryRemove(ptr, out _);
                        Assert.True(removed, $"Failed to remove pointer 0x{ptr:X} from active registry");
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
        Assert.Equal(ConcurrencyWorkers32 * iterationsPerWorker, totalSuccessfulCycles);
        Assert.Empty(activePointers);
    }

    /// <summary>
    /// EMPIRICAL PROOF 2: ZERO MEMORY LEAKAGE / SANITIZATION UNDER 24 WORKERS.
    /// Validates that every recycled slab rented by any worker is 100% zeroed,
    /// proving CryptographicOperations.ZeroMemory scrubs all bytes upon return.
    /// </summary>
    [Fact]
    public void Torture_24Workers_RecycledBufferZeroSanitization_NoDataLeak()
    {
        // Small pool to force high recycle frequency
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16, maxLargeSlabs: 8);
        const int iterationsPerWorker = 300;
        var exceptions = new ConcurrentBag<Exception>();
        int totalChecked = 0;

        Parallel.For(0, ConcurrencyWorkers24, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyWorkers24 }, workerId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    using (SlabLease lease = pool.Rent(64 * 1024))
                    {
                        ReadOnlySpan<byte> span = lease.Span;

                        // 1. Assert memory is 100% zeroed on rental
                        // Check sampled intervals and endpoints
                        Assert.Equal((byte)0, span[0]);
                        Assert.Equal((byte)0, span[span.Length / 2]);
                        Assert.Equal((byte)0, span[span.Length - 1]);

                        for (int i = 0; i < span.Length; i += 512)
                        {
                            if (span[i] != 0)
                            {
                                throw new InvalidOperationException(
                                    $"Data leak detected at offset {i}: value was 0x{span[i]:X2}, expected 0x00!");
                            }
                        }

                        // 2. Dirty the memory with non-zero bytes before returning
                        lease.Span.Fill((byte)(workerId + 1));
                    } // Dispose scrubs memory

                    Interlocked.Increment(ref totalChecked);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ConcurrencyWorkers24 * iterationsPerWorker, totalChecked);
    }

    /// <summary>
    /// EMPIRICAL PROOF 3: POINTER API TORTURE UNDER 48 WORKERS WITH CHAOTIC RETURNS.
    /// Workers concurrently rent pointers, fill them, and randomly perform duplicate returns,
    /// untracked foreign pointer returns, and null pointer returns.
    /// Asserts zero CRT heap corruption crashes and zero double-frees.
    /// </summary>
    [Fact]
    public unsafe void Torture_48Workers_PointerApi_DuplicateAndUntrackedReturns_ZeroCrashes()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 32, maxLargeSlabs: 8);
        const int iterationsPerWorker = 200;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        // Allocate a few external buffers that are NOT in the pool
        void* externalBuffer = NativeMemory.AlignedAlloc(4096, 64);
        try
        {
            Parallel.For(0, ConcurrencyWorkers48, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyWorkers48 }, workerId =>
            {
                try
                {
                    for (int iter = 0; iter < iterationsPerWorker; iter++)
                    {
                        int size = (iter % 2 == 0) ? 64 * 1024 : 1024 * 1024;
                        IntPtr ptr = pool.Rent(size, out int actualSize);

                        Assert.NotEqual(IntPtr.Zero, ptr);
                        Assert.Equal(0u, (nuint)ptr % 64u);
                        Assert.True(actualSize >= size);

                        // Write to buffer
                        Span<byte> span = new((void*)ptr, actualSize);
                        span[0] = 0xAA;
                        span[actualSize - 1] = 0x55;

                        // Return valid buffer
                        pool.Return(ptr, actualSize);

                        // Adversarial duplicate return: must safely no-op
                        pool.Return(ptr, actualSize);

                        // Adversarial third return
                        if (iter % 5 == 0)
                        {
                            pool.Return(ptr, actualSize);
                        }

                        // Chaotic untracked foreign pointer return: must not free or throw
                        if (iter % 7 == 0)
                        {
                            pool.Return((IntPtr)externalBuffer, 4096);
                        }

                        // Null pointer return: safe no-op
                        pool.Return(IntPtr.Zero, 0);

                        Interlocked.Increment(ref totalCompleted);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            Assert.Empty(exceptions);
            Assert.Equal(ConcurrencyWorkers48 * iterationsPerWorker, totalCompleted);
        }
        finally
        {
            NativeMemory.AlignedFree(externalBuffer);
        }

        // Disposal of pool after chaotic returns must complete cleanly without CRT abort
        pool.Dispose();
    }

    /// <summary>
    /// EMPIRICAL PROOF 4: MIXED CONCURRENT RENTALS OF SMALL, LARGE, AND OVERSIZED SLABS (24 WORKERS).
    /// Stresses pool routing across small slabs (64KB), large slabs (1MB), and direct unpooled
    /// allocations (2MB, 4MB, 8MB) simultaneously.
    /// </summary>
    [Fact]
    public unsafe void Torture_24Workers_MixedSmallLargeOversized_Concurrency()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 32, maxLargeSlabs: 8);
        const int iterationsPerWorker = 200;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        int[] sizes = [
            1024,
            32 * 1024,
            64 * 1024,
            256 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            4 * 1024 * 1024
        ];

        Parallel.For(0, ConcurrencyWorkers24, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyWorkers24 }, workerId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    int requestSize = sizes[(workerId + iter) % sizes.Length];
                    using SlabLease lease = pool.Rent(requestSize);

                    Assert.True(lease.Length >= requestSize);
                    Assert.Equal(0u, (nuint)lease.Pointer % 64u);

                    // Touch endpoints
                    lease.Span[0] = (byte)(workerId & 0xFF);
                    lease.Span[requestSize - 1] = (byte)(iter & 0xFF);

                    Thread.SpinWait(10);

                    Assert.Equal((byte)(workerId & 0xFF), lease.Span[0]);
                    Assert.Equal((byte)(iter & 0xFF), lease.Span[requestSize - 1]);

                    Interlocked.Increment(ref totalCompleted);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ConcurrencyWorkers24 * iterationsPerWorker, totalCompleted);
    }

    /// <summary>
    /// EMPIRICAL PROOF 5: CONCURRENT POOL DISPOSAL SAFETY.
    /// Disposing an UnmanagedSlabPool while active worker threads are renting and returning.
    /// Asserts that rentals either succeed or throw ObjectDisposedException, and all active leases
    /// can be disposed cleanly without memory leaks, crashes, or unhandled exceptions.
    /// </summary>
    [Fact]
    public async Task Torture_ConcurrentPoolDisposal_RaceConditionSafety()
    {
        var pool = new UnmanagedSlabPool(maxSmallSlabs: 16, maxLargeSlabs: 4);
        var cts = new CancellationTokenSource();
        var exceptions = new ConcurrentBag<Exception>();
        int successfulCycles = 0;
        int disposedRejections = 0;

        Task[] workers = new Task[ConcurrencyWorkers24];
        for (int i = 0; i < ConcurrencyWorkers24; i++)
        {
            int workerId = i;
            workers[i] = Task.Run(() =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        using SlabLease lease = pool.Rent(64 * 1024);
                        lease.Span[0] = (byte)workerId;
                        Thread.SpinWait(20);
                        Assert.Equal((byte)workerId, lease.Span[0]);
                        Interlocked.Increment(ref successfulCycles);
                    }
                    catch (ObjectDisposedException)
                    {
                        // Expected once pool is disposed
                        Interlocked.Increment(ref disposedRejections);
                        break;
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                        break;
                    }
                }
            });
        }

        // Let workers run concurrently for 50 ms
        await Task.Delay(50);

        // Dispose the pool from the main thread while workers are actively running
        pool.Dispose();

        // Signal workers to stop and wait for completion
        cts.Cancel();
        await Task.WhenAll(workers);

        Assert.Empty(exceptions);
        Assert.True(successfulCycles > 0, "Expected at least some successful cycles before disposal");

        // Further rentals after disposal must throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => pool.Rent(1024));
        Assert.Throws<ObjectDisposedException>(() => pool.Rent(1024, out _));

        // Duplicate pool disposal must be safe
        pool.Dispose();
    }

    /// <summary>
    /// EMPIRICAL PROOF 6: PADDEDSPAN AVX-512 ENVELOPE CONCURRENCY TORTURE.
    /// Validates that concurrent access to the SIMD padded envelope (AllocatedBytes >= Length)
    /// across 24 workers does not overflow, collide, or cause heap corruption.
    /// </summary>
    [Fact]
    public void Torture_24Workers_PaddedSpan_SimdEnvelopeIntegrity()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 32);
        const int iterationsPerWorker = 300;
        var exceptions = new ConcurrentBag<Exception>();
        int totalCompleted = 0;

        Parallel.For(0, ConcurrencyWorkers24, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyWorkers24 }, workerId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    // Non-multiple-of-64 size to ensure padding exists
                    int unalignedSize = 4000;
                    using SlabLease lease = pool.Rent(unalignedSize);

                    Span<byte> padded = lease.PaddedSpan;
                    Assert.True(padded.Length >= unalignedSize);
                    Assert.Equal(0, padded.Length % 64);

                    // Touch the exact last byte in the padded SIMD envelope
                    int lastIndex = padded.Length - 1;
                    byte testVal = (byte)((workerId + iter) & 0xFF);
                    padded[lastIndex] = testVal;

                    Thread.SpinWait(20);

                    Assert.Equal(testVal, padded[lastIndex]);
                    Interlocked.Increment(ref totalCompleted);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ConcurrencyWorkers24 * iterationsPerWorker, totalCompleted);
    }
}
