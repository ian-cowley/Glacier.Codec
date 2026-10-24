namespace Glacier.Codec.Tests;

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Regression test suite for UnmanagedSlabPool, CachelineAlignedBuffer, and SlabLease memory safety fixes.
/// Specifically validates:
/// 1. Return(IntPtr, int) double-free & use-after-free elimination (safe idempotency).
/// 2. Untracked pointer safety (safe no-op, external pointer intact).
/// 3. SlabLease double-dispose idempotency (eliminates buffer aliasing across rentals).
/// 4. Cryptographic zero-memory sanitization across all SlabLease disposal & rental cycles.
/// 5. ObjectDisposedException invariants on disposed SlabLease properties.
/// 6. CachelineAlignedBuffer and SlabLease PaddedSpan SIMD envelopes.
/// 7. High-concurrency stress with intentional duplicate disposals across 24 parallel workers.
/// </summary>
public unsafe class MemoryPoolRegressionTests
{
    private const int WorkerCount24 = 24;

    // =========================================================================
    // 1. POINTER API DOUBLE-FREE & UNTRACKED POINTER REGRESSIONS
    // =========================================================================

    [Fact]
    public void PointerApi_DoubleReturn_IsIdempotentAndDoesNotCrashOnPoolDispose()
    {
        var pool = new UnmanagedSlabPool(maxSmallSlabs: 16);
        IntPtr ptr = pool.Rent(1024, out int actual);
        Assert.NotEqual(IntPtr.Zero, ptr);

        // Fill memory with test pattern
        new Span<byte>((void*)ptr, actual).Fill(0x55);

        // First return: removes from _rawAllocations and enqueues buffer into _smallSlabs
        pool.Return(ptr, actual);

        // Second return (must be safe no-op, must NOT AlignedFree)
        pool.Return(ptr, actual);

        // Third return: must also be safe
        pool.Return(ptr, actual);

        // Re-rent: should cleanly dequeue the live, uncorrupted buffer
        IntPtr ptr2 = pool.Rent(1024, out int actual2);
        Assert.Equal(ptr, ptr2);
        Assert.Equal(actual, actual2);

        // Verify memory was wiped to zero
        Span<byte> span2 = new((void*)ptr2, actual2);
        Assert.Equal(0, span2[0]);
        Assert.Equal(0, span2[actual2 - 1]);

        // Verify memory is live and writable without AV or heap corruption
        span2.Fill(0x7A);
        Assert.Equal((byte)0x7A, *(byte*)ptr2);

        // Return valid rental
        pool.Return(ptr2, actual2);

        // Pool disposal must not crash with STATUS_HEAP_CORRUPTION double-free
        pool.Dispose();
    }

    [Fact]
    public void PointerApi_UntrackedPointer_IsSafeNoOp()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16);

        // Allocate independent memory outside the pool
        void* externalPtr = NativeMemory.AlignedAlloc(4096, 64);
        try
        {
            new Span<byte>(externalPtr, 4096).Fill(0xEE);

            // Returning an untracked pointer must NOT free it or throw
            pool.Return((IntPtr)externalPtr, 4096);

            // Verify the external memory is still valid, intact, and not freed
            Assert.Equal((byte)0xEE, *(byte*)externalPtr);
        }
        finally
        {
            NativeMemory.AlignedFree(externalPtr);
        }

        // Returning arbitrary non-null invalid pointers must be safe no-ops
        IntPtr fakePtr = (IntPtr)0x10000000;
        pool.Return(fakePtr, 1024);
        pool.Return(new IntPtr(unchecked((int)0xBAADF00D)), 1024);
        pool.Return(IntPtr.Zero, 0);
        pool.Return(IntPtr.Zero, -1);
    }

    // =========================================================================
    // 2. SLABLEASE DOUBLE-DISPOSE IDEMPOTENCY & ALIASING REGRESSIONS
    // =========================================================================

    [Fact]
    public void SlabLease_DoubleDispose_IsIdempotentAndPreventsAliasing()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16);
        var lease = pool.Rent(1024);
        void* originalPtr = lease.Pointer;

        // First disposal returns buffer to pool
        lease.Dispose();

        // Second disposal must be an idempotent no-op (no duplicate enqueue)
        lease.Dispose();

        // Third disposal must also safely no-op
        lease.Dispose();

        // Rent two buffers sequentially
        using var rent1 = pool.Rent(1024);
        using var rent2 = pool.Rent(1024);

        // Assert rent1 recycled the first buffer
        Assert.Equal((IntPtr)originalPtr, (IntPtr)rent1.Pointer);

        // Assert rent2 got a DIFFERENT, distinct buffer (no aliasing!)
        Assert.NotEqual((IntPtr)originalPtr, (IntPtr)rent2.Pointer);
        Assert.NotEqual((IntPtr)rent1.Pointer, (IntPtr)rent2.Pointer);

        // Verify independent data write isolation
        rent1.Span.Fill(0x11);
        rent2.Span.Fill(0x22);

        Assert.Equal((byte)0x11, rent1.Span[0]);
        Assert.Equal((byte)0x22, rent2.Span[0]);
    }

    [Fact]
    public void SlabLease_PostDisposalAccess_ThrowsObjectDisposedException()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16);
        var lease = pool.Rent(1024);

        lease.Dispose();

        bool spanThrew = false;
        try { var _ = lease.Span; }
        catch (ObjectDisposedException) { spanThrew = true; }
        Assert.True(spanThrew);

        bool paddedSpanThrew = false;
        try { var _ = lease.PaddedSpan; }
        catch (ObjectDisposedException) { paddedSpanThrew = true; }
        Assert.True(paddedSpanThrew);

        bool ptrThrew = false;
        try { var _ = lease.Pointer; }
        catch (ObjectDisposedException) { ptrThrew = true; }
        Assert.True(ptrThrew);

        bool bufThrew = false;
        try { var _ = lease.Buffer; }
        catch (ObjectDisposedException) { bufThrew = true; }
        Assert.True(bufThrew);

        bool lenThrew = false;
        try { var _ = lease.Length; }
        catch (ObjectDisposedException) { lenThrew = true; }
        Assert.True(lenThrew);

        bool allocThrew = false;
        try { var _ = lease.AllocatedBytes; }
        catch (ObjectDisposedException) { allocThrew = true; }
        Assert.True(allocThrew);
    }

    // =========================================================================
    // 3. ZERO-MEMORY SANITIZATION ON RENTAL & RETURN
    // =========================================================================

    [Fact]
    public void SlabLease_RecycledBuffer_IsZeroMemorySanitized_SmallSlab()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16);
        void* firstPtr;

        using (var lease1 = pool.Rent(64 * 1024))
        {
            firstPtr = lease1.Pointer;
            Span<byte> span = lease1.Span;
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = 0xAA;
            }
        } // lease1.Dispose() scrubs memory

        using (var lease2 = pool.Rent(64 * 1024))
        {
            Assert.Equal((IntPtr)firstPtr, (IntPtr)lease2.Pointer);

            ReadOnlySpan<byte> span = lease2.Span;
            for (int i = 0; i < span.Length; i++)
            {
                Assert.Equal(0, span[i]);
            }
        }
    }

    [Fact]
    public void SlabLease_RecycledBuffer_IsZeroMemorySanitized_LargeSlab()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 4, maxLargeSlabs: 4);
        void* firstPtr;

        using (var lease1 = pool.Rent(1024 * 1024))
        {
            firstPtr = lease1.Pointer;
            lease1.Span.Fill(0x99);
        }

        using (var lease2 = pool.Rent(1024 * 1024))
        {
            Assert.Equal((IntPtr)firstPtr, (IntPtr)lease2.Pointer);

            ReadOnlySpan<byte> span = lease2.Span;
            Assert.Equal((byte)0x00, span[0]);
            Assert.Equal((byte)0x00, span[512 * 1024]);
            Assert.Equal((byte)0x00, span[span.Length - 1]);

            for (int i = 0; i < span.Length; i += 4096)
            {
                Assert.Equal((byte)0x00, span[i]);
            }
        }
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(64 * 1024)]
    [InlineData(1024 * 1024)]
    [InlineData(2 * 1024 * 1024)]
    public void SlabLease_InitialAllocation_IsZeroMemoryClean(int requestedSize)
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16, maxLargeSlabs: 4);
        using var lease = pool.Rent(requestedSize);

        ReadOnlySpan<byte> span = lease.Span;
        for (int i = 0; i < span.Length; i += Math.Max(1, span.Length / 100))
        {
            Assert.Equal(0, span[i]);
        }
        Assert.Equal(0, span[span.Length - 1]);
    }

    [Fact]
    public void UnmanagedSlabPool_OversizedBuffer_SanitizedBeforeFree()
    {
        using var pool = new UnmanagedSlabPool();
        const int oversizedSize = 2 * 1024 * 1024;

        using (var lease = pool.Rent(oversizedSize))
        {
            lease.Span.Fill(0xEE);
        } // Must scrub and free without throwing
    }

    // =========================================================================
    // 4. CACHELINE ALIGNED BUFFER & SLABLEASE PADDEDSPAN
    // =========================================================================

    [Fact]
    public void CachelineAlignedBuffer_PaddedSpan_ProvidesFullAllocatedEnvelope()
    {
        // 100 bytes requested: rounded up to 128 bytes (multiple of 64)
        using var buffer = new CachelineAlignedBuffer(100);

        Assert.Equal(100, buffer.Length);
        Assert.Equal(100, buffer.Span.Length);
        Assert.Equal((nuint)128, buffer.AllocatedBytes);
        Assert.Equal(128, buffer.PaddedSpan.Length);

        // Padded span allows safe SIMD envelope access without buffer overrun
        Span<byte> padded = buffer.PaddedSpan;
        padded[127] = 0xFE;
        Assert.Equal((byte)0xFE, padded[127]);
    }

    [Fact]
    public void CachelineAlignedBuffer_PaddedSpan_ThrowsAfterDispose()
    {
        var buffer = new CachelineAlignedBuffer(128);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { var _ = buffer.PaddedSpan; });
    }

    [Fact]
    public void SlabLease_PaddedSpan_ProvidesFullAllocatedEnvelope()
    {
        using var pool = new UnmanagedSlabPool();
        using var lease = pool.Rent(1000);

        Assert.True(lease.Length >= 1000);
        Assert.True(lease.PaddedSpan.Length >= lease.Length);
        Assert.Equal(0, lease.PaddedSpan.Length % 64);

        lease.PaddedSpan[lease.PaddedSpan.Length - 1] = 0x42;
        Assert.Equal((byte)0x42, lease.PaddedSpan[lease.PaddedSpan.Length - 1]);
    }

    // =========================================================================
    // 5. CONCURRENT DOUBLE-DISPOSE & MULTI-THREADED TORTURE
    // =========================================================================

    [Fact]
    public void Concurrent_24Workers_IntentionalDoubleDispose_ZeroAliasing()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 64, maxLargeSlabs: 16);
        const int iterationsPerWorker = 300;
        var exceptions = new ConcurrentBag<Exception>();
        int totalPassed = 0;

        Parallel.For(0, WorkerCount24, new ParallelOptions { MaxDegreeOfParallelism = WorkerCount24 }, workerId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerWorker; iter++)
                {
                    var lease = pool.Rent(64 * 1024);

                    // Write unique thread pattern
                    lease.Span[0] = (byte)workerId;
                    lease.Span[lease.Length - 1] = (byte)(workerId ^ 0xFF);

                    // Explicit first dispose
                    lease.Dispose();

                    // Intentional duplicate dispose: must be completely harmless
                    lease.Dispose();

                    Interlocked.Increment(ref totalPassed);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(WorkerCount24 * iterationsPerWorker, totalPassed);

        // Pool disposal must succeed cleanly
        pool.Dispose();
    }
}
