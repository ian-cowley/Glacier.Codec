namespace Glacier.Codec.Tests;

using System;
using System.Buffers;
using System.Threading.Tasks;
using Glacier.Codec.Memory;
using Xunit;

public unsafe class MemoryPoolTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1024)]
    [InlineData(65536)]
    [InlineData(1048576)]
    public void CachelineAlignedBuffer_Is64ByteAligned(int size)
    {
        using var buffer = new CachelineAlignedBuffer(size);
        nuint address = (nuint)buffer.Pointer;

        Assert.Equal(0u, address % 64u);
        Assert.Equal(size, buffer.Length);
        Assert.True(buffer.AllocatedBytes >= (nuint)size);
        Assert.Equal(0u, buffer.AllocatedBytes % 64u);
        Assert.True(buffer.IsAlignedTo64Bytes);
    }

    [Fact]
    public void CachelineAlignedBuffer_ZeroLength_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(0));
    }

    [Fact]
    public void CachelineAlignedBuffer_NegativeLength_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(-1));
    }

    [Fact]
    public void CachelineAlignedBuffer_ReadWriteIntegrity()
    {
        const int size = 4096;
        using var buffer = new CachelineAlignedBuffer(size);

        Span<byte> span = buffer.Span;
        for (int i = 0; i < size; i++)
        {
            span[i] = (byte)(i & 0xFF);
        }

        byte* ptr = (byte*)buffer.Pointer;
        for (int i = 0; i < size; i++)
        {
            Assert.Equal((byte)(i & 0xFF), ptr[i]);
        }
    }

    [Fact]
    public void CachelineAlignedBuffer_MemoryManager_PinningMatchesPointer()
    {
        using var buffer = new CachelineAlignedBuffer(512);
        Memory<byte> memory = buffer.Memory;
        Assert.Equal(512, memory.Length);

        using MemoryHandle handle = memory.Pin();
        Assert.Equal((IntPtr)buffer.Pointer, (IntPtr)handle.Pointer);
    }

    [Fact]
    public void CachelineAlignedBuffer_Dispose_ThrowsOnSubsequentAccess()
    {
        var buffer = new CachelineAlignedBuffer(256);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { var _ = buffer.Span; });
        Assert.Throws<ObjectDisposedException>(() => { var _ = buffer.Pointer; });
    }

    [Fact]
    public void CachelineAlignedBuffer_DoubleDispose_IsIdempotent()
    {
        var buffer = new CachelineAlignedBuffer(256);
        buffer.Dispose();
        buffer.Dispose(); // Must not throw or crash
    }

    [Fact]
    public void UnmanagedSlabPool_RentSmall_Returns64KAlignedSlab()
    {
        using var pool = new UnmanagedSlabPool();
        using SlabLease lease = pool.Rent(4096);

        Assert.True(lease.Length >= 65536);
        Assert.Equal(0u, (nuint)lease.Pointer % 64u);
    }

    [Fact]
    public void UnmanagedSlabPool_RentLarge_Returns1MbAlignedSlab()
    {
        using var pool = new UnmanagedSlabPool();
        using SlabLease lease = pool.Rent(100000);

        Assert.True(lease.Length >= 1048576);
        Assert.Equal(0u, (nuint)lease.Pointer % 64u);
    }

    [Fact]
    public void UnmanagedSlabPool_RecyclesReturnedBuffer()
    {
        using var pool = new UnmanagedSlabPool();
        void* firstPtr;

        using (SlabLease lease1 = pool.Rent(1024))
        {
            firstPtr = lease1.Pointer;
            lease1.Span[0] = 42;
        }

        // After lease1 is disposed, renting again should recycle the exact same buffer
        using (SlabLease lease2 = pool.Rent(1024))
        {
            Assert.Equal((IntPtr)firstPtr, (IntPtr)lease2.Pointer);
        }
    }

    [Fact]
    public void UnmanagedSlabPool_MultiThreadedStress_NoDeadlockOrCorruption()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 64, maxLargeSlabs: 16);
        const int threadCount = 16;
        const int iterationsPerThread = 200;

        Parallel.For(0, threadCount, _ =>
        {
            for (int i = 0; i < iterationsPerThread; i++)
            {
                using SlabLease lease = pool.Rent(1024);
                Span<byte> span = lease.Span;
                span[0] = (byte)i;
                span[span.Length - 1] = (byte)(i ^ 0xFF);
                Assert.Equal(0u, (nuint)lease.Pointer % 64u);
            }
        });
    }

    [Fact]
    public void UnmanagedSlabPool_SharedInstance_IsFunctional()
    {
        using SlabLease lease = UnmanagedSlabPool.Shared.Rent(512);
        Assert.NotNull(lease.Buffer);
        Assert.Equal(0u, (nuint)lease.Pointer % 64u);
    }
}
