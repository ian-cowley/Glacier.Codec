using System;
using Xunit;
using Glacier.Codec.Memory;

namespace Glacier.Codec.Tests.E2E.Tier2_BoundaryCases;

public class Tier2_HardwareMemoryBoundaries
{
    [Fact]
    public void Boundary_CachelineBuffer_ZeroOrNegativeByteAllocation_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(-1024));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(1048576)]
    public void Boundary_CachelineBuffer_Strict64ByteAlignmentAcrossSizes(int size)
    {
        using var buffer = new CachelineAlignedBuffer(size);
        Assert.True(buffer.IsAlignedTo64Bytes, $"Buffer of size {size} must be 64-byte aligned.");
        Assert.Equal(size, buffer.Length);
        Assert.Equal(size, buffer.Span.Length);
    }

    [Fact]
    public void Boundary_CachelineBuffer_DisposedBufferAccess_ThrowsObjectDisposedException()
    {
        var buffer = new CachelineAlignedBuffer(128);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { var _ = buffer.Span; });
    }

    [Fact]
    public void Boundary_CachelineBuffer_DoubleDispose_IsIdempotent()
    {
        var buffer = new CachelineAlignedBuffer(256);
        buffer.Dispose();
        buffer.Dispose(); // Must not throw
    }

    [Fact]
    public void Boundary_UnmanagedSlabPool_DisposedPoolAccess_ThrowsObjectDisposedException()
    {
        var pool = new UnmanagedSlabPool();
        pool.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pool.Rent(1024, out _));
    }

    [Fact]
    public void Boundary_SecureMemory_ZeroOrNegativeByteAllocation_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureMemory(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureMemory(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureMemory(-5));
    }

    [Fact]
    public void Boundary_SecureMemory_DoubleDispose_IsIdempotent()
    {
        var secMem = new SecureMemory(32);
        secMem.Dispose();
        secMem.Dispose(); // Must not throw
    }
}
