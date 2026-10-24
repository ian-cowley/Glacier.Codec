namespace Glacier.Codec.Tests;

using System;
using Glacier.Codec.Hardware;
using Xunit;

public sealed class HardwareArbiterTests
{
    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 1)]
    [InlineData(64 * 1024, 1)]
    [InlineData(512 * 1024, 1)]
    [InlineData(1024 * 1024 - 1, 1)]
    [InlineData(1024 * 1024 - 1, 15)]
    public void RouteWorkload_SmallPayload_RoutesToCpuVector(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuVector, target);
        Assert.True(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable: true));
    }

    [Theory]
    [InlineData(1024 * 1024, 1)]
    [InlineData(2 * 1024 * 1024, 1)]
    [InlineData(4 * 1024 * 1024 - 1, 1)]
    [InlineData(2 * 1024 * 1024, 15)]
    public void RouteWorkload_IntermediatePayload_RoutesToCpuParallelPool(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
        Assert.False(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable: true));
    }

    [Theory]
    [InlineData(4 * 1024 * 1024, 1)]
    [InlineData(8 * 1024 * 1024, 1)]
    [InlineData(16 * 1024 * 1024, 1)]
    [InlineData(64 * 1024 * 1024, 1)]
    public void RouteWorkload_LargePayload_WithGpu_RoutesToGpuCompute(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.GpuCompute, target);
        Assert.True(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable: true));
        Assert.False(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
    }

    [Theory]
    [InlineData(4 * 1024 * 1024, 1)]
    [InlineData(16 * 1024 * 1024, 1)]
    [InlineData(64 * 1024 * 1024, 1)]
    public void RouteWorkload_LargePayload_WithoutGpu_FallsBackToCpuParallelPool(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: false);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable: false));
    }

    [Theory]
    [InlineData(64 * 1024, 16)]
    [InlineData(64 * 1024, 32)]
    [InlineData(1024 * 1024, 16)]
    public void RouteWorkload_BatchThreshold_WithGpu_RoutesToGpuCompute(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.GpuCompute, target);
    }

    [Theory]
    [InlineData(64 * 1024, 16)]
    [InlineData(64 * 1024, 32)]
    public void RouteWorkload_BatchThreshold_WithoutGpu_FallsBackToCpuParallelPool(int payloadBytes, int batchCount)
    {
        var target = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable: false);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
    }

    [Fact]
    public void RouteWorkload_CustomOptions_AppliesCustomThresholds()
    {
        var custom = new HardwareArbiterOptions(
            CpuVectorThresholdBytes: 512 * 1024,      // 512 KB
            GpuSizeThresholdBytes: 2 * 1024 * 1024,   // 2 MB
            GpuBatchThresholdCount: 8);               // 8 batches

        // 256 KB < 512 KB -> CpuVector
        Assert.Equal(ExecutionTarget.CpuVector, HardwareArbiter.RouteWorkload(256 * 1024, 1, true, custom));

        // 1 MB >= 512 KB and < 2 MB -> CpuParallelPool
        Assert.Equal(ExecutionTarget.CpuParallelPool, HardwareArbiter.RouteWorkload(1024 * 1024, 1, true, custom));

        // 2 MB >= 2 MB -> GpuCompute
        Assert.Equal(ExecutionTarget.GpuCompute, HardwareArbiter.RouteWorkload(2 * 1024 * 1024, 1, true, custom));

        // 256 KB with 8 batches -> GpuCompute
        Assert.Equal(ExecutionTarget.GpuCompute, HardwareArbiter.RouteWorkload(256 * 1024, 8, true, custom));
    }

    [Theory]
    [InlineData(-1, 1)]
    [InlineData(-1024, 1)]
    public void RouteWorkload_NegativePayload_ThrowsArgumentOutOfRangeException(int payloadBytes, int batchCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(payloadBytes, batchCount));
    }

    [Theory]
    [InlineData(1024, 0)]
    [InlineData(1024, -1)]
    public void RouteWorkload_InvalidBatchCount_ThrowsArgumentOutOfRangeException(int payloadBytes, int batchCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(payloadBytes, batchCount));
    }
}
