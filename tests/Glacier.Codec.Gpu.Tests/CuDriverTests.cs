using System;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Xunit;

namespace Glacier.Codec.Gpu.Tests;

public class CuDriverTests
{
    [Fact]
    public void CuDriver_IsAvailableProperty_IsConsistentWithDeviceCount()
    {
        bool available = CuDriver.IsAvailable;
        int count = GpuDevice.GetDeviceCount();

        if (!available)
        {
            Assert.Equal(0, count);
        }
        else
        {
            Assert.True(count >= 0);
        }
    }

    [Fact]
    public void CuDriver_Check_ThrowsOnlyOnNonZeroErrorCode()
    {
        CuDriver.Check(0, "noop");
        var ex = Assert.Throws<InvalidOperationException>(() => CuDriver.Check(222, "testOp"));
        Assert.Contains("222", ex.Message);
        Assert.Contains("testOp", ex.Message);
    }

    [Fact]
    [Trait("Category", "Gpu")]
    public void CuDriver_DeviceTelemetry_WorksOnAvailableCudaGpu()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var dev = GpuDevice.Create(0);
        Assert.False(string.IsNullOrWhiteSpace(dev.DeviceName));
        Assert.StartsWith("sm_", dev.ComputeCapability);
        Assert.True(dev.MultiprocessorCount > 0);
        Assert.True(dev.TotalMemoryBytes > 0);
    }
}
