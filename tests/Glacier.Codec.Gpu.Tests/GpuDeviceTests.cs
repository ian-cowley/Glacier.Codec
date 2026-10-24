using System;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Xunit;

namespace Glacier.Codec.Gpu.Tests;

public class GpuDeviceTests
{
    [Fact]
    public void GpuDriver_IsAvailable_OnCudaHardware()
    {
        if (!CuDriver.IsAvailable)
        {
            // Skip when running in non-GPU CI runners
            return;
        }

        int count = GpuDevice.GetDeviceCount();
        Assert.True(count >= 1, "Expected at least 1 CUDA GPU device.");

        using var device = GpuDevice.Create(0);
        Assert.NotNull(device.DeviceName);
        Assert.StartsWith("sm_", device.ComputeCapability);
        Assert.True(device.MultiprocessorCount > 0);
        Assert.True(device.TotalMemoryBytes > 0);

        // Verification of RTX 4060 or Ampere/Ada
        Assert.True(device.ContextHandle != IntPtr.Zero);
    }
}
