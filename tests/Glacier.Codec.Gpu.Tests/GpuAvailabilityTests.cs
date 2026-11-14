using System;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Xunit;

namespace Glacier.Codec.Gpu.Tests;

public class GpuAvailabilityTests
{
    [Fact]
    public void GpuDevice_GetDeviceCount_DoesNotThrowWithoutHardware()
    {
        int count = GpuDevice.GetDeviceCount();
        Assert.True(count >= 0);

        if (!CuDriver.IsAvailable)
        {
            Assert.Equal(0, count);
            Assert.Throws<PlatformNotSupportedException>(() => GpuDevice.Create(0));
        }
    }
}
