namespace Glacier.Codec.Tests;

using System;
using System.Runtime.InteropServices;
using Glacier.Codec.Hardware;
using Xunit;

public sealed class CpuCapabilitiesTests
{
    [Fact]
    public void LogicalCoreCount_MustBePositive()
    {
        Assert.True(CpuCapabilities.LogicalCoreCount > 0, "Host must have at least 1 logical core.");
        Assert.Equal(Environment.ProcessorCount, CpuCapabilities.LogicalCoreCount);
    }

    [Fact]
    public void Architecture_MustBeMutuallyExclusive()
    {
        if (RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.X86)
        {
            Assert.True(CpuCapabilities.IsX86_64);
            Assert.False(CpuCapabilities.IsArm64);
        }
        else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            Assert.False(CpuCapabilities.IsX86_64);
            Assert.True(CpuCapabilities.IsArm64);
        }
    }

    [Fact]
    public void Architecture_CrossPlatformInvariants_DoNotThrow()
    {
        if (CpuCapabilities.IsX86_64)
        {
            // On x86-64, ARM properties must evaluate to false without throwing exceptions
            Assert.False(CpuCapabilities.HasArm64AdvSimd);
            Assert.False(CpuCapabilities.HasArm64Aes);
            Assert.False(CpuCapabilities.HasArm64Sha256);
            Assert.False(CpuCapabilities.HasArm64Sha1);
            Assert.False(CpuCapabilities.HasArm64Crc32);
            Assert.False(CpuCapabilities.HasArm64Dp);
            Assert.False(CpuCapabilities.HasArm64Sve);
        }
        else if (CpuCapabilities.IsArm64)
        {
            // On ARM64, x86 properties must evaluate to false without throwing exceptions
            Assert.False(CpuCapabilities.HasAvx512F);
            Assert.False(CpuCapabilities.HasAvx512BW);
            Assert.False(CpuCapabilities.HasAvx2);
            Assert.False(CpuCapabilities.HasAesNi);
            Assert.False(CpuCapabilities.HasVectorAes);
            Assert.False(CpuCapabilities.HasVpclmulqdq);
            Assert.False(CpuCapabilities.HasShaNi);
        }
    }

    [Fact]
    public void DetectedTier_ReturnsValidEnum()
    {
        HardwareTier tier = CpuCapabilities.DetectedTier;
        Assert.True(Enum.IsDefined(typeof(HardwareTier), tier));

        if (CpuCapabilities.HasAvx512F && CpuCapabilities.HasAvx512BW && (CpuCapabilities.HasVectorAes || CpuCapabilities.HasAesNi))
        {
            Assert.Equal(HardwareTier.Tier0_UltrawideVector, tier);
        }
        else if (CpuCapabilities.HasAvx2 && CpuCapabilities.HasAesNi)
        {
            Assert.Equal(HardwareTier.Tier1_MainstreamVector, tier);
        }
    }

    [Fact]
    public void GenericVectorWidth_IsConsistentWithIntrinsics()
    {
        if (CpuCapabilities.HasAvx512F)
        {
            Assert.True(CpuCapabilities.HasVector512);
        }
        if (CpuCapabilities.HasAvx2)
        {
            Assert.True(CpuCapabilities.HasVector256);
        }
    }
}
