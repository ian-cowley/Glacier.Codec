#pragma warning disable SYSLIB5003 // Suppress experimental diagnostic for ARM Sve
namespace Glacier.Codec.Hardware;

using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Hardware capability tier for vector and cryptographic acceleration.
/// </summary>
public enum HardwareTier : byte
{
    /// <summary>
    /// Portable constant-time scalar fallback executing standard C# integer ALU.
    /// </summary>
    Tier2_ScalarFallback = 0,

    /// <summary>
    /// Mainstream vector SIMD (AVX2 + AES-NI + PCLMULQDQ on x86-64, AdvSimd on ARM64).
    /// </summary>
    Tier1_MainstreamVector = 1,

    /// <summary>
    /// Ultrawide vector SIMD (AVX-512 + VAES + VPCLMULQDQ + SHA-NI on x86-64, ARMv8 Cryptographic extensions on ARM64).
    /// </summary>
    Tier0_UltrawideVector = 2
}

/// <summary>
/// Statically queries and caches CPU vector capabilities, SIMD width, and cryptographic instruction extensions.
/// Compatible with .NET 10 Native AOT, cross-platform x86-64 and ARM64 architectures.
/// </summary>
public static class CpuCapabilities
{
    private static readonly bool s_hasShaNi;
    private static readonly bool s_hasVectorAes;
    private static readonly bool s_hasVpclmulqdq;

    static CpuCapabilities()
    {
        if (X86Base.IsSupported)
        {
            try
            {
                var (_, ebx, ecx, _) = X86Base.CpuId(7, 0);
                s_hasShaNi = (ebx & (1 << 29)) != 0;
                s_hasVectorAes = (ecx & (1 << 9)) != 0;
                s_hasVpclmulqdq = (ecx & (1 << 10)) != 0 || Pclmulqdq.V512.IsSupported;
            }
            catch
            {
                s_hasShaNi = false;
                s_hasVectorAes = false;
                s_hasVpclmulqdq = Pclmulqdq.V512.IsSupported;
            }
        }
    }

    // Architecture Information
    public static bool IsX86_64 => RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.X86;
    public static bool IsArm64 => RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
    public static int LogicalCoreCount => Environment.ProcessorCount;

    // x86-64 Vector & AVX-512 Extensions
    public static bool HasAvx512F => Avx512F.IsSupported;
    public static bool HasAvx512BW => Avx512BW.IsSupported;
    public static bool HasAvx512DQ => Avx512DQ.IsSupported;
    public static bool HasAvx512CD => Avx512CD.IsSupported;
    public static bool HasAvx512VL => Avx512F.VL.IsSupported;
    public static bool HasAvx512Vbmi => Avx512Vbmi.IsSupported;
    public static bool HasAvx512Vbmi2 => Avx512Vbmi2.IsSupported;
    public static bool HasAvx2 => Avx2.IsSupported;
    public static bool HasAvx => Avx.IsSupported;
    public static bool HasFma => Fma.IsSupported;

    // x86-64 Cryptographic Extensions
    public static bool HasAesNi => System.Runtime.Intrinsics.X86.Aes.IsSupported;
    public static bool HasPclmulqdq => Pclmulqdq.IsSupported;
    public static bool HasPclmulqdqV256 => Pclmulqdq.V256.IsSupported;
    public static bool HasPclmulqdqV512 => Pclmulqdq.V512.IsSupported;
    public static bool HasVpclmulqdq => s_hasVpclmulqdq;
    public static bool HasVectorAes => s_hasVectorAes;
    public static bool HasShaNi => s_hasShaNi;
    public static bool HasGfni => Gfni.IsSupported;
    public static bool HasGfniV512 => Gfni.V512.IsSupported;

    // ARM64 Extensions
    public static bool HasArm64AdvSimd => AdvSimd.Arm64.IsSupported;
    public static bool HasArm64Aes => System.Runtime.Intrinsics.Arm.Aes.Arm64.IsSupported;
    public static bool HasArm64Sha256 => System.Runtime.Intrinsics.Arm.Sha256.Arm64.IsSupported;
    public static bool HasArm64Sha1 => System.Runtime.Intrinsics.Arm.Sha1.Arm64.IsSupported;
    public static bool HasArm64Crc32 => System.Runtime.Intrinsics.Arm.Crc32.Arm64.IsSupported;
    public static bool HasArm64Dp => Dp.Arm64.IsSupported;
    public static bool HasArm64Sve => Sve.IsSupported;

    // Generic Hardware Acceleration Width
    public static bool HasVector512 => Vector512.IsHardwareAccelerated;
    public static bool HasVector256 => Vector256.IsHardwareAccelerated;
    public static bool HasVector128 => Vector128.IsHardwareAccelerated;

    /// <summary>
    /// Gets the highest available hardware execution tier on this host CPU.
    /// </summary>
    public static HardwareTier DetectedTier
    {
        get
        {
            if (IsX86_64)
            {
                if (HasAvx512F && HasAvx512BW && (HasVectorAes || HasAesNi))
                {
                    return HardwareTier.Tier0_UltrawideVector;
                }
                if (HasAvx2 && HasAesNi)
                {
                    return HardwareTier.Tier1_MainstreamVector;
                }
            }
            else if (IsArm64)
            {
                if (HasArm64AdvSimd && HasArm64Aes && HasArm64Sha256)
                {
                    return HardwareTier.Tier0_UltrawideVector;
                }
                if (HasArm64AdvSimd)
                {
                    return HardwareTier.Tier1_MainstreamVector;
                }
            }

            return HardwareTier.Tier2_ScalarFallback;
        }
    }
}
