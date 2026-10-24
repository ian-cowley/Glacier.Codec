namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Runtime.CompilerServices;
using Glacier.Codec.Hardware;

/// <summary>
/// High-throughput compression kernel dispatcher for SHA-256 routing between ARM64 hardware intrinsics and unrolled scalar execution.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hardware Acceleration Status:</b>
/// <list type="bullet">
/// <item>
/// <description><b>ARM64:</b> Dispatches to <see cref="Sha256KernelArm64"/> utilizing genuine hardware intrinsics
/// (<see cref="System.Runtime.Intrinsics.Arm.Sha256"/>) from the ARMv8 Cryptographic Extensions.</description>
/// </item>
/// <item>
/// <description><b>x86-64 / AMD64:</b> As of .NET 10, the x86 SHA-NI instruction set (<c>sha256rnds2</c>, <c>sha256msg1</c>, <c>sha256msg2</c>)
/// is not exposed in <c>System.Runtime.Intrinsics.X86</c>. To eliminate performance degradation caused by synthetic vector unpacking
/// facades (<c>Vector128.GetElement</c> / <c>Vector128.Create</c>), all x86-64 workloads are routed directly to the highly optimized,
/// fully unrolled 64-round pure C# scalar kernel (<see cref="Sha256KernelScalar"/>).</description>
/// </item>
/// <item>
/// <description><b>Fallback / Other Architectures:</b> Routed directly to <see cref="Sha256KernelScalar"/>.</description>
/// </item>
/// </list>
/// </para>
/// <para>
/// Guarantees zero BCL delegation, zero heap allocations, and 100% Native AOT compatibility across all execution paths.
/// </para>
/// </remarks>
internal static class Sha256Kernel
{
    /// <summary>
    /// Compresses a contiguous sequence of 64-byte blocks into the SHA-256 state with zero heap allocations.
    /// Dispatches to ARM64 hardware intrinsics when available, falling back to unrolled scalar execution.
    /// </summary>
    /// <param name="state">Reference to the 256-bit SHA-256 working state.</param>
    /// <param name="blocks">Contiguous span of 64-byte blocks (length must be a multiple of 64).</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressBlocks(ref Sha256State state, ReadOnlySpan<byte> blocks)
    {
        // ARM64 hardware-accelerated path via ARMv8 Cryptographic Extensions (System.Runtime.Intrinsics.Arm.Sha256)
        if (CpuCapabilities.IsArm64 && CpuCapabilities.HasArm64Sha256)
        {
            Sha256KernelArm64.CompressBlocks(ref state, blocks);
            return;
        }

        // x86-64 and scalar fallback path:
        // .NET 10 does not currently expose Intel/AMD SHA-NI intrinsics under System.Runtime.Intrinsics.X86.
        // Direct unrolled scalar execution outperforms synthetic Vector128 software unpacking loops.
        Sha256KernelScalar.CompressBlocks(ref state, blocks);
    }

    /// <summary>
    /// Compresses a single 64-byte block into the SHA-256 state.
    /// </summary>
    /// <param name="state">Reference to the 256-bit SHA-256 working state.</param>
    /// <param name="block">Span of at least 64 bytes representing the message block.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressBlock(ref Sha256State state, ReadOnlySpan<byte> block)
    {
        CompressBlocks(ref state, block.Slice(0, 64));
    }
}
