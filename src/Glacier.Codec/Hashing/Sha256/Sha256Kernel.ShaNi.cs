namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Architectural notice and fallback routing for x86-64 SHA-NI.
/// </summary>
/// <remarks>
/// <para>
/// <b>Architectural Status:</b>
/// In .NET 10, the Intel and AMD SHA-NI hardware instruction set (<c>sha256rnds2</c>, <c>sha256msg1</c>, <c>sha256msg2</c>)
/// is not exposed in <see cref="System.Runtime.Intrinsics.X86"/> (unlike ARM64's <see cref="System.Runtime.Intrinsics.Arm.Sha256"/>).
/// </para>
/// <para>
/// Previous prototype iterations included a synthetic software emulation class (<c>Sha256Intrinsics</c>) that unpacked vector
/// elements into scalar registers via <c>GetElement(0..3)</c>, performed standard scalar bitwise logic, and repacked them
/// into <see cref="System.Runtime.Intrinsics.Vector128{T}"/>. Because that synthetic software wrapper degraded throughput
/// due to lane extraction overhead, it has been completely eliminated.
/// </para>
/// <para>
/// All SHA-256 compression on x86-64 is routed directly to <see cref="Sha256KernelScalar"/> via <see cref="Sha256Kernel.CompressBlocks"/>.
/// This class is preserved solely as an internal non-breaking redirect with zero overhead.
/// </para>
/// </remarks>
internal static class Sha256KernelShaNi
{
    /// <summary>
    /// Gets a value indicating whether hardware-accelerated x86 SHA-NI intrinsics are exposed by the .NET runtime.
    /// Always returns <see langword="false"/> in .NET 10 because <c>System.Runtime.Intrinsics.X86</c> does not expose SHA-NI instructions.
    /// </summary>
    public static bool IsSupported => false;

    /// <summary>
    /// Directs block compression directly to the high-performance unrolled scalar kernel <see cref="Sha256KernelScalar"/>.
    /// Zero heap allocations, zero BCL delegation.
    /// </summary>
    /// <param name="state">Reference to the 256-bit SHA-256 working state.</param>
    /// <param name="blocks">Contiguous span of 64-byte blocks.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressBlocks(ref Sha256State state, ReadOnlySpan<byte> blocks)
    {
        Sha256KernelScalar.CompressBlocks(ref state, blocks);
    }
}
