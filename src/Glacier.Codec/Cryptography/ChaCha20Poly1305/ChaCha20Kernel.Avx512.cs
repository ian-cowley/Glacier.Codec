namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 acceleration kernel for ChaCha20 quarter-rounds.
/// </summary>
internal static class ChaCha20KernelAvx512
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(
        ref Vector512<uint> a,
        ref Vector512<uint> b,
        ref Vector512<uint> c,
        ref Vector512<uint> d)
    {
        a += b; d = Avx512F.RotateLeft(d ^ a, 16);
        c += d; b = Avx512F.RotateLeft(b ^ c, 12);
        a += b; d = Avx512F.RotateLeft(d ^ a, 8);
        c += d; b = Avx512F.RotateLeft(b ^ c, 7);
    }
}
