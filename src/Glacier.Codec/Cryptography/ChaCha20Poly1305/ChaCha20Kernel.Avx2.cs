namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

/// <summary>
/// Vectorized SIMD ChaCha20 quarter-rounds and block generation via Vector128.
/// </summary>
internal static class ChaCha20KernelAvx2
{
    private const uint C0 = 0x61707865;
    private const uint C1 = 0x3320646e;
    private const uint C2 = 0x79622d32;
    private const uint C3 = 0x6b206574;

    private static readonly Vector128<uint> Permute1 = Vector128.Create(1u, 2u, 3u, 0u);
    private static readonly Vector128<uint> Permute2 = Vector128.Create(2u, 3u, 0u, 1u);
    private static readonly Vector128<uint> Permute3 = Vector128.Create(3u, 0u, 1u, 2u);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotL(Vector128<uint> v, int shift) =>
        (v << shift) | (v >>> (32 - shift));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(
        ref Vector128<uint> a,
        ref Vector128<uint> b,
        ref Vector128<uint> c,
        ref Vector128<uint> d)
    {
        a += b; d = RotL(d ^ a, 16);
        c += d; b = RotL(b ^ c, 12);
        a += b; d = RotL(d ^ a, 8);
        c += d; b = RotL(b ^ c, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void GenerateBlock128(
        ReadOnlySpan<byte> key,
        uint counter,
        ReadOnlySpan<byte> nonce,
        Span<byte> destination)
    {
        uint k0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
        uint k1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
        uint k2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
        uint k3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
        uint k4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
        uint k5 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
        uint k6 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
        uint k7 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));

        uint n0 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
        uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
        uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));

        Vector128<uint> orig0 = Vector128.Create(C0, C1, C2, C3);
        Vector128<uint> orig1 = Vector128.Create(k0, k1, k2, k3);
        Vector128<uint> orig2 = Vector128.Create(k4, k5, k6, k7);
        Vector128<uint> orig3 = Vector128.Create(counter, n0, n1, n2);

        Vector128<uint> r0 = orig0;
        Vector128<uint> r1 = orig1;
        Vector128<uint> r2 = orig2;
        Vector128<uint> r3 = orig3;

        for (int r = 0; r < 10; r++)
        {
            // Column round
            QuarterRound(ref r0, ref r1, ref r2, ref r3);

            // Diagonal round: permute rows 1, 2, 3
            r1 = Vector128.Shuffle(r1, Permute1);
            r2 = Vector128.Shuffle(r2, Permute2);
            r3 = Vector128.Shuffle(r3, Permute3);

            QuarterRound(ref r0, ref r1, ref r2, ref r3);

            // Inverse permute rows 1, 2, 3
            r1 = Vector128.Shuffle(r1, Permute3);
            r2 = Vector128.Shuffle(r2, Permute2);
            r3 = Vector128.Shuffle(r3, Permute1);
        }

        (r0 + orig0).AsByte().CopyTo(destination.Slice(0, 16));
        (r1 + orig1).AsByte().CopyTo(destination.Slice(16, 16));
        (r2 + orig2).AsByte().CopyTo(destination.Slice(32, 16));
        (r3 + orig3).AsByte().CopyTo(destination.Slice(48, 16));
    }
}
