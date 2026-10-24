namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Pure constant-time 64-bit limb arithmetic kernel for Poly1305 (RFC 8439).
/// Evaluates polynomials modulo 2^130 - 5 with clamped r and 128-bit limb products.
/// </summary>
internal static class Poly1305Kernel
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ClampKey(ReadOnlySpan<byte> key, out ulong r0, out ulong r1, out ulong s1)
    {
        r0 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(0, 8)) & 0x0ffffffc0fffffffUL;
        r1 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(8, 8)) & 0x0ffffffc0ffffffcUL;
        s1 = r1 + (r1 >> 2); // 5/4 * r1
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ProcessBlock(
        ref ulong h0,
        ref ulong h1,
        ref ulong h2,
        ulong m0,
        ulong m1,
        ulong padBit,
        ulong r0,
        ulong r1,
        ulong s1)
    {
        // 1. h += m (with padBit at bit 128)
        UInt128 t0 = (UInt128)h0 + m0;
        h0 = (ulong)t0;
        UInt128 t1 = (UInt128)h1 + (ulong)(t0 >> 64) + m1;
        h1 = (ulong)t1;
        h2 += (ulong)(t1 >> 64) + padBit;

        // 2. Cross-products modulo 2^130 - 5
        UInt128 d0 = ((UInt128)h0 * r0) + ((UInt128)h1 * s1);
        UInt128 d1 = ((UInt128)h0 * r1) + ((UInt128)h1 * r0) + ((UInt128)h2 * s1);
        h2 = h2 * (ulong)r0;

        // 3. Carry propagation
        h0 = (ulong)d0;
        d1 += (d0 >> 64);
        h1 = (ulong)d1;
        h2 += (ulong)(d1 >> 64);

        // 4. Modulo 2^130 - 5 fold (first stage)
        ulong c = (h2 >> 2) * 5;
        h2 &= 3;

        UInt128 c0 = (UInt128)h0 + c;
        h0 = (ulong)c0;
        UInt128 c1 = (UInt128)h1 + (ulong)(c0 >> 64);
        h1 = (ulong)c1;
        h2 += (ulong)(c1 >> 64);

        // 5. Modulo 2^130 - 5 fold (second stage to ensure h2 <= 3)
        ulong c2 = (h2 >> 2) * 5;
        h2 &= 3;

        UInt128 cc0 = (UInt128)h0 + c2;
        h0 = (ulong)cc0;
        UInt128 cc1 = (UInt128)h1 + (ulong)(cc0 >> 64);
        h1 = (ulong)cc1;
        h2 += (ulong)(cc1 >> 64);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void FinalizeTag(
        ref ulong h0,
        ref ulong h1,
        ref ulong h2,
        ReadOnlySpan<byte> key,
        Span<byte> tag)
    {
        // 1. Fully reduce modulo 2^130 - 5 by checking if (h + 5) >= 2^130
        UInt128 g0_128 = (UInt128)h0 + 5;
        ulong g0 = (ulong)g0_128;
        UInt128 g1_128 = (UInt128)h1 + (ulong)(g0_128 >> 64);
        ulong g1 = (ulong)g1_128;
        ulong g2 = h2 + (ulong)(g1_128 >> 64);

        ulong mask = (ulong)-(long)(g2 >> 2); // 0xFFFFFFFFFFFFFFFF if g2 >= 4, else 0
        h0 = (g0 & mask) | (h0 & ~mask);
        h1 = (g1 & mask) | (h1 & ~mask);

        // 2. Add secret key s modulo 2^128
        ulong s0 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(16, 8));
        ulong s1_val = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(24, 8));

        UInt128 final0 = (UInt128)h0 + s0;
        h0 = (ulong)final0;
        h1 = h1 + s1_val + (ulong)(final0 >> 64); // Upper carry modulo 2^128 discarded

        // 3. Serialize 16-byte tag little-endian
        BinaryPrimitives.WriteUInt64LittleEndian(tag.Slice(0, 8), h0);
        BinaryPrimitives.WriteUInt64LittleEndian(tag.Slice(8, 8), h1);
    }

    public static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        ClampKey(key, out ulong r0, out ulong r1, out ulong s1);

        ulong h0 = 0, h1 = 0, h2 = 0;
        int offset = 0;
        int length = message.Length;

        // Process full 16-byte blocks
        while (offset + 16 <= length)
        {
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(offset, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(offset + 8, 8));
            ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 1, r0, r1, s1);
            offset += 16;
        }

        // Process partial last block if any
        if (offset < length)
        {
            Span<byte> partial = stackalloc byte[16];
            message.Slice(offset).CopyTo(partial);
            partial[length - offset] = 0x01; // RFC 8439 pad byte

            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(partial.Slice(0, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(partial.Slice(8, 8));
            ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 0, r0, r1, s1);
        }

        FinalizeTag(ref h0, ref h1, ref h2, key, tag);
    }
}
