namespace Glacier.Codec.Cryptography.EllipticCurve;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Constant-time GF(2^255 - 19) field arithmetic using 5x51-bit unsigned limbs.
/// Zero secret-dependent branches and zero table lookups.
/// </summary>
internal struct FieldElement25519
{
    private const ulong Mask51 = 0x7FFFFFFFFFFFFUL;

    public ulong H0, H1, H2, H3, H4;

    public static FieldElement25519 Zero => default;

    public static FieldElement25519 One => new() { H0 = 1 };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement25519 FromBytes(ReadOnlySpan<byte> s)
    {
        ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(0, 8));
        ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(8, 8));
        ulong t2 = BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(16, 8));
        // RFC 7748 Section 5: ignore bit 255 of the u-coordinate
        ulong t3 = BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(24, 8)) & 0x7FFFFFFFFFFFFFFFUL;

        return new FieldElement25519
        {
            H0 = t0 & Mask51,
            H1 = ((t0 >> 51) | (t1 << 13)) & Mask51,
            H2 = ((t1 >> 38) | (t2 << 26)) & Mask51,
            H3 = ((t2 >> 25) | (t3 << 39)) & Mask51,
            H4 = (t3 >> 12) & Mask51
        };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CarryReduce()
    {
        H1 += H0 >> 51; H0 &= Mask51;
        H2 += H1 >> 51; H1 &= Mask51;
        H3 += H2 >> 51; H2 &= Mask51;
        H4 += H3 >> 51; H3 &= Mask51;
        H0 += (H4 >> 51) * 19UL; H4 &= Mask51;
        H1 += H0 >> 51; H0 &= Mask51;
    }

    public readonly void ToBytes(Span<byte> destination)
    {
        FieldElement25519 t = this;
        t.CarryReduce();

        // Branchless canonical reduction mod p = 2^255 - 19:
        // q = 1 iff v >= 2^255 - 19 (i.e. v + 19 >= 2^255), else 0.
        ulong q = (t.H0 + 19UL) >> 51;
        q = (t.H1 + q) >> 51;
        q = (t.H2 + q) >> 51;
        q = (t.H3 + q) >> 51;
        q = (t.H4 + q) >> 51;

        t.H0 += 19UL * q;
        ulong c = t.H0 >> 51; t.H0 &= Mask51;
        t.H1 += c; c = t.H1 >> 51; t.H1 &= Mask51;
        t.H2 += c; c = t.H2 >> 51; t.H2 &= Mask51;
        t.H3 += c; c = t.H3 >> 51; t.H3 &= Mask51;
        t.H4 += c; t.H4 &= Mask51;

        ulong w0 = t.H0 | (t.H1 << 51);
        ulong w1 = (t.H1 >> 13) | (t.H2 << 38);
        ulong w2 = (t.H2 >> 26) | (t.H3 << 25);
        ulong w3 = (t.H3 >> 39) | (t.H4 << 12);

        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(0, 8), w0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8, 8), w1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(16, 8), w2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(24, 8), w3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement25519 Add(in FieldElement25519 a, in FieldElement25519 b)
    {
        var r = new FieldElement25519
        {
            H0 = a.H0 + b.H0,
            H1 = a.H1 + b.H1,
            H2 = a.H2 + b.H2,
            H3 = a.H3 + b.H3,
            H4 = a.H4 + b.H4
        };
        r.CarryReduce();
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement25519 Sub(in FieldElement25519 a, in FieldElement25519 b)
    {
        // Add 2*p = 2*(2^255 - 19) before subtracting so unsigned limbs never underflow
        // (b limbs are < 2^51 after CarryReduce, or < 2^52 before). Using 4*p guarantees positivity even for unreduced limbs < 2^53.
        var r = new FieldElement25519
        {
            H0 = a.H0 + 0x1FFFFFFFFFFFB4UL - b.H0,
            H1 = a.H1 + 0x1FFFFFFFFFFFFCUL - b.H1,
            H2 = a.H2 + 0x1FFFFFFFFFFFFCUL - b.H2,
            H3 = a.H3 + 0x1FFFFFFFFFFFFCUL - b.H3,
            H4 = a.H4 + 0x1FFFFFFFFFFFFCUL - b.H4
        };
        r.CarryReduce();
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static FieldElement25519 Mul(in FieldElement25519 a, in FieldElement25519 b)
    {
        ulong a0 = a.H0, a1 = a.H1, a2 = a.H2, a3 = a.H3, a4 = a.H4;
        ulong b0 = b.H0, b1 = b.H1, b2 = b.H2, b3 = b.H3, b4 = b.H4;

        ulong b1_19 = b1 * 19UL;
        ulong b2_19 = b2 * 19UL;
        ulong b3_19 = b3 * 19UL;
        ulong b4_19 = b4 * 19UL;

        UInt128 t0 = (UInt128)a0 * b0 + (UInt128)a1 * b4_19 + (UInt128)a2 * b3_19 + (UInt128)a3 * b2_19 + (UInt128)a4 * b1_19;
        UInt128 t1 = (UInt128)a0 * b1 + (UInt128)a1 * b0    + (UInt128)a2 * b4_19 + (UInt128)a3 * b3_19 + (UInt128)a4 * b2_19;
        UInt128 t2 = (UInt128)a0 * b2 + (UInt128)a1 * b1    + (UInt128)a2 * b0    + (UInt128)a3 * b4_19 + (UInt128)a4 * b3_19;
        UInt128 t3 = (UInt128)a0 * b3 + (UInt128)a1 * b2    + (UInt128)a2 * b1    + (UInt128)a3 * b0    + (UInt128)a4 * b4_19;
        UInt128 t4 = (UInt128)a0 * b4 + (UInt128)a1 * b3    + (UInt128)a2 * b2    + (UInt128)a3 * b1    + (UInt128)a4 * b0;

        t1 += t0 >> 51; ulong r0 = (ulong)t0 & Mask51;
        t2 += t1 >> 51; ulong r1 = (ulong)t1 & Mask51;
        t3 += t2 >> 51; ulong r2 = (ulong)t2 & Mask51;
        t4 += t3 >> 51; ulong r3 = (ulong)t3 & Mask51;

        ulong carry = (ulong)(t4 >> 51);
        ulong r4 = (ulong)t4 & Mask51;

        r0 += carry * 19UL;
        r1 += r0 >> 51;
        r0 &= Mask51;

        return new FieldElement25519 { H0 = r0, H1 = r1, H2 = r2, H3 = r3, H4 = r4 };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement25519 Square(in FieldElement25519 a) => Mul(in a, in a);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement25519 Mul121665(in FieldElement25519 a)
    {
        const ulong A24 = 121665UL;
        UInt128 t0 = (UInt128)a.H0 * A24;
        UInt128 t1 = (UInt128)a.H1 * A24 + (t0 >> 51);
        UInt128 t2 = (UInt128)a.H2 * A24 + (t1 >> 51);
        UInt128 t3 = (UInt128)a.H3 * A24 + (t2 >> 51);
        UInt128 t4 = (UInt128)a.H4 * A24 + (t3 >> 51);

        ulong r0 = ((ulong)t0 & Mask51) + (ulong)(t4 >> 51) * 19UL;
        ulong r1 = ((ulong)t1 & Mask51) + (r0 >> 51);
        r0 &= Mask51;

        return new FieldElement25519
        {
            H0 = r0,
            H1 = r1,
            H2 = (ulong)t2 & Mask51,
            H3 = (ulong)t3 & Mask51,
            H4 = (ulong)t4 & Mask51
        };
    }

    public static FieldElement25519 Invert(in FieldElement25519 z)
    {
        // Fixed addition chain for z^(p - 2) = z^(2^255 - 21) mod (2^255 - 19)
        FieldElement25519 z2 = Square(in z);
        FieldElement25519 z9 = Square(in z2);
        z9 = Square(in z9);
        z9 = Mul(in z9, in z);         // z^9
        FieldElement25519 z11 = Mul(in z9, in z2); // z^11

        FieldElement25519 t = Square(in z11);
        FieldElement25519 z5_0 = Mul(in t, in z9); // z^(2^5 - 1)

        t = Square(in z5_0);
        for (int i = 1; i < 5; i++) t = Square(in t);
        FieldElement25519 z10_0 = Mul(in t, in z5_0); // z^(2^10 - 1)

        t = Square(in z10_0);
        for (int i = 1; i < 10; i++) t = Square(in t);
        FieldElement25519 z20_0 = Mul(in t, in z10_0); // z^(2^20 - 1)

        t = Square(in z20_0);
        for (int i = 1; i < 20; i++) t = Square(in t);
        t = Mul(in t, in z20_0); // z^(2^40 - 1)

        for (int i = 0; i < 10; i++) t = Square(in t);
        FieldElement25519 z50_0 = Mul(in t, in z10_0); // z^(2^50 - 1)

        t = Square(in z50_0);
        for (int i = 1; i < 50; i++) t = Square(in t);
        FieldElement25519 z100_0 = Mul(in t, in z50_0); // z^(2^100 - 1)

        t = Square(in z100_0);
        for (int i = 1; i < 100; i++) t = Square(in t);
        t = Mul(in t, in z100_0); // z^(2^200 - 1)

        for (int i = 0; i < 50; i++) t = Square(in t);
        t = Mul(in t, in z50_0); // z^(2^250 - 1)

        for (int i = 0; i < 5; i++) t = Square(in t);
        return Mul(in t, in z11); // z^(2^255 - 21)
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CSwap(ulong swap, ref FieldElement25519 a, ref FieldElement25519 b)
    {
        ulong mask = 0UL - (swap & 1UL);
        ulong d0 = mask & (a.H0 ^ b.H0); a.H0 ^= d0; b.H0 ^= d0;
        ulong d1 = mask & (a.H1 ^ b.H1); a.H1 ^= d1; b.H1 ^= d1;
        ulong d2 = mask & (a.H2 ^ b.H2); a.H2 ^= d2; b.H2 ^= d2;
        ulong d3 = mask & (a.H3 ^ b.H3); a.H3 ^= d3; b.H3 ^= d3;
        ulong d4 = mask & (a.H4 ^ b.H4); a.H4 ^= d4; b.H4 ^= d4;
    }
}
