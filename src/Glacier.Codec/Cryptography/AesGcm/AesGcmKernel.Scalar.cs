namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// Pure C# constant-time scalar fallback kernel for AES-256 block encryption and GF(2^128) GHASH.
/// Uses a bitsliced GF(2^8) algebraic S-box (zero lookup tables, zero secret-dependent branches)
/// and branchless shift-and-XOR GHASH.
/// </summary>
internal static class AesGcmKernelScalar
{
    private static ReadOnlySpan<byte> Rcon => [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Gf256Square(
        uint x0, uint x1, uint x2, uint x3, uint x4, uint x5, uint x6, uint x7,
        out uint r0, out uint r1, out uint r2, out uint r3, out uint r4, out uint r5, out uint r6, out uint r7)
    {
        r0 = x0 ^ x4 ^ x6;
        r1 = x4 ^ x6 ^ x7;
        r2 = x1 ^ x5;
        r3 = x4 ^ x5 ^ x6 ^ x7;
        r4 = x2 ^ x4 ^ x7;
        r5 = x5 ^ x6;
        r6 = x3 ^ x5;
        r7 = x6 ^ x7;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Gf256Mul(
        uint a0, uint a1, uint a2, uint a3, uint a4, uint a5, uint a6, uint a7,
        uint b0, uint b1, uint b2, uint b3, uint b4, uint b5, uint b6, uint b7,
        out uint r0, out uint r1, out uint r2, out uint r3, out uint r4, out uint r5, out uint r6, out uint r7)
    {
        r0 = a0 & b0; r1 = a1 & b0; r2 = a2 & b0; r3 = a3 & b0;
        r4 = a4 & b0; r5 = a5 & b0; r6 = a6 & b0; r7 = a7 & b0;

        uint t;
        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b1; r1 ^= a1 & b1; r2 ^= a2 & b1; r3 ^= a3 & b1;
        r4 ^= a4 & b1; r5 ^= a5 & b1; r6 ^= a6 & b1; r7 ^= a7 & b1;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b2; r1 ^= a1 & b2; r2 ^= a2 & b2; r3 ^= a3 & b2;
        r4 ^= a4 & b2; r5 ^= a5 & b2; r6 ^= a6 & b2; r7 ^= a7 & b2;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b3; r1 ^= a1 & b3; r2 ^= a2 & b3; r3 ^= a3 & b3;
        r4 ^= a4 & b3; r5 ^= a5 & b3; r6 ^= a6 & b3; r7 ^= a7 & b3;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b4; r1 ^= a1 & b4; r2 ^= a2 & b4; r3 ^= a3 & b4;
        r4 ^= a4 & b4; r5 ^= a5 & b4; r6 ^= a6 & b4; r7 ^= a7 & b4;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b5; r1 ^= a1 & b5; r2 ^= a2 & b5; r3 ^= a3 & b5;
        r4 ^= a4 & b5; r5 ^= a5 & b5; r6 ^= a6 & b5; r7 ^= a7 & b5;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b6; r1 ^= a1 & b6; r2 ^= a2 & b6; r3 ^= a3 & b6;
        r4 ^= a4 & b6; r5 ^= a5 & b6; r6 ^= a6 & b6; r7 ^= a7 & b6;

        t = a7; a7 = a6; a6 = a5; a5 = a4; a4 = a3 ^ t; a3 = a2 ^ t; a2 = a1; a1 = a0 ^ t; a0 = t;
        r0 ^= a0 & b7; r1 ^= a1 & b7; r2 ^= a2 & b7; r3 ^= a3 & b7;
        r4 ^= a4 & b7; r5 ^= a5 & b7; r6 ^= a6 & b7; r7 ^= a7 & b7;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SubBytesBitsliced(
        ref uint x0, ref uint x1, ref uint x2, ref uint x3,
        ref uint x4, ref uint x5, ref uint x6, ref uint x7,
        uint affineMask)
    {
        // Compute x^254 in GF(2^8) = x^(-1) (with 0 -> 0)
        Gf256Square(x0, x1, x2, x3, x4, x5, x6, x7,
            out uint s2_0, out uint s2_1, out uint s2_2, out uint s2_3,
            out uint s2_4, out uint s2_5, out uint s2_6, out uint s2_7);

        Gf256Mul(s2_0, s2_1, s2_2, s2_3, s2_4, s2_5, s2_6, s2_7,
            x0, x1, x2, x3, x4, x5, x6, x7,
            out uint s3_0, out uint s3_1, out uint s3_2, out uint s3_3,
            out uint s3_4, out uint s3_5, out uint s3_6, out uint s3_7);

        Gf256Square(s3_0, s3_1, s3_2, s3_3, s3_4, s3_5, s3_6, s3_7,
            out uint s6_0, out uint s6_1, out uint s6_2, out uint s6_3,
            out uint s6_4, out uint s6_5, out uint s6_6, out uint s6_7);

        Gf256Square(s6_0, s6_1, s6_2, s6_3, s6_4, s6_5, s6_6, s6_7,
            out uint s12_0, out uint s12_1, out uint s12_2, out uint s12_3,
            out uint s12_4, out uint s12_5, out uint s12_6, out uint s12_7);

        Gf256Mul(s12_0, s12_1, s12_2, s12_3, s12_4, s12_5, s12_6, s12_7,
            s2_0, s2_1, s2_2, s2_3, s2_4, s2_5, s2_6, s2_7,
            out uint s14_0, out uint s14_1, out uint s14_2, out uint s14_3,
            out uint s14_4, out uint s14_5, out uint s14_6, out uint s14_7);

        Gf256Mul(s12_0, s12_1, s12_2, s12_3, s12_4, s12_5, s12_6, s12_7,
            s3_0, s3_1, s3_2, s3_3, s3_4, s3_5, s3_6, s3_7,
            out uint t0, out uint t1, out uint t2, out uint t3,
            out uint t4, out uint t5, out uint t6, out uint t7);

        // Square 4 times: x^15 -> x^240
        Gf256Square(t0, t1, t2, t3, t4, t5, t6, t7, out t0, out t1, out t2, out t3, out t4, out t5, out t6, out t7);
        Gf256Square(t0, t1, t2, t3, t4, t5, t6, t7, out t0, out t1, out t2, out t3, out t4, out t5, out t6, out t7);
        Gf256Square(t0, t1, t2, t3, t4, t5, t6, t7, out t0, out t1, out t2, out t3, out t4, out t5, out t6, out t7);
        Gf256Square(t0, t1, t2, t3, t4, t5, t6, t7, out t0, out t1, out t2, out t3, out t4, out t5, out t6, out t7);

        Gf256Mul(t0, t1, t2, t3, t4, t5, t6, t7,
            s14_0, s14_1, s14_2, s14_3, s14_4, s14_5, s14_6, s14_7,
            out uint y0, out uint y1, out uint y2, out uint y3,
            out uint y4, out uint y5, out uint y6, out uint y7);

        // FIPS 197 affine transformation (XOR 0x63)
        x0 = y0 ^ y4 ^ y5 ^ y6 ^ y7 ^ affineMask;
        x1 = y1 ^ y5 ^ y6 ^ y7 ^ y0 ^ affineMask;
        x2 = y2 ^ y6 ^ y7 ^ y0 ^ y1;
        x3 = y3 ^ y7 ^ y0 ^ y1 ^ y2;
        x4 = y4 ^ y0 ^ y1 ^ y2 ^ y3;
        x5 = y5 ^ y1 ^ y2 ^ y3 ^ y4 ^ affineMask;
        x6 = y6 ^ y2 ^ y3 ^ y4 ^ y5 ^ affineMask;
        x7 = y7 ^ y3 ^ y4 ^ y5 ^ y6;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static byte SubByteConstantTime(byte val)
    {
        uint x0 = (uint)(val & 1);
        uint x1 = (uint)((val >> 1) & 1);
        uint x2 = (uint)((val >> 2) & 1);
        uint x3 = (uint)((val >> 3) & 1);
        uint x4 = (uint)((val >> 4) & 1);
        uint x5 = (uint)((val >> 5) & 1);
        uint x6 = (uint)((val >> 6) & 1);
        uint x7 = (uint)((val >> 7) & 1);

        SubBytesBitsliced(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, affineMask: 1u);

        return (byte)(x0 | (x1 << 1) | (x2 << 2) | (x3 << 3) | (x4 << 4) | (x5 << 5) | (x6 << 6) | (x7 << 7));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SubWordBitsliced(byte b0, byte b1, byte b2, byte b3, out byte r0, out byte r1, out byte r2, out byte r3)
    {
        uint x0 = (uint)((b0 & 1) | ((b1 & 1) << 1) | ((b2 & 1) << 2) | ((b3 & 1) << 3));
        uint x1 = (uint)(((b0 >> 1) & 1) | (((b1 >> 1) & 1) << 1) | (((b2 >> 1) & 1) << 2) | (((b3 >> 1) & 1) << 3));
        uint x2 = (uint)(((b0 >> 2) & 1) | (((b1 >> 2) & 1) << 1) | (((b2 >> 2) & 1) << 2) | (((b3 >> 2) & 1) << 3));
        uint x3 = (uint)(((b0 >> 3) & 1) | (((b1 >> 3) & 1) << 1) | (((b2 >> 3) & 1) << 2) | (((b3 >> 3) & 1) << 3));
        uint x4 = (uint)(((b0 >> 4) & 1) | (((b1 >> 4) & 1) << 1) | (((b2 >> 4) & 1) << 2) | (((b3 >> 4) & 1) << 3));
        uint x5 = (uint)(((b0 >> 5) & 1) | (((b1 >> 5) & 1) << 1) | (((b2 >> 5) & 1) << 2) | (((b3 >> 5) & 1) << 3));
        uint x6 = (uint)(((b0 >> 6) & 1) | (((b1 >> 6) & 1) << 1) | (((b2 >> 6) & 1) << 2) | (((b3 >> 6) & 1) << 3));
        uint x7 = (uint)(((b0 >> 7) & 1) | (((b1 >> 7) & 1) << 1) | (((b2 >> 7) & 1) << 2) | (((b3 >> 7) & 1) << 3));

        SubBytesBitsliced(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, affineMask: 0xFu);

        r0 = (byte)((x0 & 1) | ((x1 & 1) << 1) | ((x2 & 1) << 2) | ((x3 & 1) << 3) | ((x4 & 1) << 4) | ((x5 & 1) << 5) | ((x6 & 1) << 6) | ((x7 & 1) << 7));
        r1 = (byte)(((x0 >> 1) & 1) | (((x1 >> 1) & 1) << 1) | (((x2 >> 1) & 1) << 2) | (((x3 >> 1) & 1) << 3) | (((x4 >> 1) & 1) << 4) | (((x5 >> 1) & 1) << 5) | (((x6 >> 1) & 1) << 6) | (((x7 >> 1) & 1) << 7));
        r2 = (byte)(((x0 >> 2) & 1) | (((x1 >> 2) & 1) << 1) | (((x2 >> 2) & 1) << 2) | (((x3 >> 2) & 1) << 3) | (((x4 >> 2) & 1) << 4) | (((x5 >> 2) & 1) << 5) | (((x6 >> 2) & 1) << 6) | (((x7 >> 2) & 1) << 7));
        r3 = (byte)(((x0 >> 3) & 1) | (((x1 >> 3) & 1) << 1) | (((x2 >> 3) & 1) << 2) | (((x3 >> 3) & 1) << 3) | (((x4 >> 3) & 1) << 4) | (((x5 >> 3) & 1) << 5) | (((x6 >> 3) & 1) << 6) | (((x7 >> 3) & 1) << 7));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SubBytes16(Span<byte> s)
    {
        uint x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0, x5 = 0, x6 = 0, x7 = 0;
        for (int i = 0; i < 16; i++)
        {
            byte v = s[i];
            x0 |= (uint)(v & 1) << i;
            x1 |= (uint)((v >> 1) & 1) << i;
            x2 |= (uint)((v >> 2) & 1) << i;
            x3 |= (uint)((v >> 3) & 1) << i;
            x4 |= (uint)((v >> 4) & 1) << i;
            x5 |= (uint)((v >> 5) & 1) << i;
            x6 |= (uint)((v >> 6) & 1) << i;
            x7 |= (uint)((v >> 7) & 1) << i;
        }

        SubBytesBitsliced(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, affineMask: 0xFFFFu);

        for (int i = 0; i < 16; i++)
        {
            s[i] = (byte)(
                ((x0 >> i) & 1) |
                (((x1 >> i) & 1) << 1) |
                (((x2 >> i) & 1) << 2) |
                (((x3 >> i) & 1) << 3) |
                (((x4 >> i) & 1) << 4) |
                (((x5 >> i) & 1) << 5) |
                (((x6 >> i) & 1) << 6) |
                (((x7 >> i) & 1) << 7));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte Xtime(byte b)
    {
        return (byte)((b << 1) ^ (0x1B & -(b >> 7)));
    }

    /// <summary>
    /// Expands a 32-byte AES-256 key into 15 128-bit round keys (240 bytes) in constant time.
    /// </summary>
    public static void ExpandKey(ReadOnlySpan<byte> key, Span<byte> roundKeys)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes for AES-256.", nameof(key));
        if (roundKeys.Length < 240)
            throw new ArgumentException("Round keys destination must be at least 240 bytes.", nameof(roundKeys));

        key.CopyTo(roundKeys.Slice(0, 32));

        for (int i = 8; i < 60; i++)
        {
            int prevWordOffset = (i - 1) * 4;
            byte b0 = roundKeys[prevWordOffset + 0];
            byte b1 = roundKeys[prevWordOffset + 1];
            byte b2 = roundKeys[prevWordOffset + 2];
            byte b3 = roundKeys[prevWordOffset + 3];

            if (i % 8 == 0)
            {
                byte rconVal = Rcon[i / 8];
                SubWordBitsliced(b1, b2, b3, b0, out byte t0, out byte t1, out byte t2, out byte t3);
                t0 ^= rconVal;

                int backOffset = (i - 8) * 4;
                int curOffset = i * 4;
                roundKeys[curOffset + 0] = (byte)(roundKeys[backOffset + 0] ^ t0);
                roundKeys[curOffset + 1] = (byte)(roundKeys[backOffset + 1] ^ t1);
                roundKeys[curOffset + 2] = (byte)(roundKeys[backOffset + 2] ^ t2);
                roundKeys[curOffset + 3] = (byte)(roundKeys[backOffset + 3] ^ t3);
            }
            else if (i % 8 == 4)
            {
                SubWordBitsliced(b0, b1, b2, b3, out byte t0, out byte t1, out byte t2, out byte t3);

                int backOffset = (i - 8) * 4;
                int curOffset = i * 4;
                roundKeys[curOffset + 0] = (byte)(roundKeys[backOffset + 0] ^ t0);
                roundKeys[curOffset + 1] = (byte)(roundKeys[backOffset + 1] ^ t1);
                roundKeys[curOffset + 2] = (byte)(roundKeys[backOffset + 2] ^ t2);
                roundKeys[curOffset + 3] = (byte)(roundKeys[backOffset + 3] ^ t3);
            }
            else
            {
                int backOffset = (i - 8) * 4;
                int curOffset = i * 4;
                roundKeys[curOffset + 0] = (byte)(roundKeys[backOffset + 0] ^ b0);
                roundKeys[curOffset + 1] = (byte)(roundKeys[backOffset + 1] ^ b1);
                roundKeys[curOffset + 2] = (byte)(roundKeys[backOffset + 2] ^ b2);
                roundKeys[curOffset + 3] = (byte)(roundKeys[backOffset + 3] ^ b3);
            }
        }
    }

    /// <summary>
    /// Encrypts a single 16-byte block with AES-256 (14 rounds) using constant-time bitsliced SubBytes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void EncryptBlock(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> block, Span<byte> destination)
    {
        Span<byte> state = stackalloc byte[16];

        // AddRoundKey 0
        for (int k = 0; k < 16; k++)
        {
            state[k] = (byte)(block[k] ^ roundKeys[k]);
        }

        // Rounds 1 through 13
        for (int round = 1; round <= 13; round++)
        {
            SubBytes16(state);

            byte r00 = state[0]; byte r10 = state[4]; byte r20 = state[8]; byte r30 = state[12];
            byte r01 = state[5]; byte r11 = state[9]; byte r21 = state[13]; byte r31 = state[1];
            byte r02 = state[10]; byte r12 = state[14]; byte r22 = state[2]; byte r32 = state[6];
            byte r03 = state[15]; byte r13 = state[3]; byte r23 = state[7]; byte r33 = state[11];

            int rkOffset = round * 16;
            byte u0 = (byte)(r00 ^ r01 ^ r02 ^ r03);
            state[0] = (byte)(r00 ^ u0 ^ Xtime((byte)(r00 ^ r01)) ^ roundKeys[rkOffset + 0]);
            state[1] = (byte)(r01 ^ u0 ^ Xtime((byte)(r01 ^ r02)) ^ roundKeys[rkOffset + 1]);
            state[2] = (byte)(r02 ^ u0 ^ Xtime((byte)(r02 ^ r03)) ^ roundKeys[rkOffset + 2]);
            state[3] = (byte)(r03 ^ u0 ^ Xtime((byte)(r03 ^ r00)) ^ roundKeys[rkOffset + 3]);

            byte u1 = (byte)(r10 ^ r11 ^ r12 ^ r13);
            state[4] = (byte)(r10 ^ u1 ^ Xtime((byte)(r10 ^ r11)) ^ roundKeys[rkOffset + 4]);
            state[5] = (byte)(r11 ^ u1 ^ Xtime((byte)(r11 ^ r12)) ^ roundKeys[rkOffset + 5]);
            state[6] = (byte)(r12 ^ u1 ^ Xtime((byte)(r12 ^ r13)) ^ roundKeys[rkOffset + 6]);
            state[7] = (byte)(r13 ^ u1 ^ Xtime((byte)(r13 ^ r10)) ^ roundKeys[rkOffset + 7]);

            byte u2 = (byte)(r20 ^ r21 ^ r22 ^ r23);
            state[8] = (byte)(r20 ^ u2 ^ Xtime((byte)(r20 ^ r21)) ^ roundKeys[rkOffset + 8]);
            state[9] = (byte)(r21 ^ u2 ^ Xtime((byte)(r21 ^ r22)) ^ roundKeys[rkOffset + 9]);
            state[10] = (byte)(r22 ^ u2 ^ Xtime((byte)(r22 ^ r23)) ^ roundKeys[rkOffset + 10]);
            state[11] = (byte)(r23 ^ u2 ^ Xtime((byte)(r23 ^ r20)) ^ roundKeys[rkOffset + 11]);

            byte u3 = (byte)(r30 ^ r31 ^ r32 ^ r33);
            state[12] = (byte)(r30 ^ u3 ^ Xtime((byte)(r30 ^ r31)) ^ roundKeys[rkOffset + 12]);
            state[13] = (byte)(r31 ^ u3 ^ Xtime((byte)(r31 ^ r32)) ^ roundKeys[rkOffset + 13]);
            state[14] = (byte)(r32 ^ u3 ^ Xtime((byte)(r32 ^ r33)) ^ roundKeys[rkOffset + 14]);
            state[15] = (byte)(r33 ^ u3 ^ Xtime((byte)(r33 ^ r30)) ^ roundKeys[rkOffset + 15]);
        }

        // Round 14 (Last Round: SubBytes, ShiftRows, AddRoundKey; NO MixColumns)
        {
            SubBytes16(state);

            int rkOffset = 14 * 16;
            destination[0] = (byte)(state[0] ^ roundKeys[rkOffset + 0]);
            destination[1] = (byte)(state[5] ^ roundKeys[rkOffset + 1]);
            destination[2] = (byte)(state[10] ^ roundKeys[rkOffset + 2]);
            destination[3] = (byte)(state[15] ^ roundKeys[rkOffset + 3]);

            destination[4] = (byte)(state[4] ^ roundKeys[rkOffset + 4]);
            destination[5] = (byte)(state[9] ^ roundKeys[rkOffset + 5]);
            destination[6] = (byte)(state[14] ^ roundKeys[rkOffset + 6]);
            destination[7] = (byte)(state[3] ^ roundKeys[rkOffset + 7]);

            destination[8] = (byte)(state[8] ^ roundKeys[rkOffset + 8]);
            destination[9] = (byte)(state[13] ^ roundKeys[rkOffset + 9]);
            destination[10] = (byte)(state[2] ^ roundKeys[rkOffset + 10]);
            destination[11] = (byte)(state[7] ^ roundKeys[rkOffset + 11]);

            destination[12] = (byte)(state[12] ^ roundKeys[rkOffset + 12]);
            destination[13] = (byte)(state[1] ^ roundKeys[rkOffset + 13]);
            destination[14] = (byte)(state[6] ^ roundKeys[rkOffset + 14]);
            destination[15] = (byte)(state[11] ^ roundKeys[rkOffset + 15]);
        }

        CryptographicOperations.ZeroMemory(state);
    }

    /// <summary>
    /// Evaluates GF(2^128) polynomial multiplication Z = X * H in NIST SP 800-38D reflected bit order.
    /// Completely constant-time branchless shift-and-xor algorithm.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static void GhashMultiply(ref ulong zHi, ref ulong zLo, ulong xHi, ulong xLo, ulong hHi, ulong hLo)
    {
        ulong vHi = hHi;
        ulong vLo = hLo;
        ulong curZHi = 0;
        ulong curZLo = 0;
        const ulong R = 0xE100000000000000UL;

        for (int i = 0; i < 64; i++)
        {
            ulong bit = (xHi >> (63 - i)) & 1UL;
            ulong mask = (ulong)-(long)bit;
            curZHi ^= (vHi & mask);
            curZLo ^= (vLo & mask);

            ulong lsb = vLo & 1UL;
            ulong lsbMask = (ulong)-(long)lsb;
            vLo = (vLo >> 1) | (vHi << 63);
            vHi = (vHi >> 1) ^ (R & lsbMask);
        }

        for (int i = 0; i < 64; i++)
        {
            ulong bit = (xLo >> (63 - i)) & 1UL;
            ulong mask = (ulong)-(long)bit;
            curZHi ^= (vHi & mask);
            curZLo ^= (vLo & mask);

            ulong lsb = vLo & 1UL;
            ulong lsbMask = (ulong)-(long)lsb;
            vLo = (vLo >> 1) | (vHi << 63);
            vHi = (vHi >> 1) ^ (R & lsbMask);
        }

        zHi = curZHi;
        zLo = curZLo;
    }

    /// <summary>
    /// Accumulates a 16-byte block into GHASH state: Y = (Y ^ block) * H in GF(2^128).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void GhashBlock(ref ulong yHi, ref ulong yLo, ReadOnlySpan<byte> block, ulong hHi, ulong hLo)
    {
        ulong bHi = BinaryPrimitives.ReadUInt64BigEndian(block.Slice(0, 8));
        ulong bLo = BinaryPrimitives.ReadUInt64BigEndian(block.Slice(8, 8));
        GhashMultiply(ref yHi, ref yLo, yHi ^ bHi, yLo ^ bLo, hHi, hLo);
    }
}
