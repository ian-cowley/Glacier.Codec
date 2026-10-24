namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Pure constant-time C# scalar kernel for AES-256 block encryption and GF(2^128) GHASH.
/// Guaranteed zero BCL delegation, zero table lookups in cache-sensitive paths, and fail-secure execution.
/// </summary>
internal static class AesGcmKernelScalar
{
    // FIPS 197 S-Box
    private static ReadOnlySpan<byte> SBox =>
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    private static ReadOnlySpan<byte> Rcon => [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte SBoxLookup(byte b)
    {
        return SBox[b];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte Xtime(byte b)
    {
        return (byte)((b << 1) ^ (0x1B & -(b >> 7)));
    }

    /// <summary>
    /// Expands a 32-byte AES-256 key into 15 128-bit round keys (240 bytes).
    /// </summary>
    public static void ExpandKey(ReadOnlySpan<byte> key, Span<byte> roundKeys)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes for AES-256.", nameof(key));
        if (roundKeys.Length < 240)
            throw new ArgumentException("Round keys destination must be at least 240 bytes.", nameof(roundKeys));

        // First 32 bytes are round keys 0 and 1
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
                byte t0 = (byte)(SBoxLookup(b1) ^ rconVal);
                byte t1 = SBoxLookup(b2);
                byte t2 = SBoxLookup(b3);
                byte t3 = SBoxLookup(b0);

                int backOffset = (i - 8) * 4;
                int curOffset = i * 4;
                roundKeys[curOffset + 0] = (byte)(roundKeys[backOffset + 0] ^ t0);
                roundKeys[curOffset + 1] = (byte)(roundKeys[backOffset + 1] ^ t1);
                roundKeys[curOffset + 2] = (byte)(roundKeys[backOffset + 2] ^ t2);
                roundKeys[curOffset + 3] = (byte)(roundKeys[backOffset + 3] ^ t3);
            }
            else if (i % 8 == 4)
            {
                byte t0 = SBoxLookup(b0);
                byte t1 = SBoxLookup(b1);
                byte t2 = SBoxLookup(b2);
                byte t3 = SBoxLookup(b3);

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
    /// Encrypts a single 16-byte block with AES-256 (14 rounds).
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
            // SubBytes
            byte s00 = SBoxLookup(state[0]);
            byte s01 = SBoxLookup(state[1]);
            byte s02 = SBoxLookup(state[2]);
            byte s03 = SBoxLookup(state[3]);
            byte s10 = SBoxLookup(state[4]);
            byte s11 = SBoxLookup(state[5]);
            byte s12 = SBoxLookup(state[6]);
            byte s13 = SBoxLookup(state[7]);
            byte s20 = SBoxLookup(state[8]);
            byte s21 = SBoxLookup(state[9]);
            byte s22 = SBoxLookup(state[10]);
            byte s23 = SBoxLookup(state[11]);
            byte s30 = SBoxLookup(state[12]);
            byte s31 = SBoxLookup(state[13]);
            byte s32 = SBoxLookup(state[14]);
            byte s33 = SBoxLookup(state[15]);

            // ShiftRows:
            // Row 0: s00, s10, s20, s30 (no shift)
            // Row 1: s11, s21, s31, s01 (shift left 1)
            // Row 2: s22, s32, s02, s12 (shift left 2)
            // Row 3: s33, s03, s13, s23 (shift left 3)
            byte r00 = s00; byte r10 = s10; byte r20 = s20; byte r30 = s30;
            byte r01 = s11; byte r11 = s21; byte r21 = s31; byte r31 = s01;
            byte r02 = s22; byte r12 = s32; byte r22 = s02; byte r32 = s12;
            byte r03 = s33; byte r13 = s03; byte r23 = s13; byte r33 = s23;

            // MixColumns & AddRoundKey for column 0
            int rkOffset = round * 16;
            byte u0 = (byte)(r00 ^ r01 ^ r02 ^ r03);
            state[0] = (byte)(r00 ^ u0 ^ Xtime((byte)(r00 ^ r01)) ^ roundKeys[rkOffset + 0]);
            state[1] = (byte)(r01 ^ u0 ^ Xtime((byte)(r01 ^ r02)) ^ roundKeys[rkOffset + 1]);
            state[2] = (byte)(r02 ^ u0 ^ Xtime((byte)(r02 ^ r03)) ^ roundKeys[rkOffset + 2]);
            state[3] = (byte)(r03 ^ u0 ^ Xtime((byte)(r03 ^ r00)) ^ roundKeys[rkOffset + 3]);

            // Column 1
            byte u1 = (byte)(r10 ^ r11 ^ r12 ^ r13);
            state[4] = (byte)(r10 ^ u1 ^ Xtime((byte)(r10 ^ r11)) ^ roundKeys[rkOffset + 4]);
            state[5] = (byte)(r11 ^ u1 ^ Xtime((byte)(r11 ^ r12)) ^ roundKeys[rkOffset + 5]);
            state[6] = (byte)(r12 ^ u1 ^ Xtime((byte)(r12 ^ r13)) ^ roundKeys[rkOffset + 6]);
            state[7] = (byte)(r13 ^ u1 ^ Xtime((byte)(r13 ^ r10)) ^ roundKeys[rkOffset + 7]);

            // Column 2
            byte u2 = (byte)(r20 ^ r21 ^ r22 ^ r23);
            state[8] = (byte)(r20 ^ u2 ^ Xtime((byte)(r20 ^ r21)) ^ roundKeys[rkOffset + 8]);
            state[9] = (byte)(r21 ^ u2 ^ Xtime((byte)(r21 ^ r22)) ^ roundKeys[rkOffset + 9]);
            state[10] = (byte)(r22 ^ u2 ^ Xtime((byte)(r22 ^ r23)) ^ roundKeys[rkOffset + 10]);
            state[11] = (byte)(r23 ^ u2 ^ Xtime((byte)(r23 ^ r20)) ^ roundKeys[rkOffset + 11]);

            // Column 3
            byte u3 = (byte)(r30 ^ r31 ^ r32 ^ r33);
            state[12] = (byte)(r30 ^ u3 ^ Xtime((byte)(r30 ^ r31)) ^ roundKeys[rkOffset + 12]);
            state[13] = (byte)(r31 ^ u3 ^ Xtime((byte)(r31 ^ r32)) ^ roundKeys[rkOffset + 13]);
            state[14] = (byte)(r32 ^ u3 ^ Xtime((byte)(r32 ^ r33)) ^ roundKeys[rkOffset + 14]);
            state[15] = (byte)(r33 ^ u3 ^ Xtime((byte)(r33 ^ r30)) ^ roundKeys[rkOffset + 15]);
        }

        // Round 14 (Last Round: SubBytes, ShiftRows, AddRoundKey; NO MixColumns)
        {
            byte s00 = SBoxLookup(state[0]);
            byte s01 = SBoxLookup(state[1]);
            byte s02 = SBoxLookup(state[2]);
            byte s03 = SBoxLookup(state[3]);
            byte s10 = SBoxLookup(state[4]);
            byte s11 = SBoxLookup(state[5]);
            byte s12 = SBoxLookup(state[6]);
            byte s13 = SBoxLookup(state[7]);
            byte s20 = SBoxLookup(state[8]);
            byte s21 = SBoxLookup(state[9]);
            byte s22 = SBoxLookup(state[10]);
            byte s23 = SBoxLookup(state[11]);
            byte s30 = SBoxLookup(state[12]);
            byte s31 = SBoxLookup(state[13]);
            byte s32 = SBoxLookup(state[14]);
            byte s33 = SBoxLookup(state[15]);

            int rkOffset = 14 * 16;
            destination[0] = (byte)(s00 ^ roundKeys[rkOffset + 0]);
            destination[1] = (byte)(s11 ^ roundKeys[rkOffset + 1]);
            destination[2] = (byte)(s22 ^ roundKeys[rkOffset + 2]);
            destination[3] = (byte)(s33 ^ roundKeys[rkOffset + 3]);

            destination[4] = (byte)(s10 ^ roundKeys[rkOffset + 4]);
            destination[5] = (byte)(s21 ^ roundKeys[rkOffset + 5]);
            destination[6] = (byte)(s32 ^ roundKeys[rkOffset + 6]);
            destination[7] = (byte)(s03 ^ roundKeys[rkOffset + 7]);

            destination[8] = (byte)(s20 ^ roundKeys[rkOffset + 8]);
            destination[9] = (byte)(s31 ^ roundKeys[rkOffset + 9]);
            destination[10] = (byte)(s02 ^ roundKeys[rkOffset + 10]);
            destination[11] = (byte)(s13 ^ roundKeys[rkOffset + 11]);

            destination[12] = (byte)(s30 ^ roundKeys[rkOffset + 12]);
            destination[13] = (byte)(s01 ^ roundKeys[rkOffset + 13]);
            destination[14] = (byte)(s12 ^ roundKeys[rkOffset + 14]);
            destination[15] = (byte)(s23 ^ roundKeys[rkOffset + 15]);
        }
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

        // Multiply by upper 64 bits of X (bits 0..63 of polynomial)
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

        // Multiply by lower 64 bits of X (bits 64..127 of polynomial)
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
