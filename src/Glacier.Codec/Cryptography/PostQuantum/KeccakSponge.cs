namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// Pure C# unrolled 24-round Keccak-f[1600] permutation and sponge engine (FIPS 202).
/// Supports SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, SampleNTT, and SamplePolyCBD_2 with zero heap allocations.
/// </summary>
internal struct KeccakSponge
{
    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
        0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
    ];

    private unsafe fixed ulong _state[25];
    private readonly int _rateInBytes;
    private int _byteIndex;

    public KeccakSponge(int rateInBytes)
    {
        _rateInBytes = rateInBytes;
        _byteIndex = 0;
        unsafe
        {
            fixed (ulong* s = _state)
            {
                new Span<ulong>(s, 25).Clear();
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Absorb(ReadOnlySpan<byte> data)
    {
        fixed (ulong* s = _state)
        {
            byte* stateBytes = (byte*)s;
            int offset = 0;
            int count = data.Length;

            while (count > 0)
            {
                int toAbsorb = Math.Min(_rateInBytes - _byteIndex, count);
                for (int i = 0; i < toAbsorb; i++)
                {
                    stateBytes[_byteIndex + i] ^= data[offset + i];
                }

                _byteIndex += toAbsorb;
                offset += toAbsorb;
                count -= toAbsorb;

                if (_byteIndex == _rateInBytes)
                {
                    Permute(s);
                    _byteIndex = 0;
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Pad(byte padByte)
    {
        fixed (ulong* s = _state)
        {
            byte* stateBytes = (byte*)s;
            stateBytes[_byteIndex] ^= padByte;
            stateBytes[_rateInBytes - 1] ^= 0x80;
            Permute(s);
            _byteIndex = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Squeeze(Span<byte> destination)
    {
        fixed (ulong* s = _state)
        {
            byte* stateBytes = (byte*)s;
            int offset = 0;
            int count = destination.Length;

            while (count > 0)
            {
                if (_byteIndex == _rateInBytes)
                {
                    Permute(s);
                    _byteIndex = 0;
                }

                int toSqueeze = Math.Min(_rateInBytes - _byteIndex, count);
                new ReadOnlySpan<byte>(stateBytes + _byteIndex, toSqueeze).CopyTo(destination.Slice(offset, toSqueeze));

                _byteIndex += toSqueeze;
                offset += toSqueeze;
                count -= toSqueeze;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void Permute(ulong* a)
    {
        for (int round = 0; round < 24; round++)
        {
            // --- Theta step ---
            ulong c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
            ulong c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
            ulong c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
            ulong c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
            ulong c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

            ulong d0 = c4 ^ BitOperations.RotateLeft(c1, 1);
            ulong d1 = c0 ^ BitOperations.RotateLeft(c2, 1);
            ulong d2 = c1 ^ BitOperations.RotateLeft(c3, 1);
            ulong d3 = c2 ^ BitOperations.RotateLeft(c4, 1);
            ulong d4 = c3 ^ BitOperations.RotateLeft(c0, 1);

            ulong a0 = a[0] ^ d0, a1 = a[1] ^ d1, a2 = a[2] ^ d2, a3 = a[3] ^ d3, a4 = a[4] ^ d4;
            ulong a5 = a[5] ^ d0, a6 = a[6] ^ d1, a7 = a[7] ^ d2, a8 = a[8] ^ d3, a9 = a[9] ^ d4;
            ulong a10 = a[10] ^ d0, a11 = a[11] ^ d1, a12 = a[12] ^ d2, a13 = a[13] ^ d3, a14 = a[14] ^ d4;
            ulong a15 = a[15] ^ d0, a16 = a[16] ^ d1, a17 = a[17] ^ d2, a18 = a[18] ^ d3, a19 = a[19] ^ d4;
            ulong a20 = a[20] ^ d0, a21 = a[21] ^ d1, a22 = a[22] ^ d2, a23 = a[23] ^ d3, a24 = a[24] ^ d4;

            // --- Rho and Pi steps ---
            ulong b0 = a0;
            ulong b1 = BitOperations.RotateLeft(a6, 44);
            ulong b2 = BitOperations.RotateLeft(a12, 43);
            ulong b3 = BitOperations.RotateLeft(a18, 21);
            ulong b4 = BitOperations.RotateLeft(a24, 14);

            ulong b5 = BitOperations.RotateLeft(a3, 28);
            ulong b6 = BitOperations.RotateLeft(a9, 20);
            ulong b7 = BitOperations.RotateLeft(a10, 3);
            ulong b8 = BitOperations.RotateLeft(a16, 45);
            ulong b9 = BitOperations.RotateLeft(a22, 61);

            ulong b10 = BitOperations.RotateLeft(a1, 1);
            ulong b11 = BitOperations.RotateLeft(a7, 6);
            ulong b12 = BitOperations.RotateLeft(a13, 25);
            ulong b13 = BitOperations.RotateLeft(a19, 8);
            ulong b14 = BitOperations.RotateLeft(a20, 18);

            ulong b15 = BitOperations.RotateLeft(a4, 27);
            ulong b16 = BitOperations.RotateLeft(a5, 36);
            ulong b17 = BitOperations.RotateLeft(a11, 10);
            ulong b18 = BitOperations.RotateLeft(a17, 15);
            ulong b19 = BitOperations.RotateLeft(a23, 56);

            ulong b20 = BitOperations.RotateLeft(a2, 62);
            ulong b21 = BitOperations.RotateLeft(a8, 55);
            ulong b22 = BitOperations.RotateLeft(a14, 39);
            ulong b23 = BitOperations.RotateLeft(a15, 41);
            ulong b24 = BitOperations.RotateLeft(a21, 2);

            // --- Chi and Iota steps ---
            a[0] = b0 ^ (~b1 & b2) ^ RoundConstants[round];
            a[1] = b1 ^ (~b2 & b3);
            a[2] = b2 ^ (~b3 & b4);
            a[3] = b3 ^ (~b4 & b0);
            a[4] = b4 ^ (~b0 & b1);

            a[5] = b5 ^ (~b6 & b7);
            a[6] = b6 ^ (~b7 & b8);
            a[7] = b7 ^ (~b8 & b9);
            a[8] = b8 ^ (~b9 & b5);
            a[9] = b9 ^ (~b5 & b6);

            a[10] = b10 ^ (~b11 & b12);
            a[11] = b11 ^ (~b12 & b13);
            a[12] = b12 ^ (~b13 & b14);
            a[13] = b13 ^ (~b14 & b10);
            a[14] = b14 ^ (~b10 & b11);

            a[15] = b15 ^ (~b16 & b17);
            a[16] = b16 ^ (~b17 & b18);
            a[17] = b17 ^ (~b18 & b19);
            a[18] = b18 ^ (~b19 & b15);
            a[19] = b19 ^ (~b15 & b16);

            a[20] = b20 ^ (~b21 & b22);
            a[21] = b21 ^ (~b22 & b23);
            a[22] = b22 ^ (~b23 & b24);
            a[23] = b23 ^ (~b24 & b20);
            a[24] = b24 ^ (~b20 & b21);
        }
    }

    /// <summary>FIPS 202 SHA3-256 (rate = 136 bytes, padding = 0x06, 32-byte digest).</summary>
    public static void Sha3_256(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var sponge = new KeccakSponge(rateInBytes: 136);
        sponge.Absorb(input);
        sponge.Pad(0x06);
        sponge.Squeeze(output.Slice(0, 32));
    }

    /// <summary>FIPS 202 SHA3-512 (rate = 72 bytes, padding = 0x06, 64-byte digest).</summary>
    public static void Sha3_512(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var sponge = new KeccakSponge(rateInBytes: 72);
        sponge.Absorb(input);
        sponge.Pad(0x06);
        sponge.Squeeze(output.Slice(0, 64));
    }

    /// <summary>FIPS 202 SHAKE-128 XOF (rate = 168 bytes, padding = 0x1F).</summary>
    public static void Shake128(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var sponge = new KeccakSponge(rateInBytes: 168);
        sponge.Absorb(input);
        sponge.Pad(0x1F);
        sponge.Squeeze(output);
    }

    /// <summary>FIPS 202 SHAKE-256 XOF (rate = 136 bytes, padding = 0x1F).</summary>
    public static void Shake256(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var sponge = new KeccakSponge(rateInBytes: 136);
        sponge.Absorb(input);
        sponge.Pad(0x1F);
        sponge.Squeeze(output);
    }

    /// <summary>FIPS 203 PRF_2(sigma, N): Squeezes 128 bytes from SHAKE-256(sigma || N).</summary>
    public static void Prf2(ReadOnlySpan<byte> sigma, byte n, Span<byte> output)
    {
        Span<byte> seed = stackalloc byte[33];
        sigma.CopyTo(seed.Slice(0, 32));
        seed[32] = n;
        Shake256(seed, output.Slice(0, 128));
        CryptographicOperations.ZeroMemory(seed);
    }

    /// <summary>
    /// FIPS 203 SampleNTT (Algorithm 7): Rejection samples 256 coefficients in [0, 3328]
    /// from SHAKE-128 stream of rho || j || i.
    /// </summary>
    public static void SampleNTT(ReadOnlySpan<byte> rho, byte j, byte i, Span<short> aHat)
    {
        var sponge = new KeccakSponge(rateInBytes: 168);
        Span<byte> seed = stackalloc byte[34];
        rho.CopyTo(seed.Slice(0, 32));
        seed[32] = j;
        seed[33] = i;

        sponge.Absorb(seed);
        sponge.Pad(0x1F);

        Span<byte> block = stackalloc byte[168];
        int count = 0;

        while (count < 256)
        {
            sponge.Squeeze(block);

            for (int p = 0; p + 3 <= 168 && count < 256; p += 3)
            {
                uint d1 = (uint)(block[p] | ((block[p + 1] & 0x0F) << 8));
                uint d2 = (uint)((block[p + 1] >> 4) | (block[p + 2] << 4));

                if (d1 < 3329)
                {
                    aHat[count++] = (short)d1;
                }
                if (d2 < 3329 && count < 256)
                {
                    aHat[count++] = (short)d2;
                }
            }
        }

        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(seed);
    }

    /// <summary>
    /// FIPS 203 SamplePolyCBD_2 (Algorithm 8): Centered Binomial Distribution with eta=2.
    /// Samples 256 coefficients from 128 pseudo-random bytes.
    /// </summary>
    public static void SamplePolyCBD_2(ReadOnlySpan<byte> b, Span<short> poly)
    {
        for (int k = 0; k < 128; k++)
        {
            byte val = b[k];

            int b0 = val & 1;
            int b1 = (val >> 1) & 1;
            int b2 = (val >> 2) & 1;
            int b3 = (val >> 3) & 1;
            int c0 = (b0 + b1) - (b2 + b3);
            if (c0 < 0) c0 += 3329;
            poly[2 * k] = (short)c0;

            int b4 = (val >> 4) & 1;
            int b5 = (val >> 5) & 1;
            int b6 = (val >> 6) & 1;
            int b7 = (val >> 7) & 1;
            int c1 = (b4 + b5) - (b6 + b7);
            if (c1 < 0) c1 += 3329;
            poly[2 * k + 1] = (short)c1;
        }
    }
}
