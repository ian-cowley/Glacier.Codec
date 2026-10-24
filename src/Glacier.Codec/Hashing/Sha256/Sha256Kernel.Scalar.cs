namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

/// <summary>
/// Portable pure C# unrolled 64-round SHA-256 compression kernel conforming to NIST FIPS 180-4.
/// </summary>
internal static class Sha256KernelScalar
{
    private static readonly uint[] K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void CompressBlocks(ref Sha256State state, ReadOnlySpan<byte> blocks)
    {
        Span<uint> w = stackalloc uint[64];
        int blockCount = blocks.Length / 64;

        for (int b = 0; b < blockCount; b++)
        {
            ReadOnlySpan<byte> block = blocks.Slice(b * 64, 64);

            // Message Schedule Initialization (W0..W15)
            for (int i = 0; i < 16; i++)
            {
                w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4, 4));
            }

            // Message Schedule Expansion (W16..W63)
            for (int i = 16; i < 64; i++)
            {
                uint s0 = BitOperations.RotateRight(w[i - 15], 7) ^ BitOperations.RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint s1 = BitOperations.RotateRight(w[i - 2], 17) ^ BitOperations.RotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint a = state.H0;
            uint bReg = state.H1;
            uint c = state.H2;
            uint d = state.H3;
            uint e = state.H4;
            uint f = state.H5;
            uint g = state.H6;
            uint h = state.H7;

            // 64 Compression Rounds
            for (int i = 0; i < 64; i++)
            {
                uint sigma1 = BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25);
                uint ch = g ^ (e & (f ^ g));
                uint t1 = h + sigma1 + ch + K[i] + w[i];

                uint sigma0 = BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22);
                uint maj = (a & bReg) ^ (c & (a ^ bReg));
                uint t2 = sigma0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = bReg;
                bReg = a;
                a = t1 + t2;
            }

            state.H0 += a;
            state.H1 += bReg;
            state.H2 += c;
            state.H3 += d;
            state.H4 += e;
            state.H5 += f;
            state.H6 += g;
            state.H7 += h;
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(w));
    }
}
