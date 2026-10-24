namespace Glacier.Codec.Hashing.Blake3;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Genuine 16-way parallel chunk compression kernel for BLAKE3 across 512-bit AVX-512 vector registers.
/// Compresses 16 independent full 1024-byte chunks (16384 bytes total) concurrently across 16 Vector512 registers.
/// Delivers ultra-high-throughput multi-chunk execution using hardware vprold/vprord rotations.
/// </summary>
internal static unsafe class Blake3KernelAvx512
{
    public static bool IsSupported => Avx512F.IsSupported && Avx512BW.IsSupported;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void G_Avx512(
        ref Vector512<uint> a, ref Vector512<uint> b,
        ref Vector512<uint> c, ref Vector512<uint> d,
        Vector512<uint> x, Vector512<uint> y)
    {
        a = a + b + x;
        d = Avx512F.RotateRight(d ^ a, 16);
        c = c + d;
        b = Avx512F.RotateRight(b ^ c, 12);
        a = a + b + y;
        d = Avx512F.RotateRight(d ^ a, 8);
        c = c + d;
        b = Avx512F.RotateRight(b ^ c, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteRounds_Avx512(Span<Vector512<uint>> v, ReadOnlySpan<Vector512<uint>> m)
    {
        // Round 0
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[0],  m[1]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[2],  m[3]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[4],  m[5]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[6],  m[7]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[8],  m[9]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[10], m[11]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[12], m[13]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[14], m[15]);

        // Round 1
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[2],  m[6]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[3],  m[10]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[7],  m[0]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[4],  m[13]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[1],  m[11]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[12], m[5]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[9],  m[14]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[15], m[8]);

        // Round 2
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[3],  m[4]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[10], m[12]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[13], m[2]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[7],  m[14]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[6],  m[5]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[9],  m[0]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[11], m[15]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[8],  m[1]);

        // Round 3
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[10], m[7]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[12], m[9]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[14], m[3]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[13], m[15]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[4],  m[0]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[11], m[2]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[5],  m[8]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[1],  m[6]);

        // Round 4
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[12], m[13]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[9],  m[11]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[15], m[10]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[14], m[8]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[7],  m[2]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[5],  m[3]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[0],  m[1]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[6],  m[4]);

        // Round 5
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[9],  m[14]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[11], m[5]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[8],  m[12]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[15], m[1]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[13], m[3]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[0],  m[10]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[2],  m[6]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[4],  m[7]);

        // Round 6
        G_Avx512(ref v[0], ref v[4], ref v[8],  ref v[12], m[11], m[15]);
        G_Avx512(ref v[1], ref v[5], ref v[9],  ref v[13], m[5],  m[0]);
        G_Avx512(ref v[2], ref v[6], ref v[10], ref v[14], m[1],  m[9]);
        G_Avx512(ref v[3], ref v[7], ref v[11], ref v[15], m[8],  m[6]);
        G_Avx512(ref v[0], ref v[5], ref v[10], ref v[15], m[14], m[10]);
        G_Avx512(ref v[1], ref v[6], ref v[11], ref v[12], m[2],  m[12]);
        G_Avx512(ref v[2], ref v[7], ref v[8],  ref v[13], m[3],  m[4]);
        G_Avx512(ref v[3], ref v[4], ref v[9],  ref v[14], m[7],  m[13]);
    }

    /// <summary>
    /// Compresses 16 independent full 1024-byte chunks in lockstep across 16 AVX-512 lanes.
    /// Writes 16 32-byte chaining values (512 bytes total) into <paramref name="outCvs"/>.
    /// </summary>
    /// <param name="chunksBase">Pointer to base address of 16 contiguous 1024-byte chunks (16384 bytes).</param>
    /// <param name="startChunkIndex">Base 64-bit chunk counter for the first chunk.</param>
    /// <param name="key">Pointer to 8 32-bit chaining value words.</param>
    /// <param name="flags">Operational state flags.</param>
    /// <param name="outCvs">Destination pointer for 16 32-byte chaining values.</param>
    public static void Hash16Chunks(
        byte* chunksBase, ulong startChunkIndex, uint* key, uint flags, byte* outCvs)
    {
        Span<Vector512<uint>> cv = stackalloc Vector512<uint>[8];
        for (int i = 0; i < 8; i++)
        {
            cv[i] = Vector512.Create(key[i]);
        }

        Vector512<uint> counterLow = Vector512.Create(
            (uint)(startChunkIndex + 0),
            (uint)(startChunkIndex + 1),
            (uint)(startChunkIndex + 2),
            (uint)(startChunkIndex + 3),
            (uint)(startChunkIndex + 4),
            (uint)(startChunkIndex + 5),
            (uint)(startChunkIndex + 6),
            (uint)(startChunkIndex + 7),
            (uint)(startChunkIndex + 8),
            (uint)(startChunkIndex + 9),
            (uint)(startChunkIndex + 10),
            (uint)(startChunkIndex + 11),
            (uint)(startChunkIndex + 12),
            (uint)(startChunkIndex + 13),
            (uint)(startChunkIndex + 14),
            (uint)(startChunkIndex + 15));

        Vector512<uint> counterHigh = Vector512.Create(
            (uint)((startChunkIndex + 0) >> 32),
            (uint)((startChunkIndex + 1) >> 32),
            (uint)((startChunkIndex + 2) >> 32),
            (uint)((startChunkIndex + 3) >> 32),
            (uint)((startChunkIndex + 4) >> 32),
            (uint)((startChunkIndex + 5) >> 32),
            (uint)((startChunkIndex + 6) >> 32),
            (uint)((startChunkIndex + 7) >> 32),
            (uint)((startChunkIndex + 8) >> 32),
            (uint)((startChunkIndex + 9) >> 32),
            (uint)((startChunkIndex + 10) >> 32),
            (uint)((startChunkIndex + 11) >> 32),
            (uint)((startChunkIndex + 12) >> 32),
            (uint)((startChunkIndex + 13) >> 32),
            (uint)((startChunkIndex + 14) >> 32),
            (uint)((startChunkIndex + 15) >> 32));

        Vector512<uint> iv0 = Vector512.Create(0x6A09E667u);
        Vector512<uint> iv1 = Vector512.Create(0xBB67AE85u);
        Vector512<uint> iv2 = Vector512.Create(0x3C6EF372u);
        Vector512<uint> iv3 = Vector512.Create(0xA54FF53Au);
        Vector512<uint> blockLen64 = Vector512.Create(64u);

        Span<Vector512<uint>> v = stackalloc Vector512<uint>[16];
        Span<Vector512<uint>> m = stackalloc Vector512<uint>[16];

        for (int b = 0; b < 16; b++)
        {
            uint blockFlags = flags;
            if (b == 0) blockFlags |= (uint)Blake3Flags.ChunkStart;
            if (b == 15) blockFlags |= (uint)Blake3Flags.ChunkEnd;

            v[0] = cv[0];
            v[1] = cv[1];
            v[2] = cv[2];
            v[3] = cv[3];
            v[4] = cv[4];
            v[5] = cv[5];
            v[6] = cv[6];
            v[7] = cv[7];
            v[8] = iv0;
            v[9] = iv1;
            v[10] = iv2;
            v[11] = iv3;
            v[12] = counterLow;
            v[13] = counterHigh;
            v[14] = blockLen64;
            v[15] = Vector512.Create(blockFlags);

            uint* p0  = (uint*)(chunksBase + (0 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p1  = (uint*)(chunksBase + (1 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p2  = (uint*)(chunksBase + (2 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p3  = (uint*)(chunksBase + (3 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p4  = (uint*)(chunksBase + (4 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p5  = (uint*)(chunksBase + (5 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p6  = (uint*)(chunksBase + (6 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p7  = (uint*)(chunksBase + (7 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p8  = (uint*)(chunksBase + (8 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p9  = (uint*)(chunksBase + (9 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p10 = (uint*)(chunksBase + (10 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p11 = (uint*)(chunksBase + (11 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p12 = (uint*)(chunksBase + (12 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p13 = (uint*)(chunksBase + (13 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p14 = (uint*)(chunksBase + (14 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p15 = (uint*)(chunksBase + (15 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));

            for (int w = 0; w < 16; w++)
            {
                m[w] = Vector512.Create(
                    p0[w], p1[w], p2[w], p3[w], p4[w], p5[w], p6[w], p7[w],
                    p8[w], p9[w], p10[w], p11[w], p12[w], p13[w], p14[w], p15[w]);
            }

            ExecuteRounds_Avx512(v, m);

            for (int i = 0; i < 8; i++)
            {
                cv[i] = v[i] ^ v[i + 8];
            }
        }

        // Store 16 32-byte chaining values
        for (int c = 0; c < 16; c++)
        {
            uint* dst = (uint*)(outCvs + (c * 32));
            for (int i = 0; i < 8; i++)
            {
                dst[i] = cv[i].GetElement(c);
            }
        }
    }

    /// <summary>
    /// Compresses 16 independent 64-byte parent blocks concurrently across 16 AVX-512 lanes.
    /// Writes 16 32-byte chaining values (512 bytes) into <paramref name="outCvs"/>.
    /// </summary>
    public static void Compress16Parents(byte* parentBlocksBase, uint* key, uint flags, byte* outCvs)
    {
        Span<Vector512<uint>> v = stackalloc Vector512<uint>[16];
        Span<Vector512<uint>> m = stackalloc Vector512<uint>[16];

        for (int i = 0; i < 8; i++)
            v[i] = Vector512.Create(key[i]);

        v[8]  = Vector512.Create(0x6A09E667u);
        v[9]  = Vector512.Create(0xBB67AE85u);
        v[10] = Vector512.Create(0x3C6EF372u);
        v[11] = Vector512.Create(0xA54FF53Au);
        v[12] = Vector512<uint>.Zero; // counter low = 0
        v[13] = Vector512<uint>.Zero; // counter high = 0
        v[14] = Vector512.Create(64u); // blockLen = 64
        v[15] = Vector512.Create(flags);

        // Load message words across 16 parent blocks
        uint* p0  = (uint*)(parentBlocksBase + (0 * 64));
        uint* p1  = (uint*)(parentBlocksBase + (1 * 64));
        uint* p2  = (uint*)(parentBlocksBase + (2 * 64));
        uint* p3  = (uint*)(parentBlocksBase + (3 * 64));
        uint* p4  = (uint*)(parentBlocksBase + (4 * 64));
        uint* p5  = (uint*)(parentBlocksBase + (5 * 64));
        uint* p6  = (uint*)(parentBlocksBase + (6 * 64));
        uint* p7  = (uint*)(parentBlocksBase + (7 * 64));
        uint* p8  = (uint*)(parentBlocksBase + (8 * 64));
        uint* p9  = (uint*)(parentBlocksBase + (9 * 64));
        uint* p10 = (uint*)(parentBlocksBase + (10 * 64));
        uint* p11 = (uint*)(parentBlocksBase + (11 * 64));
        uint* p12 = (uint*)(parentBlocksBase + (12 * 64));
        uint* p13 = (uint*)(parentBlocksBase + (13 * 64));
        uint* p14 = (uint*)(parentBlocksBase + (14 * 64));
        uint* p15 = (uint*)(parentBlocksBase + (15 * 64));

        for (int w = 0; w < 16; w++)
        {
            m[w] = Vector512.Create(
                p0[w], p1[w], p2[w], p3[w], p4[w], p5[w], p6[w], p7[w],
                p8[w], p9[w], p10[w], p11[w], p12[w], p13[w], p14[w], p15[w]);
        }

        ExecuteRounds_Avx512(v, m);

        Span<Vector512<uint>> cv = stackalloc Vector512<uint>[8];
        for (int i = 0; i < 8; i++)
            cv[i] = v[i] ^ v[i + 8];

        // Store 16 32-byte parent chaining values
        for (int c = 0; c < 16; c++)
        {
            uint* dst = (uint*)(outCvs + (c * 32));
            for (int i = 0; i < 8; i++)
                dst[i] = cv[i].GetElement(c);
        }
    }
}
