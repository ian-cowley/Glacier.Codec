namespace Glacier.Codec.Hashing.Blake3;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Genuine 8-way parallel chunk compression kernel for BLAKE3 across 256-bit AVX2 vector registers.
/// Compresses 8 independent full 1024-byte chunks (8192 bytes total) concurrently across 16 Vector256 registers,
/// saturating CPU SIMD execution units with parallel G quarter-rounds and hardware vector rotations.
/// </summary>
internal static unsafe class Blake3KernelAvx2
{
    public static bool IsSupported => Avx2.IsSupported;

    private static readonly Vector256<byte> Rot16Mask = Vector256.Create(
        (byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

    private static readonly Vector256<byte> Rot8Mask = Vector256.Create(
        (byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
        1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotR16(Vector256<uint> x) =>
        Avx2.Shuffle(x.AsByte(), Rot16Mask).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotR8(Vector256<uint> x) =>
        Avx2.Shuffle(x.AsByte(), Rot8Mask).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotR12(Vector256<uint> x) =>
        (x >>> 12) | (x << 20);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotR7(Vector256<uint> x) =>
        (x >>> 7) | (x << 25);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void G_Avx2(
        ref Vector256<uint> a, ref Vector256<uint> b,
        ref Vector256<uint> c, ref Vector256<uint> d,
        Vector256<uint> x, Vector256<uint> y)
    {
        a = a + b + x;
        d = RotR16(d ^ a);
        c = c + d;
        b = RotR12(b ^ c);
        a = a + b + y;
        d = RotR8(d ^ a);
        c = c + d;
        b = RotR7(b ^ c);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteRounds_Avx2(Span<Vector256<uint>> v, ReadOnlySpan<Vector256<uint>> m)
    {
        // Round 0
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[0],  m[1]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[2],  m[3]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[4],  m[5]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[6],  m[7]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[8],  m[9]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[10], m[11]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[12], m[13]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[14], m[15]);

        // Round 1
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[2],  m[6]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[3],  m[10]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[7],  m[0]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[4],  m[13]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[1],  m[11]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[12], m[5]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[9],  m[14]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[15], m[8]);

        // Round 2
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[3],  m[4]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[10], m[12]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[13], m[2]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[7],  m[14]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[6],  m[5]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[9],  m[0]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[11], m[15]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[8],  m[1]);

        // Round 3
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[10], m[7]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[12], m[9]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[14], m[3]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[13], m[15]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[4],  m[0]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[11], m[2]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[5],  m[8]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[1],  m[6]);

        // Round 4
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[12], m[13]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[9],  m[11]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[15], m[10]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[14], m[8]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[7],  m[2]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[5],  m[3]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[0],  m[1]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[6],  m[4]);

        // Round 5
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[9],  m[14]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[11], m[5]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[8],  m[12]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[15], m[1]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[13], m[3]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[0],  m[10]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[2],  m[6]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[4],  m[7]);

        // Round 6
        G_Avx2(ref v[0], ref v[4], ref v[8],  ref v[12], m[11], m[15]);
        G_Avx2(ref v[1], ref v[5], ref v[9],  ref v[13], m[5],  m[0]);
        G_Avx2(ref v[2], ref v[6], ref v[10], ref v[14], m[1],  m[9]);
        G_Avx2(ref v[3], ref v[7], ref v[11], ref v[15], m[8],  m[6]);
        G_Avx2(ref v[0], ref v[5], ref v[10], ref v[15], m[14], m[10]);
        G_Avx2(ref v[1], ref v[6], ref v[11], ref v[12], m[2],  m[12]);
        G_Avx2(ref v[2], ref v[7], ref v[8],  ref v[13], m[3],  m[4]);
        G_Avx2(ref v[3], ref v[4], ref v[9],  ref v[14], m[7],  m[13]);
    }

    /// <summary>
    /// Compresses 8 independent full 1024-byte chunks in lockstep across 8 AVX2 lanes.
    /// Writes 8 32-byte chaining values (256 bytes total) into <paramref name="outCvs"/>.
    /// </summary>
    /// <param name="chunksBase">Pointer to base address of 8 contiguous 1024-byte chunks (8192 bytes).</param>
    /// <param name="startChunkIndex">Base 64-bit chunk counter for the first chunk.</param>
    /// <param name="key">Pointer to 8 32-bit chaining value words.</param>
    /// <param name="flags">Operational state flags.</param>
    /// <param name="outCvs">Destination pointer for 8 32-byte chaining values.</param>
    public static void Hash8Chunks(
        byte* chunksBase, ulong startChunkIndex, uint* key, uint flags, byte* outCvs)
    {
        Span<Vector256<uint>> cv = stackalloc Vector256<uint>[8];
        for (int i = 0; i < 8; i++)
        {
            cv[i] = Vector256.Create(key[i]);
        }

        Vector256<uint> counterLow = Vector256.Create(
            (uint)(startChunkIndex + 0),
            (uint)(startChunkIndex + 1),
            (uint)(startChunkIndex + 2),
            (uint)(startChunkIndex + 3),
            (uint)(startChunkIndex + 4),
            (uint)(startChunkIndex + 5),
            (uint)(startChunkIndex + 6),
            (uint)(startChunkIndex + 7));

        Vector256<uint> counterHigh = Vector256.Create(
            (uint)((startChunkIndex + 0) >> 32),
            (uint)((startChunkIndex + 1) >> 32),
            (uint)((startChunkIndex + 2) >> 32),
            (uint)((startChunkIndex + 3) >> 32),
            (uint)((startChunkIndex + 4) >> 32),
            (uint)((startChunkIndex + 5) >> 32),
            (uint)((startChunkIndex + 6) >> 32),
            (uint)((startChunkIndex + 7) >> 32));

        Vector256<uint> iv0 = Vector256.Create(0x6A09E667u);
        Vector256<uint> iv1 = Vector256.Create(0xBB67AE85u);
        Vector256<uint> iv2 = Vector256.Create(0x3C6EF372u);
        Vector256<uint> iv3 = Vector256.Create(0xA54FF53Au);
        Vector256<uint> blockLen64 = Vector256.Create(64u);

        Span<Vector256<uint>> v = stackalloc Vector256<uint>[16];
        Span<Vector256<uint>> m = stackalloc Vector256<uint>[16];

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
            v[15] = Vector256.Create(blockFlags);

            uint* p0 = (uint*)(chunksBase + (0 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p1 = (uint*)(chunksBase + (1 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p2 = (uint*)(chunksBase + (2 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p3 = (uint*)(chunksBase + (3 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p4 = (uint*)(chunksBase + (4 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p5 = (uint*)(chunksBase + (5 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p6 = (uint*)(chunksBase + (6 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));
            uint* p7 = (uint*)(chunksBase + (7 * Blake3Constants.ChunkSize) + (b * Blake3Constants.BlockSize));

            for (int w = 0; w < 16; w++)
            {
                m[w] = Vector256.Create(p0[w], p1[w], p2[w], p3[w], p4[w], p5[w], p6[w], p7[w]);
            }

            ExecuteRounds_Avx2(v, m);

            for (int i = 0; i < 8; i++)
            {
                cv[i] = v[i] ^ v[i + 8];
            }
        }

        // Store 8 32-byte chaining values
        for (int c = 0; c < 8; c++)
        {
            uint* dst = (uint*)(outCvs + (c * 32));
            for (int i = 0; i < 8; i++)
            {
                dst[i] = cv[i].GetElement(c);
            }
        }
    }

    /// <summary>
    /// Compresses 8 independent 64-byte parent blocks concurrently across 8 AVX2 lanes.
    /// Writes 8 32-byte chaining values (256 bytes) into <paramref name="outCvs"/>.
    /// </summary>
    public static void Compress8Parents(byte* parentBlocksBase, uint* key, uint flags, byte* outCvs)
    {
        Span<Vector256<uint>> v = stackalloc Vector256<uint>[16];
        Span<Vector256<uint>> m = stackalloc Vector256<uint>[16];

        for (int i = 0; i < 8; i++)
            v[i] = Vector256.Create(key[i]);

        v[8]  = Vector256.Create(0x6A09E667u);
        v[9]  = Vector256.Create(0xBB67AE85u);
        v[10] = Vector256.Create(0x3C6EF372u);
        v[11] = Vector256.Create(0xA54FF53Au);
        v[12] = Vector256<uint>.Zero; // counter low = 0
        v[13] = Vector256<uint>.Zero; // counter high = 0
        v[14] = Vector256.Create(64u); // blockLen = 64
        v[15] = Vector256.Create(flags);

        // Load message words across 8 parent blocks
        uint* p0 = (uint*)(parentBlocksBase + (0 * 64));
        uint* p1 = (uint*)(parentBlocksBase + (1 * 64));
        uint* p2 = (uint*)(parentBlocksBase + (2 * 64));
        uint* p3 = (uint*)(parentBlocksBase + (3 * 64));
        uint* p4 = (uint*)(parentBlocksBase + (4 * 64));
        uint* p5 = (uint*)(parentBlocksBase + (5 * 64));
        uint* p6 = (uint*)(parentBlocksBase + (6 * 64));
        uint* p7 = (uint*)(parentBlocksBase + (7 * 64));

        for (int w = 0; w < 16; w++)
        {
            m[w] = Vector256.Create(p0[w], p1[w], p2[w], p3[w], p4[w], p5[w], p6[w], p7[w]);
        }

        ExecuteRounds_Avx2(v, m);

        Span<Vector256<uint>> cv = stackalloc Vector256<uint>[8];
        for (int i = 0; i < 8; i++)
            cv[i] = v[i] ^ v[i + 8];

        // Store 8 32-byte parent chaining values
        for (int c = 0; c < 8; c++)
        {
            uint* dst = (uint*)(outCvs + (c * 32));
            for (int i = 0; i < 8; i++)
                dst[i] = cv[i].GetElement(c);
        }
    }
}

