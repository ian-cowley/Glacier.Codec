namespace Glacier.Codec.Hashing.Blake3;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Unrolled zero-allocation 7-round ARX scalar compression kernel for BLAKE3.
/// Pre-evaluates compile-time message schedules to eliminate array copying.
/// </summary>
internal static unsafe class Blake3KernelScalar
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressBlock(uint* cv, byte* block, ulong counter, uint blockLen, uint flags, uint* outCv)
    {
        Span<uint> v = stackalloc uint[16];
        InitState(v, cv, counter, blockLen, flags);

        Span<uint> m = stackalloc uint[16];
        DecodeBlockWords(block, blockLen, m);

        ExecuteRounds(v, m);

        for (int i = 0; i < 8; i++)
        {
            outCv[i] = v[i] ^ v[i + 8];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressBlock64(uint* cv, byte* block, ulong counter, uint blockLen, uint flags, byte* outBytes)
    {
        Span<uint> v = stackalloc uint[16];
        InitState(v, cv, counter, blockLen, flags);

        Span<uint> m = stackalloc uint[16];
        DecodeBlockWords(block, blockLen, m);

        ExecuteRounds(v, m);

        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(outBytes + (i * 4), 4), v[i] ^ v[i + 8]);
            BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(outBytes + ((i + 8) * 4), 4), v[i + 8] ^ cv[i]);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitState(Span<uint> v, uint* cv, ulong counter, uint blockLen, uint flags)
    {
        for (int i = 0; i < 8; i++) v[i] = cv[i];
        v[8] = 0x6A09E667;
        v[9] = 0xBB67AE85;
        v[10] = 0x3C6EF372;
        v[11] = 0xA54FF53A;
        v[12] = (uint)counter;
        v[13] = (uint)(counter >> 32);
        v[14] = blockLen;
        v[15] = flags;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecodeBlockWords(byte* block, uint blockLen, Span<uint> m)
    {
        m.Clear();
        int words = (int)(blockLen / 4);
        for (int i = 0; i < words; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(block + (i * 4), 4));
        }
        int rem = (int)(blockLen % 4);
        if (rem > 0)
        {
            int baseIdx = words * 4;
            uint tail = 0;
            for (int j = 0; j < rem; j++) tail |= (uint)block[baseIdx + j] << (8 * j);
            m[words] = tail;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(ref uint a, ref uint b, ref uint c, ref uint d, uint x, uint y)
    {
        a = a + b + x;
        d = BitOperations.RotateRight(d ^ a, 16);
        c = c + d;
        b = BitOperations.RotateRight(b ^ c, 12);
        a = a + b + y;
        d = BitOperations.RotateRight(d ^ a, 8);
        c = c + d;
        b = BitOperations.RotateRight(b ^ c, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteRounds(Span<uint> v, ReadOnlySpan<uint> m)
    {
        // Round 0
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[0],  m[1]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[2],  m[3]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[4],  m[5]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[6],  m[7]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[8],  m[9]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[10], m[11]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[12], m[13]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[14], m[15]);

        // Round 1
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[2],  m[6]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[3],  m[10]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[7],  m[0]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[4],  m[13]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[1],  m[11]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[12], m[5]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[9],  m[14]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[15], m[8]);

        // Round 2
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[3],  m[4]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[10], m[12]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[13], m[2]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[7],  m[14]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[6],  m[5]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[9],  m[0]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[11], m[15]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[8],  m[1]);

        // Round 3
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[10], m[7]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[12], m[9]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[14], m[3]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[13], m[15]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[4],  m[0]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[11], m[2]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[5],  m[8]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[1],  m[6]);

        // Round 4
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[12], m[13]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[9],  m[11]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[15], m[10]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[14], m[8]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[7],  m[2]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[5],  m[3]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[0],  m[1]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[6],  m[4]);

        // Round 5
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[9],  m[14]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[11], m[5]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[8],  m[12]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[15], m[1]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[13], m[3]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[0],  m[10]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[2],  m[6]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[4],  m[7]);

        // Round 6
        G(ref v[0], ref v[4], ref v[8],  ref v[12], m[11], m[15]);
        G(ref v[1], ref v[5], ref v[9],  ref v[13], m[5],  m[0]);
        G(ref v[2], ref v[6], ref v[10], ref v[14], m[1],  m[9]);
        G(ref v[3], ref v[7], ref v[11], ref v[15], m[8],  m[6]);
        G(ref v[0], ref v[5], ref v[10], ref v[15], m[14], m[10]);
        G(ref v[1], ref v[6], ref v[11], ref v[12], m[2],  m[12]);
        G(ref v[2], ref v[7], ref v[8],  ref v[13], m[3],  m[4]);
        G(ref v[3], ref v[4], ref v[9],  ref v[14], m[7],  m[13]);
    }
}
