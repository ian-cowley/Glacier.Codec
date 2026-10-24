namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// High-performance, zero-allocation pure C# implementation of BLAKE2b (RFC 7693)
/// optimized for Argon2id initial digest (H0) and variable-length expansion (H').
/// Supports arbitrary output digest lengths from 1 to 64 bytes.
/// </summary>
internal struct Blake2bCore
{
    public const int BlockSize = 128;
    public const int MaxDigestSize = 64;

    private static readonly ulong[] IV =
    [
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    ];

    private static readonly byte[][] Sigma =
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
    ];

    private ulong _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7;
    private ulong _t0, _t1;
    private readonly int _digestLength;
    private int _bufferLength;
    private unsafe fixed byte _buffer[BlockSize];

    public Blake2bCore(int digestLength)
    {
        if (digestLength is < 1 or > MaxDigestSize)
            throw new ArgumentOutOfRangeException(nameof(digestLength), "Digest length must be between 1 and 64 bytes.");

        _digestLength = digestLength;
        _bufferLength = 0;
        _t0 = 0;
        _t1 = 0;

        // Initialize state with IV XOR parameter block (fanout=1, depth=1, digestLength)
        _h0 = IV[0] ^ 0x01010000UL ^ (uint)digestLength;
        _h1 = IV[1];
        _h2 = IV[2];
        _h3 = IV[3];
        _h4 = IV[4];
        _h5 = IV[5];
        _h6 = IV[6];
        _h7 = IV[7];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Update(ReadOnlySpan<byte> data)
    {
        int offset = 0;
        int count = data.Length;

        fixed (byte* bufPtr = _buffer)
        {
            if (_bufferLength > 0 && count > 0)
            {
                int toCopy = Math.Min(BlockSize - _bufferLength, count);
                data.Slice(offset, toCopy).CopyTo(new Span<byte>(bufPtr + _bufferLength, toCopy));
                _bufferLength += toCopy;
                offset += toCopy;
                count -= toCopy;

                if (_bufferLength == BlockSize && count > 0)
                {
                    IncrementCounter(BlockSize);
                    Compress(bufPtr, isLastBlock: false);
                    _bufferLength = 0;
                }
            }

            while (count > BlockSize)
            {
                IncrementCounter(BlockSize);
                fixed (byte* dataPtr = &data[offset])
                {
                    Compress(dataPtr, isLastBlock: false);
                }
                offset += BlockSize;
                count -= BlockSize;
            }

            if (count > 0)
            {
                data.Slice(offset, count).CopyTo(new Span<byte>(bufPtr + _bufferLength, count));
                _bufferLength += count;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Finalize(Span<byte> destination)
    {
        if (destination.Length < _digestLength)
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));

        IncrementCounter((ulong)_bufferLength);

        fixed (byte* bufPtr = _buffer)
        {
            // Pad remaining buffer with zeros
            if (_bufferLength < BlockSize)
            {
                new Span<byte>(bufPtr + _bufferLength, BlockSize - _bufferLength).Clear();
            }

            Compress(bufPtr, isLastBlock: true);
        }

        Span<byte> fullHash = stackalloc byte[MaxDigestSize];
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(0, 8), _h0);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(8, 8), _h1);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(16, 8), _h2);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(24, 8), _h3);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(32, 8), _h4);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(40, 8), _h5);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(48, 8), _h6);
        BinaryPrimitives.WriteUInt64LittleEndian(fullHash.Slice(56, 8), _h7);

        fullHash.Slice(0, _digestLength).CopyTo(destination);
        CryptographicOperations.ZeroMemory(fullHash);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination, int digestLength)
    {
        var blake = new Blake2bCore(digestLength);
        blake.Update(data);
        blake.Finalize(destination);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void IncrementCounter(ulong inc)
    {
        _t0 += inc;
        if (_t0 < inc)
        {
            _t1++;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void Compress(byte* block, bool isLastBlock)
    {
        ulong* m = (ulong*)block;

        ulong v0 = _h0, v1 = _h1, v2 = _h2, v3 = _h3;
        ulong v4 = _h4, v5 = _h5, v6 = _h6, v7 = _h7;
        ulong v8 = IV[0], v9 = IV[1], v10 = IV[2], v11 = IV[3];
        ulong v12 = IV[4] ^ _t0;
        ulong v13 = IV[5] ^ _t1;
        ulong v14 = isLastBlock ? (IV[6] ^ ~0UL) : IV[6];
        ulong v15 = IV[7];

        for (int r = 0; r < 12; r++)
        {
            byte[] s = Sigma[r];
            G(ref v0, ref v4, ref v8,  ref v12, m[s[0]], m[s[1]]);
            G(ref v1, ref v5, ref v9,  ref v13, m[s[2]], m[s[3]]);
            G(ref v2, ref v6, ref v10, ref v14, m[s[4]], m[s[5]]);
            G(ref v3, ref v7, ref v11, ref v15, m[s[6]], m[s[7]]);

            G(ref v0, ref v5, ref v10, ref v15, m[s[8]],  m[s[9]]);
            G(ref v1, ref v6, ref v11, ref v12, m[s[10]], m[s[11]]);
            G(ref v2, ref v7, ref v8,  ref v13, m[s[12]], m[s[13]]);
            G(ref v3, ref v4, ref v9,  ref v14, m[s[14]], m[s[15]]);
        }

        _h0 ^= v0 ^ v8;
        _h1 ^= v1 ^ v9;
        _h2 ^= v2 ^ v10;
        _h3 ^= v3 ^ v11;
        _h4 ^= v4 ^ v12;
        _h5 ^= v5 ^ v13;
        _h6 ^= v6 ^ v14;
        _h7 ^= v7 ^ v15;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ulong x, ulong y)
    {
        a = a + b + x;
        d = BitOperations.RotateRight(d ^ a, 32);
        c = c + d;
        b = BitOperations.RotateRight(b ^ c, 24);

        a = a + b + y;
        d = BitOperations.RotateRight(d ^ a, 16);
        c = c + d;
        b = BitOperations.RotateRight(b ^ c, 63);
    }
}
