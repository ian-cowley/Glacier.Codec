namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Bit packing and compression kernels for ML-KEM polynomial vectors (FIPS 203 Section 4.2).
/// Implements ByteEncode_d, ByteDecode_d, Compress_d, and Decompress_d for d in {1, 4, 5, 10, 11, 12}.
/// </summary>
internal static class Polyvec
{
    public const int N = 256;
    public const short Q = 3329;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort Compress(ushort x, int d)
    {
        // Formula: ((x << (d + 1)) + 3329) / 6658 mod 2^d
        uint num = (uint)((x << (d + 1)) + Q);
        uint res = num / (2u * (uint)Q);
        return (ushort)(res & ((1u << d) - 1u));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort Decompress(ushort y, int d)
    {
        // Formula: (3329 * y + (1 << (d - 1))) >> d
        return (ushort)(((uint)Q * y + (1u << (d - 1))) >> d);
    }

    /// <summary>
    /// Compress_10 followed by ByteEncode_10: 256 coefficients -> 320 bytes.
    /// </summary>
    public static void CompressAndEncode10(ReadOnlySpan<short> poly, Span<byte> destination)
    {
        for (int i = 0; i < 64; i++)
        {
            ushort c0 = Compress((ushort)poly[4 * i + 0], 10);
            ushort c1 = Compress((ushort)poly[4 * i + 1], 10);
            ushort c2 = Compress((ushort)poly[4 * i + 2], 10);
            ushort c3 = Compress((ushort)poly[4 * i + 3], 10);

            destination[5 * i + 0] = (byte)c0;
            destination[5 * i + 1] = (byte)((c0 >> 8) | (c1 << 2));
            destination[5 * i + 2] = (byte)((c1 >> 6) | (c2 << 4));
            destination[5 * i + 3] = (byte)((c2 >> 4) | (c3 << 6));
            destination[5 * i + 4] = (byte)(c3 >> 2);
        }
    }

    /// <summary>
    /// ByteDecode_10 followed by Decompress_10: 320 bytes -> 256 coefficients.
    /// </summary>
    public static void DecodeAndDecompress10(ReadOnlySpan<byte> source, Span<short> poly)
    {
        for (int i = 0; i < 64; i++)
        {
            ushort c0 = (ushort)(source[5 * i + 0] | ((source[5 * i + 1] & 0x03) << 8));
            ushort c1 = (ushort)((source[5 * i + 1] >> 2) | ((source[5 * i + 2] & 0x0F) << 6));
            ushort c2 = (ushort)((source[5 * i + 2] >> 4) | ((source[5 * i + 3] & 0x3F) << 4));
            ushort c3 = (ushort)((source[5 * i + 3] >> 6) | (source[5 * i + 4] << 2));

            poly[4 * i + 0] = (short)Decompress(c0, 10);
            poly[4 * i + 1] = (short)Decompress(c1, 10);
            poly[4 * i + 2] = (short)Decompress(c2, 10);
            poly[4 * i + 3] = (short)Decompress(c3, 10);
        }
    }

    /// <summary>
    /// Compress_4 followed by ByteEncode_4: 256 coefficients -> 128 bytes.
    /// </summary>
    public static void CompressAndEncode4(ReadOnlySpan<short> poly, Span<byte> destination)
    {
        for (int i = 0; i < 128; i++)
        {
            ushort c0 = Compress((ushort)poly[2 * i + 0], 4);
            ushort c1 = Compress((ushort)poly[2 * i + 1], 4);
            destination[i] = (byte)(c0 | (c1 << 4));
        }
    }

    /// <summary>
    /// ByteDecode_4 followed by Decompress_4: 128 bytes -> 256 coefficients.
    /// </summary>
    public static void DecodeAndDecompress4(ReadOnlySpan<byte> source, Span<short> poly)
    {
        for (int i = 0; i < 128; i++)
        {
            byte b = source[i];
            ushort c0 = (ushort)(b & 0x0F);
            ushort c1 = (ushort)(b >> 4);
            poly[2 * i + 0] = (short)Decompress(c0, 4);
            poly[2 * i + 1] = (short)Decompress(c1, 4);
        }
    }

    /// <summary>
    /// Compress_11 followed by ByteEncode_11: 256 coefficients -> 352 bytes.
    /// </summary>
    public static void CompressAndEncode11(ReadOnlySpan<short> poly, Span<byte> destination)
    {
        for (int i = 0; i < 32; i++)
        {
            ushort c0 = Compress((ushort)poly[8 * i + 0], 11);
            ushort c1 = Compress((ushort)poly[8 * i + 1], 11);
            ushort c2 = Compress((ushort)poly[8 * i + 2], 11);
            ushort c3 = Compress((ushort)poly[8 * i + 3], 11);
            ushort c4 = Compress((ushort)poly[8 * i + 4], 11);
            ushort c5 = Compress((ushort)poly[8 * i + 5], 11);
            ushort c6 = Compress((ushort)poly[8 * i + 6], 11);
            ushort c7 = Compress((ushort)poly[8 * i + 7], 11);

            destination[11 * i + 0] = (byte)c0;
            destination[11 * i + 1] = (byte)((c0 >> 8) | (c1 << 3));
            destination[11 * i + 2] = (byte)((c1 >> 5) | (c2 << 6));
            destination[11 * i + 3] = (byte)(c2 >> 2);
            destination[11 * i + 4] = (byte)((c2 >> 10) | (c3 << 1));
            destination[11 * i + 5] = (byte)((c3 >> 7) | (c4 << 4));
            destination[11 * i + 6] = (byte)((c4 >> 4) | (c5 << 7));
            destination[11 * i + 7] = (byte)(c5 >> 1);
            destination[11 * i + 8] = (byte)((c5 >> 9) | (c6 << 2));
            destination[11 * i + 9] = (byte)((c6 >> 6) | (c7 << 5));
            destination[11 * i + 10] = (byte)(c7 >> 3);
        }
    }

    /// <summary>
    /// ByteDecode_11 followed by Decompress_11: 352 bytes -> 256 coefficients.
    /// </summary>
    public static void DecodeAndDecompress11(ReadOnlySpan<byte> source, Span<short> poly)
    {
        for (int i = 0; i < 32; i++)
        {
            int b = 11 * i;
            ushort c0 = (ushort)(source[b + 0] | ((source[b + 1] & 0x07) << 8));
            ushort c1 = (ushort)((source[b + 1] >> 3) | ((source[b + 2] & 0x3F) << 5));
            ushort c2 = (ushort)((source[b + 2] >> 6) | (source[b + 3] << 2) | ((source[b + 4] & 0x01) << 10));
            ushort c3 = (ushort)((source[b + 4] >> 1) | ((source[b + 5] & 0x0F) << 7));
            ushort c4 = (ushort)((source[b + 5] >> 4) | ((source[b + 6] & 0x7F) << 4));
            ushort c5 = (ushort)((source[b + 6] >> 7) | (source[b + 7] << 1) | ((source[b + 8] & 0x03) << 9));
            ushort c6 = (ushort)((source[b + 8] >> 2) | ((source[b + 9] & 0x1F) << 6));
            ushort c7 = (ushort)((source[b + 9] >> 5) | (source[b + 10] << 3));

            poly[8 * i + 0] = (short)Decompress(c0, 11);
            poly[8 * i + 1] = (short)Decompress(c1, 11);
            poly[8 * i + 2] = (short)Decompress(c2, 11);
            poly[8 * i + 3] = (short)Decompress(c3, 11);
            poly[8 * i + 4] = (short)Decompress(c4, 11);
            poly[8 * i + 5] = (short)Decompress(c5, 11);
            poly[8 * i + 6] = (short)Decompress(c6, 11);
            poly[8 * i + 7] = (short)Decompress(c7, 11);
        }
    }

    /// <summary>
    /// Compress_5 followed by ByteEncode_5: 256 coefficients -> 160 bytes.
    /// </summary>
    public static void CompressAndEncode5(ReadOnlySpan<short> poly, Span<byte> destination)
    {
        for (int i = 0; i < 32; i++)
        {
            ushort c0 = Compress((ushort)poly[8 * i + 0], 5);
            ushort c1 = Compress((ushort)poly[8 * i + 1], 5);
            ushort c2 = Compress((ushort)poly[8 * i + 2], 5);
            ushort c3 = Compress((ushort)poly[8 * i + 3], 5);
            ushort c4 = Compress((ushort)poly[8 * i + 4], 5);
            ushort c5 = Compress((ushort)poly[8 * i + 5], 5);
            ushort c6 = Compress((ushort)poly[8 * i + 6], 5);
            ushort c7 = Compress((ushort)poly[8 * i + 7], 5);

            destination[5 * i + 0] = (byte)(c0 | (c1 << 5));
            destination[5 * i + 1] = (byte)((c1 >> 3) | (c2 << 2) | (c3 << 7));
            destination[5 * i + 2] = (byte)((c3 >> 1) | (c4 << 4));
            destination[5 * i + 3] = (byte)((c4 >> 4) | (c5 << 1) | (c6 << 6));
            destination[5 * i + 4] = (byte)((c6 >> 2) | (c7 << 3));
        }
    }

    /// <summary>
    /// ByteDecode_5 followed by Decompress_5: 160 bytes -> 256 coefficients.
    /// </summary>
    public static void DecodeAndDecompress5(ReadOnlySpan<byte> source, Span<short> poly)
    {
        for (int i = 0; i < 32; i++)
        {
            int b = 5 * i;
            ushort c0 = (ushort)(source[b + 0] & 0x1F);
            ushort c1 = (ushort)(((source[b + 0] >> 5) | (source[b + 1] << 3)) & 0x1F);
            ushort c2 = (ushort)((source[b + 1] >> 2) & 0x1F);
            ushort c3 = (ushort)(((source[b + 1] >> 7) | (source[b + 2] << 1)) & 0x1F);
            ushort c4 = (ushort)(((source[b + 2] >> 4) | (source[b + 3] << 4)) & 0x1F);
            ushort c5 = (ushort)((source[b + 3] >> 1) & 0x1F);
            ushort c6 = (ushort)(((source[b + 3] >> 6) | (source[b + 4] << 2)) & 0x1F);
            ushort c7 = (ushort)(source[b + 4] >> 3);

            poly[8 * i + 0] = (short)Decompress(c0, 5);
            poly[8 * i + 1] = (short)Decompress(c1, 5);
            poly[8 * i + 2] = (short)Decompress(c2, 5);
            poly[8 * i + 3] = (short)Decompress(c3, 5);
            poly[8 * i + 4] = (short)Decompress(c4, 5);
            poly[8 * i + 5] = (short)Decompress(c5, 5);
            poly[8 * i + 6] = (short)Decompress(c6, 5);
            poly[8 * i + 7] = (short)Decompress(c7, 5);
        }
    }

    /// <summary>
    /// ByteEncode_12: Encodes 256 12-bit coefficients into 384 bytes.
    /// </summary>
    public static void ByteEncode12(ReadOnlySpan<short> poly, Span<byte> destination)
    {
        for (int i = 0; i < 128; i++)
        {
            ushort c0 = (ushort)poly[2 * i + 0];
            ushort c1 = (ushort)poly[2 * i + 1];

            destination[3 * i + 0] = (byte)c0;
            destination[3 * i + 1] = (byte)((c0 >> 8) | (c1 << 4));
            destination[3 * i + 2] = (byte)(c1 >> 4);
        }
    }

    /// <summary>
    /// ByteDecode_12: Decodes 384 bytes into 256 12-bit coefficients.
    /// </summary>
    public static void ByteDecode12(ReadOnlySpan<byte> source, Span<short> poly)
    {
        for (int i = 0; i < 128; i++)
        {
            ushort c0 = (ushort)(source[3 * i + 0] | ((source[3 * i + 1] & 0x0F) << 8));
            ushort c1 = (ushort)((source[3 * i + 1] >> 4) | (source[3 * i + 2] << 4));
            poly[2 * i + 0] = (short)c0;
            poly[2 * i + 1] = (short)c1;
        }
    }

    /// <summary>
    /// Decompress_1(ByteDecode_1(m)): Decodes 32-byte message into 256 coefficients in {0, 1665}.
    /// </summary>
    public static void DecodeAndDecompress1(ReadOnlySpan<byte> message, Span<short> poly)
    {
        for (int i = 0; i < 32; i++)
        {
            byte b = message[i];
            for (int bit = 0; bit < 8; bit++)
            {
                ushort bitVal = (ushort)((b >> bit) & 1);
                poly[8 * i + bit] = (short)Decompress(bitVal, 1);
            }
        }
    }

    /// <summary>
    /// ByteEncode_1(Compress_1(w)): Compresses 256 coefficients into 32-byte message.
    /// </summary>
    public static void CompressAndEncode1(ReadOnlySpan<short> poly, Span<byte> message)
    {
        for (int i = 0; i < 32; i++)
        {
            byte b = 0;
            for (int bit = 0; bit < 8; bit++)
            {
                ushort bitVal = Compress((ushort)poly[8 * i + bit], 1);
                b |= (byte)(bitVal << bit);
            }
            message[i] = b;
        }
    }
}
