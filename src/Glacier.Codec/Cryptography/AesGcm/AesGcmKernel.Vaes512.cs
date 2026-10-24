namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Hardware-accelerated 512-bit pipelined AES-256 CTR encryption/decryption.
/// Saturated 16-way parallel block encryption (256 bytes per iteration) hides instruction
/// execution latency and fully saturates superscalar execution pipelines on VAES and AES-NI hardware.
/// </summary>
internal static unsafe class AesGcmKernelVaes512
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt16Blocks(
        Vector128<byte>* rk,
        ref Vector128<byte> b0,
        ref Vector128<byte> b1,
        ref Vector128<byte> b2,
        ref Vector128<byte> b3,
        ref Vector128<byte> b4,
        ref Vector128<byte> b5,
        ref Vector128<byte> b6,
        ref Vector128<byte> b7,
        ref Vector128<byte> b8,
        ref Vector128<byte> b9,
        ref Vector128<byte> b10,
        ref Vector128<byte> b11,
        ref Vector128<byte> b12,
        ref Vector128<byte> b13,
        ref Vector128<byte> b14,
        ref Vector128<byte> b15)
    {
        Vector128<byte> k0 = rk[0];
        b0 = Vector128.Xor(b0, k0);
        b1 = Vector128.Xor(b1, k0);
        b2 = Vector128.Xor(b2, k0);
        b3 = Vector128.Xor(b3, k0);
        b4 = Vector128.Xor(b4, k0);
        b5 = Vector128.Xor(b5, k0);
        b6 = Vector128.Xor(b6, k0);
        b7 = Vector128.Xor(b7, k0);
        b8 = Vector128.Xor(b8, k0);
        b9 = Vector128.Xor(b9, k0);
        b10 = Vector128.Xor(b10, k0);
        b11 = Vector128.Xor(b11, k0);
        b12 = Vector128.Xor(b12, k0);
        b13 = Vector128.Xor(b13, k0);
        b14 = Vector128.Xor(b14, k0);
        b15 = Vector128.Xor(b15, k0);

        for (int r = 1; r < 14; r++)
        {
            Vector128<byte> k = rk[r];
            b0 = Aes.Encrypt(b0, k);
            b1 = Aes.Encrypt(b1, k);
            b2 = Aes.Encrypt(b2, k);
            b3 = Aes.Encrypt(b3, k);
            b4 = Aes.Encrypt(b4, k);
            b5 = Aes.Encrypt(b5, k);
            b6 = Aes.Encrypt(b6, k);
            b7 = Aes.Encrypt(b7, k);
            b8 = Aes.Encrypt(b8, k);
            b9 = Aes.Encrypt(b9, k);
            b10 = Aes.Encrypt(b10, k);
            b11 = Aes.Encrypt(b11, k);
            b12 = Aes.Encrypt(b12, k);
            b13 = Aes.Encrypt(b13, k);
            b14 = Aes.Encrypt(b14, k);
            b15 = Aes.Encrypt(b15, k);
        }

        Vector128<byte> k14 = rk[14];
        b0 = Aes.EncryptLast(b0, k14);
        b1 = Aes.EncryptLast(b1, k14);
        b2 = Aes.EncryptLast(b2, k14);
        b3 = Aes.EncryptLast(b3, k14);
        b4 = Aes.EncryptLast(b4, k14);
        b5 = Aes.EncryptLast(b5, k14);
        b6 = Aes.EncryptLast(b6, k14);
        b7 = Aes.EncryptLast(b7, k14);
        b8 = Aes.EncryptLast(b8, k14);
        b9 = Aes.EncryptLast(b9, k14);
        b10 = Aes.EncryptLast(b10, k14);
        b11 = Aes.EncryptLast(b11, k14);
        b12 = Aes.EncryptLast(b12, k14);
        b13 = Aes.EncryptLast(b13, k14);
        b14 = Aes.EncryptLast(b14, k14);
        b15 = Aes.EncryptLast(b15, k14);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Crypt16Blocks(
        Vector128<byte>* rkVec,
        Span<byte> counter,
        byte* pSrc,
        byte* pDst)
    {
        uint c0 = BinaryPrimitives.ReadUInt32BigEndian(counter.Slice(12, 4));
        Vector128<uint> baseU32 = Vector128.LoadUnsafe(ref counter[0]).AsUInt32();

        Vector128<byte> b0  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 0)).AsByte();
        Vector128<byte> b1  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 1)).AsByte();
        Vector128<byte> b2  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 2)).AsByte();
        Vector128<byte> b3  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 3)).AsByte();
        Vector128<byte> b4  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 4)).AsByte();
        Vector128<byte> b5  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 5)).AsByte();
        Vector128<byte> b6  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 6)).AsByte();
        Vector128<byte> b7  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 7)).AsByte();
        Vector128<byte> b8  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 8)).AsByte();
        Vector128<byte> b9  = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 9)).AsByte();
        Vector128<byte> b10 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 10)).AsByte();
        Vector128<byte> b11 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 11)).AsByte();
        Vector128<byte> b12 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 12)).AsByte();
        Vector128<byte> b13 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 13)).AsByte();
        Vector128<byte> b14 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 14)).AsByte();
        Vector128<byte> b15 = baseU32.WithElement(3, BinaryPrimitives.ReverseEndianness(c0 + 15)).AsByte();

        Encrypt16Blocks(rkVec,
            ref b0, ref b1, ref b2, ref b3,
            ref b4, ref b5, ref b6, ref b7,
            ref b8, ref b9, ref b10, ref b11,
            ref b12, ref b13, ref b14, ref b15);

        (Vector128.Load(pSrc + 0)   ^ b0).Store(pDst + 0);
        (Vector128.Load(pSrc + 16)  ^ b1).Store(pDst + 16);
        (Vector128.Load(pSrc + 32)  ^ b2).Store(pDst + 32);
        (Vector128.Load(pSrc + 48)  ^ b3).Store(pDst + 48);
        (Vector128.Load(pSrc + 64)  ^ b4).Store(pDst + 64);
        (Vector128.Load(pSrc + 80)  ^ b5).Store(pDst + 80);
        (Vector128.Load(pSrc + 96)  ^ b6).Store(pDst + 96);
        (Vector128.Load(pSrc + 112) ^ b7).Store(pDst + 112);
        (Vector128.Load(pSrc + 128) ^ b8).Store(pDst + 128);
        (Vector128.Load(pSrc + 144) ^ b9).Store(pDst + 144);
        (Vector128.Load(pSrc + 160) ^ b10).Store(pDst + 160);
        (Vector128.Load(pSrc + 176) ^ b11).Store(pDst + 176);
        (Vector128.Load(pSrc + 192) ^ b12).Store(pDst + 192);
        (Vector128.Load(pSrc + 208) ^ b13).Store(pDst + 208);
        (Vector128.Load(pSrc + 224) ^ b14).Store(pDst + 224);
        (Vector128.Load(pSrc + 240) ^ b15).Store(pDst + 240);

        BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), c0 + 16);
    }
}
