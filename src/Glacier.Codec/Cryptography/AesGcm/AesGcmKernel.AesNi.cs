namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Hardware-accelerated AES-256 block encryption and multi-block pipelining via AES-NI.
/// Saturated 4-way and 8-way parallel block encryption hides instruction execution latency.
/// </summary>
internal static unsafe class AesGcmKernelAesNi
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> EncryptBlock(Vector128<byte>* rk, Vector128<byte> block)
    {
        Vector128<byte> s = Vector128.Xor(block, rk[0]);
        s = Aes.Encrypt(s, rk[1]);
        s = Aes.Encrypt(s, rk[2]);
        s = Aes.Encrypt(s, rk[3]);
        s = Aes.Encrypt(s, rk[4]);
        s = Aes.Encrypt(s, rk[5]);
        s = Aes.Encrypt(s, rk[6]);
        s = Aes.Encrypt(s, rk[7]);
        s = Aes.Encrypt(s, rk[8]);
        s = Aes.Encrypt(s, rk[9]);
        s = Aes.Encrypt(s, rk[10]);
        s = Aes.Encrypt(s, rk[11]);
        s = Aes.Encrypt(s, rk[12]);
        s = Aes.Encrypt(s, rk[13]);
        return Aes.EncryptLast(s, rk[14]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt4Blocks(
        Vector128<byte>* rk,
        ref Vector128<byte> b0,
        ref Vector128<byte> b1,
        ref Vector128<byte> b2,
        ref Vector128<byte> b3)
    {
        Vector128<byte> k0 = rk[0];
        b0 = Vector128.Xor(b0, k0);
        b1 = Vector128.Xor(b1, k0);
        b2 = Vector128.Xor(b2, k0);
        b3 = Vector128.Xor(b3, k0);

        for (int r = 1; r < 14; r++)
        {
            Vector128<byte> k = rk[r];
            b0 = Aes.Encrypt(b0, k);
            b1 = Aes.Encrypt(b1, k);
            b2 = Aes.Encrypt(b2, k);
            b3 = Aes.Encrypt(b3, k);
        }

        Vector128<byte> k14 = rk[14];
        b0 = Aes.EncryptLast(b0, k14);
        b1 = Aes.EncryptLast(b1, k14);
        b2 = Aes.EncryptLast(b2, k14);
        b3 = Aes.EncryptLast(b3, k14);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt8Blocks(
        Vector128<byte>* rk,
        ref Vector128<byte> b0,
        ref Vector128<byte> b1,
        ref Vector128<byte> b2,
        ref Vector128<byte> b3,
        ref Vector128<byte> b4,
        ref Vector128<byte> b5,
        ref Vector128<byte> b6,
        ref Vector128<byte> b7)
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
    }
}
