namespace Glacier.Codec.Cryptography.AesGcmSiv;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Hardware;

/// <summary>
/// RFC 8452 AES-256-GCM-SIV deterministic nonce-misuse resistant AEAD kernel.
/// </summary>
internal static unsafe class Aes256GcmSivKernel
{
    public static void DeriveMessageKeys(
        ReadOnlySpan<byte> kgkRoundKeys,
        ReadOnlySpan<byte> nonce,
        Span<byte> authKey,
        Span<byte> encKey)
    {
        Span<byte> block = stackalloc byte[16];
        Span<byte> encOut = stackalloc byte[16];
        try
        {
            nonce.Slice(0, 12).CopyTo(block.Slice(4, 12));

            // 6 AES-256 block calls taking the first 8 bytes of each output:
            // counter 0..1 -> 16-byte message authentication key
            // counter 2..5 -> 32-byte message encryption key
            for (uint counter = 0; counter < 6; counter++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0, 4), counter);
                AesGcmKernel.EncryptSingleBlock(kgkRoundKeys, block, encOut);

                if (counter < 2)
                {
                    encOut.Slice(0, 8).CopyTo(authKey.Slice((int)counter * 8, 8));
                }
                else
                {
                    encOut.Slice(0, 8).CopyTo(encKey.Slice((int)(counter - 2) * 8, 8));
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(encOut);
        }
    }

    public static void ComputeTag(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> encRoundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext,
        Span<byte> tag)
    {
        Span<byte> s = stackalloc byte[16];
        try
        {
            PolyvalKernel.ComputePolyval(authKey, aad, plaintext, s, includeLengthBlock: true);

            for (int i = 0; i < 12; i++)
            {
                s[i] ^= nonce[i];
            }

            s[15] &= 0x7F;
            AesGcmKernel.EncryptSingleBlock(encRoundKeys, s, tag.Slice(0, 16));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(s);
        }
    }

    public static void CtrCrypt(
        ReadOnlySpan<byte> encRoundKeys,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        if (source.IsEmpty)
        {
            return;
        }

        Span<byte> ctr = stackalloc byte[16];
        Span<byte> keystream = stackalloc byte[16];
        try
        {
            tag.Slice(0, 16).CopyTo(ctr);
            ctr[15] |= 0x80;

            uint c0 = BinaryPrimitives.ReadUInt32LittleEndian(ctr.Slice(0, 4));
            int offset = 0;
            int length = source.Length;

            fixed (byte* rkPtr = encRoundKeys, pSrc = source, pDst = destination)
            {
                Vector128<byte>* rkVec = (Vector128<byte>*)rkPtr;

                if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasAesNi)
                {
                    Vector128<uint> baseU32 = Vector128.LoadUnsafe(ref ctr[0]).AsUInt32();

                    while (offset + 64 <= length)
                    {
                        Vector128<byte> b0 = baseU32.WithElement(0, c0 + 0).AsByte();
                        Vector128<byte> b1 = baseU32.WithElement(0, c0 + 1).AsByte();
                        Vector128<byte> b2 = baseU32.WithElement(0, c0 + 2).AsByte();
                        Vector128<byte> b3 = baseU32.WithElement(0, c0 + 3).AsByte();

                        AesGcmKernelAesNi.Encrypt4Blocks(rkVec, ref b0, ref b1, ref b2, ref b3);

                        (Vector128.Load(pSrc + offset + 0)  ^ b0).Store(pDst + offset + 0);
                        (Vector128.Load(pSrc + offset + 16) ^ b1).Store(pDst + offset + 16);
                        (Vector128.Load(pSrc + offset + 32) ^ b2).Store(pDst + offset + 32);
                        (Vector128.Load(pSrc + offset + 48) ^ b3).Store(pDst + offset + 48);

                        c0 += 4;
                        offset += 64;
                    }
                }

                while (offset < length)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(ctr.Slice(0, 4), c0);
                    AesGcmKernel.EncryptSingleBlock(encRoundKeys, ctr, keystream);
                    c0++;

                    int remaining = Math.Min(16, length - offset);
                    for (int k = 0; k < remaining; k++)
                    {
                        pDst[offset + k] = (byte)(pSrc[offset + k] ^ keystream[k]);
                    }
                    offset += remaining;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ctr);
            CryptographicOperations.ZeroMemory(keystream);
        }
    }

    public static void Encrypt(
        ReadOnlySpan<byte> kgkRoundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> authKey = stackalloc byte[16];
        Span<byte> encKey = stackalloc byte[32];
        Span<byte> encRoundKeys = stackalloc byte[240];
        try
        {
            DeriveMessageKeys(kgkRoundKeys, nonce, authKey, encKey);
            AesGcmKernel.ExpandKey(encKey, encRoundKeys);

            // Compute tag BEFORE CtrCrypt so in-place encryption (plaintext == ciphertext) is valid
            ComputeTag(authKey, encRoundKeys, nonce, associatedData, plaintext, tag);
            CtrCrypt(encRoundKeys, tag, plaintext, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authKey);
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(encRoundKeys);
        }
    }

    public static bool Decrypt(
        ReadOnlySpan<byte> kgkRoundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> expectedTag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> authKey = stackalloc byte[16];
        Span<byte> encKey = stackalloc byte[32];
        Span<byte> encRoundKeys = stackalloc byte[240];
        Span<byte> computedTag = stackalloc byte[16];
        try
        {
            DeriveMessageKeys(kgkRoundKeys, nonce, authKey, encKey);
            AesGcmKernel.ExpandKey(encKey, encRoundKeys);

            CtrCrypt(encRoundKeys, expectedTag, ciphertext, plaintext);

            ReadOnlySpan<byte> ptSlice = plaintext.Slice(0, ciphertext.Length);
            ComputeTag(authKey, encRoundKeys, nonce, associatedData, ptSlice, computedTag);

            if (!CryptographicOperations.FixedTimeEquals(computedTag, expectedTag.Slice(0, 16)))
            {
                CryptographicOperations.ZeroMemory(plaintext.Slice(0, ciphertext.Length));
                return false;
            }

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authKey);
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(encRoundKeys);
            CryptographicOperations.ZeroMemory(computedTag);
        }
    }
}
