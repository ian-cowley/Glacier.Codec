namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// Hardware coordinator for RFC 8439 AEAD ChaCha20-Poly1305 authenticated encryption and decryption.
/// </summary>
internal static class ChaCha20Kernel
{
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        // 1. Generate one-time Poly1305 key from ChaCha20 block 0
        Span<byte> block0 = stackalloc byte[64];
        ChaCha20Cipher.GenerateBlock(key, 0, nonce, block0);
        ReadOnlySpan<byte> polyKey = block0.Slice(0, 32);

        // 2. Encrypt plaintext starting with block counter = 1
        ChaCha20Cipher.Crypt(key, nonce, 1, plaintext, ciphertext.Slice(0, plaintext.Length));

        // 3. Compute Poly1305 MAC over AAD || Pad16 || Ciphertext || Pad16 || Length Trailer
        ComputeAeadTag(polyKey, associatedData, ciphertext.Slice(0, plaintext.Length), tag);

        // 4. Zero-wipe sensitive one-time key block
        CryptographicOperations.ZeroMemory(block0);
    }

    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> expectedTag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        // 1. Generate one-time Poly1305 key from ChaCha20 block 0
        Span<byte> block0 = stackalloc byte[64];
        ChaCha20Cipher.GenerateBlock(key, 0, nonce, block0);
        ReadOnlySpan<byte> polyKey = block0.Slice(0, 32);

        // 2. Compute tag over AAD and Ciphertext and verify in constant time
        Span<byte> computedTag = stackalloc byte[16];
        ComputeAeadTag(polyKey, associatedData, ciphertext, computedTag);

        CryptographicOperations.ZeroMemory(block0);

        bool isValid = CryptographicOperations.FixedTimeEquals(computedTag, expectedTag.Slice(0, 16));
        if (!isValid)
        {
            CryptographicOperations.ZeroMemory(plaintext.Slice(0, ciphertext.Length));
            return false;
        }

        // 3. Decrypt ciphertext starting with block counter = 1
        ChaCha20Cipher.Crypt(key, nonce, 1, ciphertext, plaintext.Slice(0, ciphertext.Length));
        return true;
    }

    private static void ComputeAeadTag(
        ReadOnlySpan<byte> polyKey,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> tag)
    {
        Poly1305Kernel.ClampKey(polyKey, out ulong r0, out ulong r1, out ulong s1);

        ulong h0 = 0, h1 = 0, h2 = 0;

        // 1. Process AAD (padded to 16-byte boundary)
        int aadOffset = 0;
        while (aadOffset + 16 <= aad.Length)
        {
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(aad.Slice(aadOffset, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(aad.Slice(aadOffset + 8, 8));
            Poly1305Kernel.ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 1, r0, r1, s1);
            aadOffset += 16;
        }
        if (aadOffset < aad.Length)
        {
            Span<byte> partialAad = stackalloc byte[16];
            aad.Slice(aadOffset).CopyTo(partialAad);
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(partialAad.Slice(0, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(partialAad.Slice(8, 8));
            Poly1305Kernel.ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 1, r0, r1, s1);
        }

        // 2. Process Ciphertext (padded to 16-byte boundary)
        int ctOffset = 0;
        while (ctOffset + 16 <= ciphertext.Length)
        {
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(ciphertext.Slice(ctOffset, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(ciphertext.Slice(ctOffset + 8, 8));
            Poly1305Kernel.ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 1, r0, r1, s1);
            ctOffset += 16;
        }
        if (ctOffset < ciphertext.Length)
        {
            Span<byte> partialCt = stackalloc byte[16];
            ciphertext.Slice(ctOffset).CopyTo(partialCt);
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(partialCt.Slice(0, 8));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(partialCt.Slice(8, 8));
            Poly1305Kernel.ProcessBlock(ref h0, ref h1, ref h2, m0, m1, padBit: 1, r0, r1, s1);
        }

        // 3. Process Length Trailer (64-bit LE len(AAD) || 64-bit LE len(Ciphertext))
        ulong lenAad = (ulong)aad.Length;
        ulong lenCt = (ulong)ciphertext.Length;
        Poly1305Kernel.ProcessBlock(ref h0, ref h1, ref h2, lenAad, lenCt, padBit: 1, r0, r1, s1);

        // 4. Finalize Tag
        Poly1305Kernel.FinalizeTag(ref h0, ref h1, ref h2, polyKey, tag);
    }
}
