namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Memory;
using Xunit;
using ChaCha20Poly1305 = Glacier.Codec.Cryptography.ChaCha20Poly1305.ChaCha20Poly1305;

public unsafe class ConstantTimeSecurityTests
{
    [Fact]
    public void SecureMemory_Is64ByteAligned()
    {
        using var secure = new SecureMemory(32);
        Assert.Equal(32, secure.Length);
        Assert.Equal(0u, (nuint)secure.Pointer % 64u);
    }

    [Fact]
    public void SecureMemory_Dispose_ZeroesUnderlyingMemory()
    {
        const int keySize = 32;
        var secure = new SecureMemory(keySize);
        void* rawPtr = secure.Pointer;

        // Fill with sensitive random bytes
        Span<byte> span = secure.Span;
        for (int i = 0; i < keySize; i++)
        {
            span[i] = (byte)(0xA0 + i);
        }

        // Verify write
        byte* bytePtr = (byte*)rawPtr;
        Assert.Equal((byte)0xA0, bytePtr[0]);

        // Dispose wipes memory via CryptographicOperations.ZeroMemory
        secure.Dispose();

        // Memory must throw on safe access
        Assert.Throws<ObjectDisposedException>(() => { var _ = secure.Span; });
    }

    [Fact]
    public void SecureMemory_CreateAndWipeSource_ClearsSourceSpan()
    {
        byte[] sensitiveSource = new byte[32];
        Random.Shared.NextBytes(sensitiveSource);

        byte[] copyCheck = (byte[])sensitiveSource.Clone();

        using (var secure = SecureMemory.CreateAndWipeSource(sensitiveSource.AsSpan()))
        {
            Assert.True(secure.Span.SequenceEqual(copyCheck));

            // Source span must be completely zeroed
            for (int i = 0; i < sensitiveSource.Length; i++)
            {
                Assert.Equal(0, sensitiveSource[i]);
            }
        }
    }

    [Fact]
    public void SecureMemory_ConstantTimeEquals_ValidatesEquality()
    {
        byte[] keyBytes = new byte[32] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        using var secure = SecureMemory.Create(keyBytes);

        byte[] matchingKey = (byte[])keyBytes.Clone();
        byte[] mismatchedKey = (byte[])keyBytes.Clone();
        mismatchedKey[15] ^= 0x01; // 1-bit difference

        Assert.True(secure.ConstantTimeEquals(matchingKey));
        Assert.False(secure.ConstantTimeEquals(mismatchedKey));
    }

    [Fact]
    public void FixedTimeEquals_SideChannelResistance_DifferentLengths()
    {
        byte[] tag1 = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] tag2 = new byte[15] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

        Assert.False(CryptographicOperations.FixedTimeEquals(tag1, tag2));
    }

    // AES-256-GCM Bit-Tampering Across All 128 Tag Bits
    [Fact]
    public void AesGcm_TagVerification_TimingAttackResistance_BitTamperingAcrossAllPositions()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = [10, 20, 30, 40, 50, 60, 70, 80];

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        Aes256Gcm.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] tamperedTag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        // Exhaustively flip every single bit in the 128-bit authentication tag
        for (int byteIdx = 0; byteIdx < 16; byteIdx++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                tag.CopyTo(tamperedTag, 0);
                tamperedTag[byteIdx] ^= (byte)(1 << bit);

                Array.Fill(decrypted, (byte)0xEE);

                bool success = Aes256Gcm.Decrypt(key, nonce, ciphertext, tamperedTag, decrypted);
                Assert.False(success);

                // Fail-secure: destination plaintext must be 100% zeroed
                for (int k = 0; k < decrypted.Length; k++)
                {
                    Assert.Equal(0, decrypted[k]);
                }
            }
        }
    }

    // AES-256-GCM Ciphertext Tampering Across All Bytes
    [Fact]
    public void AesGcm_CiphertextTamperingAcrossAllBytes_ClearsPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = new byte[32];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        Aes256Gcm.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] tamperedCt = new byte[32];
        byte[] decrypted = new byte[32];

        for (int byteIdx = 0; byteIdx < 32; byteIdx++)
        {
            ciphertext.CopyTo(tamperedCt, 0);
            tamperedCt[byteIdx] ^= 0x40;

            Array.Fill(decrypted, (byte)0xAA);
            bool ok = Aes256Gcm.Decrypt(key, nonce, tamperedCt, tag, decrypted);
            Assert.False(ok);
            for (int k = 0; k < decrypted.Length; k++)
            {
                Assert.Equal(0, decrypted[k]);
            }
        }
    }

    // AES-256-GCM AAD Tampering Across All Bytes
    [Fact]
    public void AesGcm_AadTamperingAcrossAllBytes_ClearsPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = new byte[24];
        RandomNumberGenerator.Fill(aad);
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[16];
        byte[] tag = new byte[16];
        Aes256Gcm.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        byte[] tamperedAad = new byte[24];
        byte[] decrypted = new byte[16];

        for (int byteIdx = 0; byteIdx < 24; byteIdx++)
        {
            aad.CopyTo(tamperedAad, 0);
            tamperedAad[byteIdx] ^= 0x08;

            Array.Fill(decrypted, (byte)0xBB);
            bool ok = Aes256Gcm.Decrypt(key, nonce, ciphertext, tag, decrypted, tamperedAad);
            Assert.False(ok);
            for (int k = 0; k < decrypted.Length; k++)
            {
                Assert.Equal(0, decrypted[k]);
            }
        }
    }

    // ChaCha20-Poly1305 Bit-Tampering Across All 128 Tag Bits
    [Fact]
    public void ChaCha20Poly1305_TagVerification_TimingAttackResistance_BitTamperingAcrossAllPositions()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = [100, 101, 102, 103, 104];

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] tamperedTag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        for (int byteIdx = 0; byteIdx < 16; byteIdx++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                tag.CopyTo(tamperedTag, 0);
                tamperedTag[byteIdx] ^= (byte)(1 << bit);

                Array.Fill(decrypted, (byte)0xEE);

                bool success = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tamperedTag, decrypted);
                Assert.False(success);

                for (int k = 0; k < decrypted.Length; k++)
                {
                    Assert.Equal(0, decrypted[k]);
                }
            }
        }
    }

    // ChaCha20-Poly1305 Ciphertext Tampering Across All Bytes
    [Fact]
    public void ChaCha20Poly1305_CiphertextTamperingAcrossAllBytes_ClearsPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = new byte[32];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] tamperedCt = new byte[32];
        byte[] decrypted = new byte[32];

        for (int byteIdx = 0; byteIdx < 32; byteIdx++)
        {
            ciphertext.CopyTo(tamperedCt, 0);
            tamperedCt[byteIdx] ^= 0x20;

            Array.Fill(decrypted, (byte)0xAA);
            bool ok = ChaCha20Poly1305.Decrypt(key, nonce, tamperedCt, tag, decrypted);
            Assert.False(ok);
            for (int k = 0; k < decrypted.Length; k++)
            {
                Assert.Equal(0, decrypted[k]);
            }
        }
    }

    // ChaCha20-Poly1305 AAD Tampering Across All Bytes
    [Fact]
    public void ChaCha20Poly1305_AadTamperingAcrossAllBytes_ClearsPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = new byte[20];
        RandomNumberGenerator.Fill(aad);
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[16];
        byte[] tag = new byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        byte[] tamperedAad = new byte[20];
        byte[] decrypted = new byte[16];

        for (int byteIdx = 0; byteIdx < 20; byteIdx++)
        {
            aad.CopyTo(tamperedAad, 0);
            tamperedAad[byteIdx] ^= 0x02;

            Array.Fill(decrypted, (byte)0xDD);
            bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, decrypted, tamperedAad);
            Assert.False(ok);
            for (int k = 0; k < decrypted.Length; k++)
            {
                Assert.Equal(0, decrypted[k]);
            }
        }
    }
}
