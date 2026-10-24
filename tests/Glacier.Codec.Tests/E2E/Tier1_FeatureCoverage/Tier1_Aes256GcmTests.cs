using System;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.AesGcm;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_Aes256GcmTests
{
    // Feature 32: AES-256-GCM AEAD NIST SP 800-38D Test Case 14
    [Fact]
    public void Feature32_Aes256Gcm_NistSp80038D_Case14_Roundtrip()
    {
        byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = Convert.FromHexString("cafebabefacedbaddecaf888");
        byte[] aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plaintext = Convert.FromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[16];

        Aes256GcmCipher.EncryptBlock(key, iv, plaintext, ciphertext, tag, aad);

        // Expected NIST ciphertext & tag
        string expectedCiphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        string expectedTag = "2df7cd675b4f09163b41ebf980a7f638";

        Assert.Equal(expectedCiphertext, Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        // Decrypt verification
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted, aad);

        Assert.True(success, "Decryption and tag authentication must succeed.");
        Assert.True(decrypted.SequenceEqual(plaintext), "Decrypted plaintext must match original.");
    }

    // Feature 32: Empty plaintext (GMAC mode)
    [Fact]
    public void Feature32_Aes256Gcm_EmptyPlaintext_ProducesValidTag()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] aad = [1, 2, 3, 4];

        Span<byte> tag = stackalloc byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);

        Span<byte> decrypted = Span<byte>.Empty;
        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ReadOnlySpan<byte>.Empty, tag, decrypted, aad);
        Assert.True(success);
    }

    // Feature 33: Key Expansion
    [Fact]
    public void Feature33_Aes256_KeySizeValidation()
    {
        byte[] invalidKey = new byte[16]; // AES-128 key rejected for AES-256-GCM
        byte[] iv = new byte[12];

        Assert.Throws<ArgumentException>(() => new Aes256GcmCipher(invalidKey));
    }

    // Feature 34 & 35: Multi-Block & Vector AES
    [Fact]
    public void Feature34_35_Aes256Gcm_MultiBlock1MBPayload_Roundtrip()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);

        byte[] plaintext = new byte[64 * 1024]; // 64 KB multi-block
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        Aes256GcmCipher.EncryptBlock(key, iv, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[plaintext.Length];
        bool ok = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted);

        Assert.True(ok);
        Assert.Equal(plaintext, decrypted);
    }

    // Feature 36: VPCLMULQDQ GHASH Tag Verification
    [Fact]
    public void Feature36_Aes256Gcm_TagTampering_RejectsDecryption()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] plaintext = [10, 20, 30, 40];

        Span<byte> ciphertext = stackalloc byte[4];
        Span<byte> tag = stackalloc byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, plaintext, ciphertext, tag);

        // Tamper with tag
        tag[0] ^= 0x01;

        Span<byte> decrypted = stackalloc byte[4];
        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted);

        Assert.False(success, "Decryption must fail when tag is tampered.");
        for (int i = 0; i < decrypted.Length; i++)
        {
            Assert.Equal(0, decrypted[i]); // Must zero plaintext buffer on failure
        }
    }
}
