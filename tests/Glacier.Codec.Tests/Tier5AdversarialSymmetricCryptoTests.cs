namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Xunit;

/// <summary>
/// Tier 5 Adversarial Test Suite for Symmetric Authenticated Encryption (AES-GCM & ChaCha20-Poly1305).
/// Verifies GHASH carryless multiplication boundaries, fail-secure zeroization on tag mismatch,
/// in-place transforms, and Poly1305 modulo reduction edges.
/// </summary>
public sealed class Tier5AdversarialSymmetricCryptoTests
{
    // =========================================================================
    // 1. AES-256-GCM GHASH & Ciphertext Boundary Matrix
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    public void AesGcm_AadBoundaryMatrix_RoundTripAndTagVerification(int aadLength)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[100];
        byte[] aad = new byte[aadLength];

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(aad);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        bool success = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.True(success);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(0)]   // GMAC authentication-only mode
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]  // Exact 1 block
    [InlineData(63)]
    [InlineData(64)]  // 4-way AES-NI pipeline boundary
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)] // 8-way AES-NI pipeline boundary
    [InlineData(129)]
    public void AesGcm_CiphertextBoundaryMatrix_RoundTrip(int plaintextLength)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[plaintextLength];
        byte[] aad = "Associated Data Header"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintextLength];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintextLength];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        bool success = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.True(success);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void AesGcm_FailSecure_MemoryWipe_OnTagMismatch()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = "Sensitive cryptographic payload to be zeroized"u8.ToArray();
        byte[] aad = "AAD"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        // Corrupt tag by 1 bit
        tag[0] ^= 0x01;

        byte[] destination = new byte[plaintext.Length];
        Array.Fill(destination, (byte)0xEE); // pre-populate with canary bytes

        bool success = cipher.Decrypt(ciphertext, aad, nonce, tag, destination);

        Assert.False(success);
        Assert.Equal(new byte[plaintext.Length], destination); // Destination must be completely zeroized
    }

    [Fact]
    public void AesGcm_InPlace_Decryption_CorruptTag_ZeroizesBuffer()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] payload = "In-place decryption payload buffer"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] inPlaceBuffer = new byte[payload.Length];
        payload.CopyTo(inPlaceBuffer, 0);

        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(inPlaceBuffer, default, nonce, inPlaceBuffer, tag);

        // Corrupt tag
        tag[15] ^= 0x80;

        bool success = cipher.Decrypt(inPlaceBuffer, default, nonce, tag, inPlaceBuffer);

        Assert.False(success);
        Assert.Equal(new byte[payload.Length], inPlaceBuffer); // Must be zeroized fail-secure
    }

    // =========================================================================
    // 2. ChaCha20-Poly1305 Block Alignments, Modulo Edges & Fail-Secure
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]  // Exact 1 ChaCha block
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)] // Exact 2 ChaCha blocks
    [InlineData(129)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    public void ChaCha20Poly1305_BlockAlignments_RoundTrip(int payloadLength)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[payloadLength];
        byte[] aad = "RFC 8439 AAD"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadLength];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[payloadLength];

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        bool success = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.True(success);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305_InPlace_EncryptionAndDecryption()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] original = new byte[512];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(original);

        byte[] buffer = (byte[])original.Clone();
        byte[] tag = new byte[16];

        using var cipher = new ChaCha20Poly1305Cipher(key);

        // In-place encrypt
        cipher.Encrypt(buffer, default, nonce, buffer, tag);
        Assert.NotEqual(original, buffer);

        // In-place decrypt
        bool ok = cipher.Decrypt(buffer, default, nonce, tag, buffer);
        Assert.True(ok);
        Assert.Equal(original, buffer);
    }

    [Fact]
    public void ChaCha20Poly1305_Poly1305_ModuloReduction_HighEntropyLimb()
    {
        // 1024 bytes of 0xFF: forces accumulator limbs to saturate and trigger full modulo 2^130 - 5 reduction
        byte[] allOnes = new byte[1024];
        Array.Fill(allOnes, (byte)0xFF);

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[allOnes.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[allOnes.Length];

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(allOnes, default, nonce, ciphertext, tag);

        bool ok = cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        Assert.True(ok);
        Assert.Equal(allOnes, decrypted);
    }

    [Theory]
    [InlineData(0)]  // Flip bit 0 of tag
    [InlineData(15)] // Flip high byte of tag
    public void ChaCha20Poly1305_TagCorruption_ReturnsFalseAndZeroizes(int byteIndex)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = "Fail-secure test string"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];
        Array.Fill(decrypted, (byte)0xCC);

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        tag[byteIndex] ^= 0x01;

        bool ok = cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        Assert.False(ok);
        Assert.Equal(new byte[plaintext.Length], decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305_CiphertextTampering_FailsAuthentication()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[100];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        ciphertext[0] ^= 0x01;

        bool ok = cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        Assert.False(ok);
        Assert.Equal(new byte[plaintext.Length], decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305_NonceTampering_FailsAuthentication()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[100];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        nonce[0] ^= 0x01;

        bool ok = cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        Assert.False(ok);
        Assert.Equal(new byte[plaintext.Length], decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305_AadTampering_FailsAuthentication()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[100];
        byte[] aad = "Valid Header"u8.ToArray();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.Length];

        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        byte[] tamperedAad = "Tampered Header"u8.ToArray();

        bool ok = cipher.Decrypt(ciphertext, tamperedAad, nonce, tag, decrypted);
        Assert.False(ok);
        Assert.Equal(new byte[plaintext.Length], decrypted);
    }
}
