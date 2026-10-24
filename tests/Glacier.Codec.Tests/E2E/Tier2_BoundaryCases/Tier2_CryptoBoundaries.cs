using System;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.Kdf;

namespace Glacier.Codec.Tests.E2E.Tier2_BoundaryCases;

public class Tier2_CryptoBoundaries
{
    // AES-256-GCM Boundaries
    [Fact]
    public void Boundary_Aes256Gcm_EmptyPlaintext_EmptyAad()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        Span<byte> tag = stackalloc byte[16];

        Aes256GcmCipher.EncryptBlock(key, iv, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, ReadOnlySpan<byte>.Empty);

        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, ReadOnlySpan<byte>.Empty);
        Assert.True(success);
    }

    [Fact]
    public void Boundary_Aes256Gcm_SingleBitCiphertextTampering_ZeroesPlaintext()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] plaintext = [0xDE, 0xAD, 0xBE, 0xEF];

        Span<byte> ciphertext = stackalloc byte[4];
        Span<byte> tag = stackalloc byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, plaintext, ciphertext, tag);

        // Flip bit 0 of ciphertext
        ciphertext[0] ^= 0x01;

        Span<byte> decrypted = stackalloc byte[4];
        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted);

        Assert.False(success);
        Assert.Equal(0, decrypted[0]);
        Assert.Equal(0, decrypted[1]);
        Assert.Equal(0, decrypted[2]);
        Assert.Equal(0, decrypted[3]);
    }

    [Fact]
    public void Boundary_Aes256Gcm_SingleBitAadTampering_Rejects()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] aad = [1, 2, 3];
        byte[] plaintext = [5, 6, 7];

        Span<byte> ciphertext = stackalloc byte[3];
        Span<byte> tag = stackalloc byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, plaintext, ciphertext, tag, aad);

        byte[] tamperedAad = [1, 2, 4]; // 3 -> 4

        Span<byte> decrypted = stackalloc byte[3];
        bool success = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted, tamperedAad);
        Assert.False(success);
    }

    // ChaCha20-Poly1305 Boundaries
    [Fact]
    public void Boundary_ChaCha20Poly1305_EmptyPlaintext_EmptyAad()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        Span<byte> tag = stackalloc byte[16];

        ChaCha20Poly1305Cipher.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, ReadOnlySpan<byte>.Empty);

        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, ReadOnlySpan<byte>.Empty);
        Assert.True(success);
    }

    [Fact]
    public void Boundary_ChaCha20Poly1305_SingleBitCiphertextTampering_ZeroesPlaintext()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = [0xCA, 0xFE, 0xBA, 0xBE];

        Span<byte> ciphertext = stackalloc byte[4];
        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag);

        ciphertext[2] ^= 0x08;

        Span<byte> decrypted = stackalloc byte[4];
        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, decrypted);

        Assert.False(success);
        Assert.True(decrypted.SequenceEqual(new byte[4]));
    }

    // Argon2id Parameter Boundaries
    [Theory]
    [InlineData(0, 32, 4)]  // Iterations = 0 invalid
    [InlineData(3, 16, 4)]  // Memory 16 < 8*p (32) invalid
    [InlineData(3, 32, 0)]  // Parallelism = 0 invalid
    public void Boundary_Argon2id_InvalidParameters_ThrowsException(int t, int m, int p)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(t, m, p));
    }
}
