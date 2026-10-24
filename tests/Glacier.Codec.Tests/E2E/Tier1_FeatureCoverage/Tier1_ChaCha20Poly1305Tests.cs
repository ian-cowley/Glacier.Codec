using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_ChaCha20Poly1305Tests
{
    // Feature 37 & 40: RFC 8439 Section 2.8.2 AEAD Test Vector
    [Fact]
    public void Feature40_ChaCha20Poly1305_Rfc8439Section282_Roundtrip()
    {
        byte[] key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Convert.FromHexString("070000004041424344454647");
        byte[] aad = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[16];

        ChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        string expectedTag = "1ae10b594f09e26a7e902ecbd0600691";
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, decrypted, aad);

        Assert.True(success);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // Feature 38: SIMD Vectorization across multi-block
    [Fact]
    public void Feature38_ChaCha20_MultiBlockStream_Roundtrip()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[16 * 1024]; // 16 KB payload (multiple ChaCha20 64B blocks)
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[plaintext.Length];
        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, decrypted);

        Assert.True(success);
        Assert.Equal(plaintext, decrypted);
    }

    // Feature 39: Poly1305 Authenticator
    [Fact]
    public void Feature39_Poly1305_StandaloneMac()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] msg = Encoding.UTF8.GetBytes("Authentication test message for Poly1305");

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, msg, tag);

        Assert.Equal(16, tag.Length);
        Assert.False(tag.SequenceEqual(new byte[16]));
    }

    // Feature 40: AEAD with Empty Plaintext
    [Fact]
    public void Feature40_ChaCha20Poly1305_EmptyPlaintext_ProducesValidTag()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = [1, 2, 3, 4, 5];

        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305Cipher.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);

        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, aad);
        Assert.True(success);
    }

    [Fact]
    public void Feature40_ChaCha20Poly1305_TagTampering_Rejects()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = [1, 2, 3, 4];

        Span<byte> ciphertext = stackalloc byte[4];
        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag);

        tag[5] ^= 0xFF; // Tamper

        Span<byte> decrypted = stackalloc byte[4];
        bool success = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, decrypted);

        Assert.False(success);
        Assert.True(decrypted.SequenceEqual(new byte[4])); // Sanitized
    }
}
