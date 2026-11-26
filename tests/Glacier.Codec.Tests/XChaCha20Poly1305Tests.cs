namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Xunit;

public sealed class XChaCha20Poly1305Tests
{
    [Fact]
    public void HChaCha20_DraftIrtfVector_MatchesExactOutput()
    {
        // draft-irtf-cfrg-xchacha-03 Section 2.2.1
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce16 = Convert.FromHexString("000000090000004a0000000031415927");
        byte[] expectedSubkey = Convert.FromHexString("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");

        Span<byte> actualSubkey = stackalloc byte[32];
        XChaCha20Poly1305.DeriveSubkey(key, nonce16, actualSubkey);

        Assert.Equal(expectedSubkey, actualSubkey.ToArray());
    }

    [Fact]
    public void XChaCha20Poly1305_DraftIrtfAppendixA31Vector_MatchesExactCiphertextAndTag()
    {
        // draft-irtf-cfrg-xchacha-03 Appendix A.3.1
        byte[] key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Convert.FromHexString("404142434445464748494a4b4c4d4e4f5051525354555657");
        byte[] aad = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] expectedCiphertext = Convert.FromHexString(
            "bd6d179d3e83d43b9576579493c0e939" +
            "572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39" +
            "ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e" +
            "3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13" +
            "b52e");
        byte[] expectedTag = Convert.FromHexString("c0875924c1c7987947deafd8780acf49");

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        XChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);

        byte[] decrypted = new byte[plaintext.Length];
        bool ok = XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(4096)]
    public void Roundtrip_VariousPayloadSizes_Succeeds(int length)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] aad = Encoding.UTF8.GetBytes("Glacier.Storage.Header.v1");
        byte[] plaintext = new byte[length];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[length];

        using var cipher = new XChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        Assert.True(cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void InPlace_EncryptAndDecrypt_Succeeds()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] plaintext = Encoding.UTF8.GetBytes("Zero-copy in-place XChaCha20-Poly1305 payload");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] buffer = (byte[])plaintext.Clone();
        byte[] tag = new byte[16];

        XChaCha20Poly1305.Encrypt(key, nonce, buffer, buffer, tag);
        Assert.NotEqual(plaintext, buffer);
        Assert.True(XChaCha20Poly1305.Decrypt(key, nonce, buffer, tag, buffer));
        Assert.Equal(plaintext, buffer);
    }

    [Fact]
    public void TamperedTagOrCiphertext_ReturnsFalseAndZeroesDestination()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive archival payload that must be wiped on tamper.");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        XChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[plaintext.Length];
        Array.Fill(decrypted, (byte)0xAA);
        byte[] badTag = (byte[])tag.Clone();
        badTag[15] ^= 0x01;

        Assert.False(XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, badTag, decrypted));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));

        Array.Fill(decrypted, (byte)0xBB);
        byte[] badCt = (byte[])ciphertext.Clone();
        badCt[0] ^= 0x80;

        Assert.False(XChaCha20Poly1305.Decrypt(key, nonce, badCt, tag, decrypted));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void InvalidArgumentsAndDisposed_ThrowExpectedExceptions()
    {
        Assert.Throws<ArgumentException>(() => new XChaCha20Poly1305Cipher(new byte[31]));
        var cipher = new XChaCha20Poly1305Cipher(new byte[32]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[12], new byte[16], new byte[16]));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[24], new byte[16], new byte[15]));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[24], new byte[15], new byte[16]));

        cipher.Dispose();
        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(new byte[16], default, new byte[24], new byte[16], new byte[16]));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(new byte[16], default, new byte[24], new byte[16], new byte[16]));
    }
}
