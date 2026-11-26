namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Cryptography.CommittingAead;
using Xunit;

public sealed class CommittingAeadTests
{
    [Theory]
    [InlineData(CommittingAeadAlgorithm.Aes256Gcm, 12, 0)]
    [InlineData(CommittingAeadAlgorithm.Aes256Gcm, 12, 2048)]
    [InlineData(CommittingAeadAlgorithm.XChaCha20Poly1305, 24, 0)]
    [InlineData(CommittingAeadAlgorithm.XChaCha20Poly1305, 24, 2048)]
    [InlineData(CommittingAeadAlgorithm.Aes256GcmSiv, 12, 0)]
    [InlineData(CommittingAeadAlgorithm.Aes256GcmSiv, 12, 2048)]
    public void Roundtrip_AllAlgorithmsAndSizes_Succeeds(CommittingAeadAlgorithm algorithm, int nonceLen, int payloadLen)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[nonceLen];
        byte[] aad = Encoding.UTF8.GetBytes("tenant-id=42");
        byte[] plaintext = new byte[payloadLen];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadLen];
        byte[] tag = new byte[CommittingAead.TagSize];
        byte[] decrypted = new byte[payloadLen];

        using var cipher = new CommittingAeadCipher(key, algorithm);
        Assert.Equal(nonceLen, cipher.NonceSizeInBytes);
        Assert.Equal(48, cipher.TagSizeInBytes);

        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        Assert.True(cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted));
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(CommittingAeadAlgorithm.Aes256Gcm, 12)]
    [InlineData(CommittingAeadAlgorithm.XChaCha20Poly1305, 24)]
    [InlineData(CommittingAeadAlgorithm.Aes256GcmSiv, 12)]
    public void KeyCommitment_RejectsWrongKeyAndTamperedCommitmentOrTag(CommittingAeadAlgorithm algorithm, int nonceLen)
    {
        byte[] keyA = new byte[32];
        byte[] keyB = new byte[32];
        byte[] nonce = new byte[nonceLen];
        byte[] plaintext = Encoding.UTF8.GetBytes("Multi-tenant Glacier.Storage deduplicated chunk");
        RandomNumberGenerator.Fill(keyA);
        RandomNumberGenerator.Fill(keyB);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[48];
        CommittingAead.Encrypt(keyA, nonce, plaintext, ciphertext, tag, algorithm: algorithm);

        // Wrong master key fails and zeroes plaintext
        byte[] decrypted = new byte[plaintext.Length];
        Array.Fill(decrypted, (byte)0x55);
        Assert.False(CommittingAead.Decrypt(keyB, nonce, ciphertext, tag, decrypted, algorithm: algorithm));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));

        // Tampered commitment byte [0..31] fails and zeroes plaintext
        Array.Fill(decrypted, (byte)0x66);
        byte[] badCommitTag = (byte[])tag.Clone();
        badCommitTag[7] ^= 0x01;
        Assert.False(CommittingAead.Decrypt(keyA, nonce, ciphertext, badCommitTag, decrypted, algorithm: algorithm));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));

        // Tampered inner AEAD tag byte [32..47] fails and zeroes plaintext
        Array.Fill(decrypted, (byte)0x77);
        byte[] badInnerTag = (byte[])tag.Clone();
        badInnerTag[40] ^= 0x80;
        Assert.False(CommittingAead.Decrypt(keyA, nonce, ciphertext, badInnerTag, decrypted, algorithm: algorithm));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void CrossAlgorithmConfusion_FailsCleanly()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = Encoding.UTF8.GetBytes("Algorithm domain separation check");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[48];
        CommittingAead.Encrypt(key, nonce, plaintext, ciphertext, tag, algorithm: CommittingAeadAlgorithm.Aes256Gcm);

        byte[] decrypted = new byte[plaintext.Length];
        Array.Fill(decrypted, (byte)0xAA);
        Assert.False(CommittingAead.Decrypt(key, nonce, ciphertext, tag, decrypted, algorithm: CommittingAeadAlgorithm.Aes256GcmSiv));
        Assert.All(decrypted, b => Assert.Equal((byte)0, b));
    }
}
