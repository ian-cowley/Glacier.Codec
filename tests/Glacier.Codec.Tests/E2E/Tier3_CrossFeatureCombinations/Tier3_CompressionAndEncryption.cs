using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;

namespace Glacier.Codec.Tests.E2E.Tier3_CrossFeatureCombinations;

public class Tier3_CompressionAndEncryption
{
    [Fact]
    public void Pairwise_Lz4Compress_Then_Aes256GcmEncrypt_Roundtrip()
    {
        string document = "Confidential telemetry record: node=glacier-01, status=OK, memory=64GB, load=0.12.";
        byte[] plaintext = Encoding.UTF8.GetBytes(document);

        // 1. Compress
        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(plaintext.Length)];
        int compLen = Lz4Codec.Compress(plaintext, compressed);

        // 2. Encrypt compressed payload
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);

        byte[] ciphertext = new byte[compLen];
        byte[] tag = new byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, compressed.AsSpan(0, compLen), ciphertext, tag);

        // 3. Decrypt
        byte[] decryptedComp = new byte[compLen];
        bool authOk = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decryptedComp);
        Assert.True(authOk, "AEAD decryption and tag validation must succeed.");

        // 4. Decompress
        byte[] recoveredPlaintext = new byte[plaintext.Length];
        int decompLen = Lz4Codec.Decompress(decryptedComp, recoveredPlaintext);

        Assert.Equal(plaintext.Length, decompLen);
        Assert.Equal(document, Encoding.UTF8.GetString(recoveredPlaintext));
    }

    [Fact]
    public void Pairwise_ZstdCompress_Then_ChaCha20Poly1305Encrypt_Roundtrip()
    {
        byte[] data = new byte[2048];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 16); // High compressibility

        // 1. Compress
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(data.Length)];
        int compLen = ZstdCodec.Compress(data, compressed);

        // 2. Encrypt
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[compLen];
        byte[] tag = new byte[16];
        ChaCha20Poly1305Cipher.Encrypt(key, nonce, compressed.AsSpan(0, compLen), ciphertext, tag);

        // 3. Decrypt
        byte[] decryptedComp = new byte[compLen];
        bool authOk = ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, decryptedComp);
        Assert.True(authOk);

        // 4. Decompress
        byte[] recovered = new byte[data.Length];
        int decompLen = ZstdCodec.Decompress(decryptedComp, recovered);

        Assert.Equal(data.Length, decompLen);
        Assert.Equal(data, recovered);
    }

    [Fact]
    public void Pairwise_CorruptedCiphertext_FailsBeforeDecompression()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("Encrypted message test");
        byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(plaintext.Length)];
        int compLen = Lz4Codec.Compress(plaintext, compressed);

        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[compLen];
        byte[] tag = new byte[16];
        Aes256GcmCipher.EncryptBlock(key, iv, compressed.AsSpan(0, compLen), ciphertext, tag);

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01;

        byte[] decrypted = new byte[compLen];
        bool authOk = Aes256GcmCipher.DecryptBlock(key, iv, ciphertext, tag, decrypted);

        // Must reject without invoking decompressor on invalid bytes
        Assert.False(authOk);
    }
}
