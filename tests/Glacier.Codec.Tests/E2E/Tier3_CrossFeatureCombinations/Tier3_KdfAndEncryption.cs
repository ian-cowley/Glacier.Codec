using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Hashing.Blake3;

namespace Glacier.Codec.Tests.E2E.Tier3_CrossFeatureCombinations;

public class Tier3_KdfAndEncryption
{
    [Fact]
    public void Pairwise_Argon2idKdf_Drives_Aes256GcmSession()
    {
        byte[] password = Encoding.UTF8.GetBytes("UserMasterPassword#2026");
        byte[] salt = Encoding.UTF8.GetBytes("EnterpriseSalt99");

        // 1. Derive 256-bit key via Argon2id
        Span<byte> sessionKey = stackalloc byte[32];
        var kdf = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 1);
        kdf.DeriveKey(password, salt, sessionKey);

        // 2. Encrypt sensitive payload using derived key
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        byte[] secretMessage = Encoding.UTF8.GetBytes("Confidential bank account numbers: 1234-5678-9012.");

        byte[] ciphertext = new byte[secretMessage.Length];
        byte[] tag = new byte[16];
        Aes256GcmCipher.EncryptBlock(sessionKey, iv, secretMessage, ciphertext, tag);

        // 3. Decrypt using same KDF-derived key
        byte[] decrypted = new byte[secretMessage.Length];
        bool ok = Aes256GcmCipher.DecryptBlock(sessionKey, iv, ciphertext, tag, decrypted);

        Assert.True(ok);
        Assert.Equal(secretMessage, decrypted);
    }

    [Fact]
    public void Pairwise_Blake3Kdf_Drives_ChaCha20Poly1305Session()
    {
        string context = "Glacier.Codec Secure Tunnel Context v1";
        using var kdf = Blake3Hasher.CreateKeyDerivation(context);
        kdf.Append(Encoding.UTF8.GetBytes("SharedPreMasterSecret"));

        Span<byte> sessionKey = stackalloc byte[32];
        kdf.Finalize(sessionKey);

        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] message = Encoding.UTF8.GetBytes("Authenticated stream payload over Blake3 derived key.");

        byte[] ciphertext = new byte[message.Length];
        byte[] tag = new byte[16];
        ChaCha20Poly1305Cipher.Encrypt(sessionKey, nonce, message, ciphertext, tag);

        byte[] decrypted = new byte[message.Length];
        bool ok = ChaCha20Poly1305Cipher.Decrypt(sessionKey, nonce, ciphertext, tag, decrypted);

        Assert.True(ok);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void Pairwise_DifferentContexts_YieldIndependentKeys()
    {
        using var kdf1 = Blake3Hasher.CreateKeyDerivation("App.Context.User");
        using var kdf2 = Blake3Hasher.CreateKeyDerivation("App.Context.Admin");

        byte[] ikm = Encoding.UTF8.GetBytes("IdenticalInputKeyMaterial");
        kdf1.Append(ikm);
        kdf2.Append(ikm);

        Span<byte> key1 = stackalloc byte[32];
        Span<byte> key2 = stackalloc byte[32];
        kdf1.Finalize(key1);
        kdf2.Finalize(key2);

        Assert.False(key1.SequenceEqual(key2), "Different KDF contexts must derive cryptographically independent keys.");
    }
}
