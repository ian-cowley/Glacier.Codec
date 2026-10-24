using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.PostQuantum;

namespace Glacier.Codec.Tests.E2E.Tier3_CrossFeatureCombinations;

public class Tier3_PostQuantumHybridTunnel
{
    [Fact]
    public void Pairwise_MlKem768SharedSecret_Secures_Aes256GcmSession()
    {
        var kem = MlKemEngine.MlKem768;

        // 1. Receiver generates post-quantum keypair
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        // 2. Sender encapsulates shared secret
        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] senderSecret = new byte[kem.SharedSecretSizeInBytes];
        kem.Encapsulate(pk, ct, senderSecret);

        // 3. Sender encrypts data using shared secret as AES-256 key
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        byte[] payload = Encoding.UTF8.GetBytes("Post-quantum secured payload exchange over ML-KEM-768.");

        byte[] encryptedPayload = new byte[payload.Length];
        byte[] tag = new byte[16];
        Aes256GcmCipher.EncryptBlock(senderSecret, iv, payload, encryptedPayload, tag);

        // 4. Receiver decapsulates shared secret
        byte[] receiverSecret = new byte[kem.SharedSecretSizeInBytes];
        bool decapsOk = kem.Decapsulate(sk, ct, receiverSecret);
        Assert.True(decapsOk);
        Assert.Equal(senderSecret, receiverSecret);

        // 5. Receiver decrypts payload using decapsulated secret
        byte[] decryptedPayload = new byte[payload.Length];
        bool decryptOk = Aes256GcmCipher.DecryptBlock(receiverSecret, iv, encryptedPayload, tag, decryptedPayload);
        Assert.True(decryptOk);
        Assert.Equal(payload, decryptedPayload);
    }

    [Fact]
    public void Pairwise_MlKem1024SharedSecret_Secures_ChaCha20Poly1305Session()
    {
        var kem = MlKemEngine.MlKem1024;

        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] senderSecret = new byte[kem.SharedSecretSizeInBytes];
        kem.Encapsulate(pk, ct, senderSecret);

        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] payload = Encoding.UTF8.GetBytes("Post-quantum Level 5 secured payload over ML-KEM-1024.");

        byte[] encryptedPayload = new byte[payload.Length];
        byte[] tag = new byte[16];
        ChaCha20Poly1305Cipher.Encrypt(senderSecret, nonce, payload, encryptedPayload, tag);

        byte[] receiverSecret = new byte[kem.SharedSecretSizeInBytes];
        bool decapsOk = kem.Decapsulate(sk, ct, receiverSecret);
        Assert.True(decapsOk);

        byte[] decryptedPayload = new byte[payload.Length];
        bool decryptOk = ChaCha20Poly1305Cipher.Decrypt(receiverSecret, nonce, encryptedPayload, tag, decryptedPayload);
        Assert.True(decryptOk);
        Assert.Equal(payload, decryptedPayload);
    }
}
