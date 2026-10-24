using System;
using System.Text;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.PostQuantum;
using Glacier.Codec.Hashing.Blake3;

namespace Glacier.Codec.Tests.E2E.Tier4_RealWorldScenarios;

public class Tier4_PqSecureSessionHandshake
{
    [Fact]
    public void Scenario_PostQuantumHandshake_And_AuthenticatedSession()
    {
        var pqKem = MlKemEngine.MlKem768;

        // Step 1: Alice generates ephemeral ML-KEM-768 keypair
        byte[] alicePublicKey = new byte[pqKem.PublicKeySizeInBytes];
        byte[] aliceSecretKey = new byte[pqKem.SecretKeySizeInBytes];
        pqKem.GenerateKeyPair(alicePublicKey, aliceSecretKey);

        // Step 2: Bob receives Alice's public key, encapsulates 32B shared secret
        byte[] ciphertext = new byte[pqKem.CiphertextSizeInBytes];
        byte[] bobSharedSecret = new byte[pqKem.SharedSecretSizeInBytes];
        pqKem.Encapsulate(alicePublicKey, ciphertext, bobSharedSecret);

        // Step 3: Alice decapsulates shared secret using her secret key
        byte[] aliceSharedSecret = new byte[pqKem.SharedSecretSizeInBytes];
        bool decapsOk = pqKem.Decapsulate(aliceSecretKey, ciphertext, aliceSharedSecret);
        Assert.True(decapsOk, "Alice must successfully decapsulate shared secret.");
        Assert.Equal(bobSharedSecret, aliceSharedSecret);

        // Step 4: Both parties derive duplex session keys via BLAKE3 KDF (Alice->Bob key, Bob->Alice key)
        using var kdfAliceToBob = Blake3Hasher.CreateKeyDerivation("Glacier.Session.Channel.AliceToBob.v1");
        kdfAliceToBob.Append(aliceSharedSecret);
        Span<byte> keyAliceToBob = stackalloc byte[32];
        kdfAliceToBob.Finalize(keyAliceToBob);

        using var kdfBobToAlice = Blake3Hasher.CreateKeyDerivation("Glacier.Session.Channel.BobToAlice.v1");
        kdfBobToAlice.Append(bobSharedSecret);
        Span<byte> keyBobToAlice = stackalloc byte[32];
        kdfBobToAlice.Finalize(keyBobToAlice);

        // Keys are directional and cryptographically separated
        Assert.False(keyAliceToBob.SequenceEqual(keyBobToAlice));

        // Step 5: Alice sends encrypted request to Bob
        byte[] requestNonce = new byte[12];
        RandomNumberGenerator.Fill(requestNonce);
        byte[] requestAad = Encoding.UTF8.GetBytes("Routing: Host=cluster-node-7, Op=Query");
        byte[] requestBody = Encoding.UTF8.GetBytes("SELECT * FROM financial_records WHERE year = 2026;");

        byte[] encRequest = new byte[requestBody.Length];
        byte[] requestTag = new byte[16];
        Aes256GcmCipher.EncryptBlock(keyAliceToBob, requestNonce, requestBody, encRequest, requestTag, requestAad);

        // Bob decrypts request
        byte[] decRequest = new byte[requestBody.Length];
        bool bobAuth = Aes256GcmCipher.DecryptBlock(keyAliceToBob, requestNonce, encRequest, requestTag, decRequest, requestAad);
        Assert.True(bobAuth);
        Assert.Equal(requestBody, decRequest);

        // Step 6: Bob sends encrypted response to Alice
        byte[] responseNonce = new byte[12];
        RandomNumberGenerator.Fill(responseNonce);
        byte[] responseAad = Encoding.UTF8.GetBytes("Routing: Host=client-terminal, Status=200");
        byte[] responseBody = Encoding.UTF8.GetBytes("QueryResult: rows=4200, executionTime=1.2ms;");

        byte[] encResponse = new byte[responseBody.Length];
        byte[] responseTag = new byte[16];
        Aes256GcmCipher.EncryptBlock(keyBobToAlice, responseNonce, responseBody, encResponse, responseTag, responseAad);

        // Alice decrypts response
        byte[] decResponse = new byte[responseBody.Length];
        bool aliceAuth = Aes256GcmCipher.DecryptBlock(keyBobToAlice, responseNonce, encResponse, responseTag, decResponse, responseAad);
        Assert.True(aliceAuth);
        Assert.Equal(responseBody, decResponse);
    }
}
