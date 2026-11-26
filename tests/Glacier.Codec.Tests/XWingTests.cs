namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Cryptography.CommittingAead;
using Glacier.Codec.Cryptography.EllipticCurve;
using Glacier.Codec.Cryptography.PostQuantum;
using Xunit;

public sealed class XWingTests
{
    [Fact]
    public void Roundtrip_KeyGenEncapDecap_And_KeyPairDispose_Succeeds()
    {
        using var kp = XWing.Instance.CreateKeyPair();
        Assert.Equal(XWing.PublicKeyBytes, kp.PublicKey.Length);
        Assert.Equal(XWing.SecretKeyBytes, kp.SecretKey.Length);

        byte[] ct = new byte[XWing.CiphertextBytes];
        byte[] ssEnc = new byte[XWing.SharedSecretBytes];
        byte[] ssDec = new byte[XWing.SharedSecretBytes];

        kp.Encapsulate(ct, ssEnc);
        kp.Decapsulate(ct, ssDec);

        Assert.Equal(ssEnc, ssDec);
    }

    [Fact]
    public void DeterministicComposition_MatchesExplicitMlKem768PlusX25519PlusSha3Combiner()
    {
        byte[] skSeed = new byte[32];
        byte[] eseed = new byte[64];
        for (int i = 0; i < 32; i++) skSeed[i] = (byte)(i + 1);
        for (int i = 0; i < 64; i++) eseed[i] = (byte)(0x80 + i);

        byte[] pk = new byte[XWing.PublicKeyBytes];
        byte[] sk = new byte[XWing.SecretKeyBytes];
        byte[] ct = new byte[XWing.CiphertextBytes];
        byte[] ssEnc = new byte[XWing.SharedSecretBytes];
        byte[] ssDec = new byte[XWing.SharedSecretBytes];

        XWing.Instance.GenerateKeyPairDerand(skSeed, pk, sk);
        XWing.Instance.EncapsulateDerand(pk, eseed, ct, ssEnc);
        XWing.Instance.Decapsulate(sk, ct, ssDec);
        Assert.Equal(ssEnc, ssDec);

        // Manually verify exact draft-connolly-cfrg-xwing-kem derivation
        byte[] expanded = new byte[96];
        KeccakSponge.Shake256(skSeed, expanded);

        byte[] pkM = new byte[MlKem768.PublicKeyBytes];
        byte[] skM = new byte[MlKem768.SecretKeyBytes];
        MlKemEngine.MlKem768.GenerateKeyPairDerand(expanded[..32], expanded[32..64], pkM, skM);

        byte[] pkX = new byte[32];
        X25519.ScalarMultBase(expanded[64..96], pkX);

        Assert.Equal(pkM, pk[..MlKem768.PublicKeyBytes]);
        Assert.Equal(pkX, pk[MlKem768.PublicKeyBytes..]);

        byte[] ctM = new byte[MlKem768.CiphertextBytes];
        byte[] ssM = new byte[32];
        MlKemEngine.MlKem768.EncapsulateDerand(pkM, eseed[..32], ctM, ssM);

        byte[] ctX = new byte[32];
        byte[] ssX = new byte[32];
        X25519.ScalarMultBase(eseed[32..64], ctX);
        X25519.ScalarMult(eseed[32..64], pkX, ssX);

        Assert.Equal(ctM, ct[..MlKem768.CiphertextBytes]);
        Assert.Equal(ctX, ct[MlKem768.CiphertextBytes..]);

        byte[] label = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
        byte[] combinerIn = new byte[134];
        ssM.CopyTo(combinerIn, 0);
        ssX.CopyTo(combinerIn, 32);
        ctX.CopyTo(combinerIn, 64);
        pkX.CopyTo(combinerIn, 96);
        label.CopyTo(combinerIn, 128);

        byte[] expectedSs = new byte[32];
        KeccakSponge.Sha3_256(combinerIn, expectedSs);
        Assert.Equal(expectedSs, ssEnc);
    }

    [Fact]
    public void TamperedCiphertextHalves_ImplicitlyRejectWithoutException()
    {
        byte[] pk = new byte[XWing.PublicKeyBytes];
        byte[] sk = new byte[XWing.SecretKeyBytes];
        XWing.GenerateKeys(pk, sk);

        byte[] ct = new byte[XWing.CiphertextBytes];
        byte[] ssValid = new byte[32];
        XWing.EncapsulateSecret(pk, ct, ssValid);

        // Tamper ML-KEM half
        byte[] badCtM = (byte[])ct.Clone();
        badCtM[0] ^= 0x01;
        byte[] ssBadM = new byte[32];
        XWing.DecapsulateSecret(sk, badCtM, ssBadM);
        Assert.NotEqual(ssValid, ssBadM);

        // Tamper X25519 half
        byte[] badCtX = (byte[])ct.Clone();
        badCtX[MlKem768.CiphertextBytes] ^= 0x01;
        byte[] ssBadX = new byte[32];
        XWing.DecapsulateSecret(sk, badCtX, ssBadX);
        Assert.NotEqual(ssValid, ssBadX);

        // Deterministic implicit rejection on repeated tampered decapsulation
        byte[] ssBadMRepeat = new byte[32];
        XWing.DecapsulateSecret(sk, badCtM, ssBadMRepeat);
        Assert.Equal(ssBadM, ssBadMRepeat);
    }

    [Fact]
    public void NonCanonicalMlKemEncapsulationKey_ThrowsCryptographicException()
    {
        byte[] pk = new byte[XWing.PublicKeyBytes];
        byte[] sk = new byte[XWing.SecretKeyBytes];
        XWing.GenerateKeys(pk, sk);

        // Corrupt first 12-bit coefficient to 4095 (>= 3329)
        pk[0] = 0xFF;
        pk[1] |= 0x0F;

        byte[] ct = new byte[XWing.CiphertextBytes];
        byte[] ss = new byte[32];
        Assert.Throws<CryptographicException>(() => XWing.EncapsulateSecret(pk, ct, ss));
    }

    [Theory]
    [InlineData(CommittingAeadAlgorithm.XChaCha20Poly1305, 24)]
    [InlineData(CommittingAeadAlgorithm.Aes256GcmSiv, 12)]
    public void HybridPostQuantumTunnel_XWingWithCommittingAead_EndToEndSucceeds(
        CommittingAeadAlgorithm algorithm,
        int nonceLen)
    {
        using var recipient = XWing.Instance.CreateKeyPair();
        byte[] kemCt = new byte[XWing.CiphertextBytes];
        byte[] senderSecret = new byte[XWing.SharedSecretBytes];
        XWing.EncapsulateSecret(recipient.PublicKey, kemCt, senderSecret);

        byte[] nonce = new byte[nonceLen];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = Encoding.UTF8.GetBytes("Glacier.Storage.HybridEnvelope.v1");
        byte[] payload = Encoding.UTF8.GetBytes("Hybrid X-Wing + CMT-4 key-committing archival payload");

        byte[] ciphertext = new byte[payload.Length];
        byte[] tag = new byte[CommittingAead.TagSize];
        CommittingAead.Encrypt(senderSecret, nonce, payload, ciphertext, tag, aad, algorithm);

        byte[] recipientSecret = new byte[XWing.SharedSecretBytes];
        recipient.Decapsulate(kemCt, recipientSecret);
        Assert.Equal(senderSecret, recipientSecret);

        byte[] decrypted = new byte[payload.Length];
        Assert.True(CommittingAead.Decrypt(recipientSecret, nonce, ciphertext, tag, decrypted, aad, algorithm));
        Assert.Equal(payload, decrypted);
    }
}
