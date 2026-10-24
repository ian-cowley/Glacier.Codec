using System;
using Xunit;
using Glacier.Codec.Cryptography.PostQuantum;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_MlKemTests
{
    // Feature 45: ML-KEM-768 (NIST FIPS 203, Rank k=3)
    [Fact]
    public void Feature45_MlKem768_BufferSizes_StrictlyConformToFips203()
    {
        var kem = MlKemEngine.MlKem768;
        Assert.Equal(1184, kem.PublicKeySizeInBytes);
        Assert.Equal(2400, kem.SecretKeySizeInBytes);
        Assert.Equal(1088, kem.CiphertextSizeInBytes);
        Assert.Equal(32, kem.SharedSecretSizeInBytes);
    }

    [Fact]
    public void Feature45_MlKem768_KeyGenAndEncapDecap_Roundtrip()
    {
        var kem = MlKemEngine.MlKem768;

        byte[] ek = new byte[kem.PublicKeySizeInBytes];
        byte[] dk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(ek, dk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
        kem.Encapsulate(ek, ct, ssA);

        byte[] ssB = new byte[kem.SharedSecretSizeInBytes];
        bool ok = kem.Decapsulate(dk, ct, ssB);

        Assert.True(ok, "Decapsulation must succeed for valid ciphertext.");
        Assert.Equal(ssA, ssB);
    }

    // Feature 46: ML-KEM-1024 (NIST FIPS 203, Rank k=4)
    [Fact]
    public void Feature46_MlKem1024_BufferSizes_StrictlyConformToFips203()
    {
        var kem = MlKemEngine.MlKem1024;
        Assert.Equal(1568, kem.PublicKeySizeInBytes);
        Assert.Equal(3168, kem.SecretKeySizeInBytes);
        Assert.Equal(1568, kem.CiphertextSizeInBytes);
        Assert.Equal(32, kem.SharedSecretSizeInBytes);
    }

    [Fact]
    public void Feature46_MlKem1024_KeyGenAndEncapDecap_Roundtrip()
    {
        var kem = MlKemEngine.MlKem1024;

        byte[] ek = new byte[kem.PublicKeySizeInBytes];
        byte[] dk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(ek, dk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
        kem.Encapsulate(ek, ct, ssA);

        byte[] ssB = new byte[kem.SharedSecretSizeInBytes];
        bool ok = kem.Decapsulate(dk, ct, ssB);

        Assert.True(ok);
        Assert.Equal(ssA, ssB);
    }

    // Feature 47 & 48: Vectorized NTT & Keccak/SHAKE
    [Fact]
    public void Feature47_48_MlKem_DistinctCiphertextsForRepeatedEncaps()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] ek = new byte[kem.PublicKeySizeInBytes];
        byte[] dk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(ek, dk);

        byte[] ct1 = new byte[kem.CiphertextSizeInBytes];
        byte[] ss1 = new byte[32];
        byte[] ct2 = new byte[kem.CiphertextSizeInBytes];
        byte[] ss2 = new byte[32];

        kem.Encapsulate(ek, ct1, ss1);
        kem.Encapsulate(ek, ct2, ss2);

        Assert.False(ct1.AsSpan().SequenceEqual(ct2), "Ciphertexts must be randomized across encapsulations.");
        Assert.False(ss1.AsSpan().SequenceEqual(ss2), "Shared secrets must be randomized across encapsulations.");
    }

    // Feature 49: Constant-Time Implicit Rejection
    [Fact]
    public void Feature49_MlKem768_TamperedCiphertext_TriggersImplicitRejection()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] ek = new byte[kem.PublicKeySizeInBytes];
        byte[] dk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(ek, dk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] originalSs = new byte[32];
        kem.Encapsulate(ek, ct, originalSs);

        // Tamper with ciphertext
        ct[0] ^= 0x01;

        byte[] rejectedSs = new byte[32];
        bool ok = kem.Decapsulate(dk, ct, rejectedSs);

        // Decapsulate returns false, but outputs deterministic pseudo-random reject key (implicit rejection)
        Assert.False(ok);
        Assert.False(originalSs.AsSpan().SequenceEqual(rejectedSs),
            "Implicit rejection must not return the original shared secret.");
        Assert.False(rejectedSs.AsSpan().SequenceEqual(new byte[32]),
            "Reject key must be non-zero pseudo-random value.");
    }
}
