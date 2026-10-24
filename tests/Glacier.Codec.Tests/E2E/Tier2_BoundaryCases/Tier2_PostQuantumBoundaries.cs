using System;
using Xunit;
using Glacier.Codec.Cryptography.PostQuantum;

namespace Glacier.Codec.Tests.E2E.Tier2_BoundaryCases;

public class Tier2_PostQuantumBoundaries
{
    [Fact]
    public void Boundary_MlKem768_BufferUnderflow_ThrowsArgumentException()
    {
        var kem = MlKemEngine.MlKem768;

        byte[] smallPk = new byte[100]; // Expected 1184
        byte[] validSk = new byte[kem.SecretKeySizeInBytes];
        Assert.Throws<ArgumentException>(() => kem.GenerateKeyPair(smallPk, validSk));

        byte[] validPk = new byte[kem.PublicKeySizeInBytes];
        byte[] smallSk = new byte[100]; // Expected 2400
        Assert.Throws<ArgumentException>(() => kem.GenerateKeyPair(validPk, smallSk));
    }

    [Fact]
    public void Boundary_MlKem768_EncapsulateUnderflow_ThrowsArgumentException()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] smallCt = new byte[500]; // Expected 1088
        byte[] ss = new byte[32];
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(pk, smallCt, ss));

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] smallSs = new byte[16]; // Expected 32
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(pk, ct, smallSs));
    }

    [Fact]
    public void Boundary_MlKem1024_DecapsulateUnderflow_ThrowsArgumentException()
    {
        var kem = MlKemEngine.MlKem1024;
        byte[] smallSk = new byte[200];
        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ss = new byte[32];

        Assert.Throws<ArgumentException>(() => kem.Decapsulate(smallSk, ct, ss));
    }

    [Fact]
    public void Boundary_MlKem768_AllZeroCiphertext_ImplicitRejectionFailsGracefully()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] zeroCt = new byte[kem.CiphertextSizeInBytes];
        byte[] ss = new byte[32];

        bool ok = kem.Decapsulate(sk, zeroCt, ss);
        Assert.False(ok);
        Assert.False(ss.AsSpan().SequenceEqual(new byte[32]), "Reject key must be derived pseudo-random value.");
    }

    [Fact]
    public void Boundary_MlKem1024_TamperedCiphertext_ProducesConsistentRejectKey()
    {
        var kem = MlKemEngine.MlKem1024;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] originalSs = new byte[32];
        kem.Encapsulate(pk, ct, originalSs);

        ct[50] ^= 0x55; // Tamper

        byte[] rejectSs1 = new byte[32];
        byte[] rejectSs2 = new byte[32];

        bool ok1 = kem.Decapsulate(sk, ct, rejectSs1);
        bool ok2 = kem.Decapsulate(sk, ct, rejectSs2);

        Assert.False(ok1);
        Assert.False(ok2);
        // Deterministic implicit rejection: same corrupted ciphertext produces same reject key
        Assert.Equal(rejectSs1, rejectSs2);
    }
}
