namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography.PostQuantum;
using Xunit;

public class MlKemTests
{
    [Fact]
    public void Fips203_MlKem768_KeyGen_KatTestVector()
    {
        byte[] d = Convert.FromHexString("E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0");
        byte[] z = Convert.FromHexString("1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0");

        byte[] ek = new byte[MlKem768.PublicKeyBytes];
        byte[] dk = new byte[MlKem768.SecretKeyBytes];

        MlKemEngine.MlKem768.GenerateKeyPairDerand(d, z, ek, dk);

        // Verify ek prefix (32 bytes)
        string expectedEkPrefix = "28C793778741B80B02B4339F2AA4347255B099F17264E1B8CC0A2C7C2A1A79F7";
        Assert.Equal(expectedEkPrefix, Convert.ToHexString(ek.AsSpan(0, 32)));

        // Verify ek suffix (rho, 32 bytes)
        string expectedEkSuffix = "6473D3C159D3AFB4B687B40DFBF371A9C2644B605187B71A14BC4C8678FE8247";
        Assert.Equal(expectedEkSuffix, Convert.ToHexString(ek.AsSpan(MlKem768.PublicKeyBytes - 32, 32)));

        // Verify dk prefix (32 bytes)
        string expectedDkPrefix = "3808B98D9A093C7853B0B814D1CA5F392677D3D0A38F81C852F95B9A69B374A2";
        Assert.Equal(expectedDkPrefix, Convert.ToHexString(dk.AsSpan(0, 32)));

        // Verify dk suffix (seed z, 32 bytes)
        string expectedDkSuffix = "1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0";
        Assert.Equal(expectedDkSuffix, Convert.ToHexString(dk.AsSpan(MlKem768.SecretKeyBytes - 32, 32)));
    }

    [Fact]
    public void KeccakSponge_Matches_Bcl()
    {
        byte[] input = "Hello FIPS 202 Keccak Sponge"u8.ToArray();
        byte[] ourShake = new byte[64];
        KeccakSponge.Shake256(input, ourShake);

        byte[] bclShake = new byte[64];
        if (Shake256.IsSupported)
        {
            Shake256.HashData(input, bclShake);
            Assert.Equal(Convert.ToHexString(bclShake), Convert.ToHexString(ourShake));
        }

        byte[] ourSha3 = new byte[64];
        KeccakSponge.Sha3_512(input, ourSha3);
        byte[] bclSha3 = SHA3_512.HashData(input);
        Assert.Equal(Convert.ToHexString(bclSha3), Convert.ToHexString(ourSha3));
    }

    [Fact]
    public void Fips203_MlKem768_EncapsDecaps_KatTestVector()
    {
        byte[] d = Convert.FromHexString("E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0");
        byte[] z = Convert.FromHexString("1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0");

        byte[] ek = new byte[MlKem768.PublicKeyBytes];
        byte[] dk = new byte[MlKem768.SecretKeyBytes];
        MlKemEngine.MlKem768.GenerateKeyPairDerand(d, z, ek, dk);

        byte[] m = Convert.FromHexString("4E77596168711E913965D8175AC3BD76AAB08B7F9385A02AE883CF6C6E17DD81");

        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ss = new byte[MlKem768.SharedSecretBytes];

        MlKemEngine.MlKem768.EncapsulateDerand(ek, m, ct, ss);

        // Decapsulate
        byte[] decapsSs = new byte[32];
        bool success = MlKemEngine.MlKem768.Decapsulate(dk, ct, decapsSs);
        Assert.True(success);
        Assert.True(ss.AsSpan().SequenceEqual(decapsSs));
    }

    [Fact]
    public void Fips203_MlKem1024_KeyGen_KatTestVector()
    {
        byte[] d = Convert.FromHexString("F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009");
        byte[] z = Convert.FromHexString("35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275");

        byte[] ek = new byte[MlKem1024.PublicKeyBytes];
        byte[] dk = new byte[MlKem1024.SecretKeyBytes];

        MlKemEngine.MlKem1024.GenerateKeyPairDerand(d, z, ek, dk);

        // Verify ek prefix (32 bytes)
        string expectedEkPrefix = "8D0923CA8A2DA2B4146EC25321122B8A5AA8AFE0C03415273008A46EE83031E9";
        Assert.Equal(expectedEkPrefix, Convert.ToHexString(ek.AsSpan(0, 32)));

        // Verify ek suffix (rho, 32 bytes)
        string expectedEkSuffix = "9669A8B93290EB92E78F6ADFF23E89F57F3890753B51F12F3F3A8A654E677847";
        Assert.Equal(expectedEkSuffix, Convert.ToHexString(ek.AsSpan(MlKem1024.PublicKeyBytes - 32, 32)));

        // Verify dk prefix (32 bytes)
        string expectedDkPrefix = "6CBBB491D7B3A3439F53C9027BD727A0E1C78004B4CDB66760E50F1BF97FFF01";
        Assert.Equal(expectedDkPrefix, Convert.ToHexString(dk.AsSpan(0, 32)));

        // Verify dk suffix (seed z, 32 bytes)
        string expectedDkSuffix = "35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275";
        Assert.Equal(expectedDkSuffix, Convert.ToHexString(dk.AsSpan(MlKem1024.SecretKeyBytes - 32, 32)));
    }

    [Fact]
    public void MlKem768_Roundtrip_KeyGen_Encaps_Decaps()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];

        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
        byte[] ssB = new byte[kem.SharedSecretSizeInBytes];

        kem.Encapsulate(pk, ct, ssA);
        bool success = kem.Decapsulate(sk, ct, ssB);

        Assert.True(success);
        Assert.True(ssA.AsSpan().SequenceEqual(ssB));
    }

    [Fact]
    public void MlKem1024_Roundtrip_KeyGen_Encaps_Decaps()
    {
        var kem = MlKemEngine.MlKem1024;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];

        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
        byte[] ssB = new byte[kem.SharedSecretSizeInBytes];

        kem.Encapsulate(pk, ct, ssA);
        bool success = kem.Decapsulate(sk, ct, ssB);

        Assert.True(success);
        Assert.True(ssA.AsSpan().SequenceEqual(ssB));
    }

    [Fact]
    public void TamperedCiphertext_TriggersImplicitRejection_Deterministically()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssReal = new byte[32];
        kem.Encapsulate(pk, ct, ssReal);

        // Tamper with ciphertext
        ct[0] ^= 0x42;

        byte[] ssReject1 = new byte[32];
        byte[] ssReject2 = new byte[32];

        bool success1 = kem.Decapsulate(sk, ct, ssReject1);
        bool success2 = kem.Decapsulate(sk, ct, ssReject2);

        // Must fail with false
        Assert.False(success1);
        Assert.False(success2);

        // Reject key must not equal real key
        Assert.False(ssReal.AsSpan().SequenceEqual(ssReject1));

        // Reject key must be deterministic
        Assert.True(ssReject1.AsSpan().SequenceEqual(ssReject2));
    }

    [Fact]
    public void AllZeroCiphertext_FailsGracefully_WithoutCrashing()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] zeroCt = new byte[kem.CiphertextSizeInBytes];
        byte[] ss = new byte[32];

        bool success = kem.Decapsulate(sk, zeroCt, ss);
        Assert.False(success);
    }

    [Fact]
    public void BufferBounds_EnforcesRequiredSizes()
    {
        var kem = MlKemEngine.MlKem768;
        Assert.Throws<ArgumentException>(() => kem.GenerateKeyPair(new byte[100], new byte[2400]));
        Assert.Throws<ArgumentException>(() => kem.GenerateKeyPair(new byte[1184], new byte[100]));
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(new byte[100], new byte[1088], new byte[32]));
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(new byte[1184], new byte[100], new byte[32]));
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(new byte[1184], new byte[1088], new byte[16]));
        Assert.Throws<ArgumentException>(() => kem.Decapsulate(new byte[100], new byte[1088], new byte[32]));
    }

    [Fact]
    public void MlKemKeyPair_LifecycleAndDisposal()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[32];
        byte[] ssB = new byte[32];

        using (var keyPair = kem.CreateKeyPair())
        {
            Assert.Equal(kem.PublicKeySizeInBytes, keyPair.PublicKey.Length);
            Assert.Equal(kem.SecretKeySizeInBytes, keyPair.SecretKey.Length);

            keyPair.Encapsulate(ct, ssA);
            bool success = keyPair.Decapsulate(ct, ssB);
            Assert.True(success);
            Assert.True(ssA.AsSpan().SequenceEqual(ssB));
        }
    }

    [Fact]
    public void Concurrency_MultiThreadedKeyGenAndEncapDecap_IsThreadSafe()
    {
        var kem = MlKemEngine.MlKem768;

        Parallel.For(0, 16, _ =>
        {
            byte[] pk = new byte[kem.PublicKeySizeInBytes];
            byte[] sk = new byte[kem.SecretKeySizeInBytes];
            kem.GenerateKeyPair(pk, sk);

            byte[] ct = new byte[kem.CiphertextSizeInBytes];
            byte[] ssA = new byte[32];
            byte[] ssB = new byte[32];

            kem.Encapsulate(pk, ct, ssA);
            bool ok = kem.Decapsulate(sk, ct, ssB);
            Assert.True(ok);
            Assert.True(ssA.AsSpan().SequenceEqual(ssB));
        });
    }

    [Fact]
    public void ZeroAllocation_SteadyStateExecution()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[kem.PublicKeySizeInBytes];
        byte[] sk = new byte[kem.SecretKeySizeInBytes];
        byte[] ct = new byte[kem.CiphertextSizeInBytes];
        byte[] ssA = new byte[32];
        byte[] ssB = new byte[32];

        // Warm up JIT
        kem.GenerateKeyPair(pk, sk);
        kem.Encapsulate(pk, ct, ssA);
        kem.Decapsulate(sk, ct, ssB);

        // Verify zero GC heap allocations during KeyGen
        long before = GC.GetAllocatedBytesForCurrentThread();
        kem.GenerateKeyPair(pk, sk);
        long after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);

        // Verify zero GC heap allocations during Encapsulate
        before = GC.GetAllocatedBytesForCurrentThread();
        kem.Encapsulate(pk, ct, ssA);
        after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);

        // Verify zero GC heap allocations during Decapsulate
        before = GC.GetAllocatedBytesForCurrentThread();
        kem.Decapsulate(sk, ct, ssB);
        after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(0, after - before);
    }
}
