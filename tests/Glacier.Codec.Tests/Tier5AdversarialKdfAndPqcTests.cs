namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Cryptography.PostQuantum;
using Xunit;

/// <summary>
/// Tier 5 Adversarial Test Suite for Memory-Hard KDF (Argon2id) and Post-Quantum Cryptography (ML-KEM).
/// Tests minimal RFC 9106 memory grids, NTT/INTT butterfly edges, SampleNTT rejection loops,
/// and constant-time implicit rejection upon ciphertext/key corruption.
/// </summary>
public sealed class Tier5AdversarialKdfAndPqcTests
{
    // =========================================================================
    // 1. Argon2id Minimal Memory Grids & Parameter Edge Cases
    // =========================================================================

    [Theory]
    [InlineData(1, 8, 1)]   // Minimal memory: p=1, m=8KB, t=1 (q=8, s=2)
    [InlineData(1, 8, 2)]   // Minimal memory multi-pass
    [InlineData(1, 8, 3)]   // Minimal memory 3 passes
    [InlineData(2, 16, 1)]  // Minimal memory: p=2, m=16KB, t=1
    [InlineData(2, 16, 2)]  // Minimal memory: p=2, m=16KB, t=2
    [InlineData(4, 32, 1)]  // Minimal memory: p=4, m=32KB, t=1
    [InlineData(4, 32, 2)]  // Minimal memory: p=4, m=32KB, t=2
    [InlineData(4, 32, 3)]  // Minimal memory: p=4, m=32KB, t=3
    public void Argon2id_MinimalMemory_GridParameters_Deterministic(int p, int m, int t)
    {
        byte[] pwd = new byte[32];
        byte[] saltBytes = new byte[16];
        RandomNumberGenerator.Fill(pwd);
        RandomNumberGenerator.Fill(saltBytes);

        byte[] tag1 = new byte[32];
        byte[] tag2 = new byte[32];

        using (var kdf1 = new Argon2id(iterations: t, memoryKb: m, parallelism: p))
        {
            kdf1.DeriveKey(pwd, saltBytes, tag1);
        }

        using (var kdf2 = new Argon2id(iterations: t, memoryKb: m, parallelism: p))
        {
            kdf2.DeriveKey(pwd, saltBytes, tag2);
        }

        Assert.Equal(tag1, tag2);
        Assert.False(tag1.AsSpan().SequenceEqual(new byte[32]));
    }

    [Fact]
    public void Argon2id_InvalidMemory_ThrowsArgumentOutOfRangeException()
    {
        // Must be >= 8 * parallelism
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 7, parallelism: 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 15, parallelism: 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 31, parallelism: 4));
    }

    [Fact]
    public void Argon2id_InvalidIterationsOrParallelism_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 0, memoryKb: 64, parallelism: 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 64, parallelism: 0));
    }

    [Theory]
    [InlineData(4)]   // Minimum 4 bytes
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void Argon2id_TagLength_Variations(int tagLength)
    {
        byte[] pwd = new byte[32];
        byte[] saltBytes = new byte[16];
        RandomNumberGenerator.Fill(pwd);
        RandomNumberGenerator.Fill(saltBytes);
        byte[] tag = new byte[tagLength];

        using var kdf = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 1);
        kdf.DeriveKey(pwd, saltBytes, tag);

        Assert.False(tag.AsSpan().SequenceEqual(new byte[tagLength]));
    }

    [Fact]
    public void Argon2id_WithSecretAndAssociatedData_ProducesDistinctKeys()
    {
        byte[] pwd = new byte[32];
        byte[] saltBytes = new byte[16];
        byte[] pepperBytes = new byte[16];
        byte[] aadBytes = new byte[16];
        RandomNumberGenerator.Fill(pwd);
        RandomNumberGenerator.Fill(saltBytes);
        RandomNumberGenerator.Fill(pepperBytes);
        RandomNumberGenerator.Fill(aadBytes);

        byte[] tagBase = new byte[32];
        byte[] tagWithSecret = new byte[32];
        byte[] tagWithAad = new byte[32];

        using var kdf = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 1);

        kdf.DeriveKey(pwd, saltBytes, tagBase);
        kdf.DeriveKey(pwd, saltBytes, pepperBytes, ReadOnlySpan<byte>.Empty, tagWithSecret);
        kdf.DeriveKey(pwd, saltBytes, ReadOnlySpan<byte>.Empty, aadBytes, tagWithAad);

        Assert.NotEqual(tagBase, tagWithSecret);
        Assert.NotEqual(tagBase, tagWithAad);
        Assert.NotEqual(tagWithSecret, tagWithAad);
    }

    // =========================================================================
    // 2. ML-KEM SampleNTT Rejection Sampling & Extreme NTT Butterflies
    // =========================================================================

    [Fact]
    public void MlKem_SampleNTT_50DistinctSeeds_CoefficientsInRange()
    {
        byte[] rho = new byte[32];
        short[] aHat = new short[256];

        for (int s = 0; s < 50; s++)
        {
            RandomNumberGenerator.Fill(rho);

            for (byte j = 0; j < 3; j++)
            {
                for (byte i = 0; i < 3; i++)
                {
                    KeccakSponge.SampleNTT(rho, j, i, aHat);

                    for (int k = 0; k < 256; k++)
                    {
                        Assert.InRange(aHat[k], 0, 3328);
                    }
                }
            }
        }
    }

    [Fact]
    public void MlKem_NTT_ZeroPolynomial_Invertible()
    {
        short[] poly = new short[256]; // All zeros
        short[] copy = (short[])poly.Clone();

        NttTransform.ForwardNtt(poly);
        Assert.Equal(copy, poly); // NTT of 0 is 0

        NttTransform.InverseNtt(poly);
        Assert.Equal(copy, poly); // INTT of 0 is 0
    }

    [Fact]
    public void MlKem_NTT_ConstantPolynomial_Invertible()
    {
        short[] poly = new short[256];
        poly[0] = 1; // f(x) = 1

        short[] expected = (short[])poly.Clone();

        NttTransform.ForwardNtt(poly);
        // FIPS 203 incomplete NTT decomposes into 128 quadratic factors (len >= 2),
        // so constant polynomial 1 yields pairs (1, 0)
        for (int i = 0; i < 256; i++)
        {
            Assert.Equal((i % 2 == 0) ? 1 : 0, poly[i]);
        }

        NttTransform.InverseNtt(poly);
        Assert.Equal(expected, poly);
    }

    [Fact]
    public void MlKem_NTT_ExtremeAlternatingPolynomial_Invertible()
    {
        short[] poly = new short[256];
        for (int i = 0; i < 256; i++)
        {
            poly[i] = 3328; // Equivalent to -1 mod 3329
        }

        short[] original = (short[])poly.Clone();

        NttTransform.ForwardNtt(poly);
        NttTransform.InverseNtt(poly);

        Assert.Equal(original, poly);
    }

    [Fact]
    public void MlKem_NTT_UnitImpulseHighestDegree_Invertible()
    {
        short[] poly = new short[256];
        poly[255] = 1; // Highest degree term

        short[] original = (short[])poly.Clone();

        NttTransform.ForwardNtt(poly);
        NttTransform.InverseNtt(poly);

        Assert.Equal(original, poly);
    }

    [Fact]
    public void MlKem_NTT_RandomPolynomials_ExactInvertibility()
    {
        short[] poly = new short[256];
        short[] original = new short[256];

        for (int test = 0; test < 100; test++)
        {
            for (int i = 0; i < 256; i++)
            {
                poly[i] = (short)Random.Shared.Next(0, 3329);
                original[i] = poly[i];
            }

            NttTransform.ForwardNtt(poly);
            NttTransform.InverseNtt(poly);

            Assert.Equal(original, poly);
        }
    }

    // =========================================================================
    // 3. ML-KEM Constant-Time Implicit Rejection Hardening
    // =========================================================================

    [Fact]
    public void MlKem768_Decapsulate_CorruptByte0_ImplicitRejection_ReturnsFalseAndPseudorandomKey()
    {
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem768.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem768.SharedSecretBytes];

        MlKemEngine.MlKem768.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem768.Encapsulate(pk, ct, ssGolden);

        // Corrupt byte 0 of ciphertext
        ct[0] ^= 0x01;

        bool success = MlKemEngine.MlKem768.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
        Assert.False(ssRejected.AsSpan().SequenceEqual(new byte[32])); // Pseudorandom, not zero
    }

    [Fact]
    public void MlKem768_Decapsulate_CorruptMiddleByte_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem768.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem768.SharedSecretBytes];

        MlKemEngine.MlKem768.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem768.Encapsulate(pk, ct, ssGolden);

        ct[ct.Length / 2] ^= 0x80;

        bool success = MlKemEngine.MlKem768.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }

    [Fact]
    public void MlKem768_Decapsulate_CorruptLastByte_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem768.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem768.SharedSecretBytes];

        MlKemEngine.MlKem768.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem768.Encapsulate(pk, ct, ssGolden);

        ct[ct.Length - 1] ^= 0x40;

        bool success = MlKemEngine.MlKem768.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }

    [Fact]
    public void MlKem768_Decapsulate_CorruptSecretKey_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem768.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem768.SharedSecretBytes];

        MlKemEngine.MlKem768.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem768.Encapsulate(pk, ct, ssGolden);

        sk[10] ^= 0x01; // Corrupt secret key

        bool success = MlKemEngine.MlKem768.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }

    [Fact]
    public void MlKem1024_Decapsulate_CorruptByte0_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem1024.PublicKeyBytes];
        byte[] sk = new byte[MlKem1024.SecretKeyBytes];
        byte[] ct = new byte[MlKem1024.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem1024.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem1024.SharedSecretBytes];

        MlKemEngine.MlKem1024.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem1024.Encapsulate(pk, ct, ssGolden);

        ct[0] ^= 0x01;

        bool success = MlKemEngine.MlKem1024.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }

    [Fact]
    public void MlKem1024_Decapsulate_CorruptLastByte_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem1024.PublicKeyBytes];
        byte[] sk = new byte[MlKem1024.SecretKeyBytes];
        byte[] ct = new byte[MlKem1024.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem1024.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem1024.SharedSecretBytes];

        MlKemEngine.MlKem1024.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem1024.Encapsulate(pk, ct, ssGolden);

        ct[ct.Length - 1] ^= 0xFF;

        bool success = MlKemEngine.MlKem1024.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }

    [Fact]
    public void MlKem1024_Decapsulate_CorruptSecretKey_ImplicitRejection()
    {
        byte[] pk = new byte[MlKem1024.PublicKeyBytes];
        byte[] sk = new byte[MlKem1024.SecretKeyBytes];
        byte[] ct = new byte[MlKem1024.CiphertextBytes];
        byte[] ssGolden = new byte[MlKem1024.SharedSecretBytes];
        byte[] ssRejected = new byte[MlKem1024.SharedSecretBytes];

        MlKemEngine.MlKem1024.GenerateKeyPair(pk, sk);
        MlKemEngine.MlKem1024.Encapsulate(pk, ct, ssGolden);

        sk[100] ^= 0x02;

        bool success = MlKemEngine.MlKem1024.Decapsulate(sk, ct, ssRejected);

        Assert.False(success);
        Assert.NotEqual(ssGolden, ssRejected);
    }
}
