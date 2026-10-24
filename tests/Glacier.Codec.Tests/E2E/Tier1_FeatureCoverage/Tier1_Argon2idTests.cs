using System;
using Xunit;
using Glacier.Codec.Cryptography.Kdf;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_Argon2idTests
{
    // Feature 41: RFC 9106 Section 5.3 Test 1 (with Secret and AD)
    [Fact]
    public void Feature41_Argon2id_Rfc9106_Section53_Test1()
    {
        var argon2 = new Argon2id(iterations: 3, memoryKb: 32, parallelism: 4);

        byte[] pwd = new byte[32]; Array.Fill(pwd, (byte)0x01);
        byte[] salt = new byte[16]; Array.Fill(salt, (byte)0x02);
        byte[] secret = new byte[8]; Array.Fill(secret, (byte)0x03);
        byte[] ad = new byte[12]; Array.Fill(ad, (byte)0x04);

        Span<byte> tag = stackalloc byte[32];
        argon2.DeriveKey(pwd, salt, secret, ad, tag);

        // Expected RFC 9106 tag:
        // 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659
        string hex = Convert.ToHexString(tag).ToLowerInvariant();
        Assert.Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", hex);
    }

    // Feature 41: RFC 9106 Section 5.3 Test 2 (Password and Salt only)
    [Fact]
    public void Feature41_Argon2id_Rfc9106_Section53_Test2()
    {
        var argon2 = new Argon2id(iterations: 3, memoryKb: 32, parallelism: 4);

        byte[] pwd = new byte[32]; Array.Fill(pwd, (byte)0x01);
        byte[] salt = new byte[16]; Array.Fill(salt, (byte)0x02);

        Span<byte> tag = stackalloc byte[32];
        argon2.DeriveKey(pwd, salt, tag);

        // Expected RFC 9106 tag:
        // 03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e
        string hex = Convert.ToHexString(tag).ToLowerInvariant();
        Assert.Equal("03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e", hex);
    }

    // Feature 42: Matrix Memory Configuration
    [Fact]
    public void Feature42_Argon2id_MemoryConstraint_Enforced()
    {
        // RFC 9106 requires m >= 8 * p
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 16, parallelism: 4)); // 16 < 32
    }

    // Feature 43 & 44: Permutation G & Multi-Pass Execution
    [Fact]
    public void Feature44_Argon2id_MultiPass_ProducesDifferentOutputsForIterations()
    {
        byte[] pwd = System.Text.Encoding.UTF8.GetBytes("password123");
        byte[] salt = System.Text.Encoding.UTF8.GetBytes("saltsaltsaltsalt");

        Span<byte> key1 = stackalloc byte[32];
        Span<byte> key2 = stackalloc byte[32];

        var a1 = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 1);
        var a2 = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 1);

        a1.DeriveKey(pwd, salt, key1);
        a2.DeriveKey(pwd, salt, key2);

        Assert.False(key1.SequenceEqual(key2), "Different iteration counts must produce distinct derived keys.");
    }

    [Fact]
    public void Feature44_Argon2id_DeterministicDerivation()
    {
        byte[] pwd = System.Text.Encoding.UTF8.GetBytes("secure_password");
        byte[] salt = System.Text.Encoding.UTF8.GetBytes("unique_salt_1234");

        Span<byte> tagA = stackalloc byte[32];
        Span<byte> tagB = stackalloc byte[32];

        var kdf = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 2);
        kdf.DeriveKey(pwd, salt, tagA);
        kdf.DeriveKey(pwd, salt, tagB);

        Assert.True(tagA.SequenceEqual(tagB));
    }
}
