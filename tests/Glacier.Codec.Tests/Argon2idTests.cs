namespace Glacier.Codec.Tests;

using System;
using System.Text;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Memory;
using Xunit;

public class Argon2idTests
{
    [Fact]
    public void Rfc9106_Section53_Test1_FullParameters_WithSecretAndAD()
    {
        // RFC 9106 Section 5.3 Test 1: Full parameters
        Span<byte> password = stackalloc byte[32];
        password.Fill(0x01);

        Span<byte> salt = stackalloc byte[16];
        salt.Fill(0x02);

        Span<byte> secret = stackalloc byte[8];
        secret.Fill(0x03);

        Span<byte> ad = stackalloc byte[12];
        ad.Fill(0x04);

        Span<byte> tag = stackalloc byte[32];

        using var argon2 = new Argon2id(iterations: 3, memoryKb: 32, parallelism: 4);
        argon2.DeriveKey(password, salt, secret, ad, tag);

        string expectedHex = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
        Assert.Equal(expectedHex, Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Rfc9106_Section53_Test2_PasswordAndSaltOnly()
    {
        // RFC 9106 Section 5.3 Test 2: Password and salt only
        Span<byte> password = stackalloc byte[32];
        password.Fill(0x01);

        Span<byte> salt = stackalloc byte[16];
        salt.Fill(0x02);

        Span<byte> tag = stackalloc byte[32];

        using var argon2 = new Argon2id(iterations: 3, memoryKb: 32, parallelism: 4);
        argon2.DeriveKey(password, salt, tag);

        string expectedHex = "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e";
        Assert.Equal(expectedHex, Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Rfc9106_RecommendedOption2_Baseline()
    {
        // RFC 9106 Recommended Option 2: t=2, m=65536 KiB (64 MiB), p=1
        byte[] password = Encoding.UTF8.GetBytes("password");
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");

        Span<byte> tag = stackalloc byte[32];

        using var argon2 = new Argon2id(iterations: 2, memoryKb: 65536, parallelism: 1);
        argon2.DeriveKey(password, salt, tag);

        string expectedHex = "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7";
        Assert.Equal(expectedHex, Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void ParameterValidation_EnforcesRFCBounds()
    {
        // m must be >= 8 * p
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 3, memoryKb: 16, parallelism: 4)); // 16 < 32
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 0, memoryKb: 64, parallelism: 1)); // t < 1
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2id(iterations: 1, memoryKb: 64, parallelism: 0)); // p < 1

        using var valid = new Argon2id(iterations: 1, memoryKb: 32, parallelism: 4);
        byte[] shortTag = new byte[2]; // tag < 4
        Assert.Throws<ArgumentException>(() => valid.DeriveKey(new byte[16], new byte[16], shortTag));
    }

    [Fact]
    public void MultiPass_ProducesDistinctEntropy()
    {
        byte[] pwdBytes = "SecretPassword123!"u8.ToArray();
        byte[] salt = "UniqueSaltBytes99"u8.ToArray();

        Span<byte> tag1 = stackalloc byte[32];
        Span<byte> tag2 = stackalloc byte[32];

        using var a1 = new Argon2id(iterations: 1, memoryKb: 64, parallelism: 1);
        a1.DeriveKey(pwdBytes, salt, tag1);

        using var a2 = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 1);
        a2.DeriveKey(pwdBytes, salt, tag2);

        Assert.False(tag1.SequenceEqual(tag2));
    }

    [Fact]
    public void StaticHelper_ParityWithInstanceMethod()
    {
        byte[] pwdBytes = "TestPassword"u8.ToArray();
        byte[] salt = "RandomSalt123456"u8.ToArray();

        Span<byte> tagInstance = stackalloc byte[32];
        Span<byte> tagStatic = stackalloc byte[32];
        Span<byte> tagDerive = stackalloc byte[32];

        using var argon2 = new Argon2id(iterations: 2, memoryKb: 64, parallelism: 2);
        argon2.DeriveKey(pwdBytes, salt, tagInstance);

        Argon2id.DeriveKey(pwdBytes, salt, tagStatic, iterations: 2, memoryKb: 64, parallelism: 2);
        Argon2id.Derive(pwdBytes, salt, tagDerive, iterations: 2, memoryKb: 64, parallelism: 2);

        Assert.True(tagInstance.SequenceEqual(tagStatic));
        Assert.True(tagInstance.SequenceEqual(tagDerive));
    }

    [Fact]
    public void Concurrency_MultiThreadedDerivation_IsSafeAndDeterministic()
    {
        byte[] pwdBytes = "ConcurrentTestPassword"u8.ToArray();
        byte[] salt = "ConcurrentSalt99"u8.ToArray();

        byte[] reference = new byte[32];
        Argon2id.DeriveKey(pwdBytes, salt, reference, iterations: 1, memoryKb: 64, parallelism: 2);

        Parallel.For(0, 16, _ =>
        {
            Span<byte> localTag = stackalloc byte[32];
            Argon2id.DeriveKey(pwdBytes, salt, localTag, iterations: 1, memoryKb: 64, parallelism: 2);
            Assert.True(localTag.SequenceEqual(reference));
        });
    }

    [Fact]
    public void ZeroAllocation_SteadyStateExecution()
    {
        byte[] pwdBytes = "ZeroAllocPassword"u8.ToArray();
        byte[] salt = "ZeroAllocSalt123"u8.ToArray();
        using var kdf = new Argon2id(iterations: 1, memoryKb: 32, parallelism: 4);

        Span<byte> tag = stackalloc byte[32];

        // Warm up
        kdf.DeriveKey(pwdBytes, salt, tag);

        long before = GC.GetAllocatedBytesForCurrentThread();
        kdf.DeriveKey(pwdBytes, salt, tag);
        long after = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, after - before);
    }
}
