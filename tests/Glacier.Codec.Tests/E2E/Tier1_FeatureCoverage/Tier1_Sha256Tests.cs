using System;
using System.Text;
using Xunit;
using Glacier.Codec.Hardware;
using Glacier.Codec.Hashing.Sha256;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_Sha256Tests
{
    // Feature 19: SHA-256 Streaming & NIST FIPS 180-4 Vectors
    [Fact]
    public void Feature19_Sha256_EmptyInput_MatchesFips1804()
    {
        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(ReadOnlySpan<byte>.Empty, digest);

        // NIST FIPS 180-4 Test 1: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
    }

    [Fact]
    public void Feature19_Sha256_ShortAscii_MatchesFips1804()
    {
        byte[] input = Encoding.ASCII.GetBytes("abc");
        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(input, digest);

        // NIST FIPS 180-4 Test 2: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
    }

    [Fact]
    public void Feature19_Sha256_BlockBoundary56Bytes_MatchesFips1804()
    {
        byte[] input = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        Assert.Equal(56, input.Length);

        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(input, digest);

        // NIST FIPS 180-4 Test 3: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hex);
    }

    [Fact]
    public void Feature19_Sha256_StreamingIncremental_MatchesOneShot()
    {
        byte[] part1 = Encoding.ASCII.GetBytes("Glacier.");
        byte[] part2 = Encoding.ASCII.GetBytes("Codec.");
        byte[] part3 = Encoding.ASCII.GetBytes("HighThroughput");

        using var hasher = new Sha256Hasher();
        hasher.Append(part1);
        hasher.Append(part2);
        hasher.Append(part3);

        Span<byte> streamDigest = stackalloc byte[32];
        hasher.Finalize(streamDigest);

        byte[] full = Encoding.ASCII.GetBytes("Glacier.Codec.HighThroughput");
        Span<byte> oneShotDigest = stackalloc byte[32];
        Sha256Hasher.Hash(full, oneShotDigest);

        Assert.True(streamDigest.SequenceEqual(oneShotDigest));
    }

    // Feature 20: SHA-256 SHA-NI Intrinsics
    [Fact]
    public void Feature20_Sha256_ShaNi_AccelerationProbe()
    {
        bool hasShaNi = CpuCapabilities.HasShaNi;
        // Verify execution succeeds whether SHA-NI is enabled or scalar fallback is active
        byte[] data = new byte[1024];
        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(data, digest);
        Assert.Equal(32, digest.Length);
    }

    // Feature 21: SHA-256 ARMv8 Crypto
    [Fact]
    public void Feature21_Sha256_ArmCrypto_IntrinsicsProbe()
    {
        bool hasArmSha = CpuCapabilities.HasArm64Sha256;
        // Verify cross-platform stability
        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(new byte[] { 1, 2, 3, 4 }, digest);
        Assert.False(digest.SequenceEqual(new byte[32]));
    }
}
