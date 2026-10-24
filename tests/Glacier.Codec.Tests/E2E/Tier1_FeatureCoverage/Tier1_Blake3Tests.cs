using System;
using Xunit;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hashing.Blake3;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_Blake3Tests
{
    // Feature 8: BLAKE3 1024B Chunk State
    [Fact]
    public void Feature8_Blake3_ChunkState_SingleChunkExact1024Bytes()
    {
        byte[] input = new byte[1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden reference from official BLAKE3 test vectors:
        // 42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", hex);
    }

    // Feature 9: BLAKE3 Block Compression
    [Fact]
    public void Feature9_Blake3_BlockCompression_Exact64Bytes()
    {
        byte[] input = new byte[64];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden vector: 4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", hex);
    }

    [Fact]
    public void Feature9_Blake3_BlockCompression_65BytesTwoBlocks()
    {
        byte[] input = new byte[65];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden vector: de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", hex);
    }

    // Feature 10 & 11: BLAKE3 ARX Quarter-Round & Round Permutation
    [Fact]
    public void Feature10_11_Blake3_ARXAndPermutation_1ByteGoldenVector()
    {
        byte[] input = [(byte)0];
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden vector: 2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", hex);
    }

    // Feature 12: BLAKE3 State Flags
    [Fact]
    public void Feature12_Blake3_Flags_EmptyStreamSetsChunkStartEndAndRoot()
    {
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(ReadOnlySpan<byte>.Empty, hash);

        // Golden vector for empty: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", hex);
    }

    // Feature 13: BLAKE3 Keyed MAC Mode
    [Fact]
    public void Feature13_Blake3_KeyedMacMode_MatchesOfficialVector()
    {
        byte[] key = System.Text.Encoding.UTF8.GetBytes("whats the Elvish word for friend");
        Assert.Equal(32, key.Length);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.HashKeyed(ReadOnlySpan<byte>.Empty, key, hash);

        // Golden vector: 92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", hex);
    }

    [Fact]
    public void Feature13_Blake3_KeyedMac_DifferentKeysProduceDifferentHashes()
    {
        byte[] key1 = new byte[32]; key1[0] = 1;
        byte[] key2 = new byte[32]; key2[0] = 2;
        byte[] data = [1, 2, 3, 4, 5];

        Span<byte> h1 = stackalloc byte[32];
        Span<byte> h2 = stackalloc byte[32];

        Blake3Hasher.HashKeyed(data, key1, h1);
        Blake3Hasher.HashKeyed(data, key2, h2);

        Assert.False(h1.SequenceEqual(h2));
    }

    // Feature 14: BLAKE3 Key Derivation Mode (KDF)
    [Fact]
    public void Feature14_Blake3_KeyDerivationMode_MatchesOfficialVector()
    {
        string context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        using var kdf = Blake3Hasher.CreateKeyDerivation(context);

        Span<byte> derivedKey = stackalloc byte[32];
        kdf.Finalize(derivedKey);

        // Golden vector: 2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d
        string hex = Convert.ToHexString(derivedKey).ToLowerInvariant();
        Assert.Equal("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d", hex);
    }

    // Feature 15: BLAKE3 Extendable Output (XOF)
    [Fact]
    public void Feature15_Blake3_XOF_OutputsArbitraryLength()
    {
        using var hasher = new Blake3Hasher();
        hasher.Append(System.Text.Encoding.UTF8.GetBytes("XOF test"));

        Span<byte> out64 = stackalloc byte[64];
        hasher.Finalize(out64);

        Assert.NotEqual(0, out64[0]);
        Assert.NotEqual(0, out64[45]);
        Assert.NotEqual(0, out64[63]);
    }

    // Feature 16 & 17: BLAKE3 AVX2 & AVX-512 Kernels
    [Fact]
    public void Feature16_17_Blake3_VectorKernelEquivalence()
    {
        // 2048 bytes exercises multiple chunks
        byte[] input = new byte[2048];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden vector: e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", hex);
    }

    // Feature 18: BLAKE3 Parallel Tree Reduction
    [Fact]
    public void Feature18_Blake3_ParallelTreeReduction_4096Bytes()
    {
        byte[] input = new byte[4096];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        // Golden vector: 015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", hex);
    }
}
