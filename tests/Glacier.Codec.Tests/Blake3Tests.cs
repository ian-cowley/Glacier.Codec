namespace Glacier.Codec.Tests;

using System;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing.Blake3;

public class Blake3Tests
{
    [Fact]
    public void Blake3_GoldenVector_0Bytes()
    {
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(ReadOnlySpan<byte>.Empty, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_1Byte()
    {
        byte[] input = [(byte)0];
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_64BytesSingleBlock()
    {
        byte[] input = new byte[64];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_65BytesTwoBlocks()
    {
        byte[] input = new byte[65];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_1024BytesSingleChunk()
    {
        byte[] input = new byte[1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_2048BytesTwoChunks()
    {
        byte[] input = new byte[2048];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", hex);
    }

    [Fact]
    public void Blake3_GoldenVector_4096BytesFourChunks()
    {
        byte[] input = new byte[4096];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", hex);
    }

    [Fact]
    public void Blake3_KeyedMacMode_MatchesOfficialVector()
    {
        byte[] key = Encoding.UTF8.GetBytes("whats the Elvish word for friend");
        Assert.Equal(32, key.Length);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.HashKeyed(ReadOnlySpan<byte>.Empty, key, hash);

        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", hex);
    }

    [Fact]
    public void Blake3_KeyDerivationMode_MatchesOfficialVector()
    {
        string context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        using var kdf = Blake3Hasher.CreateKeyDerivation(context);

        Span<byte> derivedKey = stackalloc byte[32];
        kdf.Finalize(derivedKey);

        string hex = Convert.ToHexString(derivedKey).ToLowerInvariant();
        Assert.Equal("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d", hex);
    }

    [Fact]
    public void Blake3_ExtendableOutput_ArbitraryLength()
    {
        using var hasher = new Blake3Hasher();
        hasher.Append(Encoding.UTF8.GetBytes("XOF test"));

        Span<byte> out64 = stackalloc byte[64];
        hasher.Finalize(out64);

        Assert.NotEqual(0, out64[0]);
        Assert.NotEqual(0, out64[45]);
        Assert.NotEqual(0, out64[63]);
    }

    [Fact]
    public void Blake3_StreamingIncremental_MatchesOneShot()
    {
        byte[] payload = new byte[5000];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 251);

        using var hasher = new Blake3Hasher();
        int offset = 0;
        int[] chunkSizes = [10, 54, 64, 100, 796, 1024, 2952];
        foreach (int size in chunkSizes)
        {
            hasher.Append(payload.AsSpan(offset, size));
            offset += size;
        }

        Span<byte> streamDigest = stackalloc byte[32];
        hasher.Finalize(streamDigest);

        Span<byte> oneShotDigest = stackalloc byte[32];
        Blake3Hasher.Hash(payload, oneShotDigest);

        Assert.True(streamDigest.SequenceEqual(oneShotDigest));
    }

    [Fact]
    public void Blake3_DisposedThrowsObjectDisposedException()
    {
        var hasher = new Blake3Hasher();
        hasher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => hasher.Append(new byte[10]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Reset());
        Assert.Throws<ObjectDisposedException>(() => hasher.GetCurrentHash(new byte[32]));
    }
}
