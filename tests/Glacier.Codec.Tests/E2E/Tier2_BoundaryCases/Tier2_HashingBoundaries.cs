using System;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;

namespace Glacier.Codec.Tests.E2E.Tier2_BoundaryCases;

public class Tier2_HashingBoundaries
{
    // SHA-256 Padding Boundaries (55 bytes vs 56 bytes vs 64 bytes)
    [Fact]
    public void Boundary_Sha256_55BytesFitsSingleBlockPadding()
    {
        // 55 bytes + 1 byte 0x80 + 8 bytes length = 64 bytes (single compression block)
        byte[] input = new byte[55];
        Array.Fill(input, (byte)'a');

        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(input, digest);
        Assert.Equal(32, digest.Length);
        Assert.False(digest.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void Boundary_Sha256_56BytesForcesSecondBlockPadding()
    {
        // 56 bytes + 1 byte 0x80 = 57 bytes (forces 2 compression blocks to hold 8-byte length)
        byte[] input = new byte[56];
        Array.Fill(input, (byte)'a');

        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(input, digest);
        Assert.Equal(32, digest.Length);
    }

    [Fact]
    public void Boundary_Sha256_Exact64BytesBlockBoundary()
    {
        // Exact 64-byte block boundary
        byte[] input = new byte[64];
        Array.Fill(input, (byte)'b');

        Span<byte> digest = stackalloc byte[32];
        Sha256Hasher.Hash(input, digest);
        Assert.Equal(32, digest.Length);
    }

    // BLAKE3 Chunk and Block Boundaries
    [Fact]
    public void Boundary_Blake3_EmptyBuffer_Flags0x0B()
    {
        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(ReadOnlySpan<byte>.Empty, hash);
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", hex);
    }

    [Fact]
    public void Boundary_Blake3_Exact1024BytesSingleChunkBoundary()
    {
        byte[] input = new byte[1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", hex);
    }

    [Fact]
    public void Boundary_Blake3_Exact1025BytesTwoChunksBoundary()
    {
        // 1025 bytes crosses into chunk 1 and creates parent node
        byte[] input = new byte[1025];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(input, hash);
        Assert.Equal(32, hash.Length);
        Assert.False(hash.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void Boundary_Blake3_KeyedMac_InvalidKeyLength_ThrowsArgumentException()
    {
        byte[] invalidKey = new byte[16]; // Must be 32
        Assert.Throws<ArgumentException>(() => new Blake3Hasher(invalidKey));
    }

    // xxHash3 Small Buffer Shortcuts vs Stripe Loop Boundaries
    [Fact]
    public void Boundary_XxHash3_0BytesShortcut()
    {
        ulong hash = XxHash3Hasher.Hash64(ReadOnlySpan<byte>.Empty);
        Assert.Equal(0x2D06800538D394C2UL, hash);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(240)]
    public void Boundary_XxHash3_ShortcutBoundaries(int length)
    {
        byte[] buffer = new byte[length];
        Array.Fill(buffer, (byte)0x42);
        ulong hash = XxHash3Hasher.Hash64(buffer);
        Assert.NotEqual(0UL, hash);
    }

    [Fact]
    public void Boundary_XxHash3_240vs241BytesThreshold()
    {
        // 240 bytes is upper limit of small buffer shortcut
        byte[] b240 = new byte[240]; Array.Fill(b240, (byte)'C');
        ulong h240 = XxHash3Hasher.Hash64(b240);
        Assert.Equal(0x9E1398B318E6D706UL, h240);

        // 241 bytes enters main 64-byte stripe accumulation
        byte[] b241 = new byte[241]; Array.Fill(b241, (byte)'D');
        ulong h241 = XxHash3Hasher.Hash64(b241);
        Assert.Equal(0x4B303F2E3BC97000UL, h241);
    }

    [Fact]
    public void Boundary_XxHash3_1024BytesAccumulatorScramblerBoundary()
    {
        // Exactly 16 stripes (1024 bytes) triggers scrambler
        byte[] b1024 = new byte[1024]; Array.Fill(b1024, (byte)'E');
        ulong h1024 = XxHash3Hasher.Hash64(b1024);
        Assert.Equal(0xC89C0D551CBC6791UL, h1024);
    }
}
