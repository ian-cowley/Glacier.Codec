namespace Glacier.Codec.Tests;

using System;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hashing.Sha256;

public class Sha256Tests
{
    [Fact]
    public void Fips1804_EmptyInput_MatchesGoldenDigest()
    {
        Span<byte> digest = stackalloc byte[32];
        Sha256.Hash(ReadOnlySpan<byte>.Empty, digest);

        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
    }

    [Fact]
    public void Fips1804_ShortAsciiAbc_MatchesGoldenDigest()
    {
        byte[] input = Encoding.ASCII.GetBytes("abc");
        Span<byte> digest = stackalloc byte[32];
        Sha256.Hash(input, digest);

        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
    }

    [Fact]
    public void Fips1804_56ByteMessage_MatchesGoldenDigest()
    {
        byte[] input = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        Span<byte> digest = stackalloc byte[32];
        Sha256.Hash(input, digest);

        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hex);
    }

    [Fact]
    public void Fips1804_112ByteMessage_MatchesGoldenDigest()
    {
        byte[] input = Encoding.ASCII.GetBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        Span<byte> digest = stackalloc byte[32];
        Sha256.Hash(input, digest);

        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", hex);
    }

    [Fact]
    public void Fips1804_OneMillionA_MatchesGoldenDigest()
    {
        byte[] chunk = new byte[1000];
        Array.Fill(chunk, (byte)'a');

        using var hasher = new Sha256Hasher();
        for (int i = 0; i < 1000; i++)
        {
            hasher.Append(chunk);
        }

        Span<byte> digest = stackalloc byte[32];
        hasher.Finalize(digest);

        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        Assert.Equal("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hex);
    }

    [Fact]
    public void Sha256_ZeroAllocationsOnHotPath()
    {
        byte[] input = new byte[256];
        Array.Fill(input, (byte)0x42);
        Span<byte> digest = stackalloc byte[32];

        // Warm up JIT
        Sha256.Hash(input, digest);

        long before = GC.GetAllocatedBytesForCurrentThread();
        Sha256.Hash(input, digest);
        long after = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, after - before);
    }

    [Fact]
    public void Sha256_TryHash_BehavesCorrectly()
    {
        byte[] input = [1, 2, 3, 4];
        Span<byte> tooSmall = stackalloc byte[16];
        Assert.False(Sha256.TryHash(input, tooSmall, out int writtenSmall));
        Assert.Equal(0, writtenSmall);

        Span<byte> full = stackalloc byte[32];
        Assert.True(Sha256.TryHash(input, full, out int writtenFull));
        Assert.Equal(32, writtenFull);
    }

    [Fact]
    public void Sha256_VerifyHash_ConstantTimeComparison()
    {
        byte[] input = Encoding.UTF8.GetBytes("TestPayload");
        Span<byte> digest = stackalloc byte[32];
        Sha256.Hash(input, digest);

        Assert.True(Sha256.VerifyHash(input, digest));

        digest[0] ^= 0xFF;
        Assert.False(Sha256.VerifyHash(input, digest));
    }

    [Fact]
    public void Sha256Hasher_StreamingIncrementalChunks_MatchesOneShot()
    {
        byte[] full = new byte[1024];
        for (int i = 0; i < full.Length; i++) full[i] = (byte)(i * 31);

        using var hasher = new Sha256Hasher();
        int offset = 0;
        int[] chunkSizes = [1, 7, 55, 1, 64, 127, 256, 513];
        foreach (int size in chunkSizes)
        {
            hasher.Append(full.AsSpan(offset, size));
            offset += size;
        }

        Span<byte> streamDigest = stackalloc byte[32];
        hasher.Finalize(streamDigest);

        Span<byte> oneShotDigest = stackalloc byte[32];
        Sha256.Hash(full, oneShotDigest);

        Assert.True(streamDigest.SequenceEqual(oneShotDigest));
    }

    [Fact]
    public void Sha256Hasher_GetCurrentHash_IsNonDestructive()
    {
        using var hasher = new Sha256Hasher();
        hasher.Append(Encoding.UTF8.GetBytes("Part1"));

        Span<byte> intermediate = stackalloc byte[32];
        hasher.GetCurrentHash(intermediate);

        hasher.Append(Encoding.UTF8.GetBytes("Part2"));

        Span<byte> final = stackalloc byte[32];
        hasher.Finalize(final);

        Span<byte> expected = stackalloc byte[32];
        Sha256.Hash(Encoding.UTF8.GetBytes("Part1Part2"), expected);

        Assert.True(final.SequenceEqual(expected));
    }

    [Fact]
    public void Sha256Hasher_DisposedThrowsObjectDisposedException()
    {
        var hasher = new Sha256Hasher();
        hasher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => hasher.Append(new byte[10]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Reset());
        Assert.Throws<ObjectDisposedException>(() => hasher.GetCurrentHash(new byte[32]));
    }
}
