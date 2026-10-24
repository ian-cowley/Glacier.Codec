namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Hashing.XxHash3;
using BclXxHash3 = System.IO.Hashing.XxHash3;
using BclXxHash128 = System.IO.Hashing.XxHash128;

public class XxHash3BclParityTests
{
    private static readonly ulong[] TestSeeds =
    [
        0UL,
        1UL,
        12345UL,
        123456789UL,
        0x9E3779B185EBCA87UL,
        0xC2B2AE3D27D4EB4FUL,
        0x165667B19E3779F9UL,
        0xFFFFFFFFFFFFFFFFUL
    ];

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void OneShot_Hash64_MatchesBcl_AcrossSeeds(int length)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);

        foreach (ulong seed in TestSeeds)
        {
            ulong expected = BclXxHash3.HashToUInt64(buffer, (long)seed);
            ulong actual = XxHash3.Hash64(buffer, seed);
            Assert.Equal(expected, actual);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void OneShot_Hash128_MatchesBcl_AcrossSeeds(int length)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);

        foreach (ulong seed in TestSeeds)
        {
            UInt128 expected = BclXxHash128.HashToUInt128(buffer, (long)seed);
            UInt128 actual = XxHash3.Hash128(buffer, seed);
            Assert.Equal(expected, actual);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(15)]
    [InlineData(31)]
    [InlineData(65)]
    [InlineData(130)]
    [InlineData(240)]
    [InlineData(250)]
    [InlineData(1025)]
    public void Streaming_Hash64_MatchesBcl_AcrossSeeds(int length)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);
        Span<byte> dest = stackalloc byte[8];

        foreach (ulong seed in TestSeeds)
        {
            ulong expected = BclXxHash3.HashToUInt64(buffer, (long)seed);

            using var stream = new XxHash3Stream(hashSize: 8, seed: seed);
            int offset = 0;
            while (offset < length)
            {
                int chunkSize = Math.Min(length - offset, Random.Shared.Next(1, 64));
                stream.Append(buffer.AsSpan(offset, chunkSize));
                offset += chunkSize;
            }

            stream.GetCurrentHash(dest);
            ulong actual = BinaryPrimitives.ReadUInt64LittleEndian(dest);

            Assert.Equal(expected, actual);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(15)]
    [InlineData(31)]
    [InlineData(65)]
    [InlineData(130)]
    [InlineData(240)]
    [InlineData(250)]
    [InlineData(1025)]
    public void Streaming_Hash128_MatchesBcl_AcrossSeeds(int length)
    {
        byte[] buffer = new byte[length];
        Random.Shared.NextBytes(buffer);
        Span<byte> dest = stackalloc byte[16];

        foreach (ulong seed in TestSeeds)
        {
            UInt128 expected = BclXxHash128.HashToUInt128(buffer, (long)seed);

            using var stream = new XxHash3Stream(hashSize: 16, seed: seed);
            int offset = 0;
            while (offset < length)
            {
                int chunkSize = Math.Min(length - offset, Random.Shared.Next(1, 64));
                stream.Append(buffer.AsSpan(offset, chunkSize));
                offset += chunkSize;
            }

            stream.GetCurrentHash(dest);
            ulong low = BinaryPrimitives.ReadUInt64LittleEndian(dest);
            ulong high = BinaryPrimitives.ReadUInt64LittleEndian(dest.Slice(8));
            UInt128 actual = new UInt128(high, low);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void OneShot_Continuous0To4096_MatchesBcl_AcrossSeeds()
    {
        byte[] buffer = new byte[4096];
        Random.Shared.NextBytes(buffer);

        ulong[] seeds = [0UL, 1UL, 12345UL, 123456789UL, 0x9E3779B185EBCA87UL];

        for (int len = 0; len <= 4096; len++)
        {
            ReadOnlySpan<byte> slice = buffer.AsSpan(0, len);
            foreach (ulong seed in seeds)
            {
                ulong expected64 = BclXxHash3.HashToUInt64(slice, (long)seed);
                ulong actual64 = XxHash3.Hash64(slice, seed);
                Assert.True(expected64 == actual64, $"Hash64 mismatch at length {len}, seed {seed}: expected 0x{expected64:X16}, got 0x{actual64:X16}");

                UInt128 expected128 = BclXxHash128.HashToUInt128(slice, (long)seed);
                UInt128 actual128 = XxHash3.Hash128(slice, seed);
                Assert.True(expected128 == actual128, $"Hash128 mismatch at length {len}, seed {seed}: expected {expected128}, got {actual128}");
            }
        }
    }

    [Fact]
    public void Streaming_Continuous0To4096_MatchesBcl_AcrossSeeds()
    {
        byte[] buffer = new byte[4096];
        Random.Shared.NextBytes(buffer);
        Span<byte> dest64 = stackalloc byte[8];
        Span<byte> dest128 = stackalloc byte[16];

        ulong[] seeds = [0UL, 123456789UL, 0x9E3779B185EBCA87UL];

        for (int len = 0; len <= 4096; len += (len < 512 ? 1 : 17))
        {
            ReadOnlySpan<byte> slice = buffer.AsSpan(0, len);
            foreach (ulong seed in seeds)
            {
                ulong expected64 = BclXxHash3.HashToUInt64(slice, (long)seed);
                using (var stream64 = new XxHash3Stream(8, seed))
                {
                    int offset = 0;
                    while (offset < len)
                    {
                        int chunk = Math.Min(len - offset, (offset % 53) + 1);
                        stream64.Append(slice.Slice(offset, chunk));
                        offset += chunk;
                    }
                    stream64.GetCurrentHash(dest64);
                    ulong actual64 = BinaryPrimitives.ReadUInt64LittleEndian(dest64);
                    Assert.True(expected64 == actual64, $"Streaming Hash64 mismatch at length {len}, seed {seed}");
                }

                UInt128 expected128 = BclXxHash128.HashToUInt128(slice, (long)seed);
                using (var stream128 = new XxHash3Stream(16, seed))
                {
                    int offset = 0;
                    while (offset < len)
                    {
                        int chunk = Math.Min(len - offset, (offset % 53) + 1);
                        stream128.Append(slice.Slice(offset, chunk));
                        offset += chunk;
                    }
                    stream128.GetCurrentHash(dest128);
                    ulong low = BinaryPrimitives.ReadUInt64LittleEndian(dest128);
                    ulong high = BinaryPrimitives.ReadUInt64LittleEndian(dest128.Slice(8));
                    UInt128 actual128 = new UInt128(high, low);
                    Assert.True(expected128 == actual128, $"Streaming Hash128 mismatch at length {len}, seed {seed}");
                }
            }
        }
    }
}
