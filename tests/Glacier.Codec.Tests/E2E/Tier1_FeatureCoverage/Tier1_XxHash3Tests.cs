using System;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing.XxHash3;

namespace Glacier.Codec.Tests.E2E.Tier1_FeatureCoverage;

public class Tier1_XxHash3Tests
{
    // Feature 26: xxHash3 Small Buffer Shortcuts (0B, 1-3B, 4-8B, 9-16B, 17-128B, 129-240B)
    [Fact]
    public void Feature26_XxHash3_EmptyInput_MatchesGoldenVector()
    {
        ulong hash = XxHash3Hasher.Hash64(ReadOnlySpan<byte>.Empty);
        // Golden vector: 0x2D06800538D394C2
        Assert.Equal(0x2D06800538D394C2UL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len1Byte_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("a");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0xE6C632B61E964E1F
        Assert.Equal(0xE6C632B61E964E1FUL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len3Bytes_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("abc");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0x78AF5F94892F3950
        Assert.Equal(0x78AF5F94892F3950UL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len4Bytes_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("abcd");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0x6497A96F53A89890
        Assert.Equal(0x6497A96F53A89890UL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len8Bytes_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("12345678");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0x62E29B4CAD9E2EF6
        Assert.Equal(0x62E29B4CAD9E2EF6UL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len16Bytes_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("1234567890123456");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0xD6CFFF267D11AD76
        Assert.Equal(0xD6CFFF267D11AD76UL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len17Bytes_MatchesGoldenVector()
    {
        byte[] input = Encoding.ASCII.GetBytes("12345678901234567");
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0xE4C4D5CF2C91C94E
        Assert.Equal(0xE4C4D5CF2C91C94EUL, hash);
    }

    [Fact]
    public void Feature26_XxHash3_Len240Bytes_MatchesGoldenVector()
    {
        byte[] input = new byte[240];
        Array.Fill(input, (byte)'C');
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0x9E1398B318E6D706
        Assert.Equal(0x9E1398B318E6D706UL, hash);
    }

    // Feature 22 & 23: 64-Byte Stripe Kernel & 8 Accumulators
    [Fact]
    public void Feature22_23_XxHash3_241BytesFirstStripeLoop_MatchesGoldenVector()
    {
        // 241 bytes exceeds 240B threshold and enters stripe accumulation
        byte[] input = new byte[241];
        Array.Fill(input, (byte)'D');
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0x4B303F2E3BC97000
        Assert.Equal(0x4B303F2E3BC97000UL, hash);
    }

    // Feature 25: Accumulator Scrambler (Every 1024 Bytes)
    [Fact]
    public void Feature25_XxHash3_1024BytesAccumulatorScrambler_MatchesGoldenVector()
    {
        byte[] input = new byte[1024];
        Array.Fill(input, (byte)'E');
        ulong hash = XxHash3Hasher.Hash64(input);
        // Golden vector: 0xC89C0D551CBC6791
        Assert.Equal(0xC89C0D551CBC6791UL, hash);
    }

    // Feature 29 & 30: 64-Bit & 128-Bit Finalizers
    [Fact]
    public void Feature30_XxHash3_128BitFinalizer_EmptyBuffer()
    {
        UInt128 hash128 = XxHash3Hasher.Hash128(ReadOnlySpan<byte>.Empty);
        // Golden vector: 0x99AA06D3014798D86001C324468D497F
        ulong low = (ulong)(hash128 & ulong.MaxValue);
        ulong high = (ulong)(hash128 >> 64);
        Assert.Equal(0x6001C324468D497FUL, low);
        Assert.Equal(0x99AA06D3014798D8UL, high);
    }

    // Feature 31: xxHash3 Streaming Hasher
    [Fact]
    public void Feature31_XxHash3_StreamingAppend_MatchesOneShot()
    {
        using var streamHasher = new XxHash3Hasher();
        streamHasher.Append(new byte[] { 1, 2, 3 });
        streamHasher.Append(new byte[] { 4, 5, 6, 7, 8 });

        Span<byte> hashBytes = stackalloc byte[8];
        streamHasher.Finalize(hashBytes);

        byte[] all = [1, 2, 3, 4, 5, 6, 7, 8];
        ulong oneShot = XxHash3Hasher.Hash64(all);
        ulong streamed = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);

        Assert.Equal(oneShot, streamed);
    }
}
