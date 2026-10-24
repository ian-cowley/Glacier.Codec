namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing.XxHash3;

public class XxHash3Tests
{
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
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(1024)]
    public void XxHash3_CompareAgainstSystemIoHashing(int length)
    {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++) buffer[i] = (byte)(i * 31 + 7);

        ulong expected = System.IO.Hashing.XxHash3.HashToUInt64(buffer);
        ulong actual = XxHash3Hasher.Hash64(buffer);

        Assert.Equal(expected, actual);
    }



    [Fact]
    public void XxHash3_GoldenVector_17to240Bytes()
    {
        Assert.Equal(0xE4C4D5CF2C91C94EUL, XxHash3Hasher.Hash64(Encoding.ASCII.GetBytes("12345678901234567")));

        byte[] b240 = new byte[240];
        Array.Fill(b240, (byte)'C');
        Assert.Equal(0x9E1398B318E6D706UL, XxHash3Hasher.Hash64(b240));
    }

    [Fact]
    public void XxHash3_GoldenVector_241BytesStripeLoop()
    {
        byte[] b241 = new byte[241];
        Array.Fill(b241, (byte)'D');
        Assert.Equal(0x4B303F2E3BC97000UL, XxHash3Hasher.Hash64(b241));
    }

    [Fact]
    public void XxHash3_GoldenVector_1024BytesAccumulatorScrambler()
    {
        byte[] b1024 = new byte[1024];
        Array.Fill(b1024, (byte)'E');
        Assert.Equal(0xC89C0D551CBC6791UL, XxHash3Hasher.Hash64(b1024));
    }

    [Fact]
    public void XxHash3_128Bit_EmptyInput_MatchesGoldenVector()
    {
        UInt128 hash128 = XxHash3Hasher.Hash128(ReadOnlySpan<byte>.Empty);
        ulong low = (ulong)(hash128 & ulong.MaxValue);
        ulong high = (ulong)(hash128 >> 64);

        Assert.Equal(0x6001C324468D497FUL, low);
        Assert.Equal(0x99AA06D3014798D8UL, high);
    }

    [Fact]
    public void XxHash3_StreamingAppend_MatchesOneShot()
    {
        using var streamHasher = new XxHash3Hasher();
        streamHasher.Append(new byte[] { 1, 2, 3 });
        streamHasher.Append(new byte[] { 4, 5, 6, 7, 8 });
        streamHasher.Append(new byte[] { 9, 10, 11, 12, 13, 14, 15, 16 });

        Span<byte> hashBytes = stackalloc byte[8];
        streamHasher.Finalize(hashBytes);

        byte[] all = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        ulong oneShot = XxHash3Hasher.Hash64(all);
        ulong streamed = BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);

        Assert.Equal(oneShot, streamed);
    }

    [Fact]
    public void XxHash3_StreamingLargePayload_MatchesOneShot()
    {
        byte[] payload = new byte[5000];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 251);

        using var streamHasher = new XxHash3Hasher();
        int offset = 0;
        int[] chunkSizes = [100, 200, 300, 400, 500, 1000, 2500];
        foreach (int size in chunkSizes)
        {
            streamHasher.Append(payload.AsSpan(offset, size));
            offset += size;
        }

        Span<byte> streamDigest = stackalloc byte[8];
        streamHasher.Finalize(streamDigest);

        ulong streamed = BinaryPrimitives.ReadUInt64LittleEndian(streamDigest);
        ulong oneShot = XxHash3Hasher.Hash64(payload);

        Assert.Equal(oneShot, streamed);
    }

    [Fact]
    public void XxHash3_KeyedMode_CustomSeed()
    {
        using var stream = new XxHash3Stream(8, 0);
        byte[] seedBytes = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(seedBytes, 12345UL);
        stream.SetKey(seedBytes);

        byte[] input = Encoding.UTF8.GetBytes("KeyedTestInput");
        stream.Append(input);
        Span<byte> hash = stackalloc byte[8];
        stream.Finalize(hash);

        ulong streamed = BinaryPrimitives.ReadUInt64LittleEndian(hash);
        ulong oneShot = XxHash3Hasher.Hash64(input, 12345UL);

        Assert.Equal(oneShot, streamed);
    }

    [Fact]
    public void XxHash3_DisposedThrowsObjectDisposedException()
    {
        var hasher = new XxHash3Hasher();
        hasher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => hasher.Append(new byte[10]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Reset());
        Assert.Throws<ObjectDisposedException>(() => hasher.GetCurrentHash(new byte[8]));
    }
}
