using System;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Glacier.Codec.Hashing.Blake3;
using Xunit;

namespace Glacier.Codec.Gpu.Tests;

public class GpuBlake3Tests
{
    [Fact]
    [Trait("Category", "Gpu")]
    public void Blake3Batch_MatchesCpuStandard_BitForBit()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuBlake3Engine(device);

        int blockCount = 64;
        byte[] inputData = new byte[blockCount * 64];
        new Random(99).NextBytes(inputData);

        byte[] gpuOutput = new byte[blockCount * 32];
        engine.HashBatch(inputData, gpuOutput, flags: 0x0B);

        // Verify each 64-byte block against Glacier.Codec CPU Blake3Hasher
        Span<byte> expected = stackalloc byte[32];
        for (int i = 0; i < blockCount; i++)
        {
            Blake3Hasher.Hash(inputData.AsSpan(i * 64, 64), expected);
            byte[] actual = gpuOutput.AsSpan(i * 32, 32).ToArray();

            Assert.Equal(expected.ToArray(), actual);
        }
    }

    [Fact]
    [Trait("Category", "Gpu")]
    public void Blake3NonceSearch_FindsValidMatches()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuBlake3Engine(device);

        byte[] headerTemplate = new byte[64];
        new Random(404).NextBytes(headerTemplate.AsSpan(0, 60));

        uint mask = 0xFFFF0000;
        uint searchCount = 200_000;
        uint[] foundNonces = engine.SearchNonce(headerTemplate, 0, mask, searchCount, flags: 0x0B, maxResults: 10);

        Assert.NotEmpty(foundNonces);

        // Verify each found nonce on CPU Blake3
        Span<byte> hash = stackalloc byte[32];
        foreach (uint nonce in foundNonces)
        {
            byte[] testBlock = (byte[])headerTemplate.Clone();
            BitConverter.TryWriteBytes(testBlock.AsSpan(60, 4), nonce);

            Blake3Hasher.Hash(testBlock, hash);
            uint firstWord = BitConverter.ToUInt32(hash);

            Assert.Equal(0u, firstWord & mask);
        }
    }

    [Fact]
    [Trait("Category", "Gpu")]
    public void Blake3NonceSearch_Leading16And12BitsZero_MatchesHexPrefix()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuBlake3Engine(device);

        byte[] headerTemplate = new byte[64];
        new Random(777).NextBytes(headerTemplate.AsSpan(0, 60));

        // 16-bit leading-zero prefix mask in little-endian word 0: 0x0000FFFF
        uint[] matches16 = engine.SearchNonce(headerTemplate, 0, 0x0000FFFFu, 500_000, flags: 0x0B, maxResults: 8);
        Assert.NotEmpty(matches16);

        Span<byte> hash = stackalloc byte[32];
        foreach (uint nonce in matches16)
        {
            byte[] block = (byte[])headerTemplate.Clone();
            BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);
            Blake3Hasher.Hash(block, hash);
            Assert.Equal(0, hash[0]);
            Assert.Equal(0, hash[1]);
            Assert.StartsWith("0000", Convert.ToHexString(hash));
        }

        // 12-bit sub-byte prefix mask in little-endian word 0: 0x0000F0FF
        uint[] matches12 = engine.SearchNonce(headerTemplate, 0, 0x0000F0FFu, 100_000, flags: 0x0B, maxResults: 8);
        Assert.NotEmpty(matches12);

        foreach (uint nonce in matches12)
        {
            byte[] block = (byte[])headerTemplate.Clone();
            BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);
            Blake3Hasher.Hash(block, hash);
            Assert.Equal(0, hash[0]);
            Assert.Equal(0, hash[1] & 0xF0);
        }
    }
}
