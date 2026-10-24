using System;
using System.Security.Cryptography;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Xunit;

namespace Glacier.Codec.Gpu.Tests;

public class GpuSha256Tests
{
    [Fact]
    public void Sha256Batch_MatchesCpuStandard_BitForBit()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuSha256Engine(device);

        int blockCount = 64;
        byte[] inputData = new byte[blockCount * 64];
        new Random(42).NextBytes(inputData);

        byte[] gpuOutput = new byte[blockCount * 32];
        engine.HashBatch(inputData, gpuOutput);

        // Verify every block against standard CPU SHA-256
        for (int i = 0; i < blockCount; i++)
        {
            byte[] expected = SHA256.HashData(inputData.AsSpan(i * 64, 64));
            byte[] actual = gpuOutput.AsSpan(i * 32, 32).ToArray();

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void Sha256NonceSearch_FindsValidMatches()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuSha256Engine(device);

        byte[] headerTemplate = new byte[64];
        new Random(1337).NextBytes(headerTemplate.AsSpan(0, 60));

        // Require leading 16 bits to be zero: 0xFFFF0000 mask
        uint mask = 0xFFFF0000;
        uint searchCount = 200_000; // Search 200k nonces
        uint[] foundNonces = engine.SearchNonce(headerTemplate, 0, mask, searchCount, maxResults: 10);

        Assert.NotEmpty(foundNonces);

        // Verify each found nonce on CPU
        foreach (uint nonce in foundNonces)
        {
            byte[] testBlock = (byte[])headerTemplate.Clone();
            BitConverter.TryWriteBytes(testBlock.AsSpan(60, 4), nonce);

            byte[] hash = SHA256.HashData(testBlock);
            uint firstWord = ((uint)hash[0] << 24) | ((uint)hash[1] << 16) | ((uint)hash[2] << 8) | hash[3];

            Assert.Equal(0u, firstWord & mask);
        }
    }
}
