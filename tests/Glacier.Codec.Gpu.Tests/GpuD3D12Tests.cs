using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Glacier.Codec.Gpu.Engines;
using Glacier.Codec.Hashing.Blake3;
using Xunit;
using Xunit.Abstractions;

namespace Glacier.Codec.Gpu.Tests;

public class GpuD3D12Tests
{
    private readonly ITestOutputHelper _output;

    public GpuD3D12Tests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void D3D12Engine_DetectsAndBindsGpu()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var factory = Vortice.DXGI.DXGI.CreateDXGIFactory1<Vortice.DXGI.IDXGIFactory4>();
        for (uint i = 0; factory.EnumAdapters1(i, out Vortice.DXGI.IDXGIAdapter1 a).Success; i++)
        {
            var d = a.Description1;
            _output.WriteLine($"[DXGI Adapter #{i}] '{d.Description}' (VendorId: 0x{d.VendorId:X4}, DedicatedVRAM: {d.DedicatedVideoMemory}, SharedRAM: {d.SharedSystemMemory})");
            a.Dispose();
        }

        using var engine = new GpuD3D12Engine();
        _output.WriteLine($"[Selected Engine] Adapter: {engine.AdapterName} | IsAmdRadeon: {engine.IsAmdRadeon}");
        Assert.NotNull(engine.AdapterName);
    }

    [Fact]
    public void D3D12Engine_Blake3NonceSearch_FindsValidMatches()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var engine = new GpuD3D12Engine();
        byte[] template = new byte[64];
        new Random(555).NextBytes(template.AsSpan(0, 60));

        uint mask = 0xFFFF0000;
        uint searchCount = 500_000;

        uint[] matches = engine.SearchNonceBlake3(template, 0, mask, searchCount, flags: 0x0B, maxResults: 10);
        Assert.NotEmpty(matches);

        Span<byte> hash = stackalloc byte[32];
        foreach (uint nonce in matches)
        {
            byte[] block = (byte[])template.Clone();
            BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);

            Blake3Hasher.Hash(block, hash);
            uint firstWord = BitConverter.ToUInt32(hash);

            Assert.Equal(0u, firstWord & mask);
        }
    }

    [Fact]
    public void D3D12Engine_Sha256NonceSearch_FindsValidMatches()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var engine = new GpuD3D12Engine();
        byte[] template = new byte[64];
        new Random(666).NextBytes(template.AsSpan(0, 60));

        uint mask = 0xFFFF0000;
        uint searchCount = 500_000;

        uint[] matches = engine.SearchNonceSha256(template, 0, mask, searchCount, maxResults: 10);
        Assert.NotEmpty(matches);

        foreach (uint nonce in matches)
        {
            byte[] block = (byte[])template.Clone();
            BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);

            byte[] hash = SHA256.HashData(block);
            uint firstWord = ((uint)hash[0] << 24) | ((uint)hash[1] << 16) | ((uint)hash[2] << 8) | hash[3];

            Assert.Equal(0u, firstWord & mask);
        }
    }

    [Fact]
    public void D3D12Engine_ThroughputBenchmark()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var engine = new GpuD3D12Engine();
        byte[] template = new byte[64];
        new Random(1234).NextBytes(template.AsSpan(0, 60));

        uint count = 2_000_000;
        uint mask = 0xFFFFFFFF;

        // Warmup
        engine.SearchNonceBlake3(template, 0, mask, 100_000, maxResults: 1);

        var sw = Stopwatch.StartNew();
        engine.SearchNonceBlake3(template, 0, mask, count, maxResults: 1);
        sw.Stop();

        double blake3Mh = (count / sw.Elapsed.TotalSeconds) / 1_000_000.0;
        _output.WriteLine($"[D3D12 {engine.AdapterName}] BLAKE3 Throughput: {blake3Mh:F2} MH/s in {sw.ElapsedMilliseconds} ms");

        sw.Restart();
        engine.SearchNonceSha256(template, 0, mask, count, maxResults: 1);
        sw.Stop();

        double sha256Mh = (count / sw.Elapsed.TotalSeconds) / 1_000_000.0;
        _output.WriteLine($"[D3D12 {engine.AdapterName}] SHA-256 Throughput: {sha256Mh:F2} MH/s in {sw.ElapsedMilliseconds} ms");
    }
}
