using System;
using System.Diagnostics;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Xunit;
using Xunit.Abstractions;

namespace Glacier.Codec.Gpu.Tests;

public class GpuThroughputBenchmarkTests
{
    private readonly ITestOutputHelper _output;

    public GpuThroughputBenchmarkTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Benchmark_GpuSha256_Throughput()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuSha256Engine(device);

        byte[] template = new byte[64];
        new Random(777).NextBytes(template.AsSpan(0, 60));

        uint testCount = 5_000_000; // 5 Million nonces in 1 batch
        uint mask = 0xFFFFFFFF;    // Extremely difficult so atomic add overhead is near 0

        // Warmup
        engine.SearchNonce(template, 0, mask, 100_000, maxResults: 1);

        var sw = Stopwatch.StartNew();
        engine.SearchNonce(template, 0, mask, testCount, maxResults: 1);
        sw.Stop();

        double elapsedSeconds = sw.Elapsed.TotalSeconds;
        double megaHashesPerSec = (testCount / elapsedSeconds) / 1_000_000.0;

        _output.WriteLine($"[GPU SHA-256 Benchmark] Device: {device.DeviceName} ({device.ComputeCapability})");
        _output.WriteLine($"Processed {testCount:N0} nonces in {sw.ElapsedMilliseconds} ms -> {megaHashesPerSec:F2} MH/s ({megaHashesPerSec / 1000.0:F3} GH/s)");
        Assert.True(megaHashesPerSec > 50.0, "Expected at least 50 MH/s on dedicated GPU.");
    }

    [Fact]
    public void Benchmark_GpuBlake3_Throughput()
    {
        if (!CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0) return;

        using var device = GpuDevice.Create(0);
        using var engine = new GpuBlake3Engine(device);

        byte[] template = new byte[64];
        new Random(888).NextBytes(template.AsSpan(0, 60));

        uint testCount = 5_000_000;
        uint mask = 0xFFFFFFFF;

        // Warmup
        engine.SearchNonce(template, 0, mask, 100_000, flags: 0x0B, maxResults: 1);

        var sw = Stopwatch.StartNew();
        engine.SearchNonce(template, 0, mask, testCount, flags: 0x0B, maxResults: 1);
        sw.Stop();

        double elapsedSeconds = sw.Elapsed.TotalSeconds;
        double megaHashesPerSec = (testCount / elapsedSeconds) / 1_000_000.0;

        _output.WriteLine($"[GPU BLAKE3 Benchmark] Device: {device.DeviceName} ({device.ComputeCapability})");
        _output.WriteLine($"Processed {testCount:N0} nonces in {sw.ElapsedMilliseconds} ms -> {megaHashesPerSec:F2} MH/s ({megaHashesPerSec / 1000.0:F3} GH/s)");
        Assert.True(megaHashesPerSec > 100.0, "Expected at least 100 MH/s on dedicated GPU.");
    }
}
