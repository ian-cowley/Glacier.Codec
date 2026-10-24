namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Hashing.Sha256;

[MemoryDiagnoser]
[BenchmarkCategory("Hashing", "Sha256")]
public class Sha256ThroughputBenchmarks : IDisposable
{
    [Params(1024, 65536, 1048576)]
    public int PayloadSize { get; set; }

    private byte[] _input = null!;
    private byte[] _digest = null!;
    private Sha256Hasher _hasher = null!;

    [GlobalSetup]
    public void Setup()
    {
        _input = new byte[PayloadSize];
        _digest = new byte[32];
        Random.Shared.NextBytes(_input);
        _hasher = new Sha256Hasher();
    }

    [Benchmark(Description = "SHA-256 Hardware SHA-NI One-Shot")]
    public void Sha256_Hash_OneShot()
    {
        Sha256.Hash(_input, _digest);
    }

    [Benchmark(Description = "SHA-256 Streaming Ingestion (Chunked)")]
    public void Sha256_Streaming()
    {
        _hasher.Reset();
        _hasher.Append(_input);
        _hasher.Finalize(_digest);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _hasher.Dispose();
    }
}
