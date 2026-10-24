namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Hashing.Blake3;

[MemoryDiagnoser]
[BenchmarkCategory("Hashing", "Blake3")]
public class Blake3ThroughputBenchmarks : IDisposable
{
    [Params(65536, 1048576, 16777216, 67108864)]
    public int PayloadSize { get; set; }

    private byte[] _input = null!;
    private byte[] _output = null!;
    private byte[] _key = null!;
    private Blake3Hasher _streamingHasher = null!;

    [GlobalSetup]
    public void Setup()
    {
        _input = new byte[PayloadSize];
        _output = new byte[32];
        _key = new byte[32];

        Random.Shared.NextBytes(_input);
        Random.Shared.NextBytes(_key);

        _streamingHasher = new Blake3Hasher();
    }

    [Benchmark(Description = "BLAKE3 One-Shot Hash (Auto Parallel >= 1MB)")]
    public void Blake3_Hash_OneShot()
    {
        Blake3Hasher.Hash(_input, _output);
    }

    [Benchmark(Description = "BLAKE3 Keyed MAC")]
    public void Blake3_Hash_Keyed()
    {
        Blake3Hasher.HashKeyed(_input, _key, _output);
    }

    [Benchmark(Description = "BLAKE3 Streaming Append & Finalize")]
    public void Blake3_Streaming()
    {
        _streamingHasher.Reset();
        _streamingHasher.Append(_input);
        _streamingHasher.Finalize(_output);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _streamingHasher.Dispose();
    }
}
