namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Hashing.XxHash3;

[MemoryDiagnoser]
[BenchmarkCategory("Hashing", "XxHash3")]
public class XxHash3ThroughputBenchmarks
{
    [Params(64, 240, 65536, 1048576, 16777216)]
    public int PayloadSize { get; set; }

    private byte[] _input = null!;

    [GlobalSetup]
    public void Setup()
    {
        _input = new byte[PayloadSize];
        Random.Shared.NextBytes(_input);
    }

    [Benchmark(Description = "xxHash3 64-bit Non-Cryptographic Hash")]
    public ulong XxHash3_Hash64()
    {
        return XxHash3.Hash64(_input);
    }

    [Benchmark(Description = "xxHash3 128-bit Non-Cryptographic Hash")]
    public UInt128 XxHash3_Hash128()
    {
        return XxHash3.Hash128(_input);
    }
}
