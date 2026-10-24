namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.Kdf;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "Kdf")]
public class Argon2idBenchmarks
{
    private byte[] _password = null!;
    private byte[] _salt = null!;
    private byte[] _derivedKey = null!;

    [GlobalSetup]
    public void Setup()
    {
        _password = new byte[32];
        _salt = new byte[16];
        _derivedKey = new byte[32];

        Random.Shared.NextBytes(_password);
        Random.Shared.NextBytes(_salt);
    }

    [Benchmark(Description = "Argon2id Fast Profile (t=1, m=1MB, p=4)")]
    public void Argon2id_Fast_1MB()
    {
        Argon2id.DeriveKey(_password, _salt, _derivedKey, iterations: 1, memoryKb: 1024, parallelism: 4);
    }

    [Benchmark(Description = "Argon2id Medium Profile (t=3, m=8MB, p=4)")]
    public void Argon2id_Medium_8MB()
    {
        Argon2id.DeriveKey(_password, _salt, _derivedKey, iterations: 3, memoryKb: 8192, parallelism: 4);
    }

    [Benchmark(Description = "Argon2id RFC 9106 Recommended (t=3, m=64MB, p=4)")]
    public void Argon2id_RFC9106_64MB()
    {
        Argon2id.DeriveKey(_password, _salt, _derivedKey, iterations: 3, memoryKb: 65536, parallelism: 4);
    }
}
