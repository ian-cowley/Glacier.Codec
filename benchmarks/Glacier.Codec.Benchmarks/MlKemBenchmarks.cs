namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.PostQuantum;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "PostQuantum")]
public class MlKemBenchmarks
{
    private byte[] _pk768 = null!;
    private byte[] _sk768 = null!;
    private byte[] _ct768 = null!;
    private byte[] _ss768 = null!;

    private byte[] _pk1024 = null!;
    private byte[] _sk1024 = null!;
    private byte[] _ct1024 = null!;
    private byte[] _ss1024 = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pk768 = new byte[MlKem768.PublicKeyBytes];
        _sk768 = new byte[MlKem768.SecretKeyBytes];
        _ct768 = new byte[MlKem768.CiphertextBytes];
        _ss768 = new byte[MlKem768.SharedSecretBytes];

        _pk1024 = new byte[MlKem1024.PublicKeyBytes];
        _sk1024 = new byte[MlKem1024.SecretKeyBytes];
        _ct1024 = new byte[MlKem1024.CiphertextBytes];
        _ss1024 = new byte[MlKem1024.SharedSecretBytes];

        // Generate base keypairs and ciphertexts
        MlKemEngine.MlKem768.GenerateKeyPair(_pk768, _sk768);
        MlKemEngine.MlKem768.Encapsulate(_pk768, _ct768, _ss768);

        MlKemEngine.MlKem1024.GenerateKeyPair(_pk1024, _sk1024);
        MlKemEngine.MlKem1024.Encapsulate(_pk1024, _ct1024, _ss1024);
    }

    [Benchmark(Description = "ML-KEM-768 KeyGen (FIPS 203 Level 3)")]
    public void MlKem768_KeyGen()
    {
        MlKemEngine.MlKem768.GenerateKeyPair(_pk768, _sk768);
    }

    [Benchmark(Description = "ML-KEM-768 Encapsulate (FIPS 203 Level 3)")]
    public void MlKem768_Encaps()
    {
        MlKemEngine.MlKem768.Encapsulate(_pk768, _ct768, _ss768);
    }

    [Benchmark(Description = "ML-KEM-768 Decapsulate (FIPS 203 Level 3)")]
    public bool MlKem768_Decaps()
    {
        return MlKemEngine.MlKem768.Decapsulate(_sk768, _ct768, _ss768);
    }

    [Benchmark(Description = "ML-KEM-1024 KeyGen (FIPS 203 Level 5)")]
    public void MlKem1024_KeyGen()
    {
        MlKemEngine.MlKem1024.GenerateKeyPair(_pk1024, _sk1024);
    }

    [Benchmark(Description = "ML-KEM-1024 Encapsulate (FIPS 203 Level 5)")]
    public void MlKem1024_Encaps()
    {
        MlKemEngine.MlKem1024.Encapsulate(_pk1024, _ct1024, _ss1024);
    }

    [Benchmark(Description = "ML-KEM-1024 Decapsulate (FIPS 203 Level 5)")]
    public bool MlKem1024_Decaps()
    {
        return MlKemEngine.MlKem1024.Decapsulate(_sk1024, _ct1024, _ss1024);
    }
}
