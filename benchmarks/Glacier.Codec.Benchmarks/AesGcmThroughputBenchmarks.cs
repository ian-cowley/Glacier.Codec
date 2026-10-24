namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.AesGcm;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "AesGcm")]
public class AesGcmThroughputBenchmarks : IDisposable
{
    [Params(1024, 65536, 1048576)]
    public int PayloadSize { get; set; }

    private byte[] _key = null!;
    private byte[] _nonce = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _tag = null!;
    private byte[] _decrypted = null!;
    private byte[] _aad = null!;
    private Aes256GcmCipher _cipher = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        _nonce = new byte[12];
        _plaintext = new byte[PayloadSize];
        _ciphertext = new byte[PayloadSize];
        _tag = new byte[16];
        _decrypted = new byte[PayloadSize];
        _aad = new byte[16];

        Random.Shared.NextBytes(_key);
        Random.Shared.NextBytes(_nonce);
        Random.Shared.NextBytes(_plaintext);
        Random.Shared.NextBytes(_aad);

        _cipher = new Aes256GcmCipher(_key);

        // Pre-encrypt for decryption benchmark
        _cipher.Encrypt(_plaintext, _aad, _nonce, _ciphertext, _tag);
    }

    [Benchmark(Description = "AES-256-GCM Steady-State Encrypt (Pre-Expanded Keys)")]
    public void Aes256Gcm_Encrypt_SteadyState()
    {
        _cipher.Encrypt(_plaintext, _aad, _nonce, _ciphertext, _tag);
    }

    [Benchmark(Description = "AES-256-GCM Steady-State Decrypt (Pre-Expanded Keys)")]
    public bool Aes256Gcm_Decrypt_SteadyState()
    {
        return _cipher.Decrypt(_ciphertext, _aad, _nonce, _tag, _decrypted);
    }

    [Benchmark(Description = "AES-256-GCM One-Shot Block Encrypt (Includes Key Expansion)")]
    public void Aes256Gcm_Encrypt_OneShot()
    {
        Aes256Gcm.Encrypt(_key, _nonce, _plaintext, _ciphertext, _tag, _aad);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _cipher.Dispose();
    }
}
