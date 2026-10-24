namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "ChaCha20")]
public class ChaCha20Poly1305ThroughputBenchmarks : IDisposable
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
    private ChaCha20Poly1305Cipher _cipher = null!;

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

        _cipher = new ChaCha20Poly1305Cipher(_key);
        _cipher.Encrypt(_plaintext, _aad, _nonce, _ciphertext, _tag);
    }

    [Benchmark(Description = "ChaCha20-Poly1305 Steady-State Encrypt (RFC 8439)")]
    public void ChaCha20Poly1305_Encrypt_SteadyState()
    {
        _cipher.Encrypt(_plaintext, _aad, _nonce, _ciphertext, _tag);
    }

    [Benchmark(Description = "ChaCha20-Poly1305 Steady-State Decrypt (RFC 8439)")]
    public bool ChaCha20Poly1305_Decrypt_SteadyState()
    {
        return _cipher.Decrypt(_ciphertext, _aad, _nonce, _tag, _decrypted);
    }

    [Benchmark(Description = "ChaCha20 Stream Cipher Raw Encryption (No MAC)")]
    public void ChaCha20_Crypt_Raw()
    {
        ChaCha20Cipher.Crypt(_key, _nonce, 1, _plaintext, _ciphertext);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _cipher.Dispose();
    }
}
