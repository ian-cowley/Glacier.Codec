namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.AesGcmSiv;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.CommittingAead;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "ModernAead")]
public class ModernAeadBenchmarks : IDisposable
{
    [Params(4096, 1048576)]
    public int PayloadSize { get; set; }

    private byte[] _key = null!;
    private byte[] _nonce12 = null!;
    private byte[] _nonce24 = null!;
    private byte[] _aad = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _decrypted = null!;
    private byte[] _tag16 = null!;
    private byte[] _tag48 = null!;

    private XChaCha20Poly1305Cipher _xchacha = null!;
    private Aes256GcmSivCipher _gcmSiv = null!;
    private CommittingAeadCipher _committing = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        _nonce12 = new byte[12];
        _nonce24 = new byte[24];
        _aad = new byte[16];
        _plaintext = new byte[PayloadSize];
        _ciphertext = new byte[PayloadSize];
        _decrypted = new byte[PayloadSize];
        _tag16 = new byte[16];
        _tag48 = new byte[CommittingAead.TagSize];

        Random.Shared.NextBytes(_key);
        Random.Shared.NextBytes(_nonce12);
        Random.Shared.NextBytes(_nonce24);
        Random.Shared.NextBytes(_aad);
        Random.Shared.NextBytes(_plaintext);

        _xchacha = new XChaCha20Poly1305Cipher(_key);
        _gcmSiv = new Aes256GcmSivCipher(_key);
        _committing = new CommittingAeadCipher(_key, CommittingAeadAlgorithm.Aes256GcmSiv);
    }

    [Benchmark(Description = "XChaCha20-Poly1305 Encrypt")]
    public void XChaCha20_Encrypt() => _xchacha.Encrypt(_plaintext, _aad, _nonce24, _ciphertext, _tag16);

    [Benchmark(Description = "XChaCha20-Poly1305 Decrypt")]
    public bool XChaCha20_Decrypt() => _xchacha.Decrypt(_ciphertext, _aad, _nonce24, _tag16, _decrypted);

    [Benchmark(Description = "AES-256-GCM-SIV Encrypt (RFC 8452)")]
    public void Aes256GcmSiv_Encrypt() => _gcmSiv.Encrypt(_plaintext, _aad, _nonce12, _ciphertext, _tag16);

    [Benchmark(Description = "AES-256-GCM-SIV Decrypt (RFC 8452)")]
    public bool Aes256GcmSiv_Decrypt() => _gcmSiv.Decrypt(_ciphertext, _aad, _nonce12, _tag16, _decrypted);

    [Benchmark(Description = "CommittingAead (CMT-4 + GCM-SIV) Encrypt")]
    public void CommittingAead_Encrypt() => _committing.Encrypt(_plaintext, _aad, _nonce12, _ciphertext, _tag48);

    [Benchmark(Description = "CommittingAead (CMT-4 + GCM-SIV) Decrypt")]
    public bool CommittingAead_Decrypt() => _committing.Decrypt(_ciphertext, _aad, _nonce12, _tag48, _decrypted);

    [GlobalCleanup]
    public void Dispose()
    {
        _xchacha.Dispose();
        _gcmSiv.Dispose();
        _committing.Dispose();
    }
}
