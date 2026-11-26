namespace Glacier.Codec.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Cryptography.EllipticCurve;
using Glacier.Codec.Cryptography.PostQuantum;

[MemoryDiagnoser]
[BenchmarkCategory("Cryptography", "PostQuantum", "Hybrid")]
public class XWingBenchmarks
{
    private byte[] _pk = null!;
    private byte[] _sk = null!;
    private byte[] _ct = null!;
    private byte[] _ss = null!;

    private byte[] _xSk = null!;
    private byte[] _xPk = null!;
    private byte[] _xOut = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pk = new byte[XWing.PublicKeyBytes];
        _sk = new byte[XWing.SecretKeyBytes];
        _ct = new byte[XWing.CiphertextBytes];
        _ss = new byte[XWing.SharedSecretBytes];
        XWing.GenerateKeys(_pk, _sk);
        XWing.EncapsulateSecret(_pk, _ct, _ss);

        _xSk = new byte[X25519.KeySize];
        _xPk = new byte[X25519.KeySize];
        _xOut = new byte[X25519.KeySize];
        X25519.GenerateKeyPair(_xPk, _xSk);
    }

    [Benchmark(Description = "X25519 ScalarMultBase (RFC 7748)")]
    public void X25519_ScalarMultBase() => X25519.ScalarMultBase(_xSk, _xOut);

    [Benchmark(Description = "X25519 ScalarMult (RFC 7748)")]
    public void X25519_ScalarMult() => X25519.ScalarMult(_xSk, _xPk, _xOut);

    [Benchmark(Description = "X-Wing KeyGen (ML-KEM-768 + X25519)")]
    public void XWing_KeyGen() => XWing.GenerateKeys(_pk, _sk);

    [Benchmark(Description = "X-Wing Encapsulate (ML-KEM-768 + X25519)")]
    public void XWing_Encaps() => XWing.EncapsulateSecret(_pk, _ct, _ss);

    [Benchmark(Description = "X-Wing Decapsulate (ML-KEM-768 + X25519)")]
    public void XWing_Decaps() => XWing.DecapsulateSecret(_sk, _ct, _ss);
}
