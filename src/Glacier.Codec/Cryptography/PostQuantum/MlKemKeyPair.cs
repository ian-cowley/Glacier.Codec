namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using Glacier.Codec.Memory;

/// <summary>
/// High-integrity post-quantum key pair container.
/// Holds public key in managed buffer and wraps secret key in <see cref="SecureMemory"/>
/// to guarantee zeroization upon disposal.
/// </summary>
public readonly struct MlKemKeyPair : IDisposable
{
    private readonly MlKemEngine _engine;
    private readonly byte[] _publicKey;
    private readonly SecureMemory _secretKey;

    internal MlKemKeyPair(MlKemEngine engine, byte[] publicKey, SecureMemory secretKey)
    {
        _engine = engine;
        _publicKey = publicKey;
        _secretKey = secretKey;
    }

    /// <summary>Public encapsulation key.</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    /// <summary>Secret decapsulation key.</summary>
    public ReadOnlySpan<byte> SecretKey => _secretKey.ReadOnlySpan;

    /// <summary>Encapsulates a shared secret using this key pair's public key.</summary>
    public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        _engine.Encapsulate(_publicKey, ciphertext, sharedSecret);
    }

    /// <summary>Decapsulates a shared secret from received ciphertext using this key pair's secret key.</summary>
    public bool Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        return _engine.Decapsulate(_secretKey.ReadOnlySpan, ciphertext, sharedSecret);
    }

    public void Dispose()
    {
        _secretKey.Dispose();
    }
}
