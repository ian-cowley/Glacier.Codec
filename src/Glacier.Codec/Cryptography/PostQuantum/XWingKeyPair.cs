namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Memory;

/// <summary>
/// High-integrity X-Wing hybrid post-quantum + classical key pair container.
/// Holds the 1216-byte public key in a managed buffer and wraps the 32-byte seed secret key
/// in <see cref="SecureMemory"/> to guarantee zeroization upon disposal.
/// </summary>
public readonly struct XWingKeyPair : IDisposable
{
    private readonly XWing _engine;
    private readonly byte[] _publicKey;
    private readonly SecureMemory _secretKey;

    internal XWingKeyPair(XWing engine, byte[] publicKey, SecureMemory secretKey)
    {
        _engine = engine;
        _publicKey = publicKey;
        _secretKey = secretKey;
    }

    /// <summary>X-Wing public encapsulation key (1216 bytes: ML-KEM-768 || X25519).</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    /// <summary>X-Wing secret seed key (32 bytes).</summary>
    public ReadOnlySpan<byte> SecretKey => _secretKey.ReadOnlySpan;

    /// <summary>Encapsulates a hybrid shared secret using this key pair's public key.</summary>
    public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        _engine.Encapsulate(_publicKey, ciphertext, sharedSecret);
    }

    /// <summary>Decapsulates a hybrid shared secret from received ciphertext using this key pair's secret key.</summary>
    public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        _engine.Decapsulate(_secretKey.ReadOnlySpan, ciphertext, sharedSecret);
    }

    public void Dispose()
    {
        _secretKey.Dispose();
    }
}
