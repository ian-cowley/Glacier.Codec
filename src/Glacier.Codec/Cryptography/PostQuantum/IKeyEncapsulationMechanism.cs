namespace Glacier.Codec.Cryptography.PostQuantum;

using System;

/// <summary>
/// Post-quantum Key Encapsulation Mechanism (KEM) contract (FIPS 203 ML-KEM).
/// </summary>
public interface IKeyEncapsulationMechanism
{
    /// <summary>Public key size in bytes.</summary>
    int PublicKeySizeInBytes { get; }

    /// <summary>Secret key size in bytes.</summary>
    int SecretKeySizeInBytes { get; }

    /// <summary>Ciphertext size in bytes.</summary>
    int CiphertextSizeInBytes { get; }

    /// <summary>Shared secret size in bytes.</summary>
    int SharedSecretSizeInBytes { get; }

    /// <summary>Generates a public/secret key pair.</summary>
    void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey);

    /// <summary>Encapsulates a shared secret using the recipient's public key.</summary>
    void Encapsulate(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret);

    /// <summary>Decapsulates a shared secret from ciphertext using secret key.</summary>
    /// <returns><c>true</c> if decapsulation succeeded; otherwise, <c>false</c> (or implicit rejection).</returns>
    bool Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);
}
