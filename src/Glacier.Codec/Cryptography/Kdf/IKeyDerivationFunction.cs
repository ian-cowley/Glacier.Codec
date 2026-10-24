namespace Glacier.Codec.Cryptography.Kdf;

using System;

/// <summary>
/// Contract for password-based or cryptographic key derivation functions.
/// </summary>
public interface IKeyDerivationFunction
{
    /// <summary>
    /// Derives output cryptographic key from password and salt.
    /// </summary>
    void DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Span<byte> derivedKey);
}
