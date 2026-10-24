namespace Glacier.Codec.Cryptography;

using System;

/// <summary>
/// Authenticated Encryption with Associated Data (AEAD) cipher contract.
/// Enforces constant-time verification to prevent side-channel timing attacks.
/// </summary>
public interface IAeadCipher : IDisposable
{
    /// <summary>Required key size in bytes.</summary>
    int KeySizeInBytes { get; }

    /// <summary>Required nonce/IV size in bytes.</summary>
    int NonceSizeInBytes { get; }

    /// <summary>Authentication tag size in bytes.</summary>
    int TagSizeInBytes { get; }

    /// <summary>
    /// Encrypts plaintext and computes authentication tag over ciphertext and associated data.
    /// </summary>
    void Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertext,
        Span<byte> tag);

    /// <summary>
    /// Decrypts ciphertext and verifies authentication tag using constant-time comparison.
    /// </summary>
    /// <returns><c>true</c> if authentication tag is valid and decrypted; otherwise, <c>false</c>.</returns>
    bool Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext);
}
