namespace Glacier.Codec.Cryptography.CommittingAead;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Static convenience entry point for BLAKE3 CMT-4 key-committing AEAD encryption and decryption.
/// </summary>
public static class CommittingAead
{
    public const int KeySize = CommittingAeadCipher.KeySize;
    public const int TagSize = CommittingAeadCipher.TagSize;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default,
        CommittingAeadAlgorithm algorithm = CommittingAeadAlgorithm.Aes256GcmSiv)
    {
        using var cipher = new CommittingAeadCipher(key, algorithm);
        cipher.Encrypt(plaintext, associatedData, nonce, ciphertext, tag);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default,
        CommittingAeadAlgorithm algorithm = CommittingAeadAlgorithm.Aes256GcmSiv)
    {
        using var cipher = new CommittingAeadCipher(key, algorithm);
        return cipher.Decrypt(ciphertext, associatedData, nonce, tag, plaintext);
    }
}
