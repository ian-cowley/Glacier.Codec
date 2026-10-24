namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Static convenience entry point for ChaCha20-Poly1305 AEAD authenticated encryption and decryption.
/// </summary>
public static class ChaCha20Poly1305
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        return ChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, plaintext, associatedData);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryEncrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        out int bytesWritten,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < plaintext.Length || tag.Length < ChaCha20Poly1305Cipher.TagSize)
        {
            bytesWritten = 0;
            return false;
        }

        Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
        bytesWritten = plaintext.Length;
        return true;
    }
}
