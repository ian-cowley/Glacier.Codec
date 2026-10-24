namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Static convenience entry point for AES-256-GCM authenticated encryption and decryption.
/// </summary>
public static class Aes256Gcm
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
        Aes256GcmCipher.EncryptBlock(key, nonce, plaintext, ciphertext, tag, associatedData);
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
        return Aes256GcmCipher.DecryptBlock(key, nonce, ciphertext, tag, plaintext, associatedData);
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
        if (ciphertext.Length < plaintext.Length || tag.Length < Aes256GcmCipher.TagSize)
        {
            bytesWritten = 0;
            return false;
        }

        Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
        bytesWritten = plaintext.Length;
        return true;
    }
}
