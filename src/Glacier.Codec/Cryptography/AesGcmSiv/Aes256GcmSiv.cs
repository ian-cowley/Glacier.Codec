namespace Glacier.Codec.Cryptography.AesGcmSiv;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Static convenience entry point for RFC 8452 AES-256-GCM-SIV authenticated encryption and decryption.
/// </summary>
public static class Aes256GcmSiv
{
    public const int KeySize = Aes256GcmSivCipher.KeySize;
    public const int NonceSize = Aes256GcmSivCipher.NonceSize;
    public const int TagSize = Aes256GcmSivCipher.TagSize;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        Aes256GcmSivCipher.EncryptBlock(key, nonce, plaintext, ciphertext, tag, associatedData);
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
        return Aes256GcmSivCipher.DecryptBlock(key, nonce, ciphertext, tag, plaintext, associatedData);
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
        if (key.Length != KeySize || nonce.Length != NonceSize ||
            ciphertext.Length < plaintext.Length || tag.Length < TagSize)
        {
            bytesWritten = 0;
            return false;
        }

        Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
        bytesWritten = plaintext.Length;
        return true;
    }
}
