namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Static convenience entry point for XChaCha20-Poly1305 (192-bit nonce) AEAD authenticated encryption and decryption.
/// </summary>
public static class XChaCha20Poly1305
{
    public const int KeySize = XChaCha20Poly1305Cipher.KeySize;
    public const int NonceSize = XChaCha20Poly1305Cipher.NonceSize;
    public const int TagSize = XChaCha20Poly1305Cipher.TagSize;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DeriveSubkey(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce16,
        Span<byte> subkey)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be exactly {KeySize} bytes.", nameof(key));
        if (nonce16.Length != 16)
            throw new ArgumentException("HChaCha20 nonce must be exactly 16 bytes.", nameof(nonce16));
        if (subkey.Length < 32)
            throw new ArgumentException("Subkey destination must be at least 32 bytes.", nameof(subkey));

        ChaCha20KernelScalar.HChaCha20(key, nonce16, subkey);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        XChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
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
        return XChaCha20Poly1305Cipher.Decrypt(key, nonce, ciphertext, tag, plaintext, associatedData);
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
