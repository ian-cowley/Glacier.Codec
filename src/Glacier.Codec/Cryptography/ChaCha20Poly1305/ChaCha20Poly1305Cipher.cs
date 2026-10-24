namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;
using System.Threading;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Memory;

/// <summary>
/// RFC 8439 Authenticated Encryption with Associated Data (AEAD) cipher combining
/// ChaCha20 20-round stream cipher and Poly1305 one-time authenticator.
/// </summary>
public sealed class ChaCha20Poly1305Cipher : IAeadCipher
{
    public const int KeySize = 32;       // 256 bits
    public const int NonceSize = 12;     // 96 bits
    public const int TagSize = 16;       // 128 bits

    private SecureMemory? _key;
    private int _disposed;

    public int KeySizeInBytes => KeySize;
    public int NonceSizeInBytes => NonceSize;
    public int TagSizeInBytes => TagSize;

    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"ChaCha20-Poly1305 key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        }

        _key = new SecureMemory(key);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public void Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        ThrowIfDisposed();
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag destination buffer must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (ciphertext.Length < plaintext.Length)
            throw new ArgumentException($"Ciphertext destination buffer too small ({ciphertext.Length} bytes) for plaintext ({plaintext.Length} bytes).", nameof(ciphertext));

        ChaCha20Kernel.Encrypt(
            _key!.ReadOnlySpan,
            nonce,
            plaintext,
            ciphertext,
            tag,
            associatedData);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public bool Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        ThrowIfDisposed();
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag buffer must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (plaintext.Length < ciphertext.Length)
            throw new ArgumentException($"Plaintext destination buffer too small ({plaintext.Length} bytes) for ciphertext ({ciphertext.Length} bytes).", nameof(plaintext));

        return ChaCha20Kernel.Decrypt(
            _key!.ReadOnlySpan,
            nonce,
            ciphertext,
            tag,
            plaintext,
            associatedData);
    }

    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        using var cipher = new ChaCha20Poly1305Cipher(key);
        cipher.Encrypt(plaintext, associatedData, nonce, ciphertext, tag);
    }

    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        using var cipher = new ChaCha20Poly1305Cipher(key);
        return cipher.Decrypt(ciphertext, associatedData, nonce, tag, plaintext);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _key?.Dispose();
            _key = null;
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }
}
