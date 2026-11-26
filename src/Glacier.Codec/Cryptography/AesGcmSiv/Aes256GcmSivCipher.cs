namespace Glacier.Codec.Cryptography.AesGcmSiv;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Memory;

/// <summary>
/// RFC 8452 AES-256-GCM-SIV deterministic, nonce-misuse resistant AEAD cipher.
/// </summary>
public sealed class Aes256GcmSivCipher : IAeadCipher
{
    public const int KeySize = 32;            // 256 bits (Key-Generating Key)
    public const int NonceSize = 12;          // 96 bits
    public const int TagSize = 16;            // 128 bits
    public const int ExpandedKeyBytes = 240;  // 15 round keys * 16 bytes

    private SecureMemory? _expandedKeys;
    private int _disposed;

    public int KeySizeInBytes => KeySize;
    public int NonceSizeInBytes => NonceSize;
    public int TagSizeInBytes => TagSize;

    public Aes256GcmSivCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"AES-256-GCM-SIV key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        }

        _expandedKeys = new SecureMemory(ExpandedKeyBytes);
        AesGcmKernel.ExpandKey(key, _expandedKeys.Span);
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
            throw new ArgumentException($"Tag destination must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (ciphertext.Length < plaintext.Length)
            throw new ArgumentException($"Ciphertext destination buffer too small ({ciphertext.Length} bytes) for plaintext ({plaintext.Length} bytes).", nameof(ciphertext));

        Aes256GcmSivKernel.Encrypt(
            _expandedKeys!.ReadOnlySpan,
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
            throw new ArgumentException($"Tag must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (plaintext.Length < ciphertext.Length)
            throw new ArgumentException($"Plaintext destination buffer too small ({plaintext.Length} bytes) for ciphertext ({ciphertext.Length} bytes).", nameof(plaintext));

        return Aes256GcmSivKernel.Decrypt(
            _expandedKeys!.ReadOnlySpan,
            nonce,
            ciphertext,
            tag,
            plaintext,
            associatedData);
    }

    public static void EncryptBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"AES-256-GCM-SIV key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag destination must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (ciphertext.Length < plaintext.Length)
            throw new ArgumentException($"Ciphertext destination buffer too small ({ciphertext.Length} bytes) for plaintext ({plaintext.Length} bytes).", nameof(ciphertext));

        Span<byte> expandedKeys = stackalloc byte[ExpandedKeyBytes];
        try
        {
            AesGcmKernel.ExpandKey(key, expandedKeys);
            Aes256GcmSivKernel.Encrypt(expandedKeys, nonce, plaintext, ciphertext, tag, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expandedKeys);
        }
    }

    public static bool DecryptBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"AES-256-GCM-SIV key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (plaintext.Length < ciphertext.Length)
            throw new ArgumentException($"Plaintext destination buffer too small ({plaintext.Length} bytes) for ciphertext ({ciphertext.Length} bytes).", nameof(plaintext));

        Span<byte> expandedKeys = stackalloc byte[ExpandedKeyBytes];
        try
        {
            AesGcmKernel.ExpandKey(key, expandedKeys);
            return Aes256GcmSivKernel.Decrypt(expandedKeys, nonce, ciphertext, tag, plaintext, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expandedKeys);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _expandedKeys?.Dispose();
            _expandedKeys = null;
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }
}
