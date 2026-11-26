namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Memory;

/// <summary>
/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) Authenticated Encryption with Associated Data (AEAD) cipher.
/// Extends ChaCha20-Poly1305 with a 192-bit (24-byte) nonce via HChaCha20 subkey derivation,
/// enabling safe stateless random nonce generation at wire speed.
/// </summary>
public sealed class XChaCha20Poly1305Cipher : IAeadCipher
{
    public const int KeySize = 32;       // 256 bits
    public const int NonceSize = 24;     // 192 bits
    public const int TagSize = 16;       // 128 bits

    private SecureMemory? _key;
    private int _disposed;

    public int KeySizeInBytes => KeySize;
    public int NonceSizeInBytes => NonceSize;
    public int TagSizeInBytes => TagSize;

    public XChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"XChaCha20-Poly1305 key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
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

        Span<byte> subkey = stackalloc byte[32];
        Span<byte> chachaNonce = stackalloc byte[12];
        try
        {
            ChaCha20KernelScalar.HChaCha20(_key!.ReadOnlySpan, nonce.Slice(0, 16), subkey);
            chachaNonce.Slice(0, 4).Clear();
            nonce.Slice(16, 8).CopyTo(chachaNonce.Slice(4, 8));

            ChaCha20Kernel.Encrypt(
                subkey,
                chachaNonce,
                plaintext,
                ciphertext,
                tag,
                associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(chachaNonce);
        }
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

        Span<byte> subkey = stackalloc byte[32];
        Span<byte> chachaNonce = stackalloc byte[12];
        try
        {
            ChaCha20KernelScalar.HChaCha20(_key!.ReadOnlySpan, nonce.Slice(0, 16), subkey);
            chachaNonce.Slice(0, 4).Clear();
            nonce.Slice(16, 8).CopyTo(chachaNonce.Slice(4, 8));

            return ChaCha20Kernel.Decrypt(
                subkey,
                chachaNonce,
                ciphertext,
                tag,
                plaintext,
                associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(chachaNonce);
        }
    }

    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"XChaCha20-Poly1305 key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag destination buffer must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (ciphertext.Length < plaintext.Length)
            throw new ArgumentException($"Ciphertext destination buffer too small ({ciphertext.Length} bytes) for plaintext ({plaintext.Length} bytes).", nameof(ciphertext));

        Span<byte> subkey = stackalloc byte[32];
        Span<byte> chachaNonce = stackalloc byte[12];
        try
        {
            ChaCha20KernelScalar.HChaCha20(key, nonce.Slice(0, 16), subkey);
            chachaNonce.Slice(0, 4).Clear();
            nonce.Slice(16, 8).CopyTo(chachaNonce.Slice(4, 8));

            ChaCha20Kernel.Encrypt(subkey, chachaNonce, plaintext, ciphertext, tag, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(chachaNonce);
        }
    }

    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"XChaCha20-Poly1305 key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes (received {nonce.Length}).", nameof(nonce));
        if (tag.Length < TagSize)
            throw new ArgumentException($"Tag buffer must be at least {TagSize} bytes (received {tag.Length}).", nameof(tag));
        if (plaintext.Length < ciphertext.Length)
            throw new ArgumentException($"Plaintext destination buffer too small ({plaintext.Length} bytes) for ciphertext ({ciphertext.Length} bytes).", nameof(plaintext));

        Span<byte> subkey = stackalloc byte[32];
        Span<byte> chachaNonce = stackalloc byte[12];
        try
        {
            ChaCha20KernelScalar.HChaCha20(key, nonce.Slice(0, 16), subkey);
            chachaNonce.Slice(0, 4).Clear();
            nonce.Slice(16, 8).CopyTo(chachaNonce.Slice(4, 8));

            return ChaCha20Kernel.Decrypt(subkey, chachaNonce, ciphertext, tag, plaintext, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(chachaNonce);
        }
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
