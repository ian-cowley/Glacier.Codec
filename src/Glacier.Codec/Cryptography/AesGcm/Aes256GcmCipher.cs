namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Runtime.CompilerServices;
using System.Threading;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Memory;

/// <summary>
/// Authenticated Encryption with Associated Data (AEAD) cipher utilizing AES-256-GCM (NIST SP 800-38D).
/// Features zero-allocation steady-state encryption/decryption, hardware acceleration, and fail-secure tag verification.
/// </summary>
public sealed class Aes256GcmCipher : IAeadCipher
{
    public const int KeySize = 32;       // 256 bits
    public const int NonceSize = 12;     // 96 bits
    public const int TagSize = 16;       // 128 bits
    public const int ExpandedKeyBytes = 240; // 15 round keys * 16 bytes
    public const int HTableBytes = 8 * 16; // 128 bytes (8 powers of H: H^1..H^8)

    private SecureMemory? _expandedKeys;
    private SecureMemory? _hTable;
    private int _disposed;

    public int KeySizeInBytes => KeySize;
    public int NonceSizeInBytes => NonceSize;
    public int TagSizeInBytes => TagSize;

    /// <summary>
    /// Initializes a new instance with a 32-byte AES-256 key.
    /// </summary>
    public Aes256GcmCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"AES-256 key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        }

        _expandedKeys = new SecureMemory(ExpandedKeyBytes);
        _hTable = new SecureMemory(HTableBytes);

        AesGcmKernel.ExpandKey(key, _expandedKeys.Span);
        AesGcmKernel.PrecomputeHTable(_expandedKeys.ReadOnlySpan, _hTable.Span);
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

        if (plaintext.Length >= 256 * 1024 && Environment.ProcessorCount > 1)
        {
            AesGcmParallelEngine.EncryptParallel(
                _expandedKeys!.ReadOnlySpan,
                _hTable!.ReadOnlySpan,
                nonce,
                plaintext,
                ciphertext,
                tag,
                associatedData);
            return;
        }

        AesGcmKernel.Encrypt(
            _expandedKeys!.ReadOnlySpan,
            _hTable!.ReadOnlySpan,
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

        if (ciphertext.Length >= 256 * 1024 && Environment.ProcessorCount > 1)
        {
            return AesGcmParallelEngine.DecryptParallel(
                _expandedKeys!.ReadOnlySpan,
                _hTable!.ReadOnlySpan,
                nonce,
                ciphertext,
                tag,
                plaintext,
                associatedData);
        }

        return AesGcmKernel.Decrypt(
            _expandedKeys!.ReadOnlySpan,
            _hTable!.ReadOnlySpan,
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
        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, associatedData, nonce, ciphertext, tag);
    }

    public static bool DecryptBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        using var cipher = new Aes256GcmCipher(key);
        return cipher.Decrypt(ciphertext, associatedData, nonce, tag, plaintext);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _expandedKeys?.Dispose();
            _expandedKeys = null;
            _hTable?.Dispose();
            _hTable = null;
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }
}
