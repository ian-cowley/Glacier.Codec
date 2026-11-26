namespace Glacier.Codec.Cryptography.CommittingAead;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.AesGcmSiv;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Memory;

/// <summary>
/// CMT-4 key-committing AEAD cipher using keyed BLAKE3 per-nonce subkey and commitment derivation.
/// Produces a 48-byte tag (<c>commitment[32] || innerTag[16]</c>) binding the ciphertext to the exact
/// master key, nonce, algorithm, AAD, and plaintext, preventing multi-key collision attacks.
/// </summary>
public sealed class CommittingAeadCipher : IAeadCipher
{
    public const int KeySize = 32;
    public const int CommitmentSize = 32;
    public const int InnerTagSize = 16;
    public const int TagSize = CommitmentSize + InnerTagSize; // 48 bytes

    // "Glacier.Codec.CommittingAead.v1:" (32 bytes)
    private static ReadOnlySpan<byte> DomainPrefix => "Glacier.Codec.CommittingAead.v1:"u8;

    private SecureMemory? _masterKey;
    private readonly CommittingAeadAlgorithm _algorithm;
    private int _disposed;

    public CommittingAeadAlgorithm Algorithm => _algorithm;
    public int KeySizeInBytes => KeySize;
    public int NonceSizeInBytes => _algorithm == CommittingAeadAlgorithm.XChaCha20Poly1305 ? 24 : 12;
    public int TagSizeInBytes => TagSize;

    public CommittingAeadCipher(ReadOnlySpan<byte> key, CommittingAeadAlgorithm algorithm = CommittingAeadAlgorithm.Aes256GcmSiv)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Master key must be exactly {KeySize} bytes (received {key.Length}).", nameof(key));
        if (!Enum.IsDefined(algorithm))
            throw new ArgumentOutOfRangeException(nameof(algorithm));

        _masterKey = new SecureMemory(key);
        _algorithm = algorithm;
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
        ValidateBuffers(nonce, ciphertext.Length, plaintext.Length, tag.Length);

        Span<byte> derived = stackalloc byte[64];
        try
        {
            DeriveSubkeyAndCommitment(_masterKey!.ReadOnlySpan, _algorithm, nonce, derived);
            ReadOnlySpan<byte> subKey = derived.Slice(0, 32);
            ReadOnlySpan<byte> commitment = derived.Slice(32, 32);

            Span<byte> innerTag = tag.Slice(CommitmentSize, InnerTagSize);
            switch (_algorithm)
            {
                case CommittingAeadAlgorithm.Aes256Gcm:
                    Aes256Gcm.Encrypt(subKey, nonce, plaintext, ciphertext, innerTag, associatedData);
                    break;
                case CommittingAeadAlgorithm.XChaCha20Poly1305:
                    XChaCha20Poly1305.Encrypt(subKey, nonce, plaintext, ciphertext, innerTag, associatedData);
                    break;
                case CommittingAeadAlgorithm.Aes256GcmSiv:
                    Aes256GcmSiv.Encrypt(subKey, nonce, plaintext, ciphertext, innerTag, associatedData);
                    break;
            }

            commitment.CopyTo(tag.Slice(0, CommitmentSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
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
        ValidateBuffers(nonce, plaintext.Length, ciphertext.Length, tag.Length);

        Span<byte> derived = stackalloc byte[64];
        try
        {
            DeriveSubkeyAndCommitment(_masterKey!.ReadOnlySpan, _algorithm, nonce, derived);
            ReadOnlySpan<byte> subKey = derived.Slice(0, 32);
            ReadOnlySpan<byte> expectedCommitment = derived.Slice(32, 32);

            // Verify key+nonce+algorithm commitment in constant time before touching ciphertext
            if (!CryptographicOperations.FixedTimeEquals(tag.Slice(0, CommitmentSize), expectedCommitment))
            {
                CryptographicOperations.ZeroMemory(plaintext.Slice(0, ciphertext.Length));
                return false;
            }

            ReadOnlySpan<byte> innerTag = tag.Slice(CommitmentSize, InnerTagSize);
            return _algorithm switch
            {
                CommittingAeadAlgorithm.Aes256Gcm => Aes256Gcm.Decrypt(subKey, nonce, ciphertext, innerTag, plaintext, associatedData),
                CommittingAeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305.Decrypt(subKey, nonce, ciphertext, innerTag, plaintext, associatedData),
                CommittingAeadAlgorithm.Aes256GcmSiv => Aes256GcmSiv.Decrypt(subKey, nonce, ciphertext, innerTag, plaintext, associatedData),
                _ => false
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    private static void DeriveSubkeyAndCommitment(
        ReadOnlySpan<byte> masterKey,
        CommittingAeadAlgorithm algorithm,
        ReadOnlySpan<byte> nonce,
        Span<byte> derived64)
    {
        Span<byte> context = stackalloc byte[32 + 1 + nonce.Length];
        DomainPrefix.CopyTo(context.Slice(0, 32));
        context[32] = (byte)algorithm;
        nonce.CopyTo(context.Slice(33));

        Blake3Hasher.HashKeyed(context, masterKey, derived64);
    }

    private void ValidateBuffers(ReadOnlySpan<byte> nonce, int destLen, int srcLen, int tagLen)
    {
        if (nonce.Length != NonceSizeInBytes)
            throw new ArgumentException($"Nonce must be exactly {NonceSizeInBytes} bytes (received {nonce.Length}).", nameof(nonce));
        if (tagLen < TagSize)
            throw new ArgumentException($"Tag must be at least {TagSize} bytes (received {tagLen}).");
        if (destLen < srcLen)
            throw new ArgumentException($"Destination buffer too small ({destLen} bytes) for source ({srcLen} bytes).");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _masterKey?.Dispose();
            _masterKey = null;
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }
}
