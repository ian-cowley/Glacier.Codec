namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Security.Cryptography;

/// <summary>
/// FIPS 203 ML-KEM-1024 Key Encapsulation Mechanism (Rank k=4, NIST Security Level 5).
/// </summary>
public sealed class MlKem1024 : MlKemEngine
{
    public const int PublicKeyBytes = 1568;
    public const int SecretKeyBytes = 3168;
    public const int CiphertextBytes = 1568;
    public const int SharedSecretBytes = 32;

    public override int PublicKeySizeInBytes => PublicKeyBytes;
    public override int SecretKeySizeInBytes => SecretKeyBytes;
    public override int CiphertextSizeInBytes => CiphertextBytes;

    public MlKem1024() : base(rankK: 4, du: 11, dv: 5) { }

    public override void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey)
    {
        if (publicKey.Length < PublicKeyBytes)
            throw new ArgumentException("Public key buffer too small.", nameof(publicKey));
        if (secretKey.Length < SecretKeyBytes)
            throw new ArgumentException("Secret key buffer too small.", nameof(secretKey));

        Span<byte> d = stackalloc byte[32];
        Span<byte> z = stackalloc byte[32];
        RandomNumberGenerator.Fill(d);
        RandomNumberGenerator.Fill(z);

        KeyGenInternal(d, z, publicKey, secretKey);

        CryptographicOperations.ZeroMemory(d);
        CryptographicOperations.ZeroMemory(z);
    }

    public override void Encapsulate(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (publicKey.Length < PublicKeyBytes)
            throw new ArgumentException("Public key buffer too small.", nameof(publicKey));
        if (ciphertext.Length < CiphertextBytes)
            throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes)
            throw new ArgumentException("Shared secret buffer too small.", nameof(sharedSecret));

        Span<byte> m = stackalloc byte[32];
        RandomNumberGenerator.Fill(m);

        EncapsInternal(publicKey, m, ciphertext, sharedSecret);

        CryptographicOperations.ZeroMemory(m);
    }

    public override bool Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (secretKey.Length < SecretKeyBytes)
            throw new ArgumentException("Secret key buffer too small.", nameof(secretKey));
        if (ciphertext.Length < CiphertextBytes)
            throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes)
            throw new ArgumentException("Shared secret buffer too small.", nameof(sharedSecret));

        return DecapsInternal(secretKey, ciphertext, sharedSecret);
    }

    /// <summary>Deterministic key generation for NIST ACVP KAT test vectors.</summary>
    public void GenerateKeyPairDerand(
        ReadOnlySpan<byte> d,
        ReadOnlySpan<byte> z,
        Span<byte> publicKey,
        Span<byte> secretKey)
    {
        if (d.Length != 32) throw new ArgumentException("Seed d must be 32 bytes.", nameof(d));
        if (z.Length != 32) throw new ArgumentException("Seed z must be 32 bytes.", nameof(z));
        if (publicKey.Length < PublicKeyBytes) throw new ArgumentException("Public key buffer too small.", nameof(publicKey));
        if (secretKey.Length < SecretKeyBytes) throw new ArgumentException("Secret key buffer too small.", nameof(secretKey));

        KeyGenInternal(d, z, publicKey, secretKey);
    }

    /// <summary>Deterministic encapsulation for NIST ACVP KAT test vectors.</summary>
    public void EncapsulateDerand(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> m,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        if (m.Length != 32) throw new ArgumentException("Randomness m must be 32 bytes.", nameof(m));
        if (publicKey.Length < PublicKeyBytes) throw new ArgumentException("Public key buffer too small.", nameof(publicKey));
        if (ciphertext.Length < CiphertextBytes) throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes) throw new ArgumentException("Shared secret buffer too small.", nameof(sharedSecret));

        EncapsInternal(publicKey, m, ciphertext, sharedSecret);
    }

    // Static convenience helpers
    public static void GenerateKeys(Span<byte> publicKey, Span<byte> secretKey) => MlKem1024.GenerateKeyPair(publicKey, secretKey);
    public static void EncapsulateSecret(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret) => MlKem1024.Encapsulate(publicKey, ciphertext, sharedSecret);
    public static bool DecapsulateSecret(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) => MlKem1024.Decapsulate(secretKey, ciphertext, sharedSecret);
}
