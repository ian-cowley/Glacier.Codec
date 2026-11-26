namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.EllipticCurve;
using Glacier.Codec.Memory;

/// <summary>
/// X-Wing hybrid Key Encapsulation Mechanism (draft-connolly-cfrg-xwing-kem) combining
/// NIST FIPS 203 ML-KEM-768 and RFC 7748 X25519 via SHA3-256 combiner.
/// </summary>
public sealed class XWing : IKeyEncapsulationMechanism, IDisposable
{
    public const int PublicKeyBytes = MlKem768.PublicKeyBytes + X25519.KeySize;     // 1216 bytes
    public const int SecretKeyBytes = 32;                                             // 32-byte seed
    public const int CiphertextBytes = MlKem768.CiphertextBytes + X25519.KeySize;   // 1120 bytes
    public const int SharedSecretBytes = 32;
    public const int EncapsSeedBytes = 64;

    // X-Wing domain separation label: "\.//^\" (0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)
    private static ReadOnlySpan<byte> XWingLabel => [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

    public static XWing Instance { get; } = new();

    public int PublicKeySizeInBytes => PublicKeyBytes;
    public int SecretKeySizeInBytes => SecretKeyBytes;
    public int CiphertextSizeInBytes => CiphertextBytes;
    public int SharedSecretSizeInBytes => SharedSecretBytes;

    public XWingKeyPair CreateKeyPair()
    {
        var sk = new SecureMemory(SecretKeyBytes);
        byte[] pk = new byte[PublicKeyBytes];
        GenerateKeyPair(pk, sk.Span);
        return new XWingKeyPair(this, pk, sk);
    }

    public void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey)
    {
        if (publicKey.Length < PublicKeyBytes)
            throw new ArgumentException($"Public key buffer must be at least {PublicKeyBytes} bytes.", nameof(publicKey));
        if (secretKey.Length < SecretKeyBytes)
            throw new ArgumentException($"Secret key buffer must be at least {SecretKeyBytes} bytes.", nameof(secretKey));

        Span<byte> seed = stackalloc byte[SecretKeyBytes];
        try
        {
            RandomNumberGenerator.Fill(seed);
            GenerateKeyPairDerand(seed, publicKey, secretKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public void GenerateKeyPairDerand(
        ReadOnlySpan<byte> seed,
        Span<byte> publicKey,
        Span<byte> secretKey)
    {
        if (seed.Length != SecretKeyBytes)
            throw new ArgumentException($"Seed must be exactly {SecretKeyBytes} bytes.", nameof(seed));
        if (publicKey.Length < PublicKeyBytes)
            throw new ArgumentException($"Public key buffer must be at least {PublicKeyBytes} bytes.", nameof(publicKey));
        if (secretKey.Length < SecretKeyBytes)
            throw new ArgumentException($"Secret key buffer must be at least {SecretKeyBytes} bytes.", nameof(secretKey));

        Span<byte> skM = stackalloc byte[MlKem768.SecretKeyBytes];
        Span<byte> skX = stackalloc byte[X25519.KeySize];
        try
        {
            ExpandDecapsulationKey(
                seed,
                skM,
                skX,
                publicKey.Slice(0, MlKem768.PublicKeyBytes),
                publicKey.Slice(MlKem768.PublicKeyBytes, X25519.KeySize));

            seed.CopyTo(secretKey.Slice(0, SecretKeyBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(skM);
            CryptographicOperations.ZeroMemory(skX);
        }
    }

    public void Encapsulate(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (publicKey.Length != PublicKeyBytes)
            throw new ArgumentException($"Encapsulation key must be {PublicKeyBytes} bytes.", nameof(publicKey));
        if (ciphertext.Length < CiphertextBytes)
            throw new ArgumentException($"Ciphertext buffer must be at least {CiphertextBytes} bytes.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes)
            throw new ArgumentException($"Shared secret buffer must be at least {SharedSecretBytes} bytes.", nameof(sharedSecret));

        Span<byte> eseed = stackalloc byte[EncapsSeedBytes];
        try
        {
            RandomNumberGenerator.Fill(eseed);
            EncapsulateDerand(publicKey, eseed, ciphertext, sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(eseed);
        }
    }

    public void EncapsulateDerand(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> eseed,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        if (publicKey.Length != PublicKeyBytes)
            throw new ArgumentException($"Encapsulation key must be {PublicKeyBytes} bytes.", nameof(publicKey));
        if (eseed.Length != EncapsSeedBytes)
            throw new ArgumentException($"Encapsulation seed must be {EncapsSeedBytes} bytes.", nameof(eseed));
        if (ciphertext.Length < CiphertextBytes)
            throw new ArgumentException($"Ciphertext buffer must be at least {CiphertextBytes} bytes.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes)
            throw new ArgumentException($"Shared secret buffer must be at least {SharedSecretBytes} bytes.", nameof(sharedSecret));

        ReadOnlySpan<byte> pkM = publicKey.Slice(0, MlKem768.PublicKeyBytes);
        ReadOnlySpan<byte> pkX = publicKey.Slice(MlKem768.PublicKeyBytes, X25519.KeySize);
        ReadOnlySpan<byte> m = eseed.Slice(0, 32);
        ReadOnlySpan<byte> ekX = eseed.Slice(32, X25519.KeySize);

        Span<byte> ctM = ciphertext.Slice(0, MlKem768.CiphertextBytes);
        Span<byte> ctX = ciphertext.Slice(MlKem768.CiphertextBytes, X25519.KeySize);

        Span<byte> ssM = stackalloc byte[32];
        Span<byte> ssX = stackalloc byte[32];
        try
        {
            // Validates pkM modulus bounds per FIPS 203 §7.2 inside EncapsulateDerand
            MlKemEngine.MlKem768.EncapsulateDerand(pkM, m, ctM, ssM);
            X25519.ScalarMultBase(ekX, ctX);
            X25519.ScalarMult(ekX, pkX, ssX);

            Combiner(ssM, ssX, ctX, pkX, sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
        }
    }

    public void Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (secretKey.Length != SecretKeyBytes)
            throw new ArgumentException($"Decapsulation key must be {SecretKeyBytes} bytes.", nameof(secretKey));
        if (ciphertext.Length != CiphertextBytes)
            throw new ArgumentException($"Ciphertext must be {CiphertextBytes} bytes.", nameof(ciphertext));
        if (sharedSecret.Length < SharedSecretBytes)
            throw new ArgumentException($"Shared secret buffer must be at least {SharedSecretBytes} bytes.", nameof(sharedSecret));

        Span<byte> skM = stackalloc byte[MlKem768.SecretKeyBytes];
        Span<byte> skX = stackalloc byte[X25519.KeySize];
        Span<byte> pkM = stackalloc byte[MlKem768.PublicKeyBytes];
        Span<byte> pkX = stackalloc byte[X25519.KeySize];
        Span<byte> ssM = stackalloc byte[32];
        Span<byte> ssX = stackalloc byte[32];
        try
        {
            ExpandDecapsulationKey(secretKey, skM, skX, pkM, pkX);

            ReadOnlySpan<byte> ctM = ciphertext.Slice(0, MlKem768.CiphertextBytes);
            ReadOnlySpan<byte> ctX = ciphertext.Slice(MlKem768.CiphertextBytes, X25519.KeySize);

            MlKemEngine.MlKem768.Decapsulate(skM, ctM, ssM);
            // Raw ScalarMult (including all-zero output on low-order ctX) preserves IND-CCA2 implicit rejection
            X25519.ScalarMult(skX, ctX, ssX);

            Combiner(ssM, ssX, ctX, pkX, sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(skM);
            CryptographicOperations.ZeroMemory(skX);
            CryptographicOperations.ZeroMemory(pkM);
            CryptographicOperations.ZeroMemory(pkX);
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
        }
    }

    private static void ExpandDecapsulationKey(
        ReadOnlySpan<byte> skSeed,
        Span<byte> skM,
        Span<byte> skX,
        Span<byte> pkM,
        Span<byte> pkX)
    {
        Span<byte> expanded = stackalloc byte[96];
        try
        {
            KeccakSponge.Shake256(skSeed.Slice(0, SecretKeyBytes), expanded);
            MlKemEngine.MlKem768.GenerateKeyPairDerand(
                expanded.Slice(0, 32),
                expanded.Slice(32, 32),
                pkM,
                skM);

            expanded.Slice(64, 32).CopyTo(skX);
            X25519.ScalarMultBase(skX, pkX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
        }
    }

    private static void Combiner(
        ReadOnlySpan<byte> ssM,
        ReadOnlySpan<byte> ssX,
        ReadOnlySpan<byte> ctX,
        ReadOnlySpan<byte> pkX,
        Span<byte> sharedSecret)
    {
        Span<byte> input = stackalloc byte[32 + 32 + 32 + 32 + 6];
        try
        {
            ssM.Slice(0, 32).CopyTo(input.Slice(0, 32));
            ssX.Slice(0, 32).CopyTo(input.Slice(32, 32));
            ctX.Slice(0, 32).CopyTo(input.Slice(64, 32));
            pkX.Slice(0, 32).CopyTo(input.Slice(96, 32));
            XWingLabel.CopyTo(input.Slice(128, 6));

            KeccakSponge.Sha3_256(input, sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    // Static convenience helpers
    public static void GenerateKeys(Span<byte> publicKey, Span<byte> secretKey) => Instance.GenerateKeyPair(publicKey, secretKey);
    public static void EncapsulateSecret(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret) => Instance.Encapsulate(publicKey, ciphertext, sharedSecret);
    public static void DecapsulateSecret(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) => Instance.Decapsulate(secretKey, ciphertext, sharedSecret);

    public void Dispose() { }
}
