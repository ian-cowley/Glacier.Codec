namespace Glacier.Codec.Cryptography.CommittingAead;

/// <summary>
/// Inner AEAD cipher wrapped by <see cref="CommittingAeadCipher"/> for CMT-4 key commitment.
/// </summary>
public enum CommittingAeadAlgorithm : byte
{
    Aes256Gcm = 1,
    XChaCha20Poly1305 = 2,
    Aes256GcmSiv = 3
}
