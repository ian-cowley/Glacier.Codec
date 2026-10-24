#if !HAS_GLACIER_CODEC

namespace Glacier.Codec.Hardware
{
    public enum ExecutionTarget : byte
    {
        CpuVector = 0,
        CpuParallelPool = 1,
        GpuCompute = 2
    }

    public enum HardwareTier : byte
    {
        Tier2_ScalarFallback = 0,
        Tier1_MainstreamVector = 1,
        Tier0_UltrawideVector = 2
    }
}

namespace Glacier.Codec.Hashing
{
    public interface IStreamingHasher : IDisposable
    {
        int HashSizeInBytes { get; }
        void Reset();
        void Append(ReadOnlySpan<byte> data);
        void GetCurrentHash(Span<byte> destination);
        void Finalize(Span<byte> destination);
    }

    public interface IKeyedHasher : IStreamingHasher
    {
        void SetKey(ReadOnlySpan<byte> key);
    }

    [Flags]
    public enum Blake3Flags : uint
    {
        None = 0,
        ChunkStart = 1 << 0,
        ChunkEnd = 1 << 1,
        Parent = 1 << 2,
        Root = 1 << 3,
        KeyedHash = 1 << 4,
        DeriveKeyContext = 1 << 5,
        DeriveKeyMaterial = 1 << 6
    }
}

namespace Glacier.Codec.Cryptography
{
    public interface IAeadCipher : IDisposable
    {
        int KeySizeInBytes { get; }
        int NonceSizeInBytes { get; }
        int TagSizeInBytes { get; }

        void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> nonce,
            Span<byte> ciphertext,
            Span<byte> tag);

        bool Decrypt(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext);
    }
}

namespace Glacier.Codec.Cryptography.Kdf
{
    public interface IKeyDerivationFunction
    {
        void DeriveKey(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> derivedKey);
    }
}

namespace Glacier.Codec.Cryptography.PostQuantum
{
    public interface IKeyEncapsulationMechanism
    {
        int PublicKeySizeInBytes { get; }
        int SecretKeySizeInBytes { get; }
        int CiphertextSizeInBytes { get; }
        int SharedSecretSizeInBytes { get; }

        void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey);
        void Encapsulate(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret);
        bool Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);
    }
}

namespace Glacier.Codec.Compression
{
    public interface ICompressionCodec
    {
        int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination);
        int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination);
        int GetMaxCompressedSize(int sourceLength);
    }
}

#endif
