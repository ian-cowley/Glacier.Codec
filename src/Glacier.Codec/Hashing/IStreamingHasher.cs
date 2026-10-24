namespace Glacier.Codec.Hashing;

using System;

/// <summary>
/// Zero-allocation contract for high-throughput streaming digest and hash engines.
/// </summary>
public interface IStreamingHasher : IDisposable
{
    /// <summary>Output digest size in bytes.</summary>
    int HashSizeInBytes { get; }

    /// <summary>Resets internal state for hashing a new stream.</summary>
    void Reset();

    /// <summary>Appends data to the running digest.</summary>
    void Append(ReadOnlySpan<byte> data);

    /// <summary>Extracts intermediate digest without finalizing state.</summary>
    void GetCurrentHash(Span<byte> destination);

    /// <summary>Finalizes the digest into destination and resets state.</summary>
    void Finalize(Span<byte> destination);
}
