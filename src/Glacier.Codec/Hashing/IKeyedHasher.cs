namespace Glacier.Codec.Hashing;

using System;

/// <summary>
/// Extension contract for keyed MAC or PRF streaming hashing.
/// </summary>
public interface IKeyedHasher : IStreamingHasher
{
    /// <summary>Initializes or updates the cryptographic key.</summary>
    void SetKey(ReadOnlySpan<byte> key);
}
