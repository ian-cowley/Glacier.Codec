namespace Glacier.Codec.Hashing;

using System;

/// <summary>
/// Operational state flags for BLAKE3 chunk and tree reduction processing.
/// </summary>
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
