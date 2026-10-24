namespace Glacier.Codec.Compression.Lz4;

/// <summary>
/// Constants and parameters for LZ4 block and frame format specifications.
/// Conforms to official LZ4 specifications (Block Format &amp; Frame Format v1.6.2).
/// </summary>
public static class Lz4Constants
{
    /// <summary>Standard LZ4 frame magic number (0x184D2204, Little-Endian: 04 22 4D 18).</summary>
    public const uint MagicNumber = 0x184D2204U;

    /// <summary>Legacy LZ4 frame magic number (0x184C2102).</summary>
    public const uint LegacyMagicNumber = 0x184C2102U;

    /// <summary>Minimum magic number for LZ4 skippable frames.</summary>
    public const uint SkippableMagicMin = 0x184D2A50U;

    /// <summary>Maximum magic number for LZ4 skippable frames.</summary>
    public const uint SkippableMagicMax = 0x184D2A5FU;

    /// <summary>Minimum match length required to encode an LZ4 copy sequence (4 bytes).</summary>
    public const int MinMatch = 4;

    /// <summary>Number of trailing literal bytes required at end of an uncompressed block (5 bytes).</summary>
    public const int LastLiterals = 5;

    /// <summary>Match finding limit distance from block end (12 bytes: MinMatch + LastLiterals + 3).</summary>
    public const int MfLimit = 12;

    /// <summary>Maximum lookback backward offset distance representable in 16 bits (65,535 bytes).</summary>
    public const int MaxDistance = 65535;

    /// <summary>Log2 size of the primary compression hash table (14 bits -> 16,384 entries = 64 KB).</summary>
    public const int HashLog = 14;

    /// <summary>Number of entries in the 14-bit hash table (16,384 entries).</summary>
    public const int HashTableEntries = 1 << HashLog;

    /// <summary>Fibonacci golden ratio multiplicative hash multiplier for 32-bit integer keys.</summary>
    public const uint KnuthFactor = 2654435761U; // 0x9E3779B1

    /// <summary>Memory copy vector stride for SIMD branchless wild-copy (16 bytes).</summary>
    public const int WildCopyLength = 16;

    /// <summary>Standard block maximum sizes for frame descriptors.</summary>
    public const int BlockMaxSize64K = 64 * 1024;
    public const int BlockMaxSize256K = 256 * 1024;
    public const int BlockMaxSize1M = 1024 * 1024;
    public const int BlockMaxSize4M = 4 * 1024 * 1024;
}
