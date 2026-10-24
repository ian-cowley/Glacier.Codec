namespace Glacier.Codec.Compression.Zstd;

/// <summary>
/// Constants, magic numbers, and standardized distribution tables for Zstandard (RFC 8878).
/// </summary>
public static class ZstdConstants
{
    /// <summary>Standard Zstandard frame magic number (0xFD2FB528, Little-Endian: 28 B5 2F FD).</summary>
    public const uint MagicNumber = 0xFD2FB528U;

    /// <summary>Minimum magic number for Zstandard skippable frames.</summary>
    public const uint SkippableMagicMin = 0x184D2A50U;

    /// <summary>Maximum magic number for Zstandard skippable frames.</summary>
    public const uint SkippableMagicMax = 0x184D2A5FU;

    /// <summary>Raw (uncompressed) block type (0).</summary>
    public const int BlockTypeRaw = 0;

    /// <summary>Run-length encoded block type (1).</summary>
    public const int BlockTypeRle = 1;

    /// <summary>Compressed (Huffman + FSE) block type (2).</summary>
    public const int BlockTypeCompressed = 2;

    /// <summary>Reserved block type (3) - illegal in RFC 8878.</summary>
    public const int BlockTypeReserved = 3;

    /// <summary>Raw uncompressed literals block type (0).</summary>
    public const int LiteralsTypeRaw = 0;

    /// <summary>RLE literals block type (1).</summary>
    public const int LiteralsTypeRle = 1;

    /// <summary>Compressed Huffman literals block with new tree description (2).</summary>
    public const int LiteralsTypeCompressed = 2;

    /// <summary>Treeless literals block reusing previous Huffman tree (3).</summary>
    public const int LiteralsTypeTreeless = 3;

    /// <summary>Maximum allowed block size in RFC 8878 (128 KB).</summary>
    public const int MaxBlockSize = 128 * 1024;

    /// <summary>Predefined normalized distribution for Literal Lengths (AccuracyLog = 6, 36 symbols).</summary>
    public static readonly short[] PredefinedLiteralLengthsDistribution =
    [
        4,  3,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  1,  1,  1,
        2,  2,  2,  2,  2,  2,  2,  2,  2,  3,  2,  1,  1,  1,  1,  1,
        -1, -1, -1, -1
    ];

    /// <summary>Predefined normalized distribution for Match Lengths (AccuracyLog = 6, 53 symbols).</summary>
    public static readonly short[] PredefinedMatchLengthsDistribution =
    [
        1,  4,  3,  2,  2,  2,  2,  2,  2,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1
    ];

    /// <summary>Predefined normalized distribution for Offsets (AccuracyLog = 5, 29 symbols).</summary>
    public static readonly short[] PredefinedOffsetsDistribution =
    [
        1,  1,  1,  1,  1,  1,  2,  2,  2,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  1,  1,  1, -1, -1, -1, -1, -1
    ];

    /// <summary>RFC 8878 Table 16: Literal Length Codes (0..35) baseline values.</summary>
    public static readonly int[] Table16_Baseline =
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
        2048, 4096, 8192, 16384, 32768, 65536
    ];

    /// <summary>RFC 8878 Table 16: Literal Length Codes (0..35) number of extra bits.</summary>
    public static readonly byte[] Table16_Bits =
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16
    ];

    /// <summary>RFC 8878 Table 17: Match Length Codes (0..52) baseline values.</summary>
    public static readonly int[] Table17_Baseline =
    [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
        1027, 2051, 4099, 8195, 16387, 32771, 65539
    ];

    /// <summary>RFC 8878 Table 17: Match Length Codes (0..52) number of extra bits.</summary>
    public static readonly byte[] Table17_Bits =
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16
    ];
}
