namespace Glacier.Codec.Hashing.Blake3;

/// <summary>
/// Operational constants, standard IV words, and permutation schedules for BLAKE3.
/// </summary>
internal static class Blake3Constants
{
    public const int ChunkSize = 1024;
    public const int BlockSize = 64;
    public const int KeySize = 32;
    public const int DefaultHashSize = 32;
    public const int MaxTreeDepth = 54;

    public static readonly uint[] IV = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ];

    public static readonly byte[] Sigma = [
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    ];
}
