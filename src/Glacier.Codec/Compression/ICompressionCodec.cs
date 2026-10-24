namespace Glacier.Codec.Compression;

using System;

/// <summary>
/// Zero-allocation block compression and decompression contract.
/// </summary>
public interface ICompressionCodec
{
    /// <summary>Compresses source block into destination buffer.</summary>
    /// <returns>Number of compressed bytes written.</returns>
    int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination);

    /// <summary>Decompresses source block into destination buffer.</summary>
    /// <returns>Number of decompressed bytes written.</returns>
    int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination);

    /// <summary>Computes maximum compressed size for a given input length.</summary>
    int GetMaxCompressedSize(int sourceLength);
}
