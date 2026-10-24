namespace Glacier.Codec.Compression;

using System;

/// <summary>
/// Stateful, zero-allocation streaming compressor interface.
/// Provides block-by-block and chunked streaming compression.
/// </summary>
public interface IStreamingCompressor : IDisposable
{
    /// <summary>
    /// Resets internal compression state and sliding history window for a new stream.
    /// </summary>
    void Reset();

    /// <summary>
    /// Compresses an input chunk into destination buffer.
    /// </summary>
    /// <param name="source">Input uncompressed chunk.</param>
    /// <param name="destination">Output buffer for compressed bytes.</param>
    /// <param name="isFinalChunk">True if this is the final chunk of the stream.</param>
    /// <returns>Number of compressed bytes written to destination.</returns>
    int CompressChunk(ReadOnlySpan<byte> source, Span<byte> destination, bool isFinalChunk);

    /// <summary>
    /// Computes maximum compressed chunk size for the given input chunk length.
    /// </summary>
    /// <param name="chunkLength">Length of the input chunk in bytes.</param>
    /// <returns>Maximum possible size of the compressed output chunk.</returns>
    int GetMaxCompressedChunkSize(int chunkLength);
}
