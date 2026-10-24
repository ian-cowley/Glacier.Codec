namespace Glacier.Codec.Compression;

using System;

/// <summary>
/// Stateful, zero-allocation streaming decompressor interface.
/// Provides block-by-block and chunked streaming decompression.
/// </summary>
public interface IStreamingDecompressor : IDisposable
{
    /// <summary>
    /// Resets internal decompression state and sliding history window for a new stream.
    /// </summary>
    void Reset();

    /// <summary>
    /// Decompresses an input chunk into destination buffer.
    /// </summary>
    /// <param name="source">Compressed input chunk.</param>
    /// <param name="destination">Destination buffer for decompressed data.</param>
    /// <param name="bytesConsumed">Number of compressed bytes consumed from source.</param>
    /// <returns>Number of decompressed bytes written to destination.</returns>
    int DecompressChunk(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed);
}
