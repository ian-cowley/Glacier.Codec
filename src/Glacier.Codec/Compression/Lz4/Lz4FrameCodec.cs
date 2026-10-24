namespace Glacier.Codec.Compression.Lz4;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.CompilerServices;
using Glacier.Codec.Hashing.XxHash32;
using Glacier.Codec.Memory;

/// <summary>
/// High-throughput streaming LZ4 frame codec conforming to the LZ4 Frame Format v1.6.2 specification.
/// Features FLG/BD descriptor parsing, header validation, uncompressed/compressed blocks,
/// block checksums, EndMark termination, and xxHash32 content checksum verification.
/// </summary>
public static class Lz4FrameCodec
{
    /// <summary>Standard LZ4 frame magic number (0x184D2204).</summary>
    public const uint MagicNumber = Lz4Constants.MagicNumber;

    /// <summary>
    /// Encodes uncompressed payload into a self-contained LZ4 Frame format byte stream.
    /// </summary>
    public static int EncodeFrame(
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        bool contentChecksum = true,
        bool blockChecksum = false)
    {
        if (destination.Length < 15)
        {
            throw new ArgumentException("Destination buffer too small for LZ4 frame header.", nameof(destination));
        }

        int dst = 0;

        // 1. Magic Number (0x184D2204 LE: 04 22 4D 18)
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), MagicNumber);
        dst += 4;

        int descriptorStart = dst;

        // 2. FLG byte: Version 01, BlockIndependence=1
        byte flg = 0x60;
        if (contentChecksum) flg |= 0x04;
        if (blockChecksum) flg |= 0x10;
        destination[dst++] = flg;

        // 3. BD byte: 64KB maximum block size (0x40)
        destination[dst++] = 0x40;

        int descriptorLength = dst - descriptorStart;

        // 4. Header Checksum: (XXH32(descriptor) >> 8) & 0xFF
        uint hc = (XxHash32.Hash(destination.Slice(descriptorStart, descriptorLength), 0) >> 8) & 0xFF;
        destination[dst++] = (byte)hc;

        if (source.IsEmpty)
        {
            // EndMark 0x00000000
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0);
            dst += 4;

            if (contentChecksum)
            {
                // XXH32 empty content checksum (0x02CC5D05)
                uint emptyCsum = XxHash32.Hash(ReadOnlySpan<byte>.Empty, 0);
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), emptyCsum);
                dst += 4;
            }

            return dst;
        }

        // 5. Data Blocks (Chunked by 64KB max block size)
        int srcPos = 0;
        while (srcPos < source.Length)
        {
            int chunkSize = Math.Min(source.Length - srcPos, Lz4Constants.BlockMaxSize64K);
            ReadOnlySpan<byte> chunk = source.Slice(srcPos, chunkSize);

            int maxCompSize = Lz4Codec.MaximumCompressedSize(chunkSize);
            using var slab = UnmanagedSlabPool.Shared.Rent(maxCompSize);
            int compLen = Lz4Codec.Compress(chunk, slab.Span);

            if (compLen >= chunkSize)
            {
                // Uncompressed / Raw Block (MSB set)
                uint rawBlockHeader = 0x80000000U | (uint)chunkSize;
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), rawBlockHeader);
                dst += 4;

                chunk.CopyTo(destination.Slice(dst, chunkSize));
                dst += chunkSize;

                if (blockChecksum)
                {
                    uint bsum = XxHash32.Hash(chunk, 0);
                    BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), bsum);
                    dst += 4;
                }
            }
            else
            {
                // Compressed Block (MSB = 0)
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), (uint)compLen);
                dst += 4;

                slab.Span.Slice(0, compLen).CopyTo(destination.Slice(dst, compLen));
                dst += compLen;

                if (blockChecksum)
                {
                    uint bsum = XxHash32.Hash(slab.Span.Slice(0, compLen), 0);
                    BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), bsum);
                    dst += 4;
                }
            }

            srcPos += chunkSize;
        }

        // 6. EndMark (0x00000000)
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0);
        dst += 4;

        // 7. Content Checksum
        if (contentChecksum)
        {
            uint csum = XxHash32.Hash(source, 0);
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), csum);
            dst += 4;
        }

        return dst;
    }

    /// <summary>
    /// Decodes a complete LZ4 Frame format stream into destination uncompressed buffer.
    /// </summary>
    public static int DecodeFrame(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length < 7) throw new InvalidDataException("LZ4 frame too short.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));

        // Check for skippable frames (0x184D2A50 - 0x184D2A5F)
        if (magic >= Lz4Constants.SkippableMagicMin && magic <= Lz4Constants.SkippableMagicMax)
        {
            if (source.Length < 8) throw new InvalidDataException("Truncated skippable frame.");
            uint skipSize = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(4, 4));
            if (8 + skipSize > (uint)source.Length) throw new InvalidDataException("Skippable frame size exceeds buffer.");
            return 0;
        }

        if (magic != MagicNumber) throw new InvalidDataException($"Invalid LZ4 magic: 0x{magic:X8}");

        int src = 4;
        int descriptorStart = src;

        byte flg = source[src++];
        byte bd = source[src++];

        // Validate version
        int version = (flg >> 6) & 0x03;
        if (version != 1) throw new InvalidDataException($"Unsupported LZ4 frame version: {version}");

        // Validate reserved bits
        if ((flg & 0x02) != 0) throw new InvalidDataException("Corrupted LZ4 FLG: reserved bit 1 is set.");
        if ((bd & 0x8F) != 0) throw new InvalidDataException("Corrupted LZ4 BD: reserved bits are set.");

        bool blockIndependence = (flg & 0x20) != 0;
        bool blockChecksum = (flg & 0x10) != 0;
        bool contentSizeFlag = (flg & 0x08) != 0;
        bool contentChecksumFlag = (flg & 0x04) != 0;
        bool dictIdFlag = (flg & 0x01) != 0;

        int blockMaxSizeId = (bd >> 4) & 0x07;
        if (blockMaxSizeId < 4 || blockMaxSizeId > 7)
        {
            throw new InvalidDataException($"Invalid LZ4 block max size ID: {blockMaxSizeId}");
        }

        ulong contentSize = 0;
        if (contentSizeFlag)
        {
            if (src + 8 > source.Length) throw new InvalidDataException("LZ4 truncated content size field.");
            contentSize = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(src, 8));
            src += 8;
        }

        if (dictIdFlag)
        {
            if (src + 4 > source.Length) throw new InvalidDataException("LZ4 truncated dict ID field.");
            src += 4;
        }

        // Validate Header Checksum
        if (src >= source.Length) throw new InvalidDataException("LZ4 truncated header checksum.");
        byte storedHc = source[src++];
        int descLen = (src - 1) - descriptorStart;
        byte computedHc = (byte)((XxHash32.Hash(source.Slice(descriptorStart, descLen), 0) >> 8) & 0xFF);
        if (storedHc != computedHc)
        {
            throw new InvalidDataException($"Corrupt LZ4 frame header checksum: expected 0x{computedHc:X2}, got 0x{storedHc:X2}.");
        }

        // Read Data Blocks
        int dst = 0;
        while (src + 4 <= source.Length)
        {
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(src, 4));
            src += 4;

            if (blockSize == 0)
            {
                // EndMark reached
                break;
            }

            bool isUncompressed = (blockSize & 0x80000000U) != 0;
            int size = (int)(blockSize & 0x7FFFFFFFU);

            if (src + size > source.Length) throw new InvalidDataException("LZ4 data block truncated.");

            ReadOnlySpan<byte> blockData = source.Slice(src, size);
            src += size;

            if (blockChecksum)
            {
                if (src + 4 > source.Length) throw new InvalidDataException("LZ4 truncated block checksum.");
                uint storedBsum = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(src, 4));
                src += 4;
                uint computedBsum = XxHash32.Hash(blockData, 0);
                if (storedBsum != computedBsum) throw new InvalidDataException("LZ4 block checksum mismatch.");
            }

            if (isUncompressed)
            {
                if (dst + size > destination.Length) throw new InvalidDataException("Destination buffer too small.");
                blockData.CopyTo(destination.Slice(dst, size));
                dst += size;
            }
            else
            {
                int decomp = Lz4Codec.Decompress(blockData, destination.Slice(dst));
                dst += decomp;
            }
        }

        // Verify Content Checksum if requested
        if (contentChecksumFlag)
        {
            if (src + 4 > source.Length) throw new InvalidDataException("LZ4 truncated content checksum.");
            uint storedCsum = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(src, 4));
            src += 4;

            uint computedCsum = XxHash32.Hash(destination.Slice(0, dst), 0);
            if (storedCsum != computedCsum)
            {
                throw new InvalidDataException($"Corrupt LZ4 content checksum: expected 0x{computedCsum:X8}, got 0x{storedCsum:X8}.");
            }
        }

        return dst;
    }
}

/// <summary>
/// Stateful, zero-allocation streaming LZ4 compressor.
/// </summary>
public sealed class Lz4StreamCompressor : IStreamingCompressor
{
    private bool _isDisposed;

    /// <inheritdoc />
    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
    }

    /// <inheritdoc />
    public int CompressChunk(ReadOnlySpan<byte> source, Span<byte> destination, bool isFinalChunk)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return Lz4Codec.Compress(source, destination);
    }

    /// <inheritdoc />
    public int GetMaxCompressedChunkSize(int chunkLength)
    {
        return Lz4Codec.MaximumCompressedSize(chunkLength);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _isDisposed = true;
    }
}

/// <summary>
/// Stateful, zero-allocation streaming LZ4 decompressor.
/// </summary>
public sealed class Lz4StreamDecompressor : IStreamingDecompressor
{
    private bool _isDisposed;

    /// <inheritdoc />
    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
    }

    /// <inheritdoc />
    public int DecompressChunk(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        int written = Lz4Codec.Decompress(source, destination);
        bytesConsumed = source.Length;
        return written;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _isDisposed = true;
    }
}
