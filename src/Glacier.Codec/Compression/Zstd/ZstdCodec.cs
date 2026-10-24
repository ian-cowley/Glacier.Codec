namespace Glacier.Codec.Compression.Zstd;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.CompilerServices;
using Glacier.Codec.Hashing.XxHash32;
using Glacier.Codec.Memory;

/// <summary>
/// Ultra-high-throughput Zstandard (RFC 8878) block and frame codec.
/// Supports standard and skippable frames, raw/RLE/compressed blocks,
/// 1-stream and 4-stream backward Huffman literals, FSE sequence decoding,
/// 3-entry repeat offset rolling history, and xxHash64 content checksums.
/// </summary>
public sealed class ZstdCodec : ICompressionCodec
{
    /// <summary>RFC 8878 Zstandard standard frame magic number (0xFD2FB528).</summary>
    public const uint MagicNumber = ZstdConstants.MagicNumber;

    /// <inheritdoc />
    public int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Compress(source, destination);

    /// <inheritdoc />
    public int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Decompress(source, destination);

    /// <inheritdoc />
    public int GetMaxCompressedSize(int sourceLength) => MaximumCompressedSize(sourceLength);

    /// <summary>
    /// Computes maximum compressed frame buffer size required for input length.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaximumCompressedSize(int inputLength)
    {
        if (inputLength < 0) throw new ArgumentOutOfRangeException(nameof(inputLength));
        return inputLength + (inputLength / 128) + 64;
    }

    /// <summary>
    /// Compresses source bytes into an RFC 8878 compliant Zstandard frame.
    /// </summary>
    public static int Compress(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int dst = 0;

        // 1. Magic Number (0xFD2FB528 LE: 28 B5 2F FD)
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), MagicNumber);
        dst += 4;

        if (source.IsEmpty)
        {
            // Empty frame: FHD Single_Segment=1, Checksum=0, FCS_Flag=0 (0x20)
            destination[dst++] = 0x20;
            // Frame Content Size (0x00)
            destination[dst++] = 0x00;
            // Block Header: Last=1, Raw=0, Size=0 (0x000001)
            destination[dst++] = 0x01;
            destination[dst++] = 0x00;
            destination[dst++] = 0x00;
            return dst;
        }

        // FHD: Single_Segment=1 (0x20), Content_Checksum=1 (0x04)
        if (source.Length < 256)
        {
            destination[dst++] = 0x24; // FCS_Flag=0, Single_Segment=1, Checksum=1
            destination[dst++] = (byte)source.Length;
        }
        else
        {
            destination[dst++] = 0xA4; // FCS_Flag=2, Single_Segment=1, Checksum=1
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), (uint)source.Length);
            dst += 4;
        }

        // Chunk input into RFC 8878 compliant blocks (<= 128 KB each)
        int srcPos = 0;
        while (srcPos < source.Length)
        {
            int chunkSize = Math.Min(source.Length - srcPos, ZstdConstants.MaxBlockSize);
            bool isLast = (srcPos + chunkSize >= source.Length);
            ReadOnlySpan<byte> chunk = source.Slice(srcPos, chunkSize);

            // Check if chunk qualifies for RLE block encoding
            bool isChunkRle = false;
            if (chunk.Length >= 16)
            {
                byte first = chunk[0];
                int run = 1;
                while (run < chunk.Length && chunk[run] == first) run++;
                if (run == chunk.Length) isChunkRle = true;
            }

            if (isChunkRle)
            {
                // Emit RLE Block: Last=(isLast ? 1 : 0), Type=1 (RLE), Size=chunkSize
                uint blockHeader = (isLast ? 1U : 0U) | (1U << 1) | ((uint)chunkSize << 3);
                destination[dst++] = (byte)(blockHeader & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 8) & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 16) & 0xFF);

                destination[dst++] = chunk[0];
            }
            else
            {
                // Emit Raw Block: Last=(isLast ? 1 : 0), Type=0 (Raw), Size=chunkSize
                uint blockHeader = (isLast ? 1U : 0U) | (0U << 1) | ((uint)chunkSize << 3);
                destination[dst++] = (byte)(blockHeader & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 8) & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 16) & 0xFF);

                chunk.CopyTo(destination.Slice(dst, chunkSize));
                dst += chunkSize;
            }

            srcPos += chunkSize;
        }

        // Content Checksum: lower 32-bits of XXH64(source, seed=0)
        ulong hash64 = XxHash32.Hash64(source, 0);
        uint checksum32 = (uint)(hash64 & 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), checksum32);
        dst += 4;

        return dst;
    }

    /// <summary>
    /// Decompresses an RFC 8878 Zstandard frame into destination uncompressed buffer.
    /// </summary>
    public static int Decompress(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.IsEmpty) throw new InvalidDataException("Zstd frame is truncated: empty input.");
        if (source.Length < 4) throw new InvalidDataException("Zstd frame too short.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));

        // Skippable frames (0x184D2A50 - 0x184D2A5F)
        if (magic >= ZstdConstants.SkippableMagicMin && magic <= ZstdConstants.SkippableMagicMax)
        {
            if (source.Length < 8) throw new InvalidDataException("Truncated skippable frame.");
            uint skipSize = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(4, 4));
            if (8 + skipSize > (uint)source.Length) throw new InvalidDataException("Skippable frame exceeds bounds.");
            return 0;
        }

        if (magic != MagicNumber) throw new InvalidDataException($"Invalid Zstd magic number: 0x{magic:X8}");

        if (source.Length < 5) throw new InvalidDataException("Truncated Zstd frame header.");

        int src = 4;
        byte fhd = source[src++];

        // Verify reserved bits
        if ((fhd & 0x18) != 0)
        {
            throw new InvalidDataException("Corrupted Zstd frame header descriptor: reserved bits non-zero.");
        }

        int fcsFlag = (fhd >> 6) & 0x03;
        bool singleSegment = (fhd & 0x20) != 0;
        bool contentChecksum = (fhd & 0x04) != 0;
        int dictIdFlag = fhd & 0x03;

        ulong windowSize = 0;
        if (!singleSegment)
        {
            if (src >= source.Length) throw new InvalidDataException("Truncated window descriptor.");
            byte wd = source[src++];
            int exp = (wd >> 3) & 0x1F;
            int mant = wd & 0x07;
            ulong windowBase = 1UL << (10 + exp);
            windowSize = windowBase + ((windowBase / 8UL) * (ulong)mant);
        }

        if (dictIdFlag > 0)
        {
            int dictBytes = dictIdFlag == 1 ? 1 : (dictIdFlag == 2 ? 2 : 4);
            if (src + dictBytes > source.Length) throw new InvalidDataException("Truncated dict ID.");
            src += dictBytes;
        }

        ulong fcs = 0;
        int fcsBytes = 0;
        if (singleSegment)
        {
            fcsBytes = fcsFlag == 0 ? 1 : (fcsFlag == 1 ? 2 : (fcsFlag == 2 ? 4 : 8));
        }
        else if (fcsFlag > 0)
        {
            fcsBytes = fcsFlag == 1 ? 2 : (fcsFlag == 2 ? 4 : 8);
        }

        if (fcsBytes > 0)
        {
            if (src + fcsBytes > source.Length) throw new InvalidDataException("Truncated frame content size.");
            if (fcsBytes == 1) fcs = source[src];
            else if (fcsBytes == 2) fcs = (ulong)(BinaryPrimitives.ReadUInt16LittleEndian(source.Slice(src, 2)) + 256);
            else if (fcsBytes == 4) fcs = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(src, 4));
            else fcs = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(src, 8));
            src += fcsBytes;
        }

        int dst = 0;
        var seqExec = new SequenceExecutor();

        // Decompress blocks
        bool isLastBlock = false;
        while (!isLastBlock)
        {
            if (src + 3 > source.Length)
            {
                if (contentChecksum && src + 4 <= source.Length) break;
                throw new InvalidDataException("Truncated block header.");
            }

            uint b0 = source[src++];
            uint b1 = source[src++];
            uint b2 = source[src++];
            uint header24 = b0 | (b1 << 8) | (b2 << 16);

            isLastBlock = (header24 & 0x01) != 0;
            int blockType = (int)((header24 >> 1) & 0x03);
            int blockSize = (int)(header24 >> 3);

            if (blockType == ZstdConstants.BlockTypeReserved)
            {
                throw new InvalidDataException("Encountered reserved block type (3).");
            }

            if (blockSize > ZstdConstants.MaxBlockSize)
            {
                throw new InvalidDataException($"Block size ({blockSize}) exceeds maximum allowed window limit (128 KB).");
            }

            int payloadSize = blockType == ZstdConstants.BlockTypeRle ? 1 : blockSize;
            if (src + payloadSize > source.Length)
            {
                throw new InvalidDataException("Block payload truncated.");
            }

            ReadOnlySpan<byte> blockPayload = source.Slice(src, payloadSize);
            src += payloadSize;

            if (blockType == ZstdConstants.BlockTypeRaw)
            {
                if (dst + blockSize > destination.Length) throw new InvalidDataException("Destination buffer overflow.");
                blockPayload.CopyTo(destination.Slice(dst, blockSize));
                dst += blockSize;
            }
            else if (blockType == ZstdConstants.BlockTypeRle)
            {
                if (blockPayload.IsEmpty) throw new InvalidDataException("Truncated RLE block payload.");
                byte rleByte = blockPayload[0];
                if (dst + blockSize > destination.Length) throw new InvalidDataException("Destination buffer overflow.");
                destination.Slice(dst, blockSize).Fill(rleByte);
                dst += blockSize;
            }
            else if (blockType == ZstdConstants.BlockTypeCompressed)
            {
                DecodeCompressedBlock(blockPayload, destination, ref dst, ref seqExec);
            }
        }

        // Verify Content Checksum if present
        if (contentChecksum)
        {
            if (src + 4 > source.Length) throw new InvalidDataException("Truncated content checksum trailer.");
            uint expected = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(src, 4));
            src += 4;

            ulong hash64 = XxHash32.Hash64(destination.Slice(0, dst), 0);
            uint calculated = (uint)(hash64 & 0xFFFFFFFF);
            if (expected != calculated)
            {
                throw new InvalidDataException($"Zstd content checksum validation failed: expected 0x{expected:X8}, got 0x{calculated:X8}.");
            }
        }

        return dst;
    }

    private static void DecodeCompressedBlock(
        ReadOnlySpan<byte> block,
        Span<byte> destination,
        ref int dst,
        ref SequenceExecutor seqExec)
    {
        if (block.IsEmpty) return;

        // 1. Parse Literals Section Header
        byte litHeader = block[0];
        int litType = litHeader & 0x03;
        int sizeFormat = (litHeader >> 2) & 0x03;

        int regSize = 0;
        int compSize = 0;
        int litHeaderBytes = 0;
        bool is4Stream = false;

        if (litType == ZstdConstants.LiteralsTypeRaw || litType == ZstdConstants.LiteralsTypeRle)
        {
            if (sizeFormat == 0 || sizeFormat == 2)
            {
                regSize = litHeader >> 3;
                litHeaderBytes = 1;
            }
            else if (sizeFormat == 1)
            {
                if (block.Length < 2) throw new InvalidDataException("Truncated literals header.");
                regSize = (litHeader >> 4) + (block[1] << 4);
                litHeaderBytes = 2;
            }
            else // sizeFormat == 3
            {
                if (block.Length < 3) throw new InvalidDataException("Truncated literals header.");
                regSize = (litHeader >> 4) + (block[1] << 4) + (block[2] << 12);
                litHeaderBytes = 3;
            }
        }
        else // Compressed or Treeless
        {
            is4Stream = sizeFormat > 0;
            if (sizeFormat == 0 || sizeFormat == 1)
            {
                if (block.Length < 3) throw new InvalidDataException("Truncated literals header.");
                uint v = (uint)(block[0] | (block[1] << 8) | (block[2] << 16));
                regSize = (int)((v >> 4) & 0x3FF);
                compSize = (int)((v >> 14) & 0x3FF);
                litHeaderBytes = 3;
            }
            else if (sizeFormat == 2)
            {
                if (block.Length < 4) throw new InvalidDataException("Truncated literals header.");
                uint v = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(0, 4));
                regSize = (int)((v >> 4) & 0x3FFF);
                compSize = (int)((v >> 18) & 0x3FFF);
                litHeaderBytes = 4;
            }
            else // sizeFormat == 3
            {
                if (block.Length < 5) throw new InvalidDataException("Truncated literals header.");
                ulong v = block[0] | ((ulong)block[1] << 8) | ((ulong)block[2] << 16) | ((ulong)block[3] << 24) | ((ulong)block[4] << 32);
                regSize = (int)((v >> 4) & 0x3FFFF);
                compSize = (int)((v >> 22) & 0x3FFFF);
                litHeaderBytes = 5;
            }
        }

        using var slab = UnmanagedSlabPool.Shared.Rent(Math.Max(regSize, 1024));
        Span<byte> literals = slab.Span.Slice(0, regSize);

        int litDataOffset = litHeaderBytes;

        if (litType == ZstdConstants.LiteralsTypeRaw)
        {
            block.Slice(litDataOffset, regSize).CopyTo(literals);
            litDataOffset += regSize;
        }
        else if (litType == ZstdConstants.LiteralsTypeRle)
        {
            byte b = block[litDataOffset++];
            literals.Fill(b);
        }
        else if (litType == ZstdConstants.LiteralsTypeCompressed)
        {
            Span<HuffmanTableEntry> huffTable = stackalloc HuffmanTableEntry[2048];
            int treeBytes = HuffmanDecoder.BuildTable(block.Slice(litDataOffset), huffTable, out int maxBits);
            litDataOffset += treeBytes;

            int streamsSize = compSize - treeBytes;
            ReadOnlySpan<byte> streamsPayload = block.Slice(litDataOffset, streamsSize);
            litDataOffset += streamsSize;

            if (is4Stream)
            {
                HuffmanDecoder.Decode4Streams(streamsPayload, huffTable, maxBits, literals);
            }
            else
            {
                HuffmanDecoder.Decode1Stream(streamsPayload, huffTable, maxBits, literals);
            }
        }
        else if (litType == ZstdConstants.LiteralsTypeTreeless)
        {
            throw new InvalidDataException("Treeless literals block cannot appear as first block without dictionary.");
        }

        // 2. Parse Sequences Section
        ReadOnlySpan<byte> seqSection = block.Slice(litDataOffset);
        if (seqSection.IsEmpty)
        {
            // All literals, no sequences
            literals.CopyTo(destination.Slice(dst));
            dst += literals.Length;
            return;
        }

        int seqOffset = 0;
        byte seqB0 = seqSection[seqOffset++];
        int numSequences;

        if (seqB0 == 0)
        {
            numSequences = 0;
        }
        else if (seqB0 < 128)
        {
            numSequences = seqB0;
        }
        else if (seqB0 < 255)
        {
            if (seqOffset >= seqSection.Length) throw new InvalidDataException("Truncated sequences header.");
            numSequences = ((seqB0 - 128) << 8) + seqSection[seqOffset++];
        }
        else
        {
            if (seqOffset + 2 > seqSection.Length) throw new InvalidDataException("Truncated sequences header.");
            numSequences = seqSection[seqOffset++] + (seqSection[seqOffset++] << 8) + 0x7F00;
        }

        if (numSequences == 0)
        {
            literals.CopyTo(destination.Slice(dst));
            dst += literals.Length;
            return;
        }

        // Symbol Compression Modes
        if (seqOffset >= seqSection.Length) throw new InvalidDataException("Truncated symbol compression modes.");
        byte modes = seqSection[seqOffset++];
        if ((modes & 0x03) != 0) throw new InvalidDataException("Reserved bits in Symbol_Compression_Modes must be zero.");

        int llMode = (modes >> 6) & 0x03;
        int ofMode = (modes >> 4) & 0x03;
        int mlMode = (modes >> 2) & 0x03;

        Span<FseTableEntry> tableLL = stackalloc FseTableEntry[64];
        Span<FseTableEntry> tableOF = stackalloc FseTableEntry[32];
        Span<FseTableEntry> tableML = stackalloc FseTableEntry[64];

        int llAccuracy = 6;
        int ofAccuracy = 5;
        int mlAccuracy = 6;

        // Setup LL Table
        if (llMode == 0)
        {
            FseDecoder.PredefinedLiteralLengthsTable.CopyTo(tableLL);
        }
        else if (llMode == 1)
        {
            FseDecoder.BuildRleTable(seqSection[seqOffset++], tableLL);
            llAccuracy = 0;
        }
        else if (llMode == 2)
        {
            int hBytes = FseDecoder.ReadTable(seqSection.Slice(seqOffset), 35, 9, tableLL, out llAccuracy);
            seqOffset += hBytes;
        }

        // Setup OF Table
        if (ofMode == 0)
        {
            FseDecoder.PredefinedOffsetsTable.CopyTo(tableOF);
        }
        else if (ofMode == 1)
        {
            FseDecoder.BuildRleTable(seqSection[seqOffset++], tableOF);
            ofAccuracy = 0;
        }
        else if (ofMode == 2)
        {
            int hBytes = FseDecoder.ReadTable(seqSection.Slice(seqOffset), 31, 8, tableOF, out ofAccuracy);
            seqOffset += hBytes;
        }

        // Setup ML Table
        if (mlMode == 0)
        {
            FseDecoder.PredefinedMatchLengthsTable.CopyTo(tableML);
        }
        else if (mlMode == 1)
        {
            FseDecoder.BuildRleTable(seqSection[seqOffset++], tableML);
            mlAccuracy = 0;
        }
        else if (mlMode == 2)
        {
            int hBytes = FseDecoder.ReadTable(seqSection.Slice(seqOffset), 52, 9, tableML, out mlAccuracy);
            seqOffset += hBytes;
        }

        // 3. Decode Backward Bitstream for Sequences
        var bitReader = new ZstdBitReader(seqSection.Slice(seqOffset));

        uint stateLL = bitReader.ReadBits(llAccuracy);
        uint stateOF = bitReader.ReadBits(ofAccuracy);
        uint stateML = bitReader.ReadBits(mlAccuracy);

        int litIdx = 0;

        for (int i = 0; i < numSequences; i++)
        {
            byte ofCode = tableOF[(int)stateOF].Symbol;
            byte mlCode = tableML[(int)stateML].Symbol;
            byte llCode = tableLL[(int)stateLL].Symbol;

            // Read Extra Bits in strict RFC 8878 order: Offset -> Match Length -> Literal Length
            int ofBits = ofCode;
            uint ofExtra = bitReader.ReadBits(ofBits);
            int offsetCode = (1 << ofCode) + (int)ofExtra;

            int mlBits = ZstdConstants.Table17_Bits[mlCode];
            uint mlExtra = bitReader.ReadBits(mlBits);
            int matchLength = ZstdConstants.Table17_Baseline[mlCode] + (int)mlExtra;

            int llBits = ZstdConstants.Table16_Bits[llCode];
            uint llExtra = bitReader.ReadBits(llBits);
            int literalLength = ZstdConstants.Table16_Baseline[llCode] + (int)llExtra;

            int offset = seqExec.ResolveOffset(offsetCode, literalLength);

            // Update FSE states in strict order: LL -> ML -> OF
            if (i < numSequences - 1)
            {
                stateLL = tableLL[(int)stateLL].NewState + bitReader.ReadBits(tableLL[(int)stateLL].NumBits);
                stateML = tableML[(int)stateML].NewState + bitReader.ReadBits(tableML[(int)stateML].NumBits);
                stateOF = tableOF[(int)stateOF].NewState + bitReader.ReadBits(tableOF[(int)stateOF].NumBits);
            }

            seqExec.Execute(literals, ref litIdx, literalLength, matchLength, offset, destination, ref dst);
        }

        // 4. Copy remaining trailing literals
        if (litIdx < literals.Length)
        {
            int remLits = literals.Length - litIdx;
            literals.Slice(litIdx, remLits).CopyTo(destination.Slice(dst, remLits));
            dst += remLits;
        }
    }
}

/// <summary>
/// Stateful, zero-allocation streaming Zstandard compressor.
/// </summary>
public sealed class ZstdStreamCompressor : IStreamingCompressor
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
        return ZstdCodec.Compress(source, destination);
    }

    /// <inheritdoc />
    public int GetMaxCompressedChunkSize(int chunkLength)
    {
        return ZstdCodec.MaximumCompressedSize(chunkLength);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _isDisposed = true;
    }
}

/// <summary>
/// Stateful, zero-allocation streaming Zstandard decompressor.
/// </summary>
public sealed class ZstdStreamDecompressor : IStreamingDecompressor
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
        int written = ZstdCodec.Decompress(source, destination);
        bytesConsumed = source.Length;
        return written;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _isDisposed = true;
    }
}
