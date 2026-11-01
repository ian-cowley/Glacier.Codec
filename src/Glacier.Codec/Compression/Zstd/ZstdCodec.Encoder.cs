namespace Glacier.Codec.Compression.Zstd;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Glacier.Codec.Hashing.XxHash32;
using Glacier.Codec.Memory;

public sealed partial class ZstdCodec
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ZstdSeq
    {
        public int LiteralLength;
        public int OffsetCode;
        public int MatchLength;
    }

    /// <summary>
    /// Compresses source bytes into an RFC 8878 compliant Zstandard frame using LZ77 + Predefined FSE
    /// compressed blocks (Type = 2), RLE blocks (Type = 1), and incompressible raw block fallback (Type = 0),
    /// with zero steady-state GC heap allocations.
    /// </summary>
    public static int Compress(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.IsEmpty)
        {
            if (destination.Length < 9)
            {
                throw new ArgumentException("Destination buffer too small for empty Zstandard frame.", nameof(destination));
            }

            int emptyDst = 0;
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(emptyDst, 4), MagicNumber);
            emptyDst += 4;
            destination[emptyDst++] = 0x20; // Single_Segment=1, Checksum=0, FCS_Flag=0
            destination[emptyDst++] = 0x00; // FCS = 0
            destination[emptyDst++] = 0x01; // Block Header: Last=1, Raw=0, Size=0
            destination[emptyDst++] = 0x00;
            destination[emptyDst++] = 0x00;
            return emptyDst;
        }

        int headerSize = source.Length < 256 ? 6 : 9;
        if (destination.Length < headerSize + 4)
        {
            throw new ArgumentException("Destination buffer too small for Zstandard frame header and checksum.", nameof(destination));
        }

        int dst = 0;

        // 1. Magic Number (0xFD2FB528 LE: 28 B5 2F FD)
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), MagicNumber);
        dst += 4;

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

        // Rent reusable zero-allocation unmanaged scratch slab across all blocks in the frame
        int maxChunk = Math.Min(source.Length, ZstdConstants.MaxBlockSize);
        int maxSequences = (maxChunk / 4) + 1;
        const int hashEntries = 4096;
        int hashBytes = hashEntries * sizeof(int);
        int seqBytes = maxSequences * Unsafe.SizeOf<ZstdSeq>();
        int totalScratchBytes = hashBytes + maxChunk + seqBytes + maxChunk + 64;
        using var scratchSlab = UnmanagedSlabPool.Shared.Rent(totalScratchBytes);

        // Chunk input into RFC 8878 compliant blocks (<= 128 KB each)
        int srcPos = 0;
        while (srcPos < source.Length)
        {
            int chunkSize = Math.Min(source.Length - srcPos, ZstdConstants.MaxBlockSize);
            bool isLast = (srcPos + chunkSize >= source.Length);
            ReadOnlySpan<byte> chunk = source.Slice(srcPos, chunkSize);

            // Check if chunk qualifies for RLE block encoding
            bool isChunkRle = false;
            if (chunk.Length >= 4)
            {
                byte first = chunk[0];
                int run = 1;
                while (run < chunk.Length && chunk[run] == first) run++;
                if (run == chunk.Length) isChunkRle = true;
            }

            if (isChunkRle)
            {
                // 3-byte block header + 1 RLE byte + 4-byte trailing checksum reserve (if last)
                int required = 4 + (isLast ? 4 : 0);
                if (destination.Length - dst < required)
                {
                    throw new ArgumentException("Destination buffer too small for Zstandard RLE block.", nameof(destination));
                }

                uint blockHeader = (isLast ? 1U : 0U) | ((uint)ZstdConstants.BlockTypeRle << 1) | ((uint)chunkSize << 3);
                destination[dst++] = (byte)(blockHeader & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 8) & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 16) & 0xFF);
                destination[dst++] = chunk[0];
            }
            else if (chunkSize >= 16 && TryEncodeCompressedBlock(chunk, scratchSlab, hashEntries, maxSequences, out Span<byte> compBlock))
            {
                int compLen = compBlock.Length;
                int required = 3 + compLen + (isLast ? 4 : 0);
                if (destination.Length - dst < required)
                {
                    throw new ArgumentException("Destination buffer too small for Zstandard compressed block.", nameof(destination));
                }

                uint blockHeader = (isLast ? 1U : 0U) | ((uint)ZstdConstants.BlockTypeCompressed << 1) | ((uint)compLen << 3);
                destination[dst++] = (byte)(blockHeader & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 8) & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 16) & 0xFF);

                compBlock.CopyTo(destination.Slice(dst, compLen));
                dst += compLen;
            }
            else
            {
                int required = 3 + chunkSize + (isLast ? 4 : 0);
                if (destination.Length - dst < required)
                {
                    throw new ArgumentException("Destination buffer too small for Zstandard raw block.", nameof(destination));
                }

                uint blockHeader = (isLast ? 1U : 0U) | ((uint)ZstdConstants.BlockTypeRaw << 1) | ((uint)chunkSize << 3);
                destination[dst++] = (byte)(blockHeader & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 8) & 0xFF);
                destination[dst++] = (byte)((blockHeader >> 16) & 0xFF);

                chunk.CopyTo(destination.Slice(dst, chunkSize));
                dst += chunkSize;
            }

            srcPos += chunkSize;
        }

        if (destination.Length - dst < 4)
        {
            throw new ArgumentException("Destination buffer too small for Zstandard content checksum.", nameof(destination));
        }

        // Content Checksum: lower 32-bits of XXH64(source, seed=0)
        ulong hash64 = XxHash32.Hash64(source, 0);
        uint checksum32 = (uint)(hash64 & 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), checksum32);
        dst += 4;

        return dst;
    }

    private static unsafe bool TryEncodeCompressedBlock(
        ReadOnlySpan<byte> chunk,
        SlabLease scratchSlab,
        int hashEntries,
        int maxSequences,
        out Span<byte> encodedBlock)
    {
        encodedBlock = Span<byte>.Empty;
        int chunkLen = chunk.Length;

        byte* basePtr = (byte*)scratchSlab.Pointer;
        int* hashTable = (int*)basePtr;
        byte* litBuf = basePtr + (hashEntries * sizeof(int));
        ZstdSeq* seqBuf = (ZstdSeq*)(litBuf + chunkLen);
        byte* outBuf = (byte*)(seqBuf + maxSequences);

        new Span<int>(hashTable, hashEntries).Fill(-1);

        int litCount = 0;
        int seqCount = 0;

        fixed (byte* pChunk = chunk)
        {
            int ip = 0;
            int anchor = 0;
            int mfLimit = chunkLen - 8;
            int matchLimit = chunkLen - 4;

            if (mfLimit > 0)
            {
                hashTable[Hash4(pChunk)] = 0;
                ip = 1;
            }

            while (ip < mfLimit)
            {
                uint h = Hash4(pChunk + ip);
                int candidate = hashTable[h];
                hashTable[h] = ip;

                if (candidate >= 0 &&
                    BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(pChunk + ip, 4)) ==
                    BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(pChunk + candidate, 4)))
                {
                    int litLen = ip - anchor;
                    if (litLen > 0)
                    {
                        new ReadOnlySpan<byte>(pChunk + anchor, litLen).CopyTo(new Span<byte>(litBuf + litCount, litLen));
                        litCount += litLen;
                    }

                    int matchLen = 4;
                    while (ip + matchLen < matchLimit && pChunk[ip + matchLen] == pChunk[candidate + matchLen])
                    {
                        matchLen++;
                    }

                    int offset = ip - candidate;
                    seqBuf[seqCount++] = new ZstdSeq
                    {
                        LiteralLength = litLen,
                        OffsetCode = offset + 3,
                        MatchLength = matchLen
                    };

                    ip += matchLen;
                    anchor = ip;

                    if (ip < mfLimit)
                    {
                        hashTable[Hash4(pChunk + ip - 2)] = ip - 2;
                    }

                    if (seqCount >= maxSequences || seqCount >= 0xFFFF)
                    {
                        break;
                    }
                }
                else
                {
                    ip++;
                }
            }

            if (seqCount == 0)
            {
                return false;
            }

            int trailingLits = chunkLen - anchor;
            if (trailingLits > 0)
            {
                new ReadOnlySpan<byte>(pChunk + anchor, trailingLits).CopyTo(new Span<byte>(litBuf + litCount, trailingLits));
                litCount += trailingLits;
            }
        }

        // Encode block into outBuf (must strictly beat chunkLen to be emitted as Compressed_Block)
        Span<byte> outSpan = new Span<byte>(outBuf, chunkLen);
        int pos = 0;

        // 1. Raw_Literals_Block header (RFC 8878 Section 3.1.1.3.1.1)
        int litHeaderBytes = litCount < 32 ? 1 : (litCount < 4096 ? 2 : 3);
        if (pos + litHeaderBytes + litCount + 6 >= chunkLen)
        {
            return false;
        }

        if (litHeaderBytes == 1)
        {
            outSpan[pos++] = (byte)((litCount << 3) | ZstdConstants.LiteralsTypeRaw);
        }
        else if (litHeaderBytes == 2)
        {
            uint lh = (uint)((litCount << 4) | (1 << 2) | ZstdConstants.LiteralsTypeRaw);
            outSpan[pos++] = (byte)(lh & 0xFF);
            outSpan[pos++] = (byte)((lh >> 8) & 0xFF);
        }
        else
        {
            uint lh = (uint)((litCount << 4) | (3 << 2) | ZstdConstants.LiteralsTypeRaw);
            outSpan[pos++] = (byte)(lh & 0xFF);
            outSpan[pos++] = (byte)((lh >> 8) & 0xFF);
            outSpan[pos++] = (byte)((lh >> 16) & 0xFF);
        }

        if (litCount > 0)
        {
            new ReadOnlySpan<byte>(litBuf, litCount).CopyTo(outSpan.Slice(pos, litCount));
            pos += litCount;
        }

        // 2. Sequences Section Header (RFC 8878 Section 3.1.1.3.2.1)
        if (seqCount < 128)
        {
            outSpan[pos++] = (byte)seqCount;
        }
        else if (seqCount < 0x7F00)
        {
            outSpan[pos++] = (byte)((seqCount >> 8) + 128);
            outSpan[pos++] = (byte)(seqCount & 0xFF);
        }
        else
        {
            outSpan[pos++] = 255;
            int adj = seqCount - 0x7F00;
            outSpan[pos++] = (byte)(adj & 0xFF);
            outSpan[pos++] = (byte)((adj >> 8) & 0xFF);
        }

        // Symbol_Compression_Modes = 0x00 (Predefined_Mode for LL, OF, ML)
        outSpan[pos++] = 0x00;

        // 3. Encode Sequences Backward Bitstream
        Span<byte> bitDest = outSpan.Slice(pos);
        var writer = new ZstdBitWriter(bitDest);

        uint[] llMap = FseDecoder.PredefinedLLEncodeMap;
        uint[] mlMap = FseDecoder.PredefinedMLEncodeMap;
        uint[] ofMap = FseDecoder.PredefinedOFEncodeMap;

        int lastIdx = seqCount - 1;
        GetLiteralLengthCode(seqBuf[lastIdx].LiteralLength, out byte llCodeLast, out int llBitsLast, out uint llExtraLast);
        GetMatchLengthCode(seqBuf[lastIdx].MatchLength, out byte mlCodeLast, out int mlBitsLast, out uint mlExtraLast);
        GetOffsetCode(seqBuf[lastIdx].OffsetCode, out byte ofCodeLast, out int ofBitsLast, out uint ofExtraLast);

        int stateLL = FseDecoder.PredefinedLLFirstState[llCodeLast];
        int stateML = FseDecoder.PredefinedMLFirstState[mlCodeLast];
        int stateOF = FseDecoder.PredefinedOFFirstState[ofCodeLast];

        try
        {
            // Push extra bits for final sequence in reverse of decoder read order (LL, ML, OF)
            writer.AddBits(llExtraLast, llBitsLast);
            writer.AddBits(mlExtraLast, mlBitsLast);
            writer.AddBits(ofExtraLast, ofBitsLast);

            for (int i = lastIdx - 1; i >= 0; i--)
            {
                GetLiteralLengthCode(seqBuf[i].LiteralLength, out byte llCode, out int llBits, out uint llExtra);
                GetMatchLengthCode(seqBuf[i].MatchLength, out byte mlCode, out int mlBits, out uint mlExtra);
                GetOffsetCode(seqBuf[i].OffsetCode, out byte ofCode, out int ofBits, out uint ofExtra);

                // Push FSE state transition bits in reverse of decoder update order (OF, ML, LL)
                uint pOF = ofMap[ofCode * 32 + stateOF];
                writer.AddBits(pOF >> 16, (int)((pOF >> 8) & 0xFF));
                stateOF = (int)(pOF & 0xFF);

                uint pML = mlMap[mlCode * 64 + stateML];
                writer.AddBits(pML >> 16, (int)((pML >> 8) & 0xFF));
                stateML = (int)(pML & 0xFF);

                uint pLL = llMap[llCode * 64 + stateLL];
                writer.AddBits(pLL >> 16, (int)((pLL >> 8) & 0xFF));
                stateLL = (int)(pLL & 0xFF);

                // Push extra bits in reverse of decoder read order (LL, ML, OF)
                writer.AddBits(llExtra, llBits);
                writer.AddBits(mlExtra, mlBits);
                writer.AddBits(ofExtra, ofBits);
            }

            // Push initial FSE states in reverse of decoder read order (ML=6b, OF=5b, LL=6b)
            writer.AddBits((uint)stateML, 6);
            writer.AddBits((uint)stateOF, 5);
            writer.AddBits((uint)stateLL, 6);

            int bitBytes = writer.Finish();
            int totalCompressedLen = pos + bitBytes;
            if (totalCompressedLen >= chunkLen)
            {
                return false;
            }

            encodedBlock = new Span<byte>(outBuf, totalCompressedLen);
            return true;
        }
        catch (ArgumentException)
        {
            // Compressed bitstream did not beat chunkLen -> fall back cleanly to Raw_Block
            return false;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe uint Hash4(byte* p)
    {
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(p, 4));
        return (v * 2654435761U) >> 20; // 12-bit hash (4096 entries)
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GetLiteralLengthCode(int litLen, out byte code, out int extraBits, out uint extraVal)
    {
        if (litLen <= 15)
        {
            code = (byte)litLen;
            extraBits = 0;
            extraVal = 0;
            return;
        }

        int c = litLen >= 64 ? Math.Min(35, BitOperations.Log2((uint)litLen) + 19) : 24;
        while (litLen < ZstdConstants.Table16_Baseline[c]) c--;
        code = (byte)c;
        extraBits = ZstdConstants.Table16_Bits[c];
        extraVal = (uint)(litLen - ZstdConstants.Table16_Baseline[c]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GetMatchLengthCode(int matchLen, out byte code, out int extraBits, out uint extraVal)
    {
        if (matchLen <= 34)
        {
            code = (byte)(matchLen - 3);
            extraBits = 0;
            extraVal = 0;
            return;
        }

        int c = 52;
        while (matchLen < ZstdConstants.Table17_Baseline[c]) c--;
        code = (byte)c;
        extraBits = ZstdConstants.Table17_Bits[c];
        extraVal = (uint)(matchLen - ZstdConstants.Table17_Baseline[c]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GetOffsetCode(int offsetCode, out byte code, out int extraBits, out uint extraVal)
    {
        int n = BitOperations.Log2((uint)offsetCode);
        code = (byte)n;
        extraBits = n;
        extraVal = (uint)(offsetCode - (1 << n));
    }
}
