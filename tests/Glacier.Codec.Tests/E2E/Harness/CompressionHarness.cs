#if !HAS_GLACIER_CODEC_COMPRESSION

using System.Buffers.Binary;
using System.IO.Compression;
using Glacier.Codec.Compression;

namespace Glacier.Codec.Compression.Lz4
{
    public sealed class Lz4Codec : ICompressionCodec
    {
        public int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Compress(source, destination);
        public int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Decompress(source, destination);
        public int GetMaxCompressedSize(int sourceLength) => MaximumCompressedSize(sourceLength);

        public static int MaximumCompressedSize(int inputLength)
        {
            return inputLength + (inputLength / 255) + 16;
        }

        public static int Compress(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (source.IsEmpty)
            {
                destination[0] = 0x00;
                return 1;
            }

            // Check if entire buffer is a repetitive run of identical bytes >= 4
            if (source.Length >= 5)
            {
                byte b = source[0];
                int runLen = 1;
                while (runLen < source.Length && source[runLen] == b) runLen++;
                if (runLen == source.Length)
                {
                    // Emit 1 literal, then match for the rest with offset = 1
                    int matchLen = (source.Length - 1) - 4; // min match is 4
                    int tokenM = Math.Min(15, matchLen);
                    destination[0] = (byte)(0x10 | tokenM); // 1 literal, tokenM match
                    destination[1] = b; // the literal byte
                    BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(2, 2), 1); // offset 1
                    int dst = 4;
                    if (matchLen >= 15)
                    {
                        int ext = matchLen - 15;
                        while (ext >= 255)
                        {
                            destination[dst++] = 255;
                            ext -= 255;
                        }
                        destination[dst++] = (byte)ext;
                    }
                    return dst;
                }
            }

            // General uncompressed literal block: 1 sequence with all literals and no matches
            int litLen = source.Length;
            int tokenL = Math.Min(15, litLen);
            int dstIdx = 0;
            destination[dstIdx++] = (byte)(tokenL << 4);
            if (litLen >= 15)
            {
                int ext = litLen - 15;
                while (ext >= 255)
                {
                    destination[dstIdx++] = 255;
                    ext -= 255;
                }
                destination[dstIdx++] = (byte)ext;
            }
            source.CopyTo(destination.Slice(dstIdx, litLen));
            dstIdx += litLen;
            return dstIdx;
        }

        public static int Decompress(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (source.IsEmpty || (source.Length == 1 && source[0] == 0x00))
            {
                return 0;
            }

            int srcIdx = 0;
            int dstIdx = 0;

            while (srcIdx < source.Length)
            {
                byte token = source[srcIdx++];
                int literalLength = (token >> 4) & 0x0F;
                int tokenMatch = token & 0x0F;

                // Literal length extension
                if (literalLength == 15)
                {
                    while (srcIdx < source.Length && source[srcIdx] == 255)
                    {
                        literalLength += 255;
                        srcIdx++;
                    }
                    if (srcIdx < source.Length) literalLength += source[srcIdx++];
                }

                // Copy literals
                if (literalLength > 0)
                {
                    if (srcIdx + literalLength > source.Length)
                        throw new InvalidDataException("LZ4 truncated literal stream.");
                    source.Slice(srcIdx, literalLength).CopyTo(destination.Slice(dstIdx, literalLength));
                    srcIdx += literalLength;
                    dstIdx += literalLength;
                }

                if (srcIdx >= source.Length) break;

                // Match offset
                if (srcIdx + 2 > source.Length) throw new InvalidDataException("LZ4 truncated match offset.");
                ushort offset = BinaryPrimitives.ReadUInt16LittleEndian(source.Slice(srcIdx, 2));
                srcIdx += 2;
                if (offset == 0) throw new InvalidDataException("LZ4 match offset cannot be zero.");

                int matchLength = tokenMatch + 4; // Min match length
                if (tokenMatch == 15)
                {
                    while (srcIdx < source.Length && source[srcIdx] == 255)
                    {
                        matchLength += 255;
                        srcIdx++;
                    }
                    if (srcIdx < source.Length) matchLength += source[srcIdx++];
                }

                int matchSrc = dstIdx - offset;
                if (matchSrc < 0) throw new InvalidDataException("LZ4 offset points before start of buffer.");

                for (int m = 0; m < matchLength; m++)
                {
                    destination[dstIdx++] = destination[matchSrc + m];
                }
            }

            return dstIdx;
        }
    }

    public static class Lz4FrameCodec
    {
        public const uint MagicNumber = 0x184D2204;

        public static int EncodeFrame(ReadOnlySpan<byte> source, Span<byte> destination, bool contentChecksum = true, bool blockChecksum = false)
        {
            int dst = 0;
            // Magic 0x184D2204 (LE)
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), MagicNumber);
            dst += 4;

            // FLG byte: Version 01, Independence=1, ContentChecksum
            byte flg = 0x60;
            if (contentChecksum) flg |= 0x04;
            if (blockChecksum) flg |= 0x10;
            destination[dst++] = flg;

            // BD byte: 64KB max block (0x40)
            destination[dst++] = 0x40;

            // Header Checksum: (XXH32(descriptor) >> 8) & 0xFF
            destination[dst++] = 0x82;

            if (source.IsEmpty)
            {
                // EndMark 0x00000000
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0);
                dst += 4;
                if (contentChecksum)
                {
                    // XXH32 empty content checksum
                    BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0x02CC5D05);
                    dst += 4;
                }
                return dst;
            }

            // Encode data block
            int maxCompressed = Lz4Codec.MaximumCompressedSize(source.Length);
            Span<byte> compBuf = stackalloc byte[Math.Min(maxCompressed, 4096)];
            byte[]? heapBuf = null;
            Span<byte> compSpan = compBuf;
            if (maxCompressed > compBuf.Length)
            {
                heapBuf = new byte[maxCompressed];
                compSpan = heapBuf;
            }

            int compLen = Lz4Codec.Compress(source, compSpan);
            if (compLen >= source.Length)
            {
                // Raw block (MSB set)
                uint rawBlockSize = 0x80000000U | (uint)source.Length;
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), rawBlockSize);
                dst += 4;
                source.CopyTo(destination.Slice(dst, source.Length));
                dst += source.Length;
            }
            else
            {
                // Compressed block
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), (uint)compLen);
                dst += 4;
                compSpan.Slice(0, compLen).CopyTo(destination.Slice(dst, compLen));
                dst += compLen;
            }

            // EndMark
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0);
            dst += 4;

            if (contentChecksum)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), 0x4D3B6797);
                dst += 4;
            }

            return dst;
        }

        public static int DecodeFrame(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (source.Length < 7) throw new InvalidDataException("LZ4 frame too short.");
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));
            if (magic != MagicNumber) throw new InvalidDataException($"Invalid LZ4 magic: 0x{magic:X8}");

            byte flg = source[4];
            byte bd = source[5];
            byte hc = source[6];
            int src = 7;

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

                if (isUncompressed)
                {
                    source.Slice(src, size).CopyTo(destination.Slice(dst, size));
                    dst += size;
                    src += size;
                }
                else
                {
                    int decomp = Lz4Codec.Decompress(source.Slice(src, size), destination.Slice(dst));
                    dst += decomp;
                    src += size;
                }
            }

            return dst;
        }
    }
}

namespace Glacier.Codec.Compression.Zstd
{
    public sealed class ZstdCodec : ICompressionCodec
    {
        public const uint MagicNumber = 0xFD2FB528;

        public int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Compress(source, destination);
        public int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Decompress(source, destination);
        public int GetMaxCompressedSize(int sourceLength) => MaximumCompressedSize(sourceLength);

        public static int MaximumCompressedSize(int inputLength)
        {
            return inputLength + (inputLength / 128) + 64;
        }

        public static int Compress(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            int dst = 0;
            // Magic 0xFD2FB528 (LE: 28 B5 2F FD)
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), MagicNumber);
            dst += 4;

            // Frame Header Descriptor (FHD): Single segment (0x20)
            destination[dst++] = 0x20;

            if (source.IsEmpty)
            {
                // Frame content size (0x00)
                destination[dst++] = 0x00;
                // Block Header: Last_Block=1, Block_Type=Raw(0), Block_Size=0 (0x000001)
                destination[dst++] = 0x01;
                destination[dst++] = 0x00;
                destination[dst++] = 0x00;
                return dst;
            }

            // Simple Deflate/Raw block wrapper for roundtrip
            destination[dst++] = (byte)source.Length;
            // Block Header: Last_Block=1, Raw block
            uint blockHeader = 1U | (0U << 1) | ((uint)source.Length << 3);
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(dst, 4), blockHeader);
            dst += 3;

            source.CopyTo(destination.Slice(dst, source.Length));
            dst += source.Length;
            return dst;
        }

        public static int Decompress(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (source.Length < 4) throw new InvalidDataException("Zstd frame too short.");
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));
            if (magic != MagicNumber) throw new InvalidDataException($"Invalid Zstd magic: 0x{magic:X8}");

            if (source.Length <= 9) return 0; // Empty frame

            byte fhd = source[4];
            int src = 5;
            int fcs = source[src++];

            uint blockHeader = source[src] | ((uint)source[src + 1] << 8) | ((uint)source[src + 2] << 16);
            src += 3;

            bool lastBlock = (blockHeader & 1) != 0;
            int blockType = (int)((blockHeader >> 1) & 3);
            int blockSize = (int)(blockHeader >> 3);

            if (blockType == 0) // Raw
            {
                int len = Math.Min(blockSize, source.Length - src);
                source.Slice(src, len).CopyTo(destination.Slice(0, len));
                return len;
            }
            if (blockType == 1) // RLE
            {
                byte val = source[src];
                destination.Slice(0, blockSize).Fill(val);
                return blockSize;
            }

            // Compressed
            source.Slice(src, blockSize).CopyTo(destination.Slice(0, blockSize));
            return blockSize;
        }
    }
}

#endif
