namespace Glacier.Codec.Compression.Zstd;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Huffman direct lookup table entry.
/// </summary>
public struct HuffmanTableEntry
{
    public byte Symbol;
    public byte NumBits;
}

/// <summary>
/// Canonical Huffman decoder for RFC 8878 Zstandard literal sections.
/// Supports direct and FSE-compressed weights, canonical codebook generation,
/// and backward 1-stream and 4-stream interleaved decoding.
/// </summary>
public static class HuffmanDecoder
{
    private struct SymbolInfo
    {
        public byte Symbol;
        public byte Weight;
        public byte NumBits;
        public ushort Code;
    }

    /// <summary>
    /// Builds an 11-bit maximum direct lookup Huffman table from literal section description bytes.
    /// </summary>
    public static int BuildTable(
        ReadOnlySpan<byte> source,
        Span<HuffmanTableEntry> table,
        out int maxBits)
    {
        if (source.IsEmpty) throw new InvalidDataException("Empty Huffman tree description.");

        Span<byte> weights = stackalloc byte[256];
        int numSymbols = 0;
        int bytesConsumed = 0;

        byte headerByte = source[0];
        if (headerByte >= 128)
        {
            // Direct Representation
            numSymbols = headerByte - 127;
            int weightBytes = (numSymbols + 1) / 2;
            bytesConsumed = 1 + weightBytes;

            if (bytesConsumed > source.Length) throw new InvalidDataException("Truncated direct Huffman weights description.");

            int sym = 0;
            for (int i = 0; i < weightBytes && sym < numSymbols; i++)
            {
                byte b = source[1 + i];
                weights[sym++] = (byte)(b >> 4);
                if (sym < numSymbols)
                {
                    weights[sym++] = (byte)(b & 0x0F);
                }
            }
        }
        else
        {
            // FSE-Compressed Representation
            int fseStreamLength = headerByte;
            bytesConsumed = 1 + fseStreamLength;
            if (bytesConsumed > source.Length) throw new InvalidDataException("Truncated FSE Huffman weights description.");

            ReadOnlySpan<byte> fseBytes = source.Slice(1, fseStreamLength);
            Span<FseTableEntry> fseTable = stackalloc FseTableEntry[64];
            int fseHeaderBytes = FseDecoder.ReadTable(fseBytes, maxSymbol: 255, maxAccuracyLog: 6, fseTable, out int accuracyLog);

            // Decode weights using 2 interleaved states from backward bitstream
            var bitReader = new ZstdBitReader(fseBytes.Slice(fseHeaderBytes));
            uint state1 = bitReader.ReadBits(accuracyLog);
            uint state2 = bitReader.ReadBits(accuracyLog);

            while (!bitReader.IsFinished && numSymbols < 255)
            {
                weights[numSymbols++] = fseTable[(int)state1].Symbol;
                if (numSymbols >= 255) break;
                state1 = fseTable[(int)state1].NewState + bitReader.ReadBits(fseTable[(int)state1].NumBits);

                weights[numSymbols++] = fseTable[(int)state2].Symbol;
                if (numSymbols >= 255) break;
                state2 = fseTable[(int)state2].NewState + bitReader.ReadBits(fseTable[(int)state2].NumBits);
            }
        }

        // Deduce omitted final symbol weight per RFC 8878 Section 4.2.1.3
        int weightSum = 0;
        for (int i = 0; i < numSymbols; i++)
        {
            byte w = weights[i];
            if (w > 0)
            {
                weightSum += 1 << (w - 1);
            }
        }

        if (weightSum == 0) throw new InvalidDataException("Corrupted Huffman weights: total weight sum is 0.");

        maxBits = BitOperations.Log2((uint)(weightSum - 1)) + 1;
        if (maxBits > 11) throw new InvalidDataException($"Corrupted Huffman weights: tree depth ({maxBits}) exceeds 11 bits.");

        int rest = (1 << maxBits) - weightSum;
        if (rest > 0)
        {
            if (!BitOperations.IsPow2(rest)) throw new InvalidDataException("Corrupted Huffman weights: remainder is not a power of 2.");
            weights[numSymbols++] = (byte)(BitOperations.Log2((uint)rest) + 1);
        }

        // Build canonical prefix codes
        Span<SymbolInfo> symbols = stackalloc SymbolInfo[numSymbols];
        int activeCount = 0;
        for (int i = 0; i < numSymbols; i++)
        {
            byte w = weights[i];
            if (w > 0)
            {
                symbols[activeCount++] = new SymbolInfo
                {
                    Symbol = (byte)i,
                    Weight = w,
                    NumBits = (byte)(maxBits + 1 - w)
                };
            }
        }

        var activeSlice = symbols.Slice(0, activeCount);
        // Sort primarily by weight ascending (largest NumBits first), secondarily by symbol value ascending
        activeSlice.Sort((a, b) =>
        {
            if (a.Weight != b.Weight) return a.Weight.CompareTo(b.Weight);
            return a.Symbol.CompareTo(b.Symbol);
        });

        // Assign canonical codes
        int code = 0;
        int currentBits = activeSlice[0].NumBits;
        for (int i = 0; i < activeSlice.Length; i++)
        {
            int bits = activeSlice[i].NumBits;
            if (currentBits > bits)
            {
                code >>= (currentBits - bits);
                currentBits = bits;
            }
            activeSlice[i].Code = (ushort)code;
            code++;
        }

        // Populate direct lookup table (size 2^maxBits)
        int tableSize = 1 << maxBits;
        if (table.Length < tableSize) throw new ArgumentException("Table span too small.", nameof(table));

        for (int i = 0; i < activeSlice.Length; i++)
        {
            var sym = activeSlice[i];
            int shift = maxBits - sym.NumBits;
            int baseIdx = sym.Code << shift;
            int count = 1 << shift;

            for (int j = 0; j < count; j++)
            {
                table[baseIdx + j] = new HuffmanTableEntry
                {
                    Symbol = sym.Symbol,
                    NumBits = sym.NumBits
                };
            }
        }

        return bytesConsumed;
    }

    /// <summary>
    /// Decodes a single backward Huffman bitstream into the destination buffer.
    /// </summary>
    public static void Decode1Stream(
        ReadOnlySpan<byte> compressedStream,
        ReadOnlySpan<HuffmanTableEntry> table,
        int maxBits,
        Span<byte> destination)
    {
        var bitReader = new ZstdBitReader(compressedStream);
        for (int i = 0; i < destination.Length; i++)
        {
            uint bits = bitReader.PeekBits(maxBits);
            var entry = table[(int)bits];
            destination[i] = entry.Symbol;
            bitReader.ConsumeBits(entry.NumBits);
        }
    }

    /// <summary>
    /// Decodes 4 interleaved backward Huffman bitstreams into the destination buffer.
    /// </summary>
    public static void Decode4Streams(
        ReadOnlySpan<byte> compressedStreamsWithJumpTable,
        ReadOnlySpan<HuffmanTableEntry> table,
        int maxBits,
        Span<byte> destination)
    {
        if (compressedStreamsWithJumpTable.Length < 6)
        {
            throw new InvalidDataException("4-stream literals jump table truncated.");
        }

        ushort s1Size = BinaryPrimitives.ReadUInt16LittleEndian(compressedStreamsWithJumpTable.Slice(0, 2));
        ushort s2Size = BinaryPrimitives.ReadUInt16LittleEndian(compressedStreamsWithJumpTable.Slice(2, 2));
        ushort s3Size = BinaryPrimitives.ReadUInt16LittleEndian(compressedStreamsWithJumpTable.Slice(4, 2));

        int streamsPayload = compressedStreamsWithJumpTable.Length - 6;
        int s4Size = streamsPayload - s1Size - s2Size - s3Size;
        if (s4Size < 0) throw new InvalidDataException("4-stream literals jump table exceeds payload size.");

        int pos = 6;
        ReadOnlySpan<byte> stream1 = compressedStreamsWithJumpTable.Slice(pos, s1Size); pos += s1Size;
        ReadOnlySpan<byte> stream2 = compressedStreamsWithJumpTable.Slice(pos, s2Size); pos += s2Size;
        ReadOnlySpan<byte> stream3 = compressedStreamsWithJumpTable.Slice(pos, s3Size); pos += s3Size;
        ReadOnlySpan<byte> stream4 = compressedStreamsWithJumpTable.Slice(pos, s4Size);

        int totalLits = destination.Length;
        int seg = (totalLits + 3) / 4;
        int reg1 = seg;
        int reg2 = seg;
        int reg3 = seg;
        int reg4 = totalLits - (3 * seg);

        int dstOffset = 0;
        Decode1Stream(stream1, table, maxBits, destination.Slice(dstOffset, reg1)); dstOffset += reg1;
        Decode1Stream(stream2, table, maxBits, destination.Slice(dstOffset, reg2)); dstOffset += reg2;
        Decode1Stream(stream3, table, maxBits, destination.Slice(dstOffset, reg3)); dstOffset += reg3;
        Decode1Stream(stream4, table, maxBits, destination.Slice(dstOffset, reg4));
    }
}
