namespace Glacier.Codec.Compression.Zstd;

using System;
using System.IO;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// Finite State Entropy (tANS) decoding table entry.
/// </summary>
public struct FseTableEntry
{
    public byte Symbol;
    public byte NumBits;
    public ushort NewState;
}

/// <summary>
/// Zero-allocation Finite State Entropy (FSE / tANS) decoder for RFC 8878 Zstandard sequence and weight streams.
/// </summary>
public static class FseDecoder
{
    public static readonly FseTableEntry[] PredefinedLiteralLengthsTable;
    public static readonly FseTableEntry[] PredefinedMatchLengthsTable;
    public static readonly FseTableEntry[] PredefinedOffsetsTable;

    // Precomputed O(1) inverse tANS transition maps for Predefined FSE encoding:
    // Indexed by [symbol * tableSize + targetState], packed as: prevState | (nbBits << 8) | (bitsToWrite << 16).
    internal static readonly uint[] PredefinedLLEncodeMap;
    internal static readonly uint[] PredefinedMLEncodeMap;
    internal static readonly uint[] PredefinedOFEncodeMap;
    internal static readonly byte[] PredefinedLLFirstState;
    internal static readonly byte[] PredefinedMLFirstState;
    internal static readonly byte[] PredefinedOFFirstState;

    static FseDecoder()
    {
        PredefinedLiteralLengthsTable = new FseTableEntry[64];
        BuildTable(
            ZstdConstants.PredefinedLiteralLengthsDistribution,
            ZstdConstants.PredefinedLiteralLengthsDistribution.Length - 1,
            6,
            PredefinedLiteralLengthsTable);
        BuildEncodeLookup(PredefinedLiteralLengthsTable, 36, 64, out PredefinedLLEncodeMap, out PredefinedLLFirstState);

        PredefinedMatchLengthsTable = new FseTableEntry[64];
        BuildTable(
            ZstdConstants.PredefinedMatchLengthsDistribution,
            ZstdConstants.PredefinedMatchLengthsDistribution.Length - 1,
            6,
            PredefinedMatchLengthsTable);
        BuildEncodeLookup(PredefinedMatchLengthsTable, 53, 64, out PredefinedMLEncodeMap, out PredefinedMLFirstState);

        PredefinedOffsetsTable = new FseTableEntry[32];
        BuildTable(
            ZstdConstants.PredefinedOffsetsDistribution,
            ZstdConstants.PredefinedOffsetsDistribution.Length - 1,
            5,
            PredefinedOffsetsTable);
        BuildEncodeLookup(PredefinedOffsetsTable, 29, 32, out PredefinedOFEncodeMap, out PredefinedOFFirstState);
    }

    private static void BuildEncodeLookup(
        FseTableEntry[] decTable,
        int symbolCount,
        int tableSize,
        out uint[] encodeMap,
        out byte[] firstState)
    {
        encodeMap = new uint[symbolCount * tableSize];
        firstState = new byte[symbolCount];
        Array.Fill(firstState, (byte)0xFF);

        for (int u = 0; u < tableSize; u++)
        {
            var entry = decTable[u];
            if (firstState[entry.Symbol] == 0xFF)
            {
                firstState[entry.Symbol] = (byte)u;
            }

            int span = 1 << entry.NumBits;
            int baseIdx = entry.Symbol * tableSize;
            for (int lowBits = 0; lowBits < span; lowBits++)
            {
                int targetState = entry.NewState + lowBits;
                encodeMap[baseIdx + targetState] = (uint)(u | (entry.NumBits << 8) | (lowBits << 16));
            }
        }
    }

    /// <summary>
    /// Builds a decoding table from normalized probability counters per RFC 8878 Section 4.1.2.
    /// </summary>
    public static void BuildTable(
        ReadOnlySpan<short> normalizedCounters,
        int maxSymbol,
        int accuracyLog,
        Span<FseTableEntry> table)
    {
        int tableSize = 1 << accuracyLog;
        if (table.Length < tableSize) throw new ArgumentException("Table span too small.", nameof(table));

        int highThreshold = tableSize - 1;
        Span<ushort> symbolNext = stackalloc ushort[maxSymbol + 1];

        // 1. Assign low-probability (-1) symbols
        for (int s = 0; s <= maxSymbol; s++)
        {
            if (normalizedCounters[s] == -1)
            {
                table[highThreshold--].Symbol = (byte)s;
                symbolNext[s] = 1;
            }
            else
            {
                symbolNext[s] = (ushort)normalizedCounters[s];
            }
        }

        // 2. Spread symbols across table using step
        int step = (tableSize >> 1) + (tableSize >> 3) + 3;
        int tableMask = tableSize - 1;
        int position = 0;

        for (int s = 0; s <= maxSymbol; s++)
        {
            int count = normalizedCounters[s];
            for (int i = 0; i < count; i++)
            {
                table[position].Symbol = (byte)s;
                position = (position + step) & tableMask;
                while (position > highThreshold)
                {
                    position = (position + step) & tableMask;
                }
            }
        }

        // 3. Compute NumBits and NewState
        for (int u = 0; u < tableSize; u++)
        {
            byte symbol = table[u].Symbol;
            ushort nextState = symbolNext[symbol]++;
            int numBits = accuracyLog - BitOperations.Log2((uint)nextState);
            table[u].NumBits = (byte)numBits;
            table[u].NewState = (ushort)((nextState << numBits) - tableSize);
        }
    }

    /// <summary>
    /// Builds an RLE FSE table where every state maps to the single specified symbol.
    /// </summary>
    public static void BuildRleTable(byte symbol, Span<FseTableEntry> table)
    {
        for (int i = 0; i < table.Length; i++)
        {
            table[i].Symbol = symbol;
            table[i].NumBits = 0;
            table[i].NewState = 0;
        }
    }

    /// <summary>
    /// Parses an FSE distribution header and builds the custom decoding table.
    /// </summary>
    public static int ReadTable(
        ReadOnlySpan<byte> source,
        int maxSymbol,
        int maxAccuracyLog,
        Span<FseTableEntry> table,
        out int accuracyLog)
    {
        var reader = new ZstdForwardBitReader(source);
        accuracyLog = (int)(reader.ReadBits(4) + 5);
        if (accuracyLog > maxAccuracyLog)
        {
            throw new InvalidDataException($"FSE AccuracyLog ({accuracyLog}) exceeds maximum ({maxAccuracyLog}).");
        }

        int tableSize = 1 << accuracyLog;
        int remaining = tableSize;
        Span<short> normalized = stackalloc short[maxSymbol + 1];
        int s = 0;

        while (remaining > 0 && s <= maxSymbol)
        {
            int width = BitOperations.Log2((uint)(remaining + 1)) + 1;
            int threshold = (1 << width) - 1 - (remaining + 1);
            uint val = reader.PeekBits(width);
            int countBits;

            uint lowMask = (1u << (width - 1)) - 1u;
            if ((val & lowMask) < (uint)threshold)
            {
                countBits = width - 1;
                val &= lowMask;
            }
            else
            {
                countBits = width;
                if (val > lowMask) val -= (uint)threshold;
            }

            reader.ConsumeBits(countBits);
            int probability = (int)val - 1;
            normalized[s++] = (short)probability;

            if (probability == -1)
            {
                remaining -= 1;
            }
            else if (probability > 0)
            {
                remaining -= probability;
            }
            else // probability == 0
            {
                uint repeat;
                do
                {
                    repeat = reader.ReadBits(2);
                    for (uint r = 0; r < repeat && s <= maxSymbol; r++)
                    {
                        normalized[s++] = 0;
                    }
                }
                while (repeat == 3 && s <= maxSymbol);
            }
        }

        if (remaining != 0)
        {
            throw new InvalidDataException($"Corrupted FSE table description: remaining probability sum ({remaining}) != 0.");
        }

        BuildTable(normalized, s - 1, accuracyLog, table);
        return reader.BytesConsumed;
    }
}
