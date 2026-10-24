namespace Glacier.Codec.Compression.Zstd;

using System;
using System.IO;
using System.Runtime.CompilerServices;

/// <summary>
/// Sequence execution engine maintaining the 3-entry rolling repeat offset history (R1, R2, R3)
/// and reproducing decompressed literals and history matches per RFC 8878 Section 3.1.1.5.
/// </summary>
public struct SequenceExecutor
{
    private int _r1;
    private int _r2;
    private int _r3;

    public SequenceExecutor()
    {
        _r1 = 1;
        _r2 = 4;
        _r3 = 8;
    }

    /// <summary>R1 repeat offset.</summary>
    public int R1 => _r1;
    /// <summary>R2 repeat offset.</summary>
    public int R2 => _r2;
    /// <summary>R3 repeat offset.</summary>
    public int R3 => _r3;

    /// <summary>
    /// Resets the rolling repeat offset history to standard initial state (1, 4, 8).
    /// </summary>
    public void Reset()
    {
        _r1 = 1;
        _r2 = 4;
        _r3 = 8;
    }

    /// <summary>
    /// Resolves an offset code into a physical match distance and updates the rolling history stack.
    /// Implements RFC 8878 Section 3.1.1.1.1 rules and the LL == 0 shift exception.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int ResolveOffset(int offsetCode, int literalLength)
    {
        int offset;
        if (literalLength > 0)
        {
            if (offsetCode == 1)
            {
                offset = _r1;
            }
            else if (offsetCode == 2)
            {
                offset = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
            else if (offsetCode == 3)
            {
                offset = _r3;
                _r3 = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
            else // offsetCode > 3
            {
                offset = offsetCode - 3;
                _r3 = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
        }
        else // literalLength == 0 exception
        {
            if (offsetCode == 1)
            {
                offset = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
            else if (offsetCode == 2)
            {
                offset = _r3;
                _r3 = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
            else if (offsetCode == 3)
            {
                offset = _r1 - 1;
                if (offset <= 0)
                {
                    throw new InvalidDataException("Invalid repeat offset: offset resolved to zero or negative.");
                }
                _r3 = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
            else // offsetCode > 3
            {
                offset = offsetCode - 3;
                _r3 = _r2;
                _r2 = _r1;
                _r1 = offset;
            }
        }

        return offset;
    }

    /// <summary>
    /// Executes a single sequence triplet (literalLength, matchLength, offset) into destination.
    /// Handles self-overlapping run-length encoding.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Execute(
        ReadOnlySpan<byte> literals,
        ref int litIdx,
        int literalLength,
        int matchLength,
        int offset,
        Span<byte> destination,
        ref int dstIdx)
    {
        // 1. Copy literals
        if (literalLength > 0)
        {
            if (litIdx + literalLength > literals.Length)
            {
                throw new InvalidDataException("Literals buffer underflow during sequence execution.");
            }
            if (dstIdx + literalLength > destination.Length)
            {
                throw new InvalidDataException("Destination buffer overflow during sequence literals copy.");
            }

            literals.Slice(litIdx, literalLength).CopyTo(destination.Slice(dstIdx, literalLength));
            litIdx += literalLength;
            dstIdx += literalLength;
        }

        // 2. Copy match
        if (matchLength > 0)
        {
            int matchSrc = dstIdx - offset;
            if (matchSrc < 0)
            {
                throw new InvalidDataException($"Match offset ({offset}) exceeds decoded history window boundary ({dstIdx}).");
            }
            if (dstIdx + matchLength > destination.Length)
            {
                throw new InvalidDataException("Destination buffer overflow during sequence match copy.");
            }

            if (offset == 1)
            {
                // Single-byte RLE run
                byte b = destination[matchSrc];
                destination.Slice(dstIdx, matchLength).Fill(b);
                dstIdx += matchLength;
            }
            else
            {
                // Overlapping or non-overlapping match copy
                for (int m = 0; m < matchLength; m++)
                {
                    destination[dstIdx++] = destination[matchSrc + m];
                }
            }
        }
    }
}
