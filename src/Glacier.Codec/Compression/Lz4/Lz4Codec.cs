namespace Glacier.Codec.Compression.Lz4;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using Glacier.Codec.Memory;

/// <summary>
/// Ultra-high-throughput LZ4 block compressor and decompressor conforming to the official LZ4 block specification.
/// Features SIMD Vector256/Vector128 match extension, 64-bit word diffing, branchless wild-copy, and self-referential RLE resolution.
/// Zero GC heap allocations on hot paths via unmanaged slab pool.
/// </summary>
public sealed unsafe class Lz4Codec : ICompressionCodec
{
    /// <inheritdoc />
    public int CompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Compress(source, destination);

    /// <inheritdoc />
    public int DecompressBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Decompress(source, destination);

    /// <inheritdoc />
    public int GetMaxCompressedSize(int sourceLength) => MaximumCompressedSize(sourceLength);

    /// <summary>
    /// Computes the maximum worst-case compressed size for an input buffer of length <paramref name="inputLength"/>.
    /// Formula: N + floor(N / 255) + 16.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaximumCompressedSize(int inputLength)
    {
        if (inputLength < 0) throw new ArgumentOutOfRangeException(nameof(inputLength));
        return inputLength + (inputLength / 255) + 16;
    }

    /// <summary>
    /// Compresses uncompressed data into LZ4 block format.
    /// </summary>
    /// <param name="source">Source uncompressed byte span.</param>
    /// <param name="destination">Destination span for compressed block.</param>
    /// <returns>Number of compressed bytes written.</returns>
    public static int Compress(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int srcLen = source.Length;
        if (srcLen == 0)
        {
            if (destination.IsEmpty) throw new ArgumentException("Destination buffer too small.", nameof(destination));
            destination[0] = 0x00;
            return 1;
        }

        // Short blocks (< 13 bytes) cannot contain matches due to MfLimit (12 bytes)
        if (srcLen < Lz4Constants.MfLimit + 1)
        {
            return EmitLiteralOnlySequence(source, destination);
        }

        fixed (byte* pSource = source)
        fixed (byte* pDest = destination)
        {
            byte* ip = pSource;
            byte* anchor = ip;
            byte* iend = pSource + srcLen;
            byte* mflimit = iend - Lz4Constants.MfLimit;
            byte* matchlimit = iend - Lz4Constants.LastLiterals;

            byte* op = pDest;
            byte* oend = pDest + destination.Length;

            using var lease = UnmanagedSlabPool.Shared.Rent(Lz4Constants.HashTableEntries * sizeof(int));
            int* hashTable = (int*)lease.Pointer;
            new Span<int>(hashTable, Lz4Constants.HashTableEntries).Fill(-1);

            // Prime first position
            hashTable[Lz4MatchFinder.ComputeHash(ip)] = 0;
            ip++;
            uint forwardH;

            // Main search loop
            while (ip < mflimit)
            {
                int forwardStep = 1;
                byte* match;
                int refIdx;

                // Find match candidate
                while (true)
                {
                    forwardH = (uint)Lz4MatchFinder.ComputeHash(ip);
                    refIdx = hashTable[forwardH];
                    hashTable[forwardH] = (int)(ip - pSource);

                    if (refIdx >= 0 && (ip - (pSource + refIdx)) <= Lz4Constants.MaxDistance)
                    {
                        match = pSource + refIdx;
                        if (BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(ip, 4)) ==
                            BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(match, 4)))
                        {
                            // 4-byte match confirmed!
                            break;
                        }
                    }

                    ip += forwardStep;
                    if (ip >= mflimit) goto _last_literals;
                }

                // Match found: extend forward beyond 4 bytes
                int matchLength = 4 + Lz4MatchFinder.ExtendMatch(ip + 4, match + 4, matchlimit);
                int litLength = (int)(ip - anchor);

                // Check destination space
                if (op + litLength + 16 + (matchLength >> 8) > oend)
                {
                    throw new ArgumentException("Destination buffer too small for LZ4 compression.", nameof(destination));
                }

                // Encode Token: high 4 bits = litLength, low 4 bits = (matchLength - 4)
                int tokenL = litLength < 15 ? litLength : 15;
                int tokenM = (matchLength - 4) < 15 ? (matchLength - 4) : 15;
                *op++ = (byte)((tokenL << 4) | tokenM);

                // Multi-byte literal length extension
                if (litLength >= 15)
                {
                    int len = litLength - 15;
                    while (len >= 255)
                    {
                        *op++ = 255;
                        len -= 255;
                    }
                    *op++ = (byte)len;
                }

                // Copy literals
                if (litLength > 0)
                {
                    new ReadOnlySpan<byte>(anchor, litLength).CopyTo(new Span<byte>(op, litLength));
                    op += litLength;
                }

                // Write 2-byte match offset (little-endian)
                ushort offset = (ushort)(ip - match);
                BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(op, 2), offset);
                op += 2;

                // Multi-byte match length extension
                if (matchLength - 4 >= 15)
                {
                    int len = (matchLength - 4) - 15;
                    while (len >= 255)
                    {
                        *op++ = 255;
                        len -= 255;
                    }
                    *op++ = (byte)len;
                }

                // Advance past match
                ip += matchLength;
                anchor = ip;

                // Update hash table for next lookup
                if (ip < mflimit)
                {
                    hashTable[Lz4MatchFinder.ComputeHash(ip - 2)] = (int)(ip - 2 - pSource);
                }
            }

        _last_literals:
            // Emit trailing literals sequence
            int lastLits = (int)(iend - anchor);
            int lastTokenL = lastLits < 15 ? lastLits : 15;
            *op++ = (byte)(lastTokenL << 4);

            if (lastLits >= 15)
            {
                int len = lastLits - 15;
                while (len >= 255)
                {
                    *op++ = 255;
                    len -= 255;
                }
                *op++ = (byte)len;
            }

            if (lastLits > 0)
            {
                new ReadOnlySpan<byte>(anchor, lastLits).CopyTo(new Span<byte>(op, lastLits));
                op += lastLits;
            }

            return (int)(op - pDest);
        }
    }

    /// <summary>
    /// Decompresses an LZ4 compressed block into uncompressed bytes.
    /// </summary>
    /// <param name="source">Compressed LZ4 block span.</param>
    /// <param name="destination">Destination uncompressed span.</param>
    /// <returns>Number of decompressed bytes written.</returns>
    public static int Decompress(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.IsEmpty || (source.Length == 1 && source[0] == 0x00))
        {
            return 0;
        }

        fixed (byte* pSource = source)
        fixed (byte* pDest = destination)
        {
            byte* ip = pSource;
            byte* iend = pSource + source.Length;

            byte* op = pDest;
            byte* oend = pDest + destination.Length;

            while (ip < iend)
            {
                // 1. Read Token
                byte token = *ip++;
                int literalLength = (token >> 4) & 0x0F;
                int tokenMatch = token & 0x0F;

                // 2. Multi-byte literal length extension
                if (literalLength == 15)
                {
                    while (ip < iend && *ip == 255)
                    {
                        literalLength += 255;
                        ip++;
                    }
                    if (ip >= iend) throw new InvalidDataException("LZ4 truncated literal length extension.");
                    literalLength += *ip++;
                }

                // 3. Copy Literals
                if (literalLength > 0)
                {
                    if (ip + literalLength > iend) throw new InvalidDataException("LZ4 truncated literal stream.");
                    if (op + literalLength > oend) throw new InvalidDataException("LZ4 destination buffer too small for literals.");

                    // Wild-copy for literals when distance to output buffer end allows
                    if (literalLength >= 16 && op + literalLength <= oend - Lz4Constants.WildCopyLength)
                    {
                        byte* srcLit = ip;
                        byte* dstLit = op;
                        byte* litLimit = op + literalLength;

                        if (Vector256.IsHardwareAccelerated && op + literalLength <= oend - 32)
                        {
                            while (dstLit + 32 <= litLimit)
                            {
                                Vector256.Store(Vector256.Load(srcLit), dstLit);
                                srcLit += 32;
                                dstLit += 32;
                            }
                        }

                        if (Vector128.IsHardwareAccelerated)
                        {
                            while (dstLit + 16 <= litLimit)
                            {
                                Vector128.Store(Vector128.Load(srcLit), dstLit);
                                srcLit += 16;
                                dstLit += 16;
                            }
                        }

                        while (dstLit < litLimit)
                        {
                            *dstLit++ = *srcLit++;
                        }
                    }
                    else
                    {
                        new ReadOnlySpan<byte>(ip, literalLength).CopyTo(new Span<byte>(op, literalLength));
                    }

                    ip += literalLength;
                    op += literalLength;
                }

                // Check if end of block reached (final sequence has no match)
                if (ip >= iend) break;

                // 4. Read 2-byte Match Offset
                if (ip + 2 > iend) throw new InvalidDataException("LZ4 truncated match offset.");
                ushort offset = BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(ip, 2));
                ip += 2;

                if (offset == 0) throw new InvalidDataException("LZ4 match offset cannot be zero.");

                byte* match = op - offset;
                if (match < pDest) throw new InvalidDataException("LZ4 offset points before start of buffer.");

                // 5. Read Match Length
                int matchLength = tokenMatch + Lz4Constants.MinMatch;
                if (tokenMatch == 15)
                {
                    while (ip < iend && *ip == 255)
                    {
                        matchLength += 255;
                        ip++;
                    }
                    if (ip >= iend) throw new InvalidDataException("LZ4 truncated match length extension.");
                    matchLength += *ip++;
                }

                if (op + matchLength > oend) throw new InvalidDataException("LZ4 destination buffer too small for match copy.");

                // 6. Execute Match Copy (with Overlap / RLE Handling)
                if (offset == 1)
                {
                    // Single-byte RLE run
                    byte b = *match;
                    new Span<byte>(op, matchLength).Fill(b);
                    op += matchLength;
                }
                else if (offset == 2)
                {
                    // 2-byte pattern repetition
                    ushort pat = BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(match, 2));
                    byte* matchEnd = op + matchLength;
                    while (op + 2 <= matchEnd)
                    {
                        BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(op, 2), pat);
                        op += 2;
                    }
                    if (op < matchEnd) *op++ = (byte)pat;
                }
                else if (offset < 8)
                {
                    // Small irregular overlapping matches (3, 4, 5, 6, 7)
                    for (int m = 0; m < matchLength; m++)
                    {
                        *op++ = *(match + m);
                    }
                }
                else
                {
                    // Non-overlapping within 8 bytes: high-speed wild copy
                    byte* matchEnd = op + matchLength;
                    byte* mSrc = match;

                    if (offset >= 32 && op + matchLength <= oend - 32 && Vector256.IsHardwareAccelerated)
                    {
                        while (op + 32 <= matchEnd)
                        {
                            Vector256.Store(Vector256.Load(mSrc), op);
                            mSrc += 32;
                            op += 32;
                        }
                    }

                    if (offset >= 16 && op + matchLength <= oend - 16 && Vector128.IsHardwareAccelerated)
                    {
                        while (op + 16 <= matchEnd)
                        {
                            Vector128.Store(Vector128.Load(mSrc), op);
                            mSrc += 16;
                            op += 16;
                        }
                    }

                    while (op + 8 <= matchEnd)
                    {
                        BinaryPrimitives.WriteUInt64LittleEndian(new Span<byte>(op, 8),
                            BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(mSrc, 8)));
                        mSrc += 8;
                        op += 8;
                    }

                    while (op < matchEnd)
                    {
                        *op++ = *mSrc++;
                    }
                }
            }

            return (int)(op - pDest);
        }
    }

    private static int EmitLiteralOnlySequence(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int litLen = source.Length;
        int tokenL = litLen < 15 ? litLen : 15;
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
}
