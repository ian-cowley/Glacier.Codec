namespace Glacier.Codec.Compression.Zstd;

using System;
using System.IO;
using System.Numerics;
using System.Runtime.CompilerServices;

/// <summary>
/// High-performance backward bit reader ref struct for RFC 8878 Zstandard bitstreams.
/// Operates backwards from the stream delimiter bit in the final byte towards the beginning.
/// Zero GC allocations.
/// </summary>
public ref struct ZstdBitReader
{
    private readonly ReadOnlySpan<byte> _source;
    private int _bytePos;
    private ulong _container;
    private int _bitsLeft;

    /// <summary>
    /// Initializes a new instance of the <see cref="ZstdBitReader"/> struct from a backward bitstream span.
    /// </summary>
    public ZstdBitReader(ReadOnlySpan<byte> source)
    {
        _source = source;
        if (source.IsEmpty)
        {
            _container = 0;
            _bitsLeft = 0;
            _bytePos = 0;
            return;
        }

        byte lastByte = source[source.Length - 1];
        if (lastByte == 0)
        {
            throw new InvalidDataException("Corrupted backward bitstream: missing end-mark bit (last byte is 0x00).");
        }

        int bitsInLastByte = BitOperations.Log2(lastByte);
        _container = (ulong)(lastByte & ((1 << bitsInLastByte) - 1));
        _bitsLeft = bitsInLastByte;
        _bytePos = source.Length - 1;

        Refill();
    }

    /// <summary>
    /// Current number of unconsumed bits remaining in the 64-bit reservoir.
    /// </summary>
    public int BitsLeft => _bitsLeft;

    /// <summary>
    /// True if the stream and reservoir have been completely consumed.
    /// </summary>
    public bool IsFinished => _bitsLeft <= 0 && _bytePos == 0;

    /// <summary>
    /// Reloads the 64-bit register backwards from the source span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Refill()
    {
        while (_bitsLeft <= 56 && _bytePos > 0)
        {
            _bytePos--;
            _container |= ((ulong)_source[_bytePos]) << _bitsLeft;
            _bitsLeft += 8;
        }
    }

    /// <summary>
    /// Peeks <paramref name="count"/> bits from the bit container without advancing position.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint PeekBits(int count)
    {
        if (count == 0) return 0;
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count) throw new InvalidDataException("Bitstream underflow while peeking bits.");
        }
        return (uint)(_container & ((1UL << count) - 1));
    }

    /// <summary>
    /// Consumes <paramref name="count"/> bits previously inspected.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ConsumeBits(int count)
    {
        _container >>= count;
        _bitsLeft -= count;
    }

    /// <summary>
    /// Reads and consumes <paramref name="count"/> bits from the backward bitstream.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadBits(int count)
    {
        if (count == 0) return 0;
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count) throw new InvalidDataException("Bitstream underflow while reading bits.");
        }

        uint value = (uint)(_container & ((1UL << count) - 1));
        _container >>= count;
        _bitsLeft -= count;
        return value;
    }
}

/// <summary>
/// High-performance forward bit reader ref struct for parsing FSE headers and probability distributions.
/// Reads bits forward from byte 0.
/// </summary>
public ref struct ZstdForwardBitReader
{
    private readonly ReadOnlySpan<byte> _source;
    private int _bytePos;
    private ulong _container;
    private int _bitsLeft;

    public ZstdForwardBitReader(ReadOnlySpan<byte> source)
    {
        _source = source;
        _bytePos = 0;
        _container = 0;
        _bitsLeft = 0;
        Refill();
    }

    public int BytesConsumed => _bytePos - (_bitsLeft >> 3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Refill()
    {
        while (_bitsLeft <= 56 && _bytePos < _source.Length)
        {
            _container |= ((ulong)_source[_bytePos++]) << _bitsLeft;
            _bitsLeft += 8;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint PeekBits(int count)
    {
        if (count == 0) return 0;
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count) throw new InvalidDataException("Forward bitstream underflow.");
        }
        return (uint)(_container & ((1UL << count) - 1));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ConsumeBits(int count)
    {
        _container >>= count;
        _bitsLeft -= count;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadBits(int count)
    {
        if (count == 0) return 0;
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count) throw new InvalidDataException("Forward bitstream underflow.");
        }

        uint value = (uint)(_container & ((1UL << count) - 1));
        _container >>= count;
        _bitsLeft -= count;
        return value;
    }
}
