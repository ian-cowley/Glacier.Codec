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
    /// Reloads the 64-bit register backwards from the source span (MSB-downward per RFC 8878).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Refill()
    {
        while (_bitsLeft <= 56 && _bytePos > 0)
        {
            _bytePos--;
            _container = (_container << 8) | _source[_bytePos];
            _bitsLeft += 8;
        }
    }

    /// <summary>
    /// Peeks <paramref name="count"/> bits from the bit container without advancing position.
    /// Zero-pads missing low bits at stream end to support canonical prefix-table lookups;
    /// callers must validate actual bit availability via <see cref="ConsumeBits"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint PeekBits(int count)
    {
        if (count == 0) return 0;
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft <= 0)
            {
                throw new InvalidDataException("Bitstream underflow while peeking bits.");
            }
            if (_bitsLeft < count)
            {
                ulong padMask = (1UL << count) - 1UL;
                return (uint)((_container << (count - _bitsLeft)) & padMask);
            }
        }

        return (uint)((_container >> (_bitsLeft - count)) & ((1UL << count) - 1UL));
    }

    /// <summary>
    /// Consumes <paramref name="count"/> bits previously inspected.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ConsumeBits(int count)
    {
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count)
            {
                throw new InvalidDataException("Bitstream underflow while consuming bits.");
            }
        }
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

        uint value = (uint)((_container >> (_bitsLeft - count)) & ((1UL << count) - 1UL));
        _bitsLeft -= count;
        return value;
    }

    /// <summary>
    /// Attempts to read <paramref name="count"/> bits, returning false without throwing if fewer than
    /// <paramref name="count"/> bits remain in the entire backward bitstream.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryReadBits(int count, out uint value)
    {
        if (count == 0)
        {
            value = 0;
            return true;
        }
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count)
            {
                value = 0;
                return false;
            }
        }

        value = (uint)((_container >> (_bitsLeft - count)) & ((1UL << count) - 1UL));
        _bitsLeft -= count;
        return true;
    }
}

/// <summary>
/// High-performance zero-allocation forward bit accumulator that produces RFC 8878 backward bitstreams
/// (terminated by a trailing sentinel '1' bit in the final byte).
/// </summary>
public ref struct ZstdBitWriter
{
    private readonly Span<byte> _destination;
    private int _bytePos;
    private ulong _container;
    private int _bitCount;

    public ZstdBitWriter(Span<byte> destination)
    {
        _destination = destination;
        _bytePos = 0;
        _container = 0;
        _bitCount = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AddBits(uint value, int count)
    {
        if (count == 0) return;
        ulong masked = value & ((1UL << count) - 1UL);
        _container |= masked << _bitCount;
        _bitCount += count;

        while (_bitCount >= 8)
        {
            if (_bytePos >= _destination.Length)
            {
                throw new ArgumentException("Zstd bitstream destination buffer overflow.");
            }
            _destination[_bytePos++] = (byte)_container;
            _container >>= 8;
            _bitCount -= 8;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int Finish()
    {
        // Append mandatory RFC 8878 end-of-stream sentinel '1' bit
        AddBits(1U, 1);
        if (_bitCount > 0)
        {
            if (_bytePos >= _destination.Length)
            {
                throw new ArgumentException("Zstd bitstream destination buffer overflow.");
            }
            _destination[_bytePos++] = (byte)_container;
            _container = 0;
            _bitCount = 0;
        }
        return _bytePos;
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
            if (_bitsLeft <= 0) throw new InvalidDataException("Forward bitstream underflow.");
        }
        return (uint)(_container & ((1UL << count) - 1));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ConsumeBits(int count)
    {
        if (_bitsLeft < count)
        {
            Refill();
            if (_bitsLeft < count) throw new InvalidDataException("Forward bitstream underflow.");
        }
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
