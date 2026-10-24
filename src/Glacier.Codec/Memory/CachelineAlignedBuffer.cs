namespace Glacier.Codec.Memory;

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// High-performance unmanaged buffer aligned to a 64-byte L1 cacheline boundary.
/// Implements <see cref="MemoryManager{T}"/> to provide zero-copy, cache-aligned <see cref="Memory{T}"/>
/// and <see cref="Span{T}"/> for AVX-512, VAES, and high-throughput streaming pipelines.
/// </summary>
public sealed unsafe class CachelineAlignedBuffer : MemoryManager<byte>, IMemoryOwner<byte>
{
    public const int CachelineAlignment = 64;

    private void* _pointer;
    private readonly int _length;
    private readonly nuint _allocatedBytes;
    private readonly bool _ownsMemory;
    private int _disposed;

    /// <summary>
    /// Allocates unmanaged memory aligned to 64 bytes.
    /// Memory is automatically zeroed upon allocation.
    /// </summary>
    /// <param name="byteLength">Requested length in bytes.</param>
    /// <param name="clear">Whether to zero-initialize the allocated memory.</param>
    public CachelineAlignedBuffer(int byteLength, bool clear = true)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(byteLength);
        _length = byteLength;
        _ownsMemory = true;

        // Pad allocation size to a multiple of 64 bytes to prevent SIMD load overruns
        _allocatedBytes = ((nuint)byteLength + 63) & ~(nuint)63;
        _pointer = NativeMemory.AlignedAlloc(_allocatedBytes, CachelineAlignment);

        if (clear)
        {
            NativeMemory.Clear(_pointer, _allocatedBytes);
        }
    }

    /// <summary>
    /// Wraps an existing unmanaged pointer aligned to 64 bytes.
    /// </summary>
    public CachelineAlignedBuffer(void* pointer, int byteLength, bool ownsMemory = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(byteLength);
        if (byteLength > 0 && pointer == null)
        {
            throw new ArgumentNullException(nameof(pointer));
        }

        if (byteLength > 0 && ((nuint)pointer & (CachelineAlignment - 1)) != 0)
        {
            throw new ArgumentException($"Pointer must be aligned to a {CachelineAlignment}-byte boundary.", nameof(pointer));
        }

        _pointer = pointer;
        _length = byteLength;
        _allocatedBytes = (nuint)byteLength;
        _ownsMemory = ownsMemory;
    }

    /// <summary>Raw unmanaged pointer aligned to 64 bytes.</summary>
    public void* Pointer
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return _pointer;
        }
    }

    /// <summary>Byte length of the accessible buffer.</summary>
    public int Length => _length;

    /// <summary>Total unmanaged bytes allocated (padded to multiple of 64 bytes).</summary>
    public nuint AllocatedBytes => _allocatedBytes;

    /// <summary>True if the buffer pointer is aligned to a 64-byte boundary.</summary>
    public bool IsAlignedTo64Bytes => _pointer == null || ((nuint)_pointer & (CachelineAlignment - 1)) == 0;

    /// <summary>Direct access to the underlying <see cref="Span{T}"/>.</summary>
    public Span<byte> Span
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => GetSpan();
    }

    /// <summary>Direct access to the underlying <see cref="ReadOnlySpan{T}"/>.</summary>
    public ReadOnlySpan<byte> ReadOnlySpan
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => GetSpan();
    }

    /// <summary>
    /// Direct access to the underlying <see cref="Span{T}"/> covering all allocated padded bytes (multiple of 64).
    /// Safe for AVX-512 and SIMD vector overread envelopes without triggering out-of-bounds exceptions.
    /// </summary>
    public Span<byte> PaddedSpan
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_allocatedBytes == 0 || _pointer == null)
            {
                return Span<byte>.Empty;
            }

            return new Span<byte>(_pointer, (int)_allocatedBytes);
        }
    }

    /// <summary>Provides a Span representation of the buffer.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override Span<byte> GetSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (_length == 0 || _pointer == null)
        {
            return Span<byte>.Empty;
        }

        return new Span<byte>(_pointer, _length);
    }

    /// <summary>Pins the memory block (no-op for unmanaged memory).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override MemoryHandle Pin(int elementIndex = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (_length == 0 && elementIndex == 0)
        {
            return new MemoryHandle(null);
        }

        ArgumentOutOfRangeException.ThrowIfNegative(elementIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(elementIndex, _length);
        return new MemoryHandle((byte*)_pointer + elementIndex);
    }

    /// <summary>Unpins the memory block (no-op for unmanaged memory).</summary>
    public override void Unpin()
    {
        // Unmanaged memory does not move; no unpinning is required.
    }

    /// <summary>Disposes the unmanaged memory buffer.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Disposes the unmanaged memory buffer.</summary>
    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            if (_ownsMemory && _pointer != null)
            {
                NativeMemory.AlignedFree(_pointer);
                _pointer = null;
            }
        }
    }
}
