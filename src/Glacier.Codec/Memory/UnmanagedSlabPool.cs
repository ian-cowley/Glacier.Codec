namespace Glacier.Codec.Memory;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;

/// <summary>
/// High-throughput, zero-allocation slab pool renting 64-byte aligned unmanaged chunks.
/// Eliminates GC allocation overhead during high-speed stream hashing, encryption, and compression.
/// Uses bounded slot arrays to guarantee strictly zero GC heap allocations on steady-state rentals and returns.
/// </summary>
public sealed unsafe class UnmanagedSlabPool : IDisposable
{
    public const int SmallSlabSize = 64 * 1024;        // 64 KB
    public const int LargeSlabSize = 1024 * 1024;      // 1 MB
    public const int HugeSlabSize = 4 * 1024 * 1024;   // 4 MB (covers up to 64 MB BLAKE3 CV buffer)

    public const int SlabSize64K = SmallSlabSize;
    public const int SlabSize1M = LargeSlabSize;
    public const int SlabSize4M = HugeSlabSize;

    private readonly CachelineAlignedBuffer?[] _smallSlabs;
    private readonly CachelineAlignedBuffer?[] _largeSlabs;
    private readonly CachelineAlignedBuffer?[] _hugeSlabs;
    private int _smallSlabTop;
    private int _largeSlabTop;
    private int _hugeSlabTop;

    private readonly object _smallLock = new();
    private readonly object _largeLock = new();
    private readonly object _hugeLock = new();

    private struct RawEntry
    {
        public IntPtr Ptr;
        public CachelineAlignedBuffer Buffer;
        public int Tier; // 1 = small, 2 = large, 3 = huge, 0 = oversized
    }
    private readonly RawEntry[] _rawEntries = new RawEntry[512];
    private readonly object _rawLock = new();

    private readonly int _maxSmallSlabs;
    private readonly int _maxLargeSlabs;
    private readonly int _maxHugeSlabs;
    private int _disposed;

    /// <summary>
    /// Global shared singleton instance of the slab pool.
    /// </summary>
    public static UnmanagedSlabPool Shared { get; } = CreateShared();

    private static UnmanagedSlabPool CreateShared()
    {
        int concurrency = Math.Max(32, Environment.ProcessorCount);
        var pool = new UnmanagedSlabPool(
            maxSmallSlabs: 256,
            maxLargeSlabs: Math.Max(64, concurrency),
            maxHugeSlabs: Math.Max(64, concurrency));
        pool.Prewarm(concurrency);
        return pool;
    }

    /// <summary>
    /// Pre-allocates up to <paramref name="count"/> slabs across each tier to guarantee
    /// zero-allocation rentals from the very first request under high concurrency.
    /// </summary>
    /// <param name="count">Number of slabs to pre-allocate in each tier.</param>
    public void Prewarm(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        lock (_smallLock)
        {
            while (_smallSlabTop < count && _smallSlabTop < _maxSmallSlabs)
            {
                _smallSlabs[_smallSlabTop++] = new CachelineAlignedBuffer(SmallSlabSize, clear: true);
            }
        }
        lock (_largeLock)
        {
            while (_largeSlabTop < count && _largeSlabTop < _maxLargeSlabs)
            {
                _largeSlabs[_largeSlabTop++] = new CachelineAlignedBuffer(LargeSlabSize, clear: true);
            }
        }
        lock (_hugeLock)
        {
            while (_hugeSlabTop < count && _hugeSlabTop < _maxHugeSlabs)
            {
                _hugeSlabs[_hugeSlabTop++] = new CachelineAlignedBuffer(HugeSlabSize, clear: true);
            }
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UnmanagedSlabPool"/> class.
    /// </summary>
    /// <param name="maxSmallSlabs">Maximum 64 KB slabs retained in cache.</param>
    /// <param name="maxLargeSlabs">Maximum 1 MB slabs retained in cache.</param>
    /// <param name="maxHugeSlabs">Maximum 4 MB slabs retained in cache.</param>
    public UnmanagedSlabPool(int maxSmallSlabs = 256, int maxLargeSlabs = 64, int maxHugeSlabs = 64)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSmallSlabs);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLargeSlabs);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxHugeSlabs);

        _maxSmallSlabs = maxSmallSlabs;
        _maxLargeSlabs = maxLargeSlabs;
        _maxHugeSlabs = maxHugeSlabs;

        _smallSlabs = new CachelineAlignedBuffer?[maxSmallSlabs];
        _largeSlabs = new CachelineAlignedBuffer?[maxLargeSlabs];
        _hugeSlabs = new CachelineAlignedBuffer?[maxHugeSlabs];
    }

    /// <summary>
    /// Rents an unmanaged slab with at least <paramref name="minimumSize"/> bytes.
    /// </summary>
    /// <param name="minimumSize">Minimum capacity required in bytes.</param>
    /// <returns>A stack-allocated <see cref="SlabLease"/> holding the rented buffer.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SlabLease Rent(int minimumSize)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minimumSize);

        if (minimumSize <= SmallSlabSize)
        {
            CachelineAlignedBuffer? buf = null;
            lock (_smallLock)
            {
                if (_smallSlabTop > 0)
                {
                    buf = _smallSlabs[--_smallSlabTop];
                    _smallSlabs[_smallSlabTop] = null;
                }
            }
            buf ??= new CachelineAlignedBuffer(SmallSlabSize, clear: true);
            return new SlabLease(this, buf, tier: 1, isPooled: true);
        }

        if (minimumSize <= LargeSlabSize)
        {
            CachelineAlignedBuffer? buf = null;
            lock (_largeLock)
            {
                if (_largeSlabTop > 0)
                {
                    buf = _largeSlabs[--_largeSlabTop];
                    _largeSlabs[_largeSlabTop] = null;
                }
            }
            buf ??= new CachelineAlignedBuffer(LargeSlabSize, clear: true);
            return new SlabLease(this, buf, tier: 2, isPooled: true);
        }

        if (minimumSize <= HugeSlabSize)
        {
            CachelineAlignedBuffer? buf = null;
            lock (_hugeLock)
            {
                if (_hugeSlabTop > 0)
                {
                    buf = _hugeSlabs[--_hugeSlabTop];
                    _hugeSlabs[_hugeSlabTop] = null;
                }
            }
            buf ??= new CachelineAlignedBuffer(HugeSlabSize, clear: true);
            return new SlabLease(this, buf, tier: 3, isPooled: true);
        }

        // Oversized buffer: allocate directly and free on disposal
        return new SlabLease(this, new CachelineAlignedBuffer(minimumSize, clear: true), tier: 0, isPooled: false);
    }

    /// <summary>
    /// Rents an unmanaged slab pointer with at least <paramref name="minSize"/> bytes.
    /// </summary>
    /// <param name="minSize">Minimum capacity required in bytes.</param>
    /// <param name="actualSize">Actual capacity of the rented slab.</param>
    /// <returns>IntPtr to 64-byte aligned memory.</returns>
    public IntPtr Rent(int minSize, out int actualSize)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minSize);

        var lease = Rent(minSize);
        actualSize = lease.Buffer.Length;
        IntPtr ptr = (IntPtr)lease.Buffer.Pointer;

        lock (_rawLock)
        {
            for (int i = 0; i < _rawEntries.Length; i++)
            {
                if (_rawEntries[i].Ptr == IntPtr.Zero)
                {
                    _rawEntries[i] = new RawEntry { Ptr = ptr, Buffer = lease.Buffer, Tier = lease.Tier };
                    return ptr;
                }
            }
        }

        throw new InvalidOperationException("Raw allocation tracking table exhausted.");
    }

    /// <summary>
    /// Returns an unmanaged slab pointer back to the pool, wiping memory.
    /// Untracked or duplicate-returned pointers are safely ignored to guarantee idempotency.
    /// </summary>
    /// <param name="ptr">Pointer to returned buffer.</param>
    /// <param name="size">Size of returned buffer in bytes.</param>
    public void Return(IntPtr ptr, int size)
    {
        if (ptr == IntPtr.Zero) return;

        CachelineAlignedBuffer? buf = null;
        int tier = 0;

        lock (_rawLock)
        {
            for (int i = 0; i < _rawEntries.Length; i++)
            {
                if (_rawEntries[i].Ptr == ptr)
                {
                    buf = _rawEntries[i].Buffer;
                    tier = _rawEntries[i].Tier;
                    _rawEntries[i] = default;
                    break;
                }
            }
        }

        if (buf != null)
        {
            Return(buf, tier, isPooled: tier > 0);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void Return(CachelineAlignedBuffer buffer, int tier, bool isPooled)
    {
        if (buffer == null) return;

        CryptographicOperations.ZeroMemory(new Span<byte>(buffer.Pointer, (int)buffer.AllocatedBytes));

        if (_disposed != 0 || !isPooled)
        {
            buffer.Dispose();
            return;
        }

        if (tier == 1)
        {
            lock (_smallLock)
            {
                if (_smallSlabTop < _maxSmallSlabs)
                {
                    _smallSlabs[_smallSlabTop++] = buffer;
                    return;
                }
            }
        }
        else if (tier == 2)
        {
            lock (_largeLock)
            {
                if (_largeSlabTop < _maxLargeSlabs)
                {
                    _largeSlabs[_largeSlabTop++] = buffer;
                    return;
                }
            }
        }
        else if (tier == 3)
        {
            lock (_hugeLock)
            {
                if (_hugeSlabTop < _maxHugeSlabs)
                {
                    _hugeSlabs[_hugeSlabTop++] = buffer;
                    return;
                }
            }
        }

        buffer.Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            lock (_rawLock)
            {
                for (int i = 0; i < _rawEntries.Length; i++)
                {
                    _rawEntries[i].Buffer?.Dispose();
                    _rawEntries[i] = default;
                }
            }

            lock (_smallLock)
            {
                while (_smallSlabTop > 0)
                {
                    _smallSlabs[--_smallSlabTop]?.Dispose();
                    _smallSlabs[_smallSlabTop] = null;
                }
            }

            lock (_largeLock)
            {
                while (_largeSlabTop > 0)
                {
                    _largeSlabs[--_largeSlabTop]?.Dispose();
                    _largeSlabs[_largeSlabTop] = null;
                }
            }

            lock (_hugeLock)
            {
                while (_hugeSlabTop > 0)
                {
                    _hugeSlabs[--_hugeSlabTop]?.Dispose();
                    _hugeSlabs[_hugeSlabTop] = null;
                }
            }
        }
    }
}

/// <summary>
/// Stack-allocated lease representing an unmanaged slab rental.
/// Returning the lease via <see cref="Dispose"/> recycles the buffer with zero heap allocation.
/// </summary>
public ref struct SlabLease
{
    private readonly UnmanagedSlabPool _pool;
    private readonly CachelineAlignedBuffer _buffer;
    private readonly int _tier;
    private readonly bool _isPooled;
    private bool _disposed;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal SlabLease(UnmanagedSlabPool pool, CachelineAlignedBuffer buffer, int tier, bool isPooled)
    {
        _pool = pool;
        _buffer = buffer;
        _tier = tier;
        _isPooled = isPooled;
        _disposed = false;
    }

    internal int Tier => _tier;

    public bool IsSmall => _tier == 1;

    /// <summary>The rented unmanaged buffer.</summary>
    public CachelineAlignedBuffer Buffer
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer;
        }
    }

    /// <summary>Span view of the rented memory.</summary>
    public Span<byte> Span
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer.Span;
        }
    }

    /// <summary>
    /// Direct access to the underlying buffer's padded span covering all allocated bytes (multiple of 64).
    /// </summary>
    public Span<byte> PaddedSpan
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer.PaddedSpan;
        }
    }

    /// <summary>Raw unmanaged pointer aligned to 64 bytes.</summary>
    public unsafe void* Pointer
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer.Pointer;
        }
    }

    /// <summary>Usable length in bytes.</summary>
    public int Length
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer.Length;
        }
    }

    /// <summary>Total allocated bytes in the buffer including padding.</summary>
    public nuint AllocatedBytes
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (_disposed) ThrowDisposed();
            return _buffer.AllocatedBytes;
        }
    }

    /// <summary>
    /// Returns the rented slab back to its parent pool.
    /// Strictly idempotent: multiple invocations safely no-op to prevent duplicate enqueueing.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose()
    {
        if (!_disposed && _buffer != null && _pool != null)
        {
            _disposed = true;
            _pool.Return(_buffer, _tier, _isPooled);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowDisposed() => throw new ObjectDisposedException(nameof(SlabLease));
}
