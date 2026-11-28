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
        public CachelineAlignedBuffer? Buffer;
        public int Tier; // 1 = small, 2 = large, 3 = huge, 0 = oversized
        public int Next;
    }

    private const int InitialRawCapacity = 512;
    private int[] _rawBuckets;
    private RawEntry[] _rawEntries;
    private int _rawCount;
    private int _rawFreeList = -1;
    private int _rawFreeCount;
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
        // Prewarm managed shell wrappers with deferred native allocation:
        // 0 B native RAM consumed at startup AND 0 B GC heap allocations on first concurrent Rent!
        pool.PrewarmShells(
            smallCount: 256,
            largeCount: Math.Max(64, concurrency),
            hugeCount: Math.Max(64, concurrency));
        return pool;
    }

    private void PrewarmShells(int smallCount, int largeCount, int hugeCount)
    {
        lock (_smallLock)
        {
            while (_smallSlabTop < smallCount && _smallSlabTop < _maxSmallSlabs)
            {
                _smallSlabs[_smallSlabTop++] = new CachelineAlignedBuffer(SmallSlabSize, deferNativeAllocation: true, 0);
            }
        }
        lock (_largeLock)
        {
            while (_largeSlabTop < largeCount && _largeSlabTop < _maxLargeSlabs)
            {
                _largeSlabs[_largeSlabTop++] = new CachelineAlignedBuffer(LargeSlabSize, deferNativeAllocation: true, 0);
            }
        }
        lock (_hugeLock)
        {
            while (_hugeSlabTop < hugeCount && _hugeSlabTop < _maxHugeSlabs)
            {
                _hugeSlabs[_hugeSlabTop++] = new CachelineAlignedBuffer(HugeSlabSize, deferNativeAllocation: true, 0);
            }
        }
    }

    /// <summary>
    /// Pre-allocates up to <paramref name="count"/> slabs across each tier to guarantee
    /// zero-allocation rentals from the very first request under high concurrency.
    /// </summary>
    /// <param name="count">Number of slabs to pre-allocate in each tier.</param>
    public void Prewarm(int count) => Prewarm(count, count, count);

    /// <summary>
    /// Pre-allocates tier-specific slab counts to bound startup native footprint while maintaining zero-allocation steady-state rentals.
    /// </summary>
    public void Prewarm(int smallCount, int largeCount, int hugeCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(smallCount);
        ArgumentOutOfRangeException.ThrowIfNegative(largeCount);
        ArgumentOutOfRangeException.ThrowIfNegative(hugeCount);
        lock (_smallLock)
        {
            while (_smallSlabTop < smallCount && _smallSlabTop < _maxSmallSlabs)
            {
                _smallSlabs[_smallSlabTop++] = new CachelineAlignedBuffer(SmallSlabSize, clear: true);
            }
        }
        lock (_largeLock)
        {
            while (_largeSlabTop < largeCount && _largeSlabTop < _maxLargeSlabs)
            {
                _largeSlabs[_largeSlabTop++] = new CachelineAlignedBuffer(LargeSlabSize, clear: true);
            }
        }
        lock (_hugeLock)
        {
            while (_hugeSlabTop < hugeCount && _hugeSlabTop < _maxHugeSlabs)
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

        _rawBuckets = new int[InitialRawCapacity];
        Array.Fill(_rawBuckets, -1);
        _rawEntries = new RawEntry[InitialRawCapacity];
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
            if (buf != null)
            {
                buf.EnsureNativeAllocated();
            }
            else
            {
                buf = new CachelineAlignedBuffer(SmallSlabSize, clear: true);
            }
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
            if (buf != null)
            {
                buf.EnsureNativeAllocated();
            }
            else
            {
                buf = new CachelineAlignedBuffer(LargeSlabSize, clear: true);
            }
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
            if (buf != null)
            {
                buf.EnsureNativeAllocated();
            }
            else
            {
                buf = new CachelineAlignedBuffer(HugeSlabSize, clear: true);
            }
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
            if (_disposed != 0)
            {
                lease.Buffer.Dispose();
                throw new ObjectDisposedException(nameof(UnmanagedSlabPool));
            }

            int index;
            if (_rawFreeCount > 0)
            {
                index = _rawFreeList;
                _rawFreeList = _rawEntries[index].Next;
                _rawFreeCount--;
            }
            else
            {
                if (_rawCount == _rawEntries.Length)
                {
                    ResizeRawTable();
                }
                index = _rawCount++;
            }

            int bucket = GetBucketIndex(ptr, _rawBuckets.Length);
            _rawEntries[index] = new RawEntry
            {
                Ptr = ptr,
                Buffer = lease.Buffer,
                Tier = lease.Tier,
                Next = _rawBuckets[bucket]
            };
            _rawBuckets[bucket] = index;
            return ptr;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetBucketIndex(IntPtr ptr, int bucketCount)
    {
        ulong u = (ulong)ptr >> 6;
        u ^= u >> 16;
        return (int)u & (bucketCount - 1);
    }

    private void ResizeRawTable()
    {
        int newCapacity = _rawEntries.Length * 2;
        var newBuckets = new int[newCapacity];
        Array.Fill(newBuckets, -1);
        var newEntries = new RawEntry[newCapacity];
        Array.Copy(_rawEntries, newEntries, _rawCount);

        for (int i = 0; i < _rawCount; i++)
        {
            if (newEntries[i].Ptr != IntPtr.Zero)
            {
                int bucket = GetBucketIndex(newEntries[i].Ptr, newCapacity);
                newEntries[i].Next = newBuckets[bucket];
                newBuckets[bucket] = i;
            }
        }

        _rawBuckets = newBuckets;
        _rawEntries = newEntries;
    }

    /// <summary>
    /// Returns an unmanaged slab pointer back to the pool, wiping memory.
    /// Untracked or null pointers (<see cref="IntPtr.Zero"/>) are safely ignored.
    /// </summary>
    /// <remarks>
    /// Thread-safety boundary: a duplicate <c>Return(ptr, size)</c> call is idempotent only while no
    /// concurrent <see cref="Rent(int, out int)"/> can re-issue the exact same <paramref name="ptr"/> address
    /// (raw <see cref="IntPtr"/> values carry no per-rental generation token, so a delayed duplicate return
    /// can collide with a subsequent rental via ABA). Callers requiring concurrent double-dispose idempotency
    /// under multi-threaded <c>Rent</c>/<c>Return</c> contention must use <see cref="SlabLease"/> via
    /// <see cref="Rent(int)"/>, whose per-lease disposal state makes <see cref="SlabLease.Dispose"/> strictly ABA-safe.
    /// </remarks>
    /// <param name="ptr">Pointer to returned buffer.</param>
    /// <param name="size">Size of returned buffer in bytes.</param>
    public void Return(IntPtr ptr, int size)
    {
        if (ptr == IntPtr.Zero) return;

        CachelineAlignedBuffer? buf = null;
        int tier = 0;

        lock (_rawLock)
        {
            int bucket = GetBucketIndex(ptr, _rawBuckets.Length);
            int prev = -1;
            int curr = _rawBuckets[bucket];
            while (curr >= 0)
            {
                if (_rawEntries[curr].Ptr == ptr)
                {
                    buf = _rawEntries[curr].Buffer;
                    tier = _rawEntries[curr].Tier;
                    if (prev < 0)
                    {
                        _rawBuckets[bucket] = _rawEntries[curr].Next;
                    }
                    else
                    {
                        _rawEntries[prev].Next = _rawEntries[curr].Next;
                    }

                    _rawEntries[curr] = new RawEntry
                    {
                        Ptr = IntPtr.Zero,
                        Buffer = null,
                        Tier = 0,
                        Next = _rawFreeList
                    };
                    _rawFreeList = curr;
                    _rawFreeCount++;
                    break;
                }
                prev = curr;
                curr = _rawEntries[curr].Next;
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

        if (buffer.Pointer != null)
        {
            ZeroMemoryChunked((byte*)buffer.Pointer, buffer.AllocatedBytes);
        }

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void ZeroMemoryChunked(byte* ptr, nuint totalBytes)
    {
        nuint offset = 0;
        while (offset < totalBytes)
        {
            nuint remaining = totalBytes - offset;
            int chunk = remaining > (nuint)int.MaxValue ? int.MaxValue : (int)remaining;
            CryptographicOperations.ZeroMemory(new Span<byte>(ptr + offset, chunk));
            offset += (nuint)chunk;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            lock (_rawLock)
            {
                for (int i = 0; i < _rawCount; i++)
                {
                    _rawEntries[i].Buffer?.Dispose();
                    _rawEntries[i] = default;
                }
                Array.Fill(_rawBuckets, -1);
                _rawCount = 0;
                _rawFreeList = -1;
                _rawFreeCount = 0;
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
