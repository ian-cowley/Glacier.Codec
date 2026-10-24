namespace Glacier.Codec.Memory;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

/// <summary>
/// Unmanaged memory container for sensitive cryptographic key material.
/// Enforces 64-byte alignment and scrubs physical RAM upon disposal via
/// <see cref="CryptographicOperations.ZeroMemory"/>.
/// </summary>
public sealed unsafe class SecureMemory : IDisposable
{
    private void* _pointer;
    private readonly int _length;
    private int _disposed;

    /// <summary>
    /// Allocates unmanaged zeroed memory for cryptographic key material.
    /// </summary>
    /// <param name="byteLength">Length of key material in bytes.</param>
    public SecureMemory(int byteLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(byteLength);
        _length = byteLength;

        nuint allocSize = ((nuint)byteLength + 63) & ~(nuint)63;
        _pointer = NativeMemory.AlignedAlloc(allocSize, 64);
        NativeMemory.Clear(_pointer, allocSize);
    }

    /// <summary>
    /// Initializes secure memory with initial key material.
    /// </summary>
    public SecureMemory(ReadOnlySpan<byte> initialData) : this(initialData.Length)
    {
        if (initialData.Length > 0 && _pointer != null)
        {
            initialData.CopyTo(new Span<byte>(_pointer, _length));
        }
    }

    /// <summary>
    /// Factory creating secure memory pre-filled with secret bytes.
    /// </summary>
    public static SecureMemory Create(ReadOnlySpan<byte> secretKey)
    {
        return new SecureMemory(secretKey);
    }

    /// <summary>
    /// Factory copying secret bytes into secure memory and zero-wiping the source span.
    /// </summary>
    public static SecureMemory CreateAndWipeSource(Span<byte> secretKey)
    {
        var secure = new SecureMemory(secretKey);
        CryptographicOperations.ZeroMemory(secretKey);
        return secure;
    }

    /// <summary>Span view of the secure key material.</summary>
    public Span<byte> Span
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_length == 0 || _pointer == null)
            {
                return Span<byte>.Empty;
            }

            return new Span<byte>(_pointer, _length);
        }
    }

    /// <summary>ReadOnlySpan view of the secure key material.</summary>
    public ReadOnlySpan<byte> ReadOnlySpan
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => Span;
    }

    /// <summary>Raw unmanaged pointer to key material.</summary>
    public void* Pointer
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return _pointer;
        }
    }

    /// <summary>Length of key material in bytes.</summary>
    public int Length => _length;

    /// <summary>
    /// Performs a constant-time comparison against an expected key or tag to prevent timing side channels.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ConstantTimeEquals(ReadOnlySpan<byte> other)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return CryptographicOperations.FixedTimeEquals(Span, other);
    }

    /// <summary>
    /// Scrubs unmanaged memory via <see cref="CryptographicOperations.ZeroMemory"/> and frees memory.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            if (_pointer != null)
            {
                nuint allocSize = ((nuint)_length + 63) & ~(nuint)63;
                CryptographicOperations.ZeroMemory(new Span<byte>(_pointer, (int)allocSize));
                NativeMemory.AlignedFree(_pointer);
                _pointer = null;
            }

            GC.SuppressFinalize(this);
        }
    }

    ~SecureMemory()
    {
        Dispose();
    }
}
