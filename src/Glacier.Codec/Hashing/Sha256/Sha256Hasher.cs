namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Glacier.Codec.Hashing;

/// <summary>
/// Zero-allocation streaming cryptographic SHA-256 hasher implementing <see cref="IStreamingHasher"/>.
/// Manages 64-byte aligned chunk ingestion and deterministic memory zeroization upon disposal.
/// </summary>
public sealed unsafe class Sha256Hasher : IStreamingHasher
{
    private struct FixedBuffer64
    {
        public fixed byte Data[64];
    }

    private Sha256State _state;
#pragma warning disable CS0169
    private FixedBuffer64 _buffer;
#pragma warning restore CS0169
    private int _bufferLength;
    private ulong _totalBytes;
    private bool _disposed;

    public int HashSizeInBytes => Sha256.HashSizeInBytes;

    public Sha256Hasher()
    {
        Reset();
    }

    /// <summary>
    /// Resets internal hash state to standard FIPS 180-4 initial constants.
    /// </summary>
    public void Reset()
    {
        ThrowIfDisposed();
        _state = Sha256State.CreateInitial();
        fixed (byte* p = _buffer.Data)
        {
            CryptographicOperations.ZeroMemory(new Span<byte>(p, 64));
        }
        _bufferLength = 0;
        _totalBytes = 0;
    }

    /// <summary>
    /// Ingests data into the running SHA-256 digest stream.
    /// </summary>
    public void Append(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        if (data.IsEmpty) return;

        _totalBytes += (ulong)data.Length;

        // Stage 1: Fill residual 64-byte buffer if partially filled
        if (_bufferLength > 0)
        {
            int toCopy = Math.Min(64 - _bufferLength, data.Length);
            fixed (byte* p = _buffer.Data)
            {
                data.Slice(0, toCopy).CopyTo(new Span<byte>(p + _bufferLength, toCopy));
            }
            _bufferLength += toCopy;
            data = data.Slice(toCopy);

            if (_bufferLength == 64)
            {
                fixed (byte* p = _buffer.Data)
                {
                    Sha256Kernel.CompressBlock(ref _state, new ReadOnlySpan<byte>(p, 64));
                }
                _bufferLength = 0;
            }
        }

        // Stage 2: In-place bulk processing of 64-byte block multiples directly from input span
        int fullBlocks = data.Length / 64;
        if (fullBlocks > 0)
        {
            int blockBytes = fullBlocks * 64;
            Sha256Kernel.CompressBlocks(ref _state, data.Slice(0, blockBytes));
            data = data.Slice(blockBytes);
        }

        // Stage 3: Stage remaining bytes (< 64) into residual buffer
        if (!data.IsEmpty)
        {
            fixed (byte* p = _buffer.Data)
            {
                data.CopyTo(new Span<byte>(p, data.Length));
            }
            _bufferLength = data.Length;
        }
    }

    /// <summary>
    /// Extracts running intermediate hash without modifying ongoing stream state.
    /// </summary>
    public void GetCurrentHash(Span<byte> destination)
    {
        ThrowIfDisposed();
        if (destination.Length < HashSizeInBytes)
        {
            throw new ArgumentException($"Destination span must be at least {HashSizeInBytes} bytes.", nameof(destination));
        }

        // Stack clone of running state
        Sha256State clonedState = _state;
        Span<byte> padBuffer = stackalloc byte[128];
        fixed (byte* p = _buffer.Data)
        {
            new ReadOnlySpan<byte>(p, _bufferLength).CopyTo(padBuffer);
        }

        int padLen = _bufferLength;
        padBuffer[padLen++] = 0x80;

        int totalBlocks;
        if (padLen <= 56)
        {
            padBuffer.Slice(padLen, 56 - padLen).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(padBuffer.Slice(56, 8), _totalBytes * 8UL);
            totalBlocks = 1;
        }
        else
        {
            padBuffer.Slice(padLen, 64 - padLen).Clear();
            padBuffer.Slice(64, 56).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(padBuffer.Slice(120, 8), _totalBytes * 8UL);
            totalBlocks = 2;
        }

        Sha256Kernel.CompressBlocks(ref clonedState, padBuffer.Slice(0, totalBlocks * 64));
        clonedState.WriteDigest(destination.Slice(0, HashSizeInBytes));
        CryptographicOperations.ZeroMemory(padBuffer);
    }

    /// <summary>
    /// Finalizes hash calculation into <paramref name="destination"/> and resets state.
    /// </summary>
    public void Finalize(Span<byte> destination)
    {
        GetCurrentHash(destination);
        Reset();
    }

    /// <summary>
    /// Static one-shot hash method forwarded to <see cref="Sha256.Hash"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Hash(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Sha256.Hash(source, destination);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            fixed (byte* p = _buffer.Data)
            {
                CryptographicOperations.ZeroMemory(new Span<byte>(p, 64));
            }
            _state.Zeroize();
            _bufferLength = 0;
            _totalBytes = 0;
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Sha256Hasher));
        }
    }
}
