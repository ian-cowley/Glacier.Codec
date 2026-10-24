namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hardware;

/// <summary>
/// High-throughput streaming xxHash3 hasher managing 64-byte stripe accumulation,
/// 1024-byte accumulator scrambling, and branchless short buffer finalization.
/// Conforms 100% to the official xxHash3 specification and .NET System.IO.Hashing across seeded and unseeded modes.
/// </summary>
public unsafe class XxHash3Stream : IKeyedHasher
{
    private struct InternalBuffer256
    {
        public fixed byte Data[XxHash3Constants.InternalBufferLengthBytes];
    }

    private struct Accumulators8
    {
        public fixed ulong Data[XxHash3Constants.AccumulatorCount];
    }

    private struct Secret192
    {
        public fixed byte Data[XxHash3Constants.SecretLengthBytes];
    }

    private readonly int _hashSize;
    private ulong _seed;
    private bool _hasCustomSecret;
    private ulong _totalLength;
    private int _bufferedCount;
    private ulong _stripesInBlock;
    private bool _disposed;

#pragma warning disable CS0169
    private InternalBuffer256 _buffer;
    private Accumulators8 _acc;
    private Secret192 _secret;
#pragma warning restore CS0169

    public int HashSizeInBytes => _hashSize;

    public XxHash3Stream(int hashSize = 8, ulong seed = 0)
    {
        if (hashSize is not (8 or 16))
        {
            throw new ArgumentOutOfRangeException(nameof(hashSize), "Hash size must be 8 or 16 bytes.");
        }

        _hashSize = hashSize;
        _seed = seed;
        _hasCustomSecret = false;
        InitSecret();
        Reset();
    }

    private void InitSecret()
    {
        fixed (byte* pSec = _secret.Data)
        {
            if (_seed == 0)
            {
                XxHash3Constants.DefaultSecret.CopyTo(new Span<byte>(pSec, XxHash3Constants.SecretLengthBytes));
            }
            else
            {
                XxHash3.DeriveSecretFromSeed(new Span<byte>(pSec, XxHash3Constants.SecretLengthBytes), _seed);
            }
        }
    }

    public void SetKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        fixed (byte* pSec = _secret.Data)
        {
            var secSpan = new Span<byte>(pSec, XxHash3Constants.SecretLengthBytes);
            if (key.Length == 8)
            {
                _seed = BinaryPrimitives.ReadUInt64LittleEndian(key);
                _hasCustomSecret = false;
                XxHash3.DeriveSecretFromSeed(secSpan, _seed);
            }
            else if (key.Length >= XxHash3Constants.SecretSizeMin)
            {
                int copyLen = Math.Min(key.Length, XxHash3Constants.SecretLengthBytes);
                key.Slice(0, copyLen).CopyTo(secSpan);
                _hasCustomSecret = true;
                _seed = 0;
            }
            else if (key.IsEmpty)
            {
                _seed = 0;
                _hasCustomSecret = false;
                XxHash3Constants.DefaultSecret.CopyTo(secSpan);
            }
            else
            {
                throw new ArgumentException($"Custom secret must be at least {XxHash3Constants.SecretSizeMin} bytes or 8-byte seed.", nameof(key));
            }
        }
        Reset();
    }

    public void Reset()
    {
        ThrowIfDisposed();
        _totalLength = 0;
        _bufferedCount = 0;
        _stripesInBlock = 0;

        fixed (ulong* pAcc = _acc.Data)
        {
            for (int i = 0; i < XxHash3Constants.AccumulatorCount; i++)
            {
                pAcc[i] = XxHash3Constants.InitAccumulators[i];
            }
        }

        fixed (byte* pBuf = _buffer.Data)
        {
            new Span<byte>(pBuf, XxHash3Constants.InternalBufferLengthBytes).Clear();
        }
    }

    public void Append(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        if (data.IsEmpty) return;

        _totalLength += (ulong)data.Length;

        fixed (byte* pBuf = _buffer.Data)
        fixed (ulong* pAcc = _acc.Data)
        fixed (byte* pSec = _secret.Data)
        fixed (byte* pSrc = &MemoryMarshal.GetReference(data))
        {
            if (data.Length <= XxHash3Constants.InternalBufferLengthBytes - _bufferedCount)
            {
                data.CopyTo(new Span<byte>(pBuf + _bufferedCount, data.Length));
                _bufferedCount += data.Length;
                return;
            }

            int sourceIndex = 0;
            if (_bufferedCount != 0)
            {
                int loadSize = XxHash3Constants.InternalBufferLengthBytes - _bufferedCount;
                data.Slice(0, loadSize).CopyTo(new Span<byte>(pBuf + _bufferedCount, loadSize));
                sourceIndex = loadSize;

                ConsumeStripes(pAcc, ref _stripesInBlock, 16, pBuf, 4, pSec);
                _bufferedCount = 0;
            }

            int remaining = data.Length - sourceIndex;
            if (remaining > 16 * 64)
            {
                ulong stripes = (ulong)(remaining - 1) / 64;
                ulong stripesToEnd = 16 - _stripesInBlock;

                AccumulateStripes(pAcc, pSrc + sourceIndex, pSec + (int)_stripesInBlock * 8, (int)stripesToEnd);
                ScrambleAccumulators(pAcc, pSec + 128);
                _stripesInBlock = 0;
                sourceIndex += (int)stripesToEnd * 64;
                stripes -= stripesToEnd;

                while (stripes >= 16)
                {
                    AccumulateStripes(pAcc, pSrc + sourceIndex, pSec, 16);
                    ScrambleAccumulators(pAcc, pSec + 128);
                    sourceIndex += 16 * 64;
                    stripes -= 16;
                }

                AccumulateStripes(pAcc, pSrc + sourceIndex, pSec, (int)stripes);
                sourceIndex += (int)stripes * 64;
                _stripesInBlock = stripes;

                data.Slice(sourceIndex - 64, 64).CopyTo(new Span<byte>(pBuf + XxHash3Constants.InternalBufferLengthBytes - 64, 64));
            }
            else if (remaining > XxHash3Constants.InternalBufferLengthBytes)
            {
                do
                {
                    ConsumeStripes(pAcc, ref _stripesInBlock, 16, pSrc + sourceIndex, 4, pSec);
                    sourceIndex += XxHash3Constants.InternalBufferLengthBytes;
                }
                while (data.Length - sourceIndex > XxHash3Constants.InternalBufferLengthBytes);

                data.Slice(sourceIndex - 64, 64).CopyTo(new Span<byte>(pBuf + XxHash3Constants.InternalBufferLengthBytes - 64, 64));
            }

            int tailLen = data.Length - sourceIndex;
            data.Slice(sourceIndex, tailLen).CopyTo(new Span<byte>(pBuf, tailLen));
            _bufferedCount = tailLen;
        }
    }

    private static void ConsumeStripes(ulong* accumulators, ref ulong stripesSoFar, ulong stripesPerBlock, byte* source, ulong stripes, byte* secret)
    {
        ulong stripesToEndOfBlock = stripesPerBlock - stripesSoFar;
        if (stripesToEndOfBlock <= stripes)
        {
            ulong remainingStripes = stripes - stripesToEndOfBlock;
            AccumulateStripes(accumulators, source, secret + (int)stripesSoFar * XxHash3Constants.SecretConsumeRateBytes, (int)stripesToEndOfBlock);
            ScrambleAccumulators(accumulators, secret + (XxHash3Constants.SecretLengthBytes - XxHash3Constants.StripeLengthBytes));
            AccumulateStripes(accumulators, source + (int)stripesToEndOfBlock * XxHash3Constants.StripeLengthBytes, secret, (int)remainingStripes);
            stripesSoFar = remainingStripes;
        }
        else
        {
            AccumulateStripes(accumulators, source, secret + (int)stripesSoFar * XxHash3Constants.SecretConsumeRateBytes, (int)stripes);
            stripesSoFar += stripes;
        }
    }

    private static void AccumulateStripes(ulong* accumulators, byte* source, byte* secret, int count)
    {
        for (int i = 0; i < count; i++)
        {
            byte* stripe = source + i * XxHash3Constants.StripeLengthBytes;
            byte* sec = secret + i * XxHash3Constants.SecretConsumeRateBytes;
            AccumulateSingleStripe(accumulators, stripe, sec);
        }
    }

    private static void AccumulateSingleStripe(ulong* accumulators, byte* stripe, byte* secret)
    {
        if (CpuCapabilities.HasAvx512F && XxHash3KernelAvx512.IsSupported)
        {
            XxHash3KernelAvx512.AccumulateStripe(accumulators, stripe, secret);
        }
        else if (CpuCapabilities.HasAvx2 && XxHash3KernelAvx2.IsSupported)
        {
            XxHash3KernelAvx2.AccumulateStripe(accumulators, stripe, secret);
        }
        else if (CpuCapabilities.IsArm64 && XxHash3KernelArmNeon.IsSupported)
        {
            XxHash3KernelArmNeon.AccumulateStripe(accumulators, stripe, secret);
        }
        else
        {
            XxHash3KernelScalar.AccumulateStripe(accumulators, stripe, secret);
        }
    }

    private static void ScrambleAccumulators(ulong* accumulators, byte* secret)
    {
        if (CpuCapabilities.HasAvx512F && XxHash3KernelAvx512.IsSupported)
        {
            XxHash3KernelAvx512.Scramble(accumulators, secret);
        }
        else if (CpuCapabilities.HasAvx2 && XxHash3KernelAvx2.IsSupported)
        {
            XxHash3KernelAvx2.Scramble(accumulators, secret);
        }
        else if (CpuCapabilities.IsArm64 && XxHash3KernelArmNeon.IsSupported)
        {
            XxHash3KernelArmNeon.Scramble(accumulators, secret);
        }
        else
        {
            XxHash3KernelScalar.Scramble(accumulators, secret);
        }
    }

    public void GetCurrentHash(Span<byte> destination)
    {
        ThrowIfDisposed();
        if (destination.Length < _hashSize)
        {
            throw new ArgumentException($"Destination span must be at least {_hashSize} bytes.", nameof(destination));
        }

        fixed (byte* pBuf = _buffer.Data)
        fixed (byte* pSec = _secret.Data)
        {
            var secSpan = new ReadOnlySpan<byte>(pSec, XxHash3Constants.SecretLengthBytes);

            // Small input path (<= 240B)
            if (_totalLength <= (ulong)XxHash3Constants.MidSizeMaxBytes)
            {
                var inputSlice = new ReadOnlySpan<byte>(pBuf, (int)_totalLength);
                ReadOnlySpan<byte> secToUse = _hasCustomSecret ? secSpan : XxHash3Constants.DefaultSecret;
                if (_hashSize == 8)
                {
                    ulong h64 = XxHash3.Hash64Internal(inputSlice, _seed, secToUse);
                    BinaryPrimitives.WriteUInt64LittleEndian(destination, h64);
                }
                else
                {
                    UInt128 h128 = XxHash3.Hash128Internal(inputSlice, _seed, secToUse);
                    BinaryPrimitives.WriteUInt64LittleEndian(destination, (ulong)(h128 & ulong.MaxValue));
                    BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), (ulong)(h128 >> 64));
                }
                return;
            }

            // Long input path: Clone accumulators and finish tail stripes
            Span<ulong> clonedAcc = stackalloc ulong[XxHash3Constants.AccumulatorCount];
            fixed (ulong* pAcc = _acc.Data)
            {
                for (int i = 0; i < XxHash3Constants.AccumulatorCount; i++) clonedAcc[i] = pAcc[i];
            }

            fixed (ulong* pCloned = clonedAcc)
            {
                byte* tailStripe;
                if (_bufferedCount >= 64)
                {
                    int stripes = (_bufferedCount - 1) / 64;
                    ulong stripesSoFar = _stripesInBlock;
                    ConsumeStripes(pCloned, ref stripesSoFar, 16, pBuf, (ulong)stripes, pSec);
                    tailStripe = pBuf + _bufferedCount - 64;
                }
                else
                {
                    byte* tempTail = stackalloc byte[64];
                    int prefixLen = 64 - _bufferedCount;
                    new ReadOnlySpan<byte>(pBuf + XxHash3Constants.InternalBufferLengthBytes - prefixLen, prefixLen).CopyTo(new Span<byte>(tempTail, prefixLen));
                    new ReadOnlySpan<byte>(pBuf, _bufferedCount).CopyTo(new Span<byte>(tempTail + prefixLen, _bufferedCount));
                    tailStripe = tempTail;
                }

                // Overlapping tail stripe
                AccumulateSingleStripe(pCloned, tailStripe, pSec + 121);

                if (_hashSize == 8)
                {
                    ulong h64 = XxHash3.MergeAccumulators64(pCloned, pSec + XxHash3Constants.SecretMergeAccsStartBytes, _totalLength * XxHash3Constants.Prime64_1);
                    BinaryPrimitives.WriteUInt64LittleEndian(destination, h64);
                }
                else
                {
                    ulong low = XxHash3.MergeAccumulators64(pCloned, pSec + XxHash3Constants.SecretMergeAccsStartBytes, _totalLength * XxHash3Constants.Prime64_1);
                    ulong high = XxHash3.MergeAccumulators64(pCloned, pSec + (XxHash3Constants.SecretLengthBytes - XxHash3Constants.StripeLengthBytes - XxHash3Constants.SecretMergeAccsStartBytes), ~(_totalLength * XxHash3Constants.Prime64_2));
                    BinaryPrimitives.WriteUInt64LittleEndian(destination, low);
                    BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), high);
                }
            }
        }
    }

    public void Finalize(Span<byte> destination)
    {
        GetCurrentHash(destination);
        Reset();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            fixed (byte* pBuf = _buffer.Data)
            fixed (ulong* pAcc = _acc.Data)
            fixed (byte* pSec = _secret.Data)
            {
                CryptographicOperations.ZeroMemory(new Span<byte>(pBuf, XxHash3Constants.InternalBufferLengthBytes));
                CryptographicOperations.ZeroMemory(new Span<byte>(pAcc, XxHash3Constants.AccumulatorCount * sizeof(ulong)));
                CryptographicOperations.ZeroMemory(new Span<byte>(pSec, XxHash3Constants.SecretLengthBytes));
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }
}
