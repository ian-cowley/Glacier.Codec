namespace Glacier.Codec.Hashing.Blake3;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hardware;
using Glacier.Codec.Memory;

/// <summary>
/// Zero-allocation, high-throughput BLAKE3 cryptographic hasher implementing <see cref="IKeyedHasher"/>.
/// Manages 1024-byte chunk parallelization, O(1) stack Merkle tree reduction, Keyed MAC, KDF, and XOF modes.
/// Fully accelerated with AVX-512 16-way and AVX2 8-way vector compression kernels and multi-core parallel tree reduction.
/// </summary>
public sealed unsafe class Blake3Hasher : IKeyedHasher
{
    private struct Key8 { public fixed uint Data[8]; }
    private struct ChunkCv8 { public fixed uint Data[8]; }
    private struct BlockBuffer64 { public fixed byte Data[64]; }
    private struct CvStack54 { public fixed uint Data[Blake3Constants.MaxTreeDepth * 8]; }

#pragma warning disable CS0169
    private Key8 _key;
    private ChunkCv8 _chunkCv;
    private BlockBuffer64 _blockBuffer;
    private CvStack54 _cvStack;
#pragma warning restore CS0169

    private ulong _chunkCounter;
    private byte _blockLength;
    private byte _blocksCompressed;
    private byte _cvStackDepth;
    private Blake3Flags _flags;
    private bool _disposed;

    public int HashSizeInBytes => Blake3Constants.DefaultHashSize;

    public Blake3Hasher()
    {
        fixed (uint* k = _key.Data)
        fixed (uint* iv = Blake3Constants.IV)
            Buffer.MemoryCopy(iv, k, 32, 32);
        _flags = Blake3Flags.None;
        Reset();
    }

    public Blake3Hasher(ReadOnlySpan<byte> key) => SetKey(key);

    public void SetKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        if (key.Length != Blake3Constants.KeySize)
            throw new ArgumentException($"BLAKE3 key must be exactly {Blake3Constants.KeySize} bytes.", nameof(key));

        fixed (uint* k = _key.Data)
        {
            for (int i = 0; i < 8; i++)
                k[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        }

        _flags |= Blake3Flags.KeyedHash;
        Reset();
    }

    public void Reset()
    {
        ThrowIfDisposed();
        fixed (uint* cv = _chunkCv.Data)
        fixed (uint* k = _key.Data)
            Buffer.MemoryCopy(k, cv, 32, 32);

        fixed (byte* buf = _blockBuffer.Data)
            new Span<byte>(buf, 64).Clear();

        _chunkCounter = 0;
        _blockLength = 0;
        _blocksCompressed = 0;
        _cvStackDepth = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        fixed (uint* cv = _chunkCv.Data)
        fixed (byte* buf = _blockBuffer.Data)
        fixed (uint* k = _key.Data)
        {
            // Vector chunk batching fast path: when aligned at a chunk boundary
            if (_blockLength == 0 && _blocksCompressed == 0 && data.Length > Blake3Constants.ChunkSize)
            {
                // In BLAKE3, leave at least 1 byte in stream to ensure final chunk is handled during Finalize
                int safeFullChunks = (data.Length - 1) / Blake3Constants.ChunkSize;
                fixed (byte* pData = data)
                {
                    int chunkOffset = 0;
                    if (Blake3KernelAvx512.IsSupported)
                    {
                        Span<byte> outCvs16 = stackalloc byte[16 * 32];
                        fixed (byte* pCvs = outCvs16)
                        {
                            while (safeFullChunks >= 16)
                            {
                                Blake3KernelAvx512.Hash16Chunks(pData + chunkOffset, _chunkCounter, k, (uint)_flags, pCvs);
                                for (int c = 0; c < 16; c++)
                                {
                                    Buffer.MemoryCopy(pCvs + (c * 32), cv, 32, 32);
                                    _chunkCounter++;
                                    PushChunkCvToStack();
                                }
                                Buffer.MemoryCopy(k, cv, 32, 32);
                                chunkOffset += 16 * Blake3Constants.ChunkSize;
                                safeFullChunks -= 16;
                            }
                        }
                    }

                    if (Blake3KernelAvx2.IsSupported)
                    {
                        Span<byte> outCvs8 = stackalloc byte[8 * 32];
                        fixed (byte* pCvs = outCvs8)
                        {
                            while (safeFullChunks >= 8)
                            {
                                Blake3KernelAvx2.Hash8Chunks(pData + chunkOffset, _chunkCounter, k, (uint)_flags, pCvs);
                                for (int c = 0; c < 8; c++)
                                {
                                    Buffer.MemoryCopy(pCvs + (c * 32), cv, 32, 32);
                                    _chunkCounter++;
                                    PushChunkCvToStack();
                                }
                                Buffer.MemoryCopy(k, cv, 32, 32);
                                chunkOffset += 8 * Blake3Constants.ChunkSize;
                                safeFullChunks -= 8;
                            }
                        }
                    }

                    if (chunkOffset > 0)
                        data = data.Slice(chunkOffset);
                }
            }

            // Standard block streaming
            while (data.Length > 0)
            {
                if (_blockLength == 64)
                {
                    uint flags = (uint)_flags;
                    if (_blocksCompressed == 0) flags |= (uint)Blake3Flags.ChunkStart;

                    if (_blocksCompressed == 15)
                    {
                        flags |= (uint)Blake3Flags.ChunkEnd;
                        Blake3KernelScalar.CompressBlock(cv, buf, _chunkCounter++, 64, flags, cv);
                        PushChunkCvToStack();
                        Buffer.MemoryCopy(k, cv, 32, 32);
                        _blocksCompressed = 0;
                    }
                    else
                    {
                        Blake3KernelScalar.CompressBlock(cv, buf, _chunkCounter, 64, flags, cv);
                        _blocksCompressed++;
                    }
                    _blockLength = 0;
                }

                int want = 64 - _blockLength;
                int take = Math.Min(want, data.Length);
                data.Slice(0, take).CopyTo(new Span<byte>(buf + _blockLength, take));
                _blockLength += (byte)take;
                data = data.Slice(take);
            }
        }
    }

    private void PushChunkCvToStack()
    {
        ulong totalChunks = _chunkCounter;
        Span<uint> currentCv = stackalloc uint[8];
        fixed (uint* cv = _chunkCv.Data)
            for (int i = 0; i < 8; i++) currentCv[i] = cv[i];

        fixed (uint* stack = _cvStack.Data)
        fixed (uint* key = _key.Data)
        {
            Span<byte> parentBlock = stackalloc byte[64];
            while ((totalChunks & 1) == 0 && _cvStackDepth > 0)
            {
                _cvStackDepth--;
                uint* leftCv = stack + (_cvStackDepth * 8);
                fixed (byte* pBlock = parentBlock)
                {
                    Buffer.MemoryCopy(leftCv, pBlock, 32, 32);
                    fixed (uint* cCv = currentCv)
                    {
                        Buffer.MemoryCopy(cCv, pBlock + 32, 32, 32);
                        Blake3KernelScalar.CompressBlock(key, pBlock, 0, 64, (uint)_flags | (uint)Blake3Flags.Parent, cCv);
                    }
                }
                totalChunks >>= 1;
            }

            fixed (uint* cCv = currentCv)
                Buffer.MemoryCopy(cCv, stack + (_cvStackDepth * 8), 32, 32);
        }
        _cvStackDepth++;
    }

    public void GetCurrentHash(Span<byte> destination) => FinalizeSeek(0, destination);

    public void Finalize(Span<byte> destination)
    {
        FinalizeSeek(0, destination);
        Reset();
    }

    public void FinalizeSeek(ulong seekOffset, Span<byte> destination)
    {
        ThrowIfDisposed();
        if (destination.Length == 0) return;

        fixed (uint* cv = _chunkCv.Data)
        fixed (byte* block = _blockBuffer.Data)
        fixed (uint* key = _key.Data)
        fixed (uint* stack = _cvStack.Data)
        {
            if (_cvStackDepth == 0)
            {
                uint flags = (uint)_flags | (uint)(Blake3Flags.ChunkEnd | Blake3Flags.Root);
                if (_blocksCompressed == 0) flags |= (uint)Blake3Flags.ChunkStart;
                EmitRootOutput(cv, block, _chunkCounter, _blockLength, flags, seekOffset, destination);
                return;
            }

            uint tailFlags = (uint)_flags | (uint)Blake3Flags.ChunkEnd;
            if (_blocksCompressed == 0) tailFlags |= (uint)Blake3Flags.ChunkStart;

            Span<uint> currentCv = stackalloc uint[8];
            fixed (uint* cCv = currentCv)
                Blake3KernelScalar.CompressBlock(cv, block, _chunkCounter, _blockLength, tailFlags, cCv);

            Span<byte> parentBlock = stackalloc byte[64];
            for (int i = _cvStackDepth - 1; i >= 0; i--)
            {
                bool isRoot = (i == 0);
                uint pFlags = (uint)_flags | (uint)Blake3Flags.Parent | (isRoot ? (uint)Blake3Flags.Root : 0);

                uint* leftCv = stack + (i * 8);
                fixed (byte* pBlock = parentBlock)
                {
                    Buffer.MemoryCopy(leftCv, pBlock, 32, 32);
                    fixed (uint* cCv = currentCv)
                        Buffer.MemoryCopy(cCv, pBlock + 32, 32, 32);

                    if (isRoot)
                    {
                        EmitRootOutput(key, pBlock, 0, 64, pFlags, seekOffset, destination);
                        return;
                    }

                    fixed (uint* cCv = currentCv)
                        Blake3KernelScalar.CompressBlock(key, pBlock, 0, 64, pFlags, cCv);
                }
            }
        }
    }

    internal static void EmitRootOutput(
        uint* cv, byte* block, ulong counter, uint blockLen, uint flags, ulong seekOffset, Span<byte> destination)
    {
        ulong blockIndex = seekOffset / 64;
        int blockOffset = (int)(seekOffset % 64);
        int destOffset = 0;
        Span<byte> outputBlock = stackalloc byte[64];

        while (destOffset < destination.Length)
        {
            fixed (byte* ob = outputBlock)
                Blake3KernelScalar.CompressBlock64(cv, block, counter + blockIndex, blockLen, flags, ob);

            int available = 64 - blockOffset;
            int toCopy = Math.Min(available, destination.Length - destOffset);
            outputBlock.Slice(blockOffset, toCopy).CopyTo(destination.Slice(destOffset, toCopy));

            destOffset += toCopy;
            blockOffset = 0;
            blockIndex++;
        }
    }

    public static Blake3Hasher CreateKeyDerivation(string context)
    {
        ArgumentNullException.ThrowIfNull(context);
        int maxBytes = System.Text.Encoding.UTF8.GetMaxByteCount(context.Length);
        Span<byte> ctxStack = maxBytes <= 256 ? stackalloc byte[maxBytes] : new byte[maxBytes];
        int written = System.Text.Encoding.UTF8.GetBytes(context, ctxStack);
        ReadOnlySpan<byte> ctxBytes = ctxStack.Slice(0, written);

        Span<byte> contextKey = stackalloc byte[Blake3Constants.KeySize];
        fixed (uint* iv = Blake3Constants.IV)
            HashInternal(iv, ctxBytes, (uint)Blake3Flags.DeriveKeyContext, 0, contextKey);

        var kdfHasher = new Blake3Hasher(contextKey);
        kdfHasher._flags = Blake3Flags.DeriveKeyMaterial;
        return kdfHasher;
    }

    /// <summary>
    /// Computes the BLAKE3 hash of <paramref name="input"/> into <paramref name="destination"/>.
    /// Guaranteed strictly ZERO heap allocations in steady-state one-shot hashing.
    /// Workloads &gt;= 1 MB automatically route to multi-threaded parallel tree reduction.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        if (destination.Length < Blake3Constants.DefaultHashSize)
            throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));

        ExecutionTarget target = HardwareArbiter.RouteWorkload(input.Length, gpuAvailable: false);
        if ((target is ExecutionTarget.CpuParallelPool or ExecutionTarget.GpuCompute) && input.Length >= 1024 * 1024 && Environment.ProcessorCount > 1)
        {
            HashParallel(input, destination);
            return;
        }

        fixed (uint* iv = Blake3Constants.IV)
            HashInternal(iv, input, (uint)Blake3Flags.None, 0, destination);
    }

    /// <summary>
    /// Computes the keyed BLAKE3 MAC of <paramref name="input"/> using <paramref name="key"/>.
    /// Strictly zero heap allocations in steady-state.
    /// Workloads &gt;= 1 MB automatically route to multi-threaded parallel tree reduction.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void HashKeyed(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, Span<byte> destination)
    {
        if (destination.Length < Blake3Constants.DefaultHashSize)
            throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));
        if (key.Length != Blake3Constants.KeySize)
            throw new ArgumentException($"BLAKE3 key must be exactly {Blake3Constants.KeySize} bytes.", nameof(key));

        Span<uint> keyWords = stackalloc uint[8];
        for (int i = 0; i < 8; i++)
            keyWords[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));

        fixed (uint* pKey = keyWords)
        {
            ExecutionTarget target = HardwareArbiter.RouteWorkload(input.Length, gpuAvailable: false);
            if ((target is ExecutionTarget.CpuParallelPool or ExecutionTarget.GpuCompute) && input.Length >= 1024 * 1024 && Environment.ProcessorCount > 1)
            {
                HashParallelCore(pKey, input, (uint)Blake3Flags.KeyedHash, destination);
                return;
            }

            HashInternal(pKey, input, (uint)Blake3Flags.KeyedHash, 0, destination);
        }
    }

    private static void HashInternal(
        uint* key, ReadOnlySpan<byte> input, uint flags, ulong seekOffset, Span<byte> destination)
    {
        if (input.Length <= Blake3Constants.ChunkSize)
        {
            HashSingleChunkStack(key, input, flags, seekOffset, destination);
            return;
        }

        HashMultiChunkStack(key, input, flags, seekOffset, destination);
    }

    private static void HashSingleChunkStack(
        uint* key, ReadOnlySpan<byte> input, uint flags, ulong seekOffset, Span<byte> destination)
    {
        fixed (byte* pInput = input)
        {
            Span<uint> runningCv = stackalloc uint[8];
            for (int i = 0; i < 8; i++) runningCv[i] = key[i];

            int totalLen = input.Length;
            int numBlocks = Math.Max(1, (totalLen + 63) / 64);

            fixed (uint* pCv = runningCv)
            {
                Span<byte> blockBuf = stackalloc byte[64];
                fixed (byte* pBuf = blockBuf)
                {
                    for (int b = 0; b < numBlocks; b++)
                    {
                        int blockOffset = b * 64;
                        int blockLen = Math.Min(64, totalLen - blockOffset);

                        uint blockFlags = flags;
                        if (b == 0) blockFlags |= (uint)Blake3Flags.ChunkStart;
                        if (b == numBlocks - 1) blockFlags |= (uint)(Blake3Flags.ChunkEnd | Blake3Flags.Root);

                        byte* blockPtr = blockLen == 64 ? pInput + blockOffset : pBuf;
                        if (blockLen < 64)
                        {
                            blockBuf.Clear();
                            if (blockLen > 0) Buffer.MemoryCopy(pInput + blockOffset, pBuf, 64, blockLen);
                        }

                        if (b == numBlocks - 1)
                        {
                            EmitRootOutput(pCv, blockPtr, 0, (uint)blockLen, blockFlags, seekOffset, destination);
                            return;
                        }

                        Blake3KernelScalar.CompressBlock(pCv, blockPtr, 0, (uint)blockLen, blockFlags, pCv);
                    }
                }
            }
        }
    }

    private static void HashMultiChunkStack(
        uint* key, ReadOnlySpan<byte> input, uint flags, ulong seekOffset, Span<byte> destination)
    {
        Span<uint> cvStack = stackalloc uint[Blake3Constants.MaxTreeDepth * 8];
        Span<uint> currentCv = stackalloc uint[8];
        Span<byte> parentBlock = stackalloc byte[64];
        Span<byte> blockBuf = stackalloc byte[64];

        fixed (uint* pStack = cvStack, pCur = currentCv)
        fixed (byte* pParent = parentBlock, pBuf = blockBuf, pInput = input)
        {
            int stackDepth = 0;
            ulong chunkCounter = 0;
            int fullChunks = input.Length / Blake3Constants.ChunkSize;
            int remainingBytes = input.Length % Blake3Constants.ChunkSize;

            for (int c = 0; c < fullChunks; c++)
            {
                if (c == fullChunks - 1 && remainingBytes == 0) break;

                byte* chunk = pInput + (c * Blake3Constants.ChunkSize);
                for (int i = 0; i < 8; i++) pCur[i] = key[i];

                for (int b = 0; b < 16; b++)
                {
                    uint bFlags = flags;
                    if (b == 0) bFlags |= (uint)Blake3Flags.ChunkStart;
                    if (b == 15) bFlags |= (uint)Blake3Flags.ChunkEnd;
                    Blake3KernelScalar.CompressBlock(pCur, chunk + (b * 64), (ulong)c, 64, bFlags, pCur);
                }

                chunkCounter++;
                ulong totalChunks = chunkCounter;
                while ((totalChunks & 1) == 0 && stackDepth > 0)
                {
                    stackDepth--;
                    Buffer.MemoryCopy(pStack + (stackDepth * 8), pParent, 32, 32);
                    Buffer.MemoryCopy(pCur, pParent + 32, 32, 32);
                    Blake3KernelScalar.CompressBlock(key, pParent, 0, 64, flags | (uint)Blake3Flags.Parent, pCur);
                    totalChunks >>= 1;
                }
                Buffer.MemoryCopy(pCur, pStack + (stackDepth * 8), 32, 32);
                stackDepth++;
            }

            int finalChunkIdx = remainingBytes == 0 ? fullChunks - 1 : fullChunks;
            int finalChunkOffset = finalChunkIdx * Blake3Constants.ChunkSize;
            int finalChunkLen = remainingBytes == 0 ? Blake3Constants.ChunkSize : remainingBytes;

            byte* finalChunk = pInput + finalChunkOffset;
            for (int i = 0; i < 8; i++) pCur[i] = key[i];

            int numBlocks = Math.Max(1, (finalChunkLen + 63) / 64);
            for (int b = 0; b < numBlocks; b++)
            {
                int blockOffset = b * 64;
                int blockLen = Math.Min(64, finalChunkLen - blockOffset);
                uint bFlags = flags;
                if (b == 0) bFlags |= (uint)Blake3Flags.ChunkStart;
                if (b == numBlocks - 1) bFlags |= (uint)Blake3Flags.ChunkEnd;

                byte* blockPtr = blockLen == 64 ? finalChunk + blockOffset : pBuf;
                if (blockLen < 64)
                {
                    blockBuf.Clear();
                    Buffer.MemoryCopy(finalChunk + blockOffset, pBuf, 64, blockLen);
                }
                Blake3KernelScalar.CompressBlock(pCur, blockPtr, (ulong)finalChunkIdx, (uint)blockLen, bFlags, pCur);
            }

            for (int i = stackDepth - 1; i >= 0; i--)
            {
                bool isRoot = (i == 0);
                uint pFlags = flags | (uint)Blake3Flags.Parent | (isRoot ? (uint)Blake3Flags.Root : 0);
                Buffer.MemoryCopy(pStack + (i * 8), pParent, 32, 32);
                Buffer.MemoryCopy(pCur, pParent + 32, 32, 32);

                if (isRoot)
                {
                    EmitRootOutput(key, pParent, 0, 64, pFlags, seekOffset, destination);
                    return;
                }
                Blake3KernelScalar.CompressBlock(key, pParent, 0, 64, pFlags, pCur);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HashParallel(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        fixed (uint* iv = Blake3Constants.IV)
            Blake3ParallelEngine.HashParallel(iv, input, (uint)Blake3Flags.None, destination);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HashParallelCore(uint* key, ReadOnlySpan<byte> input, uint flags, Span<byte> destination)
    {
        Blake3ParallelEngine.HashParallel(key, input, flags, destination);
    }


    public void Dispose()
    {
        if (_disposed) return;
        fixed (uint* k = _key.Data)
        fixed (uint* cv = _chunkCv.Data)
        fixed (byte* buf = _blockBuffer.Data)
        fixed (uint* stack = _cvStack.Data)
        {
            CryptographicOperations.ZeroMemory(new Span<byte>(k, 32));
            CryptographicOperations.ZeroMemory(new Span<byte>(cv, 32));
            CryptographicOperations.ZeroMemory(new Span<byte>(buf, 64));
            CryptographicOperations.ZeroMemory(new Span<byte>(stack, Blake3Constants.MaxTreeDepth * 8 * 4));
        }
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, typeof(Blake3Hasher));
    }
}
