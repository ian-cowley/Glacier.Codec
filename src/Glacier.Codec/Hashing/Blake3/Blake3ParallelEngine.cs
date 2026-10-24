namespace Glacier.Codec.Hashing.Blake3;

using System;
using System.Runtime.CompilerServices;
using System.Threading;
using Glacier.Codec.Memory;

/// <summary>
/// Zero-allocation high-performance parallel execution engine for BLAKE3.
/// Maintains dedicated persistent worker threads and vectorized Merkle tree reduction.
/// </summary>
internal static unsafe class Blake3ParallelEngine
{
    private static readonly int s_workerCount = Math.Max(1, Environment.ProcessorCount);
    private static readonly Thread[] s_threads = new Thread[s_workerCount - 1];
    private static readonly ManualResetEventSlim[] s_startEvents = new ManualResetEventSlim[s_workerCount - 1];
    private static readonly CountdownEvent s_doneEvent = new(s_workerCount - 1);
    private static readonly WorkerState[] s_workerStates = new WorkerState[s_workerCount];
    private static readonly object s_dispatchLock = new();
    private static volatile bool s_shutdown;

    private struct WorkerState
    {
        public byte* Input;
        public uint* Key;
        public byte* Cvs;
        public int StartBatch;
        public int BatchCount;
        public int BatchSize;
        public uint Flags;
    }

    static Blake3ParallelEngine()
    {
        for (int i = 0; i < s_workerCount - 1; i++)
        {
            s_startEvents[i] = new ManualResetEventSlim(false);
            int threadIndex = i + 1;
            s_threads[i] = new Thread(() => WorkerLoop(threadIndex))
            {
                IsBackground = true,
                Name = $"Blake3ParallelWorker-{threadIndex}",
                Priority = ThreadPriority.AboveNormal
            };
            s_threads[i].Start();
        }

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            s_shutdown = true;
            for (int i = 0; i < s_workerCount - 1; i++)
            {
                s_startEvents[i]?.Set();
            }
        };
    }

    private static void WorkerLoop(int workerIndex)
    {
        int eventIdx = workerIndex - 1;
        while (!s_shutdown)
        {
            s_startEvents[eventIdx].Wait();
            s_startEvents[eventIdx].Reset();
            if (s_shutdown) break;

            try
            {
                ref var state = ref s_workerStates[workerIndex];
                ExecuteBatches(state.Input, state.Key, state.Cvs, state.StartBatch, state.BatchCount, state.BatchSize, state.Flags);
            }
            finally
            {
                s_doneEvent.Signal();
            }
        }
    }

    public static void HashParallel(uint* key, ReadOnlySpan<byte> input, uint flags, Span<byte> destination)
    {
        int totalChunks = (input.Length + Blake3Constants.ChunkSize - 1) / Blake3Constants.ChunkSize;
        int fullChunks = input.Length / Blake3Constants.ChunkSize;
        bool hasPartialChunk = (input.Length % Blake3Constants.ChunkSize) != 0;

        int cvsBytes = totalChunks * 32;
        using var lease = UnmanagedSlabPool.Shared.Rent(cvsBytes);
        byte* pCvs = (byte*)lease.Pointer;

        fixed (byte* pInput = input)
        {
            int batchSize = 1;
            if (Blake3KernelAvx512.IsSupported) batchSize = 16;
            else if (Blake3KernelAvx2.IsSupported) batchSize = 8;

            int fullBatches = fullChunks / batchSize;
            int chunksHandledByBatches = fullBatches * batchSize;

            int activeWorkers = Math.Min(s_workerCount, fullBatches);
            if (activeWorkers <= 1)
            {
                ExecuteBatches(pInput, key, pCvs, 0, fullBatches, batchSize, flags);
            }
            else
            {
                lock (s_dispatchLock)
                {
                    int batchesPerWorker = fullBatches / activeWorkers;
                    int extraBatches = fullBatches % activeWorkers;
                    int currentBatch = 0;

                    int w0Count = batchesPerWorker + (extraBatches > 0 ? 1 : 0);
                    currentBatch += w0Count;

                    s_doneEvent.Reset(activeWorkers - 1);
                    for (int w = 1; w < activeWorkers; w++)
                    {
                        int count = batchesPerWorker + (w < extraBatches ? 1 : 0);
                        s_workerStates[w].Input = pInput;
                        s_workerStates[w].Key = key;
                        s_workerStates[w].Cvs = pCvs;
                        s_workerStates[w].StartBatch = currentBatch;
                        s_workerStates[w].BatchCount = count;
                        s_workerStates[w].BatchSize = batchSize;
                        s_workerStates[w].Flags = flags;
                        currentBatch += count;

                        s_startEvents[w - 1].Set();
                    }

                    // Worker 0 executes on calling thread
                    ExecuteBatches(pInput, key, pCvs, 0, w0Count, batchSize, flags);

                    s_doneEvent.Wait();
                }
            }

            // Remainder scalar chunk processing if any
            if (chunksHandledByBatches < fullChunks || hasPartialChunk)
            {
                ProcessRemainingChunks(pInput, key, pCvs, input.Length, fullChunks, chunksHandledByBatches, hasPartialChunk, flags);
            }

            // High-Performance Parallel / Vectorized Merkle Tree Reduction
            ReduceTree(pCvs, totalChunks, key, flags, destination);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteBatches(
        byte* input, uint* key, byte* cvs, int startBatch, int batchCount, int batchSize, uint flags)
    {
        int end = startBatch + batchCount;
        for (int b = startBatch; b < end; b++)
        {
            int chunkStart = b * batchSize;
            byte* chunkPtr = input + (chunkStart * Blake3Constants.ChunkSize);
            byte* cvPtr = cvs + (chunkStart * 32);

            if (batchSize == 16)
                Blake3KernelAvx512.Hash16Chunks(chunkPtr, (ulong)chunkStart, key, flags, cvPtr);
            else if (batchSize == 8)
                Blake3KernelAvx2.Hash8Chunks(chunkPtr, (ulong)chunkStart, key, flags, cvPtr);
            else
                ExecuteBatchScalar(chunkPtr, (ulong)chunkStart, key, flags, cvPtr);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteBatchScalar(byte* chunkPtr, ulong chunkStart, uint* key, uint flags, byte* cvPtr)
    {
        Span<uint> runCv = stackalloc uint[8];
        fixed (uint* pCv = runCv)
        {
            for (int i = 0; i < 8; i++) pCv[i] = key[i];
            for (int blk = 0; blk < 16; blk++)
            {
                uint bFlags = flags;
                if (blk == 0) bFlags |= (uint)Blake3Flags.ChunkStart;
                if (blk == 15) bFlags |= (uint)Blake3Flags.ChunkEnd;

                byte* blkPtr = chunkPtr + (blk * 64);
                uint* outTarget = (blk == 15) ? (uint*)cvPtr : pCv;
                Blake3KernelScalar.CompressBlock(pCv, blkPtr, chunkStart, 64, bFlags, outTarget);
            }
        }
    }

    private static void ProcessRemainingChunks(
        byte* pInput, uint* key, byte* pCvs, int inputLength, int fullChunks, int handled, bool hasPartial, uint flags)
    {
        Span<uint> runningCv = stackalloc uint[8];
        fixed (uint* pCv = runningCv)
        {
            for (int c = handled; c < fullChunks; c++)
            {
                byte* chunk = pInput + (c * Blake3Constants.ChunkSize);
                for (int i = 0; i < 8; i++) runningCv[i] = key[i];
                for (int b = 0; b < 16; b++)
                {
                    uint blockFlags = flags;
                    if (b == 0) blockFlags |= (uint)Blake3Flags.ChunkStart;
                    if (b == 15) blockFlags |= (uint)Blake3Flags.ChunkEnd;
                    uint* outTarget = (b == 15) ? (uint*)(pCvs + (c * 32)) : pCv;
                    Blake3KernelScalar.CompressBlock(pCv, chunk + (b * 64), (ulong)c, 64, blockFlags, outTarget);
                }
            }

            if (hasPartial)
            {
                int totalChunks = (inputLength + Blake3Constants.ChunkSize - 1) / Blake3Constants.ChunkSize;
                int lastChunkIdx = totalChunks - 1;
                int lastChunkOffset = lastChunkIdx * Blake3Constants.ChunkSize;
                int lastChunkLen = inputLength - lastChunkOffset;
                byte* chunk = pInput + lastChunkOffset;
                ulong counter = (ulong)lastChunkIdx;
                uint* cvDst = (uint*)(pCvs + (lastChunkIdx * 32));

                int numBlocks = Math.Max(1, (lastChunkLen + 63) / 64);
                for (int i = 0; i < 8; i++) runningCv[i] = key[i];

                Span<byte> blockBuf = stackalloc byte[64];
                fixed (byte* pBuf = blockBuf)
                {
                    for (int b = 0; b < numBlocks; b++)
                    {
                        int blockOffset = b * 64;
                        int blockLen = Math.Min(64, lastChunkLen - blockOffset);

                        uint blockFlags = flags;
                        if (b == 0) blockFlags |= (uint)Blake3Flags.ChunkStart;
                        if (b == numBlocks - 1) blockFlags |= (uint)Blake3Flags.ChunkEnd;

                        byte* blockPtr = blockLen == 64 ? chunk + blockOffset : pBuf;
                        if (blockLen < 64)
                        {
                            blockBuf.Clear();
                            Buffer.MemoryCopy(chunk + blockOffset, pBuf, 64, blockLen);
                        }

                        uint* outTarget = (b == numBlocks - 1) ? cvDst : pCv;
                        Blake3KernelScalar.CompressBlock(pCv, blockPtr, counter, (uint)blockLen, blockFlags, outTarget);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Reduces the array of chaining values into root digest.
    /// Uses fast in-place vectorized reduction for power-of-two subtrees.
    /// </summary>
    public static void ReduceTree(byte* cvs, int count, uint* key, uint flags, Span<byte> destination)
    {
        if (count == 1)
        {
            new Span<byte>(cvs, 32).CopyTo(destination);
            return;
        }

        // Fast path: Exact power-of-two chunk count (e.g., 16 MB = 16384, 64 MB = 65536)
        if ((count & (count - 1)) == 0)
        {
            ReducePowerOfTwoTree(cvs, count, key, flags, destination);
            return;
        }

        // General path for non-power-of-two lengths: Standard BLAKE3 Merkle Stack
        ReduceArbitraryTree(cvs, count, key, flags, destination);
    }

    private static void ReducePowerOfTwoTree(byte* cvs, int count, uint* key, uint flags, Span<byte> destination)
    {
        int currentCount = count;
        uint parentFlags = flags | (uint)Blake3Flags.Parent;

        while (currentCount > 2)
        {
            int parentBlocks = currentCount / 2;

            if (Blake3KernelAvx512.IsSupported && parentBlocks >= 16)
            {
                int full16 = parentBlocks / 16;
                for (int i = 0; i < full16; i++)
                {
                    byte* inPtr = cvs + (i * 16 * 64);
                    byte* outPtr = cvs + (i * 16 * 32);
                    Blake3KernelAvx512.Compress16Parents(inPtr, key, parentFlags, outPtr);
                }

                int remainder = parentBlocks % 16;
                int remStart = full16 * 16;
                for (int i = 0; i < remainder; i++)
                {
                    int p = remStart + i;
                    Blake3KernelScalar.CompressBlock(key, cvs + (p * 64), 0, 64, parentFlags, (uint*)(cvs + (p * 32)));
                }
            }
            else if (Blake3KernelAvx2.IsSupported && parentBlocks >= 8)
            {
                int full8 = parentBlocks / 8;
                for (int i = 0; i < full8; i++)
                {
                    byte* inPtr = cvs + (i * 8 * 64);
                    byte* outPtr = cvs + (i * 8 * 32);
                    Blake3KernelAvx2.Compress8Parents(inPtr, key, parentFlags, outPtr);
                }

                int remainder = parentBlocks % 8;
                int remStart = full8 * 8;
                for (int i = 0; i < remainder; i++)
                {
                    int p = remStart + i;
                    Blake3KernelScalar.CompressBlock(key, cvs + (p * 64), 0, 64, parentFlags, (uint*)(cvs + (p * 32)));
                }
            }
            else
            {
                for (int p = 0; p < parentBlocks; p++)
                {
                    Blake3KernelScalar.CompressBlock(key, cvs + (p * 64), 0, 64, parentFlags, (uint*)(cvs + (p * 32)));
                }
            }

            currentCount = parentBlocks;
        }

        // Final 2 chaining values: Compress with Root flag
        uint rootFlags = flags | (uint)Blake3Flags.Parent | (uint)Blake3Flags.Root;
        Blake3Hasher.EmitRootOutput(key, cvs, 0, 64, rootFlags, 0, destination);
    }

    private static void ReduceArbitraryTree(byte* cvs, int count, uint* key, uint flags, Span<byte> destination)
    {
        Span<uint> stack = stackalloc uint[Blake3Constants.MaxTreeDepth * 8];
        Span<byte> parentBlock = stackalloc byte[64];
        Span<uint> currentCv = stackalloc uint[8];
        fixed (uint* pStack = stack, pCur = currentCv)
        fixed (byte* pParent = parentBlock)
        {
            int stackDepth = 0;
            for (int c = 0; c < count - 1; c++)
            {
                Buffer.MemoryCopy(cvs + (c * 32), pCur, 32, 32);
                ulong totalChunks = (ulong)(c + 1);
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

            Buffer.MemoryCopy(cvs + ((count - 1) * 32), pCur, 32, 32);
            for (int i = stackDepth - 1; i >= 0; i--)
            {
                bool isRoot = (i == 0);
                uint pFlags = flags | (uint)Blake3Flags.Parent | (isRoot ? (uint)Blake3Flags.Root : 0);
                Buffer.MemoryCopy(pStack + (i * 8), pParent, 32, 32);
                Buffer.MemoryCopy(pCur, pParent + 32, 32, 32);

                if (isRoot)
                {
                    Blake3Hasher.EmitRootOutput(key, pParent, 0, 64, pFlags, 0, destination);
                    return;
                }
                Blake3KernelScalar.CompressBlock(key, pParent, 0, 64, pFlags, pCur);
            }
        }
    }
}
