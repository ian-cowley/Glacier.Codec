namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Threading;
using Glacier.Codec.Hardware;

/// <summary>
/// Zero-allocation, high-performance parallel execution engine for AES-256-GCM.
/// Distributes CTR mode keystream generation and GF(2^128) carryless multiplication across
/// persistent worker threads to achieve &gt; 10.0 GB/s wire speed on VAES hardware.
/// </summary>
internal static unsafe class AesGcmParallelEngine
{
    private static readonly int s_workerCount = Math.Clamp(Environment.ProcessorCount, 1, 16);
    private static readonly Thread[] s_threads = new Thread[s_workerCount - 1];
    private static readonly ManualResetEventSlim[] s_startEvents = new ManualResetEventSlim[s_workerCount - 1];
    private static readonly CountdownEvent s_doneEvent = new(s_workerCount - 1);
    private static readonly WorkerState[] s_workerStates = new WorkerState[s_workerCount];
    private static readonly object s_dispatchLock = new();
    private static volatile bool s_shutdown;

    private struct WorkerState
    {
        public Vector128<byte>* RoundKeys;
        public byte* Input;
        public byte* Output;
        public int Length;
        public uint StartCounter;
        public byte Nonce0, Nonce1, Nonce2, Nonce3, Nonce4, Nonce5, Nonce6, Nonce7, Nonce8, Nonce9, Nonce10, Nonce11;
        public Vector128<ulong> H1, H2, H3, H4;
        public Vector512<ulong> H8to5, H4to1;
        public bool HasV512;
        public ulong InitialYHi;
        public ulong InitialYLo;
        public ulong OutYHi;
        public ulong OutYLo;
        public int Mode; // 1 = Encrypt (CTR then GHASH), 2 = Decrypt GHASH only, 3 = Decrypt CTR only
    }

    static AesGcmParallelEngine()
    {
        for (int i = 0; i < s_workerCount - 1; i++)
        {
            s_startEvents[i] = new ManualResetEventSlim(false);
            int threadIndex = i + 1;
            s_threads[i] = new Thread(() => WorkerLoop(threadIndex))
            {
                IsBackground = true,
                Name = $"AesGcmParallelWorker-{threadIndex}",
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
                ExecuteWorkerJob(ref s_workerStates[workerIndex]);
            }
            finally
            {
                s_doneEvent.Signal();
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExecuteWorkerJob(ref WorkerState state)
    {
        Span<byte> ctr = stackalloc byte[16];
        ctr[0] = state.Nonce0; ctr[1] = state.Nonce1; ctr[2] = state.Nonce2; ctr[3] = state.Nonce3;
        ctr[4] = state.Nonce4; ctr[5] = state.Nonce5; ctr[6] = state.Nonce6; ctr[7] = state.Nonce7;
        ctr[8] = state.Nonce8; ctr[9] = state.Nonce9; ctr[10] = state.Nonce10; ctr[11] = state.Nonce11;
        BinaryPrimitives.WriteUInt32BigEndian(ctr.Slice(12, 4), state.StartCounter);

        if (state.Mode == 1) // Encrypt: CTR then GHASH
        {
            AesGcmKernel.GctrCryptDirect(state.RoundKeys, ctr, state.Input, state.Output, state.Length);
            ulong yHi = state.InitialYHi, yLo = state.InitialYLo;
            ReadOnlySpan<byte> cipherSpan = new(state.Output, state.Length);
            if (state.HasV512)
                AesGcmKernelPclmul512.ProcessBlocks(ref yHi, ref yLo, cipherSpan, state.H8to5, state.H4to1, state.H1, state.H2, state.H3, state.H4);
            else
                AesGcmKernelPclmul.ProcessBlocks(ref yHi, ref yLo, cipherSpan, state.H1, state.H2, state.H3, state.H4);
            state.OutYHi = yHi;
            state.OutYLo = yLo;
        }
        else if (state.Mode == 2) // Decrypt: GHASH + CTR in single pass
        {
            ulong yHi = state.InitialYHi, yLo = state.InitialYLo;
            ReadOnlySpan<byte> cipherSpan = new(state.Input, state.Length);
            if (state.HasV512)
                AesGcmKernelPclmul512.ProcessBlocks(ref yHi, ref yLo, cipherSpan, state.H8to5, state.H4to1, state.H1, state.H2, state.H3, state.H4);
            else
                AesGcmKernelPclmul.ProcessBlocks(ref yHi, ref yLo, cipherSpan, state.H1, state.H2, state.H3, state.H4);
            state.OutYHi = yHi;
            state.OutYLo = yLo;

            AesGcmKernel.GctrCryptDirect(state.RoundKeys, ctr, state.Input, state.Output, state.Length);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> PowH(Vector128<ulong> h1, int power)
    {
        Vector128<ulong> result = h1;
        power--;
        Vector128<ulong> baseVal = h1;
        while (power > 0)
        {
            if ((power & 1) != 0)
                result = AesGcmKernelPclmul.MulOne(result, baseVal);
            baseVal = AesGcmKernelPclmul.MulOne(baseVal, baseVal);
            power >>= 1;
        }
        return result;
    }

    public static void EncryptParallel(
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> hTable,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> j0 = stackalloc byte[16];
        AesGcmKernel.ComputeJ0(nonce, hTable, j0);

        Span<byte> tagMask = stackalloc byte[16];
        AesGcmKernel.EncryptSingleBlock(roundKeys, j0, tagMask);

        uint baseCounter = BinaryPrimitives.ReadUInt32BigEndian(j0.Slice(12, 4)) + 1;

        int totalBytes = plaintext.Length;
        int totalBlocks = (totalBytes + 15) / 16;
        int numWorkers = Math.Min(s_workerCount, totalBlocks / 256);
        if (numWorkers <= 1)
        {
            AesGcmKernel.Encrypt(roundKeys, hTable, nonce, plaintext, ciphertext, tag, associatedData);
            return;
        }

        int chunkBlocks = (totalBlocks / numWorkers / 16) * 16;
        if (chunkBlocks == 0) chunkBlocks = totalBlocks / numWorkers;
        int chunkBytes = chunkBlocks * 16;

        ulong yAadHi = 0, yAadLo = 0;
        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(8, 8));
        var h1 = Vector128.Create(hLo, hHi);
        var h2 = AesGcmKernel.LoadPower(hTable.Slice(16, 16));
        var h3 = AesGcmKernel.LoadPower(hTable.Slice(32, 16));
        var h4 = AesGcmKernel.LoadPower(hTable.Slice(48, 16));
        bool hasV512 = CpuCapabilities.HasVpclmulqdq && hTable.Length >= 128;
        Vector512<ulong> h8to5 = default, h4to1 = default;
        if (hasV512)
        {
            var h5 = AesGcmKernel.LoadPower(hTable.Slice(64, 16));
            var h6 = AesGcmKernel.LoadPower(hTable.Slice(80, 16));
            var h7 = AesGcmKernel.LoadPower(hTable.Slice(96, 16));
            var h8 = AesGcmKernel.LoadPower(hTable.Slice(112, 16));
            h8to5 = Vector512.Create(Vector256.Create(h8, h7), Vector256.Create(h6, h5));
            h4to1 = Vector512.Create(Vector256.Create(h4, h3), Vector256.Create(h2, h1));
        }

        if (associatedData.Length > 0)
        {
            if (hasV512)
                AesGcmKernelPclmul512.ProcessBlocks(ref yAadHi, ref yAadLo, associatedData, h8to5, h4to1, h1, h2, h3, h4);
            else
                AesGcmKernelPclmul.ProcessBlocks(ref yAadHi, ref yAadLo, associatedData, h1, h2, h3, h4);
        }

        Vector128<ulong> yAccum;
        fixed (byte* rkPtr = roundKeys)
        fixed (byte* pPlain = plaintext)
        fixed (byte* pCipher = ciphertext)
        {
            Vector128<byte>* rkVec = (Vector128<byte>*)rkPtr;

            lock (s_dispatchLock)
            {
                s_doneEvent.Reset(numWorkers - 1);

                for (int w = 0; w < numWorkers; w++)
                {
                    int offset = w * chunkBytes;
                    int len = (w == numWorkers - 1) ? totalBytes - offset : chunkBytes;
                    uint ctrStart = baseCounter + (uint)(w * chunkBlocks);

                    ref var st = ref s_workerStates[w];
                    st.RoundKeys = rkVec;
                    st.Input = pPlain + offset;
                    st.Output = pCipher + offset;
                    st.Length = len;
                    st.StartCounter = ctrStart;
                    st.Nonce0 = j0[0]; st.Nonce1 = j0[1]; st.Nonce2 = j0[2]; st.Nonce3 = j0[3];
                    st.Nonce4 = j0[4]; st.Nonce5 = j0[5]; st.Nonce6 = j0[6]; st.Nonce7 = j0[7];
                    st.Nonce8 = j0[8]; st.Nonce9 = j0[9]; st.Nonce10 = j0[10]; st.Nonce11 = j0[11];
                    st.H1 = h1; st.H2 = h2; st.H3 = h3; st.H4 = h4;
                    st.H8to5 = h8to5; st.H4to1 = h4to1;
                    st.HasV512 = hasV512;
                    st.InitialYHi = (w == 0) ? yAadHi : 0;
                    st.InitialYLo = (w == 0) ? yAadLo : 0;
                    st.Mode = 1;

                    if (w > 0)
                    {
                        s_startEvents[w - 1].Set();
                    }
                }

                // Worker 0 runs on calling thread
                ExecuteWorkerJob(ref s_workerStates[0]);

                s_doneEvent.Wait();

                // Combine GHASH results inside lock to prevent state race under concurrency
                Vector128<ulong> hm = PowH(h1, chunkBlocks);
                yAccum = Vector128.Create(s_workerStates[0].OutYLo, s_workerStates[0].OutYHi);

                for (int w = 1; w < numWorkers; w++)
                {
                    int wLen = s_workerStates[w].Length;
                    int wBlocks = (wLen + 15) / 16;
                    Vector128<ulong> mult = (wBlocks == chunkBlocks) ? hm : PowH(h1, wBlocks);
                    yAccum = AesGcmKernelPclmul.MulOne(yAccum, mult) ^ Vector128.Create(s_workerStates[w].OutYLo, s_workerStates[w].OutYHi);
                }
            }
        }

        // Fold lengths and tag mask
        Span<byte> lenBlock = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(0, 8), (ulong)associatedData.Length * 8);
        BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)plaintext.Length * 8);

        ulong yHiFin = yAccum.GetElement(1);
        ulong yLoFin = yAccum.GetElement(0);
        AesGcmKernelPclmul.GhashBlock(ref yHiFin, ref yLoFin, lenBlock, h1);

        Span<byte> computedTag = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(computedTag.Slice(0, 8), yHiFin);
        BinaryPrimitives.WriteUInt64BigEndian(computedTag.Slice(8, 8), yLoFin);

        for (int i = 0; i < 16; i++)
            tag[i] = (byte)(computedTag[i] ^ tagMask[i]);
    }

    public static bool DecryptParallel(
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> hTable,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> expectedTag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> j0 = stackalloc byte[16];
        AesGcmKernel.ComputeJ0(nonce, hTable, j0);

        Span<byte> tagMask = stackalloc byte[16];
        AesGcmKernel.EncryptSingleBlock(roundKeys, j0, tagMask);

        int totalBytes = ciphertext.Length;
        int totalBlocks = (totalBytes + 15) / 16;
        int numWorkers = Math.Min(s_workerCount, totalBlocks / 256);
        if (numWorkers <= 1)
        {
            return AesGcmKernel.Decrypt(roundKeys, hTable, nonce, ciphertext, expectedTag, plaintext, associatedData);
        }

        int chunkBlocks = (totalBlocks / numWorkers / 16) * 16;
        if (chunkBlocks == 0) chunkBlocks = totalBlocks / numWorkers;
        int chunkBytes = chunkBlocks * 16;

        ulong yAadHi = 0, yAadLo = 0;
        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(8, 8));
        var h1 = Vector128.Create(hLo, hHi);
        var h2 = AesGcmKernel.LoadPower(hTable.Slice(16, 16));
        var h3 = AesGcmKernel.LoadPower(hTable.Slice(32, 16));
        var h4 = AesGcmKernel.LoadPower(hTable.Slice(48, 16));
        bool hasV512 = CpuCapabilities.HasVpclmulqdq && hTable.Length >= 128;
        Vector512<ulong> h8to5 = default, h4to1 = default;
        if (hasV512)
        {
            var h5 = AesGcmKernel.LoadPower(hTable.Slice(64, 16));
            var h6 = AesGcmKernel.LoadPower(hTable.Slice(80, 16));
            var h7 = AesGcmKernel.LoadPower(hTable.Slice(96, 16));
            var h8 = AesGcmKernel.LoadPower(hTable.Slice(112, 16));
            h8to5 = Vector512.Create(Vector256.Create(h8, h7), Vector256.Create(h6, h5));
            h4to1 = Vector512.Create(Vector256.Create(h4, h3), Vector256.Create(h2, h1));
        }

        if (associatedData.Length > 0)
        {
            if (hasV512)
                AesGcmKernelPclmul512.ProcessBlocks(ref yAadHi, ref yAadLo, associatedData, h8to5, h4to1, h1, h2, h3, h4);
            else
                AesGcmKernelPclmul.ProcessBlocks(ref yAadHi, ref yAadLo, associatedData, h1, h2, h3, h4);
        }

        fixed (byte* rkPtr = roundKeys)
        fixed (byte* pCipher = ciphertext)
        fixed (byte* pPlain = plaintext)
        {
            Vector128<byte>* rkVec = (Vector128<byte>*)rkPtr;

            uint baseCounter = BinaryPrimitives.ReadUInt32BigEndian(j0.Slice(12, 4)) + 1;

            Vector128<ulong> yAccum;

            // Single Pass: Parallel GHASH over ciphertext and CTR decryption
            lock (s_dispatchLock)
            {
                s_doneEvent.Reset(numWorkers - 1);

                for (int w = 0; w < numWorkers; w++)
                {
                    int offset = w * chunkBytes;
                    int len = (w == numWorkers - 1) ? totalBytes - offset : chunkBytes;
                    uint ctrStart = baseCounter + (uint)(w * chunkBlocks);

                    ref var st = ref s_workerStates[w];
                    st.RoundKeys = rkVec;
                    st.Input = pCipher + offset;
                    st.Output = pPlain + offset;
                    st.Length = len;
                    st.StartCounter = ctrStart;
                    st.Nonce0 = j0[0]; st.Nonce1 = j0[1]; st.Nonce2 = j0[2]; st.Nonce3 = j0[3];
                    st.Nonce4 = j0[4]; st.Nonce5 = j0[5]; st.Nonce6 = j0[6]; st.Nonce7 = j0[7];
                    st.Nonce8 = j0[8]; st.Nonce9 = j0[9]; st.Nonce10 = j0[10]; st.Nonce11 = j0[11];
                    st.H1 = h1; st.H2 = h2; st.H3 = h3; st.H4 = h4;
                    st.H8to5 = h8to5; st.H4to1 = h4to1;
                    st.HasV512 = hasV512;
                    st.InitialYHi = (w == 0) ? yAadHi : 0;
                    st.InitialYLo = (w == 0) ? yAadLo : 0;
                    st.Mode = 2; // Single-pass GHASH + CTR

                    if (w > 0)
                    {
                        s_startEvents[w - 1].Set();
                    }
                }

                ExecuteWorkerJob(ref s_workerStates[0]);

                s_doneEvent.Wait();

                // Combine GHASH results inside lock to prevent state race under concurrency
                Vector128<ulong> hm = PowH(h1, chunkBlocks);
                yAccum = Vector128.Create(s_workerStates[0].OutYLo, s_workerStates[0].OutYHi);

                for (int w = 1; w < numWorkers; w++)
                {
                    int wLen = s_workerStates[w].Length;
                    int wBlocks = (wLen + 15) / 16;
                    Vector128<ulong> mult = (wBlocks == chunkBlocks) ? hm : PowH(h1, wBlocks);
                    yAccum = AesGcmKernelPclmul.MulOne(yAccum, mult) ^ Vector128.Create(s_workerStates[w].OutYLo, s_workerStates[w].OutYHi);
                }
            }

            Span<byte> lenBlock = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(0, 8), (ulong)associatedData.Length * 8);
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)ciphertext.Length * 8);

            ulong yHiFin = yAccum.GetElement(1);
            ulong yLoFin = yAccum.GetElement(0);
            AesGcmKernelPclmul.GhashBlock(ref yHiFin, ref yLoFin, lenBlock, h1);

            Span<byte> computedTag = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(computedTag.Slice(0, 8), yHiFin);
            BinaryPrimitives.WriteUInt64BigEndian(computedTag.Slice(8, 8), yLoFin);

            for (int i = 0; i < 16; i++)
                computedTag[i] ^= tagMask[i];

            if (!CryptographicOperations.FixedTimeEquals(computedTag, expectedTag.Slice(0, 16)))
            {
                CryptographicOperations.ZeroMemory(plaintext.Slice(0, ciphertext.Length));
                return false;
            }

            return true;
        }
    }
}
