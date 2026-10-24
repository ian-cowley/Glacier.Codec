namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Glacier.Codec.Memory;

/// <summary>
/// RFC 9106 Argon2id memory-hard password-based key derivation function.
/// Features configurable time, memory, and parallelism parameters with zero heap allocation.
/// Resistant to GPU time-memory trade-off (TMTO) and side-channel timing attacks.
/// </summary>
public sealed class Argon2id : IKeyDerivationFunction, IDisposable
{
    public const int DefaultIterations = 3;
    public const int DefaultMemoryKb = 65536; // 64 MB recommended by RFC 9106
    public const int DefaultParallelism = 4;
    public const int Version = 0x13;         // 19 (Version 1.3)
    public const int Type = 2;               // 2 (Argon2id)
    public const int BlockSize = 1024;       // 1024 bytes per block (128 ulongs)
    public const int WordsPerBlock = 128;

    private bool _disposed;

    public int Iterations { get; }
    public int MemoryKb { get; }
    public int Parallelism { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2id"/> class.
    /// </summary>
    /// <param name="iterations">Number of passes t (>= 1).</param>
    /// <param name="memoryKb">Memory size m in KiB (>= 8 * parallelism).</param>
    /// <param name="parallelism">Degree of parallelism p (>= 1).</param>
    public Argon2id(int iterations = DefaultIterations, int memoryKb = DefaultMemoryKb, int parallelism = DefaultParallelism)
    {
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be at least 1.");
        if (parallelism < 1)
            throw new ArgumentOutOfRangeException(nameof(parallelism), "Parallelism must be at least 1.");
        if (memoryKb < 8 * parallelism)
            throw new ArgumentOutOfRangeException(nameof(memoryKb), $"Memory must be at least 8 * parallelism KiB ({8 * parallelism} KiB).");

        Iterations = iterations;
        MemoryKb = memoryKb;
        Parallelism = parallelism;
    }

    /// <summary>
    /// Derives output cryptographic key from password and salt.
    /// </summary>
    public void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> derivedKey)
    {
        DeriveKey(password, salt, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, derivedKey);
    }

    /// <summary>
    /// Derives output cryptographic key from password, salt, optional secret (pepper), and optional associated data.
    /// </summary>
    public void DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> associatedData,
        Span<byte> derivedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        DeriveKeyCore(password, salt, secret, associatedData, derivedKey, Iterations, MemoryKb, Parallelism);
    }

    private static unsafe void DeriveKeyCore(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> associatedData,
        Span<byte> derivedKey,
        int iterations,
        int memoryKb,
        int parallelism)
    {
        if (derivedKey.Length < 4)
            throw new ArgumentException("Derived key length must be at least 4 bytes.", nameof(derivedKey));

        int p = parallelism;
        int t = iterations;
        int m = memoryKb;
        int tagLen = derivedKey.Length;

        // Total blocks m' = 4 * p * floor(m / (4 * p))
        int mPrime = 4 * p * (m / (4 * p));
        int q = mPrime / p;         // Lane length in blocks
        int s = q / 4;              // Segment length in blocks (slice length)

        int totalBytes = mPrime * BlockSize;

        // 1. Compute H0 initial digest (64 bytes)
        Span<byte> h0 = stackalloc byte[64];
        ComputeH0(p, tagLen, m, t, Version, Type, password, salt, secret, associatedData, h0);

        // 2. Rent 64-byte aligned unmanaged slab for memory matrix
        using SlabLease lease = UnmanagedSlabPool.Shared.Rent(totalBytes);
        byte* matrixPtr = (byte*)lease.Pointer;
        ulong* matrixWords = (ulong*)matrixPtr;

        try
        {
            // 3. Initialize first two blocks per lane (B[i, 0] and B[i, 1])
            Span<byte> seedBuf = stackalloc byte[72];
            h0.CopyTo(seedBuf.Slice(0, 64));

            for (int lane = 0; lane < p; lane++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(seedBuf.Slice(64, 4), 0);
                BinaryPrimitives.WriteInt32LittleEndian(seedBuf.Slice(68, 4), lane);
                Span<byte> b0 = new(matrixPtr + (lane * q + 0) * BlockSize, BlockSize);
                ComputeHPrime(seedBuf, b0);

                BinaryPrimitives.WriteInt32LittleEndian(seedBuf.Slice(64, 4), 1);
                Span<byte> b1 = new(matrixPtr + (lane * q + 1) * BlockSize, BlockSize);
                ComputeHPrime(seedBuf, b1);
            }

            // 4. Multi-pass block iteration
            for (int pass = 0; pass < t; pass++)
            {
                for (int slice = 0; slice < 4; slice++)
                {
                    for (int lane = 0; lane < p; lane++)
                    {
                        ExecuteSliceOnLane(lane, pass, slice, p, t, mPrime, q, s, matrixWords);
                    }
                }
            }

            // 5. Finalization: XOR last column of all lanes
            ulong* cBlock = stackalloc ulong[WordsPerBlock];
            ulong* firstLaneLastCol = matrixWords + (0 * q + (q - 1)) * WordsPerBlock;
            for (int k = 0; k < WordsPerBlock; k++)
            {
                cBlock[k] = firstLaneLastCol[k];
            }

            for (int lane = 1; lane < p; lane++)
            {
                ulong* laneLastCol = matrixWords + (lane * q + (q - 1)) * WordsPerBlock;
                for (int k = 0; k < WordsPerBlock; k++)
                {
                    cBlock[k] ^= laneLastCol[k];
                }
            }

            // 6. Compute Tag = H'(C, tagLen)
            ReadOnlySpan<byte> cSpan = new(cBlock, BlockSize);
            ComputeHPrime(cSpan, derivedKey);

            // Zeroize intermediate cBlock
            CryptographicOperations.ZeroMemory(new Span<byte>(cBlock, BlockSize));
        }
        finally
        {
            // Wipe memory matrix securely before returning slab
            CryptographicOperations.ZeroMemory(lease.Span.Slice(0, totalBytes));
            CryptographicOperations.ZeroMemory(h0);
        }
    }

    private static unsafe void ExecuteSliceOnLane(
        int lane,
        int pass,
        int slice,
        int totalLanes,
        int totalPasses,
        int totalBlocks,
        int laneLength,
        int sliceLength,
        ulong* matrixWords)
    {
        ulong* addrBlock = stackalloc ulong[WordsPerBlock];
        int startIdx = (pass == 0 && slice == 0) ? 2 : 0;

        for (int idx = startIdx; idx < sliceLength; idx++)
        {
            int currentCol = slice * sliceLength + idx;
            int prevCol = (currentCol > 0) ? currentCol - 1 : laneLength - 1;

            ulong* prev = matrixWords + (lane * laneLength + prevCol) * WordsPerBlock;

            uint j1, j2;
            if (pass == 0 && slice < 2)
            {
                // Argon2i mode: generate 1024-byte pseudo-random addresses
                if (idx % WordsPerBlock == 0 || idx == startIdx)
                {
                    Argon2idKernel.GenerateAddressBlock(
                        addrBlock,
                        (ulong)pass,
                        (ulong)lane,
                        (ulong)slice,
                        (ulong)totalBlocks,
                        (ulong)totalPasses,
                        (ulong)Type,
                        (ulong)(idx / WordsPerBlock));
                }

                ulong randWord = addrBlock[idx % WordsPerBlock];
                j1 = (uint)(randWord & 0xFFFFFFFFUL);
                j2 = (uint)(randWord >> 32);
            }
            else
            {
                // Argon2d mode: extract addressing from prev block word 0
                ulong randWord = prev[0];
                j1 = (uint)(randWord & 0xFFFFFFFFUL);
                j2 = (uint)(randWord >> 32);
            }

            var (lRef, z) = Argon2idKernel.ComputeReferenceIndex(
                j1, j2, pass, slice, lane, idx, sliceLength, laneLength, totalLanes);

            ulong* refBlock = matrixWords + (lRef * laneLength + z) * WordsPerBlock;
            ulong* destBlock = matrixWords + (lane * laneLength + currentCol) * WordsPerBlock;

            if (pass == 0)
            {
                Argon2idKernel.MixBlock(destBlock, prev, refBlock);
            }
            else
            {
                Argon2idKernel.MixBlockXor(destBlock, prev, refBlock);
            }
        }

        CryptographicOperations.ZeroMemory(new Span<byte>(addrBlock, BlockSize));
    }

    /// <summary>
    /// Computes H0 initial 64-byte digest per RFC 9106 Section 3.2.
    /// </summary>
    private static void ComputeH0(
        int p, int tagLen, int m, int t, int v, int y,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
        var blake = new Blake2bCore(64);

        Span<byte> header = stackalloc byte[24];
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(0, 4), p);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(4, 4), tagLen);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(8, 4), m);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(12, 4), t);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(16, 4), v);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(20, 4), y);
        blake.Update(header);

        Span<byte> lenBuf = stackalloc byte[4];

        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, password.Length);
        blake.Update(lenBuf);
        if (!password.IsEmpty) blake.Update(password);

        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, salt.Length);
        blake.Update(lenBuf);
        if (!salt.IsEmpty) blake.Update(salt);

        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, secret.Length);
        blake.Update(lenBuf);
        if (!secret.IsEmpty) blake.Update(secret);

        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, associatedData.Length);
        blake.Update(lenBuf);
        if (!associatedData.IsEmpty) blake.Update(associatedData);

        blake.Finalize(destination);
    }

    /// <summary>
    /// Computes variable-length hash H'(A, length) per RFC 9106 Section 3.3.
    /// </summary>
    private static void ComputeHPrime(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        int length = destination.Length;
        Span<byte> lenPrefix = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenPrefix, length);

        if (length <= 64)
        {
            var blake = new Blake2bCore(length);
            blake.Update(lenPrefix);
            blake.Update(input);
            blake.Finalize(destination);
            return;
        }

        // length > 64: cascading Blake2b rounds
        int r = (length + 31) / 32 - 2;

        Span<byte> v = stackalloc byte[64];

        // V_1 = Blake2b_64(LE32(length) || input)
        var blake1 = new Blake2bCore(64);
        blake1.Update(lenPrefix);
        blake1.Update(input);
        blake1.Finalize(v);

        v.Slice(0, 32).CopyTo(destination.Slice(0, 32));

        for (int i = 2; i <= r; i++)
        {
            Blake2bCore.ComputeHash(v, v, 64);
            v.Slice(0, 32).CopyTo(destination.Slice((i - 1) * 32, 32));
        }

        // Final round V_{r+1} = Blake2b_{length - 32*r}(V_r)
        int remaining = length - 32 * r;
        Blake2bCore.ComputeHash(v, destination.Slice(32 * r, remaining), remaining);

        CryptographicOperations.ZeroMemory(v);
    }

    /// <summary>
    /// Backward-compatible static one-shot key derivation helper.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Derive(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Span<byte> derivedKey,
        int iterations = DefaultIterations,
        int memoryKb = DefaultMemoryKb,
        int parallelism = DefaultParallelism)
    {
        DeriveKey(password, salt, derivedKey, iterations, memoryKb, parallelism);
    }

    /// <summary>
    /// Static one-shot key derivation helper. Strictly zero heap allocation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Span<byte> derivedKey,
        int iterations = DefaultIterations,
        int memoryKb = DefaultMemoryKb,
        int parallelism = DefaultParallelism)
    {
        DeriveKeyCore(password, salt, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, derivedKey, iterations, memoryKb, parallelism);
    }

    /// <summary>
    /// Static one-shot key derivation helper with secret and associated data. Strictly zero heap allocation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> associatedData,
        Span<byte> derivedKey,
        int iterations = DefaultIterations,
        int memoryKb = DefaultMemoryKb,
        int parallelism = DefaultParallelism)
    {
        DeriveKeyCore(password, salt, secret, associatedData, derivedKey, iterations, memoryKb, parallelism);
    }

    public void Dispose()
    {
        _disposed = true;
    }
}
