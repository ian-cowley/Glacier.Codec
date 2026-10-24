namespace Glacier.Codec.Cryptography.Kdf;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using Glacier.Codec.Hardware;

/// <summary>
/// Hardware dispatcher and algorithmic indexing engine for Argon2id (RFC 9106).
/// Computes hybrid reference coordinates (Argon2i/Argon2d) and dispatches block compression G.
/// </summary>
internal static class Argon2idKernel
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void MixBlock(ulong* dest, ulong* x, ulong* y)
    {
        if (CpuCapabilities.HasAvx2)
        {
            Argon2idKernelAvx2.MixBlock(dest, x, y);
        }
        else
        {
            Argon2idKernelScalar.MixBlock(dest, x, y);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void MixBlockXor(ulong* dest, ulong* x, ulong* y)
    {
        if (CpuCapabilities.HasAvx2)
        {
            Argon2idKernelAvx2.MixBlockXor(dest, x, y);
        }
        else
        {
            Argon2idKernelScalar.MixBlockXor(dest, x, y);
        }
    }

    /// <summary>
    /// Generates 1024-byte pseudo-random address block for Argon2i data-independent indexing mode.
    /// address_block = G(ZERO, G(ZERO, input_block))
    /// </summary>
    public static unsafe void GenerateAddressBlock(
        ulong* addressBlock,
        ulong pass,
        ulong lane,
        ulong slice,
        ulong totalBlocks,
        ulong totalPasses,
        ulong type,
        ulong batchIndex)
    {
        ulong* input = stackalloc ulong[128];
        new Span<ulong>(input, 128).Clear();

        input[0] = pass;
        input[1] = lane;
        input[2] = slice;
        input[3] = totalBlocks;
        input[4] = totalPasses;
        input[5] = type;
        input[6] = batchIndex + 1; // 1-based counter

        ulong* zero = stackalloc ulong[128];
        new Span<ulong>(zero, 128).Clear();

        ulong* temp = stackalloc ulong[128];
        MixBlock(temp, zero, input);
        MixBlock(addressBlock, zero, temp);
    }

    /// <summary>
    /// Computes reference lane (lRef) and reference column (z) per RFC 9106 Section 3.4.2.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (int lRef, int z) ComputeReferenceIndex(
        uint j1,
        uint j2,
        int pass,
        int slice,
        int lane,
        int indexInSlice,
        int sliceLength,
        int laneLength,
        int totalLanes)
    {
        // 1. Reference lane selection
        int lRef;
        if (pass == 0 && slice == 0)
        {
            lRef = lane;
        }
        else
        {
            lRef = (int)(j2 % (uint)totalLanes);
        }

        // 2. Candidate reference area size |W|
        bool sameLane = (lane == lRef);
        int wSize;

        if (pass == 0)
        {
            if (slice == 0)
            {
                wSize = indexInSlice - 1;
            }
            else
            {
                wSize = sameLane
                    ? (slice * sliceLength + indexInSlice - 1)
                    : (slice * sliceLength + (indexInSlice == 0 ? -1 : 0));
            }
        }
        else
        {
            wSize = sameLane
                ? (laneLength - sliceLength + indexInSlice - 1)
                : (laneLength - sliceLength + (indexInSlice == 0 ? -1 : 0));
        }

        if (wSize <= 0)
        {
            return (lRef, 0);
        }

        // 3. Starting position
        int startPos;
        if (pass == 0)
        {
            startPos = 0;
        }
        else
        {
            startPos = (slice == 3) ? 0 : ((slice + 1) * sliceLength);
        }

        // 4. Skewed distribution mapping J1 over candidate window
        ulong rel = (ulong)j1;
        rel = (rel * rel) >> 32;
        rel = (ulong)wSize - 1 - (((ulong)wSize * rel) >> 32);

        int z = (int)(((ulong)startPos + rel) % (ulong)laneLength);
        return (lRef, z);
    }
}
