namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hardware;
using Xunit;

/// <summary>
/// Comprehensive unit and boundary test suite covering BLAKE3 vector kernels and parallel thresholds.
/// Designed for Glacier.Codec Milestone M2.
/// 
/// Test Coverage:
/// 1. Exact Boundary Sizes:
///    - 8192 B   (8 chunks: exact AVX2 8-way SIMD kernel threshold)
///    - 8209 B   (8192 B + 17 B unaligned offset: exercises 8-chunk AVX2 kernel plus partial remainder)
///    - 16384 B  (16 chunks: exact AVX-512 16-way SIMD kernel threshold)
///    - 16449 B  (16384 B + 65 B unaligned offset: exercises 16-chunk AVX-512 kernel plus multi-block remainder)
///    - 32768 B  (32 chunks: exercises multi-batch vector reduction loop: AVX-512 16-way + AVX2 8-way)
///    - 1048576 B (1024 chunks / 1 MB: exact parallel tree reduction threshold)
/// 2. Direct Vector Kernel Unit Tests:
///    - Direct invocation of Blake3KernelAvx2.Hash8Chunks vs Blake3KernelScalar reference.
///    - Direct invocation of Blake3KernelAvx512.Hash16Chunks vs Blake3KernelScalar reference.
/// 3. Bit-Exact Parity:
///    - 100% parity against official BLAKE3 golden test vectors (test_vectors.json / official Rust blake3 crate).
///    - Standard (Default), Keyed MAC, and Key Derivation (KDF) modes across all boundary payloads.
///    - One-shot vs sequential streaming vs irregular fragmented appends.
/// 4. Extendable Output (XOF):
///    - 64-byte and 128-byte digests across vector threshold boundaries.
/// 5. Memory Alignment & Span Slicing:
///    - Unaligned source buffers (byte offset % 64 != 0) ensuring zero SIMD alignment faults.
/// 6. Zero Heap Allocation Verification:
///    - Steady-state 0 B GC allocation verification using GC.GetAllocatedBytesForCurrentThread().
/// </summary>
public unsafe class Blake3VectorKernelTests
{
    private const string OfficialKeyString = "whats the Elvish word for friend";
    private const string OfficialKdfContext = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    // Official reference golden vector hex strings computed by the canonical BLAKE3 implementation
    // using the repeating byte pattern: input[i] = (byte)(i % 251)
    private static readonly byte[] OfficialKey = Encoding.UTF8.GetBytes(OfficialKeyString);

    private const string Golden_8192_Default = "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63";
    private const string Golden_8192_Keyed   = "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a";
    private const string Golden_8192_Derive  = "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d";

    private const string Golden_8209_Default = "7a9d1fbb3de36ab3f51b9e0273250b3c91c7ba9ea25a8f71f7c5add6cd3f8770";
    private const string Golden_8209_Keyed   = "fb59a64c3d78ad1694095d4b861774cfd05d5ff402c79cbf085b1130aaf5ce6a";
    private const string Golden_8209_Derive  = "f640141ad06fc7d03539e4be1f865eb67a0ad1210dc35199a2b1cb94a02a3927";

    private const string Golden_16384_Default = "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4";
    private const string Golden_16384_Keyed   = "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d";
    private const string Golden_16384_Derive  = "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1";

    private const string Golden_16449_Default = "da6b71723af7609bc37a6a1c6a18608a3412e52bc8d7e611bfca55d5685db004";
    private const string Golden_16449_Keyed   = "791e74776c5a657fbbf11e0b7cfaf318696b51c51a32c3b3d242bd4321f6e6d7";
    private const string Golden_16449_Derive  = "9427873392b6a574d814cd988c0f189a49a8c0753c2d8295eed916b552590c5f";

    private const string Golden_32768_Default = "162183d1f9184474f5a5c9e6224e66720cdb6523f822e52d9b1efa30893f48f9";
    private const string Golden_32768_Keyed   = "b55ea5b43fc6d975a3084de4a7947e3416bdcfc67f090999f54903e1298e6b0f";
    private const string Golden_32768_Derive  = "74f1ef1f6e8645f358b879bef080c70ab4acbc05c2b9033757b2d20b996fac88";

    private const string Golden_1048576_Default = "74cb441fd087764ca9c3694da742ebe30cbeb3060a17009ca81825c7a8d10343";
    private const string Golden_1048576_Keyed   = "59b889b0821111fc4c249dc98b5435b767b44fb881542c61a85c1bebbffb2906";
    private const string Golden_1048576_Derive  = "8e1484f3996130ebdfd55a93b734f485e1590f3adbf57ffa02d2ae9207bf0293";

    private static byte[] CreatePatternBuffer(int length)
    {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++)
        {
            buffer[i] = (byte)(i % 251);
        }
        return buffer;
    }

    // =========================================================================
    // SECTION 1: DIRECT VECTOR KERNEL UNIT TESTS (WHITE-BOX EQUIVALENCE)
    // =========================================================================

    [Fact]
    public void Kernel_Avx2_Hash8Chunks_BitExactWithScalarReference()
    {
        if (!Blake3KernelAvx2.IsSupported)
        {
            return; // Target hardware lacks AVX2
        }

        const int numChunks = 8;
        const int totalBytes = numChunks * Blake3Constants.ChunkSize; // 8192 B
        byte[] input = CreatePatternBuffer(totalBytes);

        Span<byte> avx2Cvs = stackalloc byte[numChunks * 32];
        Span<byte> scalarCvs = stackalloc byte[numChunks * 32];

        fixed (byte* pInput = input)
        fixed (uint* pKey = Blake3Constants.IV)
        fixed (byte* pAvx2 = avx2Cvs)
        fixed (byte* pScalar = scalarCvs)
        {
            // 1. Compute 8 chunk chaining values via AVX2 SIMD kernel
            Blake3KernelAvx2.Hash8Chunks(pInput, 0, pKey, 0, pAvx2);

            // 2. Compute 8 chunk chaining values independently via unrolled scalar kernel
            Span<uint> runCv = stackalloc uint[8];
            fixed (uint* pCv = runCv)
            {
                for (int c = 0; c < numChunks; c++)
                {
                    byte* chunk = pInput + (c * Blake3Constants.ChunkSize);
                    for (int i = 0; i < 8; i++) runCv[i] = pKey[i];

                    uint* dstCv = (uint*)(pScalar + (c * 32));

                    for (int b = 0; b < 16; b++)
                    {
                        uint bFlags = 0;
                        if (b == 0) bFlags |= (uint)Blake3Flags.ChunkStart;
                        if (b == 15) bFlags |= (uint)Blake3Flags.ChunkEnd;

                        byte* blkPtr = chunk + (b * 64);
                        uint* outTarget = (b == 15) ? dstCv : pCv;
                        Blake3KernelScalar.CompressBlock(pCv, blkPtr, (ulong)c, 64, bFlags, outTarget);
                    }
                }
            }
        }

        // Verify each 32-byte chaining value matches identically
        for (int c = 0; c < numChunks; c++)
        {
            ReadOnlySpan<byte> avx2Slice = avx2Cvs.Slice(c * 32, 32);
            ReadOnlySpan<byte> scalarSlice = scalarCvs.Slice(c * 32, 32);
            Assert.True(avx2Slice.SequenceEqual(scalarSlice),
                $"AVX2 chaining value mismatch at chunk index {c}.");
        }
    }

    [Fact]
    public void Kernel_Avx512_Hash16Chunks_BitExactWithScalarReference()
    {
        if (!Blake3KernelAvx512.IsSupported)
        {
            return; // Target hardware lacks AVX-512F / AVX-512BW
        }

        const int numChunks = 16;
        const int totalBytes = numChunks * Blake3Constants.ChunkSize; // 16384 B
        byte[] input = CreatePatternBuffer(totalBytes);

        Span<byte> avx512Cvs = stackalloc byte[numChunks * 32];
        Span<byte> scalarCvs = stackalloc byte[numChunks * 32];

        fixed (byte* pInput = input)
        fixed (uint* pKey = Blake3Constants.IV)
        fixed (byte* pAvx512 = avx512Cvs)
        fixed (byte* pScalar = scalarCvs)
        {
            // 1. Compute 16 chunk chaining values via AVX-512 16-way SIMD kernel
            Blake3KernelAvx512.Hash16Chunks(pInput, 0, pKey, 0, pAvx512);

            // 2. Compute 16 chunk chaining values independently via unrolled scalar kernel
            Span<uint> runCv = stackalloc uint[8];
            fixed (uint* pCv = runCv)
            {
                for (int c = 0; c < numChunks; c++)
                {
                    byte* chunk = pInput + (c * Blake3Constants.ChunkSize);
                    for (int i = 0; i < 8; i++) runCv[i] = pKey[i];

                    uint* dstCv = (uint*)(pScalar + (c * 32));

                    for (int b = 0; b < 16; b++)
                    {
                        uint bFlags = 0;
                        if (b == 0) bFlags |= (uint)Blake3Flags.ChunkStart;
                        if (b == 15) bFlags |= (uint)Blake3Flags.ChunkEnd;

                        byte* blkPtr = chunk + (b * 64);
                        uint* outTarget = (b == 15) ? dstCv : pCv;
                        Blake3KernelScalar.CompressBlock(pCv, blkPtr, (ulong)c, 64, bFlags, outTarget);
                    }
                }
            }
        }

        // Verify each 32-byte chaining value matches identically
        for (int c = 0; c < numChunks; c++)
        {
            ReadOnlySpan<byte> avx512Slice = avx512Cvs.Slice(c * 32, 32);
            ReadOnlySpan<byte> scalarSlice = scalarCvs.Slice(c * 32, 32);
            Assert.True(avx512Slice.SequenceEqual(scalarSlice),
                $"AVX-512 chaining value mismatch at chunk index {c}.");
        }
    }

    // =========================================================================
    // SECTION 2: BOUNDARY THRESHOLD OFFICIAL GOLDEN VECTOR PARITY
    // =========================================================================

    [Theory]
    [InlineData(8192, Golden_8192_Default)]
    [InlineData(8209, Golden_8209_Default)]
    [InlineData(16384, Golden_16384_Default)]
    [InlineData(16449, Golden_16449_Default)]
    [InlineData(32768, Golden_32768_Default)]
    [InlineData(1048576, Golden_1048576_Default)]
    public void Blake3_OneShot_MatchesOfficialGoldenVectors(int length, string expectedHex)
    {
        byte[] input = CreatePatternBuffer(length);
        Span<byte> hash = stackalloc byte[32];

        Blake3Hasher.Hash(input, hash);

        string actualHex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal(expectedHex, actualHex);
    }

    [Theory]
    [InlineData(8192, Golden_8192_Keyed)]
    [InlineData(8209, Golden_8209_Keyed)]
    [InlineData(16384, Golden_16384_Keyed)]
    [InlineData(16449, Golden_16449_Keyed)]
    [InlineData(32768, Golden_32768_Keyed)]
    [InlineData(1048576, Golden_1048576_Keyed)]
    public void Blake3_KeyedMac_MatchesOfficialGoldenVectors(int length, string expectedHex)
    {
        byte[] input = CreatePatternBuffer(length);
        Span<byte> hash = stackalloc byte[32];

        Blake3Hasher.HashKeyed(input, OfficialKey, hash);

        string actualHex = Convert.ToHexString(hash).ToLowerInvariant();
        Assert.Equal(expectedHex, actualHex);
    }

    [Theory]
    [InlineData(8192, Golden_8192_Derive)]
    [InlineData(8209, Golden_8209_Derive)]
    [InlineData(16384, Golden_16384_Derive)]
    [InlineData(16449, Golden_16449_Derive)]
    [InlineData(32768, Golden_32768_Derive)]
    [InlineData(1048576, Golden_1048576_Derive)]
    public void Blake3_KeyDerivation_MatchesOfficialGoldenVectors(int length, string expectedHex)
    {
        byte[] input = CreatePatternBuffer(length);
        using var kdf = Blake3Hasher.CreateKeyDerivation(OfficialKdfContext);
        kdf.Append(input);

        Span<byte> derivedKey = stackalloc byte[32];
        kdf.Finalize(derivedKey);

        string actualHex = Convert.ToHexString(derivedKey).ToLowerInvariant();
        Assert.Equal(expectedHex, actualHex);
    }

    // =========================================================================
    // SECTION 3: STREAMING & FRAGMENTED PIPELINE PARITY
    // =========================================================================

    [Theory]
    [InlineData(8192)]
    [InlineData(8209)]
    [InlineData(16384)]
    [InlineData(16449)]
    [InlineData(32768)]
    [InlineData(1048576)]
    public void Blake3_StreamingIncremental_MatchesOneShotExactly(int length)
    {
        byte[] input = CreatePatternBuffer(length);

        Span<byte> oneShot = stackalloc byte[32];
        Blake3Hasher.Hash(input, oneShot);

        using var streamHasher = new Blake3Hasher();
        streamHasher.Append(input);

        Span<byte> streamed = stackalloc byte[32];
        streamHasher.Finalize(streamed);

        Assert.True(oneShot.SequenceEqual(streamed),
            $"Streaming hash deviated from one-shot hash on length {length}.");
    }

    [Theory]
    [InlineData(8192)]
    [InlineData(8209)]
    [InlineData(16384)]
    [InlineData(16449)]
    [InlineData(32768)]
    public void Blake3_StreamingFragmented_IrregularAppends_MatchesOneShot(int length)
    {
        byte[] input = CreatePatternBuffer(length);

        Span<byte> expected = stackalloc byte[32];
        Blake3Hasher.Hash(input, expected);

        using var streamHasher = new Blake3Hasher();
        int offset = 0;
        int[] sliceSizes = [53, 1024, 7, 2048, 257, 4096, 17, 512, 19];
        int sliceIdx = 0;

        while (offset < length)
        {
            int slice = sliceSizes[sliceIdx % sliceSizes.Length];
            int take = Math.Min(slice, length - offset);
            streamHasher.Append(input.AsSpan(offset, take));
            offset += take;
            sliceIdx++;
        }

        Span<byte> actual = stackalloc byte[32];
        streamHasher.Finalize(actual);

        Assert.True(expected.SequenceEqual(actual),
            $"Fragmented streaming hash deviated from one-shot hash on length {length}.");
    }

    // =========================================================================
    // SECTION 4: EXTENDABLE OUTPUT (XOF) ACROSS VECTOR BOUNDARIES
    // =========================================================================

    [Theory]
    [InlineData(8192, 64)]
    [InlineData(16384, 128)]
    [InlineData(32768, 64)]
    public void Blake3_ExtendableOutput_MatchesDefaultPrefixAndGeneratesEntropy(int length, int outputLen)
    {
        byte[] input = CreatePatternBuffer(length);

        // 1. Standard 32-byte hash
        Span<byte> stdHash = stackalloc byte[32];
        Blake3Hasher.Hash(input, stdHash);

        // 2. Extendable output hash
        using var hasher = new Blake3Hasher();
        hasher.Append(input);

        Span<byte> xofOutput = stackalloc byte[outputLen];
        hasher.Finalize(xofOutput);

        // Prefix check: First 32 bytes of XOF must match default 32-byte digest
        Assert.True(stdHash.SequenceEqual(xofOutput.Slice(0, 32)),
            "First 32 bytes of extended output must match default hash.");

        // Entropy check: Remaining extended bytes must not be all zeroes
        bool hasNonZero = false;
        for (int i = 32; i < outputLen; i++)
        {
            if (xofOutput[i] != 0) { hasNonZero = true; break; }
        }
        Assert.True(hasNonZero, "Extended output words beyond 32 bytes must be non-zero.");
    }

    // =========================================================================
    // SECTION 5: UNALIGNED SPAN MEMORY ROBUSTNESS
    // =========================================================================

    [Theory]
    [InlineData(8192, 1)]
    [InlineData(8192, 7)]
    [InlineData(16384, 3)]
    [InlineData(16384, 13)]
    [InlineData(32768, 31)]
    public void Blake3_UnalignedMemoryOffsets_NoHardwareAlignmentFaults(int length, int offset)
    {
        byte[] rawBuffer = new byte[length + offset + 64];
        for (int i = 0; i < length; i++)
        {
            rawBuffer[offset + i] = (byte)(i % 251);
        }

        ReadOnlySpan<byte> unalignedSpan = rawBuffer.AsSpan(offset, length);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(unalignedSpan, hash);

        string actualHex = Convert.ToHexString(hash).ToLowerInvariant();

        string expectedHex = length switch
        {
            8192 => Golden_8192_Default,
            16384 => Golden_16384_Default,
            32768 => Golden_32768_Default,
            _ => throw new ArgumentOutOfRangeException(nameof(length))
        };

        Assert.Equal(expectedHex, actualHex);
    }

    // =========================================================================
    // SECTION 6: ZERO HEAP ALLOCATION VERIFICATION (STEADY-STATE)
    // =========================================================================

    [Theory]
    [InlineData(8192)]
    [InlineData(8209)]
    [InlineData(16384)]
    [InlineData(16449)]
    [InlineData(32768)]
    public void Blake3_ZeroAllocations_OneShot_SubParallelThreshold_AllocatesZeroBytes(int length)
    {
        byte[] buffer = CreatePatternBuffer(length);
        ReadOnlySpan<byte> span = buffer;
        Span<byte> dest = stackalloc byte[32];

        // JIT warm-up
        for (int i = 0; i < 50; i++)
        {
            Blake3Hasher.Hash(span, dest);
        }

        // Steady-state measurement
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            Blake3Hasher.Hash(span, dest);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocated = after - before;
        Assert.Equal(0, allocated);
    }

    [Theory]
    [InlineData(8192)]
    [InlineData(8209)]
    [InlineData(16384)]
    [InlineData(16449)]
    [InlineData(32768)]
    [InlineData(1048576)]
    public void Blake3_ZeroAllocations_Streaming_AllThresholds_AllocatesZeroBytes(int length)
    {
        byte[] buffer = CreatePatternBuffer(length);
        Span<byte> dest = stackalloc byte[32];
        using var hasher = new Blake3Hasher();

        // JIT warm-up
        for (int i = 0; i < 20; i++)
        {
            hasher.Reset();
            hasher.Append(buffer);
            hasher.Finalize(dest);
        }

        // Steady-state measurement: resetting and appending to existing instance must allocate 0 bytes
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 50; i++)
        {
            hasher.Reset();
            hasher.Append(buffer);
            hasher.Finalize(dest);
        }
        long after = GC.GetAllocatedBytesForCurrentThread();

        long allocated = after - before;
        Assert.Equal(0, allocated);
    }
}
