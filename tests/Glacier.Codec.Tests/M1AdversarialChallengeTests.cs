namespace Glacier.Codec.Tests;

using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Glacier.Codec.Hardware;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Adversarial Stress & Fuzzing Harness for Milestone M1 (Glacier.Codec).
/// Authored by Empirical Challenger 1.
/// Verifies:
/// 1. 64-byte alignment across thousands of arbitrary and pathological sizes.
/// 2. Memory access safety across full span length without memory violations.
/// 3. SecureMemory zero-wiping and constant-time equality side-channel resistance.
/// 4. HardwareArbiter routing threshold boundaries and high-density fuzzing.
/// </summary>
public unsafe class M1AdversarialChallengeTests
{
    // =========================================================================
    // 1. MEMORY ALIGNMENT STRESS TESTS
    // =========================================================================

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(1048575)]
    [InlineData(1048576)]
    [InlineData(1048577)]
    [InlineData(4194304)]
    public void MemoryAlignment_PathologicalSizes_AllStrictly64ByteAligned(int size)
    {
        using var buffer = new CachelineAlignedBuffer(size, clear: true);
        nuint address = (nuint)buffer.Pointer;

        // 1. Strict 64-byte cacheline alignment invariant
        Assert.Equal(0u, address & 63u);
        Assert.True(buffer.IsAlignedTo64Bytes);

        // 2. Length and capacity invariants
        Assert.Equal(size, buffer.Length);
        Assert.Equal(size, buffer.Span.Length);
        Assert.True(buffer.AllocatedBytes >= (nuint)size);
        Assert.Equal(0u, buffer.AllocatedBytes & 63u); // Allocated size padded to multiple of 64

        // 3. Write and read verification across entire span without access violations
        Span<byte> span = buffer.Span;
        byte testSeed = (byte)(size & 0x7F);
        for (int i = 0; i < size; i++)
        {
            span[i] = (byte)(testSeed + (i & 0xFF));
        }

        // Verify direct pointer read matches span
        byte* rawPtr = (byte*)buffer.Pointer;
        for (int i = 0; i < size; i++)
        {
            byte expected = (byte)(testSeed + (i & 0xFF));
            Assert.Equal(expected, rawPtr[i]);
        }

        // 4. MemoryManager pinning verification
        using MemoryHandle handle = buffer.Memory.Pin();
        Assert.Equal((IntPtr)buffer.Pointer, (IntPtr)handle.Pointer);
    }

    [Fact]
    public void MemoryAlignment_ThousandsOfRandomSizes_AllStrictly64ByteAligned()
    {
        var random = new Random(42);
        const int iterations = 1000;

        for (int iter = 0; iter < iterations; iter++)
        {
            // Pick arbitrary pseudo-random sizes between 1 byte and 512 KB
            int size = random.Next(1, 512 * 1024);

            using var buffer = new CachelineAlignedBuffer(size, clear: false);
            nuint address = (nuint)buffer.Pointer;

            Assert.Equal(0u, address & 63u);
            Assert.Equal(size, buffer.Length);

            // Boundary byte write and verify (first, middle, last)
            Span<byte> span = buffer.Span;
            span[0] = 0xAA;
            span[size / 2] = 0x55;
            span[size - 1] = 0x33;

            byte* ptr = (byte*)buffer.Pointer;
            Assert.Equal(0xAA, ptr[0]);
            Assert.Equal(0x55, ptr[size / 2]);
            Assert.Equal(0x33, ptr[size - 1]);
        }
    }

    [Fact]
    public void MemoryAlignment_ParallelConcurrentAllocationStress_NoViolations()
    {
        const int threadCount = 16;
        const int allocationsPerThread = 100;

        Parallel.For(0, threadCount, threadId =>
        {
            var localRand = new Random(1000 + threadId);
            for (int i = 0; i < allocationsPerThread; i++)
            {
                int size = localRand.Next(1, 65536);
                using var buf = new CachelineAlignedBuffer(size, clear: true);

                nuint addr = (nuint)buf.Pointer;
                Assert.Equal(0u, addr & 63u);

                Span<byte> s = buf.Span;
                s[0] = (byte)threadId;
                s[size - 1] = (byte)(threadId ^ 0xFF);

                Assert.Equal((byte)threadId, s[0]);
                Assert.Equal((byte)(threadId ^ 0xFF), s[size - 1]);
            }
        });
    }

    [Fact]
    public void MemoryAlignment_InvalidSizes_ThrowArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(-65536));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(int.MinValue));
    }

    [Fact]
    public void MemoryAlignment_PointerWrapping_Enforces64ByteAlignment()
    {
        // Allocate valid 64-byte aligned buffer
        using var baseBuffer = new CachelineAlignedBuffer(256);
        byte* alignedPtr = (byte*)baseBuffer.Pointer;

        // Offset 0 is aligned: wrapping succeeds
        using (var wrapper0 = new CachelineAlignedBuffer(alignedPtr, 128, ownsMemory: false))
        {
            Assert.True(wrapper0.IsAlignedTo64Bytes);
            Assert.Equal((IntPtr)alignedPtr, (IntPtr)wrapper0.Pointer);
        }

        // Offset 64 is aligned: wrapping succeeds
        using (var wrapper64 = new CachelineAlignedBuffer(alignedPtr + 64, 64, ownsMemory: false))
        {
            Assert.True(wrapper64.IsAlignedTo64Bytes);
            Assert.Equal((IntPtr)(alignedPtr + 64), (IntPtr)wrapper64.Pointer);
        }

        // Misaligned offsets (1, 7, 13, 31, 63): must throw ArgumentException
        int[] unalignedOffsets = [1, 2, 7, 13, 31, 63];
        foreach (int offset in unalignedOffsets)
        {
            Assert.Throws<ArgumentException>(() => new CachelineAlignedBuffer(alignedPtr + offset, 64, ownsMemory: false));
        }

        // Null pointer with positive length throws ArgumentNullException
        Assert.Throws<ArgumentNullException>(() => new CachelineAlignedBuffer(null, 64, ownsMemory: false));

        // Negative length throws ArgumentOutOfRangeException
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachelineAlignedBuffer(alignedPtr, -1, ownsMemory: false));

        // Length 0 with null pointer succeeds (empty buffer)
        using var empty = new CachelineAlignedBuffer(null, 0, ownsMemory: false);
        Assert.Equal(0, empty.Length);
        Assert.True(empty.Span.IsEmpty);
    }

    // =========================================================================
    // 2. SECURE MEMORY & ZERO-WIPING STRESS TESTS
    // =========================================================================

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void SecureMemory_CreateAndWipeSource_Wipes100PercentOfSourceBytes(int keySize)
    {
        byte[] sourceKey = new byte[keySize];
        var rng = new Random(12345 + keySize);
        rng.NextBytes(sourceKey);

        // Ensure non-zero bytes throughout
        for (int i = 0; i < sourceKey.Length; i++)
        {
            if (sourceKey[i] == 0) sourceKey[i] = 0xAA;
        }

        byte[] originalCopy = (byte[])sourceKey.Clone();

        using (var secure = SecureMemory.CreateAndWipeSource(sourceKey.AsSpan()))
        {
            // 1. SecureMemory receives the exact original secret bytes
            Assert.Equal(keySize, secure.Length);
            Assert.True(secure.Span.SequenceEqual(originalCopy));
            Assert.Equal(0u, (nuint)secure.Pointer & 63u);

            // 2. Source span must be completely wiped to all 0x00
            for (int i = 0; i < sourceKey.Length; i++)
            {
                Assert.Equal((byte)0, sourceKey[i]);
            }
        }
    }

    [Fact]
    public void SecureMemory_ConstantTimeEquals_ExhaustiveBitFlipsAcrossKey()
    {
        int[] testLengths = [16, 24, 32, 64];

        foreach (int len in testLengths)
        {
            byte[] key = new byte[len];
            Random.Shared.NextBytes(key);

            using var secure = SecureMemory.Create(key);

            // Identical key must return true
            Assert.True(secure.ConstantTimeEquals(key));

            // Exhaustive bit flip: test EVERY single bit position
            byte[] corrupted = (byte[])key.Clone();
            for (int byteIdx = 0; byteIdx < len; byteIdx++)
            {
                for (int bitIdx = 0; bitIdx < 8; bitIdx++)
                {
                    corrupted[byteIdx] ^= (byte)(1 << bitIdx);

                    bool matches = secure.ConstantTimeEquals(corrupted);
                    Assert.False(matches);

                    // Restore bit
                    corrupted[byteIdx] ^= (byte)(1 << bitIdx);
                }
            }
        }
    }

    [Fact]
    public void SecureMemory_ConstantTimeEquals_ExhaustiveByteDifferences()
    {
        const int len = 32;
        byte[] key = new byte[len];
        Random.Shared.NextBytes(key);

        using var secure = SecureMemory.Create(key);
        byte[] modified = (byte[])key.Clone();

        byte[] deltas = [1, 2, 0x55, 0xAA, 0x80, 0xFF];

        for (int i = 0; i < len; i++)
        {
            byte original = modified[i];
            foreach (byte delta in deltas)
            {
                modified[i] = (byte)(original ^ delta);

                Assert.False(secure.ConstantTimeEquals(modified));
            }
            modified[i] = original;
        }
    }

    [Fact]
    public void SecureMemory_ConstantTimeEquals_LengthMismatches_ReturnsFalse()
    {
        byte[] key32 = new byte[32];
        Random.Shared.NextBytes(key32);

        using var secure = SecureMemory.Create(key32);

        Assert.False(secure.ConstantTimeEquals(key32.AsSpan(0, 31)));
        Assert.False(secure.ConstantTimeEquals(key32.AsSpan(0, 16)));
        Assert.False(secure.ConstantTimeEquals(key32.AsSpan(0, 1)));
        Assert.False(secure.ConstantTimeEquals(ReadOnlySpan<byte>.Empty));

        byte[] key33 = new byte[33];
        key32.CopyTo(key33, 0);
        Assert.False(secure.ConstantTimeEquals(key33));
    }

    [Fact]
    public void UnmanagedSlabPool_ZeroMemoryScrubbing_VerifiesMemoryClearedOnReturn()
    {
        using var pool = new UnmanagedSlabPool(maxSmallSlabs: 16, maxLargeSlabs: 4);

        // Test 64 KB slab
        IntPtr slab64 = pool.Rent(64 * 1024, out int size64);
        Assert.True(size64 >= 64 * 1024);

        // Fill entire 64 KB with non-zero pattern
        new Span<byte>((void*)slab64, size64).Fill(0xD7);

        // Return slab (should zero out memory)
        pool.Return(slab64, size64);

        // Re-rent slab and assert 100% of bytes are zeroed
        IntPtr reRented64 = pool.Rent(64 * 1024, out int reSize64);
        Assert.Equal(slab64, reRented64);

        var span64 = new ReadOnlySpan<byte>((void*)reRented64, reSize64);
        for (int i = 0; i < reSize64; i++)
        {
            Assert.Equal((byte)0, span64[i]);
        }
        pool.Return(reRented64, reSize64);

        // Test 1 MB slab
        IntPtr slab1M = pool.Rent(1024 * 1024, out int size1M);
        Assert.True(size1M >= 1024 * 1024);

        new Span<byte>((void*)slab1M, size1M).Fill(0xE5);
        pool.Return(slab1M, size1M);

        IntPtr reRented1M = pool.Rent(1024 * 1024, out int reSize1M);
        Assert.Equal(slab1M, reRented1M);

        var span1M = new ReadOnlySpan<byte>((void*)reRented1M, reSize1M);
        for (int i = 0; i < reSize1M; i++)
        {
            Assert.Equal((byte)0, span1M[i]);
        }
        pool.Return(reRented1M, reSize1M);
    }

    [Fact]
    public void SecureMemory_DisposedAccess_ThrowsObjectDisposedException()
    {
        var secure = new SecureMemory(32);
        secure.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { var _ = secure.Span; });
        Assert.Throws<ObjectDisposedException>(() => { var _ = secure.ReadOnlySpan; });
        Assert.Throws<ObjectDisposedException>(() => { var _ = secure.Pointer; });
        Assert.Throws<ObjectDisposedException>(() => secure.ConstantTimeEquals(new byte[32]));

        // Double dispose must not throw
        secure.Dispose();
    }

    // =========================================================================
    // 3. HARDWARE ARBITER BOUNDARY FUZZING TESTS
    // =========================================================================

    [Theory]
    [InlineData(0, 1, true, ExecutionTarget.CpuVector)]
    [InlineData(0, 15, true, ExecutionTarget.CpuVector)]
    [InlineData(0, 16, true, ExecutionTarget.CpuVector)]
    [InlineData(0, 32, true, ExecutionTarget.CpuVector)]
    [InlineData(1, 1, true, ExecutionTarget.CpuVector)]
    [InlineData(1024 * 1024 - 1, 1, true, ExecutionTarget.CpuVector)]
    [InlineData(1024 * 1024 - 1, 15, true, ExecutionTarget.CpuVector)]
    [InlineData(1024 * 1024, 1, true, ExecutionTarget.CpuParallelPool)]
    [InlineData(1024 * 1024, 15, true, ExecutionTarget.CpuParallelPool)]
    [InlineData(1024 * 1024 + 1, 1, true, ExecutionTarget.CpuParallelPool)]
    [InlineData(4 * 1024 * 1024 - 1, 1, true, ExecutionTarget.CpuParallelPool)]
    [InlineData(4 * 1024 * 1024 - 1, 15, true, ExecutionTarget.CpuParallelPool)]
    [InlineData(4 * 1024 * 1024, 1, true, ExecutionTarget.GpuCompute)]
    [InlineData(4 * 1024 * 1024 + 1, 1, true, ExecutionTarget.GpuCompute)]
    [InlineData(16 * 1024 * 1024, 1, true, ExecutionTarget.GpuCompute)]
    [InlineData(4 * 1024 * 1024, 1, false, ExecutionTarget.CpuParallelPool)]
    [InlineData(16 * 1024 * 1024, 1, false, ExecutionTarget.CpuParallelPool)]
    [InlineData(1, 16, true, ExecutionTarget.GpuCompute)]
    [InlineData(512 * 1024, 16, true, ExecutionTarget.GpuCompute)]
    [InlineData(512 * 1024, 32, true, ExecutionTarget.GpuCompute)]
    [InlineData(512 * 1024, 16, false, ExecutionTarget.CpuParallelPool)]
    [InlineData(512 * 1024, 32, false, ExecutionTarget.CpuParallelPool)]
    public void HardwareArbiter_ThresholdBoundaries_ExactRoutingMatch(
        int payloadBytes, int batchCount, bool gpuAvailable, ExecutionTarget expected)
    {
        ExecutionTarget actual = HardwareArbiter.RouteWorkload(payloadBytes, batchCount, gpuAvailable);
        Assert.Equal(expected, actual);

        // Verify helper methods
        if (expected == ExecutionTarget.GpuCompute)
        {
            Assert.True(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable));
            Assert.False(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
        }
        else if (expected == ExecutionTarget.CpuVector)
        {
            Assert.False(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable));
            Assert.True(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
        }
        else
        {
            Assert.False(HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount, gpuAvailable));
            Assert.False(HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
        }
    }

    [Theory]
    [InlineData(-1, 1)]
    [InlineData(-1024, 1)]
    [InlineData(-1048576, 1)]
    [InlineData(int.MinValue, 1)]
    public void HardwareArbiter_NegativePayload_ThrowsArgumentOutOfRangeException(int payloadBytes, int batchCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(payloadBytes, batchCount));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
    }

    [Theory]
    [InlineData(1024, 0)]
    [InlineData(1024, -1)]
    [InlineData(1024, -16)]
    [InlineData(1024, int.MinValue)]
    public void HardwareArbiter_InvalidBatchCount_ThrowsArgumentOutOfRangeException(int payloadBytes, int batchCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(payloadBytes, batchCount));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.ShouldOffloadToGpu(payloadBytes, batchCount));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.ShouldVectorizeCpu(payloadBytes, batchCount));
    }

    [Fact]
    public void HardwareArbiter_ComprehensiveFuzzing_10000RandomCombinations()
    {
        var rng = new Random(9999);
        const int fuzzCount = 10000;

        for (int i = 0; i < fuzzCount; i++)
        {
            // Random thresholds
            int cpuThreshold = rng.Next(1024, 2 * 1024 * 1024);
            int gpuThreshold = rng.Next(cpuThreshold + 1024, 16 * 1024 * 1024);
            int batchThreshold = rng.Next(2, 64);

            var options = new HardwareArbiterOptions(
                CpuVectorThresholdBytes: cpuThreshold,
                GpuSizeThresholdBytes: gpuThreshold,
                GpuBatchThresholdCount: batchThreshold);

            // Random inputs
            int payload = rng.Next(0, 32 * 1024 * 1024);
            int batch = rng.Next(1, 128);
            bool gpu = rng.Next(2) == 1;

            ExecutionTarget expected;
            if (payload == 0)
            {
                expected = ExecutionTarget.CpuVector;
            }
            else if (payload < cpuThreshold && batch < batchThreshold)
            {
                expected = ExecutionTarget.CpuVector;
            }
            else if (payload >= gpuThreshold || batch >= batchThreshold)
            {
                expected = gpu ? ExecutionTarget.GpuCompute : ExecutionTarget.CpuParallelPool;
            }
            else
            {
                expected = ExecutionTarget.CpuParallelPool;
            }

            ExecutionTarget actual = HardwareArbiter.RouteWorkload(payload, batch, gpu, in options);
            Assert.Equal(expected, actual);
        }
    }
}
