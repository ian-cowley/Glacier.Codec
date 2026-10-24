#if !HAS_GLACIER_CODEC

#pragma warning disable SYSLIB5003

using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace Glacier.Codec.Hardware
{
    public readonly record struct HardwareArbiterOptions(
        int CpuVectorThresholdBytes = HardwareArbiter.DefaultCpuVectorThresholdBytes,
        int GpuSizeThresholdBytes = HardwareArbiter.DefaultGpuSizeThresholdBytes,
        int GpuBatchThresholdCount = HardwareArbiter.DefaultGpuBatchThresholdCount);

    public static class CpuCapabilities
    {
        private static readonly bool s_hasShaNi;
        private static readonly bool s_hasVectorAes;

        static CpuCapabilities()
        {
            if (X86Base.IsSupported)
            {
                try
                {
                    var (_, ebx, ecx, _) = X86Base.CpuId(7, 0);
                    s_hasShaNi = (ebx & (1 << 29)) != 0;
                    s_hasVectorAes = (ecx & (1 << 9)) != 0 && (Avx512F.IsSupported || System.Runtime.Intrinsics.X86.Aes.IsSupported);
                }
                catch
                {
                    s_hasShaNi = false;
                    s_hasVectorAes = false;
                }
            }
        }

        // Architecture Information
        public static bool IsX86_64 => RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.X86;
        public static bool IsArm64 => RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
        public static int LogicalCoreCount => Environment.ProcessorCount;

        // x86-64 Vector & AVX-512 Extensions
        public static bool HasAvx512F => Avx512F.IsSupported;
        public static bool HasAvx512BW => Avx512BW.IsSupported;
        public static bool HasAvx512DQ => Avx512DQ.IsSupported;
        public static bool HasAvx512CD => Avx512CD.IsSupported;
        public static bool HasAvx512VL => Avx512F.VL.IsSupported;
        public static bool HasAvx512Vbmi => Avx512Vbmi.IsSupported;
        public static bool HasAvx512Vbmi2 => Avx512Vbmi2.IsSupported;
        public static bool HasAvx2 => Avx2.IsSupported;
        public static bool HasAvx => Avx.IsSupported;
        public static bool HasFma => Fma.IsSupported;

        // x86-64 Cryptographic Extensions
        public static bool HasAesNi => System.Runtime.Intrinsics.X86.Aes.IsSupported;
        public static bool HasPclmulqdq => Pclmulqdq.IsSupported;
        public static bool HasPclmulqdqV256 => Pclmulqdq.V256.IsSupported;
        public static bool HasPclmulqdqV512 => Pclmulqdq.V512.IsSupported && Avx512BW.IsSupported && Vector512.IsHardwareAccelerated;
        public static bool HasVpclmulqdq => Pclmulqdq.V512.IsSupported && Avx512BW.IsSupported && Vector512.IsHardwareAccelerated;
        public static bool HasVectorAes => s_hasVectorAes;
        public static bool HasShaNi => s_hasShaNi;
        public static bool HasGfni => Gfni.IsSupported;
        public static bool HasGfniV512 => Gfni.V512.IsSupported;

        // ARM64 Extensions
        public static bool HasArm64AdvSimd => AdvSimd.Arm64.IsSupported;
        public static bool HasArm64Aes => System.Runtime.Intrinsics.Arm.Aes.Arm64.IsSupported;
        public static bool HasArm64Sha256 => System.Runtime.Intrinsics.Arm.Sha256.Arm64.IsSupported;
        public static bool HasArm64Sha1 => System.Runtime.Intrinsics.Arm.Sha1.Arm64.IsSupported;
        public static bool HasArm64Crc32 => System.Runtime.Intrinsics.Arm.Crc32.Arm64.IsSupported;
        public static bool HasArm64Dp => Dp.Arm64.IsSupported;
        public static bool HasArm64Sve => Sve.IsSupported;

        // Generic Hardware Acceleration Width
        public static bool HasVector512 => Vector512.IsHardwareAccelerated;
        public static bool HasVector256 => Vector256.IsHardwareAccelerated;
        public static bool HasVector128 => Vector128.IsHardwareAccelerated;

        public static HardwareTier DetectedTier
        {
            get
            {
                if (IsX86_64)
                {
                    if (HasAvx512F && HasAvx512BW && (HasVectorAes || HasAesNi))
                    {
                        return HardwareTier.Tier0_UltrawideVector;
                    }
                    if (HasAvx2 && HasAesNi)
                    {
                        return HardwareTier.Tier1_MainstreamVector;
                    }
                }
                else if (IsArm64)
                {
                    if (HasArm64AdvSimd && HasArm64Aes && HasArm64Sha256)
                    {
                        return HardwareTier.Tier0_UltrawideVector;
                    }
                    if (HasArm64AdvSimd)
                    {
                        return HardwareTier.Tier1_MainstreamVector;
                    }
                }

                return HardwareTier.Tier2_ScalarFallback;
            }
        }
    }

    public static class HardwareArbiter
    {
        public const int DefaultCpuVectorThresholdBytes = 1024 * 1024; // 1 MB
        public const int DefaultGpuSizeThresholdBytes = 4 * 1024 * 1024; // 4 MB
        public const int DefaultGpuBatchThresholdCount = 16;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ExecutionTarget RouteWorkload(int payloadBytes, int batchCount = 1, bool gpuAvailable = true)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(payloadBytes);
            ArgumentOutOfRangeException.ThrowIfLessThan(batchCount, 1);

            if (payloadBytes == 0)
            {
                return ExecutionTarget.CpuVector;
            }

            if (payloadBytes < DefaultCpuVectorThresholdBytes && batchCount < DefaultGpuBatchThresholdCount)
            {
                return ExecutionTarget.CpuVector;
            }

            if (payloadBytes >= DefaultGpuSizeThresholdBytes || batchCount >= DefaultGpuBatchThresholdCount)
            {
                return gpuAvailable ? ExecutionTarget.GpuCompute : ExecutionTarget.CpuParallelPool;
            }

            return ExecutionTarget.CpuParallelPool;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ExecutionTarget RouteWorkload(int payloadBytes, int batchCount, bool gpuAvailable, in HardwareArbiterOptions options)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(payloadBytes);
            ArgumentOutOfRangeException.ThrowIfLessThan(batchCount, 1);

            if (payloadBytes == 0)
            {
                return ExecutionTarget.CpuVector;
            }

            if (payloadBytes < options.CpuVectorThresholdBytes && batchCount < options.GpuBatchThresholdCount)
            {
                return ExecutionTarget.CpuVector;
            }

            if (payloadBytes >= options.GpuSizeThresholdBytes || batchCount >= options.GpuBatchThresholdCount)
            {
                return gpuAvailable ? ExecutionTarget.GpuCompute : ExecutionTarget.CpuParallelPool;
            }

            return ExecutionTarget.CpuParallelPool;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool ShouldOffloadToGpu(int payloadBytes, int batchCount = 1, bool gpuAvailable = true)
        {
            return RouteWorkload(payloadBytes, batchCount, gpuAvailable) == ExecutionTarget.GpuCompute;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool ShouldVectorizeCpu(int payloadBytes, int batchCount = 1)
        {
            return RouteWorkload(payloadBytes, batchCount) == ExecutionTarget.CpuVector;
        }
    }
}

namespace Glacier.Codec.Memory
{
    public unsafe sealed class CachelineAlignedBuffer : IDisposable
    {
        private void* _ptr;
        private readonly nuint _byteLength;
        private bool _disposed;

        public CachelineAlignedBuffer(int byteLength)
        {
            if (byteLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(byteLength), "Buffer length must be greater than zero.");

            _byteLength = (nuint)byteLength;
            _ptr = NativeMemory.AlignedAlloc(_byteLength, 64);
            NativeMemory.Clear(_ptr, _byteLength);
        }

        public Span<byte> Span
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(CachelineAlignedBuffer));
                return new Span<byte>(_ptr, (int)_byteLength);
            }
        }

        public IntPtr Pointer => (IntPtr)_ptr;
        public int Length => (int)_byteLength;

        public bool IsAlignedTo64Bytes => ((nuint)_ptr % 64) == 0;

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != null)
                {
                    CryptographicOperations.ZeroMemory(new Span<byte>(_ptr, (int)_byteLength));
                    NativeMemory.AlignedFree(_ptr);
                    _ptr = null;
                }
                _disposed = true;
            }
        }
    }

    public unsafe sealed class UnmanagedSlabPool : IDisposable
    {
        private readonly ConcurrentBag<IntPtr> _slabs64K = new();
        private readonly ConcurrentBag<IntPtr> _slabs1M = new();
        private readonly List<IntPtr> _allAllocations = new();
        private readonly object _lock = new();
        private bool _disposed;

        public const int SlabSize64K = 64 * 1024;
        public const int SlabSize1M = 1024 * 1024;

        public IntPtr Rent(int minSize, out int actualSize)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(UnmanagedSlabPool));

            if (minSize <= SlabSize64K)
            {
                actualSize = SlabSize64K;
                if (_slabs64K.TryTake(out IntPtr cached))
                    return cached;
                return AllocateAligned(SlabSize64K);
            }

            actualSize = Math.Max(minSize, SlabSize1M);
            if (actualSize == SlabSize1M && _slabs1M.TryTake(out IntPtr cached1M))
                return cached1M;

            return AllocateAligned(actualSize);
        }

        public void Return(IntPtr ptr, int size)
        {
            if (_disposed)
            {
                NativeMemory.AlignedFree((void*)ptr);
                return;
            }

            // Zero memory before placing back in pool
            CryptographicOperations.ZeroMemory(new Span<byte>((void*)ptr, size));

            if (size == SlabSize64K)
            {
                _slabs64K.Add(ptr);
            }
            else if (size == SlabSize1M)
            {
                _slabs1M.Add(ptr);
            }
            else
            {
                lock (_lock)
                {
                    _allAllocations.Remove(ptr);
                }
                NativeMemory.AlignedFree((void*)ptr);
            }
        }

        private IntPtr AllocateAligned(int size)
        {
            void* ptr = NativeMemory.AlignedAlloc((nuint)size, 64);
            NativeMemory.Clear(ptr, (nuint)size);
            lock (_lock)
            {
                _allAllocations.Add((IntPtr)ptr);
            }
            return (IntPtr)ptr;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                lock (_lock)
                {
                    foreach (var ptr in _allAllocations)
                    {
                        NativeMemory.AlignedFree((void*)ptr);
                    }
                    _allAllocations.Clear();
                }
                _disposed = true;
            }
        }
    }

    public unsafe sealed class SecureMemory : IDisposable
    {
        private void* _ptr;
        private readonly int _length;
        private bool _disposed;

        public SecureMemory(int size)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size));
            _length = size;
            _ptr = NativeMemory.AllocZeroed((nuint)size);
        }

        public SecureMemory(ReadOnlySpan<byte> initialData) : this(initialData.Length)
        {
            initialData.CopyTo(new Span<byte>(_ptr, _length));
        }

        public Span<byte> Span
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(SecureMemory));
                return new Span<byte>(_ptr, _length);
            }
        }

        public int Length => _length;

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != null)
                {
                    CryptographicOperations.ZeroMemory(new Span<byte>(_ptr, _length));
                    NativeMemory.Free(_ptr);
                    _ptr = null;
                }
                _disposed = true;
            }
        }
    }
}

#endif
