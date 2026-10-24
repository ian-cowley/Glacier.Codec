namespace Glacier.Codec.Hardware;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Configuration options for the hardware arbiter workload routing thresholds.
/// </summary>
/// <param name="CpuVectorThresholdBytes">Payload size threshold below which CPU vector units are favored (default: 1 MB).</param>
/// <param name="GpuSizeThresholdBytes">Payload size threshold above which GPU compute shaders are favored (default: 4 MB).</param>
/// <param name="GpuBatchThresholdCount">Batch stream count above which GPU compute shaders are favored (default: 16).</param>
public readonly record struct HardwareArbiterOptions(
    int CpuVectorThresholdBytes = HardwareArbiter.DefaultCpuVectorThresholdBytes,
    int GpuSizeThresholdBytes = HardwareArbiter.DefaultGpuSizeThresholdBytes,
    int GpuBatchThresholdCount = HardwareArbiter.DefaultGpuBatchThresholdCount);

/// <summary>
/// Decides whether a given payload routes to ultra-low-latency CPU vector registers,
/// multi-threaded CPU thread pools, or asynchronous GPU compute pipelines.
/// </summary>
public static class HardwareArbiter
{
    /// <summary>
    /// Default threshold (1 MB) below which CPU vector registers achieve lower end-to-end latency
    /// than GPU dispatch overhead or thread context-switching.
    /// </summary>
    public const int DefaultCpuVectorThresholdBytes = 1024 * 1024; // 1 MB

    /// <summary>
    /// Default threshold (4 MB) above which massive GPU compute throughput and high VRAM bandwidth
    /// outperform CPU thread pools.
    /// </summary>
    public const int DefaultGpuSizeThresholdBytes = 4 * 1024 * 1024; // 4 MB

    /// <summary>
    /// Default batch stream count (16) at which parallel GPU work queues amortize PCIe and dispatch overhead.
    /// </summary>
    public const int DefaultGpuBatchThresholdCount = 16;

    /// <summary>
    /// Routes a workload based on payload size and batch count using default system thresholds.
    /// </summary>
    /// <param name="payloadBytes">Total payload size in bytes.</param>
    /// <param name="batchCount">Number of concurrent or batched streams (defaults to 1).</param>
    /// <param name="gpuAvailable">Whether a GPU compute engine is initialized and available.</param>
    /// <returns>Selected <see cref="ExecutionTarget"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ExecutionTarget RouteWorkload(int payloadBytes, int batchCount = 1, bool gpuAvailable = true)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(payloadBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(batchCount, 1);

        // Rule 0: Empty payload always stays on CPU vector/scalar
        if (payloadBytes == 0)
        {
            return ExecutionTarget.CpuVector;
        }

        // Rule 1: Small streams (< 1MB) and low batch count execute CPU SIMD for sub-microsecond latency
        if (payloadBytes < DefaultCpuVectorThresholdBytes && batchCount < DefaultGpuBatchThresholdCount)
        {
            return ExecutionTarget.CpuVector;
        }

        // Rule 2: Multi-megabyte (>= 4MB) or batched streams (>= 16) dispatch to GPU if available
        if (payloadBytes >= DefaultGpuSizeThresholdBytes || batchCount >= DefaultGpuBatchThresholdCount)
        {
            return gpuAvailable ? ExecutionTarget.GpuCompute : ExecutionTarget.CpuParallelPool;
        }

        // Rule 3: Intermediate sizes (1MB to < 4MB) route to CPU thread pool
        return ExecutionTarget.CpuParallelPool;
    }

    /// <summary>
    /// Routes a workload based on custom threshold options.
    /// </summary>
    /// <param name="payloadBytes">Total payload size in bytes.</param>
    /// <param name="batchCount">Number of concurrent or batched streams.</param>
    /// <param name="gpuAvailable">Whether a GPU compute engine is initialized and available.</param>
    /// <param name="options">Custom arbiter threshold options.</param>
    /// <returns>Selected <see cref="ExecutionTarget"/>.</returns>
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

    /// <summary>
    /// Returns true if the workload should be offloaded to GPU compute.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ShouldOffloadToGpu(int payloadBytes, int batchCount = 1, bool gpuAvailable = true)
    {
        return RouteWorkload(payloadBytes, batchCount, gpuAvailable) == ExecutionTarget.GpuCompute;
    }

    /// <summary>
    /// Returns true if the workload should execute on single-threaded CPU vector registers.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ShouldVectorizeCpu(int payloadBytes, int batchCount = 1)
    {
        return RouteWorkload(payloadBytes, batchCount) == ExecutionTarget.CpuVector;
    }
}
