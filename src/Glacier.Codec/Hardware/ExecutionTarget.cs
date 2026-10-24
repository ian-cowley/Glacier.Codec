namespace Glacier.Codec.Hardware;

/// <summary>
/// Execution pipeline target selected by the hardware arbiter.
/// </summary>
public enum ExecutionTarget : byte
{
    /// <summary>
    /// Synchronous execution on the calling thread utilizing CPU vector registers (AVX-512 / AVX2 / ARM Neon).
    /// Optimized for sub-microsecond latency on small payloads (&lt; 1 MB).
    /// </summary>
    CpuVector = 0,

    /// <summary>
    /// In-process multi-threaded thread pool utilizing work-stealing parallelism across logical CPU cores.
    /// Selected for intermediate workloads (1 MB to &lt; 4 MB) or when GPU hardware is unavailable.
    /// </summary>
    CpuParallelPool = 1,

    /// <summary>
    /// Asynchronous GPU compute pipeline executing Direct3D 12 / Vulkan compute shaders.
    /// Selected for massive payloads (&gt;= 4 MB) or batched requests (&gt;= 16 streams) where GPU compute throughput
    /// amortizes kernel dispatch and PCIe transfer overhead.
    /// </summary>
    GpuCompute = 2
}
