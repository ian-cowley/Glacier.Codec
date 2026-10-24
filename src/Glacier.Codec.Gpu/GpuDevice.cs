using System;
using Glacier.Codec.Gpu.Drivers;

namespace Glacier.Codec.Gpu;

/// <summary>
/// Encapsulates an NVIDIA CUDA GPU execution context and device telemetry.
/// </summary>
public sealed class GpuDevice : IDisposable
{
    private IntPtr _context;
    private readonly int _deviceOrdinal;
    private readonly string _deviceName;
    private readonly string _computeCapability;
    private readonly int _smCount;
    private readonly long _totalMemoryBytes;
    private bool _disposed;

    public int DeviceOrdinal => _deviceOrdinal;
    public string DeviceName => _deviceName;
    public string ComputeCapability => _computeCapability;
    public int MultiprocessorCount => _smCount;
    public long TotalMemoryBytes => _totalMemoryBytes;
    public IntPtr ContextHandle => _context;

    private GpuDevice(int ordinal, IntPtr context, string name, string cc, int smCount, long memBytes)
    {
        _deviceOrdinal = ordinal;
        _context = context;
        _deviceName = name;
        _computeCapability = cc;
        _smCount = smCount;
        _totalMemoryBytes = memBytes;
    }

    /// <summary>
    /// Gets the number of CUDA-capable GPU devices available in the system.
    /// </summary>
    public static int GetDeviceCount()
    {
        if (!CuDriver.IsAvailable) return 0;
        try
        {
            if (CuDriver.Init(0) != 0) return 0;
            if (CuDriver.DeviceGetCount(out int count) != 0) return 0;
            return count;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Initializes and creates a GPU context on the specified device ordinal (default 0).
    /// </summary>
    public static GpuDevice Create(int deviceOrdinal = 0)
    {
        if (!CuDriver.IsAvailable)
            throw new PlatformNotSupportedException("NVIDIA CUDA driver (nvcuda.dll) is not available.");

        CuDriver.Check(CuDriver.Init(0), "cuInit");
        CuDriver.Check(CuDriver.DeviceGetCount(out int count), "cuDeviceGetCount");
        if (deviceOrdinal < 0 || deviceOrdinal >= count)
            throw new ArgumentOutOfRangeException(nameof(deviceOrdinal), $"Invalid device ordinal {deviceOrdinal}. System has {count} CUDA device(s).");

        CuDriver.Check(CuDriver.DeviceGet(out int dev, deviceOrdinal), "cuDeviceGet");
        string name = CuDriver.GetDeviceName(dev);
        string cc = CuDriver.GetComputeCapability(dev);
        int smCount = CuDriver.GetMultiprocessorCount(dev);
        CuDriver.Check(CuDriver.DeviceTotalMem(out nuint totalMem, dev), "cuDeviceTotalMem");

        CuDriver.Check(CuDriver.CtxCreate(out IntPtr ctx, 0, dev), "cuCtxCreate");
        return new GpuDevice(deviceOrdinal, ctx, name, cc, smCount, (long)totalMem);
    }

    /// <summary>
    /// Makes this GPU context current on the calling thread.
    /// </summary>
    public void MakeCurrent()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CuDriver.Check(CuDriver.CtxSetCurrent(_context), "cuCtxSetCurrent");
    }

    /// <summary>
    /// Synchronizes all pending GPU commands on this context.
    /// </summary>
    public void Synchronize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        MakeCurrent();
        CuDriver.Check(CuDriver.CtxSynchronize(), "cuCtxSynchronize");
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_context != IntPtr.Zero)
            {
                CuDriver.CtxDestroy(_context);
                _context = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
