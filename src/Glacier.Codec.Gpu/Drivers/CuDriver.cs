using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Glacier.Codec.Gpu.Drivers;

/// <summary>
/// Direct, zero-overhead P/Invoke bindings for the NVIDIA CUDA Driver API (nvcuda.dll / libcuda.so).
/// Directly targets driver-level entry points without requiring the CUDA Toolkit or cudart runtime.
/// </summary>
public static class CuDriver
{
    private const string CudaLibWindows = "nvcuda.dll";
    private const string CudaLibLinux = "libcuda.so.1";

    private static readonly Lazy<bool> _isAvailable = new(() =>
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return NativeLibrary.TryLoad(CudaLibWindows, out IntPtr handle) && handle != IntPtr.Zero;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return (NativeLibrary.TryLoad(CudaLibLinux, out IntPtr handle) ||
                        NativeLibrary.TryLoad("libcuda.so", out handle)) && handle != IntPtr.Zero;
            }
            return false;
        }
        catch
        {
            return false;
        }
    });

    /// <summary>
    /// Gets whether the underlying NVIDIA CUDA driver library is present and loadable.
    /// </summary>
    public static bool IsAvailable => _isAvailable.Value;

    [DllImport(CudaLibWindows, EntryPoint = "cuInit")]
    public static extern int Init(uint flags);

    [DllImport(CudaLibWindows, EntryPoint = "cuDriverGetVersion")]
    public static extern int DriverGetVersion(out int driverVersion);

    [DllImport(CudaLibWindows, EntryPoint = "cuDeviceGetCount")]
    public static extern int DeviceGetCount(out int count);

    [DllImport(CudaLibWindows, EntryPoint = "cuDeviceGet")]
    public static extern int DeviceGet(out int device, int ordinal);

    [DllImport(CudaLibWindows, EntryPoint = "cuDeviceGetName")]
    public static extern int DeviceGetName(byte[] name, int len, int dev);

    [DllImport(CudaLibWindows, EntryPoint = "cuDeviceTotalMem_v2")]
    public static extern int DeviceTotalMem(out nuint bytes, int dev);

    [DllImport(CudaLibWindows, EntryPoint = "cuDeviceGetAttribute")]
    public static extern int DeviceGetAttribute(out int pi, int attrib, int dev);

    [DllImport(CudaLibWindows, EntryPoint = "cuCtxCreate_v2")]
    public static extern int CtxCreate(out IntPtr pctx, uint flags, int dev);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuCtxSetCurrent")]
    public static extern int CtxSetCurrent(IntPtr ctx);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuCtxGetCurrent")]
    public static extern int CtxGetCurrent(out IntPtr pctx);

    [DllImport(CudaLibWindows, EntryPoint = "cuCtxDestroy_v2")]
    public static extern int CtxDestroy(IntPtr ctx);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuCtxSynchronize")]
    public static extern int CtxSynchronize();

    [DllImport(CudaLibWindows, EntryPoint = "cuModuleLoadData")]
    public static extern int ModuleLoadData(out IntPtr module, byte[] image);

    [DllImport(CudaLibWindows, EntryPoint = "cuModuleUnload")]
    public static extern int ModuleUnload(IntPtr module);

    [DllImport(CudaLibWindows, EntryPoint = "cuModuleGetFunction")]
    public static extern int ModuleGetFunction(out IntPtr hfunc, IntPtr hmod, string name);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemAlloc_v2")]
    public static extern int MemAlloc(out IntPtr dptr, nuint bytesize);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemFree_v2")]
    public static extern int MemFree(IntPtr dptr);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemcpyHtoD_v2")]
    public static extern int MemcpyHtoD(IntPtr dstDevice, IntPtr srcHost, nuint byteCount);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemcpyDtoH_v2")]
    public static extern int MemcpyDtoH(IntPtr dstHost, IntPtr srcDevice, nuint byteCount);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemcpyHtoDAsync_v2")]
    public static extern int MemcpyHtoDAsync(IntPtr dstDevice, IntPtr srcHost, nuint byteCount, IntPtr hStream);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuMemcpyDtoHAsync_v2")]
    public static extern int MemcpyDtoHAsync(IntPtr dstHost, IntPtr srcDevice, nuint byteCount, IntPtr hStream);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuLaunchKernel")]
    public static extern int LaunchKernel(
        IntPtr f,
        uint gridDimX, uint gridDimY, uint gridDimZ,
        uint blockDimX, uint blockDimY, uint blockDimZ,
        uint sharedMemBytes, IntPtr hStream,
        IntPtr kernelParams, IntPtr extra);

    [DllImport(CudaLibWindows, EntryPoint = "cuStreamCreate")]
    public static extern int StreamCreate(out IntPtr phStream, uint flags);

    [SuppressGCTransition]
    [DllImport(CudaLibWindows, EntryPoint = "cuStreamSynchronize")]
    public static extern int StreamSynchronize(IntPtr hStream);

    [DllImport(CudaLibWindows, EntryPoint = "cuStreamDestroy_v2")]
    public static extern int StreamDestroy(IntPtr hStream);

    public static string GetDeviceName(int device)
    {
        var buf = new byte[256];
        DeviceGetName(buf, buf.Length, device);
        return Encoding.ASCII.GetString(buf).TrimEnd('\0');
    }

    public static string GetComputeCapability(int device)
    {
        DeviceGetAttribute(out int major, 75 /* CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR */, device);
        DeviceGetAttribute(out int minor, 76 /* CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR */, device);
        return $"sm_{major}{minor}";
    }

    public static int GetMultiprocessorCount(int device)
    {
        DeviceGetAttribute(out int smCount, 16 /* CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT */, device);
        return smCount;
    }

    public static void Check(int res, string op)
    {
        if (res != 0)
        {
            throw new InvalidOperationException($"CUDA Driver API Error during '{op}': code {res}");
        }
    }
}
