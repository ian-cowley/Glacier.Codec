using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Vortice.D3DCompiler;
using Vortice.Direct3D;
using Vortice.Direct3D12;
using Vortice.DXGI;

namespace Glacier.Codec.Gpu.Engines;

/// <summary>
/// Direct3D 12 DirectCompute engine for single-block 64-byte BLAKE3 and SHA-256 nonce search
/// across Windows DXGI adapters (AMD Radeon, Intel, and NVIDIA).
/// </summary>
public sealed unsafe class GpuD3D12Engine : IDisposable
{
    private const uint DefaultResultsCapacity = 64;

    private readonly Lock _execLock = new();
    private IDXGIFactory4? _factory;
    private IDXGIAdapter1? _adapter;
    private ID3D12Device? _device;
    private ID3D12CommandQueue? _queue;
    private ID3D12CommandAllocator? _cmdAlloc;
    private ID3D12GraphicsCommandList? _cmdList;
    private ID3D12Fence? _fence;
    private ulong _fenceValue;
    private AutoResetEvent? _fenceEvent;

    private ID3D12RootSignature? _rootSig;
    private ID3D12PipelineState? _psoBlake3;
    private ID3D12PipelineState? _psoSha256;

    // Persistent pooled D3D12 buffers
    private ID3D12Resource? _tmplUploadBuffer;
    private ID3D12Resource? _zeroUploadBuffer;
    private ID3D12Resource? _foundCountGpu;
    private ID3D12Resource? _readbackCount;
    private ID3D12Resource? _foundNoncesGpu;
    private ID3D12Resource? _readbackResults;
    private uint _resultsCapacity;

    private readonly string _adapterName = string.Empty;
    private readonly bool _isAmdRadeon;
    private bool _disposed;

    public string AdapterName => _adapterName;
    public bool IsAmdRadeon => _isAmdRadeon;

    [StructLayout(LayoutKind.Sequential)]
    private struct MiningParams
    {
        public uint BaseNonce;
        public uint TargetMask;
        public uint MaxEvaluations;
        public uint MaxResults;
        public uint Extra;
        public uint Pad0;
        public uint Pad1;
        public uint Pad2;
    }

    public GpuD3D12Engine(string? preferredGpuName = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Direct3D 12 Compute is only supported on Windows.");

        try
        {
            _factory = DXGI.CreateDXGIFactory1<IDXGIFactory4>();

            // Enumerate adapters
            IDXGIAdapter1? chosen = null;
            for (uint i = 0; _factory.EnumAdapters1(i, out IDXGIAdapter1 a).Success; i++)
            {
                var desc = a.Description1;
                string name = desc.Description;
                if ((desc.Flags & AdapterFlags.Software) != 0 || name.Contains("Basic Render", StringComparison.OrdinalIgnoreCase))
                {
                    a.Dispose();
                    continue;
                }

                if (!string.IsNullOrEmpty(preferredGpuName) && name.Contains(preferredGpuName, StringComparison.OrdinalIgnoreCase))
                {
                    chosen?.Dispose();
                    chosen = a;
                    break;
                }

                // Strongly prefer AMD Radeon GPU
                if (name.Contains("Radeon", StringComparison.OrdinalIgnoreCase))
                {
                    chosen?.Dispose();
                    chosen = a;
                    break;
                }

                if (chosen == null)
                {
                    chosen = a;
                }
                else
                {
                    a.Dispose();
                }
            }

            _adapter = chosen ?? throw new InvalidOperationException("No suitable Direct3D 12 GPU adapter found.");
            _adapterName = _adapter.Description1.Description;
            _isAmdRadeon = _adapterName.Contains("Radeon", StringComparison.OrdinalIgnoreCase);

            if (D3D12.D3D12CreateDevice(_adapter, FeatureLevel.Level_11_0, out ID3D12Device? dev).Failure)
                throw new InvalidOperationException($"Failed to create Direct3D 12 device on {_adapterName}");

            _device = dev!;

            var queueDesc = new CommandQueueDescription(CommandListType.Compute);
            _queue = _device.CreateCommandQueue(queueDesc);
            _cmdAlloc = _device.CreateCommandAllocator(CommandListType.Compute);
            _cmdList = _device.CreateCommandList<ID3D12GraphicsCommandList>(0, CommandListType.Compute, _cmdAlloc);
            _cmdList.Close();

            _fence = _device.CreateFence(0);
            _fenceValue = 0;
            _fenceEvent = new AutoResetEvent(false);

            // Root Signature:
            // Root Parameter 0: 32-bit constants (b0) -> 8 uints
            // Root Parameter 1: Shader Resource View (t0 SRV)
            // Root Parameter 2: Unordered Access View (u0 UAV)
            // Root Parameter 3: Unordered Access View (u1 UAV)
            var rootParams = new RootParameter1[]
            {
                new RootParameter1(new RootConstants(0, 0, 8), ShaderVisibility.All), // b0
                new RootParameter1(RootParameterType.ShaderResourceView, new RootDescriptor1(0, 0), ShaderVisibility.All), // t0
                new RootParameter1(RootParameterType.UnorderedAccessView, new RootDescriptor1(0, 0), ShaderVisibility.All), // u0
                new RootParameter1(RootParameterType.UnorderedAccessView, new RootDescriptor1(1, 0), ShaderVisibility.All), // u1
            };

            var rootSigDesc = new VersionedRootSignatureDescription(new RootSignatureDescription1(
                RootSignatureFlags.None,
                rootParams));

            _rootSig = _device.CreateRootSignature(rootSigDesc);

            // Compile HLSL Compute Shaders
            byte[] blake3Bytecode = CompileShader("blake3_compute.hlsl");
            byte[] sha256Bytecode = CompileShader("sha256_compute.hlsl");

            var psoDescBlake3 = new ComputePipelineStateDescription
            {
                RootSignature = _rootSig,
                ComputeShader = blake3Bytecode
            };
            _psoBlake3 = _device.CreateComputePipelineState(psoDescBlake3);

            var psoDescSha256 = new ComputePipelineStateDescription
            {
                RootSignature = _rootSig,
                ComputeShader = sha256Bytecode
            };
            _psoSha256 = _device.CreateComputePipelineState(psoDescSha256);

            // Allocate persistent pooled resources
            _tmplUploadBuffer = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Upload),
                HeapFlags.None,
                ResourceDescription.Buffer(64),
                ResourceStates.GenericRead);

            _zeroUploadBuffer = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Upload),
                HeapFlags.None,
                ResourceDescription.Buffer(sizeof(uint)),
                ResourceStates.GenericRead);

            void* pZero;
            var zeroMap = _zeroUploadBuffer.Map(0, &pZero);
            if (zeroMap.Failure)
                throw new InvalidOperationException($"D3D12 zero upload buffer Map failed: {zeroMap.Code}");
            try
            {
                *(uint*)pZero = 0u;
            }
            finally
            {
                _zeroUploadBuffer.Unmap(0);
            }

            _foundCountGpu = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Default),
                HeapFlags.None,
                ResourceDescription.Buffer(sizeof(uint), ResourceFlags.AllowUnorderedAccess),
                ResourceStates.CopyDest);

            _readbackCount = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Readback),
                HeapFlags.None,
                ResourceDescription.Buffer(sizeof(uint)),
                ResourceStates.CopyDest);

            _resultsCapacity = DefaultResultsCapacity;
            ulong initialResultsBytes = (ulong)_resultsCapacity * sizeof(uint);

            _foundNoncesGpu = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Default),
                HeapFlags.None,
                ResourceDescription.Buffer(initialResultsBytes, ResourceFlags.AllowUnorderedAccess),
                ResourceStates.UnorderedAccess);

            _readbackResults = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Readback),
                HeapFlags.None,
                ResourceDescription.Buffer(initialResultsBytes),
                ResourceStates.CopyDest);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private static byte[] CompileShader(string fileName)
    {
        string hlsl = LoadShaderSource(fileName);
        var bytes = Compiler.Compile(hlsl, "CSMain", fileName, "cs_5_0", ShaderFlags.OptimizationLevel3);
        if (bytes.IsEmpty)
        {
            throw new InvalidOperationException($"HLSL Compilation failed for {fileName}: empty bytecode returned.");
        }
        return bytes.ToArray();
    }

    private static string LoadShaderSource(string fileName)
    {
        var assembly = typeof(GpuD3D12Engine).Assembly;
        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (name.EndsWith(fileName, StringComparison.OrdinalIgnoreCase))
            {
                using var stream = assembly.GetManifestResourceStream(name)!;
                using var reader = new StreamReader(stream, Encoding.UTF8);
                return reader.ReadToEnd();
            }
        }

        string localPath = Path.Combine(AppContext.BaseDirectory, "Shaders", fileName);
        if (File.Exists(localPath)) return File.ReadAllText(localPath);

        throw new FileNotFoundException($"HLSL Shader '{fileName}' not found.");
    }

    public uint[] SearchNonceBlake3(
        ReadOnlySpan<byte> template,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint flags = 0x0B,
        uint maxResults = 16)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return ExecuteCompute(
            _psoBlake3!,
            template,
            baseNonce,
            targetZerosMask,
            searchCount,
            flags,
            maxResults);
    }

    public uint[] SearchNonceSha256(
        ReadOnlySpan<byte> template,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint maxResults = 16)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return ExecuteCompute(
            _psoSha256!,
            template,
            baseNonce,
            targetZerosMask,
            searchCount,
            0,
            maxResults);
    }

    private void EnsureResultsCapacity(uint requiredResults)
    {
        if (requiredResults <= _resultsCapacity) return;

        uint newCapacity = Math.Max(requiredResults, _resultsCapacity * 2);
        ulong newBytes = (ulong)newCapacity * sizeof(uint);

        var newFoundNonces = _device!.CreateCommittedResource(
            new HeapProperties(HeapType.Default),
            HeapFlags.None,
            ResourceDescription.Buffer(newBytes, ResourceFlags.AllowUnorderedAccess),
            ResourceStates.UnorderedAccess);

        try
        {
            var newReadback = _device.CreateCommittedResource(
                new HeapProperties(HeapType.Readback),
                HeapFlags.None,
                ResourceDescription.Buffer(newBytes),
                ResourceStates.CopyDest);

            _foundNoncesGpu?.Dispose();
            _readbackResults?.Dispose();
            _foundNoncesGpu = newFoundNonces;
            _readbackResults = newReadback;
            _resultsCapacity = newCapacity;
        }
        catch
        {
            newFoundNonces.Dispose();
            throw;
        }
    }

    private uint[] ExecuteCompute(
        ID3D12PipelineState pso,
        ReadOnlySpan<byte> template,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint extra,
        uint maxResults)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (searchCount == 0 || maxResults == 0)
        {
            return Array.Empty<uint>();
        }

        Span<byte> blockTemplate = stackalloc byte[64];
        template[..Math.Min(60, template.Length)].CopyTo(blockTemplate);

        lock (_execLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            EnsureResultsCapacity(maxResults);

            // Upload template
            void* pData;
            var tmplMap = _tmplUploadBuffer!.Map(0, &pData);
            if (tmplMap.Failure)
                throw new InvalidOperationException($"D3D12 template buffer Map failed: {tmplMap.Code}");
            try
            {
                fixed (byte* pTmpl = blockTemplate)
                {
                    Buffer.MemoryCopy(pTmpl, pData, 64, 64);
                }
            }
            finally
            {
                _tmplUploadBuffer.Unmap(0);
            }

            _cmdAlloc!.Reset();
            _cmdList!.Reset(_cmdAlloc, pso);

            // Zero foundCountGpu on GPU (_foundCountGpu enters in CopyDest state)
            _cmdList.CopyBufferRegion(_foundCountGpu!, 0, _zeroUploadBuffer!, 0, sizeof(uint));
            _cmdList.ResourceBarrierTransition(_foundCountGpu!, ResourceStates.CopyDest, ResourceStates.UnorderedAccess);

            _cmdList.SetComputeRootSignature(_rootSig!);
            _cmdList.SetPipelineState(pso);

            MiningParams param = new MiningParams
            {
                BaseNonce = baseNonce,
                TargetMask = targetZerosMask,
                MaxEvaluations = searchCount,
                MaxResults = maxResults,
                Extra = extra
            };

            _cmdList.SetComputeRoot32BitConstants(0, (uint)(sizeof(MiningParams) / sizeof(uint)), (IntPtr)(&param), 0);
            _cmdList.SetComputeRootShaderResourceView(1, _tmplUploadBuffer.GPUVirtualAddress);
            _cmdList.SetComputeRootUnorderedAccessView(2, _foundCountGpu!.GPUVirtualAddress);
            _cmdList.SetComputeRootUnorderedAccessView(3, _foundNoncesGpu!.GPUVirtualAddress);

            uint threadsPerGroup = 256;
            uint groups = (searchCount + threadsPerGroup - 1) / threadsPerGroup;

            _cmdList.Dispatch(groups, 1, 1);

            // Resource barriers to transition UAV -> CopySource
            _cmdList.ResourceBarrierTransition(_foundCountGpu, ResourceStates.UnorderedAccess, ResourceStates.CopySource);
            _cmdList.ResourceBarrierTransition(_foundNoncesGpu, ResourceStates.UnorderedAccess, ResourceStates.CopySource);

            ulong copyResultsBytes = (ulong)maxResults * sizeof(uint);
            _cmdList.CopyBufferRegion(_readbackCount!, 0, _foundCountGpu, 0, sizeof(uint));
            _cmdList.CopyBufferRegion(_readbackResults!, 0, _foundNoncesGpu, 0, copyResultsBytes);

            // Restore pooled resource states for subsequent runs
            _cmdList.ResourceBarrierTransition(_foundCountGpu, ResourceStates.CopySource, ResourceStates.CopyDest);
            _cmdList.ResourceBarrierTransition(_foundNoncesGpu, ResourceStates.CopySource, ResourceStates.UnorderedAccess);

            _cmdList.Close();

            _queue!.ExecuteCommandList(_cmdList);
            WaitForGpu();

            // Readback count
            uint count = 0;
            var countMap = _readbackCount!.Map(0, &pData);
            if (countMap.Failure)
                throw new InvalidOperationException($"D3D12 count readback Map failed: {countMap.Code}");
            try
            {
                count = *(uint*)pData;
            }
            finally
            {
                _readbackCount.Unmap(0);
            }

            uint returnCount = Math.Min(count, maxResults);
            if (returnCount == 0) return Array.Empty<uint>();

            uint[] results = new uint[returnCount];
            var resMap = _readbackResults!.Map(0, &pData);
            if (resMap.Failure)
                throw new InvalidOperationException($"D3D12 results readback Map failed: {resMap.Code}");
            try
            {
                fixed (uint* pRes = results)
                {
                    ulong copyBytes = (ulong)returnCount * sizeof(uint);
                    Buffer.MemoryCopy(pData, pRes, copyBytes, copyBytes);
                }
            }
            finally
            {
                _readbackResults.Unmap(0);
            }

            return results;
        }
    }

    private void WaitForGpu()
    {
        _fenceValue++;
        _queue!.Signal(_fence!, _fenceValue);
        if (_fence!.CompletedValue < _fenceValue)
        {
            _fence.SetEventOnCompletion(_fenceValue, _fenceEvent!.SafeWaitHandle.DangerousGetHandle());
            _fenceEvent.WaitOne();
        }
    }

    public void Dispose()
    {
        lock (_execLock)
        {
            if (!_disposed)
            {
                _disposed = true;
                _readbackResults?.Dispose();
                _foundNoncesGpu?.Dispose();
                _readbackCount?.Dispose();
                _foundCountGpu?.Dispose();
                _zeroUploadBuffer?.Dispose();
                _tmplUploadBuffer?.Dispose();
                _fenceEvent?.Dispose();
                _psoBlake3?.Dispose();
                _psoSha256?.Dispose();
                _rootSig?.Dispose();
                _fence?.Dispose();
                _cmdList?.Dispose();
                _cmdAlloc?.Dispose();
                _queue?.Dispose();
                _device?.Dispose();
                _adapter?.Dispose();
                _factory?.Dispose();
            }
        }
    }
}
