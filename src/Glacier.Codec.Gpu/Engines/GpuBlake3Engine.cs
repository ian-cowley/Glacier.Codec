using System;
using System.Runtime.InteropServices;
using Glacier.Codec.Gpu.Compilation;
using Glacier.Codec.Gpu.Drivers;

namespace Glacier.Codec.Gpu.Engines;

/// <summary>
/// Hardware-accelerated BLAKE3 GPU engine executing bare-metal PTX assembly.
/// Supports high-throughput parallel batch hashing and proof-of-work nonce discovery.
/// </summary>
public sealed class GpuBlake3Engine : IDisposable
{
    private readonly GpuDevice _device;
    private IntPtr _module;
    private IntPtr _fnBatch;
    private IntPtr _fnNonceSearch;
    private bool _disposed;

    public GpuDevice Device => _device;

    public GpuBlake3Engine(GpuDevice device)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
        _device.MakeCurrent();

        byte[] ptx = PtxSources.Blake3Ptx;
        CuDriver.Check(CuDriver.ModuleLoadData(out _module, ptx), "cuModuleLoadData(Blake3Ptx)");
        CuDriver.Check(CuDriver.ModuleGetFunction(out _fnBatch, _module, "blake3_batch_kernel"), "cuModuleGetFunction(blake3_batch_kernel)");
        CuDriver.Check(CuDriver.ModuleGetFunction(out _fnNonceSearch, _module, "blake3_nonce_search_kernel"), "cuModuleGetFunction(blake3_nonce_search_kernel)");
    }

    /// <summary>
    /// Computes BLAKE3 single-chunk hashes for a batch of 64-byte blocks in parallel on the GPU.
    /// </summary>
    /// <param name="inputBlocks">Contiguous input blocks (must be a multiple of 64 bytes).</param>
    /// <param name="outputHashes">Output buffer for 32-byte digest per block.</param>
    /// <param name="flags">BLAKE3 chunk flags (default 0x0B = CHUNK_START | CHUNK_END | ROOT).</param>
    public unsafe void HashBatch(ReadOnlySpan<byte> inputBlocks, Span<byte> outputHashes, uint flags = 0x0B)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (inputBlocks.Length == 0) return;
        if (inputBlocks.Length % 64 != 0)
            throw new ArgumentException("Input length must be a multiple of 64 bytes.", nameof(inputBlocks));

        int blockCount = inputBlocks.Length / 64;
        int expectedOutputLen = blockCount * 32;
        if (outputHashes.Length < expectedOutputLen)
            throw new ArgumentException($"Output buffer too small: required {expectedOutputLen}, got {outputHashes.Length}", nameof(outputHashes));

        _device.MakeCurrent();

        nuint inBytes = (nuint)inputBlocks.Length;
        nuint outBytes = (nuint)expectedOutputLen;

        CuDriver.Check(CuDriver.MemAlloc(out IntPtr dInput, inBytes), "cuMemAlloc(dInput)");
        CuDriver.Check(CuDriver.MemAlloc(out IntPtr dOutput, outBytes), "cuMemAlloc(dOutput)");

        try
        {
            fixed (byte* pIn = inputBlocks)
            {
                CuDriver.Check(CuDriver.MemcpyHtoD(dInput, (IntPtr)pIn, inBytes), "cuMemcpyHtoD(dInput)");
            }

            uint threadsPerBlock = 256;
            uint blocks = (uint)((blockCount + threadsPerBlock - 1) / threadsPerBlock);
            uint totalBlocks = (uint)blockCount;

            void*[] args = new void*[]
            {
                &dInput,
                &dOutput,
                &totalBlocks,
                &flags
            };

            fixed (void** pArgs = args)
            {
                CuDriver.Check(CuDriver.LaunchKernel(
                    _fnBatch,
                    blocks, 1, 1,
                    threadsPerBlock, 1, 1,
                    0, IntPtr.Zero,
                    (IntPtr)pArgs, IntPtr.Zero), "cuLaunchKernel(blake3_batch)");
            }

            CuDriver.Check(CuDriver.CtxSynchronize(), "cuCtxSynchronize");

            fixed (byte* pOut = outputHashes)
            {
                CuDriver.Check(CuDriver.MemcpyDtoH((IntPtr)pOut, dOutput, outBytes), "cuMemcpyDtoH(dOutput)");
            }
        }
        finally
        {
            CuDriver.MemFree(dInput);
            CuDriver.MemFree(dOutput);
        }
    }

    /// <summary>
    /// Searches for a 32-bit nonce that produces a BLAKE3 hash satisfying the difficulty zeros mask.
    /// </summary>
    /// <param name="headerTemplate">60-byte fixed header prefix (the last 4 bytes are tested nonces).</param>
    /// <param name="baseNonce">Starting nonce offset.</param>
    /// <param name="targetZerosMask">Difficulty bitmask (e.g. 0xFFFF0000 requires leading 16 bits zero).</param>
    /// <param name="searchCount">Number of nonces to evaluate in parallel.</param>
    /// <param name="flags">BLAKE3 chunk flags (default 0x0B = CHUNK_START | CHUNK_END | ROOT).</param>
    /// <param name="maxResults">Maximum number of winning nonces to record.</param>
    /// <returns>Array of matching nonces found on the GPU.</returns>
    public unsafe uint[] SearchNonce(
        ReadOnlySpan<byte> headerTemplate,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint flags = 0x0B,
        uint maxResults = 16)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (headerTemplate.Length < 60)
            throw new ArgumentException("Header template must be at least 60 bytes.", nameof(headerTemplate));

        _device.MakeCurrent();

        Span<byte> blockTemplate = stackalloc byte[64];
        headerTemplate[..Math.Min(60, headerTemplate.Length)].CopyTo(blockTemplate);

        nuint tmplBytes = 64;
        nuint resultsBytes = (nuint)(maxResults * sizeof(uint));
        nuint countBytes = sizeof(uint);

        CuDriver.Check(CuDriver.MemAlloc(out IntPtr dTemplate, tmplBytes), "cuMemAlloc(dTemplate)");
        CuDriver.Check(CuDriver.MemAlloc(out IntPtr dCount, countBytes), "cuMemAlloc(dCount)");
        CuDriver.Check(CuDriver.MemAlloc(out IntPtr dResults, resultsBytes), "cuMemAlloc(dResults)");

        try
        {
            fixed (byte* pTmpl = blockTemplate)
            {
                CuDriver.Check(CuDriver.MemcpyHtoD(dTemplate, (IntPtr)pTmpl, tmplBytes), "cuMemcpyHtoD(dTemplate)");
            }

            uint zeroCount = 0;
            CuDriver.Check(CuDriver.MemcpyHtoD(dCount, (IntPtr)(&zeroCount), countBytes), "cuMemcpyHtoD(dCount)");

            uint threadsPerBlock = 256;
            uint blocks = (searchCount + threadsPerBlock - 1) / threadsPerBlock;

            void*[] args = new void*[]
            {
                &dTemplate,
                &baseNonce,
                &targetZerosMask,
                &flags,
                &searchCount,
                &dCount,
                &dResults,
                &maxResults
            };

            fixed (void** pArgs = args)
            {
                CuDriver.Check(CuDriver.LaunchKernel(
                    _fnNonceSearch,
                    blocks, 1, 1,
                    threadsPerBlock, 1, 1,
                    0, IntPtr.Zero,
                    (IntPtr)pArgs, IntPtr.Zero), "cuLaunchKernel(blake3_nonce_search)");
            }

            CuDriver.Check(CuDriver.CtxSynchronize(), "cuCtxSynchronize");

            uint foundCount = 0;
            CuDriver.Check(CuDriver.MemcpyDtoH((IntPtr)(&foundCount), dCount, countBytes), "cuMemcpyDtoH(dCount)");

            uint returnCount = Math.Min(foundCount, maxResults);
            if (returnCount == 0) return Array.Empty<uint>();

            uint[] results = new uint[returnCount];
            fixed (uint* pRes = results)
            {
                CuDriver.Check(CuDriver.MemcpyDtoH((IntPtr)pRes, dResults, (nuint)(returnCount * sizeof(uint))), "cuMemcpyDtoH(dResults)");
            }

            return results;
        }
        finally
        {
            CuDriver.MemFree(dTemplate);
            CuDriver.MemFree(dCount);
            CuDriver.MemFree(dResults);
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_module != IntPtr.Zero)
            {
                CuDriver.ModuleUnload(_module);
                _module = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
