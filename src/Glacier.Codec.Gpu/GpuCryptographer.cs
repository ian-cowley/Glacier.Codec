using System;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;

namespace Glacier.Codec.Gpu;

/// <summary>
/// High-level entry point for hardware-accelerated GPU cryptographic operations.
/// Auto-detects NVIDIA GPUs and manages execution contexts.
/// </summary>
public static class GpuCryptographer
{
    /// <summary>
    /// Gets whether a compatible NVIDIA GPU and CUDA driver are available for GPU acceleration.
    /// </summary>
    public static bool IsHardwareAccelerated => GpuDevice.GetDeviceCount() > 0;

    /// <summary>
    /// Hashes an array of 64-byte blocks using SHA-256 on the primary GPU.
    /// </summary>
    public static void Sha256Batch(ReadOnlySpan<byte> inputBlocks, Span<byte> outputHashes, int deviceOrdinal = 0)
    {
        using var device = GpuDevice.Create(deviceOrdinal);
        using var engine = new GpuSha256Engine(device);
        engine.HashBatch(inputBlocks, outputHashes);
    }

    /// <summary>
    /// Hashes an array of 64-byte blocks using BLAKE3 on the primary GPU.
    /// </summary>
    public static void Blake3Batch(ReadOnlySpan<byte> inputBlocks, Span<byte> outputHashes, uint flags = 0x0B, int deviceOrdinal = 0)
    {
        using var device = GpuDevice.Create(deviceOrdinal);
        using var engine = new GpuBlake3Engine(device);
        engine.HashBatch(inputBlocks, outputHashes, flags);
    }

    /// <summary>
    /// Searches for valid proof-of-work nonces matching difficulty mask using GPU SHA-256.
    /// </summary>
    public static uint[] SearchSha256Nonce(
        ReadOnlySpan<byte> headerTemplate,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint maxResults = 16,
        int deviceOrdinal = 0)
    {
        using var device = GpuDevice.Create(deviceOrdinal);
        using var engine = new GpuSha256Engine(device);
        return engine.SearchNonce(headerTemplate, baseNonce, targetZerosMask, searchCount, maxResults);
    }

    /// <summary>
    /// Searches for valid proof-of-work nonces matching difficulty mask using GPU BLAKE3.
    /// </summary>
    public static uint[] SearchBlake3Nonce(
        ReadOnlySpan<byte> headerTemplate,
        uint baseNonce,
        uint targetZerosMask,
        uint searchCount,
        uint flags = 0x0B,
        uint maxResults = 16,
        int deviceOrdinal = 0)
    {
        using var device = GpuDevice.Create(deviceOrdinal);
        using var engine = new GpuBlake3Engine(device);
        return engine.SearchNonce(headerTemplate, baseNonce, targetZerosMask, searchCount, flags, maxResults);
    }
}
