using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace Glacier.Codec.Gpu.Compilation;

/// <summary>
/// Provides access to embedded universal forward-compatible PTX assembly modules.
/// </summary>
public static class PtxSources
{
    private static readonly Lazy<byte[]> _sha256Ptx = new(() => LoadResource("sha256_kernel.ptx"));
    private static readonly Lazy<byte[]> _blake3Ptx = new(() => LoadResource("blake3_kernel.ptx"));

    /// <summary>
    /// Gets the null-terminated UTF-8 PTX image for the SHA-256 batch and nonce kernels.
    /// </summary>
    public static byte[] Sha256Ptx => _sha256Ptx.Value;

    /// <summary>
    /// Gets the null-terminated UTF-8 PTX image for the BLAKE3 batch and nonce kernels.
    /// </summary>
    public static byte[] Blake3Ptx => _blake3Ptx.Value;

    private static byte[] LoadResource(string resourceName)
    {
        var assembly = typeof(PtxSources).Assembly;
        string? fullName = null;
        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (name.EndsWith(resourceName, StringComparison.OrdinalIgnoreCase))
            {
                fullName = name;
                break;
            }
        }

        if (fullName == null)
        {
            // Fallback to local Shaders directory on disk
            string localPath = Path.Combine(AppContext.BaseDirectory, "Shaders", resourceName);
            if (File.Exists(localPath))
            {
                byte[] raw = File.ReadAllBytes(localPath);
                return EnsureNullTerminated(raw);
            }
            throw new FileNotFoundException($"Embedded PTX resource '{resourceName}' not found in assembly.");
        }

        using var stream = assembly.GetManifestResourceStream(fullName)!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return EnsureNullTerminated(ms.ToArray());
    }

    private static byte[] EnsureNullTerminated(byte[] bytes)
    {
        if (bytes.Length > 0 && bytes[^1] == 0) return bytes;
        var result = new byte[bytes.Length + 1];
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        result[^1] = 0;
        return result;
    }
}
