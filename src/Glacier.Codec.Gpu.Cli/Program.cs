using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Glacier.Codec.Hashing.Blake3;
using Vortice.DXGI;

namespace Glacier.Codec.Gpu.Cli;

public enum CliCommand
{
    Bench,
    BenchAmd,
    Info,
    Search,
    Help
}

public readonly record struct CliOptions(
    CliCommand Command,
    string Algorithm = "blake3",
    uint DifficultyBits = 16,
    bool PreferD3D12 = false,
    bool PreferAmd = false);

public readonly record struct CliParseResult(bool IsSuccess, CliOptions Options, string? ErrorMessage = null);

public static class Program
{
    public static string GetHelpText() =>
        """
        Usage:
          Glacier.Codec.Gpu.Cli [command] [options]

        Commands:
          info                              Print detected CUDA and Direct3D 12 GPU devices
          search [algo] [bits] [backend]    Run GPU nonce search (algo: blake3|sha256, bits: 0..32, backend: cuda|d3d)
          bench [amd]                       Run GPU throughput benchmarks (default)
          bench-amd | amd                   Run Direct3D 12 benchmarks on AMD/DXGI adapter
          help | --help | -h                Show this help message
        """;

    public static uint ComputeDifficultyMask(uint difficultyBits) => difficultyBits switch
    {
        >= 32 => 0xFFFFFFFF,
        0 => 0x00000000,
        _ => (uint)(0xFFFFFFFFUL << (int)(32 - difficultyBits))
    };

    public static uint ComputeBlake3DifficultyMask(uint difficultyBits)
        => BinaryPrimitives.ReverseEndianness(ComputeDifficultyMask(difficultyBits));

    public static uint ComputeDifficultyMask(uint difficultyBits, string algorithm)
        => string.Equals(algorithm, "blake3", StringComparison.OrdinalIgnoreCase)
            ? ComputeBlake3DifficultyMask(difficultyBits)
            : ComputeDifficultyMask(difficultyBits);

    public static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, uint difficultyBits)
    {
        if (difficultyBits == 0) return true;
        uint maxBits = (uint)hash.Length * 8u;
        if (difficultyBits > maxBits) difficultyBits = maxBits;

        int fullBytes = (int)(difficultyBits / 8);
        for (int i = 0; i < fullBytes; i++)
        {
            if (hash[i] != 0) return false;
        }

        int remBits = (int)(difficultyBits % 8);
        if (remBits > 0)
        {
            byte mask = (byte)(0xFF << (8 - remBits));
            if ((hash[fullBytes] & mask) != 0) return false;
        }

        return true;
    }

    public static CliParseResult ParseArgs(string[]? args)
    {
        if (args is null || args.Length == 0)
        {
            return new CliParseResult(true, new CliOptions(CliCommand.Bench));
        }

        string cmd = args[0].ToLowerInvariant();
        switch (cmd)
        {
            case "help":
            case "--help":
            case "-h":
            case "/?":
                return new CliParseResult(true, new CliOptions(CliCommand.Help));

            case "info":
                return new CliParseResult(true, new CliOptions(CliCommand.Info));

            case "bench-amd":
            case "amd":
                return new CliParseResult(true, new CliOptions(CliCommand.BenchAmd, PreferAmd: true));

            case "bench":
                bool preferAmd = args.Length > 1 && args[1].Contains("amd", StringComparison.OrdinalIgnoreCase);
                return new CliParseResult(true, new CliOptions(CliCommand.Bench, PreferAmd: preferAmd));

            case "search":
                string algo = args.Length > 1 ? args[1].ToLowerInvariant() : "blake3";
                if (algo is not ("blake3" or "sha256"))
                {
                    return new CliParseResult(false, default, $"Unsupported algorithm '{args[1]}'. Expected 'blake3' or 'sha256'.");
                }

                uint diffBits = 16;
                if (args.Length > 2)
                {
                    if (!uint.TryParse(args[2], out diffBits) || diffBits > 32)
                    {
                        return new CliParseResult(false, default, $"Invalid difficulty '{args[2]}'. Expected integer between 0 and 32.");
                    }
                }

                bool useD3D = args.Length > 3 && args[3].Contains("d3d", StringComparison.OrdinalIgnoreCase);
                return new CliParseResult(true, new CliOptions(CliCommand.Search, algo, diffBits, useD3D));

            default:
                return new CliParseResult(false, default, $"Unknown command '{args[0]}'. Use --help for usage.");
        }
    }

    public static int Main(string[] args)
    {
        CliParseResult parsed = ParseArgs(args);
        if (!parsed.IsSuccess)
        {
            Console.Error.WriteLine($"Error: {parsed.ErrorMessage}");
            Console.WriteLine(GetHelpText());
            return 1;
        }

        if (parsed.Options.Command == CliCommand.Help)
        {
            Console.WriteLine(GetHelpText());
            return 0;
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
   ______ __           _                ______           __            ______            
  / ____// /____ _ ____(_)___   _____   / ____/____  ____/ /___   _____ / ____/____  __  __
 / / __ / // __ `// ___// / _ \ / ___/  / /    / __ \/ __  // _ \ / ___// / __ / __ \/ / / /
/ /_/ // // /_/ // /__ / //  __// /     / /___ / /_/ // /_/ //  __// /__ / /_/ // /_/ // /_/ / 
\____//_/ \__,_/ \___//_/ \___//_/      \____/ \____/ \__,_/ \___/ \___/ \____// .___/ \__,_/  
                                                                              /_/               
      Glacier.Codec.Gpu - Universal Hardware Nonce Engine (NVIDIA CUDA & AMD Radeon D3D12)
");
        Console.ResetColor();

        switch (parsed.Options.Command)
        {
            case CliCommand.Info:
                PrintAllDeviceInfo();
                return 0;

            case CliCommand.Search:
                if (parsed.Options.PreferD3D12 || !CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0)
                {
                    RunD3D12NonceSearch(parsed.Options.Algorithm, parsed.Options.DifficultyBits);
                }
                else
                {
                    RunCudaNonceSearch(parsed.Options.Algorithm, parsed.Options.DifficultyBits);
                }
                return 0;

            case CliCommand.BenchAmd:
                PrintD3D12Info();
                RunD3D12Benchmark("blake3");
                RunD3D12Benchmark("sha256");
                return 0;

            case CliCommand.Bench:
            default:
                PrintAllDeviceInfo();
                if (CuDriver.IsAvailable && GpuDevice.GetDeviceCount() > 0)
                {
                    RunCudaBenchmark("blake3");
                    RunCudaBenchmark("sha256");
                }
                if (OperatingSystem.IsWindows())
                {
                    RunD3D12Benchmark("blake3");
                    RunD3D12Benchmark("sha256");
                }
                return 0;
        }
    }

    private static void PrintAllDeviceInfo()
    {
        if (CuDriver.IsAvailable)
        {
            int count = GpuDevice.GetDeviceCount();
            if (count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[NVIDIA CUDA Subsystem] Detected {count} CUDA Device(s):");
                Console.ResetColor();
                for (int i = 0; i < count; i++)
                {
                    using var dev = GpuDevice.Create(i);
                    double vramGb = dev.TotalMemoryBytes / (1024.0 * 1024.0 * 1024.0);
                    Console.WriteLine($"  CUDA #{i}: {dev.DeviceName} ({dev.ComputeCapability}) | SMs: {dev.MultiprocessorCount} | VRAM: {vramGb:F2} GB");
                }
                Console.WriteLine();
            }
        }

        PrintD3D12Info();
    }

    private static void PrintD3D12Info()
    {
        if (!OperatingSystem.IsWindows()) return;

        try
        {
            using var factory = DXGI.CreateDXGIFactory1<IDXGIFactory4>();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("[Direct3D 12 Compute Subsystem (AMD Radeon / Intel / NVIDIA)]:");
            Console.ResetColor();

            for (uint i = 0; factory.EnumAdapters1(i, out IDXGIAdapter1 a).Success; i++)
            {
                var desc = a.Description1;
                string name = desc.Description;
                if ((desc.Flags & AdapterFlags.Software) != 0 || name.Contains("Basic Render", StringComparison.OrdinalIgnoreCase))
                {
                    a.Dispose();
                    continue;
                }

                double vramGb = desc.DedicatedVideoMemory / (1024.0 * 1024.0 * 1024.0);
                double sharedGb = desc.SharedSystemMemory / (1024.0 * 1024.0 * 1024.0);
                bool isAmd = name.Contains("Radeon", StringComparison.OrdinalIgnoreCase) || desc.VendorId == 0x1002;
                string tag = isAmd ? "[AMD RDNA iGPU/dGPU]" : "[Discrete GPU]";

                Console.WriteLine($"  D3D12 #{i}: {name} {tag} | Dedicated VRAM: {vramGb:F2} GB | Shared UMA RAM: {sharedGb:F2} GB");
                a.Dispose();
            }
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"D3D12 query warning: {ex.Message}");
        }
    }

    private static void RunCudaBenchmark(string algo)
    {
        using var dev = GpuDevice.Create(0);
        byte[] template = new byte[64];
        Random.Shared.NextBytes(template.AsSpan(0, 60));

        uint batchCount = 10_000_000;
        uint mask = 0xFFFFFFFF;

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"--- Benchmarking CUDA {algo.ToUpperInvariant()} Nonce Throughput on {dev.DeviceName} ---");
        Console.ResetColor();

        if (algo == "blake3")
        {
            using var engine = new GpuBlake3Engine(dev);
            engine.SearchNonce(template, 0, mask, 500_000, maxResults: 1);

            var sw = Stopwatch.StartNew();
            engine.SearchNonce(template, 0, mask, batchCount, maxResults: 1);
            sw.Stop();

            double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  CUDA {algo.ToUpperInvariant()} Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s) in {sw.ElapsedMilliseconds} ms");
            Console.ResetColor();
        }
        else
        {
            using var engine = new GpuSha256Engine(dev);
            engine.SearchNonce(template, 0, mask, 500_000, maxResults: 1);

            var sw = Stopwatch.StartNew();
            engine.SearchNonce(template, 0, mask, batchCount, maxResults: 1);
            sw.Stop();

            double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  CUDA {algo.ToUpperInvariant()} Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s) in {sw.ElapsedMilliseconds} ms");
            Console.ResetColor();
        }
        Console.WriteLine();
    }

    private static void RunD3D12Benchmark(string algo)
    {
        try
        {
            using var engine = new GpuD3D12Engine();
            byte[] template = new byte[64];
            Random.Shared.NextBytes(template.AsSpan(0, 60));

            uint batchCount = 5_000_000;
            uint mask = 0xFFFFFFFF;

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"--- Benchmarking D3D12 {algo.ToUpperInvariant()} Nonce Throughput on {engine.AdapterName} ---");
            Console.ResetColor();

            if (algo == "blake3")
            {
                engine.SearchNonceBlake3(template, 0, mask, 100_000, maxResults: 1);

                var sw = Stopwatch.StartNew();
                engine.SearchNonceBlake3(template, 0, mask, batchCount, maxResults: 1);
                sw.Stop();

                double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  D3D12 {algo.ToUpperInvariant()} Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s) in {sw.ElapsedMilliseconds} ms");
                Console.ResetColor();
            }
            else
            {
                engine.SearchNonceSha256(template, 0, mask, 100_000, maxResults: 1);

                var sw = Stopwatch.StartNew();
                engine.SearchNonceSha256(template, 0, mask, batchCount, maxResults: 1);
                sw.Stop();

                double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  D3D12 {algo.ToUpperInvariant()} Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s) in {sw.ElapsedMilliseconds} ms");
                Console.ResetColor();
            }
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"D3D12 Benchmark warning: {ex.Message}");
        }
    }

    private static void RunCudaNonceSearch(string algo, uint difficultyBits)
    {
        using var dev = GpuDevice.Create(0);
        byte[] template = new byte[64];
        Random.Shared.NextBytes(template.AsSpan(0, 60));

        uint mask = ComputeDifficultyMask(difficultyBits, algo);

        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"[CUDA Miner] Starting GPU Nonce Miner ({algo.ToUpperInvariant()}) on {dev.DeviceName}...");
        Console.WriteLine($"Difficulty: Leading {difficultyBits} bits must be 0 (Mask: 0x{mask:X8})");
        Console.ResetColor();

        uint chunkSize = 10_000_000;
        uint baseNonce = 0;
        ulong totalEvaluated = 0;
        int totalFound = 0;

        var overallSw = Stopwatch.StartNew();
        if (algo == "blake3")
        {
            using var engine = new GpuBlake3Engine(dev);
            Span<byte> hash = stackalloc byte[32];
            for (int round = 1; round <= 3; round++)
            {
                var sw = Stopwatch.StartNew();
                uint[] matches = engine.SearchNonce(template, baseNonce, mask, chunkSize, maxResults: 16);
                sw.Stop();
                totalEvaluated += chunkSize;
                baseNonce += chunkSize;
                double rateMh = (chunkSize / sw.Elapsed.TotalSeconds) / 1_000_000.0;
                Console.WriteLine($"[Round {round}] Tested {chunkSize:N0} nonces in {sw.ElapsedMilliseconds} ms ({rateMh:F2} MH/s) | Matches: {matches.Length}");
                foreach (var nonce in matches)
                {
                    totalFound++;
                    byte[] block = (byte[])template.Clone();
                    BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);
                    Blake3Hasher.Hash(block, hash);
                    if (!HasLeadingZeroBits(hash, difficultyBits))
                    {
                        throw new InvalidOperationException(
                            $"CUDA BLAKE3 candidate nonce 0x{nonce:X8} failed CPU verification for {difficultyBits} leading zero bits: {Convert.ToHexString(hash)}");
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  >>> MATCH: 0x{nonce:X8} | Hash: {Convert.ToHexString(hash)}");
                    Console.ResetColor();
                }
            }
        }
        else
        {
            using var engine = new GpuSha256Engine(dev);
            Span<byte> hash = stackalloc byte[32];
            for (int round = 1; round <= 3; round++)
            {
                var sw = Stopwatch.StartNew();
                uint[] matches = engine.SearchNonce(template, baseNonce, mask, chunkSize, maxResults: 16);
                sw.Stop();
                totalEvaluated += chunkSize;
                baseNonce += chunkSize;
                double rateMh = (chunkSize / sw.Elapsed.TotalSeconds) / 1_000_000.0;
                Console.WriteLine($"[Round {round}] Tested {chunkSize:N0} nonces in {sw.ElapsedMilliseconds} ms ({rateMh:F2} MH/s) | Matches: {matches.Length}");
                foreach (var nonce in matches)
                {
                    totalFound++;
                    byte[] block = (byte[])template.Clone();
                    BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);
                    SHA256.HashData(block, hash);
                    if (!HasLeadingZeroBits(hash, difficultyBits))
                    {
                        throw new InvalidOperationException(
                            $"CUDA SHA-256 candidate nonce 0x{nonce:X8} failed CPU verification for {difficultyBits} leading zero bits: {Convert.ToHexString(hash)}");
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  >>> MATCH: 0x{nonce:X8} | Hash: {Convert.ToHexString(hash)}");
                    Console.ResetColor();
                }
            }
        }
        overallSw.Stop();
        double avgRate = (totalEvaluated / overallSw.Elapsed.TotalSeconds) / 1_000_000.0;
        Console.WriteLine($"\n[Summary] Evaluated {totalEvaluated:N0} nonces in {overallSw.Elapsed.TotalSeconds:F2}s ({avgRate:F2} MH/s) | Total Solved: {totalFound}\n");
    }

    private static void RunD3D12NonceSearch(string algo, uint difficultyBits)
    {
        using var engine = new GpuD3D12Engine();
        byte[] template = new byte[64];
        Random.Shared.NextBytes(template.AsSpan(0, 60));

        uint mask = ComputeDifficultyMask(difficultyBits, algo);

        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"[Direct3D 12 Miner] Starting GPU Nonce Miner ({algo.ToUpperInvariant()}) on {engine.AdapterName}...");
        Console.WriteLine($"Difficulty: Leading {difficultyBits} bits must be 0 (Mask: 0x{mask:X8})");
        Console.ResetColor();

        uint chunkSize = 5_000_000;
        uint baseNonce = 0;
        ulong totalEvaluated = 0;
        int totalFound = 0;

        var overallSw = Stopwatch.StartNew();
        Span<byte> hash = stackalloc byte[32];

        for (int round = 1; round <= 3; round++)
        {
            var sw = Stopwatch.StartNew();
            uint[] matches = algo == "blake3"
                ? engine.SearchNonceBlake3(template, baseNonce, mask, chunkSize, maxResults: 16)
                : engine.SearchNonceSha256(template, baseNonce, mask, chunkSize, maxResults: 16);
            sw.Stop();

            totalEvaluated += chunkSize;
            baseNonce += chunkSize;

            double rateMh = (chunkSize / sw.Elapsed.TotalSeconds) / 1_000_000.0;
            Console.WriteLine($"[Round {round}] Tested {chunkSize:N0} nonces in {sw.ElapsedMilliseconds} ms ({rateMh:F2} MH/s) | Matches: {matches.Length}");

            foreach (var nonce in matches)
            {
                totalFound++;
                byte[] block = (byte[])template.Clone();
                BitConverter.TryWriteBytes(block.AsSpan(60, 4), nonce);

                if (algo == "blake3") Blake3Hasher.Hash(block, hash);
                else SHA256.HashData(block, hash);

                if (!HasLeadingZeroBits(hash, difficultyBits))
                {
                    throw new InvalidOperationException(
                        $"D3D12 {algo.ToUpperInvariant()} candidate nonce 0x{nonce:X8} failed CPU verification for {difficultyBits} leading zero bits: {Convert.ToHexString(hash)}");
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  >>> MATCH: 0x{nonce:X8} | Hash: {Convert.ToHexString(hash)}");
                Console.ResetColor();
            }
        }

        overallSw.Stop();
        double avgRate = (totalEvaluated / overallSw.Elapsed.TotalSeconds) / 1_000_000.0;
        Console.WriteLine($"\n[Summary] Evaluated {totalEvaluated:N0} nonces in {overallSw.Elapsed.TotalSeconds:F2}s ({avgRate:F2} MH/s) | Total Solved: {totalFound}\n");
    }
}
