using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Glacier.Codec.Hashing.Blake3;
using Vortice.DXGI;

namespace Glacier.Codec.Gpu.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
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

        string cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "bench";
        bool preferAmd = args.Length > 1 && args[1].Contains("amd", StringComparison.OrdinalIgnoreCase);

        switch (cmd)
        {
            case "info":
                PrintAllDeviceInfo();
                return 0;

            case "search":
                string searchAlgo = args.Length > 1 ? args[1].ToLowerInvariant() : "blake3";
                uint diffZeros = args.Length > 2 && uint.TryParse(args[2], out uint d) ? d : 16;
                bool useD3D = args.Length > 3 && args[3].Contains("d3d", StringComparison.OrdinalIgnoreCase);
                if (useD3D || !CuDriver.IsAvailable || GpuDevice.GetDeviceCount() == 0)
                {
                    RunD3D12NonceSearch(searchAlgo, diffZeros);
                }
                else
                {
                    RunCudaNonceSearch(searchAlgo, diffZeros);
                }
                return 0;

            case "bench-amd":
            case "amd":
                PrintD3D12Info();
                RunD3D12Benchmark("blake3");
                RunD3D12Benchmark("sha256");
                return 0;

            case "bench":
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

        uint mask = difficultyBits switch
        {
            >= 32 => 0xFFFFFFFF,
            0 => 0x00000000,
            _ => (uint)(0xFFFFFFFFUL << (int)(32 - difficultyBits))
        };

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
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  >>> MATCH: 0x{nonce:X8} | Hash: {Convert.ToHexString(hash)}");
                    Console.ResetColor();
                }
            }
        }
        else
        {
            using var engine = new GpuSha256Engine(dev);
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
                    byte[] hash = SHA256.HashData(block);
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

        uint mask = difficultyBits switch
        {
            >= 32 => 0xFFFFFFFF,
            0 => 0x00000000,
            _ => (uint)(0xFFFFFFFFUL << (int)(32 - difficultyBits))
        };

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
