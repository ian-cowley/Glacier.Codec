using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Glacier.Codec.Gpu;
using Glacier.Codec.Gpu.Drivers;
using Glacier.Codec.Gpu.Engines;
using Glacier.Codec.Hashing.Blake3;

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
             Glacier.Codec.Gpu - Hardware Cryptographic & Nonce Engine
");
        Console.ResetColor();

        if (!CuDriver.IsAvailable)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] NVIDIA CUDA Driver (nvcuda.dll / libcuda.so) is not available.");
            Console.ResetColor();
            return 1;
        }

        int count = GpuDevice.GetDeviceCount();
        if (count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] No CUDA-capable GPU devices detected.");
            Console.ResetColor();
            return 1;
        }

        string cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "bench";

        switch (cmd)
        {
            case "info":
                PrintDeviceInfo(count);
                return 0;

            case "search":
                string searchAlgo = args.Length > 1 ? args[1].ToLowerInvariant() : "blake3";
                uint diffZeros = args.Length > 2 && uint.TryParse(args[2], out uint d) ? d : 20;
                RunNonceSearch(searchAlgo, diffZeros);
                return 0;

            case "bench":
            default:
                PrintDeviceInfo(count);
                RunBenchmark("blake3");
                RunBenchmark("sha256");
                return 0;
        }
    }

    private static void PrintDeviceInfo(int count)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[GPU System Telemetry] Detected {count} NVIDIA CUDA Device(s):");
        Console.ResetColor();

        for (int i = 0; i < count; i++)
        {
            using var dev = GpuDevice.Create(i);
            double vramGb = dev.TotalMemoryBytes / (1024.0 * 1024.0 * 1024.0);
            Console.WriteLine($"  Device #{i}: {dev.DeviceName}");
            Console.WriteLine($"    Architecture: {dev.ComputeCapability} | Multiprocessors (SMs): {dev.MultiprocessorCount}");
            Console.WriteLine($"    VRAM: {vramGb:F2} GB ({dev.TotalMemoryBytes:N0} bytes)");
        }
        Console.WriteLine();
    }

    private static void RunBenchmark(string algo)
    {
        using var dev = GpuDevice.Create(0);
        byte[] template = new byte[64];
        Random.Shared.NextBytes(template.AsSpan(0, 60));

        uint batchCount = 10_000_000; // 10 Million hashes
        uint mask = 0xFFFFFFFF;       // zero matches to measure pure compute pipeline

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"--- Benchmarking {algo.ToUpperInvariant()} Nonce Throughput on {dev.DeviceName} ---");
        Console.ResetColor();

        if (algo == "blake3")
        {
            using var engine = new GpuBlake3Engine(dev);
            // Warmup
            engine.SearchNonce(template, 0, mask, 500_000, maxResults: 1);

            var sw = Stopwatch.StartNew();
            engine.SearchNonce(template, 0, mask, batchCount, maxResults: 1);
            sw.Stop();

            double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
            Console.WriteLine($"  Processed: {batchCount:N0} nonces in {sw.ElapsedMilliseconds} ms");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s)");
            Console.ResetColor();
        }
        else
        {
            using var engine = new GpuSha256Engine(dev);
            // Warmup
            engine.SearchNonce(template, 0, mask, 500_000, maxResults: 1);

            var sw = Stopwatch.StartNew();
            engine.SearchNonce(template, 0, mask, batchCount, maxResults: 1);
            sw.Stop();

            double rateMh = (batchCount / sw.Elapsed.TotalSeconds) / 1_000_000.0;
            Console.WriteLine($"  Processed: {batchCount:N0} nonces in {sw.ElapsedMilliseconds} ms");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  Throughput: {rateMh:F2} MH/s ({rateMh / 1000.0:F3} GH/s)");
            Console.ResetColor();
        }
        Console.WriteLine();
    }

    private static void RunNonceSearch(string algo, uint difficultyBits)
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
        Console.WriteLine($"Starting Live GPU Nonce Miner ({algo.ToUpperInvariant()}) on {dev.DeviceName}...");
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

            for (int round = 1; round <= 5; round++)
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
                    Console.WriteLine($"  >>> MATCH FOUND! Nonce: 0x{nonce:X8} ({nonce}) | Hash: {Convert.ToHexString(hash)}");
                    Console.ResetColor();
                }
            }
        }
        else
        {
            using var engine = new GpuSha256Engine(dev);
            for (int round = 1; round <= 5; round++)
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
                    Console.WriteLine($"  >>> MATCH FOUND! Nonce: 0x{nonce:X8} ({nonce}) | Hash: {Convert.ToHexString(hash)}");
                    Console.ResetColor();
                }
            }
        }

        overallSw.Stop();
        double avgRate = (totalEvaluated / overallSw.Elapsed.TotalSeconds) / 1_000_000.0;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[Summary] Evaluated {totalEvaluated:N0} nonces in {overallSw.Elapsed.TotalSeconds:F2}s (Average: {avgRate:F2} MH/s) | Total Solved: {totalFound}");
        Console.ResetColor();
    }
}
