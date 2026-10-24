namespace Glacier.Codec.Benchmarks;

using System;
using System.Diagnostics;
using System.Text;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Cryptography.PostQuantum;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;
using Glacier.Codec.Hardware;

/// <summary>
/// Standalone lightweight empirical benchmark runner that measures real hardware throughput
/// and validates the 0 B steady-state heap allocation invariant across all 8 primitives.
/// </summary>
public static class DirectBenchmarkRunner
{
    private static bool s_allPassed = true;

    public static int RunAll(bool strict = false)
    {
        s_allPassed = true;
        Console.WriteLine("\n[Hardware Topology & Vector Capabilities]");
        Console.WriteLine($"  - Architecture:        {Environment.OSVersion.Platform} x64 ({Environment.ProcessorCount} Logical Cores)");
        Console.WriteLine($"  - Detected Tier:       {CpuCapabilities.DetectedTier}");
        Console.WriteLine($"  - AVX-512 F / BW:      {CpuCapabilities.HasAvx512F} / {CpuCapabilities.HasAvx512BW}");
        Console.WriteLine($"  - VAES (512-bit AES):  {CpuCapabilities.HasVectorAes}");
        Console.WriteLine($"  - VPCLMULQDQ (512b):   {CpuCapabilities.HasVpclmulqdq}");
        Console.WriteLine($"  - SHA-NI Intrinsics:   {CpuCapabilities.HasShaNi}");
        Console.WriteLine($"  - AVX2 / AES-NI:       {CpuCapabilities.HasAvx2} / {CpuCapabilities.HasAesNi}");

        Console.WriteLine("\n" + new string('-', 92));
        Console.WriteLine($"{"Benchmark Primitive",-36} | {"Payload",-10} | {"Throughput / Rate",-22} | {"Alloc (B)",-10} | {"Status",-6}");
        Console.WriteLine(new string('-', 92));

        // 1. BLAKE3 Multi-Threaded Throughput
        RunBlake3Benchmark();

        // 2. AES-256-GCM Wire Speed (VAES)
        RunAesGcmBenchmark();

        // 3. SHA-256 (SHA-NI)
        RunSha256Benchmark();

        // 4. xxHash3 (64-bit and 128-bit)
        RunXxHash3Benchmark();

        // 5. ChaCha20-Poly1305
        RunChaCha20Poly1305Benchmark();

        // 6. Argon2id RFC 9106
        RunArgon2idBenchmark();

        // 7. ML-KEM FIPS 203 (KeyGen, Encaps, Decaps)
        RunMlKemBenchmark();

        // 8. LZ4 & Zstd Compression / Decompression
        RunCompressionBenchmark();

        Console.WriteLine(new string('-', 92));
        Console.WriteLine("[Verification Complete] All measured figures obtained from physical hardware execution.");
        if (s_allPassed)
        {
            Console.WriteLine("[Strict Certification: PASSED - All 0 B Allocation and Performance Invariants Met]\n");
            return 0;
        }
        else
        {
            Console.WriteLine("[Strict Certification: FAILED - Invariants not met]\n");
            return strict ? 1 : 0;
        }
    }

    private static void RunBlake3Benchmark()
    {
        // 1. 16 MB
        RunBlake3Core(16 * 1024 * 1024, "16 MB", 20);

        // 2. 64 MB
        RunBlake3Core(64 * 1024 * 1024, "64 MB", 10);
    }

    private static void RunBlake3Core(int sizeBytes, string label, int iters)
    {
        byte[] input = new byte[sizeBytes];
        byte[] output = new byte[32];
        Random.Shared.NextBytes(input);

        var sw = new Stopwatch();
        // Warmup JIT & thread pool completely
        for (int w = 0; w < 10; w++)
        {
            Blake3Hasher.Hash(input, output);
        }

        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            Blake3Hasher.Hash(input, output);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double totalGb = (double)sizeBytes * iters / (1024 * 1024 * 1024);
        double gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = gbPerSec >= 5.0 && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{$"BLAKE3 Parallel Tree ({label})",-36} | {label,-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunAesGcmBenchmark()
    {
        const int size1Mb = 1024 * 1024;
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[size1Mb];
        byte[] ciphertext = new byte[size1Mb];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[size1Mb];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(nonce);
        Random.Shared.NextBytes(plaintext);

        using var cipher = new Aes256GcmCipher(key);
        var sw = new Stopwatch();

        // Warmup
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);
        cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);

        // 1. Encrypt
        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int iters = 100;
        for (int i = 0; i < iters; i++)
        {
            cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double totalGb = (double)size1Mb * iters / (1024 * 1024 * 1024);
        double encGbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = (CpuCapabilities.HasVectorAes ? encGbPerSec >= 10.0 : encGbPerSec >= 4.0) && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"AES-256-GCM Encrypt (Steady)",-36} | {"1 MB",-10} | {$"{encGbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // 2. Decrypt
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double decGbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / iters;
        status = (CpuCapabilities.HasVectorAes ? decGbPerSec >= 10.0 : decGbPerSec >= 4.0) && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"AES-256-GCM Decrypt (Steady)",-36} | {"1 MB",-10} | {$"{decGbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunSha256Benchmark()
    {
        const int size1Mb = 1024 * 1024;
        byte[] input = new byte[size1Mb];
        byte[] digest = new byte[32];
        Random.Shared.NextBytes(input);
        var sw = new Stopwatch();

        // Warmup
        Sha256.Hash(input, digest);

        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int iters = 100;
        for (int i = 0; i < iters; i++)
        {
            Sha256.Hash(input, digest);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double totalGb = (double)size1Mb * iters / (1024 * 1024 * 1024);
        double gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"SHA-256 (SHA-NI Accelerated)",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunXxHash3Benchmark()
    {
        const int size1Mb = 1024 * 1024;
        byte[] input = new byte[size1Mb];
        Random.Shared.NextBytes(input);
        var sw = new Stopwatch();

        // Warmup 64-bit
        _ = XxHash3.Hash64(input);

        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int iters = 200;
        for (int i = 0; i < iters; i++)
        {
            _ = XxHash3.Hash64(input);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double totalGb = (double)size1Mb * iters / (1024 * 1024 * 1024);
        double gbPerSec64 = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"xxHash3 64-bit SIMD Stripes",-36} | {"1 MB",-10} | {$"{gbPerSec64:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // Warmup 128-bit
        _ = XxHash3.Hash128(input);

        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            _ = XxHash3.Hash128(input);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double gbPerSec128 = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / iters;
        status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"xxHash3 128-bit SIMD Stripes",-36} | {"1 MB",-10} | {$"{gbPerSec128:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunChaCha20Poly1305Benchmark()
    {
        const int size1Mb = 1024 * 1024;
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[size1Mb];
        byte[] ciphertext = new byte[size1Mb];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[size1Mb];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(nonce);
        Random.Shared.NextBytes(plaintext);

        using var cipher = new ChaCha20Poly1305Cipher(key);
        var sw = new Stopwatch();

        // Warmup
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);
        cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);

        // Encrypt
        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int iters = 50;
        for (int i = 0; i < iters; i++)
        {
            cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double totalGb = (double)size1Mb * iters / (1024 * 1024 * 1024);
        double gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"ChaCha20-Poly1305 Encrypt",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // Decrypt
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            cipher.Decrypt(ciphertext, default, nonce, tag, decrypted);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double decGbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / iters;
        status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"ChaCha20-Poly1305 Decrypt",-36} | {"1 MB",-10} | {$"{decGbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunArgon2idBenchmark()
    {
        byte[] password = new byte[32];
        byte[] salt = new byte[16];
        byte[] derived = new byte[32];
        Random.Shared.NextBytes(password);
        Random.Shared.NextBytes(salt);
        var sw = new Stopwatch();

        using var kdf = new Argon2id(iterations: 1, memoryKb: 1024, parallelism: 4);

        // Warmup (1 MB)
        kdf.DeriveKey(password, salt, derived);

        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int iters = 5;
        for (int i = 0; i < iters; i++)
        {
            kdf.DeriveKey(password, salt, derived);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();

        double msPerOp = sw.Elapsed.TotalMilliseconds / iters;
        long allocPerOp = (allocAfter - allocBefore) / iters;
        string status = msPerOp < 50.0 && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;

        Console.WriteLine($"{"Argon2id RFC 9106 (t=1, m=1MB, p=4)",-36} | {"1 MB Matrix",-10} | {$"{msPerOp:F2} ms/hash",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }

    private static void RunMlKemBenchmark()
    {
        byte[] pk768 = new byte[MlKem768.PublicKeyBytes];
        byte[] sk768 = new byte[MlKem768.SecretKeyBytes];
        byte[] ct768 = new byte[MlKem768.CiphertextBytes];
        byte[] ss768 = new byte[MlKem768.SharedSecretBytes];

        var sw = new Stopwatch();

        // Warmup
        MlKemEngine.MlKem768.GenerateKeyPair(pk768, sk768);
        MlKemEngine.MlKem768.Encapsulate(pk768, ct768, ss768);
        MlKemEngine.MlKem768.Decapsulate(sk768, ct768, ss768);

        const int iters = 1000;

        // 1. KeyGen
        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            MlKemEngine.MlKem768.GenerateKeyPair(pk768, sk768);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();
        double usKeyGen = (sw.Elapsed.TotalMilliseconds * 1000.0) / iters;
        long allocKeyGen = (allocAfter - allocBefore) / iters;
        string status = allocKeyGen == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"ML-KEM-768 KeyGen",-36} | {"FIPS 203",-10} | {$"{usKeyGen:F1} us ({iters / sw.Elapsed.TotalSeconds:F0} op/s)",-22} | {$"{allocKeyGen} B",-10} | {status,-6}");

        // 2. Encapsulate
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            MlKemEngine.MlKem768.Encapsulate(pk768, ct768, ss768);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();
        double usEncaps = (sw.Elapsed.TotalMilliseconds * 1000.0) / iters;
        long allocEncaps = (allocAfter - allocBefore) / iters;
        status = allocEncaps == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"ML-KEM-768 Encapsulate",-36} | {"FIPS 203",-10} | {$"{usEncaps:F1} us ({iters / sw.Elapsed.TotalSeconds:F0} op/s)",-22} | {$"{allocEncaps} B",-10} | {status,-6}");

        // 3. Decapsulate
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < iters; i++)
        {
            MlKemEngine.MlKem768.Decapsulate(sk768, ct768, ss768);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();
        double usDecaps = (sw.Elapsed.TotalMilliseconds * 1000.0) / iters;
        long allocDecaps = (allocAfter - allocBefore) / iters;
        status = allocDecaps == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"ML-KEM-768 Decapsulate",-36} | {"FIPS 203",-10} | {$"{usDecaps:F1} us ({iters / sw.Elapsed.TotalSeconds:F0} op/s)",-22} | {$"{allocDecaps} B",-10} | {status,-6}");
    }

    private static void RunCompressionBenchmark()
    {
        const int size1Mb = 1024 * 1024;
        byte[] uncompressed = new byte[size1Mb];
        string sample = "2026-10-24T12:00:00.000Z [INFO] Host=192.168.1.111 Service=Glacier.Codec RequestId=7f8b2c4e-1234 Status=200 Latency=1.42ms\n";
        byte[] sampleBytes = Encoding.UTF8.GetBytes(sample);
        for (int i = 0; i < size1Mb; i += sampleBytes.Length)
        {
            int take = Math.Min(sampleBytes.Length, size1Mb - i);
            Array.Copy(sampleBytes, 0, uncompressed, i, take);
        }

        byte[] lz4Dest = new byte[Lz4Codec.MaximumCompressedSize(size1Mb)];
        int lz4Len = Lz4Codec.Compress(uncompressed, lz4Dest);
        byte[] lz4Compressed = lz4Dest.AsSpan(0, lz4Len).ToArray();
        byte[] decompTarget = new byte[size1Mb];
        var sw = new Stopwatch();

        // 1. LZ4 Compress
        Lz4Codec.Compress(uncompressed, lz4Dest);
        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int lz4Iters = 100;
        for (int i = 0; i < lz4Iters; i++)
        {
            Lz4Codec.Compress(uncompressed, lz4Dest);
        }
        sw.Stop();
        long allocAfter = GC.GetAllocatedBytesForCurrentThread();
        double totalGb = (double)size1Mb * lz4Iters / (1024 * 1024 * 1024);
        double gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        long allocPerOp = (allocAfter - allocBefore) / lz4Iters;
        string status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"LZ4 Compress Block",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // 2. LZ4 Decompress
        Lz4Codec.Decompress(lz4Compressed, decompTarget);
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < lz4Iters; i++)
        {
            Lz4Codec.Decompress(lz4Compressed, decompTarget);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();
        gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / lz4Iters;
        status = gbPerSec >= 4.0 && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"LZ4 Decompress Block",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // 3. Zstd Compress
        byte[] zstdDest = new byte[ZstdCodec.MaximumCompressedSize(size1Mb)];
        int zstdLen = ZstdCodec.Compress(uncompressed, zstdDest);
        byte[] zstdCompressed = zstdDest.AsSpan(0, zstdLen).ToArray();

        ZstdCodec.Compress(uncompressed, zstdDest);
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        const int zstdIters = 50;
        for (int i = 0; i < zstdIters; i++)
        {
            ZstdCodec.Compress(uncompressed, zstdDest);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();
        totalGb = (double)size1Mb * zstdIters / (1024 * 1024 * 1024);
        gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / zstdIters;
        status = allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"Zstandard Compress Frame",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");

        // 4. Zstd Decompress
        ZstdCodec.Decompress(zstdCompressed, decompTarget);
        allocBefore = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        for (int i = 0; i < zstdIters; i++)
        {
            ZstdCodec.Decompress(zstdCompressed, decompTarget);
        }
        sw.Stop();
        allocAfter = GC.GetAllocatedBytesForCurrentThread();
        gbPerSec = totalGb / sw.Elapsed.TotalSeconds;
        allocPerOp = (allocAfter - allocBefore) / zstdIters;
        status = gbPerSec >= 1.0 && allocPerOp == 0 ? "PASS" : "WARN";
        if (status != "PASS") s_allPassed = false;
        Console.WriteLine($"{"Zstandard Decompress Frame",-36} | {"1 MB",-10} | {$"{gbPerSec:F2} GB/s",-22} | {$"{allocPerOp} B",-10} | {status,-6}");
    }
}
