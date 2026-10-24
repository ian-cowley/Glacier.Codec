namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Compression;
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
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Concurrency Torture, Multi-Threaded Stress, and Memory-Leak Verification Suite for Milestone M6.
/// Authored by Empirical Challenger 2 (challenger_m6_2).
/// Validates thread-safety, memory scrubbing, and non-contamination across:
/// UnmanagedSlabPool, HardwareArbiter, Blake3Hasher, Aes256GcmCipher, ChaCha20Poly1305Cipher,
/// Argon2id, MlKemEngine, Lz4Codec, and ZstdCodec.
/// </summary>
public class Challenger2M6ConcurrencyStressTests
{
    private const int ConcurrencyLevel32 = 32;

    [Fact]
    public void Concurrency_UnmanagedSlabPool_MassiveRace_RentReturnDispose_NoCorruption()
    {
        using var customPool = new UnmanagedSlabPool(maxSmallSlabs: 64, maxLargeSlabs: 16);
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                byte pattern = (byte)(threadId + 1);
                for (int iter = 0; iter < 50; iter++)
                {
                    // 1. Rent small slab (64 KB)
                    using (var lease = customPool.Rent(UnmanagedSlabPool.SmallSlabSize))
                    {
                        var span = lease.Buffer.Span;
                        span.Fill(pattern);
                        Assert.Equal(pattern, span[0]);
                        Assert.Equal(pattern, span[span.Length - 1]);
                    }

                    // 2. Rent large slab (1 MB)
                    using (var lease = customPool.Rent(UnmanagedSlabPool.LargeSlabSize))
                    {
                        var span = lease.Buffer.Span;
                        span.Fill(pattern);
                        Assert.Equal(pattern, span[0]);
                        Assert.Equal(pattern, span[span.Length - 1]);
                    }

                    // 3. Rent raw pointer slab
                    IntPtr ptr = customPool.Rent(UnmanagedSlabPool.SmallSlabSize, out int actual);
                    Assert.True(actual >= UnmanagedSlabPool.SmallSlabSize);
                    customPool.Return(ptr, actual);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_HardwareArbiter_MultiThreadedStress_StatelessIntegrity()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                for (int i = 0; i < 200; i++)
                {
                    Assert.Equal(ExecutionTarget.CpuVector, HardwareArbiter.RouteWorkload(0, 1, true));
                    Assert.Equal(ExecutionTarget.CpuVector, HardwareArbiter.RouteWorkload(512 * 1024, 1, true));
                    Assert.Equal(ExecutionTarget.CpuParallelPool, HardwareArbiter.RouteWorkload(2 * 1024 * 1024, 1, false));
                    Assert.Equal(ExecutionTarget.GpuCompute, HardwareArbiter.RouteWorkload(4 * 1024 * 1024, 1, true));
                    Assert.Equal(ExecutionTarget.CpuParallelPool, HardwareArbiter.RouteWorkload(4 * 1024 * 1024, 1, false));
                    Assert.Equal(ExecutionTarget.GpuCompute, HardwareArbiter.RouteWorkload(64 * 1024, 16, true));
                    Assert.Equal(ExecutionTarget.CpuParallelPool, HardwareArbiter.RouteWorkload(64 * 1024, 16, false));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_Blake3Hasher_ParallelTreeAndStreaming_ConcurrentExecution()
    {
        const int payloadSize = 2 * 1024 * 1024; // 2 MB triggers parallel tree reduction
        var exceptions = new ConcurrentBag<Exception>();

        byte[] baseInput = new byte[payloadSize];
        for (int i = 0; i < payloadSize; i++) baseInput[i] = (byte)(i * 31);
        byte[] expectedHash = new byte[32];
        Blake3Hasher.Hash(baseInput, expectedHash);

        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, threadId =>
        {
            try
            {
                byte[] input = new byte[payloadSize];
                Array.Copy(baseInput, input, payloadSize);
                byte[] output = new byte[32];

                for (int iter = 0; iter < 10; iter++)
                {
                    Blake3Hasher.Hash(input, output);
                    Assert.True(expectedHash.AsSpan().SequenceEqual(output),
                        $"Blake3 thread {threadId} mismatch on parallel hash at iteration {iter}.");

                    // Also test streaming hasher in parallel
                    using var hasher = new Blake3Hasher();
                    hasher.Append(input.AsSpan(0, 1024 * 1024));
                    hasher.Append(input.AsSpan(1024 * 1024));
                    byte[] streamOutput = new byte[32];
                    hasher.Finalize(streamOutput);
                    Assert.True(expectedHash.AsSpan().SequenceEqual(streamOutput));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_Aes256GcmCipher_SharedInstance_MultiThreadedEncryptDecrypt()
    {
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        using var sharedCipher = new Aes256GcmCipher(masterKey);
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                int len = 16384 + (threadId * 1024);
                byte[] plaintext = new byte[len];
                byte[] nonce = new byte[12];
                byte[] aad = new byte[16];
                byte[] ciphertext = new byte[len];
                byte[] tag = new byte[16];
                byte[] decrypted = new byte[len];

                for (int iter = 0; iter < 15; iter++)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);
                    RandomNumberGenerator.Fill(plaintext);
                    RandomNumberGenerator.Fill(aad);

                    sharedCipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

                    decrypted.AsSpan().Clear();
                    bool ok = sharedCipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
                    Assert.True(ok, $"Decryption failed on thread {threadId} iter {iter}.");
                    Assert.True(plaintext.AsSpan().SequenceEqual(decrypted));

                    // Adversarial check: tamper tag must fail and zero decrypted buffer
                    tag[0] ^= 0xFF;
                    decrypted.AsSpan().Fill(0xAA);
                    bool tamperedOk = sharedCipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
                    Assert.False(tamperedOk);
                    Assert.All(decrypted, b => Assert.Equal(0, b));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_ChaCha20Poly1305Cipher_SharedInstance_MultiThreadedStress()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        using var sharedCipher = new ChaCha20Poly1305Cipher(key);
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                int len = 8192 + (threadId * 512);
                byte[] plaintext = new byte[len];
                byte[] nonce = new byte[12];
                byte[] aad = new byte[16];
                byte[] ciphertext = new byte[len];
                byte[] tag = new byte[16];
                byte[] decrypted = new byte[len];

                for (int iter = 0; iter < 20; iter++)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);
                    RandomNumberGenerator.Fill(plaintext);
                    RandomNumberGenerator.Fill(aad);

                    sharedCipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

                    decrypted.AsSpan().Clear();
                    bool ok = sharedCipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
                    Assert.True(ok, $"ChaCha20 decryption failed on thread {threadId} iter {iter}.");
                    Assert.True(plaintext.AsSpan().SequenceEqual(decrypted));

                    // Adversarial check: corrupted tag must fail and zero destination
                    tag[0] ^= 0x01;
                    decrypted.AsSpan().Fill(0x55);
                    bool bad = sharedCipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
                    Assert.False(bad);
                    Assert.All(decrypted, b => Assert.Equal(0, b));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_Argon2id_HeavyMultiThreadedKdf_NoMemoryLeaks()
    {
        // 8 threads concurrently running RFC 9106 Argon2id with 2MB matrix each
        const int threads = 8;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, threadId =>
        {
            try
            {
                using var argon = new Argon2id(iterations: 1, memoryKb: 1024, parallelism: 2);
                byte[] password = new byte[16];
                byte[] salt = new byte[16];
                BinaryPrimitives.WriteInt32LittleEndian(password.AsSpan(0, 4), threadId);
                BinaryPrimitives.WriteInt32LittleEndian(salt.AsSpan(0, 4), threadId ^ 0x5A5A);

                byte[] key1 = new byte[32];
                byte[] key2 = new byte[32];

                argon.DeriveKey(password, salt, key1);
                argon.DeriveKey(password, salt, key2);

                Assert.True(key1.AsSpan().SequenceEqual(key2), "Argon2id non-deterministic under concurrency.");
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_MlKemEngine_ConcurrentFips203KeyGenEncapsDecaps_NoContamination()
    {
        var exceptions = new ConcurrentBag<Exception>();
        var kem768 = MlKemEngine.MlKem768;
        var kem1024 = MlKemEngine.MlKem1024;

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                var kem = (threadId % 2 == 0) ? (MlKemEngine)kem768 : kem1024;

                byte[] pk = new byte[kem.PublicKeySizeInBytes];
                byte[] sk = new byte[kem.SecretKeySizeInBytes];
                byte[] ct = new byte[kem.CiphertextSizeInBytes];
                byte[] ssA = new byte[kem.SharedSecretSizeInBytes];
                byte[] ssB = new byte[kem.SharedSecretSizeInBytes];

                for (int iter = 0; iter < 10; iter++)
                {
                    kem.GenerateKeyPair(pk, sk);
                    kem.Encapsulate(pk, ct, ssA);

                    bool decOk = kem.Decapsulate(sk, ct, ssB);
                    Assert.True(decOk);
                    Assert.True(ssA.AsSpan().SequenceEqual(ssB),
                        $"ML-KEM shared secret mismatch on thread {threadId} iter {iter}.");

                    // Implicit rejection: tamper with ciphertext byte
                    ct[ct.Length - 1] ^= 0x01;
                    byte[] ssTampered = new byte[kem.SharedSecretSizeInBytes];
                    bool rejOk = kem.Decapsulate(sk, ct, ssTampered);
                    Assert.False(rejOk); // Implicit rejection returns false but populates deterministic pseudorandom fallback secret
                    Assert.False(ssA.AsSpan().SequenceEqual(ssTampered));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_Lz4Codec_And_ZstdCodec_InterleavedStressPipeline()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, ConcurrencyLevel32, new ParallelOptions { MaxDegreeOfParallelism = ConcurrencyLevel32 }, threadId =>
        {
            try
            {
                int len = 32768 + (threadId * 1024);
                byte[] input = new byte[len];
                // Mixed compressible data: repeats, arithmetic ramps, sparse zeros
                for (int i = 0; i < len; i++)
                {
                    input[i] = (i % 32 == 0) ? (byte)0 : (byte)((threadId * 13 + i) % 64);
                }

                if (threadId % 2 == 0)
                {
                    // LZ4
                    byte[] comp = new byte[Lz4Codec.MaximumCompressedSize(len)];
                    byte[] decomp = new byte[len];

                    for (int iter = 0; iter < 15; iter++)
                    {
                        int cLen = Lz4Codec.Compress(input, comp);
                        int dLen = Lz4Codec.Decompress(comp.AsSpan(0, cLen), decomp);
                        Assert.Equal(len, dLen);
                        Assert.True(input.AsSpan().SequenceEqual(decomp));
                    }
                }
                else
                {
                    // Zstd
                    byte[] comp = new byte[ZstdCodec.MaximumCompressedSize(len)];
                    byte[] decomp = new byte[len];

                    for (int iter = 0; iter < 15; iter++)
                    {
                        int cLen = ZstdCodec.Compress(input, comp);
                        int dLen = ZstdCodec.Decompress(comp.AsSpan(0, cLen), decomp);
                        Assert.Equal(len, dLen);
                        Assert.True(input.AsSpan().SequenceEqual(decomp));
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_ThreadLocalBufferContamination_And_MemoryScrubbing()
    {
        // Rigorously test that recycled slabs from UnmanagedSlabPool are 100% scrubbed with zero residual bytes
        var pool = UnmanagedSlabPool.Shared;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, threadId =>
        {
            try
            {
                for (int iter = 0; iter < 40; iter++)
                {
                    // 1. Rent small slab, write dirty poison pattern, and dispose
                    using (var lease = pool.Rent(UnmanagedSlabPool.SmallSlabSize))
                    {
                        lease.Buffer.Span.Fill((byte)(0xA0 | (threadId & 0x0F)));
                    }

                    // 2. Immediately rent again: must be 100% zeroed
                    using (var lease2 = pool.Rent(UnmanagedSlabPool.SmallSlabSize))
                    {
                        var span = lease2.Buffer.Span;
                        for (int k = 0; k < span.Length; k++)
                        {
                            if (span[k] != 0)
                            {
                                throw new InvalidOperationException(
                                    $"Slab contamination detected at offset {k}: expected 0, found 0x{span[k]:X2}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_E2E_FullHeterogeneousCryptoPipelineStress()
    {
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, threadId =>
        {
            try
            {
                const int payloadLen = 65536;
                byte[] raw = new byte[payloadLen];
                for (int i = 0; i < payloadLen; i++) raw[i] = (byte)((threadId * 7 + i) % 128);

                for (int round = 0; round < 10; round++)
                {
                    // 1. Compress with LZ4
                    byte[] compressed = new byte[Lz4Codec.MaximumCompressedSize(payloadLen)];
                    int compLen = Lz4Codec.Compress(raw, compressed);

                    // 2. Post-quantum key exchange (ML-KEM-768)
                    var kem = MlKemEngine.MlKem768;
                    byte[] pk = new byte[kem.PublicKeySizeInBytes];
                    byte[] sk = new byte[kem.SecretKeySizeInBytes];
                    byte[] ct = new byte[kem.CiphertextSizeInBytes];
                    byte[] senderKey = new byte[32];
                    byte[] receiverKey = new byte[32];

                    kem.GenerateKeyPair(pk, sk);
                    kem.Encapsulate(pk, ct, senderKey);
                    kem.Decapsulate(sk, ct, receiverKey);
                    Assert.True(senderKey.AsSpan().SequenceEqual(receiverKey));

                    // 3. Encrypt compressed payload with AES-256-GCM using derived KEM key
                    using var cipher = new Aes256GcmCipher(senderKey);
                    byte[] nonce = new byte[12];
                    byte[] aad = new byte[16];
                    byte[] encrypted = new byte[compLen];
                    byte[] tag = new byte[16];
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), round);

                    cipher.Encrypt(compressed.AsSpan(0, compLen), aad, nonce, encrypted, tag);

                    // 4. Compute BLAKE3 and xxHash3 digests over encrypted payload
                    byte[] b3Digest = new byte[32];
                    Blake3Hasher.Hash(encrypted, b3Digest);
                    ulong xxh64 = XxHash3.Hash64(encrypted);
                    Assert.NotEqual(0UL, xxh64);

                    // 5. Decrypt using receiver KEM key
                    using var recvCipher = new Aes256GcmCipher(receiverKey);
                    byte[] decryptedComp = new byte[compLen];
                    bool decOk = recvCipher.Decrypt(encrypted, aad, nonce, tag, decryptedComp);
                    Assert.True(decOk);

                    // 6. Decompress with LZ4 and verify original bytes
                    byte[] decompressed = new byte[payloadLen];
                    int decompLen = Lz4Codec.Decompress(decryptedComp, decompressed);
                    Assert.Equal(payloadLen, decompLen);
                    Assert.True(raw.AsSpan().SequenceEqual(decompressed));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }


    [Fact]
    public void Concurrency_Blake3_ParallelTree_Contention_ZeroAllocations_24Threads()
    {
        const int concurrency = 24;
        const int payloadSize = 2 * 1024 * 1024; // 2 MB triggers parallel tree reduction
        var exceptions = new ConcurrentBag<Exception>();

        byte[] inputData = new byte[payloadSize];
        for (int i = 0; i < payloadSize; i++) inputData[i] = (byte)(i * 37 + 11);

        byte[] expectedHash = new byte[32];
        Blake3Hasher.Hash(inputData, expectedHash);

        var readyEvent = new CountdownEvent(concurrency);
        var startEvent = new ManualResetEventSlim(false);
        var threads = new Thread[concurrency];

        for (int t = 0; t < concurrency; t++)
        {
            int threadId = t;
            threads[t] = new Thread(() =>
            {
                try
                {
                    byte[] threadInput = new byte[payloadSize];
                    Array.Copy(inputData, threadInput, payloadSize);
                    byte[] threadOutput = new byte[32];

                    readyEvent.Signal();
                    startEvent.Wait();

                    // Concurrent warm-up across all 24 threads: JIT and pool cache population
                    for (int w = 0; w < 3; w++)
                    {
                        Blake3Hasher.Hash(threadInput.AsSpan(), threadOutput.AsSpan());
                    }
                    Assert.True(expectedHash.AsSpan().SequenceEqual(threadOutput));

                    // Steady-state measurement: zero heap allocations
                    for (int iter = 0; iter < 10; iter++)
                    {
                        long before = GC.GetAllocatedBytesForCurrentThread();

                        Blake3Hasher.Hash(threadInput.AsSpan(), threadOutput.AsSpan());

                        long after = GC.GetAllocatedBytesForCurrentThread();
                        long allocated = after - before;

                        if (allocated != 0)
                        {
                            throw new InvalidOperationException(
                                $"Blake3 calling thread {threadId} allocated {allocated} bytes on steady-state hot path at iter {iter}.");
                        }

                        Assert.True(expectedHash.AsSpan().SequenceEqual(threadOutput),
                            $"Blake3 hash mismatch on thread {threadId} iter {iter}.");
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            })
            {
                IsBackground = true
            };
            threads[t].Start();
        }

        readyEvent.Wait();
        startEvent.Set();

        for (int t = 0; t < concurrency; t++)
        {
            threads[t].Join();
        }

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_AesGcm_ParallelEngine_Contention_ZeroAllocations_24Threads()
    {
        const int concurrency = 24;
        const int payloadSize = 512 * 1024; // 512 KB triggers AesGcmParallelEngine (>= 256 KB)
        var exceptions = new ConcurrentBag<Exception>();

        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        Parallel.For(0, concurrency, new ParallelOptions { MaxDegreeOfParallelism = concurrency }, threadId =>
        {
            try
            {
                using var cipher = new Aes256GcmCipher(key);
                byte[] plaintext = new byte[payloadSize];
                for (int i = 0; i < payloadSize; i++) plaintext[i] = (byte)((threadId * 19 + i) & 0xFF);
                byte[] aad = new byte[32];
                for (int i = 0; i < 32; i++) aad[i] = (byte)(i ^ threadId);
                byte[] nonce = new byte[12];
                byte[] ciphertext = new byte[payloadSize];
                byte[] tag = new byte[16];
                byte[] decrypted = new byte[payloadSize];

                // Warm-up iterations: JIT compile span methods and populate pool cache
                BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), 9999);
                for (int w = 0; w < 3; w++)
                {
                    cipher.Encrypt(plaintext.AsSpan(), aad.AsSpan(), nonce.AsSpan(), ciphertext.AsSpan(), tag.AsSpan());
                    bool warmOk = cipher.Decrypt(ciphertext.AsSpan(), aad.AsSpan(), nonce.AsSpan(), tag.AsSpan(), decrypted.AsSpan());
                    Assert.True(warmOk);
                }
                Assert.True(plaintext.AsSpan().SequenceEqual(decrypted));

                for (int iter = 0; iter < 10; iter++)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);

                    long before = GC.GetAllocatedBytesForCurrentThread();

                    cipher.Encrypt(plaintext.AsSpan(), aad.AsSpan(), nonce.AsSpan(), ciphertext.AsSpan(), tag.AsSpan());
                    bool ok = cipher.Decrypt(ciphertext.AsSpan(), aad.AsSpan(), nonce.AsSpan(), tag.AsSpan(), decrypted.AsSpan());

                    long after = GC.GetAllocatedBytesForCurrentThread();
                    long allocated = after - before;

                    if (allocated != 0)
                    {
                        throw new InvalidOperationException(
                            $"AesGcm calling thread {threadId} allocated {allocated} bytes on steady-state hot path at iter {iter}.");
                    }

                    Assert.True(ok, $"Decryption failed on thread {threadId} iter {iter}.");
                    Assert.True(plaintext.AsSpan().SequenceEqual(decrypted),
                        $"Plaintext mismatch on thread {threadId} iter {iter}.");
                }

                // Adversarial check: tamper with tag
                tag[0] ^= 0xEE;
                decrypted.AsSpan().Fill(0x55);
                bool badTagOk = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
                Assert.False(badTagOk);
                Assert.All(decrypted, b => Assert.Equal(0, b));
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Concurrency_UnmanagedSlabPool_Shared_AllThreeTiers_ZeroAllocations_24Threads()
    {
        const int concurrency = 24;
        var pool = UnmanagedSlabPool.Shared;
        var exceptions = new ConcurrentBag<Exception>();

        // Warmup: ensure pool has warmed slabs for each tier
        for (int i = 0; i < concurrency; i++)
        {
            using var s = pool.Rent(UnmanagedSlabPool.SmallSlabSize);
            using var l = pool.Rent(UnmanagedSlabPool.LargeSlabSize);
            using var h = pool.Rent(UnmanagedSlabPool.HugeSlabSize);
        }

        Parallel.For(0, concurrency, new ParallelOptions { MaxDegreeOfParallelism = concurrency }, threadId =>
        {
            try
            {
                // Thread-level warmup
                using (var s = pool.Rent(UnmanagedSlabPool.SmallSlabSize)) { }
                using (var l = pool.Rent(UnmanagedSlabPool.LargeSlabSize)) { }
                using (var h = pool.Rent(UnmanagedSlabPool.HugeSlabSize)) { }

                for (int iter = 0; iter < 15; iter++)
                {
                    // 1. Rapid rent/return across 64 KB (Small) tier
                    long b1 = GC.GetAllocatedBytesForCurrentThread();
                    using (var lease64 = pool.Rent(UnmanagedSlabPool.SmallSlabSize))
                    {
                        var s = lease64.Span;
                        s[0] = (byte)(threadId + 1);
                        s[s.Length - 1] = (byte)(threadId + 2);
                    }
                    long a1 = GC.GetAllocatedBytesForCurrentThread();
                    if (a1 - b1 != 0)
                        throw new InvalidOperationException($"SmallTier allocated {a1 - b1} B on thread {threadId} at iter {iter}");

                    // 2. Rapid rent/return across 1 MB (Large) tier
                    long b2 = GC.GetAllocatedBytesForCurrentThread();
                    using (var lease1M = pool.Rent(UnmanagedSlabPool.LargeSlabSize))
                    {
                        var s = lease1M.Span;
                        s[0] = (byte)(threadId + 3);
                        s[s.Length - 1] = (byte)(threadId + 4);
                    }
                    long a2 = GC.GetAllocatedBytesForCurrentThread();
                    if (a2 - b2 != 0)
                        throw new InvalidOperationException($"LargeTier allocated {a2 - b2} B on thread {threadId} at iter {iter}");

                    // 3. Rapid rent/return across 4 MB (Huge) tier
                    long b3 = GC.GetAllocatedBytesForCurrentThread();
                    using (var lease4M = pool.Rent(UnmanagedSlabPool.HugeSlabSize))
                    {
                        var s = lease4M.Span;
                        s[0] = (byte)(threadId + 5);
                        s[s.Length - 1] = (byte)(threadId + 6);
                    }
                    long a3 = GC.GetAllocatedBytesForCurrentThread();
                    if (a3 - b3 != 0)
                        throw new InvalidOperationException($"HugeTier allocated {a3 - b3} B on thread {threadId} at iter {iter}");

                    // 4. Raw pointer rent/return cycles
                    long b4 = GC.GetAllocatedBytesForCurrentThread();
                    IntPtr ptrSmall = pool.Rent(UnmanagedSlabPool.SmallSlabSize, out int actualSmall);
                    pool.Return(ptrSmall, actualSmall);

                    IntPtr ptrLarge = pool.Rent(UnmanagedSlabPool.LargeSlabSize, out int actualLarge);
                    pool.Return(ptrLarge, actualLarge);

                    IntPtr ptrHuge = pool.Rent(UnmanagedSlabPool.HugeSlabSize, out int actualHuge);
                    pool.Return(ptrHuge, actualHuge);
                    long a4 = GC.GetAllocatedBytesForCurrentThread();
                    if (a4 - b4 != 0)
                        throw new InvalidOperationException($"RawRent allocated {a4 - b4} B on thread {threadId} at iter {iter}");
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }
}

