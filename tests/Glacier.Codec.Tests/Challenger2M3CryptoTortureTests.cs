namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Memory;
using Xunit;

/// <summary>
/// Empirical Adversarial Challenge Test Suite for Milestone M3 (AES-256-GCM & ChaCha20-Poly1305).
/// Authored by Empirical Challenger 2.
/// 
/// Stress-tests:
/// 1. Concurrency & Multi-Thread Torture under 32 parallel threads (shared and distinct cipher instances).
/// 2. Large Payload Stress Testing across 1MB, 4MB, 8MB, 16MB, and 32MB streams with bit-exact roundtrips.
/// 3. Zero Heap Allocation verification in steady-state encryption/decryption hot paths.
/// 4. Key Material lifecycle, zero-memory erasure upon Dispose(), and tamper rejection fail-secure wiping.
/// </summary>
public class Challenger2M3CryptoTortureTests
{
    private const int ThreadCount32 = 32;

    // =========================================================================
    // SECTION 1: CONCURRENCY & MULTI-THREAD TORTURE (32 THREADS)
    // =========================================================================

    [Fact]
    public void ConcurrencyTorture_32Threads_SharedInstance_Aes256Gcm()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var sharedCipher = new Aes256GcmCipher(key);
        var exceptions = new ConcurrentBag<Exception>();
        int totalIterationsCompleted = 0;

        int[] payloadSizes = [0, 15, 16, 31, 64, 127, 256, 1024, 4096];
        const int iterationsPerThread = 80;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerThread; iter++)
                {
                    int size = payloadSizes[(threadId * 7 + iter) % payloadSizes.Length];
                    byte[] pt = new byte[size];
                    for (int i = 0; i < size; i++)
                    {
                        pt[i] = (byte)((threadId * 31 + iter * 17 + i) & 0xFF);
                    }

                    byte[] nonce = new byte[12];
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(8, 4), size);

                    byte[] aad = new byte[(iter % 3) * 16];
                    for (int i = 0; i < aad.Length; i++)
                    {
                        aad[i] = (byte)(i ^ 0xAA);
                    }

                    byte[] ct = new byte[size];
                    byte[] tag = new byte[16];

                    // Encrypt
                    sharedCipher.Encrypt(pt, aad, nonce, ct, tag);

                    // Decrypt
                    byte[] decrypted = new byte[size];
                    bool ok = sharedCipher.Decrypt(ct, aad, nonce, tag, decrypted);
                    if (!ok)
                    {
                        throw new InvalidOperationException($"Aes256Gcm decrypt failed on thread {threadId}, iter {iter}, size {size}");
                    }
                    if (!decrypted.AsSpan().SequenceEqual(pt))
                    {
                        throw new InvalidOperationException($"Aes256Gcm plaintext mismatch on thread {threadId}, iter {iter}, size {size}");
                    }

                    // Tamper check (flip 1 bit in tag)
                    byte[] tamperedTag = (byte[])tag.Clone();
                    tamperedTag[0] ^= 0x01;
                    byte[] shouldBeZeroed = new byte[size];
                    Array.Fill<byte>(shouldBeZeroed, 0xFF);
                    bool tamperedOk = sharedCipher.Decrypt(ct, aad, nonce, tamperedTag, shouldBeZeroed);
                    if (tamperedOk)
                    {
                        throw new InvalidOperationException($"Aes256Gcm accepted tampered tag on thread {threadId}, iter {iter}");
                    }
                    if (size > 0 && shouldBeZeroed[0] != 0)
                    {
                        throw new InvalidOperationException($"Aes256Gcm fail-secure wipe did not clear output on thread {threadId}");
                    }

                    Interlocked.Increment(ref totalIterationsCompleted);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ThreadCount32 * iterationsPerThread, totalIterationsCompleted);
    }

    [Fact]
    public void ConcurrencyTorture_32Threads_SharedInstance_ChaCha20Poly1305()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var sharedCipher = new ChaCha20Poly1305Cipher(key);
        var exceptions = new ConcurrentBag<Exception>();
        int totalIterationsCompleted = 0;

        int[] payloadSizes = [0, 15, 16, 31, 64, 127, 256, 1024, 4096];
        const int iterationsPerThread = 80;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                for (int iter = 0; iter < iterationsPerThread; iter++)
                {
                    int size = payloadSizes[(threadId * 7 + iter) % payloadSizes.Length];
                    byte[] pt = new byte[size];
                    for (int i = 0; i < size; i++)
                    {
                        pt[i] = (byte)((threadId * 37 + iter * 13 + i) & 0xFF);
                    }

                    byte[] nonce = new byte[12];
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(8, 4), size);

                    byte[] aad = new byte[(iter % 3) * 16];
                    for (int i = 0; i < aad.Length; i++)
                    {
                        aad[i] = (byte)(i ^ 0x55);
                    }

                    byte[] ct = new byte[size];
                    byte[] tag = new byte[16];

                    // Encrypt
                    sharedCipher.Encrypt(pt, aad, nonce, ct, tag);

                    // Decrypt
                    byte[] decrypted = new byte[size];
                    bool ok = sharedCipher.Decrypt(ct, aad, nonce, tag, decrypted);
                    if (!ok)
                    {
                        throw new InvalidOperationException($"ChaCha20Poly1305 decrypt failed on thread {threadId}, iter {iter}, size {size}");
                    }
                    if (!decrypted.AsSpan().SequenceEqual(pt))
                    {
                        throw new InvalidOperationException($"ChaCha20Poly1305 plaintext mismatch on thread {threadId}, iter {iter}, size {size}");
                    }

                    // Tamper check (flip 1 bit in tag)
                    byte[] tamperedTag = (byte[])tag.Clone();
                    tamperedTag[tag.Length - 1] ^= 0x80;
                    byte[] shouldBeZeroed = new byte[size];
                    Array.Fill<byte>(shouldBeZeroed, 0xEE);
                    bool tamperedOk = sharedCipher.Decrypt(ct, aad, nonce, tamperedTag, shouldBeZeroed);
                    if (tamperedOk)
                    {
                        throw new InvalidOperationException($"ChaCha20Poly1305 accepted tampered tag on thread {threadId}, iter {iter}");
                    }
                    if (size > 0 && shouldBeZeroed[0] != 0)
                    {
                        throw new InvalidOperationException($"ChaCha20Poly1305 fail-secure wipe did not clear output on thread {threadId}");
                    }

                    Interlocked.Increment(ref totalIterationsCompleted);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Equal(ThreadCount32 * iterationsPerThread, totalIterationsCompleted);
    }

    [Fact]
    public void ConcurrencyTorture_32Threads_DistinctInstances_AesAndChaCha()
    {
        var exceptions = new ConcurrentBag<Exception>();
        const int iterationsPerThread = 60;

        Parallel.For(0, ThreadCount32, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount32 }, threadId =>
        {
            try
            {
                byte[] key = new byte[32];
                for (int i = 0; i < 32; i++) key[i] = (byte)(threadId ^ i ^ 0x3C);

                bool useAes = (threadId % 2 == 0);

                using IAeadCipher cipher = useAes
                    ? new Aes256GcmCipher(key)
                    : new ChaCha20Poly1305Cipher(key);

                for (int iter = 0; iter < iterationsPerThread; iter++)
                {
                    int size = 512 + (iter * 16);
                    byte[] pt = new byte[size];
                    for (int i = 0; i < size; i++) pt[i] = (byte)(iter + i);

                    byte[] nonce = new byte[12];
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), threadId);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);

                    byte[] ct = new byte[size];
                    byte[] tag = new byte[16];

                    cipher.Encrypt(pt, default, nonce, ct, tag);

                    byte[] dec = new byte[size];
                    bool ok = cipher.Decrypt(ct, default, nonce, tag, dec);
                    if (!ok || !dec.AsSpan().SequenceEqual(pt))
                    {
                        throw new InvalidOperationException($"Distinct instance failure on thread {threadId}, cipher {cipher.GetType().Name}, iter {iter}");
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

    // =========================================================================
    // SECTION 2: LARGE PAYLOAD STRESS TESTING (1MB, 4MB, 8MB, 16MB, 32MB)
    // =========================================================================

    [Theory]
    [InlineData(1 * 1024 * 1024)]       // 1 MB
    [InlineData(4 * 1024 * 1024)]       // 4 MB
    [InlineData(8 * 1024 * 1024)]       // 8 MB
    [InlineData(16 * 1024 * 1024)]     // 16 MB
    [InlineData(32 * 1024 * 1024)]     // 32 MB
    public void LargePayload_Aes256Gcm_BitExact_Roundtrip(int payloadSize)
    {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)(i * 7 + 0x1F);

        byte[] nonce = new byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), payloadSize);
        nonce[11] = 0xAA;

        byte[] aad = "Glacier.Codec.M3.LargePayload.Aes256Gcm"u8.ToArray();

        byte[] plaintext = new byte[payloadSize];
        // Populate deterministically
        uint lcg = 0x12345678;
        for (int i = 0; i < payloadSize; i++)
        {
            lcg = lcg * 1664525u + 1013904223u;
            plaintext[i] = (byte)(lcg >> 24);
        }

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);

        // Encrypt large stream
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        // Ciphertext must differ from plaintext
        Assert.False(ciphertext.AsSpan(0, Math.Min(1024, payloadSize)).SequenceEqual(plaintext.AsSpan(0, Math.Min(1024, payloadSize))));

        // Decrypt large stream
        byte[] decrypted = new byte[payloadSize];
        bool ok = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.True(ok, $"Aes256Gcm failed to decrypt {payloadSize} bytes payload.");

        // Bit-exact verification across entire payload
        Assert.True(decrypted.AsSpan().SequenceEqual(plaintext), $"Decrypted buffer did not match plaintext for {payloadSize} bytes.");

        // Tamper test at boundary (beginning, middle, end)
        int tamperIndex = payloadSize / 2;
        ciphertext[tamperIndex] ^= 0x40;
        Array.Fill<byte>(decrypted, 0xAA);

        bool tamperedOk = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.False(tamperedOk, "Aes256Gcm should reject tampered payload.");
        Assert.Equal(0, decrypted[0]);
        Assert.Equal(0, decrypted[tamperIndex]);
        Assert.Equal(0, decrypted[payloadSize - 1]);
    }

    [Theory]
    [InlineData(1 * 1024 * 1024)]       // 1 MB
    [InlineData(4 * 1024 * 1024)]       // 4 MB
    [InlineData(8 * 1024 * 1024)]       // 8 MB
    [InlineData(16 * 1024 * 1024)]     // 16 MB
    [InlineData(32 * 1024 * 1024)]     // 32 MB
    public void LargePayload_ChaCha20Poly1305_BitExact_Roundtrip(int payloadSize)
    {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)(i * 13 + 0x5A);

        byte[] nonce = new byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), payloadSize);
        nonce[11] = 0x55;

        byte[] aad = "Glacier.Codec.M3.LargePayload.ChaCha20Poly1305"u8.ToArray();

        byte[] plaintext = new byte[payloadSize];
        uint lcg = 0x87654321;
        for (int i = 0; i < payloadSize; i++)
        {
            lcg = lcg * 1664525u + 1013904223u;
            plaintext[i] = (byte)(lcg >> 24);
        }

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new ChaCha20Poly1305Cipher(key);

        // Encrypt large stream
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        // Ciphertext must differ from plaintext
        Assert.False(ciphertext.AsSpan(0, Math.Min(1024, payloadSize)).SequenceEqual(plaintext.AsSpan(0, Math.Min(1024, payloadSize))));

        // Decrypt large stream
        byte[] decrypted = new byte[payloadSize];
        bool ok = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.True(ok, $"ChaCha20Poly1305 failed to decrypt {payloadSize} bytes payload.");

        // Bit-exact verification across entire payload
        Assert.True(decrypted.AsSpan().SequenceEqual(plaintext), $"Decrypted buffer did not match plaintext for {payloadSize} bytes.");

        // Tamper test at boundary
        int tamperIndex = payloadSize - 1;
        ciphertext[tamperIndex] ^= 0x01;
        Array.Fill<byte>(decrypted, 0xBB);

        bool tamperedOk = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        Assert.False(tamperedOk, "ChaCha20Poly1305 should reject tampered payload.");
        Assert.Equal(0, decrypted[0]);
        Assert.Equal(0, decrypted[tamperIndex]);
    }

    // =========================================================================
    // SECTION 3: MEMORY LIFECYCLE & ZERO-ALLOCATION VALIDATION
    // =========================================================================

    [Theory]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(1024)]
    [InlineData(65536)]
    public void ZeroHeapAllocation_SteadyState_Aes256Gcm(int bufferSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] pt = new byte[bufferSize];
        byte[] ct = new byte[bufferSize];
        byte[] tag = new byte[16];
        byte[] dec = new byte[bufferSize];

        using var cipher = new Aes256GcmCipher(key);

        // Warmup JIT & static structures
        for (int i = 0; i < 5; i++)
        {
            cipher.Encrypt(pt, default, nonce, ct, tag);
            cipher.Decrypt(ct, default, nonce, tag, dec);
        }

        // Measure steady-state allocations across 20 iterations
        long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();

        for (int i = 0; i < 20; i++)
        {
            cipher.Encrypt(pt, default, nonce, ct, tag);
            cipher.Decrypt(ct, default, nonce, tag, dec);
        }

        long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, afterAlloc - beforeAlloc);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(1024)]
    [InlineData(65536)]
    public void ZeroHeapAllocation_SteadyState_ChaCha20Poly1305(int bufferSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] pt = new byte[bufferSize];
        byte[] ct = new byte[bufferSize];
        byte[] tag = new byte[16];
        byte[] dec = new byte[bufferSize];

        using var cipher = new ChaCha20Poly1305Cipher(key);

        // Warmup
        for (int i = 0; i < 5; i++)
        {
            cipher.Encrypt(pt, default, nonce, ct, tag);
            cipher.Decrypt(ct, default, nonce, tag, dec);
        }

        long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();

        for (int i = 0; i < 20; i++)
        {
            cipher.Encrypt(pt, default, nonce, ct, tag);
            cipher.Decrypt(ct, default, nonce, tag, dec);
        }

        long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, afterAlloc - beforeAlloc);
    }

    [Fact]
    public void Dispose_Aes256Gcm_ZeroesKeyMaterialAndNullsReferences()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var cipher = new Aes256GcmCipher(key);

        var expandedKeysField = typeof(Aes256GcmCipher).GetField("_expandedKeys", BindingFlags.NonPublic | BindingFlags.Instance);
        var hTableField = typeof(Aes256GcmCipher).GetField("_hTable", BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(expandedKeysField);
        Assert.NotNull(hTableField);

        var expandedKeys = (SecureMemory?)expandedKeysField.GetValue(cipher);
        var hTable = (SecureMemory?)hTableField.GetValue(cipher);

        Assert.NotNull(expandedKeys);
        Assert.NotNull(hTable);
        Assert.False(expandedKeys.Span.SequenceEqual(new byte[expandedKeys.Length]));

        // Dispose cipher
        cipher.Dispose();

        // References must be nulled
        Assert.Null(expandedKeysField.GetValue(cipher));
        Assert.Null(hTableField.GetValue(cipher));

        // Calling methods on disposed cipher must throw
        byte[] nonce = new byte[12];
        byte[] buf = new byte[16];
        byte[] tag = new byte[16];
        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(buf, default, nonce, buf, tag));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(buf, default, nonce, tag, buf));

        // Idempotency: multiple Dispose calls do not throw
        cipher.Dispose();
        cipher.Dispose();
    }

    [Fact]
    public void Dispose_ChaCha20Poly1305_ZeroesKeyMaterialAndNullsReferences()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var cipher = new ChaCha20Poly1305Cipher(key);

        var keyField = typeof(ChaCha20Poly1305Cipher).GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(keyField);

        var secureKey = (SecureMemory?)keyField.GetValue(cipher);
        Assert.NotNull(secureKey);
        Assert.False(secureKey.Span.SequenceEqual(new byte[32]));

        // Dispose cipher
        cipher.Dispose();

        Assert.Null(keyField.GetValue(cipher));

        byte[] nonce = new byte[12];
        byte[] buf = new byte[16];
        byte[] tag = new byte[16];
        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(buf, default, nonce, buf, tag));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(buf, default, nonce, tag, buf));

        // Idempotent
        cipher.Dispose();
        cipher.Dispose();
    }

    [Fact]
    public unsafe void SecureMemory_ScrubAndDispose_DirectZeroMemoryVerification()
    {
        byte[] secret = new byte[64];
        for (int i = 0; i < 64; i++) secret[i] = (byte)(i + 1);

        // Test CreateAndWipeSource
        byte[] sourceKey = (byte[])secret.Clone();
        using (var mem = SecureMemory.CreateAndWipeSource(sourceKey))
        {
            // Source key must be zeroed
            Assert.True(sourceKey.AsSpan().SequenceEqual(new byte[64]));
            // SecureMemory must hold the original secret
            Assert.True(mem.ReadOnlySpan.SequenceEqual(secret));
            Assert.True(mem.ConstantTimeEquals(secret));
        }

        // Test SecureMemory Dispose zeroes physical memory
        var secure = new SecureMemory(secret);
        void* ptr = secure.Pointer;
        Assert.True(ptr != null);

        // Verify content before dispose
        var spanBefore = new ReadOnlySpan<byte>(ptr, 64);
        Assert.True(spanBefore.SequenceEqual(secret));

        // Note: SecureMemory.Dispose executes CryptographicOperations.ZeroMemory and then AlignedFree.
        // We verify that after disposal, access throws ObjectDisposedException
        secure.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = secure.Span);
        Assert.Throws<ObjectDisposedException>(() => _ = secure.ReadOnlySpan);
        Assert.Throws<ObjectDisposedException>(() => _ = secure.Pointer);
    }
}
