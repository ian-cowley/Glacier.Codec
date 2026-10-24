namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Hardware;
using Xunit;

/// <summary>
/// Empirical Challenger 1 Torture Test Suite for Milestone M6 Iteration 2 Gate Review.
/// Rigorously verifies Aes256GcmCipher and AesGcmParallelEngine across:
/// 1. 13 boundary & edge case payload sizes (0B, 1B, 15B, 16B, 17B, 255B, 256B, 1KB, 64KB, 255KB, 256KB, 1MB, 4MB).
/// 2. Golden oracle bit-exact parity against .NET BCL System.Security.Cryptography.AesGcm.
/// 3. Parity between Parallel Engine, single-block PCLMULQDQ hardware kernel, and scalar software fallback.
/// 4. Tag and ciphertext tampering rejection across all payload sizes.
/// 5. Fail-secure zeroization: destination buffer is zeroized via CryptographicOperations.ZeroMemory upon tag mismatch.
/// 6. Constant-time tag equality check via CryptographicOperations.FixedTimeEquals.
/// </summary>
public class Challenger1M6AesGcmTortureTests
{
    private static readonly int[] EdgeCaseSizes =
    [
        0,                 // 0 B (empty)
        1,                 // 1 B (sub-block)
        15,                // 15 B (just under 1 block)
        16,                // 16 B (exact 1 block)
        17,                // 17 B (1 block + 1 byte)
        255,               // 255 B (just under 16 blocks)
        256,               // 256 B (exact 16 blocks / VAES-512 stripe)
        1024,              // 1 KB
        64 * 1024,         // 64 KB
        255 * 1024,        // 255 KB (below parallel engine threshold)
        256 * 1024,        // 256 KB (exact parallel engine threshold)
        1024 * 1024,       // 1 MB (multi-worker parallel engine)
        4 * 1024 * 1024    // 4 MB (stress multi-worker parallel engine)
    ];

    public static TheoryData<int> GetEdgeCaseSizes()
    {
        var data = new TheoryData<int>();
        foreach (int size in EdgeCaseSizes)
        {
            data.Add(size);
        }
        return data;
    }

    // =========================================================================
    // SECTION 1: ROUNDTRIP & GOLDEN ORACLE PARITY ACROSS ALL EDGE CASE SIZES
    // =========================================================================

    [Theory]
    [MemberData(nameof(GetEdgeCaseSizes))]
    public void Boundary_Aes256Gcm_BitExactRoundtrip_And_BclOracleParity(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] aad = "Glacier.Codec.M6.Challenger1.AAD"u8.ToArray();
        byte[] plaintext = new byte[payloadSize];
        // Populate with deterministic non-zero PRNG sequence
        uint lcg = 0x9E3779B9u + (uint)payloadSize;
        for (int i = 0; i < payloadSize; i++)
        {
            lcg = lcg * 1664525u + 1013904223u;
            plaintext[i] = (byte)(lcg >> 24);
        }

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        // 1. Encrypt via Glacier Aes256GcmCipher
        using (var cipher = new Aes256GcmCipher(key))
        {
            cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        }

        // 2. Encrypt identical input via .NET BCL System.Security.Cryptography.AesGcm
        byte[] bclCiphertext = new byte[payloadSize];
        byte[] bclTag = new byte[16];
        using (var bclAesGcm = new System.Security.Cryptography.AesGcm(key, 16))
        {
            bclAesGcm.Encrypt(nonce, plaintext, bclCiphertext, bclTag, aad);
        }

        // 3. Verify 100% bit-exact parity between Glacier and BCL oracle
        Assert.True(ciphertext.AsSpan().SequenceEqual(bclCiphertext),
            $"Ciphertext mismatch against BCL oracle for payload size {payloadSize} B");
        Assert.True(tag.AsSpan().SequenceEqual(bclTag),
            $"Tag mismatch against BCL oracle for payload size {payloadSize} B");

        // 4. Decrypt via Glacier Aes256GcmCipher
        byte[] decrypted = new byte[payloadSize];
        bool decryptSuccess;
        using (var cipher = new Aes256GcmCipher(key))
        {
            decryptSuccess = cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
        }

        Assert.True(decryptSuccess, $"Decryption failed for payload size {payloadSize} B");
        Assert.True(decrypted.AsSpan().SequenceEqual(plaintext),
            $"Decrypted plaintext mismatch for payload size {payloadSize} B");

        // 5. Cross-decrypt: Glacier decrypts BCL ciphertext; BCL decrypts Glacier ciphertext
        byte[] crossDecrypted = new byte[payloadSize];
        using (var cipher = new Aes256GcmCipher(key))
        {
            bool crossOk = cipher.Decrypt(bclCiphertext, aad, nonce, bclTag, crossDecrypted);
            Assert.True(crossOk, "Glacier cipher failed to decrypt BCL-produced ciphertext");
            Assert.True(crossDecrypted.AsSpan().SequenceEqual(plaintext));
        }

        byte[] bclCrossDecrypted = new byte[payloadSize];
        using (var bclAesGcm = new System.Security.Cryptography.AesGcm(key, 16))
        {
            bclAesGcm.Decrypt(nonce, ciphertext, tag, bclCrossDecrypted, aad);
            Assert.True(bclCrossDecrypted.AsSpan().SequenceEqual(plaintext));
        }
    }

    [Theory]
    [MemberData(nameof(GetEdgeCaseSizes))]
    public void Boundary_Aes256Gcm_EmptyAad_BitExactRoundtrip(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[payloadSize];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, ReadOnlySpan<byte>.Empty, nonce, ciphertext, tag);

        byte[] bclCiphertext = new byte[payloadSize];
        byte[] bclTag = new byte[16];
        using (var bcl = new System.Security.Cryptography.AesGcm(key, 16))
        {
            bcl.Encrypt(nonce, plaintext, bclCiphertext, bclTag, ReadOnlySpan<byte>.Empty);
        }

        Assert.True(ciphertext.AsSpan().SequenceEqual(bclCiphertext), $"Empty AAD CT mismatch at {payloadSize} B");
        Assert.True(tag.AsSpan().SequenceEqual(bclTag), $"Empty AAD Tag mismatch at {payloadSize} B");

        byte[] decrypted = new byte[payloadSize];
        bool ok = cipher.Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, nonce, tag, decrypted);
        Assert.True(ok);
        Assert.True(decrypted.AsSpan().SequenceEqual(plaintext));
    }

    // =========================================================================
    // SECTION 2: PARITY BETWEEN PARALLEL ENGINE, PCLMULQDQ, AND SCALAR FALLBACK
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(64 * 1024)]
    [InlineData(255 * 1024)]
    [InlineData(256 * 1024)]
    [InlineData(512 * 1024)]
    public void EngineParity_SequentialKernel_Vs_ScalarFallback(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < 32; i++) key[i] = (byte)(i * 3 + 1);
        for (int i = 0; i < 12; i++) nonce[i] = (byte)(i * 7 + 2);

        byte[] aad = "ParityVerificationAAD"u8.ToArray();
        byte[] pt = new byte[payloadSize];
        for (int i = 0; i < payloadSize; i++) pt[i] = (byte)(i ^ 0x5C);

        byte[] expKeys = new byte[240];
        byte[] hTable = new byte[128];
        AesGcmKernel.ExpandKey(key, expKeys);
        AesGcmKernel.PrecomputeHTable(expKeys, hTable);

        // 1. Sequential hardware kernel (PCLMUL / VPCLMULQDQ)
        byte[] ctHw = new byte[payloadSize];
        byte[] tagHw = new byte[16];
        AesGcmKernel.Encrypt(expKeys, hTable, nonce, pt, ctHw, tagHw, aad);

        // 2. Pure scalar software fallback
        byte[] ctScalar = new byte[payloadSize];
        byte[] tagScalar = new byte[16];
        ScalarAesGcmEncrypt(key, nonce, pt, ctScalar, tagScalar, aad);

        // Verify bit-exact equality between HW kernel and scalar fallback
        Assert.True(ctHw.AsSpan().SequenceEqual(ctScalar),
            $"Ciphertext mismatch between HW and Scalar at {payloadSize} B");
        Assert.True(tagHw.AsSpan().SequenceEqual(tagScalar),
            $"Tag mismatch between HW and Scalar at {payloadSize} B");
    }

    [Theory]
    [InlineData(256 * 1024)]        // 256 KB
    [InlineData(512 * 1024)]        // 512 KB
    [InlineData(1024 * 1024)]       // 1 MB
    [InlineData(2 * 1024 * 1024)]   // 2 MB
    public void EngineParity_ParallelEngine_Vs_SequentialKernel_Vs_Bcl(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] aad = "LargeEngineParityAAD"u8.ToArray();
        byte[] pt = new byte[payloadSize];
        RandomNumberGenerator.Fill(pt);

        byte[] expKeys = new byte[240];
        byte[] hTable = new byte[128];
        AesGcmKernel.ExpandKey(key, expKeys);
        AesGcmKernel.PrecomputeHTable(expKeys, hTable);

        // 1. Sequential single-threaded kernel
        byte[] ctSeq = new byte[payloadSize];
        byte[] tagSeq = new byte[16];
        AesGcmKernel.Encrypt(expKeys, hTable, nonce, pt, ctSeq, tagSeq, aad);

        // 2. Parallel multi-threaded engine
        byte[] ctPar = new byte[payloadSize];
        byte[] tagPar = new byte[16];
        AesGcmParallelEngine.EncryptParallel(expKeys, hTable, nonce, pt, ctPar, tagPar, aad);

        // 3. BCL Oracle
        byte[] ctBcl = new byte[payloadSize];
        byte[] tagBcl = new byte[16];
        using (var bcl = new System.Security.Cryptography.AesGcm(key, 16))
        {
            bcl.Encrypt(nonce, pt, ctBcl, tagBcl, aad);
        }

        // Verify parallel engine matches sequential kernel AND BCL oracle bit-for-bit
        Assert.True(ctPar.AsSpan().SequenceEqual(ctSeq), $"Parallel CT != Sequential CT at {payloadSize} B");
        Assert.True(tagPar.AsSpan().SequenceEqual(tagSeq), $"Parallel Tag != Sequential Tag at {payloadSize} B");
        Assert.True(ctPar.AsSpan().SequenceEqual(ctBcl), $"Parallel CT != BCL CT at {payloadSize} B");
        Assert.True(tagPar.AsSpan().SequenceEqual(tagBcl), $"Parallel Tag != BCL Tag at {payloadSize} B");

        // Verify parallel decryption
        byte[] decrypted = new byte[payloadSize];
        bool ok = AesGcmParallelEngine.DecryptParallel(expKeys, hTable, nonce, ctPar, tagPar, decrypted, aad);
        Assert.True(ok, $"Parallel decrypt failed at {payloadSize} B");
        Assert.True(decrypted.AsSpan().SequenceEqual(pt));
    }

    [Fact]
    public void Concurrency_AesGcmParallelEngine_MultiThreadedCalls_ExposesStateRace()
    {
        const int numThreads = 8;
        const int payloadSize = 256 * 1024; // 256 KB triggers parallel engine
        var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        using var cipher = new Aes256GcmCipher(key);

        System.Threading.Tasks.Parallel.For(0, numThreads, new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = numThreads }, t =>
        {
            try
            {
                byte[] pt = new byte[payloadSize];
                for (int i = 0; i < payloadSize; i++) pt[i] = (byte)(t * 13 + i);
                byte[] nonce = new byte[12];
                byte[] ct = new byte[payloadSize];
                byte[] tag = new byte[16];
                byte[] dec = new byte[payloadSize];

                for (int iter = 0; iter < 10; iter++)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(0, 4), t);
                    BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(4, 4), iter);

                    cipher.Encrypt(pt, default, nonce, ct, tag);

                    bool ok = cipher.Decrypt(ct, default, nonce, tag, dec);
                    if (!ok)
                    {
                        throw new InvalidOperationException($"Decryption returned false on thread {t} at iter {iter} (tag mismatch due to race condition)");
                    }
                    if (!pt.AsSpan().SequenceEqual(dec))
                    {
                        throw new InvalidOperationException($"Plaintext mismatch on thread {t} at iter {iter}");
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // This assertion documents the empirical finding
        Assert.Empty(exceptions);
    }

    [Fact]
    public void GhashMultiplication_BitExact_Across_Pclmul_Pclmul512_And_Scalar()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] expKeys = new byte[240];
        byte[] hTable = new byte[128];
        AesGcmKernel.ExpandKey(key, expKeys);
        AesGcmKernel.PrecomputeHTable(expKeys, hTable);

        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.AsSpan(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.AsSpan(8, 8));
        var h1 = System.Runtime.Intrinsics.Vector128.Create(hLo, hHi);
        var h2 = AesGcmKernel.LoadPower(hTable.AsSpan(16, 16));
        var h3 = AesGcmKernel.LoadPower(hTable.AsSpan(32, 16));
        var h4 = AesGcmKernel.LoadPower(hTable.AsSpan(48, 16));

        var h5 = AesGcmKernel.LoadPower(hTable.AsSpan(64, 16));
        var h6 = AesGcmKernel.LoadPower(hTable.AsSpan(80, 16));
        var h7 = AesGcmKernel.LoadPower(hTable.AsSpan(96, 16));
        var h8 = AesGcmKernel.LoadPower(hTable.AsSpan(112, 16));

        // Test over 500 blocks of random test data
        byte[] testData = new byte[500 * 16];
        RandomNumberGenerator.Fill(testData);

        // 1. Scalar GHASH
        ulong yScalarHi = 0, yScalarLo = 0;
        for (int i = 0; i < 500; i++)
        {
            AesGcmKernelScalar.GhashBlock(ref yScalarHi, ref yScalarLo, testData.AsSpan(i * 16, 16), hHi, hLo);
        }

        // 2. Single-block PCLMULQDQ GHASH (if supported)
        if (System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported)
        {
            ulong yPclmulHi = 0, yPclmulLo = 0;
            AesGcmKernelPclmul.ProcessBlocks(ref yPclmulHi, ref yPclmulLo, testData, h1, h2, h3, h4);
            Assert.Equal(yScalarHi, yPclmulHi);
            Assert.Equal(yScalarLo, yPclmulLo);
        }

        // 3. VPCLMULQDQ 512 GHASH (if supported)
        if (AesGcmKernelPclmul512.IsSupported)
        {
            var h8to5 = System.Runtime.Intrinsics.Vector512.Create(
                System.Runtime.Intrinsics.Vector256.Create(h8, h7),
                System.Runtime.Intrinsics.Vector256.Create(h6, h5));
            var h4to1 = System.Runtime.Intrinsics.Vector512.Create(
                System.Runtime.Intrinsics.Vector256.Create(h4, h3),
                System.Runtime.Intrinsics.Vector256.Create(h2, h1));

            ulong yPclmul512Hi = 0, yPclmul512Lo = 0;
            AesGcmKernelPclmul512.ProcessBlocks(ref yPclmul512Hi, ref yPclmul512Lo, testData, h8to5, h4to1, h1, h2, h3, h4);
            Assert.Equal(yScalarHi, yPclmul512Hi);
            Assert.Equal(yScalarLo, yPclmul512Lo);
        }
    }

    // =========================================================================
    // SECTION 3: TAG TAMPERING REJECTION ACROSS ALL PAYLOAD SIZES
    // =========================================================================

    [Theory]
    [MemberData(nameof(GetEdgeCaseSizes))]
    public void TamperRejection_CorruptedTag_RejectsAcrossAllSizes(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[payloadSize];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        // Test bit-flip at byte 0
        byte[] tamperedTag0 = (byte[])tag.Clone();
        tamperedTag0[0] ^= 0x01;
        byte[] dest = new byte[payloadSize];
        bool ok0 = cipher.Decrypt(ciphertext, default, nonce, tamperedTag0, dest);
        Assert.False(ok0, $"Cipher accepted tag with bit-flip at byte 0 for size {payloadSize} B");

        // Test bit-flip at byte 15
        byte[] tamperedTag15 = (byte[])tag.Clone();
        tamperedTag15[15] ^= 0x80;
        bool ok15 = cipher.Decrypt(ciphertext, default, nonce, tamperedTag15, dest);
        Assert.False(ok15, $"Cipher accepted tag with bit-flip at byte 15 for size {payloadSize} B");

        // Test bit-flip at byte 7 (middle)
        byte[] tamperedTag7 = (byte[])tag.Clone();
        tamperedTag7[7] ^= 0x40;
        bool ok7 = cipher.Decrypt(ciphertext, default, nonce, tamperedTag7, dest);
        Assert.False(ok7, $"Cipher accepted tag with bit-flip at byte 7 for size {payloadSize} B");
    }

    // =========================================================================
    // SECTION 4: FAIL-SECURE ZEROIZATION UPON TAG OR CIPHERTEXT MISMATCH
    // =========================================================================

    [Theory]
    [MemberData(nameof(GetEdgeCaseSizes))]
    public void FailSecure_TagMismatch_ZeroizesDestinationBuffer(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[payloadSize];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        // Corrupt tag
        byte[] tamperedTag = (byte[])tag.Clone();
        tamperedTag[0] ^= 0xFF;

        // Dirty destination buffer with non-zero sentinel pattern 0xAA
        byte[] dest = new byte[payloadSize];
        Array.Fill<byte>(dest, 0xAA);

        bool success = cipher.Decrypt(ciphertext, default, nonce, tamperedTag, dest);

        Assert.False(success, "Decryption should fail with corrupted tag.");

        // Invariant: Destination buffer MUST be strictly zeroed out
        for (int i = 0; i < payloadSize; i++)
        {
            if (dest[i] != 0)
            {
                Assert.Fail($"Fail-secure violation: dest[{i}] = 0x{dest[i]:X2} (expected 0x00) for size {payloadSize} B");
            }
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(64 * 1024)]
    [InlineData(255 * 1024)]
    [InlineData(256 * 1024)]
    [InlineData(1024 * 1024)]
    public void FailSecure_CiphertextTamper_ZeroizesDestinationBuffer(int payloadSize)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[payloadSize];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadSize];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, default, nonce, ciphertext, tag);

        // Tamper 1 bit in ciphertext (at beginning, middle, and end)
        int[] tamperIndices = [0, payloadSize / 2, payloadSize - 1];

        foreach (int idx in tamperIndices)
        {
            byte[] tamperedCt = (byte[])ciphertext.Clone();
            tamperedCt[idx] ^= 0x20;

            byte[] dest = new byte[payloadSize];
            Array.Fill<byte>(dest, 0xBB);

            bool success = cipher.Decrypt(tamperedCt, default, nonce, tag, dest);
            Assert.False(success, $"Decryption should fail with tampered ciphertext at index {idx}");

            for (int i = 0; i < payloadSize; i++)
            {
                if (dest[i] != 0)
                {
                    Assert.Fail($"Fail-secure violation: dest[{i}] = 0x{dest[i]:X2} after CT tamper at {idx} for size {payloadSize} B");
                }
            }
        }
    }

    // =========================================================================
    // SECTION 5: CONSTANT-TIME VERIFICATION AND ROBUSTNESS
    // =========================================================================

    [Fact]
    public void ConstantTimeEqualityCheck_SourceCodeUsesFixedTimeEquals()
    {
        // Programmatic verification that Constant-Time equality is enforced in source
        string aesKernelSource = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "../../../../../src/Glacier.Codec/Cryptography/AesGcm/AesGcmKernel.cs"));
        Assert.Contains("CryptographicOperations.FixedTimeEquals", aesKernelSource);

        string aesParallelSource = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "../../../../../src/Glacier.Codec/Cryptography/AesGcm/AesGcmParallelEngine.cs"));
        Assert.Contains("CryptographicOperations.FixedTimeEquals", aesParallelSource);
    }

    [Fact]
    public void BufferBoundsValidation_ThrowsArgumentException_OnInvalidDimensions()
    {
        byte[] key = new byte[32];
        using var cipher = new Aes256GcmCipher(key);

        byte[] nonce12 = new byte[12];
        byte[] nonceInvalid = new byte[11];
        byte[] pt = new byte[32];
        byte[] ct = new byte[32];
        byte[] tag16 = new byte[16];
        byte[] tagInvalid = new byte[15];

        // Nonce length != 12
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(pt, default, nonceInvalid, ct, tag16));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(ct, default, nonceInvalid, tag16, pt));

        // Tag length < 16
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(pt, default, nonce12, ct, tagInvalid));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(ct, default, nonce12, tagInvalid, pt));

        // Undersized destination buffers
        byte[] ctTooSmall = new byte[31];
        byte[] ptTooSmall = new byte[31];
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(pt, default, nonce12, ctTooSmall, tag16));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(ct, default, nonce12, tag16, ptTooSmall));
    }

    // =========================================================================
    // HELPER: SCALAR REFERENCE ENCRYPTION IMPLEMENTATION
    // =========================================================================

    private static void ScalarAesGcmEncrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> expKeys = stackalloc byte[240];
        AesGcmKernelScalar.ExpandKey(key, expKeys);

        Span<byte> h = stackalloc byte[16];
        Span<byte> zero = stackalloc byte[16];
        AesGcmKernelScalar.EncryptBlock(expKeys, zero, h);
        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(h.Slice(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(h.Slice(8, 8));

        // J0
        Span<byte> j0 = stackalloc byte[16];
        nonce.CopyTo(j0.Slice(0, 12));
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

        // Tag mask = AES_K(J0)
        Span<byte> tagMask = stackalloc byte[16];
        AesGcmKernelScalar.EncryptBlock(expKeys, j0, tagMask);

        // Counter = inc32(J0)
        Span<byte> counter = stackalloc byte[16];
        j0.CopyTo(counter);
        BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), 2);

        // CTR encrypt
        int offset = 0;
        Span<byte> ks = stackalloc byte[16];
        while (offset < plaintext.Length)
        {
            AesGcmKernelScalar.EncryptBlock(expKeys, counter, ks);
            uint cVal = BinaryPrimitives.ReadUInt32BigEndian(counter.Slice(12, 4));
            BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), cVal + 1);

            int rem = Math.Min(16, plaintext.Length - offset);
            for (int k = 0; k < rem; k++)
            {
                ciphertext[offset + k] = (byte)(plaintext[offset + k] ^ ks[k]);
            }
            offset += rem;
        }

        // GHASH over AAD and Ciphertext
        ulong yHi = 0, yLo = 0;
        int aadOff = 0;
        while (aadOff + 16 <= associatedData.Length)
        {
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, associatedData.Slice(aadOff, 16), hHi, hLo);
            aadOff += 16;
        }
        if (aadOff < associatedData.Length)
        {
            Span<byte> pAad = stackalloc byte[16];
            associatedData.Slice(aadOff).CopyTo(pAad);
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, pAad, hHi, hLo);
        }

        int ctOff = 0;
        while (ctOff + 16 <= ciphertext.Length)
        {
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, ciphertext.Slice(ctOff, 16), hHi, hLo);
            ctOff += 16;
        }
        if (ctOff < ciphertext.Length)
        {
            Span<byte> pCt = stackalloc byte[16];
            ciphertext.Slice(ctOff).CopyTo(pCt);
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, pCt, hHi, hLo);
        }

        Span<byte> lenBlock = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(0, 8), (ulong)associatedData.Length * 8UL);
        BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)ciphertext.Length * 8UL);
        AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, lenBlock, hHi, hLo);

        ulong maskHi = BinaryPrimitives.ReadUInt64BigEndian(tagMask.Slice(0, 8));
        ulong maskLo = BinaryPrimitives.ReadUInt64BigEndian(tagMask.Slice(8, 8));
        BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(0, 8), yHi ^ maskHi);
        BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(8, 8), yLo ^ maskLo);
    }
}
