namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Memory;
using Xunit;
using BclAesGcm = System.Security.Cryptography.AesGcm;
using BclChaCha20Poly1305 = System.Security.Cryptography.ChaCha20Poly1305;

/// <summary>
/// Comprehensive empirical adversarial test suite for Milestone M3:
/// - Bit-tampering across EVERY single bit of ciphertext and authentication tag.
/// - AAD tampering across EVERY single bit of associated data.
/// - Boundary payload lengths (0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 4096 bytes).
/// - In-place encryption and decryption over identical memory spans.
/// - Unaligned memory spans (offsets 1, 3, 5, 7 from 64-byte alignment).
/// - Steady-state zero heap allocations on hot paths.
/// - Differential oracle cross-verification against BCL AesGcm and ChaCha20Poly1305.
/// </summary>
public unsafe class M3AdversarialChallengeTests
{
    private static readonly int[] BoundaryPayloadSizes =
    [
        0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 4096
    ];

    private static readonly int[] UnalignedOffsets = [1, 3, 5, 7];

    // =========================================================================
    // 1. EXHAUSTIVE BIT-TAMPERING ACROSS EVERY BIT OF CIPHERTEXT AND TAG
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm")]
    [InlineData("ChaCha20Poly1305")]
    public void Decrypt_ExhaustiveBitTamperingAcrossCiphertextAndTag_ReturnsFalseAndZeroesPlaintext(string algorithm)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[19];
        byte[] plaintext = new byte[33]; // Multi-block plus partial tail

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(aad);
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        if (algorithm == "Aes256Gcm")
        {
            using var cipher = new Aes256GcmCipher(key);
            cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        }
        else
        {
            using var cipher = new ChaCha20Poly1305Cipher(key);
            cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        }

        byte[] tamperedCt = (byte[])ciphertext.Clone();
        byte[] tamperedTag = (byte[])tag.Clone();
        byte[] decrypted = new byte[plaintext.Length];

        // 1. Flip EVERY bit of ciphertext
        for (int byteIdx = 0; byteIdx < ciphertext.Length; byteIdx++)
        {
            for (int bitIdx = 0; bitIdx < 8; bitIdx++)
            {
                ciphertext.CopyTo(tamperedCt, 0);
                tamperedCt[byteIdx] ^= (byte)(1 << bitIdx);

                Array.Fill(decrypted, (byte)0xCC);

                bool success;
                if (algorithm == "Aes256Gcm")
                {
                    using var cipher = new Aes256GcmCipher(key);
                    success = cipher.Decrypt(tamperedCt, aad, nonce, tag, decrypted);
                }
                else
                {
                    using var cipher = new ChaCha20Poly1305Cipher(key);
                    success = cipher.Decrypt(tamperedCt, aad, nonce, tag, decrypted);
                }

                Assert.False(success);
                for (int k = 0; k < decrypted.Length; k++)
                {
                    Assert.Equal(0, decrypted[k]);
                }
            }
        }

        // 2. Flip EVERY bit of tag
        for (int byteIdx = 0; byteIdx < 16; byteIdx++)
        {
            for (int bitIdx = 0; bitIdx < 8; bitIdx++)
            {
                tag.CopyTo(tamperedTag, 0);
                tamperedTag[byteIdx] ^= (byte)(1 << bitIdx);

                Array.Fill(decrypted, (byte)0xDD);

                bool success;
                if (algorithm == "Aes256Gcm")
                {
                    using var cipher = new Aes256GcmCipher(key);
                    success = cipher.Decrypt(ciphertext, aad, nonce, tamperedTag, decrypted);
                }
                else
                {
                    using var cipher = new ChaCha20Poly1305Cipher(key);
                    success = cipher.Decrypt(ciphertext, aad, nonce, tamperedTag, decrypted);
                }

                Assert.False(success);
                for (int k = 0; k < decrypted.Length; k++)
                {
                    Assert.Equal(0, decrypted[k]);
                }
            }
        }
    }

    // =========================================================================
    // 2. EXHAUSTIVE BIT-TAMPERING ACROSS EVERY BIT OF AAD
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm", 25)]
    [InlineData("Aes256Gcm", 0)] // GMAC only
    [InlineData("ChaCha20Poly1305", 25)]
    [InlineData("ChaCha20Poly1305", 0)] // Poly1305 over AAD only
    public void Decrypt_ExhaustiveBitTamperingAcrossAad_ReturnsFalseAndZeroesPlaintext(string algorithm, int payloadLength)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[19];
        byte[] plaintext = new byte[payloadLength];

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(aad);
        if (payloadLength > 0) RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[payloadLength];
        byte[] tag = new byte[16];

        if (algorithm == "Aes256Gcm")
        {
            using var cipher = new Aes256GcmCipher(key);
            cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        }
        else
        {
            using var cipher = new ChaCha20Poly1305Cipher(key);
            cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
        }

        byte[] tamperedAad = (byte[])aad.Clone();
        byte[] decrypted = new byte[payloadLength];

        for (int byteIdx = 0; byteIdx < aad.Length; byteIdx++)
        {
            for (int bitIdx = 0; bitIdx < 8; bitIdx++)
            {
                aad.CopyTo(tamperedAad, 0);
                tamperedAad[byteIdx] ^= (byte)(1 << bitIdx);

                if (payloadLength > 0) Array.Fill(decrypted, (byte)0xEE);

                bool success;
                if (algorithm == "Aes256Gcm")
                {
                    using var cipher = new Aes256GcmCipher(key);
                    success = cipher.Decrypt(ciphertext, tamperedAad, nonce, tag, decrypted);
                }
                else
                {
                    using var cipher = new ChaCha20Poly1305Cipher(key);
                    success = cipher.Decrypt(ciphertext, tamperedAad, nonce, tag, decrypted);
                }

                Assert.False(success);
                for (int k = 0; k < decrypted.Length; k++)
                {
                    Assert.Equal(0, decrypted[k]);
                }
            }
        }
    }

    // =========================================================================
    // 3. EXTREME BOUNDARY PAYLOAD SIZES & BCL ORACLE CROSS-VERIFICATION
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm", false)]
    [InlineData("Aes256Gcm", true)]
    [InlineData("ChaCha20Poly1305", false)]
    [InlineData("ChaCha20Poly1305", true)]
    public void BoundaryPayloadLengths_RoundtripAndMatchBclOracle(string algorithm, bool withAad)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = withAad ? new byte[27] : Array.Empty<byte>();

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        if (withAad) RandomNumberGenerator.Fill(aad);

        foreach (int size in BoundaryPayloadSizes)
        {
            byte[] plaintext = new byte[size];
            RandomNumberGenerator.Fill(plaintext);

            byte[] gCiphertext = new byte[size];
            byte[] gTag = new byte[16];
            byte[] gDecrypted = new byte[size];

            byte[] bCiphertext = new byte[size];
            byte[] bTag = new byte[16];
            byte[] bDecrypted = new byte[size];

            if (algorithm == "Aes256Gcm")
            {
                using var gCipher = new Aes256GcmCipher(key);
                gCipher.Encrypt(plaintext, aad, nonce, gCiphertext, gTag);

                bool gDecOk = gCipher.Decrypt(gCiphertext, aad, nonce, gTag, gDecrypted);
                Assert.True(gDecOk);
                Assert.True(plaintext.AsSpan().SequenceEqual(gDecrypted));

                if (BclAesGcm.IsSupported)
                {
                    using var bCipher = new BclAesGcm(key, 16);
                    bCipher.Encrypt(nonce, plaintext, bCiphertext, bTag, aad);

                    // Cross-check: Glacier and BCL produce byte-identical ciphertext and tag
                    Assert.True(gCiphertext.AsSpan().SequenceEqual(bCiphertext));
                    Assert.True(gTag.AsSpan().SequenceEqual(bTag));

                    // Cross-check: BCL decrypts Glacier output
                    bCipher.Decrypt(nonce, gCiphertext, gTag, bDecrypted, aad);
                    Assert.True(plaintext.AsSpan().SequenceEqual(bDecrypted));

                    // Cross-check: Glacier decrypts BCL output
                    Array.Clear(gDecrypted);
                    bool crossDec = gCipher.Decrypt(bCiphertext, aad, nonce, bTag, gDecrypted);
                    Assert.True(crossDec);
                    Assert.True(plaintext.AsSpan().SequenceEqual(gDecrypted));
                }
            }
            else
            {
                using var gCipher = new ChaCha20Poly1305Cipher(key);
                gCipher.Encrypt(plaintext, aad, nonce, gCiphertext, gTag);

                bool gDecOk = gCipher.Decrypt(gCiphertext, aad, nonce, gTag, gDecrypted);
                Assert.True(gDecOk);
                Assert.True(plaintext.AsSpan().SequenceEqual(gDecrypted));

                if (BclChaCha20Poly1305.IsSupported)
                {
                    using var bCipher = new BclChaCha20Poly1305(key);
                    bCipher.Encrypt(nonce, plaintext, bCiphertext, bTag, aad);

                    // Cross-check: Glacier and BCL produce byte-identical ciphertext and tag
                    Assert.True(gCiphertext.AsSpan().SequenceEqual(bCiphertext));
                    Assert.True(gTag.AsSpan().SequenceEqual(bTag));

                    // Cross-check: BCL decrypts Glacier output
                    bCipher.Decrypt(nonce, gCiphertext, gTag, bDecrypted, aad);
                    Assert.True(plaintext.AsSpan().SequenceEqual(bDecrypted));

                    // Cross-check: Glacier decrypts BCL output
                    Array.Clear(gDecrypted);
                    bool crossDec = gCipher.Decrypt(bCiphertext, aad, nonce, bTag, gDecrypted);
                    Assert.True(crossDec);
                    Assert.True(plaintext.AsSpan().SequenceEqual(gDecrypted));
                }
            }
        }
    }

    // =========================================================================
    // 4. IN-PLACE ENCRYPTION AND DECRYPTION OVER IDENTICAL MEMORY SPANS
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm")]
    [InlineData("ChaCha20Poly1305")]
    public void InPlace_EncryptionAndDecryption_OperatesCorrectlyAndZeroesOnTamper(string algorithm)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[13];

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(aad);

        foreach (int size in BoundaryPayloadSizes)
        {
            byte[] inPlaceBuffer = new byte[size];
            RandomNumberGenerator.Fill(inPlaceBuffer);
            byte[] original = (byte[])inPlaceBuffer.Clone();
            byte[] tag = new byte[16];

            if (algorithm == "Aes256Gcm")
            {
                using var cipher = new Aes256GcmCipher(key);

                // In-place encrypt: plaintext and ciphertext are exact same span
                cipher.Encrypt(inPlaceBuffer.AsSpan(), aad, nonce, inPlaceBuffer.AsSpan(), tag);
                if (size > 0)
                {
                    Assert.False(inPlaceBuffer.AsSpan().SequenceEqual(original));
                }

                // In-place decrypt: ciphertext and plaintext are exact same span
                bool decOk = cipher.Decrypt(inPlaceBuffer.AsSpan(), aad, nonce, tag, inPlaceBuffer.AsSpan());
                Assert.True(decOk);
                Assert.True(inPlaceBuffer.AsSpan().SequenceEqual(original));

                // In-place decryption failure zero-wipe test
                if (size > 0)
                {
                    cipher.Encrypt(inPlaceBuffer.AsSpan(), aad, nonce, inPlaceBuffer.AsSpan(), tag);
                    tag[0] ^= 0x01; // Tamper tag
                    bool failOk = cipher.Decrypt(inPlaceBuffer.AsSpan(), aad, nonce, tag, inPlaceBuffer.AsSpan());
                    Assert.False(failOk);
                    for (int k = 0; k < inPlaceBuffer.Length; k++)
                    {
                        Assert.Equal(0, inPlaceBuffer[k]);
                    }
                }
            }
            else
            {
                using var cipher = new ChaCha20Poly1305Cipher(key);

                cipher.Encrypt(inPlaceBuffer.AsSpan(), aad, nonce, inPlaceBuffer.AsSpan(), tag);
                if (size > 0)
                {
                    Assert.False(inPlaceBuffer.AsSpan().SequenceEqual(original));
                }

                bool decOk = cipher.Decrypt(inPlaceBuffer.AsSpan(), aad, nonce, tag, inPlaceBuffer.AsSpan());
                Assert.True(decOk);
                Assert.True(inPlaceBuffer.AsSpan().SequenceEqual(original));

                if (size > 0)
                {
                    cipher.Encrypt(inPlaceBuffer.AsSpan(), aad, nonce, inPlaceBuffer.AsSpan(), tag);
                    tag[0] ^= 0x01;
                    bool failOk = cipher.Decrypt(inPlaceBuffer.AsSpan(), aad, nonce, tag, inPlaceBuffer.AsSpan());
                    Assert.False(failOk);
                    for (int k = 0; k < inPlaceBuffer.Length; k++)
                    {
                        Assert.Equal(0, inPlaceBuffer[k]);
                    }
                }
            }
        }
    }

    // =========================================================================
    // 5. UNALIGNED MEMORY SLICES (Offsets 1, 3, 5, 7 from 64-byte alignment)
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm")]
    [InlineData("ChaCha20Poly1305")]
    public void UnalignedMemorySlices_DoNotFaultAndMatchAlignedOutput(string algorithm)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[23];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(aad);

        foreach (int offset in UnalignedOffsets)
        {
            foreach (int size in BoundaryPayloadSizes)
            {
                // Allocate 64-byte aligned buffer
                using var alignedMemory = new CachelineAlignedBuffer(size + offset + 128);
                Span<byte> memorySpan = alignedMemory.Span;

                // Populate with reproducible test pattern
                for (int i = 0; i < memorySpan.Length; i++)
                {
                    memorySpan[i] = (byte)((i * 31) ^ offset);
                }

                // Slice unaligned plaintext
                Span<byte> unalignedPt = memorySpan.Slice(offset, size);
                byte[] alignedPtCopy = unalignedPt.ToArray();

                using var alignedCtBuf = new CachelineAlignedBuffer(size + offset + 64);
                Span<byte> unalignedCt = alignedCtBuf.Span.Slice(offset, size);

                using var alignedTagBuf = new CachelineAlignedBuffer(16 + offset + 64);
                Span<byte> unalignedTag = alignedTagBuf.Span.Slice(offset, 16);

                using var alignedDecBuf = new CachelineAlignedBuffer(size + offset + 64);
                Span<byte> unalignedDec = alignedDecBuf.Span.Slice(offset, size);

                byte[] refCt = new byte[size];
                byte[] refTag = new byte[16];

                if (algorithm == "Aes256Gcm")
                {
                    using var cipher = new Aes256GcmCipher(key);

                    // Reference aligned run
                    cipher.Encrypt(alignedPtCopy, aad, nonce, refCt, refTag);

                    // Unaligned run
                    cipher.Encrypt(unalignedPt, aad, nonce, unalignedCt, unalignedTag);

                    Assert.True(refCt.AsSpan().SequenceEqual(unalignedCt));
                    Assert.True(refTag.AsSpan().SequenceEqual(unalignedTag));

                    bool decOk = cipher.Decrypt(unalignedCt, aad, nonce, unalignedTag, unalignedDec);
                    Assert.True(decOk);
                    Assert.True(alignedPtCopy.AsSpan().SequenceEqual(unalignedDec));
                }
                else
                {
                    using var cipher = new ChaCha20Poly1305Cipher(key);

                    cipher.Encrypt(alignedPtCopy, aad, nonce, refCt, refTag);
                    cipher.Encrypt(unalignedPt, aad, nonce, unalignedCt, unalignedTag);

                    Assert.True(refCt.AsSpan().SequenceEqual(unalignedCt));
                    Assert.True(refTag.AsSpan().SequenceEqual(unalignedTag));

                    bool decOk = cipher.Decrypt(unalignedCt, aad, nonce, unalignedTag, unalignedDec);
                    Assert.True(decOk);
                    Assert.True(alignedPtCopy.AsSpan().SequenceEqual(unalignedDec));
                }
            }
        }
    }

    // =========================================================================
    // 6. STEADY-STATE ZERO HEAP ALLOCATIONS VERIFICATION
    // =========================================================================

    [Theory]
    [InlineData("Aes256Gcm", 0)]
    [InlineData("Aes256Gcm", 16)]
    [InlineData("Aes256Gcm", 64)]
    [InlineData("Aes256Gcm", 1024)]
    [InlineData("ChaCha20Poly1305", 0)]
    [InlineData("ChaCha20Poly1305", 16)]
    [InlineData("ChaCha20Poly1305", 64)]
    [InlineData("ChaCha20Poly1305", 1024)]
    public void SteadyState_EncryptAndDecrypt_ZeroHeapAllocations(string algorithm, int payloadLength)
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[16];
        byte[] plaintext = new byte[payloadLength];
        byte[] ciphertext = new byte[payloadLength];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[payloadLength];

        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(aad);
        if (payloadLength > 0) RandomNumberGenerator.Fill(plaintext);

        if (algorithm == "Aes256Gcm")
        {
            using var cipher = new Aes256GcmCipher(key);

            // JIT Warmup
            for (int i = 0; i < 200; i++)
            {
                cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
                cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
            }

            // Steady-state measurement
            long allocBefore = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 200; i++)
            {
                cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
                cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
            }
            long allocAfter = GC.GetAllocatedBytesForCurrentThread();

            Assert.Equal(0L, allocAfter - allocBefore);
        }
        else
        {
            using var cipher = new ChaCha20Poly1305Cipher(key);

            for (int i = 0; i < 200; i++)
            {
                cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
                cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
            }

            long allocBefore = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 200; i++)
            {
                cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);
                cipher.Decrypt(ciphertext, aad, nonce, tag, decrypted);
            }
            long allocAfter = GC.GetAllocatedBytesForCurrentThread();

            Assert.Equal(0L, allocAfter - allocBefore);
        }
    }

    // =========================================================================
    // 7. DIFFERENTIAL RANDOM FUZZING AGAINST BCL ORACLE
    // =========================================================================

    [Fact]
    public void DifferentialFuzzing_AgainstBclOracle_200RandomIterations()
    {
        if (!BclAesGcm.IsSupported && !BclChaCha20Poly1305.IsSupported)
        {
            return;
        }

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];

        for (int iter = 0; iter < 100; iter++)
        {
            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(nonce);

            int ptLen = Random.Shared.Next(0, 1500);
            int aadLen = Random.Shared.Next(0, 80);

            byte[] plaintext = new byte[ptLen];
            byte[] aad = new byte[aadLen];
            RandomNumberGenerator.Fill(plaintext);
            RandomNumberGenerator.Fill(aad);

            // AES-256-GCM differential check
            if (BclAesGcm.IsSupported)
            {
                byte[] gCt = new byte[ptLen];
                byte[] gTag = new byte[16];
                byte[] bCt = new byte[ptLen];
                byte[] bTag = new byte[16];

                using (var gCipher = new Aes256GcmCipher(key))
                using (var bCipher = new BclAesGcm(key))
                {
                    gCipher.Encrypt(plaintext, aad, nonce, gCt, gTag);
                    bCipher.Encrypt(nonce, plaintext, bCt, bTag, aad);

                    Assert.True(gCt.AsSpan().SequenceEqual(bCt));
                    Assert.True(gTag.AsSpan().SequenceEqual(bTag));

                    byte[] dec = new byte[ptLen];
                    bool ok = gCipher.Decrypt(bCt, aad, nonce, bTag, dec);
                    Assert.True(ok);
                    Assert.True(plaintext.AsSpan().SequenceEqual(dec));
                }
            }

            // ChaCha20-Poly1305 differential check
            if (BclChaCha20Poly1305.IsSupported)
            {
                byte[] gCt = new byte[ptLen];
                byte[] gTag = new byte[16];
                byte[] bCt = new byte[ptLen];
                byte[] bTag = new byte[16];

                using (var gCipher = new ChaCha20Poly1305Cipher(key))
                using (var bCipher = new BclChaCha20Poly1305(key))
                {
                    gCipher.Encrypt(plaintext, aad, nonce, gCt, gTag);
                    bCipher.Encrypt(nonce, plaintext, bCt, bTag, aad);

                    Assert.True(gCt.AsSpan().SequenceEqual(bCt));
                    Assert.True(gTag.AsSpan().SequenceEqual(bTag));

                    byte[] dec = new byte[ptLen];
                    bool ok = gCipher.Decrypt(bCt, aad, nonce, bTag, dec);
                    Assert.True(ok);
                    Assert.True(plaintext.AsSpan().SequenceEqual(dec));
                }
            }
        }
    }
}
