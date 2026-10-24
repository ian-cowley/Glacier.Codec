namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography.AesGcm;
using Xunit;

public class Aes256GcmTests
{
    // NIST SP 800-38D Test Case 13 (Empty plaintext, empty AAD, all-zero key and nonce)
    [Fact]
    public void NistSp80038D_Case13_EmptyPlaintext_EmptyAad()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, ReadOnlySpan<byte>.Empty);

        Assert.Equal("530f8afbc74536b9a963b4f1c4cb738b", Convert.ToHexString(tag).ToLowerInvariant());

        bool ok = Aes256Gcm.Decrypt(key, iv, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, ReadOnlySpan<byte>.Empty);
        Assert.True(ok);
    }

    // NIST SP 800-38D Test Case 14 (16-byte block, empty AAD, all-zero key and nonce)
    [Fact]
    public void NistSp80038D_Case14_16ByteBlock()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] plaintext = new byte[16];

        Span<byte> ciphertext = stackalloc byte[16];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, plaintext, ciphertext, tag);

        Assert.Equal("cea7403d4d606b6e074ec5d3baf39d18", Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal("d0d1c8a799996bf0265b98b5d48ab919", Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[16];
        bool ok = Aes256Gcm.Decrypt(key, iv, ciphertext, tag, decrypted);
        Assert.True(ok);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // NIST SP 800-38D Test Case 15 (64-byte plaintext, empty AAD)
    [Fact]
    public void NistSp80038D_Case15_64BytePlaintext()
    {
        byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = Convert.FromHexString("cafebabefacedbaddecaf888");
        byte[] plaintext = Convert.FromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Span<byte> ciphertext = stackalloc byte[64];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, plaintext, ciphertext, tag);

        string expectedCt = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        string expectedTag = "b094dac5d93471bdec1a502270e3cc6c";

        Assert.Equal(expectedCt, Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[64];
        bool ok = Aes256Gcm.Decrypt(key, iv, ciphertext, tag, decrypted);
        Assert.True(ok);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // NIST SP 800-38D Test Case 16 (60-byte non-multiple-of-16 plaintext, 20-byte AAD)
    [Fact]
    public void NistSp80038D_Case16_NonMultipleOf16Plaintext_WithAad()
    {
        byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = Convert.FromHexString("cafebabefacedbaddecaf888");
        byte[] aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plaintext = Convert.FromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

        Span<byte> ciphertext = stackalloc byte[60];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, plaintext, ciphertext, tag, aad);

        string expectedCt = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        string expectedTag = "76fc6ece0f4e1768cddf8853bb2d551b";

        Assert.Equal(expectedCt, Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[60];
        bool ok = Aes256Gcm.Decrypt(key, iv, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // NIST SP 800-38D (64-byte plaintext with 20-byte AAD)
    [Fact]
    public void NistSp80038D_64BytePlaintext_With20ByteAad()
    {
        byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = Convert.FromHexString("cafebabefacedbaddecaf888");
        byte[] aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plaintext = Convert.FromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Span<byte> ciphertext = stackalloc byte[64];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, plaintext, ciphertext, tag, aad);

        string expectedCt = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        string expectedTag = "2df7cd675b4f09163b41ebf980a7f638";

        Assert.Equal(expectedCt, Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[64];
        bool ok = Aes256Gcm.Decrypt(key, iv, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // GMAC Authentication-Only Mode (0 plaintext, 20-byte AAD)
    [Fact]
    public void NistSp80038D_GmacMode_0Plaintext_20Aad()
    {
        byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = Convert.FromHexString("cafebabefacedbaddecaf888");
        byte[] aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        Span<byte> tag = stackalloc byte[16];
        Aes256Gcm.Encrypt(key, iv, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);

        Assert.Equal("9f6be07603c0b0bd1272854063e9c9ba", Convert.ToHexString(tag).ToLowerInvariant());

        bool ok = Aes256Gcm.Decrypt(key, iv, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, aad);
        Assert.True(ok);
    }

    // Single-byte payload boundary
    [Fact]
    public void Boundary_1BytePayload_1ByteAad()
    {
        byte[] key = Convert.FromHexString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        byte[] iv = Convert.FromHexString("a0a1a2a3a4a5a6a7a8a9aaab");
        byte[] plaintext = [0xff];
        byte[] aad = [0xee];

        Span<byte> ciphertext = stackalloc byte[1];
        Span<byte> tag = stackalloc byte[16];

        Aes256Gcm.Encrypt(key, iv, plaintext, ciphertext, tag, aad);

        Assert.Equal("46", Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal("0d8ea4c3d3854980273726f4d17701e2", Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[1];
        bool ok = Aes256Gcm.Decrypt(key, iv, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.Equal(0xff, decrypted[0]);
    }

    // Argument validations
    [Fact]
    public void ArgumentValidation_InvalidKeySize_Throws()
    {
        byte[] invalidKey = new byte[16];
        Assert.Throws<ArgumentException>(() => new Aes256GcmCipher(invalidKey));
    }

    [Fact]
    public void ArgumentValidation_InvalidNonceSize_Throws()
    {
        using var cipher = new Aes256GcmCipher(new byte[32]);
        byte[] invalidNonce = new byte[8];
        byte[] pt = new byte[10];
        byte[] ct = new byte[10];
        byte[] tag = new byte[16];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(pt, default, invalidNonce, ct, tag));
    }

    [Fact]
    public void ArgumentValidation_SmallTagBuffer_Throws()
    {
        using var cipher = new Aes256GcmCipher(new byte[32]);
        byte[] nonce = new byte[12];
        byte[] pt = new byte[10];
        byte[] ct = new byte[10];
        byte[] shortTag = new byte[8];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(pt, default, nonce, ct, shortTag));
    }

    // In-Place Encryption & Decryption
    [Fact]
    public void InPlace_EncryptionAndDecryption_Succeeds()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] buffer = new byte[128];
        RandomNumberGenerator.Fill(buffer);
        byte[] original = (byte[])buffer.Clone();

        Span<byte> tag = stackalloc byte[16];

        // In-place encrypt
        Aes256Gcm.Encrypt(key, nonce, buffer, buffer, tag);
        Assert.False(buffer.AsSpan().SequenceEqual(original));

        // In-place decrypt
        bool success = Aes256Gcm.Decrypt(key, nonce, buffer, tag, buffer);
        Assert.True(success);
        Assert.True(buffer.AsSpan().SequenceEqual(original));
    }

    // Fail-Secure Plaintext Wiping on Tampering
    [Fact]
    public void FailSecure_CiphertextTamper_ZeroesPlaintextBuffer()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = [1, 2, 3, 4, 5, 6, 7, 8];

        byte[] ct = new byte[8];
        byte[] tag = new byte[16];
        Aes256Gcm.Encrypt(key, nonce, plaintext, ct, tag);

        // Tamper with ciphertext
        ct[3] ^= 0x01;

        byte[] decrypted = new byte[8];
        Array.Fill(decrypted, (byte)0xEE);

        bool success = Aes256Gcm.Decrypt(key, nonce, ct, tag, decrypted);
        Assert.False(success);

        // Entire plaintext destination must be zeroed
        for (int i = 0; i < decrypted.Length; i++)
        {
            Assert.Equal(0, decrypted[i]);
        }
    }

    [Fact]
    public void FailSecure_TagTamper_ZeroesPlaintextBuffer()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = [10, 20, 30, 40];

        byte[] ct = new byte[4];
        byte[] tag = new byte[16];
        Aes256Gcm.Encrypt(key, nonce, plaintext, ct, tag);

        tag[0] ^= 0x80; // Tamper

        byte[] decrypted = new byte[4];
        Array.Fill(decrypted, (byte)0xFF);

        bool success = Aes256Gcm.Decrypt(key, nonce, ct, tag, decrypted);
        Assert.False(success);
        for (int i = 0; i < decrypted.Length; i++)
        {
            Assert.Equal(0, decrypted[i]);
        }
    }

    // Large payload multi-block streaming
    [Theory]
    [InlineData(64)]
    [InlineData(1024)]
    [InlineData(65536)]
    [InlineData(262144)]
    public void MultiBlockStream_Roundtrip(int size)
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = new byte[37]; // odd length AAD
        RandomNumberGenerator.Fill(aad);

        byte[] plaintext = new byte[size];
        RandomNumberGenerator.Fill(plaintext);

        byte[] ciphertext = new byte[size];
        byte[] tag = new byte[16];

        Aes256Gcm.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[size];
        bool ok = Aes256Gcm.Decrypt(key, nonce, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.Equal(plaintext, decrypted);
    }

    // Unaligned memory slices
    [Fact]
    public void UnalignedSpans_ExecutesCorrectly()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] bigBuffer = new byte[256];
        RandomNumberGenerator.Fill(bigBuffer);

        // Slice at odd offset 3
        Span<byte> pt = bigBuffer.AsSpan(3, 73);
        byte[] ptCopy = pt.ToArray();

        byte[] ctBuffer = new byte[256];
        Span<byte> ct = ctBuffer.AsSpan(5, 73); // offset 5

        byte[] tagBuffer = new byte[32];
        Span<byte> tag = tagBuffer.AsSpan(1, 16); // offset 1

        Aes256Gcm.Encrypt(key, nonce, pt, ct, tag);

        byte[] decBuffer = new byte[256];
        Span<byte> dec = decBuffer.AsSpan(7, 73); // offset 7

        bool ok = Aes256Gcm.Decrypt(key, nonce, ct, tag, dec);
        Assert.True(ok);
        Assert.True(dec.SequenceEqual(ptCopy));
    }

    // Zero-allocation steady-state assertion
    [Fact]
    public void ZeroAllocation_SteadyState_Asserted()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] pt = new byte[1024];
        byte[] ct = new byte[1024];
        byte[] tag = new byte[16];
        byte[] dec = new byte[1024];

        using var cipher = new Aes256GcmCipher(key);

        // Warmup JIT
        cipher.Encrypt(pt, default, nonce, ct, tag);
        cipher.Decrypt(ct, default, nonce, tag, dec);

        long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();

        cipher.Encrypt(pt, default, nonce, ct, tag);
        cipher.Decrypt(ct, default, nonce, tag, dec);

        long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

        Assert.Equal(0, afterAlloc - beforeAlloc);
    }

    // Concurrency and Multi-threading
    [Fact]
    public void ConcurrentOperations_ThreadSafe()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var cipher = new Aes256GcmCipher(key);

        Parallel.For(0, 50, i =>
        {
            byte[] nonce = new byte[12];
            BinaryPrimitives.WriteInt32LittleEndian(nonce, i);

            byte[] pt = new byte[256];
            RandomNumberGenerator.Fill(pt);

            byte[] ct = new byte[256];
            byte[] tag = new byte[16];

            cipher.Encrypt(pt, default, nonce, ct, tag);

            byte[] dec = new byte[256];
            bool ok = cipher.Decrypt(ct, default, nonce, tag, dec);
            Assert.True(ok);
            Assert.Equal(pt, dec);
        });
    }

    // Disposal
    [Fact]
    public void DisposedInstance_ThrowsObjectDisposedException()
    {
        var cipher = new Aes256GcmCipher(new byte[32]);
        cipher.Dispose();

        byte[] nonce = new byte[12];
        byte[] buf = new byte[16];
        byte[] tag = new byte[16];

        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(buf, default, nonce, buf, tag));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(buf, default, nonce, tag, buf));
    }
}
