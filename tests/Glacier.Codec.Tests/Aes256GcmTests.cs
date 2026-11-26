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

    [Fact]
    public void ScalarBitslicedSBox_MatchesExactFips197TableForAll256Inputs()
    {
        byte[] fips197SBox =
        [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ];

        for (int i = 0; i < 256; i++)
        {
            Assert.Equal(fips197SBox[i], AesGcmKernelScalar.SubByteConstantTime((byte)i));
        }
    }
}
