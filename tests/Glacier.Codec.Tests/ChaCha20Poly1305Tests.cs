namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Glacier.Codec.Cryptography;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Xunit;
using ChaCha20Poly1305 = Glacier.Codec.Cryptography.ChaCha20Poly1305.ChaCha20Poly1305;

public class ChaCha20Poly1305Tests
{
    // RFC 8439 §2.1.1 Quarter-Round on Four Numbers
    [Fact]
    public void Rfc8439_Section211_QuarterRoundOnFourNumbers()
    {
        uint a = 0x11111111;
        uint b = 0x01020304;
        uint c = 0x9b8d6f43;
        uint d = 0x01234567;

        ChaCha20KernelScalar.QuarterRound(ref a, ref b, ref c, ref d);

        Assert.Equal(0xea2a92f4u, a);
        Assert.Equal(0xcb1cf8ceu, b);
        Assert.Equal(0x4581472eu, c);
        Assert.Equal(0x5881c4bbu, d);
    }

    // RFC 8439 §2.3.2 ChaCha20 Block Function
    [Fact]
    public void Rfc8439_Section232_ChaCha20BlockFunction()
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000090000004a00000000");
        uint counter = 1;

        Span<byte> block = stackalloc byte[64];
        ChaCha20Cipher.GenerateBlock(key, counter, nonce, block);

        string expectedHex = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        Assert.Equal(expectedHex, Convert.ToHexString(block).ToLowerInvariant());
    }

    // RFC 8439 §2.4.2 ChaCha20 Cipher (Sunscreen text)
    [Fact]
    public void Rfc8439_Section242_ChaCha20Cipher_Sunscreen()
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000000000004a00000000");
        uint counter = 1;

        byte[] plaintext = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        ChaCha20Cipher.Crypt(key, nonce, counter, plaintext, ciphertext);

        string expectedCt = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
        Assert.Equal(expectedCt, Convert.ToHexString(ciphertext).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        ChaCha20Cipher.Crypt(key, nonce, counter, ciphertext, decrypted);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // RFC 8439 §2.5.2 Poly1305 MAC
    [Fact]
    public void Rfc8439_Section252_Poly1305Mac()
    {
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] message = Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, message, tag);

        Assert.Equal("a8061dc1305136c6c22b8baf0c0127a9", Convert.ToHexString(tag).ToLowerInvariant());
        Assert.True(Poly1305.VerifyMac(key, message, tag));
    }

    // RFC 8439 §2.8.2 AEAD End-to-End
    [Fact]
    public void Rfc8439_Section282_AeadEndToEnd()
    {
        byte[] key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Convert.FromHexString("070000004041424344454647");
        byte[] aad = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[16];

        ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);

        string expectedCt = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        string expectedTag = "1ae10b594f09e26a7e902ecbd0600691";

        Assert.Equal(expectedCt, Convert.ToHexString(ciphertext).ToLowerInvariant());
        Assert.Equal(expectedTag, Convert.ToHexString(tag).ToLowerInvariant());

        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, decrypted, aad);
        Assert.True(ok);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    // RFC 8439 Appendix A.3 Poly1305 Vector #5 (Partial reduction not fully reduced)
    [Fact]
    public void Rfc8439_AppendixA3_Vector5()
    {
        byte[] key = new byte[32];
        key[0] = 0x02; // r = 2
        byte[] data = new byte[16];
        Array.Fill(data, (byte)0xFF);

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, data, tag);

        byte[] expected = new byte[16];
        expected[0] = 0x03;
        Assert.True(tag.SequenceEqual(expected));
    }

    // RFC 8439 Appendix A.3 Poly1305 Vector #6 (s addition overflow)
    [Fact]
    public void Rfc8439_AppendixA3_Vector6()
    {
        byte[] key = new byte[32];
        key[0] = 0x02; // r = 2
        for (int i = 16; i < 32; i++) key[i] = 0xFF; // s = all ones

        byte[] data = new byte[16];
        data[0] = 0x02;

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, data, tag);

        byte[] expected = new byte[16];
        expected[0] = 0x03;
        Assert.True(tag.SequenceEqual(expected));
    }

    // RFC 8439 Appendix A.3 Poly1305 Vector #7 (Carry through all-ones)
    [Fact]
    public void Rfc8439_AppendixA3_Vector7()
    {
        byte[] key = new byte[32];
        key[0] = 0x01; // r = 1

        byte[] data = new byte[48];
        for (int i = 0; i < 16; i++) data[i] = 0xFF;
        data[16] = 0xF0;
        for (int i = 17; i < 32; i++) data[i] = 0xFF;
        data[32] = 0x11;

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, data, tag);

        byte[] expected = new byte[16];
        expected[0] = 0x05;
        Assert.True(tag.SequenceEqual(expected));
    }

    // RFC 8439 Appendix A.3 Poly1305 Vector #8 (Polynomial result exactly 2^130 - 5)
    [Fact]
    public void Rfc8439_AppendixA3_Vector8()
    {
        byte[] key = new byte[32];
        key[0] = 0x01; // r = 1

        byte[] data = new byte[48];
        for (int i = 0; i < 16; i++) data[i] = 0xFF;
        data[16] = 0xFB;
        for (int i = 17; i < 32; i++) data[i] = 0xFE;
        for (int i = 32; i < 48; i++) data[i] = 0x01;

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, data, tag);

        byte[] expected = new byte[16];
        Assert.True(tag.SequenceEqual(expected));
    }

    // RFC 8439 Appendix A.3 Poly1305 Vector #9 (Polynomial result exactly 2^130 - 6)
    [Fact]
    public void Rfc8439_AppendixA3_Vector9()
    {
        byte[] key = new byte[32];
        key[0] = 0x02; // r = 2

        byte[] data = new byte[16];
        data[0] = 0xFD;
        for (int i = 1; i < 16; i++) data[i] = 0xFF;

        Span<byte> tag = stackalloc byte[16];
        Poly1305.ComputeMac(key, data, tag);

        byte[] expected = new byte[16];
        expected[0] = 0xFA;
        for (int i = 1; i < 16; i++) expected[i] = 0xFF;
        Assert.True(tag.SequenceEqual(expected));
    }

    // Empty Plaintext AEAD
    [Fact]
    public void EmptyPlaintext_WithAad_ProducesValidTag()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = [1, 2, 3, 4, 5, 6, 7];

        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);

        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, aad);
        Assert.True(ok);
    }

    // Empty AAD AEAD
    [Fact]
    public void EmptyAad_PlaintextOnly_Roundtrip()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] pt = Encoding.UTF8.GetBytes("Testing ChaCha20Poly1305 with empty AAD string");

        Span<byte> ct = stackalloc byte[pt.Length];
        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag);

        Span<byte> dec = stackalloc byte[pt.Length];
        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ct, tag, dec);
        Assert.True(ok);
        Assert.True(dec.SequenceEqual(pt));
    }

    // In-Place Encryption and Decryption
    [Fact]
    public void InPlace_Roundtrip_Succeeds()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] buffer = new byte[200];
        RandomNumberGenerator.Fill(buffer);
        byte[] original = (byte[])buffer.Clone();

        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, buffer, buffer, tag);
        Assert.False(buffer.AsSpan().SequenceEqual(original));

        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, buffer, tag, buffer);
        Assert.True(ok);
        Assert.True(buffer.AsSpan().SequenceEqual(original));
    }

    // Fail-Secure Plaintext Wiping on Tampering
    [Fact]
    public void FailSecure_CiphertextTamper_ZeroesPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] pt = [10, 20, 30, 40, 50];

        byte[] ct = new byte[5];
        byte[] tag = new byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag);

        ct[2] ^= 0x01; // Tamper

        byte[] dec = new byte[5];
        Array.Fill(dec, (byte)0xCC);

        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ct, tag, dec);
        Assert.False(ok);
        for (int i = 0; i < dec.Length; i++)
        {
            Assert.Equal(0, dec[i]);
        }
    }

    [Fact]
    public void FailSecure_AadTamper_ZeroesPlaintext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = [1, 2, 3];
        byte[] pt = [9, 8, 7];

        byte[] ct = new byte[3];
        byte[] tag = new byte[16];
        ChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag, aad);

        byte[] tamperedAad = [1, 2, 4];
        byte[] dec = new byte[3];
        Array.Fill(dec, (byte)0xCC);

        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ct, tag, dec, tamperedAad);
        Assert.False(ok);
        for (int i = 0; i < dec.Length; i++)
        {
            Assert.Equal(0, dec[i]);
        }
    }

    // Large payload multi-block streaming
    [Theory]
    [InlineData(64)]
    [InlineData(512)]
    [InlineData(4096)]
    [InlineData(65536)]
    public void LargePayload_MultiBlockStreaming(int size)
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] pt = new byte[size];
        RandomNumberGenerator.Fill(pt);
        byte[] ct = new byte[size];
        byte[] tag = new byte[16];

        ChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag);

        byte[] dec = new byte[size];
        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ct, tag, dec);
        Assert.True(ok);
        Assert.Equal(pt, dec);
    }

    // Unaligned memory slices
    [Fact]
    public void UnalignedSpans_ExecutesCorrectly()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] ptBuf = new byte[256];
        RandomNumberGenerator.Fill(ptBuf);
        Span<byte> pt = ptBuf.AsSpan(3, 85);
        byte[] ptCopy = pt.ToArray();

        byte[] ctBuf = new byte[256];
        Span<byte> ct = ctBuf.AsSpan(7, 85);
        byte[] tagBuf = new byte[32];
        Span<byte> tag = tagBuf.AsSpan(1, 16);

        ChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag);

        byte[] decBuf = new byte[256];
        Span<byte> dec = decBuf.AsSpan(5, 85);

        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, ct, tag, dec);
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

        using var cipher = new ChaCha20Poly1305Cipher(key);

        // Warmup
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

        using var cipher = new ChaCha20Poly1305Cipher(key);

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
        var cipher = new ChaCha20Poly1305Cipher(new byte[32]);
        cipher.Dispose();

        byte[] nonce = new byte[12];
        byte[] buf = new byte[16];
        byte[] tag = new byte[16];

        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(buf, default, nonce, buf, tag));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(buf, default, nonce, tag, buf));
    }
}
