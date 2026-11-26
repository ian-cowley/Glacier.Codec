namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using System.Text;
using Glacier.Codec.Cryptography.AesGcmSiv;
using Xunit;

public sealed class Aes256GcmSivTests
{
    [Fact]
    public void Polyval_Rfc8452AppendixA_MatchesExactDigest()
    {
        byte[] h = Convert.FromHexString("25629347589242761d31f826ba4b757b");
        byte[] blocks = Convert.FromHexString("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362");
        byte[] expected = Convert.FromHexString("f7a3b47b846119fae5b7866cf5e5b77e");

        Span<byte> actual = stackalloc byte[16];
        PolyvalKernel.ComputePolyval(h, blocks, ReadOnlySpan<byte>.Empty, actual, includeLengthBlock: false);

        Assert.Equal(expected, actual.ToArray());
    }

    [Fact]
    public void Aes256GcmSiv_Rfc8452AppendixC2_ZeroLengthVector_MatchesExactTag()
    {
        byte[] key = new byte[32];
        key[0] = 0x01;
        byte[] nonce = new byte[12];
        nonce[0] = 0x03;
        byte[] expectedTag = Convert.FromHexString("07f5f4169bbf55a8400cd47ea6fd400f");

        byte[] tag = new byte[16];
        Aes256GcmSiv.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag);
        Assert.Equal(expectedTag, tag);

        Assert.True(Aes256GcmSiv.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty));
    }

    [Fact]
    public void Aes256GcmSiv_Rfc8452AppendixC2_8ByteAnd16ByteVectors_MatchExactOutputs()
    {
        byte[] key = new byte[32];
        key[0] = 0x01;
        byte[] nonce = new byte[12];
        nonce[0] = 0x03;

        // 8-byte plaintext: 0100000000000000
        byte[] pt8 = Convert.FromHexString("0100000000000000");
        byte[] expected8 = Convert.FromHexString("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28");
        byte[] ct8 = new byte[8];
        byte[] tag8 = new byte[16];
        Aes256GcmSiv.Encrypt(key, nonce, pt8, ct8, tag8);
        Assert.Equal(expected8[..8], ct8);
        Assert.Equal(expected8[8..], tag8);

        // 16-byte plaintext: 01000000000000000000000000000000
        byte[] pt16 = Convert.FromHexString("01000000000000000000000000000000");
        byte[] expected16 = Convert.FromHexString("85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366");
        byte[] ct16 = new byte[16];
        byte[] tag16 = new byte[16];
        Aes256GcmSiv.Encrypt(key, nonce, pt16, ct16, tag16);
        Assert.Equal(expected16[..16], ct16);
        Assert.Equal(expected16[16..], tag16);
    }

    [Theory]
    [InlineData(20, 12, "181ee526aa52db3799d607e77f995e73e66f3a026eb2c83095e1dbd6fca8207f59e1faf2")]
    [InlineData(37, 19, "3fba2ae7d5cd9f96eb71f301e078ca0a592878c610e38c875d1661890a2cf0a7159df93cb0e147a0bb9e5cd01449a70e2b0d9f4185")]
    [InlineData(64, 0, "c1bb98dca36933840ed99c85b3ea05555ae644fce8b443b0ae265aa83b47d8f159d390bf0bc4204625e1c04f7d8c72f4d5d2fc87e8360c10c28d2695a407948ef64e763c3c6fa637fdaf60ec5d2b030e")]
    public void Aes256GcmSiv_MultiBlockAndPartialAadVectors_MatchReference(int ptLen, int aadLen, string expectedHex)
    {
        byte[] key = new byte[32];
        key[0] = 0x01;
        byte[] nonce = new byte[12];
        nonce[0] = 0x03;

        byte[] pt = new byte[ptLen];
        for (int i = 0; i < ptLen; i++) pt[i] = (byte)i;
        byte[] aad = new byte[aadLen];
        for (int i = 0; i < aadLen; i++) aad[i] = (byte)(0x10 + i);

        byte[] expected = Convert.FromHexString(expectedHex);
        byte[] ct = new byte[ptLen];
        byte[] tag = new byte[16];
        Aes256GcmSiv.Encrypt(key, nonce, pt, ct, tag, aad);

        Assert.Equal(expected[..ptLen], ct);
        Assert.Equal(expected[ptLen..], tag);

        byte[] decrypted = new byte[ptLen];
        Assert.True(Aes256GcmSiv.Decrypt(key, nonce, ct, tag, decrypted, aad));
        Assert.Equal(pt, decrypted);
    }

    [Fact]
    public void NonceMisuseResistance_RepeatedNonceBehavior_Holds()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] pt1 = Encoding.UTF8.GetBytes("Glacier archival chunk payload A - deterministic SIV check");
        byte[] pt2 = (byte[])pt1.Clone();
        pt2[0] ^= 0x01; // 1-bit flip

        byte[] ct1a = new byte[pt1.Length];
        byte[] tag1a = new byte[16];
        byte[] ct1b = new byte[pt1.Length];
        byte[] tag1b = new byte[16];
        byte[] ct2 = new byte[pt2.Length];
        byte[] tag2 = new byte[16];

        using var cipher = new Aes256GcmSivCipher(key);
        cipher.Encrypt(pt1, default, nonce, ct1a, tag1a);
        cipher.Encrypt(pt1, default, nonce, ct1b, tag1b);
        cipher.Encrypt(pt2, default, nonce, ct2, tag2);

        // Identical inputs yield deterministic identical outputs
        Assert.Equal(ct1a, ct1b);
        Assert.Equal(tag1a, tag1b);

        // Distinct plaintexts under the same (key, nonce) yield completely distinct keystream & tag
        Assert.NotEqual(tag1a, tag2);
        Assert.NotEqual(ct1a, ct2);
    }

    [Fact]
    public void InPlace_And_TamperZeroization_WorkProperly()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] original = Encoding.UTF8.GetBytes("In-place AES-256-GCM-SIV multi-block payload exceeding 64 bytes for AES-NI 4-way pipeline!");
        byte[] buffer = (byte[])original.Clone();
        byte[] tag = new byte[16];

        Aes256GcmSiv.Encrypt(key, nonce, buffer, buffer, tag);
        Assert.NotEqual(original, buffer);

        byte[] badTag = (byte[])tag.Clone();
        badTag[0] ^= 0x01;
        byte[] outBuf = (byte[])buffer.Clone();
        Assert.False(Aes256GcmSiv.Decrypt(key, nonce, outBuf, badTag, outBuf));
        Assert.All(outBuf, b => Assert.Equal((byte)0, b));

        Assert.True(Aes256GcmSiv.Decrypt(key, nonce, buffer, tag, buffer));
        Assert.Equal(original, buffer);
    }

    [Fact]
    public void InvalidArgumentsAndDisposed_ThrowExpectedExceptions()
    {
        Assert.Throws<ArgumentException>(() => new Aes256GcmSivCipher(new byte[16]));
        var cipher = new Aes256GcmSivCipher(new byte[32]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[8], new byte[16], new byte[16]));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[12], new byte[16], new byte[15]));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[16], default, new byte[12], new byte[15], new byte[16]));

        cipher.Dispose();
        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt(new byte[16], default, new byte[12], new byte[16], new byte[16]));
        Assert.Throws<ObjectDisposedException>(() => cipher.Decrypt(new byte[16], default, new byte[12], new byte[16], new byte[16]));
    }
}
