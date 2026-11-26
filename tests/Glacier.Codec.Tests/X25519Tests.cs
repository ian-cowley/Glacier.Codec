namespace Glacier.Codec.Tests;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.EllipticCurve;
using Xunit;

public sealed class X25519Tests
{
    [Fact]
    public void Rfc7748_Section52_Vector1_MatchesExactOutput()
    {
        byte[] scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] uCoord = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] expected = Convert.FromHexString("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        byte[] actual = new byte[32];
        X25519.ScalarMult(scalar, uCoord, actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Rfc7748_Section52_Vector2_HighBitSetAndNonCanonical_MatchesExactOutput()
    {
        byte[] scalar = Convert.FromHexString("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        byte[] uCoord = Convert.FromHexString("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        byte[] expected = Convert.FromHexString("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

        byte[] actual = new byte[32];
        X25519.ScalarMult(scalar, uCoord, actual);
        Assert.Equal(expected, actual);

        // RFC 7748 §5: MSB (bit 255) of u-coordinate must be masked off
        byte[] uCoordMsbZero = (byte[])uCoord.Clone();
        uCoordMsbZero[31] &= 0x7F;
        byte[] actualMsbZero = new byte[32];
        X25519.ScalarMult(scalar, uCoordMsbZero, actualMsbZero);
        Assert.Equal(expected, actualMsbZero);
    }

    [Fact]
    public void Rfc7748_Section52_Iterated1And1000Rounds_MatchExactVectors()
    {
        byte[] k = new byte[32];
        k[0] = 9;
        byte[] u = new byte[32];
        u[0] = 9;
        byte[] next = new byte[32];

        byte[] expected1 = Convert.FromHexString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        byte[] expected1000 = Convert.FromHexString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

        for (int i = 1; i <= 1000; i++)
        {
            X25519.ScalarMult(k, u, next);
            Buffer.BlockCopy(k, 0, u, 0, 32);
            Buffer.BlockCopy(next, 0, k, 0, 32);

            if (i == 1)
            {
                Assert.Equal(expected1, k);
            }
        }

        Assert.Equal(expected1000, k);
    }

    [Fact]
    public void Rfc7748_Section61_DiffieHellmanVector_MatchesExactSharedSecret()
    {
        byte[] aliceSk = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] aliceExpectedPk = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        byte[] bobSk = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bobExpectedPk = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        byte[] expectedShared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        byte[] alicePk = new byte[32];
        byte[] bobPk = new byte[32];
        X25519.ScalarMultBase(aliceSk, alicePk);
        X25519.ScalarMultBase(bobSk, bobPk);

        Assert.Equal(aliceExpectedPk, alicePk);
        Assert.Equal(bobExpectedPk, bobPk);

        byte[] sharedA = new byte[32];
        byte[] sharedB = new byte[32];
        Assert.True(X25519.TrySharedSecret(aliceSk, bobPk, sharedA));
        Assert.True(X25519.TrySharedSecret(bobSk, alicePk, sharedB));
        Assert.Equal(expectedShared, sharedA);
        Assert.Equal(expectedShared, sharedB);
    }

    [Fact]
    public void NonCanonicalFieldReduction_And_LowOrderPoints_HandledCorrectly()
    {
        // p = 2^255 - 19 -> ed ff ff ... 7f
        byte[] nonCanonicalZero = new byte[32];
        Array.Fill(nonCanonicalZero, (byte)0xFF);
        nonCanonicalZero[0] = 0xED;
        nonCanonicalZero[31] = 0x7F;

        byte[] sk = new byte[32];
        RandomNumberGenerator.Fill(sk);

        byte[] res = new byte[32];
        Assert.False(X25519.TrySharedSecret(sk, nonCanonicalZero, res));
        Assert.All(res, b => Assert.Equal((byte)0, b));

        // Canonical 0 and order-2 point (p - 1, or 1) also yield all-zero shared secret
        byte[] one = new byte[32];
        one[0] = 1;
        Assert.False(X25519.TrySharedSecret(sk, one, res));
        Assert.All(res, b => Assert.Equal((byte)0, b));
    }
}
