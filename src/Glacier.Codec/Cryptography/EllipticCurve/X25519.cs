namespace Glacier.Codec.Cryptography.EllipticCurve;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// Clean-room, constant-time RFC 7748 X25519 Elliptic Curve Diffie-Hellman (Curve25519 Montgomery ladder).
/// </summary>
public static class X25519
{
    public const int KeySize = 32;

    private static ReadOnlySpan<byte> BasePoint =>
    [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    /// <summary>
    /// Computes the X25519 scalar multiplication <paramref name="scalar"/> * <paramref name="uCoordinate"/>
    /// per RFC 7748 Section 5 using a constant-time Montgomery ladder.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate, Span<byte> result)
    {
        if (scalar.Length != KeySize)
            throw new ArgumentException($"X25519 scalar must be {KeySize} bytes.", nameof(scalar));
        if (uCoordinate.Length != KeySize)
            throw new ArgumentException($"X25519 u-coordinate must be {KeySize} bytes.", nameof(uCoordinate));
        if (result.Length < KeySize)
            throw new ArgumentException($"Result buffer must be at least {KeySize} bytes.", nameof(result));

        Span<byte> k = stackalloc byte[KeySize];
        try
        {
            scalar.CopyTo(k);
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;

            FieldElement25519 x1 = FieldElement25519.FromBytes(uCoordinate);
            FieldElement25519 x2 = FieldElement25519.One;
            FieldElement25519 z2 = FieldElement25519.Zero;
            FieldElement25519 x3 = x1;
            FieldElement25519 z3 = FieldElement25519.One;
            ulong swap = 0;

            for (int t = 254; t >= 0; t--)
            {
                ulong kBit = (ulong)((k[t >> 3] >> (t & 7)) & 1);
                swap ^= kBit;
                FieldElement25519.CSwap(swap, ref x2, ref x3);
                FieldElement25519.CSwap(swap, ref z2, ref z3);
                swap = kBit;

                FieldElement25519 a = FieldElement25519.Add(in x2, in z2);
                FieldElement25519 aa = FieldElement25519.Square(in a);
                FieldElement25519 b = FieldElement25519.Sub(in x2, in z2);
                FieldElement25519 bb = FieldElement25519.Square(in b);
                FieldElement25519 e = FieldElement25519.Sub(in aa, in bb);
                FieldElement25519 c = FieldElement25519.Add(in x3, in z3);
                FieldElement25519 d = FieldElement25519.Sub(in x3, in z3);
                FieldElement25519 da = FieldElement25519.Mul(in d, in a);
                FieldElement25519 cb = FieldElement25519.Mul(in c, in b);

                FieldElement25519 daPlusCb = FieldElement25519.Add(in da, in cb);
                FieldElement25519 daMinusCb = FieldElement25519.Sub(in da, in cb);
                x3 = FieldElement25519.Square(in daPlusCb);
                z3 = FieldElement25519.Mul(in x1, FieldElement25519.Square(in daMinusCb));
                x2 = FieldElement25519.Mul(in aa, in bb);

                FieldElement25519 eA24 = FieldElement25519.Mul121665(in e);
                z2 = FieldElement25519.Mul(in e, FieldElement25519.Add(in aa, in eA24));
            }

            FieldElement25519.CSwap(swap, ref x2, ref x3);
            FieldElement25519.CSwap(swap, ref z2, ref z3);

            FieldElement25519 z2Inv = FieldElement25519.Invert(in z2);
            FieldElement25519 xOut = FieldElement25519.Mul(in x2, in z2Inv);
            xOut.ToBytes(result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
        }
    }

    /// <summary>
    /// Computes the X25519 public key for <paramref name="scalar"/> using the Curve25519 basepoint u=9.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ScalarMultBase(ReadOnlySpan<byte> scalar, Span<byte> publicKey)
    {
        ScalarMult(scalar, BasePoint, publicKey);
    }

    /// <summary>
    /// Generates a fresh random X25519 key pair.
    /// </summary>
    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey)
    {
        if (publicKey.Length < KeySize)
            throw new ArgumentException($"Public key buffer must be at least {KeySize} bytes.", nameof(publicKey));
        if (secretKey.Length < KeySize)
            throw new ArgumentException($"Secret key buffer must be at least {KeySize} bytes.", nameof(secretKey));

        Span<byte> sk = secretKey.Slice(0, KeySize);
        RandomNumberGenerator.Fill(sk);
        ScalarMultBase(sk, publicKey);
    }

    /// <summary>
    /// Computes the X25519 shared secret and returns <c>false</c> in constant time if the result is the
    /// all-zero low-order point (RFC 7748 Section 6.1 contributor check).
    /// </summary>
    public static bool TrySharedSecret(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        ScalarMult(secretKey, peerPublicKey, sharedSecret);

        byte nonZero = 0;
        for (int i = 0; i < KeySize; i++)
        {
            nonZero |= sharedSecret[i];
        }

        return nonZero != 0;
    }
}
