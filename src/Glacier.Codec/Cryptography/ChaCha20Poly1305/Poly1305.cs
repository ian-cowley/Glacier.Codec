namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
/// High-speed RFC 8439 Poly1305 one-time MAC authenticator.
/// </summary>
public static class Poly1305
{
    public const int KeySizeInBytes = 32;
    public const int TagSizeInBytes = 16;

    /// <summary>
    /// Computes the RFC 8439 Poly1305 one-time MAC of message using a 32-byte key.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        if (key.Length != KeySizeInBytes)
            throw new ArgumentException($"Poly1305 key must be exactly {KeySizeInBytes} bytes (received {key.Length}).", nameof(key));
        if (tag.Length < TagSizeInBytes)
            throw new ArgumentException($"Tag destination buffer must be at least {TagSizeInBytes} bytes (received {tag.Length}).", nameof(tag));

        Poly1305Kernel.ComputeMac(key, message, tag.Slice(0, TagSizeInBytes));
    }

    /// <summary>
    /// Computes and verifies Poly1305 MAC in constant time.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expectedTag)
    {
        if (expectedTag.Length != TagSizeInBytes)
            return false;

        Span<byte> actualTag = stackalloc byte[TagSizeInBytes];
        ComputeMac(key, message, actualTag);
        return CryptographicOperations.FixedTimeEquals(actualTag, expectedTag);
    }
}
