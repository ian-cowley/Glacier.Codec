namespace Glacier.Codec.Cryptography.ChaCha20Poly1305;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

/// <summary>
/// Low-level ChaCha20 stream cipher implementing 20-round keystream expansion (RFC 8439).
/// </summary>
public static class ChaCha20Cipher
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void GenerateBlock(
        ReadOnlySpan<byte> key,
        uint counter,
        ReadOnlySpan<byte> nonce,
        Span<byte> destination)
    {
        if (Vector128.IsHardwareAccelerated)
        {
            ChaCha20KernelAvx2.GenerateBlock128(key, counter, nonce, destination);
            return;
        }

        ChaCha20KernelScalar.GenerateBlock(key, counter, nonce, destination);
    }

    /// <summary>
    /// Encrypts or decrypts a payload in-place or out-of-place using the ChaCha20 stream cipher.
    /// </summary>
    public static void Crypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        uint initialCounter,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be exactly 32 bytes.", nameof(key));
        if (nonce.Length != 12)
            throw new ArgumentException("Nonce must be exactly 12 bytes.", nameof(nonce));
        if (destination.Length < source.Length)
            throw new ArgumentException("Destination buffer too small.", nameof(destination));

        uint counter = initialCounter;
        int length = source.Length;
        int offset = 0;

        Span<byte> block = stackalloc byte[64];

        while (offset + 64 <= length)
        {
            GenerateBlock(key, counter++, nonce, block);

            if (Vector128.IsHardwareAccelerated)
            {
                Vector128.Xor(Vector128.Create(source.Slice(offset + 0, 16)), Vector128.Create(block.Slice(0, 16))).CopyTo(destination.Slice(offset + 0, 16));
                Vector128.Xor(Vector128.Create(source.Slice(offset + 16, 16)), Vector128.Create(block.Slice(16, 16))).CopyTo(destination.Slice(offset + 16, 16));
                Vector128.Xor(Vector128.Create(source.Slice(offset + 32, 16)), Vector128.Create(block.Slice(32, 16))).CopyTo(destination.Slice(offset + 32, 16));
                Vector128.Xor(Vector128.Create(source.Slice(offset + 48, 16)), Vector128.Create(block.Slice(48, 16))).CopyTo(destination.Slice(offset + 48, 16));
            }
            else
            {
                for (int k = 0; k < 64; k++)
                {
                    destination[offset + k] = (byte)(source[offset + k] ^ block[k]);
                }
            }

            offset += 64;
        }

        if (offset < length)
        {
            GenerateBlock(key, counter++, nonce, block);
            int remaining = length - offset;
            for (int k = 0; k < remaining; k++)
            {
                destination[offset + k] = (byte)(source[offset + k] ^ block[k]);
            }
        }
    }
}
