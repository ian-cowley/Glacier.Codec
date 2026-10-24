namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

/// <summary>
/// ARM64 hardware accelerated AES-256 block encryption via ARMv8 Cryptographic extensions.
/// </summary>
internal static unsafe class AesGcmKernelArm64
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> EncryptBlock(Vector128<byte>* rk, Vector128<byte> block)
    {
        Vector128<byte> state = block;

        // Rounds 0 through 12 (AESE + AESMC)
        for (int r = 0; r < 13; r++)
        {
            state = Aes.Encrypt(state, rk[r]);
            state = Aes.MixColumns(state);
        }

        // Round 13 (AESE only; no MixColumns before final round)
        state = Aes.Encrypt(state, rk[13]);

        // Round 14 (Final round key XOR)
        return Vector128.Xor(state, rk[14]);
    }
}
