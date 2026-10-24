namespace Glacier.Codec.Hashing.Sha256;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using ArmSha256 = System.Runtime.Intrinsics.Arm.Sha256;

/// <summary>
/// Hardware-accelerated ARM64 SHA-256 compression kernel utilizing ARMv8 Crypto extensions.
/// </summary>
internal static class Sha256KernelArm64
{
    private static readonly uint[] K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void CompressBlocks(ref Sha256State state, ReadOnlySpan<byte> blocks)
    {
        if (!ArmSha256.IsSupported)
        {
            Sha256KernelScalar.CompressBlocks(ref state, blocks);
            return;
        }

        int blockCount = blocks.Length / 64;
        Vector128<uint> abcd = Vector128.Create(state.H0, state.H1, state.H2, state.H3);
        Vector128<uint> efgh = Vector128.Create(state.H4, state.H5, state.H6, state.H7);

        for (int b = 0; b < blockCount; b++)
        {
            ReadOnlySpan<byte> block = blocks.Slice(b * 64, 64);

            Vector128<uint> origAbcd = abcd;
            Vector128<uint> origEfgh = efgh;

            Vector128<uint> w0 = LoadBigEndian128(block.Slice(0, 16));
            Vector128<uint> w1 = LoadBigEndian128(block.Slice(16, 16));
            Vector128<uint> w2 = LoadBigEndian128(block.Slice(32, 16));
            Vector128<uint> w3 = LoadBigEndian128(block.Slice(48, 16));

            for (int t = 0; t < 16; t += 4)
            {
                Round4(ref abcd, ref efgh, w0, t);
                Vector128<uint> s0 = ArmSha256.ScheduleUpdate0(w0, w1);
                w0 = ArmSha256.ScheduleUpdate1(s0, w2, w3);

                Round4(ref abcd, ref efgh, w1, t + 4);
                Vector128<uint> s1 = ArmSha256.ScheduleUpdate0(w1, w2);
                w1 = ArmSha256.ScheduleUpdate1(s1, w3, w0);

                Round4(ref abcd, ref efgh, w2, t + 8);
                Vector128<uint> s2 = ArmSha256.ScheduleUpdate0(w2, w3);
                w2 = ArmSha256.ScheduleUpdate1(s2, w0, w1);

                Round4(ref abcd, ref efgh, w3, t + 12);
                Vector128<uint> s3 = ArmSha256.ScheduleUpdate0(w3, w0);
                w3 = ArmSha256.ScheduleUpdate1(s3, w1, w2);
            }

            abcd += origAbcd;
            efgh += origEfgh;
        }

        state.H0 = abcd.GetElement(0);
        state.H1 = abcd.GetElement(1);
        state.H2 = abcd.GetElement(2);
        state.H3 = abcd.GetElement(3);
        state.H4 = efgh.GetElement(0);
        state.H5 = efgh.GetElement(1);
        state.H6 = efgh.GetElement(2);
        state.H7 = efgh.GetElement(3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round4(ref Vector128<uint> abcd, ref Vector128<uint> efgh, Vector128<uint> w, int round)
    {
        Vector128<uint> k0 = Vector128.Create(K[round], K[round + 1], K[round + 2], K[round + 3]);
        Vector128<uint> wk = w + k0;

        Vector128<uint> abcd1 = ArmSha256.HashUpdate1(abcd, efgh, wk);
        Vector128<uint> efgh1 = ArmSha256.HashUpdate2(efgh, abcd, wk);

        abcd = ArmSha256.HashUpdate1(abcd1, efgh1, wk);
        efgh = ArmSha256.HashUpdate2(efgh1, abcd1, wk);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> LoadBigEndian128(ReadOnlySpan<byte> slice)
    {
        return Vector128.Create(
            BinaryPrimitives.ReadUInt32BigEndian(slice.Slice(0, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(slice.Slice(4, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(slice.Slice(8, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(slice.Slice(12, 4))
        );
    }
}
