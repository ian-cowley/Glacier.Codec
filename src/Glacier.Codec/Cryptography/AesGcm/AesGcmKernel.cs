namespace Glacier.Codec.Cryptography.AesGcm;

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Glacier.Codec.Hardware;

/// <summary>
/// Hardware dispatcher and coordinator for AES-256-GCM AEAD encryption and decryption.
/// Automatically dispatches to AES-NI, ARM64 Crypto, or Scalar kernel.
/// </summary>
internal static unsafe class AesGcmKernel
{
    public static void ExpandKey(ReadOnlySpan<byte> key, Span<byte> roundKeys)
    {
        AesGcmKernelScalar.ExpandKey(key, roundKeys);
    }

    public static void PrecomputeHTable(ReadOnlySpan<byte> roundKeys, Span<byte> hTable)
    {
        Span<byte> zeroBlock = stackalloc byte[16];
        EncryptSingleBlock(roundKeys, zeroBlock, hTable.Slice(0, 16));

        if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasPclmulqdq && hTable.Length >= 64)
        {
            ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(0, 8));
            ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(8, 8));
            var h1 = Vector128.Create(hLo, hHi);
            var h2 = AesGcmKernelPclmul.MulOne(h1, h1);
            var h3 = AesGcmKernelPclmul.MulOne(h1, h2);
            var h4 = AesGcmKernelPclmul.MulOne(h2, h2);

            StorePower(h2, hTable.Slice(16, 16));
            StorePower(h3, hTable.Slice(32, 16));
            StorePower(h4, hTable.Slice(48, 16));

            if (hTable.Length >= 128)
            {
                var h5 = AesGcmKernelPclmul.MulOne(h1, h4);
                var h6 = AesGcmKernelPclmul.MulOne(h2, h4);
                var h7 = AesGcmKernelPclmul.MulOne(h3, h4);
                var h8 = AesGcmKernelPclmul.MulOne(h4, h4);

                StorePower(h5, hTable.Slice(64, 16));
                StorePower(h6, hTable.Slice(80, 16));
                StorePower(h7, hTable.Slice(96, 16));
                StorePower(h8, hTable.Slice(112, 16));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StorePower(Vector128<ulong> h, Span<byte> dest)
    {
        BinaryPrimitives.WriteUInt64BigEndian(dest.Slice(0, 8), h.GetElement(1));
        BinaryPrimitives.WriteUInt64BigEndian(dest.Slice(8, 8), h.GetElement(0));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static Vector128<ulong> LoadPower(ReadOnlySpan<byte> src)
    {
        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(src.Slice(0, 8));
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(src.Slice(8, 8));
        return Vector128.Create(lo, hi);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void EncryptSingleBlock(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> block, Span<byte> destination)
    {
        fixed (byte* rkPtr = roundKeys)
        {
            Vector128<byte>* rkVec = (Vector128<byte>*)rkPtr;

            if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasAesNi)
            {
                Vector128<byte> b = Vector128.Create(block);
                Vector128<byte> encrypted = AesGcmKernelAesNi.EncryptBlock(rkVec, b);
                encrypted.CopyTo(destination);
                return;
            }

            if (CpuCapabilities.IsArm64 && CpuCapabilities.HasArm64Aes)
            {
                Vector128<byte> b = Vector128.Create(block);
                Vector128<byte> encrypted = AesGcmKernelArm64.EncryptBlock(rkVec, b);
                encrypted.CopyTo(destination);
                return;
            }
        }

        AesGcmKernelScalar.EncryptBlock(roundKeys, block, destination);
    }

    public static void Encrypt(
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> hTable,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        // 1. Compute initial counter J0
        Span<byte> j0 = stackalloc byte[16];
        ComputeJ0(nonce, hTable, j0);

        // 2. Encrypt J0 to obtain tag mask
        Span<byte> tagMask = stackalloc byte[16];
        EncryptSingleBlock(roundKeys, j0, tagMask);

        // 3. GCTR encryption of plaintext starting from J1 = inc32(J0)
        Span<byte> counter = stackalloc byte[16];
        j0.CopyTo(counter);
        IncrementCounter32(counter);

        GctrCrypt(roundKeys, counter, plaintext, ciphertext);

        // 4. GHASH over AAD and Ciphertext
        Span<byte> computedTag = stackalloc byte[16];
        ComputeGhash(hTable, associatedData, ciphertext.Slice(0, plaintext.Length), tagMask, computedTag);

        computedTag.CopyTo(tag.Slice(0, 16));
    }

    public static bool Decrypt(
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> hTable,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> expectedTag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        // 1. Compute initial counter J0
        Span<byte> j0 = stackalloc byte[16];
        ComputeJ0(nonce, hTable, j0);

        // 2. Encrypt J0 to obtain tag mask
        Span<byte> tagMask = stackalloc byte[16];
        EncryptSingleBlock(roundKeys, j0, tagMask);

        // 3. Compute GHASH over AAD and Ciphertext to verify tag
        Span<byte> computedTag = stackalloc byte[16];
        ComputeGhash(hTable, associatedData, ciphertext, tagMask, computedTag);

        // Constant-time tag check
        bool isValid = CryptographicOperations.FixedTimeEquals(computedTag, expectedTag.Slice(0, 16));
        if (!isValid)
        {
            CryptographicOperations.ZeroMemory(plaintext.Slice(0, ciphertext.Length));
            return false;
        }

        // 4. GCTR decrypt starting from J1 = inc32(J0)
        Span<byte> counter = stackalloc byte[16];
        j0.CopyTo(counter);
        IncrementCounter32(counter);

        GctrCrypt(roundKeys, counter, ciphertext, plaintext);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void ComputeJ0(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> hTable, Span<byte> j0)
    {
        if (nonce.Length == 12)
        {
            // Standard 96-bit IV: J0 = IV || 0^31 || 1
            nonce.CopyTo(j0.Slice(0, 12));
            j0[12] = 0;
            j0[13] = 0;
            j0[14] = 0;
            j0[15] = 1;
        }
        else
        {
            // Arbitrary length IV: J0 = GHASH(IV || 0^s || len(IV)_64BE)
            ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(0, 8));
            ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(8, 8));
            ulong yHi = 0, yLo = 0;

            if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasPclmulqdq && hTable.Length >= 16)
            {
                var h1 = Vector128.Create(hLo, hHi);
                int offset = 0;
                while (offset + 16 <= nonce.Length)
                {
                    AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, nonce.Slice(offset, 16), h1);
                    offset += 16;
                }

                if (offset < nonce.Length)
                {
                    Span<byte> pad = stackalloc byte[16];
                    nonce.Slice(offset).CopyTo(pad);
                    AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, pad, h1);
                }

                Span<byte> lenBlock = stackalloc byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)nonce.Length * 8UL);
                AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, lenBlock, h1);
            }
            else
            {
                int offset = 0;
                while (offset + 16 <= nonce.Length)
                {
                    AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, nonce.Slice(offset, 16), hHi, hLo);
                    offset += 16;
                }

                if (offset < nonce.Length)
                {
                    Span<byte> pad = stackalloc byte[16];
                    nonce.Slice(offset).CopyTo(pad);
                    AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, pad, hHi, hLo);
                }

                Span<byte> lenBlock = stackalloc byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)nonce.Length * 8UL);
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, lenBlock, hHi, hLo);
            }

            BinaryPrimitives.WriteUInt64BigEndian(j0.Slice(0, 8), yHi);
            BinaryPrimitives.WriteUInt64BigEndian(j0.Slice(8, 8), yLo);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void IncrementCounter32(Span<byte> counter)
    {
        uint val = BinaryPrimitives.ReadUInt32BigEndian(counter.Slice(12, 4));
        BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), val + 1);
    }

    private static void GctrCrypt(
        ReadOnlySpan<byte> roundKeys,
        Span<byte> counter,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        fixed (byte* rkPtr = roundKeys, pSrc = source, pDst = destination)
        {
            GctrCryptDirect((Vector128<byte>*)rkPtr, counter, pSrc, pDst, source.Length);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void GctrCryptDirect(
        Vector128<byte>* rkVec,
        Span<byte> counter,
        byte* pSrc,
        byte* pDst,
        int length)
    {
        int offset = 0;

        if (CpuCapabilities.IsX86_64 && (CpuCapabilities.HasVectorAes || CpuCapabilities.HasAesNi))
        {
            // 16-way pipelined execution (256 bytes per iteration)
            while (offset + 256 <= length)
            {
                AesGcmKernelVaes512.Crypt16Blocks(rkVec, counter, pSrc + offset, pDst + offset);
                offset += 256;
            }

            Span<byte> cb = stackalloc byte[16];

            // 8-way pipelined execution (128 bytes per iteration)
            while (offset + 128 <= length)
            {
                uint c0 = BinaryPrimitives.ReadUInt32BigEndian(counter.Slice(12, 4));
                counter.Slice(0, 12).CopyTo(cb.Slice(0, 12));

                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 0);
                Vector128<byte> b0 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 1);
                Vector128<byte> b1 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 2);
                Vector128<byte> b2 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 3);
                Vector128<byte> b3 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 4);
                Vector128<byte> b4 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 5);
                Vector128<byte> b5 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 6);
                Vector128<byte> b6 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 7);
                Vector128<byte> b7 = Vector128.Create(cb);

                AesGcmKernelAesNi.Encrypt8Blocks(rkVec, ref b0, ref b1, ref b2, ref b3, ref b4, ref b5, ref b6, ref b7);

                (Vector128.Load(pSrc + offset + 0)   ^ b0).Store(pDst + offset + 0);
                (Vector128.Load(pSrc + offset + 16)  ^ b1).Store(pDst + offset + 16);
                (Vector128.Load(pSrc + offset + 32)  ^ b2).Store(pDst + offset + 32);
                (Vector128.Load(pSrc + offset + 48)  ^ b3).Store(pDst + offset + 48);
                (Vector128.Load(pSrc + offset + 64)  ^ b4).Store(pDst + offset + 64);
                (Vector128.Load(pSrc + offset + 80)  ^ b5).Store(pDst + offset + 80);
                (Vector128.Load(pSrc + offset + 96)  ^ b6).Store(pDst + offset + 96);
                (Vector128.Load(pSrc + offset + 112) ^ b7).Store(pDst + offset + 112);

                BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), c0 + 8);
                offset += 128;
            }

            // 4-way pipelined execution (64 bytes per iteration)
            while (offset + 64 <= length)
            {
                uint c0 = BinaryPrimitives.ReadUInt32BigEndian(counter.Slice(12, 4));
                counter.Slice(0, 12).CopyTo(cb.Slice(0, 12));

                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 0);
                Vector128<byte> b0 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 1);
                Vector128<byte> b1 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 2);
                Vector128<byte> b2 = Vector128.Create(cb);
                BinaryPrimitives.WriteUInt32BigEndian(cb.Slice(12, 4), c0 + 3);
                Vector128<byte> b3 = Vector128.Create(cb);

                AesGcmKernelAesNi.Encrypt4Blocks(rkVec, ref b0, ref b1, ref b2, ref b3);

                (Vector128.Load(pSrc + offset + 0)  ^ b0).Store(pDst + offset + 0);
                (Vector128.Load(pSrc + offset + 16) ^ b1).Store(pDst + offset + 16);
                (Vector128.Load(pSrc + offset + 32) ^ b2).Store(pDst + offset + 32);
                (Vector128.Load(pSrc + offset + 48) ^ b3).Store(pDst + offset + 48);

                BinaryPrimitives.WriteUInt32BigEndian(counter.Slice(12, 4), c0 + 4);
                offset += 64;
            }
        }

        // Single block loop & partial tail
        Span<byte> keystream = stackalloc byte[16];
        while (offset < length)
        {
            if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasAesNi)
            {
                Vector128<byte> b = AesGcmKernelAesNi.EncryptBlock(rkVec, Vector128.Create(counter));
                b.CopyTo(keystream);
            }
            else
            {
                AesGcmKernelScalar.EncryptBlock(new ReadOnlySpan<byte>(rkVec, 240), counter, keystream);
            }
            IncrementCounter32(counter);

            int remaining = Math.Min(16, length - offset);
            for (int k = 0; k < remaining; k++)
            {
                pDst[offset + k] = (byte)(pSrc[offset + k] ^ keystream[k]);
            }
            offset += remaining;
        }
    }

    private static void ComputeGhash(
        ReadOnlySpan<byte> hTable,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tagMask,
        Span<byte> tag)
    {
        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(0, 8));
        ulong hLo = BinaryPrimitives.ReadUInt64BigEndian(hTable.Slice(8, 8));
        ulong yHi = 0, yLo = 0;

        if (CpuCapabilities.IsX86_64 && CpuCapabilities.HasPclmulqdq && hTable.Length >= 64)
        {
            var h1 = Vector128.Create(hLo, hHi);
            var h2 = LoadPower(hTable.Slice(16, 16));
            var h3 = LoadPower(hTable.Slice(32, 16));
            var h4 = LoadPower(hTable.Slice(48, 16));

            if (CpuCapabilities.HasVpclmulqdq && AesGcmKernelPclmul512.IsSupported && hTable.Length >= 128)
            {
                var h5 = LoadPower(hTable.Slice(64, 16));
                var h6 = LoadPower(hTable.Slice(80, 16));
                var h7 = LoadPower(hTable.Slice(96, 16));
                var h8 = LoadPower(hTable.Slice(112, 16));
                var h8to5 = Vector512.Create(Vector256.Create(h8, h7), Vector256.Create(h6, h5));
                var h4to1 = Vector512.Create(Vector256.Create(h4, h3), Vector256.Create(h2, h1));

                if (aad.Length > 0)
                    AesGcmKernelPclmul512.ProcessBlocks(ref yHi, ref yLo, aad, h8to5, h4to1, h1, h2, h3, h4);
                if (ciphertext.Length > 0)
                    AesGcmKernelPclmul512.ProcessBlocks(ref yHi, ref yLo, ciphertext, h8to5, h4to1, h1, h2, h3, h4);
            }
            else
            {
                if (aad.Length > 0)
                    AesGcmKernelPclmul.ProcessBlocks(ref yHi, ref yLo, aad, h1, h2, h3, h4);
                if (ciphertext.Length > 0)
                    AesGcmKernelPclmul.ProcessBlocks(ref yHi, ref yLo, ciphertext, h1, h2, h3, h4);
            }

            // Length Block
            Span<byte> lenBlock = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(0, 8), (ulong)aad.Length * 8UL);
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)ciphertext.Length * 8UL);
            AesGcmKernelPclmul.GhashBlock(ref yHi, ref yLo, lenBlock, h1);
        }
        else
        {
            // 1. Process AAD
            int aadOffset = 0;
            while (aadOffset + 16 <= aad.Length)
            {
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, aad.Slice(aadOffset, 16), hHi, hLo);
                aadOffset += 16;
            }
            if (aadOffset < aad.Length)
            {
                Span<byte> partialAad = stackalloc byte[16];
                aad.Slice(aadOffset).CopyTo(partialAad);
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, partialAad, hHi, hLo);
            }

            // 2. Process Ciphertext
            int ctOffset = 0;
            while (ctOffset + 16 <= ciphertext.Length)
            {
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, ciphertext.Slice(ctOffset, 16), hHi, hLo);
                ctOffset += 16;
            }
            if (ctOffset < ciphertext.Length)
            {
                Span<byte> partialCt = stackalloc byte[16];
                ciphertext.Slice(ctOffset).CopyTo(partialCt);
                AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, partialCt, hHi, hLo);
            }

            // 3. Process Length Block (64-bit len(AAD) in bits || 64-bit len(Ciphertext) in bits)
            Span<byte> lenBlock = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(0, 8), (ulong)aad.Length * 8UL);
            BinaryPrimitives.WriteUInt64BigEndian(lenBlock.Slice(8, 8), (ulong)ciphertext.Length * 8UL);
            AesGcmKernelScalar.GhashBlock(ref yHi, ref yLo, lenBlock, hHi, hLo);
        }

        // 4. Tag = GHASH ^ TagMask
        ulong maskHi = BinaryPrimitives.ReadUInt64BigEndian(tagMask.Slice(0, 8));
        ulong maskLo = BinaryPrimitives.ReadUInt64BigEndian(tagMask.Slice(8, 8));

        BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(0, 8), yHi ^ maskHi);
        BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(8, 8), yLo ^ maskLo);
    }
}
