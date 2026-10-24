namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Cryptography.Kdf;
using Glacier.Codec.Cryptography.PostQuantum;
using Glacier.Codec.Hashing;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.XxHash3;
using Glacier.Codec.Hardware;
using Xunit;

/// <summary>
/// Tier 5 Adversarial Test Suite for Hardware Intrinsics & Arbiter Fallback Paths.
/// Tests 18 edge conditions and parity invariants between SIMD and scalar kernels.
/// </summary>
public sealed unsafe class Tier5AdversarialHardwareArbiterTests
{
    [Fact]
    public void Arb01_RouteWorkload_NegativePayload_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(-1, 1, gpuAvailable: true));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(-500, 10, gpuAvailable: false));
    }

    [Fact]
    public void Arb02_RouteWorkload_ZeroBatchCount_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(1024, 0, gpuAvailable: true));
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareArbiter.RouteWorkload(1024, -2, gpuAvailable: false));
    }

    [Fact]
    public void Arb03_RouteWorkload_ZeroBytes_AlwaysCpuVector()
    {
        var targetWithGpu = HardwareArbiter.RouteWorkload(0, 1, gpuAvailable: true);
        var targetNoGpu = HardwareArbiter.RouteWorkload(0, 1, gpuAvailable: false);
        var targetLargeBatch = HardwareArbiter.RouteWorkload(0, 100, gpuAvailable: true);

        Assert.Equal(ExecutionTarget.CpuVector, targetWithGpu);
        Assert.Equal(ExecutionTarget.CpuVector, targetNoGpu);
        Assert.Equal(ExecutionTarget.CpuVector, targetLargeBatch);
    }

    [Fact]
    public void Arb04_RouteWorkload_OneByte_ReturnsCpuVector()
    {
        var target = HardwareArbiter.RouteWorkload(1, 1, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuVector, target);
        Assert.True(HardwareArbiter.ShouldVectorizeCpu(1, 1));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(1, 1, gpuAvailable: true));
    }

    [Fact]
    public void Arb05_RouteWorkload_Payload1MBMinus1_Batch15_ReturnsCpuVector()
    {
        const int payload = 1024 * 1024 - 1;
        var target = HardwareArbiter.RouteWorkload(payload, 15, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuVector, target);
        Assert.True(HardwareArbiter.ShouldVectorizeCpu(payload, 15));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payload, 15, gpuAvailable: true));
    }

    [Fact]
    public void Arb06_RouteWorkload_PayloadExact1MB_Batch15_ReturnsCpuParallelPool()
    {
        const int payload = 1024 * 1024;
        var target = HardwareArbiter.RouteWorkload(payload, 15, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
        Assert.False(HardwareArbiter.ShouldVectorizeCpu(payload, 15));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payload, 15, gpuAvailable: true));
    }

    [Fact]
    public void Arb07_RouteWorkload_PayloadExact1MB_Batch16_GpuTrue_ReturnsGpuCompute()
    {
        const int payload = 1024 * 1024;
        var target = HardwareArbiter.RouteWorkload(payload, 16, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.GpuCompute, target);
        Assert.True(HardwareArbiter.ShouldOffloadToGpu(payload, 16, gpuAvailable: true));
    }

    [Fact]
    public void Arb08_RouteWorkload_Payload4MBMinus1_Batch1_ReturnsCpuParallelPool()
    {
        const int payload = 4 * 1024 * 1024 - 1;
        var target = HardwareArbiter.RouteWorkload(payload, 1, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
        Assert.False(HardwareArbiter.ShouldVectorizeCpu(payload, 1));
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payload, 1, gpuAvailable: true));
    }

    [Fact]
    public void Arb09_RouteWorkload_PayloadExact4MB_Batch1_GpuTrue_ReturnsGpuCompute()
    {
        const int payload = 4 * 1024 * 1024;
        var target = HardwareArbiter.RouteWorkload(payload, 1, gpuAvailable: true);
        Assert.Equal(ExecutionTarget.GpuCompute, target);
        Assert.True(HardwareArbiter.ShouldOffloadToGpu(payload, 1, gpuAvailable: true));
    }

    [Fact]
    public void Arb10_RouteWorkload_PayloadExact4MB_Batch1_GpuFalse_ReturnsCpuParallelPool()
    {
        const int payload = 4 * 1024 * 1024;
        var target = HardwareArbiter.RouteWorkload(payload, 1, gpuAvailable: false);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
        Assert.False(HardwareArbiter.ShouldOffloadToGpu(payload, 1, gpuAvailable: false));
    }

    [Fact]
    public void Arb11_RouteWorkload_Payload100B_Batch16_GpuFalse_ReturnsCpuParallelPool()
    {
        var target = HardwareArbiter.RouteWorkload(100, 16, gpuAvailable: false);
        Assert.Equal(ExecutionTarget.CpuParallelPool, target);
    }

    [Fact]
    public void Arb12_Blake3_Avx512_Avx2_Scalar_Parity_Contiguous16Chunks()
    {
        byte[] chunks = new byte[16 * Blake3Constants.ChunkSize];
        RandomNumberGenerator.Fill(chunks);

        uint[] key = [0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u];
        byte[] scalarCvs = new byte[16 * 32];

        fixed (byte* pChunks = chunks)
        fixed (uint* pKey = key)
        fixed (byte* pScalarCvs = scalarCvs)
        {
            Span<uint> runningCv = stackalloc uint[8];

            // Compute CVs using scalar kernel across 16 chunks
            for (int c = 0; c < 16; c++)
            {
                byte* chunk = pChunks + (c * Blake3Constants.ChunkSize);
                for (int i = 0; i < 8; i++) runningCv[i] = pKey[i];

                fixed (uint* pCv = runningCv)
                {
                    for (int b = 0; b < 16; b++)
                    {
                        uint flags = 0;
                        if (b == 0) flags |= (uint)Blake3Flags.ChunkStart;
                        if (b == 15) flags |= (uint)Blake3Flags.ChunkEnd;

                        uint* target = (b == 15) ? (uint*)(pScalarCvs + (c * 32)) : pCv;
                        Blake3KernelScalar.CompressBlock(pCv, chunk + (b * 64), (ulong)c, 64, flags, target);
                    }
                }
            }

            // Verify AVX-512 parity if supported
            if (Blake3KernelAvx512.IsSupported)
            {
                byte[] avx512Cvs = new byte[16 * 32];
                fixed (byte* pAvx512 = avx512Cvs)
                {
                    Blake3KernelAvx512.Hash16Chunks(pChunks, 0, pKey, 0, pAvx512);
                }
                Assert.Equal(scalarCvs, avx512Cvs);
            }

            // Verify AVX2 parity if supported
            if (Blake3KernelAvx2.IsSupported)
            {
                byte[] avx2Cvs = new byte[16 * 32];
                fixed (byte* pAvx2 = avx2Cvs)
                {
                    Blake3KernelAvx2.Hash8Chunks(pChunks, 0, pKey, 0, pAvx2);
                    Blake3KernelAvx2.Hash8Chunks(pChunks + (8 * Blake3Constants.ChunkSize), 8, pKey, 0, pAvx2 + (8 * 32));
                }
                Assert.Equal(scalarCvs, avx2Cvs);
            }
        }
    }

    [Fact]
    public void Arb13_XxHash3_Stripe_Vector_Scalar_Parity()
    {
        byte[][] testStripes =
        [
            new byte[64], // All zeros
            new byte[64], // All ones
            new byte[64], // Alternating 0xAA
            new byte[64]  // Random
        ];

        Array.Fill(testStripes[1], (byte)0xFF);
        Array.Fill(testStripes[2], (byte)0xAA);
        RandomNumberGenerator.Fill(testStripes[3]);

        byte[] secret = new byte[XxHash3Constants.SecretLengthBytes];
        RandomNumberGenerator.Fill(secret);

        foreach (var stripe in testStripes)
        {
            ulong[] accScalar = [1, 2, 3, 4, 5, 6, 7, 8];
            ulong[] accAvx512 = [1, 2, 3, 4, 5, 6, 7, 8];
            ulong[] accAvx2 = [1, 2, 3, 4, 5, 6, 7, 8];

            fixed (ulong* pAccScalar = accScalar)
            fixed (ulong* pAccAvx512 = accAvx512)
            fixed (ulong* pAccAvx2 = accAvx2)
            fixed (byte* pStripe = stripe)
            fixed (byte* pSecret = secret)
            {
                XxHash3KernelScalar.AccumulateStripe(pAccScalar, pStripe, pSecret);

                if (XxHash3KernelAvx512.IsSupported)
                {
                    XxHash3KernelAvx512.AccumulateStripe(pAccAvx512, pStripe, pSecret);
                    Assert.Equal(accScalar, accAvx512);
                }

                if (XxHash3KernelAvx2.IsSupported)
                {
                    XxHash3KernelAvx2.AccumulateStripe(pAccAvx2, pStripe, pSecret);
                    Assert.Equal(accScalar, accAvx2);
                }
            }
        }
    }

    [Fact]
    public void Arb14_Aes256_Block_AesNi_Scalar_Parity()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] roundKeys = new byte[240];
        AesGcmKernel.ExpandKey(key, roundKeys);

        byte[] block = new byte[16];
        byte[] outScalar = new byte[16];
        byte[] outAesNi = new byte[16];

        for (int i = 0; i < 50; i++)
        {
            RandomNumberGenerator.Fill(block);

            AesGcmKernelScalar.EncryptBlock(roundKeys, block, outScalar);

            if (CpuCapabilities.HasAesNi)
            {
                fixed (byte* rkPtr = roundKeys)
                {
                    Vector128<byte>* rkVec = (Vector128<byte>*)rkPtr;
                    Vector128<byte> blkVec = Vector128.Create(block);
                    Vector128<byte> res = AesGcmKernelAesNi.EncryptBlock(rkVec, blkVec);
                    res.CopyTo(outAesNi);
                }
                Assert.Equal(outScalar, outAesNi);
            }
        }
    }

    [Fact]
    public void Arb15_ChaCha20_Keystream_Avx2_Scalar_Parity()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        uint[] testCounters = [0, 1, 2, int.MaxValue, uint.MaxValue - 1];
        byte[] blockScalar = new byte[64];
        byte[] blockAvx2 = new byte[64];

        foreach (uint ctr in testCounters)
        {
            ChaCha20KernelScalar.GenerateBlock(key, ctr, nonce, blockScalar);
            ChaCha20KernelAvx2.GenerateBlock128(key, ctr, nonce, blockAvx2);

            Assert.Equal(blockScalar, blockAvx2);
        }
    }

    [Fact]
    public void Arb16_Argon2id_MixBlock_Avx2_Scalar_Parity()
    {
        ulong[] x = new ulong[128];
        ulong[] y = new ulong[128];
        ulong[] destScalar = new ulong[128];
        ulong[] destAvx2 = new ulong[128];

        for (int i = 0; i < 128; i++)
        {
            x[i] = unchecked((ulong)Random.Shared.NextInt64());
            y[i] = unchecked((ulong)Random.Shared.NextInt64());
        }

        fixed (ulong* px = x, py = y, pds = destScalar, pda = destAvx2)
        {
            Argon2idKernelScalar.MixBlock(pds, px, py);

            if (CpuCapabilities.HasAvx2)
            {
                Argon2idKernelAvx2.MixBlock(pda, px, py);
                Assert.Equal(destScalar, destAvx2);
            }
        }
    }

    [Fact]
    public void Arb17_MlKem_PolyAddSub_Vector_Scalar_Parity()
    {
        short[] f = new short[256];
        short[] g = new short[256];
        short[] hScalarAdd = new short[256];
        short[] hVectorAdd = new short[256];
        short[] hScalarSub = new short[256];
        short[] hVectorSub = new short[256];

        for (int i = 0; i < 256; i++)
        {
            f[i] = (short)Random.Shared.Next(0, 3329);
            g[i] = (short)Random.Shared.Next(0, 3329);
        }

        NttTransformScalar.PolyAdd(f, g, hScalarAdd);
        NttTransform.PolyAdd(f, g, hVectorAdd);
        Assert.Equal(hScalarAdd, hVectorAdd);

        NttTransformScalar.PolySub(f, g, hScalarSub);
        NttTransform.PolySub(f, g, hVectorSub);
        Assert.Equal(hScalarSub, hVectorSub);
    }

    [Fact]
    public void Arb18_CpuCapabilities_Invariants_Hold()
    {
        Assert.True(CpuCapabilities.LogicalCoreCount > 0);

        if (CpuCapabilities.IsX86_64)
        {
            if (CpuCapabilities.HasAvx512F && CpuCapabilities.HasAvx512BW && (CpuCapabilities.HasVectorAes || CpuCapabilities.HasAesNi))
            {
                Assert.Equal(HardwareTier.Tier0_UltrawideVector, CpuCapabilities.DetectedTier);
            }
            else if (CpuCapabilities.HasAvx2 && CpuCapabilities.HasAesNi)
            {
                Assert.Equal(HardwareTier.Tier1_MainstreamVector, CpuCapabilities.DetectedTier);
            }
        }
    }
}
