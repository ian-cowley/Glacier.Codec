namespace Glacier.Codec.Tests;

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.EllipticCurve;
using Glacier.Codec.Cryptography.PostQuantum;
using Xunit;

/// <summary>
/// Statistical constant-time side-channel verification suite based on paired randomized dudect:
/// measures interleaved randomized pairs (Class 0 vs Class 1 back-to-back) to cancel VM drift,
/// applies 95th-percentile |diff| outlier cropping, and evaluates the paired t-statistic.
/// </summary>
[Trait("Category", "ConstantTime")]
public sealed class ConstantTimeTests
{
    private const double ConstantTimeThreshold = 10.0;

    private static double MeasurePairedT(
        Action class0,
        Action class1,
        int warmupRounds = 400,
        int pairsPerRun = 1500)
    {
        for (int i = 0; i < warmupRounds; i++)
        {
            class0();
            class1();
        }

        long[] diffs = new long[pairsPerRun];
        long[] absDiffs = new long[pairsPerRun];
        var rng = new Random(0x5EED_D0DE);

        for (int i = 0; i < pairsPerRun; i++)
        {
            long d0, d1;
            if ((rng.Next() & 1) == 0)
            {
                long a0 = Stopwatch.GetTimestamp();
                class0();
                long a1 = Stopwatch.GetTimestamp();
                long b0 = Stopwatch.GetTimestamp();
                class1();
                long b1 = Stopwatch.GetTimestamp();
                d0 = a1 - a0;
                d1 = b1 - b0;
            }
            else
            {
                long b0 = Stopwatch.GetTimestamp();
                class1();
                long b1 = Stopwatch.GetTimestamp();
                long a0 = Stopwatch.GetTimestamp();
                class0();
                long a1 = Stopwatch.GetTimestamp();
                d0 = a1 - a0;
                d1 = b1 - b0;
            }

            long diff = d0 - d1;
            diffs[i] = diff;
            absDiffs[i] = diff < 0 ? -diff : diff;
        }

        // Crop upper 5% largest |diff| outliers to filter OS preemption spikes
        Array.Sort(absDiffs);
        long cutoff = absDiffs[(int)(pairsPerRun * 0.95)];

        long n = 0;
        double mean = 0;
        double m2 = 0;

        for (int i = 0; i < pairsPerRun; i++)
        {
            long d = diffs[i];
            long absD = d < 0 ? -d : d;
            if (absD > cutoff)
            {
                continue;
            }

            n++;
            double delta = d - mean;
            mean += delta / n;
            m2 += delta * (d - mean);
        }

        if (n < 30)
        {
            return 0.0;
        }

        double variance = m2 / (n - 1);
        double se = Math.Sqrt(variance / n);
        if (se <= 1e-12)
        {
            return 0.0;
        }

        return mean / se;
    }

    private static void AssertConstantTime(Action class0, Action class1, int pairs = 1500)
    {
        double minAbsT = double.MaxValue;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            double t = Math.Abs(MeasurePairedT(class0, class1, warmupRounds: 400, pairsPerRun: pairs));
            if (t < minAbsT)
            {
                minAbsT = t;
            }
            if (t < ConstantTimeThreshold)
            {
                return;
            }
        }

        Assert.Fail($"Potential timing side-channel detected: minimum |t| = {minAbsT:F2} >= {ConstantTimeThreshold:F1} across 3 trials.");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool LeakyByteEquals(byte[] a, byte[] b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    private static volatile int s_sink;

    [Fact]
    public void Dudect_DetectsDeliberateEarlyExitLeak()
    {
        byte[] baseline = new byte[16384];
        byte[] match = new byte[16384];
        byte[] earlyDiff = new byte[16384];
        earlyDiff[0] = 0xFF;

        double t = MeasurePairedT(
            () =>
            {
                int acc = 0;
                for (int i = 0; i < 8; i++) acc += LeakyByteEquals(baseline, earlyDiff) ? 1 : 0;
                s_sink = acc;
            },
            () =>
            {
                int acc = 0;
                for (int i = 0; i < 8; i++) acc += LeakyByteEquals(baseline, match) ? 1 : 0;
                s_sink = acc;
            },
            warmupRounds: 300,
            pairsPerRun: 1000);

        Assert.True(Math.Abs(t) > ConstantTimeThreshold,
            $"Expected dudect harness to detect deliberate early-exit leak (|t|={Math.Abs(t):F2}).");
    }

    [Fact]
    public void Dudect_MlKem768_Decapsulate_ValidVsTampered_IsConstantTime()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        kem.GenerateKeyPair(pk, sk);

        byte[] ctValid = new byte[MlKem768.CiphertextBytes];
        byte[] ssOut = new byte[MlKem768.SharedSecretBytes];
        kem.Encapsulate(pk, ctValid, ssOut);

        byte[] ctTampered = (byte[])ctValid.Clone();
        ctTampered[0] ^= 0xFF;
        ctTampered[500] ^= 0x55;

        AssertConstantTime(
            () =>
            {
                kem.Decapsulate(sk, ctValid, ssOut);
                s_sink = ssOut[0];
            },
            () =>
            {
                kem.Decapsulate(sk, ctTampered, ssOut);
                s_sink = ssOut[0];
            },
            pairs: 1000);
    }

    [Fact]
    public void Dudect_X25519_ScalarMult_LowVsHighHammingWeight_IsConstantTime()
    {
        byte[] lowWeightScalar = new byte[32];
        byte[] highWeightScalar = new byte[32];
        Array.Fill(highWeightScalar, (byte)0xFF);

        byte[] uCoord = new byte[32];
        uCoord[0] = 9;
        byte[] outBuf = new byte[32];

        AssertConstantTime(
            () =>
            {
                X25519.ScalarMult(lowWeightScalar, uCoord, outBuf);
                s_sink = outBuf[0];
            },
            () =>
            {
                X25519.ScalarMult(highWeightScalar, uCoord, outBuf);
                s_sink = outBuf[0];
            },
            pairs: 800);
    }

    [Fact]
    public void Dudect_KeccakSponge_SamplePolyCBD2_ZeroVsNegativeHeavy_IsConstantTime()
    {
        // Equal Hamming weight (4 bits/byte): 0x33 -> +2 (never wraps) vs 0xCC -> -2 (always wraps +3329)
        byte[] positiveSeed = new byte[128];
        Array.Fill(positiveSeed, (byte)0x33);
        byte[] negativeHeavySeed = new byte[128];
        Array.Fill(negativeHeavySeed, (byte)0xCC);
        short[] poly = new short[256];

        AssertConstantTime(
            () =>
            {
                int acc = 0;
                for (int r = 0; r < 64; r++)
                {
                    KeccakSponge.SamplePolyCBD_2(positiveSeed, poly);
                    acc += poly[0];
                }
                s_sink = acc;
            },
            () =>
            {
                int acc = 0;
                for (int r = 0; r < 64; r++)
                {
                    KeccakSponge.SamplePolyCBD_2(negativeHeavySeed, poly);
                    acc += poly[0];
                }
                s_sink = acc;
            },
            pairs: 1200);
    }

    [Fact]
    public void Dudect_Aes256Gcm_Decrypt_TagMismatchFirstVsLastByte_IsConstantTime()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] pt = new byte[256];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(pt);

        byte[] ct = new byte[256];
        byte[] tag = new byte[16];
        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(pt, default, nonce, ct, tag);

        byte[] badTagFirst = (byte[])tag.Clone();
        badTagFirst[0] ^= 0x01;
        byte[] badTagLast = (byte[])tag.Clone();
        badTagLast[15] ^= 0x01;
        byte[] outPt = new byte[256];

        AssertConstantTime(
            () =>
            {
                int ok = 0;
                for (int r = 0; r < 32; r++)
                {
                    ok += cipher.Decrypt(ct, default, nonce, badTagFirst, outPt) ? 1 : 0;
                }
                s_sink = ok;
            },
            () =>
            {
                int ok = 0;
                for (int r = 0; r < 32; r++)
                {
                    ok += cipher.Decrypt(ct, default, nonce, badTagLast, outPt) ? 1 : 0;
                }
                s_sink = ok;
            },
            pairs: 1200);
    }

    [Fact]
    public void Dudect_AesGcmKernelScalar_BitslicedEncryptBlock_ZeroVsHighEntropy_IsConstantTime()
    {
        byte[] rkZero = new byte[240];
        byte[] rkRandom = new byte[240];
        RandomNumberGenerator.Fill(rkRandom);

        byte[] zeroBlock = new byte[16];
        byte[] randomBlock = new byte[16];
        RandomNumberGenerator.Fill(randomBlock);

        byte[] dst = new byte[16];

        AssertConstantTime(
            () =>
            {
                int acc = 0;
                for (int r = 0; r < 8; r++)
                {
                    AesGcmKernelScalar.EncryptBlock(rkZero, zeroBlock, dst);
                    acc += dst[0];
                }
                s_sink = acc;
            },
            () =>
            {
                int acc = 0;
                for (int r = 0; r < 8; r++)
                {
                    AesGcmKernelScalar.EncryptBlock(rkRandom, randomBlock, dst);
                    acc += dst[0];
                }
                s_sink = acc;
            },
            pairs: 1000);
    }
}
