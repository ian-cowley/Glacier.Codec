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
/// Statistical constant-time side-channel verification suite based on dudect (Reparaz et al.):
/// measures interleaved randomized Class 0 vs Class 1 execution timings, applies 95th-percentile
/// upper-tail cropping to reject OS preemption outliers, and evaluates Welch's t-statistic.
/// </summary>
public sealed class ConstantTimeTests
{
    private const double ConstantTimeThreshold = 10.0;

    private static double MeasureWelchT(
        Action class0,
        Action class1,
        int warmupRounds = 250,
        int samplesPerRun = 2000)
    {
        for (int i = 0; i < warmupRounds; i++)
        {
            class0();
            class1();
        }

        long[] timings = new long[samplesPerRun];
        byte[] classes = new byte[samplesPerRun];
        var rng = new Random(0x5EED_D0DE);

        for (int i = 0; i < samplesPerRun; i++)
        {
            byte cls = (byte)(rng.Next() & 1);
            classes[i] = cls;

            long t0 = Stopwatch.GetTimestamp();
            if (cls == 0)
            {
                class0();
            }
            else
            {
                class1();
            }
            long t1 = Stopwatch.GetTimestamp();
            timings[i] = t1 - t0;
        }

        // Crop upper 5% tail across combined samples to filter OS scheduling spikes
        long[] sorted = (long[])timings.Clone();
        Array.Sort(sorted);
        long cutoff = sorted[(int)(samplesPerRun * 0.95)];

        long n0 = 0, n1 = 0;
        double mean0 = 0, mean1 = 0;
        double m2_0 = 0, m2_1 = 0;

        for (int i = 0; i < samplesPerRun; i++)
        {
            long val = timings[i];
            if (val > cutoff)
            {
                continue;
            }

            if (classes[i] == 0)
            {
                n0++;
                double delta = val - mean0;
                mean0 += delta / n0;
                m2_0 += delta * (val - mean0);
            }
            else
            {
                n1++;
                double delta = val - mean1;
                mean1 += delta / n1;
                m2_1 += delta * (val - mean1);
            }
        }

        if (n0 < 30 || n1 < 30)
        {
            return 0.0;
        }

        double var0 = m2_0 / (n0 - 1);
        double var1 = m2_1 / (n1 - 1);
        double denom = Math.Sqrt((var0 / n0) + (var1 / n1));
        if (denom <= 1e-12)
        {
            return 0.0;
        }

        return (mean0 - mean1) / denom;
    }

    private static void AssertConstantTime(Action class0, Action class1, int samples = 2000)
    {
        double minAbsT = double.MaxValue;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            double t = Math.Abs(MeasureWelchT(class0, class1, warmupRounds: 250, samplesPerRun: samples));
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

        double t = MeasureWelchT(
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
            warmupRounds: 200,
            samplesPerRun: 1200);

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
            samples: 1200);
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
            samples: 1000);
    }

    [Fact]
    public void Dudect_KeccakSponge_SamplePolyCBD2_ZeroVsNegativeHeavy_IsConstantTime()
    {
        byte[] zeroSeed = new byte[128];
        byte[] negativeHeavySeed = new byte[128];
        // 0xCC = 1100_1100 => (b0+b1)-(b2+b3) = 0-2 = -2 (hits negative wrap path every nibble)
        Array.Fill(negativeHeavySeed, (byte)0xCC);
        short[] poly = new short[256];

        AssertConstantTime(
            () =>
            {
                int acc = 0;
                for (int r = 0; r < 64; r++)
                {
                    KeccakSponge.SamplePolyCBD_2(zeroSeed, poly);
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
            samples: 1500);
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
            samples: 1500);
    }
}
