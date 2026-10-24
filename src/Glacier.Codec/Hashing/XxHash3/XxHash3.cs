namespace Glacier.Codec.Hashing.XxHash3;

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using Glacier.Codec.Hardware;

/// <summary>
/// Ultra-high-throughput xxHash3 static non-cryptographic hash engine (64-bit and 128-bit).
/// Implements branchless shortcuts for 0..240 bytes and vectorized 64-byte stripe pipelines for long streams.
/// Conforms 100% to the official xxHash3 specification and .NET System.IO.Hashing across seeded and unseeded modes.
/// </summary>
public static unsafe class XxHash3
{
    private const ulong RrmxmxPrime = 0x9FB21C651E98DF25UL;
    private const ulong Xxh3AvalanchePrime = 0x165667919E3779F9UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<byte> source, ulong seed = 0)
    {
        // For inputs <= 240 bytes, xxHash3 small-payload algorithms use DefaultSecret directly
        // and apply the seed arithmetically inside the hash functions.
        if (source.Length <= XxHash3Constants.MidSizeMaxBytes)
        {
            return Hash64Internal(source, seed, XxHash3Constants.DefaultSecret);
        }

        if (seed == 0)
        {
            return Hash64Internal(source, seed, XxHash3Constants.DefaultSecret);
        }

        Span<byte> customSecret = stackalloc byte[XxHash3Constants.SecretLengthBytes];
        DeriveSecretFromSeed(customSecret, seed);
        return Hash64Internal(source, seed, customSecret);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128 Hash128(ReadOnlySpan<byte> source, ulong seed = 0)
    {
        // For inputs <= 240 bytes, xxHash3 128-bit small-payload algorithms use DefaultSecret directly
        // and apply the seed arithmetically inside the hash functions.
        if (source.Length <= XxHash3Constants.MidSizeMaxBytes)
        {
            return Hash128Internal(source, seed, XxHash3Constants.DefaultSecret);
        }

        if (seed == 0)
        {
            return Hash128Internal(source, seed, XxHash3Constants.DefaultSecret);
        }

        Span<byte> customSecret = stackalloc byte[XxHash3Constants.SecretLengthBytes];
        DeriveSecretFromSeed(customSecret, seed);
        return Hash128Internal(source, seed, customSecret);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong Hash64Internal(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        if (len <= 16)
        {
            return Hash64Len0To16(source, seed, secret);
        }
        if (len <= 128)
        {
            return Hash64Len17To128(source, seed, secret);
        }
        if (len <= XxHash3Constants.MidSizeMaxBytes)
        {
            return Hash64Len129To240(source, seed, secret);
        }

        return Hash64Long(source, seed, secret);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static UInt128 Hash128Internal(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        if (len <= 16)
        {
            return Hash128Len0To16(source, seed, secret);
        }
        if (len <= 128)
        {
            return Hash128Len17To128(source, seed, secret);
        }
        if (len <= XxHash3Constants.MidSizeMaxBytes)
        {
            return Hash128Len129To240(source, seed, secret);
        }

        return Hash128Long(source, seed, secret);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len0To16(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        if (len > 8)
        {
            return Hash64Len9To16(source, seed, secret);
        }
        if (len >= 4)
        {
            return Hash64Len4To8(source, seed, secret);
        }
        if (len > 0)
        {
            return Hash64Len1To3(source, seed, secret);
        }

        ulong secretVal = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(56, 8)) ^
                          BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(64, 8));
        return Avalanche64(seed ^ secretVal);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len1To3(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        byte c1 = source[0];
        byte c2 = source[len >> 1];
        byte c3 = source[len - 1];
        uint combined = ((uint)c1 << 16) | ((uint)c2 << 24) | c3 | ((uint)len << 8);

        uint sec0 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(0, 4));
        uint sec4 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(4, 4));
        ulong bitflip = (sec0 ^ sec4) + seed;
        ulong keyed = (ulong)combined ^ bitflip;
        return Avalanche64(keyed);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len4To8(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        seed ^= (ulong)BinaryPrimitives.ReverseEndianness((uint)seed) << 32;

        uint input1 = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));
        uint input2 = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(len - 4, 4));
        ulong input64 = input2 + ((ulong)input1 << 32);

        ulong sec8 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(8, 8));
        ulong sec16 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(16, 8));
        ulong bitflip = (sec8 ^ sec16) - seed;
        ulong keyed = input64 ^ bitflip;
        return Rrmxmx(keyed, (ulong)len);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len9To16(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong sec24 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(24, 8));
        ulong sec32 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(32, 8));
        ulong sec40 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(40, 8));
        ulong sec48 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(48, 8));

        ulong bitflip1 = (sec24 ^ sec32) + seed;
        ulong bitflip2 = (sec40 ^ sec48) - seed;

        ulong inputLo = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(0, 8)) ^ bitflip1;
        ulong inputHi = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(len - 8, 8)) ^ bitflip2;

        ulong acc = (ulong)len + BinaryPrimitives.ReverseEndianness(inputLo) + inputHi + Multiply64To128ThenFold(inputLo, inputHi);
        return Avalanche(acc);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len17To128(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong acc = (ulong)len * XxHash3Constants.Prime64_1;

        if (len > 32)
        {
            if (len > 64)
            {
                if (len > 96)
                {
                    acc += Mix16Bytes(source.Slice(48, 16), secret.Slice(96, 16), seed);
                    acc += Mix16Bytes(source.Slice(len - 64, 16), secret.Slice(112, 16), seed);
                }
                acc += Mix16Bytes(source.Slice(32, 16), secret.Slice(64, 16), seed);
                acc += Mix16Bytes(source.Slice(len - 48, 16), secret.Slice(80, 16), seed);
            }
            acc += Mix16Bytes(source.Slice(16, 16), secret.Slice(32, 16), seed);
            acc += Mix16Bytes(source.Slice(len - 32, 16), secret.Slice(48, 16), seed);
        }
        acc += Mix16Bytes(source.Slice(0, 16), secret.Slice(0, 16), seed);
        acc += Mix16Bytes(source.Slice(len - 16, 16), secret.Slice(16, 16), seed);
        return Avalanche(acc);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64Len129To240(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong acc = (ulong)len * XxHash3Constants.Prime64_1;
        int nbRounds = len / 16;

        for (int i = 0; i < 8; i++)
        {
            acc += Mix16Bytes(source.Slice(16 * i, 16), secret.Slice(16 * i, 16), seed);
        }
        acc = Avalanche(acc);

        for (int i = 8; i < nbRounds; i++)
        {
            acc += Mix16Bytes(source.Slice(16 * i, 16), secret.Slice(16 * (i - 8) + 3, 16), seed);
        }
        acc += Mix16Bytes(source.Slice(len - 16, 16), secret.Slice(136 - 17, 16), seed);
        return Avalanche(acc);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static ulong Hash64Long(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        Span<ulong> acc = stackalloc ulong[XxHash3Constants.AccumulatorCount];
        XxHash3Constants.InitAccumulators.CopyTo(acc);

        fixed (ulong* pAcc = acc)
        fixed (byte* pSrc = source)
        fixed (byte* pSec = secret)
        {
            ProcessStripes(pAcc, pSrc, source.Length, pSec, secret.Length);
            return MergeAccumulators64(pAcc, pSec + XxHash3Constants.SecretMergeAccsStartBytes, (ulong)source.Length * XxHash3Constants.Prime64_1);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len0To16(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        if (len > 8)
        {
            return Hash128Len9To16(source, seed, secret);
        }
        if (len >= 4)
        {
            return Hash128Len4To8(source, seed, secret);
        }
        if (len > 0)
        {
            return Hash128Len1To3(source, seed, secret);
        }

        ulong sec64 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(64, 8));
        ulong sec72 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(72, 8));
        ulong sec80 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(80, 8));
        ulong sec88 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(88, 8));

        ulong low = Avalanche64(seed ^ (sec64 ^ sec72));
        ulong high = Avalanche64(seed ^ (sec80 ^ sec88));
        return new UInt128(high, low);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len1To3(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        byte c1 = source[0];
        byte c2 = source[len >> 1];
        byte c3 = source[len - 1];

        uint combinedL = ((uint)c1 << 16) | ((uint)c2 << 24) | c3 | ((uint)len << 8);
        uint combinedH = BitOperations.RotateLeft(BinaryPrimitives.ReverseEndianness(combinedL), 13);

        uint sec0 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(0, 4));
        uint sec4 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(4, 4));
        uint sec8 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(8, 4));
        uint sec12 = BinaryPrimitives.ReadUInt32LittleEndian(secret.Slice(12, 4));

        ulong bitflipL = (sec0 ^ sec4) + seed;
        ulong bitflipH = (sec8 ^ sec12) - seed;

        ulong low = Avalanche64((ulong)combinedL ^ bitflipL);
        ulong high = Avalanche64((ulong)combinedH ^ bitflipH);
        return new UInt128(high, low);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len4To8(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        seed ^= (ulong)BinaryPrimitives.ReverseEndianness((uint)seed) << 32;

        uint input1 = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(0, 4));
        uint input2 = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(len - 4, 4));
        ulong input64 = input1 + ((ulong)input2 << 32);

        ulong sec16 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(16, 8));
        ulong sec24 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(24, 8));
        ulong bitflip = (sec16 ^ sec24) + seed;

        ulong high = Math.BigMul(input64 ^ bitflip, XxHash3Constants.Prime64_1 + ((ulong)len << 2), out ulong low);
        high += low << 1;
        low ^= high >> 3;
        low ^= low >> 35;
        low *= RrmxmxPrime;
        low ^= low >> 28;
        high = Avalanche(high);
        return new UInt128(high, low);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len9To16(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong sec32 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(32, 8));
        ulong sec40 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(40, 8));
        ulong sec48 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(48, 8));
        ulong sec56 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(56, 8));

        ulong bitflip1 = (sec32 ^ sec40) - seed;
        ulong bitflip2 = (sec48 ^ sec56) + seed;

        ulong inputLo = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(0, 8));
        ulong inputHi = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(len - 8, 8));

        ulong mul1High = Math.BigMul(inputLo ^ inputHi ^ bitflip1, XxHash3Constants.Prime64_1, out ulong mul1Low);
        mul1Low += (ulong)(len - 1) << 54;
        inputHi ^= bitflip2;
        mul1High += inputHi + (ulong)(uint)inputHi * (XxHash3Constants.Prime32_2 - 1);
        mul1Low ^= BinaryPrimitives.ReverseEndianness(mul1High);

        ulong mul2High = Math.BigMul(mul1Low, XxHash3Constants.Prime64_2, out ulong mul2Low);
        mul2High += unchecked(mul1High * XxHash3Constants.Prime64_2);
        mul2Low = Avalanche(mul2Low);
        mul2High = Avalanche(mul2High);
        return new UInt128(mul2High, mul2Low);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len17To128(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong accLo = (ulong)len * XxHash3Constants.Prime64_1;
        ulong accHi = 0;

        switch ((len - 1) / 32)
        {
            default:
                Mix32Bytes(ref accLo, ref accHi, source.Slice(48, 16), source.Slice(len - 64, 16), secret.Slice(96, 32), seed);
                goto case 2;
            case 2:
                Mix32Bytes(ref accLo, ref accHi, source.Slice(32, 16), source.Slice(len - 48, 16), secret.Slice(64, 32), seed);
                goto case 1;
            case 1:
                Mix32Bytes(ref accLo, ref accHi, source.Slice(16, 16), source.Slice(len - 32, 16), secret.Slice(32, 32), seed);
                break;
            case 0:
                break;
        }
        Mix32Bytes(ref accLo, ref accHi, source.Slice(0, 16), source.Slice(len - 16, 16), secret.Slice(0, 32), seed);
        return AvalancheHash128(accLo, accHi, (uint)len, seed);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 Hash128Len129To240(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        int len = source.Length;
        ulong accLo = (ulong)len * XxHash3Constants.Prime64_1;
        ulong accHi = 0;

        Mix32Bytes(ref accLo, ref accHi, source.Slice(0, 16), source.Slice(16, 16), secret.Slice(0, 32), seed);
        Mix32Bytes(ref accLo, ref accHi, source.Slice(32, 16), source.Slice(48, 16), secret.Slice(32, 32), seed);
        Mix32Bytes(ref accLo, ref accHi, source.Slice(64, 16), source.Slice(80, 16), secret.Slice(64, 32), seed);
        Mix32Bytes(ref accLo, ref accHi, source.Slice(96, 16), source.Slice(112, 16), secret.Slice(96, 32), seed);
        accLo = Avalanche(accLo);
        accHi = Avalanche(accHi);

        uint num = (uint)(len - 128) / 32;
        if (num != 0)
        {
            Mix32Bytes(ref accLo, ref accHi, source.Slice(128, 16), source.Slice(144, 16), secret.Slice(128 - 125, 32), seed);
            if (num >= 2)
            {
                Mix32Bytes(ref accLo, ref accHi, source.Slice(160, 16), source.Slice(176, 16), secret.Slice(160 - 125, 32), seed);
                if (num == 3)
                {
                    Mix32Bytes(ref accLo, ref accHi, source.Slice(192, 16), source.Slice(208, 16), secret.Slice(192 - 125, 32), seed);
                }
            }
        }
        Mix32Bytes(ref accLo, ref accHi, source.Slice(len - 16, 16), source.Slice(len - 32, 16), secret.Slice(136 - 17 - 16, 32), 0 - seed);
        return AvalancheHash128(accLo, accHi, (uint)len, seed);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static UInt128 Hash128Long(ReadOnlySpan<byte> source, ulong seed, ReadOnlySpan<byte> secret)
    {
        Span<ulong> acc = stackalloc ulong[XxHash3Constants.AccumulatorCount];
        XxHash3Constants.InitAccumulators.CopyTo(acc);

        fixed (ulong* pAcc = acc)
        fixed (byte* pSrc = source)
        fixed (byte* pSec = secret)
        {
            ProcessStripes(pAcc, pSrc, source.Length, pSec, secret.Length);

            ulong low = MergeAccumulators64(pAcc, pSec + XxHash3Constants.SecretMergeAccsStartBytes, (ulong)source.Length * XxHash3Constants.Prime64_1);
            ulong high = MergeAccumulators64(pAcc, pSec + (secret.Length - XxHash3Constants.StripeLengthBytes - XxHash3Constants.SecretMergeAccsStartBytes), ~((ulong)source.Length * XxHash3Constants.Prime64_2));
            return new UInt128(high, low);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void ProcessStripes(ulong* accumulators, byte* source, int length, byte* secret, int secretLength)
    {
        int stripesPerBlock = (secretLength - XxHash3Constants.StripeLengthBytes) / XxHash3Constants.SecretConsumeRateBytes;
        int blockLength = stripesPerBlock * XxHash3Constants.StripeLengthBytes;
        int blocks = (length - 1) / blockLength;

        // Choose fast vectorized kernel based on CPU capabilities
        bool hasAvx512 = CpuCapabilities.HasAvx512F && XxHash3KernelAvx512.IsSupported;
        bool hasAvx2 = CpuCapabilities.HasAvx2 && XxHash3KernelAvx2.IsSupported;
        bool hasNeon = CpuCapabilities.IsArm64 && XxHash3KernelArmNeon.IsSupported;

        for (int b = 0; b < blocks; b++)
        {
            byte* blockSource = source + (b * blockLength);
            for (int s = 0; s < stripesPerBlock; s++)
            {
                byte* stripeSource = blockSource + (s * XxHash3Constants.StripeLengthBytes);
                byte* stripeSecret = secret + (s * XxHash3Constants.SecretConsumeRateBytes);

                if (hasAvx512)
                {
                    XxHash3KernelAvx512.AccumulateStripe(accumulators, stripeSource, stripeSecret);
                }
                else if (hasAvx2)
                {
                    XxHash3KernelAvx2.AccumulateStripe(accumulators, stripeSource, stripeSecret);
                }
                else if (hasNeon)
                {
                    XxHash3KernelArmNeon.AccumulateStripe(accumulators, stripeSource, stripeSecret);
                }
                else
                {
                    XxHash3KernelScalar.AccumulateStripe(accumulators, stripeSource, stripeSecret);
                }
            }

            byte* scrambleSecret = secret + secretLength - XxHash3Constants.StripeLengthBytes;
            if (hasAvx512)
            {
                XxHash3KernelAvx512.Scramble(accumulators, scrambleSecret);
            }
            else if (hasAvx2)
            {
                XxHash3KernelAvx2.Scramble(accumulators, scrambleSecret);
            }
            else if (hasNeon)
            {
                XxHash3KernelArmNeon.Scramble(accumulators, scrambleSecret);
            }
            else
            {
                XxHash3KernelScalar.Scramble(accumulators, scrambleSecret);
            }
        }

        // Final remaining block
        int stripesRemaining = ((length - 1) - (blocks * blockLength)) / XxHash3Constants.StripeLengthBytes;
        byte* lastBlockSource = source + (blocks * blockLength);

        for (int s = 0; s < stripesRemaining; s++)
        {
            byte* stripeSource = lastBlockSource + (s * XxHash3Constants.StripeLengthBytes);
            byte* stripeSecret = secret + (s * XxHash3Constants.SecretConsumeRateBytes);

            if (hasAvx512)
            {
                XxHash3KernelAvx512.AccumulateStripe(accumulators, stripeSource, stripeSecret);
            }
            else if (hasAvx2)
            {
                XxHash3KernelAvx2.AccumulateStripe(accumulators, stripeSource, stripeSecret);
            }
            else if (hasNeon)
            {
                XxHash3KernelArmNeon.AccumulateStripe(accumulators, stripeSource, stripeSecret);
            }
            else
            {
                XxHash3KernelScalar.AccumulateStripe(accumulators, stripeSource, stripeSecret);
            }
        }

        // Last stripe overlapping tail (source + length - 64)
        byte* tailStripe = source + length - XxHash3Constants.StripeLengthBytes;
        byte* tailSecret = secret + secretLength - XxHash3Constants.StripeLengthBytes - XxHash3Constants.SecretLastAccStartBytes;

        if (hasAvx512)
        {
            XxHash3KernelAvx512.AccumulateStripe(accumulators, tailStripe, tailSecret);
        }
        else if (hasAvx2)
        {
            XxHash3KernelAvx2.AccumulateStripe(accumulators, tailStripe, tailSecret);
        }
        else if (hasNeon)
        {
            XxHash3KernelArmNeon.AccumulateStripe(accumulators, tailStripe, tailSecret);
        }
        else
        {
            XxHash3KernelScalar.AccumulateStripe(accumulators, tailStripe, tailSecret);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong MergeAccumulators64(ulong* accumulators, byte* secret, ulong startVal)
    {
        ulong result = startVal;
        result += Multiply64To128ThenFold(accumulators[0] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 0, 8)),
                                          accumulators[1] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 8, 8)));
        result += Multiply64To128ThenFold(accumulators[2] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 16, 8)),
                                          accumulators[3] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 24, 8)));
        result += Multiply64To128ThenFold(accumulators[4] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 32, 8)),
                                          accumulators[5] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 40, 8)));
        result += Multiply64To128ThenFold(accumulators[6] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 48, 8)),
                                          accumulators[7] ^ BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(secret + 56, 8)));
        return Avalanche(result);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Mix32Bytes(ref ulong accLo, ref ulong accHi, ReadOnlySpan<byte> in1, ReadOnlySpan<byte> in2, ReadOnlySpan<byte> secret, ulong seed)
    {
        ulong in1Lo = BinaryPrimitives.ReadUInt64LittleEndian(in1.Slice(0, 8));
        ulong in1Hi = BinaryPrimitives.ReadUInt64LittleEndian(in1.Slice(8, 8));
        ulong in2Lo = BinaryPrimitives.ReadUInt64LittleEndian(in2.Slice(0, 8));
        ulong in2Hi = BinaryPrimitives.ReadUInt64LittleEndian(in2.Slice(8, 8));

        accLo += Mix16Bytes(in1, secret.Slice(0, 16), seed);
        accLo ^= in2Lo + in2Hi;

        accHi += Mix16Bytes(in2, secret.Slice(16, 16), seed);
        accHi ^= in1Lo + in1Hi;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 AvalancheHash128(ulong accLo, ulong accHi, uint len, ulong seed)
    {
        ulong hashLo = accLo + accHi;
        ulong hashHi = unchecked(accLo * XxHash3Constants.Prime64_1 + 
                                 accHi * XxHash3Constants.Prime64_4 + 
                                 ((ulong)len - seed) * XxHash3Constants.Prime64_2);
        ulong low = Avalanche(hashLo);
        ulong high = 0UL - Avalanche(hashHi);
        return new UInt128(high, low);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Mix16Bytes(ReadOnlySpan<byte> input, ReadOnlySpan<byte> secret, ulong seed)
    {
        ulong inputLow = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(0, 8));
        ulong inputHigh = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(8, 8));
        ulong secretLow = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(0, 8));
        ulong secretHigh = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(8, 8));
        return Multiply64To128ThenFold(inputLow ^ (secretLow + seed), inputHigh ^ (secretHigh - seed));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Multiply64To128ThenFold(ulong lhs, ulong rhs)
    {
        ulong low = Math.BigMul(lhs, rhs, out ulong high);
        return low ^ high;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Avalanche(ulong hash)
    {
        hash ^= hash >> 37;
        hash *= Xxh3AvalanchePrime;
        hash ^= hash >> 32;
        return hash;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Avalanche64(ulong hash)
    {
        hash ^= hash >> 33;
        hash *= XxHash3Constants.Prime64_2;
        hash ^= hash >> 29;
        hash *= XxHash3Constants.Prime64_3;
        hash ^= hash >> 32;
        return hash;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Rrmxmx(ulong h64, ulong len)
    {
        h64 ^= BitOperations.RotateLeft(h64, 49) ^ BitOperations.RotateLeft(h64, 24);
        h64 *= RrmxmxPrime;
        h64 ^= (h64 >> 35) + len;
        h64 *= RrmxmxPrime;
        return h64 ^ (h64 >> 28);
    }

    internal static void DeriveSecretFromSeed(Span<byte> customSecret, ulong seed)
    {
        for (int i = 0; i < XxHash3Constants.SecretLengthBytes; i += 16)
        {
            ulong s0 = BinaryPrimitives.ReadUInt64LittleEndian(XxHash3Constants.DefaultSecret.Slice(i, 8)) + seed;
            ulong s1 = BinaryPrimitives.ReadUInt64LittleEndian(XxHash3Constants.DefaultSecret.Slice(i + 8, 8)) - seed;
            BinaryPrimitives.WriteUInt64LittleEndian(customSecret.Slice(i, 8), s0);
            BinaryPrimitives.WriteUInt64LittleEndian(customSecret.Slice(i + 8, 8), s1);
        }
    }
}
