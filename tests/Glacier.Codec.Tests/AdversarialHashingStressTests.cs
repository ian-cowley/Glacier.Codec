namespace Glacier.Codec.Tests;

using System;
using System.Buffers.Binary;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Hashing.Sha256;
using Glacier.Codec.Hashing.XxHash3;

/// <summary>
/// Empirical Adversarial Stress & Fuzzing Harness for Milestone M2 (Glacier.Codec).
/// Authored by Empirical Challenger 1.
/// Verifies:
/// 1. BLAKE3 chunk boundary transitions, multi-chunk tree hashing, streaming equivalence, keyed MAC, KDF, and XOF.
/// 2. xxHash3 continuous length fuzzing (0 to 256 bytes) against BCL XxHash3, 64-bit and 128-bit parity, and fragmented streaming buffers.
/// 3. SHA-256 cross-check against System.Security.Cryptography.SHA256 across 10,000 random buffers (0B to 64KB) and fragmented streaming.
/// </summary>
public class AdversarialHashingStressTests
{
    // =========================================================================
    // 1. BLAKE3 CHUNK BOUNDARY & MERKLE TREE ADVERSARIAL STRESS
    // =========================================================================

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(2047)]
    [InlineData(2048)]
    [InlineData(2049)]
    [InlineData(3071)]
    [InlineData(3072)]
    [InlineData(3073)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(8192)]
    [InlineData(8193)]
    [InlineData(16384)]
    public void Blake3_ChunkBoundaries_OneShotVsStreaming1ByteAppends(int length)
    {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++)
        {
            buffer[i] = (byte)((i * 37 + 11) % 251);
        }

        Span<byte> oneShot = stackalloc byte[32];
        Blake3Hasher.Hash(buffer, oneShot);

        // Streaming with 1-byte appends across entire buffer
        using var streamHasher = new Blake3Hasher();
        for (int i = 0; i < length; i++)
        {
            streamHasher.Append(buffer.AsSpan(i, 1));
        }

        Span<byte> streamed = stackalloc byte[32];
        streamHasher.Finalize(streamed);

        Assert.True(oneShot.SequenceEqual(streamed),
            $"BLAKE3 mismatch for length {length}: OneShot={Convert.ToHexString(oneShot)} vs Streamed1B={Convert.ToHexString(streamed)}");
    }

    [Theory]
    [InlineData(1025, 7)]
    [InlineData(1025, 63)]
    [InlineData(1025, 64)]
    [InlineData(1025, 65)]
    [InlineData(2048, 13)]
    [InlineData(2049, 17)]
    [InlineData(4096, 511)]
    [InlineData(8192, 1024)]
    [InlineData(10000, 333)]
    public void Blake3_IrregularChunkSplits_MatchOneShot(int totalLength, int chunkSize)
    {
        byte[] buffer = new byte[totalLength];
        for (int i = 0; i < totalLength; i++)
        {
            buffer[i] = (byte)((i * 19 + 7) % 251);
        }

        Span<byte> oneShot = stackalloc byte[32];
        Blake3Hasher.Hash(buffer, oneShot);

        using var hasher = new Blake3Hasher();
        int offset = 0;
        while (offset < totalLength)
        {
            int take = Math.Min(chunkSize, totalLength - offset);
            hasher.Append(buffer.AsSpan(offset, take));
            offset += take;
        }

        Span<byte> streamed = stackalloc byte[32];
        hasher.Finalize(streamed);

        Assert.True(oneShot.SequenceEqual(streamed),
            $"BLAKE3 chunk split {chunkSize} mismatch for length {totalLength}");
    }

    [Theory]
    [InlineData(1)]  // 1 chunk
    [InlineData(2)]  // 2 chunks (exact binary pair)
    [InlineData(3)]  // 3 chunks (unbalanced tree)
    [InlineData(4)]  // 4 chunks (depth 2 complete)
    [InlineData(5)]  // 5 chunks
    [InlineData(7)]  // 7 chunks
    [InlineData(8)]  // 8 chunks (depth 3 complete)
    [InlineData(9)]  // 9 chunks
    [InlineData(15)] // 15 chunks
    [InlineData(16)] // 16 chunks
    [InlineData(17)] // 17 chunks
    [InlineData(32)] // 32 chunks
    [InlineData(33)] // 33 chunks
    public void Blake3_MultiChunkTreeReduction_DeterministicAcrossChunkCounts(int chunkCount)
    {
        int length = chunkCount * 1024;
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++)
        {
            buffer[i] = (byte)((i * 41 + 13) % 251);
        }

        Span<byte> hash1 = stackalloc byte[32];
        Blake3Hasher.Hash(buffer, hash1);

        Span<byte> hash2 = stackalloc byte[32];
        using var streamHasher = new Blake3Hasher();
        // Append in chunks of 1024
        for (int c = 0; c < chunkCount; c++)
        {
            streamHasher.Append(buffer.AsSpan(c * 1024, 1024));
        }
        streamHasher.Finalize(hash2);

        Assert.True(hash1.SequenceEqual(hash2),
            $"BLAKE3 tree reduction mismatch for {chunkCount} chunks ({length} bytes)");
        Assert.False(hash1.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void Blake3_KeyedHashing_ArbitraryLengthsMatchStreaming()
    {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)(i + 10);

        int[] lengths = [0, 1, 63, 64, 65, 500, 1023, 1024, 1025, 2048, 5000];
        Span<byte> oneShot = stackalloc byte[32];
        Span<byte> streamed = stackalloc byte[32];

        foreach (int len in lengths)
        {
            byte[] input = new byte[len];
            for (int i = 0; i < len; i++) input[i] = (byte)(i * 3 + 1);

            Blake3Hasher.HashKeyed(input, key, oneShot);

            using var hasher = new Blake3Hasher(key);
            int half = len / 2;
            hasher.Append(input.AsSpan(0, half));
            hasher.Append(input.AsSpan(half));
            hasher.Finalize(streamed);

            Assert.True(oneShot.SequenceEqual(streamed),
                $"BLAKE3 keyed hash mismatch for length {len}");
        }
    }

    [Fact]
    public void Blake3_KdfContextStringDerivation_ProducesDistinctKeys()
    {
        string[] contexts =
        [
            "MyApp 2026-10-23 Context A",
            "MyApp 2026-10-23 Context B",
            "VeryLongContextStringExceeding64BytesToEnsureProperChunkingAndInternalFlagsOperationAcrossCompressionFunctionRounds_1234567890",
            "Short"
        ];

        byte[][] keys = new byte[contexts.Length][];
        for (int i = 0; i < contexts.Length; i++)
        {
            using var kdf = Blake3Hasher.CreateKeyDerivation(contexts[i]);
            keys[i] = new byte[32];
            kdf.Finalize(keys[i]);
            Assert.False(keys[i].AsSpan().SequenceEqual(new byte[32]));
        }

        // Verify mutual uniqueness
        for (int i = 0; i < contexts.Length; i++)
        {
            for (int j = i + 1; j < contexts.Length; j++)
            {
                Assert.False(keys[i].AsSpan().SequenceEqual(keys[j]),
                    $"KDF produced identical keys for context '{contexts[i]}' and '{contexts[j]}'");
            }
        }
    }

    [Theory]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(100)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]
    public void Blake3_XofMultiBlockSqueezing_GeneratesExpectedLengthAndHighEntropy(int squeezeLength)
    {
        byte[] input = Encoding.UTF8.GetBytes("Adversarial XOF Test Input for Multi-Block Squeezing Verification");
        using var hasher = new Blake3Hasher();
        hasher.Append(input);

        byte[] squeezed = new byte[squeezeLength];
        hasher.Finalize(squeezed);

        // Check non-zero and high distinct byte entropy
        int zeroCount = 0;
        for (int i = 0; i < squeezeLength; i++)
        {
            if (squeezed[i] == 0) zeroCount++;
        }
        // Even in 1024 bytes, probability of more than 50% zeroes in cryptographic XOF is effectively 0
        Assert.True(zeroCount < squeezeLength / 2, $"XOF output contained excessive zeroes: {zeroCount}/{squeezeLength}");

        // If squeezed > 64, block 0 (bytes 0..63) and block 1 (bytes 64..127) must not be identical
        if (squeezeLength >= 128)
        {
            Assert.False(squeezed.AsSpan(0, 64).SequenceEqual(squeezed.AsSpan(64, 64)),
                "XOF repeated identical 64-byte blocks across block counter increments!");
        }
    }

    [Fact]
    public void Blake3_FinalizeSeek_MatchesSqueezeOffset()
    {
        byte[] input = Encoding.UTF8.GetBytes("Seeking test payload");
        using var hasher1 = new Blake3Hasher();
        hasher1.Append(input);
        byte[] fullSqueeze = new byte[192];
        hasher1.Finalize(fullSqueeze);

        // Seek to offset 70 and read 32 bytes
        using var hasher2 = new Blake3Hasher();
        hasher2.Append(input);
        byte[] seekSqueeze = new byte[32];
        hasher2.FinalizeSeek(70, seekSqueeze);

        Assert.True(fullSqueeze.AsSpan(70, 32).SequenceEqual(seekSqueeze),
            "FinalizeSeek(70, 32) did not match full squeezed stream at offset 70");
    }

    // =========================================================================
    // 2. XXHASH3 CONTINUOUS PAYLOAD FUZZING (0 to 256 BYTES) & STREAMING
    // =========================================================================

    [Fact]
    public void XxHash3_ContinuousFuzzing_Lengths0Through256_DefaultSeed_MatchBclXxHash3()
    {
        var rng = new Random(1337);

        for (int len = 0; len <= 256; len++)
        {
            byte[] payload = new byte[len];
            rng.NextBytes(payload);

            ulong expected = System.IO.Hashing.XxHash3.HashToUInt64(payload);
            ulong actual = XxHash3Hasher.Hash64(payload);
            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void XxHash3_ContinuousFuzzing_Lengths0Through256_CustomSeed_Analysis()
    {
        var rng = new Random(1337);
        var failuresOriginal = new System.Collections.Generic.List<int>();
        var failuresWithDefaultSecretForShort = new System.Collections.Generic.List<int>();

        Span<byte> customSecret = stackalloc byte[XxHash3Constants.SecretLengthBytes];

        for (int len = 0; len <= 256; len++)
        {
            byte[] payload = new byte[len];
            rng.NextBytes(payload);

            ulong seed = 123456789UL;
            ulong expectedSeeded = System.IO.Hashing.XxHash3.HashToUInt64(payload, (long)seed);
            ulong actualSeeded = XxHash3Hasher.Hash64(payload, seed);

            if (expectedSeeded != actualSeeded)
            {
                failuresOriginal.Add(len);
            }

            ulong actualShortDefault;
            if (len <= 240)
            {
                actualShortDefault = Glacier.Codec.Hashing.XxHash3.XxHash3.Hash64Internal(payload, seed, XxHash3Constants.DefaultSecret);
            }
            else
            {
                Glacier.Codec.Hashing.XxHash3.XxHash3.DeriveSecretFromSeed(customSecret, seed);
                actualShortDefault = Glacier.Codec.Hashing.XxHash3.XxHash3.Hash64Internal(payload, seed, customSecret);
            }

            if (expectedSeeded != actualShortDefault)
            {
                failuresWithDefaultSecretForShort.Add(len);
            }
        }

        Assert.Empty(failuresOriginal); // Fixed: lengths 0..256 now all match BCL seeded hashing
        Assert.True(failuresWithDefaultSecretForShort.Count == 0,
            $"Hypothesis check: failures with DefaultSecret for len<=240: {failuresWithDefaultSecretForShort.Count} failures [{string.Join(",", failuresWithDefaultSecretForShort.Take(10))}]");
    }

    [Fact]
    public void XxHash3_128Bit_MatchesOneShotAcrossContinuousLengths()
    {
        var rng = new Random(4242);
        Span<byte> streamDest = stackalloc byte[16];

        for (int len = 0; len <= 256; len++)
        {
            byte[] payload = new byte[len];
            rng.NextBytes(payload);

            UInt128 h128 = XxHash3Hasher.Hash128(payload);
            ulong low = (ulong)(h128 & ulong.MaxValue);
            ulong high = (ulong)(h128 >> 64);

            // 128-bit hash must not be completely zero
            Assert.False(low == 0 && high == 0, $"XxHash3 128-bit returned 0 for length {len}");

            // Verify streaming 128-bit matches one-shot
            using var stream128 = new XxHash3Stream(16, 0);
            stream128.Append(payload);
            stream128.Finalize(streamDest);

            ulong streamLow = BinaryPrimitives.ReadUInt64LittleEndian(streamDest);
            ulong streamHigh = BinaryPrimitives.ReadUInt64LittleEndian(streamDest.Slice(8));

            Assert.Equal(low, streamLow);
            Assert.Equal(high, streamHigh);
        }
    }

    [Fact]
    public void XxHash3_Streaming_FragmentedBuffers_MatchOneShot()
    {
        var rng = new Random(9999);

        // Test pathological fragmentation patterns:
        // Pattern 1: 3B + 19B + 500B + 1000B (crosses 240B shortcut and 1024B scrambler)
        int[] fragmentLengths = [3, 19, 500, 1000];
        int totalLen = 3 + 19 + 500 + 1000;
        byte[] fullPayload = new byte[totalLen];
        rng.NextBytes(fullPayload);

        using var streamHasher = new XxHash3Hasher();
        int offset = 0;
        foreach (int fragLen in fragmentLengths)
        {
            streamHasher.Append(fullPayload.AsSpan(offset, fragLen));
            offset += fragLen;
        }

        Span<byte> streamDigest = stackalloc byte[8];
        streamHasher.Finalize(streamDigest);

        ulong streamed = BinaryPrimitives.ReadUInt64LittleEndian(streamDigest);
        ulong oneShot = XxHash3Hasher.Hash64(fullPayload);
        ulong bcl = System.IO.Hashing.XxHash3.HashToUInt64(fullPayload);

        Assert.Equal(bcl, oneShot);
        Assert.Equal(oneShot, streamed);
    }

    [Theory]
    [InlineData(239, 1, 1)]      // Around 240B threshold
    [InlineData(240, 1, 0)]      // Exactly 241B
    [InlineData(1023, 1, 1)]     // Around 1024B scrambler threshold
    [InlineData(1024, 1, 1)]     // Crosses 1024B scrambler
    [InlineData(100, 100, 100)]  // 300B (exceeds 240B via small chunks)
    [InlineData(64, 64, 64)]     // Stripe multiples
    public void XxHash3_Streaming_ThresholdBoundaryFragments_MatchOneShot(int chunk1, int chunk2, int chunk3)
    {
        int total = chunk1 + chunk2 + chunk3;
        byte[] payload = new byte[total];
        for (int i = 0; i < total; i++) payload[i] = (byte)((i * 23 + 5) % 256);

        using var streamHasher = new XxHash3Hasher();
        streamHasher.Append(payload.AsSpan(0, chunk1));
        if (chunk2 > 0) streamHasher.Append(payload.AsSpan(chunk1, chunk2));
        if (chunk3 > 0) streamHasher.Append(payload.AsSpan(chunk1 + chunk2, chunk3));

        Span<byte> dest = stackalloc byte[8];
        streamHasher.Finalize(dest);
        ulong streamed = BinaryPrimitives.ReadUInt64LittleEndian(dest);

        ulong expected = System.IO.Hashing.XxHash3.HashToUInt64(payload);
        Assert.Equal(expected, streamed);
    }

    // =========================================================================
    // 3. SHA-256 10,000 RANDOM BUFFERS CROSS-CHECK AGAINST BCL
    // =========================================================================

    [Fact]
    public void Sha256_CrossCheckAgainstBcl_10000RandomBuffers()
    {
        var rng = new Random(42); // Deterministic seed

        Span<byte> glacierHash = stackalloc byte[32];
        Span<byte> bclHash = stackalloc byte[32];

        // 10,000 test cases with diverse distribution:
        // - Dense testing around 0..130 bytes (boundary conditions: 0, 55, 56, 64, 119, 120, 128)
        // - Medium payloads (129..2048 bytes)
        // - Larger payloads up to 65,536 bytes (64 KB)
        for (int iteration = 0; iteration < 10_000; iteration++)
        {
            int length;
            if (iteration < 2000)
            {
                // Dense boundary testing: lengths 0 to 130
                length = iteration % 131;
            }
            else if (iteration < 6000)
            {
                // Power-of-two boundaries and offsets +/- 3
                int baseExp = rng.Next(6, 12); // 64 to 2048
                int delta = rng.Next(-3, 4);
                length = Math.Clamp((1 << baseExp) + delta, 0, 4096);
            }
            else if (iteration < 9000)
            {
                // Uniform random between 128 and 4096 bytes
                length = rng.Next(128, 4096);
            }
            else
            {
                // Large buffers up to 64 KB
                length = rng.Next(4096, 65536);
            }

            byte[] buffer = new byte[length];
            rng.NextBytes(buffer);

            // Compute via Glacier.Codec Sha256
            Sha256.Hash(buffer, glacierHash);

            // Compute via System.Security.Cryptography.SHA256
            System.Security.Cryptography.SHA256.HashData(buffer, bclHash);

            if (!CryptographicOperations.FixedTimeEquals(glacierHash, bclHash))
            {
                Assert.Fail($"SHA-256 mismatch at iteration {iteration} (length {length}): " +
                            $"Glacier={Convert.ToHexString(glacierHash)} vs BCL={Convert.ToHexString(bclHash)}");
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(119)]
    [InlineData(120)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(1000)]
    public void Sha256_StreamingHasher_FragmentedAppends_MatchesBcl(int length)
    {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++) buffer[i] = (byte)((i * 17 + 3) % 256);

        Span<byte> bclHash = stackalloc byte[32];
        System.Security.Cryptography.SHA256.HashData(buffer, bclHash);

        // Test 1-byte appends
        using var streamHasher = new Sha256Hasher();
        for (int i = 0; i < length; i++)
        {
            streamHasher.Append(buffer.AsSpan(i, 1));
        }

        Span<byte> streamHash = stackalloc byte[32];
        streamHasher.Finalize(streamHash);

        Assert.True(CryptographicOperations.FixedTimeEquals(streamHash, bclHash),
            $"Streaming SHA-256 mismatch for length {length}");
    }
}
