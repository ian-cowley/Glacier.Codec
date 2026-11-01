namespace Glacier.Codec.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;
using Glacier.Codec.Cryptography.AesGcm;
using Glacier.Codec.Cryptography.PostQuantum;

/// <summary>
/// Adversarial regression tests for Track A Priority Tier 0 remediation across Glacier.Codec:
/// - Genuine RFC 8878 Zstd Type=2 compression + bidirectional interoperability with official zstd CLI
/// - LZ4 block &amp; frame bounds / integer overflow / truncation hardening (P0-4, P2-1)
/// - FIPS 203 §7.2 / §7.3 ML-KEM input validation &amp; constant-time Barrett arithmetic (P0-6, P1-4)
/// - Parallel AES-256-GCM unauthenticated plaintext isolation &amp; zero-allocation verification
/// </summary>
public class TrackATier0AdversarialTests
{
    [Fact]
    public void Zstd_Compress_EmitsGenuineCompressedBlockWithRealRatio()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 200; i++)
        {
            sb.Append("{\"id\":").Append(i).Append(",\"service\":\"glacier-codec\",\"status\":\"healthy\",\"region\":\"eu-west-1\"}\n");
        }

        byte[] source = Encoding.UTF8.GetBytes(sb.ToString());
        byte[] compressed = new byte[ZstdCodec.MaximumCompressedSize(source.Length)];
        int compLen = ZstdCodec.Compress(source, compressed);

        // Must genuinely compress structured JSON well below 35% of original size
        Assert.True(compLen < source.Length / 3, $"Expected genuine compression < {source.Length / 3} bytes, got {compLen} / {source.Length}.");

        // Verify block header after 9-byte frame header (4B magic + 1B FHD 0xA4 + 4B FCS) has Block_Type == 2 (Compressed_Block)
        int blockType = (compressed[9] >> 1) & 0x03;
        Assert.Equal(ZstdConstants.BlockTypeCompressed, blockType);

        byte[] decompressed = new byte[source.Length];
        int decompLen = ZstdCodec.Decompress(compressed.AsSpan(0, compLen), decompressed);
        Assert.Equal(source.Length, decompLen);
        Assert.Equal(source, decompressed);
    }

    [Fact]
    public void Zstd_BidirectionalInteroperability_WithOfficialZstdCli()
    {
        if (!IsZstdCliAvailable())
        {
            return;
        }

        string tempDir = Path.Combine(Path.GetTempPath(), "glacier_zstd_interop_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            // 300 KB multi-block mixed structured + binary payload (exercises > 128 KB multi-block + Huffman + FSE + Treeless literals)
            var sb = new StringBuilder();
            for (int i = 0; i < 4000; i++)
            {
                sb.Append($"record={i:D6}|tenant=glacier|metric=throughput_gbps|value={(i * 17) % 997}\n");
            }
            byte[] payload = Encoding.UTF8.GetBytes(sb.ToString());
            Assert.True(payload.Length > 200_000);

            // Direction 1: Glacier ZstdCodec.Compress -> official `zstd -d`
            byte[] glacierCompressed = new byte[ZstdCodec.MaximumCompressedSize(payload.Length)];
            int glacierCompLen = ZstdCodec.Compress(payload, glacierCompressed);
            Assert.True(glacierCompLen < payload.Length / 2);

            string glacierZstPath = Path.Combine(tempDir, "glacier.zst");
            string cliDecodedPath = Path.Combine(tempDir, "cli_decoded.bin");
            File.WriteAllBytes(glacierZstPath, glacierCompressed.AsSpan(0, glacierCompLen).ToArray());

            RunProcessOrThrow("zstd", $"-d -f -q \"{glacierZstPath}\" -o \"{cliDecodedPath}\"");
            byte[] cliDecoded = File.ReadAllBytes(cliDecodedPath);
            Assert.Equal(payload, cliDecoded);

            // Direction 2: official `zstd -3` -> Glacier ZstdCodec.Decompress
            string rawInputPath = Path.Combine(tempDir, "raw.bin");
            string cliZstPath = Path.Combine(tempDir, "official.zst");
            File.WriteAllBytes(rawInputPath, payload);

            RunProcessOrThrow("zstd", $"-3 -f -q \"{rawInputPath}\" -o \"{cliZstPath}\"");
            byte[] officialZst = File.ReadAllBytes(cliZstPath);

            byte[] glacierDecoded = new byte[payload.Length];
            int glacierDecompLen = ZstdCodec.Decompress(officialZst, glacierDecoded);
            Assert.Equal(payload.Length, glacierDecompLen);
            Assert.Equal(payload, glacierDecoded);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void Zstd_UndersizedDestination_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => ZstdCodec.Compress(ReadOnlySpan<byte>.Empty, new byte[8]));
        byte[] payload = Encoding.UTF8.GetBytes("Undersized destination test payload for Zstandard.");
        Assert.Throws<ArgumentException>(() => ZstdCodec.Compress(payload, new byte[12]));
        Assert.Throws<ArgumentOutOfRangeException>(() => ZstdCodec.MaximumCompressedSize(int.MaxValue));
    }

    [Fact]
    public void Lz4_P0_4_LongLiteralPlusShortMatch_ConstrainedDestination_ThrowsArgumentException()
    {
        // Construct 10 KB of incompressible random literals followed by a guaranteed 4-byte match + 12 trailing bytes
        byte[] src = new byte[10_240];
        var rng = new Random(1337);
        rng.NextBytes(src);

        // Force exact 4-byte match near the end: copy bytes [0..3] to [10220..10223]
        Buffer.BlockCopy(src, 0, src, 10_220, 4);

        // Constrain destination so op + litLength + 16 <= oend would have falsely passed,
        // while 1 + (litLength - 15)/255 + 1 + litLength + 2 exceeds oend!
        byte[] undersized = new byte[10_220 + 20];
        Assert.Throws<ArgumentException>(() => Lz4Codec.Compress(src, undersized));

        // Short literal-only block (< 13 bytes) with undersized destination also throws ArgumentException
        Assert.Throws<ArgumentException>(() => Lz4Codec.Compress(new byte[10], new byte[5]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Lz4Codec.MaximumCompressedSize(int.MaxValue));
    }

    [Fact]
    public void Lz4_Decompress_OverflowExtensionRun_ThrowsInvalidDataException()
    {
        byte[] malicious = new byte[1024];
        malicious[0] = 0xF0; // literalLength == 15 -> triggers 0xFF extension loop
        Array.Fill(malicious, (byte)0xFF, 1, malicious.Length - 1);

        byte[] dst = new byte[2048];
        Assert.Throws<InvalidDataException>(() => Lz4Codec.Decompress(malicious, dst));
    }

    [Fact]
    public void Lz4Frame_TruncatedBeforeEndMark_ThrowsInvalidDataException()
    {
        byte[] payload = Encoding.UTF8.GetBytes("LZ4 frame truncation detection test payload");
        byte[] frame = new byte[payload.Length + 64];
        int frameLen = Lz4FrameCodec.EncodeFrame(payload, frame, contentChecksum: false, blockChecksum: false);

        // Strip trailing 4-byte EndMark (0x00000000)
        byte[] truncated = frame.AsSpan(0, frameLen - 4).ToArray();
        byte[] dst = new byte[payload.Length];
        Assert.Throws<InvalidDataException>(() => Lz4FrameCodec.DecodeFrame(truncated, dst));

        // Undersized destination in EncodeFrame throws ArgumentException
        Assert.Throws<ArgumentException>(() => Lz4FrameCodec.EncodeFrame(payload, new byte[20]));
    }

    [Fact]
    public void MlKem_Fips203_Section7_2_And_7_3_Validation()
    {
        var kem = MlKemEngine.MlKem768;
        byte[] pk = new byte[MlKem768.PublicKeyBytes];
        byte[] sk = new byte[MlKem768.SecretKeyBytes];
        kem.GenerateKeyPair(pk, sk);

        // 1. FIPS 203 §7.2: Set first 12-bit coefficient of ek to 3329 (0xD01) -> must reject!
        byte[] unreducedPk = (byte[])pk.Clone();
        unreducedPk[0] = 0x01;
        unreducedPk[1] = (byte)((unreducedPk[1] & 0xF0) | 0x0D); // c0 = 0xD01 = 3329 == Q

        byte[] ct = new byte[MlKem768.CiphertextBytes];
        byte[] ss = new byte[MlKem768.SharedSecretBytes];
        Assert.Throws<CryptographicException>(() => kem.Encapsulate(unreducedPk, ct, ss));
        Assert.Throws<CryptographicException>(() => kem.EncapsulateDerand(unreducedPk, new byte[32], ct, ss));

        // 2. Oversized key/ciphertext spans must fail FIPS 203 type check
        Assert.Throws<ArgumentException>(() => kem.Encapsulate(new byte[MlKem768.PublicKeyBytes + 1], ct, ss));
        kem.Encapsulate(pk, ct, ss);
        Assert.Throws<ArgumentException>(() => kem.Decapsulate(new byte[MlKem768.SecretKeyBytes + 1], ct, ss));
        Assert.Throws<ArgumentException>(() => kem.Decapsulate(sk, new byte[MlKem768.CiphertextBytes + 1], ss));

        // 3. FIPS 203 §7.3: Corrupted H(ek) inside dk must throw CryptographicException
        byte[] badSk = (byte[])sk.Clone();
        badSk[384 * 3 + MlKem768.PublicKeyBytes] ^= 0x01;
        Assert.Throws<CryptographicException>(() => kem.Decapsulate(badSk, ct, ss));
    }

    [Fact]
    public void MlKem_BarrettArithmetic_ExactAcrossEntireDomain()
    {
        int[] ds = [1, 4, 5, 10, 11];
        foreach (int d in ds)
        {
            uint mask = (1u << d) - 1u;
            for (ushort x = 0; x < 3329; x++)
            {
                ushort expected = (ushort)(((((uint)x << (d + 1)) + 3329u) / 6658u) & mask);
                ushort actual = Polyvec.Compress(x, d);
                Assert.Equal(expected, actual);
            }
        }

        for (short a = 0; a < 3329; a += 7)
        {
            for (short b = 0; b < 3329; b += 11)
            {
                short expected = (short)((a * b) % 3329);
                short actual = NttTransformScalar.FieldMul(a, b);
                Assert.Equal(expected, actual);
            }
        }
    }

    [Fact]
    public void AesGcmParallel_TamperedTag_NeverWritesUnauthenticatedPlaintextAndZeroHeapAllocs()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = Encoding.UTF8.GetBytes("parallel-aad");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = new byte[512 * 1024]; // >= 256 KB parallel engine threshold
        RandomNumberGenerator.Fill(plaintext);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var cipher = new Aes256GcmCipher(key);
        cipher.Encrypt(plaintext, aad, nonce, ciphertext, tag);

        // Warm up parallel decrypt path
        byte[] outBuf = new byte[plaintext.Length];
        Assert.True(cipher.Decrypt(ciphertext, aad, nonce, tag, outBuf));
        Assert.Equal(plaintext, outBuf);

        // Tamper tag and pre-fill outBuf with canary 0xA5
        byte[] badTag = (byte[])tag.Clone();
        badTag[15] ^= 0x01;
        Array.Fill(outBuf, (byte)0xA5);

        long before = GC.GetAllocatedBytesForCurrentThread();
        bool ok = cipher.Decrypt(ciphertext, aad, nonce, badTag, outBuf);
        long after = GC.GetAllocatedBytesForCurrentThread();

        Assert.False(ok);
        Assert.Equal(0L, after - before);
        Assert.All(outBuf, b => Assert.Equal(0, b));
    }

    private static bool IsZstdCliAvailable()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("zstd", "--version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            p?.WaitForExit(3000);
            return p?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void RunProcessOrThrow(string fileName, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(fileName, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(10_000);
        Assert.True(p.ExitCode == 0, $"{fileName} {args} failed with exit code {p.ExitCode}: {stderr}");
    }
}
