namespace Glacier.Codec.Benchmarks;

using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using Glacier.Codec.Compression.Lz4;
using Glacier.Codec.Compression.Zstd;

[MemoryDiagnoser]
[BenchmarkCategory("Compression")]
public class CompressionThroughputBenchmarks
{
    [Params(65536, 1048576)]
    public int PayloadSize { get; set; }

    private byte[] _uncompressed = null!;
    private byte[] _compressBlockDest = null!;
    private byte[] _compressFrameDest = null!;
    private byte[] _compressZstdDest = null!;
    private byte[] _lz4BlockCompressed = null!;
    private byte[] _lz4FrameCompressed = null!;
    private byte[] _zstdCompressed = null!;
    private byte[] _decompressed = null!;

    [GlobalSetup]
    public void Setup()
    {
        _uncompressed = new byte[PayloadSize];
        _decompressed = new byte[PayloadSize];

        // Synthesize realistic tabular / log data with compressible patterns
        string samplePattern = "2026-10-24T12:00:00.000Z [INFO] Host=192.168.1.111 Service=Glacier.Codec RequestId=7f8b2c4e-1234 Status=200 Latency=1.42ms\n";
        byte[] patternBytes = Encoding.UTF8.GetBytes(samplePattern);
        for (int i = 0; i < PayloadSize; i += patternBytes.Length)
        {
            int copyLen = Math.Min(patternBytes.Length, PayloadSize - i);
            Array.Copy(patternBytes, 0, _uncompressed, i, copyLen);
        }

        int maxLz4 = Lz4Codec.MaximumCompressedSize(PayloadSize);
        _compressBlockDest = new byte[maxLz4];
        _compressFrameDest = new byte[maxLz4 + 1024];
        _lz4BlockCompressed = new byte[maxLz4];
        _lz4FrameCompressed = new byte[maxLz4 + 1024];

        int maxZstd = ZstdCodec.MaximumCompressedSize(PayloadSize);
        _compressZstdDest = new byte[maxZstd];
        _zstdCompressed = new byte[maxZstd];

        // Pre-compress for decompression benchmarks
        int lz4Len = Lz4Codec.Compress(_uncompressed, _lz4BlockCompressed);
        Array.Resize(ref _lz4BlockCompressed, lz4Len);

        int lz4FrameLen = Lz4FrameCodec.EncodeFrame(_uncompressed, _lz4FrameCompressed);
        Array.Resize(ref _lz4FrameCompressed, lz4FrameLen);

        int zstdLen = ZstdCodec.Compress(_uncompressed, _zstdCompressed);
        Array.Resize(ref _zstdCompressed, zstdLen);
    }

    [Benchmark(Description = "LZ4 Compress Block")]
    public int Lz4_CompressBlock()
    {
        return Lz4Codec.Compress(_uncompressed, _compressBlockDest);
    }

    [Benchmark(Description = "LZ4 Decompress Block")]
    public int Lz4_DecompressBlock()
    {
        return Lz4Codec.Decompress(_lz4BlockCompressed, _decompressed);
    }

    [Benchmark(Description = "LZ4 Frame Encode")]
    public int Lz4Frame_Encode()
    {
        return Lz4FrameCodec.EncodeFrame(_uncompressed, _compressFrameDest);
    }

    [Benchmark(Description = "LZ4 Frame Decode")]
    public int Lz4Frame_Decode()
    {
        return Lz4FrameCodec.DecodeFrame(_lz4FrameCompressed, _decompressed);
    }

    [Benchmark(Description = "Zstd Compress Frame (RFC 8878)")]
    public int Zstd_Compress()
    {
        return ZstdCodec.Compress(_uncompressed, _compressZstdDest);
    }

    [Benchmark(Description = "Zstd Decompress Frame (RFC 8878)")]
    public int Zstd_Decompress()
    {
        return ZstdCodec.Decompress(_zstdCompressed, _decompressed);
    }
}
