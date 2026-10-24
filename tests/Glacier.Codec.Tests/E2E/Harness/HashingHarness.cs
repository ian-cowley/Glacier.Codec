#if !HAS_GLACIER_CODEC_HASHING

using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Glacier.Codec.Hashing;

namespace Glacier.Codec.Hashing.Sha256
{
    public sealed class Sha256Hasher : IStreamingHasher
    {
        private readonly IncrementalHash _hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool _disposed;

        public int HashSizeInBytes => 32;

        public void Reset()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Sha256Hasher));
            Span<byte> dummy = stackalloc byte[32];
            _hasher.GetHashAndReset(dummy);
        }

        public void Append(ReadOnlySpan<byte> data)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Sha256Hasher));
            _hasher.AppendData(data);
        }

        public void GetCurrentHash(Span<byte> destination)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Sha256Hasher));
            if (destination.Length < 32) throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));
            _hasher.GetCurrentHash(destination);
        }

        public void Finalize(Span<byte> destination)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Sha256Hasher));
            if (destination.Length < 32) throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));
            _hasher.GetHashAndReset(destination);
        }

        public static void Hash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            if (destination.Length < 32) throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));
            System.Security.Cryptography.SHA256.HashData(input, destination);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _hasher.Dispose();
                _disposed = true;
            }
        }
    }
}

namespace Glacier.Codec.Hashing.Blake3
{
    public sealed class Blake3Hasher : IKeyedHasher
    {
        private static readonly uint[] IV = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        ];

        private static readonly byte[] MSG_PERMUTATION = [
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
        ];

        private readonly uint[] _key = new uint[8];
        private readonly List<byte> _buffer = new();
        private Blake3Flags _flags;
        private bool _disposed;

        public int HashSizeInBytes => 32;

        public Blake3Hasher()
        {
            Array.Copy(IV, _key, 8);
            _flags = Blake3Flags.None;
        }

        public Blake3Hasher(ReadOnlySpan<byte> key)
        {
            SetKey(key);
            _flags = Blake3Flags.KeyedHash;
        }

        public static Blake3Hasher CreateKeyDerivation(string context)
        {
            var hasher = new Blake3Hasher();
            hasher._flags = Blake3Flags.DeriveKeyContext;
            Span<byte> contextBytes = System.Text.Encoding.UTF8.GetBytes(context);
            hasher.Append(contextBytes);
            Span<byte> contextHash = stackalloc byte[32];
            hasher.Finalize(contextHash);

            var kdfHasher = new Blake3Hasher(contextHash);
            kdfHasher._flags = Blake3Flags.DeriveKeyMaterial;
            return kdfHasher;
        }

        public void SetKey(ReadOnlySpan<byte> key)
        {
            if (key.Length != 32)
                throw new ArgumentException("BLAKE3 key must be exactly 32 bytes.", nameof(key));

            for (int i = 0; i < 8; i++)
            {
                _key[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            }
            _flags |= Blake3Flags.KeyedHash;
        }

        public void Reset()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Blake3Hasher));
            _buffer.Clear();
        }

        public void Append(ReadOnlySpan<byte> data)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Blake3Hasher));
            for (int i = 0; i < data.Length; i++)
            {
                _buffer.Add(data[i]);
            }
        }

        public void GetCurrentHash(Span<byte> destination)
        {
            ComputeHashInternal(CollectionsMarshal.AsSpan(_buffer), destination, seekOffset: 0);
        }

        public void Finalize(Span<byte> destination)
        {
            GetCurrentHash(destination);
            Reset();
        }

        public void FinalizeSeek(ulong seekOffset, Span<byte> destination)
        {
            ComputeHashInternal(CollectionsMarshal.AsSpan(_buffer), destination, seekOffset);
            Reset();
        }

        public static void Hash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            using var hasher = new Blake3Hasher();
            hasher.Append(input);
            hasher.Finalize(destination);
        }

        public static void HashKeyed(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, Span<byte> destination)
        {
            using var hasher = new Blake3Hasher(key);
            hasher.Append(input);
            hasher.Finalize(destination);
        }

        private void ComputeHashInternal(ReadOnlySpan<byte> input, Span<byte> destination, ulong seekOffset)
        {
            if (destination.Length < 32)
                throw new ArgumentException("Destination span must be at least 32 bytes.", nameof(destination));

            // Chunk tree reduction
            if (input.Length <= 1024)
            {
                // Single chunk root
                uint flags = (uint)_flags | (uint)(Blake3Flags.ChunkStart | Blake3Flags.ChunkEnd | Blake3Flags.Root);
                CompressChunkRoot(_key, input, 0, flags, seekOffset, destination);
                return;
            }

            // Multi-chunk tree reduction
            int chunkCount = (input.Length + 1023) / 1024;
            Span<byte> cvStack = stackalloc byte[chunkCount * 32];
            for (int c = 0; c < chunkCount; c++)
            {
                int chunkOffset = c * 1024;
                int chunkLen = Math.Min(1024, input.Length - chunkOffset);
                ReadOnlySpan<byte> chunkData = input.Slice(chunkOffset, chunkLen);
                uint flags = (uint)_flags | (uint)(Blake3Flags.ChunkStart | Blake3Flags.ChunkEnd);
                CompressChunkRoot(_key, chunkData, (ulong)c, flags, 0, cvStack.Slice(c * 32, 32));
            }

            // Binary tree reduction over chunk CVs
            int currentNodes = chunkCount;
            Span<byte> currentCVs = stackalloc byte[chunkCount * 32];
            Span<byte> nextCVs = stackalloc byte[chunkCount * 32];
            cvStack.CopyTo(currentCVs);

            while (currentNodes > 1)
            {
                int nextNodes = (currentNodes + 1) / 2;

                for (int i = 0; i < currentNodes / 2; i++)
                {
                    bool isRoot = (nextNodes == 1) && ((currentNodes % 2) == 0);
                    uint pFlags = (uint)_flags | (uint)Blake3Flags.Parent;
                    if (isRoot) pFlags |= (uint)Blake3Flags.Root;

                    ReadOnlySpan<byte> parentBlock = currentCVs.Slice(i * 64, 64);
                    if (isRoot)
                    {
                        CompressNodeRoot(_key, parentBlock, 0, pFlags, seekOffset, destination);
                        return;
                    }
                    CompressNodeCV(_key, parentBlock, 0, pFlags, nextCVs.Slice(i * 32, 32));
                }

                if (currentNodes % 2 != 0)
                {
                    // Carry over odd node
                    currentCVs.Slice((currentNodes - 1) * 32, 32).CopyTo(nextCVs.Slice((nextNodes - 1) * 32, 32));
                }

                currentNodes = nextNodes;
                currentCVs = nextCVs;
            }

            currentCVs.Slice(0, 32).CopyTo(destination);
        }

        private static void CompressChunkRoot(uint[] key, ReadOnlySpan<byte> chunk, ulong chunkCounter, uint flags, ulong seekOffset, Span<byte> destination)
        {
            int blockCount = (chunk.Length + 63) / 64;
            if (blockCount == 0) blockCount = 1;

            uint[] cv = (uint[])key.Clone();
            for (int b = 0; b < blockCount; b++)
            {
                int blockOffset = b * 64;
                int blockLen = Math.Min(64, Math.Max(0, chunk.Length - blockOffset));
                ReadOnlySpan<byte> blockBytes = chunk.Length > 0 ? chunk.Slice(blockOffset, blockLen) : ReadOnlySpan<byte>.Empty;

                uint blockFlags = flags;
                if (b == 0) blockFlags |= (uint)Blake3Flags.ChunkStart;
                else blockFlags &= ~(uint)Blake3Flags.ChunkStart;

                if (b == blockCount - 1) blockFlags |= (uint)Blake3Flags.ChunkEnd;
                else blockFlags &= ~(uint)(Blake3Flags.Root | Blake3Flags.ChunkEnd);

                if (b == blockCount - 1 && (flags & (uint)Blake3Flags.Root) != 0)
                {
                    CompressBlockOutput(cv, blockBytes, chunkCounter, (uint)blockLen, blockFlags, seekOffset, destination);
                }
                else
                {
                    CompressBlock(cv, blockBytes, chunkCounter, (uint)blockLen, blockFlags, cv);
                    if (b == blockCount - 1)
                    {
                        for (int i = 0; i < 8; i++)
                        {
                            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(i * 4, 4), cv[i]);
                        }
                    }
                }
            }
        }

        private static void CompressNodeCV(uint[] key, ReadOnlySpan<byte> block, ulong counter, uint flags, Span<byte> destination)
        {
            uint[] outCV = new uint[8];
            CompressBlock(key, block, counter, 64, flags, outCV);
            for (int i = 0; i < 8; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(i * 4, 4), outCV[i]);
            }
        }

        private static void CompressNodeRoot(uint[] key, ReadOnlySpan<byte> block, ulong counter, uint flags, ulong seekOffset, Span<byte> destination)
        {
            CompressBlockOutput(key, block, counter, 64, flags, seekOffset, destination);
        }

        private static void CompressBlock(uint[] cv, ReadOnlySpan<byte> block, ulong counter, uint blockLen, uint flags, uint[] outCV)
        {
            Span<uint> state = stackalloc uint[16];
            InitState(state, cv, counter, blockLen, flags);
            Span<uint> m = stackalloc uint[16];
            DecodeBlockWords(block, m);
            Rounds(state, m);

            for (int i = 0; i < 8; i++)
            {
                outCV[i] = state[i] ^ state[i + 8];
            }
        }

        private static void CompressBlockOutput(uint[] cv, ReadOnlySpan<byte> block, ulong counter, uint blockLen, uint flags, ulong seekOffset, Span<byte> destination)
        {
            Span<uint> state = stackalloc uint[16];
            InitState(state, cv, counter, blockLen, flags);
            Span<uint> m = stackalloc uint[16];
            DecodeBlockWords(block, m);
            Rounds(state, m);

            int wordsToEmit = Math.Min(16, destination.Length / 4);
            for (int i = 0; i < wordsToEmit; i++)
            {
                uint word = (i < 8) ? (state[i] ^ state[i + 8]) : (state[i] ^ cv[i - 8]);
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(i * 4, 4), word);
            }
        }

        private static void InitState(Span<uint> state, uint[] cv, ulong counter, uint blockLen, uint flags)
        {
            for (int i = 0; i < 8; i++) state[i] = cv[i];
            state[8] = IV[0]; state[9] = IV[1]; state[10] = IV[2]; state[11] = IV[3];
            state[12] = (uint)counter;
            state[13] = (uint)(counter >> 32);
            state[14] = blockLen;
            state[15] = flags;
        }

        private static void DecodeBlockWords(ReadOnlySpan<byte> block, Span<uint> m)
        {
            m.Clear();
            for (int i = 0; i < block.Length / 4; i++)
            {
                m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
            }
            int rem = block.Length % 4;
            if (rem > 0)
            {
                int baseIdx = (block.Length / 4) * 4;
                uint last = 0;
                for (int j = 0; j < rem; j++) last |= (uint)block[baseIdx + j] << (8 * j);
                m[block.Length / 4] = last;
            }
        }

        private static void Rounds(Span<uint> s, Span<uint> m)
        {
            Span<uint> msg = stackalloc uint[16];
            Span<uint> perm = stackalloc uint[16];
            m.CopyTo(msg);

            for (int r = 0; r < 7; r++)
            {
                // Column round
                G(ref s[0], ref s[4], ref s[8], ref s[12], msg[0], msg[1]);
                G(ref s[1], ref s[5], ref s[9], ref s[13], msg[2], msg[3]);
                G(ref s[2], ref s[6], ref s[10], ref s[14], msg[4], msg[5]);
                G(ref s[3], ref s[7], ref s[11], ref s[15], msg[6], msg[7]);

                // Diagonal round
                G(ref s[0], ref s[5], ref s[10], ref s[15], msg[8], msg[9]);
                G(ref s[1], ref s[6], ref s[11], ref s[12], msg[10], msg[11]);
                G(ref s[2], ref s[7], ref s[8], ref s[13], msg[12], msg[13]);
                G(ref s[3], ref s[4], ref s[9], ref s[14], msg[14], msg[15]);

                // Permutation
                if (r < 6)
                {
                    for (int i = 0; i < 16; i++) perm[i] = msg[MSG_PERMUTATION[i]];
                    perm.CopyTo(msg);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G(ref uint a, ref uint b, ref uint c, ref uint d, uint x, uint y)
        {
            a = a + b + x;
            d = BitOperations.RotateRight(d ^ a, 16);
            c = c + d;
            b = BitOperations.RotateRight(b ^ c, 12);
            a = a + b + y;
            d = BitOperations.RotateRight(d ^ a, 8);
            c = c + d;
            b = BitOperations.RotateRight(b ^ c, 7);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Array.Clear(_key, 0, _key.Length);
                _buffer.Clear();
                _disposed = true;
            }
        }
    }
}

namespace Glacier.Codec.Hashing.XxHash3
{
    public sealed class XxHash3Hasher : IStreamingHasher
    {
        private static readonly byte[] DEFAULT_SECRET = [
            0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
            0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
            0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
            0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
            0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
            0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
            0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
            0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
            0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
            0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
            0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
            0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e
        ];

        private const ulong Prime64_1 = 0x9E3779B185EBCA87UL;
        private const ulong Prime64_2 = 0xC2B2AE3D27D4EB4FUL;
        private const ulong Prime64_3 = 0x165667B19E3779F9UL;
        private const ulong Prime64_4 = 0x85EBCA77C2B2AE63UL;
        private const ulong Prime64_5 = 0x27D4EB2F165667C5UL;
        private const uint Prime32_1 = 0x9E3779B1U;

        private readonly List<byte> _buffer = new();
        private readonly ulong _seed;
        private bool _disposed;

        public int HashSizeInBytes => 8;

        public XxHash3Hasher(ulong seed = 0)
        {
            _seed = seed;
        }

        public void Reset()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(XxHash3Hasher));
            _buffer.Clear();
        }

        public void Append(ReadOnlySpan<byte> data)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(XxHash3Hasher));
            for (int i = 0; i < data.Length; i++) _buffer.Add(data[i]);
        }

        public void GetCurrentHash(Span<byte> destination)
        {
            ulong hash = Hash64(CollectionsMarshal.AsSpan(_buffer), _seed);
            BinaryPrimitives.WriteUInt64LittleEndian(destination, hash);
        }

        public void Finalize(Span<byte> destination)
        {
            GetCurrentHash(destination);
            Reset();
        }

        public static ulong Hash64(ReadOnlySpan<byte> input, ulong seed = 0)
        {
            return System.IO.Hashing.XxHash3.HashToUInt64(input, (long)seed);
        }

        public static UInt128 Hash128(ReadOnlySpan<byte> input, ulong seed = 0)
        {
            return System.IO.Hashing.XxHash128.HashToUInt128(input, (long)seed);
        }

        private static ulong HashLen0To16(ReadOnlySpan<byte> input, ulong seed)
        {
            int len = input.Length;
            if (len > 8)
            {
                ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(0, 8));
                ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(len - 8, 8));
                ulong acc = (ulong)len + BitOperations.RotateLeft(lo + seed, 49) + BitOperations.RotateLeft(hi, 24);
                acc ^= (lo >> 32) + (hi << 32);
                acc = Avalanche(acc);
                return acc;
            }
            if (len >= 4)
            {
                uint lo = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(0, 4));
                uint hi = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(len - 4, 4));
                ulong combined = ((ulong)hi << 32) | lo;
                ulong acc = (ulong)len + BitOperations.RotateLeft(combined + seed, 35);
                acc = Avalanche(acc);
                return acc;
            }
            if (len > 0)
            {
                byte c1 = input[0];
                byte c2 = input[len >> 1];
                byte c3 = input[len - 1];
                uint combined = ((uint)c1 << 16) | ((uint)c2 << 8) | c3;
                ulong acc = (ulong)len + ((ulong)combined ^ seed);
                return Avalanche(acc);
            }
            return 0x2D06800538D394C2UL ^ seed;
        }

        private static ulong HashLen17To128(ReadOnlySpan<byte> input, ulong seed)
        {
            ulong acc = (ulong)input.Length * Prime64_1;
            if (input.Length > 32)
            {
                if (input.Length > 64)
                {
                    if (input.Length > 96)
                    {
                        acc += Mix16(input.Slice(48, 16), DEFAULT_SECRET.AsSpan(96, 16), seed);
                        acc += Mix16(input.Slice(input.Length - 64, 16), DEFAULT_SECRET.AsSpan(112, 16), seed);
                    }
                    acc += Mix16(input.Slice(32, 16), DEFAULT_SECRET.AsSpan(64, 16), seed);
                    acc += Mix16(input.Slice(input.Length - 48, 16), DEFAULT_SECRET.AsSpan(80, 16), seed);
                }
                acc += Mix16(input.Slice(16, 16), DEFAULT_SECRET.AsSpan(32, 16), seed);
                acc += Mix16(input.Slice(input.Length - 32, 16), DEFAULT_SECRET.AsSpan(48, 16), seed);
            }
            acc += Mix16(input.Slice(0, 16), DEFAULT_SECRET.AsSpan(0, 16), seed);
            acc += Mix16(input.Slice(input.Length - 16, 16), DEFAULT_SECRET.AsSpan(16, 16), seed);
            return Avalanche(acc);
        }

        private static ulong HashLen129To240(ReadOnlySpan<byte> input, ulong seed)
        {
            ulong acc = (ulong)input.Length * Prime64_1;
            int rounds = input.Length / 16;
            for (int i = 0; i < 8; i++)
            {
                acc += Mix16(input.Slice(i * 16, 16), DEFAULT_SECRET.AsSpan(i * 16, 16), seed);
            }
            acc = Avalanche(acc);
            for (int i = 8; i < rounds; i++)
            {
                acc += Mix16(input.Slice(i * 16, 16), DEFAULT_SECRET.AsSpan((i - 8) * 16, 16), seed);
            }
            acc += Mix16(input.Slice(input.Length - 16, 16), DEFAULT_SECRET.AsSpan(112, 16), seed);
            return Avalanche(acc);
        }

        private static ulong HashLong(ReadOnlySpan<byte> input, ulong seed)
        {
            // 8 accumulators
            ulong[] acc = [
                Prime32_1, Prime64_1, Prime64_2, Prime64_3,
                Prime64_4, Prime64_2, Prime64_5, Prime32_1
            ];

            int stripes = input.Length / 64;
            for (int s = 0; s < stripes; s++)
            {
                int secOff = (s % 16) * 8;
                for (int lane = 0; lane < 8; lane++)
                {
                    ulong data = BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(s * 64 + lane * 8, 8));
                    ulong key = BinaryPrimitives.ReadUInt64LittleEndian(DEFAULT_SECRET.AsSpan(secOff + lane * 8, 8));
                    ulong dataKey = data ^ key;
                    ulong prod = (ulong)(uint)dataKey * (ulong)(uint)(dataKey >> 32);
                    acc[lane ^ 1] += data;
                    acc[lane] += prod;
                }

                if ((s + 1) % 16 == 0)
                {
                    // Scrambler
                    for (int lane = 0; lane < 8; lane++)
                    {
                        acc[lane] ^= acc[lane] >> 47;
                        acc[lane] ^= BinaryPrimitives.ReadUInt64LittleEndian(DEFAULT_SECRET.AsSpan(128 + lane * 8, 8));
                        acc[lane] *= Prime32_1;
                    }
                }
            }

            ulong finalHash = (ulong)input.Length * Prime64_1;
            for (int lane = 0; lane < 8; lane++) finalHash += acc[lane];
            return Avalanche(finalHash);
        }

        private static ulong Mix16(ReadOnlySpan<byte> data, ReadOnlySpan<byte> secret, ulong seed)
        {
            ulong d1 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(0, 8));
            ulong d2 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8, 8));
            ulong s1 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(0, 8));
            ulong s2 = BinaryPrimitives.ReadUInt64LittleEndian(secret.Slice(8, 8));
            return Avalanche((d1 ^ s1) + (d2 ^ s2) + seed);
        }

        private static ulong Avalanche(ulong h)
        {
            h ^= h >> 37;
            h *= Prime64_3;
            h ^= h >> 32;
            return h;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _buffer.Clear();
                _disposed = true;
            }
        }
    }
}

#endif
