using System;
using System.Threading.Tasks;
using Xunit;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Memory;

namespace Glacier.Codec.Tests.E2E.Tier3_CrossFeatureCombinations;

public class Tier3_ParallelTreeAndMemory
{
    [Fact]
    public void Pairwise_CachelineAlignedBuffer_WithBlake3TreeHashing()
    {
        // 16 KB buffer aligned to 64-byte boundary
        int size = 16 * 1024;
        using var alignedBuf = new CachelineAlignedBuffer(size);
        Assert.True(alignedBuf.IsAlignedTo64Bytes);

        Span<byte> span = alignedBuf.Span;
        for (int i = 0; i < size; i++) span[i] = (byte)(i % 251);

        Span<byte> hash = stackalloc byte[32];
        Blake3Hasher.Hash(span, hash);

        Assert.Equal(32, hash.Length);
        Assert.False(hash.SequenceEqual(new byte[32]));
    }

    [Fact]
    public async Task Pairwise_UnmanagedSlabPool_MultiThreadedHashing()
    {
        using var pool = new UnmanagedSlabPool();
        const int taskCount = 8;
        Task[] tasks = new Task[taskCount];

        for (int t = 0; t < taskCount; t++)
        {
            int threadId = t;
            tasks[t] = Task.Run(() =>
            {
                IntPtr slab = pool.Rent(64 * 1024, out int actualSize);
                try
                {
                    unsafe
                    {
                        var span = new Span<byte>((void*)slab, actualSize);
                        span.Fill((byte)threadId);

                        Span<byte> hash = stackalloc byte[32];
                        Blake3Hasher.Hash(span, hash);
                        Assert.Equal(32, hash.Length);
                    }
                }
                finally
                {
                    pool.Return(slab, actualSize);
                }
            });
        }

        await Task.WhenAll(tasks);
    }
}
