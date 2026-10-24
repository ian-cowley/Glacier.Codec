// Glacier.Codec.Gpu - CUDA High-Throughput BLAKE3 Batch & Nonce Search Kernel
// Optimized for Ada Lovelace (RTX 4060, sm_89) and Ampere (RTX 3060, sm_86)

#include <cuda_runtime.h>
#include <stdint.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

__device__ __forceinline__ void g_func(
    uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d,
    uint32_t mx, uint32_t my)
{
    a = a + b + mx;
    d = ROTR(d ^ a, 16);
    c = c + d;
    b = ROTR(b ^ c, 12);
    a = a + b + my;
    d = ROTR(d ^ a, 8);
    c = c + d;
    b = ROTR(b ^ c, 7);
}

__device__ __forceinline__ void round_fn(uint32_t v[16], const uint32_t m[16]) {
    // Column round
    g_func(v[0], v[4], v[8],  v[12], m[0], m[1]);
    g_func(v[1], v[5], v[9],  v[13], m[2], m[3]);
    g_func(v[2], v[6], v[10], v[14], m[4], m[5]);
    g_func(v[3], v[7], v[11], v[15], m[6], m[7]);

    // Diagonal round
    g_func(v[0], v[5], v[10], v[15], m[8],  m[9]);
    g_func(v[1], v[6], v[11], v[12], m[10], m[11]);
    g_func(v[2], v[7], v[8],  v[13], m[12], m[13]);
    g_func(v[3], v[4], v[9],  v[14], m[14], m[15]);
}

__device__ __forceinline__ void permute(uint32_t m[16]) {
    uint32_t t[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) t[i] = m[i];

    m[0]  = t[2];
    m[1]  = t[6];
    m[2]  = t[3];
    m[3]  = t[10];
    m[4]  = t[7];
    m[5]  = t[0];
    m[6]  = t[4];
    m[7]  = t[13];
    m[8]  = t[1];
    m[9]  = t[11];
    m[10] = t[12];
    m[11] = t[5];
    m[12] = t[9];
    m[13] = t[14];
    m[14] = t[15];
    m[15] = t[8];
}

__device__ __forceinline__ void blake3_compress(
    const uint32_t cv[8],
    const uint32_t block[16],
    uint32_t block_len,
    uint32_t flags,
    uint32_t out[8])
{
    uint32_t v[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) v[i] = cv[i];
    v[8]  = 0x6A09E667;
    v[9]  = 0xBB67AE85;
    v[10] = 0x3C6EF372;
    v[11] = 0xA54FF53A;
    v[12] = 0; // counter low
    v[13] = 0; // counter high
    v[14] = block_len;
    v[15] = flags;

    uint32_t m[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) m[i] = block[i];

    #pragma unroll
    for (int r = 0; r < 7; r++) {
        round_fn(v, m);
        if (r < 6) permute(m);
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i] = v[i] ^ v[i + 8];
    }
}

extern "C" __global__ void blake3_batch_kernel(
    const uint32_t* __restrict__ input_blocks, // 64 bytes (16 uint32s) per block
    uint32_t* __restrict__ output_hashes,      // 32 bytes (8 uint32s) per block
    uint32_t total_blocks,
    uint32_t flags)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= total_blocks) return;

    const uint32_t IV[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    uint32_t block[16];
    const uint32_t* in_ptr = input_blocks + (tid * 16);
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        block[i] = in_ptr[i];
    }

    uint32_t out[8];
    blake3_compress(IV, block, 64, flags, out);

    uint32_t* out_ptr = output_hashes + (tid * 8);
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out_ptr[i] = out[i];
    }
}

extern "C" __global__ void blake3_nonce_search_kernel(
    const uint32_t* __restrict__ header_template, // 16 uint32s (64 bytes), word 15 is nonce slot
    uint32_t base_nonce,
    uint32_t target_zeros_mask,                  // Mask condition
    uint32_t flags,
    uint32_t max_evaluations,
    uint32_t* __restrict__ found_count,
    uint32_t* __restrict__ found_nonces,
    uint32_t max_results)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= max_evaluations) return;

    uint32_t nonce = base_nonce + tid;

    const uint32_t IV[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    uint32_t block[16];
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        block[i] = header_template[i];
    }
    block[15] = nonce;

    uint32_t out[8];
    blake3_compress(IV, block, 64, flags, out);

    if ((out[0] & target_zeros_mask) == 0) {
        uint32_t idx = atomicAdd(found_count, 1);
        if (idx < max_results) {
            found_nonces[idx] = nonce;
        }
    }
}
