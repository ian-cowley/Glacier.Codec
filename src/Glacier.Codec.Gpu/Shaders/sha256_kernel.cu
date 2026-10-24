// Glacier.Codec.Gpu - CUDA High-Throughput SHA-256 Batch & Nonce Search Kernel
// Optimized for Ada Lovelace (RTX 4060, sm_89) and Ampere (RTX 3060, sm_86)

#include <cuda_runtime.h>
#include <stdint.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__ uint32_t bswap32(uint32_t x) {
    return __byte_perm(x, 0, 0x0123);
}

__device__ __forceinline__ void sha256_transform(uint32_t state[8], const uint32_t data[16]) {
    uint32_t w[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = bswap32(data[i]);
    }
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// Computes standard FIPS 180-4 SHA-256 for a 64-byte message (Block 0 = data, Block 1 = padding & length 512 bits)
extern "C" __global__ void sha256_batch_kernel(
    const uint32_t* __restrict__ input_blocks, // 64 bytes (16 uint32s) per block
    uint32_t* __restrict__ output_hashes,      // 32 bytes (8 uint32s) per block
    uint32_t total_blocks)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= total_blocks) return;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Block 0: 64 bytes of message
    uint32_t block0[16];
    const uint32_t* in_ptr = input_blocks + (tid * 16);
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        block0[i] = in_ptr[i];
    }
    sha256_transform(state, block0);

    // Block 1: standard SHA-256 padding for 64-byte (512-bit) message
    // 0x80 in first byte, zeros, and length 512 = 0x0200 at end in big-endian
    uint32_t block1[16];
    block1[0] = bswap32(0x80000000);
    #pragma unroll
    for (int i = 1; i < 15; i++) {
        block1[i] = 0;
    }
    block1[15] = bswap32(512); // 512 bits length
    sha256_transform(state, block1);

    uint32_t* out_ptr = output_hashes + (tid * 8);
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out_ptr[i] = bswap32(state[i]);
    }
}

// Searches for 32-bit nonce that satisfies difficulty mask on standard 64-byte message
extern "C" __global__ void sha256_nonce_search_kernel(
    const uint32_t* __restrict__ header_template, // 16 uint32s (64 bytes), word 15 is nonce slot
    uint32_t base_nonce,
    uint32_t target_zeros_mask,                  // Leading zeros mask (e.g. 0xFFFF0000)
    uint32_t max_evaluations,
    uint32_t* __restrict__ found_count,          // Atomic counter of matches
    uint32_t* __restrict__ found_nonces,         // Buffer of winning nonces
    uint32_t max_results)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= max_evaluations) return;

    uint32_t nonce = base_nonce + tid;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Block 0: Message with candidate nonce
    uint32_t block0[16];
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        block0[i] = header_template[i];
    }
    block0[15] = nonce;
    sha256_transform(state, block0);

    // Block 1: Padding
    uint32_t block1[16];
    block1[0] = bswap32(0x80000000);
    #pragma unroll
    for (int i = 1; i < 15; i++) {
        block1[i] = 0;
    }
    block1[15] = bswap32(512);
    sha256_transform(state, block1);

    // state[0] has high 32-bits of the SHA-256 hash
    if ((state[0] & target_zeros_mask) == 0) {
        uint32_t idx = atomicAdd(found_count, 1);
        if (idx < max_results) {
            found_nonces[idx] = nonce;
        }
    }
}
