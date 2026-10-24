// Glacier.Codec.Gpu - AMD Radeon 890M (RDNA 3.5, gfx1150) HIP Compute Kernel
// Native ROCm 7.x accelerated parallel nonce discovery for Linux AMD APUs

#include <hip/hip_runtime.h>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__device__ __constant__ uint32_t K[64] = {
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
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

__device__ __forceinline__ void g_func(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t mx, uint32_t my) {
    a = a + b + mx; d = ROTR(d ^ a, 16);
    c = c + d;      b = ROTR(b ^ c, 12);
    a = a + b + my; d = ROTR(d ^ a, 8);
    c = c + d;      b = ROTR(b ^ c, 7);
}

__device__ __forceinline__ void round_fn(uint32_t v[16], const uint32_t m[16]) {
    g_func(v[0], v[4], v[8],  v[12], m[0], m[1]);
    g_func(v[1], v[5], v[9],  v[13], m[2], m[3]);
    g_func(v[2], v[6], v[10], v[14], m[4], m[5]);
    g_func(v[3], v[7], v[11], v[15], m[6], m[7]);
    g_func(v[0], v[5], v[10], v[15], m[8],  m[9]);
    g_func(v[1], v[6], v[11], v[12], m[10], m[11]);
    g_func(v[2], v[7], v[8],  v[13], m[12], m[13]);
    g_func(v[3], v[4], v[9],  v[14], m[14], m[15]);
}

__device__ __forceinline__ void permute(uint32_t m[16]) {
    uint32_t t[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) t[i] = m[i];
    m[0] = t[2];  m[1] = t[6];  m[2] = t[3];  m[3] = t[10];
    m[4] = t[7];  m[5] = t[0];  m[6] = t[4];  m[7] = t[13];
    m[8] = t[1];  m[9] = t[11]; m[10]= t[12]; m[11]= t[5];
    m[12]= t[9];  m[13]= t[14]; m[14]= t[15]; m[15]= t[8];
}

__global__ void blake3_nonce_search(
    const uint32_t* __restrict__ header_template,
    uint32_t base_nonce,
    uint32_t target_zeros_mask,
    uint32_t max_evaluations,
    uint32_t* __restrict__ found_count,
    uint32_t* __restrict__ found_nonces,
    uint32_t max_results)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= max_evaluations) return;
    uint32_t nonce = base_nonce + tid;

    uint32_t v[16] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0, 0, 64, 0x0B
    };

    uint32_t m[16];
    #pragma unroll
    for (int i = 0; i < 15; i++) m[i] = header_template[i];
    m[15] = nonce;

    #pragma unroll
    for (int r = 0; r < 7; r++) {
        round_fn(v, m);
        if (r < 6) permute(m);
    }

    uint32_t out0 = v[0] ^ v[8];
    if ((out0 & target_zeros_mask) == 0) {
        uint32_t idx = atomicAdd(found_count, 1);
        if (idx < max_results) {
            found_nonces[idx] = nonce;
        }
    }
}

__device__ __forceinline__ void sha256_transform(uint32_t state[8], const uint32_t data[16]) {
    uint32_t w[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = bswap32(data[i]);
    #pragma unroll
    for (int i = 16; i < 64; i++) w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__global__ void sha256_nonce_search(
    const uint32_t* __restrict__ header_template,
    uint32_t base_nonce,
    uint32_t target_zeros_mask,
    uint32_t max_evaluations,
    uint32_t* __restrict__ found_count,
    uint32_t* __restrict__ found_nonces,
    uint32_t max_results)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= max_evaluations) return;
    uint32_t nonce = base_nonce + tid;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint32_t block0[16];
    #pragma unroll
    for (int i = 0; i < 15; i++) block0[i] = header_template[i];
    block0[15] = nonce;
    sha256_transform(state, block0);

    uint32_t block1[16];
    block1[0] = bswap32(0x80000000);
    #pragma unroll
    for (int i = 1; i < 15; i++) block1[i] = 0;
    block1[15] = bswap32(512);
    sha256_transform(state, block1);

    if ((state[0] & target_zeros_mask) == 0) {
        uint32_t idx = atomicAdd(found_count, 1);
        if (idx < max_results) {
            found_nonces[idx] = nonce;
        }
    }
}

int main() {
    hipDeviceProp_t prop;
    hipGetDeviceProperties(&prop, 0);
    std::cout << "==============================================================" << std::endl;
    std::cout << "  Glacier.Codec.Gpu - AMD Radeon 890M (RDNA 3.5) Hardware Benchmark" << std::endl;
    std::cout << "  Device: " << prop.name << " (gcnArch: " << prop.gcnArchName << ")" << std::endl;
    std::cout << "  Compute Units: " << prop.multiProcessorCount << " | Unified Memory: " << (prop.integrated ? "YES (UMA)" : "NO") << std::endl;
    std::cout << "  Total VRAM/System RAM: " << (prop.totalGlobalMem / (1024*1024*1024.0)) << " GB" << std::endl;
    std::cout << "==============================================================" << std::endl;

    uint32_t* d_tmpl;
    uint32_t* d_count;
    uint32_t* d_nonces;
    hipMalloc(&d_tmpl, 64);
    hipMalloc(&d_count, 4);
    hipMalloc(&d_nonces, 16 * 4);

    uint32_t h_tmpl[16] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    hipMemcpy(d_tmpl, h_tmpl, 64, hipMemcpyHostToDevice);

    uint32_t test_count = 10000000;
    uint32_t mask = 0xFFFFFFFF; // pure throughput benchmark
    uint32_t threads = 256;
    uint32_t blocks = (test_count + threads - 1) / threads;

    // Warmup
    blake3_nonce_search<<<blocks, threads>>>(d_tmpl, 0, mask, 100000, d_count, d_nonces, 16);
    hipDeviceSynchronize();

    // Benchmark BLAKE3
    auto t0 = std::chrono::high_resolution_clock::now();
    blake3_nonce_search<<<blocks, threads>>>(d_tmpl, 0, mask, test_count, d_count, d_nonces, 16);
    hipDeviceSynchronize();
    auto t1 = std::chrono::high_resolution_clock::now();
    double s_blake3 = std::chrono::duration<double>(t1 - t0).count();
    double mh_blake3 = (test_count / s_blake3) / 1000000.0;

    std::cout << "[AMD 890M BLAKE3] Tested " << test_count << " nonces in " << (s_blake3 * 1000) << " ms -> "
              << std::fixed << std::setprecision(2) << mh_blake3 << " MH/s (" << (mh_blake3 / 1000.0) << " GH/s)" << std::endl;

    // Benchmark SHA-256
    sha256_nonce_search<<<blocks, threads>>>(d_tmpl, 0, mask, 100000, d_count, d_nonces, 16);
    hipDeviceSynchronize();

    t0 = std::chrono::high_resolution_clock::now();
    sha256_nonce_search<<<blocks, threads>>>(d_tmpl, 0, mask, test_count, d_count, d_nonces, 16);
    hipDeviceSynchronize();
    t1 = std::chrono::high_resolution_clock::now();
    double s_sha = std::chrono::duration<double>(t1 - t0).count();
    double mh_sha = (test_count / s_sha) / 1000000.0;

    std::cout << "[AMD 890M SHA-256] Tested " << test_count << " nonces in " << (s_sha * 1000) << " ms -> "
              << std::fixed << std::setprecision(2) << mh_sha << " MH/s (" << (mh_sha / 1000.0) << " GH/s)" << std::endl;

    // Live search test with 16-bit zeros
    uint32_t zero = 0;
    hipMemcpy(d_count, &zero, 4, hipMemcpyHostToDevice);
    uint32_t live_mask = 0xFFFF0000;
    blake3_nonce_search<<<blocks, threads>>>(d_tmpl, 0, live_mask, test_count, d_count, d_nonces, 16);
    hipDeviceSynchronize();

    uint32_t found = 0;
    hipMemcpy(&found, d_count, 4, hipMemcpyDeviceToHost);
    std::vector<uint32_t> results(std::min(found, 16u));
    if (!results.empty()) {
        hipMemcpy(results.data(), d_nonces, results.size() * 4, hipMemcpyDeviceToHost);
    }

    std::cout << "[AMD 890M Live Mining] Total matches found: " << found << std::endl;
    for (size_t i = 0; i < results.size(); i++) {
        std::cout << "  >>> Discovered Nonce: 0x" << std::hex << std::uppercase << results[i] << std::dec << std::endl;
    }

    hipFree(d_tmpl);
    hipFree(d_count);
    hipFree(d_nonces);
    return 0;
}
