// Glacier.Codec.Gpu - HLSL Compute Shader for AMD Radeon iGPUs (RDNA 3.5 / RDNA 3) & DirectCompute
// High-throughput SHA-256 parallel nonce discovery

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

cbuffer MiningParams : register(b0)
{
    uint g_baseNonce;
    uint g_targetMask;
    uint g_maxEvaluations;
    uint g_maxResults;
    uint g_pad0;
};

StructuredBuffer<uint> g_template : register(t0);
RWStructuredBuffer<uint> g_foundCount : register(u0);
RWStructuredBuffer<uint> g_foundNonces : register(u1);

uint bswap32(uint x)
{
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

void sha256_transform(inout uint state[8], uint data[16])
{
    uint w[64];
    [unroll] for (int i = 0; i < 16; i++) {
        w[i] = bswap32(data[i]);
    }
    [unroll] for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    [unroll]
    for (int i = 0; i < 64; i++) {
        uint t1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        uint t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

[numthreads(256, 1, 1)]
void CSMain(uint3 id : SV_DispatchThreadID)
{
    uint tid = id.x;
    if (tid >= g_maxEvaluations) return;

    uint nonce = g_baseNonce + tid;

    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint block0[16];
    [unroll] for (int i = 0; i < 15; i++) {
        block0[i] = g_template[i];
    }
    block0[15] = nonce;
    sha256_transform(state, block0);

    // Block 1: standard padding for 64-byte message (512 bits)
    uint block1[16];
    block1[0] = bswap32(0x80000000);
    [unroll] for (int i = 1; i < 15; i++) {
        block1[i] = 0;
    }
    block1[15] = bswap32(512);
    sha256_transform(state, block1);

    if ((state[0] & g_targetMask) == 0) {
        uint originalVal;
        InterlockedAdd(g_foundCount[0], 1, originalVal);
        if (originalVal < g_maxResults) {
            g_foundNonces[originalVal] = nonce;
        }
    }
}
