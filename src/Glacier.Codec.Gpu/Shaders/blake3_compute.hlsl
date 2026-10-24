// Glacier.Codec.Gpu - HLSL Compute Shader for AMD Radeon iGPUs (RDNA 3.5 / RDNA 3) & DirectCompute
// High-throughput BLAKE3 parallel nonce discovery

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

cbuffer MiningParams : register(b0)
{
    uint g_baseNonce;
    uint g_targetMask;
    uint g_maxEvaluations;
    uint g_maxResults;
    uint g_flags;
};

StructuredBuffer<uint> g_template : register(t0); // 16 uints (64 bytes)
RWStructuredBuffer<uint> g_foundCount : register(u0);
RWStructuredBuffer<uint> g_foundNonces : register(u1);

void g_func(inout uint a, inout uint b, inout uint c, inout uint d, uint mx, uint my)
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

void round_fn(inout uint v[16], uint m[16])
{
    g_func(v[0], v[4], v[8],  v[12], m[0], m[1]);
    g_func(v[1], v[5], v[9],  v[13], m[2], m[3]);
    g_func(v[2], v[6], v[10], v[14], m[4], m[5]);
    g_func(v[3], v[7], v[11], v[15], m[6], m[7]);

    g_func(v[0], v[5], v[10], v[15], m[8],  m[9]);
    g_func(v[1], v[6], v[11], v[12], m[10], m[11]);
    g_func(v[2], v[7], v[8],  v[13], m[12], m[13]);
    g_func(v[3], v[4], v[9],  v[14], m[14], m[15]);
}

void permute(inout uint m[16])
{
    uint t[16];
    [unroll] for (int i = 0; i < 16; i++) t[i] = m[i];

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

[numthreads(256, 1, 1)]
void CSMain(uint3 id : SV_DispatchThreadID)
{
    uint tid = id.x;
    if (tid >= g_maxEvaluations) return;

    uint nonce = g_baseNonce + tid;

    uint v[16];
    v[0]  = 0x6A09E667; v[1]  = 0xBB67AE85;
    v[2]  = 0x3C6EF372; v[3]  = 0xA54FF53A;
    v[4]  = 0x510E527F; v[5]  = 0x9B05688C;
    v[6]  = 0x1F83D9AB; v[7]  = 0x5BE0CD19;
    v[8]  = 0x6A09E667; v[9]  = 0xBB67AE85;
    v[10] = 0x3C6EF372; v[11] = 0xA54FF53A;
    v[12] = 0;          v[13] = 0;
    v[14] = 64;         v[15] = g_flags;

    uint m[16];
    [unroll] for (int i = 0; i < 15; i++) {
        m[i] = g_template[i];
    }
    m[15] = nonce;

    [unroll]
    for (int r = 0; r < 7; r++) {
        round_fn(v, m);
        if (r < 6) permute(m);
    }

    uint out0 = v[0] ^ v[8];
    if ((out0 & g_targetMask) == 0) {
        uint originalVal;
        InterlockedAdd(g_foundCount[0], 1, originalVal);
        if (originalVal < g_maxResults) {
            g_foundNonces[originalVal] = nonce;
        }
    }
}
