# Glacier.Codec.Gpu

High-performance, bare-metal GPU cryptographic hashing and parallel nonce search engine for the Glacier ecosystem.

Executes hand-crafted, forward-compatible CUDA PTX assembly directly via the NVIDIA display driver (`nvcuda.dll` on Windows, `libcuda.so` on Linux), completely bypassing runtime overhead and **requiring zero CUDA SDK / Toolkit installations**.

---

## Hardware Benchmarks (NVIDIA GeForce RTX 4060 Laptop GPU, sm_89)

| Algorithm | Mode | Throughput | Evaluated Batch | Latency |
| :--- | :--- | :--- | :--- | :--- |
| **BLAKE3** | Parallel Nonce Search / Mining | **4,045.63 MH/s (4.04 GH/s)** | 10,000,000 nonces | 2 ms |
| **SHA-256** | Parallel Nonce Search / Mining | **1,021.51 MH/s (1.02 GH/s)** | 10,000,000 nonces | 9 ms |
| **BLAKE3** | Batch Hash (64-byte chunks) | Verified Bit-for-Bit vs. CPU | 64 blocks | < 1 ms |
| **SHA-256** | Batch Hash (FIPS 180-4 standard) | Verified Bit-for-Bit vs. CPU | 64 blocks | < 1 ms |

---

## Remote Machine Deployment (RTX 3060 12GB)

The compiled CLI binary at `publish/Glacier.Codec.Gpu.Cli/Glacier.Codec.Gpu.Cli.exe` is **100% self-contained Native AOT** (1.9 MB):
1. Copy `Glacier.Codec.Gpu.Cli.exe` to the remote RTX 3060 PC (e.g. via SMB share, SCP, or USB).
2. No .NET Runtime or CUDA SDK is required on the remote PC—only standard NVIDIA graphics drivers.
3. Run:
   ```powershell
   .\Glacier.Codec.Gpu.Cli.exe info
   .\Glacier.Codec.Gpu.Cli.exe bench
   .\Glacier.Codec.Gpu.Cli.exe search blake3 16
   ```

---

## Architecture Highlights
* **Universal Forward-Compatible PTX:** Targets `compute_75`, JIT-compiled on first launch by the NVIDIA driver for Turing, Ampere (sm_86), Ada Lovelace (sm_89), Hopper, and Blackwell.
* **Direct Driver API:** Zero cudart runtime overhead via low-level `cuLaunchKernel` and pinned page allocations.
* **Safe Co-existence:** Sub-10ms grid execution batches prevent Windows TDR (Timeout Detection and Recovery) display driver resets.
