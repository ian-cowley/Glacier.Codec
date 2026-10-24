# Glacier.Codec.Gpu

High-performance, bare-metal GPU cryptographic hashing and parallel nonce search engine for the Glacier ecosystem.

Accelerates cryptographic pipelines across both **discrete NVIDIA GPUs** (via raw CUDA PTX and `nvcuda.dll`) and **AMD Radeon iGPUs/dGPUs** (via Direct3D 12 DirectCompute and HLSL Compute Shaders) with **zero external SDK / Toolkit dependencies**.

---

## Verified Fleet Benchmarks

| Node / Machine | GPU Hardware & Architecture | BLAKE3 Nonce Search | SHA-256 Nonce Search | Backend Driver |
| :--- | :--- | :--- | :--- | :--- |
| **Beast** (`192.168.1.108`) | **NVIDIA GeForce RTX 3060** (12GB VRAM, sm_86) | **4,302.74 MH/s (4.30 GH/s)** | **1,155.29 MH/s (1.15 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **Host Machine** (Local) | **NVIDIA GeForce RTX 4060** (8GB VRAM, sm_89) | **4,045.63 MH/s (4.04 GH/s)** | **1,021.51 MH/s (1.02 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **minisforum64** (`192.168.1.101`) | **AMD Radeon 780M Graphics** (RDNA 3, UMA) | **875.70 MH/s (0.88 GH/s)** | **206.49 MH/s (0.21 GH/s)** | Direct3D 12 DirectCompute |
| **Total Cluster Throughput** | **Multi-GPU Fleet (NVIDIA + AMD)** | **~9,224.07 MH/s (9.22 GH/s)** | **~2,383.29 MH/s (2.38 GH/s)** | Heterogeneous Parallelism |

---

## Universal CLI Usage

A single 1.9 MB self-contained Native AOT binary [`publish/Glacier.Codec.Gpu.Cli/Glacier.Codec.Gpu.Cli.exe`](publish/Glacier.Codec.Gpu.Cli/Glacier.Codec.Gpu.Cli.exe) runs on any Windows machine across your cluster:

```powershell
# 1. Enumerate all CUDA GPUs and Direct3D 12 AMD Radeon adapters
.\Glacier.Codec.Gpu.Cli.exe info

# 2. Benchmark all available GPU backends
.\Glacier.Codec.Gpu.Cli.exe bench

# 3. Benchmark AMD Radeon iGPU specifically
.\Glacier.Codec.Gpu.Cli.exe amd

# 4. Run live parallel nonce discovery (e.g. BLAKE3 with leading 16-bit zeros)
.\Glacier.Codec.Gpu.Cli.exe search blake3 16
```

---

## Architectural Highlights
* **NVIDIA Bare-Metal PTX:** Targets `compute_75` universal PTX, executing directly via `nvcuda.dll` with zero CUDA Toolkit dependencies.
* **AMD Radeon D3D12 DirectCompute:** Hand-crafted HLSL compute shaders (`blake3_compute.hlsl`, `sha256_compute.hlsl`) running on Unified Memory Architectures (UMA) with 0 ns PCIe copy penalty on AMD APUs.
* **Non-blocking Dispatch:** Burst sizes under 10ms avoid Windows TDR timeouts and preserve full UI responsiveness.
