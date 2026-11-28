# Glacier.Codec.Gpu

Bare-metal GPU single-block cryptographic hashing and nonce-search engine for the Glacier ecosystem.

## Supported Backends & Scope

* **NVIDIA CUDA Driver API** (`nvcuda.dll` on Windows, `libcuda.so.1` on Linux): executes precompiled PTX kernels (`Shaders/*.ptx`, PTX ISA `.version 9.3`, `.target sm_75+`, requiring an NVIDIA CUDA 13.3+ driver).
* **Windows Direct3D 12 DirectCompute** (`cs_5_0` HLSL shaders in `Shaders/*.hlsl`): executes nonce search across Windows DXGI adapters (AMD Radeon, Intel, and NVIDIA).
* **Kernel Scope**: Fixed **64-byte single-block** batch hashing (`HashBatch` via CUDA) and **60-byte header + 4-byte nonce** proof-of-work prefix search (`SearchNonce` / `SearchNonceBlake3` / `SearchNonceSha256`) for BLAKE3 and SHA-256. Arbitrary-length multi-chunk GPU streaming and GPU AEAD (`AES-GCM` / `ChaCha20`) are not implemented in this package (use `Glacier.Codec` CPU SIMD pipelines).
* **Standalone C++ ROCm Reference (`Shaders/890m_miner.cpp`)**: An external standalone Linux ROCm/HIP C++ benchmark source file included for reference; it is **not** compiled or invoked by the .NET `Glacier.Codec.Gpu` library.

---

## Fleet Verification Benchmarks

| Node & Hostname | Hardware & GPU Architecture | BLAKE3 Nonce Search | SHA-256 Nonce Search | Acceleration Backend |
| :--- | :--- | :--- | :--- | :--- |
| **Beast** (`192.168.1.108`) | **NVIDIA GeForce RTX 3060** (12GB VRAM, sm_86) | **4,302.74 MH/s (4.30 GH/s)** | **1,155.29 MH/s (1.15 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **Host Machine** (Local) | **NVIDIA GeForce RTX 4060** (8GB VRAM, sm_89) | **4,045.63 MH/s (4.04 GH/s)** | **1,021.51 MH/s (1.02 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **Linux Node** (`192.168.1.200`) | **AMD Radeon 890M** (RDNA 3.5 `gfx1150`, 24GB UMA) | **2,237.76 MH/s (2.24 GH/s)** | **772.04 MH/s (0.77 GH/s)** | Standalone C++ ROCm 7.2 HIP (`Shaders/890m_miner.cpp`, non-.NET) |
| **minisforum64** (`192.168.1.101`) | **AMD Radeon 780M** (RDNA 3, 12 CUs, Unified Memory) | **875.70 MH/s (0.88 GH/s)** | **206.49 MH/s (0.21 GH/s)** | Direct3D 12 DirectCompute |

---

### Local Host Machine AMD 890M Status Note
On the local host laptop (Ryzen AI 9 HX 370 + RTX 4060), the integrated Radeon 890M can report Windows PnP `CM_PROB_FAILED_POST_START` (Code 43) when the hardware MUX switch is configured in **"Ultimate / Discrete GPU Only"** mode. Switching the laptop GPU mode to **"Standard / Hybrid / Optimus"** re-attaches the 890M PCIe lines for Direct3D 12 DirectCompute.
