# Glacier.Codec.Gpu

High-performance, bare-metal GPU cryptographic hashing and parallel nonce search engine for the Glacier ecosystem.

Accelerates cryptographic pipelines across:
* **Discrete NVIDIA GPUs** (via raw CUDA PTX and `nvcuda.dll`)
* **AMD Radeon iGPUs/dGPUs on Windows** (via Direct3D 12 DirectCompute and HLSL Compute Shaders)
* **AMD Radeon RDNA 3.5 APUs on Linux** (via native ROCm 7.x HIP compute kernels targeting `gfx1150`)

---

## Fleet Verification Benchmarks

| Node & Hostname | Hardware & GPU Architecture | BLAKE3 Nonce Search | SHA-256 Nonce Search | Acceleration Backend |
| :--- | :--- | :--- | :--- | :--- |
| **Beast** (`192.168.1.108`) | **NVIDIA GeForce RTX 3060** (12GB VRAM, sm_86) | **4,302.74 MH/s (4.30 GH/s)** | **1,155.29 MH/s (1.15 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **Host Machine** (Local) | **NVIDIA GeForce RTX 4060** (8GB VRAM, sm_89) | **4,045.63 MH/s (4.04 GH/s)** | **1,021.51 MH/s (1.02 GH/s)** | CUDA Driver API (`nvcuda.dll`) |
| **Linux Node** (`192.168.1.200`) | **AMD Radeon 890M** (RDNA 3.5 `gfx1150`, 24GB UMA) | **2,237.76 MH/s (2.24 GH/s)** | **772.04 MH/s (0.77 GH/s)** | Native ROCm 7.2 HIP (`gfx1150`) |
| **minisforum64** (`192.168.1.101`) | **AMD Radeon 780M** (RDNA 3, 12 CUs, Unified Memory) | **875.70 MH/s (0.88 GH/s)** | **206.49 MH/s (0.21 GH/s)** | Direct3D 12 DirectCompute |
| **Total Fleet Compute** | **Heterogeneous 4-GPU Cluster** | **~11,461.83 MH/s (11.46 GH/s)**| **~3,155.33 MH/s (3.15 GH/s)**| Unified Multi-Vendor Fleet |

---

### Local Host Machine AMD 890M Status Note
On the local host laptop (Ryzen AI 9 HX 370 + RTX 4060), the integrated Radeon 890M is currently report by Windows PnP with status `CM_PROB_FAILED_POST_START` (Code 43) because the laptop's hardware MUX switch is configured in **"Ultimate / Discrete GPU Only"** mode in ASUS G-Helper / Armoury Crate. Switching the laptop GPU mode to **"Standard / Hybrid / Optimus"** (with a reboot) re-attaches the 890M PCIe lines and unlocks an additional **~2.24 GH/s** of local iGPU compute alongside the RTX 4060.
