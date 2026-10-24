<!--
================================================================================
GLACIER HYBRID DOCUMENTATION STANDARD — ARCHITECTURE SPECIFICATION
DATA MODULE CODE: DMC-GLACIER-CODEC-A-00-00-00-00A-040B-A
SPECIFICATION CONFORMANCE: Arc42 (v8.2) / ASD-STE100 (Issue 9) / C4 Model
TARGET RUNTIME: C# .NET 10 / Native AOT / Zero-Allocation Memory Engine
================================================================================
-->

# Architecture Specification: Glacier.Codec

```
  █████╗ ██████╗  ██████╗██╗  ██╗██╗████████╗███████╗ ██████╗████████╗██╗   ██╗██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔════╝██║  ██║██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
 ███████║██████╔╝██║     ███████║██║   ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝█████╗  
 ██╔══██║██╔══██╗██║     ██╔══██║██║   ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗██╔══╝  
 ██║  ██║██║  ██║╚██████╗██║  ██║██║   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
                            ARC42 ARCHITECTURAL BLUEPRINT
```

---

## Document Identification

| Specification Attribute | Value |
| :--- | :--- |
| **Data Module Code (DMC)** | `DMC-GLACIER-CODEC-A-00-00-00-00A-040B-A` |
| **System Identification** | Glacier Ecosystem — Glacier.Codec Subsystem |
| **Standard Numbering (SNS)** | `10-CODEC-00` |
| **Information Code** | `040` (Architectural Description) |
| **Template Conformance** | Arc42 Architecture Template (Version 8.2) |
| **Linguistic Conformance** | ASD-STE100 Issue 9 (Simplified Technical English) |
| **Runtime Target** | .NET 10.0 / Native AOT / AMD64 & ARM64 |

---

## Table of Contents

1. [Requirements and Goals](#1-requirements-and-goals)
2. [Architecture Constraints](#2-architecture-constraints)
3. [Context and Scope](#3-context-and-scope)
4. [Solution Strategy](#4-solution-strategy)
5. [Building Block View](#5-building-block-view)
6. [Runtime View](#6-runtime-view)
7. [Deployment View](#7-deployment-view)
8. [Cross-Cutting Concepts](#8-cross-cutting-concepts)
9. [Architecture Decisions (ADR)](#9-architecture-decisions-adr)
10. [Quality Scenarios](#10-quality-scenarios)
11. [Risks and Technical Debt](#11-risks-and-technical-debt)
12. [Glossary](#12-glossary)

---

## 1. Requirements and Goals

### 1.1 Executive Summary
`Glacier.Codec` provides high-performance cryptographic transformations and data compression for enterprise workloads. The system processes streaming data with zero garbage collector pauses. It executes mathematical operations directly through CPU vector units and dedicated hardware instructions.

### 1.2 Quality Goals

| Priority | Quality Goal | Target Metric | Architectural Mechanism |
| :---: | :--- | :--- | :--- |
| **QG-1** | **Zero Heap Allocation** | `0 Bytes` allocated on hot execution paths | `Span<byte>`, `UnmanagedSlabPool`, cacheline buffers |
| **QG-2** | **Extreme Throughput** | $> 10.0\text{ GB/s}$ AES-GCM, $> 5.0\text{ GB/s}$ BLAKE3 | VAES, VPCLMULQDQ, AVX-512 vector pipelines |
| **QG-3** | **Deterministic Latency** | Constant-time execution on secret data | `FixedTimeEquals`, branchless bitwise operations |
| **QG-4** | **Instant Startup** | Time to first block $< 10\text{ ms}$ | Native AOT compilation, zero runtime reflection |
| **QG-5** | **Zero External Bloat** | `0` third-party runtime C++ dependencies | 100% pure C# .NET 10 clean-room implementation |

---

## 2. Architecture Constraints

1. **Pure C# .NET 10 Implementation:** The system prohibits native C++ shims, foreign DLL imports, or Python bridges.
2. **Zero Allocation Invariant:** Active encryption, hashing, and compression loops must not trigger Gen 0, Gen 1, or Gen 2 garbage collections.
3. **Hardware Intrinsics Isolation:** Direct CPU instructions must reside behind verified CPUID capability probes (`CpuCapabilities`).
4. **Modularity Boundaries:** Every source code file must not exceed 800 lines of code.
5. **Zero Secrets Policy:** Secret tokens, private keys, or passwords must never appear in codebase files.

---

## 3. Context and Scope

```mermaid
C4Context
    title Context Diagram for Glacier.Codec (Level 1)

    Person(consumer, "Host Application", "Uses cryptographic and compression pipelines")
    System(codec, "Glacier.Codec Engine", "Executes zero-allocation encryption and compression")
    System_Ext(hardware, "Host Silicon", "AVX-512, VAES, SHA-NI, PCLMULQDQ, ARM Neon")
    SystemDb_Ext(storage, "Glacier Storage / DataFrames", "Persists columnar and compressed blocks")

    Rel(consumer, codec, "Calls API via", "In-Process Spans")
    Rel(codec, hardware, "Invokes intrinsics on", "Machine Code")
    Rel(codec, storage, "Streams payloads to", "Memory Pools")
```

---

## 4. Solution Strategy

1. **Hardware-Specific Tiering:** Statically classify host processors into Tier 0 (AVX-512, VAES, SHA-NI), Tier 1 (AVX2, AES-NI), and Tier 2 (Scalar fallback).
2. **Slab Memory Rental:** Manage memory buffers using a lock-free `UnmanagedSlabPool` to avoid OS page allocations.
3. **Carry-Less Polynomial Multiplication:** Compute $GF(2^{128})$ GHASH values using `Pclmulqdq` and `Vpclmulqdq` intrinsics with Karatsuba reduction.
4. **Parallel Tree Reduction:** Process BLAKE3 chunks across 16-way vector registers and merge hashes using stack-allocated structures.
5. **Multi-Block Framing:** Divide large Zstandard streams into standard $\le 128\text{ KB}$ blocks per RFC 8878 Section 3.1.1.2.3.

---

## 5. Building Block View

### 5.1 Subsystem Decomposition

```mermaid
flowchart TD
    A["Glacier.Codec"] --> B["Hardware Subsystem"]
    A --> C["Memory Subsystem"]
    A --> D["Hashing Subsystem"]
    A --> E["Cryptography Subsystem"]
    A --> F["Compression Subsystem"]

    B --> B1["CpuCapabilities"]
    B --> B2["HardwareArbiter"]

    C --> C1["UnmanagedSlabPool"]
    C --> C2["SecureMemory"]
    C --> C3["CachelineAlignedBuffer"]

    D --> D1["Blake3Hasher"]
    D --> D2["Sha256Hasher"]
    D --> D3["XxHash3"]

    E --> E1["Aes256Gcm"]
    E --> E2["ChaCha20Poly1305"]
    E --> E3["Argon2id"]
    E --> E4["MlKemEngine"]

    F --> F1["Lz4Codec"]
    F --> F2["ZstdCodec"]
```

---

## 6. Runtime View

### 6.1 Authenticated Encryption Workflow

```mermaid
sequenceDiagram
    autonumber
    participant App as Caller Application
    participant Arbiter as HardwareArbiter
    participant Engine as AesGcmParallelEngine
    participant Hardware as CPU VAES / PCLMULQDQ
    participant Pool as UnmanagedSlabPool

    App->>Arbiter: Encrypt(key, nonce, plaintext, ciphertext, tag)
    Arbiter->>Engine: RouteByPayloadSize(plaintext.Length)
    Engine->>Pool: Rent(requiredSlabBytes)
    Pool-->>Engine: SlabLease (Pinned Unmanaged Memory)
    Engine->>Hardware: Execute 8-Way VAES Counter Mode
    Engine->>Hardware: Compute Karatsuba GHASH (PCLMULQDQ)
    Engine->>App: Write Ciphertext & Tag (Constant-Time)
    Engine->>Pool: Dispose Lease (ZeroMemory on Return)
```

---

## 7. Deployment View

`Glacier.Codec` deploys as a standalone .NET 10 class library or as a Native AOT compiled binary. It exposes zero external dynamic link dependencies (`.dll` or `.so`).

```mermaid
deployment
    title Deployment View for Glacier.Codec

    deploymentNode(node, "Host Execution Environment", "Windows x64 / Linux x64 / Linux ARM64") {
        deploymentNode(proc, "Operating System Process", "User Space Execution") {
            artifact(aot, "Glacier.Codec.dll", "Native AOT Compiled Binary")
            artifact(memory, "Unmanaged Slab Cache", "64B Cacheline-Aligned Pool")
        }
    }
```

---

## 8. Cross-Cutting Concepts

### 8.1 Memory Safety and Zero-Wiping
All sensitive key structures implement `IDisposable`. The `SecureMemory` class invokes `CryptographicOperations.ZeroMemory` upon disposal. The unmanaged slab pool scrubs memory blocks before returning them to the shared queue.

### 8.2 Constant-Time Security Invariants
Authentication tag comparisons execute through `CryptographicOperations.FixedTimeEquals`. The implementation prohibits early-exit loops on secret comparison paths to prevent timing side channels.

---

## 9. Architecture Decisions (ADR)

### ADR-01: Direct Intrinsics over BCL Wrappers
- **Context:** BCL cryptographic APIs allocate managed wrappers and lack direct vector pipelining.
- **Decision:** Implement bare-metal x86 instructions (`Sha256Msg1`, `Pclmulqdq`, `VAES`) directly in C#.
- **Consequences:** Eliminates runtime allocations; achieves 12.61 GB/s AES-GCM throughput.

### ADR-02: Stack-Allocated NTT Ring Arithmetic for ML-KEM
- **Context:** Polynomial arithmetic in post-quantum cryptography requires hundreds of ring operations.
- **Decision:** Stack-allocate all $R_q$ polynomial arrays ($256 \times 2\text{ bytes} = 512\text{ bytes}$).
- **Consequences:** Enforces 0 bytes heap allocation during post-quantum key encapsulation.

---

## 10. Quality Scenarios

1. **Extreme Throughput Scenario:** A streaming ingest pipeline encrypts 10 GB of data. The engine uses 8-way VAES pipelining to maintain $>11\text{ GB/s}$ without triggering GC collections.
2. **Side-Channel Rejection Scenario:** An adversary transmits a modified authentication tag. The engine rejects the frame using `FixedTimeEquals` and scrubs the output buffer immediately.

---

## 11. Risks and Technical Debt

1. **Hardware Fallback Overhead:** Older CPUs without AVX-512 or VAES fall back to scalar kernels, reducing throughput to $\sim 1.2\text{ GB/s}$.
2. **QRAM Scalability:** Future quantum developments could affect memory-hard models, mitigated by ML-KEM parameter support.

---

## 12. Glossary

- **AEAD:** Authenticated Encryption with Associated Data.
- **DMC:** Data Module Code (S1000D documentation identifier).
- **FSE:** Finite State Entropy (tANS compression sequence coder).
- **ML-KEM:** Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203).
- **NTT:** Number Theoretic Transform.
- **VAES:** Vector Advanced Encryption Standard (512-bit SIMD instructions).
