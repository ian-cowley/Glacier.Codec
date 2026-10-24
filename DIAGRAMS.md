<!--
================================================================================
GLACIER HYBRID DOCUMENTATION STANDARD — DECLARATIVE DIAGRAM SUITE
DATA MODULE CODE: DMC-GLACIER-CODEC-A-00-00-00-00A-040C-A
SPECIFICATION CONFORMANCE: C4 Model / Mermaid / ASD-STE100 (Issue 9) / S1000D ICN
TARGET RUNTIME: C# .NET 10 / High-Performance Hardware Pipelines / Markdown Render
================================================================================
-->

# Declarative Diagram Suite: Glacier.Codec

```
 ██████╗ ██╗ █████╗  ██████╗ ██████╗  █████╗ ███╗   ███╗███████╗
 ██╔══██╗██║██╔══██╗██╔════╝ ██╔══██╗██╔══██╗████╗ ████║██╔════╝
 ██║  ██║██║███████║██║  ███╗██████╔╝███████║██╔████╔██║███████╗
 ██║  ██║██║██╔══██║██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║╚════██║
 ██████╔╝██║██║  ██║╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║███████║
 ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
            REUSABLE ARCHITECTURAL & PIPELINE DIAGRAM SUITE
```

---

## Document Identification

| Specification Attribute | Value |
| :--- | :--- |
| **Data Module Code (DMC)** | `DMC-GLACIER-CODEC-A-00-00-00-00A-040C-A` |
| **System Identification** | Glacier Ecosystem — Glacier.Codec Visual Specifications |
| **Information Code** | `040` (Architectural & Conceptual Diagrams) |
| **Diagram Syntax** | Native Declarative Mermaid (Markdown-Embedded) |
| **Linguistic Standard** | ASD-STE100 Issue 9 Compliant |
| **Target Viewers** | GitHub Markdown, VS Code, Browser Portals, Static Site Generators |

---

## Table of Diagrams

1. [Diagram 1: System Context (C4 Level 1)](#diagram-1-system-context-c4-level-1)
2. [Diagram 2: Container Topology (C4 Level 2)](#diagram-2-container-topology-c4-level-2)
3. [Diagram 3: Component Decomposition (C4 Level 3)](#diagram-3-component-decomposition-c4-level-3)
4. [Diagram 4: Memory Layout and Buffer Lifecycle](#diagram-4-memory-layout-and-buffer-lifecycle)
5. [Diagram 5: BLAKE3 Multi-Threaded Tree Reduction Pipeline](#diagram-5-blake3-multi-threaded-tree-reduction-pipeline)

---

## Diagram 1: System Context (C4 Level 1)

### Information Control Number: `ICN-GLACIER-CODEC-C4L1-0001-A`

```mermaid
C4Context
    title System Context Diagram for Glacier.Codec (Level 1)

    Person(developer, "Software Engineer", "Develops extreme-throughput C# systems")
    System(codec, "Glacier.Codec Subsystem", "Executes zero-allocation encryption, hashing, and compression")
    System_Ext(hardware, "Host Hardware Architecture", "AMD Zen 5 / Intel Xeon (AVX-512, VAES, SHA-NI, PCLMULQDQ)")
    SystemDb_Ext(data, "Glacier Data Ecosystem", "Polaris DataFrames, Glacier.Storage, Vector Indices")

    Rel(developer, codec, "Invokes via", "In-Process Spans")
    Rel(codec, hardware, "Dispatches instructions to", "Hardware Intrinsics")
    Rel(codec, data, "Streams zero-copy blocks to", "Memory Pools")
```

> **Metaphor:** The airport security and baggage sorting facility that inspects, seals, and compacts cargo containers before they load onto transport planes.  
> **Citation:** NIST SP 800-38D (Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode).

---

## Diagram 2: Container Topology (C4 Level 2)

### Information Control Number: `ICN-GLACIER-CODEC-C4L2-0002-A`

```mermaid
C4Container
    title Container Topology Diagram for Glacier.Codec (Level 2)

    Container(arbiter, "Hardware Arbiter", "C# .NET 10", "Determines CPU capabilities and routes execution targets")
    Container(aead, "AEAD Engine", "VAES & AVX-512", "Executes AES-256-GCM and ChaCha20-Poly1305")
    Container(pqc, "Post-Quantum KEM", "NTT Polynomial Math", "Executes ML-KEM-768 and ML-KEM-1024")
    Container(digest, "Hashing Engine", "SHA-NI & AVX-512", "Executes BLAKE3, SHA-256, and xxHash3")
    Container(comp, "Compression Engine", "SIMD & FSE", "Executes LZ4 and Zstandard RFC 8878")
    ContainerDb(slab, "Unmanaged Slab Pool", "64B Aligned Memory", "Provides zero-allocation buffer leases")

    Rel(arbiter, aead, "Dispatches symmetric crypto to", "Span<byte>")
    Rel(arbiter, pqc, "Dispatches key encapsulation to", "Span<byte>")
    Rel(arbiter, digest, "Dispatches hashing to", "Span<byte>")
    Rel(arbiter, comp, "Dispatches compression to", "Span<byte>")
    Rel(aead, slab, "Rents scratch slabs from", "Zero-Alloc")
    Rel(comp, slab, "Rents dictionary slabs from", "Zero-Alloc")
```

---

## Diagram 3: Component Decomposition (C4 Level 3)

### Information Control Number: `ICN-GLACIER-CODEC-C4L3-0003-A`

```mermaid
C4Component
    title Component Diagram for Cryptography & Post-Quantum Subsystems (Level 3)

    Component(aes_gcm, "Aes256GcmCipher", "CTR Mode + GHASH", "Performs 14-round VAES encryption and Karatsuba PCLMULQDQ reduction")
    Component(chacha, "ChaCha20Poly1305Cipher", "RFC 8439 Engine", "Vectorized quarter-rounds and 64-bit limb Poly1305 MAC")
    Component(argon, "Argon2idKdf", "RFC 9106 Engine", "Hybrid memory-hard matrix generation with AVX-512 permutation G")
    Component(ml_kem, "MlKemEngine", "NIST FIPS 203 Engine", "Vectorized Montgomery NTT, Keccak-f[1600] sponge, and implicit rejection")
    Component(secure_mem, "SecureMemory", "Wipe Mechanism", "Enforces CryptographicOperations.ZeroMemory upon disposal")

    Rel(aes_gcm, secure_mem, "Guarantees key zeroing via", "IDisposable")
    Rel(chacha, secure_mem, "Guarantees key zeroing via", "IDisposable")
    Rel(argon, secure_mem, "Guarantees key zeroing via", "IDisposable")
    Rel(ml_kem, secure_mem, "Guarantees ephemeral zeroing via", "IDisposable")
```

---

## Diagram 4: Memory Layout and Buffer Lifecycle

### Information Control Number: `ICN-GLACIER-CODEC-MEM-0004-A`

```mermaid
flowchart LR
    subgraph Pool["Unmanaged Slab Pool (64-Byte Cacheline Aligned)"]
        Slab64K["64 KB Slabs (Small Streams)"]
        Slab1M["1 MB Slabs (Columnar Blocks)"]
        Slab4M["4 MB Slabs (Large Checkpoints)"]
    end

    subgraph Execution["Active Compute Pipeline"]
        Rent["SlabLease lease = Rent()"]
        Compute["Execute SIMD / Cryptographic Kernel"]
        Wipe["CryptographicOperations.ZeroMemory()"]
        Return["Return Slab to Lock-Free Queue"]
    end

    Pool -->|Rent| Rent
    Rent --> Compute
    Compute --> Wipe
    Wipe -->|Recycle| Return
    Return --> Pool
```

> **Metaphor:** High-speed surgical trays that are checked out of clean storage, used during operation, sterilized immediately, and returned for the next patient.  
> **Citation:** Drepper, U. (2007). *What Every Programmer Should Know About Memory*. Red Hat Inc.

---

## Diagram 5: BLAKE3 Multi-Threaded Tree Reduction Pipeline

### Information Control Number: `ICN-GLACIER-CODEC-BLAKE3-0005-A`

```mermaid
flowchart TD
    Data["Input Data Stream (Multi-Megabyte Payload)"]
    
    subgraph Slicing["1,024-Byte Chunk Partitioning"]
        C0["Chunk 0"]
        C1["Chunk 1"]
        C2["Chunk 2"]
        C3["Chunk 3"]
        Cn["Chunk N"]
    end

    subgraph Vectorization["16-Way AVX-512 Chunk Compression (G_Avx512)"]
        V0["Vector Block 0..15"]
        V1["Vector Block 16..31"]
    end

    subgraph MerkleStack["Stack-Allocated Tree Collapse (Zero Heap Allocation)"]
        P0["Parent Node 0"]
        P1["Parent Node 1"]
        Root["Root Node (Output Digest)"]
    end

    Data --> Slicing
    Slicing --> Vectorization
    Vectorization --> P0
    Vectorization --> P1
    P0 --> Root
    P1 --> Root
```

> **Citation:** O'Connor, J., Aumasson, J.P., Neves, S., & Wilcox-O'Hearn, Z. (2020). *BLAKE3: one function, fast everywhere*. GitHub repository.
