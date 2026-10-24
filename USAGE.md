<!--
================================================================================
GLACIER HYBRID DOCUMENTATION STANDARD — OPERATIONAL USAGE GUIDE
DATA MODULE CODE: DMC-GLACIER-CODEC-A-00-00-00-00A-520A-A
SPECIFICATION CONFORMANCE: Diátaxis (How-To) / ASD-STE100 (Issue 9) / S1000D
TARGET RUNTIME: C# .NET 10 / Native AOT / Command-Line Interface & API Surface
================================================================================
-->

# Operational Guide: Glacier.Codec

```
 ██╗   ██╗███████╗ █████╗  ██████╗ ███████╗     ██████╗ ██╗   ██╗██╗██████╗ ███████╗
 ██║   ██║██╔════╝██╔══██╗██╔════╝ ██╔════╝    ██╔════╝ ██║   ██║██║██╔══██╗██╔════╝
 ██║   ██║███████╗███████║██║  ███╗█████╗      ██║  ███╗██║   ██║██║██║  ██║█████╗  
 ██║   ██║╚════██║██╔══██║██║   ██║██╔══╝      ██║   ██║██║   ██║██║██║  ██║██╔══╝  
 ╚██████╔╝███████║██║  ██║╚██████╔╝███████╗    ╚██████╔╝╚██████╔╝██║██████╔╝███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝     ╚═════╝  ╚═════╝ ╚═╝╚═════╝ ╚══════╝
                     HOW-TO RECIPES & OPERATIONAL PROCEDURES
```

---

## Document Identification

| Specification Attribute | Value |
| :--- | :--- |
| **Data Module Code (DMC)** | `DMC-GLACIER-CODEC-A-00-00-00-00A-520A-A` |
| **System Identification** | Glacier Ecosystem — Glacier.Codec Operational Manual |
| **Information Code** | `520` (Operational & Procedure Information) |
| **Diátaxis Quadrant** | How-To Guide (Problem-Oriented) |
| **Linguistic Standard** | ASD-STE100 Issue 9 Compliant |
| **Runtime Target** | .NET 10.0 / Native AOT / AMD64 & ARM64 |

---

## Table of Contents

1. [Prerequisites and Verification](#1-prerequisites-and-verification)
2. [Hardware Capability Probing](#2-hardware-capability-probing)
3. [Core Cryptographic Recipes](#3-core-cryptographic-recipes)
   - [Recipe 1: AES-256-GCM Authenticated Encryption](#recipe-1-aes-256-gcm-authenticated-encryption)
   - [Recipe 2: ChaCha20-Poly1305 Stream Encryption](#recipe-2-chacha20-poly1305-stream-encryption)
   - [Recipe 3: High-Throughput BLAKE3 Tree Hashing](#recipe-3-high-throughput-blake3-tree-hashing)
   - [Recipe 4: Hardware SHA-256 Digesting](#recipe-4-hardware-sha-256-digesting)
   - [Recipe 5: Argon2id Memory-Hard Key Derivation](#recipe-5-argon2id-memory-hard-key-derivation)
   - [Recipe 6: Post-Quantum ML-KEM Key Encapsulation](#recipe-6-post-quantum-ml-kem-key-encapsulation)
4. [Compression Recipes](#4-compression-recipes)
   - [Recipe 7: LZ4 Block & Frame Streaming](#recipe-7-lz4-block--frame-streaming)
   - [Recipe 8: Zstandard Multi-Block Compression](#recipe-8-zstandard-multi-block-compression)
5. [Memory Management & Zero Allocation](#5-memory-management--zero-allocation)
6. [Fault Isolation and Troubleshooting](#6-fault-isolation-and-troubleshooting)

---

## 1. Prerequisites and Verification

### Prerequisites
- .NET 10.0 SDK installed on host machine.
- Operating system: Windows 11 x64, Linux x64 (Kernel 6.x+), or macOS ARM64.

### Verify Environment
```powershell
dotnet --version
dotnet build Glacier.Codec.slnx -c Release
```

---

## 2. Hardware Capability Probing

Query host CPU instruction sets at application startup:

```csharp
using Glacier.Codec.Hardware;

// Query verified CPUID vector extensions
bool hasAvx512 = CpuCapabilities.HasAvx512;
bool hasVaes = CpuCapabilities.HasVaes;
bool hasShaNi = CpuCapabilities.HasShaNi;

Console.WriteLine($"AVX-512 Support: {hasAvx512}");
Console.WriteLine($"Hardware VAES:   {hasVaes}");
Console.WriteLine($"Hardware SHA-NI: {hasShaNi}");
```

---

## 3. Core Cryptographic Recipes

### Recipe 1: AES-256-GCM Authenticated Encryption

Encrypt and decrypt data using hardware VAES and carry-less multiplication:

```csharp
using System.Security.Cryptography;
using Glacier.Codec.Cryptography.AesGcm;

// Prepare key, nonce, and payload spans
ReadOnlySpan<byte> key = stackalloc byte[32];      // 256-bit AES key
ReadOnlySpan<byte> nonce = stackalloc byte[12];    // 96-bit standard nonce
ReadOnlySpan<byte> plaintext = "Confidential columnar record"u8;

Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> tag = stackalloc byte[16];              // 128-bit authentication tag

// Encrypt payload with zero GC allocation
Aes256Gcm.Encrypt(key, nonce, plaintext, ciphertext, tag);

// Decrypt and verify tag in constant time
bool success = Aes256Gcm.Decrypt(key, nonce, ciphertext, tag, plaintext);
if (!success)
{
    throw new CryptographicException("Authentication tag verification failed.");
}
```

---

### Recipe 2: ChaCha20-Poly1305 Stream Encryption

Encrypt streaming data on hardware lacking dedicated AES acceleration:

```csharp
using Glacier.Codec.Cryptography.ChaCha20Poly1305;

ReadOnlySpan<byte> key = stackalloc byte[32];
ReadOnlySpan<byte> nonce = stackalloc byte[12];
ReadOnlySpan<byte> plaintext = "High-speed sensor telemetry"u8;

Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> tag = stackalloc byte[16];

ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ciphertext, tag);
bool valid = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, plaintext);
```

---

### Recipe 3: High-Throughput BLAKE3 Tree Hashing

Compute digests across multi-megabyte buffers using 16-way vector chunk compression:

```csharp
using Glacier.Codec.Hashing.Blake3;

ReadOnlySpan<byte> buffer = GetLargeDataSpan(); // e.g. 16MB file
Span<byte> digest = stackalloc byte[32];

// Automatically routes to 16-way AVX-512 parallel tree reduction
Blake3Hasher.Hash(buffer, digest);
```

---

### Recipe 4: Hardware SHA-256 Digesting

Compute standard FIPS 180-4 digests using raw CPU SHA-NI instructions:

```csharp
using Glacier.Codec.Hashing.Sha256;

ReadOnlySpan<byte> input = "Transaction ledger verification"u8;
Span<byte> hash = stackalloc byte[32];

Sha256.HashData(input, hash);
```

---

### Recipe 5: Argon2id Memory-Hard Key Derivation

Derive secret keys from user passwords with GPU/ASIC trade-off resistance:

```csharp
using Glacier.Codec.Cryptography.Kdf;

ReadOnlySpan<byte> password = "UserMasterPassword"u8;
ReadOnlySpan<byte> salt = stackalloc byte[16]; // Cryptographically random salt
Span<byte> derivedKey = stackalloc byte[32];

// Configure parameters: m = 64MB memory, t = 3 iterations, p = 4 parallel threads
Argon2id.DeriveKey(password, salt, iterations: 3, memoryKiB: 65536, parallelism: 4, derivedKey);
```

---

### Recipe 6: Post-Quantum ML-KEM Key Encapsulation

Generate post-quantum keypairs and exchange shared secrets using NIST FIPS 203:

```csharp
using Glacier.Codec.Cryptography.PostQuantum;

// Generate ML-KEM-768 keypair
Span<byte> publicKey = stackalloc byte[MlKem768.PublicKeyBytes];   // 1184 bytes
Span<byte> secretKey = stackalloc byte[MlKem768.SecretKeyBytes];   // 2400 bytes
MlKem768.GenerateKeyPair(publicKey, secretKey);

// Sender encapsulates shared secret into ciphertext
Span<byte> ciphertext = stackalloc byte[MlKem768.CiphertextBytes]; // 1088 bytes
Span<byte> senderSecret = stackalloc byte[32];
MlKem768.Encapsulate(publicKey, ciphertext, senderSecret);

// Receiver decapsulates shared secret using secret key (constant-time implicit rejection)
Span<byte> receiverSecret = stackalloc byte[32];
MlKem768.Decapsulate(secretKey, ciphertext, receiverSecret);
```

---

## 4. Compression Recipes

### Recipe 7: LZ4 Block & Frame Streaming

Compress and decompress data at $>15\text{ GB/s}$ throughput:

```csharp
using Glacier.Codec.Compression.Lz4;

ReadOnlySpan<byte> source = "Repeated telemetry data series for testing..."u8;
Span<byte> compressed = stackalloc byte[Lz4Codec.GetMaxCompressedSize(source.Length)];

int compressedBytes = Lz4Codec.Compress(source, compressed);

Span<byte> decompressed = stackalloc byte[source.Length];
int decompressedBytes = Lz4Codec.Decompress(compressed.Slice(0, compressedBytes), decompressed);
```

---

### Recipe 8: Zstandard Multi-Block Compression

Compress columnar data into RFC 8878 compliant multi-block frames:

```csharp
using Glacier.Codec.Compression.Zstd;

ReadOnlySpan<byte> source = GetLargeDataset(); // e.g. 500KB
Span<byte> compressed = new byte[ZstdCodec.GetMaxCompressedSize(source.Length)];

int written = ZstdCodec.Compress(source, compressed);

Span<byte> restored = new byte[source.Length];
int restoredBytes = ZstdCodec.Decompress(compressed.Slice(0, written), restored);
```

---

## 5. Memory Management & Zero Allocation

Use `UnmanagedSlabPool` to avoid managed garbage collection pressure:

```csharp
using Glacier.Codec.Memory;

// Rent 64KB unmanaged slab
using SlabLease lease = UnmanagedSlabPool.Shared.Rent(65536);
Span<byte> buffer = lease.Span;

// Perform high-throughput work
ProcessBuffer(buffer);

// Memory is automatically zero-wiped upon lease.Dispose()
```

---

## 6. Fault Isolation and Troubleshooting

| Symptom | Root Cause | Remediation Procedure |
| :--- | :--- | :--- |
| `CryptographicException: Tag mismatch` | Ciphertext or tag was modified in transit. | Verify network integrity; reject payload immediately. |
| `ArgumentException: Destination too small` | Output span is smaller than maximum compressed size. | Call `GetMaxCompressedSize()` to size destination buffers. |
| Reduced throughput on older CPUs | Silicon lacks AVX-512 or VAES instruction support. | Verify CPU flags with `CpuCapabilities`; engine uses scalar fallbacks. |
| Memory leaks in custom loops | `SlabLease` or `SecureMemory` was not disposed. | Wrap leases in `using` blocks to trigger deterministic zeroing. |
