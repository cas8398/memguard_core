# MemGuard Core

![Android](https://img.shields.io/badge/Android-Supported-brightgreen)
![iOS](https://img.shields.io/badge/iOS-Not%20Tested-lightgrey)
![Windows](https://img.shields.io/badge/Windows-Not%20Tested-lightgrey)
![macOS](https://img.shields.io/badge/macOS-Not%20Tested-lightgrey)
![Linux](https://img.shields.io/badge/Linux-Not%20Tested-lightgrey)

**Zero-leak secure storage for Flutter with hardware-backed encryption and memory-safe Rust FFI.**

> ⚠️ **IMPORTANT**: This is the **core native implementation** containing Rust `.so` libraries and Kotlin `.kt` integration code. This is NOT a standalone Flutter plugin. For the complete Flutter package with Dart API, use the main **MemGuard Plugin** (coming soon).

---

## Overview

MemGuard Core is the **native foundation** for the MemGuard secure storage system. It provides:

- **Rust FFI** (`.so` shared libraries) for memory-safe caching
- **Kotlin integration** (`.kt`) with Android KeyStore encryption
- **Zero-leak architecture** across Dart VM, platform channels, and native layers

This repository contains only the native components (Rust + Kotlin). For the complete Flutter plugin with Dart API, see the main **MemGuard Plugin** repository.

### What's Included

- ✅ Compiled Rust `.so` libraries for ARM/x86 architectures
- ✅ Kotlin platform channel implementation
- ✅ Hardware-backed AES-256-GCM encryption
- ✅ Protected memory management via Rust FFI

### What's NOT Included

- ❌ Dart API layer
- ❌ Flutter plugin boilerplate
- ❌ High-level MemGuard class interface
- ❌ Pub.dev package (use the main MemGuard Plugin instead)

---

## For Plugin Developers

If you're building a Flutter plugin that needs secure storage, you can:

1. Include these native libraries in your plugin
2. Use the Kotlin implementation as-is or customize it
3. Build your own Dart API on top of the platform channel

For end users, **wait for the main MemGuard Plugin** which wraps this core in a Flutter-friendly package.

---

## Architecture (Native Layer)

MemGuard Core implements true secure storage with **zero plaintext leaks** across the entire stack:

- **Dart VM**: Sensitive data never touches Dart memory—all values live in Rust's protected memory space
- **Platform Channel**: Only returns boolean flags (`true`/`false`/`null`/`rust_not_ready`)—never plaintext values
- **Native Storage**: Hardware-backed AES-256-GCM encryption via Android KeyStore (TEE/StrongBox)
- **Memory Cache**: Rust FFI layer with protected memory allocation for ultra-fast access

This architecture eliminates common attack vectors like heap dumps, memory inspection, and platform channel interception.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         DART LAYER                              │
│  • Never stores plaintext in Dart VM memory                    │
│  • Calls Rust FFI directly for all read operations             │
└──────────────────┬──────────────────────────────────────────────┘
                   │ Boolean signals only (true/false/null/rust_not_ready)
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PLATFORM CHANNEL                             │
│  • NEVER transmits plaintext values                            │
│  • Returns metadata/status flags only                          │
└──────────────────┬──────────────────────────────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌──────────────────┐  ┌────────────────────┐
│  KOTLIN LAYER    │  │   RUST FFI CACHE   │
│                  │  │                    │
│ • Encrypts with  │  │ • Protected memory │
│   KeyStore       │  │ • Zero-copy access │
│ • AES-256-GCM    │  │ • Hot path reads   │
│ • StrongBox/TEE  │  │                    │
└────────┬─────────┘  └─────────┬──────────┘
         │                      │
         │ Encrypted storage    │ Direct FFI
         ▼                      ▼
┌──────────────────────────────────┐
│     PERSISTENT STORAGE           │
│  (Encrypted files on disk)       │
└──────────────────────────────────┘
```

### Key Design Principles

1. **No Dart VM Exposure**: Sensitive data bypasses Dart entirely—retrieved directly from Rust
2. **Channel Security**: Platform channels return only operation status, never plaintext
3. **Hardware-Backed Keys**: Android KeyStore ensures keys never leave secure hardware
4. **Memory Protection**: Rust FFI provides protected memory allocation with explicit zeroing
5. **Tiered Caching**: Hot path reads from Rust memory, cold storage encrypted on disk

---

## Security Features

### 🔒 Hardware-Backed Encryption

- **AES-256-GCM** with 128-bit authentication tags
- **Android KeyStore** integration (StrongBox → TEE fallback)
- Keys never extractable from secure hardware
- Randomized IVs for every encryption operation

### 🛡️ Memory Protection

- **Zero Dart VM exposure** for sensitive values
- **Rust protected memory** with explicit zeroing on drop
- **No platform channel leaks**—boolean flags only
- Rate-limited direct access (5 calls/minute per key)

### 🔐 Data Integrity

- GCM authentication prevents tampering
- SHA-256 key derivation for file storage
- Atomic file operations with synchronized locks
- Comprehensive error handling for key invalidation

### 🚨 Attack Resistance

- **Memory dump safe**: No plaintext in Dart heap
- **Channel interception safe**: No sensitive data transmitted
- **Root detection**: Hardware keys resist extraction
- **Tamper detection**: GCM authentication tags verify integrity

---

## API Reference

> **Note**: These APIs are exposed via Kotlin platform channels. The main MemGuard Plugin provides a Flutter-friendly Dart wrapper.

### Core Operations (Platform Channel)

```dart
// Store securely (encrypts + caches in Rust)
await MemGuard.store('api_key', 'secret_value');

// Retrieve (always from Rust FFI—never touches Dart VM)
String? value = await MemGuard.retrieve('api_key');

// Check existence
bool exists = await MemGuard.contains('api_key');

// Delete
await MemGuard.delete('api_key');

// Emergency direct access (rate-limited, hydrates Rust cache)
String? coldValue = await MemGuard.retrieveDirect('api_key');

// Get storage statistics
Map<String, dynamic> stats = await MemGuard.getStats();

// Cleanup all data
await MemGuard.cleanupAll();
```

### Emergency Direct Access

`retrieveDirect()` is a **controlled exception** to the zero-leak protocol:

**When to use:**

- Cold app start before Rust FFI initialization
- Hot restart/reload in debug mode
- Recovery from corrupted Rust state

**Why it's acceptable:**

- Alternative is silent data loss (worse for security)
- Still encrypted with hardware-backed keys
- Data stays within app process boundary
- Rate limited (5 calls/minute per key)
- Immediately re-caches in Rust for future access

**Never use in hot path** or regular read/write operations.

---

## Platform Channel Contract

### Return Value Semantics

| Return Value       | Meaning                     | Dart Action                             |
| ------------------ | --------------------------- | --------------------------------------- |
| `true`             | Success, data in Rust cache | Call Rust FFI to retrieve actual value  |
| `false`            | Negative/doesn't exist      | Handle as not found                     |
| `null`             | Not found                   | Handle as not found                     |
| `"rust_not_ready"` | Rust FFI not initialized    | Use `retrieveDirect()` or wait for init |
| Error              | Operation failed            | Handle error                            |

### Critical Rule

**Platform channels NEVER transmit plaintext values.** All sensitive data retrieval happens via direct Rust FFI calls from Dart.

---

## Storage Stats Example

```dart
final stats = await MemGuard.getStats();
print(stats);
// {
//   "storage_type": "hardware_backed_keystore",
//   "encryption_type": "aes_256_gcm",
//   "key_strength": "256_bit",
//   "rust_initialized": true,
//   "items_count": 42,
//   "total_size_bytes": 8192,
//   "directory_path": "/data/user/0/com.app/files/memguard_secure",
//   "timestamp": 1701234567890
// }
```

---

## Error Handling

```dart
try {
  await MemGuard.store('key', 'value');
} on PlatformException catch (e) {
  switch (e.code) {
    case 'KEY_INVALID':
      // KeyStore key was invalidated (device security changed)
      // Data unrecoverable—user must re-authenticate
      break;
    case 'SECURITY_ERROR':
      // Hardware security module failure
      break;
    case 'RATE_LIMIT_EXCEEDED':
      // Too many direct access calls—use normal retrieve()
      break;
    case 'RETRIEVE_FAILED':
      // Decryption failure (corruption or tampering)
      break;
  }
}
```

---

## Implementation Details

### Encryption Specification

- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits
- **IV Size**: 12 bytes (GCM standard)
- **Tag Size**: 128 bits
- **Key Storage**: Android KeyStore (non-extractable)
- **Randomization**: Cryptographically secure per-operation IVs

### File Storage

- **Naming**: SHA-256 hash of key → `mg_<hash>.dat`
- **Location**: `{app_files_dir}/memguard_secure/`
- **Format**: `[12-byte IV || ciphertext || 16-byte auth tag]`
- **Encoding**: Base64 (NO_WRAP)

### Concurrency Safety

- Synchronized file locks per key
- Atomic read/write/delete operations
- Thread-safe Rust FFI wrapper
- ConcurrentHashMap for lock management

---

## Requirements

### Native Build Requirements

- **Android NDK**: r21+ for Rust cross-compilation
- **Rust Toolchain**: 1.70+ with Android targets
  ```bash
  rustup target add aarch64-linux-android
  rustup target add armv7-linux-androideabi
  rustup target add x86_64-linux-android
  rustup target add i686-linux-android
  ```

### Runtime Requirements

- **Android**: API 23+ (Android 6.0 Marshmallow)
  - API 28+ recommended for StrongBox support
- **Flutter**: 3.0+ (for main plugin integration)
- **Dart**: 2.17+ (for main plugin integration)

---

## Building from Source

```bash
# 1. Build Rust FFI libraries
cd rust/
cargo build --release --target aarch64-linux-android

# 2. Copy .so files to android/src/main/jniLibs/
# 3. Kotlin code is ready to use as-is
```

See `BUILDING.md` for detailed cross-compilation instructions.

---

## Integration Guide

### For Plugin Developers

1. **Include native libraries**:

   ```
   your_plugin/
   ├── android/
   │   ├── src/main/
   │   │   ├── jniLibs/
   │   │   │   ├── arm64-v8a/
   │   │   │   │   └── libmemguard_ffi.so
   │   │   │   └── [other architectures]
   │   │   └── kotlin/
   │   │       └── MemGuardPlugin.kt
   ```

2. **Register platform channel** in your plugin's main class
3. **Build Dart API** on top of the platform channel contract
4. **Document the zero-leak architecture** for your users

See `INTEGRATION.md` for complete examples.

---

## Related Repositories

- **MemGuard Plugin** (coming soon) - Complete Flutter package with Dart API
- **MemGuard Examples** (coming soon) - Sample apps demonstrating usage

---

## Requirements

### Runtime Requirements

- **Android**: API 23+ (Android 6.0 Marshmallow)
  - API 28+ recommended for StrongBox support
- **Flutter**: 3.0+ (for main plugin integration)
- **Dart**: 2.17+ (for main plugin integration)
- **Rust**: 1.70+ (for native FFI compilation)

---

## Known Limitations

- **iOS/Desktop**: Not yet tested (Android-only currently)
- **Root Detection**: Hardware keys resist but don't prevent rooted device access
- **Key Invalidation**: Biometric changes may invalidate keys (by design—controlled via `setInvalidatedByBiometricEnrollment`)
- **Storage Limit**: Practical limit ~5MB per value (KeyStore constraint)

---

## Security Considerations

### What MemGuard Protects Against

✅ Memory dumps of Dart VM  
✅ Platform channel interception  
✅ Heap inspection attacks  
✅ Data tampering (GCM authentication)  
✅ Key extraction (hardware-backed)

### What MemGuard Does NOT Protect Against

❌ Rooted devices with kernel-level access  
❌ Physical device seizure by sophisticated attackers  
❌ Compromised system frameworks (OS-level malware)  
❌ User-authorized screen recording/accessibility services

**Use case**: MemGuard is ideal for protecting API keys, tokens, credentials, and PII in production apps. It is NOT a substitute for end-to-end encryption or protection against state-level adversaries.

---

## License

[Add your license here]

---

## Contributing

Contributions to the native core are welcome! Please ensure:

- Rust code passes `cargo clippy` and `cargo test`
- Kotlin code follows Android best practices
- Security-critical changes are thoroughly reviewed

See `CONTRIBUTING.md` for guidelines.

---

## Support

For questions about:

- **Using MemGuard**: See the main MemGuard Plugin repository
- **Native integration**: Open an issue in this repository
- **Security concerns**: Email [your security contact]

---

## Acknowledgments

Built with:

- Android KeyStore for hardware-backed encryption
- Rust FFI for memory-safe caching
- GCM for authenticated encryption

---

**⚠️ Security Notice**: This library implements defense-in-depth secure storage. However, no client-side storage is absolutely secure. Always validate critical operations server-side and use additional layers (certificate pinning, request signing, etc.) for high-security applications.
