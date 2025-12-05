# Changelog for memguard_core

## [2.1.4]

- Added Linux platform support (x86_64, glibc 2.31+).

## [2.1.3]

### Added

- Initial release of `memguard_core`.
- Rust FFI integration for secure in-memory storage.
- AES-256-GCM hardware-backed encryption on Android.
- File-based persistent storage with key hashing.
- Rate-limiting for direct retrievals.
- Methods for store, retrieve, delete, contains, and cleanup.
- Secure key management via Android Keystore.
- Stats collection and storage in Rust under a fixed hash key.
- Thread-safe file operations with per-file locks.
- Emergency direct retrieval for recovery scenarios.
