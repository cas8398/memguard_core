library memguard_core;

/// Dart-only plugin class (no C++)
class MemGuardPlugin {
  /// Called by Flutter
  static void registerWith() {
    // Empty - Dart loads .so via FFI directly
  }
}
