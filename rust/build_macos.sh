#!/bin/bash
set -e

echo "🍎 Building Rust library for iOS/macOS..."

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"          # iOS ARM64 (iPhone)
    "x86_64-apple-ios"           # iOS Simulator x86_64
    "aarch64-apple-ios-sim"      # iOS Simulator ARM64 (M1/M2)
)

# macOS targets
MACOS_TARGETS=(
    "x86_64-apple-darwin"        # Intel Mac
    "aarch64-apple-darwin"       # Apple Silicon Mac
)

echo "📱 Building for iOS..."
for target in "${IOS_TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --target $target --release
done

echo "🖥️ Building for macOS..."
for target in "${MACOS_TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --target $target --release
done

echo "✅ macOS build complete!"