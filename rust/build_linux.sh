#!/bin/bash
set -e

echo "🔧 Building Rust library for Android/Linux..."

# Android targets
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "i686-linux-android"
    "x86_64-linux-android"
)

# Linux desktop targets
LINUX_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

echo "📱 Building for Android..."
for target in "${TARGETS[@]}"; do
    echo "  Building $target..."
    cargo ndk -p 31 --target $target build --release
done

echo "🖥️ Building for Linux Desktop..."
for target in "${LINUX_TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --target $target --release
done

echo "✅ Linux build complete!"