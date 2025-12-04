#!/bin/bash
set -e

echo "🔧 Building Rust library..."

# Set NDK
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/28.0.12433566}"
echo "NDK: $ANDROID_NDK_HOME"

# Build all targets
echo "Building for Android..."
cargo ndk -p 31 --target aarch64-linux-android build --release
cargo ndk -p 31 --target armv7-linux-androideabi build --release
cargo ndk -p 31 --target i686-linux-android build --release
cargo ndk -p 31 --target x86_64-linux-android build --release

echo "✅ Rust build complete!"