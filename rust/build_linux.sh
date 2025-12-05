#!/bin/bash
set -e

echo "🐧 Linux-Only Build System"
echo "=========================="

# Verify we're on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "❌ This script only works on Linux!"
    echo "   Current OS: $(uname -s)"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
echo "📋 Architecture: $ARCH"

# Determine Rust target based on architecture
case "$ARCH" in
    "x86_64")
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    "aarch64"|"arm64")
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    "armv7l")
        TARGET="armv7-unknown-linux-gnueabihf"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "🎯 Building for: $TARGET"

# Install target if needed
if ! rustup target list | grep -q "$TARGET (installed)"; then
    echo "📦 Installing target: $TARGET"
    rustup target add "$TARGET"
fi

# Clean previous build
echo "🧹 Cleaning previous build..."
cargo clean

# Build release
echo "🔨 Building release version..."
cargo build --target "$TARGET" --release

# Find and copy the .so file
SO_FILE="target/$TARGET/release/libmemguard_ffi.so"
if [ -f "$SO_FILE" ]; then
    echo "✅ Built: $SO_FILE"
    
    # Copy to Flutter plugin directory
    mkdir -p linux
    cp "$SO_FILE" linux/libmemguard_ffi.so
    echo "📁 Copied to: linux/libmemguard_ffi.so"
    
    # Verify
    echo "📊 Verification:"
    ls -lh linux/libmemguard_ffi.so
    file linux/libmemguard_ffi.so
else
    echo "❌ No .so file found!"
    echo "🔍 Searching in target directory..."
    find target -name "*.so" -type f
    exit 1
fi

echo ""
echo "🎉 Linux build complete!"