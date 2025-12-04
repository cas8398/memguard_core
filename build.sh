#!/bin/bash
set -e

echo "========================================="
echo "🤖 Building Flutter MemGuard"
echo "========================================="

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================
# Check environment
# ==============================
echo -e "${BLUE}📦 Flutter package: $(pwd)${NC}"

# Check if we're in the right directory
if [ ! -f "pubspec.yaml" ]; then
    echo -e "${RED}❌ Error: Not in Flutter package root directory${NC}"
    echo "Make sure you're in the directory containing pubspec.yaml"
    exit 1
fi

# Check if cargo-ndk is installed
if ! command -v cargo-ndk &> /dev/null; then
    echo -e "${YELLOW}⚠️  cargo-ndk not found. Installing...${NC}"
    cargo install cargo-ndk
fi

# ==============================
# 1. Clean previous builds
# ==============================
echo -e "\n${YELLOW}🧹 Cleaning previous builds...${NC}"
rm -rf rust/build/android/* 2>/dev/null || true
rm -rf rust/android/src/main/jniLibs/* 2>/dev/null || true
rm -rf rust/target 2>/dev/null || true


# ==============================
# 2. Install Rust targets if needed
# ==============================
echo -e "\n${YELLOW}🔧 Checking/installing Rust targets...${NC}"
for arch in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
    echo -n "  $arch: "
    if rustup target list | grep -q "$arch (installed)"; then
        echo -e "${GREEN}✓ installed${NC}"
    else
        echo -e "${BLUE}↓ installing${NC}"
        rustup target add "$arch"
    fi
done

# ==============================
# 3. Build Rust code
# ==============================
echo -e "\n${YELLOW}🏗️  Building Rust FFI...${NC}"
cd rust

# Check if Cargo.toml exists
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}❌ Error: Cargo.toml not found in rust/${NC}"
    exit 1
fi

# Set NDK path (update this to your NDK path)
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/28.0.12433566}"
echo -e "${BLUE}📦 Using NDK: $ANDROID_NDK_HOME${NC}"

# Build for each architecture
build_success=true
for arch in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
    echo -e "\n${BLUE}→ Building $arch...${NC}"
    
    if cargo ndk -p 31 --target $arch build --release; then
        echo -e "  ${GREEN}✓ Build successful${NC}"
        
        # Copy the .so file with proper Android ABI structure
        so_name="libmemguard_ffi.so"
        so_path="target/$arch/release/$so_name"
        
        if [ -f "$so_path" ]; then
            case $arch in
                "aarch64-linux-android")
                    mkdir -p "build/android/arm64-v8a"
                    cp "$so_path" "build/android/arm64-v8a/$so_name"
                    echo "  ${GREEN}✓ Copied to build/android/arm64-v8a/$so_name${NC}"
                    ;;
                "armv7-linux-androideabi")
                    mkdir -p "build/android/armeabi-v7a"
                    cp "$so_path" "build/android/armeabi-v7a/$so_name"
                    echo "  ${GREEN}✓ Copied to build/android/armeabi-v7a/$so_name${NC}"
                    ;;
                "i686-linux-android")
                    mkdir -p "build/android/x86"
                    cp "$so_path" "build/android/x86/$so_name"
                    echo "  ${GREEN}✓ Copied to build/android/x86/$so_name${NC}"
                    ;;
                "x86_64-linux-android")
                    mkdir -p "build/android/x86_64"
                    cp "$so_path" "build/android/x86_64/$so_name"
                    echo "  ${GREEN}✓ Copied to build/android/x86_64/$so_name${NC}"
                    ;;
            esac
        else
            echo -e "  ${YELLOW}⚠️  .so file not found at: $so_path${NC}"
            build_success=false
        fi
    else
        echo -e "  ${RED}✗ Failed to build $arch${NC}"
        build_success=false
    fi
done

# ==============================
# 4. Copy to jniLibs
# ==============================

echo -e "\n${YELLOW}📦 Copying libraries to Flutter package jniLibs...${NC}"

# Clear jniLibs directory in package structure (NOT app/)
rm -rf android/src/main/jniLibs/* 2>/dev/null || true

# Copy from build/android to package jniLibs
if [ -d "build/android" ]; then
    # Copy each ABI directory
    for abi_dir in build/android/*/; do
        if [ -d "$abi_dir" ]; then
            abi_name=$(basename "$abi_dir")
            mkdir -p "android/src/main/jniLibs/$abi_name"
            
            # Copy all .so files from this ABI directory
            if cp "$abi_dir"*.so "android/src/main/jniLibs/$abi_name/" 2>/dev/null; then
                count=$(ls -1 "android/src/main/jniLibs/$abi_name/"*.so 2>/dev/null | wc -l)
                echo -e "  ${GREEN}✓ $abi_name/: Copied $count file(s)${NC}"
            else
                echo -e "  ${YELLOW}⚠️  $abi_name/: No .so files to copy${NC}"
            fi
        fi
    done
    
    # Also copy any flat .so files (for backward compatibility)
    if ls build/android/*.so 1>/dev/null 2>&1; then
        mkdir -p android/src/main/jniLibs
        cp build/android/*.so android/src/main/jniLibs/ 2>/dev/null || true
        flat_count=$(ls -1 build/android/*.so 2>/dev/null | wc -l)
        if [ $flat_count -gt 0 ]; then
            echo -e "  ${GREEN}✓ Copied $flat_count flat .so file(s)${NC}"
        fi
    fi
else
    echo -e "  ${RED}✗ build/android directory not found!${NC}"
    build_success=false
fi

# ==============================
# 5. Show results
# ==============================
echo -e "\n${YELLOW}=========================================${NC}"
echo -e "${YELLOW}📊 Build Results${NC}"
echo -e "${YELLOW}=========================================${NC}"

if [ "$build_success" = true ]; then
    echo -e "\n${GREEN}✅ All architectures built successfully!${NC}"
else
    echo -e "\n${YELLOW}⚠️  Some architectures failed to build${NC}"
fi

# Show what's in jniLibs
echo -e "\n${BLUE}📁 Files in android/src/main/jniLibs/:${NC}"
if [ -d "android/src/main/jniLibs" ]; then
    if ls android/src/main/jniLibs/*/*.so 1>/dev/null 2>&1 || ls android/src/main/jniLibs/*.so 1>/dev/null 2>&1; then
        # Show ABI directories first
        for abi_dir in android/src/main/jniLibs/*/; do
            if [ -d "$abi_dir" ]; then
                abi_name=$(basename "$abi_dir")
                echo -e "\n${BLUE}📦 $abi_name/${NC}"
                ls -lh "$abi_dir"*.so 2>/dev/null | while read line; do echo "  $line"; done || echo -e "  ${YELLOW}No .so files${NC}"
            fi
        done
        
        # Show flat files
        if ls android/src/main/jniLibs/*.so 1>/dev/null 2>&1; then
            echo -e "\n${BLUE}📦 Root files:${NC}"
            ls -lh android/src/main/jniLibs/*.so | while read line; do echo "  $line"; done
        fi
    else
        echo -e "${YELLOW}No .so files found in jniLibs${NC}"
    fi
else
    echo -e "${YELLOW}jniLibs directory not found${NC}"
fi


# ==============================
# 6. Finish 
# ==============================
echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}🚀 Build process completed!${NC}"
echo -e "${GREEN}=========================================${NC}"

exit 0