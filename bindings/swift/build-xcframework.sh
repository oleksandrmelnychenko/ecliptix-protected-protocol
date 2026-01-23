#!/usr/bin/env bash
#
# XCFramework Build Script for Ecliptix.Protection.Protocol
# Creates a combined XCFramework for iOS + macOS Swift Package distribution
#
# This script:
# 1. Builds dependencies via vcpkg for each platform
# 2. Builds the protocol library for iOS Device, Simulator, and macOS
# 3. Merges all static libraries into platform-specific fat binaries
# 4. Creates a single XCFramework with all platforms bundled
#
# Usage: ./build-xcframework.sh [Release|Debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"
BUILD_TYPE="${1:-Release}"
VERSION="${VERSION:-1.0.0}"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-17.0}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-11.0}"

VCPKG_ROOT="${VCPKG_ROOT:-$ROOT_DIR/.build/vcpkg}"

echo "========================================"
echo "XCFramework Build - Ecliptix Protocol"
echo "========================================"
echo "Build Type: $BUILD_TYPE"
echo "Version: $VERSION"
echo ""

mkdir -p "$ARTIFACT_DIR"

# ============================================
# Setup vcpkg
# ============================================
setup_vcpkg() {
    if [ ! -d "$VCPKG_ROOT" ]; then
        echo "Setting up vcpkg..."
        git clone https://github.com/microsoft/vcpkg "$VCPKG_ROOT"
        "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
    fi
}

# ============================================
# Build dependencies for a triplet
# ============================================
build_deps() {
    local TRIPLET=$1
    echo ""
    echo "Installing dependencies for $TRIPLET..."
    echo "----------------------------------------"

    # Use minimal liboqs build
    export VCPKG_FORCE_SYSTEM_BINARIES=1

    "$VCPKG_ROOT/vcpkg" install \
        libsodium \
        "liboqs[core]" \
        openssl \
        protobuf \
        --triplet "$TRIPLET" \
        --x-install-root="$VCPKG_ROOT/installed" \
        || true
}

# ============================================
# Build protocol library for a platform
# ============================================
build_platform() {
    local PLATFORM_NAME=$1
    local TRIPLET=$2
    local SYSROOT=$3
    local ARCHS=$4
    local DEPLOYMENT_TARGET=$5

    local BUILD_DIR="$ROOT_DIR/build-$PLATFORM_NAME"

    echo ""
    echo "Building for $PLATFORM_NAME ($ARCHS)..."
    echo "========================================"

    rm -rf "$BUILD_DIR"

    export PKG_CONFIG_PATH="$VCPKG_ROOT/installed/$TRIPLET/lib/pkgconfig:$VCPKG_ROOT/installed/$TRIPLET/share/pkgconfig"
    export PKG_CONFIG_SYSROOT_DIR="$VCPKG_ROOT/installed/$TRIPLET"

    cmake -B "$BUILD_DIR" -S "$ROOT_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DECLIPTIX_BUILD_TESTS=OFF \
        -DECLIPTIX_BUILD_EXAMPLES=OFF \
        -DECLIPTIX_BUILD_SERVER_TARGET=OFF \
        -DECLIPTIX_BUILD_CLIENT_TARGET=ON \
        -DECLIPTIX_BUILD_SHARED=OFF \
        -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
        -DVCPKG_TARGET_TRIPLET="$TRIPLET" \
        -DCMAKE_OSX_SYSROOT="$SYSROOT" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCHS" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET"

    cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel

    echo "$PLATFORM_NAME build completed!"
}

# ============================================
# Merge libraries for a platform
# ============================================
merge_libs() {
    local PLATFORM_NAME=$1
    local TRIPLET=$2
    local OUTPUT_LIB=$3

    local BUILD_DIR="$ROOT_DIR/build-$PLATFORM_NAME"
    local VCPKG_LIB_DIR="$VCPKG_ROOT/installed/$TRIPLET/lib"

    echo ""
    echo "Merging libraries for $PLATFORM_NAME..."

    # Find the built library
    local LIB_EPP=""
    for candidate in "$BUILD_DIR/libepp_agent.a" "$BUILD_DIR/Release/libepp_agent.a" "$BUILD_DIR/src/libepp_agent.a"; do
        if [ -f "$candidate" ]; then
            LIB_EPP="$candidate"
            break
        fi
    done

    if [ -z "$LIB_EPP" ]; then
        echo "Error: libepp_agent.a not found in $BUILD_DIR" >&2
        find "$BUILD_DIR" -name "*.a" 2>/dev/null || true
        exit 1
    fi

    echo "Found library: $LIB_EPP"

    # Collect dependencies
    local DEPS=()
    for dep in libsodium.a liboqs.a libssl.a libcrypto.a libprotobuf.a; do
        if [ -f "$VCPKG_LIB_DIR/$dep" ]; then
            DEPS+=("$VCPKG_LIB_DIR/$dep")
        fi
    done

    echo "Dependencies: ${DEPS[*]}"

    # Merge with libtool
    libtool -static -o "$OUTPUT_LIB" "$LIB_EPP" "${DEPS[@]}"

    echo "Merged library: $OUTPUT_LIB ($(du -h "$OUTPUT_LIB" | cut -f1))"
}

# ============================================
# Create framework structure
# ============================================
create_framework() {
    local PLATFORM_NAME=$1
    local LIB_PATH=$2
    local FRAMEWORK_DIR=$3

    echo ""
    echo "Creating framework for $PLATFORM_NAME..."

    rm -rf "$FRAMEWORK_DIR"
    mkdir -p "$FRAMEWORK_DIR/Headers" "$FRAMEWORK_DIR/Modules"

    # Copy headers
    cp "$ROOT_DIR/include/ecliptix/c_api/epp_api.h" "$FRAMEWORK_DIR/Headers/"
    cp "$ROOT_DIR/include/ecliptix/c_api/epp_export.h" "$FRAMEWORK_DIR/Headers/"

    # Create module map
    cat > "$FRAMEWORK_DIR/Modules/module.modulemap" <<'EOF'
module EcliptixProtocolC {
  header "epp_api.h"
  header "epp_export.h"
  export *
}
EOF

    # Create Info.plist
    cat > "$FRAMEWORK_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.ecliptix.protocol.c</string>
  <key>CFBundleName</key>
  <string>EcliptixProtocolC</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
</dict>
</plist>
EOF

    # Copy merged library
    cp "$LIB_PATH" "$FRAMEWORK_DIR/EcliptixProtocolC"

    echo "Framework created: $FRAMEWORK_DIR"
}

# ============================================
# Main Build Process
# ============================================

setup_vcpkg

# Build for each platform
echo ""
echo "Step 1: Building dependencies..."
echo "========================================"

build_deps "arm64-ios"
build_deps "arm64-ios-simulator"
build_deps "x64-ios-simulator"
build_deps "arm64-osx"
build_deps "x64-osx"

echo ""
echo "Step 2: Building protocol library..."
echo "========================================"

# iOS Device (arm64)
build_platform "ios-device" "arm64-ios" "iphoneos" "arm64" "$IOS_DEPLOYMENT_TARGET"

# iOS Simulator (arm64)
build_platform "ios-sim-arm64" "arm64-ios-simulator" "iphonesimulator" "arm64" "$IOS_DEPLOYMENT_TARGET"

# iOS Simulator (x86_64)
build_platform "ios-sim-x64" "x64-ios-simulator" "iphonesimulator" "x86_64" "$IOS_DEPLOYMENT_TARGET"

# macOS (arm64)
build_platform "macos-arm64" "arm64-osx" "macosx" "arm64" "$MACOS_DEPLOYMENT_TARGET"

# macOS (x86_64)
build_platform "macos-x64" "x64-osx" "macosx" "x86_64" "$MACOS_DEPLOYMENT_TARGET"

echo ""
echo "Step 3: Merging libraries..."
echo "========================================"

MERGED_DIR="$ROOT_DIR/build-merged"
mkdir -p "$MERGED_DIR"

merge_libs "ios-device" "arm64-ios" "$MERGED_DIR/libepp-ios-device.a"
merge_libs "ios-sim-arm64" "arm64-ios-simulator" "$MERGED_DIR/libepp-ios-sim-arm64.a"
merge_libs "ios-sim-x64" "x64-ios-simulator" "$MERGED_DIR/libepp-ios-sim-x64.a"
merge_libs "macos-arm64" "arm64-osx" "$MERGED_DIR/libepp-macos-arm64.a"
merge_libs "macos-x64" "x64-osx" "$MERGED_DIR/libepp-macos-x64.a"

# Create fat libraries
echo ""
echo "Creating fat libraries..."

lipo -create \
    "$MERGED_DIR/libepp-ios-sim-arm64.a" \
    "$MERGED_DIR/libepp-ios-sim-x64.a" \
    -output "$MERGED_DIR/libepp-ios-simulator.a"

lipo -create \
    "$MERGED_DIR/libepp-macos-arm64.a" \
    "$MERGED_DIR/libepp-macos-x64.a" \
    -output "$MERGED_DIR/libepp-macos.a"

echo ""
echo "Step 4: Creating frameworks..."
echo "========================================"

FRAMEWORKS_DIR="$ROOT_DIR/build-frameworks"
rm -rf "$FRAMEWORKS_DIR"
mkdir -p "$FRAMEWORKS_DIR"

create_framework "ios-device" "$MERGED_DIR/libepp-ios-device.a" "$FRAMEWORKS_DIR/ios-device/EcliptixProtocolC.framework"
create_framework "ios-simulator" "$MERGED_DIR/libepp-ios-simulator.a" "$FRAMEWORKS_DIR/ios-simulator/EcliptixProtocolC.framework"
create_framework "macos" "$MERGED_DIR/libepp-macos.a" "$FRAMEWORKS_DIR/macos/EcliptixProtocolC.framework"

echo ""
echo "Step 5: Creating XCFramework..."
echo "========================================"

XCFRAMEWORK_DIR="$ROOT_DIR/build-xcframework/EcliptixProtocolC.xcframework"
rm -rf "$ROOT_DIR/build-xcframework"
mkdir -p "$ROOT_DIR/build-xcframework"

xcodebuild -create-xcframework \
    -framework "$FRAMEWORKS_DIR/ios-device/EcliptixProtocolC.framework" \
    -framework "$FRAMEWORKS_DIR/ios-simulator/EcliptixProtocolC.framework" \
    -framework "$FRAMEWORKS_DIR/macos/EcliptixProtocolC.framework" \
    -output "$XCFRAMEWORK_DIR"

echo "XCFramework created!"

echo ""
echo "Step 6: Verifying XCFramework..."
echo "========================================"

ls -la "$XCFRAMEWORK_DIR"

echo ""
echo "Step 7: Creating archive..."
echo "========================================"

ZIP_PATH="$ARTIFACT_DIR/EcliptixProtocolC.xcframework.zip"
rm -f "$ZIP_PATH"
(cd "$ROOT_DIR/build-xcframework" && zip -r "$ZIP_PATH" "EcliptixProtocolC.xcframework")

CHECKSUM="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
echo "$CHECKSUM" > "$ARTIFACT_DIR/EcliptixProtocolC.xcframework.checksum"

# Cleanup
rm -rf "$MERGED_DIR" "$FRAMEWORKS_DIR"

echo ""
echo "========================================"
echo "XCFramework Build Complete!"
echo "========================================"
echo ""
echo "Output:"
echo "  XCFramework: $XCFRAMEWORK_DIR"
echo "  Archive:     $ZIP_PATH"
echo "  Checksum:    $CHECKSUM"
echo ""
echo "Platforms:"
echo "  - iOS Device (arm64)"
echo "  - iOS Simulator (arm64, x86_64)"
echo "  - macOS (arm64, x86_64)"
echo ""
