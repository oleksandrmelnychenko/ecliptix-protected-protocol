#!/usr/bin/env bash
#
# iOS XCFramework Build Script for Ecliptix.Protection.Protocol
# Builds for iOS Device (arm64) and iOS Simulator (arm64 + x86_64)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"

VCPKG_ROOT="${VCPKG_ROOT:-$ROOT_DIR/.build/vcpkg}"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-17.0}"
VERSION="${VERSION:-0.0.0}"
BUILD_TYPE="${BUILD_TYPE:-Release}"

echo "========================================"
echo "XCFramework Build - Ecliptix Protocol"
echo "========================================"
echo "Version: $VERSION"
echo "Build Type: $BUILD_TYPE"
echo ""

mkdir -p "$ARTIFACT_DIR"

# ============================================
# Setup vcpkg
# ============================================
if [ ! -d "$VCPKG_ROOT" ]; then
    echo "Setting up vcpkg..."
    git clone https://github.com/microsoft/vcpkg "$VCPKG_ROOT"
    "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
fi

# ============================================
# Install dependencies for each triplet
# ============================================
install_deps() {
    local TRIPLET=$1
    echo ""
    echo "Installing dependencies for $TRIPLET..."
    "$VCPKG_ROOT/vcpkg" install \
        libsodium \
        "liboqs[core]" \
        openssl \
        protobuf \
        --triplet "$TRIPLET" \
        --x-install-root="$VCPKG_ROOT/installed"
}

install_deps "arm64-ios"
install_deps "arm64-ios-simulator"

# ============================================
# Build function
# ============================================
build_platform() {
    local PLATFORM_NAME=$1
    local TRIPLET=$2
    local SYSROOT=$3
    local ARCH=$4

    local BUILD_DIR="$ROOT_DIR/build-$PLATFORM_NAME"

    echo ""
    echo "Building for $PLATFORM_NAME..."
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
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

    cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel

    echo "$PLATFORM_NAME build completed!"
}

# Build for both platforms
build_platform "ios-device" "arm64-ios" "iphoneos" "arm64"
build_platform "ios-simulator" "arm64-ios-simulator" "iphonesimulator" "arm64"

# ============================================
# Merge libraries
# ============================================
merge_libs() {
    local PLATFORM_NAME=$1
    local TRIPLET=$2
    local OUTPUT=$3

    local BUILD_DIR="$ROOT_DIR/build-$PLATFORM_NAME"
    local VCPKG_LIB_DIR="$VCPKG_ROOT/installed/$TRIPLET/lib"

    echo ""
    echo "Merging libraries for $PLATFORM_NAME..."

    # Find built library
    local LIB_EPP=""
    for candidate in "$BUILD_DIR/libepp_agent.a" "$BUILD_DIR/Release/libepp_agent.a" "$BUILD_DIR/src/libepp_agent.a"; do
        if [ -f "$candidate" ]; then
            LIB_EPP="$candidate"
            break
        fi
    done

    if [ -z "$LIB_EPP" ]; then
        echo "Error: libepp_agent.a not found" >&2
        find "$BUILD_DIR" -name "*.a" 2>/dev/null || true
        exit 1
    fi

    # Collect dependencies
    local DEPS=()
    for dep in libsodium.a liboqs.a libssl.a libcrypto.a libprotobuf.a; do
        if [ -f "$VCPKG_LIB_DIR/$dep" ]; then
            DEPS+=("$VCPKG_LIB_DIR/$dep")
        fi
    done

    libtool -static -o "$OUTPUT" "$LIB_EPP" "${DEPS[@]}"
    echo "Created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
}

MERGED_DIR="$ROOT_DIR/build-merged"
mkdir -p "$MERGED_DIR"

merge_libs "ios-device" "arm64-ios" "$MERGED_DIR/libepp-ios-device.a"
merge_libs "ios-simulator" "arm64-ios-simulator" "$MERGED_DIR/libepp-ios-simulator.a"

# ============================================
# Create frameworks
# ============================================
create_framework() {
    local NAME=$1
    local LIB=$2
    local DIR=$3

    echo ""
    echo "Creating framework: $NAME..."

    rm -rf "$DIR"
    mkdir -p "$DIR/Headers" "$DIR/Modules"

    cp "$ROOT_DIR/include/ecliptix/c_api/epp_api.h" "$DIR/Headers/"
    cp "$ROOT_DIR/include/ecliptix/c_api/epp_export.h" "$DIR/Headers/"

    cat > "$DIR/Modules/module.modulemap" <<'EOF'
framework module EcliptixProtocolC {
  header "epp_api.h"
  header "epp_export.h"
  export *
}
EOF

    cat > "$DIR/Info.plist" <<EOF
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

    cp "$LIB" "$DIR/EcliptixProtocolC"
}

FRAMEWORKS_DIR="$ROOT_DIR/build-frameworks"
rm -rf "$FRAMEWORKS_DIR"
mkdir -p "$FRAMEWORKS_DIR"

create_framework "ios-device" "$MERGED_DIR/libepp-ios-device.a" "$FRAMEWORKS_DIR/ios-device/EcliptixProtocolC.framework"
create_framework "ios-simulator" "$MERGED_DIR/libepp-ios-simulator.a" "$FRAMEWORKS_DIR/ios-simulator/EcliptixProtocolC.framework"

# ============================================
# Create XCFramework
# ============================================
echo ""
echo "Creating XCFramework..."
echo "========================================"

XCFRAMEWORK_DIR="$ROOT_DIR/build-xcframework/EcliptixProtocolC.xcframework"
rm -rf "$ROOT_DIR/build-xcframework"
mkdir -p "$ROOT_DIR/build-xcframework"

xcodebuild -create-xcframework \
    -framework "$FRAMEWORKS_DIR/ios-device/EcliptixProtocolC.framework" \
    -framework "$FRAMEWORKS_DIR/ios-simulator/EcliptixProtocolC.framework" \
    -output "$XCFRAMEWORK_DIR"

echo "XCFramework created!"
ls -la "$XCFRAMEWORK_DIR"

# ============================================
# Create archive
# ============================================
echo ""
echo "Creating archive..."

ZIP_PATH="$ARTIFACT_DIR/EcliptixProtocolC.xcframework.zip"
rm -f "$ZIP_PATH"
(cd "$ROOT_DIR/build-xcframework" && zip -r "$ZIP_PATH" "EcliptixProtocolC.xcframework")

CHECKSUM="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
echo "$CHECKSUM" > "$ARTIFACT_DIR/EcliptixProtocolC.xcframework.checksum"

# Cleanup
rm -rf "$MERGED_DIR" "$FRAMEWORKS_DIR"

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Archive:  $ZIP_PATH"
echo "Checksum: $CHECKSUM"
echo ""
echo "Platforms:"
echo "  - iOS Device (arm64)"
echo "  - iOS Simulator (arm64)"
echo ""
