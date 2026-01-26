#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TYPE="${1:-Release}"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-17.0}"
VERSION="${VERSION:-1.0.0}"

VCPKG_ROOT="/Users/oleksandrmelnychenko/CLionProjects/Ecliptix.Security.SSL.Pining/.build/vcpkg"

echo "========================================"
echo "Building EPP XCFramework"
echo "========================================"

build_platform() {
    local PLATFORM_NAME=$1
    local SDK=$2
    local ARCH=$3
    local TRIPLET=$4

    local BUILD_DIR="$SCRIPT_DIR/build-$PLATFORM_NAME"
    local VCPKG_PREFIX="$VCPKG_ROOT/installed/$TRIPLET"

    echo ""
    echo "Building for $PLATFORM_NAME ($ARCH)..."
    echo "========================================"

    rm -rf "$BUILD_DIR"

    SDK_PATH=$(xcrun --sdk "$SDK" --show-sdk-path)
    CC=$(xcrun --sdk "$SDK" --find clang)
    CXX=$(xcrun --sdk "$SDK" --find clang++)

    COMMON_FLAGS="-arch $ARCH -isysroot $SDK_PATH -miphoneos-version-min=$IOS_DEPLOYMENT_TARGET"
    CFLAGS="$COMMON_FLAGS -fPIC -fvisibility=hidden -O3"
    CXXFLAGS="$CFLAGS -std=c++20"

    export PKG_CONFIG_PATH="$VCPKG_PREFIX/lib/pkgconfig"
    export PKG_CONFIG_SYSROOT_DIR="$VCPKG_PREFIX"

    cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_SYSTEM_NAME=iOS \
        -DCMAKE_OSX_SYSROOT="$SDK" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DECLIPTIX_BUILD_TESTS=OFF \
        -DECLIPTIX_BUILD_EXAMPLES=OFF \
        -DECLIPTIX_BUILD_SERVER_TARGET=OFF \
        -DECLIPTIX_BUILD_CLIENT_TARGET=ON \
        -DECLIPTIX_BUILD_SHARED=OFF \
        -DCMAKE_PREFIX_PATH="$VCPKG_PREFIX" \
        -DOPENSSL_ROOT_DIR="$VCPKG_PREFIX" \
        -DOPENSSL_INCLUDE_DIR="$VCPKG_PREFIX/include" \
        -DOPENSSL_CRYPTO_LIBRARY="$VCPKG_PREFIX/lib/libcrypto.a" \
        -DOPENSSL_SSL_LIBRARY="$VCPKG_PREFIX/lib/libssl.a" \
        -DProtobuf_INCLUDE_DIR="$VCPKG_PREFIX/include" \
        -DProtobuf_LIBRARY="$VCPKG_PREFIX/lib/libprotobuf.a" \
        -DProtobuf_LITE_LIBRARY="$VCPKG_PREFIX/lib/libprotobuf-lite.a" \
        -DProtobuf_PROTOC_EXECUTABLE="$VCPKG_ROOT/installed/arm64-osx/tools/protobuf/protoc"

    cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel
    echo "$PLATFORM_NAME build completed!"
}

# Need to install deps for simulator too
echo "Installing deps for arm64-ios-simulator..."
"$VCPKG_ROOT/vcpkg" install \
    "libsodium" "liboqs[core]" "openssl" "protobuf" "fmt" \
    --triplet arm64-ios-simulator \
    --x-install-root="$VCPKG_ROOT/installed" || true

# Build for both platforms
build_platform "ios-device" "iphoneos" "arm64" "arm64-ios"
build_platform "ios-simulator" "iphonesimulator" "arm64" "arm64-ios-simulator"

echo ""
echo "Merging libraries..."
echo "========================================"

merge_libs() {
    local PLATFORM_NAME=$1
    local TRIPLET=$2
    local OUTPUT=$3

    local BUILD_DIR="$SCRIPT_DIR/build-$PLATFORM_NAME"
    local VCPKG_LIB="$VCPKG_ROOT/installed/$TRIPLET/lib"

    echo "Merging for $PLATFORM_NAME..."

    local LIBS=("$BUILD_DIR/libepp_agent.a" "$BUILD_DIR/proto/libecliptix_proto.a")

    # Add vcpkg deps
    for dep in libsodium.a liboqs.a libcrypto.a libssl.a libprotobuf.a libfmt.a libutf8_range.a libutf8_validity.a; do
        if [ -f "$VCPKG_LIB/$dep" ]; then
            LIBS+=("$VCPKG_LIB/$dep")
        fi
    done

    # Add absl libs (protobuf dependency)
    for absl in "$VCPKG_LIB"/libabsl_*.a; do
        if [ -f "$absl" ]; then
            LIBS+=("$absl")
        fi
    done

    libtool -static -o "$OUTPUT" "${LIBS[@]}"
    echo "Created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
}

MERGED_DIR="$SCRIPT_DIR/build-merged"
mkdir -p "$MERGED_DIR"

merge_libs "ios-device" "arm64-ios" "$MERGED_DIR/libepp-ios-device.a"
merge_libs "ios-simulator" "arm64-ios-simulator" "$MERGED_DIR/libepp-ios-simulator.a"

echo ""
echo "Creating frameworks..."
echo "========================================"

FRAMEWORKS_DIR="$SCRIPT_DIR/build-frameworks"
rm -rf "$FRAMEWORKS_DIR"

create_framework() {
    local NAME=$1
    local LIB=$2
    local DIR="$FRAMEWORKS_DIR/$NAME/EcliptixProtocolC.framework"

    mkdir -p "$DIR/Headers" "$DIR/Modules"

    cp "$SCRIPT_DIR/include/ecliptix/c_api/epp_api.h" "$DIR/Headers/"
    cp "$SCRIPT_DIR/include/ecliptix/c_api/epp_export.h" "$DIR/Headers/"

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
  <key>CFBundleExecutable</key>
  <string>EcliptixProtocolC</string>
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
    echo "Created framework: $DIR"
}

create_framework "ios-device" "$MERGED_DIR/libepp-ios-device.a"
create_framework "ios-simulator" "$MERGED_DIR/libepp-ios-simulator.a"

echo ""
echo "Creating XCFramework..."
echo "========================================"

XCFRAMEWORK_DIR="$SCRIPT_DIR/build-xcframework/EcliptixProtocolC.xcframework"
rm -rf "$SCRIPT_DIR/build-xcframework"
mkdir -p "$SCRIPT_DIR/build-xcframework"

xcodebuild -create-xcframework \
    -framework "$FRAMEWORKS_DIR/ios-device/EcliptixProtocolC.framework" \
    -framework "$FRAMEWORKS_DIR/ios-simulator/EcliptixProtocolC.framework" \
    -output "$XCFRAMEWORK_DIR"

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
ls -la "$XCFRAMEWORK_DIR"
echo ""
echo "XCFramework: $XCFRAMEWORK_DIR"
