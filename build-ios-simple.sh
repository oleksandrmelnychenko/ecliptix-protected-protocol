#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TYPE="${1:-Release}"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-17.0}"

# Use vcpkg from SSL Pinning project (already has all deps built)
VCPKG_ROOT="/Users/oleksandrmelnychenko/CLionProjects/Ecliptix.Security.SSL.Pining/.build/vcpkg"
VCPKG_PREFIX="$VCPKG_ROOT/installed/arm64-ios"

echo "========================================"
echo "Building EPP for iOS (arm64)"
echo "========================================"
echo "Build Type: $BUILD_TYPE"
echo "Deployment Target: $IOS_DEPLOYMENT_TARGET"
echo "Using deps from: $VCPKG_PREFIX"
echo ""

BUILD_DIR="$SCRIPT_DIR/build-ios-device"
rm -rf "$BUILD_DIR"

SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --sdk iphoneos --find clang)
CXX=$(xcrun --sdk iphoneos --find clang++)

ARCH="arm64"
COMMON_FLAGS="-arch $ARCH -isysroot $SDK_PATH -miphoneos-version-min=$IOS_DEPLOYMENT_TARGET"
CFLAGS="$COMMON_FLAGS -fPIC -fvisibility=hidden -O3"
CXXFLAGS="$CFLAGS -std=c++20"

# Set up pkg-config for vcpkg deps
export PKG_CONFIG_PATH="$VCPKG_PREFIX/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$VCPKG_PREFIX"

cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT="iphoneos" \
    -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
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
    -Dfmt_DIR="$VCPKG_PREFIX/share/fmt" \
    -Dprotobuf_DIR="$VCPKG_PREFIX/share/protobuf" \
    -Dabsl_DIR="$VCPKG_PREFIX/share/absl" \
    -Dutf8_range_DIR="$VCPKG_PREFIX/share/utf8-range" \
    -Dliboqs_DIR="$VCPKG_PREFIX/share/liboqs" \
    -Dunofficial-sodium_DIR="$VCPKG_PREFIX/share/unofficial-sodium" \
    -DProtobuf_INCLUDE_DIR="$VCPKG_PREFIX/include" \
    -DProtobuf_LIBRARY="$VCPKG_PREFIX/lib/libprotobuf.a" \
    -DProtobuf_LITE_LIBRARY="$VCPKG_PREFIX/lib/libprotobuf-lite.a" \
    -DProtobuf_PROTOC_EXECUTABLE="$VCPKG_ROOT/installed/arm64-osx/tools/protobuf/protoc"

cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel

echo ""
echo "Build completed!"
echo "Library: $BUILD_DIR/libepp_agent.a"
ls -la "$BUILD_DIR"/*.a 2>/dev/null || find "$BUILD_DIR" -name "*.a" | head -5
