#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build-android"

VCPKG_ROOT="${VCPKG_ROOT:-$ROOT_DIR/.build/vcpkg}"
TRIPLET="arm64-android"
ANDROID_ABI="arm64-v8a"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-34}"

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK_ROOT:-}" ]; then
    ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ANDROID_NDK_HOME is required to build Android artifacts." >&2
    exit 1
fi

if [ ! -d "$VCPKG_ROOT" ]; then
    git clone https://github.com/microsoft/vcpkg "$VCPKG_ROOT"
    "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
fi

"$VCPKG_ROOT/vcpkg" install libsodium liboqs openssl protobuf fmt --triplet "$TRIPLET"

export PKG_CONFIG_PATH="$VCPKG_ROOT/installed/$TRIPLET/lib/pkgconfig:$VCPKG_ROOT/installed/$TRIPLET/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$VCPKG_ROOT/installed/$TRIPLET"

cmake -B "$BUILD_DIR" -S "$ROOT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DECLIPTIX_BUILD_TESTS=OFF \
    -DECLIPTIX_BUILD_EXAMPLES=OFF \
    -DECLIPTIX_BUILD_SERVER_TARGET=OFF \
    -DECLIPTIX_BUILD_CLIENT_TARGET=ON \
    -DECLIPTIX_BUILD_SHARED=ON \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_TARGET_TRIPLET="$TRIPLET" \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ANDROID_ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API_LEVEL"

cmake --build "$BUILD_DIR" --config Release

LIB_EPP_AGENT=""
for candidate in "$BUILD_DIR/libepp_agent.so" "$BUILD_DIR/Release/libepp_agent.so"; do
    if [ -f "$candidate" ]; then
        LIB_EPP_AGENT="$candidate"
        break
    fi
done

if [ -z "$LIB_EPP_AGENT" ]; then
    echo "libepp_agent.so not found in $BUILD_DIR" >&2
    exit 1
fi

JNI_LIB_DIR="$SCRIPT_DIR/ecliptix-protocol/src/main/jniLibs/$ANDROID_ABI"
mkdir -p "$JNI_LIB_DIR"
cp "$LIB_EPP_AGENT" "$JNI_LIB_DIR/libepp_agent.so"
