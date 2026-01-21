#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"
BUILD_DIR="$ROOT_DIR/build-ios"

VCPKG_ROOT="${VCPKG_ROOT:-$ROOT_DIR/.build/vcpkg}"
TRIPLET="arm64-ios"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-17.0}"
VERSION="${VERSION:-0.0.0}"

mkdir -p "$ARTIFACT_DIR"

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
    -DECLIPTIX_BUILD_SHARED=OFF \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_TARGET_TRIPLET="$TRIPLET" \
    -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

cmake --build "$BUILD_DIR" --config Release

LIB_EPP_AGENT=""
for candidate in "$BUILD_DIR/libepp_agent.a" "$BUILD_DIR/Release/libepp_agent.a"; do
    if [ -f "$candidate" ]; then
        LIB_EPP_AGENT="$candidate"
        break
    fi
done

if [ -z "$LIB_EPP_AGENT" ]; then
    echo "libepp_agent.a not found in $BUILD_DIR" >&2
    exit 1
fi

VCPKG_LIB_DIR="$VCPKG_ROOT/installed/$TRIPLET/lib"
DEPS=(
    "$VCPKG_LIB_DIR/libsodium.a"
    "$VCPKG_LIB_DIR/liboqs.a"
    "$VCPKG_LIB_DIR/libssl.a"
    "$VCPKG_LIB_DIR/libcrypto.a"
    "$VCPKG_LIB_DIR/libprotobuf.a"
)

for dep in "${DEPS[@]}"; do
    if [ ! -f "$dep" ]; then
        echo "Missing dependency: $dep" >&2
        exit 1
    fi
done

FRAMEWORK_DIR="$BUILD_DIR/EcliptixProtocolC.framework"
rm -rf "$FRAMEWORK_DIR"
mkdir -p "$FRAMEWORK_DIR/Headers" "$FRAMEWORK_DIR/Modules"

cp "$ROOT_DIR/include/ecliptix/c_api/epp_api.h" \
    "$FRAMEWORK_DIR/Headers/epp_api.h"
cp "$ROOT_DIR/include/ecliptix/c_api/epp_export.h" \
    "$FRAMEWORK_DIR/Headers/epp_export.h"

cat > "$FRAMEWORK_DIR/Modules/module.modulemap" <<'EOF'
module EcliptixProtocolC {
  header "epp_api.h"
  header "epp_export.h"
  export *
}
EOF

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

libtool -static -o "$FRAMEWORK_DIR/EcliptixProtocolC" "$LIB_EPP_AGENT" "${DEPS[@]}"

XCFRAMEWORK_DIR="$BUILD_DIR/EcliptixProtocolC.xcframework"
rm -rf "$XCFRAMEWORK_DIR"
xcodebuild -create-xcframework \
    -framework "$FRAMEWORK_DIR" \
    -output "$XCFRAMEWORK_DIR"

ZIP_PATH="$ARTIFACT_DIR/EcliptixProtocolC.xcframework.zip"
rm -f "$ZIP_PATH"
(cd "$BUILD_DIR" && zip -r "$ZIP_PATH" "EcliptixProtocolC.xcframework")

CHECKSUM="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
echo "$CHECKSUM" > "$ARTIFACT_DIR/EcliptixProtocolC.xcframework.checksum"
echo "Checksum: $CHECKSUM"
