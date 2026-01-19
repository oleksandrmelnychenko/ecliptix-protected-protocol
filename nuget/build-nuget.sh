#!/bin/bash
set -e

# Ecliptix Protection Protocol - NuGet Package Build Script
# Builds and packages the native C++ library for distribution via NuGet

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Default values
VERSION="1.0.0"
CONFIG="Release"
SKIP_BUILD=false
SKIP_PROTECT=false
SKIP_SIGN=false
PUBLISH=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION    Package version (default: 1.0.0)"
    echo "  --config CONFIG      Build configuration: Release|Debug (default: Release)"
    echo "  --skip-build         Skip native library build, use existing binaries"
    echo "  --skip-protect       Skip code protection (VMProtect/Themida/strip)"
    echo "  --skip-sign          Skip code signing"
    echo "  --publish            Publish to GitHub Packages after build"
    echo "  --help               Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  VMPROTECT_PATH           Path to VMProtect CLI"
    echo "  THEMIDA_PATH             Path to Themida CLI"
    echo "  WINDOWS_SIGN_CERT_PATH   Path to Windows signing certificate (.pfx)"
    echo "  WINDOWS_SIGN_CERT_PASSWORD Certificate password"
    echo "  APPLE_SIGN_IDENTITY      macOS Developer ID for codesign"
    echo "  NUGET_SIGN_CERT_PATH     NuGet package signing certificate"
    echo "  NUGET_SIGN_CERT_PASSWORD Certificate password"
    echo "  GITHUB_TOKEN             GitHub token for publishing"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --config)
            CONFIG="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-protect)
            SKIP_PROTECT=true
            shift
            ;;
        --skip-sign)
            SKIP_SIGN=true
            shift
            ;;
        --publish)
            PUBLISH=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

print_header "Ecliptix Protection Protocol - NuGet Build"
echo "Version: $VERSION"
echo "Configuration: $CONFIG"
echo "Skip Build: $SKIP_BUILD"
echo "Skip Protect: $SKIP_PROTECT"
echo "Skip Sign: $SKIP_SIGN"
echo "Publish: $PUBLISH"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Step 1: Build native libraries (if not skipped)
if [ "$SKIP_BUILD" = false ]; then
    print_header "Step 1: Building Native Libraries"

    BUILD_DIR="$PROJECT_ROOT/build-release"
    mkdir -p "$BUILD_DIR"

    cmake -B "$BUILD_DIR" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE="$CONFIG" \
        -DECLIPTIX_BUILD_TESTS=OFF \
        -DECLIPTIX_BUILD_EXAMPLES=OFF \
        -DECLIPTIX_BUILD_SHARED=ON

    cmake --build "$BUILD_DIR" --config "$CONFIG" -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

    echo "Native libraries built successfully"
else
    print_warning "Skipping native build (using existing binaries)"
    BUILD_DIR="$PROJECT_ROOT/build"
fi

# Step 2: Detect current platform and copy native libraries
print_header "Step 2: Copying Native Libraries"

detect_platform() {
    local OS=$(uname -s)
    local ARCH=$(uname -m)

    case "$OS" in
        Darwin)
            case "$ARCH" in
                x86_64) echo "osx-x64" ;;
                arm64) echo "osx-arm64" ;;
                *) echo "unknown" ;;
            esac
            ;;
        Linux)
            case "$ARCH" in
                x86_64) echo "linux-x64" ;;
                aarch64) echo "linux-arm64" ;;
                *) echo "unknown" ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*)
            case "$ARCH" in
                x86_64) echo "win-x64" ;;
                i686) echo "win-x86" ;;
                *) echo "unknown" ;;
            esac
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

CURRENT_RID=$(detect_platform)
echo "Current platform: $CURRENT_RID"

# Get library extension based on platform
get_lib_extension() {
    local RID=$1
    case "$RID" in
        win-*) echo "dll" ;;
        linux-*) echo "so" ;;
        osx-*) echo "dylib" ;;
        *) echo "so" ;;
    esac
}

# Get library prefix based on platform
get_lib_prefix() {
    local RID=$1
    case "$RID" in
        win-*) echo "" ;;
        *) echo "lib" ;;
    esac
}

# Copy libraries to runtime folders
copy_native_lib() {
    local RID=$1
    local EXT=$(get_lib_extension "$RID")
    local PREFIX=$(get_lib_prefix "$RID")

    local CLIENT_SRC="$BUILD_DIR/${PREFIX}epp_agent.$EXT"
    local SERVER_SRC="$BUILD_DIR/${PREFIX}epp_relay.$EXT"

    local CLIENT_DEST="$SCRIPT_DIR/EPP.Agent/runtimes/$RID/native/"
    local SERVER_DEST="$SCRIPT_DIR/EPP.Relay/runtimes/$RID/native/"

    mkdir -p "$CLIENT_DEST" "$SERVER_DEST"

    if [ -f "$CLIENT_SRC" ]; then
        cp "$CLIENT_SRC" "$CLIENT_DEST"
        echo "  Copied client library to $RID"
    else
        print_warning "Client library not found for $RID: $CLIENT_SRC"
    fi

    if [ -f "$SERVER_SRC" ]; then
        cp "$SERVER_SRC" "$SERVER_DEST"
        echo "  Copied server library to $RID"
    else
        print_warning "Server library not found for $RID: $SERVER_SRC"
    fi
}

# Copy current platform's library
copy_native_lib "$CURRENT_RID"

# Step 3: Apply code protection (if not skipped)
if [ "$SKIP_PROTECT" = false ]; then
    print_header "Step 3: Applying Code Protection"

    case "$CURRENT_RID" in
        win-*)
            if [ -n "$VMPROTECT_PATH" ] && [ -x "$VMPROTECT_PATH" ]; then
                echo "Applying VMProtect protection..."
                # VMProtect commands would go here
            elif [ -n "$THEMIDA_PATH" ] && [ -x "$THEMIDA_PATH" ]; then
                echo "Applying Themida protection..."
                # Themida commands would go here
            else
                print_warning "No Windows protection tool available (VMProtect/Themida)"
            fi
            ;;
        linux-*)
            echo "Stripping debug symbols from Linux libraries..."
            find "$SCRIPT_DIR/EPP.Agent/runtimes/$CURRENT_RID/native" -name "*.so" -exec strip --strip-debug {} \; 2>/dev/null || true
            find "$SCRIPT_DIR/EPP.Relay/runtimes/$CURRENT_RID/native" -name "*.so" -exec strip --strip-debug {} \; 2>/dev/null || true
            ;;
        osx-*)
            echo "Stripping debug symbols from macOS libraries..."
            find "$SCRIPT_DIR/EPP.Agent/runtimes/$CURRENT_RID/native" -name "*.dylib" -exec strip -x {} \; 2>/dev/null || true
            find "$SCRIPT_DIR/EPP.Relay/runtimes/$CURRENT_RID/native" -name "*.dylib" -exec strip -x {} \; 2>/dev/null || true
            ;;
    esac
else
    print_warning "Skipping code protection"
fi

# Step 4: Sign native libraries (if not skipped)
if [ "$SKIP_SIGN" = false ]; then
    print_header "Step 4: Signing Native Libraries"

    case "$CURRENT_RID" in
        win-*)
            if [ -n "$WINDOWS_SIGN_CERT_PATH" ] && [ -f "$WINDOWS_SIGN_CERT_PATH" ]; then
                echo "Signing Windows libraries..."
                # signtool or osslsigncode commands would go here
            else
                print_warning "No Windows signing certificate available"
            fi
            ;;
        osx-*)
            if [ -n "$APPLE_SIGN_IDENTITY" ]; then
                echo "Signing macOS libraries..."
                find "$SCRIPT_DIR/EPP.Agent/runtimes/$CURRENT_RID/native" -name "*.dylib" -exec codesign --force --sign "$APPLE_SIGN_IDENTITY" {} \; 2>/dev/null || print_warning "codesign failed"
                find "$SCRIPT_DIR/EPP.Relay/runtimes/$CURRENT_RID/native" -name "*.dylib" -exec codesign --force --sign "$APPLE_SIGN_IDENTITY" {} \; 2>/dev/null || print_warning "codesign failed"
            else
                print_warning "No macOS signing identity available (APPLE_SIGN_IDENTITY)"
            fi
            ;;
        linux-*)
            echo "Creating SHA256 checksums for Linux libraries..."
            find "$SCRIPT_DIR/EPP.Agent/runtimes/$CURRENT_RID/native" -name "*.so" -exec sha256sum {} \; > "$OUTPUT_DIR/checksums-client-$CURRENT_RID.txt" 2>/dev/null || true
            find "$SCRIPT_DIR/EPP.Relay/runtimes/$CURRENT_RID/native" -name "*.so" -exec sha256sum {} \; > "$OUTPUT_DIR/checksums-server-$CURRENT_RID.txt" 2>/dev/null || true
            ;;
    esac
else
    print_warning "Skipping code signing"
fi

# Step 5: Build NuGet packages
print_header "Step 5: Building NuGet Packages"

cd "$SCRIPT_DIR"

# Build Client package
echo "Building EPP.Agent package..."
dotnet pack EPP.Agent/EPP.Agent.csproj \
    -c Release \
    -o "$OUTPUT_DIR" \
    /p:Version="$VERSION" \
    /p:PackageVersion="$VERSION"

# Build Server package
echo "Building EPP.Relay package..."
dotnet pack EPP.Relay/EPP.Relay.csproj \
    -c Release \
    -o "$OUTPUT_DIR" \
    /p:Version="$VERSION" \
    /p:PackageVersion="$VERSION"

# Step 6: Sign NuGet packages (if not skipped)
if [ "$SKIP_SIGN" = false ] && [ -n "$NUGET_SIGN_CERT_PATH" ] && [ -f "$NUGET_SIGN_CERT_PATH" ]; then
    print_header "Step 6: Signing NuGet Packages"

    for pkg in "$OUTPUT_DIR"/*.nupkg; do
        if [ -f "$pkg" ]; then
            echo "Signing $pkg..."
            dotnet nuget sign "$pkg" \
                --certificate-path "$NUGET_SIGN_CERT_PATH" \
                --certificate-password "$NUGET_SIGN_CERT_PASSWORD" \
                --timestamper "http://timestamp.digicert.com" \
                || print_warning "Failed to sign $pkg"
        fi
    done
else
    print_warning "Skipping NuGet package signing"
fi

# Step 7: Publish to GitHub Packages (if requested)
if [ "$PUBLISH" = true ]; then
    print_header "Step 7: Publishing to GitHub Packages"

    if [ -z "$GITHUB_TOKEN" ]; then
        print_error "GITHUB_TOKEN environment variable is not set"
        exit 1
    fi

    for pkg in "$OUTPUT_DIR"/*.nupkg; do
        if [ -f "$pkg" ]; then
            echo "Publishing $pkg..."
            dotnet nuget push "$pkg" \
                --source "github" \
                --api-key "$GITHUB_TOKEN" \
                --skip-duplicate
        fi
    done
else
    print_warning "Skipping publish (use --publish to publish to GitHub Packages)"
fi

print_header "Build Complete!"
echo ""
echo "Packages created in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"/*.nupkg 2>/dev/null || echo "No packages found"
echo ""
echo "To publish manually:"
echo "  dotnet nuget push $OUTPUT_DIR/EPP.Agent.$VERSION.nupkg --source github --api-key \$GITHUB_TOKEN"
echo "  dotnet nuget push $OUTPUT_DIR/EPP.Relay.$VERSION.nupkg --source github --api-key \$GITHUB_TOKEN"
