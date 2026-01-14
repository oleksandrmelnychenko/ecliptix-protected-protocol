#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <version> <checksum>" >&2
    exit 1
fi

VERSION="$1"
CHECKSUM="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_FILE="$ROOT_DIR/Package.swift"
REPO="${GITHUB_REPOSITORY:-oleksandrmelnychenko/Ecliptix.Protection.Protocol}"
URL="https://github.com/$REPO/releases/download/v${VERSION}/EcliptixProtocolC.xcframework.zip"

python3 - "$PACKAGE_FILE" "$URL" "$CHECKSUM" <<'PY'
import re
import sys

path, url, checksum = sys.argv[1:]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

text, url_count = re.subn(r'let binaryUrl = ".*"', f'let binaryUrl = "{url}"', text)
text, checksum_count = re.subn(r'let binaryChecksum = ".*"', f'let binaryChecksum = "{checksum}"', text)

if url_count != 1 or checksum_count != 1:
    raise SystemExit("Failed to update Package.swift (expected single url and checksum)")

with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
