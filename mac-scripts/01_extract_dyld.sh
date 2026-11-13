#!/bin/bash
# CVE-2026-112659 Research: Extract 26.7.2 dyld_shared_cache on macOS
#
# This script extracts the patched JavaScriptCore and WebKit binaries
# from the iOS 26.7.2 OTA, which requires macOS-only tools (aa, ipsw).
#
# Prerequisites:
#   brew install blacktop/tap/ipsw
#   (or download from https://github.com/blacktop/ipsw/releases)
#
# Run from: any directory on your Mac
# Output: ./jb-research/binaries/26.7.x/ with extracted binaries

set -euo pipefail

WORK="$HOME/jb-research"
DEVICE="iPhone18,1"
VERSION="26.7.2"
BUILD="23H128"

mkdir -p "$WORK/binaries/26.7.x"
cd "$WORK"

echo "=== Step 1: Download iOS $VERSION OTA for $DEVICE ==="
echo "(This may already be downloaded — ipsw will skip if cached)"

# Download the OTA (will prompt for confirmation)
ipsw download ota --platform ios --device "$DEVICE" --version "$VERSION" \
    --output "$WORK/binaries/26.7.x/"

echo ""
echo "=== Step 2: Find the downloaded OTA file ==="
OTA_FILE=$(ls "$WORK/binaries/26.7.x/"*.aea 2>/dev/null | head -1)
if [ -z "$OTA_FILE" ]; then
    # Try .zip format
    OTA_FILE=$(ls "$WORK/binaries/26.7.x/"*.zip 2>/dev/null | head -1)
fi

if [ -z "$OTA_FILE" ]; then
    echo "ERROR: No OTA file found. Trying remote extraction..."
    # Try remote dyld extraction (may work on macOS)
    ipsw download ota --platform ios --device "$DEVICE" --version "$VERSION" \
        --dyld --output "$WORK/binaries/26.7.x/"
    echo "Check $WORK/binaries/26.7.x/ for extracted dyld cache"
    exit 0
fi

echo "Found OTA: $OTA_FILE"

echo ""
echo "=== Step 3: Extract dyld_shared_cache from OTA ==="
# On macOS, ipsw can use the native 'aa' tool to extract cryptex contents
ipsw ota extract "$OTA_FILE" --dyld \
    --output "$WORK/binaries/26.7.x/extracted/" || {
    echo "dyld extraction failed, trying full extract..."
    ipsw ota extract "$OTA_FILE" \
        --output "$WORK/binaries/26.7.x/extracted/"
}

echo ""
echo "=== Step 4: Find and split dyld_shared_cache ==="
DYLD=$(find "$WORK/binaries/26.7.x/extracted/" -name "dyld_shared_cache*" -type f | head -1)

if [ -z "$DYLD" ]; then
    echo "ERROR: dyld_shared_cache not found in extracted OTA"
    echo "Contents of extracted dir:"
    find "$WORK/binaries/26.7.x/extracted/" -type f | head -30
    exit 1
fi

echo "Found dyld cache: $DYLD"

echo ""
echo "=== Step 5: Extract JavaScriptCore and WebKit ==="
OUTDIR="$WORK/binaries/26.7.x/frameworks"
mkdir -p "$OUTDIR"

# Extract specific frameworks
for framework in JavaScriptCore WebKit ImageIO TCC; do
    echo "Extracting $framework..."
    ipsw dyld extract "$DYLD" --dylib "$framework" --output "$OUTDIR/" 2>/dev/null || \
    ipsw dyld extract "$DYLD" "$framework" --output "$OUTDIR/" 2>/dev/null || \
        echo "  Failed to extract $framework (may need different dylib name)"
done

echo ""
echo "=== Step 6: Dump symbols ==="
for bin in "$OUTDIR"/*; do
    if [ -f "$bin" ]; then
        name=$(basename "$bin")
        echo "Dumping symbols for $name..."
        ipsw macho info "$bin" > "$OUTDIR/${name}_info.txt" 2>/dev/null || true
        nm -defined-only "$bin" > "$OUTDIR/${name}_symbols.txt" 2>/dev/null || true
        strings "$bin" > "$OUTDIR/${name}_strings.txt" 2>/dev/null || true
    fi
done

echo ""
echo "=== DONE ==="
echo "Extracted binaries in: $OUTDIR"
ls -la "$OUTDIR/"
echo ""
echo "Next: Copy $OUTDIR to your Windows machine for BinDiff analysis,"
echo "or run BinDiff directly on the Mac."
