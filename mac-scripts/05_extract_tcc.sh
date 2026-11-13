#!/bin/bash
# Extract TCC framework from BOTH 26.6.2 and 26.7.2 for CVE-2026-86886 analysis
#
# TCC (Transparency, Consent, and Control) is a userspace framework.
# The daemon `tccd` and the framework `TCC.framework` live in the
# dyld_shared_cache on iOS.
#
# Prerequisites:
#   - Run 01_extract_dyld.sh first for 26.7.2
#   - Need 26.6.2 dyld_shared_cache (copy from Windows or re-extract)
#   - ipsw tool installed

set -euo pipefail

WORK="$HOME/jb-research"
OUTDIR_OLD="$WORK/binaries/26.6.2/frameworks"
OUTDIR_NEW="$WORK/binaries/26.7.x/frameworks"
mkdir -p "$OUTDIR_OLD" "$OUTDIR_NEW"

echo "=== CVE-2026-86886 TCC Binary Extraction ==="

# Find 26.6.2 dyld cache
# Option 1: Copied from Windows
DYLD_OLD=$(find "$WORK/binaries/26.6.2/" -name "dyld_shared_cache*" -type f 2>/dev/null | head -1)

if [ -z "$DYLD_OLD" ]; then
    echo "26.6.2 dyld_shared_cache not found locally."
    echo "Options:"
    echo "  1. Copy from Windows: C:\\Users\\jmbur\\tools\\jb-research\\binaries\\26.6.2\\"
    echo "  2. Re-extract from 26.6.2 OTA on this Mac"
    echo ""
    echo "Trying OTA extraction..."

    # Download 26.6.2 OTA
    ipsw download ota --platform ios --device "iPhone18,1" --version "26.6.2" \
        --output "$WORK/binaries/26.6.2/" 2>/dev/null || true

    OTA_OLD=$(ls "$WORK/binaries/26.6.2/"*.aea 2>/dev/null | head -1)
    if [ -n "$OTA_OLD" ]; then
        ipsw ota extract "$OTA_OLD" --dyld \
            --output "$WORK/binaries/26.6.2/extracted/" || true
        DYLD_OLD=$(find "$WORK/binaries/26.6.2/extracted/" -name "dyld_shared_cache*" -type f 2>/dev/null | head -1)
    fi
fi

# Extract from 26.6.2
if [ -n "$DYLD_OLD" ]; then
    echo "Found 26.6.2 dyld cache: $DYLD_OLD"
    for lib in TCC; do
        echo "Extracting $lib from 26.6.2..."
        ipsw dyld extract "$DYLD_OLD" --dylib "$lib" --output "$OUTDIR_OLD/" 2>/dev/null || \
        ipsw dyld extract "$DYLD_OLD" "$lib" --output "$OUTDIR_OLD/" 2>/dev/null || \
            echo "  Failed — try: ipsw dyld extract '$DYLD_OLD' 'libTCC' or 'TCC.framework/TCC'"
    done

    # Also try to extract tccd binary (standalone daemon, not in dyld cache)
    echo "Looking for tccd in OTA..."
    OTA_OLD=$(ls "$WORK/binaries/26.6.2/"*.aea 2>/dev/null | head -1)
    if [ -n "$OTA_OLD" ]; then
        ipsw ota extract "$OTA_OLD" --pattern "*/tccd" \
            --output "$OUTDIR_OLD/" 2>/dev/null || \
            echo "  tccd not found via pattern extraction"
    fi
else
    echo "WARNING: Cannot extract 26.6.2 TCC. Copy dyld cache from Windows."
fi

# Extract from 26.7.2 (should be done by 01_extract_dyld.sh)
DYLD_NEW=$(find "$WORK/binaries/26.7.x/extracted/" -name "dyld_shared_cache*" -type f 2>/dev/null | head -1)

if [ -n "$DYLD_NEW" ]; then
    echo ""
    echo "Found 26.7.2 dyld cache: $DYLD_NEW"
    for lib in TCC; do
        echo "Extracting $lib from 26.7.2..."
        ipsw dyld extract "$DYLD_NEW" --dylib "$lib" --output "$OUTDIR_NEW/" 2>/dev/null || \
        ipsw dyld extract "$DYLD_NEW" "$lib" --output "$OUTDIR_NEW/" 2>/dev/null || \
            echo "  Failed"
    done
else
    echo ""
    echo "26.7.2 dyld cache not found. Run 01_extract_dyld.sh first."
fi

echo ""
echo "=== Results ==="
echo "26.6.2 TCC: $(ls "$OUTDIR_OLD/"*TCC* 2>/dev/null || echo 'not extracted')"
echo "26.7.2 TCC: $(ls "$OUTDIR_NEW/"*TCC* 2>/dev/null || echo 'not extracted')"
echo ""
echo "Next steps:"
echo "  1. Import both into Ghidra"
echo "  2. BinDiff to find CVE-2026-86886 patch location"
echo "  3. Look for path validation changes (realpath, normpath, symlink resolution)"
echo "  4. Identify what 'protected files' can be written via the traversal"
