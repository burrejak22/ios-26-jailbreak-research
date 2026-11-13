#!/bin/bash
# BinDiff Setup: Compare 26.6.2 vs 26.7.2 binaries
#
# Prerequisites:
#   - Ghidra installed (brew install --cask ghidra, or from ghidra-sre.org)
#   - BinDiff installed (from zynamics.com or Google)
#   - Run 01_extract_dyld.sh first to get 26.7.2 binaries
#
# This script imports both versions into Ghidra, exports BinExport2 files,
# and runs BinDiff to find patched functions.

set -euo pipefail

WORK="$HOME/jb-research"
GHIDRA_HOME="${GHIDRA_HOME:-/Applications/ghidra}"
BINDIFF="${BINDIFF:-/usr/local/bin/bindiff}"

# Binary locations — adjust paths after extraction
OLD_JSC="$WORK/binaries/26.6.2/JavaScriptCore"     # From iPhone
NEW_JSC="$WORK/binaries/26.7.x/frameworks/JavaScriptCore"  # From 01_extract_dyld.sh

OLD_KERNEL="$WORK/binaries/26.6.2/kernelcache"
NEW_KERNEL="$WORK/binaries/26.7.x/kernelcache"

OLD_TCC=""  # Fill after extraction
NEW_TCC=""

GHIDRA_PROJECT="$WORK/ghidra-mac"
EXPORT_DIR="$WORK/bindiff-exports"
RESULTS_DIR="$WORK/bindiff-results"

mkdir -p "$GHIDRA_PROJECT" "$EXPORT_DIR" "$RESULTS_DIR"

echo "=== iOS 26.6.2 vs 26.7.2 BinDiff Setup ==="

# Function to import a binary into Ghidra and export BinExport2
ghidra_export() {
    local binary="$1"
    local name="$2"
    local export_file="$EXPORT_DIR/${name}.BinExport"

    if [ ! -f "$binary" ]; then
        echo "SKIP: $binary not found"
        return 1
    fi

    if [ -f "$export_file" ]; then
        echo "SKIP: $export_file already exists"
        return 0
    fi

    echo "Importing $name into Ghidra..."
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$GHIDRA_PROJECT" "BinDiff" \
        -import "$binary" \
        -scriptPath "$GHIDRA_HOME/Ghidra/Extensions/BinExport/ghidra_scripts" \
        -postScript "BinExportExporter.java" "$export_file" \
        -deleteProject \
        2>&1 | tail -5

    if [ -f "$export_file" ]; then
        echo "Exported: $export_file ($(du -h "$export_file" | cut -f1))"
    else
        echo "ERROR: Export failed for $name"
        return 1
    fi
}

# Function to run BinDiff on two exports
run_bindiff() {
    local old_export="$1"
    local new_export="$2"
    local name="$3"
    local result="$RESULTS_DIR/${name}.BinDiff"

    if [ ! -f "$old_export" ] || [ ! -f "$new_export" ]; then
        echo "SKIP: Missing exports for $name"
        return 1
    fi

    echo ""
    echo "=== Running BinDiff: $name ==="
    "$BINDIFF" --primary "$old_export" --secondary "$new_export" \
        --output_dir "$RESULTS_DIR" 2>&1

    if [ -f "$result" ]; then
        echo "Result: $result"
    else
        # BinDiff may name the output differently
        local found=$(ls "$RESULTS_DIR/"*.BinDiff 2>/dev/null | tail -1)
        if [ -n "$found" ]; then
            mv "$found" "$result"
            echo "Result: $result"
        else
            echo "ERROR: BinDiff produced no output for $name"
        fi
    fi
}

echo ""
echo "=== Step 1: Ghidra Import + BinExport2 ==="
echo ""

# JavaScriptCore (CVE-2026-112659 target)
echo "--- JavaScriptCore ---"
ghidra_export "$OLD_JSC" "JSC_26.6.2" || true
ghidra_export "$NEW_JSC" "JSC_26.7.2" || true

# Kernel (CVE-2026-86916, CVE-2026-43689 targets)
echo "--- Kernel ---"
ghidra_export "$OLD_KERNEL" "kernel_26.6.2" || true
ghidra_export "$NEW_KERNEL" "kernel_26.7.2" || true

echo ""
echo "=== Step 2: BinDiff ==="
echo ""

# JSC diff
run_bindiff "$EXPORT_DIR/JSC_26.6.2.BinExport" \
            "$EXPORT_DIR/JSC_26.7.2.BinExport" \
            "JSC_diff" || true

# Kernel diff
run_bindiff "$EXPORT_DIR/kernel_26.6.2.BinExport" \
            "$EXPORT_DIR/kernel_26.7.2.BinExport" \
            "kernel_diff" || true

echo ""
echo "=== Step 3: Extract Changed Functions ==="
echo ""

# If BinDiff CLI supports text output, extract changed functions
# Otherwise, open in BinDiff GUI:
echo "Open results in BinDiff GUI:"
echo "  $RESULTS_DIR/JSC_diff.BinDiff"
echo "  $RESULTS_DIR/kernel_diff.BinDiff"
echo ""
echo "Look for functions with similarity < 1.0 (changed between versions)."
echo ""
echo "Key targets:"
echo "  JSC: DFG::executeEffects, DFG::clobberize, canDoFastSpread,"
echo "       NewArrayWithSpread, DFG::AbstractInterpreter"
echo "  Kernel: vm_protect, flow_divert_*, chroot syscall handler,"
echo "          trust cache loaders"
echo ""
echo "=== Alternative: Use Diaphora (free) ==="
echo "If BinDiff is not installed, Diaphora works as a Ghidra/IDA plugin:"
echo "  pip install diaphora"
echo "  # Export from Ghidra using Diaphora's script, then diff"
echo ""
echo "=== DONE ==="
