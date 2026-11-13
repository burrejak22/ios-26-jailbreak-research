# iOS 26.6.2 Jailbreak Research

Security research targeting iOS 26.6.2 on iPhone 17 Pro (A19/t8150, arm64e) under the Apple Security Bounty program.

**Legal basis:** DMCA §1201(f)(j) exemptions. Own device only. Responsible disclosure to Apple.

## Target CVEs

| CVE | Component | Bug Class | Chain Role | Status |
|-----|-----------|-----------|------------|--------|
| CVE-2026-84607 | AppleAVE2 | Input validation bypass | App → Kernel | PoC written |
| CVE-2026-43689 | XNU Kernel | chroot entitlement bypass | Post-root persistence | **DEVICE TESTED (EPERM)** |
| CVE-2026-112659 | WebKit/JSC | Type confusion | Entry (Safari) | Analyzed |
| CVE-2026-86916 | Kernel | UAF | Kernel R/W | Partial |
| CVE-2026-86886 | TCC | Path traversal | Persistence | Under analysis |

## Chain Architecture (Revised 2026-11-12)

**Device testing confirmed CVE-2026-43689 requires root (uid 0) — NOT a sandbox escape.**

```
Chain A (PRIMARY):
  CVE-2026-84607 (AppleAVE2, app → kernel via VideoToolbox)
    → CVE-2026-86916 (kernel UAF → full R/W)
    → Root (modify credentials)
    → CVE-2026-43689 (chroot path confusion, post-root only)
    → CVE-2026-86886 (TCC file writes for persistence)

Chain B (WEAKENED — needs different sandbox escape):
  CVE-2026-112659 (WebKit type confusion)
    → [sandbox escape TBD — chroot ruled out]
    → CVE-2026-86916 (kernel UAF)
```

## Structure

```
notes/           — Analysis writeups for each CVE
poc/             — Proof-of-concept source code
  chroot-bypass/ — CVE-2026-43689 three-question PoC
  ave2-kernel/   — CVE-2026-84607 AppleAVE2 PoC
mac-scripts/     — Mac-side tooling for device deployment + binary extraction
diffs/           — Binary diff artifacts (function index)
ghidra/          — Ghidra analysis scripts
```

## Quick Start (Mac + iPhone)

```bash
# 1. Clone this repo on your Mac
git clone <this-repo> ~/jb-research
cd ~/jb-research

# 2. Install prerequisites
xcode-select --install
brew install ios-deploy

# 3. Connect iPhone via USB, then deploy
chmod +x mac-scripts/deploy_to_iphone.sh
./mac-scripts/deploy_to_iphone.sh

# 4. Open 'JBPoC' app on iPhone → tap 'Run Both'
```

See [mac-scripts/RESULTS_GUIDE.md](mac-scripts/RESULTS_GUIDE.md) for interpreting results.

## Key Findings

- **CVE-2026-43689 (DEVICE TESTED):** iOS 26.6.2 kernel lacks entitlement check but retains `suser()` root-uid gate. Sandboxed apps (uid 501) get EPERM. **Not a sandbox escape** — only exploitable from root-but-unentitled processes. Demoted to post-root persistence aid.
- **CVE-2026-84607:** 97 new validation strings added in 26.7, 3 new checking functions. Unchecked H.265 VPS/SPS/PPS parameters used for kernel buffer sizing.
- **CVE-2026-112659:** DFG Spread optimization type confusion. `canDoFastSpread` receives Spread node directly; `globalObjectFor` resolves from CodeOrigin, not operand — cross-realm type confusion pattern matching bug 321705.
- **A19 SPTM+MIE:** Memory Integrity Enforcement is new on A19, protecting kernel allocator backing store. Raises the bar significantly vs A15-A18.

## Binary Extraction (not in repo)

Raw binaries (kernelcaches, dyld_shared_cache, kexts) are too large for git. Extract them:

```bash
# On Mac: extract 26.7.2 binaries for diffing
brew install blacktop/tap/ipsw
chmod +x mac-scripts/01_extract_dyld.sh
./mac-scripts/01_extract_dyld.sh
```
