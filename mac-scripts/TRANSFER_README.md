# Transfer to Mac — Quick Start

## What to Copy

Copy the entire `mac-scripts/` folder to your Mac:

```bash
# Option A: USB drive / AirDrop / shared folder
# Copy: C:\Users\jmbur\tools\jb-research\mac-scripts\
# To:   ~/jb-research/mac-scripts/

# Option B: scp from Windows (if SSH enabled on Mac)
scp -r /c/Users/jmbur/tools/jb-research/mac-scripts/ your-mac:~/jb-research/mac-scripts/
```

## Run Order

### Step 1: Deploy PoCs to iPhone (THE MAIN EVENT)
```bash
cd ~/jb-research
chmod +x mac-scripts/deploy_to_iphone.sh
./mac-scripts/deploy_to_iphone.sh
```
This builds the unified PoC app and installs it on your iPhone.
Open the app → tap "Run Both" → read results.

### Step 2: Quick macOS chroot test (optional, fast)
```bash
clang -o /tmp/test_chroot mac-scripts/02_test_chroot_macos.c
/tmp/test_chroot
```
Tests if macOS shares the same missing entitlement check (probably EPERM).

### Step 3: Extract 26.7.2 binaries for diffing (later)
```bash
brew install blacktop/tap/ipsw
chmod +x mac-scripts/01_extract_dyld.sh
./mac-scripts/01_extract_dyld.sh
```

### Step 4: Extract TCC for CVE-2026-86886 analysis (later)
```bash
chmod +x mac-scripts/05_extract_tcc.sh
./mac-scripts/05_extract_tcc.sh
```

### Step 5: BinDiff (later, needs Ghidra + extracted binaries)
```bash
chmod +x mac-scripts/04_bindiff_jsc.sh
./mac-scripts/04_bindiff_jsc.sh
```

## Files in this Directory

| File | Purpose |
|------|---------|
| `deploy_to_iphone.sh` | **Main script** — builds + deploys PoC app to iPhone |
| `01_extract_dyld.sh` | Extract 26.7.2 dyld_shared_cache (JavaScriptCore, WebKit, TCC) |
| `02_test_chroot_macos.c` | Quick macOS chroot test (non-root) |
| `04_bindiff_jsc.sh` | Ghidra + BinDiff automation for 26.6.2 vs 26.7.2 |
| `05_extract_tcc.sh` | Extract TCC framework for CVE-2026-86886 analysis |
| `RESULTS_GUIDE.md` | How to interpret PoC results on device |
| `TRANSFER_README.md` | This file |

## Prerequisites (install on Mac first)

```bash
# Required for PoC deployment:
xcode-select --install    # Xcode command line tools
brew install ios-deploy    # USB deployment to iPhone

# Required for binary extraction (later):
brew install blacktop/tap/ipsw

# Optional for diffing:
# Install Ghidra from ghidra-sre.org
# Install BinDiff from zynamics.com
```

## After Running PoCs

Report results back. The key answers are:

1. **Q1:** Did `chroot(2)` return 0? (YES/NO, and if NO what errno?)
2. **Q2:** Did any escape path work? (symlink, fd, relative)
3. **Q3:** Any protected paths writable?
4. **AVE2:** Did VideoToolbox session create? Did IOKit selectors respond?
5. **Panic?** Any kernel panic after running? (check panic logs)
