# PoC Results Interpretation Guide

## How to Run

### Quick Path (terminal)
```bash
cd ~/jb-research
chmod +x mac-scripts/deploy_to_iphone.sh
./mac-scripts/deploy_to_iphone.sh
```

### If that fails — Xcode manual
1. Xcode → New → iOS App → "JBPoC" → Objective-C
2. Delete auto-generated files
3. Drag `~/jb-research/iphone-deploy/main.m` into project
4. Add frameworks: VideoToolbox, CoreMedia, AVFoundation, IOKit
5. Set deployment target to 26.0
6. Select iPhone → Cmd+R

### Monitor Output
- **On device:** Green text in the app
- **Console.app:** Open on Mac → select iPhone → filter "CVE" or "JBPoC"
- **Panic logs:** Settings → Privacy & Security → Analytics → panic-*

---

## CVE-2026-43689 Results Decision Tree

```
Q1: chroot(2) returns 0?
├── YES → BIG DEAL. Proceed to Q2.
│   ├── Q2: Symlink/fd escape works?
│   │   ├── YES → SANDBOX ESCAPE CONFIRMED
│   │   │   └── Q3: Can write to protected paths?
│   │   │       ├── YES → FULL CHAIN CANDIDATE
│   │   │       └── NO → Partial escape, need different write vector
│   │   └── NO → Chroot works but no escape. Limited value.
│   │       └── Check: can post-chroot process confuse other daemons?
│   └── Q2: Path confusion on sandbox rules?
│       ├── YES → SEATBELT BYPASS via path resolution
│       └── NO → Sandbox correctly resolves real paths
└── NO
    ├── errno=EPERM → Root-uid check blocks us. Bug requires root-but-unentitled context.
    │   └── Still useful AFTER getting root via CVE-2026-86916 kernel exploit.
    ├── errno=EACCES → Sandbox profile has syscall filter for chroot.
    │   └── Need to check if filter is in container profile or global.
    └── Other → Unexpected. Report errno.
```

### What Each Q1 Answer Means for the Chain

| Q1 Result | Chain Impact |
|-----------|-------------|
| **YES** | chroot → sandbox escape → direct path to kernel (Chain B validated) |
| **EPERM** | Need root first. Reorder chain: kernel exploit THEN chroot for persistence |
| **EACCES** | Sandbox blocks it. Must escape sandbox first via different bug |

---

## CVE-2026-84607 Results Decision Tree

```
VideoToolbox approach:
├── Session created (HEVC or H264)?
│   ├── YES → AppleAVE2 hardware encoder allocated
│   │   ├── EncodeFrame returned 0?
│   │   │   ├── YES → Parameters reached kernel
│   │   │   │   ├── Device panicked? → OOB WRITE TRIGGERED (check panic log)
│   │   │   │   └── No panic → VT may filter params before kernel
│   │   │   └── NO → VT rejected parameters (error code tells which check)
│   │   └── PrepareToEncode failed? → Hardware encoder busy/unavailable
│   └── NO → HW encoder not available (simulator? or AppleAVE2 not present)
│
IOKit approach:
├── Found AppleAVE2 service?
│   ├── YES → Service exists in IORegistry
│   │   ├── IOServiceOpen succeeded?
│   │   │   ├── YES → USER CLIENT OPENED (rare from sandbox!)
│   │   │   │   └── Selector probing results tell us available methods
│   │   │   └── NO → Sandbox blocks direct IOKit (expected)
│   │   │       └── Use VideoToolbox path instead
│   └── NO → Different driver name on this device
│       └── Check enumerated services for the right name
```

### Key Selector Results

| Selector | Expected Function | If "OK" | If "BadArgument" |
|----------|------------------|---------|------------------|
| 0 | AVE_UCCmd_Start | Can start encoder | Needs proper struct |
| 1 | AVE_UCCmd_Stop | Can stop encoder | Session not active |
| 2 | AVE_UCCmd_Process | Can submit frames | Need active session |
| 3 | AVE_UCCmd_Complete | Can complete | Need pending frame |
| 4 | AVE_UCCmd_Flush | Can flush | Session not active |

---

## After Getting Results

### If chroot succeeds (Q1=YES, Q2=YES)
1. Screenshot/copy all log output
2. Note exact paths that were writable
3. Test writing to `/private/preboot/Cryptexes/` for persistence research
4. This validates Chain B (WebKit → chroot escape → kernel)

### If chroot fails but AVE2 works
1. Focus on Chain A (direct app → kernel via VideoToolbox)
2. Check panic log for exact crash address
3. The crash tells us which unchecked parameter hit which kernel code
4. Need Ghidra to map crash address to vulnerable function

### If both fail from sandbox
1. Try from a debugger (lldb) via Xcode — removes some sandbox restrictions
2. Try entitlement injection via provisioning profile
3. Consider WebKit entry first (CVE-2026-112659) to escape WebContent sandbox

### Panic Log Location
- **On device:** Settings → Privacy & Security → Analytics & Improvements → Analytics Data → panic-*
- **Console.app:** Your Mac → Devices → iPhone → Device Logs
- **sysdiagnose:** Both volume buttons + side button → wait 10 min → Settings → Analytics
