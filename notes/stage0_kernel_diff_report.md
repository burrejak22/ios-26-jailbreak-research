# Stage 0: Kernel Binary Diff Report — iOS 26.6.2 vs 26.7.2

**Date:** 2026-11-12  
**Target:** iPhone 17 Pro (iPhone18,1, A19/t8150, arm64e)  
**Vulnerable:** iOS 26.6.2 (build 23G90, xnu-12377.162.14~4, Darwin 25.6.0)  
**Patched:** iOS 26.7.2 (build 23H128, xnu-12377.162.13.701.45~1, Darwin 25.6.0)

## Executive Summary

Binary diffing of kernelcaches and kexts between iOS 26.6.2 and 26.7.2 identified patches for multiple chain-candidate CVEs. The most significant findings:

1. **CVE-2026-43689 (chroot entitlement bypass)** — Fully characterized. Pure logic bug, trivially exploitable.
2. **CVE-2026-84607 (AppleAVE2 input validation)** — Fully characterized. 97 new validation strings, 3 new functions.
3. **CVE-2026-86916 (kernel UAF)** — Partial indicators found. `vm_protect_privileged_from_untrusted` removal and `flow_divert_pcb_handle` addition suggest VM/networking UAF.
4. **Multiple networking fixes** — IGMP/MLD assertions, mbuf signed→unsigned fix, Skywalk filter additions.

## Methodology

### Extraction
- Kernelcaches extracted from OTA `.aea` archives using `ipsw ota extract`
- Kexts split from FILESET kernelcache using `ipsw kernel kextract`
- String extraction via PowerShell `Select-String` on raw binaries
- Diff via sorted string comparison

### Kexts Analyzed
| Kext | 26.6.2 Size | 26.7.2 Size | Changed? |
|------|-------------|-------------|----------|
| com.apple.driver.AppleAVE2 | 2,629.5 KB | 2,645.5 KB | **YES (+16 KB)** |
| com.apple.kernel | 12,514.1 KB | 12,530.1 KB | **YES (+16 KB)** |
| com.apple.security.sandbox | 2,179.4 KB | 2,179.4 KB | No (identical) |
| com.apple.driver.AppleMobileFileIntegrity | 291.4 KB | 291.4 KB | No (identical) |

### String Counts
| Binary | 26.6.2 | 26.7.2 | Delta |
|--------|--------|--------|-------|
| AppleAVE2 | 12,290 | 12,387 | +97 |
| Kernel | 28,028 | 28,044 | +16 |

## CVE-2026-43689 — chroot(2) Entitlement Bypass

**Status:** DEVICE TESTED — EPERM (2026-11-12)  
**Impact:** ~~Root privileges from sandboxed app~~ Post-root persistence only  
**Complexity:** Trivial (logic bug, no memory corruption)  
**Chain role:** ~~Stage 2 (Sandbox escape)~~ → Stage 4 (Post-root persistence aid)

### Device Test Result

Tested on iPhone 17 Pro, iOS 26.6.2, uid 501 sandboxed app:
```
chroot(2) FAILED: errno=1 (Operation not permitted)
```

**Two gates exist on chroot(2):**
1. `suser()` root-uid check — requires uid 0. BLOCKS sandboxed apps (uid 501).
2. Entitlement check — MISSING on 26.6.2 (added in 26.7.2).

Sandboxed apps hit the root check first → EPERM. Bug is only exploitable from root-but-unentitled processes (system daemons). **NOT a sandbox escape.**

### Patch
New strings in 26.7.2 kernel:
```
com.apple.private.vfs.chroot
%s: proc %s[%d] calls chroot(2) without entitlement
```

**Detailed analysis:** [CVE-2026-43689_analysis.md](CVE-2026-43689_analysis.md)

## CVE-2026-84607 — AppleAVE2 Input Validation Bypass

**Status:** FULLY CHARACTERIZED  
**Impact:** Kernel code execution from sandboxed app  
**Complexity:** Medium (requires crafted H.265 parameters)  
**Chain role:** Alternative Stage 1 (Entry via IOKit)

### Patch
16 KB of new validation code. 97 new strings. 3 new validation functions:
- `AVE_Client_CheckMCTFInfo`
- `AVE_Client_CheckLRMEInfo`  
- `AVE_HEVC_CheckVPSExtBounds`

Unchecked video codec parameters (SPS/PPS/VPS/RPS) used for kernel buffer sizing, array indexing, and loop bounds. Accessible from any sandboxed app via VideoToolbox API.

**Detailed analysis:** [CVE-2026-84607_analysis.md](CVE-2026-84607_analysis.md)

## CVE-2026-86916 — Kernel UAF (Preliminary)

**Status:** PARTIALLY CHARACTERIZED  
**Impact:** Arbitrary code with kernel privileges  
**Complexity:** High (UAF requires heap manipulation)  
**Chain role:** Stage 3 (Kernel R/W)

### Indicators from Kernel Diff

**Removed from 26.6.2:**
- `vm_protect_privileged_from_untrusted` — VM protection function removal suggests code path change in VM subsystem
- `protect_privileged_from_untrusted` — Related function also removed
- `reservation without pageout? @%s:%d` — VM pager assertion removed (code path changed)
- `missing pager for copy object @%s:%d` — VM pager assertion removed

**Added in 26.7.2:**
- `site.struct flow_divert_pcb_handle` — New flow divert structure (potential UAF object tracking)

### Assessment
The VM subsystem changes (removing `vm_protect_privileged_from_untrusted` and related pager assertions) may indicate a UAF fix in the VM pager or copy-on-write code. The `flow_divert_pcb_handle` addition suggests a networking UAF fix in the flow divert subsystem. Need Ghidra disassembly to determine which change corresponds to CVE-2026-86916 vs other fixes.

## Other Security-Relevant Kernel Changes

### Networking Fixes
| Change | Type | Potential CVE |
|--------|------|---------------|
| `%s: refusing cross-protocol ifa change on route with llinfo` | New safety check | Routing confusion |
| `rt_setif` | New function | Route interface management |
| `_inm->inm_in_dtle == true` assertion | IGMP fix | Multicast DoS/corruption |
| `_in6m->in6m_in_dtle == true` assertion | MLD fix | IPv6 multicast |
| mbuf `%d+%d` → `%u+%u` | Signed→unsigned | Integer overflow in packet length |
| `FilterDropBadDirection` | Skywalk filter | Packet direction validation |
| `nx_netif_filter_pkt_to_mbuf` | Skywalk filter | Packet conversion |
| `nx_netif_filter_pkt_to_pkt` | Skywalk filter | Packet-to-packet filter |
| `fsw_dev_input_netem_enqueue` | Flowswitch | Network emulation |
| `necp_set_socket_resolver_signature_from_parameters` | NECP | Socket resolver |

### VM Subsystem Changes
- Removed: `vm_protect_privileged_from_untrusted`, `protect_privileged_from_untrusted`
- Removed: `reservation without pageout?`, `missing pager for copy object` (assertion text changes)
- These suggest a code path restructure in VM protection and pager handling

## Blockers

### dyld_shared_cache Extraction (Windows)
Cannot extract userspace binaries (WebKit, JSC, ImageIO, etc.) from 26.7.2 OTA on Windows:
- OTA uses Apple Archive format requiring macOS-only `aa` tool
- Cryptex patching: `RawImagePatch: only supported on darwin`
- No IPSWs available for any 26.7.x version
- **Impact:** Blocks CVE-2026-112659 (WebKit type confusion) binary diff

### WebKit/JSC Source
CVE-2026-112659 fix (Bugzilla 321982) under embargo. Not yet in WebKit open source.

## Chain Architecture (Revised 2026-11-12 — post device test)

```
┌─────────────────────────────────────────────────────────┐
│  JAILBREAK EXPLOIT CHAIN — iOS 26.6.2 iPhone 17 Pro    │
│  Updated after CVE-2026-43689 device test (EPERM)       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  CHAIN A — PRIMARY (direct app → kernel):               │
│  ┌─ CVE-2026-84607 (AppleAVE2) ★ CHARACTERIZED         │
│  │  App → kernel OOB via VideoToolbox (no sandbox esc)  │
│  ├─→ CVE-2026-86916 (kernel UAF) PARTIAL               │
│  │   Kernel heap corruption → full kernel R/W → root    │
│  ├─→ CVE-2026-43689 (chroot) ★ DEVICE TESTED           │
│  │   Post-root path confusion (requires uid 0 first)   │
│  └─→ CVE-2026-86886 (TCC path traversal)               │
│      Protected file writes → untethered persistence     │
│                                                         │
│  CHAIN B — WEAKENED (WebKit entry):                     │
│  ┌─ CVE-2026-112659 (WebKit/JSC) ANALYZED              │
│  │  Safari → arbitrary code exec in WebContent          │
│  ├─ [SANDBOX ESCAPE TBD — chroot RULED OUT]             │
│  │  Need alternative escape from WebContent sandbox     │
│  └─→ CVE-2026-86916 (kernel UAF)                       │
│     Kernel R/W from escaped context                     │
│                                                         │
│  KEY FINDING: CVE-2026-43689 has TWO gates:             │
│  1. suser() root-uid check — blocks uid 501 (EPERM)    │
│  2. Entitlement check — missing on 26.6.2 (the bug)    │
│  Result: Only exploitable AFTER kernel → root.          │
│                                                         │
│  Calif.io used CVE-2026-86886 for untethered JB on     │
│  iOS 27.0.1 at Hexacon (October 2026). Unpatched on    │
│  26.6.2 — our best persistence primitive.               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Recommended Next Steps

1. **Deploy PoCs to iPhone** — Answer chroot Q1/Q2/Q3 and probe AVE2 IOKit selectors.
2. **Extract TCC binaries on Mac** — Run `05_extract_tcc.sh` to get CVE-2026-86886 targets.
3. **BinDiff TCC** — Find the path traversal patch for persistence primitive.
4. **Ghidra kernel analysis** — Import both kernelcaches, locate `vm_protect_privileged_from_untrusted` in 26.6.2, trace the UAF path for CVE-2026-86916.
5. **BinDiff JSC on Mac** — Run `04_bindiff_jsc.sh` to find CVE-2026-112659 patch.
6. **Investigate untether mechanisms** — See [untethered_jb_requirements.md](untethered_jb_requirements.md) for full analysis.
7. **Monitor Calif.io** — Their kernel exploit and persistence writeup is expected soon.
