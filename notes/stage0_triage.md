# Stage 0: Bug Triage — iOS 26.6.2 Jailbreak Chain Candidates

**Objective:** For each candidate CVE, determine: (1) is the trigger reachable from a user-space app, (2) is a PoC derivable from the patch diff, and (3) what's the exploitation complexity on arm64e.

---

## Chain Architecture

```
Entry (remote or local) → Sandbox Escape → Kernel Exploit → Post-Exploitation
```

### Primary Chain A (revised 2026-11-13)

**Stage 1 — Infoleak / KASLR defeat: AVE2 OOB read (CVE-2026-112466 candidate)**

| Factor | Detail |
|--------|--------|
| Trigger surface | Alpha layer ID / VPS extension fields |
| Status | Not yet triggered; read-back route to userspace unverified |
| Priority | **Top Ghidra target on AppleAVE2 26.6.2** |
| Rationale | Only stage of this family that reads back to userspace — the chain needs it for KASLR defeat more than another write |

**Stage 2 — Kernel write: AVE2 OOB write (Hcamael-family: 112468/9/70, 112705-adjacent)**

| Factor | Detail |
|--------|--------|
| Trigger | **AlphaLayerID=255 — CONFIRMED, isolated, reproduces ~1 in 2 presses** (hit rate TBD) |
| Type | Deferred DART fault (frame encode errors at -17691, OOB write lands later during idle/teardown) |
| Status | **Primitive characterization in progress** |
| Open questions | Truncation (raw vs bitstream value), DVA determinism |

**Stage 3 — Kernel R/W: CVE-2026-86916 (kernel UAF)**

| Factor | Detail |
|--------|--------|
| Status | Pending Ghidra (read primitives / leak candidates first) |
| Note | Keep CVE-2026-84607 in doc as separate candidate — its trigger shape is **mid-session encoder-type mutation** (race property change against in-flight frames, not a single set+encode). PoC is an entirely different form factor. |

**Stage 4 — Persistence: CVE-2026-86886 (TCC path traversal)**

| Factor | Detail |
|--------|--------|
| Status | TRIAGE |

### Chain B: WebKit Entry (WEAKENED — needs different sandbox escape)

| Stage | CVE | Component | Bug Class | Status |
|-------|-----|-----------|-----------|--------|
| **Entry** | CVE-2026-112659 | WebKit/JSC | Type confusion → RCE | ANALYZED (Ghidra + candidate sites) |
| **Sandbox Escape** | ~~CVE-2026-43689~~ | ~~XNU Kernel~~ | ~~chroot entitlement bypass~~ | **DEVICE TESTED: EPERM (uid 501)** |
| **Kernel R/W** | CVE-2026-86916 | Kernel | UAF → kernel code exec | PARTIAL |
| **Persistence** | CVE-2026-86886 | TCC | Protected file modification | TRIAGE |

CVE-2026-43689 **ruled out as sandbox escape** — device test confirmed EPERM for uid 501 apps.
chroot(2) requires root (suser() gate). Demoted to post-root persistence aid. Chain B needs a
different sandbox escape mechanism or must rely on Chain A's kernel entry.

### Alternate Entries

| CVE | Component | Bug Class | Notes |
|-----|-----------|-----------|-------|
| CVE-2026-86950 | CoreGraphics | OOB write | Already analyzed, ITW-proven, bounty track |
| CVE-2026-112610/611 | CoreGraphics | OOB write | Same component as 86950, PDF trigger |
| CVE-2026-65414 | Bluetooth | OOB write → RCE | Zero-click but proximity-only |
| CVE-2026-112697 | WebKit | UAF → RCE | Alternative to 112659 |

---

## Candidate Triage

### CVE-2026-112659 — WebKit Type Confusion → RCE [PRIORITY 1]

**Component:** WebKit (JavaScriptCore)  
**Bug class:** Type confusion  
**Impact:** Arbitrary code execution  
**Credit:** OpenAI Codex Security — Amy Burnett, Chris Rohlf with Anthropic Research  
**Patched in:** iOS 26.7.2 (build 23H128, October 26, 2026)

**Reachability:** YES — WebKit is the rendering engine for Safari and all in-app web views. Any webpage can trigger JSC type confusion bugs. Reachable from:
- Safari (direct browsing)
- Any WKWebView-based app
- Mail HTML rendering (limited JS)
- iMessage link previews (limited)

**PoC derivability from patch diff:** HIGH
- Type confusions in JSC typically involve incorrect type checks or missing type barriers
- The patch will show where a type check was added or where a type barrier was inserted
- JSC type confusions often manifest as DFG/FTL JIT compiler bugs where speculative types diverge from actual types
- Known patterns: missing type check in DFG AbstractInterpreter, incorrect AI (Abstract Interpretation) type in SpeculatedType, wrong clobberize behavior
- Amy Burnett (OpenAI Codex Security) likely used automated analysis; Chris Rohlf (Anthropic) has deep browser exploitation experience

**Exploitation complexity on arm64e:** MEDIUM
- Type confusions give excellent read/write primitives — typically craft a fakeobj/addrof pair
- JSC JIT pages are RWX on some configs, RW→RX on others; may need JIT spray or write-to-JIT
- PAC complicates vtable hijacking but doesn't prevent data-only attacks
- Well-documented exploitation methodology: Project Zero, ZDI, Azimuth, etc.

**Binary extracted:** YES — JavaScriptCore (41.5 MB), WebKit (41.6 MB)  
**Patch binary needed:** 26.7.2 JavaScriptCore (download in progress)  

**Verdict:** ✅ PROCEED — Highest-priority target. Type confusions are the most reliable WebKit primitive.

---

### CVE-2026-64759 — ImageIO Integer Overflow → RCE [PRIORITY 2]

**Component:** ImageIO  
**Bug class:** Integer overflow → arbitrary code execution  
**Impact:** Arbitrary code execution  
**Credit:** XlabAI Team of Tencent Xuanwu Lab, Atuin Automated Vulnerability Discovery Engine, multiple others  
**Patched in:** iOS 26.7.2

**Reachability:** YES — ImageIO processes images in many contexts:
- Safari (inline images)
- Messages (image thumbnails)
- Mail (inline images)
- Photos (import/preview)
- Spotlight (indexing)
- Many 3rd-party apps

**PoC derivability from patch diff:** HIGH
- Integer overflows in image decoders are well-understood
- The patch will show where a bounds check or integer overflow guard was added
- Crafting a PoC image requires understanding the file format and the overflow location
- Tencent Xuanwu Lab and "Atuin Automated Vulnerability Discovery Engine" suggest fuzzing-discovered bug

**Exploitation complexity on arm64e:** MEDIUM
- Integer overflow in image decoder → undersized allocation → heap overflow
- Similar primitive to CVE-2026-86950 (CoreGraphics) but through ImageIO
- Heap exploitation on iOS is well-documented (Project Zero, Pangu, etc.)
- The multiple independent discoverers suggest the bug is relatively shallow

**Binary extracted:** Not yet (ImageIO not in priority list)  
**Action:** Extract ImageIO from dyld cache

**Verdict:** ✅ PROCEED — Strong alternative entry. Zero-click potential via iMessage images.

---

### CVE-2026-84607 — AVEVideoEncoder Race Condition → Kernel [DEPRIORITIZED]

**Component:** AVEVideoEncoder (kernel driver)  
**Bug class:** Race condition / state-consistency  
**Impact:** Kernel code execution from sandboxed app  
**Credit:** Ruslan Dautov  
**Patched in:** iOS 26.7

**CORRECTION (2026-11-13):** 84607's actual fix is a per-frame **eEncType vs
sSessionCfg.sEnc.eType state-consistency guard** — a race/type-confusion between encoder types
("improved state management"). Its trigger shape is **mid-session encoder-type mutation**, not an
out-of-range parameter value. The AlphaLayerID panic trigger is NOT this CVE — it belongs to the
Hcamael-family bounds-validation batch (112468/9/70 candidates).

**PoC form factor:** Race property change against in-flight frames (entirely different from the
single set+encode pattern used for AlphaLayerID).

**Status:** Deprioritized — Chain A Stage 2 now uses the confirmed AlphaLayerID OOB write
(Hcamael-family). 84607 remains a viable alternative if the Hcamael trigger proves
non-exploitable, but requires a dedicated race PoC.

**Binary:** AVEVideoEncoder kext in kernelcache.

**Verdict:** HOLD — different PoC form factor needed. Not the confirmed panic trigger.

---

### CVE-2026-43689 — Kernel Permissions → Root [PRIORITY 1]

**Component:** Kernel  
**Bug class:** Permissions issue  
**Impact:** Malicious app gains root privileges  
**Credit:** Andreas Jaegersberger & Ro Achterberg of Nosebeard Labs  
**Patched in:** iOS 26.7  
**CVSS:** 7.8 (High)

**Reachability:** YES — Local app, low privileges required, low attack complexity.

**PoC derivability from patch diff:** HIGH
- Permissions issues are often logic bugs, not memory corruption
- The patch will show where a permission check was added
- These are typically the most reliable exploits — no heap spray, no race, no ASLR bypass needed
- CVSS confirms: local, low privilege, low complexity

**Exploitation complexity on arm64e:** LOW
- Permissions bugs bypass all memory corruption mitigations (PAC, ASLR, etc.)
- Just need to trigger the permission anomaly
- Root access enables reading/writing protected files, debugging other processes, etc.
- May not give full kernel code execution, but root is sufficient for many jailbreak tasks

**Binary:** In kernelcache.  
**Action:** Need kernelcache extraction.

**Verdict:** ✅ PROCEED — Most reliable escalation. Permissions > memory corruption.

---

### CVE-2026-86916 — Kernel UAF → Kernel Code Execution [PRIORITY 2]

**Component:** Kernel  
**Bug class:** Use-after-free  
**Impact:** Arbitrary code with kernel privileges  
**Credit:** Wang Yu  
**Patched in:** iOS 26.7

**Reachability:** YES — Local app, implied low complexity (UAF from app context).

**PoC derivability from patch diff:** MEDIUM
- UAFs require understanding the object lifecycle (alloc → use → free → reuse)
- The patch will show where a retain/release was fixed or where the object was zeroed
- Need to identify the freed object type, its allocator (kalloc, zone, etc.), and the reuse window
- Wang Yu found 3 kernel bugs — likely has deep understanding of the kernel allocator

**Exploitation complexity on arm64e:** HIGH
- Kernel UAFs on arm64e are well-mitigated:
  - Zone poisoning detects some reuse patterns
  - PAC protects function pointers in kernel objects
  - KTRR prevents kernel code modification
  - PPL protects page tables
- But Wang Yu got "arbitrary code with kernel privileges" — the impact statement means it's exploitable
- Standard technique: free object → allocate replacement object of same size → vtable confusion

**Binary:** In kernelcache.  
**Action:** Need kernelcache extraction.

**Verdict:** ✅ PROCEED — Only if CVE-2026-43689 doesn't give enough privilege. Full kernel R/W as the nuclear option.

---

### CVE-2026-86886 — TCC Protected File Modification [PRIORITY 3]

**Component:** TCC (Transparency, Consent, and Control)  
**Bug class:** Unspecified  
**Impact:** App can modify protected system files  
**Credit:** Calif.io (Huy Nguyen), Constantin Clerc, others  
**Patched in:** iOS 26.7

**Reachability:** YES — From app context.

**PoC derivability from patch diff:** HIGH
- TCC bypasses are often logic bugs (symlink tricks, race conditions, path traversal)
- The patch will show where the file path validation was strengthened
- Calif.io and Constantin Clerc are known for TCC research

**Exploitation complexity on arm64e:** LOW
- TCC bypasses are typically logic bugs, no memory corruption needed
- Useful for persistence: modify system files to install a launch daemon or hook

**Verdict:** ✅ PROCEED — Persistence component for untether.

---

## Immediate Actions

### Now (with 26.6.2 binaries)
1. Import JavaScriptCore (41.5 MB) into Ghidra
2. Search for DFG/FTL type confusion patterns
3. Identify candidate type confusion sites (SpeculatedType, AbstractInterpreter)
4. Extract ImageIO from dyld cache

### When 26.7.2 download completes
5. Extract JavaScriptCore from 26.7.2 dyld cache
6. BinDiff 26.6.2 vs 26.7.2 JavaScriptCore → find CVE-2026-112659 patch location
7. Reverse engineer the patch → identify vulnerable code path
8. Craft triggering JavaScript

### When kernelcache is available
9. Extract kernelcache from 26.6.2 and 26.7 OTAs
10. BinDiff for CVE-2026-84607 (AVEVideoEncoder)
11. BinDiff for CVE-2026-43689 (permissions)
12. BinDiff for CVE-2026-86916 (kernel UAF)

---

## Risk Assessment

| Factor | Assessment |
|--------|------------|
| Detection risk | LOW — all research on own device, no network exploitation |
| Legal risk | LOW — own device, DMCA exemption, Apple Security Bounty |
| Reliability | HIGH — permissions bugs + type confusions are deterministic |
| Time estimate | Stage 0: 1-2 days, Stage 1: 3-5 days, Stage 2: 2-3 days |
| PAC bypass needed? | Maybe — depends on whether CVE-2026-43689 gives root without memory corruption |
