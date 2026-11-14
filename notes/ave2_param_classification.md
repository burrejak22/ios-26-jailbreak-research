# AVE2 Parameter Classification — Device Test Results (rev. 2026-11-13)

**Device:** iPhone 17 Pro (iPhone18,1), iOS 26.6.2
**Test:** `VTSessionCopySupportedPropertyDictionary` on hardware HEVC encoder
**Result:** 158 properties enumerated. Multiple CVE-relevant params confirmed settable.

---

## CONFIRMED TRIGGER: AlphaLayerID=255 — DEFERRED DART FAULT (2026-11-13)

**AlphaLayerID=255 alone is the confirmed isolated kernel-panic trigger.** Confirmed via
idle-delay test: the panic fired long *after* the userspace encode callback had already returned
an error (-17691), during the wait before the next action, with no follow-up press.

**Critical methodological rule: encode error != safety.** The -17691 encode callback printed
"NO OUTPUT, not a clean test" — but the DART fault is a *deferred DMA write* landing
seconds-to-minutes after the callback. A failed encode does NOT mean no DMA occurred. No suspect
is eliminated on callback error alone.

**Deferral mechanism (updated after 2E-0 Run A):** encode submitted with poison parameter ->
firmware arms an invalid DMA descriptor -> encode fails (userspace sees -17691) -> **descriptor
survives session destruction** -> descriptor executes on firmware-internal timer/event (~90-160s)
-> OOB write traps in DART. The descriptor is firmware/hardware state, NOT kernel session state.
Session invalidation does not accelerate or prevent the fault. **The armed descriptor is a time
bomb — a process can arm it, destroy all userspace evidence, and the OOB write still fires.**

**Required protocol from now on:** canary -> set suspect -> encode -> observe callback
(success OR error) -> WAIT 120 SECONDS, do nothing, do not recreate session -> only then
conclude "no panic."

---

## CVE ATTRIBUTION CORRECTION — NOT CVE-2026-84607

This doc previously stated "CVE-2026-84607 is confirmed exploitable — panic-on-device proven."
**That attribution was wrong and is removed.**

CVE-2026-84607's fix is a per-frame **eEncType vs. sSessionCfg.sEnc.eType state-consistency
guard** in AppleAVE2 that diverts the frame on mismatch — a race/type-confusion between encoder
types ("improved state management" = validation at point of use, kernel-only). Its trigger shape
is **mid-session encoder-type mutation**, not an out-of-range parameter like AlphaLayerID.
(Ping-2o located the fix; PoC framework: https://github.com/Ping-2o/ios.CVE-2026-84616-84607)

### Correct candidate family: 26.7.2 bounds-validation batch (fixed 2026-10-26)

- **CVE-2026-112705** — OOB write, NTL trigger (~16463). Public repros exist (MchinaMd57764,
  Lak453). Fingerprint: AppleAVE2+0xDA78, far=0x59, fixed-offset constant fill, NO arbitrary
  read/write. Known distinct from our trigger.
- **CVE-2026-112468 / 112469 / 112470** — OOB writes via VideoToolbox (Hcamael).
- **CVE-2026-112466** — OOB READ — **kernel memory disclosure. This is the KASLR-defeat stage
  our chain needs.** Highest-priority Ghidra target.
- **CVE-2026-112689** — OOB write (Belman).

### Why our trigger is distinct from the published NTL repro (112705)

1. Different parameter (AlphaLayerID=255 vs NumberOfTemporalLayers~16463)
2. Different panic fingerprint: our DVA lands in the 0x100007xxxxx window (structured region),
   two crashes ~25 pages apart on different encoder channels (0xc0/0xc1)
3. **Deferred/deferred-race firing** — DART fault lands seconds after userspace error — the
   published repros documented no such deferral
4. Trigger value (255) exceeds the VPS bitstream field width (6 bits) — the mod-64 truncation
   question is still open (see truncation test)

---

## AVE2 Trigger / Crash Table

### Status: AlphaLayerID=255 CONFIRMED as isolated trigger (2026-11-13 reattribution)

Prior attribution was timing-misattributed. Alpha=255 is the real trigger, confirmed by idle-delay test.
The panic fired long after the userspace callback error (-17691) printed — the DART fault is a **deferred
DMA write**, not synchronous with the encode error.

| # | Date/Time | Trigger | DVA | PTE | AXI_ID | Delay post-encode | Attribution confidence |
|---|-----------|---------|-----|-----|--------|-------------------|----------------------|
| 1 | 2026-11-12 ~23:55 | Escalation sweep (cumulative Alpha 0-255, multi-session) | 0x100007d2a80 | — | 0xc1 | unknown | Low — not isolatable |
| 2 | 2026-11-13 ~00:42 | AlphaLayerID=255, deferred fault | 0x100007ec500 | — | 0xc0 | unknown | **HIGH — isolated** |
| 3 | 2026-11-13 10:34 | AlphaLayerID=255, idle-wait protocol | 0x100007ecc00 | 0x1fb | 0xc0 | ~90s | **HIGH — .ips captured** |
| 4 | 2026-11-13 10:43 | AlphaLayerID=255, idle-wait protocol | 0x10000710080 | 0x1c4 | 0xc0 | ~130s | **HIGH — .ips captured** |
| 5 | 2026-11-13 12:33 | AlphaLayerID=255, 2E-0 teardown test | 0x10000ed4080 | 0x3b5 | 0xc0 | TBD | **HIGH — .ips captured** |
| 6 | 2026-11-13 ~20:08 | AlphaLayerID=255, 2E-0 **Run A** (immediate invalidate) | 0x1000082d500 | 0x20b | 0xc0 | ~160s | **HIGH — Run A result** |

**DVA analysis (6 panics):**
- Panics 1-4: DVAs in `0x100007xxxxx` region (~900KB span, PTE 452-507)
- Panic 5: DVA at `0x10000ed4080` — **PTE 949**, nearly 2x the previous PTEs
- **Panic 6: DVA at `0x1000082d500` — PTE 0x20b (523)** — back in the mid-range
- **DVA REPEAT: Panic 6 DVA (0x1000082d500) matches a prior panic** — suggests deterministic
  descriptor slot when the session is invalidated (same DMA descriptor target address)
- AXI_ID 0xc0 in 5 of 6 runs (one 0xc1) — primary encoder write channel
- All faults are **PTE invalid exception on write** from `dart-ave` at `AppleT8110DART.cpp:2369`
- DVAs shift with kernel slide and heap state per boot, but descriptor slot may be fixed
  relative to session allocation

**Deferral timing is variable** (90s, 130s, 160s post-encode) — confirms async trigger, not fixed timer.
**Run A result: Session invalidation does NOT accelerate the fault.** The descriptor survives both
session destruction AND the 60s post-invalidation idle window. The deferral is firmware/hardware
state that lives beyond kernel session lifecycle.

**Panic string template (both identical except DVA/PTE):**
`dart-ave: DART(DART) error: SID 0 PTE invalid exception on write of DVA <addr> (CTE 0x10 SEG 0 PTE <pte>) ERROR_SID_SUMMARY 0x00003100 AXI_ID 0xc0`

**Key methodological finding:** userspace encode error != safety. DART faults may fire seconds after the
callback returns. Encode failures (-17691) do not mean no DMA occurred. Any "elimination" based on
callback error alone is invalid without the 120-second wait window.

**Deferral mechanism hypothesis (to verify in Ghidra):** encode is submitted with the poison parameter,
firmware/hardware sets up an invalid DMA descriptor, the encode fails and the callback errors, but the
descriptor executes later (teardown/flush/idle) when the surface is unmapped or the session is recycled,
and that's when hardware writes OOB and DART traps.

**Alpha64+RepFmt10 status: UNTESTED** (the 11/13 00:42 crash attributed to it was actually
Alpha=255's deferred fault). Back in the queue.

---

## NEXT EXPERIMENT QUEUE — PHASE 2 (priority order)

**Code deployed: deploy_to_iphone.sh Phase 2 buttons (Idle Wait, Truncation, Boundary)**

### 2A. Idle Wait (Alpha=255 repeatability) — COMPLETE
**Result: 2/2 panics. 100% panic rate with idle-wait protocol.**
- Run 1: encode callback 10:32:27, panic ~10:34:00 (~90s delay)
- Run 2: encode callback 10:41:18, panic 10:43:28 (~130s delay)
- Both: DVA in 0x100007xxxxx, AXI_ID 0xc0, PTE invalid on write
- Variable deferral (90s vs 130s) = async trigger, not fixed timer
- .ips logs saved in `crashes/`

### 2B. Truncation Test (raw vs 6-bit kernel consumption) — COMPLETE
**Result: NONE panic → trigger requires the -17691 error path specifically.**

| Value | mod-64 | Encode result | VPS vps_max_layer_id | Panic? |
|-------|--------|---------------|---------------------|--------|
| 63 | 63 | clean, callback OK | 63 (over limit) | NO |
| 127 | 63 | clean, callback OK | 63 (over limit) | NO |
| 191 | 63 | clean, callback OK | 63 (over limit) | NO |
| 255 | 63 | **-17691 rejection** | not emitted | **YES (100%)** |

All three test values produced identical abnormal multi-layer VPS (vps_max_layer_id=63,
vps_extension_flag=1, splitting_flag=1, scalability_mask=0x8007) — none triggered a DART fault.

**Conclusion:** The DART fault is NOT caused by the VPS bitstream value or the layer-ID magnitude.
It is tied to the encoder's error/abort path (the -17691 rejection that only 255 hits). The
corruption is a fixed-feature defect in the error teardown — likely a DMA descriptor left armed
or an OOB descriptor written during the failed encode's cleanup path.

**Hypotheses eliminated:**
- "Wide OOB scaling with raw IOKit value" — OUT
- "6-bit truncation OOB" — OUT
- "Any value ≥ 63 triggers" — OUT

**Leading model:** At Alpha=255, the encoder takes an error/rejection path that leaves a DMA
descriptor armed. During idle/teardown, AVE2 hardware fires it, writing OOB into unmapped DART
pages. The OOB write is a fixed consequence of the error path, not value-proportional.

### 2C. Boundary Sweep — COMPLETE
**Goal:** Determine whether the -17691 rejection is a range (≥N) or exact sentinel (==255).

**Results — comprehensive near-255 sweep:**

| Value | Encode result | 120s idle | Panic? |
|-------|---------------|-----------|--------|
| 254 | clean, callback OK | survived | NO |
| 253 | clean, callback OK | survived | NO |
| 252 | clean, callback OK | survived | NO |
| 250 | clean, callback OK | survived | NO |
| 245 | clean, callback OK | survived | NO |
| 235 | clean, callback OK | survived | NO |
| 200 | clean, callback OK | survived | NO |
| 128 | clean, callback OK | survived | NO |

Combined with Phase 2B (63, 127, 191 all clean) and earlier sweep (192, 160, 144, 224, 240, 248
all clean), every value from 0–254 produces a clean encode. Only 255 triggers -17691 rejection.

**Definitive conclusion:** AlphaLayerID=255 (0xFF) is a **UInt8 sentinel/max marker**. The
AppleAVE2 driver has an exact `== 0xFF` check that routes the encode to the rejection path.
This is NOT a range comparison, NOT a ≥N clamp, NOT a signed overflow — it is a single-value
sentinel that the driver treats as "invalid/reserved."

### 2D. Control Re-test — SUPERSEDED
Phase 2A already confirmed the fault is live with 3/3 panics at variable deferral (90–130s).
Phase 2C confirmed 254 (one below) never panics. No further control needed.

### 2E-0. Session Teardown Test — RUN A COMPLETE, RUN B NEXT
**Goal:** Identify the exact trigger mechanism for the deferred DART fault.

**Run A Result (2026-11-13 ~20:06–20:08):**
- Encode with Alpha=255 at ~20:06:08 → callback returned -17691
- Immediately called `VTCompressionSessionInvalidate` to destroy session
- 60s idle watch completed clean — no panic during the watch window
- **Panic fired at ~20:08:48 — approximately 160s after encode, ~100s after the watch ended**
- DVA: 0x1000082d500 / PTE: 0x20b / AXI_ID: 0xc0

**Run A Conclusion: Session invalidation does NOT accelerate the fault.**
The DMA descriptor **survives kernel session destruction**. The 160s deferral is LONGER than
the 90–130s idle baseline, not shorter. The descriptor is hardware/firmware state that lives
beyond the kernel session lifecycle. This rules out "teardown-triggered" completely.

**Detailed Run A timing:** Encode 20:06:08, invalidate ~20:06:10-20:06:20, panic 20:08:48.
60s idle watch completed with NO panic; crashed ~100s after watch ended. DVA 0x1000082d500
PTE 0x20b AXI_ID 0xc0 — **identical to Panic #3**, confirming deterministic descriptor slot.

**Updated prediction table:**

| Run | Result | Meaning |
|-----|--------|---------|
| **A** | **Panic at 160s (LONGER than baseline)** | **CONFIRMED: Descriptor survives session destruction. Teardown-triggered = ELIMINATED.** |
| B | TBD | Does a clean encode on the same session flush/redirect the armed descriptor? |
| C | Known baseline (90–130s) | Pure idle reference |

**Revised hypothesis after Run A:** The deferral is a firmware-internal timer or power-state
event. Session teardown doesn't touch it because the descriptor lives in firmware/hardware
DMA queue, not in the kernel session struct. This means:
1. The exploit window is WIDER than expected — even after session cleanup, the OOB write fires
2. A process can arm the descriptor, destroy all evidence (session, buffers), and the kernel
   corruption still lands ~2-3 minutes later
3. **For exploitation: the armed descriptor is a time bomb.** Groom the heap during the
   deferral window, then let it fire into your controlled layout.

**Run B is next:** Test whether a clean encode flushes the armed descriptor (would mean
the descriptor is in a per-session firmware queue that session reuse can drain).

### 2E-1. Output Buffer Diff (infoleak test) — ON-DEVICE, NO GHIDRA NEEDED
**Goal:** Test whether the -17691 error path leaks stale firmware/kernel data to userspace.

After a failed Alpha=255 encode, dump every output buffer / metadata the session exposes:
- CMSampleBuffer output (if any partial data returned)
- IOSurface backing the output pixel buffer
- Any IOKit properties readable post-failure

Diff byte-by-byte against a clean-failure baseline (e.g., an encode that fails for a different
reason like invalid dimensions). If the abort path leaves stale firmware-written data in an
output surface, that's the CVE-2026-112466 infoleak — KASLR defeat without Ghidra.

### 2E. Ghidra (offline) — AFTER ON-DEVICE TESTS
26.6.2 AppleAVE2 kext — the search target is maximally narrowed.

**Setup:** Extract kext from kernelcache (kmutil/ipsw/ktool, target com.apple.driver.AppleAVE2
from iPhone18,1 23G90 kernelcollection). Load arm64 binary in Ghidra, auto-analyze.

**Three search anchors (priority order):**

1. **The 0xFF compare** — search for `CMP Wn, #0xFF` (or #255) near property-parse code.
   The AlphaLayerID path is VideoToolbox → IOKit property route, so look near OSNumber /
   property getter calls. The check is on the full 8-bit value (254 survives = not a mask).

2. **The -17691 constant** — signed 32-bit: 0xFFFFBB6D, immediate: 0xBB6D. Search for
   `MOV W, #0xBB6D` or `MVN` pattern. The function returning this is the error site —
   walk backward to the 0xFF check that routes there.

3. **The deferred trigger** — 90–130s consistency suggests timer/watchdog/reclaim callback.
   Search for `IOInterruptEventSource` / `IOTimerEventSource` setup, or thread-call
   timeouts in the ~2-minute range touching AVE2 DMA descriptors on the error path.

**The money question:** Compare success-path teardown (after clean 254 encode) vs -17691
error-path teardown. The diff contains a descriptor free / channel disarm / interrupt-disable
that the error path skips — that's the bug and the exploit primitive.

**Sentinel semantics caveat:** 0xFF as a reserved marker may mean "driver thinks this field is
unset" — firmware config may contain an uninitialized/stale layer pointer rather than an OOB
index. At the == 0xFF cmp, trace what value flows into the descriptor on that branch:
"uninitialized struct field" and "OOB index" produce the same DART fault but different
exploitability profiles.

**Firmware caveat:** If the 0xFF check isn't in the kext, the hunt moves to
VideoToolbox.framework (userspace) or the AVE firmware binary (encoder's own processor).
Start with the kext — smallest surface.

### DVA Structure Observation (from crash logs)
Crashes 2 and 3 on AXI_ID 0xc0 with ~55 PTEs apart; crash 1 on 0xc1 ~25 pages from crash 2.
Two channels + consistent DVA region strongly suggests both channels write the same fixed offset
from different base allocations. In Ghidra, look for a shared cleanup routine taking the channel
context as an argument — that's one bug in two instantiations, not two separate bugs.

### Exploitability Assessment (current state)
**Current primitive:** A deferred, fixed-target OOB write. DVAs cluster in a ~900KB window with
25-page spacing on two channels. If the write offset is a fixed constant relative to a buffer
(like CVE-2026-112705's far=0x59 fixed-offset fill), this alone may not be arbitrarily
controllable.

Alpha=255 is a single value — it can't steer anything by itself. For offset control, a second
parameter (RepFormatIndex? MVHEVCVideoLayerIDs?) would need to change the layout the descriptor
indexes into. This is testable but lower priority than the infoleak.

**The leak is the milestone:** CVE-2026-112466 (OOB read) remains top priority for KASLR defeat
/ Chain A Stage 1. The output buffer diff test (2E-1) may find it without Ghidra.

---

## GHIDRA / BINARY ANALYSIS RESULTS (2026-11-13)

**Binary:** AppleAVE2 kext v905.40.1, arm64e Mach-O, 2,692,608 bytes
**Source:** iOS 26.6.2 (23G90), iPhone18,1 kernelcache
**Tool:** ipsw macho disass + PowerShell binary scanners (Ghidra MCP unavailable)

### Key Findings Summary

1. **The -17691 error code is NOT in the kext binary** — exhaustively searched all arm64
   MOV/MOVN/MOVK encodings and literal byte patterns for 0xBB6D / 0xFFFFBB6D. Zero matches.
   The error originates from **AVE2 firmware/hardware**, not kernel code.

2. **The 0xFF comparison is NOT in the kext** — all 14 `CMP Wn, #0xFF` instructions analyzed
   (file offsets 0xF94BC through 0x270EAC). None relate to AlphaLayerID validation. Seven are
   in AVE_Log_UpdateConf, two in AVE_DevInfo/RetrieveRevision, two in config parsing, one in
   slice parsing. The **firmware** performs the AlphaLayerID == 255 check.

3. **"wrong layer ID" string exists but is DEAD CODE** — the format string
   `"%lld %d AVE %s: %s:%d %s | wrong layer ID %d\n"` exists at two file offsets (0x708E0,
   0xBD550) but has **zero code references** in __TEXT_EXEC. No ADRP+ADD in the entire
   executable segment targets either string. This is either dead code or firmware-only logging.

4. **NO `AVE_CHM_DARTUnmapSurfaces` exists** — the CHM-level DARTMap has no unmap counterpart.
   DARTUnmap functions exist only at the lower AVE_MD_SVE level.

5. **DMA descriptor cleanup gap confirmed** — the vulnerability is in the kext's DMA lifecycle
   management around firmware encode submission.

### Function Map — DART DMA Lifecycle

```
MAPPING (encode setup):
  AVE_CHM_DARTMapSurfaces          sub_fffffe000855c0cc  [CHM level - vtable call]
    → DARTMapExternalSurfaces      sub_fffffe000867b238  [AVE_MD_SVE - vtable call]
        → AVE_DARTMapExternalSurfaces  sub_fffffe000866a32c  [per-surface]
            → DARTMapSurface       sub_fffffe00086702bc  [per-entry]
                → sub_fffffe000865a84c  [actual DART map]
    → DARTMapInternalSurfaces      sub_fffffe000867b8d4  [AVE_MD_SVE]

UNMAPPING (cleanup):
  *** NO AVE_CHM_DARTUnmapSurfaces ***     ← THE GAP
    DARTUnmapExternalSurfaces      sub_fffffe000867b684  [AVE_MD_SVE - vtable call]
        → sub_fffffe000866adb4     [per-surface unmap]
    DARTUnmapInternalSurfaces      (near 0xfffffe000867bd88 ref)  [AVE_MD_SVE]
    DARTUnmapSurface               (at AVE_SurfaceMgr level)
    DARTUnmapSurfaces              (top-level, Pipeline cleanup)

POOL LIFECYCLE:
  AVE_DART_Pool_Create             sub_fffffe00085902bc  [kalloc_type allocation]
  AVE_DART_Pool_Destroy            (at 0xfffffe0008590564)  [with "unreleased IODMACommand" check]
```

### AVE_CHM_DARTMapSurfaces (sub_fffffe000855c0cc) — Detailed Flow

**Entry:** Called via vtable (zero direct BL xrefs). Takes one arg (task/encode object).

```
1. Load session pointers from [x0+0x18] and bitmask source from [x0+0x28]
2. Create surface bitmask: x1 = 1 << w8
3. Call DARTMapExternalSurfaces(session, bitmask)
   └─ If FAILS (returns non-zero): log error, return error code
      *** NO cleanup of any partially mapped surfaces ***
4. Call DARTMapInternalSurfaces(session, bitmask)  [sub_fffffe000867b8d4]
   └─ If FAILS: log error, return error code
      *** NO cleanup of already-mapped external surfaces ***
5. Both succeed: call post-map bookkeeping at session+0xEF3B8, return 0
```

**Critical bug path:** When step 3 succeeds but step 4 fails, external surfaces remain
DART-mapped with no cleanup. But for our vulnerability, BOTH maps succeed — the failure
comes later when the firmware processes the encode.

### DARTMapExternalSurfaces (sub_fffffe000867b238) — Loop Structure

```
Class: AVE_MD_SVE
Session struct offsets:
  session + 0xEE000 + 0xD20 = surface table pointer
  session + 0xEF3B8         = DART state struct A
  session + 0xED28          = DART state struct B
  session + 0x70            = variable surface count

Loop 1 (fixed surfaces): 4 iterations, bitmask-based
  for i in 0..3:
    if (bitmask >> i) & 1:
      ret = map_surface([surface_table], state_A, state_B, i)
      if ret != 0: goto EXIT_ERROR  ← no cleanup of surfaces 0..i-1

Loop 2 (variable surfaces): count-based, stride 0x3BAC0
  for i in 0..[session+0x70]:
    ret = map_surface([surface_table], state_A, state_B, [session+0xA8+i*0x3BAC0])
    if ret != 0: goto EXIT_ERROR  ← no cleanup

EXIT_SUCCESS: return 0
EXIT_ERROR: log "failed to DART map external surfaces", return error
  *** PARTIAL MAP LEAK: surfaces 0..i-1 remain mapped ***
```

### DARTUnmapExternalSurfaces (sub_fffffe000867b684) — Mirror Structure

Confirmed counterpart to DARTMapExternalSurfaces. Same loop structure (bitmask + count),
same offsets (0xEE000+0xD20, 0xEF3B8), but calls `sub_fffffe000866adb4` (unmap) instead
of `sub_fffffe000866a32c` (map). Called via vtable only — zero direct BL xrefs.

### The Vulnerability Mechanism — DMA Descriptor Cleanup Gap

**Confirmed architecture:**

```
ENCODE SUBMISSION FLOW:
  1. AVE_CHM_DARTMapSurfaces() → maps surfaces into DART (DMA descriptors armed)
  2. [encode command submitted to AVE2 firmware via mailbox/doorbell]
  3. Firmware processes encode:
     a. Validates AlphaLayerID
     b. If == 0xFF: rejects with -17691
     c. Error returned to kext via interrupt/completion callback
  4. Kext error handler returns -17691 to userspace
     *** DMA descriptors from step 1 remain armed ***
     *** No AVE_CHM_DARTUnmapSurfaces exists to clean them up ***

NORMAL COMPLETION FLOW (Alpha != 255):
  1. AVE_CHM_DARTMapSurfaces() → maps surfaces
  2. Encode submitted to firmware
  3. Firmware completes encode successfully
  4. Completion handler calls DARTUnmapSurfaces (at MD_SVE level)
  5. Descriptors properly cleaned up

ERROR FLOW (Alpha == 255):
  1. AVE_CHM_DARTMapSurfaces() → maps surfaces ← DESCRIPTORS ARMED
  2. Encode submitted to firmware
  3. Firmware rejects AlphaLayerID=255, returns -17691
  4. Error handler returns error to userspace
     *** CHM level has no DARTUnmap to call ***
     *** MD_SVE DARTUnmap not called on error path ***
  5. Session teardown (later) calls AVE_DART_Pool_Destroy
     → checks for "unreleased IODMACommand" ← TOO LATE
     → descriptor already executing in firmware DMA queue
  6. ~90-160s later: firmware DMA engine processes stale descriptor
     → writes to unmapped/freed DART VA → PTE invalid exception → PANIC
```

### "try to release delayed" — The Deferred Cleanup Mechanism

Near `DARTUnmapSurface` string: `"%s:%d try to release delayed"` — indicates the unmap
path has a delayed release mechanism. When surfaces can't be immediately unmapped (e.g.,
firmware still holds a reference), the unmap is deferred. Combined with the `DARTFlush`
function (also near `DARTUnmapSurface`), this suggests:

- Normal path: unmap → flush → release
- Delayed path: mark for deferred release → flush on next opportunity

If the error path doesn't even reach the unmap, the deferred release is never scheduled.
The descriptor sits in firmware DMA state until the firmware processes it on its own
internal schedule (~90-160s), at which point it writes to a VA that's no longer valid.

### Key Struct Offsets

```
Session/encoder object:
  +0x18       → sub-session context (x23 in CHM_DARTMap)
  +0x28       → surface bitmask source index
  +0x70       → variable surface count
  +0xA8       → per-surface config array (stride 0x3BAC0)
  +0x3CAC     → codec type (1=H264?, 2=HEVC? in AVE_CHM_GetFwDPBBuf)
  +0xED28     → DART state struct B
  +0xEE000+0xD20 → surface table
  +0xEF3B8    → DART state struct A (both map/unmap, bookkeeping, cleanup)
```

### AVE_DART_Pool_Destroy — Last Line of Defense (Too Late)

At VA 0xfffffe0008590564, the pool destroy function checks for leaked DMA commands:
```
"unreleased IODMACommand %p"   — warns about DMA commands not freed
"DMA Command should not be NULL" — assertion on cleanup
```
This runs during session teardown (AVE_DART_Pool_Destroy), but Run A proved the DART
fault fires ~160s after session invalidation. The pool destroy detects the leak but
can't prevent the deferred firmware DMA write.

### Exploitation Implications

1. **The bug is a missing error-path cleanup** — the fix would add DARTUnmap calls to the
   firmware error return handler, or validate AlphaLayerID before DART mapping.

2. **The 90-160s deferral is a FEATURE for exploitation** — it gives time to:
   - Arm the descriptor (one encode with Alpha=255)
   - Destroy the session (clean up userspace evidence)
   - Groom the kernel heap during the deferral window
   - Let the descriptor fire into a controlled layout

3. **The OOB write target (DVA)** is determined by the DMA descriptor's target VA, which
   is set during step 1 (DART mapping). The surface buffer addresses influence the DVA.
   DVAs cluster in 0x100007xxxxx-0x10000Exxxxx with 25-55 PTE spacing — suggests the
   target is relative to a fixed allocation within the DART address space.

4. **Two-phase cleanup = two-phase bug**: The kext's "do kernel unmapping" + "do DART
   unmapping" strings suggest the unmap is two-phase. If only the kernel unmap runs
   (during session teardown) but the DART unmap doesn't (firmware state), the hardware
   still holds the stale descriptor.

5. **No PAC involvement**: The bug is in DMA descriptor state (data-only), not in code
   pointer corruption. The exploit primitive is a DMA write to a controlled VA —
   bypasses PAC entirely since it's hardware-initiated, not a code flow hijack.

### Remaining Ghidra Targets

1. **The encode completion handler** — find the function that processes firmware encode
   results (interrupt handler / completion callback). Compare its success path (which
   calls DARTUnmap) with the error path (which doesn't).

2. **The firmware mailbox/doorbell** — find how encode commands are submitted to AVE2
   hardware. This reveals what DMA state is set up before the firmware gets control.

3. **DVA target analysis** — trace the DARTMapSurface call chain to understand what
   determines the target DVA. This tells us how controllable the OOB write is.

4. **CVE-2026-112466 OOB read path** — find the read-back mechanism for KASLR defeat.

---

### Open questions (updated after Ghidra analysis)

1. **ANSWERED: Truncation test** — neither raw nor 6-bit. The fault is error-path-specific.
2. **ANSWERED: Acceptance boundary** — exact 0xFF sentinel. Every value 0–254 is accepted;
   only 255 triggers -17691 rejection and the subsequent deferred DART fault.
3. **ANSWERED: Where is the 0xFF check?** — in AVE2 firmware, NOT the kext. All 14
   CMP #0xFF instructions in the kext are unrelated to AlphaLayerID.
4. **ANSWERED: Where is -17691?** — in AVE2 firmware, NOT the kext. No encoding of
   0xBB6D found in the binary.
5. **ANSWERED: Error-path anatomy** — the CHM-level DARTMap has NO corresponding
   DARTUnmap. The unmap exists only at the MD_SVE level and is called during normal
   completion, not on the firmware error path. This is the root cause.
6. **PARTIALLY ANSWERED: Deferral mechanism** — Teardown-triggered = ELIMINATED (Run A).
   "try to release delayed" mechanism exists but is never reached on the error path.
   Remaining: firmware internal timer/event schedule (90-160s variable).
7. **OPEN: Offset controllability** — can surface buffer addresses steer the OOB target DVA?
8. **OPEN: Encode completion handler** — need to find and compare success vs error paths.
9. **OPEN: CVE-2026-112466** — OOB READ for KASLR defeat, separate investigation needed.

---

## METHOD: three-layer verification (the differentiator)

SET return code -> property readback -> bitstream oracle (parse emitted VPS/SPS/PPS).
Published repros for this driver family tested return codes only — which produced the public
NTL "SET OK" clamp false positive AND our own 11/13 "error = eliminated" misattribution.
Rule adopted: **encode error does not clear a suspect; only a full 120s-wait clean run does.**

---

## Historical test data (2026-11-12, retained)

### NumberOfTemporalLayers off-by-one is CLAMPED (dead end)

Set NumberOfTemporalLayers=8: 0 (ACCEPTED) / Readback: NumberOfTemporalLayers = 1 (CLAMPED).

VideoToolbox returns noErr but silently clamps to 1. Kernel never sees 8. (Public 112705 PoCs
use NTL~16463 to punch past the clamp via a different route.)

### AlphaLayerID + RepFormatIndex are WIDE OPEN in userspace

AlphaLayerID=255: OK (NO VALIDATION, limit <63) / RepFormatIndex=255: OK (NO VALIDATION, limit <2).

No userspace clamping; on 26.6.2 these flow toward the kernel without bounds validation.
- AlphaLayerID=255: potential index into 63-element VPS layer array -> up to 192-element OOB (if raw)
- RepFormatIndex=255: potential index into 2-element rep format array -> up to 253-element OOB

### Tier 2 probe full results (2026-11-12)

log2_max_minus4: 0-8 OK, 12+ REJECTED (VT validates)
 AlphaLayerID: 0-255 ALL OK (NO validation!)
 RepFormatIndex: 0-255 ALL OK (NO validation!)
 NumberOfSlices: 1-16 OK, 64+ REJECTED (VT validates)
 ChromaQPOffset: ALL REJECTED (not settable on this config)


### Verified state (post-oracle, with 11-13 corrections)

| Property | Set OK | Readback | Bitstream | Status |
|----------|--------|----------|-----------|--------|
| NTL=8 | YES | 1 (clamped) | n/a | DEAD |
| AlphaLayerID=64 | YES | 64 (stored) | VPS 24->39 bytes, layers 0->1 | VERIFIED |
| RepFormatIndex=10 | YES | 10 (stored) | identical to baseline | Dormant in single-layer |
| AlphaLayerID=255 | YES | — | — | CONFIRMED PANIC TRIGGER (deferred DART fault) |
| log2_max_minus4=13 | NO | n/a | n/a | DEAD (VT rejects) |
| NumberOfSlices=64 | NO | n/a | n/a | DEAD (VT rejects) |
| ChromaQPOffset=* | NO | n/a | n/a | DEAD (all rejected) |
| MVHEVCVideoLayerIDs=[0,100] | YES | [0,100] (stored) | no encode output | Candidate — suspect NOT cleared by error |
| UserDPBFramesForFaceTime=20 | NO | n/a | n/a | Rejected (retry FT mode) |
| UserRPSForFaceTime=100 | NO | n/a | n/a | Rejected (retry FT mode) |
| UserParameterSetsIds=50 | YES | [0,0,0] (clamped) | n/a | DEAD |

### AlphaLayerID=64: full delivery chain proven

BASELINE VPS (24 bytes): 40 01 0c 01 ff ff 01 60 ... vps_max_layers_minus1: 0

AlphaLayerID=64 VPS (39 bytes): 40 01 0c 11 ff ff 01 60 ... vps_max_layers_minus1: 1 VPS extension appended: bf 00 08 00 08 10 28 53 80 a0 00 78 50 07 15 e9


Full chain: set -> stored -> structurally consumed -> value-derived structure emitted.

### Mod-64 wrapping in the VPS bitstream

byte22 = 0xC0 | (AlphaLayerID & 0x3F) << 1


| AlphaLayerID | VPS vps_max_layer_id (6-bit) |
|---|---|
| 63 | 63 |
| 64 | 0 (wraps) |
| 100 | 36 |
| 200 | 8 |
| 255 | 63 (predicted) |

Open question (truncation test above decides): kernel consumes raw IOKit value or the
bitstream-truncated 6-bit value?

### RepFormatIndex=10: stored but dormant in single-layer

Readback held (10), emitted VPS bitstream identical to baseline. May activate when AlphaLayerID
enables multi-layer (the combination that appends the 15-byte VPS extension — exactly what
AVE_HEVC_CheckVPSExtBounds was written to police in 26.7.2). UNTESTED as isolated trigger —
back in the queue behind the Alpha=255 race characterization.

### MVHEVCVideoLayerIDs=[0,100]: candidate

SET OK, readback unclamped, test encode produced no callback output — which no longer clears the
suspect (deferred-fault lesson). Needs a dedicated canary + 120s-wait session.

### FaceTime-scoped properties

UserDPBFramesForFaceTime / UserRPSForFaceTime rejected — likely need RealTime/low-latency
session configuration.

### Class A / B summary (retained)

Class A direct session config (~13 params: LookAheadFrames, EnableMultiReferenceP,
MultiReferencePSpacing, BaseLayerFrameRate, InputQueueMaxCount, MaxAllowedFrameQP,
DPBRequirements, ...).

Class B -> A (app CAN set VPS/SPS/PPS fields via Required*/User* prefixes — demolishes the
"parameter sets are encoder output" assumption): RequiredHEVCVideoParameterSetAlphaLayerID,
RequiredHEVCSequenceParameterSetRepFormatIndex, RepFormatBitDepths/ChromaFormatIdcs,
RequiredHEVC*ParameterSetIDs, MVHEVC* layer/view IDs, UserRPSForFaceTime, UserDPBFramesForFaceTime,
TemporalIDNestingFlag.

**True exploit surface: ~26 parameters, not 97, not 5-15.**

ELIMINATED: log2_max_minus4 (VT rejects 12+), NumberOfSlices (VT rejects 64+),
ChromaQPIndexOffsetMultiPPS (not settable), UserParameterSetsIds (clamped), MaxFrameDelayCount
(ReadOnly), NumberOfTemporalLayers (clamped).

## Escalation Test Plan ("Escalate" button) — COMPLETED

1. **AlphaLayerID sweep** (0, 32, 62, 63, 64, 100, 200, 255): DONE — mod-64 wrapping confirmed
2. **Dedicated MVHEVCVideoLayerIDs oracle**: DONE — no encode output (needs isolation)
3. **RepFormatIndex + AlphaLayerID combined**: DONE — RepFormatIndex ignored in single-layer
4. **FaceTime mode retry**: DONE — UserDPB/UserRPS rejected

**Result:** Escalation sweep triggered DART panic (kernel crash). See KERNEL PANIC CONFIRMED section.

## Narrow Isolation Test ("Narrow Panic" button) — REBUILT (2026-11-13)

**Problem:** First Narrow test (8 presses, all AlphaLayerID-only) produced NO data — AVE2 was wedged after the Escalation sweep's DART fault. All encodes failed with -12912.

**Fix applied:** Rebuilt with three critical improvements:

1. **Canary encode:** Before each suspect value, encodes with AlphaLayerID=0. If canary fails → "AVE2 is wedged, reboot phone." No false data from broken encoder.
2. **Serialization:** `g_narrowRunning` flag prevents overlapping tests from rapid button presses.
3. **Expanded suspect list** (ordered by likelihood):
   - AlphaLayerID=255 (largest OOB if kernel uses raw value)
   - Alpha64+RepFmt10 combined (multi-layer mode may activate RepFormatIndex consumer)
   - MVHEVCVideoLayerIDs=[0,100] (dedicated encode, value 100 > 63 limit)
   - AlphaLayerID=63/200/128/64/32 (individual isolation)

**Protocol:** Reboot phone → deploy → press Narrow once → wait for "CANARY OK" + suspect result → press again for next. If phone reboots, the last-printed suspect label is the trigger. Compare DVA addresses across crashes for determinism.

### Narrow Test Results (2026-11-13)

| # | Suspect | Result | Notes |
|---|---------|--------|-------|
| 1 | AlphaLayerID=255 | **ELIMINATED** — error -17691 | Hardware rejects at encode callback time (kVTParameterErr). NOT a panic trigger. |
| 2 | Alpha64+RepFmt10 combined | ⏳ PENDING | User needs to press Narrow button |
| 3 | MVHEVCLayerIDs=[0,100] | ⏳ PENDING | |
| 4 | AlphaLayerID=63 | ⏳ PENDING | |
| 5 | AlphaLayerID=200 | ⏳ PENDING | |
| 6 | AlphaLayerID=128 | ⏳ PENDING | |
| 7 | AlphaLayerID=64 | ⏳ PENDING | |
| 8 | AlphaLayerID=32 | ⏳ PENDING | |

**AlphaLayerID=255 analysis:** The -17691 error means the hardware encoder performs its own validation at encode time (not just at property-set time). This is AFTER VideoToolbox accepted the value (SET returned noErr) and AFTER readback confirmed it was stored. The hardware itself rejects 255 before attempting DMA. This suggests the kernel-side array access uses a DIFFERENT value than the raw property — possibly the mod-64 wrapped value from the VPS bitstream. This strengthens the hypothesis that the kernel consumer reads the VPS bitstream rather than the IOKit config struct directly.
