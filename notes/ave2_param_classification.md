# AVE2 Parameter Classification — Device Test Results (rev. 2026-11-14)

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

**Fire-context variance explained (model v3.1, corrected 2026-11-14):** DVA differences across
panics 1-6 are now explained by the three confirmed DART unmap paths (Ghidra-traced):
- **Timer/channel-service path (idle panics):** Process timer → AVE_Heartbeat_ServicePipeline →
  AVE_ServiceEncodeChannels → AVE_EncodeChannel_Service → ... → AVE_ChannelService_DARTUnmap →
  FUN_0x866e870 → DARTUnmapSurface_TwoPhase. Direct per-surface unmap during channel servicing.
  Different channel service states at fire time → different DVAs.
- **Encode-submission path (Run B target):** Userspace encode → AVE_EncodeSubmit_TriggerCleanup
  (gated on +0xf8==1) → AVE_EncodeCycle_Cleanup → ReleaseAllDelayed → DARTUnmapSurface_TwoPhase.
  Synchronous, walks delayed-release queue — deterministic.
- **Session-teardown-at-zero path:** AVE_ClientClose → count==0 → AVE_SessionDestroy →
  AVE_SurfaceMgr_Cleanup → ReleaseDelayed → DARTUnmapSurface_TwoPhase.
The 2A idle panics are the timer/channel-service path. Run A's 160s deferral is
VTCompressionSessionInvalidate changing the session state (possibly clearing +0xf8 or altering
channel service conditions), shifting when the channel service reaches the stale surface.

**Deferral timing is variable** (90s, 130s, 160s post-encode) — confirms async trigger, not fixed timer.
**Run A result: Session invalidation does NOT accelerate the fault.** The descriptor survives both
session destruction AND the 60s post-invalidation idle window. The deferral is firmware/hardware
state that lives beyond kernel session lifecycle.

**Panic string template (both identical except DVA/PTE):**
`dart-ave: DART(DART) error: SID 0 PTE invalid exception on write of DVA <addr> (CTE 0x10 SEG 0 PTE <pte>) ERROR_SID_SUMMARY 0x00003100 AXI_ID 0xc0`

**Key methodological finding:** userspace encode error != safety. DART faults may fire seconds after the
callback returns. Encode failures (-17691) do not mean no DMA occurred. Any "elimination" based on
callback error alone is invalid without the 120-second wait window.

**ROOT CAUSE (Ghidra-confirmed, corrected model 2026-11-14):** Surfaces normally stay mapped for
the session's life (map once at encode setup, unmap only at reconfigure/teardown) — normal IOKit
practice, not a bug. On Alpha=255, the firmware aborts mid-encode but leaves an output DMA
descriptor pending in its hardware queue (this is the actual bug — abort doesn't cancel/synchronize
in-flight DMA state). The kext's slot cleanup (AVE_IPC_FreeCommandSlot at 0x8631064) only frees
kernel bookkeeping — it never tells the firmware to drain its DMA queue. Later (~90-160s), the
surface manager's delayed release path (AVE_SurfaceMgr_ReleaseDelayed at 0x866e284) unmaps the
DART PTE via DARTUnmapSurface_TwoPhase. The stale firmware DMA descriptor then fires into an
unmapped DVA → DART fault/panic. Root cause: abort path fails to quiesce firmware DMA before the
mapping lifecycle reclaims the PTE. The 26.7.x fix is almost certainly a firmware drain/flush
before release on error.

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

**Run A Conclusion (REINTERPRETED 2026-11-14 after Ghidra analysis):**
Session invalidation changes the timing but does not prevent the fault. The 160s deferral
(longer than 90–130s idle baseline) is explained by the corrected model: VTCompressionSession-
Invalidate triggers a different teardown path than the natural idle lifecycle, potentially
changing when AVE_SurfaceMgr_ReleaseDelayed runs. In all cases, the race is between:
- The stale firmware DMA descriptor firing (firmware-internal timing)
- AVE_SurfaceMgr_ReleaseDelayed unmapping the DART PTE (session lifecycle timing)
The panic fires when the PTE is unmapped BEFORE the descriptor completes. The "unreleased
IODMACommand" check in AVE_DART_Pool_Destroy confirms descriptors can outlive their sessions.

**Detailed Run A timing:** Encode 20:06:08, invalidate ~20:06:10-20:06:20, panic 20:08:48.
DVA 0x1000082d500 PTE 0x20b AXI_ID 0xc0 — **identical to Panic #3**.

**Updated prediction table:**

| Run | Result | Meaning |
|-----|--------|---------|
| **A** | **Panic at 160s** | **CONFIRMED: Stale DMA descriptor fires after delayed surface release unmaps PTE** |
| B | TBD | Does a clean encode on the same session flush/redirect the armed descriptor? |
| C | Known baseline (90–130s) | Pure idle reference |

**Corrected mechanism (from Ghidra):** The deferral is the session lifecycle delay — how long
until the surface manager runs its delayed release. AVE_SurfaceMgr_ReleaseDelayed calls
DARTUnmapSurface_TwoPhase, clearing the PTE. The firmware's stale descriptor then writes
through the now-invalid DVA → DART fault. This means:
1. The exploit window is the gap between PTE unmap and descriptor fire
2. Re-claiming the DVA slot with attacker-controlled memory BEFORE the PTE is unmapped
   converts the panic into a controlled write primitive
3. The "time bomb" model still holds — the descriptor fires regardless of session state

**Run B is next** — tests a specific prediction from Ghidra: since AVE_SurfaceMgr_ReleaseAllDelayed
runs at the start of the next encode cycle, a clean encode on the live session should trigger the
delayed-release walk deterministically and early. If Run B panics fast (~seconds after the clean
encode rather than ~minutes after the failed one), the timing is now attacker-controlled — a major
exploitability upgrade.

**Run B v2 protocol (one reboot, frame-by-frame logging, specific prediction from Ghidra 2026-11-14):**

1. Fresh reboot → app → canary OK.
2. Arm: Alpha=255 → encode → -17691 observed, note wall-clock.
3. Same session, no invalidation, set Alpha=0 → encode clean frames **one at a time**,
   logging each frame number + timestamp as you go. Give each ~10s before the next.
   Continue for up to 10 frames / 5 minutes total.
4. Watch and timestamp continuously for panic.

Record per frame: frame#, wall-clock submitted, wall-clock callback, result code.
Record overall: arm→first-clean delta, last-clean→panic delta if it fires, DVA + PTE + AXI_ID
from the .ips.

**Interpretation (v2, frame-count disambiguates +0xf8 gate):**
- Panic ≤ ~10s after clean frame #1 → **v4 model confirmed**: +0xf8 was already 1 from the
  arming encode, first submission's TriggerCleanup walks the delayed release immediately.
  Fire timing is attacker-controlled. This is the exploitability milestone.
- Panic after frame #2 (not #1) → gate was cleared by error, re-armed by success — the
  0→1 transition in AVE_SetEncodeActiveState triggers the immediate cleanup. Still attacker-
  controlled but requires one "priming" frame.
- Panic at normal 90–160s regardless of frame count → the walk happens at a different pipeline
  point than we think; the clean encode still helps narrow it.
- No panic in 5 min / 10 frames → the delayed-release queue didn't hold your surface (queue
  entry condition `(flags & 0xf0000) == 0` is the gate). That itself is a finding: then ask
  what puts the surface on the delayed queue, in Ghidra.

**Run B prediction (CORRECTED Ghidra model 2026-11-14):** The clean encode's submission
directly calls AVE_EncodeSubmit_TriggerCleanup (0x85ccd48) which, if *(session+0xf8)==1,
calls AVE_EncodeCycle_Cleanup → AVE_SurfaceMgr_ReleaseAllDelayed. This walks the delayed-
release queue, calling DARTUnmapSurface_TwoPhase on queued surfaces. This is a SYNCHRONOUS
path — no timer dependency. If the Alpha=255 abort queued a surface for delayed release,
the clean encode's submission should trigger the PTE invalidation immediately, converting
the "random 90-160s" deferral into precise attacker-controlled fire timing.

**If Run B confirms, go straight to 3.0 (re-claim) on the next boot:** arm → clean-encode
to control fire timing → spray ~dozens of 320x240 IOSurfaces/sessions with checksummed
contents → clean-encode to trigger the walk → watch which surface's bytes change and which
bytes. Any diff = the write primitive observed firsthand, value/offset/data all captured.
Don't need the output-surface index first — match all four shapes and the diff tells you
empirically which one got written.

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

### Exploitability Assessment (UPDATED 2026-11-14 — corrected model)

**Primitive type:** Deferred DMA write through stale DART mapping. Not "fixed-target OOB" but
rather "write through freed-then-faulted PTE." Crash DVAs (0x100007xxxx–0x10000Exxxx) are all
below the type-3 DART aperture limit (0x70800000) — the deferred write is in-aperture-but-unmapped,
not out-of-range. Consistent with a freed-then-faulted PTE.

**Corrected exploit model — DART re-claim:**

DVA is IOMapper-allocated (not userspace-steerable), but the physical backing and DART mapping
lifecycle ARE controllable. The exploit isn't "aim the write" — it's repopulate the DVA before
the stale descriptor fires.

**Write primitive variant:** During the 90–160s window between arming and fire, force new DART
allocations to re-claim the freed DVA slot (DVAs are sequentially allocated from the DART
aperture). Map memory you control at the old DVA. Stale descriptor fires → write lands in your
surface → you read it back, observe the exact written value/offset, no panic.

**Read primitive variant (possible 112466 shape):** Same setup, but if any part of the aborted
encode's firmware output lands in the reclaim surface, you've captured firmware-written data in
userspace — that's the infoleak.

Both variants start from the same experiment (3.0 DART re-claim race).

**PAC bypass:** Inherent — DMA writes go through DART hardware, not CPU pointer authentication.
The write target is physical memory, not a CPU-visible virtual address.

**The leak is the milestone:** CVE-2026-112466 (OOB read) remains top priority for KASLR defeat
/ Chain A Stage 1. The output buffer diff test (2E-1) may find it without Ghidra.

---

## GHIDRA / BINARY ANALYSIS RESULTS (2026-11-13)

**Binary:** AppleAVE2 kext v905.40.1, arm64e Mach-O, 2,692,608 bytes
**Source:** iOS 26.6.2 (23G90), iPhone18,1 kernelcache
**Tool:** ipsw macho disass + PowerShell binary scanners + **Ghidra 12.1.4 MCP decompiler (verified 2026-11-14)**

### Key Findings Summary

1. **The -17691 error code is NOT in the kext binary** — exhaustively searched all arm64
   MOV/MOVN/MOVK encodings and literal byte patterns for 0xBB6D / 0xFFFFBB6D. Zero matches.
   The error originates from **AVE2 firmware/hardware**, not kernel code.

2. **The 0xFF comparison is NOT in the kext** — all 14 `CMP Wn, #0xFF` instructions analyzed
   (file offsets 0xF94BC through 0x270EAC). None relate to AlphaLayerID validation. Seven are
   in AVE_Log_UpdateConf, two in AVE_DevInfo/RetrieveRevision, two in config parsing, one in
   slice parsing. The **firmware** performs the AlphaLayerID == 255 check.

3. **"wrong layer ID" string is NOT dead code (CORRECTED via Ghidra 2026-11-14)** — Ghidra
   found PARAM xrefs from `AVE_ValidateLayerParams` (0xfffffe0008636d70). However, this is
   a **kext-level layer count validator** that checks `param_3 >= 2` and returns 0xFFFFFC17
   (-1001). This is NOT the firmware's -17691/AlphaLayerID=255 check — it's a separate
   validation that the layer count doesn't exceed supported limits.

4. **NO `AVE_CHM_DARTUnmapSurfaces` exists** — the CHM-level DARTMap has no unmap counterpart.
   DARTUnmap functions exist only at the lower AVE_MD_SVE level.

5. **DMA descriptor cleanup gap confirmed** — abort path fails to quiesce firmware DMA before
   the mapping lifecycle reclaims the DART PTE. Slot cleanup (AVE_IPC_FreeCommandSlot) is pure
   kernel bookkeeping; `AVE_SurfaceMgr_ReleaseDelayed` later unmaps the PTE while the firmware's
   stale DMA descriptor is still live.

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
6. **ANSWERED (CORRECTED 2026-11-14): Deferral mechanism** — Two paths reach DARTUnmapSurface_TwoPhase:
   (a) **Timer/idle path:** Process timers fire periodically, calling AVE_Heartbeat_ServicePipeline
   (0x85ce4f0) which is a heartbeat/service function (NOT a cleanup trigger). Its encode channel
   service sub-call (AVE_EncodeChannel_Service at 0x860f318) reaches DARTUnmapSurface_TwoPhase
   through FUN_0x866e870 (direct per-surface unmap during channel servicing). 90-160s variability
   is timer interval + channel service conditions.
   (b) **Encode submission path (Run B target):** Userspace encode submission directly calls
   AVE_EncodeSubmit_TriggerCleanup (0x85ccd48) which, gated on *(session+0xf8)==1, calls
   AVE_EncodeCycle_Cleanup → ReleaseAllDelayed → DARTUnmapSurface_TwoPhase. Synchronous path.
   (c) **Session teardown:** AVE_ClientClose → count==0 → AVE_SessionDestroy → SurfaceMgr_Cleanup
   → ReleaseDelayed → DARTUnmapSurface_TwoPhase.
   NOT firmware-internal timing.
6a. **ANSWERED (2026-11-14): +0xf8 gate — who writes it?** The field `*(session+0xf8)` is the
   **encode-active state flag**, controlled by `AVE_SetEncodeActiveState` (0x85ca838). Writers:
   - `AVE_UC_EncodeStartStop` (0x86b41f0) — IOUserClient method. param_2=1 → sets +0xf8=1
     (start encoding, also starts timers). param_2=0 → sets +0xf8=0 (stop, also stops timers).
   - `AVE_UC_PowerEvent` (0x86b45d4) — power management handler. On sleep/power events
     (codes 0xE0000310, 0xE0000250), dispatches +0xf8=0 (force stop).
   - **No other writers exist** — firmware errors do NOT clear +0xf8.
   **Critical implication for Run B:** After a failed Alpha=255 encode, +0xf8 stays 1 because
   only explicit userspace stop or power events clear it. The gate is open for the clean encode's
   submission to reach AVE_EncodeCycle_Cleanup → ReleaseAllDelayed. **Run B is confirmed viable.**
   The Run B frame-count test disambiguates whether +0xf8 *transitions* matter (set by 0→1 at
   encode start triggers an immediate cleanup on transition).
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

---

## GHIDRA DECOMPILER VERIFICATION (2026-11-14)

**Tool:** Ghidra 12.1.4 with GhidraMCP extension (LaurieWired), decompiler output
**All findings below verified via C pseudocode decompilation, not just disassembly.**

### Verification Status

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| 1 | -17691 not in kext | **VERIFIED** | String search "17691" = 0 results |
| 2 | 0xFF not for alpha | **VERIFIED** | (prior disasm analysis holds) |
| 3 | "wrong layer ID" not dead | **CORRECTED** | Xref from AVE_ValidateLayerParams; checks layer count >= 2, returns -1001 |
| 4 | No CHM-level DARTUnmap | **VERIFIED** | Decompilation confirms asymmetric call hierarchy |
| 5 | DMA cleanup gap | **VERIFIED** | DARTUnmap only on success path (AVE_PipelineReconfigure) |
| 6 | Partial-map leak | **VERIFIED** | Decompilation shows early return without cleanup |

### Finding 1: AVE_CHM_DARTMapSurfaces — No CHM-Level Unmap Counterpart

**Decompiled** `AVE_CHM_DARTMapSurfaces` (0xfffffe000855c0cc):
```c
undefined8 AVE_CHM_DARTMapSurfaces(long param_1) {
    lVar1 = *(long *)(param_1 + 0x20);
    // Create bitmask from param_1+0x28
    uVar3 = DARTMapExternalSurfaces(lVar1, 1L << (*(uint*)(param_1+0x28) & 0x3f));
    if ((int)uVar3 == 0) {
        uVar3 = DARTMapInternalSurfaces(lVar1, ...);
        if ((int)uVar3 == 0) {
            // SUCCESS: bookkeeping on lVar1 + 0xef3b8
            return 0;
        }
        // ERROR: "failed to DART map internal surfaces" — NO CLEANUP OF EXTERNAL
    } else {
        // ERROR: "failed to DART map external surfaces" — NO CLEANUP
    }
    return uVar3;
}
```

**Xrefs TO AVE_CHM_DARTMapSurfaces:** 1 DATA + 1 CALL from FUN_fffffe00085fa6cc
**No corresponding AVE_CHM_DARTUnmapSurfaces exists anywhere in the binary.**

### Finding 2: DARTUnmap Is Only Called on Success/Reconfigure Path

**Full call chains (Ghidra xref-traced):**

```
MAP chain (encode setup):
  FUN_fffffe00085fc3b4
    → FUN_fffffe00085fa6cc
      → AVE_CHM_DARTMapSurfaces (0x855c0cc)
        → DARTMapExternalSurfaces (0x867b238) → AVE_DARTMapExternalSurfaces → DARTMapSurface
        → DARTMapInternalSurfaces (0x867b8d4)

UNMAP chain (cleanup — DIFFERENT hierarchy):
  FUN_fffffe00085c5764
    → AVE_PipelineReconfigure (0x85c3d54)
      → DARTUnmapSurfaces_Wrapper (0x868b400)
        → FUN_fffffe000868b2e8
          → DARTUnmapExternalSurfaces (0x867b684) → AVE_DARTUnmapExternalSurfaces → DARTUnmapSurface
```

**Critical:** AVE_PipelineReconfigure calls DARTUnmap ONLY after three preconditions succeed:
```c
// AVE_PipelineReconfigure (0xfffffe00085c3d54) simplified:
ret = unregister_client(param_1, param_2);
if (ret == 0) {
    ret = update_EUMap(param_2, param_3);
    if (ret == 0) {
        ret = register_client(param_1, param_2);
        if (ret == 0) {
            // ONLY HERE: DARTUnmap is called
            DARTUnmapSurfaces_Wrapper(sessions, bitmask);
            reset_pipeline(...);
            submit(...);
            return 0;
        }
        // "fail to register client" — NO UNMAP
    }
    // "fail to update EUMap" — NO UNMAP
}
// "fail to unregister client" — NO UNMAP
```

This is the **normal pipeline reconfiguration** path, not the firmware error handler. When
firmware rejects AlphaLayerID=255, this function is never called — the error returns through
a completely different code path that has no DARTUnmap.

### Finding 3: Partial-Map Leak in DARTMapExternalSurfaces

**Decompiled** `DARTMapExternalSurfaces` (0xfffffe000867b238) — bitmask loop:
```c
// Loop 1: bitmask-based (when param_2 != 0)
uVar4 = 0;
do {
    if ((param_2 >> (uVar4 & 0x3f) & 1) != 0) {
        uVar2 = AVE_DARTMapExternalSurfaces(..., uVar4);
        if ((int)uVar2 != 0) {
            // "failed to DART map external surfaces"
            return uVar2;  // ← LEAK: surfaces 0..uVar4-1 remain mapped
        }
    }
    uVar4++;
} while (uVar4 != 4);
```
**No cleanup of already-mapped surfaces on error.** This is a secondary leak independent
of the AlphaLayerID=255 bug — it occurs if ANY surface mapping fails mid-loop.

### Finding 4: DARTUnmapExternalSurfaces Xrefs Confirm Limited Callers

**Xrefs TO DARTUnmapExternalSurfaces (0xfffffe000867b684):**
- 1 DATA ref (vtable at 0xfffffe000b4e8dff)
- 1 CALL from FUN_fffffe000868b2e8 (inside DARTUnmapSurfaces_Wrapper chain)

**Xrefs TO DARTMapExternalSurfaces (0xfffffe000867b238):**
- 1 DATA ref (vtable at 0xfffffe000b4e8dfd)
- 1 CALL from AVE_CHM_DARTMapSurfaces (0xfffffe000855c0cc)
- 1 CALL from FUN_fffffe000868aeb4 (second map entry point)

The unmap has FEWER callers than the map — further confirming the asymmetry.

### Finding 5: "try to release delayed" IS THE RACE SITE (CORRECTED 2026-11-14)

**Previous claim "unreachable on error path" was WRONG.** Decompilation of
`AVE_SurfaceMgr_ReleaseDelayed` (0xfffffe000866e284) shows it:
1. Walks the delayed-release surface queue
2. For each surface, checks flags via FUN_0x865b3ec
3. **If `(flags & 0xf0000) == 0` → calls DARTUnmapSurface_TwoPhase(surface)** ← THIS IS THE UNMAP
4. On success: "release delayed surface", deallocates
5. On failure: "failed to release delayed surface", re-queues

**Callers:**
- `AVE_SurfaceMgr_ReleaseAllDelayed` (0x86708a4) — called at next encode cycle start,
  with "release all delayed surfaces" log. Called from FUN_0x85cabf4 (encode setup).
- `AVE_SurfaceMgr_Cleanup` (0x866dc50) — called at session/driver teardown, drains both
  delayed and regular queues. Called from FUN_0x866de18 → FUN_0x85c70d8 (IOService lifecycle)
  and FUN_0x85c8960 → FUN_0x86b12d0 (IOService::start cleanup when session count=0).

**This is the precise race site.** The sequence is:
1. Encode setup maps DART surfaces
2. Firmware rejects Alpha=255, leaves DMA descriptor pending in hardware queue
3. Kext's error path (LAB_0x8606770) zeroes kernel bookkeeping — does NOT quiesce firmware
4. ~90-160s later: session lifecycle triggers delayed surface release
5. AVE_SurfaceMgr_ReleaseDelayed → DARTUnmapSurface_TwoPhase → DART PTE invalidated
6. Stale firmware DMA descriptor fires → writes to now-unmapped DVA → DART panic

**The 90-160s timing** is the session lifecycle delay — how long until VideoToolbox tears
down or recycles the AVE2 driver session after the encode error. Not a firmware timer.

**Slot cleanup confirmed as bookkeeping-only:** AVE_IPC_FreeCommandSlot (0x8631064) maps a
DVA to an IPC pool offset and calls FUN_0x8553558 to "free memory to IPC pool." It does NOT
cancel/quiesce the firmware command, does NOT flush DMA, does NOT notify firmware. This is
the exact defect — kernel believes the command is done, firmware still has a live DMA descriptor.

### Finding 6: DARTUnmapSurface (0xfffffe0008670484) — The Leaf Unmapper

```c
undefined8 DARTUnmapSurface(undefined8 *param_1, long param_2, ulong param_3) {
    if (param_2 == 0 || param_3 > 3) {
        // "wrong parameters" → return 0xfffffc17 (-1001)
    }
    lock(param_1[0]);
    if (capability_bit_not_set) {
        return 0xfffffc0a;  // surface type not enabled for DART
    }
    actual_unmap(param_2, param_3);  // FUN_fffffe000865874c
    size_accounting(param_2);         // FUN_fffffe000865b5fc
    unlock(param_1[0]);
    return 0;
}
```

The actual unmap is `FUN_fffffe000865874c` which reverses what `sub_fffffe000865a84c` (DART map)
does. Both operate on the same surface descriptor and DART state structures.

### Finding 7: AVE_ValidateLayerParams — "wrong layer ID" Context

**Decompiled** `AVE_ValidateLayerParams` (0xfffffe0008636d70):
```c
// Simplified control flow:
if (param_3 >= 2) {
    log("wrong layer ID %d", param_3);
    return 0xfffffc17;  // -1001, NOT -17691
}
if ((param_4 & 7) != 0) {
    log("not padded to bytes");
    return 0xfffffc18;
}
if (offset + size >= 0x801) {
    log("PS data overflows");
    return 0xfffffc15;
}
// copy data, return 0
```

This validates parameter set layer IDs during encode configuration, NOT during firmware
encode execution. It's a kext-level bounds check (layer < 2), returning -1001 on failure.
Completely separate from the firmware's AlphaLayerID=255 → -17691 rejection.

### Functions Renamed in Ghidra Project

| Address | Old Name | New Name |
|---------|----------|----------|
| 0xfffffe000855c0cc | FUN_fffffe000855c0cc | AVE_CHM_DARTMapSurfaces |
| 0xfffffe000867b238 | FUN_fffffe000867b238 | DARTMapExternalSurfaces |
| 0xfffffe000867b684 | FUN_fffffe000867b684 | DARTUnmapExternalSurfaces |
| 0xfffffe000867b8d4 | FUN_fffffe000867b8d4 | DARTMapInternalSurfaces |
| 0xfffffe000866a32c | FUN_fffffe000866a32c | AVE_DARTMapExternalSurfaces |
| 0xfffffe000866adb4 | FUN_fffffe000866adb4 | AVE_DARTUnmapExternalSurfaces |
| 0xfffffe00086702bc | FUN_fffffe00086702bc | DARTMapSurface |
| 0xfffffe0008670484 | FUN_fffffe0008670484 | DARTUnmapSurface |
| 0xfffffe000868b400 | FUN_fffffe000868b400 | DARTUnmapSurfaces_Wrapper |
| 0xfffffe00085c3d54 | FUN_fffffe00085c3d54 | AVE_PipelineReconfigure |
| 0xfffffe0008636d70 | FUN_fffffe0008636d70 | AVE_ValidateLayerParams |

### Additional Functions Renamed (this session, continued)

| Address | Old Name | New Name |
|---------|----------|----------|
| 0xfffffe000860587c | FUN_fffffe000860587c | AVE_ISR_ReceiveCommandDone |
| 0xfffffe0008607474 | FUN_fffffe0008607474 | AVE_ISR_InterruptHandler |
| 0xfffffe00086072e8 | FUN_fffffe00086072e8 | AVE_ISR_ChannelDispatch |
| 0xfffffe0008565460 | FUN_fffffe0008565460 | AVE_FrameCompletionNotify |
| 0xfffffe00086055f0 | FUN_fffffe00086055f0 | AVE_ProcessOutputData_Dispatch |
| 0xfffffe000860398c | FUN_fffffe000860398c | AVE_ProcessCommandResult |
| 0xfffffe000865a84c | FUN_fffffe000865a84c | AVE_DART_MapSurface_Impl |
| 0xfffffe0008593a9c | FUN_fffffe0008593a9c | AVE_IODMACommand_MapSurface |
| 0xfffffe0008603cd8 | FUN_fffffe0008603cd8 | AVE_ProcessEncodeOutput |
| 0xfffffe000866e284 | FUN_fffffe000866e284 | AVE_SurfaceMgr_ReleaseDelayed |
| 0xfffffe000866dc50 | FUN_fffffe000866dc50 | AVE_SurfaceMgr_Cleanup |
| 0xfffffe00086708a4 | FUN_fffffe00086708a4 | AVE_SurfaceMgr_ReleaseAllDelayed |
| 0xfffffe0008631064 | FUN_fffffe0008631064 | AVE_IPC_FreeCommandSlot |

### Functions Renamed (2026-11-14, session count & timer analysis)

| Address | Old Name | New Name |
|---------|----------|----------|
| 0xfffffe00086b2e0c | FUN_fffffe00086b2e0c | AVE_ClientClose |
| 0xfffffe00085c9820 | FUN_fffffe00085c9820 | AVE_PerClientCleanup_DARTUnmap |
| 0xfffffe00085c70d8 | FUN_fffffe00085c70d8 | AVE_SessionInit |
| 0xfffffe00085c8960 | FUN_fffffe00085c8960 | AVE_SessionDestroy |
| 0xfffffe00085c843c | FUN_fffffe00085c843c | AVE_InternalProcessTimer_Callback |
| 0xfffffe00085c860c | FUN_fffffe00085c860c | AVE_ExternalProcessTimer_Callback |
| 0xfffffe00085c87dc | FUN_fffffe00085c87dc | AVE_SwTimer_Callback |
| 0xfffffe00085cabf4 | FUN_fffffe00085cabf4 | AVE_EncodeCycle_Cleanup |
| 0xfffffe000866de18 | FUN_fffffe000866de18 | AVE_SurfaceMgr_Cleanup_Wrapper |

### Functions Renamed (2026-11-14, param_2 analysis & pipeline correction)

| Address | Old Name | New Name |
|---------|----------|----------|
| 0xfffffe00085ce4f0 | FUN_fffffe00085ce4f0 | AVE_Heartbeat_ServicePipeline |
| 0xfffffe00085c6684 | FUN_fffffe00085c6684 | AVE_ProcessCompletionQueue |
| 0xfffffe00085c6860 | FUN_fffffe00085c6860 | AVE_ServiceEncodeChannels |
| 0xfffffe00085c68c4 | FUN_fffffe00085c68c4 | AVE_ServiceSwCChannels |
| 0xfffffe00085cea98 | FUN_fffffe00085cea98 | AVE_ComputeTimerInterval |
| 0xfffffe00085ccd48 | FUN_fffffe00085ccd48 | AVE_EncodeSubmit_TriggerCleanup |
| 0xfffffe00085ce220 | FUN_fffffe00085ce220 | AVE_EncodeSubmit_WithCleanup |
| 0xfffffe000860f318 | FUN_fffffe000860f318 | AVE_EncodeChannel_Service |
| 0xfffffe000860a3c0 | FUN_fffffe000860a3c0 | AVE_ChannelService_DARTUnmap |

### Functions Renamed (2026-11-14, +0xf8 gate analysis)

| Address | Old Name | New Name |
|---------|----------|----------|
| 0xfffffe00085ca838 | FUN_fffffe00085ca838 | AVE_SetEncodeActiveState |
| 0xfffffe00086b41f0 | FUN_fffffe00086b41f0 | AVE_UC_EncodeStartStop |
| 0xfffffe00086b45d4 | FUN_fffffe00086b45d4 | AVE_UC_PowerEvent |

---

## GHIDRA DEEP ANALYSIS — DART LIFECYCLE & EXPLOIT CHAIN (2026-11-14)

### DELIVERABLE 1: DART Map/Unmap Call Graph with Real Names

All DART lifecycle functions with addresses, names, and callers:

```
DART LIFECYCLE FUNCTIONS — COMPLETE CALL GRAPH
═══════════════════════════════════════════════

MAP CHAIN (encode setup → DART map):
────────────────────────────────────
  IOUserClient external method (0x86a* range)
    → FUN_fffffe00085cae90 / FUN_fffffe00085ce4f0 (encode pipeline setup)
      → FUN_fffffe00085c6860 (encode path setup)
        → FUN_fffffe000860f318 (encode dispatch)
          → FUN_fffffe00085fc4d4 (pre-encode DART setup)
            → FUN_fffffe00085fc3b4 (DART map orchestrator)
              → FUN_fffffe00085fa6cc (CHM DART map caller)
                → AVE_CHM_DARTMapSurfaces (0xfffffe000855c0cc)
                    CALLERS: FUN_fffffe00085fa6cc (1 xref)
                    CALLS:
                    ├── DARTMapExternalSurfaces (0xfffffe000867b238)
                    │     → AVE_DARTMapExternalSurfaces (0xfffffe000866a32c) [per surface]
                    │       → DARTMapSurface (0xfffffe00086702bc)
                    │         → AVE_DART_MapSurface_Impl (0xfffffe000865a84c)
                    │           → AVE_IODMACommand_MapSurface (0xfffffe0008593a9c)
                    │             → IODMACommand::genIOVMSegments() [vtable+0xb8]
                    │               → DART hardware mapper allocates DVA
                    └── DARTMapInternalSurfaces (0xfffffe000867b8d4) [bitmask-based]

UNMAP CHAIN (cleanup — COMPLETELY SEPARATE hierarchy):
──────────────────────────────────────────────────────
  FUN_fffffe00085c5764
    → AVE_PipelineReconfigure (0xfffffe00085c3d54)
        CALLERS: FUN_fffffe00085c5764 (1 xref)
        CONDITION: ONLY after unregister→updateEUMap→register ALL succeed
        CALLS:
        → DARTUnmapSurfaces_Wrapper (0xfffffe000868b400)
            CALLERS: AVE_PipelineReconfigure ONLY (1 code xref)
            → FUN_fffffe000868b2e8
              → DARTUnmapExternalSurfaces (0xfffffe000867b684)
                → AVE_DARTUnmapExternalSurfaces (0xfffffe000866adb4) [per surface]
                  → DARTUnmapSurface (0xfffffe0008670484)
                    → DARTUnmapSurface_TwoPhase (0xfffffe0008658064)
                        Contains: "do kernel unmapping", "do DART unmapping"

INTERRUPT/COMPLETION CHAIN (firmware response — NO UNMAP):
──────────────────────────────────────────────────────────
  AVE_ISR_InterruptHandler (0xfffffe0008607474)
    Contains: "interrupt %p %d 0x%x"
    Checks: state==3 (command complete)
    → AVE_ISR_ChannelDispatch (0xfffffe00086072e8)
      ├── Channel 1: FUN_fffffe0008603570 (HW interrupt)
      └── Channel 2: AVE_ISR_ReceiveCommandDone (0xfffffe000860587c)
            Contains: "receive command done", "firmware command error"
            → AVE_ProcessCommandResult (0xfffffe000860398c)
            │   Contains: "firmware command error", "frame drop"
            │   On error: logs error, handles -0x3f6/-0x3fa with frame drop, NO UNMAP
            │
            ├── [SUCCESS path] → AVE_ProcessOutputData_Dispatch (0xfffffe00086055f0)
            │     Dispatches by command type (2-6, default)
            │     Type 2 (encode): → AVE_ProcessEncodeOutput (0xfffffe0008603cd8)
            │       → AVE_FrameCompletionNotify (0xfffffe0008565460)
            │         → FUN_fffffe00085f1b44 (client notification callback) ×2
            │         NO DARTUNMAP ANYWHERE IN SUCCESS PATH
            │
            └── [ERROR path] → LAB_fffffe0008606770 (slot cleanup)
                  Clears command buffer slot only
                  NO DARTUNMAP, NO output processing, NO client notification

PROCESS TIMER → HEARTBEAT → CHANNEL SERVICE → DART UNMAP (IDLE-PANIC PATH):
─────────────────────────────────────────────────────────────────────────────
  AVE_InternalProcessTimer_Callback (0x85c843c) [IOTimerEventSource]
    → AVE_Heartbeat_ServicePipeline(session, 0xFF) [completions-first order]
  AVE_ExternalProcessTimer_Callback (0x85c860c) [IOTimerEventSource]
    → AVE_Heartbeat_ServicePipeline(session, 0xFF) [completions-first order]
  AVE_SwTimer_Callback (0x85c87dc) [IOTimerEventSource]
    → AVE_Heartbeat_ServicePipeline(session, 0) [channels-first, when +0xf8==1]

  AVE_Heartbeat_ServicePipeline (0x85ce4f0):
    param_2=0xFF: AVE_ProcessCompletionQueue → AVE_ServiceEncodeChannels → AVE_ServiceSwCChannels
    param_2=0:    AVE_ServiceEncodeChannels → AVE_ServiceSwCChannels → AVE_ProcessCompletionQueue
    Then: AVE_ComputeTimerInterval → reschedule timer

  PATH TO DART UNMAP (via encode channel service, NOT delayed-release walk):
    → AVE_ServiceEncodeChannels (0x85c6860) [iterates +0xfc channels at +0x120]
      → AVE_EncodeChannel_Service (0x860f318) [per-channel]
        → FUN_0x8601d4c → FUN_0x8601938 → FUN_0x85fc904
          → FUN_0x860a998 → FUN_0x860af60
            → AVE_ChannelService_DARTUnmap (0x860a3c0)
              → FUN_0x866e870 → DARTUnmapSurface_TwoPhase  ← INVALIDATES STALE PTE

ENCODE SUBMISSION → CLEANUP → DELAYED RELEASE (RUN B PATH — DIRECT):
─────────────────────────────────────────────────────────────────────
  IOUserClient external method (encode submission)
    → AVE_EncodeSubmit_WithCleanup (0x85ce220)
      → AVE_EncodeSubmit_TriggerCleanup (0x85ccd48)
        GATE: *(session+0xf8) == 1 [encode-active flag]
        → AVE_EncodeCycle_Cleanup (0x85cabf4)
          → AVE_SurfaceMgr_ReleaseAllDelayed (0x86708a4)
            → AVE_SurfaceMgr_ReleaseDelayed (0x866e284)
              → DARTUnmapSurface_TwoPhase  ← INVALIDATES ALL DELAYED SURFACES

CLIENT CLOSE → SESSION TEARDOWN:
─────────────────────────────────
  AVE_ClientClose (0xfffffe00086b2e0c) [vtable, IOUserClient::clientClose]
    → AVE_PerClientCleanup_DARTUnmap (0xfffffe00085c9820)
    │   → DARTUnmapSurface(surface_mgr, surface, client_index)  [per-client surface]
    │   → Decrements per-session counter at +0xfc
    │
    └── if (driver_client_count == 0):
          → AVE_SessionDestroy (0xfffffe00085c8960)
            → AVE_SurfaceMgr_Cleanup_Wrapper (0xfffffe000866de18)
              → AVE_SurfaceMgr_Cleanup (0xfffffe000866dc50)
                → AVE_SurfaceMgr_ReleaseDelayed (0xfffffe000866e284)
                  → DARTUnmapSurface_TwoPhase  ← INVALIDATES ALL DELAYED SURFACES

SESSION POOL TEARDOWN:
──────────────────────
  AVE_DART_Pool_Destroy (0xfffffe00085904b0)
    Contains: "unreleased IODMACommand"
    Destroys IODMACommand pool objects
    Called during session/client destruction
```

**FULL FUNCTION TABLE:**

| Address | Name | Callers | Role |
|---------|------|---------|------|
| 0xfffffe000855c0cc | AVE_CHM_DARTMapSurfaces | FUN_0x85fa6cc (1) | Top-level CHM map |
| 0xfffffe000867b238 | DARTMapExternalSurfaces | AVE_CHM_DARTMapSurfaces, FUN_0x868aeb4 (2) | External surface map loop |
| 0xfffffe000867b684 | DARTUnmapExternalSurfaces | FUN_0x868b2e8 (1) | External surface unmap loop |
| 0xfffffe000867b8d4 | DARTMapInternalSurfaces | AVE_CHM_DARTMapSurfaces (1) | Internal surface map loop |
| 0xfffffe000866a32c | AVE_DARTMapExternalSurfaces | DARTMapExternalSurfaces (per-surface) | Per-surface map wrapper |
| 0xfffffe000866adb4 | AVE_DARTUnmapExternalSurfaces | DARTUnmapExternalSurfaces (per-surface) | Per-surface unmap wrapper |
| 0xfffffe00086702bc | DARTMapSurface | AVE_DARTMapExternalSurfaces + others | DART map with lock |
| 0xfffffe0008670484 | DARTUnmapSurface | AVE_DARTUnmapExternalSurfaces + others | DART unmap with lock |
| 0xfffffe000865a84c | AVE_DART_MapSurface_Impl | DARTMapSurface (1) | IOMapper + IODMACommand setup |
| 0xfffffe0008593a9c | AVE_IODMACommand_MapSurface | AVE_DART_MapSurface_Impl (1) | IODMACommand::genIOVMSegments |
| 0xfffffe000868b400 | DARTUnmapSurfaces_Wrapper | AVE_PipelineReconfigure ONLY (1) | Top-level unmap entry |
| 0xfffffe00085c3d54 | AVE_PipelineReconfigure | FUN_0x85c5764 (1) | Pipeline reconfigure (conditional unmap) |
| 0xfffffe0008658064 | DARTUnmapSurface_TwoPhase | DARTUnmapSurface chain | "do kernel unmapping"/"do DART unmapping" |
| 0xfffffe00085904b0 | AVE_DART_Pool_Destroy | teardown path | "unreleased IODMACommand" |
| 0xfffffe00085902bc | AVE_DART_Pool_Create | init path | IODMACommand pool allocator |
| 0xfffffe0008607474 | AVE_ISR_InterruptHandler | hardware interrupt | Top-level ISR |
| 0xfffffe00086072e8 | AVE_ISR_ChannelDispatch | AVE_ISR_InterruptHandler | Per-channel dispatch |
| 0xfffffe000860587c | AVE_ISR_ReceiveCommandDone | AVE_ISR_ChannelDispatch (ch2) | Completion handler |
| 0xfffffe000860398c | AVE_ProcessCommandResult | AVE_ISR_ReceiveCommandDone | Command result processor |
| 0xfffffe00086055f0 | AVE_ProcessOutputData_Dispatch | AVE_ISR_ReceiveCommandDone | Output type dispatcher |
| 0xfffffe0008603cd8 | AVE_ProcessEncodeOutput | AVE_ProcessOutputData_Dispatch (type 2) | Encode output handler |
| 0xfffffe0008565460 | AVE_FrameCompletionNotify | AVE_ProcessEncodeOutput + others | Frame done notification |
| 0xfffffe0008636d70 | AVE_ValidateLayerParams | encode setup path | "wrong layer ID" (kext-level) |

### DELIVERABLE 2: Proof That Abort Leaves Pending DMA (Corrected Model)

**THE DEFINITIVE PROOF:**

Neither the success nor error completion path calls DARTUnmap — unmap runs only from
AVE_PipelineReconfigure and AVE_SurfaceMgr_ReleaseDelayed (delayed release). The bug is
NOT "missing unmap in the ISR" but rather: the abort path fails to quiesce firmware DMA
before the delayed surface release reclaims the DART PTE. The slot cleanup
(AVE_IPC_FreeCommandSlot) zeros kernel bookkeeping without cancelling the firmware command.

The firmware encode completion handler (`AVE_ISR_ReceiveCommandDone` at 0xfffffe000860587c)
processes firmware results through `AVE_ProcessCommandResult` (0xfffffe000860398c). The
critical branch:

```c
// Inside AVE_ISR_ReceiveCommandDone (0xfffffe000860587c):
// After AVE_ProcessCommandResult returns...

if ((int)uVar25 == 0) {
    // === SUCCESS PATH ===
    // Calls AVE_ProcessOutputData_Dispatch → AVE_ProcessEncodeOutput
    // → AVE_FrameCompletionNotify → client callback
    // STILL NO DARTUnmap — just output processing + notification
    FUN_fffffe00086055f0(param_1, lVar12, param_3);  // process output data
    // ...
    FUN_fffffe0008565460(lVar12, lVar17, 1, 0);       // notify: status=1 (success)
} else {
    // === FIRMWARE ERROR PATH ("firmware command error") ===
    // Logs error, goes DIRECTLY to slot cleanup
    // NO AVE_ProcessOutputData_Dispatch
    // NO AVE_FrameCompletionNotify
    // NO DARTUnmap
    goto LAB_fffffe0008606770;  // → clear command slot, return
}

// LAB_fffffe0008606770 (slot cleanup only):
FUN_fffffe0008631064(*(param_1 + 0xe0), lVar21);  // clear slot
*plVar2 = 0;                                       // zero command pointer
*(param_1 + 0xf0) &= ~bitmask;                     // clear active flag
*(param_1 + 0xf4 + slot*4) -= 1;                   // decrement counter
// RETURN — no DARTUnmap, no surface cleanup
```

**Verification — DARTUnmap is NEVER called from any completion path:**

1. `AVE_ISR_ReceiveCommandDone` (0x860587c): NO DARTUnmap calls
2. `AVE_ProcessCommandResult` (0x860398c): NO DARTUnmap calls
3. `AVE_ProcessOutputData_Dispatch` (0x86055f0): NO DARTUnmap calls (just dispatcher)
4. `AVE_ProcessEncodeOutput` (0x8603cd8): NO DARTUnmap calls
5. `AVE_FrameCompletionNotify` (0x8565460): NO DARTUnmap calls

**DARTUnmapSurfaces_Wrapper (0x868b400) cross-references:**
- 1 DATA ref (vtable pointer at 0x0b4e8ea7)
- 1 CODE ref: `AVE_PipelineReconfigure` (0x85c3d54) — THE ONLY CALLER

**AVE_PipelineReconfigure conditions for calling DARTUnmap:**
```c
// unregister → updateEUMap → register must ALL succeed
result = unregister(...);
if (result == 0) {
    result = updateEUMap(...);
    if (result == 0) {
        result = register(...);
        if (result == 0) {
            DARTUnmapSurfaces_Wrapper(...);  // ONLY HERE
        }
    }
}
// ANY error → return WITHOUT calling DARTUnmap
```

**CONCLUSION:** DARTUnmap is NEVER called from the interrupt/completion handler chain.
It is ONLY called from AVE_PipelineReconfigure, which is on a completely different call
hierarchy (pipeline setup/teardown, not firmware response processing). When firmware
rejects AlphaLayerID=255, the error path clears the command slot and returns — the
DART-mapped surfaces from the encode setup are NEVER cleaned up.

### DELIVERABLE 3: DVA Origin & Steerability Analysis

**DARTMapSurface chain decompiled (0x86702bc → 0x865a84c → 0x8593a9c):**

```
DARTMapSurface (0x86702bc):
  Validates: param_2 != 0, param_3 (surface_index) <= 3
  Takes lock: FUN_0x853c6d8(param_1[0])
  Checks bitmask: (param_1[1] >> index >> 16) & 1  [surface valid flag]
  Checks: surface pointer at param_1[0x20 + index*8] != 0
  CALLS: AVE_DART_MapSurface_Impl(param_2, index)
  On success: accumulates size at param_1[0x98 + index*8]
  Releases lock

AVE_DART_MapSurface_Impl (0x865a84c):
  Checks: *(param_1 + 0x68) != 0         [surface must be created]
  Checks: *(param_1 + 0xf1) bit 2 set    [some state flag]
  Checks: not already mapped via bitmask at *(param_1 + 0xf0)

  MAPPING SEQUENCE:
  1. uVar11 = *(param_1 + 0x78)           ← IOMapper (DART hardware instance)
  2. uVar10 = func_0x9ecc544(*(param_1+0x68))  ← IOMemoryDescriptor from IOSurface
  3. FUN_0x859593c(param_3, uVar11, uVar10)    ← IODMACommand::setMemoryDescriptor
  4. result = FUN_0x8593a9c(param_3, *(param_1+0x78), &dva_out)
                                           ← IODMACommand::genIOVMSegments [THE DART MAP]
  5. DVA stored at: *(param_1 + 0xc0 + index*8) = dva_out

  RANGE CHECK (DART type 3 only):
  if (dva + *(param_1 + 0xe0) >= 0x70800001)
    → "DART mapped address is out of range [0x%llx, 0x%llx)"
    → returns 0xFFFFFC06

  On mapping failure: "failed to do DART mapping"
  On error: calls FUN_0x8594a78 (IODMACommand::clearMemoryDescriptor), zeros stored DVA

AVE_IODMACommand_MapSurface (0x8593a9c):
  Checks: *(param_1 + 0x63c) == 1        [pool must be initialized]
  Gets DMA command from pool: FUN_0x8594228(param_1, &cmd)
  
  ACTUAL DART MAP via vtable calls:
  1. (**(cmd+0x18) + 0x88)(mapper, 1)     ← IODMACommand::setMemoryDescriptor
  2. (**(cmd+0x18) + 0xb8)(mapper, &addr, &segments, &count)
                                           ← IODMACommand::genIOVMSegments [HARDWARE MAP]
  3. On success: *(cmd + 0x20) = mapped_addr  ← DVA stored in command object
  4. Increments: *(param_1 + 0x688) += 1      [total map count]
  5. Accumulates: *(param_1 + 0x690) += (*param_2->vtable+0xb0)(param_2)  [total size]
  
  On failure: "failed to get mapped DART address", returns 0xFFFFFC18
```

**DVA STEERABILITY ASSESSMENT:**

| Property | Value | Implication |
|----------|-------|-------------|
| DVA source | IODMACommand::genIOVMSegments() via IOMapper (DART HW) | Hardware-allocated IOVA |
| DVA controllable? | NO — allocated from DART aperture by kernel IOMapper | Attacker cannot choose DVA value |
| DVA predictable? | PARTIALLY — sequential allocation from DART pool | Can be influenced by allocation pattern |
| DART aperture max | 0x70800000 (~1.88 GB, type 3 check) | Fixed hardware limit |
| Physical backing | IOSurface provided by userspace (via IOMemoryDescriptor) | Attacker controls physical pages |
| Surface count | Max 4 per encode (param_3 <= 3) | Up to 4 leaked DART mappings per trigger |

**EXPLOIT STEERABILITY MODEL:**

The DVA itself is NOT directly steerable — it's allocated by the DART hardware mapper
from its IOVA aperture. However, the exploit does NOT need DVA steerability because:

1. **The physical backing is userspace-controlled**: The IOSurface memory descriptor comes
   from userspace via func_0x9ecc544, so the attacker controls WHICH physical pages get
   DART-mapped.

2. **The leak is about stale DART mappings, not stale DVAs**: After the firmware error,
   the DART mapping (DVA → physical address) persists. When the deferred DMA fires 90-160s
   later, it writes through the stale DART entry to whatever physical address it maps.

3. **Physical page recycling is the attack vector**: 
   - Map IOSurface A → DART maps its physical pages, gets DVA X
   - Trigger AlphaLayerID=255 → firmware error → DART mapping DVA X → phys(A) persists
   - Free IOSurface A → physical pages returned to kernel allocator
   - Spray kernel objects → physical pages of A get reallocated for kernel heap objects
   - Deferred DMA fires → writes through DVA X → DART translates to phys(A) → corrupts
     kernel heap objects now occupying those physical pages

4. **PAC bypass is inherent**: DMA writes bypass PAC because they go through the DART
   hardware, not through CPU pointer authentication. The write target is physical memory,
   not a CPU-visible virtual address.

### DELIVERABLE 4: Encode Submission Path & CVE-2026-112466 (Partial)

**Encode Submission Path (traced via xrefs, CORRECTED 2026-11-14):**

```
AppleAVE2UserClient external method
  → AVE_EncodeSubmit_WithCleanup (0x85ce220) [calls cleanup with +0xf8 gate]
  → AVE_Heartbeat_ServicePipeline (0x85ce4f0) [heartbeat/service, NOT cleanup]
    → AVE_ServiceEncodeChannels (0x85c6860) [per-channel iteration]
      → AVE_EncodeChannel_Service (0x860f318) [per-channel dispatch]
        → FUN_0x860f118 (alternate encode path)
        → FUN_0x85fc4d4 (pre-encode DART setup)
          → FUN_0x85fc3b4 (DART map orchestrator)
            → FUN_0x85fa6cc
              → AVE_CHM_DARTMapSurfaces (0x855c0cc)
                [DART map chain continues as in Deliverable 1]
```

**EncodesAlpha reference:**
- String "EncodesAlpha" at 0xfffffe00072be45a
- Referenced from FUN_fffffe0008645bf0 (massive encode setup function, 192K+ chars decompiled)
- This function handles all encode parameter setup including alpha layer configuration

**CVE-2026-112466 (OOB READ for KASLR defeat) — Not Yet Located:**
- FUN_fffffe000869f0f8 is just frame-number matching (checks offset 0x28 == 0xa8), not the
  actual data transfer path. The data transfer is via shared IOSurface DMA — firmware writes
  directly into the mapped IOSurface without a kernel-side memcpy.
- The OOB read would be in the re-claim variant: if firmware output data lands in a reclaimed
  surface during the 90-160s window, the attacker captures firmware-written data in userspace.
- REQUIRES: experiment 3.0 (DART re-claim race) and analysis of what firmware writes into
  output surfaces during aborted encodes.

### Remaining Targets (priority order, updated 2026-11-14 model v3)

**HIGHEST-VALUE NEXT: ON-DEVICE Run B** — one reboot, tests whether a clean encode on the live
session triggers the delayed-release walk (prediction from Ghidra: it should). See Run B protocol
above. If Run B confirms attacker-controlled timing, proceed directly to 3.0 proper (DART re-claim).

**Experiment 3.0 (DART re-claim race)** — same as designed, with task 3 refinement: since the
stale descriptor is an output descriptor targeting the mapped IOSurface backing, the reclaim should
re-populate DVAs via fresh IOSurface allocations (same small sizes as encode surfaces, 320x240-class
buffers — match the shapes the map path creates). If the descriptor fires through a re-claimed valid
mapping, surface diff catches the written bytes.

**Remaining Ghidra (narrow, priority order):**

1. **Driver-teardown session-count path — COMPLETE (2026-11-14)**
   - AVE_ClientClose (0x86b2e0c) = vtable entry (IOUserClient::clientClose). Zero code callers.
   - Takes lock, decrements client count at driver_obj + 0xb8 (byte offset).
   - Calls AVE_PerClientCleanup_DARTUnmap (0x85c9820) which calls DARTUnmapSurface for the
     client's specific surface (param_2 < 4 = surface index).
   - If client count == 0: AVE_SessionDestroy (0x85c8960) → AVE_SurfaceMgr_Cleanup_Wrapper
     (0x866de18) → AVE_SurfaceMgr_Cleanup (0x866dc50) → AVE_SurfaceMgr_ReleaseDelayed →
     DARTUnmapSurface_TwoPhase for ALL delayed-queue surfaces.
   - Session context at driver_obj + 0x98; count at driver_obj + 0xb8.
   - AVE_SessionInit (0x85c70d8) increments session count at session_context + 0x160 on success.

   **IDLE-PANIC TIMER MECHANISM (CORRECTED 2026-11-14, param_2 analysis):**
   Three timers created during AVE_SessionInit:
   - **Internal process timer** (session + 0x70): callback AVE_InternalProcessTimer_Callback
     (0x85c843c) → calls AVE_Heartbeat_ServicePipeline(session, 0xFF)
   - **External process timer** (session + 0x88): callback AVE_ExternalProcessTimer_Callback
     (0x85c860c) → calls AVE_Heartbeat_ServicePipeline(session, 0xFF)
   - **Sw timer** (session + 0x98): callback AVE_SwTimer_Callback (0x85c87dc) → conditionally
     calls AVE_Heartbeat_ServicePipeline(session, 0) when session + 0xf8 == 1

   **param_2 (0xFF vs 0) controls call ordering, NOT a sentinel:**
   AVE_Heartbeat_ServicePipeline (0x85ce4f0) is a heartbeat/service function that processes
   three sub-systems in order. param_2 controls the priority:
   - param_2 != 0 (0xFF, process timers): **completions first** — AVE_ProcessCompletionQueue,
     then AVE_ServiceEncodeChannels, then AVE_ServiceSwCChannels
   - param_2 == 0 (Sw timer): **channels first** — AVE_ServiceEncodeChannels,
     AVE_ServiceSwCChannels, then AVE_ProcessCompletionQueue
   The 0xFF value is NOT the AlphaLayerID sentinel — it's a boolean-like priority flag meaning
   "drain completions before servicing channels." After the three sub-calls, the function
   computes the next timer interval via AVE_ComputeTimerInterval (0x85cea98) and reschedules.

   **CORRECTED UNMAP PATH (2026-11-14):** The timer path does NOT directly reach
   AVE_EncodeCycle_Cleanup → ReleaseAllDelayed as previously claimed. The actual path is:
   - Timer → AVE_Heartbeat_ServicePipeline → AVE_ServiceEncodeChannels (0x85c6860)
     → AVE_EncodeChannel_Service (0x860f318) → FUN_0x8601d4c → ... →
     AVE_ChannelService_DARTUnmap (0x860a3c0) → FUN_0x866e870 → DARTUnmapSurface_TwoPhase
   This is a **direct per-surface DART unmap** during encode channel servicing, not through
   the delayed-release walk. The 90-160s variability is how often the timer fires and whether
   the channel service function finds the stale surface to unmap.

   AVE_EncodeCycle_Cleanup is gated on `*(session+0xf8) == 1` inside
   AVE_EncodeSubmit_TriggerCleanup (0x85ccd48) and is only called from IOUserClient
   external methods (encode submissions), NOT from the timer path.

   **Run B prediction (STRENGTHENED by correction):** A clean encode submission from userspace
   directly calls the encode external method → AVE_EncodeSubmit_TriggerCleanup (gated on
   +0xf8==1, which is 1 during an active encode session) → AVE_EncodeCycle_Cleanup →
   AVE_SurfaceMgr_ReleaseAllDelayed → DARTUnmapSurface_TwoPhase. This is a **synchronous,
   direct path** to the delayed-release walk — no timer dependency, no channel service
   intermediary. Run B should panic within seconds.

   **Run C corollary:** Killing the app process entirely (not just VTCompressionSession-
   Invalidate) triggers AVE_ClientClose → client count to 0 → AVE_SessionDestroy →
   AVE_SurfaceMgr_Cleanup → full delayed-release walk → fast panic. This is a destructive
   fire-control variant (loses the userspace process). Run B (encode-driven) is strictly
   better: fires the walk without teardown, keeping the process alive to observe/collect.

2. **+0xf8 encode-active state gate — RESOLVED (2026-11-14)**

   `AVE_SetEncodeActiveState` (0x85ca838) is the sole writer of `*(session+0xf8)`. Decompiled:
   ```c
   void AVE_SetEncodeActiveState(long session, int new_state) {
       if (new_state == *(int *)(session + 0xf8)) return;  // no-op if unchanged
       // Log: "Start %p %d <- %d" (new ← old)
       if (new_state == 0) {
           FUN_0x85cae90(session, -1);  // shutdown/stop path
       } else if (new_state == 1 && completion_queue_empty(session + 0xa8)) {
           AVE_EncodeCycle_Cleanup(session, -1);  // immediate cleanup on 0→1 transition
       }
       *(int *)(session + 0xf8) = new_state;
       // Log: "End %p %d <- %d %d"
   }
   ```

   **Callers (2 total, both IOUserClient level):**
   - `AVE_UC_EncodeStartStop` (0x86b41f0): IOUserClient external method.
     - param_2=1 (start): sets FUN_0x86b4544(1), FUN_0x86b458c(1) [timer start], then
       dispatches AVE_SetEncodeActiveState(session, 1) through command gate.
     - param_2=0 (stop): dispatches AVE_SetEncodeActiveState(session, 0) through command gate,
       then sets FUN_0x86b4544(0), FUN_0x86b458c(0) [timer stop].
   - `AVE_UC_PowerEvent` (0x86b45d4): IOUserClient power event handler.
     - On specific power codes (0xE0000310, 0xE0000250): dispatches
       AVE_SetEncodeActiveState(session, 0) through command gate (force stop on sleep).

   **Key insight:** Firmware error codes (-17691) do NOT clear +0xf8. The flag persists as 1
   after a failed Alpha=255 encode because only explicit userspace start/stop calls or power
   events control it. The Run B prediction is confirmed viable: the gate is open for the clean
   encode's TriggerCleanup to reach ReleaseAllDelayed.

   **Transition behavior note:** When +0xf8 transitions from 0→1 and the completion queue is
   empty, AVE_SetEncodeActiveState calls AVE_EncodeCycle_Cleanup immediately. This means if
   +0xf8 were somehow 0 at the time of the clean encode (it shouldn't be, but the Run B v2
   frame-count test disambiguates), the start→encode sequence would still trigger cleanup on
   the 0→1 transition.

3. **Command struct at error time — PARTIAL (2026-11-14)**
   - IPC command buffer is itself a DART-mapped surface (at IPC_pool + 0x28).
   - AVE_IPC_FreeCommandSlot converts command DVA to pool-relative offset:
     `pool_offset = FUN_0x865b494(surface, type, 0) + (command_DVA - base_DVA)`
   - Surface DVAs stored at surface_desc + 0xc0 + index*8 (indices 0-3).
   - Surface index per encode task at task_obj + 0x28 (bitmask `1 << (val & 0x3f)`).
   - Which of 4 indices is "output" vs "input" not yet determined from Ghidra alone.
     AXI_ID 0xc0 (encoder write channel) in all panics = firmware writes to output surface.
   - FUN_0x865b474 = DVA accessor: returns `*(surface + 0x98) + offset` (base DVA + byte offset).

3. **IOUserClient external-method selector map — DEFERRED**
   Vtable entries are arm64e PAC-encoded; raw memory reads don't directly decode the dispatch
   table. Requires specialized arm64e vtable analysis. Lower priority — the PoC can use
   VideoToolbox initially and switch to direct IOKit calls later.

**NOTE (task 3 negative / deprioritization):** FUN_0x869f0f8 (previously suspected as 112466
read-side) is just frame-number matching — checks `*(param_2+0x28) == *(param_3+0xa8)`, copies
one 4-byte value on match. The 112466 OOB read is NOT in the output-processing chain. Data
transfer is via shared IOSurface DMA (firmware writes directly into mapped IOSurface, no
kernel-side memcpy to exploit). The read primitive, if it exists on this trigger, is more likely
in the stale-descriptor write landing in a re-claimed readable surface = read-back via 3.0
Outcome A, or is an entirely separate code path. **Deprioritize further Ghidra work on the
output processing chain accordingly.**
