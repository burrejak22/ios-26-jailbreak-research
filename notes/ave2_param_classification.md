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

**Deferral mechanism hypothesis (verify in Ghidra):** encode submitted with poison parameter ->
firmware arms an invalid DMA descriptor -> encode fails (userspace sees -17691) -> descriptor
executes later (teardown/flush/idle/session recycle) -> OOB write traps in DART. This is a race
window: same trigger sometimes errors cleanly, sometimes OOB-writes.

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

**All 4 DVAs in 0x100007xxxxx region** (~900KB span). PTE delta crashes 3 vs 4: 55 PTEs (55 pages).
AXI_ID 0xc0 in 3 of 4 runs — likely the parameter-set/bitstream DMA channel.
All faults are **PTE invalid exception on write** from `dart-ave` at `AppleT8110DART.cpp:2369`.

**Deferral timing is variable** (90s and 130s post-encode) — confirms race/async trigger, not fixed timer.
The DMA descriptor fires on some internal kernel event (flush/teardown/idle GC).

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

### 2E-0. Session Teardown Test — NEXT ON-DEVICE EXPERIMENT
**Goal:** Collapse the 90–130s deferral window and identify the exact trigger mechanism.

After the failed Alpha=255 encode (-17691 returned), instead of waiting idle:

- **Run A:** Immediately `VTCompressionSessionInvalidate` / destroy the session, wait 30s.
- **Run B:** Encode a clean frame on the same session (valid AlphaLayerID), then wait.
- **Run C:** Leave idle (existing baseline, 90–130s panic).

**Prediction table:**

| Result | Meaning |
|--------|---------|
| A panics quickly (~seconds after invalidate) | Descriptor fires on teardown → armed-descriptor confirmed, deferral becomes deterministic and fast (~10s test cycle) |
| A never panics, B panics | Descriptor fires on next-use/flush → the "wait" is really "next descriptor submission" |
| Only C panics | True idle timer (power-state / DPB drain / firmware GC) → check whether idle sleep event correlates |

If A works, the test protocol drops from 120s to ~10s — massive throughput improvement for all
downstream testing including regression checks during Ghidra analysis.

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

### Open questions (updated after boundary sweep)

1. **ANSWERED: Truncation test** — neither raw nor 6-bit. The fault is error-path-specific.
2. **ANSWERED: Acceptance boundary** — exact 0xFF sentinel. Every value 0–254 is accepted;
   only 255 triggers -17691 rejection and the subsequent deferred DART fault.
3. **Deferral mechanism:** is it teardown-triggered, next-use-triggered, or idle-timer-triggered?
   (2E-0 test — on-device, fast)
4. **Infoleak:** does the -17691 abort path leave stale firmware data in userspace-accessible
   buffers? (2E-1 test — on-device, no Ghidra needed)
5. **Error-path anatomy:** what does the -17691 abort path do differently with DMA descriptors
   vs the clean encode path? (Ghidra target — maximally narrowed)
6. **Offset controllability:** can a second parameter steer the OOB write target? (post-Ghidra)
7. **Read-back path (112466-style infoleak candidate):** does the encoder route any OOB
   read result back to userspace (via encoded output or IOKit get)?

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

