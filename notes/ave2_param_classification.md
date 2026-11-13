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

### 2A. Idle Wait (Alpha=255 repeatability)
**Button: "Idle Wait"**
Protocol: canary -> 15s cooldown -> Alpha=255 encode -> 120s countdown -> done.
Run 5x. Record: time-to-panic (if any), .ips DVA+AXI_ID per crash.
Goal: establish panic-rate probability and time-to-fire distribution.
If panic fires during idle = race characterization (DMA descriptor executes on teardown/flush/idle).
If no panic in 5x = the earlier panics were sequence-dependent, not value-dependent.

### 2B. Truncation Test (raw vs 6-bit kernel consumption)
**Button: "Truncation" (cycles through 63, 127, 191)**
Protocol: canary -> 10s cooldown -> Alpha=N encode -> 120s wait.
One value per button press. Reboot between panics.
All three reduce to 63 in the 6-bit VPS field:
- ALL panic -> kernel consumes the raw IOKit value -> wide OOB (~192 elements), steerable
- Only 63 panics -> kernel consumes bitstream-truncated value -> single-element OOB
- None panic (but 255 does) -> trigger requires the -17691 error path specifically

### 2C. Boundary Sweep (minimum panicking value)
**Button: "Boundary" (cycles through 128, 192, 160, 144, 136, 224, 240, 248)**
Protocol: canary -> 10s cooldown -> Alpha=N encode -> 120s wait.
Known: 255 panics, <=64 survives. Binary search for the threshold.
Record DVA + AXI_ID per crash — deterministic DVA vs input = steerable primitive.

### 2D. Ghidra (offline)
26.6.2 AppleAVE2 kext — consumer of AlphaLayerID / VPS-extension fields; write
side (this panic) AND read-back side (112466-style leak candidate).

### Open questions (drive the next experiments)

1. **Truncation test:** does kernel consume raw IOKit value (255) or bitstream-truncated
   (255 & 0x3F = 63)? Single test, 3 reboots each. Decides primitive quality:
   - Only 63 panics -> 1-element OOB (could still be groomable)
   - 127/191/255 all panic -> raw value path, wide possibly steerable OOB
2. **Deterministic DVA vs Alpha value mapping** — steerable primitive vs crash-only
3. **Read-back path (112466-style infoleak candidate):** does the encoder route any OOB
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

