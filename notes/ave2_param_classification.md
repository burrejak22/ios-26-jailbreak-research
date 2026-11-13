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
- **CVE-2026-112466** — OOB READ / kernel memory disclosure — the KASLR-defeat stage the chain
  needs. **Top Ghidra priority.**
- **CVE-2026-112689** — OOB write (Belman).

### Why our trigger is distinct from the published NTL repro (112705)

1. Different parameter (AlphaLayerID=255 vs NumberOfTemporalLayers~16463)
2. Different panic fingerprint: our DVA lands in the 0x100007xxxxx window (structured region),
   crashes hit different sub-allocations on different encoder write channels (AXI_ID 0xc0/0xc1)
3. **Deferred firing** — DART fault lands well after the userspace callback; published NTL repros
   are synchronous, deterministic, fixed-offset fills
4. Trigger value 255 exceeds the VPS bitstream field width (6 bits) — truncation question open

---

## CRASH TABLE

| # | Date/Time | Trigger | DVA | AXI_ID | Attribution confidence |
|---|-----------|---------|-----|--------|-----------------------|
| 1 | 2026-11-12 ~23:55 | Escalation sweep (cumulative Alpha 0-255, multi-session) | 0x100007d2a80 | 0xc1 | Low — cumulative, not isolatable |
| 2 | 2026-11-13 ~00:42 | AlphaLayerID=255 (suspect 1), deferred fault; initially misattributed to Alpha64+RepFmt10 | 0x100007ec500 | 0xc0 | HIGH — reattributed 2026-11-13 |
| 3 | 2026-11-13 (idle-wait session) | AlphaLayerID=255, delayed fire during idle wait, no follow-up press | (fill from .ips) | (fill from .ips) | HIGH — clean isolated protocol |

**DVA delta crashes 1 vs 2: -0x1BD80 (~25 pages apart), same 0x100007xxxxx region, different
AXI_ID channels (0xc0 vs 0xc1)** — different hardware write channels likely = different DMA paths
(parameter-set/bitstream output vs frame-data). Different sub-allocations of a structured mapping
region = control surface, not noise.

**Alpha64+RepFmt10 status: UNTESTED** (the 11/13 00:42 crash attributed to it was actually
Alpha=255's deferred fault). Back in the queue.

---

## NEXT EXPERIMENT QUEUE (priority order)

1. **Alpha=255 idle-time test x5** — canary -> set 255 -> encode -> observe -17691 -> do nothing
   5 min. Panic while idle? time-to-panic? If no panic: swipe app away (teardown), then press
   Narrow again (new session). Which event fires the panic = the race characterization.
2. **Truncation test** — Alpha = 63, 127, 191 (one per reboot, canary first, each with the
   120s wait). All three reduce to 63 in the 6-bit VPS field:
   - ALL panic -> kernel consumes the raw IOKit value -> wide, possibly steerable OOB (~192 elements)
   - Only 63 panics -> kernel consumes bitstream-truncated value -> single-element OOB
   - None panic (but 255 does) -> trigger requires the -17691 error path
3. **Boundary sweep** around first-panicking value from (2); record DVA + AXI_ID per crash.
   Deterministic DVA vs input = steerable primitive; constant DVA = crash-only.
4. **Ghidra**: 26.6.2 AppleAVE2 kext — consumer of AlphaLayerID / VPS-extension fields; write
   side (this panic) AND read-back side (112466-style leak candidate).

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

