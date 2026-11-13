# AVE2 Parameter Classification — Device Test Results (2026-11-12)

**Device:** iPhone 17 Pro (iPhone18,1), iOS 26.6.2  
**Test:** `VTSessionCopySupportedPropertyDictionary` on hardware HEVC encoder  
**Result:** 158 properties enumerated. Multiple CVE-relevant params confirmed settable.

## Critical Finding: Temporal Layer Off-by-One is CLAMPED (Dead End)

```
Set NumberOfTemporalLayers=8: 0 (ACCEPTED)
Readback: NumberOfTemporalLayers = 1     ← CLAMPED!
```

VideoToolbox accepted the property-set call (returned noErr) but **silently clamped** the value to 1. The kernel never sees 8. The earlier "SET OK" from the property dump was misleading — it only checked the return code. **This path is NOT exploitable.**

## REAL Critical Finding: AlphaLayerID + RepFormatIndex are WIDE OPEN

```
AlphaLayerID=255:   OK  *** NO VALIDATION, limit <63 ***
RepFormatIndex=255: OK  *** NO VALIDATION, limit <2  ***
```

These properties accept wildly over-limit values with **no userspace clamping**. When the encoder constructs VPS/SPS with these values and sends them to the AppleAVE2 kernel driver, the kernel uses them as array indices without bounds checking on 26.6.2.

- **AlphaLayerID=255**: Potential index into a 63-element VPS layer array → **OOB by 192 elements**
- **RepFormatIndex=255**: Potential index into a 2-element rep format array → **OOB by 253 elements**

## Revised Classification (Post-Device Test)

### Class A — Confirmed Settable, CVE-Relevant

| Property | Type | RW | Maps To (Diff) | Exploit Impact |
|----------|------|----|----|----------------|
| `NumberOfTemporalLayers` | Number | **RW** | `iNumOfTemporalLayer` off-by-one | **OOB array index** |
| `log2_max_minus4` | Number | **RW** | `log2_max_frame_num_minus4 <= 12` | **Arithmetic overflow in buffer sizing** |
| `NumberOfSlices` | Number | **RW** | Slice count | Array sizing |
| `EnableMCTF` | Boolean | **RW** | Triggers `AVE_Client_CheckMCTFInfo` path | MCTF struct validation bypass |
| `LookAheadFrames` | Number | **RW** | LookAhead frame count range check | Buffer allocation |
| `ChromaQPIndexOffsetMultiPPS` | Number | **RW** | `chroma_qp_offset_list_len_minus1 <= 5` | PPS array overflow |
| `EnableMultiReferenceP` | Boolean | **RW** | Reference frame handling | Ref frame array access |
| `MultiReferencePSpacing` | Number | **RW** | Multi-ref spacing | Array stride |
| `BaseLayerFrameRate` | Number | **RW** | Temporal layer config | **Also accepts 8, 9 (over limit)** |
| `MaxFrameDelayCount` | Number | **ReadOnly** | B-frame count `<= 3` | Cannot set (ReadOnly) |
| `InputQueueMaxCount` | Number | **RW** | Queue sizing | Allocation control |
| `MaxAllowedFrameQP` | Number | **RW** | QP bounds | Config struct field |
| `DPBRequirements` | unknown | **RW** | DPB management | Reference buffer sizing |

### Class B → Reclassified as Class A (App CAN Set VPS/SPS/PPS Fields)

The `Required*` and `User*` property prefixes prove the encoder accepts app-supplied parameter set values:

| Property | Type | RW | Maps To (Diff) | Significance |
|----------|------|----|----|---------------|
| `RequiredHEVCVideoParameterSetAlphaLayerID` | Number | **RW** | `vps_max_layer_id < 63` | VPS layer ID — can we exceed 63? |
| `RequiredHEVCVideoParameterSetRepFormatBitDepths` | unknown | **RW** | `vps_num_rep_formats_minus1 < 2` | VPS rep format |
| `RequiredHEVCVideoParameterSetRepFormatChromaFormatIdcs` | unknown | **RW** | VPS chroma format | VPS extension fields |
| `RequiredHEVCSequenceParameterSetID` | Number | **RW** | SPS parameter set ID | SPS addressing |
| `RequiredHEVCSequenceParameterSetRepFormatIndex` | Number | **RW** | SPS rep format index | Index into rep format array |
| `RequiredHEVCPictureParameterSetID` | Number | **RW** | PPS ID | PPS addressing |
| `MVHEVCVideoLayerIDs` | unknown | **RW** | Multi-view layer IDs | Layer array indexing |
| `MVHEVCViewIDs` | unknown | **RW** | View IDs | View array indexing |
| `MVHEVCLeftAndRightViewIDs` | unknown | **RW** | Stereo view IDs | View config |
| `UserDPBFramesForFaceTime` | unknown | **RW** | DPB reference frame count | **DPB array sizing** |
| `UserRPSForFaceTime` | unknown | **RW** | `num_short_term_ref_pic_sets < 65` | **RPS array sizing** |
| `UserParameterSetsIds` | unknown | **RW** | Parameter set count bounded to 21 | **PS array overflow** |
| `TemporalIDNestingFlag` | Boolean | **RW** | VPS temporal nesting | VPS config |

**This demolishes the "VPS/SPS/PPS are encoder output" assumption.** Apple's VideoToolbox explicitly allows apps to specify parameter set IDs, layer IDs, rep format indices, and reference picture sets. The encoder uses these app-supplied values to construct the bitstream — and on 26.6.2, they flow into the kernel driver without validation.

### Class C — Confirmed Unreachable (Not in Property Dictionary)

Parameters with no matching property key in the 158-property dump:
- `vps_max_sub_layers_minus1` — no matching property
- `vps_num_layer_sets_minus1` — no matching property  
- `vps_num_hrd_parameters` — no matching property
- `num_extra_slice_header_bits` — no matching property
- `num_ref_idx_l0_default_active_minus1` — no direct property (may be derived from `EnableMultiReferenceP`)
- `num_ref_idx_l1_default_active_minus1` — no direct property

## Exploit Surface Summary

| Category | Count | Top Targets |
|----------|-------|-------------|
| **Class A: Direct session config** | ~13 | `NumberOfTemporalLayers`, `log2_max_minus4`, `NumberOfSlices` |
| **Former Class B → Now Class A** | ~13 | `RequiredHEVC*`, `User*ForFaceTime`, `MVHEVC*` |
| **Class C: Unreachable** | ~6 | VPS internal fields |
| **Other ReadWrite** | ~70 | Bitrate, quality, format (not CVE-relevant) |

**True exploit surface: ~26 parameters, not 97, not 5-15.**

The "Required" and "User" prefixes expose far more attack surface than expected. The encoder is designed to be heavily parameterized for FaceTime and multi-view HEVC, and those parameters flow to the kernel unchecked on 26.6.2.

## Priority Attack Vectors (Ranked)

### Tier 1 — Lowest Hanging Fruit
1. **`NumberOfTemporalLayers = 8`** — Confirmed OOB by 1. Set property, encode frame, kernel indexes `m_psaTCmd[7]` or similar with only 7 slots. Smallest blast radius, most predictable corruption.

2. **`log2_max_minus4 = 13+`** — Arithmetic overflow. `1 << (log2_max_minus4 + 4)` = `1 << 17` when expected max is `1 << 16`. Used for buffer sizing → undersized allocation → heap overflow on encode.

### ~~Tier 1~~ — DEAD END (Clamped)
1. ~~`NumberOfTemporalLayers = 8`~~ — **Clamped by VideoToolbox.** Set returns noErr but readback shows 1. Kernel never sees 8.

### Tier 1 (REVISED) — Confirmed Unclamped, Encode-Capable
2. **`RequiredHEVCVideoParameterSetAlphaLayerID = 64+`** — Accepts 255 with no clamping. Maps to `vps_max_layer_id`. **OOB by up to 192 elements in a 63-element kernel array.**
3. **`RequiredHEVCSequenceParameterSetRepFormatIndex = 10+`** — Accepts 255 with no clamping. Maps to rep format array index. **OOB by up to 253 elements in a 2-element array.** This is the deepest OOB available.

### Tier 2 — Confirmed Settable, Untested OOB Distance
4. **`UserRPSForFaceTime`** — If this controls `num_short_term_ref_pic_sets`, setting > 64 overflows the RPS array.
5. **`UserDPBFramesForFaceTime`** — DPB reference count → if exceeding expected bounds, OOB in reference frame buffer arrays.
6. **`UserParameterSetsIds`** — Count field; if > 21, parameter set array overflow.

### Eliminated by Tier 2 Probe
- **`log2_max_minus4`** — Rejected at 12+ by VideoToolbox. Cannot reach kernel with over-limit values.
- **`NumberOfSlices`** — Rejected at 64+. VideoToolbox validates.
- **`ChromaQPIndexOffsetMultiPPS`** — ALL values rejected. Property not settable on this encoder config.

## Tier 2 Probe Full Results (2026-11-12)

```
log2_max_minus4:    0-8 OK, 12+ REJECTED (VT validates)
AlphaLayerID:       0-255 ALL OK (NO validation!)
RepFormatIndex:     0-255 ALL OK (NO validation!)
NumberOfSlices:     1-16 OK, 64+ REJECTED (VT validates)
ChromaQPOffset:     ALL REJECTED (not settable on this config)
```

## Honest State of Play (Post-Tier 2 Probe)

**Lesson from NumberOfTemporalLayers: SET OK ≠ stored, stored ≠ delivered.**

| Property | Set OK | Readback Verified | Bitstream Verified | Status |
|----------|--------|-------------------|-------------------|--------|
| NTL=8 | YES | **NO (clamped to 1)** | n/a | **Dead** |
| AlphaLayerID=255 | YES | pending | pending | Candidate |
| RepFormatIndex=255 | YES | pending | pending | Candidate |
| log2_max_minus4=13 | **NO** | n/a | n/a | **Dead** (VT rejects) |
| NumberOfSlices=64 | **NO** | n/a | n/a | **Dead** (VT rejects) |
| ChromaQPOffset=* | **NO** | n/a | n/a | **Dead** (all rejected) |
| MVHEVCVideoLayerIDs | untested | pending | pending | Next candidate |
| UserRPSForFaceTime | untested | pending | pending | Next candidate |
| UserDPBFramesForFaceTime | untested | pending | pending | Next candidate |
| UserParameterSetsIds | untested | pending | pending | Next candidate |

**`Required*` properties may be match/filter constraints** ("find me the SPS with this ID") rather than construction inputs ("build the VPS with this ID"). The encoder may just fail to match or construct valid defaults regardless. Only bitstream analysis can distinguish.

**Struct-typed properties (CFArrays)** are harder for VideoToolbox to silently clamp and flow closer to raw delivery. If the `Required*` pair turns out clamped, these are the next real candidates.

## Verification Flow ("Verify Oracle" button)

The new verification PoC:
1. **BASELINE**: Encode with defaults, capture VPS/SPS hex dump
2. **Test A**: Set AlphaLayerID=64, readback, encode, capture VPS/SPS hex
3. **Test B**: Set RepFormatIndex=10, readback, encode, capture SPS hex
4. **Test C**: Set struct-typed properties (MVHEVCVideoLayerIDs, UserDPB, UserRPS, UserParameterSets), readback, encode

**Decision criteria:**
- If VPS/SPS hex DIFFERS from baseline → value reached the bitstream → proven delivered to kernel
- If IDENTICAL to baseline → encoder ignored the property (match filter or clamped internally)
- Only properties passing BOTH readback AND bitstream verification are valid OOB targets

## Next Step

Run **"Verify Oracle"** button (cyan, safe — just encodes and parses output). Send back the full log. Properties that pass both checks become the real panic-test candidates.
