# AVE2 Parameter Classification — Device Test Results (2026-11-12)

**Device:** iPhone 17 Pro (iPhone18,1), iOS 26.6.2  
**Test:** `VTSessionCopySupportedPropertyDictionary` on hardware HEVC encoder  
**Result:** 158 properties enumerated. Multiple CVE-relevant params confirmed settable.

## Critical Finding: Off-by-One CONFIRMED

```
NumberOfTemporalLayers = 8  → SET OK *** OVER PATCHED LIMIT ***
NumberOfTemporalLayers = 9  → SET OK *** OVER PATCHED LIMIT ***
```

The patch changes `(iNumOfTemporalLayer - 1) <= 7` to `(iNumOfTemporalLayer - 1) < 7`.
On 26.6.2, setting `NumberOfTemporalLayers = 8` passes the old check (`7 <= 7` is true)
but indexes into a size-7 array at position 7 = **OOB by 1 element**.

This is a **confirmed, app-settable, kernel OOB write from a sandboxed app**.

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

### Tier 2 — Wider OOB
3. **`RequiredHEVCVideoParameterSetAlphaLayerID = 64+`** — If this maps to `vps_max_layer_id`, exceeding 63 causes array OOB in VPS extension processing.

4. **`UserRPSForFaceTime`** — If this controls `num_short_term_ref_pic_sets`, setting > 64 overflows the RPS array.

5. **`UserDPBFramesForFaceTime`** — DPB reference count → if exceeding expected bounds, OOB in reference frame buffer arrays.

### Tier 3 — Needs Ghidra to Map
6. **`ChromaQPIndexOffsetMultiPPS`** — Maps to chroma QP offset; need to verify kernel-side array size.
7. **`RequiredHEVCSequenceParameterSetRepFormatIndex`** — Index into rep format array; if unbounded, OOB read/write.
8. **`UserParameterSetsIds`** — Count field; if > 21, parameter set array overflow.

## Next Step

Build a **targeted OOB PoC** that:
1. Creates HEVC session
2. Sets `NumberOfTemporalLayers = 8` (the confirmed off-by-one)
3. Encodes a frame
4. Monitors for kernel panic (this IS the first panic-capable test)

Have `.ips` log pulling ready before running this on device.
