# AVE2 Wire Format Reference — kext 905.40.1

**Source:** eddinos2/CVE-2026-64747, aquarat/apple-m-series-ave-driver
**Applies to:** iPhone18,1 iOS 26.6.2, AppleAVE2 905.40.1

## IOKit Selector Table

| sel | func | structIn | structOut | role |
|-----|------|----------|-----------|------|
| 1 | FUN_642e7c → 643478 | 0x920 | 0x28 | **CREATE** (IO_Open) |
| 2 | FUN_643978 → 643cc8 | 0x28 | 0x20 | **DESTROY** (teardown via FUN_64b040) |
| 3 | FUN_64417c | 0x38 | 0x20 | UNKNOWN verb |
| 4 | FUN_644a38 → 645044 → 523f40 | 0x1a0a0 | 0x20 | **CONFIGURE** (IO_Prepare) |
| 5 | FUN_64150c | 0x1a0b0 | 0x150 | UNKNOWN (process?) |
| 6-10 | 642024/64283c/643054/64386c/644084 | 0x30 | 0x20 | verb family |

PAC decode quirk: `(raw & 0xffffff) | 0xfffffff008600000 + 0x4000`
IOServiceOpen type=1 for encoder client. Types 2-5 open but create fails.

## Session CREATE (sel1, 0x920 bytes)

| offset | field | validation |
|--------|-------|------------|
| +0x10/+0x18/+0x20 | s64 common params | all >= 0 |
| +0x28 | char[15] version | must == "905.40.1" |
| +0x8c | DPM config | zeros pass |
| +0xac | DLB config | *(u32*)(+0xac) <= 6, *(u32*)(+0xb0) < 3; zeros pass |
| +0x808 | u64 log index | must exceed static counter (monotonic) |
| +0x910 | s32 log level | >= 1 |
| +0x914 | s32 log count | > 0 |
| +0x918 | s32 encType | >= 1 |

Output: cookie at out+0x00 (uc+0xf8), echo in+0x08/+0x10, status at out+0x18, id at out+0x20 (uc+0xe8)

## CONFIGURE Command (sel4, 0x1a0a0 bytes)

Header at +0x00, command struct base at +0x338.

| abs offset | field | validation |
|------------|-------|------------|
| +0x10/+0x18/+0x20 | s64 common params | all >= 0 |
| +0x350 | s32 priority | (u32)(pri+100) < 0x12d |
| +0xd90 | s32 width | w*h > 0x1ffe0000 → reject |
| +0xd94 | s32 height | same |
| +0x2ffc | u32 slices | (slices-1) < 0x20 |
| +0x3204 | s32 encType | if clientType==1: must equal session+0x270 |

Max extent: 0x338 + 0x19d68 = 0x1a0a0 (exactly the min input size)

## Session Object Kernel Offsets

| offset | field | source |
|--------|-------|--------|
| session+0x268 | s32 clientType | valid range 1..5 |
| session+0x270 | s32 encType | must match configure |
| session+0x274 | s32 state | must be 1 for configure |
| session+0xf8 | s32 encode-active flag | written by AVE_SetEncodeActiveState |
| session+0xa8 | completion queue | checked by SetEncodeActiveState |
| session+0x1838/+0x183c | width/height | from configure cmd+0xa58 |
| session+0xef6e0 | surface pointer table | internal surfaces |
| session+0xef3b8 | DART state struct A | |
| session+0xeed20 | DART mapper object | |
| session+0xeed28 | DART state struct B | |
| uc+0x160 | session ptr | |
| uc+0xd8 | driver backptr | |
| uc+0xe8/0xf0 | clientType/mode | cached on UC |

## Surface Architecture (from aquarat)

- 35-slot InfoSet: 19 internal + 7 "out" allocations
- Full 41-row surface-index → slot map
- Kext-allocated surfaces: linear blobs, 16 KB aligned, no geometry keys
- Coded output @ 1920x1080: 3,112,960 B; header 49,152 B
- DPB reconstruction surfaces per slot: MSB + LSB (tile-metadata) planes
- LRME scaled-luma surfaces: 1 per DPB slot
- Colocated MV buffers: 128 bytes per MB, 64-byte aligned
- Entropy buffers: 4 columns × n rows
- Source neighbor scratch: Info (256B/col), Pixel (1024B/col), Data (56B/col), FwData (64B/col)

## Internal DART Mapper Surface Categories

From FUN_0x866bd68 decompile (called by DARTMapInternalSurfaces):

| type ID | param_2 offset | count | likely role |
|---------|---------------|-------|-------------|
| 0x05 | +0x000 | 2 | state/control |
| 0x06 | +0x010 | 2×2×17 | reconstruction/reference |
| 0x0b | +0x508 | 30 | coded output pool |
| 0x0d | +0x6e8 | 2×2 | aux 1 |
| 0x0e | +0x708 | 2×2 | aux 2 |
| 0x0f | +0x728 | 2×2×17 | reference (alt set) |
| 0x10 | +0x948 | 2×7 | entropy/SEB |
| 0x11 | +0x9b8 | 2×2×17 | reference (set 3) |
| 0x12 | +0xbd8 | 1 | singleton |
| 0x15 | +0x1fe0 | 4 | LRME / low-res |
| 0x16 | +0x2000 | 4 | LRME / low-res results |
| 0x17 | +0x2020 | 4 | colocated MV |
| 0x18 | +0x2040 | 4 | source neighbor |
| 0x19 | +0x2060 | 2 | transcoded data |
| 0x1a | +0x2070 | 4×16 | source neighbor (extended) |
| 0x20 | +0x2270 | 4 | aux |
| 0x21 | +0x2290 | 1 | singleton 2 |
| 0x22 | +0x2298 | 4 | aux |
| 0x23 | +0x22b8 | 2×8 | aux (extended) |

## Return Codes

| value | meaning |
|-------|---------|
| 0xe00002c2 | kIOReturnBadArgument |
| 0xe00002d9 | kIOReturnNotAttached |
| 0xfffffc17 | -1001 clamp/gate hit |
| 0xfffffc0d | wrong state (no session) |
| 0xfffffc09 | version mismatch / firmware cmd error |
| 0xfffffc18 | log index not monotonic |
| 0xfffffc03 | wrong command type |
| 0xfffffc10 | failed to find client/CHM |
| 0xfffffc16 | unknown command category |
| -17691 | firmware encode rejection (AlphaLayerID=255) |

## Key Ghidra Function Map (expanded)

| address | name | role |
|---------|------|------|
| 0x855c0cc | AVE_CHM_DARTMapSurfaces | Entry: maps external then internal |
| 0x867b238 | DARTMapExternalSurfaces | 4 fixed surfaces, bitmask i=0..3 |
| 0x867b684 | DARTUnmapExternalSurfaces | Mirror of map |
| 0x867b8d4 | DARTMapInternalSurfaces | Driver-allocated, stride 0x3bac0 |
| 0x866bd68 | FUN_0x866bd68 | Full internal surface DART mapper |
| 0x865b474 | FUN_0x865b474 | DVA accessor: surface+0x98 + offset |
| 0x85ce220 | AVE_EncodeSubmit_WithCleanup | Top-level encode submit |
| 0x85cd990 | FUN_0x85cd990 | Encode preparation (HwCMap dispatch) |
| 0x859da10 | FUN_0x859da10 | HW submit (channel readiness) |
| 0x860587c | AVE_ISR_ReceiveCommandDone | ISR: command completion handler |
| 0x8603cd8 | AVE_ProcessEncodeOutput | Output surface readback |
| 0x86055f0 | AVE_ProcessOutputData_Dispatch | Dispatch by type (2=encode) |
| 0x869f0f8 | FUN_0x869f0f8 | Frame number verify + size write |
| 0x86109f0 | FUN_0x86109f0 | Encode channel surface dispatch |
| 0x85ca838 | AVE_SetEncodeActiveState | Sole writer of session+0xf8 |
| 0x86b41f0 | AVE_UC_EncodeStartStop | IOUserClient start/stop |
| 0x86b45d4 | AVE_UC_PowerEvent | Power handler |
| 0x85cabf4 | AVE_EncodeCycle_Cleanup | Cleanup on encode cycle |
| 0x85ccd48 | AVE_EncodeSubmit_TriggerCleanup | Post-submit cleanup trigger |
| 0x860f318 | AVE_EncodeChannel_Service | Channel service |
| 0x860a3c0 | AVE_ChannelService_DARTUnmap | Channel DART unmap |
| 0x8631064 | AVE_IPC_FreeCommandSlot | Free IPC command slot |
| 0x86b2e0c | AVE_ClientClose | Client close handler |
| 0x85c9820 | AVE_PerClientCleanup_DARTUnmap | Per-client DART cleanup |
