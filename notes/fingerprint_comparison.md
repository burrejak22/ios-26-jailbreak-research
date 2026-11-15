# Panic Fingerprint Comparison: Ours vs panicIDK

## Our Panics (AlphaLayerID=255, iOS 26.6.2, kext 905.40.1)

| panic | DVA | PTE | AXI_ID | trigger | backtrace top |
|-------|-----|-----|--------|---------|---------------|
| 1 (idle) | 0x100007ecc00 | 0x1fb | 0xc0 | idle after arm | AppleT8110DART |
| 2 (idle) | 0x10000710080 | 0x1c4 | 0xc0 | idle after arm | AppleT8110DART |
| 3 (control) | 0x1000082d500 | 0x20b | 0xc0 | control run | AppleT8110DART |
| 6 (runA) | 0x1000082d500 | 0x20b | 0xc0 | teardown | AppleT8110DART |
| 7 (runB) | 0x1000082d4c0 | 0x20b | 0xc0 | teardown | AppleT8110DART |
| 8 (runC1) | 0x100007ec500 | 0x1fb | 0xc0 | idle timer | AppleT8110DART |

| A1 | ? | 0x3cc | 0xc0 | Alpha=0 clone | AppleT8110DART |
| A2 | 0x10000ef0c00 | 0x3bc | 0xc0 | Alpha=255 clone | AppleT8110DART |
| 10 (C2-EK) | 0x1000082d500 | 0x20b | 0xc0 | daemon killed, fire at T+155 | AppleT8110DART |

PTE clusters:
- **0x20b band** (panics 3, 6, 7, 10): standard arm — 4 hits, most common target
- **0x1fb band** (panics 1, 8): idle-context
- **0x3cc/0x3bc band** (A1, A2): Alpha=255 sessions — different DART mapping path
- **0x1c4** (panic 2): outlier

All AXI_ID = 0xc0 (firmware DMA write channel).
Crash site: DART hardware trap — "PTE invalid exception on write".
Backtrace: entirely in AppleT8110DART, not AppleAVE2 driver code.

| A3 (spray) | 0x1000082d1c0 | 0x20b | 0xc0 | Mode A3 spray — spray FAILED to absorb | AppleT8110DART |

PTE clusters:
- **0x20b band** (panics 3, 6, 7, 10, A3): standard arm — **5 hits**, dominant target
- **0x1fb band** (panics 1, 8): idle-context
- **0x3cc/0x3bc band** (A1, A2): Alpha=255 sessions — different DART mapping path
- **0x1c4** (panic 2): outlier

DVA sub-page analysis for PTE 0x20b panics:
- 0x1000082d500 (panics 3, 6, 10): offset 0x1500 within page
- 0x1000082d4c0 (panic 7): offset 0x14c0 within page
- 0x1000082d1c0 (A3): offset 0x11c0 within page
All within same 16K page (index 0x400020b). Firmware write offset varies by codec state.

## Mode A3 Spray Result (2026-11-15)

**SPRAY FAILED.** 20 thin (320x240 Alpha=255) + 30 fat (1920x1080 no-Alpha) sessions
did NOT re-map PTE 0x20b. Panic still occurred at the stale page.

Strong evidence for **forward-only (bump) DART allocator**: if freed pages were recycled
via free-list, 50 spray sessions should have covered PTE 0x20b. They didn't.

Implication: spray-after-free cannot cover the target. Need either:
1. Ghidra confirmation of allocator type (DARTMapInternalSurfaces)
2. Reverse approach: pre-allocate sessions, free specific ones to position the arm
   session's allocation at a controlled PTE, then spray THOSE pages
3. Alternative: exploit the deterministic PTE (0x20b) by finding what maps there
   BEFORE the arm and racing to remap it

## C2-EK Discriminator Result (2026-11-15)

**VERDICT: Fire is KEXT TIMER, not daemon-coupled. Mode A IS VIABLE.**

Timeline:
- ARM: 03:36:17, FREE: 03:38:19 (T+0), KILL WINDOW: T+25
- Daemon killed between T+121 and T+155 (videocodecd: terminatedSnapshot, 16KB resident)
- **PANIC at ~T+155** — matches ~156s fire model exactly

Interpretation:
- The ~156s fire timer is independent of videocodecd's lifecycle
- It is a kext/firmware-level timer in the DART subsystem
- Daemon can be dead and the fire still occurs on schedule
- Mode A3 spray approach is viable — only PTE coverage matters

## panicIDK Panics (NumberOfTemporalLayers, iOS 27.0, kext 913.43)

| property | FAR | x19 | crash site | backtrace |
|----------|-----|-----|------------|-----------|
| NTL=16464 | 0x59 | 1 | AppleAVE2+0xDA78 | AVE_Client_Destroy → UninitSurfacePool → AVE_SurfacePool::Uninit |

Write type: software OOB — NTL=16464 causes pcaSurfacePool[0] = 1, then teardown dereferences (1+0x58 = 0x59).
Crash site: CPU executing AVE2 driver code, data abort on dereference.

## Verdict: DIFFERENT BUG CLASS

| dimension | ours | panicIDK |
|-----------|------|----------|
| write mechanism | hardware DMA via firmware (AXI bus) | software OOB in driver (CPU) |
| crash trigger | DART PTE invalid trap (hardware MMU) | data abort on bad pointer deref (CPU) |
| crash location | AppleT8110DART (IOMMU driver) | AppleAVE2 (encoder driver) |
| faulting address | DVA in DART address space (0x10000xxxxx) | FAR=0x59 (low virtual, null-page deref) |
| register signature | no x19 pattern | x19=1 (the written value) |
| write timing | deferred: firmware DMA at next encode cycle or teardown | immediate: OOB fill during property set |
| controllability | stale descriptor targets coded-output PTE band | single-slot write, value = 1 |
| validation gap | Alpha=255 accepted, VPS latched, DART maps freed before firmware finishes | NTL not bounded, raw count used as loop limit |

Key distinction: our bug is a **hardware DMA write through stale DART mappings** — the firmware writes via AXI_ID 0xc0 to PTEs that the kernel has already freed. panicIDK's is a **software OOB in the driver's surface pool array** — the CPU writes past the end of an array. Same driver, same general area, fundamentally different primitive.

This means:
1. Our bug is likely NOT a duplicate of the panicIDK/NTL chain (CVE-2026-112705)
2. Our bug's DMA-write-through-stale-DART signature doesn't match any of the published credited fingerprints
3. The bounty may still be live for this specific trigger/mechanism
4. BUT: it could still be in the 26.7.2 "improved bounds checking" batch if Apple fixed the Alpha validation path alongside the NTL path

## Ghidra Reverse Engineering: DART Allocator (2026-11-15)

Binary: com.apple.driver.AppleAVE2, kext 905.40.1 (iOS 26.6.2)
Image base: fffffe000724a7b0, 2819 functions, AARCH64 AppleSilicon

### Pool Architecture (AVE_DART_Pool)

Each pool is a struct with **three linked lists** and a flat buffer of 0x28-byte entries:

| Offset | List | Purpose |
|--------|------|---------|
| +0x28 | Free | Virgin slots from pool creation (no IODMACommand yet) |
| +0x48 | Returned | Used-and-freed slots (IODMACommand retained for reuse) |
| +0x68 | Active | Currently mapped slots (IODMACommand in use, DMA live) |

Pool entries cycle: Free → Active → Returned → Active → Returned → ...

### Allocation Path (`FUN_fffffe000859084c`)

**The allocator IS a free-list with recycling, NOT bump-only.**

Priority order:
1. **Returned list first** (+0x48) — reuses entry AND its IODMACommand object
2. **Free list second** (+0x28) — creates new IODMACommand via `IODMACommand::withSpecification`
3. **If both empty** — returns failure; caller (`FUN_fffffe0008594228`) creates a new pool

Returned entries are preferred over virgin entries. The IODMACommand is retained across reuse.

### Deallocation Path (`FUN_fffffe0008594630`)

1. Finds which pool owns the entry (range check: `pool->buffer <= entry < pool->buffer + count * 0x28`)
2. Unlinks entry from Active list (+0x68)
3. Adds entry to Returned list (+0x48)
4. **Pool pruning**: if total_count >= initial_count × 2, destroy the LAST pool whose Active list is empty

### Two-Phase Unmap (`DARTUnmapSurface_TwoPhase`) — CORRECTED

1. `FUN_fffffe00086585b4` — **kernel-shared surface release** (bit 11 of bitmap at +0xf0).
   This is NOT the PTE invalidation — only releases a kernel mapping object at +0x80.
2. `FUN_fffffe000865874c` × 4 — **per-surface IODMACommand::clearMapping** + pool return.
   THIS is where DVAs are freed — calls `IODMACommand::clearMapping()` which tells the
   kernel IOMMU to release the DVA. Then returns the pool entry to the Returned list.
3. `FUN_fffffe0008658c30` — **DMA completion**. Checks bitmap 0xf0800 is clear (all unmapped).
   If surfaces still mapped: logs "Surface is busy", returns -0x3f8 (INCOMPLETE).
   If clear: calls `IODMACommand::complete()` + release on object at +0x78, clears bit 10.
4. `FUN_fffffe0008658eb4` — **fence release**
5. Surface object release at +0x68, clear size/state fields.

**CRITICAL TIMING HOLE**: Phase 2 (IODMACommand::clearMapping) is where the DVA is freed.
If `VTCompressionSessionInvalidate` is asynchronous, or if the IOKit user-client teardown
is deferred (e.g., JBPoC process holds the connection open), phase 2 may not have completed
during A3's spray window. The "Surface is busy" check in phase 3 confirms that the unmap
can fail partway through if surfaces are still in flight.

**IMPLICATION FOR A3 FAILURE**: The A3 spray may have run BEFORE phase 2 freed the DVAs.
If so, the IOMMU allocator never had PTE 0x20b's DVA in its free pool during the spray.
This is a timing artifact, not proof of non-recycling.

**THE BUG MECHANISM**: The firmware's DMA engine holds a stale DVA in its coded-output
descriptor. The descriptor references a DVA that was valid when the encode was submitted.
After session teardown (whenever phase 2 completes), the IOMMU frees the DVA and invalidates
the PTE. The firmware's deferred write (~156s) fires to the now-invalid PTE → DART trap.

**OPEN QUESTION**: The DVA allocator lives in IODARTFamily (separate kext in kernelcache,
not in AppleAVE2). Historic Apple IOVM allocators DO recycle — "sequential" is unproven
until IODARTFamily is decompiled. Needs extraction from kernelcache (72MB, at
`firmware/23G90__iPhone18,1/kernelcache.release.iPhone18,1`).

### Why A3 Spray Failed (Revised Understanding)

The AVE2 pool-level allocator DOES recycle entries. But the spray failed because:
- When a returned entry is reused, `IODMACommand::prepare()` asks the **kernel IOMMU** for a NEW DVA
- The kernel DART allocator assigns DVAs sequentially (forward/bump at the IOMMU level)
- Freed DVAs are NOT recycled by the kernel DART — they go into the TLB invalidation queue
- So spray sessions get NEW DVAs (higher PTE indices), not the freed PTE 0x20b

The two allocation layers:
1. **AVE2 pool** (user-space facing): free-list with recycling ← confirmed by Ghidra
2. **Kernel DART/IOMMU** (hardware facing): sequential DVA allocation ← this is what spray can't cover

### Surface Classes Mapped by DARTMapInternalSurfaces

`FUN_fffffe000866bd68` maps ~15+ surface categories with type IDs from `FUN_fffffe000869673c`:
- Types 5, 6: base surfaces (2 each, with 0x110-stride multi-plane arrays of 0x11 entries)
- Type 0xb: 30 surfaces at offset 0x508
- Types 0xd, 0xe: 2×2 surfaces at offsets 0x6e8, 0x708
- Types 0xf, 0x10: multi-plane (2×2×0x11 and 2×7) at offsets 0x728, 0x948
- Type 0x11: multi-plane (2×2×0x11) at offset 0x9b8
- Type 0x12: single surface at offset 0xbd8
- Types 0x15-0x18: 4 surfaces each at offsets 0x1fe0-0x2060
- Type 0x19: 2 surfaces at offset 0x2060
- Type 0x1a: 4×16 surfaces at offset 0x2070
- Types 0x20-0x23: 4 + 1 + 4 + 2×8 surfaces at offsets 0x2270-0x22b8

Total: ~100+ surfaces per session, each getting its own DART mapping.
This is why PTE 0x20b is deterministic — the coded-output buffer lands at a consistent index
in the DVA allocation sequence.

### Pivotal Fork: Corpus Evidence for Fire-With-Session-Alive

Panics 1, 2, 8 all occurred with the session ALIVE (Run C: "Session NOT invalidated"):

| Panic | PTE | Session State | Experiment |
|-------|-----|---------------|------------|
| 1 | 0x1fb | ALIVE | idle after arm |
| 2 | 0x1c4 | ALIVE | idle after arm |
| 8 | 0x1fb | ALIVE (Run C) | idle timer |
| 3 | 0x20b | FREED | control run |
| 6 | 0x20b | FREED | teardown |
| 7 | 0x20b | FREED | teardown |
| 10 | 0x20b | FREED | C2-EK |
| A3 | 0x20b | FREED | spray |

**Pattern**: session alive → PTE 0x1fb/0x1c4 (lower indices); session freed → PTE 0x20b.

This suggests the fire DOES happen with the session alive, but targets DIFFERENT pages.
Possible explanations:
- videocodecd daemon teardown partially unmaps some surfaces while session is alive
- Power management / screen lock causes partial DART unmap
- The firmware writes to multiple pages; the one that's unmapped depends on session state

Mode A5 will confirm this with a clean, controlled test. If panic → fire escapes session
pages, and adjacency-based grooming becomes the primary attack vector. If survive →
early panics were from daemon/PM interference, not the core fire.

### IODARTFamily DVA Allocator: IORangeAllocator (CONFIRMED)

**Source**: Ghidra headless decompilation of IODARTFamily kext from kernelcache 23G90.

The IODARTVMAllocatorGeneric class (instance vtable at 0xfffffe00081448d0) wraps an
`IORangeAllocator` (created via `func_0xfffffe000ae0a3b0`, stored at object offset +0x48).

**Allocation path** (vtable+0x80 → FUN_fffffe0009b8a90c):
1. Calls `IORangeAllocator::allocate` (vtable+0xb0) with requested page count
2. Returns start page index of allocated range
3. Creates an IODARTVMSpace object to track the mapping
4. On failure: "VM exhausted" — DVAs on a finite range, first-fit

**Free path** (vtable+0x98 → FUN_fffffe0009b8aedc):
1. Reads start page (VMSpace+0x50) and count (VMSpace+0x54) from the freed mapping
2. Destroys the VMSpace tracking object
3. Calls `IORangeAllocator::deallocate` (vtable+0xc0) with (startPage, pageCount)
4. Pages return to the free pool for reuse

**IORangeAllocator properties** (well-known IOKit class):
- Sorted free-list of (start, length) ranges
- First-fit allocation: walks the list, takes the first range >= requested size
- Coalescing on free: merges adjacent free ranges
- **DVAs ARE recyclable** — freed pages go back to the pool

**A3 spray failure root cause CONFIRMED: Phase-2 timing hole**

The spray sessions' `IORangeAllocator::allocate` calls ran BEFORE the armed session's
Phase 2 (`IODMACommand::clearMapping` → `IODARTVMAllocatorGeneric::releaseVMSpace` →
`IORangeAllocator::deallocate`) freed the DVA pages. The freed DVAs were still allocated
in the range allocator when the spray ran, so the spray got fresh DVAs from the end of
the range instead.

**Fix for A3**: Force Phase-2 completion (confirmed teardown + sleep), then spray
same-class sessions. IORangeAllocator first-fit will recycle the exact freed range.

**Key function addresses (IODARTFamily)**:
| Function | Address | Role |
|----------|---------|------|
| IODARTVMAllocatorGeneric::allocate | fffffe0009b8a90c | vtable+0x80: allocate via IORangeAllocator |
| IODARTVMAllocatorGeneric::allocFromReserved | fffffe0009b8abcc | vtable+0x88: allocate from reserved range |
| IODARTVMAllocatorGeneric::releaseVMSpace | fffffe0009b8aedc | vtable+0x98: free DVAs back to IORangeAllocator |
| IODARTVMAllocatorGeneric::findVMSpace | fffffe0009b8e19c | vtable+0xa8: lookup VMSpace by DVA |
| Instance vtable | fffffe00081448d0 | 32 entries, PAC-signed IA |
| IORangeAllocator (create) | fffffe000ae0a3b0 | Kernel IOKit range allocator factory |

### Implication for Co-Tenancy (Mode A4)

The co-tenancy hypothesis is STILL valid but now PROVEN at the IOMMU level:
- IORangeAllocator first-fit means freed DVAs are recycled in order
- A victim session created AFTER teardown gets the exact freed DVA range
- If the victim's coded-output surface reuses the armed session's DVA pages,
  stale firmware DMA writes corrupt the victim's buffer → controlled write
- The timing fix: ensure Phase-2 completes (IODMACommand::clearMapping finishes)
  BEFORE creating the victim session

The sub-page offset evidence supports this: all PTE 0x20b panics show different byte offsets
within the same page (0x11c0, 0x14c0, 0x1500), suggesting the firmware writes to a specific
offset within a page-aligned allocation.

### Key Function Addresses

| Function | Address | Role |
|----------|---------|------|
| DARTMapInternalSurfaces | fffffe000867b8d4 | Top-level: map all internal surfaces |
| FUN_fffffe000866bd68 | fffffe000866bd68 | Iterator: map each surface class |
| DARTMapSurface | fffffe00086702bc | Per-surface: lock, check, delegate |
| AVE_DART_MapSurface_Impl | fffffe000865a84c | Per-surface: IODMACommand map |
| AVE_IODMACommand_MapSurface | fffffe0008593a9c | IODMACommand: prepare + get DVA |
| DARTUnmapSurface | fffffe0008670484 | Per-surface: unmap |
| DARTUnmapSurface_TwoPhase | fffffe0008658064 | Full teardown: PTE invalidate + cleanup |
| FUN_fffffe000865874c | fffffe000865874c | Per-surface unmap impl |
| AVE_DART_Pool_Create | fffffe00085902bc | Pool: allocate struct + entries |
| AVE_DART_Pool_Destroy | fffffe00085904b0 | Pool: release IODMACommands + free |
| FUN_fffffe0008594228 | fffffe0008594228 | Pool: get entry (allocate from pool) |
| FUN_fffffe0008594630 | fffffe0008594630 | Pool: return entry (dealloc to pool) |
| FUN_fffffe000859084c | fffffe000859084c | Pool: try-get from single pool |
| FUN_fffffe0008594a78 | fffffe0008594a78 | Full unmap: IODMACommand release + pool return |

## What to verify
- Check if any of the 26.7.2 CVEs specifically mention DMA or DART (none do in the advisory text — all say "bounds checking" or "improved validation")
- The Hcamael quartet (CVE-2026-112470/112469/112468 OOB writes + 112466 OOB read) — their "corrupt kernel memory" language could cover DART-based writes
- File a report emphasizing the DMA/DART mechanism as distinct from software OOB
