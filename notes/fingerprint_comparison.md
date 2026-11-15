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

## What to verify
- Check if any of the 26.7.2 CVEs specifically mention DMA or DART (none do in the advisory text — all say "bounds checking" or "improved validation")
- The Hcamael quartet (CVE-2026-112470/112469/112468 OOB writes + 112466 OOB read) — their "corrupt kernel memory" language could cover DART-based writes
- File a report emphasizing the DMA/DART mechanism as distinct from software OOB
