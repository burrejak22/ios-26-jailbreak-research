# AppleAVE2 Competitive Landscape (Nov 2026)

## Credited Teams in the 26.7/26.7.2 Patch Batch

### iOS 26.7 (Sept 2026, advisory 149041)
- **CVE-2026-65410** — Calif.io + Claude/Anthropic Research. "Improved checks." AI-assisted.
- **CVE-2026-84616** — Peter Malone. Type confusion in AVEVideoEncoder.
- **CVE-2026-84607** — Ruslan Dautov. Mid-session encoder-type race → kernel code execution from sandbox.

### iOS 26.7.2 (Oct 2026, advisory 149227) — the validation batch
- **CVE-2026-112705** — Calif.io (Marco Schmitt, Andrey Chernykh, Josh Maine). OOB write.
- **CVE-2026-112689** — Franco Belman, Blackwing Intelligence. "Unexpected system termination or corrupt kernel memory."
- **CVE-2026-112470/112469/112468** — Hcamael + 鱼哥@aipy. OOB writes, "corrupt kernel memory."
- **CVE-2026-112466** — Hcamael + 鱼哥@aipy. OOB read.

## Key Public Campaigns

### Calif.io
- 38+ bugs reported to Apple. AI assembly line using Claude Mythos Preview.
- Five-day timeline from "no bugs" to working macOS kernel exploit.
- Heavy coordination with Apple (Apple Park meetings), disclosure withheld until fixes ship.
- Published exploitation challenge for M5 kernel memory corruption.

### Ping-2o/panicIDK (public GitHub)
- Same driver, same general class (OOB write via VT properties).
- Trigger: NumberOfTemporalLayers (NTL=16464) — single-slot write into pcaSurfacePool[0].
- Write is teardown-scheduled: AVE_Client_Destroy → UninitSurfacePool → AVE_SurfacePool::Uninit.
- Fingerprint: FAR=0x59, x19=1, PC at AppleAVE2+0xDA78.
- Ranks as CVE-2026-112705 (Calif.io's).
- Key note: 27.2 fix is gate-only — vulnerable write loops unchanged, just validation added.

### Frollir/avetemporalpoc
- NTL panic reproduction on iPhone 17 Pro, iOS 27.0.1.
- NTL=16463 panics, 16462 survives.

## Our Position

### What's distinct about our approach
1. **DMA-based write, not software OOB** — firmware writes through stale DART mappings via AXI_ID 0xc0. Entirely different crash signature (DART PTE invalid vs CPU data abort).
2. **AlphaLayerID=255 trigger** — not NumberOfTemporalLayers. Different property, different validation gap.
3. **Deferred timing** — ~160s deferred fire window, teardown-coupled but asynchronous.
4. **PTE determinism** — cross-boot PTE band {0x1c4, 0x1fb, 0x20b} in coded-output buffer region.

### Strategic assessment
- **Bounty**: reduced odds for the trigger alone (likely in the batch), but DMA/DART mechanism may be distinct enough for a separate CVE. Emphasis on hardware-mediated write vs software OOB.
- **Jailbreak**: odds UP. On unfixed 26.6.2, no gates to bypass. panicIDK's model validates our teardown-scheduled write timing. Historical playbook (IOKit methods 6/7, clientbuf chain) provides a second path.
- **Version ceiling**: 26.7.2+ has the validation gates. Stay on 26.6.2.

## Historical AVE2 Exploitation (reference)
- CVE-2019-8795: AppleAVE2 bounds → controlled vcall/arbitrary kfree (Project Zero).
- ziVA era: direct IOKit access needed sandbox escape first; now videocodecd mediates VT but AppleAVE2UserClient may be directly openable.
- Jamf writeup: IOKit external methods 6 (SetSessionSettings) and 7 (encode clientbuf) — IOSurface loading into kernel linked list → multiple security flaws → code execution.
- IOSurface fake-object spray (Liang Chen/Pangu): standard reallocation technique after controlled free.

## Parallel Track Candidates
1. **Mode A (primary)**: DART clone-reclaim — already built, ready to run.
2. **IOKit Method 6/7**: SetSessionSettings corruption path. Deterministic, no timing race. Requires probing if AppleAVE2UserClient methods are reachable from the sandboxed app on 905.40.1.
3. **CVE-2026-84607 race**: mid-session eEncType mutation. Known soft spot, not yet tested.
