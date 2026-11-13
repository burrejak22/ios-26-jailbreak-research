# Untethered Jailbreak Requirements — iOS 26.6.2, iPhone 17 Pro (A19)

**Date:** 2026-11-12  
**Target:** iPhone 17 Pro (iPhone18,1, A19/t8150, arm64e)  
**iOS:** 26.6.2 (build 23G90)

---

## What "Untethered" Means on Modern iOS

An **untethered jailbreak** survives device reboots without any host computer interaction. After power-cycling, the jailbreak payload re-executes automatically during the boot process, maintaining root access and code execution.

This is the hardest class of jailbreak. The alternatives are:
- **Tethered:** Requires re-exploitation from a host computer on every reboot
- **Semi-tethered:** Requires running an app on-device after every reboot to re-jailbreak
- **Semi-untethered:** Same as semi-tethered but the re-exploitation app is on-device (e.g., Dopamine, unc0ver)

**Why untethered is exceptionally hard on iOS 26:** Apple has layered 6+ independent barriers that all need bypassing for persistence. No public untethered jailbreak has been demonstrated for iOS 26.x on A15+ hardware. The only claimed untethered JB is Calif.io's demo on iOS 27.0.1 (October 2026, Hexacon), which has not been published.

---

## iOS 26 Boot Chain — Barriers to Persistence

### Layer 1: Secure Boot (ROM → iBoot → Kernel)

```
SecureROM (immutable) → LLB → iBoot → kernelcache → /sbin/launchd
     │                    │       │        │
     └── ROM CA key       │       │        └── Trust cache verified
                          │       └── SSV root hash verified  
                          └── Img4 signature verified at each stage
```

**What it means:** Every boot stage cryptographically verifies the next. The ROM contains Apple's root CA public key. An unsigned or modified kernel will not boot. On A19, the chain includes:
- **SecureROM** — Immutable, in silicon. Verifies LLB.
- **LLB (Low-Level Bootloader)** — Verifies iBoot
- **iBoot** — Verifies the kernelcache AND the SSV seal
- **Static Trust Cache** — Hashes of every allowed executable, checked before any binary runs

**Bypass requirement:** Either compromise a boot stage (iBoot exploit, extremely rare) or find a way to execute after the verified kernel boots without modifying the boot chain.

**Note on usbliter8:** A BootROM exploit for A12/A13 was published June 2026 by Paradigm Shift. This does NOT affect A19 (iPhone 17 Pro). Our device is immune to BootROM attacks unless a new ROM bug is found.

### Layer 2: Signed System Volume (SSV)

The root filesystem (`/`) is a **sealed, immutable APFS snapshot** verified by a Merkle tree of SHA-256 hashes. The root hash (seal) is signed by Apple and checked by iBoot.

**Strings from 26.6.2 kernel confirming SSV enforcement:**
```
ssv-seal-broken
Unable to find entry in sealed submap @%s:%d
```

**What this means for persistence:**
- Cannot modify `/System`, `/usr`, `/bin`, `/sbin`, or any OS file
- Cannot add a launch daemon plist to `/Library/LaunchDaemons/`
- Cannot replace `/sbin/launchd` or any boot binary
- Any modification breaks the seal → device enters recovery mode on reboot

**Bypass requirement:** Either:
1. Find a way to mount a modified system volume with a valid seal (requires Apple's signing key — impossible)
2. Avoid the system volume entirely — persist in writable partitions

### Layer 3: SPTM + TXM (replaces PPL on A15+/M2+)

On A19 (iPhone 17 Pro), the Secure Page Table Monitor (SPTM) and Trusted Execution Monitor (TXM) replace the older Page Protection Layer (PPL):

- **SPTM** runs at a HIGHER privilege than the kernel. Controls page tables, memory permissions, and the kernel allocator backing store.
- **TXM** enforces code-signing and execution policy at a lower privilege than SPTM but separate from the kernel.
- **MIE (Memory Integrity Enforcement)** — NEW on A19. Comprehensive memory safety defense protecting the kernel allocator's backing store and tag storage.

**What this means for persistence:**
- Kernel code pages are immutable at runtime (KTRR/SPTM)
- Cannot patch kernel functions in memory
- Cannot load unsigned kernel extensions
- Page table modifications require SPTM cooperation
- Even with kernel R/W, cannot directly execute arbitrary kernel code

**Bypass requirement:** Either:
1. SPTM bypass (hardware-level, extremely rare — The Apple Wiki lists very few)
2. Data-only kernel attack that doesn't require code execution
3. TXM bypass to load custom trust cache entries

### Layer 4: Trust Caches

**Strings from 26.6.2 kernel:**
```
trust_cache_init
_load_trust_cache
_load_trust_cache_with_type
_load_legacy_trust_cache
_query_trust_cache
_pmap_lookup_in_loaded_trust_caches
_pmap_lookup_in_static_trust_cache
_static_trust_cache_capabilities
_unload_trust_cache
```

Every executable on iOS must be present in a trust cache (a list of CDHashes). AMFI (Apple Mobile File Integrity) checks the trust cache before allowing any binary to execute.

**Static trust cache:** Embedded in the kernelcache, verified as part of the boot chain. Cannot be modified.
**Loaded trust caches:** Can be loaded at runtime by entitled processes. This is how Cryptex updates work.

**What this means for persistence:**
- Cannot simply drop a binary on disk and have it run
- Any persistence payload must either:
  - Be code-signed with an Apple-issued certificate
  - Be injected into an existing trust-cached process
  - Exploit the trust cache loading mechanism

### Layer 5: Cryptex System

**Strings from 26.6.2 kernel:**
```
cryptex1.boot.os
cryptex1.boot.app
cryptex1.preboot.os
cryptex1.preboot.app
cryptex1.safari-downlevel
cryptex1.generic
cryptex1.generic.supplemental
personalized.cryptex-research
personalized.ephemeral-cryptex
/private/preboot/Cryptexes
com.apple.private.cryptexd-rsr-write
```

Apple uses Cryptexes for Rapid Security Responses (RSR) — signed, mountable disk images that overlay system frameworks. They are:
- **Personalized** to each device (tied to device identity)
- **Signed** by Apple (Img4 signature)
- Mounted at `/private/preboot/Cryptexes`
- Contains separate OS and App components

**The key observation:** `personalized.cryptex-research` and `personalized.ephemeral-cryptex` suggest Apple has a research/debug cryptex mechanism. And `com.apple.private.cryptexd-rsr-write` is an entitlement for writing RSR cryptexes.

**Potential persistence vector:** If we can forge or load a custom cryptex that survives reboot, we get code execution with trust cache entries. This requires either:
1. Stealing the device's cryptex personalization keys (requires SEP compromise)
2. Exploiting `cryptexd` to load an unsigned cryptex
3. Using `cryptex-research` path if the entitlement check is weak (similar to CVE-2026-43689's missing entitlement)

### Layer 6: AMFI (Apple Mobile File Integrity)

AMFI is the kernel-side enforcement for code signing. It checks:
- Trust cache membership
- Code signature validity
- Entitlements
- Provisioning profile chain

**Our AMFI binary is identical between 26.6.2 and 26.7.2** (same size, no changes). This means any AMFI weaknesses present in 26.6.2 were NOT fixed in 26.7.2.

---

## Viable Persistence Strategies for iOS 26.6.2

Given these barriers, there are only a few viable approaches to untethered persistence:

### Strategy A: Writable Partition Persistence (Most Likely)

**Concept:** Don't touch the sealed system volume. Instead, persist in the **data partition** (`/private/var/`) which is writable and NOT sealed.

**Mechanism:**
1. After kernel exploitation, modify a file that is:
   - On the data partition (writable)
   - Read by a privileged process during early boot
   - Not integrity-checked by anything stronger than the filesystem
2. The modified file causes code execution on next boot
3. That code re-exploits the kernel using the same chain

**Candidate targets on the data partition:**
- **Configuration plists** read by system daemons at boot
- **User-installed profiles** (`/private/var/containers/Shared/SystemGroup/`)
- **Managed preferences** (`/private/var/Managed Preferences/`)
- **Cache files** that are regenerated from data-partition sources
- **`/private/preboot/`** — Preboot volume is separate from SSV

**CVE-2026-86886 role:** The TCC path traversal could be the mechanism to write to a protected location on the data partition that is normally inaccessible to apps, even with root.

**Challenge:** Even with a file written, the binary it points to must be trusted (trust cache). Solutions:
- **ROP/JOP chain** in a trusted binary (dyld, launchd) triggered by corrupted data
- **Dyld environment variable** injection (`DYLD_INSERT_LIBRARIES` — traditionally blocked on iOS, but worth testing post-kernel-exploit)
- **Corrupted preference file** causing a trusted daemon to behave unexpectedly

### Strategy B: Trust Cache Injection

**Concept:** Use kernel R/W to add our payload's CDHash to a loaded trust cache, then drop the binary on the data partition.

**Mechanism:**
1. Kernel exploit gives R/W
2. Locate loaded trust cache structures in kernel memory
3. Add our binary's CDHash to the loaded trust cache
4. Drop binary to `/private/var/`
5. Create a launch daemon plist pointing to it in writable location

**Challenge:** Trust cache modifications don't survive reboot — the static trust cache is in the kernelcache (sealed), and loaded trust caches are reloaded fresh. Need a way to reload the custom trust cache on every boot.

**Possible solution:** If we can modify the Preboot volume or inject into the cryptex loading path, the trust cache could be loaded as part of the boot sequence.

### Strategy C: Exploit Re-Triggering via Data Corruption

**Concept:** Corrupt data that is processed by a trusted binary during boot, causing the trusted binary to re-trigger the exploit chain.

**Mechanism:**
1. Place crafted data file on the data partition
2. On boot, a system daemon processes this file
3. The crafted data triggers a vulnerability in the daemon (e.g., an image parsing bug, a plist parsing bug, a database corruption)
4. The daemon now has code execution → re-runs kernel exploit → full jailbreak restored

**Best candidate:** A **format string** or **parsing bug** in a daemon that processes user-controllable data at boot time. This avoids trust cache issues because the code executes within an already-trusted process.

**Example targets:**
- `configd` processing network preferences
- `mediaserverd` processing cached media
- `backboardd` processing UI state
- `SpringBoard` processing app state
- **`notifyd`** processing notification registrations

### Strategy D: Kernel Data-Only Persistence (Advanced)

**Concept:** Don't execute code — instead, use kernel R/W to modify kernel data structures that change security policy.

**Mechanism:**
1. On each boot, trigger kernel exploit
2. Modify AMFI's in-memory enforcement flags
3. Modify sandbox policies in memory
4. Modify trust cache checks to always succeed
5. Now any binary can run unsigned

**Challenge:** Still need the initial trigger on each boot. This is "semi-untethered" unless combined with Strategy A or C for the trigger.

---

## CVE-2026-86886 Deep Dive — The Persistence Primitive

### What We Know

- **Type:** Path traversal → protected file modification
- **Impact:** App can modify protected system files
- **Credited to:** Calif.io (Huy Nguyen), Constantin Clerc, others
- **Patched in:** iOS 26.7
- **CVSS:** ~5.5
- **Connection:** Calif.io demonstrated untethered JB on iOS 27.0.1 — this CVE is likely part of their chain

### What "Protected System Files" Means

In TCC context, "protected" doesn't mean SSV-sealed. It means files protected by TCC policies:
- TCC database itself (`/private/var/db/TCC/TCC.db`)
- Location services data
- Contacts, calendars, photos databases
- Screen recording permissions
- **System Preferences/Configuration** that affect boot behavior

### Path Traversal Mechanics

TCC path traversals typically work by:
1. A symlink or path component trick that makes TCC resolve the path differently than the filesystem
2. The app asks to write to `/allowed/path/../../../protected/path`
3. TCC checks `/allowed/path` (allowed) but the kernel resolves to `/protected/path`
4. OR: A TOCTOU race between TCC's path check and the actual write

### Analysis Plan

**TCC is a userspace daemon (`tccd`)**, not in the kernel. The binary is in the dyld_shared_cache. To analyze:

1. **On Mac:** Extract `tccd` and `TCC.framework` from both 26.6.2 and 26.7.2 dyld_shared_cache
2. **BinDiff:** Compare the two versions to find the exact path validation fix
3. **Reverse engineer:** Identify the path traversal primitive
4. **Determine persistence value:** Can the path traversal write to a location that affects boot behavior?

### Extraction Script (Mac-side)

```bash
# Add to 01_extract_dyld.sh targets:
# Extract TCC framework and daemon
ipsw dyld extract "$DYLD" --dylib "TCC" --output "$OUTDIR/"
# tccd is a standalone binary, may need:
ipsw ota extract "$OTA_FILE" --pattern "*tccd*" --output "$OUTDIR/"
```

---

## Specific Chain for Untethered JB on iOS 26.6.2

### Phase 1: Initial Exploitation (one-time)

```
Chain A (preferred):
  CVE-2026-84607 (AppleAVE2) → kernel code execution
  CVE-2026-86916 (kernel UAF) → stable kernel R/W

Chain B (alternative):
  CVE-2026-112659 (WebKit) → code exec in WebContent
  CVE-2026-43689 (chroot) → sandbox escape  
  CVE-2026-86916 (kernel UAF) → kernel R/W
```

### Phase 2: Post-Exploitation Setup

With kernel R/W established:
1. **Disable AMFI** enforcement in memory (patch AMFI flags)
2. **Disable Sandbox** for our process
3. **Escalate to root** (modify process credentials in kernel)
4. **Disable SIP/SSV** runtime checks (if possible without SPTM bypass)

### Phase 3: Persistence Installation

With root + kernel R/W:
1. **CVE-2026-86886** — Write persistence payload to protected location
2. **Trust cache injection** — Add payload CDHash to loaded trust cache
3. **Boot trigger** — Create mechanism to re-execute on reboot:
   - Option A: Corrupt a plist/config on data partition read at boot
   - Option B: Modify Preboot volume cryptex loading
   - Option C: Inject into a daemon's data that triggers re-exploitation

### Phase 4: Boot-Time Re-Exploitation

On every reboot:
1. Boot trigger fires (corrupted config/data processed by trusted daemon)
2. Trusted daemon hits vulnerability → code execution
3. Code execution triggers kernel exploit (CVE-2026-84607 or similar)
4. Kernel R/W re-established
5. AMFI/sandbox/SIP disabled in memory
6. Jailbreak environment restored

---

## Open Questions Requiring Device Testing

| # | Question | How to Test | Impact |
|---|----------|-------------|--------|
| 1 | Can a sandboxed app call chroot(2) on 26.6.2? | Deploy PoC to iPhone | Validates sandbox escape |
| 2 | Does post-chroot Seatbelt path confusion work? | Chroot PoC Q2 | Validates escape primitive |
| 3 | Which IOKit selectors does AppleAVE2 expose? | IOKit probe on device | Required for kernel exploit |
| 4 | What's in `/private/preboot/Cryptexes/` on 26.6.2? | ls on jailbroken/rooted device | Persistence feasibility |
| 5 | Can `personalized.cryptex-research` be used without entitlement? | Similar to chroot test | Potential persistence vector |
| 6 | Which daemons read data-partition configs at boot? | dtrace/instruments on Mac + extrapolate | Persistence trigger targets |
| 7 | Is DYLD_INSERT_LIBRARIES blocked at kernel level or AMFI? | Test after disabling AMFI | Simplest persistence if available |
| 8 | Does CVE-2026-86886 allow writing to Preboot? | TCC binary analysis + PoC | Critical for persistence |

---

## Comparison with Calif.io's Approach

Calif.io demonstrated an untethered JB on iOS 27.0.1 at Hexacon (October 2026). What we know:
- Used bugs credited as CVE-2026-86886 (TCC path traversal) and a kernel OOB write
- Survived reboot (demonstrated live)
- Has NOT published technical details
- Plans to release kernel exploit code "within about a week" (as of late October 2026)
- Chain described as "mostly fixed" by iOS 27.2

**Implications for our 26.6.2 work:**
- CVE-2026-86886 is unpatched on 26.6.2 (patched in 26.7) — we have it
- If Calif used it for persistence, the same technique works on 26.6.2
- Their kernel OOB write is a different bug than our CVE-2026-86916/84607, but serves the same purpose
- When they publish, their persistence technique will likely be directly applicable

---

## Risk Assessment

| Factor | Level | Notes |
|--------|-------|-------|
| **SPTM bypass needed?** | MAYBE | Data-only attacks may avoid SPTM. MIE on A19 makes this harder than A15-A18. |
| **PAC bypass needed?** | YES (for code pointers) | Can potentially avoid with data-only techniques |
| **Persistence complexity** | VERY HIGH | 6 layers of protection. Untethered is the hardest part. |
| **Reliability** | MEDIUM | Logic bugs (chroot, TCC) are reliable. Memory corruption (AVE2, kernel UAF) less so. |
| **Detection risk** | LOW | Own device, local exploitation |
| **Time estimate** | 2-4 weeks for untethered persistence after initial chain works |

---

## Immediate Next Steps

1. **Deploy PoCs to iPhone** — Answer the 3 chroot questions and probe AVE2 IOKit
2. **Extract TCC binary on Mac** — From 26.6.2 dyld_shared_cache for CVE-2026-86886 analysis
3. **BinDiff TCC** — Compare 26.6.2 vs 26.7.2 to find the path traversal
4. **Kernel deep dive** — CVE-2026-86916 UAF location via Ghidra on kernelcaches
5. **Enumerate boot-time data readers** — Which daemons process writable data at boot?
6. **Monitor Calif.io publication** — Their kernel exploit and persistence technique will be directly relevant
7. **Explore cryptex-research path** — Is `personalized.cryptex-research` a viable persistence vector?
