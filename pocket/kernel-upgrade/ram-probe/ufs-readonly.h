// SPDX-License-Identifier: GPL-2.0-only
// Bounded userspace block reads only. UFS kernel initialization is not read-only.
#ifndef POCKET_UFS_READONLY_H
#define POCKET_UFS_READONLY_H
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef void (*tpufs_report_fn)(const char *);

static int tpufs_path(char *out, size_t length, const char *root,
                      const char *name, const char *suffix)
{
    int n = snprintf(out, length, "%s/%s%s", root, name, suffix);
    return n >= 0 && (size_t)n < length ? 0 : -1;
}

static int tpufs_name(const char *name)
{
    size_t length = strnlen(name, 32);
    if (!length || length == 32 || name[0] == '.') return 0;
    for (size_t i = 0; i < length; ++i)
        if (!isalnum((unsigned char)name[i]) && name[i] != '_' && name[i] != '-') return 0;
    return 1;
}

// Truncation is a failure for numeric attributes, rather than accepting a prefix.
static int tpufs_attribute(const char *path, char *out, size_t length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, length);
    int saved = errno;
    close(fd);
    errno = saved;
    if (n < 0 || (size_t)n >= length) return -1;
    out[n] = 0;
    return 0;
}

static int tpufs_uint(const char *text, unsigned long long *number)
{
    if (!isdigit((unsigned char)*text)) return -1;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno) return -1;
    while (isspace((unsigned char)*end)) ++end;
    if (*end) return -1;
    *number = value;
    return 0;
}

static int tpufs_device_number(const char *text, dev_t *number)
{
    char *end;
    if (!isdigit((unsigned char)*text)) return -1;
    errno = 0;
    unsigned long maj = strtoul(text, &end, 10);
    if (errno || *end++ != ':' || !isdigit((unsigned char)*end)) return -1;
    char *tail;
    errno = 0;
    unsigned long min = strtoul(end, &tail, 10);
    if (errno || maj > UINT_MAX || min > UINT_MAX) return -1;
    while (isspace((unsigned char)*tail)) ++tail;
    if (*tail) return -1;
    dev_t result = makedev(maj, min);
    if (major(result) != maj || minor(result) != min) return -1;
    *number = result;
    return 0;
}

static int tpufs_block_identity(const struct stat *info, dev_t expected)
{
    return S_ISBLK(info->st_mode) && info->st_rdev == expected;
}

// Only the canonical platform HCI path can establish ownership. A matching
// substring (or a class symlink outside that subtree) is never sufficient.
static int tpufs_owned(const char *controller, const char *block)
{
    size_t length = strlen(controller);
    const char *base = strrchr(controller, '/');
    if (!base || strcmp(base + 1, "11270000.ufshci")) return 0;
    if (strncmp(controller, block, length) || block[length] != '/') return 0;
    const char *marker = strstr(block + length, "/block/");
    return marker && marker[7] && !strchr(marker + 7, '/');
}

struct tpufs_read_result { ssize_t bytes; int error, mbr, gpt; };

static struct tpufs_read_result tpufs_read_signature(int fd)
{
    unsigned char bytes[1024];
    struct tpufs_read_result result = {0};
    // A single bounded pread: short reads are reported and never filled/retried.
    result.bytes = pread(fd, bytes, sizeof(bytes), 0);
    if (result.bytes < 0) { result.error = errno; return result; }
    result.mbr = result.bytes >= 512 && bytes[510] == 0x55 && bytes[511] == 0xaa;
    result.gpt = result.bytes >= 520 && !memcmp(bytes + 512, "EFI PART", 8);
    memset(bytes, 0, sizeof(bytes));
    return result;
}

// The fstat override is only for host tests with regular synthetic block files.
#ifndef TPUFS_FSTAT
#define TPUFS_FSTAT fstat
#endif

static int tpufs_scan(const char *sysroot, const char *devroot,
                       int read_blocks, tpufs_report_fn report)
{
    char path[PATH_MAX], controller[PATH_MAX], classes[PATH_MAX];
    if (tpufs_path(path, sizeof(path), sysroot,
                   "bus/platform/devices/11270000.ufshci", "") ||
        !realpath(path, controller)) return 0;
    if (tpufs_path(classes, sizeof(classes), sysroot, "class/block", "")) return 0;
    DIR *directory = opendir(classes);
    if (!directory) return 0;
    unsigned inspected = 0, found = 0;
    struct dirent *entry;
    while (inspected++ < 256 && found < 32 && (entry = readdir(directory))) {
        const char *name = entry->d_name;
        char block[PATH_MAX], text[128], model[49] = "unavailable";
        if (!tpufs_name(name) || tpufs_path(path, sizeof(path), classes, name, "") ||
            !realpath(path, block) || !tpufs_owned(controller, block)) continue;
        struct stat info;
        if (tpufs_path(path, sizeof(path), block, "partition", "")) continue;
        errno = 0;
        if (!lstat(path, &info) || errno != ENOENT) continue;
        dev_t expected;
        if (tpufs_path(path, sizeof(path), block, "dev", "") ||
            tpufs_attribute(path, text, sizeof(text)) || tpufs_device_number(text, &expected)) continue;
        unsigned long long sectors;
        if (tpufs_path(path, sizeof(path), block, "size", "") ||
            tpufs_attribute(path, text, sizeof(text)) || tpufs_uint(text, &sectors) || !sectors) continue;
        if (!tpufs_path(path, sizeof(path), block, "device/model", "") &&
            !tpufs_attribute(path, text, sizeof(text))) {
            size_t i;
            for (i = 0; i < sizeof(model)-1 && text[i] && text[i] != '\n'; ++i)
                model[i] = text[i] >= 32 && text[i] <= 126 ? text[i] : '?';
            model[i] = 0;
        }
        char message[256];
        snprintf(message, sizeof(message), "ufs-ro name=%.31s sectors512=%llu model=%.48s", name, sectors, model);
        report(message);
        ++found;
        if (!read_blocks) continue;
        if (tpufs_path(path, sizeof(path), devroot, name, "")) continue;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) {
            snprintf(message, sizeof(message), "ufs-ro name=%.31s open_error=%d", name, errno);
            report(message); continue;
        }
        if (TPUFS_FSTAT(fd, &info) || !tpufs_block_identity(&info, expected)) {
            report("ufs-ro rejected device-node identity; no block read");
            close(fd); continue;
        }
        struct tpufs_read_result result = tpufs_read_signature(fd);
        close(fd);
        snprintf(message, sizeof(message), "ufs-ro name=%.31s read_bytes=%zd read_error=%d mbr=%d gpt512=%d",
                 name, result.bytes, result.error, result.mbr, result.gpt);
        report(message);
    }
    closedir(directory);
    return (int)found;
}

static void tpufs_worker(const char *sysroot, const char *devroot,
                          int read_blocks, tpufs_report_fn report)
{
    // Wait for initial async SCSI scan, then leave up to five more seconds for
    // other LUNs before one final bounded enumeration. No repeated block reads.
    for (unsigned second = 0; second < 20; ++second) {
        if (tpufs_scan(sysroot, devroot, 0, report)) {
            sleep(5);
            (void)tpufs_scan(sysroot, devroot, read_blocks, report);
            report("ufs-ro scan complete; userspace block workload ended");
            return;
        }
        sleep(1);
    }
    report("ufs-ro no qualifying whole UFS block devices within scan deadline");
}

// Call only AFTER the existing independent return timer is armed. PID1 returns
// immediately and continues serving USB. A stalled worker cannot block either.
static int tpufs_start(const char *sysroot, const char *devroot,
                        int read_blocks, tpufs_report_fn report)
{
    pid_t supervisor = fork();
    if (supervisor < 0) { report("ufs-ro supervisor fork failed"); return -1; }
    if (supervisor) return 0;
    // PID1 ignores SIGCHLD. Reset it here so our worker remains waitable and
    // its PID cannot be recycled before the supervisor decides to terminate it.
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) { report("ufs-ro signal reset failed"); _exit(1); }
    pid_t worker = fork();
    if (worker < 0) { report("ufs-ro worker fork failed"); _exit(1); }
    if (!worker) { tpufs_worker(sysroot, devroot, read_blocks, report); _exit(0); }
    for (unsigned second = 0; second < 30; ++second) {
        int status;
        pid_t done = waitpid(worker, &status, WNOHANG);
        if (done == worker) {
            if (!WIFEXITED(status) || WEXITSTATUS(status)) report("ufs-ro worker exited abnormally");
            _exit(0);
        }
        if (done < 0 && errno != EINTR) {
            // Ownership is uncertain after a failed wait; never kill a stale PID.
            report("ufs-ro wait failed; leaving worker to independent reboot timer");
            _exit(1);
        }
        sleep(1);
    }
    report("ufs-ro 30-second budget expired; terminating worker without blocking wait");
    kill(worker, SIGKILL);
    _exit(1);
}
#endif
