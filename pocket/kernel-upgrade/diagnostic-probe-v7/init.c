// SPDX-License-Identifier: GPL-2.0-only
// Combined v7: v6 probes (UFS reads, feature query, watchdog pinger) with the MTU3 USB 2.0 device mode.
// The kernel configures UFS and negotiates secure SHM; the boot is not read-only.
#define _GNU_SOURCE
#include <linux/watchdog.h>
#include <sys/ioctl.h>
#include <time.h>
#include "../ram-probe/ufs-readonly.h"
#include "../tkcore-probe/feature_query.h"
#define PROBE_LABEL "TP510-RAM-V7"
#define PROBE_PRODUCT "Titan Pocket 5.10 RAM diagnostic v7"
#define PROBE_RETURN_SECONDS 150
// Pinging stops this long after init starts, 30 s past the return timer, so
// the watchdog still resets the phone (about one timeout later) if the timer's
// restart never happens.
#define PROBE_WATCHDOG_SECONDS (PROBE_RETURN_SECONDS + 30)
#define PROBE_WORKLOAD "RAM diagnostic: bounded whole-UFS header reads; no filesystem mounts, writes or TA sessions."
static void report(const char *message);

static double seconds_since(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) + (now.tv_nsec - start->tv_nsec) / 1e9;
}

// Opens the boot-adopted watchdog before the core's open deadline and keeps it
// alive. Never writes the magic close character, so the watchdog stays armed.
static void watchdog_pinger(void)
{
    pid_t child = fork();
    if (child < 0) { report("watchdog fork failed; hardware watchdog stays unpinged"); return; }
    if (child) return;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char text[64], message[160];
    dev_t expected;
    int fd = -1;
    for (int attempt = 0; attempt < 10 && fd < 0; attempt++) {
        if (attempt) sleep(1);
        if (tpufs_attribute("/sys/class/watchdog/watchdog0/dev", text, sizeof(text)) ||
            tpufs_device_number(text, &expected)) continue;
        // devtmpfs supplies the node. Never create a fallback guessed device.
        int candidate = open("/dev/watchdog0", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat info;
        if (candidate < 0) continue;
        if (fstat(candidate, &info) || !S_ISCHR(info.st_mode) || info.st_rdev != expected) {
            close(candidate);
            report("watchdog node does not match sysfs; not opened");
            _exit(1);
        }
        fd = candidate;
    }
    if (fd < 0) { report("watchdog0 not available; boot open deadline applies"); _exit(1); }
    int timeout = 0;
    if (ioctl(fd, WDIOC_GETTIMEOUT, &timeout) || timeout < 3) timeout = 3;
    unsigned interval = (unsigned)timeout / 3;
    snprintf(message, sizeof(message), "watchdog opened timeout=%d s ping=%u s until %d s after init",
             timeout, interval, PROBE_WATCHDOG_SECONDS);
    report(message);
    unsigned failures = 0;
    while (seconds_since(&start) < PROBE_WATCHDOG_SECONDS) {
        if (ioctl(fd, WDIOC_KEEPALIVE, 0) && failures++ < 3) {
            snprintf(message, sizeof(message), "watchdog keepalive failed: %s", strerror(errno));
            report(message);
        }
        unsigned remaining = interval;
        while (remaining) remaining = sleep(remaining);
    }
    report("watchdog pinging stopped; hardware watchdog will reset the phone");
    for (;;) pause();
}

static void combined_probes(void)
{
    watchdog_pinger();
    (void)tpufs_start("/sys", "/dev", 1, report);
    pid_t child = fork();
    if (child < 0) { report("tk-query fork failed"); return; }
    if (child) return;
    char text[64], message[160];
    dev_t expected;
    if (tpufs_attribute("/sys/class/misc/tkcoredrv/dev", text, sizeof(text)) ||
        tpufs_device_number(text, &expected)) {
        report("tk-query no valid misc device in this boot; no ioctl"); _exit(1);
    }
    // devtmpfs supplies the node. Never create a fallback guessed device.
    struct tp_tkcore_query_result result;
    int status = tp_tkcore_feature_query(expected, &result);
    snprintf(message, sizeof(message), "tk-query status=%d stage=%d errno=%d flags=0x%08x",
             status, (int)result.stage, result.error_number, result.feature_flags);
    report(message);
    _exit(status ? 1 : 0);
}
#define PROBE_AFTER_MOUNTS() combined_probes()
#include "../ram-probe/init.c"
