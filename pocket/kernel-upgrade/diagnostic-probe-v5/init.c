// SPDX-License-Identifier: GPL-2.0-only
// Combined v5: independent USB/timer, bounded UFS reads, local TK feature query.
// The kernel configures UFS and negotiates secure SHM; the boot is not read-only.
#define _GNU_SOURCE
#include "../ram-probe/ufs-readonly.h"
#include "../tkcore-probe/feature_query.h"
#define PROBE_LABEL "TP510-RAM-V5"
#define PROBE_PRODUCT "Titan Pocket 5.10 RAM diagnostic v5"
#define PROBE_RETURN_SECONDS 150
#define PROBE_WORKLOAD "RAM diagnostic: bounded whole-UFS header reads; no filesystem mounts, writes or TA sessions."
static void report(const char *message);
static void combined_probes(void)
{
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
