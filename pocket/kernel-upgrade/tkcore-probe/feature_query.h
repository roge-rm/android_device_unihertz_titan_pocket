/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TP_TKCORE_FEATURE_QUERY_H
#define TP_TKCORE_FEATURE_QUERY_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Read the four-byte local driver feature mask only. Never starts a TA/session. */
#define TP_TKCORE_QUERY_FEATURE _IOR('t', 183, uint32_t)
_Static_assert(TP_TKCORE_QUERY_FEATURE == 0x800474b7UL, "Stock feature-query ABI");
enum tp_tkcore_query_stage {
    TP_TKCORE_QUERY_EXPECTED_DEVICE,
    TP_TKCORE_QUERY_PATH,
    TP_TKCORE_QUERY_OPEN,
    TP_TKCORE_QUERY_FD,
    TP_TKCORE_QUERY_IOCTL,
    TP_TKCORE_QUERY_CLOSE,
    TP_TKCORE_QUERY_DONE
};
struct tp_tkcore_query_result {
    enum tp_tkcore_query_stage stage;
    int error_number;
    uint32_t feature_flags;
};

/* expected_device must come from /sys/class/misc/tkcoredrv/dev in this boot.
 * The parent init owns devtmpfs and optional RAM-only node creation. This helper
 * cannot create a node, run a daemon, mount storage, mmap or issue another ioctl.
 * Count of syscalls is bounded; kernel/secure-world latency is not guaranteed.
 */
static int tp_tkcore_feature_query(dev_t expected_device,
                                  struct tp_tkcore_query_result *result)
{
    struct stat info;
    int fd, saved = 0;
    if (!result) return -EINVAL;
    memset(result, 0, sizeof(*result));
    result->stage = TP_TKCORE_QUERY_EXPECTED_DEVICE;
    if (!expected_device) { result->error_number = EINVAL; return -EINVAL; }
    result->stage = TP_TKCORE_QUERY_PATH;
    if (lstat("/dev/tkcoredrv", &info)) {
        result->error_number = errno; return -result->error_number;
    }
    if (!S_ISCHR(info.st_mode) || info.st_rdev != expected_device) {
        result->error_number = ENODEV; return -ENODEV;
    }
    result->stage = TP_TKCORE_QUERY_OPEN;
    fd = open("/dev/tkcoredrv", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { result->error_number = errno; return -result->error_number; }
    result->stage = TP_TKCORE_QUERY_FD;
    if (fstat(fd, &info)) saved = errno;
    else if (!S_ISCHR(info.st_mode) || info.st_rdev != expected_device) saved = ENODEV;
    else {
        result->stage = TP_TKCORE_QUERY_IOCTL;
        if (ioctl(fd, TP_TKCORE_QUERY_FEATURE, &result->feature_flags)) saved = errno;
    }
    enum tp_tkcore_query_stage failed_stage = result->stage;
    if (close(fd) && !saved) { saved = errno; failed_stage = TP_TKCORE_QUERY_CLOSE; }
    result->error_number = saved;
    result->stage = saved ? failed_stage : TP_TKCORE_QUERY_DONE;
    return -saved;
}
#endif
