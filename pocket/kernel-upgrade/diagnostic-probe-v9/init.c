// SPDX-License-Identifier: GPL-2.0-only
// Combined v9: v8's probes (read-only partition hashes, runtime reserved memory,
// ACM input hashing, USB connection state and I2C chip ID reads) plus the aw9523
// keyboard ID on i2c4, with one reset pulse on GPIO 178 only after a NACK. Each
// probe runs in a bounded child. The kernel configures UFS and negotiates secure SHM; the boot
// is not read-only.
#define _GNU_SOURCE
#include <linux/gpio.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/watchdog.h>
#include <sys/ioctl.h>
#include <time.h>
#include "../ram-probe/ufs-readonly.h"
#include "../tkcore-probe/feature_query.h"
#include "probes.h"
#define PROBE_LABEL "TP510-RAM-V9"
#define PROBE_PRODUCT "Titan Pocket 5.10 RAM diagnostic v9"
#define PROBE_RETURN_SECONDS 300
// Pinging stops this long after init starts, 30 s past the return timer, so
// the watchdog still resets the phone (about one timeout later) if the timer's
// restart never happens.
#define PROBE_WATCHDOG_SECONDS (PROBE_RETURN_SECONDS + 30)
// Partition reads stop here so the last log lines land well before the return timer.
#define PROBE_HASH_DEADLINE_SECONDS 250
#define PROBE_HASH_BUDGET_SECONDS 260
#define PROBE_RMEM_BUDGET_SECONDS 20
// USB state is sampled once per second until shortly before the return timer.
#define PROBE_CABLE_SECONDS (PROBE_RETURN_SECONDS - 5)
// ACM input is hashed for this long after the first received byte.
#define PROBE_ECHO_SECONDS 60
// Adapter lookup waits up to this long; each read is bounded by the adapter's own 2 s timeout.
#define PROBE_I2C_WAIT_SECONDS 10
#define PROBE_I2C_BUDGET_SECONDS 60
#define PROBE_WORKLOAD "RAM diagnostic: bounded whole-UFS header reads, read-only partition hashes, I2C ID reads (register pointer then read), aw9523 reset pulse only after a NACK; no filesystem mounts, storage writes or TA sessions."
static void report(const char *message);

static int echo_hook(const char *data, ssize_t count);
static int echo_timeout(void);
static void echo_tick(void);
#define PROBE_SERIAL_INPUT(data, count) echo_hook((data), (count))
#define PROBE_POLL_TIMEOUT() echo_timeout()
#define PROBE_POLL_TICK() echo_tick()

static struct timespec probe_start;

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

// Supervisor plus worker, as tpufs_start does. PID1 returns at once; the
// supervisor kills the worker when its budget runs out.
static void bounded_child(const char *name, unsigned budget, void (*work)(void))
{
    char message[160];
    pid_t supervisor = fork();
    if (supervisor < 0) { snprintf(message, sizeof(message), "%s supervisor fork failed", name); report(message); return; }
    if (supervisor) return;
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) _exit(1);
    pid_t worker = fork();
    if (worker < 0) { snprintf(message, sizeof(message), "%s worker fork failed", name); report(message); _exit(1); }
    if (!worker) { work(); _exit(0); }
    for (unsigned second = 0; second < budget; ++second) {
        int status;
        pid_t done = waitpid(worker, &status, WNOHANG);
        if (done == worker) _exit(0);
        if (done < 0 && errno != EINTR) {
            snprintf(message, sizeof(message), "%s wait failed; leaving worker to the return timer", name);
            report(message);
            _exit(1);
        }
        sleep(1);
    }
    snprintf(message, sizeof(message), "%s %u-second budget expired; terminating worker", name, budget);
    report(message);
    kill(worker, SIGKILL);
    _exit(1);
}

// ---- 1. Read-only partition hashes ----
static const char *const hash_targets[] = {"lk", "dtbo", "vbmeta", "boot", "recovery", "super"};

// Opens the UFS whole disk that carries a valid GPT. Ownership and node
// identity are checked the same way the v5 header reads do.
static int open_gpt_disk(char *disk, size_t disk_length, unsigned *lbs, uint64_t *blocks)
{
    char path[PATH_MAX], controller[PATH_MAX], block[PATH_MAX], text[64];
    if (!realpath("/sys/bus/platform/devices/11270000.ufshci", controller)) return -1;
    DIR *directory = opendir("/sys/class/block");
    if (!directory) return -1;
    struct dirent *entry;
    int found = -1;
    unsigned inspected = 0;
    while (found < 0 && inspected++ < 256 && (entry = readdir(directory))) {
        const char *name = entry->d_name;
        if (!tpufs_name(name) || tpufs_path(path, sizeof(path), "/sys/class/block", name, "") ||
            !realpath(path, block) || !tpufs_owned(controller, block)) continue;
        struct stat info;
        if (tpufs_path(path, sizeof(path), block, "partition", "")) continue;
        errno = 0;
        if (!lstat(path, &info) || errno != ENOENT) continue;
        dev_t expected;
        unsigned long long sectors, size;
        if (tpufs_path(path, sizeof(path), block, "dev", "") || tpufs_attribute(path, text, sizeof(text)) ||
            tpufs_device_number(text, &expected)) continue;
        if (tpufs_path(path, sizeof(path), block, "size", "") || tpufs_attribute(path, text, sizeof(text)) ||
            tpufs_uint(text, &sectors)) continue;
        if (tpufs_path(path, sizeof(path), block, "queue/logical_block_size", "") ||
            tpufs_attribute(path, text, sizeof(text)) || tpufs_uint(text, &size) || size < 512 || size > 4096) continue;
        if (tpufs_path(path, sizeof(path), "/dev", name, "")) continue;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) continue;
        if (fstat(fd, &info) || !tpufs_block_identity(&info, expected)) { close(fd); continue; }
        unsigned char header[8];
        if (pread(fd, header, sizeof(header), (off_t)size) != (ssize_t)sizeof(header) ||
            memcmp(header, "EFI PART", 8)) { close(fd); continue; }
        snprintf(disk, disk_length, "%s", name);
        *lbs = (unsigned)size;
        *blocks = sectors * 512 / size;
        found = fd;
    }
    closedir(directory);
    return found;
}

// Cross-checks the userspace GPT against the kernel's partition scan.
static void kernel_partition_check(const char *disk, const struct tp8_gpt_part *part, unsigned lbs)
{
    char path[PATH_MAX], text[64], message[200];
    unsigned long long start = 0, size = 0;
    int n = snprintf(path, sizeof(path), "/sys/class/block/%s%u/start", disk, part->index);
    int ok = n > 0 && (size_t)n < sizeof(path) && !tpufs_attribute(path, text, sizeof(text)) && !tpufs_uint(text, &start);
    n = snprintf(path, sizeof(path), "/sys/class/block/%s%u/size", disk, part->index);
    ok = ok && n > 0 && (size_t)n < sizeof(path) && !tpufs_attribute(path, text, sizeof(text)) && !tpufs_uint(text, &size);
    int match = ok && start == part->first * (lbs / 512) && size == (part->last - part->first + 1) * (lbs / 512);
    snprintf(message, sizeof(message), "part-hash name=%s kernel_partition=%s%u present=%d match=%d",
             part->name, disk, part->index, ok, match);
    report(message);
}

static void partition_hashes(void)
{
    char disk[32], message[256];
    unsigned lbs = 0;
    uint64_t blocks = 0;
    int fd = -1;
    for (unsigned second = 0; second < 30 && fd < 0; ++second) {
        fd = open_gpt_disk(disk, sizeof(disk), &lbs, &blocks);
        if (fd < 0) sleep(1);
    }
    if (fd < 0) { report("part-hash no UFS disk with a GPT within 30 s; no partition reads"); return; }
    static struct tp8_gpt_part parts[TP8_GPT_MAX_ENTRIES];
    const char *why = "";
    int count = tp8_gpt_read(fd, lbs, blocks, parts, TP8_GPT_MAX_ENTRIES, &why);
    snprintf(message, sizeof(message), "part-hash disk=%s logical_block=%u blocks=%llu gpt_entries=%d%s%s",
             disk, lbs, (unsigned long long)blocks, count, count < 0 ? " error=" : "", count < 0 ? why : "");
    report(message);
    if (count < 0) { close(fd); return; }
    double deadline = tp8_now() + (PROBE_HASH_DEADLINE_SECONDS - seconds_since(&probe_start));
    for (size_t t = 0; t < sizeof(hash_targets) / sizeof(*hash_targets); ++t) {
        const struct tp8_gpt_part *part = NULL;
        for (int i = 0; i < count && !part; ++i)
            if (!strcmp(parts[i].name, hash_targets[t])) part = &parts[i];
        if (!part) {
            snprintf(message, sizeof(message), "part-hash name=%s not_in_gpt", hash_targets[t]);
            report(message); continue;
        }
        uint64_t bytes = (part->last - part->first + 1) * lbs;
        snprintf(message, sizeof(message), "part-hash name=%s gpt_index=%u first_lba=%llu last_lba=%llu bytes=%llu",
                 part->name, part->index, (unsigned long long)part->first, (unsigned long long)part->last,
                 (unsigned long long)bytes);
        report(message);
        kernel_partition_check(disk, part, lbs);
        if (tp8_hash_range(fd, part->name, part->first * lbs, bytes, deadline, report) && tp8_now() >= deadline) {
            report("part-hash deadline reached; remaining partitions skipped");
            break;
        }
    }
    close(fd);
    report("part-hash complete; read-only partition workload ended");
}

// ---- 2. Runtime reserved memory ----
static ssize_t read_file(const char *path, unsigned char *buffer, size_t length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < length) {
        ssize_t n = read(fd, buffer + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    return (ssize_t)used;
}

static unsigned property_u32(const char *node, const char *name, unsigned fallback)
{
    char path[PATH_MAX];
    unsigned char value[4];
    snprintf(path, sizeof(path), "%s/%s", node, name);
    return read_file(path, value, sizeof(value)) == 4 ? tp8_be32(value) : fallback;
}

// Prints a property as cell pairs, a string list or a flag.
static void property_text(const char *node, const char *name, unsigned ac, unsigned sc, char *out, size_t length)
{
    char path[PATH_MAX];
    unsigned char value[4096];
    snprintf(path, sizeof(path), "%s/%s", node, name);
    ssize_t n = read_file(path, value, sizeof(value));
    if (n < 0) { snprintf(out, length, "-"); return; }
    if (!strcmp(name, "compatible") || !strcmp(name, "status")) {
        size_t k = 0;
        for (ssize_t i = 0; i < n && k + 1 < length; ++i)
            out[k++] = value[i] ? (value[i] >= 32 && value[i] < 127 ? (char)value[i] : '?') : (i + 1 < n ? ';' : 0);
        out[k < length ? k : length - 1] = 0;
        return;
    }
    if (!n) { snprintf(out, length, "1"); return; }
    if (tp8_cells(value, (size_t)n, ac, sc, out, length) < 0) snprintf(out, length, "raw%zd", n);
}

static void log_reserved_nodes(const char *base)
{
    char node[PATH_MAX], message[900];
    snprintf(node, sizeof(node), "%s/reserved-memory", base);
    unsigned ac = property_u32(node, "#address-cells", 2), sc = property_u32(node, "#size-cells", 2);
    DIR *directory = opendir(node);
    if (!directory) { report("rmem no /reserved-memory node in the runtime tree"); return; }
    struct dirent *entry;
    unsigned nodes = 0;
    while (nodes < 96 && (entry = readdir(directory))) {
        if (entry->d_name[0] == '.' || entry->d_type != DT_DIR) continue;
        char child[PATH_MAX], compatible[96], reg[320], size[48], align[48], alloc[160], nomap[8], reusable[8], status[24];
        if (snprintf(child, sizeof(child), "%s/%s", node, entry->d_name) >= (int)sizeof(child)) continue;
        property_text(child, "compatible", ac, sc, compatible, sizeof(compatible));
        property_text(child, "reg", ac, sc, reg, sizeof(reg));
        property_text(child, "size", 0, sc, size, sizeof(size));
        property_text(child, "alignment", 0, sc, align, sizeof(align));
        property_text(child, "alloc-ranges", ac, sc, alloc, sizeof(alloc));
        property_text(child, "no-map", ac, sc, nomap, sizeof(nomap));
        property_text(child, "reusable", ac, sc, reusable, sizeof(reusable));
        property_text(child, "status", ac, sc, status, sizeof(status));
        snprintf(message, sizeof(message),
                 "rmem node=%.63s compatible=%s reg=%s size=%s alignment=%s alloc-ranges=%s no-map=%s reusable=%s status=%s",
                 entry->d_name, compatible, reg, size, align, alloc, nomap, reusable, status);
        report(message);
        ++nodes;
    }
    closedir(directory);
    snprintf(message, sizeof(message), "rmem nodes=%u address-cells=%u size-cells=%u", nodes, ac, sc);
    report(message);
    // Memory nodes, so reservations can be placed against the RAM LK passed.
    unsigned ac_root = property_u32(base, "#address-cells", 2), sc_root = property_u32(base, "#size-cells", 2);
    directory = opendir(base);
    if (!directory) return;
    while ((entry = readdir(directory))) {
        if (strncmp(entry->d_name, "memory", 6) || entry->d_type != DT_DIR) continue;
        char child[PATH_MAX], reg[600];
        if (snprintf(child, sizeof(child), "%s/%s", base, entry->d_name) >= (int)sizeof(child)) continue;
        property_text(child, "reg", ac_root, sc_root, reg, sizeof(reg));
        snprintf(message, sizeof(message), "rmem memory-node=%.63s reg=%s", entry->d_name, reg);
        report(message);
    }
    closedir(directory);
}

static void log_memreserve(void)
{
    static unsigned char fdt[1u << 20];
    char message[200], hex[65];
    ssize_t n = read_file("/sys/firmware/fdt", fdt, sizeof(fdt));
    if (n <= 0) { report("rmem /sys/firmware/fdt unavailable; no memreserve list"); return; }
    struct tp8_sha256 c;
    tp8_sha256_init(&c);
    tp8_sha256_update(&c, fdt, (size_t)n);
    tp8_sha256_hex(&c, hex);
    uint64_t base[64], size[64];
    int count = tp8_memreserve(fdt, (size_t)n, base, size, 64);
    snprintf(message, sizeof(message), "rmem fdt bytes=%zd sha256=%s memreserve_entries=%d", n, hex, count);
    report(message);
    for (int i = 0; i < count; ++i) {
        snprintf(message, sizeof(message), "rmem memreserve index=%d base=0x%llx size=0x%llx",
                 i, (unsigned long long)base[i], (unsigned long long)size[i]);
        report(message);
    }
}

// /proc/iomem lists memblock nomap regions and memblock reservations as "reserved".
static void log_iomem(void)
{
    static unsigned char text[65536];
    ssize_t n = read_file("/proc/iomem", text, sizeof(text) - 1);
    if (n <= 0) { report("rmem /proc/iomem unavailable"); return; }
    text[n] = 0;
    unsigned logged = 0, skipped = 0;
    char message[200];
    for (char *line = (char *)text, *next; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!strstr(line, ": reserved") && !strstr(line, ": System RAM") && !strstr(line, ": Kernel")) continue;
        if (logged >= 128) { ++skipped; continue; }
        snprintf(message, sizeof(message), "rmem iomem %s", line);
        report(message);
        ++logged;
    }
    snprintf(message, sizeof(message), "rmem iomem lines=%u skipped=%u", logged, skipped);
    report(message);
}

static void reserved_memory(void)
{
    log_reserved_nodes("/sys/firmware/devicetree/base");
    log_memreserve();
    log_iomem();
    report("rmem complete");
}

// ---- 5. USB connection state ----
static void cable_monitor(void)
{
    char udc[64] = "", path[PATH_MAX], state[64], previous[64] = "", speed[64], message[200];
    unsigned changes = 0;
    while (seconds_since(&probe_start) < PROBE_CABLE_SECONDS) {
        if (!udc[0]) {
            DIR *directory = opendir("/sys/class/udc");
            struct dirent *entry;
            while (directory && (entry = readdir(directory)))
                if (tp8_udc_name(entry->d_name)) { snprintf(udc, sizeof(udc), "%s", entry->d_name); break; }
            if (directory) closedir(directory);
        }
        if (udc[0]) {
            snprintf(path, sizeof(path), "/sys/class/udc/%s/state", udc);
            if (tpufs_attribute(path, state, sizeof(state))) snprintf(state, sizeof(state), "unreadable");
            state[strcspn(state, "\n")] = 0;
            if (strcmp(state, previous)) {
                snprintf(path, sizeof(path), "/sys/class/udc/%s/current_speed", udc);
                if (tpufs_attribute(path, speed, sizeof(speed))) snprintf(speed, sizeof(speed), "unreadable");
                speed[strcspn(speed, "\n")] = 0;
                if (++changes <= 120) {
                    snprintf(message, sizeof(message), "usb-state t=%.1f udc=%s state=%s speed=%s change=%u",
                             seconds_since(&probe_start), udc, state, speed, changes);
                    report(message);
                }
                snprintf(previous, sizeof(previous), "%s", state);
            }
        }
        sleep(1);
    }
    snprintf(message, sizeof(message), "usb-state monitor ended changes=%u last=%s", changes, previous[0] ? previous : "none");
    report(message);
}

// ---- 4. I2C chip IDs ----
// True when the platform device has a bound driver.
static int platform_bound(const char *device)
{
    char path[PATH_MAX];
    struct stat info;
    snprintf(path, sizeof(path), "/sys/bus/platform/devices/%s/driver", device);
    return !lstat(path, &info);
}

static int gpiochip_open(void);

// Lists devices bound to the MT6771 pinctrl driver, and gpiochip0's label and size.
static void pinctrl_devices(void)
{
    char message[240];
    unsigned found = 0;
    DIR *directory = opendir("/sys/bus/platform/drivers/mt6771-pinctrl");
    struct dirent *entry;
    while (directory && (entry = readdir(directory))) {
        if (!strchr(entry->d_name, '.') || entry->d_name[0] == '.') continue;
        snprintf(message, sizeof(message), "i2c-id pinctrl-driver device=%s", entry->d_name);
        report(message);
        ++found;
    }
    if (directory) closedir(directory);
    snprintf(message, sizeof(message), "i2c-id pinctrl-driver %s devices=%u", directory ? "present" : "absent", found);
    report(message);
    int fd = gpiochip_open();
    if (fd < 0) return;
    struct gpiochip_info chip;
    memset(&chip, 0, sizeof(chip));
    if (ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, &chip))
        snprintf(message, sizeof(message), "i2c-id gpiochip0 chipinfo errno=%d", errno);
    else
        snprintf(message, sizeof(message), "i2c-id gpiochip0 name=%s label=%s lines=%u", chip.name, chip.label, chip.lines);
    report(message);
    close(fd);
}

// Finds the i2c-N child of a controller's platform device, or -1.
static int i2c_adapter_for(const char *device)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/bus/platform/devices/%s", device);
    DIR *directory = opendir(path);
    if (!directory) return -1;
    struct dirent *entry;
    int number = -1;
    while (number < 0 && (entry = readdir(directory))) number = tp8_i2c_adapter_name(entry->d_name);
    closedir(directory);
    return number;
}

// Reads a regulator's state by its DT regulator-name; "absent" if no match.
static void regulator_state(const char *name, char *out, size_t length)
{
    snprintf(out, length, "absent");
    DIR *directory = opendir("/sys/class/regulator");
    struct dirent *entry;
    char path[PATH_MAX], text[64];
    while (directory && (entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/sys/class/regulator/%s/name", entry->d_name);
        if (tpufs_attribute(path, text, sizeof(text))) continue;
        text[strcspn(text, "\n")] = 0;
        if (strcmp(text, name)) continue;
        snprintf(path, sizeof(path), "/sys/class/regulator/%s/state", entry->d_name);
        if (tpufs_attribute(path, text, sizeof(text))) snprintf(text, sizeof(text), "unreadable");
        text[strcspn(text, "\n")] = 0;
        snprintf(out, length, "%s", text);
        break;
    }
    if (directory) closedir(directory);
}

// Opens /dev/gpiochip0 read-only after matching its device number to sysfs, or -1.
static int gpiochip_open(void)
{
    char text[64];
    dev_t expected;
    if (tpufs_attribute("/sys/bus/gpio/devices/gpiochip0/dev", text, sizeof(text)) ||
        tpufs_device_number(text, &expected)) { report("i2c-id gpiochip0 absent; no GPIO access"); return -1; }
    int fd = open("/dev/gpiochip0", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISCHR(info.st_mode) || info.st_rdev != expected) {
        if (fd >= 0) close(fd);
        report("i2c-id gpiochip0 node does not match sysfs; not used");
        return -1;
    }
    return fd;
}

// Line direction only, through GPIO_GET_LINEINFO_IOCTL; no line is requested.
static void gpio_directions(void)
{
    static const unsigned lines[] = {1, 9, 18, 153};
    char message[200];
    int fd = gpiochip_open();
    if (fd < 0) return;
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i) {
        struct gpioline_info line;
        memset(&line, 0, sizeof(line));
        line.line_offset = lines[i];
        if (ioctl(fd, GPIO_GET_LINEINFO_IOCTL, &line)) {
            snprintf(message, sizeof(message), "i2c-id gpio=%u lineinfo errno=%d", lines[i], errno);
        } else {
            snprintf(message, sizeof(message), "i2c-id gpio=%u direction=%s used=%d", lines[i],
                     (line.flags & GPIOLINE_FLAG_IS_OUT) ? "out" : "in", !!(line.flags & GPIOLINE_FLAG_KERNEL));
        }
        report(message);
    }
    close(fd);
}

// Opens /dev/i2c-N read-only after matching its device number to sysfs.
static int i2c_open(int number)
{
    char path[PATH_MAX], text[64];
    dev_t expected;
    snprintf(path, sizeof(path), "/sys/class/i2c-dev/i2c-%d/dev", number);
    if (tpufs_attribute(path, text, sizeof(text)) || tpufs_device_number(text, &expected)) return -1;
    snprintf(path, sizeof(path), "/dev/i2c-%d", number);
    // devtmpfs supplies the node. Never create a fallback guessed device.
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info;
    if (fd >= 0 && (fstat(fd, &info) || !S_ISCHR(info.st_mode) || info.st_rdev != expected)) { close(fd); fd = -1; }
    return fd;
}

// One ID read: a register-pointer write and a short read in one I2C_RDWR.
struct id_read {
    const struct tp8_i2c_target *t;
    int fd, status, error;
    unsigned char data[TP8_I2C_MAX_READ];
    int line;   // GPIO line request fd during the reset pulse, else -1
};

static int id_read_once(void *ctx)
{
    struct id_read *r = ctx;
    const struct tp8_i2c_target *t = r->t;
    unsigned char pointer[2];
    memcpy(pointer, t->reg, sizeof(pointer));
    memset(r->data, 0, sizeof(r->data));
    struct i2c_msg messages[2] = {
        {.addr = t->address, .flags = 0, .len = (uint16_t)t->reg_length, .buf = pointer},
        {.addr = t->address, .flags = I2C_M_RD, .len = (uint16_t)t->read_length, .buf = r->data},
    };
    struct i2c_rdwr_ioctl_data transfer = {.msgs = messages, .nmsgs = 2};
    r->status = ioctl(r->fd, I2C_RDWR, &transfer);
    r->error = r->status < 0 ? errno : r->status == 2 ? 0 : EIO;
    return r->error;
}

// Line info and level of an aw9523 line, before anything drives it. The level comes from
// a request with no direction flag, which leaves direction as it is. On paris the
// request also sets the pin's mode to 0 (GPIO), the only mode of GPIO 178 and the
// EINT mode stock uses for GPIO 0.
static void reset_line_state(unsigned offset, const char *role)
{
    char message[240];
    int chip = gpiochip_open();
    if (chip < 0) return;
    struct gpio_v2_line_info info;
    memset(&info, 0, sizeof(info));
    info.offset = offset;
    if (ioctl(chip, GPIO_V2_GET_LINEINFO_IOCTL, &info)) {
        snprintf(message, sizeof(message), "aw9523 gpio=%u role=%s lineinfo errno=%d", offset, role, errno);
        report(message);
        close(chip);
        return;
    }
    unsigned long long f = info.flags;
    snprintf(message, sizeof(message),
             "aw9523 gpio=%u role=%s name=%s consumer=%s flags=0x%llx direction=%s used=%d active_low=%d bias=%s drive=%s",
             offset, role, info.name[0] ? info.name : "-", info.consumer[0] ? info.consumer : "-", f,
             (f & GPIO_V2_LINE_FLAG_OUTPUT) ? "out" : (f & GPIO_V2_LINE_FLAG_INPUT) ? "in" : "?",
             !!(f & GPIO_V2_LINE_FLAG_USED), !!(f & GPIO_V2_LINE_FLAG_ACTIVE_LOW),
             (f & GPIO_V2_LINE_FLAG_BIAS_PULL_UP) ? "pull-up" : (f & GPIO_V2_LINE_FLAG_BIAS_PULL_DOWN) ? "pull-down" :
             (f & GPIO_V2_LINE_FLAG_BIAS_DISABLED) ? "disabled" : "unknown",
             (f & GPIO_V2_LINE_FLAG_OPEN_DRAIN) ? "open-drain" : (f & GPIO_V2_LINE_FLAG_OPEN_SOURCE) ? "open-source" : "push-pull");
    report(message);
    if (f & GPIO_V2_LINE_FLAG_USED) {
        snprintf(message, sizeof(message), "aw9523 gpio=%u role=%s level=- in use, not requested", offset, role);
        report(message);
        close(chip);
        return;
    }
    struct gpio_v2_line_request request;
    memset(&request, 0, sizeof(request));
    request.offsets[0] = offset;
    request.num_lines = 1;
    snprintf(request.consumer, sizeof(request.consumer), "tp510-v9-read");
    if (ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &request)) {
        snprintf(message, sizeof(message), "aw9523 gpio=%u role=%s level=- request errno=%d", offset, role, errno);
    } else {
        struct gpio_v2_line_values values = {.bits = 0, .mask = 1};
        if (ioctl(request.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &values))
            snprintf(message, sizeof(message), "aw9523 gpio=%u role=%s level=- get errno=%d", offset, role, errno);
        else
            snprintf(message, sizeof(message), "aw9523 gpio=%u role=%s level=%d", offset, role, (int)(values.bits & 1));
        close(request.fd);
    }
    report(message);
    close(chip);
}

// Reset pulse callbacks: the only GPIO writes in v9, used only after a NACK.
static int reset_request_high(void *ctx)
{
    struct id_read *r = ctx;
    r->line = -1;
    int chip = gpiochip_open();
    if (chip < 0) return ENODEV;
    struct gpio_v2_line_request request;
    memset(&request, 0, sizeof(request));
    request.offsets[0] = TP9_AW9523_RESET_GPIO;
    request.num_lines = 1;
    snprintf(request.consumer, sizeof(request.consumer), "tp510-v9-reset");
    request.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
    request.config.num_attrs = 1;
    request.config.attrs[0].attr.id = GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES;
    request.config.attrs[0].attr.values = 1;
    request.config.attrs[0].mask = 1;
    int error = ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &request) ? errno : 0;
    close(chip);
    if (!error) r->line = request.fd;
    return error;
}

static int reset_set(void *ctx, int value)
{
    struct id_read *r = ctx;
    struct gpio_v2_line_values values = {.bits = (uint64_t)(value & 1), .mask = 1};
    return ioctl(r->line, GPIO_V2_LINE_SET_VALUES_IOCTL, &values) ? errno : 0;
}

static void reset_sleep_us(void *ctx, unsigned us)
{
    (void)ctx;
    struct timespec wait = {.tv_sec = us / 1000000u, .tv_nsec = (long)(us % 1000000u) * 1000};
    while (nanosleep(&wait, &wait) && errno == EINTR) {}
}

// Closing the request leaves the line output-high, the state stock leaves after its probe.
static void reset_release(void *ctx)
{
    struct id_read *r = ctx;
    if (r->line >= 0) close(r->line);
    r->line = -1;
}

static void i2c_read_id(const struct tp8_i2c_target *t, int adapter)
{
    char message[240], hex[2 * TP8_I2C_MAX_READ + 1] = "", reg[8], state[32] = "none";
    tp8_hex_bytes(t->reg, t->reg_length, reg, sizeof(reg));
    if (!tp8_i2c_target_valid(t)) return;
    if (t->supply) {
        regulator_state(t->supply, state, sizeof(state));
        if (strcmp(state, "enabled")) {
            snprintf(message, sizeof(message), "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=- result=skipped supply %s %s",
                     t->stock_bus, adapter, t->address, t->chip, reg, t->supply, state);
            report(message);
            return;
        }
    }
    int fd = adapter < 0 ? -1 : i2c_open(adapter);
    if (fd < 0) {
        snprintf(message, sizeof(message), "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=- result=no-adapter",
                 t->stock_bus, adapter, t->address, t->chip, reg);
        report(message);
        return;
    }
    struct id_read read = {.t = t, .fd = fd, .line = -1};
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char extra[96] = "";
    if (t->reset_gpio >= 0) {
        reset_line_state(TP9_AW9523_RESET_GPIO, "reset");
        reset_line_state(TP9_AW9523_INT_GPIO, "int");
        static const struct tp9_reset_ops ops = {id_read_once, reset_request_high, reset_set, reset_sleep_us, reset_release};
        struct tp9_reset_result r = tp9_reset_read(&ops, &read, report);
        snprintf(extra, sizeof(extra), " reads=%u reset=%s gpio_errno=%d", r.reads,
                 r.pulsed ? "pulsed" : r.gpio_error ? "failed" : "no", r.gpio_error);
    } else {
        id_read_once(&read);
    }
    close(fd);
    if (read.status == 2) {
        tp8_hex_bytes(read.data, t->read_length, hex, sizeof(hex));
        char match[32] = "";
        if (t->expect >= 0) snprintf(match, sizeof(match), " expect=%02x match=%s", t->expect, read.data[0] == t->expect ? "yes" : "no");
        snprintf(message, sizeof(message), "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=%s result=ok%s supply=%s ms=%.0f%s",
                 t->stock_bus, adapter, t->address, t->chip, reg, hex, match, state, seconds_since(&start) * 1000, extra);
    } else {
        // ENXIO is a NACK: absent, unpowered or held in reset. ETIMEDOUT/EIO point at the bus.
        snprintf(message, sizeof(message), "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=- result=error status=%d errno=%d supply=%s ms=%.0f%s",
                 t->stock_bus, adapter, t->address, t->chip, reg, read.status, read.error, state, seconds_since(&start) * 1000, extra);
    }
    report(message);
}

#define CONTROLLERS 4
static void i2c_ids(void)
{
    static const char *const controllers[CONTROLLERS] = {"11007000.i2c", "1100f000.i2c", "11005000.i2c", "11008000.i2c"};
    char message[200], state[32];
    // 5.10 names the device from its first reg (0x10005000) and the node name.
    snprintf(message, sizeof(message), "i2c-id pinctrl=%s pwrap=%s pmic-regulators=%s",
             platform_bound("10005000.1000b000.pinctrl") ? "bound" : "unbound",
             platform_bound("1000d000.pwrap") ? "bound" : "unbound",
             access("/sys/class/regulator", F_OK) ? "absent" : "present");
    report(message);
    regulator_state("vldo28", state, sizeof(state));
    snprintf(message, sizeof(message), "i2c-id regulator vldo28=%s", state);
    report(message);
    pinctrl_devices();
    gpio_directions();
    int adapters[CONTROLLERS] = {-1, -1, -1, -1};
    for (unsigned second = 0; second <= PROBE_I2C_WAIT_SECONDS; ++second) {
        int missing = 0;
        for (int i = 0; i < CONTROLLERS; ++i)
            if (adapters[i] < 0 && (adapters[i] = i2c_adapter_for(controllers[i])) < 0) ++missing;
        if (!missing) break;
        if (second < PROBE_I2C_WAIT_SECONDS) sleep(1);
    }
    for (int i = 0; i < CONTROLLERS; ++i) {
        snprintf(message, sizeof(message), "i2c-id controller=%s driver=%s adapter=%d", controllers[i],
                 platform_bound(controllers[i]) ? "bound" : "unbound", adapters[i]);
        report(message);
    }
    for (size_t i = 0; i < TP8_I2C_TARGETS; ++i) {
        const struct tp8_i2c_target *t = &tp8_i2c_targets[i];
        int adapter = -1;
        for (int c = 0; c < CONTROLLERS; ++c) if (!strcmp(t->device, controllers[c])) adapter = adapters[c];
        i2c_read_id(t, adapter);
    }
    report("i2c-id complete");
}

// ---- 3. ACM input hashing (PID1, called from the serial loop) ----
static struct tp8_lines echo_lines;
static int echo_state; // 0 waiting for input, 1 hashing, 2 closed
static struct timespec echo_started;

static void echo_close(void)
{
    char message[160];
    snprintf(message, sizeof(message), "acm-echo window closed lines=%u unterminated_bytes=%llu total_bytes=%llu",
             echo_lines.lines, (unsigned long long)echo_lines.length, (unsigned long long)echo_lines.total);
    report(message);
    echo_state = 2;
}

static void echo_tick(void)
{
    if (echo_state == 1 && seconds_since(&echo_started) >= PROBE_ECHO_SECONDS) echo_close();
}

static int echo_timeout(void)
{
    return echo_state == 1 ? 1000 : -1;
}

// Input inside the window is hashed and never parsed as a command.
static int echo_hook(const char *data, ssize_t count)
{
    echo_tick();
    if (echo_state == 2 || count <= 0) return 0;
    if (!echo_state) {
        tp8_lines_init(&echo_lines);
        clock_gettime(CLOCK_MONOTONIC, &echo_started);
        echo_state = 1;
        report("acm-echo window opened; input is hashed for 60 s and never executed");
    }
    tp8_lines_feed(&echo_lines, data, (size_t)count, report);
    return 1;
}

static void combined_probes(void)
{
    clock_gettime(CLOCK_MONOTONIC, &probe_start);
    watchdog_pinger();
    (void)tpufs_start("/sys", "/dev", 1, report);
    bounded_child("part-hash", PROBE_HASH_BUDGET_SECONDS, partition_hashes);
    bounded_child("rmem", PROBE_RMEM_BUDGET_SECONDS, reserved_memory);
    bounded_child("usb-state", PROBE_RETURN_SECONDS, cable_monitor);
    bounded_child("i2c-id", PROBE_I2C_BUDGET_SECONDS, i2c_ids);
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
