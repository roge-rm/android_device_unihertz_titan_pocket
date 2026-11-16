// SPDX-License-Identifier: GPL-2.0-only
// Pstore reader /init for the Titan Pocket recovery partition, on the v11 diagnostic kernel.
// Boots straight after a first-boot loop pass, before any 4.14 kernel reuses ramoops.
// PID 1 mounts proc, sysfs and devtmpfs, mounts pstore read-only, copies every pstore file
// into a tmpfs, then sets up an ACM gadget and streams a dump every 10 s: each pstore file
// framed with its name, size and sha256, then the current kmsg, framed the same way.
// Accepts `reboot` and `reboot-bootloader` on the ACM, as v11 does, and asks for a
// bootloader restart after 300 s. It never opens a block device and mounts no block filesystem.
// Host test build (-DPSTORE_HOST_TEST): tools/test-pocket-pstore-reader.py.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/watchdog.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "../ram-probe/commands.h"

#define LABEL "TP510-PSTORE"            // USB serial; tools/capture-pocket-pstore.py matches it
#define PRODUCT "Titan Pocket 5.10 pstore reader"
#define GADGET "tp510"                  // as the v11 diagnostic; no Android in recovery
#define CONFIG "configs/c.1"
#define FUNCTION "acm.usb0"
#define LINK CONFIG "/" FUNCTION
#define COPY_DIR "/pstore-copy"         // tmpfs holding the copies
#define RETURN_SECONDS 300
// Pinging stops 30 s after the return timer, as v11, so the watchdog still resets the phone
// if the restart never happens.
#define WATCHDOG_SECONDS (RETURN_SECONDS + 30)
#define INTERVAL_MS 10000               // a dump starts this often, and a stalled one is dropped
#define TICK_MS 1000                    // UDC bind, tty reopen and pstore rescan interval
#define CHUNK 4096
#define FILE_MAX (2 << 20)              // ramoops console is 256 KiB, records 4 KiB
#define TOTAL_MAX (8 << 20)
#define FILES_MAX 128
#define KMSG_MAX (4 << 20)
#ifndef READER_SOURCE_SHA256
#define READER_SOURCE_SHA256 "unset"
#endif

// The packager looks for this marker and the source hash in /init.
const char reader_marker[] __attribute__((used)) =
    LABEL " pstore reader init; reader-source-sha256=" READER_SOURCE_SHA256;

#ifdef PSTORE_HOST_TEST
// Host test build only, run under qemu-user. Paths go under a fake root, mounts and node
// creation are left out, the watchdog is not opened and a restart writes the target to
// <root>/reboot-request and ends the test process group. The phone build has none of this.
const char test_marker[] __attribute__((used)) = "PSTORE_HOST_TEST_BUILD";
static char test_root[512];
static char test_paths[8][1024];
static int test_next;
static const char *P(const char *path)
{
    char *out = test_paths[test_next++ & 7];
    snprintf(out, sizeof(test_paths[0]), "%s%s", test_root, path);
    return out;
}
static long test_env(const char *name, long fallback)
{
    const char *value = getenv(name);
    return value ? atol(value) : fallback;
}
#define RETURN_MS test_env("PSTORE_TEST_RETURN_MS", RETURN_SECONDS * 1000L)
#define DUMP_MS test_env("PSTORE_TEST_INTERVAL_MS", INTERVAL_MS)
#define ATTR_FLAGS (O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)
#define fs_mount(source, target, type, flags, data) 0
#define TEST_SUFFIX test_marker
static void test_function(void)
{
    int fd = open("functions/" FUNCTION "/port_num", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) { if (write(fd, "0\n", 2) != 2) { /* read back fails the setup */ } close(fd); }
}
#else
#define P(path) (path)
#define RETURN_MS (RETURN_SECONDS * 1000L)
#define DUMP_MS ((long)INTERVAL_MS)
#define ATTR_FLAGS (O_WRONLY | O_CLOEXEC)
#define fs_mount(source, target, type, flags, data) mount(source, target, type, flags, data)
#define TEST_SUFFIX ""
#define test_function() ((void)0)
#endif

// ---- sha256 (FIPS 180-4) ----

struct sha256 { uint32_t h[8]; uint8_t block[64]; size_t used; uint64_t bytes; };

static const uint32_t sha_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(struct sha256 *s, const uint8_t *p)
{
    uint32_t w[64], a[8];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4 * i] << 24 | p[4 * i + 1] << 16 | p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(a, s->h, sizeof(a));
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = a[7] + (ROR(a[4], 6) ^ ROR(a[4], 11) ^ ROR(a[4], 25)) + ((a[4] & a[5]) ^ (~a[4] & a[6])) + sha_k[i] + w[i];
        uint32_t t2 = (ROR(a[0], 2) ^ ROR(a[0], 13) ^ ROR(a[0], 22)) + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
        memmove(a + 1, a, 7 * sizeof(a[0]));
        a[4] += t1;
        a[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) s->h[i] += a[i];
}

static void sha_hex(const void *data, size_t size, char out[65])
{
    struct sha256 s = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
                       {0}, 0, 0};
    const uint8_t *p = data;
    s.bytes = size;
    for (; size >= 64; p += 64, size -= 64) sha_block(&s, p);
    memcpy(s.block, p, size);
    s.used = size;
    s.block[s.used++] = 0x80;
    if (s.used > 56) { memset(s.block + s.used, 0, 64 - s.used); sha_block(&s, s.block); s.used = 0; }
    memset(s.block + s.used, 0, 56 - s.used);
    for (int i = 0; i < 8; i++) s.block[56 + i] = (uint8_t)((s.bytes * 8) >> (56 - 8 * i));
    sha_block(&s, s.block);
    for (int i = 0; i < 8; i++) snprintf(out + 8 * i, 9, "%08x", s.h[i]);
}

// ---- small helpers ----

static struct timespec started;

static long elapsed_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - started.tv_sec) * 1000 + (now.tv_nsec - started.tv_nsec) / 1000000;
}

static void report(const char *message)
{
    int fd = open(P("/dev/kmsg"), O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) {
        dprintf(fd, "<6>" LABEL ": %s\n", message);
        close(fd);
    }
}

static void reportf(const char *format, const char *a, const char *b)
{
    char message[256];
    snprintf(message, sizeof(message), format, a, b);
    report(message);
}

static int directory(const char *path)
{
    return mkdir(path, 0755) && errno != EEXIST ? -1 : 0;
}

static int attribute(const char *path, const char *value)
{
    int fd = open(path, ATTR_FLAGS, 0644);
    if (fd < 0) return -1;
    size_t length = strlen(value);
    ssize_t result = write(fd, value, length);
    int saved = errno;
    close(fd);
    errno = saved;
    return result == (ssize_t)length ? 0 : -1;
}

static ssize_t read_small(const char *path, char *out, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, size - 1);
    close(fd);
    if (n < 0) return -1;
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = 0;
    return n;
}

// Growing byte buffer for one dump.
struct buffer { char *data; size_t size, room; };

static int put(struct buffer *b, const void *data, size_t size)
{
    if (b->size + size > b->room) {
        size_t room = b->room ? b->room : 1 << 16;
        while (room < b->size + size) room *= 2;
        char *grown = realloc(b->data, room);
        if (!grown) return -1;
        b->data = grown;
        b->room = room;
    }
    memcpy(b->data + b->size, data, size);
    b->size += size;
    return 0;
}

static int putf(struct buffer *b, const char *format, ...) __attribute__((format(printf, 2, 3)));
static int putf(struct buffer *b, const char *format, ...)
{
    char line[1536];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n < 0) return -1;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    return put(b, line, n);
}

// ---- restart ----

static void restart(const char *target)
{
#ifdef PSTORE_HOST_TEST
    int fd = open(P("/reboot-request"), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) { dprintf(fd, "%s at %ld ms\n", target ? target : "normal", elapsed_ms()); close(fd); }
    kill(0, SIGKILL);
    _exit(0);
#else
    // The 5.10 kernel has no reboot-mode driver, so "bootloader" most likely ends as a plain reset.
    if (target) syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, target);
    else reboot(RB_AUTOBOOT);
    report("restart syscall failed; trying a normal restart");
    reboot(RB_AUTOBOOT);
#endif
}

static void return_timer(void)
{
    pid_t child = fork();
    if (child == 0) {
        long left = RETURN_MS;
        while (left > 0) {
            long step = left > 1000 ? 1000 : left;
            usleep(step * 1000);
            left -= step;
        }
        report("return timer expired; requesting bootloader restart");
        restart("bootloader");
        _exit(1);
    }
    if (child < 0) report("return timer fork failed; restart by the keys or the watchdog");
}

// Opens the boot-adopted watchdog and pings it until WATCHDOG_SECONDS, as v11 does. Never writes
// the magic close character, so the watchdog stays armed.
static void watchdog_pinger(void)
{
#ifndef PSTORE_HOST_TEST
    pid_t child = fork();
    if (child < 0) { report("watchdog fork failed; hardware watchdog stays unpinged"); return; }
    if (child) return;
    char text[64], message[160];
    int fd = -1;
    for (int attempt = 0; attempt < 10 && fd < 0; attempt++) {
        if (attempt) sleep(1);
        unsigned major_number, minor_number;
        if (read_small("/sys/class/watchdog/watchdog0/dev", text, sizeof(text)) <= 0 ||
            sscanf(text, "%u:%u", &major_number, &minor_number) != 2) continue;
        // devtmpfs supplies the node. Never make a guessed one.
        int candidate = open("/dev/watchdog0", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat info;
        if (candidate < 0) continue;
        if (fstat(candidate, &info) || !S_ISCHR(info.st_mode) || info.st_rdev != makedev(major_number, minor_number)) {
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
             timeout, interval, WATCHDOG_SECONDS);
    report(message);
    unsigned failures = 0;
    while (elapsed_ms() < WATCHDOG_SECONDS * 1000L) {
        if (ioctl(fd, WDIOC_KEEPALIVE, 0) && failures++ < 3) {
            snprintf(message, sizeof(message), "watchdog keepalive failed: %s", strerror(errno));
            report(message);
        }
        unsigned remaining = interval;
        while (remaining) remaining = sleep(remaining);
    }
    report("watchdog pinging stopped; hardware watchdog will reset the phone");
    for (;;) pause();
#endif
}

// ---- pstore copies ----

struct saved { char name[64]; char *data; size_t size, original; char sha[65]; int copied; };
static struct saved files[FILES_MAX];
static int file_count;
static size_t file_bytes;
static char pstore_state[160] = "not mounted";
static char copy_state[160] = "not mounted";
static int copy_mounted;

static int known(const char *name)
{
    for (int i = 0; i < file_count; i++)
        if (!strcmp(files[i].name, name)) return 1;
    return 0;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct saved *)a)->name, ((const struct saved *)b)->name);
}

// Reads every pstore file not seen yet into memory and writes a copy into the tmpfs. Files that
// show up later (a backend that registers after the mount) are picked up by the next rescan.
// Pstore is mounted read-only, so nothing is ever erased.
static int save_pstore(void)
{
    int added = 0;
    int dir_fd = open(P("/sys/fs/pstore"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = dir_fd >= 0 ? fdopendir(dir_fd) : NULL;
    if (!dir) { if (dir_fd >= 0) close(dir_fd); return 0; }
    struct dirent *entry;
    while ((entry = readdir(dir)) && file_count < FILES_MAX) {
        if (entry->d_name[0] == '.' || strlen(entry->d_name) >= sizeof(files[0].name) || known(entry->d_name)) continue;
        int fd = openat(dir_fd, entry->d_name, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        struct stat info;
        if (fstat(fd, &info) || !S_ISREG(info.st_mode)) { close(fd); continue; }
        struct saved *s = &files[file_count];
        size_t room = TOTAL_MAX - file_bytes;
        size_t limit = room < FILE_MAX ? room : FILE_MAX;
        if ((size_t)info.st_size < limit) limit = info.st_size;
        s->data = malloc(limit ? limit : 1);
        if (!s->data) { close(fd); continue; }
        s->size = 0;
        while (s->size < limit) {
            ssize_t n = read(fd, s->data + s->size, limit - s->size);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            s->size += n;
        }
        close(fd);
        s->original = (size_t)info.st_size > s->size ? (size_t)info.st_size : s->size;
        snprintf(s->name, sizeof(s->name), "%s", entry->d_name);
        sha_hex(s->data, s->size, s->sha);
        if (copy_mounted) {
            char path[128];
            snprintf(path, sizeof(path), "%s/%s", P(COPY_DIR), s->name);
            int out = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            size_t done = 0;
            while (out >= 0 && done < s->size) {
                ssize_t n = write(out, s->data + done, s->size - done);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                done += n;
            }
            s->copied = out >= 0 && done == s->size;
            if (out >= 0) close(out);
        }
        file_bytes += s->size;
        file_count++;
        added++;
        char message[200];
        snprintf(message, sizeof(message), "saved pstore %s %zu bytes sha256=%.16s", s->name, s->size, s->sha);
        report(message);
    }
    closedir(dir);
    if (added) qsort(files, file_count, sizeof(files[0]), by_name);
    return added;
}

// ---- gadget, as the first-boot wrapper sets it up ----

static int gadget_dir = -1, udc_fd = -1, udc_class = -1, dev_dir = -1;
static char tty_name[16] = "ttyGS0";

static int gadget_setup(void)
{
    if (fs_mount("configfs", P("/sys/kernel/config"), "configfs", MS_NOSUID | MS_NODEV, NULL) && errno != EBUSY)
        return -1;
    // Configfs resolves the symlink target from the cwd, so work inside the gadget.
    if (chdir(P("/sys/kernel/config/usb_gadget")) || directory(GADGET) || chdir(GADGET)) return -1;
    if (attribute("idVendor", "0x1d6b") || attribute("idProduct", "0x0104") ||
        directory("strings") || directory("strings/0x409") ||
        attribute("strings/0x409/serialnumber", LABEL) ||
        attribute("strings/0x409/manufacturer", "Titan Pocket kernel bring-up") ||
        attribute("strings/0x409/product", PRODUCT) ||
        directory("configs") || directory(CONFIG) || directory(CONFIG "/strings") ||
        directory(CONFIG "/strings/0x409") ||
        attribute(CONFIG "/strings/0x409/configuration", "Pstore stream") ||
        attribute(CONFIG "/MaxPower", "100") || directory("functions") || directory("functions/" FUNCTION))
        return -1;
    test_function();
    if (symlink("functions/" FUNCTION, LINK) && errno != EEXIST) return -1;
    char port[16];
    if (read_small("functions/" FUNCTION "/port_num", port, sizeof(port)) <= 0) return -1;
    snprintf(tty_name, sizeof(tty_name), "ttyGS%s", port);
    gadget_dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    udc_fd = open("UDC", ATTR_FLAGS, 0644);
    if (chdir("/")) { /* only directory fds are used from here */ }
    // /sys/class/udc may not exist yet; bind_udc opens it on each try.
    udc_class = open(P("/sys/class/udc"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return gadget_dir < 0 || udc_fd < 0 ? -1 : 0;
}

static int bind_udc(void)
{
    static int reported;
    if (udc_class < 0) {
        udc_class = open(P("/sys/class/udc"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (udc_class < 0 && !reported) {
            reported = 1;
            reportf("/sys/class/udc not open yet: %s%s", strerror(errno), "; retrying");
        }
        if (udc_class < 0) return -1;
    }
    int fd = openat(udc_class, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir) { if (fd >= 0) close(fd); return -1; }
    struct dirent *entry;
    int result = -1;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        size_t length = strlen(entry->d_name);
        result = write(udc_fd, entry->d_name, length) == (ssize_t)length ? 0 : -1;
        if (!result) reportf("ACM gadget bound to %s%s", entry->d_name, "");
        break;
    }
    closedir(dir);
    return result;
}

// Character node for ttyGSn, in case devtmpfs has not made it yet.
static void tty_node(void)
{
#ifndef PSTORE_HOST_TEST
    char path[64], number[32];
    unsigned major_number, minor_number;
    snprintf(path, sizeof(path), "/sys/class/tty/%s/dev", tty_name);
    if (read_small(path, number, sizeof(number)) > 0 && sscanf(number, "%u:%u", &major_number, &minor_number) == 2)
        mknodat(dev_dir, tty_name, S_IFCHR | 0600, makedev(major_number, minor_number));
#endif
}

static int open_tty(void)
{
    int fd = openat(dev_dir, tty_name, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct termios mode;
    if (!tcgetattr(fd, &mode)) {
        cfmakeraw(&mode);
        tcsetattr(fd, TCSANOW, &mode);
    }
    return fd;
}

// ---- dump ----

static void module_parameters(struct buffer *b)
{
    static const char *names[] = {"mem_address", "mem_size", "mem_type", "record_size", "console_size",
                                  "ftrace_size", "pmsg_size", "ecc", "dump_oops", "max_reason"};
    putf(b, "ramoops parameters:");
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[96], value[64];
        snprintf(path, sizeof(path), "/sys/module/ramoops/parameters/%s", names[i]);
        if (read_small(P(path), value, sizeof(value)) >= 0) putf(b, " %s=%s", names[i], value);
    }
    putf(b, "\n");
}

// The kmsg ring as it is now, read from the start; EPIPE after an overrun skips ahead.
static void put_kmsg(struct buffer *b)
{
    struct buffer k = {0};
    int fd = open(P("/dev/kmsg"), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    char chunk[8192];
    while (fd >= 0 && k.size < KMSG_MAX) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n < 0 && (errno == EINTR || errno == EPIPE)) continue;
        if (n <= 0) break;
        if (put(&k, chunk, n)) break;
    }
    if (fd >= 0) close(fd);
    char sha[65];
    sha_hex(k.data ? k.data : "", k.size, sha);
    putf(b, "=== kmsg %zu sha256=%s ===\n", k.size, sha);
    if (k.size) put(b, k.data, k.size);
    putf(b, "\n=== end kmsg ===\n");
    free(k.data);
}

static int dump_number;

static int make_dump(struct buffer *b)
{
    struct utsname version;
    char cmdline[2048] = "";
    if (uname(&version)) memset(&version, 0, sizeof(version));
    read_small(P("/proc/cmdline"), cmdline, sizeof(cmdline));
    b->size = 0;
    dump_number++;
    long now = elapsed_ms();
    putf(b, "\n=== " LABEL " dump %d at %ld ms ===\n%s\n%s%s", dump_number, now, reader_marker,
         TEST_SUFFIX, *TEST_SUFFIX ? "\n" : "");
    putf(b, "kernel: %s %s %s\ncmdline: %s\n", version.sysname, version.release, version.version, cmdline);
    putf(b, "pstore: %s; %d files, %zu bytes; tmpfs copy: %s\n", pstore_state, file_count, file_bytes, copy_state);
    module_parameters(b);
    putf(b, "raw ramoops region: not streamed; the kernel has no /dev/mem (CONFIG_DEVMEM off)\n");
    putf(b, "commands: reboot or reboot-bootloader then newline; bootloader restart at %ld s, %ld s from now\n",
         RETURN_MS / 1000, (RETURN_MS - now) / 1000);
    for (int i = 0; i < file_count; i++) {
        struct saved *s = &files[i];
        putf(b, "=== file %s %zu sha256=%s%s ===\n", s->name, s->size, s->sha,
             s->original > s->size ? " truncated" : "");
        if (s->size) put(b, s->data, s->size);
        putf(b, "\n=== end file %s ===\n", s->name);
    }
    put_kmsg(b);
    return putf(b, "=== end dump %d files=%d ===\n", dump_number, file_count);
}

// ---- PID 1 ----

int main(void)
{
    clock_gettime(CLOCK_MONOTONIC, &started);
#ifdef PSTORE_HOST_TEST
    snprintf(test_root, sizeof(test_root), "%s", getenv("PSTORE_TEST_ROOT") ? getenv("PSTORE_TEST_ROOT") : "/nonexistent");
#endif
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    directory(P("/proc")); directory(P("/sys")); directory(P("/dev"));
    int proc = !fs_mount("proc", P("/proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    int sys = !fs_mount("sysfs", P("/sys"), "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    int dev = !fs_mount("devtmpfs", P("/dev"), "devtmpfs", MS_NOSUID, "mode=0755");
#ifndef PSTORE_HOST_TEST
    // devtmpfs makes kmsg itself; the node is only for a devtmpfs that failed to mount.
    mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
#endif
    report("pstore reader init started");
    if (!proc || !sys || !dev) report("proc, sysfs or devtmpfs mount failed; carrying on");
    // Pstore first, read-only, before anything else touches the system.
    if (fs_mount("pstore", P("/sys/fs/pstore"), "pstore", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) &&
        errno != EBUSY)
        snprintf(pstore_state, sizeof(pstore_state), "mount failed: %s", strerror(errno));
    else
        snprintf(pstore_state, sizeof(pstore_state), "mounted read-only");
    directory(P(COPY_DIR));
    if (fs_mount("tmpfs", P(COPY_DIR), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=16m,mode=0700")) {
        snprintf(copy_state, sizeof(copy_state), "tmpfs mount failed: %s", strerror(errno));
    } else {
        copy_mounted = 1;
        snprintf(copy_state, sizeof(copy_state), "tmpfs at " COPY_DIR);
    }
    save_pstore();
    int copied = 0;
    for (int i = 0; i < file_count; i++) copied += files[i].copied;
    if (copy_mounted && copied != file_count)
        snprintf(copy_state, sizeof(copy_state), "tmpfs at " COPY_DIR ", %d of %d files written", copied, file_count);
    watchdog_pinger();
    return_timer();
    dev_dir = open(P("/dev"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (gadget_setup()) reportf("gadget setup failed: %s%s", strerror(errno), "");
    else report("ACM gadget made; binding the controller");

    struct buffer dump = {0};
    struct tpdiag_parser parser = {0};
    size_t sent = 0;
    int tty = -1, bound = 0, sending = 0;
    long last_tick = -TICK_MS, dump_started = 0, progress = 0;
    for (;;) {
        long now = elapsed_ms();
        if (now - last_tick >= TICK_MS) {
            last_tick = now;
            if (!bound && udc_fd >= 0) bound = !bind_udc();
            if (save_pstore()) report("new pstore files after the first copy");
            if (tty < 0 && dev_dir >= 0) {
                tty_node();
                if ((tty = open_tty()) >= 0) { sending = 0; dump_started = now - DUMP_MS; }
            }
        }
        // A fresh dump every DUMP_MS, or as soon as one has made no progress for DUMP_MS
        // (no host reading), so a host that attaches late gets a whole one within a cycle.
        if (tty >= 0 && ((!sending && now - dump_started >= DUMP_MS) || (sending && now - progress >= DUMP_MS))) {
            if (sending) report("dump stalled; starting a fresh one");
            make_dump(&dump);
            sent = 0;
            sending = 1;
            dump_started = progress = now;
        }
        struct pollfd event = {tty, POLLIN | (sending ? POLLOUT : 0), 0};
        long wait = TICK_MS - (elapsed_ms() - last_tick);
        if (!sending && tty >= 0 && DUMP_MS - (elapsed_ms() - dump_started) < wait)
            wait = DUMP_MS - (elapsed_ms() - dump_started);
        if (wait < 0) wait = 0;
        if (poll(&event, tty >= 0 ? 1 : 0, wait) < 0 && errno != EINTR) usleep(100000);
        if (tty < 0 || !event.revents) continue;
        int hung = (event.revents & (POLLERR | POLLNVAL)) != 0;
        if (!hung && event.revents & (POLLIN | POLLHUP)) {
            char input[64];
            ssize_t count = read(tty, input, sizeof(input));
            if (count == 0 || (count < 0 && errno != EAGAIN && errno != EINTR)) hung = 1;
            for (ssize_t i = 0; i < count; i++) {
                enum tpdiag_command command = tpdiag_feed(&parser, input[i]);
                if (command == TPDIAG_NONE) continue;
                const char *target = command == TPDIAG_BOOTLOADER ? "bootloader" : NULL;
                report(target ? "USB reboot-bootloader command received" : "USB reboot command received");
                dprintf(tty, "\n" LABEL ": requesting %s restart\n", target ? "bootloader" : "normal");
                restart(target);
            }
        }
        if (!hung && sending && event.revents & POLLOUT) {
            size_t left = dump.size - sent;
            ssize_t n = write(tty, dump.data + sent, left < CHUNK ? left : CHUNK);
            if (n > 0) {
                sent += n;
                progress = elapsed_ms();
                if (sent == dump.size) sending = 0;
            } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
                hung = 1;
            }
        }
        if (hung) {
            // Hung up (USB reset or cable): reopen on the next tick and start a fresh dump.
            close(tty);
            tty = -1;
            sending = 0;
        }
    }
}
