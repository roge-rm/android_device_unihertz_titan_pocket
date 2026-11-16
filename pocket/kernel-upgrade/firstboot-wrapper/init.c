// SPDX-License-Identifier: GPL-2.0-only
// First-boot wrapper /init for the Titan Pocket ROM boot image (first flash v2).
// PID 1 saves pstore, sets up an ACM gadget, forks a logger and execs the product's
// first-stage init (/init.android), which stays PID 1. The logger streams a banner,
// the saved pstore files and live /dev/kmsg over ACM. The gadget is Android's own g1,
// made early with Android's config and string names; as soon as Android first touches
// g1, or after a timeout, the logger unbinds it and removes only its ACM function and link.
// It reads no input, never opens a block device and never restarts the phone.
// Hand-back reasoning: evidence/kernel-upgrade/first-flash-v1/wrapper-handback.md.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define LABEL "TP510-FIRSTBOOT-V2"      // USB serial; tools/capture-pocket-diagnostic.py matches it
// The kernel keeps the first configfs gadget of a boot as android_device and never clears it
// (configfs.c android_device_create), so the gadget made here must be the g1 Android goes on
// to use, and it is never removed. Names as in vendor init.mt6771.usb.rc.
#define GADGET "g1"
#define CONFIG "configs/b.1"
#define FUNCTION "acm.usb0"             // ours only; Android makes acm.gs0 to acm.gs3
#define LINK CONFIG "/" FUNCTION        // ours only; Android's links are f1 to f5
#ifdef FIRSTBOOT_STREAM
// Stream variant: Android touching g1 is logged and USB stays ours until the timeout. The
// hand-back comes before adbd starts (about 30 s), so Android's ffs.ready bind isn't blocked.
#define HANDBACK_TIMEOUT_MS 25000
#else
#define HANDBACK_TIMEOUT_MS 120000      // fallback if Android is never seen touching g1
#endif
#define RESCAN_MS 1000                  // usb_gadget rescan, UDC bind and tty reopen interval
#define PSTORE_FILE_MAX (1 << 20)       // ramoops console is 256 KiB, records 4 KiB
#define PSTORE_TOTAL_MAX (4 << 20)
#define PSTORE_FILES_MAX 128
#ifndef WRAPPER_SOURCE_SHA256
#define WRAPPER_SOURCE_SHA256 "unset"
#endif

// The packager looks for this marker and the source hash in /init.
const char wrapper_marker[] __attribute__((used)) =
    LABEL " wrapper init; wrapper-source-sha256=" WRAPPER_SOURCE_SHA256;

#ifdef FIRSTBOOT_HOST_TEST
// Host test build only (tools/test-pocket-firstboot-wrapper.py, under qemu-user). The phone
// build has none of this: paths are fixed, mounts are real and there is no environment input.
const char test_marker[] __attribute__((used)) = "FIRSTBOOT_HOST_TEST_BUILD";
static char test_root[512];
static char test_path_buffer[8][1024];
static int test_path_next;
static const char *P(const char *path)
{
    char *out = test_path_buffer[test_path_next++ & 7];
    snprintf(out, sizeof(test_path_buffer[0]), "%s%s", test_root, path);
    return out;
}
static long test_timeout_ms(void)
{
    const char *value = getenv("FIRSTBOOT_TEST_TIMEOUT_MS");
    return value ? atol(value) : HANDBACK_TIMEOUT_MS;
}
#define TIMEOUT_MS test_timeout_ms()
#define TEST_SUFFIX test_marker
#define EXEC_PATH (getenv("FIRSTBOOT_TEST_EXEC") ? getenv("FIRSTBOOT_TEST_EXEC") : P("/init.android"))
#define USE_INOTIFY (!getenv("FIRSTBOOT_TEST_NO_INOTIFY"))
#define ATTR_FLAGS (O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)
#define KMSG_OUT_FLAGS (O_WRONLY | O_APPEND | O_CLOEXEC)    // fake kmsg is a regular file
#define IDLE_READ() usleep(10000)                          // which is always readable
#define fs_mount(source, target, type, flags) 0
#define fs_umount(target, flags) ((void)0)
// Configfs drops attribute files and default groups on rmdir; a plain directory does not.
static void test_clear(int dir_fd, const char *path)
{
    int fd = openat(dir_fd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir) { if (fd >= 0) close(fd); return; }
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (entry->d_type == DT_DIR) {
            test_clear(fd, entry->d_name);
            unlinkat(fd, entry->d_name, AT_REMOVEDIR);
        } else if (entry->d_type == DT_REG) {
            unlinkat(fd, entry->d_name, 0);
        }
    }
    closedir(dir);
}
// Configfs makes default groups and attributes with each gadget, config and function.
static void test_configfs(const char *made)
{
    if (!strcmp(made, GADGET)) {
        mkdir(GADGET "/functions", 0755); mkdir(GADGET "/configs", 0755);
        mkdir(GADGET "/strings", 0755); mkdir(GADGET "/os_desc", 0755);
    } else if (!strcmp(made, CONFIG)) {
        mkdir(CONFIG "/strings", 0755);
    } else {
        int fd = open("functions/" FUNCTION "/port_num", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) { if (write(fd, "0\n", 2) != 2) { /* read back fails the setup */ } close(fd); }
    }
}
#else
#define P(path) (path)
#define TIMEOUT_MS ((long)HANDBACK_TIMEOUT_MS)
#define TEST_SUFFIX ""
#define EXEC_PATH "/init.android"
#define USE_INOTIFY 1
#define ATTR_FLAGS (O_WRONLY | O_CLOEXEC)
#define KMSG_OUT_FLAGS (O_WRONLY | O_CLOEXEC)
#define IDLE_READ() ((void)0)
#define fs_mount(source, target, type, flags) mount(source, target, type, flags, NULL)
#define fs_umount(target, flags) umount2(target, flags)
#define test_clear(dir_fd, path) ((void)0)
#define test_configfs(made) ((void)0)
#endif

// Everything the logger needs, opened by PID 1 before the exec. Later opens are relative
// to these directory fds, so nothing depends on paths in Android's tree after switch-root.
// made: PID 1 created g1. owner and mode: g1 as made, to spot the chown and chmod by Android init.
static struct {
    int kmsg_in, kmsg_out, usb_tty, udc, gadgets, gadget, functions, config, udc_class, dev, notify;
    int watch_gadgets, watch_gadget, watch_functions, made;
    uid_t owner;
    mode_t mode;
    char tty_name[16];
} fds = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, ""};

struct saved { char name[64]; char *data; size_t size; char head[128], tail[96]; size_t head_n, tail_n; };
static struct saved pstore[PSTORE_FILES_MAX];
static int pstore_count;
static size_t pstore_bytes;
static char banner[2048];
static size_t banner_n;
static struct timespec started;

static long elapsed_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    return (now.tv_sec - started.tv_sec) * 1000 + (now.tv_nsec - started.tv_nsec) / 1000000;
}

static void report(const char *message)
{
    if (fds.kmsg_out >= 0) dprintf(fds.kmsg_out, "<6>" LABEL ": %s\n", message);
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

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct saved *)a)->name, ((const struct saved *)b)->name);
}

// Copies every pstore file into memory. Read-only mount; records are never erased.
static void save_pstore(void)
{
    if (fs_mount("pstore", P("/sys/fs/pstore"), "pstore", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC) &&
        errno != EBUSY) {
        reportf("pstore mount failed: %s%s", strerror(errno), "");
        return;
    }
    int dir_fd = open(P("/sys/fs/pstore"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = dir_fd >= 0 ? fdopendir(dir_fd) : NULL;
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) && pstore_count < PSTORE_FILES_MAX) {
            if (entry->d_name[0] == '.' || strlen(entry->d_name) >= sizeof(pstore[0].name)) continue;
            int fd = openat(dir_fd, entry->d_name, O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
            struct stat info;
            if (fstat(fd, &info) || !S_ISREG(info.st_mode)) { close(fd); continue; }
            struct saved *s = &pstore[pstore_count];
            size_t room = PSTORE_TOTAL_MAX - pstore_bytes;
            size_t limit = room < PSTORE_FILE_MAX ? room : PSTORE_FILE_MAX;
            if ((size_t)info.st_size < limit) limit = info.st_size;
            s->data = limit ? malloc(limit) : NULL;
            if (!s->data) { close(fd); continue; }
            s->size = 0;
            while (s->size < limit) {
                ssize_t n = read(fd, s->data + s->size, limit - s->size);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                s->size += n;
            }
            close(fd);
            strcpy(s->name, entry->d_name);
            pstore_bytes += s->size;
            pstore_count++;
        }
        closedir(dir);
    } else if (dir_fd >= 0) {
        close(dir_fd);
    }
    qsort(pstore, pstore_count, sizeof(pstore[0]), by_name);
    for (int i = 0; i < pstore_count; i++) {
        struct saved *s = &pstore[i];
        s->head_n = snprintf(s->head, sizeof(s->head), "\n=== pstore %s %zu bytes ===\n", s->name, s->size);
        s->tail_n = snprintf(s->tail, sizeof(s->tail), "\n=== end pstore %s ===\n", s->name);
    }
    fs_umount(P("/sys/fs/pstore"), 0);
}

// Android's g1 with one ACM function of ours. UDC is bound later by the logger so PID 1 never
// waits for the controller. Default groups (functions, configs, strings) come with the mkdir.
static int other_entry(int dir_fd, const char *skip, char *name, size_t size);

static int gadget_setup(void)
{
    if (fs_mount("configfs", P("/sys/kernel/config"), "configfs", MS_NOSUID | MS_NODEV) && errno != EBUSY)
        return -1;
    fds.gadgets = open(P("/sys/kernel/config/usb_gadget"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fds.gadgets < 0) return -1;
    // No gadget can exist yet; if one does, it is not ours to change.
    char name[64];
    if (other_entry(fds.gadgets, NULL, name, sizeof(name))) { errno = EEXIST; return -1; }
    // Configfs resolves the symlink target from the cwd, so work inside the gadget.
    if (chdir(P("/sys/kernel/config/usb_gadget")) || mkdir(GADGET, 0755)) return -1;
    fds.made = 1;
    test_configfs(GADGET);
    if (chdir(GADGET)) return -1;
    if (attribute("idVendor", "0x1d6b") || attribute("idProduct", "0x0104") ||
        directory("strings/0x409") ||
        attribute("strings/0x409/serialnumber", LABEL) ||
        attribute("strings/0x409/manufacturer", "Titan Pocket kernel bring-up") ||
        attribute("strings/0x409/product", "5.10 first boot log") ||
        directory(CONFIG))
        return -1;
    test_configfs(CONFIG);
    if (directory(CONFIG "/strings/0x409") ||
        attribute(CONFIG "/strings/0x409/configuration", "Kernel log stream") ||
        attribute(CONFIG "/MaxPower", "100") || directory("functions/" FUNCTION))
        return -1;
    test_configfs(FUNCTION);
    if (symlink("functions/" FUNCTION, LINK) && errno != EEXIST) return -1;
    struct stat info;
    fds.gadget = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    fds.functions = open("functions", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    fds.config = open(CONFIG, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    fds.udc = open("UDC", ATTR_FLAGS, 0644);
    if (fds.gadget < 0 || fds.functions < 0 || fds.config < 0 || fds.udc < 0 || fstat(fds.gadget, &info)) return -1;
    fds.owner = info.st_uid;
    fds.mode = info.st_mode & 07777;
    char port[16];
    if (read_small("functions/" FUNCTION "/port_num", port, sizeof(port)) <= 0) return -1;
    snprintf(fds.tty_name, sizeof(fds.tty_name), "ttyGS%s", port);
    return 0;
}

static int open_tty(void)
{
    int fd = openat(fds.dev, fds.tty_name, O_WRONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct termios mode;
    if (!tcgetattr(fd, &mode)) {
        cfmakeraw(&mode);
        tcsetattr(fd, TCSANOW, &mode);
    }
    return fd;
}

// Character node for ttyGSn in our devtmpfs, in case devtmpfs has not made it yet.
static void tty_node(void)
{
#ifndef FIRSTBOOT_HOST_TEST
    char path[64], number[32];
    unsigned major_number, minor_number;
    snprintf(path, sizeof(path), "/sys/class/tty/%s/dev", fds.tty_name);
    if (read_small(path, number, sizeof(number)) > 0 && sscanf(number, "%u:%u", &major_number, &minor_number) == 2)
        mknodat(fds.dev, fds.tty_name, S_IFCHR | 0600, makedev(major_number, minor_number));
#endif
}

static void make_banner(void)
{
    struct utsname version;
    char cmdline[1024] = "";
    if (uname(&version)) memset(&version, 0, sizeof(version));
    read_small(P("/proc/cmdline"), cmdline, sizeof(cmdline));
    banner_n = snprintf(banner, sizeof(banner),
        "\n%s\n%s%skernel: %s %s %s\ncmdline: %s\nstarted: %ld.%03ld s after boot\n"
        "pstore: %d files, %zu bytes saved before Android init\n"
#ifdef FIRSTBOOT_STREAM
        "USB stream variant: Android touching g1 is only logged; USB goes to Android after %ld s\n"
#else
        "USB hand-back: when Android first touches g1, or after %ld s\n"
#endif
        "Read-only stream; nothing sent to this port is read. Android init runs as PID 1 from %s\n",
        wrapper_marker, TEST_SUFFIX, *TEST_SUFFIX ? "\n" : "", version.sysname, version.release, version.version, cmdline,
        (long)started.tv_sec, started.tv_nsec / 1000000, pstore_count, pstore_bytes, TIMEOUT_MS / 1000,
        EXEC_PATH);
    if (banner_n >= sizeof(banner)) banner_n = sizeof(banner) - 1;
}

// ---- logger child ----

static const char live_marker[] = "\n=== live kmsg from boot start ===\n";
static char kmsg_buffer[8192];

// Stream position: 0 banner, then three pieces per pstore file, then the live marker, then kmsg.
static int piece;
static const char *out_p;
static size_t out_n;

static int next_piece(void)
{
    int fixed = 1 + 3 * pstore_count + 1;
    while (piece < fixed) {
        int i = piece++;
        if (i == 0) { out_p = banner; out_n = banner_n; }
        else if (i == fixed - 1) { out_p = live_marker; out_n = sizeof(live_marker) - 1; }
        else {
            struct saved *s = &pstore[(i - 1) / 3];
            int part = (i - 1) % 3;
            out_p = part == 0 ? s->head : part == 1 ? s->data : s->tail;
            out_n = part == 0 ? s->head_n : part == 1 ? s->size : s->tail_n;
        }
        if (out_n) return 1;
    }
    ssize_t n = read(fds.kmsg_in, kmsg_buffer, sizeof(kmsg_buffer));
    if (n > 0) { out_p = kmsg_buffer; out_n = n; return 1; }
    IDLE_READ();
    return 0;    // EAGAIN, or EPIPE after a ring overrun: the next read resumes
}

// First entry of a configfs directory other than skip; 1 if found, its name copied out.
static int other_entry(int dir_fd, const char *skip, char *name, size_t size)
{
    int fd = openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir) { if (fd >= 0) close(fd); return 0; }
    struct dirent *entry;
    int found = 0;
    while (!found && (entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") && (!skip || strcmp(entry->d_name, skip))) {
            snprintf(name, size, "%s", entry->d_name);
            found = 1;
        }
    closedir(dir);
    return found;
}

// A link in b.1 other than ours. config_usb_cfg_link refuses a bound gadget, so one there means
// our bind is gone (Android wrote none) or never was, and Android may own the controller now.
static int android_linked(void)
{
    int fd = openat(fds.config, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir) { if (fd >= 0) close(fd); return 0; }
    struct dirent *entry;
    int found = 0;
    while ((entry = readdir(dir)))
        if (entry->d_type == DT_LNK && strcmp(entry->d_name, FUNCTION)) found = 1;
    closedir(dir);
    return found;
}

static char why[160];

// Android's first touch of g1. In a normal boot that is vendor init.mt6771.usb.rc post-fs:
// mkdir on the existing g1 chowns it to shell (IN_ATTRIB), then attribute writes (IN_MODIFY)
// and function mkdirs (IN_CREATE). The only write of ours is to UDC, which is skipped.
static int inotify_saw_android(void)
{
    char events[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    int found = 0;
    while (!found && fds.notify >= 0) {
        ssize_t n = read(fds.notify, events, sizeof(events));
        if (n <= 0) break;
        for (char *p = events; !found && p < events + n;) {
            struct inotify_event *event = (struct inotify_event *)p;
            const char *name = event->len ? event->name : "";
            p += sizeof(*event) + event->len;
            if (event->mask & IN_Q_OVERFLOW) {
                snprintf(why, sizeof(why), "inotify queue overflow");
                found = 1;
            } else if (event->mask & IN_IGNORED) {
                // A watch went away; the rescan and the timeout still run.
                close(fds.notify);
                fds.notify = -1;
            } else if (event->wd == fds.watch_gadgets && event->mask & (IN_CREATE | IN_MOVED_TO) && strcmp(name, GADGET)) {
                snprintf(why, sizeof(why), "Android made usb_gadget/%s (inotify)", name);
                found = 1;
            } else if (event->wd == fds.watch_gadget && event->mask & IN_ATTRIB) {
                if (*name) snprintf(why, sizeof(why), "Android changed g1/%s attributes (inotify)", name);
                else snprintf(why, sizeof(why), "Android changed g1 owner or mode (inotify)");
                found = 1;
            } else if (event->wd == fds.watch_gadget && event->mask & IN_MODIFY && strcmp(name, "UDC")) {
                snprintf(why, sizeof(why), "Android wrote g1/%s (inotify)", name);
                found = 1;
            } else if (event->wd == fds.watch_functions && event->mask & (IN_CREATE | IN_MOVED_TO) && strcmp(name, FUNCTION)) {
                snprintf(why, sizeof(why), "Android made functions/%s (inotify)", name);
                found = 1;
            }
        }
    }
    return found;
}

// Once a second, in case an event is lost or inotify is not there.
static int rescan_saw_android(void)
{
    struct stat info;
    char name[64];
    if (!fstat(fds.gadget, &info) && (info.st_uid != fds.owner || (info.st_mode & 07777) != fds.mode)) {
        snprintf(why, sizeof(why), "Android changed g1 owner or mode (rescan)");
        return 1;
    }
    if (other_entry(fds.gadgets, GADGET, name, sizeof(name))) {
        snprintf(why, sizeof(why), "Android made usb_gadget/%s (rescan)", name);
        return 1;
    }
    if (other_entry(fds.functions, FUNCTION, name, sizeof(name))) {
        snprintf(why, sizeof(why), "Android made functions/%s (rescan)", name);
        return 1;
    }
    return 0;
}

// Called when Android has touched g1 (why says how); returns 1 if USB should be handed back.
// The stream variant logs each distinct touch, at most 32, and keeps streaming.
static int android_touched(void)
{
#ifdef FIRSTBOOT_STREAM
    static char last[sizeof(why)];
    static int count;
    if (!strcmp(last, why)) return 0;
    snprintf(last, sizeof(last), "%s", why);
    char line[256];
    if (count < 32) snprintf(line, sizeof(line), "Android touched g1 at %ld ms; still streaming: %s", elapsed_ms(), why);
    else snprintf(line, sizeof(line), "Android touched g1 more; further touches not logged");
    if (count <= 32) report(line);
    count++;
    return 0;
#else
    return 1;
#endif
}

static int bind_udc(void)
{
    int fd = openat(fds.udc_class, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir) { if (fd >= 0) close(fd); return -1; }
    struct dirent *entry;
    int result = -1;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        size_t length = strlen(entry->d_name);
        result = write(fds.udc, entry->d_name, length) == (ssize_t)length ? 0 : -1;
        if (!result) reportf("ACM gadget bound to %s%s", entry->d_name, "");
        break;
    }
    closedir(dir);
    return result;
}

static void remove_dir(int dir_fd, const char *path)
{
    test_clear(dir_fd, path);
    if (unlinkat(dir_fd, path, AT_REMOVEDIR) && errno != ENOENT)
        reportf("rmdir %s failed: %s", path, strerror(errno));
}

// Removes our link and function and nothing else: g1, its strings and b.1 stay for Android.
// The tty must be closed first, as gserial_free_line waits for the port to close.
static void drop_own_function(int gadget)
{
    if (unlinkat(gadget, LINK, 0) && errno != ENOENT) reportf("unlink %s failed: %s", LINK, strerror(errno));
    remove_dir(gadget, "functions/" FUNCTION);
}

// Unbind first: the controller is then free for Android, and the ACM port is disconnected, so
// closing the tty does not wait up to 15 s for unsent data (gs_close).
static void hand_back(const char *reason, int bound)
{
    char line[256];
    int n = snprintf(line, sizeof(line), "\n=== " LABEL " hand-back: %s at %ld ms; USB goes to Android ===\n",
                     reason, elapsed_ms());
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    // Best effort: no wait for it to reach the host.
    if (fds.usb_tty >= 0 && write(fds.usb_tty, line, n) < 0) { /* dropped */ }
    reportf("handing USB back to Android: %s%s", reason, "");
    // Unlinking ours from a bound b.1 would unbind Android's gadget (config_usb_cfg_unlink).
    int android = android_linked();
    if (bound && !android && write(fds.udc, "\n", 1) != 1) reportf("UDC unbind failed: %s%s", strerror(errno), "");
    close(fds.udc);
    if (fds.usb_tty >= 0) close(fds.usb_tty);
    fds.usb_tty = -1;
    if (android) report("Android has linked functions in b.1; UDC, our link and function left as they are");
    else drop_own_function(fds.gadget);
    report("hand-back done; logger exits");
    _exit(0);
}

static void logger(void)
{
    signal(SIGPIPE, SIG_IGN);
    setsid();
    prctl(PR_SET_NAME, "tp510-fblog", 0, 0, 0);
    int bound = 0, tty_failed = 0;
    long last_tick = -RESCAN_MS;
    for (;;) {
        long now = elapsed_ms();
        if (now >= TIMEOUT_MS) hand_back("timeout", bound);
        if (fds.notify >= 0 && inotify_saw_android() && android_touched()) hand_back(why, bound);
        if (now - last_tick >= RESCAN_MS) {
            last_tick = now;
            if (rescan_saw_android() && android_touched()) hand_back(why, bound);
            if (!bound) bound = !bind_udc();
            if (fds.usb_tty < 0 && (fds.usb_tty = open_tty()) >= 0) {
                if (tty_failed) report("ACM tty reopened; resending banner and pstore");
                piece = 0; out_n = 0;
            }
        }
        if (fds.usb_tty >= 0 && !out_n) next_piece();
        struct pollfd events[3];
        int count = 0, tty_slot = -1;
        if (fds.notify >= 0) events[count++] = (struct pollfd){fds.notify, POLLIN, 0};
        if (fds.usb_tty >= 0 && out_n) { tty_slot = count; events[count++] = (struct pollfd){fds.usb_tty, POLLOUT, 0}; }
        else if (fds.usb_tty >= 0) events[count++] = (struct pollfd){fds.kmsg_in, POLLIN, 0};
        long wait = RESCAN_MS - (elapsed_ms() - last_tick);
        long left = TIMEOUT_MS - elapsed_ms();
        if (left < wait) wait = left;
        if (wait < 0) wait = 0;
        if (poll(events, count, wait) < 0 && errno != EINTR) usleep(100000);
        if (tty_slot < 0 || !events[tty_slot].revents) continue;
        ssize_t sent = write(fds.usb_tty, out_p, out_n);
        if (sent > 0) { out_p += sent; out_n -= sent; continue; }
        if (sent < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        // Hung up (USB reset or cable): reopen on the next tick and start the stream again.
        close(fds.usb_tty);
        fds.usb_tty = -1;
        tty_failed = 1;
        out_n = 0;
    }
}

// ---- PID 1 ----

static int watch(const char *path, uint32_t mask)
{
    return inotify_add_watch(fds.notify, P(path), mask | IN_ONLYDIR);
}

static int start_logger(void)
{
    if (gadget_setup()) { reportf("gadget setup failed: %s%s", strerror(errno), ""); return -1; }
    if (chdir("/")) return -1;
    fds.kmsg_in = open(P("/dev/kmsg"), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    fds.dev = open(P("/dev"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    fds.udc_class = open(P("/sys/class/udc"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (USE_INOTIFY && (fds.notify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) >= 0 &&
        ((fds.watch_gadgets = watch("/sys/kernel/config/usb_gadget", IN_CREATE | IN_MOVED_TO)) < 0 ||
         (fds.watch_gadget = watch("/sys/kernel/config/usb_gadget/" GADGET, IN_ATTRIB | IN_MODIFY)) < 0 ||
         (fds.watch_functions = watch("/sys/kernel/config/usb_gadget/" GADGET "/functions", IN_CREATE | IN_MOVED_TO)) < 0)) {
        close(fds.notify);
        fds.notify = -1;
    }
    if (fds.notify < 0) report("inotify unavailable; g1 rescan and timeout only");
    if (fds.kmsg_in < 0 || fds.dev < 0 || fds.udc_class < 0) { report("logger fds failed"); return -1; }
    tty_node();
    fds.usb_tty = open_tty();
    make_banner();
    pid_t child = fork();
    if (child == 0) logger();
    if (child < 0) { report("fork failed"); return -1; }
    // Only the logger keeps the tty, so its hand-back can remove the function without waiting on us.
    if (fds.usb_tty >= 0) close(fds.usb_tty);
    fds.usb_tty = -1;
    return 0;
}

// The logger could not start: close the tty, then remove our link and function. Never g1, which
// stays the boot's android_device; Android's rc fills in the rest. The logger never bound UDC.
static void drop_gadget(void)
{
    if (fds.usb_tty >= 0) close(fds.usb_tty);
    fds.usb_tty = -1;
    if (!fds.made) return;
    int gadget = openat(fds.gadgets, GADGET, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (gadget >= 0) {
        drop_own_function(gadget);
        close(gadget);
    }
}

static void check_unmounted(const char *path)
{
    struct stat root, info;
    if (!stat(P("/"), &root) && !stat(path, &info) && info.st_dev != root.st_dev)
        reportf("%s is still a mount point; Android init may refuse to mount it%s", path, "");
}

int main(int argc, char **argv)
{
    (void)argc;
    // No signal or umask changes here: Android init inherits them across the exec.
    clock_gettime(CLOCK_BOOTTIME, &started);
#ifdef FIRSTBOOT_HOST_TEST
    snprintf(test_root, sizeof(test_root), "%s", getenv("FIRSTBOOT_TEST_ROOT") ? getenv("FIRSTBOOT_TEST_ROOT") : "/nonexistent");
#endif
    directory(P("/proc")); directory(P("/sys")); directory(P("/dev"));
    int proc = !fs_mount("proc", P("/proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC);
    int sys = !fs_mount("sysfs", P("/sys"), "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC);
    int dev = !fs_mount("devtmpfs", P("/dev"), "devtmpfs", MS_NOSUID);
    fds.kmsg_out = open(P("/dev/kmsg"), KMSG_OUT_FLAGS);
    reportf("wrapper init started; saving pstore, then Android init from %s%s", EXEC_PATH, "");
    if (!proc || !sys || !dev) report("proc, sysfs or devtmpfs mount failed; continuing to Android init");
    if (sys) save_pstore();
    if (!sys || start_logger()) {
        if (chdir("/")) { /* drop_gadget only uses directory fds */ }
        drop_gadget();
        report("logger not started; no USB stream this boot");
    }
    if (chdir("/")) { /* stays where it is; Android init uses absolute paths */ }
    // Android first-stage init mounts proc and sysfs itself and treats EBUSY as fatal, and
    // switch-root moves every mount it finds. Detach ours so it sees a bare initramfs; the
    // logger keeps its fds into the detached trees.
    fs_umount(P("/sys/kernel/config"), MNT_DETACH);
    fs_umount(P("/sys"), MNT_DETACH);
    fs_umount(P("/proc"), MNT_DETACH);
    fs_umount(P("/dev"), MNT_DETACH);
    check_unmounted(P("/proc")); check_unmounted(P("/sys")); check_unmounted(P("/dev"));
    execv(EXEC_PATH, argv);
    reportf("exec %s failed: %s", EXEC_PATH, strerror(errno));
    // PID 1 exiting makes the kernel panic; panic=10 then restarts through the software path.
    return 127;
}
