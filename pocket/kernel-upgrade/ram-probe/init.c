// SPDX-License-Identifier: GPL-2.0-only
// RAM bring-up logger. Optional bounded probes are selected by the wrapper.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>
#include "commands.h"

#ifndef PROBE_AFTER_MOUNTS
#define PROBE_AFTER_MOUNTS() ((void)0)
#endif
#ifndef PROBE_WORKLOAD
#define PROBE_WORKLOAD "RAM-only logger: no block devices opened or mounted by init."
#endif

#ifndef PROBE_LABEL
#define PROBE_LABEL "TP510-RAM"
#endif
#ifndef PROBE_PRODUCT
#define PROBE_PRODUCT "5.10 RAM diagnostic"
#endif
#ifndef PROBE_RETURN_SECONDS
#define PROBE_RETURN_SECONDS 0
#endif
// Serial input hooks. PROBE_SERIAL_INPUT returns nonzero when the probe took
// the bytes, so they are not parsed as commands.
#ifndef PROBE_SERIAL_INPUT
#define PROBE_SERIAL_INPUT(data, count) 0
#endif
#ifndef PROBE_POLL_TIMEOUT
#define PROBE_POLL_TIMEOUT() (-1)
#endif
#ifndef PROBE_POLL_TICK
#define PROBE_POLL_TICK() ((void)0)
#endif

static void report(const char *message)
{
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        dprintf(fd, "<6>" PROBE_LABEL ": %s\n", message);
        close(fd);
    }
    dprintf(STDERR_FILENO, PROBE_LABEL ": %s\n", message);
}

static int device_node(const char *path, unsigned major_number, unsigned minor_number)
{
    if (mknod(path, S_IFCHR | 0600, makedev(major_number, minor_number)) && errno != EEXIST)
        return -1;
    struct stat info;
    if (stat(path, &info) || !S_ISCHR(info.st_mode) ||
        info.st_rdev != makedev(major_number, minor_number)) return -1;
    return 0;
}

static int serial_node(void)
{
    FILE *stream = fopen("/sys/class/tty/ttyGS0/dev", "re");
    if (!stream) return -1;
    unsigned major_number, minor_number;
    int count = fscanf(stream, "%u:%u", &major_number, &minor_number);
    fclose(stream);
    return count == 2 ? device_node("/dev/ttyGS0", major_number, minor_number) : -1;
}

static void return_timer(void)
{
#if PROBE_RETURN_SECONDS > 0
    pid_t child = fork();
    if (child == 0) {
        unsigned remaining = PROBE_RETURN_SECONDS;
        while (remaining) remaining = sleep(remaining);
        report("automatic return timer expired; requesting normal restart");
        reboot(RB_AUTOBOOT);
        _exit(1);
    }
    if (child < 0) {
        report("return timer creation failed; requesting normal restart");
        reboot(RB_AUTOBOOT);
        for (;;) pause();
    }
#endif
}

static int directory(const char *path)
{
    if (mkdir(path, 0755) && errno != EEXIST) return -1;
    return 0;
}

static int setup_devices(void)
{
    if (directory("/dev")) return -1;
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") && errno != EBUSY) {
        if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755")) return -1;
    }
    if (device_node("/dev/console", 5, 1) || device_node("/dev/null", 1, 3) ||
        device_node("/dev/kmsg", 1, 11)) return -1;
    return 0;
}

static int attribute(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t length = strlen(value);
    ssize_t result = write(fd, value, length);
    int saved = errno;
    close(fd);
    errno = saved;
    return result == (ssize_t)length ? 0 : -1;
}

static int gadget(void)
{
    if (mount("configfs", "/sys/kernel/config", "configfs", MS_NOSUID | MS_NODEV, NULL) && errno != EBUSY)
        return -1;
    if (chdir("/sys/kernel/config/usb_gadget")) return -1;
    if (directory("tp510") || chdir("tp510")) return -1;
    if (attribute("idVendor", "0x1d6b") || attribute("idProduct", "0x0104") ||
        directory("strings/0x409") ||
        attribute("strings/0x409/serialnumber", PROBE_LABEL) ||
        attribute("strings/0x409/manufacturer", "Titan Pocket kernel bring-up") ||
        attribute("strings/0x409/product", PROBE_PRODUCT) ||
        directory("configs/c.1") || directory("configs/c.1/strings/0x409") ||
        attribute("configs/c.1/strings/0x409/configuration", "Kernel log stream") ||
        attribute("configs/c.1/MaxPower", "100") || directory("functions/acm.usb0"))
        return -1;
    // Configfs resolves the target immediately from the calling process's cwd;
    // unlike a regular filesystem, it does not resolve from the link's parent.
    if (symlink("functions/acm.usb0", "configs/c.1/acm.usb0") && errno != EEXIST) {
        char message[160];
        snprintf(message, sizeof(message), "link ACM function into USB configuration failed: %s", strerror(errno));
        report(message);
        return -1;
    }
    for (;;) {
        DIR *dir = opendir("/sys/class/udc");
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir))) {
                if (entry->d_name[0] == '.') continue;
                int result = attribute("UDC", entry->d_name);
                closedir(dir);
                return result;
            }
            closedir(dir);
        }
        report("waiting for USB device controller");
        sleep(5);
    }
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    return_timer();
    directory("/proc"); directory("/sys");
    if (setup_devices()) for (;;) pause();
    int console = open("/dev/console", O_RDWR | O_CLOEXEC);
    if (console >= 0) {
        for (int fd = 0; fd < 3; fd++) dup2(console, fd);
        if (console > 2) close(console);
    }
    report("init reached; RAM-only logger; no storage mounts or Android services");
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)) {
        report("proc/sysfs mount failed");
        for (;;) pause();
    }
    PROBE_AFTER_MOUNTS();
    if (gadget()) {
        report("USB gadget setup failed; UART/kernel logs needed");
        for (;;) pause();
    }
    report("ACM gadget bound; open the host serial port to receive kernel logs");
    for (;;) {
        if (serial_node()) { sleep(1); continue; }
        int serial = open("/dev/ttyGS0", O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (serial < 0) { sleep(1); continue; }
        struct termios mode;
        if (!tcgetattr(serial, &mode)) {
            cfmakeraw(&mode);
            tcsetattr(serial, TCSANOW, &mode);
        }
        struct utsname version;
        if (!uname(&version))
            dprintf(serial, "\n" PROBE_LABEL " %s %s\n" PROBE_WORKLOAD "\nCommands: reboot or reboot-bootloader followed by newline.\nAutomatic restart timer: %u seconds from init start (0 means disabled).\n",
                    version.sysname, version.release, (unsigned)PROBE_RETURN_SECONDS);
        int logs = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (logs < 0) {
            dprintf(serial, "Cannot open kernel log: %s\n", strerror(errno));
            close(serial); sleep(1); continue;
        }
        struct tpdiag_parser parser = {0};
        for (;;) {
            struct pollfd events[] = {{logs, POLLIN, 0}, {serial, POLLIN, 0}};
            if (poll(events, 2, PROBE_POLL_TIMEOUT()) < 0) {
                if (errno == EINTR) continue;
                break;
            }
            PROBE_POLL_TICK();
            if (events[1].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
            if (events[1].revents & POLLIN) {
                char input[32];
                ssize_t count = read(serial, input, sizeof(input));
                if (count <= 0) break;
                if (!PROBE_SERIAL_INPUT(input, count)) for (ssize_t i = 0; i < count; i++) {
                    enum tpdiag_command command = tpdiag_feed(&parser, input[i]);
                    if (command == TPDIAG_REBOOT) {
                        report("explicit USB reboot command received");
                        dprintf(serial, PROBE_LABEL ": requesting normal restart\n");
                        reboot(RB_AUTOBOOT);
                        report("reboot syscall failed");
                    } else if (command == TPDIAG_BOOTLOADER) {
                        report("explicit USB reboot-to-bootloader command received");
                        dprintf(serial, PROBE_LABEL ": requesting bootloader restart\n");
                        syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                                LINUX_REBOOT_CMD_RESTART2, "bootloader");
                        report("bootloader restart syscall failed");
                    }
                }
            }
            if (!(events[0].revents & POLLIN)) continue;
            char buffer[8192];
            ssize_t size = read(logs, buffer, sizeof(buffer));
            if (size < 0 && (errno == EINTR || errno == EPIPE || errno == EAGAIN)) continue;
            if (size <= 0) break;
            ssize_t sent = 0;
            while (sent < size) {
                ssize_t count = write(serial, buffer + sent, size - sent);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) break;
                sent += count;
            }
            if (sent != size) break;
        }
        close(logs); close(serial); sleep(1);
    }
}
