// SPDX-License-Identifier: Apache-2.0
// Runs the stock camerahalserver in this process with libpocketcammeta.so
// linked in, so the shim's sort_camera_metadata() wraps the HAL's.
//
// init can't preload it: the exec into mtk_hal_camera sets AT_SECURE and bionic
// drops LD_PRELOAD, and AOSP policy forbids hal_camera_server from exec without
// a domain change. So this loads the stock executable with dlopen() (vendor's
// default namespace permits /vendor) and calls its main(). Its preinit, init and
// fini arrays are empty, so nothing of its startup is skipped.

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define TAG "camerahalserver-pocket"
#define HALSERVER "/vendor/bin/hw/camerahalserver"
// Stock January vendor camerahalserver: GNU build id and main() offset (the
// R_AARCH64_RELATIVE value in its GOT that _start passes to __libc_init).
static const unsigned char BUILD_ID[16] = {0x65, 0x5d, 0x3f, 0xfc, 0xc5, 0x2d, 0xf9, 0xda,
                                           0x1a, 0x4d, 0xc0, 0x23, 0x98, 0x93, 0x94, 0x76};
#define MAIN_OFFSET 0x2048

extern int sort_camera_metadata(void *);

struct found {
    ElfW(Addr) base;
    int build_id_ok;
};

static int match(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct found *f = data;
    const char *suffix = "/bin/hw/camerahalserver";
    size_t len = info->dlpi_name ? strlen(info->dlpi_name) : 0;
    if (len < strlen(suffix) || strcmp(info->dlpi_name + len - strlen(suffix), suffix) != 0)
        return 0;
    f->base = info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_NOTE)
            continue;
        const char *p = (const char *)(info->dlpi_addr + ph->p_vaddr);
        const char *end = p + ph->p_memsz;
        while (p + sizeof(ElfW(Nhdr)) <= end) {
            const ElfW(Nhdr) *n = (const ElfW(Nhdr) *)p;
            const char *name = p + sizeof(*n);
            const unsigned char *desc = (const unsigned char *)name + ((n->n_namesz + 3) & ~3u);
            if (n->n_type == NT_GNU_BUILD_ID && n->n_namesz == 4 && !memcmp(name, "GNU", 4) &&
                n->n_descsz == sizeof(BUILD_ID) && !memcmp(desc, BUILD_ID, sizeof(BUILD_ID)))
                f->build_id_ok = 1;
            p = (const char *)desc + ((n->n_descsz + 3) & ~3u);
        }
    }
    return 1;
}

// Logs to logcat and, where the policy lets it, to the kernel log.
__attribute__((format(printf, 1, 2))) static void fail(const char *fmt, ...) {
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    __android_log_write(ANDROID_LOG_FATAL, TAG, msg);
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        dprintf(fd, "<3>" TAG ": %s\n", msg);
        close(fd);
    }
}

int main(int argc, char **argv) {
    // Keep the shim linked even with --as-needed.
    volatile void *keep = (void *)sort_camera_metadata;
    (void)keep;
    prctl(PR_SET_NAME, "camerahalserver");
    if (!dlopen(HALSERVER, RTLD_NOW)) {
        fail("dlopen %s: %s; camera disabled", HALSERVER, dlerror());
        return 1;
    }
    struct found f = {0, 0};
    dl_iterate_phdr(match, &f);
    if (!f.base || !f.build_id_ok) {
        // The main() offset only fits that build, so calling it would crash.
        fail("%s is not the stock build (build id 655d3ffc...) this launcher was made for; "
             "camera disabled, rebuild the launcher for the new binary", HALSERVER);
        return 1;
    }
    int (*stock_main)(int, char **) = (int (*)(int, char **))(f.base + MAIN_OFFSET);
    argv[0] = (char *)HALSERVER;
    return stock_main(argc, argv);
}
