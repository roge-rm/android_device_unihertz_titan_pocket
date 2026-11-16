// SPDX-License-Identifier: Apache-2.0
// Linked into camerahalserver-pocket, which runs the stock camerahalserver.
// Fixes the RAW_SENSOR rows of the stock HAL's static metadata: camera 0
// advertises RAW at 4672x3504 but its min frame and stall durations only have a
// RAW row for 4000x3000, which apps such as GCam reject. An orphan RAW duration
// row (a size with no RAW stream configuration) is rewritten in place to the
// advertised size, taking the JPEG value at that size, so the entry count and
// buffer layout stay the same.
//
// The HAL calls sort_camera_metadata() on the static metadata right after
// converting it (MetadataProvider::constructStaticMetadata in
// libmtkcam_metastore.so), so this wraps that call. Bionic's global group is
// the main executable, LD_PRELOADs and libraries flagged DF_1_GLOBAL; this one
// is linked with -z global, so its definition wins for every library loaded
// after the launcher.

#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define TAG "pocket_cammeta"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

// system/media/camera camera_metadata.h
typedef struct camera_metadata camera_metadata_t;
typedef struct {
    size_t index;
    uint32_t tag;
    uint8_t type;
    size_t count;
    union {
        uint8_t *u8;
        int32_t *i32;
        int64_t *i64;
        void *p;
    } data;
} camera_metadata_entry_t;

#define TYPE_INT32 1
#define TYPE_INT64 3
#define SCALER_STREAM_CONFIGS 0xd000a  // android.scaler.availableStreamConfigurations
#define SCALER_MIN_DURATIONS 0xd000b   // android.scaler.availableMinFrameDurations
#define SCALER_STALL_DURATIONS 0xd000c // android.scaler.availableStallDurations
#define FORMAT_RAW_SENSOR 0x20
#define FORMAT_BLOB 0x21
#define DIRECTION_OUTPUT 0
#define MAX_RAW_SIZES 8

typedef int (*sort_fn)(camera_metadata_t *);
typedef int (*find_fn)(camera_metadata_t *, uint32_t, camera_metadata_entry_t *);

static sort_fn real_sort;
static find_fn real_find;
static pthread_once_t once = PTHREAD_ONCE_INIT;

// libcamera_metadata comes from the VNDK and may not be loaded yet when this
// library is, so it is looked up on the first call.
static void resolve(void) {
    void *h = dlopen("libcamera_metadata.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h)
        h = dlopen("libcamera_metadata.so", RTLD_NOW);
    if (h) {
        real_sort = (sort_fn)dlsym(h, "sort_camera_metadata");
        real_find = (find_fn)dlsym(h, "find_camera_metadata_entry");
    }
    if (!real_sort)
        real_sort = (sort_fn)dlsym(RTLD_NEXT, "sort_camera_metadata");
    if (!real_find)
        real_find = (find_fn)dlsym(RTLD_NEXT, "find_camera_metadata_entry");
    if (!real_sort || !real_find)
        LOGW("libcamera_metadata not found, metadata left as is");
}

static int64_t *find_row(int64_t *rows, size_t n, int64_t fmt, int64_t w, int64_t h) {
    for (size_t i = 0; i + 4 <= n; i += 4)
        if (rows[i] == fmt && rows[i + 1] == w && rows[i + 2] == h)
            return rows + i;
    return NULL;
}

static int is_raw_size(const int32_t (*sizes)[2], int count, int64_t w, int64_t h) {
    for (int i = 0; i < count; i++)
        if (sizes[i][0] == w && sizes[i][1] == h)
            return 1;
    return 0;
}

static void fix_durations(camera_metadata_t *m, uint32_t tag, const char *name,
                          const int32_t (*sizes)[2], int count) {
    camera_metadata_entry_t e;
    if (real_find(m, tag, &e) != 0 || e.type != TYPE_INT64 || e.count % 4)
        return;
    int64_t *rows = e.data.i64;
    for (int s = 0; s < count; s++) {
        int64_t w = sizes[s][0], h = sizes[s][1];
        if (find_row(rows, e.count, FORMAT_RAW_SENSOR, w, h))
            continue;
        int64_t *jpeg = find_row(rows, e.count, FORMAT_BLOB, w, h);
        int64_t *orphan = NULL;
        for (size_t i = 0; i + 4 <= e.count && !orphan; i += 4)
            if (rows[i] == FORMAT_RAW_SENSOR && !is_raw_size(sizes, count, rows[i + 1], rows[i + 2]))
                orphan = rows + i;
        if (!jpeg || !orphan) {
            LOGW("%s: no RAW row for %lldx%lld and no %s to take one from", name,
                 (long long)w, (long long)h, jpeg ? "orphan RAW row" : "JPEG row");
            continue;
        }
        LOGI("%s: RAW %lldx%lld %lld ns replaces RAW %lldx%lld %lld ns", name, (long long)w,
             (long long)h, (long long)jpeg[3], (long long)orphan[1], (long long)orphan[2],
             (long long)orphan[3]);
        orphan[1] = w;
        orphan[2] = h;
        orphan[3] = jpeg[3];
    }
}

static void fix_raw(camera_metadata_t *m) {
    camera_metadata_entry_t e;
    if (real_find(m, SCALER_STREAM_CONFIGS, &e) != 0 || e.type != TYPE_INT32 || e.count % 4)
        return;
    int32_t sizes[MAX_RAW_SIZES][2];
    int count = 0;
    for (size_t i = 0; i + 4 <= e.count && count < MAX_RAW_SIZES; i += 4) {
        const int32_t *r = e.data.i32 + i;
        if (r[0] == FORMAT_RAW_SENSOR && r[3] == DIRECTION_OUTPUT) {
            sizes[count][0] = r[1];
            sizes[count][1] = r[2];
            count++;
        }
    }
    if (!count)
        return;
    fix_durations(m, SCALER_MIN_DURATIONS, "availableMinFrameDurations", sizes, count);
    fix_durations(m, SCALER_STALL_DURATIONS, "availableStallDurations", sizes, count);
}

int sort_camera_metadata(camera_metadata_t *dst) {
    pthread_once(&once, resolve);
    if (!real_sort)
        return -1;
    if (dst && real_find)
        fix_raw(dst);
    return real_sort(dst);
}
