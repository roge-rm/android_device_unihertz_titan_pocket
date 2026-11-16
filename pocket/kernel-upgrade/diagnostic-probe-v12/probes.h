// SPDX-License-Identifier: GPL-2.0-only
// v12 probe helpers: everything v11 carries (v9's SHA-256, GPT parsing, read-only partition
// hashing, FDT memreserve parsing, ACM line hashing, the aw9523 reset sequence, the LP (super)
// metadata parser and the dm-ioctl buffer builders), plus two v12 additions for the TrustKernel
// keymaster session probe: a teed command-line builder that keeps every writable path under a
// tmpfs root and never emits an RPMB option, a builder for the legacy /dev/__properties__ area,
// and a raw-ioctl TEEC client that opens a context and a session on /dev/tkcoredrv. Host-testable; nothing here touches a device, and the parser and
// the builders only read or format.
#ifndef POCKET_DIAGNOSTIC_V12_PROBES_H
#define POCKET_DIAGNOSTIC_V12_PROBES_H
#include <errno.h>
#include <linux/dm-ioctl.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
// TrustKernel TEE client ABI: the actual stock tkcore uapi headers, for the session probe below.
#include <linux/tee_ioc.h>

typedef void (*tp8_report_fn)(const char *);

// ---- SHA-256 (FIPS 180-4), plain C ----
struct tp8_sha256 { uint32_t state[8]; uint64_t bytes; unsigned char block[64]; size_t used; };

static const uint32_t tp8_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define TP8_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void tp8_sha256_init(struct tp8_sha256 *c)
{
    static const uint32_t initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->state, initial, sizeof(initial));
    c->bytes = 0;
    c->used = 0;
}

static void tp8_sha256_block(uint32_t *s, const unsigned char *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = TP8_ROR(w[i-15], 7) ^ TP8_ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = TP8_ROR(w[i-2], 17) ^ TP8_ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + (TP8_ROR(e, 6) ^ TP8_ROR(e, 11) ^ TP8_ROR(e, 25)) + ((e & f) ^ (~e & g)) + tp8_k[i] + w[i];
        uint32_t t2 = (TP8_ROR(a, 2) ^ TP8_ROR(a, 13) ^ TP8_ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

static void tp8_sha256_update(struct tp8_sha256 *c, const void *data, size_t length)
{
    const unsigned char *p = data;
    c->bytes += length;
    if (c->used) {
        size_t take = 64 - c->used < length ? 64 - c->used : length;
        memcpy(c->block + c->used, p, take);
        c->used += take; p += take; length -= take;
        if (c->used < 64) return;
        tp8_sha256_block(c->state, c->block);
        c->used = 0;
    }
    for (; length >= 64; p += 64, length -= 64) tp8_sha256_block(c->state, p);
    memcpy(c->block, p, length);
    c->used = length;
}

// Finalizes a copy, so the caller can keep hashing for prefix checkpoints.
static void tp8_sha256_hex(const struct tp8_sha256 *context, char out[65])
{
    struct tp8_sha256 c = *context;
    uint64_t bits = c.bytes * 8;
    unsigned char pad = 0x80, zero = 0, length[8];
    tp8_sha256_update(&c, &pad, 1);
    while (c.used != 56) tp8_sha256_update(&c, &zero, 1);
    for (int i = 0; i < 8; ++i) length[i] = (unsigned char)(bits >> (56 - 8*i));
    tp8_sha256_update(&c, length, 8);
    for (int i = 0; i < 8; ++i) snprintf(out + 8*i, 9, "%08x", c.state[i]);
}

// ---- CRC32 (IEEE, reflected), as GPT uses ----
static uint32_t tp8_crc32(const unsigned char *p, size_t length)
{
    uint32_t crc = 0xffffffffu;
    while (length--) {
        crc ^= *p++;
        for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1));
    }
    return ~crc;
}

static uint64_t tp8_le64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = v << 8 | p[i];
    return v;
}
static uint32_t tp8_le32(const unsigned char *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
static uint64_t tp8_be64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = v << 8 | p[i];
    return v;
}
static uint32_t tp8_be32(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

// ---- GPT ----
struct tp8_gpt_part { char name[37]; uint64_t first, last; unsigned index; };

#define TP8_GPT_MAX_ENTRIES 256u

// Reads the primary GPT at LBA 1 with bounded preads; checks both CRCs.
// Returns the number of used entries, or -1 with a short reason.
static int tp8_gpt_read(int fd, unsigned lbs, uint64_t disk_blocks, struct tp8_gpt_part *parts,
                        unsigned max, const char **why)
{
    if (lbs < 512 || lbs > 4096 || (lbs & (lbs - 1))) { *why = "bad_block_size"; return -1; }
    unsigned char header[4096];
    ssize_t n = pread(fd, header, lbs, lbs);
    if (n != (ssize_t)lbs) { *why = "header_read"; return -1; }
    if (memcmp(header, "EFI PART", 8)) { *why = "no_signature"; return -1; }
    uint32_t size = tp8_le32(header + 12), crc = tp8_le32(header + 16);
    if (size < 92 || size > lbs) { *why = "header_size"; return -1; }
    memset(header + 16, 0, 4);
    if (tp8_crc32(header, size) != crc) { *why = "header_crc"; return -1; }
    uint64_t current = tp8_le64(header + 24), last_usable = tp8_le64(header + 48);
    uint64_t entries_lba = tp8_le64(header + 72);
    uint32_t count = tp8_le32(header + 80), entry_size = tp8_le32(header + 84), entries_crc = tp8_le32(header + 88);
    if (current != 1 || last_usable >= disk_blocks) { *why = "header_lba"; return -1; }
    if (!count || count > TP8_GPT_MAX_ENTRIES || entry_size < 128 || entry_size > 512 || entry_size % 8) {
        *why = "entry_geometry"; return -1;
    }
    size_t table = (size_t)count * entry_size;
    if (entries_lba < 2 || entries_lba >= disk_blocks || entries_lba > UINT64_MAX / lbs) { *why = "entry_lba"; return -1; }
    unsigned char *entries = malloc(table);
    if (!entries) { *why = "no_memory"; return -1; }
    n = pread(fd, entries, table, (off_t)(entries_lba * lbs));
    if (n != (ssize_t)table || tp8_crc32(entries, table) != entries_crc) {
        free(entries); *why = n != (ssize_t)table ? "entries_read" : "entries_crc"; return -1;
    }
    unsigned used = 0;
    static const unsigned char unused[16];
    for (uint32_t i = 0; i < count && used < max; ++i) {
        const unsigned char *e = entries + (size_t)i * entry_size;
        if (!memcmp(e, unused, 16)) continue;
        struct tp8_gpt_part *part = &parts[used];
        part->first = tp8_le64(e + 32);
        part->last = tp8_le64(e + 40);
        part->index = i + 1;
        size_t k = 0;
        for (; k < 36; ++k) {
            unsigned code = e[56 + 2*k] | e[57 + 2*k] << 8;
            if (!code) break;
            part->name[k] = code >= 32 && code < 127 ? (char)code : '?';
        }
        part->name[k] = 0;
        if (part->first > part->last || part->last > last_usable) continue;
        ++used;
    }
    free(entries);
    return (int)used;
}

static double tp8_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

#define TP8_CHUNK (1u << 20)
#define TP8_CHECKPOINT (1ull << 30)

// Hashes bytes [offset, offset + bytes) with bounded 1 MiB preads. Stops at
// the monotonic deadline and logs the prefix hash reached, which stock can
// reproduce with head -c. Never writes. Returns 0 when the whole range hashed.
static int tp8_hash_range(int fd, const char *name, uint64_t offset, uint64_t bytes,
                          double deadline, tp8_report_fn report)
{
    char message[320], hex[65];
    unsigned char *buffer = malloc(TP8_CHUNK);
    if (!buffer) { snprintf(message, sizeof(message), "part-hash name=%s no_memory", name); report(message); return -1; }
    struct tp8_sha256 c;
    tp8_sha256_init(&c);
    double start = tp8_now(), reading = 0;
    uint64_t done = 0, next_checkpoint = TP8_CHECKPOINT;
    int error = 0, stopped = 0;
    while (done < bytes) {
        if (tp8_now() >= deadline) { stopped = 1; break; }
        size_t want = bytes - done < TP8_CHUNK ? (size_t)(bytes - done) : TP8_CHUNK;
        double before = tp8_now();
        ssize_t n = pread(fd, buffer, want, (off_t)(offset + done));
        reading += tp8_now() - before;
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : -1; break; }
        tp8_sha256_update(&c, buffer, (size_t)n);
        done += (uint64_t)n;
#ifdef POSIX_FADV_DONTNEED
        if (!(done % (64u << 20))) (void)posix_fadvise(fd, (off_t)offset, (off_t)done, POSIX_FADV_DONTNEED);
#endif
        if (done == next_checkpoint && done < bytes) {
            tp8_sha256_hex(&c, hex);
            snprintf(message, sizeof(message), "part-hash name=%s prefix_bytes=%llu sha256=%s seconds=%.2f",
                     name, (unsigned long long)done, hex, tp8_now() - start);
            report(message);
            next_checkpoint += TP8_CHECKPOINT;
        }
    }
    free(buffer);
    double elapsed = tp8_now() - start;
    double mib = done / 1048576.0;
    tp8_sha256_hex(&c, hex);
    if (done == bytes)
        snprintf(message, sizeof(message),
                 "part-hash name=%s bytes=%llu sha256=%s seconds=%.2f read_seconds=%.2f mibps=%.1f read_mibps=%.1f",
                 name, (unsigned long long)bytes, hex, elapsed, reading,
                 elapsed > 0 ? mib / elapsed : 0, reading > 0 ? mib / reading : 0);
    else
        snprintf(message, sizeof(message),
                 "part-hash name=%s %s=%d partial prefix_bytes=%llu of=%llu sha256=%s seconds=%.2f read_seconds=%.2f mibps=%.1f",
                 name, stopped ? "stopped_at_deadline" : "read_error", stopped ? 1 : error,
                 (unsigned long long)done, (unsigned long long)bytes, hex, elapsed, reading,
                 elapsed > 0 ? mib / elapsed : 0);
    report(message);
    return done == bytes ? 0 : -1;
}

// ---- FDT memreserve block ----
// Parses at most max entries from a flattened tree; returns the count or -1.
static int tp8_memreserve(const unsigned char *fdt, size_t length, uint64_t *base, uint64_t *size, unsigned max)
{
    if (length < 40 || tp8_be32(fdt) != 0xd00dfeedu) return -1;
    uint32_t total = tp8_be32(fdt + 4), offset = tp8_be32(fdt + 16);
    if (total > length || offset < 40 || offset % 8 || offset >= total) return -1;
    unsigned count = 0;
    for (uint32_t at = offset; at + 16 <= total; at += 16) {
        uint64_t b = tp8_be64(fdt + at), s = tp8_be64(fdt + at + 8);
        if (!b && !s) return (int)count;
        if (count == max) return -1;
        base[count] = b; size[count] = s; ++count;
    }
    return -1;
}

// Formats big-endian address/size cell pairs as "0xbase+0xsize,...", or
// "0xsize" when there are no address cells.
// Returns the number of pairs, or -1 when the length does not fit the cells.
static int tp8_cells(const unsigned char *data, size_t length, unsigned address_cells, unsigned size_cells,
                     char *out, size_t out_length)
{
    size_t pair = 4u * (address_cells + size_cells);
    out[0] = 0;
    if (!pair || address_cells > 2 || size_cells > 2 || length % pair) return -1;
    size_t used = 0;
    int count = 0;
    for (size_t at = 0; at < length; at += pair, ++count) {
        uint64_t a = 0, s = 0;
        for (unsigned i = 0; i < address_cells; ++i) a = a << 32 | tp8_be32(data + at + 4*i);
        for (unsigned i = 0; i < size_cells; ++i) s = s << 32 | tp8_be32(data + at + 4*(address_cells + i));
        int n = address_cells
            ? snprintf(out + used, out_length - used, "%s0x%llx+0x%llx", count ? "," : "",
                       (unsigned long long)a, (unsigned long long)s)
            : snprintf(out + used, out_length - used, "%s0x%llx", count ? "," : "", (unsigned long long)s);
        if (n < 0 || (size_t)n >= out_length - used) {
            if (out_length > 4) strcpy(out + out_length - 4, "...");
            return count + 1;
        }
        used += (size_t)n;
    }
    return count;
}

// UDC names are platform device names such as "11201000.usb3", so dots are
// allowed; ".", ".." and anything with a slash are not.
static int tp8_udc_name(const char *name)
{
    size_t length = strnlen(name, 64);
    if (!length || length == 64 || name[0] == '.') return 0;
    for (size_t i = 0; i < length; ++i) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              c == '.' || c == '_' || c == '-' || c == ':')) return 0;
    }
    return 1;
}

// ---- ACM line hashing ----
// Bytes are hashed per newline-terminated line and never interpreted.
struct tp8_lines { struct tp8_sha256 hash; uint64_t length, total; unsigned lines; };

static void tp8_lines_init(struct tp8_lines *l)
{
    memset(l, 0, sizeof(*l));
    tp8_sha256_init(&l->hash);
}

#define TP8_ECHO_MAX_LOGGED 64u

static void tp8_lines_feed(struct tp8_lines *l, const char *data, size_t count, tp8_report_fn report)
{
    l->total += count;
    size_t start = 0;
    for (size_t i = 0; i < count; ++i) {
        if (data[i] != '\n') continue;
        tp8_sha256_update(&l->hash, data + start, i - start);
        l->length += i - start;
        start = i + 1;
        if (++l->lines <= TP8_ECHO_MAX_LOGGED) {
            char hex[65], message[160];
            tp8_sha256_hex(&l->hash, hex);
            snprintf(message, sizeof(message), "acm-echo line=%u bytes=%llu sha256=%s",
                     l->lines, (unsigned long long)l->length, hex);
            report(message);
        }
        tp8_sha256_init(&l->hash);
        l->length = 0;
    }
    tp8_sha256_update(&l->hash, data + start, count - start);
    l->length += count - start;
}

// ---- I2C chip ID reads ----
// Known stock addresses only. Each read is one I2C_RDWR transaction: a write of
// the register pointer (1 or 2 bytes) and a short read. No bus scan, no other
// writes. A chip with a supply gate is only read if that regulator already
// reports enabled; nothing here turns a supply on. The only GPIO write is the
// aw9523 reset pulse below, and only after a NACK.
#define TP9_AW9523_RESET_GPIO 178
// aw9523 interrupt line, logged only.
#define TP9_AW9523_INT_GPIO 0
struct tp8_i2c_target {
    const char *device;     // platform device of the controller
    unsigned stock_bus;     // bus number on the stock kernel
    const char *chip;
    uint16_t address;       // 7-bit
    unsigned char reg[2];
    unsigned reg_length, read_length;
    const char *supply;     // regulator that must already be on, or NULL
    int expect;             // expected first byte, or -1
    int reset_gpio;         // reset line pulsed only after a NACK, or -1
};

static const struct tp8_i2c_target tp8_i2c_targets[] = {
    // GT1151 picks 0x5d or 0x14 from the INT level at reset; both are tried, never reset.
    {"11007000.i2c", 0, "gt1151qm", 0x5d, {0x81, 0x40}, 2, 4, "vldo28", -1, -1},
    {"11007000.i2c", 0, "gt1151qm", 0x14, {0x81, 0x40}, 2, 4, "vldo28", -1, -1},
    {"1100f000.i2c", 3, "fs16xx", 0x34, {0x03}, 1, 2, NULL, -1, -1},
    {"11005000.i2c", 6, "oz8806", 0x2f, {0x00}, 1, 1, NULL, -1, -1},
    {"11005000.i2c", 6, "synaptics-pad", 0x20, {0xe9}, 1, 6, NULL, -1, -1},
    {"11005000.i2c", 6, "synaptics-pad", 0x2c, {0xe9}, 1, 6, NULL, -1, -1},
    // aw9523 keyboard: stock probe reads reg 0x10 and wants 0x23. Reset is GPIO 178, no supply.
    {"11008000.i2c", 4, "aw9523", 0x58, {0x10}, 1, 1, NULL, 0x23, TP9_AW9523_RESET_GPIO},
};
#define TP8_I2C_TARGETS (sizeof(tp8_i2c_targets) / sizeof(tp8_i2c_targets[0]))
#define TP8_I2C_MAX_READ 8u

static int tp8_i2c_target_valid(const struct tp8_i2c_target *t)
{
    return t->address >= 0x08 && t->address <= 0x77 && t->reg_length >= 1 && t->reg_length <= 2 &&
           t->read_length >= 1 && t->read_length <= TP8_I2C_MAX_READ;
}

// ---- aw9523 reset after a NACK ----
// Stock aw9523_i2c_probe drives reset 1, 0, msleep(1), 1, msleep(1), then tries
// the ID read 3 times 5 ms apart. Here the read runs once with no reset; only
// an ENXIO (NACK) leads to one pulse, then up to 3 more reads.
#define TP9_RESET_LOW_US 2000u     // at least 1 ms low
#define TP9_RESET_SETTLE_US 5000u  // high before the first retry
#define TP9_RETRY_GAP_US 5000u
#define TP9_RETRIES 3u

struct tp9_reset_ops {
    int (*read_id)(void *ctx);           // one ID read; 0 or an errno
    int (*request_high)(void *ctx);      // request the line as output, value 1; 0 or an errno
    int (*set)(void *ctx, int value);    // 0 or an errno
    void (*sleep_us)(void *ctx, unsigned us);
    void (*release)(void *ctx);
};

struct tp9_reset_result {
    int error;          // errno of the last read, 0 on success
    unsigned reads;     // ID reads done, 1 to 1 + TP9_RETRIES
    int pulsed;         // 1 when the whole pulse went through
    int gpio_error;     // errno of a failed GPIO step, else 0
};

static void tp9_step(tp8_report_fn report, const char *step, int error)
{
    char message[120];
    snprintf(message, sizeof(message), "aw9523 reset gpio=%u step=%s errno=%d", TP9_AW9523_RESET_GPIO, step, error);
    report(message);
}

static void tp9_read_line(tp8_report_fn report, unsigned attempt, int reset, int error)
{
    char message[120];
    snprintf(message, sizeof(message), "aw9523 read attempt=%u after_reset=%d errno=%d", attempt, reset, error);
    report(message);
}

static struct tp9_reset_result tp9_reset_read(const struct tp9_reset_ops *ops, void *ctx, tp8_report_fn report)
{
    struct tp9_reset_result r = {0, 1, 0, 0};
    r.error = ops->read_id(ctx);
    tp9_read_line(report, 0, 0, r.error);
    if (r.error != ENXIO) return r;
    r.gpio_error = ops->request_high(ctx);
    tp9_step(report, "request-output-high", r.gpio_error);
    if (r.gpio_error) return r;
    r.gpio_error = ops->set(ctx, 0);
    tp9_step(report, "low", r.gpio_error);
    if (!r.gpio_error) {
        ops->sleep_us(ctx, TP9_RESET_LOW_US);
        r.gpio_error = ops->set(ctx, 1);
        tp9_step(report, "high", r.gpio_error);
    }
    if (!r.gpio_error) {
        ops->sleep_us(ctx, TP9_RESET_SETTLE_US);
        r.pulsed = 1;
    }
    ops->release(ctx);
    tp9_step(report, "released", 0);
    if (!r.pulsed) return r;
    for (unsigned attempt = 1; attempt <= TP9_RETRIES; ++attempt) {
        if (attempt > 1) ops->sleep_us(ctx, TP9_RETRY_GAP_US);
        r.error = ops->read_id(ctx);
        ++r.reads;
        tp9_read_line(report, attempt, 1, r.error);
        // Only a NACK is worth another try; anything else points at the bus.
        if (r.error != ENXIO) {
            if (r.error) {
                char message[120];
                snprintf(message, sizeof(message), "aw9523 retry stopped attempt=%u errno=%d", attempt, r.error);
                report(message);
            }
            break;
        }
    }
    return r;
}

// Returns N for a sysfs entry named exactly "i2c-N", otherwise -1.
static int tp8_i2c_adapter_name(const char *name)
{
    if (strncmp(name, "i2c-", 4) || !name[4]) return -1;
    long value = 0;
    for (const char *p = name + 4; *p; ++p) {
        if (*p < '0' || *p > '9' || p - name > 8) return -1;
        value = value * 10 + (*p - '0');
    }
    if (name[4] == '0' && name[5]) return -1;
    return (int)value;
}

static void tp8_hex_bytes(const unsigned char *data, size_t length, char *out, size_t out_length)
{
    static const char digits[] = "0123456789abcdef";
    size_t used = 0;
    if (!out_length) return;
    for (size_t i = 0; i < length && used + 2 < out_length; ++i) {
        out[used++] = digits[data[i] >> 4];
        out[used++] = digits[data[i] & 15];
    }
    out[used] = 0;
}

// ---- Touchpad reset test ----
// Only for the synaptics-pad on GPIO 9, and only when the reads at 0x20 and 0x2c both
// NACK. Stock's sequence: request the line high, wait 200 ms, low for 20 ms, high, wait 200 ms.
// Then reg 0xe9 is read from 0x20, 0x2c, and 0x20 again after a short gap.
#define TP11_PAD_RESET_GPIO 9
#define TP11_PAD_HIGH_US 200000u
#define TP11_PAD_LOW_US 20000u
#define TP11_PAD_RETRY_GAP_US 5000u
struct tp11_pad_step { int value; unsigned wait_us; };
// The first value is the one the line is requested with; each wait follows its value.
static const struct tp11_pad_step tp11_pad_steps[] = {
    {1, TP11_PAD_HIGH_US}, {0, TP11_PAD_LOW_US}, {1, TP11_PAD_HIGH_US},
};
#define TP11_PAD_STEPS (sizeof(tp11_pad_steps) / sizeof(tp11_pad_steps[0]))
// Sleep time of the whole test in microseconds: the steps plus the gap before the third read.
#define TP11_PAD_SLEEP_US (TP11_PAD_HIGH_US + TP11_PAD_LOW_US + TP11_PAD_HIGH_US + TP11_PAD_RETRY_GAP_US)

static int tp11_pad_needs_reset(int error_first, int error_second)
{
    return error_first == ENXIO && error_second == ENXIO;
}

// The i2c result line shared by every ID read. extra is appended as is.
static void tp11_i2c_line(char *out, size_t length, const struct tp8_i2c_target *t, int adapter,
                          int status, int error, const unsigned char *data, const char *state,
                          double ms, const char *extra)
{
    char hex[2 * TP8_I2C_MAX_READ + 1] = "", reg[8];
    tp8_hex_bytes(t->reg, t->reg_length, reg, sizeof(reg));
    if (status == 2) {
        tp8_hex_bytes(data, t->read_length, hex, sizeof(hex));
        char match[32] = "";
        if (t->expect >= 0) snprintf(match, sizeof(match), " expect=%02x match=%s", t->expect, data[0] == t->expect ? "yes" : "no");
        snprintf(out, length, "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=%s result=ok%s supply=%s ms=%.0f%s",
                 t->stock_bus, adapter, t->address, t->chip, reg, hex, match, state, ms, extra);
    } else {
        // ENXIO is a NACK: absent, unpowered or held in reset. ETIMEDOUT/EIO point at the bus.
        snprintf(out, length, "i2c bus=%u adapter=%d addr=0x%02x chip=%s reg=%s id=- result=error status=%d errno=%d supply=%s ms=%.0f%s",
                 t->stock_bus, adapter, t->address, t->chip, reg, status, error, state, ms, extra);
    }
}

// ---- Userdata restore-on-exit write test ----
// The four steps the draft lists, driven through callbacks so the host can run them
// against a sparse file and inject a failed write. The caller confines every offset to
// the region (the last 1 MiB of userdata); this code never names a device. Write budget
// is 2*region + one block. The pattern carries only a marker, a block counter and the
// absolute LBA, never user data.
#define TP10_WR_BLOCK 4096u
#define TP10_WR_MARKER "TP10-USERDATA-WR"
#define TP10_WR_FUA_MARKER "TP10-USERDATA-FUA"

struct tp10_write_ops {
    // Offsets are relative to the start of the region. fua asks for a durable FUA write.
    ssize_t (*pread)(void *ctx, void *buf, size_t length, uint64_t off);
    ssize_t (*pwrite)(void *ctx, const void *buf, size_t length, uint64_t off, int fua);
    int (*sync)(void *ctx);
};

struct tp10_write_result {
    int step1_ok, step2_ok, step3_ok, restore_attempted, restore_ok;
    uint64_t bytes_written, budget;
    char original_sha256[65];
};

static void tp10_fill_pattern(unsigned char *buf, size_t length, uint64_t region_base_lba, const char *marker)
{
    memset(buf, 0, length);
    size_t mlen = strlen(marker);
    if (mlen > TP10_WR_BLOCK) mlen = TP10_WR_BLOCK;
    for (size_t b = 0; (b + 1) * TP10_WR_BLOCK <= length; ++b) {
        unsigned char *blk = buf + b * TP10_WR_BLOCK;
        memcpy(blk, marker, mlen);
        uint32_t counter = (uint32_t)b;
        uint64_t lba = region_base_lba + (uint64_t)b * (TP10_WR_BLOCK / 512);
        memcpy(blk + 24, &counter, 4);
        memcpy(blk + 32, &lba, 8);
    }
}

static struct tp10_write_result tp10_write_test(const struct tp10_write_ops *ops, void *ctx,
                                                size_t region, uint64_t region_base_lba, tp8_report_fn report)
{
    struct tp10_write_result r;
    memset(&r, 0, sizeof(r));
    r.budget = 2ull * region + TP10_WR_BLOCK;
    char message[320], hex_now[65];
    void *orig = NULL, *pattern = NULL, *verify = NULL;
    if (posix_memalign(&orig, TP10_WR_BLOCK, region) || posix_memalign(&pattern, TP10_WR_BLOCK, region) ||
        posix_memalign(&verify, TP10_WR_BLOCK, region)) {
        report("userdata-write no aligned memory; no write");
        free(orig); free(pattern); free(verify);
        return r;
    }
    double t;
    // Step 1: read the original region; a short or failed read ends the test before any write.
    t = tp8_now();
    ssize_t rn = ops->pread(ctx, orig, region, 0);
    if (rn != (ssize_t)region) {
        snprintf(message, sizeof(message), "userdata-write step1 read=%zd errno=%d us=%.0f; no write",
                 rn, rn < 0 ? errno : 0, (tp8_now() - t) * 1e6);
        report(message);
        goto done;
    }
    {
        struct tp8_sha256 c;
        tp8_sha256_init(&c);
        tp8_sha256_update(&c, orig, region);
        tp8_sha256_hex(&c, r.original_sha256);
    }
    r.step1_ok = 1;
    snprintf(message, sizeof(message), "userdata-write step1 original sha256=%s us=%.0f", r.original_sha256, (tp8_now() - t) * 1e6);
    report(message);
    tp10_fill_pattern(pattern, region, region_base_lba, TP10_WR_MARKER);
    // Step 2: write the region, fdatasync (FLUSH), read back, compare.
    t = tp8_now();
    {
        ssize_t wn = ops->pwrite(ctx, pattern, region, 0, 0);
        int werr = wn < 0 ? errno : 0;
        if (wn == (ssize_t)region) r.bytes_written += region;
        r.restore_attempted = 1;
        int synced = ops->sync(ctx);
        ssize_t vn = ops->pread(ctx, verify, region, 0);
        r.step2_ok = wn == (ssize_t)region && vn == (ssize_t)region && !memcmp(pattern, verify, region);
        snprintf(message, sizeof(message), "userdata-write step2 write=%zd errno=%d fdatasync=%d readback=%zd match=%d us=%.0f",
                 wn, werr, synced, vn, r.step2_ok, (tp8_now() - t) * 1e6);
        report(message);
        if (!r.step2_ok) goto restore;
    }
    // Step 3: one 4 KiB FUA write of a second pattern into the first block, read back, compare.
    t = tp8_now();
    {
        tp10_fill_pattern(pattern, TP10_WR_BLOCK, region_base_lba, TP10_WR_FUA_MARKER);
        ssize_t wn = ops->pwrite(ctx, pattern, TP10_WR_BLOCK, 0, 1);
        int werr = wn < 0 ? errno : 0;
        if (wn == (ssize_t)TP10_WR_BLOCK) r.bytes_written += TP10_WR_BLOCK;
        ssize_t vn = ops->pread(ctx, verify, TP10_WR_BLOCK, 0);
        r.step3_ok = wn == (ssize_t)TP10_WR_BLOCK && vn == (ssize_t)TP10_WR_BLOCK && !memcmp(pattern, verify, TP10_WR_BLOCK);
        snprintf(message, sizeof(message), "userdata-write step3 pwritev2=%zd errno=%d readback=%zd match=%d us=%.0f",
                 wn, werr, vn, r.step3_ok, (tp8_now() - t) * 1e6);
        report(message);
        if (!r.step3_ok) goto restore;
    }
restore:
    // Step 4: restore the original region once, even after a partial step 2 or 3.
    if (r.restore_attempted) {
        t = tp8_now();
        ssize_t wn = ops->pwrite(ctx, orig, region, 0, 0);
        int werr = wn < 0 ? errno : 0;
        if (wn == (ssize_t)region) r.bytes_written += region;
        int synced = ops->sync(ctx);
        ssize_t vn = ops->pread(ctx, verify, region, 0);
        if (vn == (ssize_t)region) {
            struct tp8_sha256 c;
            tp8_sha256_init(&c);
            tp8_sha256_update(&c, verify, region);
            tp8_sha256_hex(&c, hex_now);
            r.restore_ok = wn == (ssize_t)region && !memcmp(hex_now, r.original_sha256, 64);
        } else {
            snprintf(hex_now, sizeof(hex_now), "unreadable");
        }
        snprintf(message, sizeof(message), "userdata-write step4 restore write=%zd errno=%d fdatasync=%d readback=%zd sha256=%s match=%d us=%.0f",
                 wn, werr, synced, vn, hex_now, r.restore_ok, (tp8_now() - t) * 1e6);
        report(message);
        if (!r.restore_ok) report("userdata restore FAILED");
    }
done:
    snprintf(message, sizeof(message), "userdata-write complete bytes_written=%llu budget=%llu within_budget=%d",
             (unsigned long long)r.bytes_written, (unsigned long long)r.budget, r.bytes_written <= r.budget);
    report(message);
    free(orig); free(pattern); free(verify);
    return r;
}

// ---- LP (super) metadata parser ----
// Reads the geometry and primary metadata slot 0 of an Android super image from a
// buffer that already holds the first part of the partition, checks both SHA256
// checksums with the v8 hash code and requires the stock layout. It never writes
// and the dm tables it yields are read-only. Host-testable against super.raw.img.
#define TP10_LP_GEOMETRY_OFFSET 4096u
#define TP10_LP_GEOMETRY_MAGIC 0x616c4467u   // "gDla"
#define TP10_LP_METADATA_OFFSET 12288u       // slot 0 header: geometry block + its backup, then the slots
#define TP10_LP_HEADER_MAGIC 0x414c5030u     // "0PLA"
#define TP10_LP_TARGET_TYPE_LINEAR 0u
#define TP10_LP_MAX_PARTITIONS 8u
#define TP10_LP_MAX_EXTENTS 16u
// The stock layout this diagnostic accepts; anything else aborts the mount test.
#define TP10_LP_STOCK_PARTITIONS 3u
static const char *const tp10_lp_stock_names[TP10_LP_STOCK_PARTITIONS] = {"system", "vendor", "product"};

struct tp10_lp_extent { uint64_t num_sectors, target_sector; };
struct tp10_lp_partition {
    char name[37];
    unsigned group_index, num_extents;
    uint64_t sectors;                         // total, 512-byte
    struct tp10_lp_extent extents[TP10_LP_MAX_EXTENTS];
};
struct tp10_lp {
    unsigned logical_block_size, num_partitions;
    uint64_t device_size, first_logical_sector;
    struct tp10_lp_partition partitions[TP10_LP_MAX_PARTITIONS];
};

// A SHA256 over a region with one field zeroed (checksum fields are hashed as zero).
static int tp10_sha_matches(const unsigned char *data, size_t length, size_t field, const unsigned char *expect)
{
    unsigned char copy[4096];
    if (length > sizeof(copy)) return 0;
    memcpy(copy, data, length);
    memset(copy + field, 0, 32);
    struct tp8_sha256 c;
    tp8_sha256_init(&c);
    tp8_sha256_update(&c, copy, length);
    char hex[65], want[65];
    tp8_sha256_hex(&c, hex);
    tp8_hex_bytes(expect, 32, want, sizeof(want));
    return !memcmp(hex, want, 64);
}

// Returns the partition count on success, or -1 with a short reason. buf must hold at
// least TP10_LP_METADATA_OFFSET + metadata_max_size bytes.
static int tp10_lp_parse(const unsigned char *buf, size_t length, struct tp10_lp *lp, const char **why)
{
    memset(lp, 0, sizeof(*lp));
    if (length < TP10_LP_METADATA_OFFSET + 512) { *why = "short_buffer"; return -1; }
    const unsigned char *g = buf + TP10_LP_GEOMETRY_OFFSET;
    if (tp8_le32(g) != TP10_LP_GEOMETRY_MAGIC) { *why = "geometry_magic"; return -1; }
    uint32_t gsize = tp8_le32(g + 4);
    if (gsize < 52 || gsize > 4096) { *why = "geometry_size"; return -1; }
    if (!tp10_sha_matches(g, gsize, 8, g + 8)) { *why = "geometry_checksum"; return -1; }
    uint32_t metadata_max = tp8_le32(g + 40), slots = tp8_le32(g + 44), lbs = tp8_le32(g + 48);
    // metadata_max_size is the per-slot metadata region (65536 on stock); header and tables sit inside it.
    if (lbs != 4096 || !slots || metadata_max < 512 || metadata_max > (1u << 20)) { *why = "geometry_fields"; return -1; }
    lp->logical_block_size = lbs;
    if (length < TP10_LP_METADATA_OFFSET + metadata_max) { *why = "short_metadata"; return -1; }
    const unsigned char *h = buf + TP10_LP_METADATA_OFFSET;
    if (tp8_le32(h) != TP10_LP_HEADER_MAGIC) { *why = "header_magic"; return -1; }
    uint32_t header_size = tp8_le32(h + 8);
    if (header_size < 80 || header_size > 256 || header_size > metadata_max) { *why = "header_size"; return -1; }
    if (!tp10_sha_matches(h, header_size, 12, h + 12)) { *why = "header_checksum"; return -1; }
    uint32_t tables_size = tp8_le32(h + 44);
    if (!tables_size || tables_size > metadata_max - header_size) { *why = "tables_size"; return -1; }
    const unsigned char *tables = h + header_size;
    {
        struct tp8_sha256 c;
        tp8_sha256_init(&c);
        tp8_sha256_update(&c, tables, tables_size);
        char hex[65], want[65];
        tp8_sha256_hex(&c, hex);
        tp8_hex_bytes(h + 48, 32, want, sizeof(want));
        if (memcmp(hex, want, 64)) { *why = "tables_checksum"; return -1; }
    }
    uint32_t po = tp8_le32(h + 80), pn = tp8_le32(h + 84), pe = tp8_le32(h + 88);
    uint32_t eo = tp8_le32(h + 92), en = tp8_le32(h + 96), ee = tp8_le32(h + 100);
    uint32_t go = tp8_le32(h + 104), gn = tp8_le32(h + 108), ge = tp8_le32(h + 112);
    uint32_t bo = tp8_le32(h + 116), bn = tp8_le32(h + 120), be = tp8_le32(h + 124);
    if (pe < 52 || ee < 24 || ge < 48 || be < 64) { *why = "descriptor_size"; return -1; }
    if (pn != TP10_LP_STOCK_PARTITIONS || pn > TP10_LP_MAX_PARTITIONS) { *why = "partition_count"; return -1; }
    if (!en || en > TP10_LP_MAX_EXTENTS) { *why = "extent_count"; return -1; }
    if (bn != 1) { *why = "block_device_count"; return -1; }
    // Every table must fit inside tables_size.
    uint64_t pend = (uint64_t)po + (uint64_t)pn * pe, eend = (uint64_t)eo + (uint64_t)en * ee;
    uint64_t gend = (uint64_t)go + (uint64_t)gn * ge, bend = (uint64_t)bo + (uint64_t)bn * be;
    if (pend > tables_size || eend > tables_size || gend > tables_size || bend > tables_size) { *why = "table_bounds"; return -1; }
    // The single block device must be "super".
    const unsigned char *bd = tables + bo;
    lp->first_logical_sector = tp8_le64(bd);
    lp->device_size = tp8_le64(bd + 16);
    char bname[37];
    size_t k = 0;
    for (; k < 36 && bd[24 + k]; ++k) bname[k] = (char)bd[24 + k];
    bname[k] = 0;
    if (strcmp(bname, "super")) { *why = "block_device_name"; return -1; }
    // Find the "main" group index.
    int main_group = -1;
    for (uint32_t i = 0; i < gn; ++i) {
        const unsigned char *gr = tables + go + (size_t)i * ge;
        char gname[37];
        size_t j = 0;
        for (; j < 36 && gr[j]; ++j) gname[j] = (char)gr[j];
        gname[j] = 0;
        if (!strcmp(gname, "main")) main_group = (int)i;
    }
    if (main_group < 0) { *why = "no_main_group"; return -1; }
    for (uint32_t i = 0; i < pn; ++i) {
        const unsigned char *p = tables + po + (size_t)i * pe;
        struct tp10_lp_partition *part = &lp->partitions[i];
        size_t n = 0;
        for (; n < 36 && p[n]; ++n) part->name[n] = (char)p[n];
        part->name[n] = 0;
        uint32_t first_extent = tp8_le32(p + 40), num_extents = tp8_le32(p + 44), group = tp8_le32(p + 48);
        if (group != (uint32_t)main_group) { *why = "partition_group"; return -1; }
        if (!num_extents || num_extents > TP10_LP_MAX_EXTENTS || (uint64_t)first_extent + num_extents > en) { *why = "partition_extents"; return -1; }
        part->group_index = group;
        part->num_extents = num_extents;
        for (uint32_t x = 0; x < num_extents; ++x) {
            const unsigned char *e = tables + eo + (size_t)(first_extent + x) * ee;
            uint64_t num_sectors = tp8_le64(e);
            uint32_t target_type = tp8_le32(e + 8);
            uint64_t target_data = tp8_le64(e + 12);
            uint32_t target_source = tp8_le32(e + 20);
            if (target_type != TP10_LP_TARGET_TYPE_LINEAR || target_source != 0) { *why = "non_linear_extent"; return -1; }
            part->extents[x].num_sectors = num_sectors;
            part->extents[x].target_sector = target_data;
            part->sectors += num_sectors;
        }
    }
    // Names must be exactly the stock set, in any order.
    for (uint32_t s = 0; s < TP10_LP_STOCK_PARTITIONS; ++s) {
        int found = 0;
        for (uint32_t i = 0; i < pn; ++i) if (!strcmp(lp->partitions[i].name, tp10_lp_stock_names[s])) found = 1;
        if (!found) { *why = "partition_name"; return -1; }
    }
    lp->num_partitions = pn;
    *why = "";
    return (int)pn;
}

// ---- dm-ioctl buffers (v11) ----
// The version sent with every dm ioctl. The kernel rejects a major that differs from its own
// or a minor above its own, so send the lowest, 4.0.0, as AOSP libdm does, not the NDK header's.
#define TP11_DM_VERSION_MAJOR 4u
#define TP11_DM_VERSION_MINOR 0u
#define TP11_DM_VERSION_PATCH 0u

// A dm_ioctl header, zeroed and versioned, data_size = size, with the control name set.
static void tp11_dm_header(struct dm_ioctl *dm, size_t size, const char *name)
{
    memset(dm, 0, sizeof(*dm));
    dm->version[0] = TP11_DM_VERSION_MAJOR;
    dm->version[1] = TP11_DM_VERSION_MINOR;
    dm->version[2] = TP11_DM_VERSION_PATCH;
    dm->data_size = (uint32_t)size;
    dm->data_start = sizeof(*dm);
    snprintf(dm->name, sizeof(dm->name), "%s", name);
}

// Builds a DM_TABLE_LOAD buffer of one read-only linear target per extent over the block
// device major:minor. Layout as the kernel walks it: the first dm_target_spec at data_start,
// each spec's next = bytes from it to the following spec, specs and params 8-byte aligned,
// params NUL-terminated, data_size = the whole buffer. Returns the buffer size, or 0 if it
// doesn't fit or an extent's params overflow.
static size_t tp11_dm_build_table(unsigned char *buffer, size_t capacity, const char *name,
                                  unsigned dev_major, unsigned dev_minor, const struct tp10_lp_partition *part)
{
    if (capacity < sizeof(struct dm_ioctl)) return 0;
    memset(buffer, 0, capacity);
    struct dm_ioctl *load = (struct dm_ioctl *)buffer;
    tp11_dm_header(load, 0, name);
    load->target_count = part->num_extents;
    load->flags = DM_READONLY_FLAG;
    size_t at = sizeof(struct dm_ioctl);
    uint64_t logical = 0;
    for (unsigned x = 0; x < part->num_extents; ++x) {
        size_t spec_at = (at + 7) & ~(size_t)7;
        if (spec_at + sizeof(struct dm_target_spec) + 64 > capacity) return 0;
        struct dm_target_spec *spec = (struct dm_target_spec *)(buffer + spec_at);
        spec->sector_start = logical;
        spec->length = part->extents[x].num_sectors;
        spec->status = 0;
        snprintf(spec->target_type, sizeof(spec->target_type), "linear");
        char *params = (char *)(spec + 1);
        int pn = snprintf(params, 64, "%u:%u %llu", dev_major, dev_minor,
                          (unsigned long long)part->extents[x].target_sector);
        if (pn <= 0 || pn >= 64) return 0;
        size_t params_end = (spec_at + sizeof(struct dm_target_spec) + (size_t)pn + 1 + 7) & ~(size_t)7;
        spec->next = (uint32_t)(params_end - spec_at);
        at = params_end;
        logical += part->extents[x].num_sectors;
    }
    load->data_size = (uint32_t)at;
    return at;
}

// ---- teed command line builder (v12) ----
// The probe runs stock vendor teed with every writable path moved under one tmpfs root, so teed
// cannot write to real storage. The options and their stock values are from the saved REA of
// teed 25bb4975… (evidence/kernel-upgrade/trustkernel-keymaster-5.10.md):
//   writable:  --prot /mnt/vendor/persist/t6, --prot /mnt/vendor/protect_f/tee,
//              --datapath /data/vendor/t6/fs, --sptapath /data/vendor/t6/app,
//              --logpath /data/vendor/t6/tkcore.log
//   read-only: --systapath /vendor/app/t6 (the read-only vendor mount), --proprefix vendor.trustkernel
//   never:     --rpmbdev and --sdrpmbdev (would open an RPMB or SDRPMB block node), --prebuilt
//              (a third storage path), --nofrp, and -p / -r (teed has no short options, but
//              getopt_long_only takes -r as --rpmbdev and -p as an abbreviation)
// The builder only ever emits the writable set rewritten under the tmpfs root plus the two
// read-only options; it refuses to emit anything else, so an RPMB option can never slip in.
#define TP12_TEED_MAX_ARGS 24u
#define TP12_TEED_MAX_ARG 160u
#define TP12_TEED_MAX_ROOT 96u

// A writable path option: the stock value is replaced by tmpfs_root + suffix.
static const struct { const char *name, *suffix; } tp12_teed_writable[] = {
    {"--prot", "/persist/t6"},
    {"--prot", "/protect_f/tee"},
    {"--datapath", "/fs"},
    {"--sptapath", "/app"},
    {"--logpath", "/tkcore.log"},
};
#define TP12_TEED_WRITABLE (sizeof(tp12_teed_writable) / sizeof(tp12_teed_writable[0]))
// Kept as on stock: systapath is the read-only vendor app dir, proprefix is a property prefix.
static const struct { const char *name, *value; } tp12_teed_kept[] = {
    {"--systapath", "/vendor/app/t6"},
    {"--proprefix", "vendor.trustkernel"},
};
#define TP12_TEED_KEPT (sizeof(tp12_teed_kept) / sizeof(tp12_teed_kept[0]))
// Options the builder must never emit.
static const char *const tp12_teed_forbidden[] = {"--rpmbdev", "--sdrpmbdev", "--prebuilt", "--nofrp", "-p", "-r"};
#define TP12_TEED_FORBIDDEN (sizeof(tp12_teed_forbidden) / sizeof(tp12_teed_forbidden[0]))

enum tp12_teed_class { TP12_TEED_UNKNOWN = 0, TP12_TEED_WRITABLE_OPT, TP12_TEED_KEPT_OPT, TP12_TEED_FORBIDDEN_OPT };

// Classifies an option name. The host test and the caller use this to prove the builder refuses
// anything but the known-safe set.
static enum tp12_teed_class tp12_teed_classify(const char *name)
{
    for (size_t i = 0; i < TP12_TEED_FORBIDDEN; ++i)
        if (!strcmp(name, tp12_teed_forbidden[i])) return TP12_TEED_FORBIDDEN_OPT;
    for (size_t i = 0; i < TP12_TEED_WRITABLE; ++i)
        if (!strcmp(name, tp12_teed_writable[i].name)) return TP12_TEED_WRITABLE_OPT;
    for (size_t i = 0; i < TP12_TEED_KEPT; ++i)
        if (!strcmp(name, tp12_teed_kept[i].name)) return TP12_TEED_KEPT_OPT;
    return TP12_TEED_UNKNOWN;
}

// True when path is root followed by "/..." with no ".." and root is a clean absolute dir.
static int tp12_path_under_tmpfs(const char *root, const char *path)
{
    size_t rl = strnlen(root, TP12_TEED_MAX_ROOT);
    if (rl < 2 || rl == TP12_TEED_MAX_ROOT || root[0] != '/' || root[rl - 1] == '/') return 0;
    if (strstr(root, "..") || strstr(path, "..")) return 0;
    if (strncmp(path, root, rl) || path[rl] != '/') return 0;
    return 1;
}

struct tp12_teed {
    char root[TP12_TEED_MAX_ROOT];
    char args[TP12_TEED_MAX_ARGS][TP12_TEED_MAX_ARG];
    unsigned count;
    int error;                      // errno-like reason of the first refusal, 0 while ok
};

static void tp12_teed_init(struct tp12_teed *b, const char *root)
{
    memset(b, 0, sizeof(*b));
    snprintf(b->root, sizeof(b->root), "%s", root);
}

static int tp12_teed_push(struct tp12_teed *b, const char *arg)
{
    if (b->error) return -1;
    if (b->count >= TP12_TEED_MAX_ARGS) { b->error = E2BIG; return -1; }
    if (strlen(arg) >= TP12_TEED_MAX_ARG) { b->error = ENAMETOOLONG; return -1; }
    snprintf(b->args[b->count++], TP12_TEED_MAX_ARG, "%s", arg);
    return 0;
}

// Adds one option by name, with the builder supplying the value. Writable paths are built under
// the tmpfs root and checked to stay there; kept options take their stock value; a forbidden or
// unknown name is refused and recorded, and nothing is emitted. Returns 0 on success, -1 on refusal.
static int tp12_teed_add(struct tp12_teed *b, const char *name, unsigned which)
{
    if (b->error) return -1;
    enum tp12_teed_class c = tp12_teed_classify(name);
    if (c == TP12_TEED_FORBIDDEN_OPT) { b->error = EPERM; return -1; }
    if (c == TP12_TEED_UNKNOWN) { b->error = EINVAL; return -1; }
    if (c == TP12_TEED_WRITABLE_OPT) {
        if (which >= TP12_TEED_WRITABLE || strcmp(tp12_teed_writable[which].name, name)) { b->error = EINVAL; return -1; }
        char path[TP12_TEED_MAX_ARG];
        int n = snprintf(path, sizeof(path), "%s%s", b->root, tp12_teed_writable[which].suffix);
        if (n <= 0 || (size_t)n >= sizeof(path) || !tp12_path_under_tmpfs(b->root, path)) { b->error = EINVAL; return -1; }
        return tp12_teed_push(b, name) || tp12_teed_push(b, path) ? -1 : 0;
    }
    if (which >= TP12_TEED_KEPT || strcmp(tp12_teed_kept[which].name, name)) { b->error = EINVAL; return -1; }
    return tp12_teed_push(b, tp12_teed_kept[which].name) || tp12_teed_push(b, tp12_teed_kept[which].value) ? -1 : 0;
}

// Builds the whole command line for the probe's teed run: argv[0], the two kept options, then
// every writable path under the tmpfs root. Returns the argc, or -1 with b->error set. No
// forbidden option is ever added, so teed opens no RPMB or SDRPMB node.
static int tp12_teed_build(struct tp12_teed *b, const char *root)
{
    tp12_teed_init(b, root);
    // The root must be a clean absolute dir; every writable path is checked again as it is built.
    size_t rl = strnlen(root, TP12_TEED_MAX_ROOT);
    if (rl < 2 || rl == TP12_TEED_MAX_ROOT || root[0] != '/' || root[rl - 1] == '/' || strstr(root, "..")) {
        b->error = EINVAL; return -1;
    }
    tp12_teed_push(b, "teed");
    for (unsigned i = 0; i < TP12_TEED_KEPT; ++i) tp12_teed_add(b, tp12_teed_kept[i].name, i);
    for (unsigned i = 0; i < TP12_TEED_WRITABLE; ++i) tp12_teed_add(b, tp12_teed_writable[i].name, i);
    return b->error ? -1 : (int)b->count;
}

// ---- legacy property area (v12) ----
// Builds the single-file /dev/__properties__ that bionic maps when the path is not a directory
// (ContextsPreSplit). Layout from bionic's prop_area.h, prop_area.cpp and prop_info.h, checked
// against prop_area::find_prop_bt in the phone's bootstrap libc:
//   header 0x80 bytes: bytes_used, serial, magic 0x504f5250, version 0xfc6ed0ab, 28 reserved words
//   data from +0x80, every offset relative to it: the root node at 0 (all zero), then the 92-byte
//   dirty backup area, then objects, each 4-byte aligned
//   node {u32 namelen, prop, left, right, children; name; NUL}, one per dot-separated segment;
//   siblings form a binary tree ordered by length, then strncmp
//   prop_info {u32 serial = valuelen << 24; char value[92]; name; NUL}
// Objects are allocated in the order prop_area::add allocates them, so the bytes equal an area
// bionic builds with the same adds. Little-endian, as the phone and the host are.
#define TP12_PROP_AREA_SIZE (128u * 1024u)
#define TP12_PROP_AREA_MAGIC 0x504f5250u
#define TP12_PROP_AREA_VERSION 0xfc6ed0abu
#define TP12_PROP_HEADER 0x80u
#define TP12_PROP_NODE 20u
#define TP12_PROP_VALUE_MAX 92u
#define TP12_PROP_INFO (4u + TP12_PROP_VALUE_MAX)
#define TP12_PROP_NAME_MAX 96u
#define TP12_PROP_NONE 0xffffffffu

// The five properties teed reads (DIAGNOSTIC_510_V12_TRIAL.md, milestone 1). The ro. values are
// the phone's build.prop ones; the two state values let teed's fs and log threads go on.
static const struct { const char *name, *value; } tp12_teed_props[] = {
    {"ro.product.brand", "Unihertz"},
    {"ro.product.model", "Titan pocket"},
    {"ro.board.platform", "mt6771"},
    {"vendor.trustkernel.fs.state", "ready"},
    {"vendor.trustkernel.log.state", "enable"},
};
#define TP12_TEED_PROPS (sizeof(tp12_teed_props) / sizeof(tp12_teed_props[0]))

struct tp12_props {
    unsigned char *area;
    uint32_t size;                  // whole file, header included
    uint32_t used;                  // bytes_used, relative to the data start
    int error;                      // errno-like reason of the first failure, 0 while ok
};

static uint32_t tp12_get32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void tp12_put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

static uint32_t tp12_prop_data_size(const struct tp12_props *a) { return a->size - TP12_PROP_HEADER; }
static unsigned char *tp12_prop_at(const struct tp12_props *a, uint32_t off) { return a->area + TP12_PROP_HEADER + off; }

// Starts an empty area in buf: header, zero root node and the dirty backup area, as the
// prop_area constructor does.
static int tp12_prop_init(struct tp12_props *a, unsigned char *buf, size_t size)
{
    memset(a, 0, sizeof(*a));
    if (size < TP12_PROP_HEADER + TP12_PROP_NODE + TP12_PROP_VALUE_MAX || size > (1u << 24)) {
        a->error = EINVAL; return -1;
    }
    memset(buf, 0, size);
    a->area = buf;
    a->size = (uint32_t)size;
    a->used = TP12_PROP_NODE + ((TP12_PROP_VALUE_MAX + 3u) & ~3u);
    tp12_put32(buf, a->used);
    tp12_put32(buf + 8, TP12_PROP_AREA_MAGIC);
    tp12_put32(buf + 12, TP12_PROP_AREA_VERSION);
    return 0;
}

// Takes an existing area for lookups only, with bionic's map_fd_ro checks on size, magic and version.
static int tp12_prop_open(struct tp12_props *a, unsigned char *buf, size_t size)
{
    memset(a, 0, sizeof(*a));
    if (size < TP12_PROP_HEADER + TP12_PROP_NODE || size > (1u << 24) ||
        tp12_get32(buf + 8) != TP12_PROP_AREA_MAGIC || tp12_get32(buf + 12) != TP12_PROP_AREA_VERSION) {
        a->error = EINVAL; return -1;
    }
    a->area = buf;
    a->size = (uint32_t)size;
    a->used = tp12_get32(buf);
    return 0;
}

// Returns the offset of a new zeroed object, or TP12_PROP_NONE when the area is full.
static uint32_t tp12_prop_alloc(struct tp12_props *a, uint32_t size)
{
    uint32_t aligned = (size + 3u) & ~3u;
    if (a->used > tp12_prop_data_size(a) || aligned > tp12_prop_data_size(a) - a->used) { a->error = ENOSPC; return TP12_PROP_NONE; }
    uint32_t off = a->used;
    a->used += aligned;
    tp12_put32(a->area, a->used);
    return off;
}

// A node offset is usable when the node and its name fit in the data. Returns its namelen, or -1.
static int tp12_prop_node_ok(const struct tp12_props *a, uint32_t off)
{
    uint32_t data = tp12_prop_data_size(a);
    if (off > data || data - off < TP12_PROP_NODE + 1) return -1;
    uint32_t namelen = tp12_get32(tp12_prop_at(a, off));
    if (namelen >= TP12_PROP_NAME_MAX || data - off - TP12_PROP_NODE < namelen + 1) return -1;
    return (int)namelen;
}

static uint32_t tp12_prop_new_node(struct tp12_props *a, const char *name, uint32_t namelen)
{
    uint32_t off = tp12_prop_alloc(a, TP12_PROP_NODE + namelen + 1);
    if (off == TP12_PROP_NONE) return off;
    unsigned char *p = tp12_prop_at(a, off);
    tp12_put32(p, namelen);
    memcpy(p + TP12_PROP_NODE, name, namelen);
    return off;
}

// bionic's cmp_prop_name: shorter first, then strncmp.
static int tp12_prop_cmp(const char *one, uint32_t one_len, const char *two, uint32_t two_len)
{
    if (one_len != two_len) return one_len < two_len ? -1 : 1;
    return strncmp(one, two, one_len);
}

// Finds, or with alloc creates, the child of parent named seg, walking the sibling tree as
// prop_area::find_prop_trie_node does. field is the byte offset of the link inside a node.
static uint32_t tp12_prop_child(struct tp12_props *a, uint32_t parent, const char *seg, uint32_t seglen, int alloc)
{
    uint32_t link = parent, field = 16;   // the parent's children link first
    for (unsigned steps = 0; steps < 4096; ++steps) {
        uint32_t next = tp12_get32(tp12_prop_at(a, link) + field);
        if (!next) {
            if (!alloc) return TP12_PROP_NONE;
            uint32_t made = tp12_prop_new_node(a, seg, seglen);
            if (made != TP12_PROP_NONE) tp12_put32(tp12_prop_at(a, link) + field, made);
            return made;
        }
        int namelen = tp12_prop_node_ok(a, next);
        if (namelen < 0) { a->error = EINVAL; return TP12_PROP_NONE; }
        int c = tp12_prop_cmp(seg, seglen, (const char *)tp12_prop_at(a, next) + TP12_PROP_NODE, (uint32_t)namelen);
        if (!c) return next;
        link = next;
        field = c < 0 ? 8 : 12;
    }
    a->error = ELOOP;
    return TP12_PROP_NONE;
}

// Walks every segment of name from the root, as prop_area::find_property does. An empty segment
// fails, as it does in bionic. Returns the last node's offset or TP12_PROP_NONE.
static uint32_t tp12_prop_walk(struct tp12_props *a, const char *name, int alloc)
{
    uint32_t current = 0;
    const char *rest = name;
    for (;;) {
        const char *dot = strchr(rest, '.');
        uint32_t seglen = (uint32_t)(dot ? (size_t)(dot - rest) : strlen(rest));
        if (!seglen) return TP12_PROP_NONE;
        current = tp12_prop_child(a, current, rest, seglen, alloc);
        if (current == TP12_PROP_NONE || !dot) return current;
        rest = dot + 1;
    }
}

// Adds one short property. Refuses names bionic cannot find, values of 92 bytes or more (the
// long-property form is not built) and duplicates.
static int tp12_prop_add(struct tp12_props *a, const char *name, const char *value)
{
    if (a->error) return -1;
    size_t namelen = strnlen(name, TP12_PROP_NAME_MAX), valuelen = strnlen(value, TP12_PROP_VALUE_MAX);
    if (!namelen || namelen >= TP12_PROP_NAME_MAX || valuelen >= TP12_PROP_VALUE_MAX ||
        name[0] == '.' || name[namelen - 1] == '.' || strstr(name, "..")) { a->error = EINVAL; return -1; }
    uint32_t node = tp12_prop_walk(a, name, 1);
    if (node == TP12_PROP_NONE) { if (!a->error) a->error = EINVAL; return -1; }
    if (tp12_get32(tp12_prop_at(a, node) + 4)) { a->error = EEXIST; return -1; }
    uint32_t info = tp12_prop_alloc(a, TP12_PROP_INFO + (uint32_t)namelen + 1);
    if (info == TP12_PROP_NONE) return -1;
    unsigned char *p = tp12_prop_at(a, info);
    tp12_put32(p, (uint32_t)valuelen << 24);
    memcpy(p + 4, value, valuelen);
    memcpy(p + TP12_PROP_INFO, name, namelen);
    tp12_put32(tp12_prop_at(a, node) + 4, info);
    return 0;
}

// Looks a name up the way __system_property_get does and returns the value, or NULL. The info
// must fit, carry the same name and have a NUL-terminated value of the length in its serial.
static const char *tp12_prop_find(struct tp12_props *a, const char *name)
{
    uint32_t node = tp12_prop_walk(a, name, 0);
    if (node == TP12_PROP_NONE) return NULL;
    uint32_t info = tp12_get32(tp12_prop_at(a, node) + 4), data = tp12_prop_data_size(a);
    size_t namelen = strlen(name);
    if (!info || info > data || data - info < TP12_PROP_INFO + namelen + 1) return NULL;
    const unsigned char *p = tp12_prop_at(a, info);
    uint32_t serial = tp12_get32(p), valuelen = serial >> 24;
    if ((serial & 1u) || valuelen >= TP12_PROP_VALUE_MAX || p[4 + valuelen] ||
        memcmp(p + TP12_PROP_INFO, name, namelen + 1)) return NULL;
    return (const char *)p + 4;
}

// Builds the teed area: the five properties in table order. Returns 0, or -1 with a->error set.
static int tp12_prop_build_teed(struct tp12_props *a, unsigned char *buf, size_t size)
{
    if (tp12_prop_init(a, buf, size)) return -1;
    for (size_t i = 0; i < TP12_TEED_PROPS; ++i)
        if (tp12_prop_add(a, tp12_teed_props[i].name, tp12_teed_props[i].value)) return -1;
    return 0;
}

// ---- raw-ioctl TEEC client (v12) ----
// Opens a context and a session on /dev/tkcoredrv without libteec, using the stock tkcore uapi
// ioctls (saved REA of teed/libteec, same evidence file). The ioctl numbers and struct sizes are
// pinned here and static-asserted against the kernel headers, so a layout drift is a build error.
#define TP12_TKCORE_NODE "/dev/tkcoredrv"
#define TP12_TEEC_VERSION_IOC          0x800474b7UL   // TEE_QUERY_DRV_FEATURE_IOC
#define TP12_TEEC_CONTEXT_SHM_IOC      0xc01874a5UL   // TEE_ALLOC_SHM_IOC (TEEC_AllocateSharedMemory, not used)
#define TP12_TEEC_CONTEXT_SHM_PERM_IOC 0xc01874a6UL   // TEE_ALLOC_SHM_PERM_IOC (not used)
#define TP12_TEEC_OPEN_SESSION_IOC     0xc03074a1UL   // TEE_OPEN_SESSION_IOC
#define TP12_TEEC_INVOKE_IOC           0xc03074a3UL   // TEE_INVOKE_COMMAND_IOC

// The five ioctl constants and nine LP64 object layouts, from the stock tkcore headers.
_Static_assert(TEE_QUERY_DRV_FEATURE_IOC == TP12_TEEC_VERSION_IOC, "feature ioctl");
_Static_assert(TEE_ALLOC_SHM_IOC == TP12_TEEC_CONTEXT_SHM_IOC, "shm ioctl");
_Static_assert(TEE_ALLOC_SHM_PERM_IOC == TP12_TEEC_CONTEXT_SHM_PERM_IOC, "permanent shm ioctl");
_Static_assert(TEE_OPEN_SESSION_IOC == TP12_TEEC_OPEN_SESSION_IOC, "session ioctl");
_Static_assert(TEE_INVOKE_COMMAND_IOC == TP12_TEEC_INVOKE_IOC, "invoke ioctl");
_Static_assert(sizeof(struct tee_cmd_io) == 48, "command envelope");
_Static_assert(sizeof(struct tee_shm_io) == 24, "shm envelope");
_Static_assert(offsetof(struct tee_cmd_io, fd_sess) == 12, "sessionfd");
_Static_assert(offsetof(struct tee_cmd_io, uuid) == 16, "uuid");
_Static_assert(offsetof(struct tee_cmd_io, data) == 24, "data");
_Static_assert(offsetof(struct tee_cmd_io, op) == 32, "operation pointer");
_Static_assert(offsetof(struct TEEC_Context, fd) == 0x100, "context fd");
_Static_assert(offsetof(struct TEEC_Operation, session) == 0x68, "operation session");
_Static_assert(sizeof(struct TEEC_Operation) == 280, "operation object");

// The keymaster TA opened at session open: 9ef77781-7bd5-4e39-965f-20f6f211f46b.
static const struct TEEC_UUID tp12_km_ta_uuid = {
    0x9ef77781, 0x7bd5, 0x4e39, {0x96, 0x5f, 0x20, 0xf6, 0xf2, 0x11, 0xf4, 0x6b}};

// Device access is behind callbacks so the host test can inject a fake driver. open returns a
// non-negative fd or -errno; ioctl returns 0 or -errno and may fill arg; close is best effort.
struct tp12_teec_ops {
    int (*open)(void *ctx, const char *path);
    int (*ioctl)(void *ctx, int fd, unsigned long request, void *arg);
    void (*close)(void *ctx, int fd);
};

struct tp12_teec_result {
    int opened;            // 1 once /dev/tkcoredrv opened
    int feature_queried;   // 1 once the feature ioctl returned 0
    uint32_t features;     // nsdrv feature flags it returned
    int session_sent;      // 1 once the open-session ioctl was issued
    int error;             // errno of the failing step, 0 on success
    uint32_t teec_result;  // GP result from tee_cmd_io.err
    uint32_t origin;       // GP origin from tee_cmd_io.origin
    int session_fd;        // fd_sess the driver returned, -1 if none
};

// The open-session envelope as stock libteec TEEC_OpenSession builds it (6bd83cdf, 0x18e4-0x1924):
// err 0, origin TEEC_ORIGIN_API, cmd 0, fd_sess -1, the uuid, data NULL and data_size 0, and op
// pointing at the caller's operation, or a zeroed one (paramTypes 0) when there is none. Login is
// not in the envelope; libteec refuses any login but public and the driver sends login 0.
static void tp12_teec_fill_open(struct tee_cmd_io *io, const struct TEEC_UUID *uuid, struct TEEC_Operation *op)
{
    memset(io, 0, sizeof(*io));
    memset(op, 0, sizeof(*op));
    io->origin = TEEC_ORIGIN_API;
    io->fd_sess = -1;
    io->uuid = (struct TEEC_UUID *)uuid;
    io->op = op;
}

// Opens the node and queries the driver features once (0x800474b7), as stock
// TEEC_InitializeContext does, then opens a session on the TA (0xc03074a1), as stock
// TEEC_OpenSession does with no operation. Stock allocates no SHM for a context or for a session
// with no operation, so neither does this. Returns 0 when the session ioctl succeeded and the TEE
// returned TEEC_SUCCESS; otherwise -1 with result->error or result->teec_result set. Issues no
// SHM, RPMB or invoke ioctl. A failed feature query is logged and ignored, as stock ignores it.
static int tp12_teec_open_session(const struct tp12_teec_ops *ops, void *ctx,
                                  const struct TEEC_UUID *uuid, struct tp12_teec_result *result,
                                  tp8_report_fn report)
{
    char message[200];
    memset(result, 0, sizeof(*result));
    result->session_fd = -1;
    int fd = ops->open(ctx, TP12_TKCORE_NODE);
    if (fd < 0) {
        result->error = -fd;
        snprintf(message, sizeof(message), "teec open %s errno=%d", TP12_TKCORE_NODE, result->error);
        report(message);
        return -1;
    }
    result->opened = 1;
    uint32_t features = 0;
    int rc = ops->ioctl(ctx, fd, TP12_TEEC_VERSION_IOC, &features);
    if (!rc) { result->feature_queried = 1; result->features = features; }
    snprintf(message, sizeof(message), "teec feature ioctl=0x%lx rc=%d features=0x%x", TP12_TEEC_VERSION_IOC, rc, (unsigned)features);
    report(message);
    struct tee_cmd_io io;
    struct TEEC_Operation op;
    tp12_teec_fill_open(&io, uuid, &op);
    result->session_sent = 1;
    rc = ops->ioctl(ctx, fd, TP12_TEEC_OPEN_SESSION_IOC, &io);
    result->teec_result = io.err;
    result->origin = io.origin;
    if (rc) {
        result->error = -rc;
        snprintf(message, sizeof(message), "teec open-session ioctl=0x%lx errno=%d result=0x%08x origin=%u",
                 TP12_TEEC_OPEN_SESSION_IOC, result->error, (unsigned)io.err, io.origin);
        report(message);
        ops->close(ctx, fd);
        return -1;
    }
    // The driver writes fd_sess back only on success.
    if (io.err == TEEC_SUCCESS && io.fd_sess >= 0) result->session_fd = io.fd_sess;
    snprintf(message, sizeof(message),
             "teec open-session uuid=%08x-%04x-%04x result=0x%08x origin=%u session_fd=%d",
             uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion,
             (unsigned)result->teec_result, result->origin, result->session_fd);
    report(message);
    ops->close(ctx, fd);
    return result->teec_result == TEEC_SUCCESS && result->session_fd >= 0 ? 0 : -1;
}

// ---- teed phase helpers (v12) ----
// Pure parts of the teed run in init.c: splitting teed's output into log lines, the readiness
// rule from milestone 1 ("Readiness and logs") and the step time limits.
#define TP12_TEED_LINE_MAX 200u        // longer lines are logged in pieces
#define TP12_TEED_MAX_LOGGED 400u      // lines past this are counted, not logged
#define TP12_TEED_LISTENING "teed listening on"

// The phase limits in seconds. The worst case is their sum plus the two hash passes.
#define TP12_HASH_PASS_SECONDS 5.0     // the six protected partitions, about 166 MiB
#define TP12_TEED_WAIT_SECONDS 30.0
#define TP12_SESSION_SECONDS 20.0
#define TP12_STOP_TERM_SECONDS 3.0     // SIGKILL after this
#define TP12_STOP_SECONDS 5.0          // give up on reaping after this
// tk_host_teardown: three umounts (tmpfs, vendor, system) retried up to 2 s each while busy,
// plus 1 s for teed's last output, devpts, the links and the dm removes.
#define TP12_UMOUNT_TRIES 20u
#define TP12_UMOUNT_WAIT_US 100000u
#define TP12_TEARDOWN_UMOUNTS 3
#define TP12_TEARDOWN_SECONDS (TP12_TEARDOWN_UMOUNTS * (TP12_UMOUNT_TRIES * TP12_UMOUNT_WAIT_US / 1e6) + 1.0)
#define TP12_SUPER_HASH_SECONDS 139.0  // the v11 run's super hash
#define TP12_PHASE_WORST_SECONDS (2 * TP12_HASH_PASS_SECONDS + TP12_TEED_WAIT_SECONDS + TP12_SESSION_SECONDS + \
                                  TP12_STOP_SECONDS + TP12_TEARDOWN_SECONDS)

// The six partitions hashed before teed starts and again after teardown.
static const char *const tp12_protected[] = {"protect1", "protect2", "persist", "nvdata", "nvcfg", "proinfo"};
#define TP12_PROTECTED (sizeof(tp12_protected) / sizeof(tp12_protected[0]))

struct tp12_lines {
    char buf[TP12_TEED_LINE_MAX + 1];
    size_t len;
    unsigned lines, dropped, split;
    int listening;                  // 1 once a line held TP12_TEED_LISTENING
};

static void tp12_lines_init(struct tp12_lines *l) { memset(l, 0, sizeof(*l)); }

// Logs the held text as one "teed: " line. Readiness is checked on every line, logged or not.
static void tp12_lines_emit(struct tp12_lines *l, tp8_report_fn report)
{
    l->buf[l->len] = 0;
    if (strstr(l->buf, TP12_TEED_LISTENING)) l->listening = 1;
    if (++l->lines <= TP12_TEED_MAX_LOGGED) {
        char message[TP12_TEED_LINE_MAX + 16];
        snprintf(message, sizeof(message), "teed: %s", l->buf);
        report(message);
    } else {
        ++l->dropped;
    }
    l->len = 0;
}

// Feeds raw output. '\n' ends a line, '\r' (the pty's ONLCR) is dropped and other control
// bytes become '?', so the log stays plain text.
static void tp12_lines_feed(struct tp12_lines *l, const char *data, size_t count, tp8_report_fn report)
{
    for (size_t i = 0; i < count; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == '\n') { tp12_lines_emit(l, report); continue; }
        if (c == '\r') continue;
        if (l->len == TP12_TEED_LINE_MAX) { ++l->split; tp12_lines_emit(l, report); }
        l->buf[l->len++] = (char)(c < 0x20 || c == 0x7f ? '?' : c);
    }
}

// Logs an unterminated tail, once teed's output has closed.
static void tp12_lines_flush(struct tp12_lines *l, tp8_report_fn report)
{
    if (l->len) tp12_lines_emit(l, report);
}

// True for a /proc/<pid>/task/<tid>/comm value of teed's tkuinit thread.
static int tp12_comm_is_tkuinit(const char *comm) { return !strncmp(comm, "tkuinit", 7); }

enum tp12_wait { TP12_WAIT_PENDING = 0, TP12_WAIT_READY, TP12_WAIT_EXITED, TP12_WAIT_TIMEOUT };

struct tp12_teed_seen {
    int exited;          // teed was reaped
    int listening;       // the listening line was read
    int tkuinit;         // tkuinit tasks now
    int tkuinit_seen;    // a tkuinit task was ever seen
    int line_buffered;   // output is a pty; 0 for the pipe fallback, which bionic fully buffers
};

// Ready once teed has opened the supplicant fd (the listening line) and tkuinit has gone, which
// shows TA loading is allowed. Through a pipe the line may sit in teed's buffer, so there a
// tkuinit seen and then gone is taken instead.
static enum tp12_wait tp12_teed_wait_state(const struct tp12_teed_seen *s, double elapsed)
{
    if (s->exited) return TP12_WAIT_EXITED;
    if (!s->tkuinit && (s->listening || (!s->line_buffered && s->tkuinit_seen))) return TP12_WAIT_READY;
    if (elapsed >= TP12_TEED_WAIT_SECONDS) return TP12_WAIT_TIMEOUT;
    return TP12_WAIT_PENDING;
}

enum tp12_stop { TP12_STOP_WAIT = 0, TP12_STOP_KILL, TP12_STOP_GIVE_UP };

// What to do while stopping teed, elapsed seconds after SIGTERM.
static enum tp12_stop tp12_stop_step(double elapsed, int killed)
{
    if (elapsed >= TP12_STOP_SECONDS) return TP12_STOP_GIVE_UP;
    if (!killed && elapsed >= TP12_STOP_TERM_SECONDS) return TP12_STOP_KILL;
    return TP12_STOP_WAIT;
}

// True when the session open has run past its limit and its child is abandoned.
static int tp12_session_expired(double elapsed) { return elapsed >= TP12_SESSION_SECONDS; }

// True when the whole phase, worst case, still leaves the super hash time before the deadline.
static int tp12_phase_fits(double now, double hash_deadline)
{
    return now + TP12_PHASE_WORST_SECONDS + TP12_SUPER_HASH_SECONDS <= hash_deadline;
}

// Copies the digest out of a complete "part-hash name=... sha256=<64 hex>" line. Returns 0, or
// -1 for a partial hash or a line with no digest.
static int tp12_hash_digest(const char *line, char out[65])
{
    out[0] = 0;
    if (strstr(line, " partial ")) return -1;
    const char *s = strstr(line, " sha256=");
    if (!s) return -1;
    s += 8;
    for (unsigned i = 0; i < 64; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { out[0] = 0; return -1; }
        out[i] = c;
    }
    if (s[64] && s[64] != ' ') { out[0] = 0; return -1; }
    out[64] = 0;
    return 0;
}
#endif
