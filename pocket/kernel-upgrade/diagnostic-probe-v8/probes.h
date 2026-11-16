// SPDX-License-Identifier: GPL-2.0-only
// v8 probe helpers: SHA-256, GPT parsing, read-only partition hashing,
// FDT memreserve parsing and ACM line hashing. Host-testable; no writes.
#ifndef POCKET_DIAGNOSTIC_V8_PROBES_H
#define POCKET_DIAGNOSTIC_V8_PROBES_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
// reports enabled; nothing here turns a supply or GPIO on.
struct tp8_i2c_target {
    const char *device;     // platform device of the controller
    unsigned stock_bus;     // bus number on the stock kernel
    const char *chip;
    uint16_t address;       // 7-bit
    unsigned char reg[2];
    unsigned reg_length, read_length;
    const char *supply;     // regulator that must already be on, or NULL
};

static const struct tp8_i2c_target tp8_i2c_targets[] = {
    // GT1151 picks 0x5d or 0x14 from the INT level at reset; both are tried, never reset.
    {"11007000.i2c", 0, "gt1151qm", 0x5d, {0x81, 0x40}, 2, 4, "vldo28"},
    {"11007000.i2c", 0, "gt1151qm", 0x14, {0x81, 0x40}, 2, 4, "vldo28"},
    {"1100f000.i2c", 3, "fs16xx", 0x34, {0x03}, 1, 2, NULL},
    {"11005000.i2c", 6, "oz8806", 0x2f, {0x00}, 1, 1, NULL},
    {"11005000.i2c", 6, "synaptics-pad", 0x20, {0xe9}, 1, 6, NULL},
    {"11005000.i2c", 6, "synaptics-pad", 0x2c, {0xe9}, 1, 6, NULL},
};
#define TP8_I2C_TARGETS (sizeof(tp8_i2c_targets) / sizeof(tp8_i2c_targets[0]))
#define TP8_I2C_MAX_READ 8u

static int tp8_i2c_target_valid(const struct tp8_i2c_target *t)
{
    return t->address >= 0x08 && t->address <= 0x77 && t->reg_length >= 1 && t->reg_length <= 2 &&
           t->read_length >= 1 && t->read_length <= TP8_I2C_MAX_READ;
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
#endif
