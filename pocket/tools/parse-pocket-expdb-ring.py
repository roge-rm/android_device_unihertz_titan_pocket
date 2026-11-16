#!/usr/bin/env python3
"""Parse the log ring in the last 2 MiB of a saved expdb image. Read-only on its input.

Layout (kernel drivers/misc/mediatek/log_store): the last 4 KiB hold struct log_emmc_header
(sig 0x785690ef, write offset, 11 flags; flag 1 is the next slot to write) followed by 16
struct emmc_log (type, start, end). Offsets are into the 2 MiB ring that ends the partition.
Slots are written in index order, so the newest is the one before the next-to-write slot.
"""
import argparse, gzip, json, re, struct, sys
from pathlib import Path

SIG = 0x785690ef
RING = 2 * 1024 * 1024
HEADER = 4096
SLOTS = 16
TYPES = {0: 'EMPTY', 1: 'PLLK', 2: 'PL', 3: 'KERNEL', 4: 'ATF', 5: 'GZ', 6: 'LAST_KERNEL'}
PHASES = {1: 'PL', 2: 'LK', 3: 'KERNEL', 4: 'ANDROID', 5: 'PL_COLD_REBOOT', 6: 'SUSPEND', 7: 'RESUME'}
FIELDS = {
    'rst_from': r'rst from: (\w+)',
    'g_rgu_status': r'g_rgu_status: \d+ \((0x[0-9a-fA-F]+)\)',
    'boot_reason': r'BOOT_REASON: (\d+)',
    'lk_boot_mode': r'lk boot mode = (\d+)',
    'rtc_time': r'RTC time:\[([^\]]*)\]',
    'kernel_versions': r'\b((?:4\.14|5\.10)\.\d+[\w.+-]*)',
}
# Text that marks a failure in LK or the kernel; the first 20 different hits per record are kept.
ALERT = re.compile(r'ASSERT|[Aa]ssertion failed|Kernel panic|panic[:(]|\bOops\b|BUG:|Unable to handle|Call trace')


def read_tail(path):
    """Return (ring bytes, header page, total size). Plain files are read from the end only."""
    path = Path(path)
    if path.suffix == '.gz':
        with gzip.open(path, 'rb') as f:
            data = f.read()
        size = len(data)
        tail = data[-RING:]
    else:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            if size < RING:
                raise ValueError('image is smaller than the 2 MiB ring')
            f.seek(size - RING)
            tail = f.read(RING)
    if len(tail) < RING:
        raise ValueError('image is smaller than the 2 MiB ring')
    return tail, tail[-HEADER:], size


def text_lines(blob):
    """Printable runs of 3+ characters; kernel records carry binary headers between lines."""
    return [m.strip() for m in re.findall(r'[\x20-\x7e\t]{3,}', blob.decode('latin1')) if m.strip()]


def intervals(start, end):
    if end >= start:
        return [(start, end)] if end > start else []
    return [(start, RING), (0, end)]


def overlap(a, b):
    return sum(max(0, min(x1, y1) - max(x0, y0)) for x0, x1 in a for y0, y1 in b)


def parse(path, last_lines=20):
    ring, header, size = read_tail(path)
    words = struct.unpack_from('<13I', header, 0)
    if words[0] != SIG:
        raise ValueError('no log ring header (signature 0x%08x, expected 0x%08x)' % (words[0], SIG))
    offset, flags = words[1], list(words[2:])
    next_slot = flags[1]
    if next_slot >= SLOTS:
        raise ValueError('next slot index %d out of range' % next_slot)
    entries = struct.unpack_from('<%dI' % (3 * SLOTS), header, 52)
    step = flags[4]
    records = []
    for slot in range(SLOTS):
        kind, start, end = entries[3 * slot:3 * slot + 3]
        rec = {'slot': slot, 'type': TYPES.get(kind, 'TYPE_%d' % kind), 'type_id': kind, 'start': start, 'end': end}
        # Newest first: age 0 is the slot before the next one to be written.
        rec['age'] = (next_slot - 1 - slot) % SLOTS
        if start > RING or end > RING:
            rec['valid'] = False
            records.append(rec)
            continue
        rec['valid'] = True
        iv = intervals(start, end)
        rec['bytes'] = sum(b - a for a, b in iv)
        rec['intervals'] = iv
        blob = b''.join(ring[a:b] for a, b in iv)
        lines = text_lines(blob)
        text = '\n'.join(lines)
        for key, pat in FIELDS.items():
            seen = []
            for v in re.findall(pat, text):
                if v not in seen:
                    seen.append(v)
            rec[key] = seen
        rec['alerts'] = list(dict.fromkeys(l for l in lines if ALERT.search(l)))[:20]
        rec['last_lines'] = lines[-last_lines:]
        records.append(rec)
    # A record's text is partly replaced when newer records were written over the same bytes.
    spans = {r['slot']: r.pop('intervals') for r in records if r['valid']}
    for rec in records:
        if not rec['valid']:
            continue
        newer = [spans[o['slot']] for o in records if o['valid'] and o['age'] < rec['age']]
        # Newer records can overlap each other, so cap by the record's own size.
        rec['overwritten_bytes'] = min(sum(overlap(spans[rec['slot']], iv) for iv in newer), rec['bytes'])
    records.sort(key=lambda r: r['age'])
    return {
        'image': str(path), 'image_bytes': size,
        'header': {'sig': '0x%08x' % words[0], 'offset': offset, 'next_slot': next_slot,
                   'newest_slot': (next_slot - 1) % SLOTS, 'flags': ['0x%x' % f for f in flags],
                   'boot_step_now': PHASES.get(step & 0xf, step & 0xf),
                   'boot_step_last': PHASES.get((step >> 4) & 0xf, (step >> 4) & 0xf),
                   'offset_matches_newest_end': any(r['age'] == 0 and r['end'] == offset for r in records)},
        'records': records,
    }


def summary(result, detail=3):
    h = result['header']
    out = ['%s: %d bytes' % (result['image'], result['image_bytes']),
           'ring offset %d, next slot %d, newest slot %d, boot step now=%s last=%s' % (
               h['offset'], h['next_slot'], h['newest_slot'], h['boot_step_now'], h['boot_step_last']),
           'newest first:']
    join = lambda v: ','.join(v) if v else '-'
    for r in result['records']:
        if not r['valid']:
            out.append('  age %2d slot %2d %-6s invalid range %d-%d' % (r['age'], r['slot'], r['type'], r['start'], r['end']))
            continue
        out.append('  age %2d slot %2d %-6s %7d-%-7d %6d B over=%-6d rst=%s rgu=%s reason=%s lkmode=%s rtc=%s%s' % (
            r['age'], r['slot'], r['type'], r['start'], r['end'], r['bytes'], r['overwritten_bytes'],
            join(r['rst_from']), join(r['g_rgu_status']), join(r['boot_reason']), join(r['lk_boot_mode']),
            r['rtc_time'][-1] if r['rtc_time'] else '-',
            ' kernel=' + join(r['kernel_versions']) if r['kernel_versions'] else ''))
        for line in r['alerts'][:3]:
            out.append('      alert: ' + line[:160])
    for r in result['records'][:detail]:
        if r['valid']:
            out.append('last lines, age %d slot %d %s:' % (r['age'], r['slot'], r['type']))
            out.extend('    ' + l[:200] for l in r['last_lines'])
    return '\n'.join(out) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('image', type=Path, help='expdb image, raw or .gz')
    p.add_argument('--json', type=Path, help='write the full result as JSON here')
    p.add_argument('--lines', type=int, default=20, help='last lines kept per record')
    p.add_argument('--detail', type=int, default=3, help='records whose last lines the text shows, newest first')
    a = p.parse_args()
    try:
        result = parse(a.image, a.lines)
    except (OSError, ValueError) as e:
        sys.exit('parse-pocket-expdb-ring: %s' % e)
    if a.json:
        a.json.write_text(json.dumps(result, indent=2) + '\n')
    sys.stdout.write(summary(result, a.detail))


if __name__ == '__main__':
    main()
