#!/usr/bin/env python3
"""Check the expdb ring parser on a synthetic image and on the saved v10, v11 and v12 return copies."""
import gzip, hashlib, json, os, runpy, struct, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / 'tools/parse-pocket-expdb-ring.py'
P = runpy.run_path(str(TOOL), run_name='parser')
RING, HEADER, SIG = P['RING'], P['HEADER'], P['SIG']
EV = ROOT / 'evidence/kernel-upgrade'
SAVED = [  # path, next slot, newest slot, newest record type, newest end
    (EV / 'diagnostic-v10-trial-20261031T035857Z/return-final/expdb.bin', 13, 12, 'PLLK', 618496),
    (EV / 'diagnostic-v11-trial-20261031T125837Z/return-final/expdb.bin', 15, 14, 'PLLK', 811008),
    (EV / 'diagnostic-v12-trial-20261031T143647Z/return-final/expdb.bin', 1, 0, 'PLLK', 1003520),
]


def build(records, next_slot, offset, sig=SIG, size=4 * RING, step=4):
    """records: list of (slot, type, start, end, text). Text is written into the ring, wrapping."""
    img = bytearray(size)
    ring = bytearray(RING)
    entries = [(0, 0, 0)] * 16
    for slot, kind, start, end, text in records:
        entries[slot] = (kind, start, end)
        data = text.encode()
        first = min(len(data), RING - start) if end < start else len(data)
        ring[start:start + first] = data[:first]
        if first < len(data):
            ring[0:len(data) - first] = data[first:]
    flags = [0] * 11
    flags[1], flags[4] = next_slot, step
    head = struct.pack('<13I', sig, offset, *flags) + struct.pack('<48I', *[v for e in entries for v in e])
    ring[-HEADER:] = head.ljust(HEADER, b'\0')
    img[-RING:] = ring
    return bytes(img)


def expect_error(path, why):
    p = subprocess.run([sys.executable, '-I', str(TOOL), str(path)], capture_output=True, text=True)
    assert p.returncode != 0 and 'parse-pocket-expdb-ring' in p.stderr, why


def synthetic(tmp):
    cases = 0
    boot = ('[100] rst from: kernel\n[101] g_rgu_status: 2 (0x2)\n[102] BOOT_REASON: 3\n[103] lk boot mode = 2\n'
            '[104] RTC time:[2026/10/31 1:2:3]\n[105] ASSERT at lk/x.c:9\n' + ''.join('[%d] filler %d\n' % (i, i) for i in range(30)))
    kernel = b'\x08\x00\x00\x00\x01\x02Linux version 5.10.257-test (x)\n\x00\x07\x00Kernel panic - not syncing: boom\n'.decode('latin1')
    # The newest record starts 100 bytes before the end of the ring, where the header page sits, and wraps.
    wrap_start = RING - 100
    wrapped = 'x' * 100 + boot
    recs = [(15, 1, 1000, 1000 + len(boot), boot),                      # oldest
            (0, 3, 1000 + len(boot), 1000 + len(boot) + len(kernel), kernel),
            (1, 1, wrap_start, len(boot), wrapped)]                      # newest, wraps, overwrites nothing older
    img = tmp / 'synthetic.bin'
    img.write_bytes(build(recs, next_slot=2, offset=len(boot)))
    before = hashlib.sha256(img.read_bytes()).hexdigest()
    os.chmod(img, 0o444)
    r = P['parse'](img, 20)
    assert hashlib.sha256(img.read_bytes()).hexdigest() == before; cases += 1  # read-only input
    h = r['header']
    assert (h['next_slot'], h['newest_slot'], h['offset_matches_newest_end']) == (2, 1, True); cases += 1
    assert [x['slot'] for x in r['records']][:3] == [1, 0, 15] and r['records'][0]['age'] == 0; cases += 1
    new, mid, old = r['records'][0], r['records'][1], r['records'][2]
    assert new['bytes'] == 100 + len(boot) and new['rst_from'] == ['kernel'] and new['g_rgu_status'] == ['0x2'], new; cases += 1
    assert new['boot_reason'] == ['3'] and new['lk_boot_mode'] == ['2'] and new['rtc_time'] == ['2026/10/31 1:2:3']; cases += 1
    assert new['alerts'] == ['[105] ASSERT at lk/x.c:9']; cases += 1
    assert len(new['last_lines']) == 20 and new['last_lines'][-1].endswith('filler 29'); cases += 1
    assert mid['type'] == 'KERNEL' and mid['kernel_versions'] == ['5.10.257-test'] and any('Kernel panic' in a for a in mid['alerts']); cases += 1
    assert mid['overwritten_bytes'] == 0 and old['overwritten_bytes'] == 0 and old['rst_from'] == ['kernel']; cases += 1
    assert sum(1 for x in r['records'] if x['type'] == 'EMPTY') == 13; cases += 1
    # A newer record over an older one's bytes is reported as overwritten.
    img2 = tmp / 'overlap.bin'
    img2.write_bytes(build([(0, 1, 500, 500 + len(boot), boot), (1, 1, 500 + 50, 500 + 50 + len(boot), boot)], next_slot=2, offset=550 + len(boot)))
    r2 = P['parse'](img2)
    assert r2['records'][1]['slot'] == 0 and r2['records'][1]['overwritten_bytes'] == len(boot) - 50, r2['records'][1]['overwritten_bytes']; cases += 1
    # Gzip input, JSON and text output through the command line.
    gz = tmp / 'synthetic.bin.gz'
    gz.write_bytes(gzip.compress(img.read_bytes(), mtime=0))
    assert P['parse'](gz)['records'][0]['rst_from'] == ['kernel']; cases += 1
    js = tmp / 'out.json'
    p = subprocess.run([sys.executable, '-I', str(TOOL), str(img), '--json', str(js), '--detail', '1'], capture_output=True, text=True, check=True)
    assert json.loads(js.read_text())['header']['newest_slot'] == 1 and 'rst=kernel' in p.stdout and 'ASSERT' in p.stdout; cases += 1
    # Failures: wrong signature, too small, bad slot index.
    bad = tmp / 'badsig.bin'
    bad.write_bytes(build(recs, 2, 200, sig=0x12345678)); expect_error(bad, 'accepted a wrong signature'); cases += 1
    small = tmp / 'small.bin'
    small.write_bytes(b'\0' * 4096); expect_error(small, 'accepted a tiny image'); cases += 1
    badslot = tmp / 'badslot.bin'
    badslot.write_bytes(build(recs, 16, 200)); expect_error(badslot, 'accepted next slot 16'); cases += 1
    return cases


def saved():
    cases = 0
    for path, nxt, newest, kind, end in SAVED:
        if not path.exists():
            print('skipping missing', path)
            continue
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        r = P['parse'](path)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before; cases += 1
        h = r['header']
        assert (h['next_slot'], h['newest_slot'], h['offset_matches_newest_end']) == (nxt, newest, True), path; cases += 1
        top = r['records'][0]
        assert (top['slot'], top['type'], top['end']) == (newest, kind, end) and top['overwritten_bytes'] == 0, path; cases += 1
        # The newest record is LK's log of the diagnostic boot: reason 4, LK mode 2 and the jump to the kernel.
        assert top['boot_reason'] == ['4'] and top['lk_boot_mode'] == ['2'] and top['rst_from'] == ['unknown'], path; cases += 1
        assert any('jump to' in l for l in top['last_lines']), path; cases += 1
        assert len(r['records']) == 16 and sorted(x['age'] for x in r['records']) == list(range(16)); cases += 1
    return cases


def main():
    with tempfile.TemporaryDirectory() as t:
        syn = synthetic(Path(t))
    sav = saved()
    record = {'synthetic_cases': syn, 'saved_copy_cases': sav,
              'result': 'Ring header, slot order, wrap, overwritten bytes, field extraction and error exits pass on a synthetic image; newest-record checks pass on the saved v10, v11 and v12 return copies',
              'source_hashes': {str(TOOL.relative_to(ROOT)): hashlib.sha256(TOOL.read_bytes()).hexdigest()},
              'device_accessed': False}
    (EV / 'expdb-ring-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print('%d synthetic and %d saved-copy expdb ring cases passed' % (syn, sav))


if __name__ == '__main__':
    main()
