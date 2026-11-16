#!/usr/bin/env python3
"""Plan, check and (only when every gate passes) assemble a Pocket super image.

Default is a dry run: it reads the stock super metadata, checks the inputs
against stock geometry and prints the lpmake command it would run. It refuses
to write anything until all three partition images exist and pass.

  --stock-only       check stock super metadata against the board config and exit
  --self-test        plan with the stock system/vendor/product images
  --lpmake-test DIR  run the real lpmake on tiny generated images in DIR and check
                     the output geometry against stock
  --write OUT        build OUT (sparse) with lpmake, then re-read and check it

Never touches a phone. Inputs are only read.
"""
import pocket_paths
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
STOCK_DIR = ROOT / 'firmware/installed-20230105'
PRODUCT_DIR = BULK / 'product-out/target/product/titan_pocket'
LPMAKE = pocket_paths.platform_source() / 'prebuilts/kernel-build-tools/linux-x86/bin/lpmake'

# Stock values, from evidence/installed-20230105/super-layout.json and the
# verified 37-partition backup (super raw SHA256 below).
STOCK_SUPER_BYTES = 4831838208
STOCK_SUPER_SHA256 = '6f8764f8318282ee6a98b75abd25a1bbf79af9c85a504f2021c41f60ba24fc88'
STOCK_METADATA_MAX = 65536
STOCK_METADATA_SLOTS = 2
STOCK_BLOCK = 4096
STOCK_GROUP = 'main'
STOCK_GROUP_MAX = 4829741056
PARTITIONS = ['system', 'vendor', 'product']
# Stock metadata says 512 KiB alignment but its data starts at 1 MiB (sector 2048).
# lpmake with 512 KiB would start data at 512 KiB, so use 1 MiB: every extent stays
# 512 KiB aligned and the data start matches stock.
ALIGN = 1024 * 1024

LP_RESERVED = 4096
LP_GEOMETRY_MAGIC = 0x616c4467
LP_HEADER_MAGIC = 0x414c5030
SPARSE_MAGIC = 0xed26ff3a
EXT4_MAGIC = 0xef53


class Fail(Exception):
    pass


def sparse_reader(path):
    """Return (total_bytes, read(offset, n)) for an Android sparse image."""
    with open(path, 'rb') as f:
        head = f.read(28)
        magic, major, minor, fhs, chs, blk, total_blks, total_chunks, _ = struct.unpack('<IHHHHIIII', head)
        if magic != SPARSE_MAGIC or major != 1:
            raise Fail(f'{path}: not a v1 sparse image')
        f.seek(fhs)
        chunks = []  # (out_offset, out_bytes, kind, file_offset or fill)
        out = 0
        for _ in range(total_chunks):
            ctype, _, csz, tsz = struct.unpack('<HHII', f.read(12))
            body = f.tell() + (chs - 12)
            nbytes = csz * blk
            if ctype == 0xCAC1:
                chunks.append((out, nbytes, 'raw', body))
            elif ctype == 0xCAC2:
                f.seek(body)
                chunks.append((out, nbytes, 'fill', f.read(4)))
            elif ctype == 0xCAC3:
                chunks.append((out, nbytes, 'skip', None))
            elif ctype != 0xCAC4:
                raise Fail(f'{path}: unknown sparse chunk 0x{ctype:x}')
            out += nbytes if ctype != 0xCAC4 else 0
            f.seek(body + (tsz - chs))
    total = total_blks * blk

    def read(offset, n):
        buf = bytearray(n)
        with open(path, 'rb') as f:
            for start, size, kind, data in chunks:
                lo, hi = max(offset, start), min(offset + n, start + size)
                if lo >= hi:
                    continue
                if kind == 'raw':
                    f.seek(data + lo - start)
                    buf[lo - offset:hi - offset] = f.read(hi - lo)
                elif kind == 'fill':
                    pat = data * ((hi - lo) // 4 + 2)
                    shift = (lo - start) % 4
                    buf[lo - offset:hi - offset] = pat[shift:shift + hi - lo]
        return bytes(buf)
    return total, read


def open_image(path):
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
    if magic == SPARSE_MAGIC:
        total, read = sparse_reader(path)
        return total, read, True
    size = path.stat().st_size

    def read(offset, n):
        with open(path, 'rb') as f:
            f.seek(offset)
            return f.read(n)
    return size, read, False


def cstr(raw):
    return raw.split(b'\0', 1)[0].decode()


def parse_lp(read):
    """Parse LP geometry and slot-0 metadata. Checks both checksums."""
    geo = read(LP_RESERVED, 4096)
    magic, struct_size = struct.unpack_from('<II', geo, 0)
    if magic != LP_GEOMETRY_MAGIC:
        raise Fail('LP geometry magic missing')
    checksum = geo[8:40]
    meta_max, slots, block = struct.unpack_from('<III', geo, 40)
    blank = geo[:8] + b'\0' * 32 + geo[40:struct_size]
    if hashlib.sha256(blank).digest() != checksum:
        raise Fail('LP geometry checksum mismatch')
    if read(LP_RESERVED + 4096, struct_size) != geo[:struct_size]:
        raise Fail('LP backup geometry differs from primary')
    base = LP_RESERVED + 2 * 4096  # primary metadata, slot 0
    hdr = read(base, 256)
    hmagic, major, minor, hsize = struct.unpack_from('<IHHI', hdr, 0)
    if hmagic != LP_HEADER_MAGIC:
        raise Fail('LP metadata header magic missing')
    hdr = hdr[:hsize]
    hcheck = hdr[12:44]
    if hashlib.sha256(hdr[:12] + b'\0' * 32 + hdr[44:]).digest() != hcheck:
        raise Fail('LP metadata header checksum mismatch')
    tables_size = struct.unpack_from('<I', hdr, 44)[0]
    tcheck = hdr[48:80]
    descs = [struct.unpack_from('<III', hdr, 80 + 12 * i) for i in range(4)]
    flags = struct.unpack_from('<I', hdr, 128)[0] if hsize >= 132 else 0
    tables = read(base + hsize, tables_size)
    if hashlib.sha256(tables).digest() != tcheck:
        raise Fail('LP metadata tables checksum mismatch')

    def table(i, fmt):
        off, num, esz = descs[i]
        return [struct.unpack_from(fmt, tables, off + k * esz) for k in range(num)]
    parts = table(0, '<36sIIII')
    extents = table(1, '<QIQI')
    groups = table(2, '<36sIQ')
    devices = table(3, '<QIIQ36sI')
    out = {
        'geometry': {'metadata_max_bytes': meta_max, 'slots': slots, 'block_bytes': block},
        'header_version': f'{major}.{minor}', 'header_flags': flags,
        'groups': [{'name': cstr(n), 'flags': fl, 'max_bytes': mx} for n, fl, mx in groups],
        'block_devices': [{'name': cstr(n), 'first_logical_sector': fls, 'alignment': al,
                           'alignment_offset': ao, 'bytes': sz, 'flags': fl}
                          for fls, al, ao, sz, n, fl in devices],
        'partitions': [],
    }
    for name, attrs, first, num, gidx in parts:
        ranges = [{'offset': e[2] * 512, 'bytes': e[0] * 512} for e in extents[first:first + num]]
        out['partitions'].append({'name': cstr(name), 'attributes': attrs,
                                  'group': cstr(groups[gidx][0]),
                                  'bytes': sum(r['bytes'] for r in ranges), 'ranges': ranges})
    return out


def check_stock_metadata(meta):
    problems = []
    g = meta['geometry']
    if (g['metadata_max_bytes'], g['slots'], g['block_bytes']) != (STOCK_METADATA_MAX, STOCK_METADATA_SLOTS, STOCK_BLOCK):
        problems.append(f'geometry {g} differs from stock')
    devs = meta['block_devices']
    if len(devs) != 1 or devs[0]['name'] != 'super' or devs[0]['bytes'] != STOCK_SUPER_BYTES:
        problems.append(f'block device {devs} differs from stock')
    grp = {x['name']: x['max_bytes'] for x in meta['groups']}
    if grp.get(STOCK_GROUP) != STOCK_GROUP_MAX:
        problems.append(f'group {STOCK_GROUP} max {grp.get(STOCK_GROUP)} differs from {STOCK_GROUP_MAX}')
    if sorted(p['name'] for p in meta['partitions']) != sorted(PARTITIONS):
        problems.append('partition names differ from system/vendor/product')
    return problems


def check_board(meta):
    """Compare BoardConfig.hardware.mk with stock metadata. Returns notes, not failures."""
    board = (pocket_paths.DEVICE_TREE / 'BoardConfig.hardware.mk').read_text()
    vals = {}
    for line in board.splitlines():
        if ':=' in line and not line.lstrip().startswith('#'):
            k, v = line.split(':=', 1)
            vals[k.strip()] = v.strip()
    notes = []
    if int(vals.get('BOARD_SUPER_PARTITION_SIZE', 0)) != STOCK_SUPER_BYTES:
        notes.append('BOARD_SUPER_PARTITION_SIZE differs from stock')
    groups = vals.get('BOARD_SUPER_PARTITION_GROUPS', '').split()
    for gname in groups:
        size = int(vals.get(f'BOARD_{gname.upper()}_SIZE', 0))
        if size != STOCK_GROUP_MAX:
            notes.append(f'board group {gname} size {size} differs from stock {STOCK_GROUP_MAX}')
    if groups != [STOCK_GROUP]:
        notes.append(f'board group name {groups} differs from stock "{STOCK_GROUP}"; this script uses "{STOCK_GROUP}" '
                     'so fastbootd and the stock layout agree. An OTA built from the board config would rewrite it.')
    return notes


def inspect_input(name, path):
    """Size, sparse flag, ext4 magic and AVB footer for one partition image."""
    info = {'name': name, 'path': str(path), 'exists': path.is_file()}
    if not info['exists']:
        return info
    size, read, sparse = open_image(path)
    info.update(bytes=size, sparse=sparse, file_bytes=path.stat().st_size)
    info['ext4'] = struct.unpack('<H', read(1024 + 56, 2))[0] == EXT4_MAGIC
    tail = read(size - 64, 64)
    info['avb_footer'] = tail[:4] == b'AVBf'
    if info['avb_footer']:
        orig, vb_off, vb_size = struct.unpack_from('>QQQ', tail, 12)
        info['avb_original_bytes'] = orig
    return info


HOST_BIN = pocket_paths.platform_source() / 'out/host/linux-x86/bin'
KEYMINT_BIN = '/system/system_ext/bin/hw/android.hardware.security.keymint-service.pocket'


def keymaster_pairing(vendor, system):
    """Problems if the vendor manifest and the system image disagree on who provides keymaster."""
    def dbg(img, cmd):
        r = subprocess.run([str(HOST_BIN / 'debugfs'), '-R', cmd, str(img)], capture_output=True, text=True)
        return r.stdout
    tmp = Path(os.environ.get('TMPDIR', '/tmp')) / f'assemble-km-{os.getpid()}.raw'
    try:
        if system.read_bytes()[:4] == b'\x3a\xff\x26\xed':
            subprocess.run([str(HOST_BIN / 'simg2img'), str(system), str(tmp)], check=True)
            raw = tmp
        else:
            raw = system
        soft = 'Inode:' in dbg(raw, f'stat {KEYMINT_BIN}')
    finally:
        tmp.unlink(missing_ok=True)
    man = dbg(vendor, 'cat /etc/vintf/manifest.xml')
    tee = '<name>android.hardware.keymaster</name>' in man
    vkm = 'android.hardware.security.keymint' in man
    problems = []
    if not (tee or vkm or soft):
        problems.append('no keymaster or KeyMint anywhere (vendor manifest and system_ext)')
    if tee and soft:
        problems.append('vendor manifest declares the TK keymaster and system_ext has the software KeyMint (overlay v5 goes with the flag, v6 without)')
    return problems


def align_up(n, a):
    return (n + a - 1) // a * a


def plan(inputs, meta):
    """Return (problems, lpmake argv without output) for the given inputs."""
    problems = []
    for i in inputs:
        if not i['exists']:
            problems.append(f"{i['name']}: missing ({i['path']})")
            continue
        if i['bytes'] % STOCK_BLOCK:
            problems.append(f"{i['name']}: {i['bytes']} bytes is not a multiple of {STOCK_BLOCK}")
        if not i['ext4']:
            problems.append(f"{i['name']}: no ext4 superblock")
        if not i['avb_footer']:
            problems.append(f"{i['name']}: no AVB footer (system/product need the build's hashtree; "
                            'the vendor overlay needs its hashtree rebuilt)')
    dev = meta['block_devices'][0]
    first = dev['first_logical_sector'] * 512
    used = sum(align_up(i.get('bytes', 0), ALIGN) for i in inputs)
    if used > STOCK_GROUP_MAX:
        problems.append(f'inputs need {used} bytes, group "{STOCK_GROUP}" allows {STOCK_GROUP_MAX}')
    if first + used > STOCK_SUPER_BYTES:
        problems.append(f'inputs need {first + used} bytes with metadata, super is {STOCK_SUPER_BYTES}')
    argv = [str(LPMAKE), '--metadata-size', str(STOCK_METADATA_MAX), '--metadata-slots', str(STOCK_METADATA_SLOTS),
            '--super-name', 'super', '--device-size', str(STOCK_SUPER_BYTES),
            '--alignment', str(ALIGN), '--alignment-offset', str(dev['alignment_offset']),
            '--group', f'{STOCK_GROUP}:{STOCK_GROUP_MAX}']
    for i in inputs:
        argv += ['--partition', f"{i['name']}:readonly:{i.get('bytes', 0)}:{STOCK_GROUP}"]
    for i in inputs:
        argv += ['--image', f"{i['name']}={i['path']}"]
    room = STOCK_GROUP_MAX - used
    return problems, argv, used, room


def verify_output(out, inputs, stock_meta):
    size, read, sparse = open_image(out)
    if size != STOCK_SUPER_BYTES:
        raise Fail(f'output expands to {size} bytes, stock super is {STOCK_SUPER_BYTES}')
    meta = parse_lp(read)
    problems = check_stock_metadata(meta)
    dev, sdev = meta['block_devices'][0], stock_meta['block_devices'][0]
    if dev['first_logical_sector'] != sdev['first_logical_sector']:
        problems.append(f"first logical sector {dev['first_logical_sector']} differs from stock {sdev['first_logical_sector']}")
    if dev['alignment'] % sdev['alignment'] or dev['alignment_offset'] != sdev['alignment_offset']:
        problems.append(f"alignment {dev['alignment']}/{dev['alignment_offset']} not compatible with stock "
                        f"{sdev['alignment']}/{sdev['alignment_offset']}")
    for p in meta['partitions']:
        for r in p['ranges']:
            if r['offset'] % sdev['alignment']:
                problems.append(f"{p['name']}: extent at {r['offset']} not aligned to stock {sdev['alignment']}")
    want = {i['name']: i['bytes'] for i in inputs}
    for p in meta['partitions']:
        if p['bytes'] != want.get(p['name']):
            problems.append(f"{p['name']}: {p['bytes']} bytes in output, input is {want.get(p['name'])}")
        if p['attributes'] != 1:
            problems.append(f"{p['name']}: attributes {p['attributes']}, stock is 1 (readonly)")
    # Spot-check the first 4 KiB of each partition against its input.
    for p in meta['partitions']:
        src = next(i for i in inputs if i['name'] == p['name'])
        _, src_read, _ = open_image(Path(src['path']))
        if p['ranges'] and read(p['ranges'][0]['offset'], 4096) != src_read(0, 4096):
            problems.append(f"{p['name']}: first block in output differs from input")
    return meta, problems


def load_stock(path):
    if not path.is_file():
        raise Fail(f'stock super missing: {path}')
    size, read, _ = open_image(path)
    if size != STOCK_SUPER_BYTES:
        raise Fail(f'stock super is {size} bytes, expected {STOCK_SUPER_BYTES}')
    meta = parse_lp(read)
    problems = check_stock_metadata(meta)
    if problems:
        raise Fail('stock super does not match recorded stock layout: ' + '; '.join(problems))
    return meta


def lpmake_test(work, stock_meta):
    """Run the real lpmake with stock geometry on three tiny ext4-shaped images."""
    work.mkdir(parents=True, exist_ok=True)
    inputs = []
    for k, name in enumerate(PARTITIONS):
        p = work / f'{name}.img'
        data = bytearray(os.urandom(4096)) + bytearray((k + 1) * 1024 * 1024)
        data[1024 + 56:1024 + 58] = struct.pack('<H', EXT4_MAGIC)
        footer = b'AVBf' + struct.pack('>II', 1, 0) + struct.pack('>QQQ', len(data) - 4096, 0, 0)
        data[-64:] = footer + b'\0' * (64 - len(footer))
        p.write_bytes(bytes(data))
        inputs.append(inspect_input(name, p))
    problems, argv, used, room = plan(inputs, stock_meta)
    if problems:
        raise Fail('synthetic plan failed: ' + '; '.join(problems))
    out = work / 'super-test.img'
    subprocess.run(argv + ['--sparse', '--output', str(out)], check=True, capture_output=True)
    meta, problems = verify_output(out, inputs, stock_meta)
    return {'output': str(out), 'output_file_bytes': out.stat().st_size, 'problems': problems,
            'partitions': meta['partitions']}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--stock-super', type=Path, default=STOCK_DIR / 'super.raw.img')
    ap.add_argument('--system', type=Path, default=PRODUCT_DIR / 'system.img')
    ap.add_argument('--product', type=Path, default=PRODUCT_DIR / 'product.img')
    ap.add_argument('--vendor', type=Path, default=None,
                    help='overlaid vendor image (required; the unmodified stock vendor is not accepted by default)')
    ap.add_argument('--allow-stock-vendor', action='store_true',
                    help='accept the unmodified stock vendor image (diagnostic only)')
    ap.add_argument('--stock-only', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--lpmake-test', type=Path)
    ap.add_argument('--write', type=Path)
    ap.add_argument('--hash-stock', action='store_true', help='also hash the 4.5 GiB stock super')
    ap.add_argument('--json', type=Path, help='write the report here')
    a = ap.parse_args()

    report = {'device_accessed': False}
    try:
        stock = load_stock(a.stock_super)
        report['stock'] = stock
        if a.hash_stock:
            h = hashlib.sha256()
            with open(a.stock_super, 'rb') as f:
                for b in iter(lambda: f.read(8 << 20), b''):
                    h.update(b)
            report['stock_sha256_matches_backup'] = h.hexdigest() == STOCK_SUPER_SHA256
            if not report['stock_sha256_matches_backup']:
                raise Fail('stock super hash differs from the verified backup')
        report['board_notes'] = check_board(stock)
        print(f"stock super OK: {STOCK_SUPER_BYTES} bytes, metadata {STOCK_METADATA_MAX} x {STOCK_METADATA_SLOTS} slots, "
              f"group {STOCK_GROUP} max {STOCK_GROUP_MAX}, first logical sector "
              f"{stock['block_devices'][0]['first_logical_sector']}, alignment {stock['block_devices'][0]['alignment']}")
        for p in stock['partitions']:
            print(f"  stock {p['name']:8} {p['bytes']:>11} bytes in {len(p['ranges'])} extents")
        for n in report['board_notes']:
            print('note:', n)
        if a.stock_only:
            return finish(report, a, 0)

        if a.lpmake_test:
            if not LPMAKE.is_file():
                raise Fail(f'lpmake missing: {LPMAKE}')
            res = lpmake_test(a.lpmake_test, stock)
            report['lpmake_test'] = res
            print(f"lpmake test: {res['output_file_bytes']} byte sparse output, "
                  f"{'PASS' if not res['problems'] else 'FAIL: ' + '; '.join(res['problems'])}")
            return finish(report, a, 1 if res['problems'] else 0)

        if a.self_test:
            paths = {n: STOCK_DIR / f'{n}.img' for n in PARTITIONS}
        else:
            vendor = a.vendor
            if vendor is None and a.allow_stock_vendor:
                vendor = STOCK_DIR / 'vendor.img'
            paths = {'system': a.system, 'vendor': vendor or Path('<overlaid vendor not given>'),
                     'product': a.product}
        inputs = [inspect_input(n, paths[n]) for n in PARTITIONS]
        report['inputs'] = inputs
        problems, argv, used, room = plan(inputs, stock)
        if a.self_test:
            stock_sizes = {p['name']: p['bytes'] for p in stock['partitions']}
            for i in inputs:
                if i.get('bytes') != stock_sizes[i['name']]:
                    problems.append(f"{i['name']}: stock image {i.get('bytes')} bytes, stock metadata {stock_sizes[i['name']]}")
        if not a.self_test and all(i['exists'] for i in inputs):
            problems += keymaster_pairing(paths['vendor'], paths['system'])
        report.update(problems=problems, lpmake=argv, bytes_used=used, group_room=room)
        for i in inputs:
            if i['exists']:
                print(f"  input {i['name']:8} {i['bytes']:>11} bytes sparse={i['sparse']} ext4={i['ext4']} "
                      f"avb_footer={i['avb_footer']}")
            else:
                print(f"  input {i['name']:8} MISSING {i['path']}")
        print(f'group use {used} of {STOCK_GROUP_MAX} bytes, {room} bytes ({room / 2**20:.0f} MiB) left')
        print('lpmake command:', ' '.join(argv + ['--sparse', '--output', str(a.write or 'OUT')]))
        if problems:
            print('REFUSED:')
            for p in problems:
                print('  -', p)
            return finish(report, a, 1)
        print('all input gates pass')
        if not a.write:
            print('dry run only; pass --write OUT to build')
            return finish(report, a, 0)
        if a.self_test:
            raise Fail('--write is not allowed with --self-test')
        if a.write.exists():
            raise Fail(f'{a.write} exists; refusing to overwrite')
        subprocess.run(argv + ['--sparse', '--output', str(a.write)], check=True)
        meta, out_problems = verify_output(a.write, inputs, stock)
        report['output'] = {'path': str(a.write), 'partitions': meta['partitions'], 'problems': out_problems}
        if out_problems:
            print('OUTPUT CHECK FAILED:', '; '.join(out_problems))
            return finish(report, a, 1)
        print(f'wrote {a.write}; geometry matches stock')
        return finish(report, a, 0)
    except Fail as e:
        report['error'] = str(e)
        print('ERROR:', e, file=sys.stderr)
        return finish(report, a, 2)


def finish(report, a, code):
    report['exit'] = code
    if a.json:
        a.json.write_text(json.dumps(report, indent=2) + '\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
