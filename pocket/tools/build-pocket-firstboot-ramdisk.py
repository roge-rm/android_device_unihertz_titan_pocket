#!/usr/bin/env python3
"""Build the first-flash v2 ramdisk: the product ramdisk with the wrapper at /init.

Offline only. Compiles kernel-upgrade/firstboot-wrapper/init.c (static aarch64, NDK clang,
the flags of tools/build-upgrade-ramdisk.py), renames the product first-stage /init to
/init.android with its mode and fields kept, puts the wrapper at /init with the same mode and
leaves every other record as it is. Writes ramdisk.img, the wrapper and a record to the bulk
artifacts/firstboot-5.10-v2/ folder and evidence/kernel-upgrade/firstboot-ramdisk-v2.json.
With --stream the wrapper is built with -DFIRSTBOOT_STREAM (keeps streaming 25 s, only logs
Android's g1 touches) and the files go to artifacts/firstboot-5.10-v5stream/ and
evidence/kernel-upgrade/firstboot-ramdisk-v5stream.json.
The cpio carries no SELinux labels; the policy labels the rootfs as it does for the product.
"""
import pocket_paths
import argparse
import gzip
import hashlib
import json
import os
import runpy
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
PRODUCT_RAMDISK = BULK / 'product-out/target/product/titan_pocket/ramdisk.img'
SOURCE = ROOT / 'kernel-upgrade/firstboot-wrapper/init.c'
OUT = BULK / 'artifacts/firstboot-5.10-v2'
EVIDENCE = ROOT / 'evidence/kernel-upgrade/firstboot-ramdisk-v2.json'
OUT_STREAM = BULK / 'artifacts/firstboot-5.10-v5stream'
EVIDENCE_STREAM = ROOT / 'evidence/kernel-upgrade/firstboot-ramdisk-v5stream.json'
PACKAGER = ROOT / 'tools/package-pocket-boot.py'
CLANG = str(pocket_paths.ndk_bin() / 'clang')
FLAGS = ['--target=aarch64-linux-android30', '-static', '-Os', '-Wall', '-Wextra', '-Werror',
         '-Wl,--build-id=sha1']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_cpio(raw):
    """newc records up to the trailer as [fields(13), name, data]; also the trailer fields and the tail."""
    records, pos = [], 0
    while True:
        if raw[pos:pos + 6] != b'070701':
            raise ValueError('bad cpio record at %d' % pos)
        fields = [int(raw[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        pos += 110
        name = raw[pos:pos + fields[11] - 1].decode()
        pos = (pos + fields[11] + 3) & ~3
        data = raw[pos:pos + fields[6]]
        pos = (pos + fields[6] + 3) & ~3
        if name == 'TRAILER!!!':
            return records, fields, raw[pos:]
        records.append([fields, name, data])


def write_cpio(records, trailer, tail_block):
    out = bytearray()
    for fields, name, data in records + [[trailer, 'TRAILER!!!', b'']]:
        encoded = name.encode() + b'\0'
        f = list(fields)
        f[6], f[11] = len(data), len(encoded)
        out += b'070701' + b''.join(b'%08x' % x for x in f) + encoded
        out += b'\0' * (-len(out) % 4)
        out += data
        out += b'\0' * (-len(out) % 4)
    if tail_block:
        out += b'\0' * (-len(out) % tail_block)
    return bytes(out)


def wrap(product_raw, wrapper):
    """Product cpio with /init renamed to /init.android and the wrapper at /init."""
    records, trailer, tail = read_cpio(product_raw)
    names = [r[1] for r in records]
    if names.count('init') != 1 or 'init.android' in names:
        raise ValueError('product ramdisk must have one /init and no /init.android')
    if any(t for t in tail):
        raise ValueError('product ramdisk has data after the cpio trailer')
    i = names.index('init')
    fields, _, product_init = records[i]
    if fields[1] & 0o170000 != 0o100000:
        raise ValueError('product /init is not a regular file')
    inode = max(r[0][0] for r in records) + 1
    android = [list(fields), 'init.android', product_init]
    android[0][0] = inode
    records[i] = [list(fields), 'init', wrapper]
    records.insert(i + 1, android)
    trailer = list(trailer)
    trailer[0] = inode + 1
    # The product archive is padded to 512 bytes; keep that.
    block = 512 if (len(product_raw) % 512 == 0) else 0
    return write_cpio(records, trailer, block), product_init


def compile_wrapper(output, source=SOURCE, test=False, stream=False):
    source_sha = sha(source.read_bytes())
    command = [CLANG, *FLAGS, '-DWRAPPER_SOURCE_SHA256="%s"' % source_sha,
               *(['-DFIRSTBOOT_HOST_TEST'] if test else []), *(['-DFIRSTBOOT_STREAM'] if stream else []),
               str(source), '-o', str(output)]
    subprocess.run(command, check=True)
    return command, output.read_bytes(), source_sha


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--product-ramdisk', type=Path, default=PRODUCT_RAMDISK)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--stream', action='store_true', help='build the stream variant (v5stream)')
    parser.add_argument('--replace', action='store_true', help='replace an earlier ramdisk.img in the output folder')
    args = parser.parse_args()
    p = runpy.run_path(str(PACKAGER))
    out = args.output_dir or (OUT_STREAM if args.stream else OUT)
    evidence = EVIDENCE_STREAM if args.stream else EVIDENCE
    target = out / 'ramdisk.img'
    if target.exists() and not args.replace:
        sys.exit('refused: %s exists; pass --replace' % target)
    if (out / 'boot.img').exists():
        sys.exit('refused: %s/boot.img exists; it was packaged from the current ramdisk' % out)
    problems = p['check_wrapper_source'](SOURCE.read_text())
    if problems:
        sys.exit('refused: wrapper source: ' + '; '.join(problems))
    product = args.product_ramdisk.read_bytes()
    if product[:2] != b'\x1f\x8b':
        sys.exit('refused: product ramdisk is not gzip')
    d = zlib.decompressobj(wbits=31)
    product_raw = d.decompress(product)
    if not d.eof or d.unused_data:
        sys.exit('refused: product ramdisk is not a single gzip member')
    out.mkdir(parents=True, exist_ok=True)
    wrapper_path = out / 'wrapper-init'
    command, wrapper, source_sha = compile_wrapper(wrapper_path, stream=args.stream)
    raw, product_init = wrap(product_raw, wrapper)
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    assert gzip.decompress(compressed) == raw
    # Independent read-back: same records as the product apart from /init and /init.android.
    new, _, _ = read_cpio(raw)
    old, _, _ = read_cpio(product_raw)
    new_by = [(r[1], r[0][1], r[2]) for r in new]
    old_by = [(r[1], r[0][1], r[2]) for r in old]
    init_mode = [r[0][1] for r in old if r[1] == 'init'][0]
    expected = []
    for name, mode, data in old_by:
        if name == 'init':
            expected += [('init', mode, wrapper), ('init.android', mode, data)]
        else:
            expected.append((name, mode, data))
    assert new_by == expected
    info = p['wrapper_info'](raw, product_raw, SOURCE.read_text())
    target.write_bytes(compressed)
    record = {
        'state': 'Built offline; not flashed or run on the phone',
        'product_ramdisk': {'path': str(args.product_ramdisk), 'bytes': len(product), 'sha256': sha(product),
                            'cpio_sha256': sha(product_raw)},
        'product_first_stage_init': {'sha256': sha(product_init), 'bytes': len(product_init), 'mode': oct(init_mode)},
        'wrapper_source': {'path': str(SOURCE.relative_to(ROOT)), 'sha256': source_sha},
        'wrapper': {'path': str(wrapper_path), 'bytes': len(wrapper), 'sha256': sha(wrapper), 'mode': oct(init_mode),
                    **info},
        'compile_command': command,
        'ramdisk': {'path': str(target), 'bytes': len(compressed), 'sha256': sha(compressed),
                    'cpio_bytes': len(raw), 'cpio_sha256': sha(raw), 'compression': 'gzip -9, mtime 0'},
        'members': [{'name': n, 'mode': oct(m), 'bytes': len(b), 'sha256': sha(b)} for n, m, b in new_by],
        'unchanged_records': len(new_by) - 2,
        'selinux_labels': 'none in cpio, as in the product ramdisk',
        'tool_sha256': sha(Path(__file__).read_bytes()),
        'device_accessed': False,
    }
    text = json.dumps(record, indent=2) + '\n'
    evidence.write_text(text)
    (out / 'ramdisk.img.json').write_text(text)
    print('firstboot %s ramdisk: %s %s (wrapper %s, /init.android %s)'
          % ('v5stream' if args.stream else 'v2', target, sha(compressed), sha(wrapper)[:16], sha(product_init)[:16]))


if __name__ == '__main__':
    main()
