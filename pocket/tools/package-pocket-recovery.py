#!/usr/bin/env python3
"""Package the product's Lineage recovery ramdisk with our 5.10 kernel as a recovery-partition image.

Offline only: never stages, flashes or talks to a device. Same layout as package-pocket-boot.py
(header v2, LK addresses, board dtb in the stock DT table, empty recovery_dtbo, boot cmdline),
with the AVB hash footer for partition `recovery` (32 MiB). The ramdisk is
ramdisk-recovery.img from `run-pocket-product-build.py recoveryimage`, unchanged.
See RECOVERY.md.
"""
import pocket_paths
import argparse
import hashlib
import json
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BOOT = runpy.run_path(str(ROOT / 'tools/package-pocket-boot.py'))
Refused = BOOT['Refused']
PRODUCT_OUT = BULK / 'product-out/target/product/titan_pocket'
RAMDISK = PRODUCT_OUT / 'ramdisk-recovery.img'
KERNEL = BULK / 'kernel-firstboot-5.10/arch/arm64/boot/Image.gz'
KERNEL_SHA = '0229a166c9a50d52347537f298149d4885e7c282c813eddd2897a40d17d9181f'   # triala5 boot kernel
BOARD_SHA = '440fbad077e9121b4be8c74146598cf2d72b40dde4bc316c6de08c66e7b9d11e'    # triala5 board dtb
OUTPUT = BULK / 'artifacts/lineage-recovery-v1/recovery.img'
PARTITION = 'recovery'
DEVICE = pocket_paths.DEVICE_TREE
# Files that must be in the ramdisk byte for byte as in the tree.
SAME_AS_TREE = {'init.recovery.mt6771.rc': DEVICE / 'recovery/init.recovery.mt6771.rc',
                'system/etc/recovery.fstab': DEVICE / 'rootdir/etc/recovery.fstab'}
REQUIRED = ['init', 'system/bin/init', 'system/bin/recovery', 'system/bin/fastbootd', 'system/bin/adbd',
            'system/bin/ueventd', 'prop.default']
# Host adb keys a development build trusts (run-pocket-product-build.py --dev-adb-keys).
# The recovery rc copies them to /adb_keys. Release ramdisks must not have them.
ADB_KEYS = pocket_paths.private_vendor() / 'unihertz/titan_pocket/proprietary/adb_keys'
KEYS_IN_RAMDISK = 'system/etc/security/pocket_adb_keys'
REQUIRED_PROPS = {'ro.boot.dynamic_partitions': 'true', 'ro.debuggable': '1',
                  'ro.build.type': 'userdebug'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def props(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            out[k] = v          # last one wins, as init's property loader
    return out


def check_ramdisk(data, cmdline, dev_adb_keys=False):
    if len(data) > BOOT['RAMDISK_MAX']:
        raise Refused('ramdisk is %d bytes, over the 16 MiB LK reservation' % len(data))
    kind, raw = BOOT['decompress_ramdisk'](data)
    entries = {name: (mode, body) for name, mode, body in BOOT['cpio_entries'](raw)}
    missing = [n for n in REQUIRED if n not in entries]
    if missing:
        raise Refused('recovery ramdisk has no ' + ', '.join(missing))
    for name, path in SAME_AS_TREE.items():
        if name not in entries or entries[name][1] != path.read_bytes():
            raise Refused('ramdisk %s differs from %s' % (name, path))
    if dev_adb_keys:
        if KEYS_IN_RAMDISK not in entries:
            raise Refused('--dev-adb-keys given but the ramdisk has no ' + KEYS_IN_RAMDISK)
        if entries[KEYS_IN_RAMDISK][1] != ADB_KEYS.read_bytes():
            raise Refused('recovery adb keys differ from ' + str(ADB_KEYS))
    elif KEYS_IN_RAMDISK in entries:
        raise Refused('ramdisk has host adb keys; pass --dev-adb-keys for a development recovery')
    hardware = [t.split('=', 1)[1] for t in cmdline.split() if t.startswith('androidboot.hardware=')]
    if hardware[-1:] != ['mt6771']:
        raise Refused('cmdline androidboot.hardware is not mt6771, so init.recovery.mt6771.rc is not imported')
    found = props(entries['prop.default'][1].decode(errors='replace'))
    wrong = {k: found.get(k) for k, v in REQUIRED_PROPS.items() if found.get(k) != v}
    if wrong:
        raise Refused('prop.default has %s' % wrong)
    return {'compression': kind, 'members': len(entries), 'uncompressed_bytes': len(raw),
            'checked_same_as_tree': {n: sha(p.read_bytes()) for n, p in SAME_AS_TREE.items()},
            'adb_keys_sha256': sha(entries[KEYS_IN_RAMDISK][1]) if KEYS_IN_RAMDISK in entries else None,
            'props': {k: found.get(k) for k in sorted(set(REQUIRED_PROPS) | {
                'ro.adb.secure', 'ro.recovery.usb.vid', 'ro.recovery.usb.adb.pid',
                'ro.recovery.usb.fastboot.pid', 'ro.build.fingerprint', 'ro.lineage.version'})}}


def package(kernel_path, ramdisk_path, output, dev_adb_keys=False):
    output = Path(output)
    if output.exists():
        raise Refused('output exists; refusing to overwrite ' + str(output))
    kernel = Path(kernel_path).read_bytes()
    if sha(kernel) != KERNEL_SHA:
        raise Refused('kernel is not the triala5 Image.gz ' + KERNEL_SHA[:8])
    ramdisk = Path(ramdisk_path).read_bytes()
    cmdline = BOOT['CMDLINE']
    arm64 = BOOT['check_arm64'](BOOT['inflate_kernel'](kernel), BOOT['KERNEL_ADDR'])
    rd = check_ramdisk(ramdisk, cmdline, dev_adb_keys)
    board_path, board, dtb, identity = BOOT['board_dtb']()
    if sha(board) != BOARD_SHA:
        raise Refused('board dtb is not the triala5 board ' + BOARD_SHA[:8])
    kernel_addr, dtb_addr, ramdisk_addr, base = BOOT['KERNEL_ADDR'], BOOT['DTB_ADDR'], BOOT['RAMDISK_ADDR'], BOOT['BASE']
    if dtb_addr + len(dtb) > ramdisk_addr:
        raise Refused('DT table runs into the ramdisk address')
    recovery_dtbo = BOOT['RECOVERY_DTBO']
    regions = [('kernel', kernel_addr, BOOT['KERNEL_RESERVE']),
               ('dtb', dtb_addr, max(BOOT['DTB_RESERVE_MIN'], len(dtb))),
               ('ramdisk', ramdisk_addr, BOOT['RAMDISK_MAX'])]
    for i, (a_name, a, a_size) in enumerate(regions):
        for b_name, b, b_size in regions[i + 1:]:
            if not (a + a_size <= b or b + b_size <= a):
                raise Refused('%s and %s regions overlap' % (a_name, b_name))
    for source, fdt in [('live-stock', BOOT['LIVE_FDT'].read_bytes()), ('board', board)]:
        for name, start, size in BOOT['reserved_ranges'](fdt):
            for region, address, count in regions:
                if not (address + count <= start or start + size <= address):
                    raise Refused('%s region overlaps %s %s' % (region, source, name))
    size = BOOT['PARTITION_SIZE']
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tmp = Path(tmp)
        for name, data in [('kernel', kernel), ('ramdisk', ramdisk), ('dtb', dtb), ('recovery_dtbo', recovery_dtbo)]:
            (tmp / name).write_bytes(data)
        work = tmp / 'recovery.img'
        command = [sys.executable, '-B', str(BOOT['MKBOOTIMG']), '--header_version', '2', '--pagesize', str(BOOT['PAGE']),
                   '--base', hex(base), '--kernel_offset', hex(kernel_addr - base),
                   '--ramdisk_offset', hex(ramdisk_addr - base), '--tags_offset', hex(dtb_addr - base),
                   '--dtb_offset', hex(dtb_addr - base), '--os_version', BOOT['OS_VERSION'],
                   '--os_patch_level', BOOT['OS_PATCH_LEVEL'], '--kernel', str(tmp / 'kernel'),
                   '--ramdisk', str(tmp / 'ramdisk'), '--dtb', str(tmp / 'dtb'),
                   '--recovery_dtbo', str(tmp / 'recovery_dtbo'), '--cmdline', cmdline, '--output', str(work)]
        subprocess.run(command, check=True)
        payload = work.read_bytes()
        if len(payload) + 0x10000 > size:
            raise Refused('recovery payload %d bytes does not fit the 32 MiB partition' % len(payload))
        avb = [sys.executable, '-B', str(BOOT['AVBTOOL']), 'add_hash_footer', '--image', str(work),
               '--partition_name', PARTITION, '--partition_size', str(size),
               '--algorithm', 'NONE', '--hash_algorithm', 'sha256', '--salt', sha(payload), '--rollback_index', '0']
        subprocess.run(avb, check=True)
        if work.stat().st_size != size:
            raise Refused('footered image is not the partition size')
        os.replace(work, output)
    image = output.read_bytes()
    return {
        'state': 'Packaged offline; not staged, flashed or boot-tested',
        'output': {'path': str(output), 'bytes': len(image), 'sha256': sha(image)},
        'payload': {'bytes': len(payload), 'sha256': sha(payload), 'free_in_partition': size - len(payload)},
        'header': {'version': 2, 'page_size': BOOT['PAGE'], 'base': base, 'kernel_addr': kernel_addr,
                   'ramdisk_addr': ramdisk_addr, 'tags_addr': dtb_addr, 'dtb_addr': dtb_addr,
                   'os_version': BOOT['OS_VERSION'], 'os_patch_level': BOOT['OS_PATCH_LEVEL'], 'cmdline': cmdline},
        'avb': {'partition_name': PARTITION, 'partition_size': size, 'algorithm': 'NONE',
                'hash_algorithm': 'sha256', 'salt': sha(payload), 'rollback_index': 0},
        'kernel': {'path': str(kernel_path), 'bytes': len(kernel), 'sha256': sha(kernel), 'arm64': arm64},
        'ramdisk': {'path': str(ramdisk_path), 'bytes': len(ramdisk), 'sha256': sha(ramdisk), **rd},
        'dtb': {'board_dtb': board_path, 'board_sha256': sha(board), 'table_bytes': len(dtb),
                'table_sha256': sha(dtb), 'identity': identity},
        'recovery_dtbo_sha256': sha(recovery_dtbo),
        'regions': [{'name': n, 'address': a, 'bytes': s} for n, a, s in regions],
        'commands': [command, avb],
        'tools_sha256': {str(p): sha(p.read_bytes()) for p in [Path(__file__), ROOT / 'tools/package-pocket-boot.py',
                                                                 BOOT['MKBOOTIMG'], BOOT['AVBTOOL']]},
        'device_accessed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--kernel', default=KERNEL)
    parser.add_argument('--ramdisk', default=RAMDISK)
    parser.add_argument('--output', default=OUTPUT)
    parser.add_argument('--dev-adb-keys', action='store_true',
                        help='development recovery: require the staged host adb keys in the ramdisk')
    args = parser.parse_args()
    try:
        record = package(args.kernel, args.ramdisk, args.output, args.dev_adb_keys)
    except Refused as e:
        print('refused: ' + str(e), file=sys.stderr)
        sys.exit(2)
    Path(str(args.output) + '.json').write_text(json.dumps(record, indent=2) + '\n')
    print('recovery image packaged: %s %s %d bytes' % (record['output']['path'], record['output']['sha256'],
                                                       record['output']['bytes']))


if __name__ == '__main__':
    main()
