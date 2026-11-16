#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the system image root has a dir for each first-stage and fstab mount point.

At switch-root, first-stage init moves each mount under / to /system/<path>, and the
read-only system root can't make a missing directory, so a missing one is a fatal reboot.
Second-stage fstab mounts outside the /mnt tmpfs need their directory in the root too.
Never touches a phone. The image is only read.
"""
import pocket_paths
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
FSTAB = pocket_paths.DEVICE_TREE / 'rootdir/etc/fstab.mt6771'
# Second-stage mount_all reads the vendor copy.
VENDOR_FSTAB = pocket_paths.private_vendor_overlay() / 'v3/stock-files/fstab.mt6771'
SYSTEM = BULK / 'product-out/target/product/titan_pocket/system.img'
# Mounted by system/core/init/first_stage_init.cpp before switch-root.
FIRST_STAGE_INIT = ['/dev', '/proc', '/sys', '/mnt', '/debug_ramdisk', '/second_stage_resources']
# Mounted by the firstboot wrapper and unmounted before it runs Android init.
WRAPPER = ['/dev', '/proc', '/sys']


def fstab_mounts(text):
    first, later = [], []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#') or len(fields) < 5 or not fields[1].startswith('/'):
            continue
        if fields[2] == 'emmc':
            continue
        (first if 'first_stage_mount' in fields[4].split(',') else later).append(fields[1])
    return first, later


def root_entries(image):
    # debugfs reads raw ext4 only, so unsparse a sparse image first.
    with open(image, 'rb') as stream:
        sparse = stream.read(4) == b'\x3a\xff\x26\xed'
    with tempfile.TemporaryDirectory(dir=BULK) as work:
        raw = image
        if sparse:
            raw = Path(work) / 'system.raw.img'
            subprocess.run(['simg2img', str(image), str(raw)], check=True)
        out = subprocess.run(['debugfs', '-R', 'ls -p /', str(raw)], check=True,
                             capture_output=True, text=True).stdout
    entries = {}
    for line in out.splitlines():
        # /inode/mode/uid/gid/name/size/
        parts = line.strip().strip('/').split('/')
        if len(parts) >= 5 and parts[4] not in ('.', '..'):
            entries[parts[4]] = int(parts[1], 8)
    return entries


def digest(path):
    sha = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            sha.update(block)
    return sha.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--system', type=Path, default=SYSTEM)
    parser.add_argument('--vendor-fstab', type=Path, default=VENDOR_FSTAB)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    first, later = fstab_mounts(FSTAB.read_text())
    assert '/system' in first and '/metadata' in first, first
    later += sum(fstab_mounts(args.vendor_fstab.read_text()), [])
    # /system is the new root itself; /mnt/* sits on the /mnt tmpfs, where fs_mgr makes the dir.
    needed = sorted({p for p in first + later + FIRST_STAGE_INIT + WRAPPER
                     if p != '/system' and not p.startswith('/mnt/')})
    entries = root_entries(args.system)
    results = []
    for path in needed:
        mode = entries.get(path.lstrip('/'))
        ok = mode is not None and mode & 0o170000 == 0o040000
        results.append({'path': path, 'directory': ok})
        print(('ok      ' if ok else 'MISSING ') + path)
    record = {'system_image': str(args.system),
              'system_sha256': digest(args.system),
              'fstab_sha256': digest(FSTAB), 'vendor_fstab_sha256': digest(args.vendor_fstab),
              'mount_points': results, 'device_accessed': False}
    if args.json:
        args.json.write_text(json.dumps(record, indent=2) + '\n')
    missing = [r['path'] for r in results if not r['directory']]
    if missing:
        raise SystemExit('System root lacks: ' + ' '.join(missing))
    print('System root has every first-stage and fstab mount point')


if __name__ == '__main__':
    main()
