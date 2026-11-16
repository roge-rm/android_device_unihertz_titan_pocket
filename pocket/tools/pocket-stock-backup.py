#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Save the phone's stock partitions to a folder on this computer, from our recovery.

The phone must be in our recovery with root adb. Nothing on the phone is written apart from
mount points under /tmp. Saves the owner-unique partitions (nvram, nvdata, nvcfg, protect1,
protect2, persist, proinfo), the partitions we replace (boot, dtbo, vbmeta, vbmeta_system and
vbmeta_vendor where they exist, vendor, and system and product when there is room), the
camerapostalgo files from the stock system, a SHA256SUMS list and backup.json with the stock
release, the phone's serial and every partition size.

Each image is streamed to the computer and hashed, then the phone hashes the partition
itself; a different hash or size stops the run. Stock recovery is not saved: our recovery is
already on the recovery partition by then, as LK's fastboot boot is not usable on this phone.
pocket-stock-restore.py takes it from Unihertz's firmware zip instead.

Runs on its own as a backup-only run, and the owner installer runs it before it flashes
anything past our recovery. Works with adb on Linux, Windows and macOS.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pocket_phone as pp  # noqa: E402

MNT = '/tmp/pocket-stock'
# Room left on the computer after every image.
MARGIN = 256 * 1024 * 1024


def write_json(path, data):
    tmp = path.with_suffix('.json.part')
    tmp.write_text(json.dumps(data, indent=2) + '\n')
    os.replace(tmp, path)


def read_props(text):
    props = {}
    for line in text.splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            props[k.strip()] = v.strip()
    return props


class Backup:
    def __init__(self, phone, cfg, out, log=print, stall=120):
        self.phone, self.cfg, self.out, self.log, self.stall = phone, cfg, out, log, stall
        self.record = {'schema': 1, 'tool': 'pocket-stock-backup', 'status': 'in_progress',
                       'started_utc': datetime.now(timezone.utc).isoformat(), 'device': {},
                       'stock': {}, 'images': [], 'skipped': [], 'not_saved': [], 'camerapostalgo': {}}

    def save(self):
        write_json(self.out / 'backup.json', self.record)

    def fail(self, reason):
        self.record['status'] = 'failed'
        self.record['error'] = reason
        self.save()
        raise pp.PhoneError(reason)

    def path_of(self, name):
        base = self.cfg['mapper'] if name in self.cfg['logical_partitions'] else self.cfg['by_name']
        return f'{base}/{name}'

    def plan(self, save_recovery, with_system):
        cfg = self.cfg
        names = [(n, 'owner') for n in cfg['owner_partitions']]
        for n in cfg['bootloader_partitions']:
            if n == 'recovery' and not save_recovery:
                stock = cfg['stock_recovery']
                self.record['not_saved'].append({
                    'name': 'recovery', 'reason': 'holds our recovery when the backup runs',
                    'source': {k: v for k, v in stock.items() if k != 'note'}})
                continue
            names.append((n, 'bootloader'))
        for n in cfg['logical_partitions']:
            if n in cfg['logical_if_room'] and not with_system:
                self.record['skipped'].append({'name': n, 'reason': 'left out by --no-system'})
                continue
            names.append((n, 'logical'))
        plan = []
        for n, kind in names:
            path = self.path_of(n)
            if not self.phone.exists(path):
                if n in cfg['optional_partitions']:
                    self.record['skipped'].append({'name': n, 'reason': 'not on this phone'})
                    continue
                if kind == 'logical':
                    self.fail(f'{path} is missing: recovery has not mapped the dynamic partitions')
                self.fail(f'{path} is missing')
            plan.append({'name': n, 'kind': kind, 'path': path, 'bytes': self.phone.size_of(path)})
        # Everything but system and product must fit; those two go in when there is room.
        free = shutil.disk_usage(self.out).free
        need = sum(p['bytes'] for p in plan if p['name'] not in cfg['logical_if_room']) + MARGIN
        if need > free:
            self.fail(f'not enough room on this computer: {need} bytes needed, {free} free')
        kept = []
        for p in plan:
            if p['name'] in cfg['logical_if_room']:
                if need + p['bytes'] > free:
                    self.record['skipped'].append({'name': p['name'], 'bytes': p['bytes'],
                                                   'reason': 'no room on this computer'})
                    continue
                need += p['bytes']
            kept.append(p)
        return kept

    def read(self, p):
        name = p['name']
        dest = self.out / f'{name}.img'
        if p['kind'] == 'owner' and self.phone.mounted(p['path']):
            self.fail(f'{name} is mounted in recovery; unmount it first')
        self.log(f'reading {name} ({p["bytes"]} bytes)')
        sha, n = self.phone.read_block(p['path'], dest, stall=self.stall)
        if n != p['bytes']:
            self.fail(f'{name}: read {n} bytes, the partition has {p["bytes"]}')
        again = self.phone.phone_sha256(p['path'])
        if again != sha:
            self.fail(f'{name}: the copy hashes to {sha}, the phone reads {again}; nothing is trusted')
        if name == 'recovery':
            stock = {v['sha256'] for k, v in self.cfg['stock_recovery'].items() if isinstance(v, dict)}
            if sha not in stock:
                self.fail('the recovery partition is not a known stock recovery; leave out --save-recovery')
        self.record['images'].append({'name': name, 'kind': p['kind'], 'file': dest.name,
                                      'bytes': n, 'sha256': sha})
        self.save()

    def mount(self, name):
        point = f'{MNT}/{name}'
        self.phone.shell('mkdir', '-p', point)
        rc, out = self.phone.shell('mount', '-t', 'ext4', '-o', 'ro', self.path_of(name), point, check=False)
        if rc:
            raise pp.PhoneError(f'cannot mount {name} read-only: {out.strip()[:200]}')
        return point

    def umount(self, point):
        self.phone.shell('umount', point, check=False)

    def stock_version(self):
        point = self.mount('vendor')
        try:
            props = read_props(self.phone.shell('cat', f'{point}/build.prop')[1])
        finally:
            self.umount(point)
        custom = props.get('ro.vendor.build.custom_version', '')
        release = custom.rsplit('_', 1)[-1] if custom.startswith('Titan_pocket_') else ''
        self.record['stock'] = {
            'custom_version': custom, 'release': release,
            'vendor_incremental': props.get('ro.vendor.build.version.incremental', ''),
            'supported': custom in pp.supported_stock()}
        self.save()

    def camerapostalgo(self):
        files = self.cfg['camerapostalgo']['files']
        rec = {'complete': False, 'files': []}
        self.record['camerapostalgo'] = rec
        try:
            point = self.mount('system')
        except pp.PhoneError as e:
            rec['error'] = str(e)
            self.save()
            self.log(f'camerapostalgo not copied: {e}')
            return
        try:
            for rel, known in files.items():
                dest = self.out / 'camerapostalgo' / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                remote = f'{point}/{rel}'
                if not self.phone.exists(remote):
                    rec['files'].append({'path': rel, 'missing': True})
                    continue
                self.phone.pull(remote, dest)
                sha = pp.sha256_file(dest)
                if self.phone.phone_sha256(remote) != sha:
                    self.fail(f'camerapostalgo {rel}: the copy differs from the phone')
                rec['files'].append({'path': rel, 'bytes': dest.stat().st_size, 'sha256': sha,
                                     'known_stock': sha == known})
            rec['complete'] = all(not f.get('missing') for f in rec['files'])
        finally:
            self.umount(point)
        self.save()

    def run(self, save_recovery=False, with_system=True):
        try:
            return self._run(save_recovery, with_system)
        except Exception as e:
            # Errors from adb or the computer, not only fail(), end up in backup.json.
            if self.record['status'] != 'failed':
                self.record['status'] = 'failed'
                self.record['error'] = str(e) or type(e).__name__
                self.save()
            raise

    def _run(self, save_recovery, with_system):
        ph = self.phone
        ph.require_recovery_root()
        reported = ph.serial_reported('recovery')
        self.record['device'] = {'adb_serial': ph.serial, 'serialno': reported,
                                 'device': ph.getprop('ro.product.device')}
        if reported and reported != ph.serial:
            self.fail(f'adb serial {ph.serial} differs from the phone serial {reported}')
        self.save()
        plan = self.plan(save_recovery, with_system)
        for p in plan:
            self.read(p)
        proinfo = next(i for i in self.record['images'] if i['name'] == 'proinfo')
        self.record['device']['proinfo_sha256'] = proinfo['sha256']
        self.stock_version()
        self.camerapostalgo()
        sums = [(i['sha256'], i['file']) for i in self.record['images']]
        sums += [(f['sha256'], 'camerapostalgo/' + f['path'])
                 for f in self.record['camerapostalgo'].get('files', []) if 'sha256' in f]
        # LF on every platform, as on the phone.
        (self.out / 'SHA256SUMS').write_bytes(''.join(f'{h}  {f}\n' for h, f in sums).encode())
        self.record['status'] = 'complete'
        self.record['finished_utc'] = datetime.now(timezone.utc).isoformat()
        self.save()
        return self.record


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--serial', required=True, help='adb serial of the phone')
    ap.add_argument('--out', type=Path, help='new folder for the backup')
    ap.add_argument('--adb')
    ap.add_argument('--fastboot')
    ap.add_argument('--config', type=Path)
    ap.add_argument('--no-system', action='store_true', help='leave out system and product')
    ap.add_argument('--save-recovery', action='store_true',
                    help='also save the recovery partition, only when it still holds stock recovery')
    ap.add_argument('--stall-timeout', type=float, default=120,
                    help='seconds without data before a read is given up')
    args = ap.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = args.out or Path.cwd() / f'pocket-stock-backup-{args.serial}-{stamp}'
    try:
        out.mkdir(parents=True)
    except FileExistsError:
        ap.exit(1, f'{out} already exists; give a new folder\n')
    try:
        phone = pp.Phone(args.serial, args.adb, args.fastboot)
        record = Backup(phone, pp.load_config(args.config), out,
                        stall=args.stall_timeout).run(args.save_recovery, not args.no_system)
    except (pp.PhoneError, OSError, ValueError, subprocess.SubprocessError) as e:
        ap.exit(1, f'backup failed: {e}\n')
    s = record['stock']
    print(f'backup saved in {out}: {len(record["images"])} images, stock {s["custom_version"] or "unknown"}'
          + ('' if s['supported'] else ' (not a supported stock release)'))
    for sk in record['skipped']:
        print(f'  not saved: {sk["name"]} ({sk["reason"]})')
    if not record['camerapostalgo'].get('complete'):
        print('  camerapostalgo files were not all copied')


if __name__ == '__main__':
    main()
