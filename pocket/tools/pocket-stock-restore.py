#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Put a pocket-stock-backup.py backup back on the phone.

Three phases, in this order, each needing the phone in its mode:
  recovery    our recovery with root adb (Advanced, Enable ADB in its menu): nvram, nvdata, nvcfg, protect1, protect2, persist
              and proinfo with dd, only where the phone's copy differs, each hashed after
  fastbootd   vendor, system and product emptied, then written with fastboot flash
  bootloader  LK: boot, dtbo, vbmeta, vbmeta_system, vbmeta_vendor and recovery last
The tool moves the phone from one phase to the next (adb reboot fastboot, fastboot reboot
bootloader) and leaves it in LK at the end.

Before the first write it checks every image against backup.json and SHA256SUMS (size and
hash), and that the phone is the one the backup came from: its serial, or its proinfo when
no serial is reported. --force-other-phone skips the phone check, never the image checks.
Stock recovery isn't in the backup, so --stock-zip gives Unihertz's firmware zip and the tool
takes recovery.img from it after checking its hash. Data is not formatted.

A full restore needs system and product in the backup: stock vendor, boot and vbmeta under
our system don't boot. --owner-only writes just the owner partitions in recovery and leaves
vendor, system, product and every LK partition as they are, for a backup without system or
a phone that keeps our system. --force-other-phone never writes the owner partitions, as
they hold the other phone's IMEI, MACs and calibration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pocket_phone as pp  # noqa: E402

PHASES = ('recovery', 'fastbootd', 'bootloader')
TMP = '/tmp/pocket-restore'


class Refused(pp.PhoneError):
    pass


def load_backup(folder, cfg):
    """Checks the whole backup. Returns (record, {name: image record with 'path'})."""
    folder = Path(folder)
    try:
        record = json.loads((folder / 'backup.json').read_text())
    except (OSError, ValueError) as e:
        raise Refused(f'no readable backup.json in {folder}: {e}')
    if record.get('schema') != 1 or record.get('status') != 'complete':
        raise Refused('the backup is not a complete pocket-stock-backup run')
    sums = {}
    try:
        lines = (folder / 'SHA256SUMS').read_bytes().decode().split('\n')
    except (OSError, UnicodeDecodeError) as e:
        raise Refused(f'no readable SHA256SUMS in {folder}: {e}')
    for k, line in enumerate(lines, 1):
        if not line:
            continue
        h, sep, f = line.partition('  ')
        if not sep or not pp.HEX64.match(h) or not f or f in sums or '\r' in f:
            raise Refused(f'SHA256SUMS line {k} is not "sha256  file"')
        sums[f] = h
    known = set(cfg['owner_partitions'] + cfg['bootloader_partitions'] + cfg['logical_partitions'])
    images = {}
    for i in record.get('images', []):
        name, file = i.get('name'), i.get('file')
        if name not in known or name in images or file != f'{name}.img':
            raise Refused(f'unexpected image record {name} {file}')
        path = folder / file
        if not path.is_file() or path.is_symlink():
            raise Refused(f'{file} is missing')
        size = path.stat().st_size
        if size != i.get('bytes'):
            raise Refused(f'{file} is {size} bytes, the backup recorded {i.get("bytes")}: truncated or damaged')
        if sums.get(file) != i.get('sha256') or pp.sha256_file(path) != i['sha256']:
            raise Refused(f'{file} does not match its recorded sha256')
        images[name] = dict(i, path=path)
    for name in cfg['owner_partitions'] + ['vendor']:
        if name not in images:
            raise Refused(f'the backup has no {name}')
    return record, images


def recovery_from_zip(zip_path, cfg, release, scratch):
    stock = cfg['stock_recovery'].get(release)
    if not stock:
        raise Refused(f'no known stock recovery for release {release}')
    with zipfile.ZipFile(zip_path) as z:
        try:
            info = z.getinfo(stock['member'])
        except KeyError:
            raise Refused(f'{zip_path} has no {stock["member"]}')
        if info.file_size != stock['bytes']:
            raise Refused('the zip recovery.img has the wrong size')
        dest = Path(scratch) / 'recovery.img'
        h = hashlib.sha256()
        with z.open(info) as src, open(dest, 'wb') as out:
            for block in iter(lambda: src.read(pp.CHUNK), b''):
                h.update(block)
                out.write(block)
    if h.hexdigest() != stock['sha256']:
        raise Refused('the zip recovery.img is not the stock one for this release')
    return {'name': 'recovery', 'file': 'recovery.img', 'bytes': stock['bytes'],
            'sha256': stock['sha256'], 'path': dest}


class Restore:
    def __init__(self, phone, cfg, record, images, force=False, log=print):
        self.phone, self.cfg, self.record, self.images = phone, cfg, record, images
        self.force, self.log = force, log
        self.checked_phone = False

    def check_phone(self, mode):
        dev = self.record.get('device', {})
        want = dev.get('serialno') or dev.get('adb_serial')
        got = self.phone.serial_reported(mode)
        if got:
            same = got == want
            what = f'serial {got}, the backup is from {want}'
        elif mode == 'recovery':
            got = self.phone.phone_sha256(f'{self.cfg["by_name"]}/proinfo')
            same = got == dev.get('proinfo_sha256')
            what = 'proinfo differs from the backup'
        else:
            same, what = False, 'the phone reports no serial'
        if not same:
            if not self.force:
                raise Refused(f'this phone is not the one backed up ({what}); --force-other-phone to go on')
            self.log(f'warning: {what}; going on as forced, owner partitions left alone')
        self.checked_phone = True

    def names(self, phase, only):
        cfg = self.cfg
        names = {'recovery': cfg['owner_partitions'], 'fastbootd': cfg['logical_partitions'],
                 'bootloader': cfg['bootloader_partitions']}[phase]
        if self.force:
            names = [n for n in names if n not in cfg['owner_partitions']]
        return [n for n in names if n in self.images and (not only or n in only)]

    def recovery_phase(self, names):
        ph = self.phone
        ph.require_recovery_root()
        self.check_phone('recovery')
        base = self.cfg['by_name']
        # LK partitions are sized here too, so a wrong image stops the run before any write.
        for n in self.cfg['bootloader_partitions']:
            if n in self.images and self.images[n]['bytes'] > ph.size_of(f'{base}/{n}'):
                raise Refused(f'{n}.img is bigger than the phone\'s {n} partition')
        todo = []
        for n in names:
            if ph.mounted(f'{base}/{n}'):
                raise Refused(f'{n} is mounted in recovery; unmount it first')
            size = ph.size_of(f'{base}/{n}')
            if size != self.images[n]['bytes']:
                raise Refused(f'{n} is {size} bytes on the phone, {self.images[n]["bytes"]} in the backup')
            if ph.phone_sha256(f'{base}/{n}') == self.images[n]['sha256']:
                self.log(f'{n} already matches the backup')
                continue
            todo.append(n)
        if not todo:
            return
        ph.shell('mkdir', '-p', TMP)
        try:
            for n in todo:
                img, dev, tmp = self.images[n], f'{base}/{n}', f'{TMP}/{n}.img'
                ph.push(img['path'], tmp)
                if ph.phone_sha256(tmp) != img['sha256']:
                    raise pp.PhoneError(f'{n}: the copy on the phone is damaged, not written')
                self.log(f'writing {n}')
                ph.shell('dd', f'if={tmp}', f'of={dev}', f'bs={pp.CHUNK}', 'conv=fsync')
                ph.shell('rm', '-f', tmp)
                if ph.phone_sha256(dev) != img['sha256']:
                    raise pp.PhoneError(f'{n} does not read back as the backup after the write')
        finally:
            ph.shell('rm', '-rf', TMP, check=False)

    def fastboot_phase(self, phase, names):
        ph = self.phone
        self.check_phone(phase)
        for n in names:
            img = self.images[n]
            if phase == 'fastbootd':
                if ph.getvar(f'is-logical:{n}') != 'yes':
                    raise Refused(f'{n} is not a logical partition in fastbootd')
            else:
                size = pp.parse_size(ph.getvar(f'partition-size:{n}'))
                if size is None:
                    raise Refused(f'LK reports no size for {n}')
                if img['bytes'] > size:
                    raise Refused(f'{n}.img is {img["bytes"]} bytes, the partition {size}')
        if phase == 'fastbootd':
            # Our system and product may be laid out differently in super. Empty them all first,
            # as the installer does, so each stock image fits when fastboot resizes it.
            for n in names:
                ph.fastboot('resize-logical-partition', n, '0')
        for n in names:
            self.log(f'flashing {n}')
            ph.fastboot('flash', n, str(self.images[n]['path']))

    def run(self, phases, only=None):
        ph = self.phone
        owner = set(self.cfg['owner_partitions'])
        writes = [n for p in phases for n in self.names(p, only)]
        if not writes:
            raise Refused('nothing to restore with these options')
        if set(writes) - owner and not {'system', 'product'} <= set(self.images):
            raise Refused('the backup has no system or product, and stock vendor, boot and vbmeta '
                          'under our system will not boot; use --owner-only to restore just the '
                          'owner partitions')
        mode = ph.mode()
        if mode != phases[0]:
            hint = '; in our recovery, pick Advanced, Enable ADB first' if phases[0] == 'recovery' and not mode else ''
            raise Refused(f'the phone is in {mode or "no known mode"}; this run starts in {phases[0]}{hint}')
        for k, phase in enumerate(phases):
            names = self.names(phase, only)
            if phase == 'recovery':
                self.recovery_phase(names)
            else:
                self.fastboot_phase(phase, names)
            if k + 1 < len(phases):
                nxt = phases[k + 1]
                if phase == 'recovery':
                    ph.adb('reboot', 'fastboot')
                else:
                    ph.fastboot('reboot', 'bootloader' if nxt == 'bootloader' else 'fastboot')
                ph.wait_for(nxt)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('backup', type=Path)
    ap.add_argument('--serial', required=True)
    ap.add_argument('--adb')
    ap.add_argument('--fastboot')
    ap.add_argument('--config', type=Path)
    ap.add_argument('--stock-zip', type=Path, help="Unihertz's firmware zip, for stock recovery")
    ap.add_argument('--no-recovery', action='store_true', help='keep the recovery partition as it is')
    ap.add_argument('--phases', nargs='+', choices=PHASES, default=list(PHASES))
    ap.add_argument('--only', nargs='+', metavar='NAME')
    ap.add_argument('--owner-only', action='store_true',
                    help='write only nvram, nvdata, nvcfg, protect1, protect2, persist and proinfo, in recovery; '
                         'vendor, system, product and the LK partitions stay as they are')
    ap.add_argument('--force-other-phone', action='store_true',
                    help='go on with a backup from another phone; its owner partitions are never written')
    ap.add_argument('--check-only', action='store_true', help='check the backup, touch no phone')
    args = ap.parse_args()
    if [p for p in PHASES if p in args.phases] != args.phases:
        ap.error('phases run in the order recovery, fastbootd, bootloader')
    try:
        cfg = pp.load_config(args.config)
        every = cfg['owner_partitions'] + cfg['logical_partitions'] + cfg['bootloader_partitions']
        unknown = sorted(set(args.only or []) - set(every))
        if unknown:
            ap.error(f'unknown partitions for --only: {", ".join(unknown)}')
        if args.owner_only:
            if args.force_other_phone:
                ap.error('--owner-only and --force-other-phone together write nothing')
            args.phases = ['recovery']
            args.only = [n for n in cfg['owner_partitions'] if not args.only or n in args.only]
        record, images = load_backup(args.backup, cfg)
        with tempfile.TemporaryDirectory(prefix='pocket-restore-') as scratch:
            wants_recovery = 'bootloader' in args.phases and not args.no_recovery and \
                (not args.only or 'recovery' in args.only)
            if wants_recovery and 'recovery' not in images:
                if not args.stock_zip:
                    raise Refused('stock recovery is not in the backup: give --stock-zip or --no-recovery')
                images['recovery'] = recovery_from_zip(args.stock_zip, cfg, record['stock'].get('release'), scratch)
            if args.no_recovery:
                images.pop('recovery', None)
            if args.check_only:
                print(f'backup checks out: {", ".join(sorted(images))}')
                return
            phone = pp.Phone(args.serial, args.adb, args.fastboot)
            Restore(phone, cfg, record, images, args.force_other_phone).run(args.phases, args.only)
    except (pp.PhoneError, OSError, zipfile.BadZipFile, subprocess.SubprocessError) as e:
        ap.exit(1, f'restore stopped: {e}\n')
    print(f'restore done; the phone is in {args.phases[-1]}. Data was not formatted: '
          "stock can't read our encrypted data, so format it before booting stock.")


if __name__ == '__main__':
    main()
