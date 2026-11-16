#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the vendor overlay to the phone's own stock vendor from our recovery, for first installs.

Pushes device/unihertz/titan_pocket/ota/pocket_vendor.sh and the vendor payload
(pocket_vendor_overlay.zip from tools/prepare-pocket-vendor-ota.py, the same files a full OTA
carries) to /tmp on the phone, checks every pushed file's hash on the phone, then runs the
script's check and, when that passes, its apply on the vendor partition. The script checks
every vendor file before its first write; see its header.

Refuses unless --backup is a complete pocket-stock-backup.py run of this phone that passes
the restore tool's checks, and the phone's vendor partition still hashes to the vendor.img in
it, so the stock vendor is on the computer before anything changes. --resume skips only that
last check, to finish an apply that stopped part way; keep the same backup for it.
"""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pocket_phone as pp  # noqa: E402

SCRIPT = pp.ROOT / 'device/unihertz/titan_pocket/ota/pocket_vendor.sh'
DEST = '/tmp/pocket-vendor'
TARGET = '/dev/block/mapper/vendor'


def unpack(payload, into):
    """The payload directory, from a zip or a directory. Returns {relative path: Path}."""
    payload = Path(payload)
    if payload.is_dir():
        root = payload
    else:
        root = Path(into) / 'payload'
        with zipfile.ZipFile(payload) as z:
            for name in z.namelist():
                rel = Path(name)
                if rel.is_absolute() or '..' in rel.parts:
                    raise pp.PhoneError(f'bad path {name} in {payload}')
            z.extractall(root)
    if not (root / 'manifest.txt').is_file():
        raise pp.PhoneError(f'{payload} has no manifest.txt')
    return root, {p.relative_to(root).as_posix(): p for p in sorted(root.rglob('*')) if p.is_file()}


def check_backup(folder, phone, resume=False):
    """The backup must check out in full, be of this phone and hold the vendor now on it."""
    spec = importlib.util.spec_from_file_location('pocket_restore', Path(__file__).resolve().parent / 'pocket-stock-restore.py')
    restore = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(restore)
    rec, images = restore.load_backup(folder, pp.load_config())
    dev = rec.get('device', {})
    got = phone.serial_reported('recovery') or phone.serial
    if got != (dev.get('serialno') or dev.get('adb_serial')):
        raise pp.PhoneError('the backup is from another phone')
    if not resume and phone.phone_sha256(TARGET) != images['vendor']['sha256']:
        raise pp.PhoneError("the phone's vendor is not the one in the backup; back up again before this step")


def run_script(phone, mode, target):
    rc, out = phone.shell('sh', f'{DEST}/pocket_vendor.sh', mode, target, f'{DEST}/payload',
                          check=False, timeout=1800)
    done = {'check': 'pocket_vendor: vendor check passed', 'apply': 'pocket_vendor: vendor overlay applied'}
    # Both the exit code and the script's last line, in case adb drops the exit code.
    return rc == 0 and done[mode] in out.splitlines(), out.strip()


def apply(phone, payload, script=SCRIPT, target=TARGET, check_only=False, log=print):
    phone.require_recovery_root()
    with tempfile.TemporaryDirectory(prefix='pocket-vendor-') as scratch:
        root, files = unpack(payload, scratch)
        phone.shell('rm', '-rf', DEST)
        phone.shell('mkdir', '-p', DEST)
        try:
            phone.push(script, f'{DEST}/pocket_vendor.sh')
            phone.push(root, f'{DEST}/payload')
            sent = {'pocket_vendor.sh': Path(script)}
            sent.update({f'payload/{k}': v for k, v in files.items()})
            for rel, local in sent.items():
                if phone.phone_sha256(f'{DEST}/{rel}') != pp.sha256_file(local):
                    raise pp.PhoneError(f'{rel} arrived damaged on the phone')
            ok, out = run_script(phone, 'check', target)
            log(out)
            if not ok:
                raise pp.PhoneError('vendor check failed, nothing written')
            if check_only:
                return 'checked'
            ok, out = run_script(phone, 'apply', target)
            log(out)
            if not ok:
                raise pp.PhoneError('vendor apply failed; run it again to finish, or restore the stock vendor')
            return 'applied'
        finally:
            phone.shell('rm', '-rf', DEST, check=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--serial', required=True)
    ap.add_argument('--payload', type=Path, required=True, help='pocket_vendor_overlay.zip or its folder')
    ap.add_argument('--backup', type=Path, required=True, help='the stock backup of this phone')
    ap.add_argument('--script', type=Path, default=SCRIPT)
    ap.add_argument('--adb')
    ap.add_argument('--fastboot')
    ap.add_argument('--check-only', action='store_true')
    ap.add_argument('--resume', action='store_true',
                    help="finish an interrupted apply: the phone's vendor may differ from the backup")
    args = ap.parse_args()
    try:
        phone = pp.Phone(args.serial, args.adb, args.fastboot)
        phone.require_recovery_root()
        check_backup(args.backup, phone, args.resume)
        result = apply(phone, args.payload, args.script, check_only=args.check_only)
    except (pp.PhoneError, OSError, ValueError, subprocess.SubprocessError) as e:
        ap.exit(1, f'vendor step stopped: {e}\n')
    print(f'vendor {result}')


if __name__ == '__main__':
    main()
