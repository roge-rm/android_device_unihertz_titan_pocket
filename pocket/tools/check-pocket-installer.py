#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline dry runs of the owner installer with a fake phone.

Makes a small fake signed release, builds an installer zip from it with
make-pocket-installer.py (synthetic release gates, all closed), unzips it and runs
tools/pocket-install.py from it against the fake adb and fastboot of
check-pocket-stock-backup.py, with LK and fastbootd answers added here. Cases:
  - happy path: writes in plan order (recovery in LK, vendor in recovery, system and product
    in fastbootd, data formatted, boot and vbmeta in LK), a complete backup and a log
  - a locked bootloader and the wrong product stop with nothing written
  - January stock stops after the recovery flash and puts stock recovery back
  - a failure mid-backup leaves only our recovery and prints the put-back command
  - a failure in fastbootd prints the restore command, which then puts the backup back
  - a no at the system step leaves the phone in fastbootd; the printed restore works from there
  - skipping the format stops in recovery with boot and vbmeta stock; --finish then checks
    system and product in fastbootd and writes them
  - --finish refuses with no state or a state from a Step 5 stop
  - the installer refuses a package file that differs from its manifest
  - the zip has no private build paths in its text files, and one that does is refused
Recovery adb answers only after a few polls, as if the owner picked Enable ADB.

--zip ZIP checks a real installer zip instead: every file against manifest.json, no private
paths in any text file, and no run of 64 or more bytes in the vendor payload's literal edit
pieces (.lit) that is also in the stock May 2024 vendor (--stock-vendor, the private copy).
No real phone, adb server or root is used.
"""
import pocket_paths
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
SERIAL = 'TESTPOCKET0001'
LK_PRODUCT = 'g66v71c2k_dfl_tee'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ckb = load('ckb', TOOLS / 'check-pocket-stock-backup.py')
mk = load('mk', TOOLS / 'make-pocket-installer.py')
STOCK_VENDOR_MAY = pocket_paths.private_vendor() / 'unihertz/titan_pocket/proprietary-2024-05/vendor.img'
DEBUGFS = Path(os.environ['POCKET_DEBUGFS']) if os.environ.get('POCKET_DEBUGFS') else pocket_paths.platform_root() / 'out/host/linux-x86/bin/debugfs'
RUN = 64
# Literal runs the scan lets through: (piece, offset, length, sha256 of the run) -> reason.
# Any other run of RUN bytes or more that is also in stock vendor fails the check.
ALLOWED_RUNS = {
    ('vendor/payload/patch/etc/selinux/vendor_sepolicy.cil/'
     '8ab247dd60da8544f7e92be8fb013bd8fd31c1e4d4b2e9714310446de9ddf298.lit', 6913, 70,
     '6b80650f4f5e5fec0ca6c047ec72af0bdb29e40d4f243aaf683c6bb37ecf44f2'):
        'our hal_power_client rules, same text as AOSP plat_pub_versioned.cil',
}


def fake_main(tool, argv):
    """LK and fastbootd answers the backup test's fake doesn't give, then its fake."""
    state_path = Path(os.environ['FAKE_PHONE'])
    st = json.loads(state_path.read_text())
    root = Path(st['root'])
    # Recovery adb before the owner picks Enable ADB: listed as unauthorized, no commands.
    if tool == 'adb' and st['mode'] == 'recovery' and st.get('adb_locked'):
        st['adb_locked'] -= 1
        state_path.write_text(json.dumps(st))
        if argv[:1] == ['devices']:
            sys.stdout.write(f'List of devices attached\n{st["serial"]}\tunauthorized\n')
            return 0
        sys.stderr.write('error: device unauthorized.\n')
        return 1
    if tool != 'fastboot' or argv[:2] != ['-s', st['serial']] or st['mode'] not in ('bootloader', 'fastbootd'):
        return ckb.fake_main(tool, argv)
    args, mode = argv[2:], st['mode']

    def log():
        with open(st['calls'], 'a') as f:
            f.write(json.dumps([tool, mode, *args]) + '\n')

    def save():
        state_path.write_text(json.dumps(st))

    if args[:1] == ['getvar'] and args[1] in ('unlocked', 'product'):
        log()
        if args[1] == 'unlocked':
            value = st['unlocked'] if mode == 'bootloader' else 'yes'
        else:
            value = st['lk_product'] if mode == 'bootloader' else 'titan_pocket'
        sys.stderr.write(f'{args[1]}: {value}\nFinished.\n')
        return 0
    if args[:1] == ['getvar'] and mode == 'fastbootd' and args[1].startswith('partition-size:') and \
            args[1].split(':')[1] in st['logical']:
        log()
        sys.stderr.write(f'{args[1]}: {hex((root / "dev/block/mapper" / args[1].split(":")[1]).stat().st_size)}\nFinished.\n')
        return 0
    if args[:1] == ['reboot']:
        log()
        st['mode'] = {'recovery': 'recovery', 'bootloader': 'bootloader', 'fastboot': 'fastbootd'}.get(
            args[1] if len(args) > 1 else '', 'system')
        if st['mode'] == 'recovery':
            st['adb_locked'] = st.get('enable_adb_after', 0)
        save()
        return 0
    if args[:1] == ['resize-logical-partition'] and mode == 'fastbootd':
        log()
        with open(root / 'dev/block/mapper' / args[1], 'r+b') as f:
            f.truncate(int(args[2]))
        return 0
    if args[:1] == ['format:ext4'] and mode == 'fastbootd':
        log()
        (root / 'dev/block/by-name' / args[1]).write_bytes(b'empty ext4 ' + args[1].encode())
        return 0
    if args[:1] == ['flash'] and st.get('fail_flash') == [mode, args[1]]:
        log()
        dev = root / 'dev/block/mapper' / args[1]
        dev.write_bytes(dev.read_bytes()[:100])
        sys.stderr.write('FAILED (remote: write error)\n')
        return 1
    return ckb.fake_main(tool, argv)


class Fail(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def avb(flags):
    return b'AVB0' + bytes(116) + struct.pack('>I', flags) + bytes(4096 - 124)


VENDOR_SH = b'''#!/bin/sh
# Stand-in for pocket_vendor.sh: check passes, apply marks the vendor.
case "$1" in
check) [ -f "$3/manifest.txt" ] || exit 1; echo "pocket_vendor: vendor check passed" ;;
apply) printf ours >> "$2"; echo "pocket_vendor: vendor overlay applied" ;;
*) exit 2 ;;
esac
'''


def fake_release(work):
    rel = work / 'release'
    rel.mkdir(parents=True)
    imgs = {'boot': hashlib.shake_256(b'our boot').digest(30 * 1024),
            'recovery': hashlib.shake_256(b'our recovery').digest(30 * 1024),
            'vbmeta': avb(3),
            'system': hashlib.shake_256(b'our system').digest(80 * 1024),
            'product': hashlib.shake_256(b'our product').digest(20 * 1024)}
    for n in ('boot', 'recovery', 'vbmeta'):
        (rel / f'{n}.img').write_bytes(imgs[n])
    (rel / 'check-signing.json').write_text(json.dumps({'vbmeta_flags': 3, 'recovery_avb': 'our key, SHA256_RSA2048',
                                                        'avb_key_sha1': '0' * 40}))
    with zipfile.ZipFile(rel / 'fake-signed-target_files.zip', 'w') as z:
        z.writestr('IMAGES/system.img', imgs['system'])
        z.writestr('IMAGES/product.img', imgs['product'])
    manifest = {'schema': 2, 'version': 'test',
                'base': {'path': pocket_paths.PRIVATE_MARKERS[0] + 'x/' + pocket_paths.PRIVATE_MARKERS[2] + '/vendor.img', 'sha256': '0' * 64, 'bytes': 1},
                'overlay': {'path': pocket_paths.PRIVATE_MARKERS[1] + 'x/' + pocket_paths.PRIVATE_MARKERS[2] + '-overlay/vendor.img', 'sha256': '1' * 64, 'bytes': 1},
                'entries': [
        {'kind': 'replace', 'path': '/lib/x.so', 'target_sha256': sha(b'ours'), 'stock_sha256': sha(b'stock x'),
         'accept': [{'sha256': sha(b'stock x'), 'from': ['May']}]}]}
    with zipfile.ZipFile(rel / 'fake-signed-ota.zip', 'w') as z:
        z.writestr('META-INF/com/android/metadata', 'post-build-incremental=1\npost-timestamp=1794717349\n'
                   'post-security-patch-level=2026-10-01\npre-device=titan_pocket\n')
        z.writestr('boot.img', imgs['boot'])
        z.writestr('recovery.img', imgs['recovery'])
        z.writestr('pocket/pocket_vendor.sh', VENDOR_SH)
        z.writestr('pocket/payload/manifest.txt', 'vendor_version_min 20240514\n')
        z.writestr('pocket/payload/manifest.json', json.dumps(manifest))
        z.writestr('pocket/payload/files/lib/x.so', b'ours')
    return rel, imgs


def build(work, rel, gates, name='titan-pocket-installer-test'):
    out = work / f'{name}.zip'
    p = subprocess.run([sys.executable, str(TOOLS / 'make-pocket-installer.py'), rel, out, '--gates', gates,
                        '--work', work / 'stage'], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip(), out


class Case:
    """An unzipped installer and a fake phone with the stock layout."""

    def __init__(self, work, zip_path, cfg, stock_recovery):
        self.work = work
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(work / 'pkg')
        self.pkg = next((work / 'pkg').iterdir())
        for f in ('install.sh', 'install.command', 'tools/pocket-install.py'):
            (self.pkg / f).chmod(0o755)
        # The fake firmware zip's recovery stands in for Unihertz's, so its hash goes in the
        # unzipped package's config and manifest.
        conf = json.loads((self.pkg / 'configs/stock-backup.json').read_text())
        conf['stock_recovery']['20240514'].update(sha256=sha(stock_recovery), bytes=len(stock_recovery))
        (self.pkg / 'configs/stock-backup.json').write_text(json.dumps(conf, indent=2))
        man = json.loads((self.pkg / 'manifest.json').read_text())
        man['files']['configs/stock-backup.json'] = ckb.sha((self.pkg / 'configs/stock-backup.json').read_bytes())
        (self.pkg / 'manifest.json').write_text(json.dumps(man, indent=2))
        self.zip = work / 'stock.zip'
        with zipfile.ZipFile(self.zip, 'w') as z:
            z.writestr(conf['stock_recovery']['20240514']['member'], stock_recovery)
        self.ph = ckb.make_phone(work / 'phone', cfg)
        for tool in ('adb', 'fastboot'):
            w = self.ph.bin / tool
            w.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} '
                         f'--fake {tool} "$@"\n')
        for n, kib in (('userdata', 16), ('md_udc', 4)):
            self.ph.dev(n).write_bytes(hashlib.shake_256(n.encode()).digest(kib * 1024))
        self.ph.state.update(mode='bootloader', unlocked='yes', lk_product=LK_PRODUCT, enable_adb_after=3)
        self.stock = {n: self.ph.dev(n).read_bytes() for n in
                      ('boot', 'recovery', 'vbmeta', 'dtbo', 'vendor', 'system', 'product', 'nvdata', 'userdata', 'md_udc')}
        self.backups = work / 'backups'

    def run(self, answers, *extra):
        self.ph.save()
        cmd = [sys.executable, str(self.pkg / 'tools/pocket-install.py'), '--adb', str(self.ph.bin / 'adb'),
               '--fastboot', str(self.ph.bin / 'fastboot'), '--backup-dir', str(self.backups), '--wait', '20', *extra]
        p = subprocess.run(cmd, input=answers, env=self.ph.env(), capture_output=True, text=True, cwd=self.pkg)
        self.ph.load()
        return p.returncode, p.stdout + p.stderr

    def writes(self):
        out = []
        for c in self.ph.calls_list():
            words = c[2:]
            if c[0] == 'fastboot' and words[0].split(':')[0] in ('flash', 'format', 'resize-logical-partition', 'erase'):
                out.append((c[1], words[0], words[1]))
            if c[0] == 'adb' and words[:1] == ['shell'] and shlex.split(words[1])[0] in ('dd', 'sh'):
                w = shlex.split(words[1])
                if w[0] == 'dd' or w[2] == 'apply':
                    out.append((c[1], w[0], w[2] if w[0] == 'sh' else w[2][3:]))
        return out

    def backup_folder(self):
        found = [p for p in self.backups.iterdir() if p.is_dir()] if self.backups.exists() else []
        return found[0] if len(found) == 1 else None


HAPPY = 'y\ny\ny\nformat\ny\n'


def case_happy(work, zip_path, cfg, imgs, stock_recovery, results):
    c = Case(work / 'happy', zip_path, cfg, stock_recovery)
    rc, out = c.run(HAPPY)
    check(rc == 0 and 'Done.' in out, f'happy path failed ({rc}):\n{out[-3000:]}')
    check('pick Advanced, then Enable ADB' in out and 'Waiting for Advanced, Enable ADB' in out,
          'no Enable ADB prompt while recovery adb was unauthorized')
    seq = c.writes()
    want = [('bootloader', 'flash', 'recovery'), ('recovery', 'sh', 'apply'),
            ('fastbootd', 'resize-logical-partition', 'system'), ('fastbootd', 'resize-logical-partition', 'product'),
            ('fastbootd', 'flash', 'system'), ('fastbootd', 'flash', 'product'),
            ('fastbootd', 'format:ext4', 'userdata'), ('fastbootd', 'format:ext4', 'md_udc'),
            ('bootloader', 'flash', 'boot'), ('bootloader', 'flash', 'vbmeta')]
    check(seq == want, f'write order {seq}')
    ph = c.ph
    check(ph.state['mode'] == 'system', f'ends in {ph.state["mode"]}')
    for n in ('recovery', 'boot', 'vbmeta'):
        check(ph.dev(n).read_bytes()[:len(imgs[n])] == imgs[n], f'{n} not written')
    for n in ('system', 'product'):
        check(ph.dev(n).read_bytes() == imgs[n], f'{n} not written')
    check(ph.dev('vendor').read_bytes() == c.stock['vendor'] + b'ours', 'vendor not applied once')
    check(ph.dev('userdata').read_bytes().startswith(b'empty ext4') and ph.dev('md_udc').read_bytes().startswith(b'empty ext4'),
          'data not formatted')
    for n in ('nvdata', 'dtbo'):
        check(ph.dev(n).read_bytes() == c.stock[n], f'{n} changed')
    folder = c.backup_folder()
    rec = json.loads((folder / 'backup.json').read_text())
    check(rec['status'] == 'complete' and rec['stock']['supported'], 'backup not complete')
    saved = {i['name'] for i in rec['images']}
    check({'nvram', 'nvdata', 'nvcfg', 'protect1', 'protect2', 'persist', 'proinfo', 'boot', 'vbmeta', 'dtbo',
           'vendor', 'system', 'product'} <= saved, f'backup has {sorted(saved)}')
    check((folder / 'boot.img').read_bytes() == c.stock['boot'] and (folder / 'vendor.img').read_bytes() == c.stock['vendor'],
          'backup is not the stock partitions')
    log = c.backups / f'{folder.name}.log'
    check(log.is_file() and 'flash recovery' in log.read_text() and 'format:ext4 userdata' in log.read_text(),
          'no log next to the backup')
    # The first write comes after the backup... except recovery: the backup reads come before the vendor write.
    calls = ph.calls_list()
    first_read = next(k for k, x in enumerate(calls) if x[0] == 'adb' and x[2] == 'exec-out')
    last_read = max(k for k, x in enumerate(calls) if x[0] == 'adb' and x[2] == 'exec-out')
    first_vendor = next(k for k, x in enumerate(calls) if x[0] == 'adb' and x[2] == 'shell' and x[3].startswith('sh '))
    check(first_read < last_read < first_vendor, 'vendor touched before the backup finished')
    results['happy'] = {'writes': [' '.join(w) for w in seq], 'backup_images': len(rec['images']), 'log': log.name}
    return c


def case_stop_in_lk(work, zip_path, cfg, stock_recovery, results, name, change, expect):
    c = Case(work / name, zip_path, cfg, stock_recovery)
    c.ph.state.update(change)
    rc, out = c.run(HAPPY)
    check(rc == 2 and expect in out and 'Nothing was written' in out, f'{name} not stopped ({rc}):\n{out[-2000:]}')
    check(not c.writes() and not c.ph.writes(), f'{name}: writes {c.writes()}')
    check(c.ph.state['mode'] == 'bootloader', f'{name}: phone left LK')
    results[name] = 'stopped in LK, nothing written'


def case_january(work, zip_path, cfg, stock_recovery, results):
    c = Case(work / 'january', zip_path, cfg, stock_recovery)
    vendor = Path(c.ph.state['mounts']['/dev/block/mapper/vendor'])
    (vendor / 'build.prop').write_text('ro.vendor.build.custom_version=Titan_pocket_20230105\n')
    rc, out = c.run('y\ny\n', '--stock-zip', str(c.zip))
    check(rc == 2 and 'older than May 2024' in out and 'Stock recovery is back' in out, f'January not stopped ({rc}):\n{out[-2000:]}')
    seq = c.writes()
    check(seq == [('bootloader', 'flash', 'recovery'), ('bootloader', 'flash', 'recovery')], f'January writes {seq}')
    check(c.ph.dev('recovery').read_bytes() == stock_recovery, 'stock recovery not put back')
    for n in ('boot', 'vbmeta', 'vendor', 'system', 'product', 'userdata'):
        check(c.ph.dev(n).read_bytes() == c.stock[n], f'January: {n} changed')
    check(c.ph.state['mode'] == 'system' and c.backup_folder() is None, 'January: backup made or not restarted')
    # Without the zip: stops, says how.
    c2 = Case(work / 'january-nozip', zip_path, cfg, stock_recovery)
    (Path(c2.ph.state['mounts']['/dev/block/mapper/vendor']) / 'build.prop').write_text(
        'ro.vendor.build.custom_version=Titan_pocket_20230105\n')
    rc, out = c2.run('y\n\n')
    check(rc == 2 and '--put-back-recovery' in out and 'Only the recovery partition' in out and
          'There is no stock backup yet' in out, f'no zip hint:\n{out[-2000:]}')
    # The printed command puts stock recovery back.
    c2.ph.state['mode'] = 'bootloader'
    rc, out = run_hint(c2, out, '--put-back-recovery', 'y\ny\n', {'PATH/TO/2024051420_g66v71c2k_dfl_tee.zip': str(c2.zip)})
    check(rc == 0 and c2.ph.dev('recovery').read_bytes() == stock_recovery, f'put-back command failed:\n{out[-1500:]}')
    results['january'] = {'with_zip': 'stopped, stock recovery flashed back, nothing else written',
                          'without_zip': 'stopped, printed --put-back-recovery command, which works'}


def run_hint(c, out, marker, answers, swap=None):
    line = next(x.strip() for x in out.splitlines() if marker in x and ('python3' in x or 'py -3' in x))
    words = shlex.split(line)
    words = [(swap or {}).get(w, w) for w in words]
    check(words[0] == 'python3', f'hint starts {words[0]}')
    c.ph.save()
    p = subprocess.run([sys.executable, *words[1:]], input=answers, env=c.ph.env(), capture_output=True,
                       text=True, cwd=c.pkg)
    c.ph.load()
    return p.returncode, p.stdout + p.stderr


def case_mid_backup(work, zip_path, cfg, stock_recovery, results):
    c = Case(work / 'midbackup', zip_path, cfg, stock_recovery)
    c.ph.state['corrupt_reads'] = ['nvdata']
    rc, out = c.run(HAPPY)
    check(rc == 1 and 'nvdata' in out and 'Only the recovery partition was changed' in out and
          '--put-back-recovery' in out and "not complete, don't use it" in out, f'mid-backup failure ({rc}):\n{out[-2000:]}')
    check(c.writes() == [('bootloader', 'flash', 'recovery')], f'writes {c.writes()}')
    rec = json.loads((c.backup_folder() / 'backup.json').read_text())
    check(rec['status'] == 'failed', 'backup not marked failed')
    results['mid_backup_failure'] = 'stopped, only recovery written, put-back command printed'


def case_fastbootd_failure(work, zip_path, cfg, stock_recovery, results):
    c = Case(work / 'fbdfail', zip_path, cfg, stock_recovery)
    c.ph.state['fail_flash'] = ['fastbootd', 'product']
    rc, out = c.run(HAPPY, '--stock-zip', str(c.zip))
    check(rc == 1 and 'pocket-stock-restore.py' in out and '--phases fastbootd bootloader' in out,
          f'fastbootd failure ({rc}):\n{out[-2000:]}')
    check(c.ph.state['mode'] == 'fastbootd', 'not left in fastbootd')
    c.ph.state['fail_flash'] = None
    rc, out = run_hint(c, out, 'pocket-stock-restore.py', '')
    check(rc == 0, f'the printed restore failed:\n{out[-2000:]}')
    for n in ('boot', 'vbmeta', 'dtbo', 'vendor', 'system', 'product'):
        check(c.ph.dev(n).read_bytes() == c.stock[n], f'restore left {n} different')
    check(c.ph.dev('recovery').read_bytes() == stock_recovery, 'restore did not put stock recovery back')
    results['fastbootd_failure'] = 'restore command printed; running it put every stock partition back'


def case_no_at_system(work, zip_path, cfg, stock_recovery, results):
    c = Case(work / 'nosystem', zip_path, cfg, stock_recovery)
    rc, out = c.run('y\ny\nn\n', '--stock-zip', str(c.zip))
    check(rc == 2 and 'The phone is in fastbootd' in out and '--phases fastbootd bootloader' in out,
          f'no at the system step ({rc}):\n{out[-2000:]}')
    check(c.ph.state['mode'] == 'fastbootd', 'not left in fastbootd')
    check(c.writes() == [('bootloader', 'flash', 'recovery'), ('recovery', 'sh', 'apply')], f'writes {c.writes()}')
    rc, out = run_hint(c, out, 'pocket-stock-restore.py', '')
    check(rc == 0, f'the printed restore failed:\n{out[-2000:]}')
    for n in ('boot', 'vbmeta', 'dtbo', 'vendor', 'system', 'product'):
        check(c.ph.dev(n).read_bytes() == c.stock[n], f'restore left {n} different')
    check(c.ph.dev('recovery').read_bytes() == stock_recovery, 'restore did not put stock recovery back')
    results['no_at_system_step'] = 'left in fastbootd with vendor ours; the printed restore ran from there and put stock back'


def case_no_format(work, zip_path, cfg, imgs, stock_recovery, results):
    c = Case(work / 'noformat', zip_path, cfg, stock_recovery)
    rc, out = c.run('y\ny\ny\nskip\n')
    check(rc == 2 and 'boot and vbmeta were not written' in out and '--finish' in out and
          'Enter fastboot' in out, f'format skipped ({rc}):\n{out[-2000:]}')
    check(c.ph.state['mode'] == 'recovery', f'format skipped: phone in {c.ph.state["mode"]}')
    for n in ('boot', 'vbmeta', 'userdata', 'md_udc'):
        check(c.ph.dev(n).read_bytes() == c.stock[n], f'format skipped: {n} changed')
    hint = out
    check(f'--backup-dir {c.backup_folder()}' in out, 'the --finish command does not name the backup folder')
    state = json.loads((c.backup_folder() / 'install-state.json').read_text())
    check(state['status'] == 'format skipped' and set(state['flashed']) == {'system', 'product'}, f'state {state}')
    # The owner formats data in recovery and goes to LK; the printed --finish writes the rest.
    c.ph.state['mode'] = 'bootloader'
    rc, out = run_hint(c, hint, '--finish', 'y\ny\ny\n')
    check(rc == 0 and 'Done.' in out, f'--finish failed ({rc}):\n{out[-2000:]}')
    seq = [w for w in c.writes() if w[2] in ('boot', 'vbmeta')]
    check(seq == [('bootloader', 'flash', 'boot'), ('bootloader', 'flash', 'vbmeta')], f'--finish writes {seq}')
    calls = c.ph.calls_list()
    check(any(x[1] == 'fastbootd' and x[2:4] == ['getvar', 'partition-size:system'] for x in calls),
          '--finish did not check system in fastbootd')
    for n in ('boot', 'vbmeta'):
        check(c.ph.dev(n).read_bytes()[:len(imgs[n])] == imgs[n], f'--finish: {n} not written')
    check(c.ph.state['mode'] == 'system', '--finish did not restart')
    results['format_skipped'] = ('stopped in recovery, boot and vbmeta stock; the printed --finish checked system '
                                 'and product in fastbootd and wrote them')


def case_finish_refused(work, zip_path, cfg, stock_recovery, results):
    # No state: a folder that never saw an install, on a stock phone.
    c = Case(work / 'finish-nostate', zip_path, cfg, stock_recovery)
    empty = work / 'finish-nostate' / 'empty-folder'
    empty.mkdir()
    rc, out = c.run('y\ny\ny\n', '--finish', '--backup-dir', str(empty), '--serial', SERIAL)
    check(rc == 2 and 'no install-state.json' in out and not c.writes(), f'--finish without state ({rc}):\n{out[-1500:]}')
    # A Step 5 stop: vendor ours, stock system still there.
    c2 = Case(work / 'finish-step5', zip_path, cfg, stock_recovery)
    rc, out = c2.run('y\ny\nn\n')
    check(rc == 2, f'step 5 stop ({rc})')
    folder = c2.backup_folder()
    c2.ph.state['mode'] = 'bootloader'
    before = c2.writes()
    rc, out = c2.run('y\ny\ny\n', '--finish', '--backup-dir', str(folder), '--serial', SERIAL)
    check(rc == 2 and 'stopped at "vendor done"' in out and c2.writes() == before,
          f'--finish after a step 5 stop ({rc}):\n{out[-1500:]}')
    for n in ('boot', 'vbmeta'):
        check(c2.ph.dev(n).read_bytes() == c2.stock[n], f'--finish after step 5 wrote {n}')
    results['finish_refused'] = 'no state and a step 5 stop refused with nothing written'


def case_damaged(work, zip_path, cfg, stock_recovery, results):
    c = Case(work / 'damaged', zip_path, cfg, stock_recovery)
    img = c.pkg / 'images/system.img'
    data = bytearray(img.read_bytes())
    data[10] ^= 1
    img.write_bytes(bytes(data))
    rc, out = c.run(HAPPY)
    check(rc == 2 and 'system.img is missing or damaged' in out and not c.ph.calls_list(), f'damaged image run:\n{out[-1500:]}')
    results['damaged_package'] = 'refused before the phone was touched'


def case_build_refusals(work, rel, gates, cfg, results):
    # A Unihertz file in the payload is refused.
    bad = work / 'bad-release'
    shutil.copytree(rel, bad)
    ota = bad / 'fake-signed-ota.zip'
    # A file with the hash of the stock vendor file the payload manifest names.
    with zipfile.ZipFile(ota, 'a') as z:
        z.writestr('pocket/payload/files/lib/stock.so', b'stock x')
    rc, out, _ = build(work / 'bad', bad, gates, 'bad')
    check(rc != 0 and 'Unihertz files' in out and 'stock vendor /lib/x.so' in out, f'Unihertz file not refused: {out}')
    # A payload text file naming a private build path is refused.
    leak = work / 'leak-release'
    shutil.copytree(rel, leak)
    with zipfile.ZipFile(leak / 'fake-signed-ota.zip', 'a') as z:
        z.writestr('pocket/payload/notes.txt', 'made from ' + pocket_paths.PRIVATE_MARKERS[1] + 'x/vendor.img\n')
    rc, out, _ = build(work / 'leak', leak, gates, 'leak')
    check(rc != 0 and 'private paths' in out and 'notes.txt' in out, f'private path not refused: {out}')
    # A release whose OTA boot differs.
    mixed = work / 'mixed-release'
    shutil.copytree(rel, mixed)
    (mixed / 'boot.img').write_bytes(b'other boot')
    rc, out, _ = build(work / 'mixed', mixed, gates, 'mixed')
    check(rc != 0 and 'not the same release' in out, f'mixed release not refused: {out}')
    results['build_refusals'] = 'Unihertz file refused, private path refused, mixed release refused'


def zip_members(zip_path):
    """{path inside the top folder: bytes} for every file, and the top folder name."""
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if not n.endswith('/')]
        tops = {n.split('/', 1)[0] for n in names}
        check(len(tops) == 1, f'the zip has more than one top folder: {sorted(tops)}')
        top = tops.pop()
        return top, {n.split('/', 1)[1]: z.read(n) for n in names}


def text_checks(files, results):
    """No private build path in any text file, and none in the payload manifest."""
    hits = [(rel, m.decode()) for rel, data in sorted(files.items())
            if not rel.endswith('.img') and mk.is_text(data) for m in mk.PRIVATE_MARKERS if m in data]
    check(not hits, 'private paths in the zip: ' + ', '.join(f'{f} ({m})' for f, m in hits))
    payload = json.loads(files['vendor/payload/manifest.json'])
    for key in ('base', 'overlay'):
        check('path' not in payload.get(key, {}), f'vendor/payload/manifest.json still has {key}.path')
    results['text_files_scanned'] = sum(1 for rel, d in files.items() if not rel.endswith('.img') and mk.is_text(d))


def literal_runs(lits, stock, k=RUN):
    """Runs of k or more bytes in the literal pieces that are also in a stock file.

    Indexes every k/2-byte window of the pieces and looks up stock windows at k/2 steps, so any
    common run of k - 1 or more bytes is found, then grows each match both ways. Windows with
    fewer than 4 different byte values (padding, runs of spaces) are left out of the index.
    Returns {(piece, start, end): stock file}.
    """
    half = k // 2
    index = {}
    for name, data in lits.items():
        for i in range(len(data) - half + 1):
            w = data[i:i + half]
            if len(set(w)) >= 4:
                index.setdefault(w, []).append((name, i))
    hits = {}
    for sname, s in stock:
        for j in range(0, len(s) - half + 1, half):
            for name, i in index.get(s[j:j + half], ()):
                d = lits[name]
                a, b = i, j
                while a > 0 and b > 0 and d[a - 1] == s[b - 1]:
                    a, b = a - 1, b - 1
                e, f = i + half, j + half
                while e < len(d) and f < len(s) and d[e] == s[f]:
                    e, f = e + 1, f + 1
                if e - a >= k:
                    hits.setdefault((name, a, e), sname)
    return hits


def merge(hits):
    """{piece: [(start, end, stock file)]} with overlapping runs joined."""
    out = {}
    for (name, a, e), sname in sorted(hits.items()):
        runs = out.setdefault(name, [])
        if runs and a <= runs[-1][1]:
            runs[-1] = (runs[-1][0], max(runs[-1][1], e), runs[-1][2])
        else:
            runs.append((a, e, sname))
    return out


def stock_files(image, dest):
    """Every regular file of a stock ext4 image, read with debugfs rdump into dest."""
    dest.mkdir(parents=True)
    subprocess.run([str(DEBUGFS), '-R', f'rdump / {dest}', str(image)], capture_output=True, timeout=600)
    out = []
    for p in sorted(dest.rglob('*')):
        if p.is_file() and not p.is_symlink():
            p.chmod(0o644)
            out.append((p.relative_to(dest).as_posix(), p.read_bytes()))
    check(len(out) > 100, f'debugfs read only {len(out)} files from {image}')
    return out


def check_zip(zip_path, stock_vendor, work):
    results = {'zip': str(zip_path), 'bytes': zip_path.stat().st_size, 'device_accessed': False}
    top, files = zip_members(zip_path)
    manifest = json.loads(files['manifest.json'])
    for rel, want in manifest['files'].items():
        check(rel in files and sha(files[rel]) == want, f'{rel} does not match manifest.json')
    extra = sorted(set(files) - set(manifest['files']) - {'manifest.json'})
    check(not extra, f'files not in manifest.json: {extra}')
    results['files_match_manifest'] = len(manifest['files'])
    text_checks(files, results)
    lits = {rel: data for rel, data in files.items() if rel.startswith('vendor/payload/patch/') and rel.endswith('.lit')}
    results['literal_pieces'] = {'count': len(lits), 'bytes': sum(map(len, lits.values()))}
    if not stock_vendor.is_file():
        results['literal_scan'] = f'skipped: no stock vendor at {stock_vendor}'
        return results, []
    scratch = work / 'stock-vendor'
    try:
        stock = stock_files(stock_vendor, scratch)
        runs = merge(literal_runs(lits, stock))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    found, allowed = [], []
    for name, rr in sorted(runs.items()):
        for a, e, sname in rr:
            reason = ALLOWED_RUNS.get((name, a, e - a, sha(lits[name][a:e])))
            if reason:
                allowed.append({'piece': name, 'start': a, 'bytes': e - a, 'stock_file': sname, 'reason': reason})
                continue
            found.append({'piece': name, 'start': a, 'bytes': e - a, 'stock_file': sname,
                          'cil': '.cil/' in name, 'text': lits[name][a:e][:80].decode(errors='replace')})
    results['literal_scan'] = {'stock_files': len(stock), 'run_bytes': RUN, 'hits': len(found),
                               'cil_hits': sum(1 for h in found if h['cil']), 'allowed': allowed}
    return results, found


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--work', type=Path, default=ROOT / 'build/installer-check')
    ap.add_argument('--zip', type=Path, help='check this installer zip instead of the dry runs')
    ap.add_argument('--stock-vendor', type=Path, default=STOCK_VENDOR_MAY,
                    help='stock May 2024 vendor.img (private), for the literal piece scan')
    args = ap.parse_args()
    if args.zip:
        args.work.mkdir(parents=True, exist_ok=True)
        try:
            results, found = check_zip(args.zip.resolve(), args.stock_vendor, args.work)
        except Fail as e:
            print(f'FAIL: {e}', file=sys.stderr)
            sys.exit(1)
        print(json.dumps(results, indent=2))
        for h in found:
            print(f'stock bytes: {h["piece"]} at {h["start"]}, {h["bytes"]} bytes, also in {h["stock_file"]}: '
                  f'{h["text"]!r}', file=sys.stderr)
        sys.exit(1 if found else 0)
    sys.path.insert(0, str(TOOLS))
    import pocket_phone as pp
    cfg = pp.load_config()
    work = args.work
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    results = {'device_accessed': False}
    try:
        rel, imgs = fake_release(work)
        gates = json.loads((ROOT / 'configs/release-gates.json').read_text())
        gates['qualified'] = {k: True for k in gates['qualified']}
        gpath = work / 'gates.json'
        gpath.write_text(json.dumps(gates))
        rc, out, zip_path = build(work, rel, gpath)
        check(rc == 0, f'build failed: {out}')
        names = zipfile.ZipFile(zip_path).namelist()
        results['zip_files'] = len(names)
        _, files = zip_members(zip_path)
        text_checks(files, results)
        stock_recovery = hashlib.shake_256(b'stock recovery').digest(32 * 1024)
        case_happy(work, zip_path, cfg, imgs, stock_recovery, results)
        case_stop_in_lk(work, zip_path, cfg, stock_recovery, results, 'locked', {'unlocked': 'no'}, 'bootloader is locked')
        case_stop_in_lk(work, zip_path, cfg, stock_recovery, results, 'wrong_product', {'lk_product': 'k62v1_64_bsp'},
                        'not a Titan Pocket')
        case_january(work, zip_path, cfg, stock_recovery, results)
        case_mid_backup(work, zip_path, cfg, stock_recovery, results)
        case_fastbootd_failure(work, zip_path, cfg, stock_recovery, results)
        case_no_at_system(work, zip_path, cfg, stock_recovery, results)
        case_no_format(work, zip_path, cfg, imgs, stock_recovery, results)
        case_finish_refused(work, zip_path, cfg, stock_recovery, results)
        case_damaged(work, zip_path, cfg, stock_recovery, results)
        case_build_refusals(work, rel, gpath, cfg, results)
        rc, out, _ = build(work / 'realgates', rel, ROOT / 'configs/release-gates.json', 'realgates')
        check(rc == 0 and 'Release gates remain open' in out, f'real gates note missing: {out}')
        results['real_gates'] = 'zip built; notes the installer refuses to run while gates are open'
    except Fail as e:
        print(f'FAIL: {e}', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(results, indent=2))
    shutil.rmtree(work)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fake']:
        sys.exit(fake_main(sys.argv[2], sys.argv[3:]))
    main()
