#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline tests of the stock backup, restore and vendor apply tools with a fake phone.

Fake adb and fastboot (this file run with --fake) keep a phone in a folder: partitions are
files under dev/block, the mode is in a state file, and every call is logged. Cases:
  - a backup run saves every partition with matching hashes, the stock release and the
    camerapostalgo files, and writes nothing to the phone
  - a read that differs from the phone's own hash stops the backup
  - a restore from a matching backup writes the changed owner partitions in recovery, then
    vendor, system and product in fastbootd, then the LK partitions with recovery from the
    firmware zip, and the phone ends up as backed up
  - a backup from another phone is refused before any write
  - a truncated image is refused before the phone is touched
  - the vendor step runs device ota/pocket_vendor.sh from our recovery on the May 2024 stock
    vendor (dumped from the pinned image) and gives the overlay file for file, and refuses
    the January 2023 vendor with nothing written
No real phone, adb server or root is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
SERIAL = 'TESTPOCKET0001'


# The fake phone

def fake_main(tool, argv):
    state_path = Path(os.environ['FAKE_PHONE'])
    st = json.loads(state_path.read_text())
    root = Path(st['root'])

    def save():
        state_path.write_text(json.dumps(st))

    def log(*what):
        with open(st['calls'], 'a') as f:
            f.write(json.dumps([tool, *what]) + '\n')

    def at(path):
        return root / path.lstrip('/')

    def out(text):
        sys.stdout.write(text)
        sys.stdout.flush()

    if argv[:1] == ['devices']:
        if tool == 'fastboot' and st['mode'] in ('fastbootd', 'bootloader'):
            out(f'{st["serial"]}\tfastboot\n')
        return 0
    if argv[:1] != ['-s'] or argv[1] != st['serial']:
        sys.stderr.write('device not found\n')
        return 1
    args = argv[2:]
    log(st['mode'], *args)

    if tool == 'fastboot':
        if st['mode'] not in ('fastbootd', 'bootloader'):
            sys.stderr.write('< waiting for device >\n')
            return 1
        user = st['mode'] == 'fastbootd'
        if args[0] == 'getvar':
            name = args[1]
            value = None
            if name == 'is-userspace':
                value = 'yes' if user else 'no'
            elif name == 'serialno':
                value = st['props'].get('ro.serialno', '')
            elif name.startswith('is-logical:'):
                value = 'yes' if user and name.split(':')[1] in st['logical'] else 'no'
            elif name.startswith('partition-size:'):
                p = at('/dev/block/by-name/' + name.split(':')[1])
                # Stock LK leaves out the 0x; fastbootd keeps it.
                value = (hex(p.stat().st_size) if user else f'{p.stat().st_size:x}') if p.exists() else None
            if value is None:
                sys.stderr.write(f'getvar:{name} FAILED (remote: unknown)\n')
                return 1
            sys.stderr.write(f'{name}: {value}\nFinished.\n')
            return 0
        if args[0] == 'flash':
            name, image = args[1], Path(args[2])
            if user != (name in st['logical']):
                sys.stderr.write(f'FAILED (remote: {name} not flashable here)\n')
                return 1
            data = image.read_bytes()
            if user:
                at('/dev/block/mapper/' + name).write_bytes(data)
            else:
                dev = at('/dev/block/by-name/' + name)
                if len(data) > dev.stat().st_size:
                    sys.stderr.write('FAILED (remote: too large)\n')
                    return 1
                with open(dev, 'r+b') as f:
                    f.write(data)
            sys.stderr.write('OKAY\n')
            return 0
        if args[0] == 'resize-logical-partition':
            if not user or args[1] not in st['logical']:
                sys.stderr.write(f'FAILED (remote: {args[1]} is not a logical partition here)\n')
                return 1
            with open(at('/dev/block/mapper/' + args[1]), 'r+b') as f:
                f.truncate(int(args[2]))
            sys.stderr.write('OKAY\n')
            return 0
        if args[0] == 'reboot':
            st['mode'] = {'bootloader': 'bootloader', 'fastboot': 'fastbootd'}.get(args[1:2] and args[1], 'system')
            save()
            return 0
        return 1

    # adb
    if args[0] == 'get-state':
        if st['mode'] != 'recovery':
            sys.stderr.write('error: device not found\n')
            return 1
        out('recovery\n')
        return 0
    if st['mode'] != 'recovery':
        sys.stderr.write('error: device not found\n')
        return 1
    if args[0] == 'reboot':
        st['mode'] = {'fastboot': 'fastbootd', 'bootloader': 'bootloader'}[args[1]]
        save()
        return 0
    if args[0] == 'push':
        src, dest = Path(args[1]), at(args[2])
        if src.is_dir():
            if dest.is_dir():
                dest = dest / src.name
            shutil.copytree(src, dest)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
        return 0
    if args[0] == 'pull':
        shutil.copyfile(at(args[1]), args[2])
        return 0
    words = [w for w in shlex.split(args[1]) if w != '2>/dev/null']
    if args[0] == 'exec-out':
        assert words[0] == 'dd' and words[1].startswith('if='), words
        name = Path(words[1][3:]).name
        if name in st.get('stall_reads', []):
            sys.stdout.buffer.write(b'x' * 4096)
            sys.stdout.flush()
            time.sleep(30)
        data = bytearray(at(words[1][3:]).read_bytes())
        if name in st['corrupt_reads'] and data:
            data[len(data) // 2] ^= 0xff
        sys.stdout.buffer.write(bytes(data))
        return 0
    assert args[0] == 'shell', args
    cmd = words[0]
    if cmd == 'getprop':
        out(st['props'].get(words[1], '') + '\n')
    elif cmd == 'id':
        out('0\n')
    elif cmd == 'test':
        return 0 if at(words[2]).exists() else 1
    elif cmd == 'blockdev':
        out(f'{at(words[2]).stat().st_size}\n')
    elif cmd == 'readlink':
        out(words[2] + '\n')
    elif cmd == 'sha256sum' and words[1] in st.get('hash_override', {}):
        out(st['hash_override'][words[1]] + f'  {words[1]}\n')
    elif cmd == 'sha256sum':
        p = at(words[1])
        if not p.is_file():
            return 1
        out(hashlib.sha256(p.read_bytes()).hexdigest() + f'  {words[1]}\n')
    elif cmd == 'mkdir':
        at(words[2]).mkdir(parents=True, exist_ok=True)
    elif cmd == 'rm':
        p = at(words[2])
        if p.is_symlink() or p.is_file():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
    elif cmd == 'mount':
        dev, point = words[-2], at(words[-1])
        if dev not in st['mounts']:
            sys.stderr.write('mount: bad fs\n')
            return 1
        if point.is_dir() and not point.is_symlink():
            point.rmdir()
        point.symlink_to(st['mounts'][dev])
    elif cmd == 'umount':
        p = at(words[1])
        if p.is_symlink():
            p.unlink()
    elif cmd == 'cat':
        p = at(words[1])
        if not p.exists():
            return 1
        out(p.read_text())
    elif cmd == 'dd':
        kv = dict(w.split('=', 1) for w in words[1:])
        data = at(kv['if']).read_bytes()
        with open(at(kv['of']), 'r+b') as f:
            f.write(data)
    elif cmd == 'sh':
        script, mode, target, payload = words[1:5]
        env = dict(st['script_env'], PATH=st['script_path'])
        p = subprocess.run(['/usr/bin/dash', str(at(script)), mode, str(at(target)), str(at(payload))],
                           env=env, capture_output=True, text=True)
        out(p.stdout + p.stderr)
        return p.returncode
    else:
        sys.stderr.write(f'fake adb: unknown command {words}\n')
        return 127
    return 0


# Test helpers

class Fail(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FakePhone:
    def __init__(self, work, cfg):
        self.work = work
        self.root = work / 'phone'
        self.state_path = work / 'state.json'
        self.calls = work / 'calls.log'
        self.bin = work / 'bin'
        self.bin.mkdir(parents=True)
        (self.root / 'proc').mkdir(parents=True)
        (self.root / 'proc/mounts').write_text('tmpfs /tmp tmpfs rw 0 0\n')
        for tool in ('adb', 'fastboot'):
            w = self.bin / tool
            w.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} '
                         f'--fake {tool} "$@"\n')
            w.chmod(0o755)
        self.cfg = cfg
        self.state = {'root': str(self.root), 'calls': str(self.calls), 'serial': SERIAL, 'mode': 'recovery',
                      'props': {'ro.serialno': SERIAL, 'ro.product.device': 'titan_pocket'},
                      'mounts': {}, 'corrupt_reads': [], 'logical': cfg['logical_partitions'],
                      'script_env': {}, 'script_path': '/usr/bin:/bin'}

    def save(self):
        self.state_path.write_text(json.dumps(self.state))

    def load(self):
        self.state = json.loads(self.state_path.read_text())

    def dev(self, name):
        base = 'mapper' if name in self.cfg['logical_partitions'] else 'by-name'
        return self.root / 'dev/block' / base / name

    def calls_list(self):
        if not self.calls.exists():
            return []
        return [json.loads(l) for l in self.calls.read_text().splitlines()]

    def writes(self):
        """Calls that change the phone."""
        bad = []
        for c in self.calls_list():
            words = c[2:]
            if c[0] == 'fastboot' and words[:1] and words[0].split(':')[0] in (
                    'flash', 'resize-logical-partition', 'format', 'erase'):
                bad.append(c)
            if c[0] == 'adb' and words[:1] == ['shell'] and shlex.split(words[1])[0] in ('dd', 'sh'):
                bad.append(c)
            if c[0] == 'adb' and words[:1] == ['push']:
                bad.append(c)
        return bad

    def env(self):
        return dict(os.environ, FAKE_PHONE=str(self.state_path))

    def run(self, tool, *args):
        self.save()
        p = subprocess.run([sys.executable, str(TOOLS / tool), '--adb', str(self.bin / 'adb'),
                            '--fastboot', str(self.bin / 'fastboot'), *map(str, args)],
                           env=self.env(), capture_output=True, text=True)
        self.load()
        return p.returncode, (p.stdout + p.stderr).strip()


def make_phone(work, cfg):
    ph = FakePhone(work, cfg)
    sizes = {'nvram': 64, 'nvdata': 64, 'nvcfg': 32, 'protect1': 8, 'protect2': 11, 'persist': 48,
             'proinfo': 3, 'boot': 32, 'recovery': 32, 'dtbo': 8, 'vbmeta': 8, 'vbmeta_system': 8,
             'vbmeta_vendor': 8, 'vendor': 40, 'system': 96, 'product': 24, 'lk': 1, 'seccfg': 8}
    for n, kib in sizes.items():
        p = ph.dev(n)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(hashlib.shake_256(n.encode()).digest(kib * 1024))
    vendor = work / 'stock-vendor'
    vendor.mkdir()
    (vendor / 'build.prop').write_text('ro.vendor.build.custom_version=Titan_pocket_20240514\n'
                                       'ro.vendor.build.version.incremental=root.20220928.141215\n')
    system = work / 'stock-system'
    for rel in cfg['camerapostalgo']['files']:
        f = system / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b'fake ' + rel.encode())
    ph.state['mounts'] = {'/dev/block/mapper/vendor': str(vendor), '/dev/block/mapper/system': str(system)}
    return ph


# Cases

def case_backup(work, cfg, results):
    ph = make_phone(work / 'backup', cfg)
    out = work / 'backup/saved'
    rc, text = ph.run('pocket-stock-backup.py', '--serial', SERIAL, '--out', out)
    check(rc == 0, f'backup failed: {text}')
    rec = json.loads((out / 'backup.json').read_text())
    check(rec['status'] == 'complete', 'backup not complete')
    names = [i['name'] for i in rec['images']]
    want = cfg['owner_partitions'] + [n for n in cfg['bootloader_partitions'] if n != 'recovery'] + \
        cfg['logical_partitions']
    check(names == want, f'images {names}, wanted {want}')
    for i in rec['images']:
        data = ph.dev(i['name']).read_bytes()
        check((out / i['file']).read_bytes() == data and i['sha256'] == sha(data) and i['bytes'] == len(data),
              f'{i["name"]} copy differs')
    sums = (out / 'SHA256SUMS').read_text().splitlines()
    check(len(sums) == len(names) + len(cfg['camerapostalgo']['files']), 'SHA256SUMS line count')
    for line in sums:
        h, f = line.split(None, 1)
        check(sha((out / f).read_bytes()) == h, f'SHA256SUMS {f}')
    check(rec['stock'] == {'custom_version': 'Titan_pocket_20240514', 'release': '20240514',
                           'vendor_incremental': 'root.20220928.141215', 'supported': True},
          f'stock record {rec["stock"]}')
    check(rec['device']['serialno'] == SERIAL and rec['device']['proinfo_sha256'] == sha(ph.dev('proinfo').read_bytes()),
          'device record')
    check([n['name'] for n in rec['not_saved']] == ['recovery'], 'recovery should be listed as not saved')
    cp = rec['camerapostalgo']
    check(cp['complete'] and len(cp['files']) == len(cfg['camerapostalgo']['files']) and
          not any(f['known_stock'] for f in cp['files']), 'camerapostalgo record')
    check(not ph.writes(), f'the backup wrote to the phone: {ph.writes()[:2]}')
    reads = [c for c in ph.calls_list() if c[2] == 'exec-out']
    check(len(reads) == len(names), 'one stream read per image')
    results['backup'] = {'images': len(names), 'camerapostalgo_files': len(cp['files']), 'phone_writes': 0}
    return ph, out


def case_mismatch(work, cfg, results):
    ph = make_phone(work / 'mismatch', cfg)
    ph.state['corrupt_reads'] = ['nvdata']
    out = work / 'mismatch/saved'
    rc, text = ph.run('pocket-stock-backup.py', '--serial', SERIAL, '--out', out)
    rec = json.loads((out / 'backup.json').read_text())
    check(rc != 0 and 'nvdata' in text and rec['status'] == 'failed', f'mismatch not caught: {rc} {text}')
    check([i['name'] for i in rec['images']] == ['nvram'], 'the run went on after the mismatch')
    check(not (out / 'SHA256SUMS').exists(), 'a failed backup wrote SHA256SUMS')
    check(not ph.writes(), 'the failed backup wrote to the phone')
    results['readback_mismatch'] = {'rc': rc, 'error': rec['error']}


def test_config(work, cfg, recovery):
    """The real config with the stock recovery hash of a fake firmware zip."""
    c = json.loads(json.dumps(cfg))
    c['stock_recovery']['20240514'].update(sha256=sha(recovery), bytes=len(recovery))
    path = work / 'config.json'
    path.write_text(json.dumps(c))
    zpath = work / 'stock.zip'
    with zipfile.ZipFile(zpath, 'w') as z:
        z.writestr(c['stock_recovery']['20240514']['member'], recovery)
    return path, zpath


def case_restore(work, cfg, ph, saved, results):
    stock_recovery = hashlib.shake_256(b'stock recovery').digest(32 * 1024)
    config, zpath = test_config(work, cfg, stock_recovery)
    want = {i['name']: (saved / i['file']).read_bytes() for i in json.loads((saved / 'backup.json').read_text())['images']}
    want['recovery'] = stock_recovery
    # The phone after our install: owner nvdata damaged, the rest ours.
    for n in ('nvdata', 'boot', 'dtbo', 'vbmeta', 'recovery', 'vendor', 'system', 'product'):
        data = bytearray(ph.dev(n).read_bytes())
        data[:16] = b'ours ours ours !'
        ph.dev(n).write_bytes(bytes(data))
    ph.calls.unlink()
    ph.state['mode'] = 'recovery'
    rc, text = ph.run('pocket-stock-restore.py', saved, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc == 0, f'restore failed: {text}')
    for n, data in want.items():
        check(ph.dev(n).read_bytes() == data, f'{n} is not restored')
    check(ph.state['mode'] == 'bootloader', 'restore should end in LK')
    seq = []
    for c in ph.calls_list():
        if c[0] == 'adb' and c[2] == 'shell' and shlex.split(c[3])[0] == 'dd':
            seq.append(('recovery', dict(w.split('=', 1) for w in shlex.split(c[3])[1:])['of'].rsplit('/', 1)[1]))
        if c[0] == 'fastboot' and c[2] == 'flash':
            seq.append((c[1], c[3]))
        if c[0] == 'fastboot' and c[2] == 'resize-logical-partition':
            check(c[4] == '0', f'resize of {c[3]} to {c[4]}')
            seq.append((c[1], 'empty ' + c[3]))
    expect = [('recovery', 'nvdata'), ('fastbootd', 'empty vendor'), ('fastbootd', 'empty system'),
              ('fastbootd', 'empty product'), ('fastbootd', 'vendor'), ('fastbootd', 'system'), ('fastbootd', 'product'),
              ('bootloader', 'boot'), ('bootloader', 'dtbo'), ('bootloader', 'vbmeta'),
              ('bootloader', 'vbmeta_system'), ('bootloader', 'vbmeta_vendor'), ('bootloader', 'recovery')]
    check(seq == expect, f'write order {seq}')
    results['restore'] = {'writes': seq, 'all_match_backup': True}
    return config, zpath


def case_other_phone(work, cfg, ph, saved, config, zpath, results):
    ph.calls.unlink()
    ph.state['mode'] = 'recovery'
    ph.state['props']['ro.serialno'] = 'OTHERPOCKET999'
    rc, text = ph.run('pocket-stock-restore.py', saved, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc != 0 and 'not the one backed up' in text, f'another phone was not refused: {text}')
    check(not ph.writes(), 'writes before refusing another phone')
    # No serial reported: proinfo decides.
    ph.state['props']['ro.serialno'] = ''
    data = bytearray(ph.dev('proinfo').read_bytes())
    data[0] ^= 1
    ph.dev('proinfo').write_bytes(bytes(data))
    rc, text = ph.run('pocket-stock-restore.py', saved, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc != 0 and 'proinfo differs' in text and not ph.writes(), f'other proinfo not refused: {text}')
    data[0] ^= 1
    ph.dev('proinfo').write_bytes(bytes(data))
    ph.state['props']['ro.serialno'] = SERIAL
    results['other_phone'] = {'serial': 'refused', 'proinfo': 'refused', 'phone_writes': 0}


def case_truncated(work, cfg, saved, config, zpath, results):
    ph = make_phone(work / 'truncated', cfg)
    copy = work / 'truncated/saved'
    shutil.copytree(saved, copy)
    boot = copy / 'boot.img'
    boot.write_bytes(boot.read_bytes()[:-4096])
    rc, text = ph.run('pocket-stock-restore.py', copy, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc != 0 and 'truncated' in text, f'truncated image not refused: {text}')
    check(not ph.calls_list(), 'the phone was touched before the backup was checked')
    # Same length, one byte changed.
    shutil.copyfile(saved / 'boot.img', boot)
    data = bytearray(boot.read_bytes())
    data[100] ^= 1
    boot.write_bytes(bytes(data))
    rc, text = ph.run('pocket-stock-restore.py', copy, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc != 0 and 'sha256' in text and not ph.calls_list(), f'changed image not refused: {text}')
    results['truncated'] = {'truncated': 'refused', 'changed_byte': 'refused', 'phone_calls': 0}


def case_stall_and_mounted(work, cfg, results):
    ph = make_phone(work / 'stall', cfg)
    ph.state['stall_reads'] = ['nvdata']
    out = work / 'stall/saved'
    t = time.monotonic()
    rc, text = ph.run('pocket-stock-backup.py', '--serial', SERIAL, '--out', out, '--stall-timeout', '1')
    took = time.monotonic() - t
    rec = json.loads((out / 'backup.json').read_text())
    check(rc != 0 and 'stalled' in text and 'Traceback' not in text, f'stalled read not caught: {text}')
    check(rec['status'] == 'failed' and 'stalled' in rec['error'] and took < 20,
          f'stall not recorded or too slow ({took:.0f} s): {rec.get("error")}')
    ph.state['stall_reads'] = []
    (ph.root / 'proc/mounts').write_text('/dev/block/by-name/persist /mnt/vendor/persist ext4 rw 0 0\n')
    out = work / 'stall/mounted'
    rc, text = ph.run('pocket-stock-backup.py', '--serial', SERIAL, '--out', out)
    check(rc != 0 and 'persist is mounted' in text, f'mounted persist was read: {text}')
    results['stalled_read'] = {'rc': rc, 'seconds': round(took, 1), 'recorded': True}
    results['mounted_owner'] = 'refused'


def case_bad_sums(work, saved, config, zpath, results):
    ph = make_phone(work / 'sums', json.loads(config.read_text()))
    copy = work / 'sums/saved'
    shutil.copytree(saved, copy)
    sums = copy / 'SHA256SUMS'
    good = sums.read_bytes()
    check(b'\r' not in good, 'SHA256SUMS has CR')
    for data, want in [(None, 'no readable SHA256SUMS'), (b'nonsense line\n' + good, 'SHA256SUMS line 1'),
                       (good.replace(b'\n', b'\r\n'), 'SHA256SUMS line')]:
        if data is None:
            sums.unlink()
        else:
            sums.write_bytes(data)
        rc, text = ph.run('pocket-stock-restore.py', copy, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
        check(rc != 0 and want in text and 'Traceback' not in text, f'bad SHA256SUMS: {text}')
    check(not ph.calls_list(), 'the phone was touched with a bad SHA256SUMS')
    rc, text = ph.run('pocket-stock-restore.py', saved, '--serial', SERIAL, '--only', 'bogus', '--check-only')
    check(rc != 0 and 'unknown partitions' in text, f'--only bogus accepted: {text}')
    results['bad_sha256sums'] = 'refused (missing, bad line, CRLF), unknown --only refused'


def case_no_system(work, cfg, config, zpath, results):
    ph = make_phone(work / 'nosys', cfg)
    out = work / 'nosys/saved'
    rc, text = ph.run('pocket-stock-backup.py', '--serial', SERIAL, '--out', out, '--no-system')
    check(rc == 0, f'backup --no-system failed: {text}')
    for n in ('nvdata', 'boot', 'vendor'):
        data = bytearray(ph.dev(n).read_bytes())
        data[:4] = b'ours'
        ph.dev(n).write_bytes(bytes(data))
    ours = {n: ph.dev(n).read_bytes() for n in ('boot', 'vendor')}
    ph.calls.unlink()
    rc, text = ph.run('pocket-stock-restore.py', out, '--serial', SERIAL, '--config', config, '--stock-zip', zpath)
    check(rc != 0 and 'no system or product' in text and not ph.writes(), f'full restore without system: {text}')
    rc, text = ph.run('pocket-stock-restore.py', out, '--serial', SERIAL, '--config', config, '--owner-only')
    check(rc == 0, f'--owner-only failed: {text}')
    check(ph.dev('nvdata').read_bytes() == (out / 'nvdata.img').read_bytes(), 'nvdata not restored')
    check(all(ph.dev(n).read_bytes() == d for n, d in ours.items()), '--owner-only changed boot or vendor')
    check(not any(c[0] == 'fastboot' and c[2] in ('flash', 'reboot') for c in ph.calls_list()) and
          ph.state['mode'] == 'recovery', '--owner-only left recovery')
    results['no_system_backup'] = {'full_restore': 'refused', 'owner_only': 'nvdata only, rest kept'}


def case_force_other(work, cfg, ph, saved, config, zpath, results):
    ph.calls.unlink()
    ph.state['mode'] = 'recovery'
    ph.state['props']['ro.serialno'] = 'OTHERPOCKET999'
    data = bytearray(ph.dev('nvdata').read_bytes())
    data[:4] = b'othr'
    ph.dev('nvdata').write_bytes(bytes(data))
    rc, text = ph.run('pocket-stock-restore.py', saved, '--serial', SERIAL, '--config', config, '--stock-zip', zpath,
                      '--force-other-phone')
    check(rc == 0, f'forced restore failed: {text}')
    check(ph.dev('nvdata').read_bytes() == bytes(data), 'forced restore wrote nvdata')
    dds = [c for c in ph.calls_list() if c[0] == 'adb' and c[2] == 'shell' and shlex.split(c[3])[0] in ('dd', 'rm')]
    check(not dds, f'forced restore ran {dds[:1]}')
    check(ph.dev('boot').read_bytes() == (saved / 'boot.img').read_bytes(), 'forced restore skipped boot')
    ph.state['props']['ro.serialno'] = SERIAL
    ph.dev('nvdata').write_bytes((saved / 'nvdata.img').read_bytes())
    results['force_other_phone'] = 'owner partitions untouched, the rest restored'


def case_vendor_backup(work, cfg, saved, results):
    ph = FakePhone(work / 'vbackup', cfg)
    ph.dev('vendor').parent.mkdir(parents=True)
    ph.dev('vendor').write_bytes(b'')
    payload = work / 'vbackup/payload'
    payload.mkdir()
    (payload / 'manifest.txt').write_text('vendor_version_min 20240514\n')
    vsha = json.loads((saved / 'backup.json').read_text())
    vsha = next(i['sha256'] for i in vsha['images'] if i['name'] == 'vendor')
    copy = work / 'vbackup/saved'
    shutil.copytree(saved, copy)
    img = copy / 'vendor.img'
    img.write_bytes(img.read_bytes()[:-1])
    ph.state['hash_override'] = {'/dev/block/mapper/vendor': vsha}
    rc, text = ph.run('pocket-vendor-apply.py', '--serial', SERIAL, '--payload', payload, '--backup', copy)
    check(rc != 0 and 'truncated' in text, f'damaged vendor.img accepted: {text}')
    ph.state['hash_override'] = {'/dev/block/mapper/vendor': '0' * 64}
    rc, text = ph.run('pocket-vendor-apply.py', '--serial', SERIAL, '--payload', payload, '--backup', saved)
    check(rc != 0 and 'not the one in the backup' in text, f'changed vendor accepted: {text}')
    check(not ph.writes(), 'the vendor step wrote after a bad backup')
    results['vendor_backup'] = 'damaged vendor.img and a different phone vendor refused'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def case_vendor(work, cfg, results, payload_zip, saved):
    ck = load('ckota', TOOLS / 'check-pocket-vendor-ota.py')
    vo = ck.VO
    base, january = vo.BASE_IMAGE, ck.JANUARY
    overlay = ck.OV.OVERLAY_DIR / vo.VERSION / 'vendor.img'
    check(ck.sha256(base) == vo.BASE_SHA256, 'the May base is not the pinned image')
    vwork = work / 'vendor'
    ph = FakePhone(vwork, cfg)
    applets = vwork / 'toybox'
    applets.mkdir()
    for a in ck.APPLETS:
        (applets / a).symlink_to(ck.TOYBOX)
    (applets / 'sync').symlink_to('/usr/bin/sync')
    ph.state['script_path'] = str(applets)
    with zipfile.ZipFile(payload_zip) as z:
        manifest = json.loads(z.read('manifest.json'))
    entries = {e['path']: e for e in manifest['entries']}
    scratch = vwork / 'img'
    scratch.mkdir()
    want = vo.tree(overlay, scratch / 'overlay')
    start = vo.tree(base, scratch / 'may')
    backup = saved
    vsha = next(i['sha256'] for i in json.loads((saved / 'backup.json').read_text())['images'] if i['name'] == 'vendor')
    # The tree stands in for the block device, so the phone's vendor hash is given.
    ph.state['hash_override'] = {'/dev/block/mapper/vendor': vsha}
    mapper = ph.root / 'dev/block/mapper'
    mapper.mkdir(parents=True)

    def run(image, name, extra=()):
        tree = vwork / 'trees' / name
        ck.rdump(image, tree)
        target = mapper / 'vendor'
        if target.is_symlink():
            target.unlink()
        target.symlink_to(tree)
        meta, ops = vwork / f'{name}.meta', vwork / f'{name}.ops'
        free = ck.free_of(image)
        ph.state['script_env'] = {'POCKET_VENDOR_META_LOG': str(meta), 'POCKET_VENDOR_OPS_LOG': str(ops),
                                  'POCKET_VENDOR_WORK': str(vwork / f'{name}-work'),
                                  'POCKET_VENDOR_FREE': f'{free[0]} {free[1]}'}
        before = ck.tree_state(tree)
        rc, text = ph.run('pocket-vendor-apply.py', '--serial', SERIAL, '--payload', payload_zip,
                          '--backup', backup, *extra)
        return rc, text, tree, before, meta, ops

    rc, text, tree, before, meta, ops = run(base, 'may')
    check(rc == 0 and 'vendor applied' in text, f'vendor step on May failed: {text}')
    m = {}
    for line in meta.read_text().splitlines():
        path, uid, gid, mode_, label = line.split()
        m['/' + path] = (int(uid), int(gid), mode_, label)
    bad = ck.compare(ck.tree_state(tree), m, want, start, entries)
    check(not bad, 'May after the vendor step differs from the overlay:\n' + '\n'.join(bad[:10]))
    check(not (ph.root / 'tmp/pocket-vendor').exists(), 'the pushed files were left on the phone')
    n_ops = len(ops.read_text().splitlines())
    shutil.rmtree(tree)

    rc, text, tree, before, meta, ops = run(january, 'january')
    check(rc != 0 and 'nothing written' in text, f'January vendor was not refused: {text}')
    check(ck.tree_state(tree) == before and not ops.exists() and not meta.exists(),
          'the January vendor changed')
    shutil.rmtree(tree)
    results['vendor_apply'] = {'may': 'overlay file for file', 'may_ops': n_ops, 'paths_compared': len(want),
                               'january': 'refused, nothing written'}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--work', type=Path, default=ROOT / 'build/stock-backup-check')
    ap.add_argument('--payload', type=Path, help='pocket_vendor_overlay.zip; default the v13 one')
    ap.add_argument('--no-vendor', action='store_true', help='skip the vendor image case')
    args = ap.parse_args()
    sys.path.insert(0, str(TOOLS))
    import pocket_phone as pp
    cfg = pp.load_config()
    work = args.work
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    results = {'device_accessed': False}
    try:
        ph, saved = case_backup(work, cfg, results)
        case_mismatch(work, cfg, results)
        config, zpath = case_restore(work, cfg, ph, saved, results)
        case_other_phone(work, cfg, ph, saved, config, zpath, results)
        case_truncated(work, cfg, saved, config, zpath, results)
        case_force_other(work, cfg, ph, saved, config, zpath, results)
        case_no_system(work, cfg, config, zpath, results)
        case_bad_sums(work, saved, config, zpath, results)
        case_stall_and_mounted(work, cfg, results)
        case_vendor_backup(work, cfg, saved, results)
        if not args.no_vendor:
            ota = load('vota', TOOLS / 'prepare-pocket-vendor-ota.py')
            case_vendor(work, cfg, results, args.payload or ota.OUT / 'pocket_vendor_overlay.zip', saved)
    except Fail as e:
        print(f'FAIL: {e}', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(results, indent=2))
    shutil.rmtree(work)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fake']:
        sys.exit(fake_main(sys.argv[2], sys.argv[3:]))
    main()
