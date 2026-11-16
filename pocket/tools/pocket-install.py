#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install our LineageOS build on a Titan Pocket, step by step, from the installer folder.

Starts with the phone in its bootloader (LK fastboot mode) and asks before each step that
writes to it:
  1. LK: checks the bootloader is unlocked, the product and the serial.
  2. LK: flashes our recovery and starts it, then waits for the owner to pick Enable ADB.
     Stock vbmeta stays for now: LK checks recovery against its own footer only and boots it
     either way while unlocked.
  3. Recovery: reads the stock release from vendor build.prop and stops unless it's the
     supported May 2024 release, putting stock recovery back.
  4. Recovery: saves the stock backup to this computer (pocket-stock-backup.py), always,
     after checking there's room. Nothing else is written before it's complete.
  5. Recovery: applies our vendor overlay to the phone's own vendor (pocket-vendor-apply.py).
  6. fastbootd: system and product, then formats data (userdata and md_udc) after a warning.
  7. LK: boot and vbmeta (flags 3), then a reboot.
Every write comes from the plan in manifest.json, checked by validate-pocket-install.py
before the phone is touched. A log goes next to the backup folder. When a step fails it says
what state the phone is in and the command that puts stock back.

Our recovery's adb needs no key but only starts once the owner picks Advanced, Enable ADB in
its menu, so the installer asks for that each time it starts recovery.

--put-back-recovery ZIP only flashes stock recovery from Unihertz's May 2024 firmware zip,
with the phone in LK. --finish --backup-dir FOLDER only writes boot and vbmeta, for a run that
wrote system and product and stopped because data wasn't formatted. It reads that run's
install-state.json in FOLDER and checks our system and product are on the phone first.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import pocket_phone as pp  # noqa: E402


def load_tool(name, file):
    spec = importlib.util.spec_from_file_location(name, TOOLS / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


backup_tool = load_tool('pocket_backup', 'pocket-stock-backup.py')
restore_tool = load_tool('pocket_restore', 'pocket-stock-restore.py')
vendor_tool = load_tool('pocket_vendor_apply', 'pocket-vendor-apply.py')
validator = load_tool('pocket_validate', 'validate-pocket-install.py')

STOCK_ZIP = '2024051420_g66v71c2k_dfl_tee.zip'
STOCK_RELEASE = '20240514'
# In the backup folder: how far the install got, so --finish knows it may write boot and vbmeta.
STATE_FILE = 'install-state.json'


class Stop(Exception):
    """A check stopped the run. Not an error in the tools."""


class Log:
    """Prints and keeps every line, with the adb and fastboot calls, in a log file."""

    def __init__(self):
        self.lines = []
        self.file = None

    def open(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, 'a', encoding='utf-8')
        for line in self.lines:
            self.file.write(line)
        self.file.flush()
        self.path = path

    def __call__(self, text='', quiet=False):
        if not quiet:
            print(text, flush=True)
        stamp = datetime.now(timezone.utc).strftime('%H:%M:%S')
        line = ''.join(f'{stamp} {t}\n' for t in str(text).splitlines() or [''])
        self.lines.append(line)
        if self.file:
            self.file.write(line)
            self.file.flush()


class LoggedPhone(pp.Phone):
    """pp.Phone that logs each call and only writes partitions from the checked plan."""

    def __init__(self, serial, adb, fastboot, log, allowed):
        super().__init__(serial, adb, fastboot)
        self.log, self.allowed = log, allowed

    def adb(self, *args, timeout=600, check=True):
        self.log(f'$ adb -s {self.serial} {" ".join(args)}', quiet=True)
        p = super().adb(*args, timeout=timeout, check=False)
        self.log(f'  rc {p.returncode} {(p.stdout + p.stderr).decode(errors="replace").strip()[:400]}', quiet=True)
        if check and p.returncode:
            raise pp.PhoneError(f'adb {" ".join(args)} failed: {(p.stderr or p.stdout).decode(errors="replace").strip()[:300]}')
        return p

    def fastboot(self, *args, timeout=1800, check=True):
        verb = args[0].split(':')[0] if args else ''
        if verb in ('flash', 'erase', 'format', 'resize-logical-partition', 'delete-logical-partition',
                    'flashing', 'oem', 'wipe-super', 'update', 'flashall', '-w'):
            if len(args) < 2 or args[1] not in self.allowed.get(verb, ()):
                raise pp.PhoneError(f'fastboot {" ".join(args)} is not in the checked plan')
        self.log(f'$ fastboot -s {self.serial} {" ".join(args)}', quiet=True)
        rc, text = super().fastboot(*args, timeout=timeout, check=False)
        self.log(f'  rc {rc} {text.strip()[:400]}', quiet=True)
        if check and rc:
            raise pp.PhoneError(f'fastboot {" ".join(args)} failed: {text.strip()[:300]}')
        return rc, text

    def read_block(self, path, dest, timeout=3600, stall=120):
        self.log(f'$ adb -s {self.serial} exec-out dd if={path}', quiet=True)
        return super().read_block(path, dest, timeout=timeout, stall=stall)


def ask(log, question):
    while True:
        try:
            a = input(f'{question} [y/N] ').strip().lower()
        except EOFError:
            a = ''
        log(f'{question} -> {a or "(no answer)"}', quiet=True)
        if a in ('y', 'yes'):
            return True
        if a in ('', 'n', 'no'):
            return False


def confirm_word(log, question, word):
    try:
        a = input(f'{question} ').strip()
    except EOFError:
        a = ''
    log(f'{question} -> {a or "(no answer)"}', quiet=True)
    return a == word


def raw_size(path):
    """Bytes an image takes on the phone: the full size for an Android sparse image."""
    with open(path, 'rb') as f:
        head = f.read(28)
    if len(head) == 28 and struct.unpack('<I', head[:4])[0] == 0xed26ff3a:
        blk, total = struct.unpack('<II', head[12:20])
        return blk * total
    return Path(path).stat().st_size


def gib(n):
    return f'{n / 1024 ** 3:.1f} GB'


class Installer:
    def __init__(self, args, log):
        self.args, self.log = args, log
        self.pkg = Path(args.package).resolve()
        self.state = 'nothing'
        # The mode the phone was last left in, for the commands in state_report.
        self.where = 'bootloader'
        self.backup_dir = None
        self.data_formatted = False
        self.serial = args.serial
        self.adb = args.adb or 'adb'
        self.fastboot = args.fastboot or 'fastboot'

    # Commands printed for the owner

    def py(self):
        return 'py -3' if os.name == 'nt' else 'python3'

    def q(self, s):
        s = str(s)
        if os.name == 'nt':
            return f'"{s}"' if ' ' in s else s
        return shlex.quote(s)

    def tool_args(self):
        return f'--serial {self.serial or "SERIAL"} --adb {self.q(self.adb)} --fastboot {self.q(self.fastboot)}'

    def zip_arg(self):
        return self.q(self.args.stock_zip or f'PATH/TO/{STOCK_ZIP}')

    def state_report(self):
        """What the phone holds now and how to put stock back."""
        s, lines = self.state, []
        folder = self.q(self.backup_dir) if self.backup_dir else 'BACKUP-FOLDER'
        restore = f'{self.py()} tools/pocket-stock-restore.py {folder} {self.tool_args()} --stock-zip {self.zip_arg()}'
        if s == 'nothing':
            lines.append('Nothing was written to the phone.')
        elif s == 'recovery':
            lines += ['Only the recovery partition was changed: it holds our recovery. Android and your data are as before.',
                      "To put stock recovery back, start the phone in fastboot mode and run, from the installer folder:",
                      f'  {self.py()} tools/pocket-install.py --put-back-recovery {self.zip_arg()} {self.tool_args()}']
        elif s == 'vendor' and self.where == 'fastbootd':
            # The owner partitions are untouched, so the restore starts in fastbootd.
            lines += ['Our recovery is on the phone and vendor is ours. The phone is in fastbootd.',
                      'Put all of stock back with:', f'  {restore} --phases fastbootd bootloader']
        elif s == 'vendor' and self.where is None:
            lines += ['Our recovery is on the phone and vendor is ours. The phone was restarting from recovery into fastbootd.',
                      'If it is in our recovery (run "adb devices" and look for recovery, after Advanced, Enable ADB), '
                      'put all of stock back with:', f'  {restore}',
                      'If it is in fastbootd ("fastboot devices" lists it), use instead:',
                      f'  {restore} --phases fastbootd bootloader']
        elif s == 'vendor':
            lines += ['Our recovery is on the phone and the vendor partition may be part changed.',
                      'With the phone in our recovery and Advanced, Enable ADB picked, put all of stock back with:',
                      f'  {restore}']
        elif s in ('fastbootd', 'lk'):
            lines.append('Vendor is ours and system, product' + (', boot or vbmeta' if s == 'lk' else '') +
                         ' may be part written' + (', data was formatted.' if self.data_formatted else '.'))
            if self.where == 'recovery':
                lines.append('To put stock back, pick Advanced, Enter fastboot in our recovery, then run:')
            elif self.where == 'fastbootd':
                lines.append('The phone is in fastbootd. Put stock back with:')
            else:
                lines.append(f'Start fastbootd (from fastboot mode: fastboot -s {self.serial} reboot fastboot), '
                             'then put stock back with:')
            lines.append(f'  {restore} --phases fastbootd bootloader')
        if self.backup_dir and s != 'nothing':
            record = self.backup_dir / 'backup.json'
            done = record.is_file() and json.loads(record.read_text()).get('status') == 'complete'
            if not self.backup_dir.exists():
                lines.append('There is no stock backup yet.')
            else:
                lines.append(f'Your stock backup is in {self.backup_dir}' + ('' if done else ' (not complete, don\'t use it)') + '.')
        return '\n'.join(lines)

    # Checks

    def load_package(self):
        self.log('Checking the installer files...')
        try:
            self.manifest = json.loads((self.pkg / 'manifest.json').read_text())
        except (OSError, ValueError) as e:
            raise Stop(f'no readable manifest.json in {self.pkg}: {e}')
        if self.manifest.get('schema') != 1:
            raise Stop('this manifest.json is for another installer version')
        for rel, want in self.manifest['files'].items():
            path = self.pkg / rel
            if not path.is_file() or pp.sha256_file(path) != want:
                raise Stop(f'{rel} is missing or damaged; download the installer again')
        self.plan = self.manifest['plan']
        self.gates = json.loads((self.pkg / 'configs/release-gates.json').read_text())
        try:
            validator.validate(self.plan, self.pkg, self.gates)
        except (validator.InvalidPlan, KeyError, TypeError) as e:
            raise Stop(f'the install plan does not pass its checks: {e}')
        self.cfg = pp.load_config(self.pkg / 'configs/stock-backup.json')
        self.device = self.manifest['device']
        self.images = {i['partition']: i for i in self.plan['images']}
        flash = set(self.images)
        self.allowed = {'flash': flash,
                        'resize-logical-partition': {i['partition'] for i in self.plan['images'] if i['mode'] == 'fastbootd'},
                        'format': set(self.plan.get('format', []))}
        self.log(f'Release {self.manifest["release"]["name"]}, plan checked: '
                 + ', '.join(f'{i["partition"]} ({i["mode"]})' for i in self.plan['images']))

    def image(self, name):
        return str(self.pkg / self.images[name]['file'])

    def find_tools(self):
        self.adb = pp.find_tool('adb', self.args.adb)
        self.fastboot = pp.find_tool('fastboot', self.args.fastboot)

    def list_devices(self, tool, *args):
        p = subprocess.run([tool, *args], capture_output=True, timeout=30)
        out = []
        for line in p.stdout.decode(errors='replace').splitlines():
            w = line.split()
            if len(w) >= 2 and not line.startswith('List of'):
                out.append((w[0], w[1]))
        return out

    def find_phone(self):
        fb = [s for s, _ in self.list_devices(self.fastboot, 'devices')]
        if not self.serial:
            if len(fb) > 1:
                raise Stop(f'more than one phone in fastboot mode ({", ".join(fb)}); give --serial')
            if fb:
                self.serial = fb[0]
            else:
                android = [s for s, st in self.list_devices(self.adb, 'devices') if st == 'device']
                if len(android) == 1 and ask(self.log, f'Phone {android[0]} is running Android. Restart it into fastboot mode?'):
                    self.serial = android[0]
                    subprocess.run([self.adb, '-s', self.serial, 'reboot', 'bootloader'], capture_output=True, timeout=60)
                else:
                    raise Stop('no phone in fastboot mode. With Android running and USB debugging on, run '
                               '"adb reboot bootloader", or start the phone in fastboot mode with its keys, then run this again.')
        self.phone = LoggedPhone(self.serial, self.adb, self.fastboot, self.log, self.allowed)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        if self.args.finish:
            # --backup-dir is the first run's backup folder itself.
            self.backup_dir = Path(self.args.backup_dir).resolve()
            self.log.open(self.backup_dir.parent / f'{self.backup_dir.name}-finish-{stamp}.log')
        else:
            parent = Path(self.args.backup_dir or self.pkg / 'backups').resolve()
            self.backup_dir = parent / f'pocket-stock-backup-{self.serial}-{stamp}'
            self.log.open(parent / f'{self.backup_dir.name}.log')
        self.log(f'Log file: {self.log.path}')
        self.phone.wait_for('bootloader', timeout=self.args.wait)

    def check_lk(self, again=False):
        ph = self.phone
        if ph.mode() != 'bootloader':
            raise Stop('the phone must be in fastboot mode (LK), not recovery or fastbootd')
        unlocked = ph.getvar('unlocked')
        if unlocked != 'yes':
            raise Stop(f'the bootloader is locked (unlocked: {unlocked}). Unlock it first; '
                       'unlocking erases the phone. See README.txt.')
        product = ph.getvar('product')
        if product != self.device['lk_product']:
            raise Stop(f'this is not a Titan Pocket: LK reports product {product}, '
                       f'a Titan Pocket reports {self.device["lk_product"]}')
        reported = ph.getvar('serialno')
        if reported and reported != self.serial:
            raise Stop(f'the phone reports serial {reported}, not {self.serial}')
        if again:
            return
        for i in self.plan['images']:
            if i['mode'] != 'bootloader':
                continue
            size = pp.parse_size(ph.getvar(f'partition-size:{i["partition"]}'))
            if size is None or size < Path(self.image(i['partition'])).stat().st_size:
                raise Stop(f'LK reports {size} bytes for {i["partition"]}, too small for our image')
        self.log(f'Phone {self.serial}: Titan Pocket, bootloader unlocked.')

    def check_fastbootd(self):
        ph = self.phone
        product = (ph.getvar('product') or '').lower()
        if product not in [p.lower() for p in self.device['fastbootd_products']]:
            raise Stop(f'fastbootd reports product {product}')
        reported = ph.getvar('serialno')
        if reported and reported != self.serial:
            raise Stop(f'fastbootd reports serial {reported}, not {self.serial}')
        for i in self.plan['images']:
            if i['mode'] == 'fastbootd' and ph.getvar(f'is-logical:{i["partition"]}') != 'yes':
                raise Stop(f'{i["partition"]} is not a dynamic partition in fastbootd')

    # Steps

    def explain(self):
        self.log('\nThis installs LineageOS on the phone in these steps. It asks before each one that writes.\n'
                 '  1. Flash our recovery and start it. You pick Advanced, Enable ADB in its menu.\n'
                 '  2. Check the phone runs the May 2024 stock release.\n'
                 '  3. Back up the stock partitions to this computer, including the IMEI, Wi-Fi and\n'
                 '     Bluetooth addresses and calibration that only this phone has.\n'
                 '  4. Change the phone\'s own vendor partition for LineageOS.\n'
                 '  5. Write system and product, then format data. Everything on the phone is erased.\n'
                 '  6. Write boot and vbmeta and restart.\n'
                 f'The backup goes in {self.backup_dir} and needs up to 5 GB.\n'
                 'Keep the phone plugged in the whole time.\n')

    def flash_recovery(self):
        if not ask(self.log, 'Step 1: flash our recovery and start it?'):
            raise Stop('stopped before the first write')
        self.state = 'recovery'
        self.phone.fastboot('flash', 'recovery', self.image('recovery'))
        self.phone.fastboot('reboot', 'recovery')
        self.where = None
        self.wait_recovery_adb()
        self.phone.require_recovery_root()
        reported = self.phone.serial_reported('recovery')
        if reported and reported != self.serial:
            raise Stop(f'recovery reports serial {reported}, not {self.serial}')

    def wait_recovery_adb(self):
        """Waits for our recovery's adb, which the owner turns on in its menu."""
        self.log('\nStarting our recovery. When its menu shows on the phone, pick Advanced, then Enable ADB\n'
                 '(the volume keys move, the power key picks). The installer goes on once it sees the phone.')
        timeout = max(self.args.wait, 900)
        end = time.monotonic() + timeout
        told = False
        while time.monotonic() < end:
            if self.phone.mode() == 'recovery':
                self.where = 'recovery'
                self.log('Recovery adb is on.')
                return
            if not told and (self.serial, 'unauthorized') in self.list_devices(self.adb, 'devices'):
                self.log('The phone is in recovery. Waiting for Advanced, Enable ADB...')
                told = True
            time.sleep(1)
        raise Stop(f'recovery adb did not come up in {timeout:.0f} s. Pick Advanced, Enable ADB in our recovery, '
                   'then run this again from fastboot mode (Advanced, Reboot to bootloader)')

    def check_stock(self):
        bk = backup_tool.Backup(self.phone, self.cfg, None, log=self.log)
        point = bk.mount('vendor')
        try:
            props = backup_tool.read_props(self.phone.shell('cat', f'{point}/build.prop')[1])
        finally:
            bk.umount(point)
        custom = props.get('ro.vendor.build.custom_version', '')
        supported = self.gates['supported_stock_firmware']
        self.log(f'Stock release on the phone: {custom or "unknown"}')
        if custom in supported:
            return
        m = re.fullmatch(r'Titan_pocket_(\d{8})', custom)
        need = re.fullmatch(r'Titan_pocket_(\d{8})', supported[0])
        if m and need and m.group(1) < need.group(1):
            why = (f'The phone has the stock release {custom}, older than May 2024. Update it with '
                   "Unihertz's updater first (Settings, System, Wireless update), then run this again.")
        else:
            why = f'The phone has the stock release {custom or "(unknown)"}, which this installer does not support.'
        self.log(why)
        self.put_back_recovery_from_recovery()
        raise Stop(why)

    def put_back_recovery_from_recovery(self):
        zip_path = self.args.stock_zip
        if not zip_path:
            try:
                given = input(f"Path to Unihertz's {STOCK_ZIP}, to put stock recovery back (Enter to skip): ").strip()
            except EOFError:
                given = ''
            self.log(f'stock zip -> {given or "(none)"}', quiet=True)
            zip_path = Path(given.strip('"')) if given else None
            self.args.stock_zip = zip_path
        if not zip_path:
            self.log('Stock recovery not put back.')
            return
        with tempfile.TemporaryDirectory(prefix='pocket-install-') as scratch:
            img = restore_tool.recovery_from_zip(zip_path, self.cfg, STOCK_RELEASE, scratch)
            if not ask(self.log, 'Restart into fastboot mode and flash stock recovery?'):
                return
            self.phone.adb('reboot', 'bootloader')
            self.phone.wait_for('bootloader', timeout=self.args.wait)
            self.where = 'bootloader'
            self.check_lk(again=True)
            self.phone.fastboot('flash', 'recovery', str(img['path']))
        self.state = 'nothing'
        self.log('Stock recovery is back. Starting Android.')
        self.phone.fastboot('reboot', check=False)

    def backup(self):
        ph, cfg = self.phone, self.cfg
        names = cfg['owner_partitions'] + [n for n in cfg['bootloader_partitions'] if n != 'recovery'] + cfg['logical_partitions']
        need = backup_tool.MARGIN
        for n in names:
            path = (cfg['mapper'] if n in cfg['logical_partitions'] else cfg['by_name']) + '/' + n
            if ph.exists(path):
                need += ph.size_of(path)
        self.backup_dir.parent.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(self.backup_dir.parent).free
        self.log(f'Step 3: backup. It needs {gib(need)} on this computer, {gib(free)} is free.')
        if need > free:
            raise Stop(f'not enough room for the backup in {self.backup_dir.parent}: free up {gib(need - free)} '
                       'or give --backup-dir on another disk')
        self.backup_dir.mkdir()
        record = backup_tool.Backup(ph, cfg, self.backup_dir, log=self.log).run(save_recovery=False, with_system=True)
        skipped = [s['name'] for s in record['skipped'] if s['name'] in cfg['logical_partitions']]
        if skipped:
            raise Stop(f'the backup left out {", ".join(skipped)}; stock could not be put back without them')
        if not record['stock'].get('supported'):
            raise Stop(f'the backup reports stock {record["stock"].get("custom_version")}, not a supported release')
        self.log(f'Backup complete: {len(record["images"])} partitions in {self.backup_dir}')
        if not record['camerapostalgo'].get('complete'):
            self.log('Note: the stock camerapostalgo files were not all copied.')

    def vendor(self):
        if not ask(self.log, "Step 4: change the phone's vendor partition for LineageOS?"):
            raise Stop('stopped before the vendor step')
        vendor_tool.check_backup(self.backup_dir, self.phone)
        self.state = 'vendor'
        vendor_tool.apply(self.phone, self.pkg / self.device['vendor_payload'], self.pkg / self.device['vendor_script'],
                          log=self.log)
        self.save_state('vendor done')
        self.log('Vendor done.')

    def save_state(self, status):
        """Writes how far the install got into the backup folder, with what was flashed."""
        logical = [i for i in self.plan['images'] if i['mode'] == 'fastbootd']
        flashed = {i['partition']: i['sha256'] for i in logical} if status != 'vendor done' else {}
        record = {'schema': 1, 'status': status, 'serial': self.serial, 'release': self.manifest['release']['name'],
                  'flashed': flashed}
        (self.backup_dir / STATE_FILE).write_text(json.dumps(record, indent=2) + '\n')

    def fastbootd(self):
        ph = self.phone
        ph.adb('reboot', 'fastboot')
        self.where = None
        self.log('Starting fastbootd...')
        ph.wait_for('fastbootd', timeout=self.args.wait)
        self.where = 'fastbootd'
        self.check_fastbootd()
        logical = [i for i in self.plan['images'] if i['mode'] == 'fastbootd']
        rec = json.loads((self.backup_dir / 'backup.json').read_text())
        kept = sum(i['bytes'] for i in rec['images'] if i['name'] in self.cfg['logical_partitions']
                   and i['name'] not in {x['partition'] for x in logical})
        total = kept + sum(raw_size(self.image(i['partition'])) for i in logical)
        if total > validator.LOGICAL_LIMIT:
            raise Stop(f'system, product and vendor need {total} bytes, more than the {validator.LOGICAL_LIMIT} in super')
        names = ' and '.join(i['partition'] for i in logical)
        if not ask(self.log, f'Step 5: write {names}?'):
            raise Stop(f'stopped before writing {names}')
        self.state = 'fastbootd'
        # As the OTA's dynamic_partitions_op_list: empty them first so the new sizes fit.
        for i in logical:
            ph.fastboot('resize-logical-partition', i['partition'], '0')
        for i in logical:
            self.log(f'Writing {i["partition"]}...')
            ph.fastboot('flash', i['partition'], self.image(i['partition']))
        self.save_state('system flashed')
        fmt = self.plan.get('format', [])
        if fmt:
            self.log('\nNext, data is formatted. Everything on the phone is erased: apps, photos, messages and '
                     'accounts. Stock data can\'t be read by LineageOS. Copy off anything you want to keep first;\n'
                     'the stock backup does not hold your data.')
            if confirm_word(self.log, 'Type format to erase data, or anything else to skip:', 'format'):
                for n in fmt:
                    self.log(f'Formatting {n}...')
                    ph.fastboot('format:ext4', n)
                self.data_formatted = True
                self.save_state('data formatted')
            else:
                # Boot and vbmeta stay stock, so the phone can't start our system on stock data.
                self.save_state('format skipped')
                ph.fastboot('reboot', 'recovery')
                self.where = 'recovery'
                raise Stop('data was not formatted, so boot and vbmeta were not written. The phone is starting our '
                           'recovery. To finish, pick Factory reset, '
                           'Format data/factory reset, then Advanced, Reboot to bootloader, and run from the installer '
                           f'folder:\n  {self.py()} tools/pocket-install.py --finish --backup-dir {self.q(self.backup_dir)} '
                           f'{self.tool_args()}')

    def lk(self):
        ph = self.phone
        ph.fastboot('reboot', 'bootloader')
        ph.wait_for('bootloader', timeout=self.args.wait)
        self.where = 'bootloader'
        self.check_lk(again=True)
        self.write_late()

    def write_late(self):
        ph = self.phone
        late = [i for i in self.plan['images'] if i['mode'] == 'bootloader' and i['partition'] != 'recovery']
        names = ' and '.join(i['partition'] for i in late)
        if not ask(self.log, f'Step 6: write {names}?'):
            raise Stop(f'stopped before writing {names}')
        self.state = 'lk'
        for i in late:
            self.log(f'Writing {i["partition"]}...')
            ph.fastboot('flash', i['partition'], self.image(i['partition']))
        self.state = 'done'
        self.save_state('done')
        self.log('Restarting. The first start takes a few minutes.')
        ph.fastboot('reboot')

    def run(self):
        self.load_package()
        self.find_tools()
        self.find_phone()
        self.check_lk()
        self.explain()
        self.flash_recovery()
        self.check_stock()
        self.backup()
        self.vendor()
        self.fastbootd()
        self.lk()
        self.log(f'\nDone. Keep the backup folder {self.backup_dir} somewhere safe: it is the only copy of this '
                 "phone's IMEI and calibration outside the phone.")

    def finish_state(self):
        """The first run's state; refuses unless it flashed our system and product and skipped the format."""
        folder = Path(self.args.backup_dir).resolve()
        try:
            st = json.loads((folder / STATE_FILE).read_text())
        except (OSError, ValueError):
            raise Stop(f'no {STATE_FILE} in {folder}. --finish only goes on from a run that wrote system and '
                       'product and then skipped the format; give that run\'s backup folder')
        want = {i['partition']: i['sha256'] for i in self.plan['images'] if i['mode'] == 'fastbootd'}
        if st.get('status') != 'format skipped':
            raise Stop(f'the install in {folder} stopped at "{st.get("status")}", not after writing system and product '
                       'with the format skipped. Boot and vbmeta are not written.')
        if st.get('flashed') != want:
            raise Stop(f'the install in {folder} wrote other system and product images than this installer has')
        if self.serial and st.get('serial') != self.serial:
            raise Stop(f'the install in {folder} was for phone {st.get("serial")}, not {self.serial}')
        return st

    def finish(self):
        """Boot and vbmeta only, after the owner formatted data in our recovery."""
        self.load_package()
        if not self.args.backup_dir:
            raise Stop('--finish needs --backup-dir, the backup folder of the run that skipped the format')
        st = self.finish_state()
        self.serial = self.serial or st['serial']
        self.find_tools()
        self.find_phone()
        self.finish_state()
        self.check_lk()
        self.state = 'fastbootd'
        ph = self.phone
        # Our system and product must be on the phone: fastboot sized each to its image when flashing.
        ph.fastboot('reboot', 'fastboot')
        self.where = None
        ph.wait_for('fastbootd', timeout=self.args.wait)
        self.where = 'fastbootd'
        self.check_fastbootd()
        for i in self.plan['images']:
            if i['mode'] != 'fastbootd':
                continue
            size = pp.parse_size(ph.getvar(f'partition-size:{i["partition"]}'))
            if size != raw_size(self.image(i['partition'])):
                raise Stop(f'{i["partition"]} is {size} bytes on the phone, not the {raw_size(self.image(i["partition"]))} '
                           'of our image: our system is not on the phone')
        ph.fastboot('reboot', 'bootloader')
        self.where = None
        ph.wait_for('bootloader', timeout=self.args.wait)
        self.where = 'bootloader'
        self.check_lk(again=True)
        if not ask(self.log, 'Did you format data in our recovery (Factory reset, Format data/factory reset)?'):
            raise Stop('format data in our recovery first, then run this again')
        self.write_late()
        self.log(f'\nDone. Keep the backup folder {self.backup_dir} somewhere safe.')

    def put_back_recovery(self):
        self.load_package()
        self.find_tools()
        self.find_phone()
        self.check_lk(again=True)
        with tempfile.TemporaryDirectory(prefix='pocket-install-') as scratch:
            img = restore_tool.recovery_from_zip(self.args.put_back_recovery, self.cfg, STOCK_RELEASE, scratch)
            if not ask(self.log, 'Flash stock recovery from the Unihertz zip?'):
                raise Stop('nothing written')
            self.phone.fastboot('flash', 'recovery', str(img['path']))
        self.log('Stock recovery is back.')
        if ask(self.log, 'Start Android now?'):
            self.phone.fastboot('reboot')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--serial', help='the phone, when more than one is plugged in')
    ap.add_argument('--adb')
    ap.add_argument('--fastboot')
    ap.add_argument('--package', default=TOOLS.parent, help='the installer folder')
    ap.add_argument('--backup-dir', type=Path,
                    help='where the backup folder and log go; default backups/ here. With --finish, the backup folder itself')
    ap.add_argument('--stock-zip', type=Path, help=f"Unihertz's {STOCK_ZIP}, to put stock recovery back if needed")
    ap.add_argument('--put-back-recovery', type=Path, metavar='ZIP',
                    help="only flash stock recovery from Unihertz's zip, with the phone in fastboot mode")
    ap.add_argument('--finish', action='store_true',
                    help='only write boot and vbmeta, with the phone in fastboot mode, after formatting data in our recovery')
    ap.add_argument('--wait', type=float, default=300, help='seconds to wait for each restart')
    args = ap.parse_args()
    log = Log()
    inst = Installer(args, log)
    try:
        if args.put_back_recovery:
            inst.put_back_recovery()
        elif args.finish:
            inst.finish()
        else:
            inst.run()
    except Stop as e:
        log(f'\nStopped: {e}')
        log(inst.state_report())
        sys.exit(2)
    except (pp.PhoneError, OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile_error()) as e:
        log(f'\nFailed: {e}')
        log(inst.state_report())
        sys.exit(1)
    except KeyboardInterrupt:
        log('\nInterrupted.')
        log(inst.state_report())
        sys.exit(130)


def zipfile_error():
    import zipfile
    return zipfile.BadZipFile


if __name__ == '__main__':
    main()
