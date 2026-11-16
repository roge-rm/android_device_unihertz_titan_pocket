# SPDX-License-Identifier: Apache-2.0
"""adb and fastboot helpers shared by the stock backup, restore and vendor apply tools.

Plain Python with the adb and fastboot binaries, so it runs on Linux, Windows and macOS.
Every call names the phone with -s SERIAL.
"""
import hashlib
import json
from pathlib import Path
import re
import queue
import shlex
import shutil
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / 'configs/stock-backup.json'
GATES = ROOT / 'configs/release-gates.json'
CHUNK = 1024 * 1024
HEX64 = re.compile(r'^[0-9a-f]{64}$')


class PhoneError(RuntimeError):
    pass


def load_config(path=None):
    cfg = json.loads(Path(path or CONFIG).read_text())
    if cfg.get('schema') != 1:
        raise PhoneError('unsupported stock backup config')
    return cfg


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def find_tool(name, given=None):
    if given:
        return str(given)
    found = shutil.which(name)
    if not found:
        raise PhoneError(f'{name} is not on PATH; install Android platform-tools')
    return found


class Phone:
    def __init__(self, serial, adb=None, fastboot=None):
        if not serial:
            raise PhoneError('a phone serial is needed')
        self.serial = serial
        self.adb_bin = find_tool('adb', adb)
        self.fastboot_bin = find_tool('fastboot', fastboot)

    # adb

    def adb(self, *args, timeout=600, check=True):
        p = subprocess.run([self.adb_bin, '-s', self.serial, *args], capture_output=True, timeout=timeout)
        if check and p.returncode:
            raise PhoneError(f'adb {" ".join(args)} failed: {(p.stderr or p.stdout).decode(errors="replace").strip()[:300]}')
        return p

    def shell(self, *words, timeout=600, check=True):
        """Runs one command in our recovery. Returns (rc, stdout text)."""
        cmd = ' '.join(shlex.quote(str(w)) for w in words)
        p = self.adb('shell', cmd, timeout=timeout, check=False)
        out = p.stdout.decode(errors='replace')
        if check and p.returncode:
            raise PhoneError(f'phone command {cmd} failed ({p.returncode}): '
                             f'{(out + p.stderr.decode(errors="replace")).strip()[:300]}')
        return p.returncode, out

    def getprop(self, name):
        return self.shell('getprop', name)[1].strip()

    def adb_state(self):
        p = subprocess.run([self.adb_bin, '-s', self.serial, 'get-state'], capture_output=True, timeout=30)
        return p.stdout.decode(errors='replace').strip() if p.returncode == 0 else None

    def require_recovery_root(self):
        if self.adb_state() != 'recovery':
            raise PhoneError(f'{self.serial} is not in recovery over adb')
        if self.shell('id', '-u')[1].strip() != '0':
            raise PhoneError('recovery adb is not root; boot our recovery')

    def exists(self, path):
        return self.shell('test', '-e', path, check=False)[0] == 0

    def mounted(self, path):
        """True when path, or the device it links to, is a mount source."""
        real = self.shell('readlink', '-f', path)[1].strip()
        sources = {line.split()[0] for line in self.shell('cat', '/proc/mounts')[1].splitlines() if line.split()}
        return path in sources or real in sources

    def size_of(self, path):
        out = self.shell('blockdev', '--getsize64', path)[1].strip()
        if not out.isdigit():
            raise PhoneError(f'no size for {path}: {out[:80]}')
        return int(out)

    def phone_sha256(self, path, timeout=1800):
        out = self.shell('sha256sum', path, timeout=timeout)[1].split()
        if not out or not HEX64.match(out[0]):
            raise PhoneError(f'no sha256 for {path}')
        return out[0]

    def read_block(self, path, dest, timeout=3600, stall=120):
        """Streams a block device to dest over adb exec-out. Returns (sha256, bytes).

        Stops when no data comes for stall seconds, or after timeout seconds in all.
        """
        h = hashlib.sha256()
        n = 0
        # exec-out has no stderr channel, so dd's summary must not reach the stream.
        cmd = f'dd if={shlex.quote(path)} bs={CHUNK} 2>/dev/null'
        p = subprocess.Popen([self.adb_bin, '-s', self.serial, 'exec-out', cmd],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        blocks = queue.Queue(maxsize=16)

        def pump():
            try:
                for block in iter(lambda: p.stdout.read1(CHUNK), b''):
                    blocks.put(block)
            finally:
                blocks.put(None)

        threading.Thread(target=pump, daemon=True).start()
        end = time.monotonic() + timeout
        try:
            with open(dest, 'wb') as out:
                while True:
                    try:
                        block = blocks.get(timeout=max(0.1, min(stall, end - time.monotonic())))
                    except queue.Empty:
                        raise PhoneError(f'reading {path} stalled or timed out')
                    if block is None:
                        break
                    h.update(block)
                    out.write(block)
                    n += len(block)
                    if time.monotonic() > end:
                        raise PhoneError(f'reading {path} timed out')
            err = p.stderr.read()
            if p.wait():
                raise PhoneError(f'reading {path} failed: {err.decode(errors="replace").strip()[:300]}')
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        return h.hexdigest(), n

    def push(self, local, remote, timeout=1800):
        self.adb('push', str(local), remote, timeout=timeout)

    def pull(self, remote, local, timeout=1800):
        self.adb('pull', remote, str(local), timeout=timeout)

    # fastboot

    def fastboot(self, *args, timeout=1800, check=True):
        p = subprocess.run([self.fastboot_bin, '-s', self.serial, *args], capture_output=True, timeout=timeout)
        text = (p.stdout + p.stderr).decode(errors='replace')
        if check and p.returncode:
            raise PhoneError(f'fastboot {" ".join(args)} failed: {text.strip()[:300]}')
        return p.returncode, text

    def getvar(self, name):
        rc, text = self.fastboot('getvar', name, timeout=60, check=False)
        for line in text.splitlines():
            if line.startswith(name + ':'):
                return line[len(name) + 1:].strip()
        return None

    def in_fastboot(self):
        p = subprocess.run([self.fastboot_bin, 'devices'], capture_output=True, timeout=30)
        return any(line.split()[:1] == [self.serial] for line in p.stdout.decode(errors='replace').splitlines())

    def mode(self):
        """'recovery', 'fastbootd', 'bootloader' or None."""
        if self.adb_state() == 'recovery':
            return 'recovery'
        if self.in_fastboot():
            return 'fastbootd' if self.getvar('is-userspace') == 'yes' else 'bootloader'
        return None

    def wait_for(self, mode, timeout=180):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.mode() == mode:
                return
            time.sleep(1)
        raise PhoneError(f'{self.serial} did not reach {mode} in {timeout} s')

    def serial_reported(self, mode):
        """The serial the phone itself reports in mode, or None."""
        if mode == 'recovery':
            return self.getprop('ro.serialno') or self.getprop('ro.boot.serialno') or None
        return self.getvar('serialno') or None


def parse_size(value):
    """A fastboot partition-size answer in bytes, or None.

    fastbootd answers 0x2000000. Stock LK answers 2000000 for the same 32 MiB partition: hex
    without the 0x (saved getvar answers, evidence/stock-recovery-readiness/bootloader-queries.json).
    """
    if not value:
        return None
    v = value.strip().lower()
    v = v[2:] if v.startswith('0x') else v
    try:
        return int(v, 16)
    except ValueError:
        return None


def supported_stock(gates_path=None):
    return json.loads(Path(gates_path or GATES).read_text()).get('supported_stock_firmware', [])
