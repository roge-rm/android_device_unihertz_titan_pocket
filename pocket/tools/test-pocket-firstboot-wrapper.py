#!/usr/bin/env python3
"""Host test of the first-boot wrapper /init under qemu-user (qemu-aarch64-static).

Offline only. Builds the wrapper with -DFIRSTBOOT_HOST_TEST (fake root from the environment,
no mounts, plain directories standing in for configfs default groups; the phone build has none
of it) and runs it against a fake tree: proc/cmdline, a pstore directory, sys/class/udc, an
empty usb_gadget directory, a regular-file kmsg and ttyGS0. The wrapper makes g1 there and execs
a host Python stand-in for Android init, which writes kmsg lines, then touches g1 the way the
vendor init.mt6771.usb.rc post-fs commands do (or not), waits for the logger child, runs the rest
of post-fs if it has not, then the adb UDC action from on boot, and records each command's result.
Also builds the stream variant (-DFIRSTBOOT_STREAM), which only logs those touches and hands back at
the timeout, and runs it through the same stand-in.
Checks the stream order, the hand-back trigger (inotify, rescan, timeout), the UDC writes, that
only our function and link are removed and g1, its strings and b.1 stay, that every rc command
succeeds, and the exec (same PID, argv, environment, no inherited fds, SIGCHLD not ignored).
Writes evidence/kernel-upgrade/firstboot-wrapper-host-test.json.
"""
import pocket_paths
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
OUT = BULK / 'artifacts/firstboot-wrapper-host-test'
REPORT = ROOT / 'evidence/kernel-upgrade/firstboot-wrapper-host-test.json'
GADGET = 'g1'
FUNCTION = 'acm.usb0'
UDC = 'fake-udc.usb'
ANDROID_UDC = '11201000.usb3'
CMDLINE = 'bootopt=64S3,32N2,64N2 androidboot.hardware=mt6771 printk.devkmsg=on panic=10'
CONSOLE = b'previous boot console\n\0binary \xff\xfe bytes\n' * 50
DMESG = b'Panic#1 Part1\n<0>Kernel panic - not syncing: test\n'
ANDROID_FUNCTIONS = ['accessory.gs2', 'audio_source.gs3', 'ffs.adb', 'mtp.gs0', 'ptp.gs1', 'rndis.gs4', 'midi.gs5',
                     'acm.gs0', 'acm.gs1', 'acm.gs2', 'acm.gs3', 'mass_storage.usb0', 'hid.gs0', 'via_modem.gs0',
                     'via_ets.gs0', 'via_atc.gs0']

# The stand-in's rc commands follow init's builtins: mkdir on an existing directory only changes
# its owner and mode (as non-root here only the mode), write opens with O_TRUNC, symlink fails if
# the link exists. UDC is appended to, so the file keeps every write for the check.
STANDIN = r'''#!/usr/bin/python3 -I
import json, os, signal, sys, time
root = os.environ['FIRSTBOOT_TEST_ROOT']
mode = os.environ['STANDIN_MODE']
g1 = root + '/sys/kernel/config/usb_gadget/g1/'
started = time.monotonic()
seen = {'pid': os.getpid(), 'argv': sys.argv[1:], 'passthrough': os.environ.get('FIRSTBOOT_TEST_PASSTHROUGH'),
        'sigchld_default': signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
        'fds': sorted((n, os.readlink('/proc/self/fd/' + n)) for n in os.listdir('/proc/self/fd')
                      if os.path.exists('/proc/self/fd/' + n)), 'commands': []}
def run(name, action):
    try:
        action()
        seen['commands'].append([name, True])
    except OSError as e:
        seen['commands'].append([name, str(e)])
def mkdir(path, mode=0o755):
    def action():
        if not os.path.isdir(g1 + path):
            os.mkdir(g1 + path, mode)
        os.chmod(g1 + path, mode)
    run('mkdir ' + path, action)
def write(path, value):
    def action():
        with open(g1 + path, 'w') as f:
            f.write(value)
    run('write ' + path, action)
def symlink(target, link):
    run('symlink ' + link, lambda: os.symlink(g1 + target, g1 + link))
def udc():
    def action():
        with open(g1 + 'UDC', 'a') as f:
            f.write('ANDROID_UDC')
    run('write UDC', action)
def post_fs():
    # vendor init.mt6771.usb.rc lines 8 to 39
    mkdir('', 0o770)
    for name, value in [('idVendor', '0x0E8D'), ('bcdDevice', '0x0223'), ('bcdUSB', '0x0200'), ('os_desc/use', '1')]:
        write(name, value)
    mkdir('strings/0x409', 0o770)
    for name in ['serialnumber', 'manufacturer', 'product']:
        write('strings/0x409/' + name, 'android ' + name)
    for name in FUNCTIONS:
        mkdir('functions/' + name)
    mkdir('configs/b.1', 0o770)
    mkdir('configs/b.1/strings/0x409', 0o770)
    write('os_desc/b_vendor_code', '0x1')
    write('os_desc/qw_sign', 'MSFT100')
    write('configs/b.1/MaxPower', '500')
    symlink('configs/b.1', 'os_desc/b.1')
def on_boot_adb():
    # product init.usb.configfs.rc lines 20 to 23, with vendor.usb.controller from vendor on boot
    write('configs/b.1/strings/0x409/configuration', 'adb')
    write('idProduct', '0x201C')
    symlink('functions/ffs.adb', 'configs/b.1/f1')
    udc()
with open(root + '/dev/kmsg', 'a') as kmsg:
    for i in range(3):
        kmsg.write('<6>standin: android init line %d\n' % i)
time.sleep(1.0)
seen['android_s'] = time.monotonic() - started
if mode == 'postfs':
    post_fs()
elif mode == 'functions':
    run('mkdir functions/accessory.gs2', lambda: os.mkdir(g1 + 'functions/accessory.gs2'))
elif mode == 'write':
    write('idVendor', '0x0E8D')
elif mode == 'linked':
    # Stands for a link of Android's in b.1 that the logger never saw coming.
    symlink('functions/acm.usb0', 'configs/b.1/f1')
status = None
while time.monotonic() - started < 20 and status is None:
    pid, code = os.waitpid(-1, os.WNOHANG)
    if pid:
        status = code
    time.sleep(0.05)
seen['child_status'] = status
seen['child_done_s'] = time.monotonic() - started
if mode not in ('postfs', 'linked'):
    post_fs()
if mode != 'linked':
    on_boot_adb()
with open(root + '/standin.json', 'w') as f:
    json.dump(seen, f)
'''.replace('ANDROID_UDC', ANDROID_UDC).replace('FUNCTIONS:', repr(ANDROID_FUNCTIONS) + ':')


def tree(base, udc=True):
    root = base / 'root'
    for d in ['proc', 'sys/fs/pstore', 'sys/class/udc', 'dev', 'sys/kernel/config/usb_gadget']:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / 'proc/cmdline').write_text(CMDLINE + '\n')
    (root / 'sys/fs/pstore/dmesg-ramoops-0').write_bytes(DMESG)
    (root / 'sys/fs/pstore/console-ramoops-0').write_bytes(CONSOLE)
    if udc:
        (root / 'sys/class/udc' / UDC).write_text('')
    (root / 'dev/kmsg').write_text('<6>kernel: early line before /init\n')
    (root / 'dev/ttyGS0').write_bytes(b'')
    return root


def listing(path):
    return sorted(p.name for p in path.iterdir()) if path.is_dir() else None


def run(qemu, binary, base, mode, env_extra, udc=True):
    root = tree(base, udc)
    standin = base / 'standin.py'
    standin.write_text(STANDIN)
    standin.chmod(0o755)
    env = {'PATH': '/usr/bin:/bin', 'FIRSTBOOT_TEST_ROOT': str(root), 'FIRSTBOOT_TEST_EXEC': str(standin),
           'FIRSTBOOT_TEST_PASSTHROUGH': '1', 'STANDIN_MODE': mode, **env_extra}
    began = time.monotonic()
    proc = subprocess.Popen([qemu, str(binary), 'first', 'second'], env=env, cwd=str(base))
    proc.wait(timeout=60)
    elapsed = time.monotonic() - began
    seen = json.loads((root / 'standin.json').read_text())
    stream = (root / 'dev/ttyGS0').read_bytes()
    g1 = root / 'sys/kernel/config/usb_gadget' / GADGET
    config = g1 / 'configs/b.1'
    return {'mode': mode, 'env': env_extra, 'returncode': proc.returncode, 'pid': proc.pid, 'seconds': round(elapsed, 2),
            'standin': seen, 'stream': stream,
            'gadgets': listing(g1.parent), 'configs': listing(g1 / 'configs'), 'functions': listing(g1 / 'functions'),
            'config_links': sorted(p.name for p in config.iterdir() if p.is_symlink()) if config.is_dir() else None,
            'kept': {d: (g1 / d).is_dir() for d in ['', 'strings/0x409', 'configs/b.1', 'configs/b.1/strings/0x409']},
            'udc_after': (g1 / 'UDC').read_text() if (g1 / 'UDC').exists() else None,
            'kmsg': (root / 'dev/kmsg').read_text(errors='replace')}


def order_ok(stream, reason, touch=None, variant=False):
    """Banner, then each pstore file in name order with its exact bytes, the live marker, kmsg, hand-back."""
    expect = [b'TP510-FIRSTBOOT-V2 wrapper init; wrapper-source-sha256=', b'FIRSTBOOT_HOST_TEST_BUILD',
              b'cmdline: ' + CMDLINE.encode(), b'pstore: 2 files, %d bytes' % (len(CONSOLE) + len(DMESG)),
              b'\n=== pstore console-ramoops-0 %d bytes ===\n' % len(CONSOLE) + CONSOLE +
              b'\n=== end pstore console-ramoops-0 ===\n',
              b'\n=== pstore dmesg-ramoops-0 %d bytes ===\n' % len(DMESG) + DMESG + b'\n=== end pstore dmesg-ramoops-0 ===\n',
              b'\n=== live kmsg from boot start ===\n', b'kernel: early line before /init',
              b'TP510-FIRSTBOOT-V2: wrapper init started', b'standin: android init line 0',
              b'standin: android init line 2']
    if variant:
        expect.insert(4, b'USB stream variant: Android touching g1 is only logged')
    if touch:
        expect.append(b'Android touched g1 at ')
        expect.append(b'ms; still streaming: ' + touch.encode())
    expect.append(b'hand-back: ' + reason.encode())
    pos = 0
    for piece in expect:
        found = stream.find(piece, pos)
        if found < 0:
            return False, piece.decode(errors='replace')[:80]
        pos = found + len(piece)
    return True, None


def main():
    qemu = shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
    if not qemu:
        sys.exit('qemu-aarch64-static is not installed (Debian package qemu-user-static); the host test needs it')
    fb = runpy.run_path(str(ROOT / 'tools/build-pocket-firstboot-ramdisk.py'))
    OUT.mkdir(parents=True, exist_ok=True)
    binary = OUT / 'init-host-test-not-for-flashing'
    command, data, source_sha = fb['compile_wrapper'](binary, test=True)
    stream_binary = OUT / 'init-host-test-stream-not-for-flashing'
    fb['compile_wrapper'](stream_binary, test=True, stream=True)
    inotify, rescan = {}, {'FIRSTBOOT_TEST_NO_INOTIFY': '1'}
    short = {'FIRSTBOOT_TEST_TIMEOUT_MS': '2500'}
    scenarios = [
        ('postfs', inotify, True, 'Android changed g1 owner or mode (inotify)'),
        ('functions', inotify, True, 'Android made functions/accessory.gs2 (inotify)'),
        ('write', inotify, True, 'Android wrote g1/idVendor (inotify)'),
        ('postfs', rescan, True, 'Android changed g1 owner or mode (rescan)'),
        ('functions', rescan, True, 'Android made functions/accessory.gs2 (rescan)'),
        ('timeout', {'FIRSTBOOT_TEST_TIMEOUT_MS': '2500'}, True, 'timeout'),
        ('postfs', inotify, False, 'Android changed g1 owner or mode (inotify)'),
        ('linked', {'FIRSTBOOT_TEST_TIMEOUT_MS': '2500'}, True, 'timeout'),
        # Stream variant: the touch is only logged, USB is handed back at the timeout.
        ('postfs', {**inotify, **short}, True, 'timeout', 'Android changed g1 owner or mode (inotify)'),
        ('functions', {**inotify, **short}, True, 'timeout', 'Android made functions/accessory.gs2 (inotify)'),
        ('write', {**inotify, **short}, True, 'timeout', 'Android wrote g1/idVendor (inotify)'),
        ('postfs', {**rescan, **short}, True, 'timeout', 'Android changed g1 owner or mode (rescan)'),
        ('functions', {**rescan, **short}, True, 'timeout', 'Android made functions/accessory.gs2 (rescan)'),
        ('postfs', {**inotify, **short}, False, 'timeout', 'Android changed g1 owner or mode (inotify)'),
        ('timeout', short, True, 'timeout', None),
        ('linked', short, True, 'timeout', None),
    ]
    results, checks = [], {}
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        for n, (mode, extra, udc, reason, *rest) in enumerate(scenarios):
            variant = bool(rest)
            touch = rest[0] if rest else None
            base = Path(tmp) / str(n)
            base.mkdir()
            r = run(qemu, stream_binary if variant else binary, base, mode, extra, udc)
            ok, missing = order_ok(r['stream'], reason, touch, variant)
            s = r['standin']
            name = '%d_%s%s%s' % (n, mode, '_rescan' if extra.get('FIRSTBOOT_TEST_NO_INOTIFY') else '',
                                  '' if udc else '_no_udc') + ('_stream' if variant else '')
            # Anything past stdin, stdout and stderr (paths, pipes, inotify or other anon inodes) came from the wrapper.
            leaked = [fd for fd in s['fds'] if fd[0] not in ('0', '1', '2')]
            failed_commands = [c for c in s['commands'] if c[1] is not True]
            c = {
                'stream_order': ok,
                'exec_same_pid': s['pid'] == r['pid'],
                'exec_argv_passed': s['argv'] == ['first', 'second'],
                'exec_env_passed': s['passthrough'] == '1',
                'exec_sigchld_not_ignored': s['sigchld_default'],
                'exec_no_wrapper_fds_inherited': not leaked,
                'child_exit_0': s['child_status'] == 0,
                'g1_strings_and_b1_kept': all(r['kept'].values()),
                'only_g1_and_b1': r['gadgets'] == [GADGET] and r['configs'] == ['b.1'],
            }
            if mode == 'linked':
                # Unlinking ours or writing UDC could unbind Android's gadget, so both are left.
                c['android_link_seen_udc_untouched'] = r['udc_after'] == UDC
                c['android_link_seen_own_link_and_function_left'] = (
                    r['config_links'] == sorted(['f1', FUNCTION]) and FUNCTION in (r['functions'] or []))
            else:
                c['own_function_removed'] = r['functions'] is not None and FUNCTION not in r['functions']
                c['own_link_removed'] = r['config_links'] is not None and FUNCTION not in r['config_links']
                c['android_g1_left_alone'] = r['functions'] == sorted(ANDROID_FUNCTIONS) and r['config_links'] == ['f1']
                c['android_rc_commands_ok'] = not failed_commands and len(s['commands']) > 30
                c['udc_bound_unbound_then_android' if udc else 'udc_only_android'] = (
                    r['udc_after'] == (UDC + '\n' if udc else '') + ANDROID_UDC)
            if variant:
                c['stream_banner_not_handback_text'] = b'USB hand-back: when Android first touches' not in r['stream']
                c['stream_touch_not_handed_back_early'] = (r['stream'].count(b'hand-back: ') == 1
                                                           and b'hand-back: timeout' in r['stream'])
            if mode in ('timeout', 'linked') or variant:
                c['hand_back_after_timeout'] = s['child_done_s'] >= 2.0
            else:
                c['hand_back_within_1500ms_of_android'] = s['child_done_s'] - s['android_s'] < 1.5
            for k, v in c.items():
                checks['%s.%s' % (name, k)] = bool(v)
            r['stream_sha256'] = __import__('hashlib').sha256(r['stream']).hexdigest()
            r['stream_head'] = r['stream'][:600].decode(errors='replace')
            r['stream_tail'] = r['stream'][-400:].decode(errors='replace')
            r['missing_from_stream'] = missing
            r['failed_commands'] = failed_commands
            del r['stream']
            results.append({'name': name, 'checks': c, **r})
    passed = all(checks.values())
    REPORT.write_text(json.dumps({
        'state': 'Host test under qemu-user with a fake tree; not run on the phone',
        'passed': passed, 'qemu': qemu, 'compile_command': command, 'stream_binary': str(stream_binary), 'wrapper_source_sha256': source_sha,
        'test_binary': str(binary), 'checks': checks, 'scenarios': results,
        'limits': ['Mounts, umounts and mknod are compiled out of the test build',
                   'configfs, kmsg and the ACM tty are plain files and directories here; their kernel behaviour '
                   '(UDC busy, link refused while bound, hangup, rmdir waits, inotify events on configfs) is from '
                   'source reading only',
                   'The stand-in runs as a normal user, so mkdir on the existing g1 changes only its mode, not its owner',
                   'The stand-in is not Android init; switch-root and SELinux are not exercised'],
        'device_accessed': False}, indent=2) + '\n')
    failed = [k for k, v in checks.items() if not v]
    print('%d checks: %s' % (len(checks), 'all passed' if passed else 'FAILED ' + ', '.join(failed)))
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
