#!/usr/bin/env python3
"""Host test of the pstore reader /init under qemu-user (qemu-aarch64-static).

Offline only. Builds kernel-upgrade/pstore-reader/init.c with -DPSTORE_HOST_TEST (paths under a
fake root, no mounts or mknod, no watchdog, a restart writes <root>/reboot-request and ends the
process group) and runs it against a fake tree: proc/cmdline, pstore files, ramoops module
parameters, sys/class/udc, an empty usb_gadget directory, a regular-file kmsg and dev/ttyGS0 as a
link to a pty, read and written from here. The stream is parsed with tools/capture-pocket-pstore.py.
Checks: every pstore file arrives byte for byte with the right size and sha256 in name order, the
tmpfs copies match, kmsg is framed and hashed, dumps repeat, a file that shows up late is picked
up, a host that attaches late still gets a whole dump, reboot-bootloader and reboot work, the
timer asks for a bootloader restart, the gadget is made with serial TP510-PSTORE, and under
qemu -strace every open is under the fake root and none names a block device.
Writes evidence/kernel-upgrade/pstore-reader/host-test.json.
"""
import pocket_paths
import hashlib
import json
import os
import pty
import re
import runpy
import select
import shutil
import subprocess
import sys
import tempfile
import time
import tty
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
OUT = BULK / 'artifacts/pstore-reader'
REPORT = ROOT / 'evidence/kernel-upgrade/pstore-reader/host-test.json'
PARSE = runpy.run_path(str(ROOT / 'tools/capture-pocket-pstore.py'))
BUILD = runpy.run_path(str(ROOT / 'tools/package-pocket-pstore-reader.py'))
CMDLINE = 'bootopt=64S3,32N2,64N2 buildvariant=userdebug rdinit=/init panic=0 watchdog.open_timeout=90'
# Console as big as the real one (256 KiB), with NULs, high bytes and lines that look like frame markers.
CONSOLE = (b'[    1.000000] previous boot console line\n\0\xff\xfe binary\n=== end file x ===\n' * 4096)[:0x40000]
FILES = {'console-ramoops-0': CONSOLE,
         'dmesg-ramoops-0': b'Panic#1 Part1\n<0>Kernel panic - not syncing: Attempted to kill init!\n' + b'x' * 3000,
         'dmesg-ramoops-1': b'Oops#1 Part1\n<1>Unable to handle kernel paging request\n'}
LATE = ('dmesg-ramoops-2', b'late record\n' * 10)
PARAMS = {'mem_address': '0x54410000', 'mem_size': '585728', 'record_size': '4096', 'console_size': '262144', 'ecc': '0'}
UDC = 'fake-udc.usb'


def tree(base):
    root = base / 'root'
    for d in ['proc', 'sys/fs/pstore', 'sys/class/udc', 'dev', 'sys/kernel/config/usb_gadget',
              'sys/module/ramoops/parameters']:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / 'proc/cmdline').write_text(CMDLINE + '\n')
    for name, data in FILES.items():
        (root / 'sys/fs/pstore' / name).write_bytes(data)
    for name, value in PARAMS.items():
        (root / 'sys/module/ramoops/parameters' / name).write_text(value + '\n')
    (root / 'sys/class/udc' / UDC).write_text('')
    (root / 'dev/kmsg').write_text('<6>kernel: early line before /init\n')
    return root


def run(qemu, binary, base, interval_ms, return_ms, script, strace=False):
    """Run the reader on a pty; script(master, root, read) drives it. Returns the stream and the reader's state."""
    root = tree(base)
    master, slave = pty.openpty()
    tty.setraw(master)
    os.symlink(os.ttyname(slave), root / 'dev/ttyGS0')
    env = {'PATH': '/usr/bin:/bin', 'PSTORE_TEST_ROOT': str(root), 'PSTORE_TEST_INTERVAL_MS': str(interval_ms),
           'PSTORE_TEST_RETURN_MS': str(return_ms)}
    stderr = open(base / 'qemu-stderr.txt', 'wb')
    command = [qemu] + (['-strace'] if strace else []) + [str(binary)]
    began = time.monotonic()
    proc = subprocess.Popen(command, env=env, cwd=str(base), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=stderr, start_new_session=True)
    # The slave stays open here too, so the master never reads EIO before the reader opens it.
    stream = bytearray()

    def read(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    stream.extend(os.read(master, 65536))
                except OSError:
                    return

    try:
        script(master, root, read)
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, 9)
            proc.wait()
        stderr.close()
        read(0.2)
        os.close(master)
        os.close(slave)
    request = (root / 'reboot-request').read_text() if (root / 'reboot-request').exists() else None
    gadget = root / 'sys/kernel/config/usb_gadget/tp510'
    return {'stream': bytes(stream), 'seconds': round(time.monotonic() - began, 2), 'returncode': proc.returncode,
            'reboot_request': request, 'root': root, 'gadget': gadget,
            'stderr': (base / 'qemu-stderr.txt').read_text(errors='replace')}


def stream_checks(r, expected_files, need_whole=2):
    dumps = PARSE['parse_stream'](r['stream'])
    whole = [d for d in dumps if d['whole']]
    c = {'whole_dumps_at_least_%d' % need_whole: len(whole) >= need_whole}
    last = whole[-1] if whole else None
    c['files_in_name_order'] = bool(last) and [f['name'] for f in last['files']] == sorted(expected_files)
    c['files_byte_for_byte'] = bool(last) and all(f['data'] == expected_files[f['name']] for f in last['files'])
    c['files_size_and_sha256'] = bool(last) and all(
        f['bytes'] == len(expected_files[f['name']]) and f['sha256'] == hashlib.sha256(expected_files[f['name']]).hexdigest()
        for f in last['files'])
    c['kmsg_framed_and_hashed'] = bool(last) and last['kmsg']['sha256_ok'] and b'kernel: early line before /init' in last['kmsg']['data']
    c['kmsg_has_reader_lines'] = bool(last) and b'TP510-PSTORE: saved pstore console-ramoops-0' in last['kmsg']['data']
    banner = last['banner'] if last else ''
    c['banner_marker_and_test_build'] = 'TP510-PSTORE pstore reader init; reader-source-sha256=' in banner and \
        'PSTORE_HOST_TEST_BUILD' in banner
    c['banner_cmdline'] = ('cmdline: ' + CMDLINE) in banner
    c['banner_ramoops_parameters'] = all('%s=%s' % kv in banner for kv in PARAMS.items())
    c['banner_raw_region_skipped'] = 'raw ramoops region: not streamed' in banner
    c['dump_numbers_increase'] = [d['dump'] for d in whole] == sorted({d['dump'] for d in whole})
    return c, dumps


def gadget_checks(r):
    g = r['gadget']
    read = lambda p: (g / p).read_text().strip() if (g / p).exists() else None
    return {'gadget_serial_TP510-PSTORE': read('strings/0x409/serialnumber') == 'TP510-PSTORE',
            'gadget_vid_pid': (read('idVendor'), read('idProduct')) == ('0x1d6b', '0x0104'),
            'gadget_acm_linked': (g / 'configs/c.1/acm.usb0').is_symlink(),
            'udc_bound': read('UDC') == UDC}


def copy_checks(r, expected_files):
    copy = r['root'] / 'pstore-copy'
    return {'tmpfs_copies_match': all((copy / n).exists() and (copy / n).read_bytes() == d
                                      for n, d in expected_files.items())}


def strace_checks(r):
    """Every path the reader opened, from qemu -strace; all under the fake root, none a block device."""
    root = str(r['root'])
    paths = re.findall(r'\b(?:openat\(-?\d+,|open\()"([^"]*)"', r['stderr'])
    absolute = [p for p in paths if p.startswith('/')]
    # Bionic's static start-up looks for the property area itself; it is not in the reader's code.
    outside = sorted({p for p in absolute if not p.startswith(root) and p != '/dev/__properties__'})
    block = sorted({p for p in paths if re.search(r'/dev/(block|sd[a-z]|mmcblk|dm-|loop|mapper)|by-name', p)})
    mounts = re.findall(r'\bmount\(', r['stderr'])
    return {'strace_saw_opens': len(paths) > 10, 'opens_only_under_fake_root': not outside,
            'no_block_device_opened': not block, 'no_mount_syscall_in_test_build': not mounts}, outside, block


def main():
    qemu = shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
    if not qemu:
        sys.exit('qemu-aarch64-static is not installed (Debian package qemu-user-static); the host test needs it')
    OUT.mkdir(parents=True, exist_ok=True)
    binary = OUT / 'init-host-test-not-for-flashing'
    command, _, source_sha = BUILD['compile_reader'](binary, test=True)
    results, checks = [], {}

    def record(name, r, c, extra=None):
        for k, v in c.items():
            checks['%s.%s' % (name, k)] = bool(v)
        entry = {'name': name, 'checks': c, 'seconds': r['seconds'], 'returncode': r['returncode'],
                 'reboot_request': r['reboot_request'], 'stream_bytes': len(r['stream']),
                 'stream_sha256': hashlib.sha256(r['stream']).hexdigest(),
                 'stream_head': r['stream'][:700].decode(errors='replace')}
        entry.update(extra or {})
        results.append(entry)

    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        tmp = Path(tmp)

        # 1. Host attached from the start; a late pstore file; then reboot-bootloader. Under -strace.
        def attached(master, root, read):
            read(1.6)
            (root / 'sys/fs/pstore' / LATE[0]).write_bytes(LATE[1])
            read(3.0)
            os.write(master, b'junk line\nreboot-bootloader\n')
            read(1.5)
        (tmp / '1').mkdir()
        r = run(qemu, binary, tmp / '1', 1000, 60000, attached, strace=True)
        expected = dict(FILES, **{LATE[0]: LATE[1]})
        c, dumps = stream_checks(r, expected)
        c.update(gadget_checks(r))
        c.update(copy_checks(r, expected))
        first_whole = next((d for d in dumps if d['whole']), None)
        c['first_dump_has_the_boot_files'] = bool(first_whole) and [f['name'] for f in first_whole['files']] == sorted(FILES)
        c['reboot_bootloader_command'] = (r['reboot_request'] or '').startswith('bootloader')
        c['restart_reply_on_acm'] = b'TP510-PSTORE: requesting bootloader restart' in r['stream']
        s, outside, block = strace_checks(r)
        c.update(s)
        record('1_attached_late_file_bootloader_command', r, c, {'opened_outside_root': outside[:20], 'block_opens': block})

        # 2. Host attaches 3.5 s late: the stalled dump is dropped and a whole fresh one follows.
        def late(master, root, read):
            time.sleep(3.5)
            read(3.0)
            os.write(master, b'reboot\n')
            read(1.0)
        (tmp / '2').mkdir()
        r = run(qemu, binary, tmp / '2', 1000, 60000, late)
        c, dumps = stream_checks(r, FILES, need_whole=1)
        # A cut-short dump, then a whole one with a higher number, and the reader's own stall line in that dump's kmsg.
        cut = [d for d in dumps if not d['whole']]
        first_whole = next((d for d in dumps if d['whole']), None)
        c['stalled_dump_cut_short_then_dropped'] = bool(cut) and bool(first_whole) and cut[0]['dump'] < first_whole['dump']
        c['reader_reported_the_stall'] = any(b'dump stalled; starting a fresh one' in d['kmsg']['data'] for d in dumps if d['whole'])
        c['reboot_command_normal'] = (r['reboot_request'] or '').startswith('normal')
        record('2_late_attach_reboot_command', r, c, {'dumps': [(d['dump'], d['whole'], d['problem']) for d in dumps]})

        # 3. No command: the timer asks for a bootloader restart.
        def idle(master, root, read):
            read(6.0)
        (tmp / '3').mkdir()
        r = run(qemu, binary, tmp / '3', 1000, 3000, idle)
        c, _ = stream_checks(r, FILES)
        m = re.match(r'bootloader at (\d+) ms', r['reboot_request'] or '')
        c['timer_bootloader_restart'] = bool(m) and 3000 <= int(m.group(1)) < 4500
        record('3_return_timer', r, c)

        # 4. Empty pstore (nothing kept from the last boot): dumps still come, with kmsg only.
        def empty(master, root, read):
            read(2.5)
            os.write(master, b'reboot-bootloader\r\n')
            read(1.0)
        (tmp / '4').mkdir()
        base = tmp / '4'
        saved = dict(FILES)
        FILES.clear()
        try:
            r = run(qemu, binary, base, 1000, 60000, empty)
        finally:
            FILES.update(saved)
        dumps = PARSE['parse_stream'](r['stream'])
        whole = [d for d in dumps if d['whole']]
        c = {'whole_dumps': len(whole) >= 2, 'no_files': bool(whole) and not whole[-1]['files'],
             'kmsg_present': bool(whole) and whole[-1]['kmsg']['sha256_ok'],
             'crlf_command_accepted': (r['reboot_request'] or '').startswith('bootloader')}
        record('4_empty_pstore', r, c)

        # The capture tool's parser on a cut stream and on a flipped byte.
        stream = r['stream']
        parsed = PARSE['parse_stream'](stream[:len(stream) - 100])
        checks['parser.cut_stream_last_dump_not_whole'] = bool(parsed) and not parsed[-1]['whole']
        flipped = bytearray(stream)
        k = flipped.find(b'kernel: early line before /init')
        flipped[k] ^= 1
        parsed = PARSE['parse_stream'](bytes(flipped))
        checks['parser.flipped_byte_fails_sha256'] = any((d['problem'] or '').startswith('sha256 mismatch') for d in parsed)

    passed = all(checks.values())
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps({
        'state': 'Host test under qemu-user with a fake tree; not run on the phone',
        'passed': passed, 'qemu': qemu, 'compile_command': command, 'reader_source_sha256': source_sha,
        'test_binary': str(binary), 'checks': checks, 'scenarios': results,
        'limits': ['Mounts, mknod and the watchdog are compiled out of the test build; restarts write a file',
                   'configfs, kmsg and pstore are plain files and directories here; the ACM tty is a pty, so USB '
                   'hang-up and reconnect (gserial) are from source reading only',
                   'Real kmsg ends a read with EAGAIN; the fake one is a file that ends with EOF',
                   'Whether the v11 kernel keeps the last boot\'s records in ramoops is not shown here'],
        'device_accessed': False}, indent=2) + '\n')
    failed = [k for k, v in checks.items() if not v]
    print('%d checks: %s' % (len(checks), 'all passed' if passed else 'FAILED ' + ', '.join(failed)))
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
