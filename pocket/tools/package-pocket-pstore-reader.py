#!/usr/bin/env python3
"""Build the pstore reader recovery image: the v11 diagnostic image with only its ramdisk replaced.

Offline only: never stages, flashes or talks to a device. Compiles
kernel-upgrade/pstore-reader/init.c (static aarch64, the NDK clang and flags of
build-pocket-firstboot-ramdisk.py), packs it as /init in a gzip newc ramdisk with dev, proc and sys,
and repacks v11's recovery.img with package-pocket-bisect.py's helpers: same mkbootimg arguments,
so kernel, DT, recovery_dtbo, cmdline and every other header field stay v11's, and the AVB footer
v11 has (partition `recovery`, 32 MiB, salt = payload sha256). The checks are bisect's
check_candidate with the ramdisk as the one changed component, plus rules on the reader source.

Writes the bulk artifacts/pstore-reader/recovery.img and recovery.img.json, and
evidence/kernel-upgrade/pstore-reader/summary.json. --self-test only runs the refusal cases.
"""
import pocket_paths
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import runpy
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
OUT = BULK / 'artifacts/pstore-reader'
EVIDENCE = ROOT / 'evidence/kernel-upgrade/pstore-reader'
SOURCE = ROOT / 'kernel-upgrade/pstore-reader/init.c'
COMMANDS = ROOT / 'kernel-upgrade/ram-probe/commands.h'
CLANG = str(pocket_paths.ndk_bin() / 'clang')
FLAGS = ['--target=aarch64-linux-android30', '-static', '-Os', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=sha1']
LABEL = 'TP510-PSTORE'
RECOVERY_SIZE = 0x2000000      # 32 MiB recovery partition, as v11's footer
MOUNT_TYPES = {'proc', 'sysfs', 'devtmpfs', 'pstore', 'tmpfs', 'configfs'}
DEV_LITERALS = {'/dev', '/dev/kmsg', '/dev/watchdog0'}

_bisect = None


def bisect():
    """package-pocket-bisect.py's helpers, loaded on first use (it checks v11's and v2's hashes)."""
    global _bisect
    if _bisect is None:
        _bisect = runpy.run_path(str(ROOT / 'tools/package-pocket-bisect.py'))
    return _bisect


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_source(text):
    """Problems with the reader source: block devices, writes to pstore, extra mounts, other commands."""
    problems = []
    rules = [(r'/dev/(block|sd[a-z]|mmcblk|nvme|loop|dm-|mapper)|by-name', 'names a block device'),
             (r'\bBLK[A-Z]+', 'uses a block device request'),
             (r'\b(system|popen|posix_spawnp?|fexecve|execl[pe]?|execvp?e?|execv)\s*\(', 'runs other commands'),
             (r'MS_REMOUNT|MS_BIND|MS_MOVE', 'remounts, binds or moves a mount'),
             (r'\bunlink(at)?\s*\(|\brmdir\s*\(|\bumount', 'removes files, directories or mounts')]
    for pattern, message in rules:
        if re.search(pattern, text):
            problems.append(message)
    for line in text.splitlines():
        code = line.split('//')[0]
        if re.search(r'(?<![\w.])mount\s*\(', code) and not code.startswith('#define fs_mount('):
            problems.append('calls mount() outside the fs_mount macro')
        if 'mknod' in code and 'S_IFCHR' not in code and not code.lstrip().startswith('#'):
            problems.append('makes a node that is not a character device')
        if 'O_RDWR' in code and 'tty_name' not in code:
            problems.append('opens something other than the ACM tty read-write')
        if re.search(r'\bioctl\s*\(', code) and 'WDIOC_' not in code:
            problems.append('ioctl other than the watchdog')
        if re.search(r'\bsyscall\s*\(', code) and 'SYS_reboot' not in code:
            problems.append('raw syscall other than reboot')
    for literal in re.findall(r'"(/dev[^"]*)"', text):
        if literal not in DEV_LITERALS:
            problems.append('names %s' % literal)
    mounts = re.findall(r'fs_mount\(\s*"[^"]*"\s*,[^,]*,\s*"([^"]*)"\s*,([^)]*)\)', text)
    for kind, flags in mounts:
        if kind not in MOUNT_TYPES:
            problems.append('mounts %s' % kind)
        if kind == 'pstore' and 'MS_RDONLY' not in flags:
            problems.append('pstore not mounted read-only')
    if 'pstore' not in [k for k, _ in mounts]:
        problems.append('no pstore mount')
    if '"' + LABEL + '"' not in text:
        problems.append('USB serial is not ' + LABEL)
    return sorted(set(problems))


def compile_reader(output, test=False):
    source_sha = sha(SOURCE.read_bytes())
    command = [CLANG, *FLAGS, '-DREADER_SOURCE_SHA256="%s"' % source_sha,
               *(['-DPSTORE_HOST_TEST'] if test else []), str(SOURCE), '-o', str(output)]
    subprocess.run(command, check=True)
    return command, Path(output).read_bytes(), source_sha


def check_binary(binary, source_sha):
    if binary[:5] != b'\x7fELF\x02' or struct.unpack_from('<HH', binary, 16) != (2, 183):
        raise Refused('init is not a static aarch64 ET_EXEC')
    offset = struct.unpack_from('<Q', binary, 32)[0]
    size, count = struct.unpack_from('<HH', binary, 54)
    if any(struct.unpack_from('<I', binary, offset + i * size)[0] == 3 for i in range(count)):
        raise Refused('init has an interpreter')
    if (LABEL + ' pstore reader init; reader-source-sha256=' + source_sha).encode() not in binary:
        raise Refused('init has no reader marker for this source')
    if b'PSTORE_HOST_TEST_BUILD' in binary:
        raise Refused('init is the host test build')


def ramdisk(binary):
    """gzip newc cpio with dev, proc, sys and /init, the layout of build-upgrade-ramdisk.py."""
    entry = runpy.run_path(str(ROOT / 'tools/build-upgrade-ramdisk.py'))['entry']
    archive = io.BytesIO()
    for i, name in enumerate(['dev', 'proc', 'sys'], 1):
        entry(archive, name, b'', stat.S_IFDIR | 0o755, i)
    entry(archive, 'init', binary, stat.S_IFREG | 0o755, 4)
    entry(archive, 'TRAILER!!!', b'', 0, 5)
    raw = archive.getvalue()
    members = cpio_members(raw)
    if members != {'dev': (stat.S_IFDIR | 0o755, b''), 'proc': (stat.S_IFDIR | 0o755, b''),
                   'sys': (stat.S_IFDIR | 0o755, b''), 'init': (stat.S_IFREG | 0o755, binary)}:
        raise Refused('ramdisk members are not dev, proc, sys and init')
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    if gzip.decompress(compressed) != raw:
        raise Refused('gzip round trip')
    return raw, compressed


def cpio_members(raw):
    pos, members = 0, {}
    while pos < len(raw):
        if raw[pos:pos + 6] != b'070701':
            raise Refused('bad cpio record at %d' % pos)
        fields = [int(raw[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        pos += 110
        name = raw[pos:pos + fields[11] - 1].decode()
        pos = (pos + fields[11] + 3) & ~3
        data = raw[pos:pos + fields[6]]
        pos = (pos + fields[6] + 3) & ~3
        if name == 'TRAILER!!!':
            break
        members[name] = (fields[1], data)
    return members


def build(rd, tmp):
    b = bisect()
    (tmp / 'src').mkdir(parents=True)
    v11_parts, v11_args, v11_header, v11_text, _, _ = b['load_sources'](tmp / 'src')
    parts = dict(v11_parts, ramdisk=rd)
    out, command = b['repack'](v11_args, parts, v11_header['cmdline'], tmp / 'repack')
    payload = out.read_bytes()
    footer = b['add_footer'](out)
    return out.read_bytes(), payload, [command, footer], (v11_parts, v11_header, v11_text)


def check(data, rd, v11, tmp):
    """bisect's check_candidate with the ramdisk the one component changed, then the ramdisk itself."""
    b = bisect()
    v11_parts, v11_header, v11_text = v11
    if b['PARTITION_SIZE'] != RECOVERY_SIZE or b['AVB_NAME'] != 'recovery':
        raise Refused('bisect helpers no longer footer for a 32 MiB recovery partition')
    result = b['check_candidate'](data, 'ramdisk', v11_parts, v11_header, v11_text, {'ramdisk': rd}, v11_header, tmp)
    checks = result['results']
    unpacked = Path(tmp) / 'unpacked' / 'ramdisk'
    raw = gzip.decompress(unpacked.read_bytes())
    members = cpio_members(raw)
    binary = members.get('init', (0, b''))[1]
    check_binary(binary, sha(SOURCE.read_bytes()))
    checks.append({'check': 'ramdisk is dev, proc, sys and the reader init', 'pass': set(members) == {'dev', 'proc', 'sys', 'init'},
                   'detail': sha(binary)})
    if set(members) != {'dev', 'proc', 'sys', 'init'}:
        raise Refused('ramdisk members %s' % sorted(members))
    # Compare the unpacked image with v11's own components and cmdline.
    header = result['header']
    same = {n: (Path(tmp) / 'unpacked' / n).read_bytes() == v11_parts[n] for n in ['kernel', 'dtb', 'recovery_dtbo']}
    same['cmdline'] = header['cmdline'] == v11_header['cmdline'] and header['extra_cmdline'] == v11_header['extra_cmdline']
    checks.append({'check': 'kernel, dtb, recovery_dtbo and cmdline are v11', 'pass': all(same.values()),
                   'detail': ', '.join('%s=%s' % kv for kv in same.items())})
    if not all(same.values()):
        raise Refused('not v11: ' + ', '.join(k for k, v in same.items() if not v))
    return result


def run(write=True):
    target = OUT / 'recovery.img'
    if write and target.exists():
        raise Refused('%s exists; refusing to overwrite' % target)
    problems = check_source(SOURCE.read_text())
    if problems:
        raise Refused('reader source: ' + '; '.join(problems))
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        tmp = Path(tmp)
        init = tmp / 'init'
        command, binary, source_sha = compile_reader(init)
        check_binary(binary, source_sha)
        raw, rd = ramdisk(binary)
        data, payload, commands, v11 = build(rd, tmp / 'build')
        result = check(data, rd, v11, tmp / 'check')
        test = self_test(tmp / 'self-test')
        v11_parts, v11_header, _ = v11
        record = {
            'state': 'Packaged offline; not staged, flashed or boot-tested',
            'purpose': 'recovery image that streams the pstore files of the previous boot over ACM, for the first-boot loop',
            'output': {'path': str(target), 'bytes': len(data), 'sha256': sha(data)},
            'payload': {'bytes': len(payload), 'sha256': sha(payload)},
            'base': {'path': str(bisect()['V11']), 'sha256': bisect()['V11_SHA']},
            'changed_from_v11': 'ramdisk only',
            'components': {n: {'sha256': sha(c), 'bytes': len(c), 'from': 'pstore reader' if n == 'ramdisk' else 'v11'}
                           for n, c in dict(v11_parts, ramdisk=rd).items()},
            'ramdisk': {'cpio_bytes': len(raw), 'cpio_sha256': sha(raw), 'members': ['dev', 'proc', 'sys', 'init'],
                        'compression': 'gzip -9, mtime 0'},
            'init': {'bytes': len(binary), 'sha256': sha(binary), 'source': str(SOURCE.relative_to(ROOT)),
                     'source_sha256': source_sha, 'commands_h_sha256': sha(COMMANDS.read_bytes()),
                     'compile_command': command},
            'usb_identity': {'vid': '1d6b', 'pid': '0104', 'serial': LABEL},
            'behaviour': {'mounts': 'proc, sysfs, devtmpfs, then pstore read-only at /sys/fs/pstore, tmpfs at /pstore-copy, configfs',
                          'block_devices': 'none opened, none mounted',
                          'dump_interval_seconds': 10, 'return_timer_seconds': 300, 'return_target': 'bootloader',
                          'watchdog_userspace_ping_seconds': 330, 'acm_commands': ['reboot', 'reboot-bootloader'],
                          'raw_ramoops_region': 'not streamed; v11 kernel has CONFIG_DEVMEM off'},
            'cmdline': v11_header['cmdline'],
            'header': result['header'], 'arm64': result['arm64'], 'regions': result['regions'],
            'reserved_ranges_checked': result['reserved_ranges_checked'], 'avb': result['avb'],
            'avbtool': {k: v['returncode'] for k, v in result['avbtool'].items()},
            'checks': result['results'], 'source_rules': 'check_source found no problems',
            'self_test': test, 'commands': commands,
            'tools_sha256': {str(p): sha(Path(p).read_bytes()) for p in
                             [Path(__file__), ROOT / 'tools/package-pocket-bisect.py', bisect()['MKBOOTIMG'],
                              bisect()['AVBTOOL'], bisect()['UNPACK']]},
            'limits': ['Whether the v11 kernel finds the loop boot\'s records in ramoops (same region and sizes in both '
                       'kernels, ecc 0) is only known from a trial',
                       'The 5.10 kernel has no reboot-mode driver, so the bootloader restart most likely ends as a plain '
                       'reset into `boot`; the owner may need the keys to reach fastboot'],
            'device_accessed': False,
        }
        if write:
            target.write_bytes(data)
            (OUT / 'recovery.img.json').write_text(json.dumps(record, indent=2) + '\n')
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            summary = {k: record[k] for k in ['state', 'output', 'payload', 'base', 'changed_from_v11', 'init',
                                              'usb_identity', 'behaviour', 'cmdline', 'limits', 'device_accessed']}
            summary['checks_passed'] = sum(c['pass'] for c in record['checks'])
            summary['self_test'] = {'cases': len(test['cases']), 'all_refused_or_accepted_as_expected': True}
            summary['record'] = str(OUT / 'recovery.img.json')
            (EVIDENCE / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        return record


def self_test(tmp):
    """Images and sources the checks must refuse, and the built one they must accept."""
    tmp = Path(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    b = bisect()
    cases = []
    command, binary, source_sha = compile_reader(tmp / 'init')
    _, rd = ramdisk(binary)
    data, _, _, v11 = build(rd, tmp / 'good')
    v11_parts, v11_header, _ = v11
    v11_args = b['unpack'](b['V11'], tmp / 'args')[1]

    def image(parts, cmdline, label):
        out, _ = b['repack'](v11_args, parts, cmdline, tmp / ('repack-' + label))
        b['add_footer'](out)
        return out.read_bytes()

    test_rd = ramdisk(compile_reader(tmp / 'init-test', test=True)[1])[1]
    other = dict(v11_parts)
    images = [('built image', data, True),
              ('v11 itself (ramdisk not replaced)', b['V11'].read_bytes(), False),
              # Checked against its own ramdisk, so only the /init checks can refuse it.
              ('host test build as /init', image(dict(v11_parts, ramdisk=test_rd), v11_header['cmdline'], 'test'), False, test_rd),
              ('cmdline changed as well', image(dict(v11_parts, ramdisk=rd), v11_header['cmdline'] + ' x=1', 'cmdline'), False),
              ('dtb changed as well', image(dict(other, ramdisk=rd, dtb=v11_parts['dtb'] + bytes(16)), v11_header['cmdline'], 'dtb'), False),
              ('image not the partition size', data[:-4096], False)]
    p = tmp / 'case-name.img'
    payload = b['payload_of'](data)[0]
    p.write_bytes(payload)
    subprocess.run([sys.executable, '-B', str(b['AVBTOOL']), 'add_hash_footer', '--image', str(p), '--partition_name',
                    'boot', '--partition_size', str(RECOVERY_SIZE), '--algorithm', 'NONE', '--hash_algorithm', 'sha256',
                    '--salt', sha(payload), '--rollback_index', '0'], check=True)
    images.append(('avb partition name boot', p.read_bytes(), False))
    for i, (label, img, expect, *own) in enumerate(images):
        try:
            check(img, own[0] if own else rd, v11, tmp / ('c%d' % i))
            accepted, reason = True, ''
        except (Refused, b['Refused'], AssertionError, subprocess.CalledProcessError, struct.error, KeyError, OSError) as e:
            accepted, reason = False, str(e)[:200]
        cases.append({'case': label, 'expect_accept': expect, 'accepted': accepted, 'reason': reason, 'pass': accepted == expect})
    text = SOURCE.read_text()
    for label, change in [
            ('source: pstore mounted read-write', lambda t: t.replace('"pstore", MS_RDONLY | ', '"pstore", ')),
            ('source: ext4 mount', lambda t: t + '\nstatic void x(void) { fs_mount("a", "b", "ext4", 0, NULL); }\n'),
            ('source: names /dev/block', lambda t: t + '\n// "/dev/block/by-name/userdata"\nstatic const char *y = "/dev/block/sdc";\n'),
            ('source: block ioctl', lambda t: t + '\nstatic void z(int f) { ioctl(f, BLKGETSIZE64, 0); }\n'),
            ('source: unlinks a pstore file', lambda t: t + '\nstatic void w(void) { unlink("/sys/fs/pstore/x"); }\n'),
            ('source: opens kmsg read-write', lambda t: t + '\nstatic int v(void) { return open("/dev/kmsg", O_RDWR); }\n'),
            ('source: other serial', lambda t: t.replace('"' + LABEL + '"', '"TP510-OTHER"'))]:
        problems = check_source(change(text))
        cases.append({'case': label, 'expect_accept': False, 'accepted': not problems, 'reason': '; '.join(problems),
                      'pass': bool(problems)})
    cases.append({'case': 'source as written', 'expect_accept': True, 'accepted': not check_source(text),
                  'reason': '; '.join(check_source(text)), 'pass': not check_source(text)})
    failed = [c for c in cases if not c['pass']]
    if failed:
        raise Refused('self-test: %s' % failed)
    return {'cases': cases, 'passed': len(cases)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--self-test', action='store_true', help='only run the refusal cases; write nothing')
    args = parser.parse_args()
    try:
        if args.self_test:
            OUT.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=OUT) as tmp:
                result = self_test(Path(tmp))
            for c in result['cases']:
                print('%-4s %s%s' % ('ok' if c['pass'] else 'FAIL', c['case'], ' (' + c['reason'] + ')' if c['reason'] else ''))
            print('self-test: %d cases' % result['passed'])
            return
        record = run()
    except (Refused, bisect()['Refused']) as e:
        print('refused: ' + str(e), file=sys.stderr)
        sys.exit(2)
    print('recovery.img', record['output']['sha256'], '%d bytes' % record['output']['bytes'])
    print('checks passed: %d; self-test cases: %d' % (sum(c['pass'] for c in record['checks']), record['self_test']['passed']))
    print('record: ' + str(OUT / 'recovery.img.json'))


if __name__ == '__main__':
    main()
