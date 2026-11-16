#!/usr/bin/env python3
"""Build bisect candidate E: the v2 first-boot boot.img with androidboot.init_fatal_panic=true added.

Offline only: never stages, flashes or talks to a device. v2 is unpacked and repacked with its own
mkbootimg arguments (package-pocket-bisect.py's unpack and repack) and only the cmdline changed,
then footered as v2 is (partition `boot`, 32 MiB, salt = payload sha256). Repacking v2 with nothing
changed must give v2 back byte for byte first.

Why: Android 16 first-stage init reads androidboot.init_fatal_panic from /proc/cmdline
(system/core/init/reboot_utils.cpp SetFatalRebootTarget, called from InitKernelLogging). With it,
InitFatalReboot writes `c` to /proc/sysrq-trigger (CONFIG_MAGIC_SYSRQ=y in the first-boot kernel),
so a fatal init error becomes a kernel panic that ramoops keeps as a dmesg record, and panic=10
adds about 10 s to the cycle. Without it init restarts at once with target `bootloader`.

Writes the bulk artifacts/bisect-v2/E/boot.img and boot.img.json. --self-test runs the refusal cases.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
B = runpy.run_path(str(ROOT / 'tools/package-pocket-bisect.py'))
OUT = B['OUT'] / 'E'
V2, V2_SHA = B['V2'], B['V2_SHA']
ADD = 'androidboot.init_fatal_panic=true'
PARTITION = 'boot'
PARTITION_SIZE = B['PARTITION_SIZE']
CMDLINE_FIELD = 512        # header v2 cmdline field, NUL included
Refused = B['Refused']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def footer(path):
    payload = path.read_bytes()
    command = [sys.executable, '-B', str(B['AVBTOOL']), 'add_hash_footer', '--image', str(path), '--partition_name',
               PARTITION, '--partition_size', str(PARTITION_SIZE), '--algorithm', 'NONE', '--hash_algorithm', 'sha256',
               '--salt', sha(payload), '--rollback_index', '0']
    subprocess.run(command, check=True)
    return command


def build(args, parts, cmdline, tmp):
    out, command = B['repack'](args, parts, cmdline, tmp)
    payload = out.read_bytes()
    avb = footer(out)
    return out.read_bytes(), payload, [command, avb]


def check(data, v2_parts, v2_header, v2_text, cmdline, tmp):
    """Every check on E: v2's components and header with only the cmdline different, v2's footer shape."""
    tmp.mkdir(parents=True)
    results = []

    def ok(name, cond, detail=''):
        results.append({'check': name, 'pass': bool(cond), 'detail': detail})
        if not cond:
            raise Refused('%s failed %s' % (name, detail))

    ok('partition size', len(data) == PARTITION_SIZE, '%d bytes' % len(data))
    payload, avb = B['payload_of'](data)
    path = tmp / 'e.img'
    path.write_bytes(data)
    parts, _, header = B['unpack'](path, tmp / 'unpacked')
    for name in B['COMPONENTS']:
        ok('round trip ' + name + ' equals v2', parts.get(name) == v2_parts.get(name), sha(parts.get(name, b'')))
    ok('cmdline is v2 plus ' + ADD, header['cmdline'] == cmdline and header['extra_cmdline'] == '', header['cmdline'])
    ok('cmdline fits the 512-byte header field', len(header['cmdline']) < CMDLINE_FIELD, '%d bytes' % len(header['cmdline']))
    ok(ADD + ' appears once', header['cmdline'].split().count(ADD) == 1
       and 'androidboot.init_fatal_reboot_target' not in header['cmdline'])
    ok('panic=10 kept', 'panic=10' in header['cmdline'].split())
    for field, value in v2_header.items():
        if field != 'cmdline':
            ok('header ' + field + ' equals v2', header[field] == value, '%r vs %r' % (header[field], value))
    arm64, regions, checked = B['placement'](header, parts['kernel'], parts['dtb'], parts['ramdisk'])
    ok('placement', True, 'kernel 0x%x image_size 0x%x' % (header['kernel_addr'], arm64['image_size']))
    d = avb['hash_descriptor']
    ok('avb partition name', d['partition_name'] == PARTITION, d['partition_name'])
    ok('avb salt is payload sha256', d['salt'] == sha(payload))
    ok('avb digest', d['digest'] == hashlib.sha256(bytes.fromhex(d['salt']) + payload).hexdigest())
    named = tmp / 'avb' / (PARTITION + '.img')
    named.parent.mkdir()
    named.write_bytes(data)
    ops = B['avb_ops'](named)
    ok('avbtool verify_image', ops['verify_image']['returncode'] == 0, ops['verify_image']['text'].strip())
    ok('avbtool info_image like v2', ops['info_image']['returncode'] == 0
       and B['avb_shape'](ops['info_image']['text']) == B['avb_shape'](v2_text))
    return {'results': results, 'header': header, 'avb': avb, 'arm64': arm64,
            'regions': [{'name': n, 'address': a, 'bytes': s} for n, a, s in regions], 'reserved_ranges_checked': checked}


def sources(tmp):
    if sha(V2.read_bytes()) != V2_SHA:
        raise Refused('%s does not match %s' % (V2, V2_SHA))
    parts, args, header = B['unpack'](V2, tmp / 'v2')
    text = B['avb_ops'](V2)['info_image']['text']
    if B['CHECK']['parse_avb'](V2.read_bytes())['hash_descriptor']['partition_name'] != PARTITION:
        raise Refused('v2 footer is not for partition boot')
    return parts, args, header, text


def run(write=True):
    if write and (OUT / 'boot.img').exists():
        raise Refused('%s exists; refusing to overwrite' % (OUT / 'boot.img'))
    B['OUT'].mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=B['OUT']) as tmp:
        tmp = Path(tmp)
        parts, args, header, text = sources(tmp)
        same, _, _ = build(args, parts, header['cmdline'], tmp / 'identity')
        if same != V2.read_bytes():
            raise Refused('repacking v2 with nothing changed does not reproduce v2')
        cmdline = header['cmdline'] + ' ' + ADD
        data, payload, commands = build(args, parts, cmdline, tmp / 'e')
        result = check(data, parts, header, text, cmdline, tmp / 'check')
        test = self_test(tmp / 'self-test', parts, args, header, text)
        record = {
            'state': 'Packaged offline; not staged, flashed or boot-tested',
            'candidate': 'E', 'partition': PARTITION,
            'changed_from_v2': {'component': 'cmdline', 'added': ADD},
            'identity_repack_reproduces_v2': True,
            'output': {'path': str(OUT / 'boot.img'), 'bytes': len(data), 'sha256': sha(data)},
            'payload': {'bytes': len(payload), 'sha256': sha(payload)},
            'source': {'path': str(V2), 'sha256': V2_SHA},
            'cmdline': {'v2': header['cmdline'], 'E': cmdline, 'bytes': len(cmdline)},
            'kernel_cmdline_room': 'v11 trial kernel log: LK-built cmdline about 990 bytes with a 260-byte header '
                                   'cmdline; E adds %d bytes over v2 (%d header bytes), well under the 2048-byte '
                                   'arm64 COMMAND_LINE_SIZE and LK 0x800 buffer' % (len(ADD) + 1, len(cmdline)),
            'components': {n: {'sha256': sha(c), 'bytes': len(c), 'from': 'v2'} for n, c in parts.items()},
            'header': result['header'], 'arm64': result['arm64'], 'regions': result['regions'],
            'reserved_ranges_checked': result['reserved_ranges_checked'], 'avb': result['avb'],
            'checks': result['results'], 'self_test': test, 'commands': commands,
            'init_source_finding': {
                'source': 'system/core/init in the platform source (android-16.0.0_r4 base, '
                          'lineage-23.2); the bulk product-source view was empty here',
                'reads_from': '/proc/cmdline first; /proc/bootconfig only when the key is absent from the cmdline '
                              '(reboot_utils.cpp SetFatalRebootTarget). Header v2 has no bootconfig, so the cmdline is the path',
                'when': 'InitKernelLogging (util.cpp), right after first-stage init mounts /proc and makes /dev/kmsg '
                        'and /dev/null; LOG(FATAL) from then on goes InitAborter -> InitFatalReboot(SIGABRT)',
                'effect': 'init_fatal_panic: unwind, then write "c" to /proc/sysrq-trigger (kernel panic); a forked child '
                          'still restarts with the target after 5 s if that fails. Without it: RESTART2 with the target',
                'default_target': 'bootloader (init_fatal_reboot_target), unless androidboot.init_fatal_reboot_target is set',
                'sysrq': 'first-boot kernel CONFIG_MAGIC_SYSRQ=y; writes to /proc/sysrq-trigger skip the sysrq_enable mask',
                'not_covered': 'a failure before InitKernelLogging (stdio to /dev/null) or an exec failure of /init.android '
                               '(the wrapper then exits, which panics the kernel anyway)',
                'reboot_reason_on_5_10': 'ignored: CONFIG_REBOOT_MODE, SYSCON_REBOOT_MODE and NVMEM_REBOOT_MODE are off, '
                                         'no reboot-mode node in the DT, and the two restart handlers (psci_sys_reset, '
                                         'priority 129, and mtk_wdt_restart, 128) do not look at the command, so '
                                         '"bootloader" is a plain reset into a normal boot'},
            'tools_sha256': {str(p): sha(Path(p).read_bytes()) for p in
                             [Path(__file__), ROOT / 'tools/package-pocket-bisect.py', B['MKBOOTIMG'], B['AVBTOOL'], B['UNPACK']]},
            'device_accessed': False,
        }
        if write:
            OUT.mkdir(parents=True, exist_ok=True)
            (OUT / 'boot.img').write_bytes(data)
            (OUT / 'boot.img.json').write_text(json.dumps(record, indent=2) + '\n')
        return record


def self_test(tmp, parts, args, header, text):
    tmp.mkdir(parents=True)
    cmdline = header['cmdline'] + ' ' + ADD
    good, _, _ = build(args, parts, cmdline, tmp / 'good')
    cases = [('E as built', good, True)]
    cases.append(('v2 itself (no flag)', V2.read_bytes(), False))
    bad, _, _ = build(args, parts, header['cmdline'] + ' androidboot.init_fatal_panic=false', tmp / 'false')
    cases.append(('flag set to false', bad, False))
    bad, _, _ = build(args, parts, cmdline + ' ' + ADD, tmp / 'twice')
    cases.append(('flag twice', bad, False))
    bad, _, _ = build(args, parts, cmdline.replace('panic=10', 'panic=0'), tmp / 'panic0')
    cases.append(('panic=10 changed', bad, False))
    bad, _, _ = build(args, dict(parts, ramdisk=parts['ramdisk'] + bytes(8)), cmdline, tmp / 'ramdisk')
    cases.append(('ramdisk changed as well', bad, False))
    payload = bytearray(B['payload_of'](good)[0])
    struct.pack_into('<I', payload, 44, 0)
    p = tmp / 'osversion.img'
    p.write_bytes(bytes(payload))
    footer(p)
    cases.append(('os_version changed as well', p.read_bytes(), False))
    p = tmp / 'recovery-name.img'
    p.write_bytes(B['payload_of'](good)[0])
    subprocess.run([sys.executable, '-B', str(B['AVBTOOL']), 'add_hash_footer', '--image', str(p), '--partition_name',
                    'recovery', '--partition_size', str(PARTITION_SIZE), '--algorithm', 'NONE', '--hash_algorithm',
                    'sha256', '--salt', sha(B['payload_of'](good)[0]), '--rollback_index', '0'], check=True)
    cases.append(('avb partition name recovery', p.read_bytes(), False))
    out = []
    for i, (label, data, expect) in enumerate(cases):
        try:
            check(data, parts, header, text, cmdline, tmp / ('c%d' % i))
            accepted, reason = True, ''
        except (Refused, AssertionError, subprocess.CalledProcessError, struct.error, KeyError) as e:
            accepted, reason = False, str(e)[:200]
        out.append({'case': label, 'expect_accept': expect, 'accepted': accepted, 'reason': reason, 'pass': accepted == expect})
    failed = [c for c in out if not c['pass']]
    if failed:
        raise Refused('self-test: %s' % failed)
    return {'cases': out, 'passed': len(out)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--self-test', action='store_true', help='only run the refusal cases; write nothing')
    a = parser.parse_args()
    try:
        if a.self_test:
            B['OUT'].mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=B['OUT']) as tmp:
                tmp = Path(tmp)
                parts, args, header, text = sources(tmp)
                result = self_test(tmp / 'self-test', parts, args, header, text)
            for c in result['cases']:
                print('%-4s %s%s' % ('ok' if c['pass'] else 'FAIL', c['case'], ' (' + c['reason'] + ')' if c['reason'] else ''))
            return
        record = run()
    except Refused as e:
        print('refused: ' + str(e), file=sys.stderr)
        sys.exit(2)
    print('E', record['output']['sha256'], record['cmdline']['E'])
    print('checks passed: %d; self-test cases: %d' % (sum(c['pass'] for c in record['checks']), record['self_test']['passed']))


if __name__ == '__main__':
    main()
