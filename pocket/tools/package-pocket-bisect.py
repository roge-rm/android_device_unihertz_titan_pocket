#!/usr/bin/env python3
"""Build the offline bisect candidates for the first-boot reset loop from the v11 and v2 images.

Offline only: never stages, flashes or talks to a device. Each candidate is the v11
diagnostic image (which boots from `boot`) with exactly one component taken from the
v2 first-boot boot.img:
  B  kernel (the first-boot Image.gz)
  C  DT table
  D  cmdline
and B2, B with the read-only v11 ramdisk (tools/build-pocket-v11ro-ramdisk.py). v11's own ramdisk
writes and restores the last 1 MiB of userdata, which must not run on the first-boot kernel, so B is
superseded by B2 and D is dropped (its cmdline change is inert). B, C and D are not rebuilt: they stay
on disk with a status in their JSON, and a run only builds B2 and refuses to overwrite it.
Both images are unpacked with unpack_bootimg.py and repacked with the same mkbootimg
arguments, so every other header field stays v11's. The AVB footer is added the way
package-pocket-diagnostic.py added v11's (partition name `recovery`, salt = payload
sha256), so the footer differs only in its digest and sizes.

--self-test runs the checks on broken candidates (wrong component swapped, misaligned
kernel, kernel running into the DT, oversized payload) and fails if any is accepted.
"""
import pocket_paths
import argparse
import gzip
import hashlib
import json
import os
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
OUT = BULK / 'artifacts/bisect-v2'
EVIDENCE = ROOT / 'evidence/kernel-upgrade/bisect-v2'
UNPACK = ROOT / 'tools/unpack_bootimg.py'
BOOT = runpy.run_path(str(ROOT / 'tools/package-pocket-boot.py'))
CHECK = runpy.run_path(str(ROOT / 'tools/check-pocket-boot-package.py'))
MKBOOTIMG = BOOT['MKBOOTIMG']
AVBTOOL = BOOT['AVBTOOL']

V11 = BULK / 'artifacts/diagnostic-5.10-v11/package/recovery.img'
V11_SHA = '3a669dae3485fbc83757fe3fdd839c1709f668acce255579449e7d672f1b6ebc'
V2 = BULK / 'artifacts/firstboot-5.10-v2/boot.img'
V2_SHA = '637ff0e3c7a2df6a3b40403bb456075855ea0d3213a64f4502949631b34977f3'
FB_KERNEL = BULK / 'kernel-firstboot-5.10/arch/arm64/boot/Image.gz'
FB_MAP = BULK / 'kernel-firstboot-5.10/System.map'
FB_CONFIG = BULK / 'kernel-firstboot-5.10/.config'
FB_BUILD = ROOT / 'evidence/kernel-upgrade/firstboot-kernel-build.json'
V11_MAP = BULK / 'kernel-diagnostic-5.10-v11/System.map'
V11_CONFIG = BULK / 'kernel-diagnostic-5.10-v11/.config'
LIVE_FDT = BOOT['LIVE_FDT']

PARTITION_SIZE = BOOT['PARTITION_SIZE']   # boot partition size the v2 packager uses
AVB_NAME = 'recovery'                      # what v11's footer carries; LK took it from `boot`
COMPONENTS = ['kernel', 'ramdisk', 'dtb', 'recovery_dtbo']
# Header fields that follow the component bytes and may change with a swap.
SIZE_FIELDS = {'kernel': ['kernel_size'], 'ramdisk': ['ramdisk_size'], 'dtb': ['dtb_size'],
               'recovery_dtbo': ['recovery_dtbo_size']}
OFFSET_FIELDS = ['recovery_dtbo_offset', 'payload_end']
CANDIDATES = {'B': 'kernel', 'C': 'dtb', 'D': 'cmdline', 'B2': 'kernel+ramdisk'}
BUILT_NOW = ['B2']
STATUS = {'B': 'superseded by B2: its v11 ramdisk writes and restores the last 1 MiB of userdata, which must not run '
               'on the first-boot kernel',
          'C': 'current',
          'D': 'dropped: the cmdline change is inert (rdinit=/init and watchdog.open_timeout=90 are defaults here)',
          'B2': 'current: v11 + first-boot kernel + read-only v11 ramdisk (serial TP510-RAM-V11RO)'}
V11RO_TOOL = ROOT / 'tools/build-pocket-v11ro-ramdisk.py'
V11RO_RAMDISK = OUT / 'ramdisk-v11ro/ramdisk.cpio.gz'

# v11 required list from package-pocket-diagnostic.py (v2+, v5+ and v10+ entries), then what the
# v11 /init touches before ACM enumerates and after: devtmpfs, configfs gadget with ACM, watchdog,
# ramoops, i2c-dev, gpio cdev, dm ioctl.
REQUIRED_V11 = ['mt6771_pinctrl_probe', 'pwrap_probe', 'mt6397_probe', 'mt6358_irq_init',
                'mt6358_regulator_probe', 'mtk_sysirq_of_init', 'gic_of_init', 'arch_timer_of_init',
                'psci_sys_reset', 'mtu3_probe', 'mtk_usb_phy_probe', 'ramoops_probe', 'mtk_wdt_probe',
                'ufshcd_pltfrm_init', 'ufs_mtk_phy_probe', 'tee_core_init', 'dm_linear_init', 'ext4_init_fs']
REQUIRED_INIT = {'populate_rootfs': 'before /init', 'devtmpfs_init': 'before ACM', 'configfs_init': 'before ACM',
                 'gadgets_make': 'before ACM', 'configfs_composite_bind': 'before ACM',
                 'acm_alloc_instance': 'before ACM', 'acm_alloc_func': 'before ACM',
                 'gserial_alloc_line': 'before ACM', 'gs_open': 'before ACM',
                 'usb_gadget_probe_driver': 'before ACM', 'watchdog_dev_init': 'watchdog ping',
                 'persistent_ram_new': 'ramoops', 'mtk_i2c_probe': 'I2C ID probe',
                 'i2cdev_attach_adapter': 'I2C ID probe (/dev/i2c-N)',
                 'gpiolib_cdev_register': 'GPIO 178 reset pulse', 'dm_ctl_ioctl': 'super mount test'}
CONFIG_WATCH = ['WATCHDOG_OPEN_TIMEOUT', 'WATCHDOG_HANDLE_BOOT_ENABLED', 'PREEMPT', 'PREEMPT_NONE',
                'USB_CONFIGFS_UEVENT', 'I2C_CHARDEV', 'MODULES', 'TRUSTKERNEL_TEE_DIAGNOSTIC_LOGGER',
                'RANDOMIZE_BASE', 'PANIC_TIMEOUT', 'CMDLINE', 'LSM']


Refused = BOOT['Refused']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(image, tmp):
    """Unpack with unpack_bootimg.py; return components, mkbootimg args and the parsed header."""
    tmp.mkdir()
    args = subprocess.run([sys.executable, '-B', str(UNPACK), '--boot_img', str(image), '--out', str(tmp),
                           '--format', 'mkbootimg', '-0'], check=True, capture_output=True).stdout
    args = [a.decode() for a in args.rstrip(b'\0\n').split(b'\0')]
    parts = {n: (tmp / n).read_bytes() for n in COMPONENTS if (tmp / n).exists()}
    header, _ = CHECK['parse_boot'](Path(image).read_bytes())
    return parts, args, header


def payload_of(data):
    avb = CHECK['parse_avb'](data)
    return data[:avb['original_image_size']], avb


def repack(args, parts, cmdline, tmp):
    """mkbootimg with v11's arguments, component files swapped for `parts` and the given cmdline."""
    tmp.mkdir()
    a = list(args)
    for name in COMPONENTS:
        flag = '--' + name
        if flag in a:
            path = tmp / name
            path.write_bytes(parts[name])
            a[a.index(flag) + 1] = str(path)
    a[a.index('--cmdline') + 1] = cmdline
    out = tmp / 'boot.img'
    command = [sys.executable, '-B', str(MKBOOTIMG)] + a + ['--output', str(out)]
    subprocess.run(command, check=True)
    return out, command


def add_footer(path):
    payload = path.read_bytes()
    command = [sys.executable, '-B', str(AVBTOOL), 'add_hash_footer', '--image', str(path),
               '--partition_name', AVB_NAME, '--partition_size', str(PARTITION_SIZE), '--algorithm', 'NONE',
               '--hash_algorithm', 'sha256', '--salt', sha(payload), '--rollback_index', '0']
    subprocess.run(command, check=True)
    return command


def avb_ops(path):
    out = {}
    for op in ['info_image', 'verify_image']:
        p = subprocess.run([sys.executable, '-B', str(AVBTOOL), op, '--image', str(path)], capture_output=True, text=True)
        out[op] = {'returncode': p.returncode, 'text': p.stdout + p.stderr}
    return out


def avb_shape(text):
    """info_image lines without the values a component swap must change."""
    vary = ('Original image size:', 'VBMeta offset:', 'Image Size:', 'Salt:', 'Digest:')
    return [line for line in text.splitlines() if not line.strip().startswith(vary)]


def placement(header, kernel, dtb, ramdisk):
    """The placement rules package-pocket-boot.py asserts, with the kernel at its image_size too."""
    load = header['kernel_addr']
    arm64 = BOOT['check_arm64'](BOOT['inflate_kernel'](kernel), load)
    if header['tags_addr'] != BOOT['DTB_ADDR'] or header['dtb_addr'] != BOOT['DTB_ADDR']:
        raise Refused('DT address is not the stock 0x54000000')
    if header['ramdisk_addr'] != BOOT['RAMDISK_ADDR']:
        raise Refused('ramdisk address is not the stock 0x55000000')
    if len(ramdisk) > BOOT['RAMDISK_MAX']:
        raise Refused('ramdisk is over the 16 MiB LK reservation')
    if header['dtb_addr'] + len(dtb) > header['ramdisk_addr']:
        raise Refused('DT table runs into the ramdisk address')
    regions = [('kernel image_size', load, arm64['image_size']),
               ('kernel reservation', load, BOOT['KERNEL_RESERVE']),
               ('dtb', header['dtb_addr'], max(BOOT['DTB_RESERVE_MIN'], len(dtb))),
               ('ramdisk', header['ramdisk_addr'], len(ramdisk)),
               ('ramdisk reservation', header['ramdisk_addr'], BOOT['RAMDISK_MAX'])]
    for i, (a_name, a, a_size) in enumerate(regions):
        for b_name, b, b_size in regions[i + 1:]:
            if a_name.split()[0] == b_name.split()[0]:
                continue
            if not (a + a_size <= b or b + b_size <= a):
                raise Refused('%s and %s overlap' % (a_name, b_name))
    blob = runpy.run_path(str(ROOT / 'tools/prepare-upgrade-boot-layout.py'))['parse_table'](dtb)['entries'][0]['blob']
    checked = []
    for source, fdt in [('live-stock', LIVE_FDT.read_bytes()), ('candidate-dtb', blob)]:
        for name, start, size in BOOT['reserved_ranges'](fdt):
            for region, address, count in regions:
                if not (address + count <= start or start + size <= address):
                    raise Refused('%s overlaps %s %s' % (region, source, name))
            checked.append([source, name, start, size])
    return arm64, regions, checked


def ro_ramdisk_check(ramdisk):
    """The ramdisk is dev, proc, sys and an init with the RO serial and none of the userdata write test."""
    tool = runpy.run_path(str(V11RO_TOOL))
    raw = gzip.decompress(ramdisk)
    pos, members = 0, {}
    while pos < len(raw):
        fields = [int(raw[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        pos += 110
        name = raw[pos:pos + fields[11] - 1].decode()
        pos = (pos + fields[11] + 3) & ~3
        members[name] = raw[pos:pos + fields[6]]
        pos = (pos + fields[6] + 3) & ~3
        if name == 'TRAILER!!!':
            break
    init = members.get('init', b'')
    problems = tool['check_binary'](init)
    if tool['LABEL'].encode() not in init:
        problems.append('init lacks serial ' + tool['LABEL'])
    if b'TP510-RAM-V11:' in init:
        problems.append('init still has the v11 serial')
    if problems:
        raise Refused('ramdisk is not the read-only v11 one: ' + '; '.join(problems))


def check_candidate(data, intent, v11_parts, v11_header, v11_avb_text, donor_parts, donor_header, tmp):
    """Every check on one footered candidate. `intent` is the one component taken from the donor."""
    tmp.mkdir(parents=True)
    results = []

    def ok(name, cond, detail=''):
        results.append({'check': name, 'pass': bool(cond), 'detail': detail})
        if not cond:
            raise Refused('%s failed %s' % (name, detail))

    ok('partition size', len(data) == PARTITION_SIZE, '%d bytes' % len(data))
    payload, avb = payload_of(data)
    ok('payload leaves room for the footer', len(payload) + 0x10000 <= PARTITION_SIZE)
    ok('partition within LK 128 MiB stage limit', PARTITION_SIZE <= BOOT['LK_STAGE_MAX'])
    path = tmp / 'candidate.img'
    path.write_bytes(data)
    parts, _, header = unpack(path, tmp / 'unpacked')
    intended = dict(v11_parts)
    cmdline = v11_header['cmdline']
    changed = intent.split('+')
    if intent == 'cmdline':
        cmdline = donor_header['cmdline']
    else:
        for name in changed:
            intended[name] = donor_parts[name]
    for name in COMPONENTS:
        ok('round trip ' + name, parts.get(name) == intended[name], sha(parts.get(name, b'')))
    ok('cmdline', header['cmdline'] == cmdline and header['extra_cmdline'] == '', header['cmdline'])
    allowed = set(OFFSET_FIELDS)
    for name in changed:
        allowed |= set(SIZE_FIELDS.get(name, []))
    if intent == 'cmdline':
        allowed |= {'cmdline'}
    for field, value in v11_header.items():
        if field not in allowed:
            ok('header ' + field + ' equals v11', header[field] == value, '%r vs %r' % (header[field], value))
    ok('payload ends where the header says', payload_of(data)[1]['original_image_size'] == header['payload_end'])
    if intent == 'kernel+ramdisk':
        ro_ramdisk_check(parts['ramdisk'])
        ok('ramdisk is the read-only v11 one', True, sha(parts['ramdisk']))
    arm64, regions, checked = placement(header, parts['kernel'], parts['dtb'], parts['ramdisk'])
    ok('placement', True, 'kernel 0x%x image_size 0x%x' % (header['kernel_addr'], arm64['image_size']))
    d = avb['hash_descriptor']
    ok('avb partition name', d['partition_name'] == AVB_NAME, d['partition_name'])
    ok('avb salt is payload sha256', d['salt'] == sha(payload))
    ok('avb digest', d['digest'] == hashlib.sha256(bytes.fromhex(d['salt']) + payload).hexdigest())
    # verify_image looks for <partition name>.img beside the image, so check a copy named after the footer.
    named = tmp / 'avb' / (AVB_NAME + '.img')
    named.parent.mkdir()
    named.write_bytes(data)
    ops = avb_ops(named)
    ok('avbtool verify_image', ops['verify_image']['returncode'] == 0, ops['verify_image']['text'].strip())
    ok('avbtool info_image like v11', ops['info_image']['returncode'] == 0
       and avb_shape(ops['info_image']['text']) == avb_shape(v11_avb_text))
    return {'results': results, 'arm64': arm64, 'regions': [{'name': n, 'address': a, 'bytes': s} for n, a, s in regions],
            'reserved_ranges_checked': checked, 'header': header, 'avb': avb, 'avbtool': ops}


def symbols(path):
    return {line.split()[-1] for line in Path(path).read_text().splitlines() if line.strip()}


def config_values(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        for option in CONFIG_WATCH:
            if line.startswith('CONFIG_%s=' % option):
                out[option] = line.split('=', 1)[1]
            elif line == '# CONFIG_%s is not set' % option:
                out[option] = 'n'
    return {o: out.get(o, 'absent') for o in CONFIG_WATCH}


def kernel_report():
    v11, fb = symbols(V11_MAP), symbols(FB_MAP)
    names = REQUIRED_V11 + list(REQUIRED_INIT)
    absent_v11 = [s for s in names if s not in v11]
    if absent_v11:
        raise Refused('symbols missing from the v11 System.map itself: %s' % absent_v11)
    missing = [{'symbol': s, 'needed_for': REQUIRED_INIT.get(s, 'package-pocket-diagnostic.py v11 list')}
               for s in names if s not in fb]
    v11c, fbc = config_values(V11_CONFIG), config_values(FB_CONFIG)
    return {'symbols_checked': names, 'missing_from_firstboot': missing,
            'missing_before_acm': [m for m in missing if m['needed_for'] in ('before /init', 'before ACM')],
            'config': {o: {'v11': v11c[o], 'firstboot': fbc[o]} for o in CONFIG_WATCH if v11c[o] != fbc[o]},
            'system_map_sha256': {'v11': sha(V11_MAP.read_bytes()), 'firstboot': sha(FB_MAP.read_bytes())}}


def load_sources(tmp):
    for path, digest in [(V11, V11_SHA), (V2, V2_SHA)]:
        if sha(path.read_bytes()) != digest:
            raise Refused('%s does not match %s' % (path, digest))
    build = json.loads(FB_BUILD.read_text())['artifacts']
    for path in [FB_KERNEL, FB_MAP]:
        if sha(path.read_bytes()) != build[str(path)]['sha256']:
            raise Refused('%s does not match %s' % (path, FB_BUILD))
    v11_parts, v11_args, v11_header = unpack(V11, tmp / 'v11')
    v2_parts, _, v2_header = unpack(V2, tmp / 'v2')
    donor = dict(v2_parts)
    donor['kernel'] = FB_KERNEL.read_bytes()
    if donor['kernel'] != v2_parts['kernel']:
        raise Refused('first-boot Image.gz is not the kernel inside v2 boot.img')
    v11_text = avb_ops(V11)['info_image']['text']
    return v11_parts, v11_args, v11_header, v11_text, donor, v2_header


def build(name, intent, src, tmp, donor=None):
    v11_parts, v11_args, v11_header, v11_text, v2_donor, donor_header = src
    donor = donor or v2_donor
    parts = dict(v11_parts)
    cmdline = v11_header['cmdline']
    if intent == 'cmdline':
        cmdline = donor_header['cmdline']
    else:
        for part in intent.split('+'):
            parts[part] = donor[part]
    out, command = repack(v11_args, parts, cmdline, tmp / ('repack-' + name))
    payload = out.read_bytes()
    avb = add_footer(out)
    return out.read_bytes(), payload, [command, avb]


def run(write=True):
    if write:
        for name in BUILT_NOW:
            if (OUT / name / 'boot.img').exists():
                raise Refused('%s exists; refusing to overwrite' % (OUT / name / 'boot.img'))
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        tmp = Path(tmp)
        src = load_sources(tmp)
        v11_parts, v11_args, v11_header, v11_text, donor, donor_header = src
        # Repack with nothing swapped must give v11 back byte for byte, or the repack is itself a change.
        same, _, _ = build('identity', 'cmdline', (v11_parts, v11_args, v11_header, v11_text, v11_parts, v11_header), tmp)
        if same != V11.read_bytes():
            raise Refused('repacking v11 with nothing swapped does not reproduce v11')
        differences = {n: {'v11': sha(v11_parts[n]), 'v2': sha(donor[n]), 'same': v11_parts[n] == donor[n]}
                       for n in COMPONENTS}
        differences['cmdline'] = {'v11': v11_header['cmdline'], 'v2': donor_header['cmdline'],
                                  'same': v11_header['cmdline'] == donor_header['cmdline']}
        header_diff = {f: [v11_header[f], donor_header[f]] for f in v11_header
                       if v11_header[f] != donor_header[f] and f not in sum(SIZE_FIELDS.values(), OFFSET_FIELDS + ['cmdline'])}
        v2_avb = CHECK['parse_avb'](V2.read_bytes())['hash_descriptor']['partition_name']
        kernel = kernel_report()
        records = {}
        ro = V11RO_RAMDISK.read_bytes()
        for name in BUILT_NOW:
            intent = CANDIDATES[name]
            # B2's ramdisk comes from the read-only v11 build, not from v2.
            source = dict(donor, ramdisk=ro) if intent == 'kernel+ramdisk' else donor
            data, payload, commands = build(name, intent, src, tmp, source)
            check = check_candidate(data, intent, v11_parts, v11_header, v11_text, source, donor_header, tmp / ('check-' + name))
            changed = {'component': intent, 'v11': {n: sha(v11_parts[n]) for n in intent.split('+')},
                       'new': {n: sha(source[n]) for n in intent.split('+')}} if '+' in intent else \
                {'component': intent, 'v11': differences[intent]['v11'], 'v2': differences[intent]['v2']}
            notes = []
            if '+' in intent:
                notes.append('kernel is the first-boot Image.gz; ramdisk is v11\'s init without the userdata write test, '
                             'serial TP510-RAM-V11RO (the super mount stays: read-only ext4, noload)')
            elif differences[intent]['same']:
                notes.append('v2 %s is byte-identical to v11; this candidate equals v11 and needs no trial' % intent)
            if data == V11.read_bytes():
                notes.append('image is byte-identical to v11 ' + V11_SHA)
            if 'kernel' in intent.split('+'):
                notes.append('first-boot kernel: %d symbols missing (%d before ACM); config differences in kernel_symbols'
                             % (len(kernel['missing_from_firstboot']), len(kernel['missing_before_acm'])))
            if intent == 'cmdline':
                notes.append('rdinit=/init dropped: 5.10 init/main.c defaults ramdisk_execute_command to "/init" and the '
                             'v11 ramdisk has /init at its root, so v11 starts the same without it')
                notes.append('watchdog.open_timeout=90 dropped: v11 kernel has CONFIG_WATCHDOG_OPEN_TIMEOUT=90 and '
                             'WATCHDOG_HANDLE_BOOT_ENABLED=y, so the watchdog boot handling stays the same')
            record = {
                'state': 'Packaged offline; not staged, flashed or boot-tested',
                'candidate': name, 'changed_from_v11': changed, 'notes': notes,
                'output': {'path': str(OUT / name / 'boot.img'), 'bytes': len(data), 'sha256': sha(data)},
                'payload': {'bytes': len(payload), 'sha256': sha(payload)},
                'sources': {'v11': {'path': str(V11), 'sha256': V11_SHA}, 'v2': {'path': str(V2), 'sha256': V2_SHA},
                            'firstboot_kernel': {'path': str(FB_KERNEL), 'sha256': sha(FB_KERNEL.read_bytes())}},
                'status': STATUS[name],
                'components': {n: {'sha256': sha(c), 'bytes': len(c),
                                   'from': ('v11 read-only build' if n == 'ramdisk' else 'v2') if n in intent.split('+') else 'v11'}
                               for n, c in ((n, source[n] if n in intent.split('+') else v11_parts[n]) for n in COMPONENTS)},
                'cmdline': {'value': check['header']['cmdline'], 'from': 'v2' if intent == 'cmdline' else 'v11'},
                'header': {k: check['header'][k] for k in check['header']},
                'arm64': check['arm64'], 'regions': check['regions'],
                'reserved_ranges_checked': check['reserved_ranges_checked'],
                'avb': check['avb'], 'avbtool': {k: v['returncode'] for k, v in check['avbtool'].items()},
                'checks': check['results'], 'commands': commands,
                'tools_sha256': {str(p): sha(Path(p).read_bytes()) for p in [Path(__file__), MKBOOTIMG, AVBTOOL, UNPACK]},
                'device_accessed': False,
            }
            if 'kernel' in intent.split('+'):
                record['kernel_symbols'] = kernel
            records[name] = (data, record)
    if write:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        for name, (data, record) in records.items():
            d = OUT / name
            d.mkdir(parents=True, exist_ok=True)
            (d / 'boot.img').write_bytes(data)
            (d / 'boot.img.json').write_text(json.dumps(record, indent=2) + '\n')
    # B, C and D were built earlier and stay as they are; only their status is recorded.
    legacy = {}
    for name in CANDIDATES:
        if name in BUILT_NOW:
            continue
        path = OUT / name / 'boot.img.json'
        record = json.loads(path.read_text())
        record['status'] = STATUS[name]
        if write:
            path.write_text(json.dumps(record, indent=2) + '\n')
        legacy[name] = (None, record)
    summary = {
        'state': 'Packaged offline; not staged, flashed or boot-tested',
        'base': {'path': str(V11), 'sha256': V11_SHA}, 'donor': {'path': str(V2), 'sha256': V2_SHA},
        'identity_repack_reproduces_v11': True,
        'v11_vs_v2': {'components': differences, 'other_header_fields': header_diff,
                      'avb_partition_name': {'v11': AVB_NAME, 'v2': v2_avb}},
        'candidates': {n: {'sha256': r['output']['sha256'], 'changed': r['changed_from_v11'], 'notes': r['notes'],
                           'status': STATUS[n], 'checks_passed': sum(c['pass'] for c in r['checks']),
                           'record': str(OUT / n / 'boot.img.json')}
                       for n, (_, r) in {**legacy, **records}.items()},
        'kernel_symbols': kernel,
        'self_test': self_test(),
        'device_accessed': False,
    }
    if write:
        (EVIDENCE / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def patched(data, offset, fmt, value):
    """Change one header field and redo the footer, so only the header check can catch it."""
    payload = bytearray(payload_of(data)[0])
    struct.pack_into(fmt, payload, offset, value)
    return bytes(payload)


def self_test():
    """Broken candidates that the checks must refuse."""
    OUT.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        tmp = Path(tmp)
        src = load_sources(tmp)
        v11_parts, v11_args, v11_header, v11_text, donor, donor_header = src

        def footered(payload, label):
            p = tmp / ('case-' + label + '.img')
            p.write_bytes(payload)
            add_footer(p)
            return p.read_bytes()

        b, _, _ = build('selftest-B', 'kernel', src, tmp)
        d, _, _ = build('selftest-D', 'cmdline', src, tmp)
        good = []
        bad = []
        # Wrong component: the B image (kernel swapped) checked as a cmdline or ramdisk swap.
        bad.append(('kernel swapped, checked as cmdline swap', b, 'cmdline'))
        bad.append(('cmdline swapped, checked as kernel swap', d, 'kernel'))
        # v2 ramdisk swapped in, checked as a kernel swap.
        parts = dict(v11_parts)
        parts['ramdisk'] = donor['ramdisk']
        out, _ = repack(v11_args, parts, v11_header['cmdline'], tmp / 'repack-ramdisk')
        add_footer(out)
        bad.append(('ramdisk swapped, checked as kernel swap', out.read_bytes(), 'kernel'))
        # Kernel address 0x40280000: 512 KiB aligned but not 2 MiB aligned for text_offset 0.
        bad.append(('kernel address not 2 MiB aligned',
                    footered(patched(b, 12, '<I', 0x40280000), 'misaligned'), 'kernel'))
        # Kernel image_size raised so the inflated kernel runs into the DT at 0x54000000.
        kernel = bytearray(BOOT['inflate_kernel'](donor['kernel']))
        struct.pack_into('<Q', kernel, 16, 0x54000000 - 0x40200000 + 0x1000)

        parts = dict(v11_parts)
        parts['kernel'] = gzip.compress(bytes(kernel), mtime=0)
        out, _ = repack(v11_args, parts, v11_header['cmdline'], tmp / 'repack-overlap')
        add_footer(out)
        shifted = dict(donor)
        shifted['kernel'] = parts['kernel']
        bad.append(('kernel image_size past the LK reservation into the DT', out.read_bytes(), 'kernel', shifted))
        # DT address moved off the stock value.
        bad.append(('dtb address moved', footered(patched(b, 1652, '<Q', 0x54100000), 'dtbaddr'), 'kernel'))
        # Right swap, but another header field changed too (os_version).
        bad.append(('os_version changed as well', footered(patched(b, 44, '<I', 0), 'osversion'), 'kernel'))
        # Footer with the wrong partition name.
        p = tmp / 'case-name.img'
        p.write_bytes(payload_of(b)[0])
        subprocess.run([sys.executable, '-B', str(AVBTOOL), 'add_hash_footer', '--image', str(p), '--partition_name',
                        'boot', '--partition_size', str(PARTITION_SIZE), '--algorithm', 'NONE', '--hash_algorithm',
                        'sha256', '--salt', sha(payload_of(b)[0]), '--rollback_index', '0'], check=True)
        bad.append(('avb partition name boot', p.read_bytes(), 'kernel'))
        # Truncated image (does not fill the partition).
        bad.append(('image not the partition size', b[:-4096], 'kernel'))
        good.append(('B as built', b, 'kernel'))
        good.append(('D as built', d, 'cmdline'))
        ro = V11RO_RAMDISK.read_bytes()
        donor_ro = dict(donor, ramdisk=ro)
        b2, _, _ = build('selftest-B2', 'kernel+ramdisk', src, tmp, donor_ro)
        good.append(('B2 as built', b2, 'kernel+ramdisk', donor_ro))
        # B2 must not be accepted with v11's own ramdisk, even when that is what the check is told to expect.
        bad.append(('B (v11 ramdisk) checked as B2', b, 'kernel+ramdisk', donor_ro))
        donor_v11 = dict(donor, ramdisk=v11_parts['ramdisk'])
        bad.append(('B2 with v11 ramdisk, expected ramdisk v11 (only the read-only check refuses)', b, 'kernel+ramdisk', donor_v11))
        bad.append(('B2 checked as a kernel-only swap', b2, 'kernel'))
        for i, case in enumerate(good + bad):
            label, data, intent = case[:3]
            donor_parts = case[3] if len(case) > 3 else donor
            expect = case in good
            try:
                check_candidate(data, intent, v11_parts, v11_header, v11_text, donor_parts, donor_header, tmp / ('c%d' % i))
                accepted, reason = True, ''
            except (Refused, AssertionError, subprocess.CalledProcessError, struct.error, KeyError) as e:
                accepted, reason = False, str(e)[:200]
            cases.append({'case': label, 'expect_accept': expect, 'accepted': accepted, 'reason': reason,
                          'pass': accepted == expect})
        # The placement rules on their own, so they are shown to bite apart from the v11 comparison.
        header = dict(v11_header)
        fb, dt, rd = donor['kernel'], v11_parts['dtb'], v11_parts['ramdisk']
        for label, change, dtb, ramdisk in [
                ('placement: kernel 0x40280000 not 2 MiB aligned', {'kernel_addr': 0x40280000}, dt, rd),
                ('placement: kernel reservation runs into the DT', {'kernel_addr': 0x48000000}, dt, rd),
                ('placement: DT moved off 0x54000000', {'dtb_addr': 0x54fe0000, 'tags_addr': 0x54fe0000}, dt, rd),
                ('placement: DT runs into the ramdisk', {}, dt + bytes(0x1000000), rd),
                ('placement: ramdisk over 16 MiB', {}, dt, rd + bytes(0x1000000)),
                ('placement: kernel below the base', {'kernel_addr': 0x3fe00000}, dt, rd)]:
            h = dict(header, **change)
            try:
                placement(h, fb, dtb, ramdisk)
                accepted, reason = True, ''
            except Refused as e:
                accepted, reason = False, str(e)[:200]
            bad.append(label)
            cases.append({'case': label, 'expect_accept': False, 'accepted': accepted, 'reason': reason,
                          'pass': not accepted})
        placement(header, fb, dt, rd)
        cases.append({'case': 'placement: first-boot kernel at v11 addresses', 'expect_accept': True,
                      'accepted': True, 'reason': '', 'pass': True})
    failed = [c for c in cases if not c['pass']]
    if failed:
        raise Refused('self-test: %s' % failed)
    return {'cases': cases, 'passed': len(cases), 'failing_cases_refused': len(bad)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--self-test', action='store_true', help='only run the failing cases; write nothing')
    args = parser.parse_args()
    try:
        if args.self_test:
            result = self_test()
            for c in result['cases']:
                print('%-4s %s%s' % ('ok' if c['pass'] else 'FAIL', c['case'], ' (' + c['reason'] + ')' if c['reason'] else ''))
            print('self-test: %d cases, %d failing cases refused' % (result['passed'], result['failing_cases_refused']))
            return
        summary = run()
    except Refused as e:
        print('refused: ' + str(e), file=sys.stderr)
        sys.exit(2)
    for name, c in summary['candidates'].items():
        print(name, c['sha256'], c['changed']['component'], '; '.join(c['notes']))
    print('self-test: %d cases passed' % summary['self_test']['passed'])
    print('summary: ' + str(EVIDENCE / 'summary.json'))


if __name__ == '__main__':
    main()
