#!/usr/bin/env python3
"""Package a 5.10 kernel and a ramdisk as a boot-partition image for the Titan Pocket.

Offline only: never stages, flashes or talks to a device. Output is a 32 MiB
header v2 image with an AVB hash footer for partition `boot`, laid out as stock
boot plus an empty recovery_dtbo, except the kernel address
(0x40200000, see firstboot-tkcore-lk-staging.md).
LK limits are from REA of the LK payload (firstboot-tkcore-lk-staging.md part B).
"""
import pocket_paths
import argparse
import gzip
import hashlib
import json
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
PLATFORM = pocket_paths.platform_source()
MKBOOTIMG = PLATFORM / 'system/tools/mkbootimg/mkbootimg.py'
AVBTOOL = ROOT / 'tools/avbtool.py'
STOCK_BOOT = ROOT / 'firmware/installed-20230105/boot.img'
STOCK_BOOT_SHA = '065e115909e1c92d26d85d1d24873f333aeb3a67c00ba65d565b56d176f8cd51'
STOCK_DTB_TABLE = ROOT / 'firmware/installed-20230105/boot/dtb'
# The v9 board with the keyboard, backlight and touchpad on, from prepare-pocket-keyboard-board.py.
BOARD_RECORD = ROOT / 'evidence/kernel-upgrade/firstboot-board-keyboard.json'
LIVE_FDT = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'

PARTITION = 'boot'
PARTITION_SIZE = 0x2000000          # partition-size:boot=2000000 from LK fastboot
PAGE = 2048
BASE = 0x40000000
KERNEL_ADDR = 0x40200000            # 2 MiB aligned; stock 0x40080000 only suits text_offset 0x80000
DTB_ADDR = 0x54000000               # stock header tags and dtb address, LK requires it
RAMDISK_ADDR = 0x55000000           # stock header ramdisk address, LK requires it
KERNEL_RESERVE = 0xc800000          # LK reserves 200 MiB at the header kernel address and inflates into it
RAMDISK_MAX = 0x1000000             # LK ramdisk reservation, 16 MiB
LK_STAGE_MAX = 0x8000000            # LK copies the whole image to 0x56900000 when it is 128 MiB or less
DTB_RESERVE_MIN = 0x80000           # region checked for the DT, as the diagnostic packager does
DTB_MERGE_MAX = 0x80000             # LK prepare_kernel_dtb limit for the boot DTB plus the overlay
# Empty overlay DT table (one entry, a 72-byte empty FDT) as in the v5 to v9 recovery diagnostics.
# LK uses a header v2 recovery_dtbo on normal boot too, in place of the dtbo partition entry.
RECOVERY_DTBO = bytes.fromhex(
    'd7b7ab1e000000880000002000000020000000010000002000000800000000000000004800000040000000000000000000000000000000000000000000000000d00dfeed0000004800000038000000480000002800000011000000100000000000000000000000100000000000000000000000000000000000000001000000000000000200000009')
RECOVERY_DTBO_SHA = 'f72e1df52c33bde1676863a21b3e7f8c3cb9a21b8ed7addefe2ac0eb8cce0635'
OS_VERSION = '11.0.0'               # stock header values, what LK hands the TEE today
OS_PATCH_LEVEL = '2022-09'
# Stock header carries `bootopt=64S3,32N2,64N2 buildvariant=user`. LK reads bootopt
# for the 64-bit boot mode; buildvariant follows the product (userdebug), as v5 to v9 did.
# loglevel, printk.time and permissive SELinux are for the first boot (owner decision 2026-10-31).
# androidboot.hardware to cgroup.memory are the stock DT /chosen/bootargs base options that LK does
# not add itself (our board dtb has empty bootargs); first-stage init finds its fstab through
# androidboot.hardware. printk.devkmsg=on and panic=10 are for this attempt.
# aw9523_key.start_suspended=0 starts the keyboard live: it otherwise waits for an fb unblank
# that can't come until the display port lands (owner decision 2026-10-31). Remove it then.
# log_buf_len=4M: the 1 MB kernel log wrapped by 35 s on Android boots, before the driver lines can be read.
CMDLINE = ('bootopt=64S3,32N2,64N2 buildvariant=userdebug clk_ignore_unused regulator_ignore_unused '
           'loglevel=8 printk.time=1 androidboot.selinux=permissive '
           'androidboot.hardware=mt6771 firmware_class.path=/vendor/firmware loop.max_part=7 '
           'cgroup.memory=nosocket,nokmem printk.devkmsg=on panic=10 log_buf_len=4M aw9523_key.start_suspended=0')
# SELinux mode: permissive (default) keeps the first-boot wrapper and the devtmpfs kernel; enforcing has
# the product ramdisk as it is (no wrapper) and the kernel without devtmpfs. The mode is in the output name.
SELINUX_MODES = ('permissive', 'enforcing')
REQUIRED_CMDLINE = ['loglevel=8', 'printk.time=1', 'androidboot.selinux=permissive',
                    'androidboot.hardware=mt6771', 'firmware_class.path=/vendor/firmware', 'loop.max_part=7',
                    'cgroup.memory=nosocket,nokmem', 'printk.devkmsg=on', 'panic=10', 'log_buf_len=4M',
                    'aw9523_key.start_suspended=0']


def cmdline_for(selinux):
    return CMDLINE.replace('androidboot.selinux=permissive', 'androidboot.selinux=' + selinux)


STUB_MARKER = b'TITAN_POCKET_STUB_RAMDISK_NOT_FOR_FLASHING'
TEST_NAME = 'not-for-flashing'
# First-flash v2: a real ramdisk must have the wrapper at /init and the product init at /init.android.
PRODUCT_RAMDISK = BULK / 'product-out/target/product/titan_pocket/ramdisk.img'
WRAPPER_SOURCE = ROOT / 'kernel-upgrade/firstboot-wrapper/init.c'
WRAPPER_MARKER = b'TP510-FIRSTBOOT-V2 wrapper init; wrapper-source-sha256='
WRAPPER_TEST_MARKER = b'FIRSTBOOT_HOST_TEST_BUILD'
WRAPPER_MOUNT_TYPES = {'proc', 'sysfs', 'devtmpfs', 'pstore', 'configfs'}


class Refused(Exception):
    pass


def join_cmdline(base, extra):
    """base plus the extra words; refuses an extra word whose key (before the =) is in base or repeated."""
    keys = {w.split('=')[0] for w in base.split()}
    for w in extra.split():
        if w.split('=')[0] in keys:
            raise Refused('--extra-cmdline word repeats or overrides a standard one: ' + w)
        keys.add(w.split('=')[0])
    return ' '.join(base.split() + extra.split())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inflate_kernel(data):
    """Inflate Image.gz the way LK needs it: one gzip member ending in stream end."""
    if data[:2] != b'\x1f\x8b':
        raise Refused('kernel is not gzip')
    d = zlib.decompressobj(wbits=31)
    try:
        image = d.decompress(data, KERNEL_RESERVE + 1)
    except zlib.error as e:
        raise Refused('kernel gzip stream is corrupt: %s' % e)
    if len(image) > KERNEL_RESERVE:
        raise Refused('decompressed kernel is over the 200 MiB LK reservation')
    if not d.eof:
        raise Refused('kernel gzip stream has no end')
    if d.unused_data:
        raise Refused('kernel gzip has %d bytes after the first member' % len(d.unused_data))
    return image


def check_arm64(image, load):
    if len(image) < 64 or image[56:60] != b'ARM\x64':
        raise Refused('kernel is not an arm64 Image')
    text_offset, image_size, flags = struct.unpack_from('<QQQ', image, 8)
    if image_size < len(image):
        raise Refused('arm64 image_size is smaller than the Image')
    if image_size > KERNEL_RESERVE:
        raise Refused('arm64 image_size 0x%x is over the 200 MiB LK reservation' % image_size)
    if flags & 1 or flags & 6 != 2:
        raise Refused('kernel is not little-endian with 4 KiB pages')
    if (load - text_offset) % 0x200000:
        raise Refused('kernel address 0x%x minus text_offset 0x%x is not 2 MiB aligned' % (load, text_offset))
    if load % 0x80000:
        raise Refused('kernel address is not 512 KiB aligned (LK panics)')
    if load < BASE or load + KERNEL_RESERVE > DTB_ADDR:
        raise Refused('LK kernel reservation [0x%x, 0x%x) is not between 0x%x and the DT at 0x%x'
                      % (load, load + KERNEL_RESERVE, BASE, DTB_ADDR))
    return {'text_offset': text_offset, 'image_size': image_size, 'flags': flags}


def lz4_legacy_decode(data, limit=1 << 30):
    """Decode an lz4 legacy frame: magic, then blocks of a 4-byte size and one lz4 block."""
    out = bytearray()
    pos = 4
    try:
        while pos + 4 <= len(data):
            size = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            if size == 0x184c2102:      # concatenated frame
                continue
            block = data[pos:pos + size]
            if len(block) != size:
                raise Refused('ramdisk lz4 block is cut short')
            pos += size
            i = 0
            while i < len(block):
                token = block[i]
                i += 1
                n = token >> 4
                if n == 15:
                    while True:
                        b = block[i]
                        i += 1
                        n += b
                        if b != 255:
                            break
                out += block[i:i + n]
                i += n
                if i >= len(block):
                    break
                offset = block[i] | block[i + 1] << 8
                i += 2
                n = token & 15
                if n == 15:
                    while True:
                        b = block[i]
                        i += 1
                        n += b
                        if b != 255:
                            break
                n += 4
                if not 0 < offset <= len(out):
                    raise Refused('ramdisk lz4 offset is out of range')
                for _ in range(n):
                    out.append(out[-offset])
            if len(out) > limit:
                raise Refused('ramdisk lz4 stream is too large')
    except IndexError:
        raise Refused('ramdisk lz4 stream is corrupt')
    return bytes(out)


def cpio_names(raw):
    """Member names of a newc cpio archive."""
    names = []
    pos = 0
    while pos + 110 <= len(raw):
        if raw[pos:pos + 6] != b'070701':
            raise Refused('ramdisk cpio has a bad record at %d' % pos)
        namesize = int(raw[pos + 94:pos + 102], 16)
        filesize = int(raw[pos + 54:pos + 62], 16)
        pos += 110
        name = raw[pos:pos + namesize - 1].decode(errors='replace')
        pos = (pos + namesize + 3) & ~3
        if name == 'TRAILER!!!':
            return names
        names.append(name.lstrip('./'))
        pos = (pos + filesize + 3) & ~3
    raise Refused('ramdisk cpio has no trailer')


def cpio_entries(raw):
    """(name, mode, data) of each newc record up to the trailer."""
    out = []
    pos = 0
    while pos + 110 <= len(raw):
        if raw[pos:pos + 6] != b'070701':
            raise Refused('ramdisk cpio has a bad record at %d' % pos)
        mode = int(raw[pos + 14:pos + 22], 16)
        filesize = int(raw[pos + 54:pos + 62], 16)
        namesize = int(raw[pos + 94:pos + 102], 16)
        pos += 110
        name = raw[pos:pos + namesize - 1].decode(errors='replace')
        pos = (pos + namesize + 3) & ~3
        if name == 'TRAILER!!!':
            return out
        out.append((name.lstrip('./'), mode, raw[pos:pos + filesize]))
        pos = (pos + filesize + 3) & ~3
    raise Refused('ramdisk cpio has no trailer')


def elf_static_aarch64(data):
    """Problems with an ELF that should be a static aarch64 executable."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return ['is not ELF']
    if data[4] != 2 or data[5] != 1:
        return ['is not 64-bit little-endian ELF']
    problems = []
    e_type, machine = struct.unpack_from('<HH', data, 16)
    if machine != 183:
        problems.append('is not aarch64 (e_machine %d)' % machine)
    if e_type != 2:
        problems.append('is not ET_EXEC (e_type %d)' % e_type)
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    types = [struct.unpack_from('<I', data, phoff + i * phentsize)[0] for i in range(phnum)
             if phoff + (i + 1) * phentsize <= len(data)]
    if 3 in types or 2 in types:
        problems.append('is not static (has PT_INTERP or PT_DYNAMIC)')
    return problems


def check_wrapper_source(text):
    """Problems with the wrapper source: no block devices, timer device, restarts, commands or extra mounts."""
    problems = []
    rules = [(r'watchdog', 'mentions watchdog'),
             (r'(?i)reboot|RB_AUTOBOOT|RB_POWER_OFF|RB_HALT_SYSTEM', 'mentions reboot'),
             (r'O_RDWR', 'opens something read-write (block device or command input)'),
             (r'/dev/(block|sd[a-z]|mmcblk|nvme|loop|dm-|mapper)', 'names a block device'),
             (r'\bBLK[A-Z]+', 'uses a block device request'),
             (r'\bioctl\s*\(|\bsyscall\s*\(', 'uses raw ioctl or syscall'),
             (r'\b(system|popen|posix_spawnp?|fexecve|execl[pe]?|execvpe?|execve)\s*\(', 'runs other commands'),
             (r'MS_REMOUNT|MS_BIND|MS_MOVE', 'remounts, binds or moves a mount')]
    for pattern, message in rules:
        if re.search(pattern, text):
            problems.append(message)
    if len(re.findall(r'\bexecv\s*\(', text)) != 1 or 'execv(EXEC_PATH, argv)' not in text:
        problems.append('must exec Android init exactly once, as execv(EXEC_PATH, argv)')
    for line in text.splitlines():
        if 'mknod' in line and 'S_IFCHR' not in line:
            problems.append('makes a node that is not a character device')
        if re.search(r'(?<![\w.])mount\s*\(', line) and not line.startswith('#define fs_mount('):
            problems.append('calls mount() outside the fs_mount macro')
    for literal in re.findall(r'"(/dev[^"]*)"', text):
        if literal not in ('/dev', '/dev/kmsg'):
            problems.append('names %s (only /dev and /dev/kmsg are allowed)' % literal)
    for kind in re.findall(r'fs_mount\(\s*"[^"]*"\s*,[^,]*,\s*"([^"]*)"', text):
        if kind not in WRAPPER_MOUNT_TYPES:
            problems.append('mounts %s' % kind)
    return sorted(set(problems))


def wrapper_info(raw, product_raw, source_text):
    """Refuse unless /init is the static aarch64 wrapper built from the checked source and
    /init.android plus every other record match the product ramdisk."""
    if product_raw is None:
        raise Refused('a real ramdisk needs the product ramdisk to compare /init.android with')
    entries = cpio_entries(raw)
    names = [n for n, _, _ in entries]
    if names.count('init.android') != 1:
        raise Refused('ramdisk has no single /init.android; the firstboot wrapper is missing')
    if names.count('init') != 1:
        raise Refused('ramdisk has no single /init')
    by = {n: (m, d) for n, m, d in entries}
    mode, wrapper = by['init']
    problems = elf_static_aarch64(wrapper)
    if problems:
        raise Refused('ramdisk /init ' + ', '.join(problems))
    if mode & 0o170000 != 0o100000 or not mode & 0o100:
        raise Refused('ramdisk /init is not an executable regular file')
    if WRAPPER_TEST_MARKER in wrapper:
        raise Refused('ramdisk /init is the wrapper host test build')
    if WRAPPER_MARKER not in wrapper:
        raise Refused('ramdisk /init is not the firstboot wrapper (no marker)')
    if WRAPPER_MARKER + sha(source_text.encode()).encode() not in wrapper:
        raise Refused('ramdisk /init wrapper marker does not match the wrapper source hash')
    problems = check_wrapper_source(source_text)
    if problems:
        raise Refused('wrapper source: ' + '; '.join(problems))
    product = cpio_entries(product_raw)
    product_init = [(m, d) for n, m, d in product if n == 'init']
    if len(product_init) != 1:
        raise Refused('product ramdisk has no single /init')
    if by['init.android'] != product_init[0]:
        raise Refused('ramdisk /init.android is not byte-identical to the product first-stage init')
    rest = [e for e in entries if e[0] not in ('init', 'init.android')]
    if rest != [e for e in product if e[0] != 'init']:
        raise Refused('ramdisk differs from the product ramdisk beyond /init and /init.android')
    return {'wrapper_sha256': sha(wrapper), 'wrapper_mode': oct(mode), 'static_aarch64': True,
            'wrapper_source_sha256': sha(source_text.encode()), 'init_android_sha256': sha(product_init[0][1]),
            'init_android_mode': oct(product_init[0][0]), 'other_records_as_product': len(rest)}


def kernel_config(image):
    """The built-in .config text (IKCONFIG) of an inflated kernel Image, or None."""
    start = image.find(b'IKCFG_ST')
    end = image.find(b'IKCFG_ED', start)
    if start < 0 or end < 0:
        return None
    return gzip.decompress(image[start + 8:end]).decode(errors='replace')


def devtmpfs_state(image):
    config = kernel_config(image)
    if config is None:
        return None
    lines = config.splitlines()
    if 'CONFIG_DEVTMPFS=y' in lines:
        return True
    if '# CONFIG_DEVTMPFS is not set' in lines:
        return False
    raise Refused('kernel config has no CONFIG_DEVTMPFS line')


def plain_info(raw, product_raw):
    """Enforcing image: the ramdisk must be the product ramdisk, with the product /init and no wrapper."""
    if product_raw is None:
        raise Refused('an enforcing ramdisk needs the product ramdisk to compare with')
    entries = cpio_entries(raw)
    names = [n for n, _, _ in entries]
    if names.count('init') != 1 or 'init.android' in names:
        raise Refused('enforcing ramdisk must have one /init and no /init.android (no wrapper)')
    if any(WRAPPER_MARKER in d or WRAPPER_TEST_MARKER in d for _, _, d in entries if d[:4] == b'\x7fELF'):
        raise Refused('enforcing ramdisk carries the first-boot wrapper')
    if entries != cpio_entries(product_raw):
        raise Refused('enforcing ramdisk differs from the product ramdisk')
    init = [d for n, _, d in entries if n == 'init'][0]
    return {'wrapper': None, 'product_init_sha256': sha(init), 'records_as_product': len(entries)}


def decompress_ramdisk(data):
    if data[:2] == b'\x1f\x8b':
        try:
            return 'gzip', gzip.decompress(data)
        except (OSError, EOFError, zlib.error) as e:
            raise Refused('ramdisk gzip is corrupt: %s' % e)
    if data[:4] == b'\x02\x21\x4c\x18':
        return 'lz4-legacy', lz4_legacy_decode(data)
    if data[:6] == b'070701':
        return 'cpio', data
    raise Refused('ramdisk is not gzip, lz4 legacy or newc cpio')


def check_fstab(raw, cmdline):
    """First-stage init looks for fstab.<androidboot.hardware> in first_stage_ramdisk/ or the root."""
    hardware = [t.split('=', 1)[1] for t in cmdline.split() if t.startswith('androidboot.hardware=')]
    if not hardware or not hardware[-1]:
        raise Refused('cmdline has no androidboot.hardware, so first-stage init cannot find the fstab')
    names = cpio_names(raw)
    wanted = ['first_stage_ramdisk/fstab.' + hardware[-1], 'fstab.' + hardware[-1]]
    if not any(n in names for n in wanted):
        raise Refused('ramdisk has no %s' % ' or '.join(wanted))


def ramdisk_info(data, test_ramdisk, cmdline=CMDLINE, product_raw=None, wrapper_source_text=None, selinux='permissive'):
    if not data:
        raise Refused('ramdisk is empty')
    if len(data) > RAMDISK_MAX:
        raise Refused('ramdisk is %d bytes, over the 16 MiB LK reservation' % len(data))
    kind, raw = decompress_ramdisk(data)
    stub = STUB_MARKER in raw
    if stub and not test_ramdisk:
        raise Refused('ramdisk is the test stub; pass --test-ramdisk to package it')
    if test_ramdisk and not stub:
        raise Refused('--test-ramdisk given but the ramdisk is not the stub')
    check_fstab(raw, cmdline)
    if stub:
        return {'compression': kind, 'test_stub': stub}
    if selinux == 'enforcing':
        return {'compression': kind, 'test_stub': stub, **plain_info(raw, product_raw)}
    if wrapper_source_text is None:
        raise Refused('a real ramdisk needs the wrapper source to check /init against')
    return {'compression': kind, 'test_stub': stub,
            'wrapper': wrapper_info(raw, product_raw, wrapper_source_text)}


def reserved_ranges(fdt):
    decode = runpy.run_path(str(ROOT / 'tools/inspect-fdt.py'))['decode']
    out = []
    for name, value in decode(fdt)['nodes'].items():
        if name.startswith('/reserved-memory/') and 'reg' in value:
            cells = value['reg']['cells']
            for i in range(0, len(cells) - 3, 4):
                out.append([name, (cells[i] << 32) | cells[i + 1], (cells[i + 2] << 32) | cells[i + 3]])
    return out


# Board variants in BOARD_RECORD. modem-off is the default: eccci never probes, so ccci_mdinit can't start MD1.
# modem-on has mdcldma, ap/md_ccif0 and md_auxadc okay (MODEM_PORT.md M1), for trial M only; its output name must
# say modem-on.
BOARDS = {'modem-off': 'board_dtb', 'modem-on': 'board_dtb_modem_on'}


def board_dtb(board='modem-off'):
    record = json.loads(BOARD_RECORD.read_text())[BOARDS[board]]
    data = Path(record['path']).read_bytes()
    if sha(data) != record['sha256']:
        raise Refused('board dtb does not match ' + str(BOARD_RECORD))
    table = runpy.run_path(str(ROOT / 'tools/prepare-upgrade-boot-layout.py'))
    identity = table['parse_table'](STOCK_DTB_TABLE.read_bytes())['entries'][0]['identity']
    packed = table['pack'](data, identity)
    assert table['parse_table'](packed)['entries'][0]['blob'] == data
    return record['path'], data, packed, identity


def module_crcs(path):
    """({imported symbol: crc} from the __versions section, {exported symbol: crc} from the __crc_ symbols)
    of a 64-bit little-endian .ko."""
    data = Path(path).read_bytes()
    shoff, shentsize, shnum, shstrndx = struct.unpack_from('<Q', data, 0x28)[0], *struct.unpack_from('<3H', data, 0x3A)
    sh = [struct.unpack_from('<IIQQQQII', data, shoff + i * shentsize) for i in range(shnum)]  # name type flags addr off size link info

    def cstr(base, i):
        return data[base + i:data.index(b'\0', base + i)].decode()
    sections = {cstr(sh[shstrndx][4], h[0]): h for h in sh}
    imports = {}
    if '__versions' in sections:
        off, size = sections['__versions'][4:6]
        for o in range(off, off + size, 64):
            imports[data[o + 8:o + 64].split(b'\0')[0].decode()] = struct.unpack_from('<Q', data, o)[0]
    exports = {}
    sym = sections['.symtab']
    for o in range(sym[4], sym[4] + sym[5], 24):
        name, info, other, shndx, value = struct.unpack_from('<IBBHQ', data, o)
        if shndx == 0xfff1 and cstr(sh[sym[6]][4], name).startswith('__crc_'):
            exports[cstr(sh[sym[6]][4], name)[6:]] = value
    return imports, exports


def check_module_crcs(symvers, module_paths):
    """Refuse unless every symbol the modules import is exported with the same crc by the kernel or by another
    of the modules, and no symbol is exported twice."""
    kernel = {f[1]: int(f[0], 16) for f in (l.split('\t') for l in symvers.read_text().splitlines()) if len(f) > 2}
    found = {m: module_crcs(p) for m, p in module_paths.items()}
    bad = []
    owners = {}
    for m, (_, exports) in sorted(found.items()):
        for name in exports:
            owners.setdefault(name, []).append(m)
    for name, ms in sorted(owners.items()):
        if name in kernel or len(ms) > 1:
            bad.append('%s is exported twice (%s)' % (name, ', '.join(ms + ['kernel'] * (name in kernel))))
    for m, (imports, _) in sorted(found.items()):
        for name, crc in sorted(imports.items()):
            have = {kernel[name]} if name in kernel else {e[name] for _, (_, e) in found.items() if name in e}
            if crc not in have:
                bad.append('%s: %s wants %#x, has %s' % (m, name, crc, sorted(map(hex, have)) or 'no export'))
    if bad:
        raise Refused('vendor overlay modules do not match the kernel exports (%s)' % symvers.name + ':\n  ' + '\n  '.join(bad))


def expected_vermagic(tree, release):
    """The vermagic a module built in this tree carries (5.10 include/linux/vermagic.h, arm64)."""
    config = (tree / '.config').read_text().splitlines()
    on = lambda name: 'CONFIG_%s=y' % name in config
    preempt = 'preempt_rt ' if on('PREEMPT_RT') else 'preempt ' if on('PREEMPT') else ''
    return '%s %s%s%s%saarch64' % (release, 'SMP ' * on('SMP'), preempt, 'mod_unload ' * on('MODULE_UNLOAD'),
                                   'modversions ' * on('MODVERSIONS'))


def check_overlay_match(kernel_tree, overlay_record):
    """Refuse unless the kernel build tree is the one the vendor overlay's modules were built against: each module's
    vermagic is the tree's, its file is the recorded one, and the symvers hash is equal or every module import has its crc exported
    (added kernel exports don't break the modules)."""
    if not kernel_tree or not overlay_record:
        raise Refused('a real image needs --kernel-tree and --vendor-overlay-record')
    tree = Path(kernel_tree)
    symvers = [tree / n for n in ('vmlinux.symvers', 'Module.symvers') if (tree / n).is_file()]
    release_file = tree / 'include/config/kernel.release'
    if not symvers or not release_file.is_file():
        raise Refused('kernel tree has no vmlinux.symvers or Module.symvers, or no kernel.release')
    record = json.loads(Path(overlay_record).read_text())
    release = release_file.read_text().strip()
    want = expected_vermagic(tree, release)
    bad = {m: i.get('vermagic') for m, i in record.get('modules', {}).items() if i.get('vermagic') != want}
    if bad or not record.get('modules'):
        raise Refused('kernel vermagic "%s" differs from the vendor overlay modules: %s' % (want, bad))
    paths = {}
    for m, i in record['modules'].items():
        if not Path(i['path']).is_file() or sha(Path(i['path']).read_bytes()) != i['sha256']:
            raise Refused('overlay module %s is missing or changed: %s' % (m, i['path']))
        paths[m] = i['path']
    got = sha(symvers[0].read_bytes())
    match = 'symvers-hash'
    if got != record.get('kernel_module_symvers_sha256'):
        check_module_crcs(symvers[0], paths)
        match = 'module-crcs'
    return {'record': str(overlay_record), 'version': record.get('version'), 'symvers_sha256': got, 'release': release,
            'match': match}


def package(kernel_path, ramdisk_path, output, test_ramdisk=False, kernel_addr=KERNEL_ADDR,
            recovery_dtbo=RECOVERY_DTBO, cmdline=None, product_ramdisk=PRODUCT_RAMDISK,
            wrapper_source=WRAPPER_SOURCE, board='modem-off', selinux='permissive',
            kernel_tree=None, overlay_record=None):
    output = Path(output)
    if selinux not in SELINUX_MODES:
        raise Refused('unknown selinux mode ' + str(selinux))
    if cmdline is None:
        cmdline = cmdline_for(selinux)
    if len(cmdline.encode()) > 511:
        raise Refused('cmdline is %d bytes, over the 511 that fit without extra_cmdline' % len(cmdline.encode()))
    if (selinux == 'enforcing') != ('enforcing' in output.name):
        raise Refused('only an enforcing image may have "enforcing" in its file name, and it must')
    other = SELINUX_MODES[0] if selinux == 'enforcing' else SELINUX_MODES[1]
    if 'androidboot.selinux=' + other in cmdline.split():
        raise Refused('cmdline has androidboot.selinux=%s but the mode is %s' % (other, selinux))
    if board not in BOARDS:
        raise Refused('unknown board ' + str(board))
    if (board == 'modem-on') != ('modem-on' in output.name):
        raise Refused('only a modem-on board image may have "modem-on" in its file name, and it must')
    for token in REQUIRED_CMDLINE:
        token = token.replace('androidboot.selinux=permissive', 'androidboot.selinux=' + selinux)
        if token not in cmdline.split():
            raise Refused('cmdline is missing ' + token)
    if output.exists():
        raise Refused('output exists; refusing to overwrite ' + str(output))
    if test_ramdisk and TEST_NAME not in output.name:
        raise Refused('an image with the stub ramdisk must have "%s" in its file name' % TEST_NAME)
    if sha(STOCK_BOOT.read_bytes()) != STOCK_BOOT_SHA:
        raise Refused('stock boot.img does not match the backup hash')
    kernel = Path(kernel_path).read_bytes()
    ramdisk = Path(ramdisk_path).read_bytes()
    image_raw = inflate_kernel(kernel)
    arm64 = check_arm64(image_raw, kernel_addr)
    if not test_ramdisk:
        # The wrapper mounts devtmpfs; the enforcing image has no wrapper and the kernel must not carry it.
        state = devtmpfs_state(image_raw)
        if state is None:
            raise Refused('kernel has no built-in config to check CONFIG_DEVTMPFS against')
        if state != (selinux == 'permissive'):
            raise Refused('%s image needs a kernel with CONFIG_DEVTMPFS %s' %
                          (selinux, 'on (the wrapper mounts it)' if selinux == 'permissive' else 'off'))
    product_raw = decompress_ramdisk(Path(product_ramdisk).read_bytes())[1] if product_ramdisk else None
    source_text = Path(wrapper_source).read_text() if wrapper_source else None
    rd = ramdisk_info(ramdisk, test_ramdisk, cmdline, product_raw, source_text, selinux)
    if not test_ramdisk:
        modules = check_overlay_match(kernel_tree, overlay_record)
    board_variant = board
    board_path, board, dtb, identity = board_dtb(board_variant)
    if DTB_ADDR + len(dtb) > RAMDISK_ADDR:
        raise Refused('DT table runs into the ramdisk address')
    if not recovery_dtbo:
        raise Refused('recovery_dtbo is missing')
    if sha(recovery_dtbo) != RECOVERY_DTBO_SHA:
        raise Refused('recovery_dtbo is not the pinned empty overlay table')
    overlay = runpy.run_path(str(ROOT / 'tools/prepare-upgrade-boot-layout.py'))['parse_table'](recovery_dtbo)['entries'][0]
    if len(board) + len(overlay['blob']) > DTB_MERGE_MAX:
        raise Refused('boot DTB plus overlay is over the 512 KiB LK merge limit')
    regions = [('kernel', kernel_addr, KERNEL_RESERVE),
               ('dtb', DTB_ADDR, max(DTB_RESERVE_MIN, len(dtb))),
               ('ramdisk', RAMDISK_ADDR, RAMDISK_MAX)]
    for i, (a_name, a, a_size) in enumerate(regions):
        for b_name, b, b_size in regions[i + 1:]:
            if not (a + a_size <= b or b + b_size <= a):
                raise Refused('%s and %s regions overlap' % (a_name, b_name))
    # Captured stock and board reserved-memory: static placement only, LK rebuilds the map.
    checked = []
    for source, fdt in [('live-stock', LIVE_FDT.read_bytes()), ('board', board)]:
        for name, start, size in reserved_ranges(fdt):
            for region, address, count in regions:
                if not (address + count <= start or start + size <= address):
                    raise Refused('%s region overlaps %s %s' % (region, source, name))
            checked.append([source, name, start, size])

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tmp = Path(tmp)
        (tmp / 'kernel').write_bytes(kernel)
        (tmp / 'ramdisk').write_bytes(ramdisk)
        (tmp / 'dtb').write_bytes(dtb)
        (tmp / 'recovery_dtbo').write_bytes(recovery_dtbo)
        work = tmp / 'boot.img'
        command = [sys.executable, '-B', str(MKBOOTIMG), '--header_version', '2', '--pagesize', str(PAGE),
                   '--base', hex(BASE), '--kernel_offset', hex(kernel_addr - BASE),
                   '--ramdisk_offset', hex(RAMDISK_ADDR - BASE), '--tags_offset', hex(DTB_ADDR - BASE),
                   '--dtb_offset', hex(DTB_ADDR - BASE), '--os_version', OS_VERSION,
                   '--os_patch_level', OS_PATCH_LEVEL, '--kernel', str(tmp / 'kernel'),
                   '--ramdisk', str(tmp / 'ramdisk'), '--dtb', str(tmp / 'dtb'),
                   '--recovery_dtbo', str(tmp / 'recovery_dtbo'),
                   '--cmdline', cmdline, '--output', str(work)]
        subprocess.run(command, check=True)
        payload = work.read_bytes()
        # Room for the vbmeta blob and footer avbtool adds (well under 64 KiB with no key).
        if len(payload) + 0x10000 > PARTITION_SIZE:
            raise Refused('boot image payload %d bytes does not fit the 32 MiB partition' % len(payload))
        if PARTITION_SIZE > LK_STAGE_MAX:
            raise Refused('partition is over the LK 128 MiB stage limit')
        # Salt from the payload keeps the footer deterministic.
        avb = [sys.executable, '-B', str(AVBTOOL), 'add_hash_footer', '--image', str(work),
               '--partition_name', PARTITION, '--partition_size', str(PARTITION_SIZE),
               '--algorithm', 'NONE', '--hash_algorithm', 'sha256', '--salt', sha(payload),
               '--rollback_index', '0']
        subprocess.run(avb, check=True)
        if work.stat().st_size != PARTITION_SIZE:
            raise Refused('footered image is not the partition size')
        os.replace(work, output)
    image = output.read_bytes()
    record = {
        'state': 'Packaged offline; not staged, flashed or boot-tested',
        'selinux': selinux,
        'wrapper': selinux == 'permissive' and not rd['test_stub'],
        'vendor_overlay_match': modules if not test_ramdisk else None,
        'test_ramdisk': rd['test_stub'],
        'output': {'path': str(output), 'bytes': len(image), 'sha256': sha(image)},
        'payload': {'bytes': len(payload), 'sha256': sha(payload)},
        'header': {'version': 2, 'page_size': PAGE, 'base': BASE, 'kernel_addr': kernel_addr,
                   'ramdisk_addr': RAMDISK_ADDR, 'tags_addr': DTB_ADDR, 'dtb_addr': DTB_ADDR,
                   'os_version': OS_VERSION, 'os_patch_level': OS_PATCH_LEVEL, 'cmdline': cmdline},
        'avb': {'partition_name': PARTITION, 'partition_size': PARTITION_SIZE, 'algorithm': 'NONE',
                'hash_algorithm': 'sha256', 'salt': sha(payload), 'rollback_index': 0},
        'kernel': {'path': str(kernel_path), 'bytes': len(kernel), 'sha256': sha(kernel), 'arm64': arm64},
        'ramdisk': {'path': str(ramdisk_path), 'bytes': len(ramdisk), 'sha256': sha(ramdisk), **rd},
        'product_ramdisk': ({'path': str(product_ramdisk), 'sha256': sha(Path(product_ramdisk).read_bytes())}
                            if product_ramdisk and not rd['test_stub'] else None),
        'wrapper_source': ({'path': str(wrapper_source), 'sha256': sha(source_text.encode())}
                           if source_text is not None and not rd['test_stub'] and selinux == 'permissive' else None),
        'dtb': {'board': board_variant, 'board_dtb': board_path, 'board_sha256': sha(board), 'table_bytes': len(dtb),
                'table_sha256': sha(dtb), 'identity': identity},
        'recovery_dtbo': {'bytes': len(recovery_dtbo), 'sha256': sha(recovery_dtbo), 'overlay_bytes': len(overlay['blob'])},
        'regions': [{'name': n, 'address': a, 'bytes': s} for n, a, s in regions],
        'reserved_ranges_checked': checked,
        'commands': [command, avb],
        'tools_sha256': {str(p): sha(p.read_bytes()) for p in [Path(__file__), MKBOOTIMG, AVBTOOL]},
        'device_accessed': False,
    }
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--kernel', required=True, help='5.10 Image.gz')
    parser.add_argument('--ramdisk', required=True, help='first-stage ramdisk (gzip, lz4 legacy or cpio)')
    parser.add_argument('--output', required=True, help='boot image to write; must not exist')
    parser.add_argument('--product-ramdisk', default=PRODUCT_RAMDISK,
                        help='product ramdisk the wrapped one was built from (default: product-out)')
    parser.add_argument('--wrapper-source', default=str(WRAPPER_SOURCE), help='wrapper init.c the /init was built from')
    parser.add_argument('--test-ramdisk', action='store_true',
                        help='allow the stub test ramdisk; output name must contain "%s"' % TEST_NAME)
    parser.add_argument('--board', choices=sorted(BOARDS), default='modem-off',
                        help='modem-off (default) or modem-on (trial M only; output name must contain "modem-on")')
    parser.add_argument('--selinux', choices=SELINUX_MODES, default='permissive',
                        help='permissive (default, wrapper ramdisk) or enforcing (product ramdisk, no wrapper; '
                             'output name must contain "enforcing")')
    parser.add_argument('--extra-cmdline', default='', help='extra kernel command line words added after the standard ones')
    parser.add_argument('--kernel-tree', help='build tree of --kernel (vmlinux.symvers, kernel.release); required unless --test-ramdisk')
    parser.add_argument('--vendor-overlay-record', help='record.json of the vendor overlay whose modules go with this kernel; required unless --test-ramdisk')
    args = parser.parse_args()
    try:
        record = package(args.kernel, args.ramdisk, args.output, args.test_ramdisk,
                         product_ramdisk=args.product_ramdisk, wrapper_source=args.wrapper_source,
                         board=args.board, selinux=args.selinux,
                         cmdline=join_cmdline(cmdline_for(args.selinux), args.extra_cmdline),
                         kernel_tree=args.kernel_tree, overlay_record=args.vendor_overlay_record)
    except Refused as e:
        print('refused: ' + str(e), file=sys.stderr)
        sys.exit(2)
    Path(str(args.output) + '.json').write_text(json.dumps(record, indent=2) + '\n')
    print('boot image packaged: %s %s' % (record['output']['path'], record['output']['sha256']))


if __name__ == '__main__':
    main()
