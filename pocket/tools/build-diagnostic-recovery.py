#!/usr/bin/env python3
"""Build and round-trip-check a stock-kernel recovery logger and exact restore image.

Local artifact preparation only: no ADB, SSH, fastboot or device writes.
"""
import pocket_paths
import gzip
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RECOVERY_SHA = 'c18cce5f01d69796ab2991fca0e5a5246185c775a87bc1598655a3e4f9539967'
BOOT_SHA = '065e115909e1c92d26d85d1d24873f333aeb3a67c00ba65d565b56d176f8cd51'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def table(data):
    magic, total, header, entry_size, count, entries, page, version = struct.unpack_from('>8I', data)
    assert magic == 0xd7b7ab1e and total <= len(data)
    assert header == 32 and entry_size == 32 and count == 1
    assert entries >= header and entries + count * entry_size <= total
    size, offset, *_ = struct.unpack_from('>8I', data, entries)
    assert offset + size <= total and data[offset:offset+4] == b'\xd0\x0d\xfe\xed'
    assert struct.unpack_from('>I', data, offset + 4)[0] <= size
    return {'bytes': len(data), 'table_bytes': total, 'entries': count,
            'fdt_offset': offset, 'fdt_bytes': size, 'page_size': page, 'version': version}


def build(evidence, output):
    if (output / 'diagnostic-recovery.img').exists():
        raise RuntimeError('Refusing to overwrite an existing diagnostic; choose a new output directory')
    evidence.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    backup = ROOT / 'backups/stock-20261029T001105.670723Z'
    manifest = json.loads((backup / 'manifest.json').read_text())
    partition = next(p for p in manifest['partitions'] if p['name'] == 'recovery')
    compressed = (backup / partition['file']).read_bytes()
    assert sha(compressed) == partition['stored_sha256']
    original = gzip.decompress(compressed)
    assert sha(original) == partition['raw_sha256'] == RECOVERY_SHA
    assert len(original) == partition['bytes'] == 33554432
    restore = output / 'stock-recovery-restore.img'
    restore.write_bytes(original)
    fields = struct.unpack_from('<10I', original, 8)
    assert original[:8] == b'ANDROID!' and fields[4:6] == (0, 0)
    assert fields[7:9] == (2048, 2)
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    unpack = ROOT / 'tools/unpack_bootimg.py'
    mkboot = pocket_paths.platform_source() / 'system/tools/mkbootimg/mkbootimg.py'
    with tempfile.TemporaryDirectory(prefix='recovery-verify-', dir=output) as temp:
        extracted = Path(temp) / 'original'
        subprocess.run([sys.executable, '-B', str(unpack), '--boot_img', str(restore), '--out', str(extracted)],
                       env=env, check=True, capture_output=True, text=True)
        for name in ['kernel', 'ramdisk', 'dtb', 'recovery_dtbo']:
            assert (extracted / name).read_bytes() == (ROOT / 'firmware/installed-20230105/recovery' / name).read_bytes()
        kernel = (extracted / 'kernel').read_bytes()
        dtb = (extracted / 'dtb').read_bytes()
        dtbo = (extracted / 'recovery_dtbo').read_bytes()
        tables = {'dtb': table(dtb), 'recovery_dtbo': table(dtbo)}
        raw_kernel = gzip.decompress(kernel)
        start = raw_kernel.index(b'IKCFG_ST') + 8
        config = gzip.decompress(raw_kernel[start:raw_kernel.index(b'IKCFG_ED', start)]).decode()
        required = ['USB_GADGET', 'USB_CONFIGFS', 'USB_CONFIGFS_ACM', 'USB_F_ACM',
                    'TMPFS', 'CONFIGFS_FS', 'PROC_FS', 'SYSFS', 'BINFMT_ELF', 'BLK_DEV_INITRD', 'RD_GZIP']
        assert all(f'CONFIG_{key}=y' in config.splitlines() for key in required)
        (evidence / 'stock-recovery-kernel.config').write_text(config)
        builder = runpy.run_path(str(ROOT / 'tools/build-upgrade-ramdisk.py'), run_name='ramdisk_library')['build']
        ramdisk_record = builder(ROOT / 'kernel-upgrade/recovery-probe/init.c', output,
                                 evidence / 'ramdisk-validation.json')
        ramdisk = output / 'ramdisk.cpio.gz'
        image = output / 'diagnostic-recovery.img'
        cmdline = 'bootopt=64S3,32N2,64N2 buildvariant=user rdinit=/init tpdiag=recovery loglevel=8 panic=15'
        command = [sys.executable, '-B', str(mkboot), '--header_version', '2', '--pagesize', '2048',
                   '--base', '0x40000000', '--kernel_offset', hex(fields[1] - 0x40000000),
                   '--ramdisk_offset', hex(fields[3] - 0x40000000),
                   '--tags_offset', hex(fields[6] - 0x40000000),
                   '--dtb_offset', hex(struct.unpack_from('<Q', original, 1652)[0] - 0x40000000),
                   '--os_version', '11.0.0', '--os_patch_level', '2022-09',
                   '--kernel', str(extracted / 'kernel'), '--ramdisk', str(ramdisk),
                   '--dtb', str(extracted / 'dtb'), '--recovery_dtbo', str(extracted / 'recovery_dtbo'),
                   '--cmdline', cmdline, '--output', str(image)]
        subprocess.run(command, env=env, check=True)
        data = image.read_bytes()
        unpadded_size = len(data)
        assert unpadded_size < len(original)
        data += b'\0' * (len(original) - unpadded_size)
        image.write_bytes(data)
        actual = struct.unpack_from('<10I', data, 8)
        for index in [0, 1, 3, 4, 5, 6, 7, 8, 9]:
            assert actual[index] == fields[index], (index, actual[index], fields[index])
        assert actual[2] == ramdisk.stat().st_size
        assert data[48:64] == original[48:64]
        assert struct.unpack_from('<I', data, 1644)[0] == 1660
        assert struct.unpack_from('<Q', data, 1652)[0] == struct.unpack_from('<Q', original, 1652)[0]
        dtbo_size, dtbo_offset = struct.unpack_from('<IQ', data, 1632)
        assert dtbo_size == len(dtbo) and dtbo_offset % 2048 == 0
        assert data[dtbo_offset:dtbo_offset+dtbo_size] == dtbo
        extracted_probe = Path(temp) / 'probe'
        checked = subprocess.run([sys.executable, '-B', str(unpack), '--boot_img', str(image),
                                  '--out', str(extracted_probe)], env=env, check=True, capture_output=True, text=True)
        for name, expected in [('kernel', kernel), ('ramdisk', ramdisk.read_bytes()), ('dtb', dtb), ('recovery_dtbo', dtbo)]:
            assert (extracted_probe / name).read_bytes() == expected, name
        assert all(x == 0 for x in data[unpadded_size:])
    record = {'status': 'locally_verified_not_installed_or_boot_tested',
              'diagnostic_image': {'path': str(image.relative_to(ROOT)), 'bytes': len(data),
                                   'unpadded_bytes': unpadded_size, 'sha256': sha(data)},
              'restore_image': {'path': str(restore.relative_to(ROOT)), 'bytes': len(original), 'sha256': RECOVERY_SHA},
              'expected_unchanged_boot_sha256': BOOT_SHA,
              'preserved_components': {name: {'bytes': len(value), 'sha256': sha(value)}
                                       for name, value in [('kernel', kernel), ('dtb', dtb), ('recovery_dtbo', dtbo)]},
              'tables': tables, 'required_builtin_kernel_options': required,
              'devtmpfs_present': 'CONFIG_DEVTMPFS=y' in config.splitlines(),
              'device_nodes': 'RAM tmpfs fallback; explicit console/null/kmsg and ttyGS0 from sysfs major:minor',
              'automatic_restart_seconds': 120, 'automatic_restart_limit': 'Requires init to run and kernel reboot support; does not restore recovery or clear BCB',
              'roundtrip': 'All four unpacked components match their intended inputs exactly',
              'header_dump': checked.stdout,
              'mkbootimg_sha256': sha(mkboot.read_bytes()), 'unpacker_sha256': sha(unpack.read_bytes()),
              'logger_sources': ramdisk_record['source_inputs'],
              'kernel_version': 'preserved stock4.14, not5.10',
              'writes_performed_by_builder': 'Local artifacts only; no device access',
              'device_requirements': ['Owner present and physical restart/bootloader route checked',
                                      'Current stock identity and boot/recovery hashes match backups',
                                      'BCB command empty; use physical recovery entry without setting boot-recovery',
                                      'Restore image staged and checked on the test host',
                                      'Separate review before writing recovery; boot/vbmeta/DTBO remain untouched'],
              'limits': ['No hardware/USB/reboot test passed by a local build',
                         'Temporarily replaces stock recovery if installed; restore explicitly afterward',
                         'No Android services or userdata mounts; stock kernel still initializes hardware',
                         'Unsigned diagnostic for an already unlocked handset; no vbmeta or bootloader change']}
    (evidence / 'package-validation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Diagnostic recovery verified: {len(data)} bytes; original kernel, DTB and embedded DTBO preserved')
    print('Exact stock recovery restore verified; no device write performed')
    return record


def main():
    import argparse
    import re
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', required=True, help='New artifact variant; existing images are never overwritten')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', args.variant):
        parser.error('Use a lowercase name with digits or hyphens, at most 40 characters')
    build(ROOT / ('evidence/kernel-upgrade/recovery-' + args.variant + '-preparation'),
          ROOT / ('artifacts/kernel-upgrade/recovery-' + args.variant))


if __name__ == '__main__':
    main()
