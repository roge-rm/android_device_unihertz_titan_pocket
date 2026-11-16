#!/usr/bin/env python3
"""Package a stock-kernel RAM logger; does not contact or flash a device."""
import pocket_paths
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    stock = ROOT / 'firmware/installed-20230105/boot'
    kernel, dtb = stock / 'kernel', stock / 'dtb'
    expected = {'kernel': 'cdc178431715fdab0f5d6c4eeb0e9606da4780e8728e6c83cd4672a3960a210b',
                'dtb': 'd11daad1f7a03f0c4f22734902b994a52ed4d97817c579976d00858b85fc0c8d'}
    for name, digest in expected.items():
        assert hashlib.sha256((stock / name).read_bytes()).hexdigest() == digest
    out = ROOT / 'artifacts/kernel-upgrade/ram-probe'
    ramdisk = out / 'ramdisk.cpio.gz'
    evidence = json.loads((ROOT / 'evidence/kernel-upgrade/ramdisk-validation.json').read_text())
    assert hashlib.sha256((ROOT / 'kernel-upgrade/ram-probe/init.c').read_bytes()).hexdigest() == evidence['source_sha256']
    for item in evidence['files']:
        p = ROOT / item['path']
        assert hashlib.sha256(p.read_bytes()).hexdigest() == item['sha256']
    image = out / 'stock-kernel-ramlog.img'
    tool = pocket_paths.platform_source() / 'system/tools/mkbootimg/mkbootimg.py'
    command = [sys.executable, '-B', str(tool), '--header_version', '2', '--pagesize', '2048',
               '--base', '0x40000000', '--kernel_offset', '0x80000',
               '--ramdisk_offset', '0x15000000', '--tags_offset', '0x14000000',
               '--dtb_offset', '0x14000000', '--os_version', '11.0.0',
               '--os_patch_level', '2022-09', '--kernel', str(kernel),
               '--ramdisk', str(ramdisk), '--dtb', str(dtb),
               '--cmdline', 'bootopt=64S3,32N2,64N2 buildvariant=user rdinit=/init loglevel=8 panic=0',
               '--output', str(image)]
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    subprocess.run(command, env=env, check=True)
    data = image.read_bytes()
    assert data[:8] == b'ANDROID!' and len(data) < 33554432
    fields = struct.unpack_from('<10I', data, 8)
    assert fields[0] == kernel.stat().st_size and fields[1] == 0x40080000
    assert fields[2] == ramdisk.stat().st_size and fields[3] == 0x55000000
    assert fields[6] == 0x54000000 and fields[7] == 2048 and fields[8] == 2
    # Independent round-trip through the existing unpacker, entirely local.
    with tempfile.TemporaryDirectory(prefix='transport-roundtrip-', dir=out) as tmp:
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/unpack_bootimg.py'),
                                 '--boot_img', str(image), '--out', tmp],
                                 env=env, check=True, capture_output=True, text=True)
        for name, original in [('kernel', kernel), ('ramdisk', ramdisk), ('dtb', dtb)]:
            assert (Path(tmp) / name).read_bytes() == original.read_bytes(), name
    record = {'image': str(image.relative_to(ROOT)), 'bytes': len(data),
              'sha256': hashlib.sha256(data).hexdigest(), 'command': command,
              'tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
              'stock_component_sha256': expected,
              'unpack_header': result.stdout, 'roundtrip': 'Kernel, ramdisk and DTB bytes match inputs exactly',
              'device_contacted': False, 'partition_written': False,
              'purpose': 'First validate temporary boot + RAM-only USB log transport with known stock kernel/DTB',
              'limitations': ['Not LineageOS and not a 5.10 boot test',
                              'Logger does not mount/open block devices; stock kernel still probes its hardware normally',
                              'No proof fastboot boot is supported or USB logger enumerates',
                              'Only for an attended temporary-boot test after phone testing resumes; not a flashing artifact']}
    (ROOT / 'evidence/kernel-upgrade/transport-probe-package.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Local stock-kernel transport probe packaged and round-trip checked: {len(data)} bytes; no device access')


if __name__ == '__main__':
    main()
