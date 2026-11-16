#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare private, hash-recorded stock runtime inputs for the real product build.

No signing, network, phone access or installation. Generated proprietary inputs
stay in bulk storage and outside the public source export.
"""
import pocket_paths
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BOOT = runpy.run_path(str(ROOT / 'tools/package-pocket-boot.py'))
# Boot p23's kernel build tree (artifacts/firstboot-5.10-p23/build.sh).
KERNEL_TREE = BULK / 'kernel-firstboot-5.10-enforcing-p23-all'
VENDOR_OTA = pocket_paths.private_vendor_overlay() / 'v13/ota/pocket_vendor_overlay.zip'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-tree', type=Path, default=KERNEL_TREE,
                        help='5.10 build tree with arch/arm64/boot/Image.gz and .config')
    parser.add_argument('--board', choices=sorted(BOOT['BOARDS']), default='modem-on', help='board dtb variant')
    # Host public keys for development builds (POCKET_DEV_ADB_KEYS, run-pocket-product-build.py
    # --dev-adb-keys). Left out unless given, so release builds can't pick up stale keys.
    parser.add_argument('--adb-keys', type=Path, help='adb_keys file, from your stock backup')
    parser.add_argument('--vendor-ota', type=Path, default=VENDOR_OTA,
                        help='vendor overlay payload from tools/prepare-pocket-vendor-ota.py')
    args = parser.parse_args()
    stock = ROOT / 'firmware/installed-20230105'
    tree = args.kernel_tree.resolve()
    inputs = {
        'vendor.img': stock / 'vendor.img',
        'com.android.vndk.v30.apex': stock / 'rootfs/system/system/apex/com.android.vndk.current.apex',
        'kernel': tree / 'arch/arm64/boot/Image.gz',
        'engineering.config': tree / '.config',
        # Vendor overlay files for OTAs (tools/prepare-pocket-vendor-ota.py), read by
        # releasetools.py from target-files RADIO/.
        'pocket_vendor_overlay.zip': args.vendor_ota,
    }
    if args.adb_keys:
        inputs['adb_keys'] = args.adb_keys
    assert inputs['vendor.img'].stat().st_size == 452378624
    assert digest(inputs['com.android.vndk.v30.apex']) == '6b11afc6fe900e839e23a65581a516d57729a3a9efabf75ec4ed611ee6c85177'
    kernel = inputs['kernel'].read_bytes()
    BOOT['check_arm64'](BOOT['inflate_kernel'](kernel), BOOT['KERNEL_ADDR'])
    config = inputs['engineering.config'].read_text()
    assert 'CONFIG_ARM64=y\n' in config and 'CONFIG_ARCH_MEDIATEK=y\n' in config
    with zipfile.ZipFile(inputs['pocket_vendor_overlay.zip']) as z:
        assert json.loads(z.read('manifest.json'))['version'] == 'v13'
    if args.adb_keys:
        keys = inputs['adb_keys'].read_text().splitlines()
        assert keys and all(k.startswith('QAAAA') for k in keys)
    output = pocket_paths.private_vendor() / 'unihertz/titan_pocket'
    proprietary = output / 'proprietary'
    proprietary.mkdir(parents=True, exist_ok=True)
    stale = proprietary / 'adb_keys'
    if not args.adb_keys and stale.exists():
        os.remove(stale)
    records = []
    for name, src in inputs.items():
        dest = proprietary / name
        before = digest(src)
        if not dest.exists() or digest(dest) != before:
            shutil.copyfile(src, dest)
        assert digest(dest) == before and digest(src) == before
        records.append({'source': str(src), 'destination': str(dest), 'bytes': dest.stat().st_size, 'sha256': before})
    # The board dtb packed in the stock DT table, and the empty recovery_dtbo, as
    # package-pocket-boot.py lays them out. BoardConfig.integration.mk reads both.
    board_path, board, table, _ = BOOT['board_dtb'](args.board)
    (proprietary / 'dtb').mkdir(exist_ok=True)
    generated = {'dtb/board.dtb': table, 'recovery_dtbo.img': BOOT['RECOVERY_DTBO']}
    assert digest_bytes(BOOT['RECOVERY_DTBO']) == BOOT['RECOVERY_DTBO_SHA']
    for name, data in generated.items():
        dest = proprietary / name
        if not dest.exists() or dest.read_bytes() != data:
            dest.write_bytes(data)
        records.append({'source': board_path if name.startswith('dtb/') else 'package-pocket-boot.py RECOVERY_DTBO',
                        'board': args.board if name.startswith('dtb/') else None,
                        'destination': str(dest), 'bytes': len(data), 'sha256': digest_bytes(data)})
    extra = sorted(p.name for p in (proprietary / 'dtb').iterdir() if p.name != 'board.dtb')
    assert not extra, 'the build joins every .dtb in proprietary/dtb: ' + ', '.join(extra)
    (output / 'Android.bp').write_text('''// PRIVATE generated input; never export the proprietary directory.
prebuilt_apex {
    name: "com.android.vndk.v30",
    src: "proprietary/com.android.vndk.v30.apex",
    prefer: true,
    filename: "com.android.vndk.v30.apex",
}
''')
    (output / 'titan_pocket-vendor.mk').write_text('''# PRIVATE generated input; coherent January vendor image.
PRODUCT_PACKAGES += com.android.vndk.v30
''')
    record = {'inputs': records, 'generated_files': {p.name: digest(p) for p in [output / 'Android.bp', output / 'titan_pocket-vendor.mk']},
              'output': str(output), 'device_accessed': False, 'qualified_for_installation': False,
              'limits': ['Userspace integration inputs only; full kernel/board, policy, HAL/runtime and installation qualification remain open',
                         'VNDK APEX presence is not proof of activation or target namespace/ABI closure',
                         'No proprietary redistribution permission is asserted']}
    evidence = ROOT / 'evidence/product-build'
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'private-inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Private vendor/VNDK/source-built kernel inputs staged in bulk storage; no phone access')


if __name__ == '__main__':
    main()
