#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the real engineering product in a separate read-only source view.

Compilation does not grant installation qualification or perform phone actions.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BASE = runpy.run_path(str(ROOT / 'tools/run-pocket-source-build.py'), run_name='source_view')
BULK = BASE['BULK']
SHARED = BASE['SHARED']
TARGETS = {'nothing', 'systemimage', 'productimage', 'bootimage', 'recoveryimage',
           'target-files-package', 'otapackage', 'check-vintf-all', 'libgui', 'libmedia',
           'libstagefright', 'libstagefright_foundation', 'plat_sepolicy.cil',
           'PocketKeyguardOverlay', 'PocketTelephonyFrameworkOverlay', 'PocketUpdaterOverlay',
           # Power HAL (device power/) and its config, alone; its policy goes with plat_sepolicy.cil
           # and the system_ext policy targets.
           'android.hardware.power-service.pocket', 'powerhint.pocket.json',
           'system_ext_sepolicy.cil',
           # The framework hook (services.jar) and the Pocket keyboard app, alone.
           'services', 'PocketInputSettings',
           # Recovery ramdisk alone, for tools/package-pocket-recovery.py.
           'out/target/product/titan_pocket/ramdisk-recovery.img'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('targets', nargs='+')
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--camera-debug', action='store_true',
                        help='camera trial builds: add init.pocket.camdebug.rc (mtkcam debug logs) to product')
    parser.add_argument('--ims', action='store_true',
                        help='IMS and VoLTE (POCKET_IMS and POCKET_IMS_FIDO_VOLTE, ims/ims.mk)')
    parser.add_argument('--gapps', action='store_true',
                        help='Google apps from MindTheGapps in the shared source vendor/gapps (POCKET_GAPPS, GAPPS.md)')
    parser.add_argument('--dev-adb-keys', action='store_true',
                        help='development builds: trust the staged host adb keys in system and recovery '
                             '(POCKET_DEV_ADB_KEYS, needs prepare-pocket-product-inputs.py --adb-keys)')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    if set(args.targets) - TARGETS:
        parser.error('Only explicit engineering compilation targets are accepted')
    inputs = json.loads((ROOT / 'evidence/product-build/private-inputs.json').read_text())
    vendor = Path(inputs['output'])
    for entry in inputs['inputs']:
        assert digest(Path(entry['destination'])) == entry['sha256']
    for name, sha in inputs['generated_files'].items():
        assert digest(vendor / name) == sha
    if args.dev_adb_keys and not (vendor / 'proprietary/adb_keys').is_file():
        raise SystemExit('--dev-adb-keys needs prepare-pocket-product-inputs.py --adb-keys first')
    mappings = {str(BULK / n): str(BULK / ('product-' + n)) for n in ['source', 'out', 'tmp', 'home']}
    for value in mappings.values():
        Path(value).mkdir(parents=True, exist_ok=True)
    command = BASE['command'](args.targets)
    # Lineage's actual product excludes protobuf_vendorcompat itself and uses
    # hardware/lineage/compat. The generic audit's inverse override is inapplicable.
    audit_override = str(ROOT / 'artifacts/build-overrides/hardware-lineage-compat.Android.bp')
    for i in range(len(command) - 2):
        if command[i:i + 2] == ['--ro-bind', audit_override]:
            del command[i:i + 3]
            break
    for i, arg in enumerate(command):
        for old, new in mappings.items():
            if arg == old or arg.startswith(old + '/'):
                command[i] = new + arg[len(old):]
                break
        if arg == 'titan_pocket_policy_audit':
            command[i] = 'lineage_titan_pocket'
        if arg == '-j12':
            command[i] = '-j' + str(args.jobs)
    view = Path(mappings[str(BULK / 'source')])
    additions = ['--tmpfs', str(view / 'vendor')]
    if args.gapps and not (SHARED / 'vendor/gapps/arm64/arm64-vendor.mk').is_file():
        raise SystemExit('--gapps needs MindTheGapps in ' + str(SHARED / 'vendor/gapps') + ' (GAPPS.md)')
    for child in sorted((SHARED / 'vendor').iterdir()):
        # vendor/gapps is only in the view for --gapps, so other builds don't parse its modules.
        if child.name == 'gapps' and not args.gapps:
            continue
        if child.name != 'unihertz':
            additions += ['--ro-bind', str(child.resolve()), str(view / 'vendor' / child.name)]
    additions += ['--dir', str(view / 'vendor/unihertz'), '--ro-bind', str(vendor), str(view / 'vendor/unihertz/titan_pocket'),
                  '--setenv', 'POCKET_ENGINEERING_BUILD', 'true']
    if args.camera_debug:
        additions += ['--setenv', 'POCKET_CAMERA_DEBUG', 'true']
    if args.ims:
        additions += ['--setenv', 'POCKET_IMS', 'true', '--setenv', 'POCKET_IMS_FIDO_VOLTE', 'true']
    if args.gapps:
        additions += ['--setenv', 'POCKET_GAPPS', 'true']
    if args.dev_adb_keys:
        additions += ['--setenv', 'POCKET_DEV_ADB_KEYS', 'true']
    # The product's 30.0.compat.cil, from tools/stage-pocket-sepolicy-compat.py. The source
    # audit view keeps the upstream file.
    compat = json.loads((ROOT / 'evidence/kernel-upgrade/sepolicy-compat-patch.json').read_text())
    override = ROOT / 'artifacts/build-overrides/sepolicy-30.0.compat.cil'
    if digest(SHARED / compat['file']) != compat['original_sha256'] or digest(override) != compat['override_sha256']:
        raise SystemExit('30.0.compat.cil override is stale; run tools/stage-pocket-sepolicy-compat.py')
    additions += ['--ro-bind', str(override), str(view / compat['file'])]
    at = command.index('--chdir')
    command[at:at] = additions
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    log = BULK / 'logs' / (stamp + '-real-product.log')
    print('Engineering product log: ' + str(log), flush=True)
    with log.open('w') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    record = {'utc': stamp, 'targets': args.targets, 'returncode': result.returncode,
              'log': str(log), 'command': command, 'product': 'lineage_titan_pocket',
              'source_read_only': True, 'network_isolated': True, 'device_accessed': False,
              'camera_debug': args.camera_debug, 'ims': args.ims, 'gapps': args.gapps, 'dev_adb_keys': args.dev_adb_keys, 'output': mappings[str(BULK / 'out')], 'source_image_qualified_for_installation': False,
              'private_inputs_sha256': digest(ROOT / 'evidence/product-build/private-inputs.json'),
              'tool_sha256': digest(Path(__file__))}
    log.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Engineering product exit ' + str(result.returncode), flush=True)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
