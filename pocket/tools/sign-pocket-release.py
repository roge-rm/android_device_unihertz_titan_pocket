#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sign a Titan Pocket target-files zip with our release keys and make the full OTA.

Steps:
  1. A prepared copy of the target-files, so releasetools keeps our boot layout:
     - BOOTABLE_IMAGES/boot.img moves to PREBUILT_IMAGES/, which sign_target_files_apks
       re-signs as is (only the AVB footer changes). From BOOTABLE_IMAGES it would be copied
       with its test-key footer.
     - BOOTABLE_IMAGES/recovery.img is dropped, so recovery is rebuilt from RECOVERY/ with the
       new otacerts.zip.
     - mkbootimg_version_args gets the header os_version and os_patch_level from
       mkbootimg_args. releasetools puts the version args last, which would give os_version 16.
     - extra_recovery_keys is dropped, so recovery trusts only our releasekey.
  2. sign_target_files_apks: APKs and APEXes with our keys (-d, as LineageOS's "Signing
     builds" guide), otacerts replaced (-o), AVB key for vbmeta, vbmeta_system, boot and
     recovery.
  3. ota_from_target_files: a full block OTA signed with releasekey. Our releasetools.py goes
     with the target-files (META/releasetools.py).
  4. vbmeta.img, boot.img and recovery.img copied out for the installer.

Keys come from --keys, else release_keys in configs/local-paths.json (tools/make-pocket-release-keys.py). Writes only to --out. No phone access.
"""
import pocket_paths
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
PRODUCT_OUT = BULK / 'product-out/target/product/titan_pocket'
TARGET_FILES = PRODUCT_OUT / 'obj/PACKAGING/target_files_intermediates/lineage_titan_pocket-target_files.zip'
HOST = BULK / 'product-out/host/linux-x86'
OUT = BULK / 'release-signed'
KEYS = pocket_paths.release_keys()
SECURITY = 'build/make/target/product/security/'
CERTS = ['releasekey', 'platform', 'shared', 'media', 'networkstack', 'sdk_sandbox', 'bluetooth', 'nfc']
# What LK parses: stock's vbmeta and recovery are SHA256_RSA2048.
AVB_ALGORITHM = 'SHA256_RSA2048'
AVB_PARTITIONS = ['vbmeta', 'vbmeta_system', 'boot', 'recovery']


def run(cmd, env, log):
    print('+ ' + shlex.join(str(c) for c in cmd[:3]) + ' ...', flush=True)
    with log.open('a') as stream:
        stream.write('\n+ ' + shlex.join(str(c) for c in cmd) + '\n')
        stream.flush()
        result = subprocess.run([str(c) for c in cmd], env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f'{Path(cmd[0]).name} failed ({result.returncode}), see {log}')


def read_info(text):
    info = {}
    for line in text.splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            info[k] = v
    return info


def option(args, name):
    tokens = shlex.split(args)
    values = [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == name]
    if not values:
        raise SystemExit(f'mkbootimg_args has no {name}')
    return values[-1]


def prepare_misc_info(text):
    """Return misc_info.txt with the changes in step 1."""
    info = read_info(text)
    version = '--os_version %s --os_patch_level %s' % (option(info['mkbootimg_args'], '--os_version'),
                                                       option(info['mkbootimg_args'], '--os_patch_level'))
    # A recovery rebuild runs outside the source tree, so no source-relative paths in its args.
    rec = shlex.split(info.get('recovery_mkbootimg_args', ''))
    if '--recovery_dtbo' in rec:
        raise SystemExit('recovery_mkbootimg_args still has --recovery_dtbo; rebuild target-files '
                         'with the current BoardConfig.integration.mk')
    if info.get('include_recovery_dtbo') != 'true':
        raise SystemExit('include_recovery_dtbo is not true')
    lines = []
    for line in text.splitlines():
        if line.startswith('mkbootimg_version_args='):
            line = 'mkbootimg_version_args=' + version
        elif line.startswith('extra_recovery_keys='):
            continue
        lines.append(line)
    return '\n'.join(lines) + '\n'


def key_args(keys, tf):
    """sign_target_files_apks key options: the platform set, APEXes and module APKs."""
    # -d maps testkey to releasekey and the rest of the set by name, except nfc.
    args = ['-d', keys, '-k', f'{SECURITY}nfc={keys / "nfc"}']
    for name in CERTS:
        for suffix in ('.pk8', '.x509.pem'):
            if not (keys / (name + suffix)).is_file():
                raise SystemExit(f'missing {name}{suffix} in {keys}')
    # APEXes: payload and container keys of the same name, as the guide does.
    for line in tf.read('META/apexkeys.txt').decode().splitlines():
        fields = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if not fields or fields.get('private_key') == 'PRESIGNED':
            continue
        name = fields['name']
        base = name[:-len('.apex')] if name.endswith('.apex') else name[:-len('.capex')]
        for suffix in ('.pem', '.pk8', '.x509.pem'):
            if not (keys / (base + suffix)).is_file():
                raise SystemExit(f'no key for {name}: missing {base}{suffix} in {keys}')
        args += ['--extra_apks', f'{name}={keys / base}',
                 '--extra_apex_payload_key', f'{name}={keys / (base + ".pem")}']
    # APKs with a module certificate of their own (not one -d maps and not PRESIGNED) get
    # releasekey, as the guide's --extra_apks list does. This includes APKs inside APEXes,
    # which aren't in the target-files by themselves, so every apkcerts.txt entry is mapped.
    for line in tf.read('META/apkcerts.txt').decode().splitlines():
        fields = dict(re.findall(r'(\w+)="([^"]*)"', line))
        name, cert = fields.get('name'), fields.get('certificate', '')
        if not name or cert in ('PRESIGNED', '') or name.endswith(('.apex', '.capex')):
            continue
        base = cert[len(SECURITY):-len('.x509.pem')] if cert.startswith(SECURITY) else None
        if base in CERTS or base == 'testkey':
            continue
        args += ['--extra_apks', f'{name}={keys / "releasekey"}']
    avb = keys / 'avb.pem'
    if not avb.is_file():
        raise SystemExit(f'missing avb.pem in {keys}')
    for part in AVB_PARTITIONS:
        args += [f'--avb_{part}_key', avb, f'--avb_{part}_algorithm', AVB_ALGORITHM]
    return args


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--target-files', type=Path, default=TARGET_FILES)
    ap.add_argument('--keys', type=Path, default=KEYS,
                    help='key folder (default: release_keys in configs/local-paths.json)')
    ap.add_argument('--host', type=Path, default=HOST, help='host tools (out/host/linux-x86)')
    ap.add_argument('--out', type=Path, default=OUT)
    args = ap.parse_args()
    keys = args.keys.expanduser().resolve()
    if not keys.is_dir():
        raise SystemExit(f'no key folder {keys}')
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    log = out / 'sign.log'
    log.write_text('')
    env = dict(os.environ)
    env['PATH'] = str(args.host / 'bin') + os.pathsep + env['PATH']

    with zipfile.ZipFile(args.target_files) as tf:
        misc_info = prepare_misc_info(tf.read('META/misc_info.txt').decode())
        if tf.read('META/otakeys.txt').strip():
            raise SystemExit('META/otakeys.txt is not empty; check which keys it lists')
        sign_keys = key_args(keys, tf)
        boot = tf.read('BOOTABLE_IMAGES/boot.img')

    work = out / 'work'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    overrides = work / 'overrides.zip'
    with zipfile.ZipFile(overrides, 'w') as z:
        z.writestr('META/misc_info.txt', misc_info, zipfile.ZIP_DEFLATED)
        z.writestr('PREBUILT_IMAGES/boot.img', boot, zipfile.ZIP_STORED)
    prepared = work / 'prepared-target_files.zip'
    run([args.host / 'bin/merge_zips', '-ignore-duplicates', '-stripDir', 'BOOTABLE_IMAGES',
         prepared, overrides, args.target_files], env, log)

    signed = out / 'lineage_titan_pocket-signed-target_files.zip'
    ota = out / 'lineage_titan_pocket-signed-ota.zip'
    for path in (signed, ota):
        if path.exists():
            path.unlink()
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        env['TMPDIR'] = tmp
        run([args.host / 'bin/sign_target_files_apks', '-v', '-p', args.host, '-o',
             *sign_keys, prepared, signed], env, log)
        run([args.host / 'bin/ota_from_target_files', '-v', '-p', args.host, '--backup=true',
             '-k', keys / 'releasekey', signed, ota], env, log)
    prepared.unlink()
    overrides.unlink()
    work.rmdir()

    with zipfile.ZipFile(signed) as z:
        for name in ('vbmeta', 'vbmeta_system', 'boot', 'recovery'):
            (out / (name + '.img')).write_bytes(z.read(f'IMAGES/{name}.img'))
    print('Signed target-files: ' + str(signed))
    print('Signed OTA: ' + str(ota))
    print('Images: ' + ', '.join(str(out / (n + '.img')) for n in ('vbmeta', 'vbmeta_system', 'boot', 'recovery')))


if __name__ == '__main__':
    sys.exit(main())
