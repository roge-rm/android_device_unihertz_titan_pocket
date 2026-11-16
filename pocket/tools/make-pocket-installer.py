#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Make the owner installer zip from a signed release (tools/sign-pocket-release.py output).

  make-pocket-installer.py RELEASE_DIR OUT.zip

Takes boot.img, recovery.img and vbmeta.img from the release folder, system.img and product.img
from its signed target-files zip, and the vendor payload and pocket_vendor.sh from its signed
OTA zip (the same files an OTA applies). The OTA's boot and recovery must match the folder's.
Adds the installer tools, configs/stock-backup.json, configs/release-gates.json, the launchers
and README.txt from tools/installer/, and manifest.json with every file's sha256 and the write
plan, which validate-pocket-install.py checks here and again on the owner's computer.

Refuses any file whose sha256 is a known Unihertz file: the camerapostalgo files and stock
recovery in stock-backup.json and every stock hash in the vendor payload manifest. The payload's
manifest.json loses the paths of the private images it was made from, and any text file that
still names a private build path is refused.
Everything is put together in --work first (default build/pocket-installer/), then zipped
into one top folder named after OUT.zip.
"""
import pocket_paths
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
TEMPLATES = TOOLS / 'installer'
CHUNK = 1024 * 1024

TOOL_FILES = ['pocket_phone.py', 'pocket-install.py', 'pocket-stock-backup.py', 'pocket-stock-restore.py',
              'pocket-vendor-apply.py', 'validate-pocket-install.py']
LAUNCHERS = ['install.sh', 'install.command', 'install.bat', 'README.txt']
EXECUTABLE = {'install.sh', 'install.command', 'tools/pocket-install.py'}
# Write order: our recovery in LK, then system and product in fastbootd, then LK.
PLAN = [('recovery', 'bootloader'), ('system', 'fastbootd'), ('product', 'fastbootd'),
        ('boot', 'bootloader'), ('vbmeta', 'bootloader')]
# Text that would give away private build paths. Images aren't scanned.
PRIVATE_MARKERS = tuple(m.encode() for m in pocket_paths.PRIVATE_MARKERS)
DEVICE = {
    # LK getvar product (saved answers, evidence/stock-recovery-readiness/bootloader-queries.json).
    'lk_product': 'g66v71c2k_dfl_tee',
    # Stock fastbootd says Titan_pocket; ours reports ro.product.device.
    'fastbootd_products': ['titan_pocket', 'Titan_pocket'],
    'vendor_payload': 'vendor/payload',
    'vendor_script': 'vendor/pocket_vendor.sh',
}


class BuildError(RuntimeError):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def one(folder, pattern):
    found = sorted(folder.glob(pattern))
    if len(found) != 1:
        raise BuildError(f'{folder} needs exactly one {pattern}, found {len(found)}')
    return found[0]


def extract(z, member, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with z.open(member) as src, open(dest, 'wb') as out:
        for block in iter(lambda: src.read(CHUNK), b''):
            h.update(block)
            out.write(block)
    return h.hexdigest()


def unihertz_hashes(cfg, payload_manifest):
    known = {}
    for rel, h in cfg['camerapostalgo']['files'].items():
        known[h] = f'stock {rel}'
    for release, v in cfg['stock_recovery'].items():
        if isinstance(v, dict):
            known[v['sha256']] = f'stock recovery {release}'
    for e in payload_manifest.get('entries', []):
        if e.get('stock_sha256'):
            known[e['stock_sha256']] = f'stock vendor {e["path"]}'
        for a in e.get('accept', []):
            if a.get('sha256') and a['sha256'] != e.get('target_sha256'):
                known.setdefault(a['sha256'], f'stock vendor {e["path"]} ({"+".join(a.get("from", []))})')
    return known


def public_payload_manifest(path):
    """Drops the private image paths from the payload's manifest.json. Hashes and sizes stay."""
    manifest = json.loads(path.read_text())
    for key in ('base', 'overlay'):
        if isinstance(manifest.get(key), dict):
            manifest[key].pop('path', None)
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def is_text(data):
    if b'\0' in data:
        return False
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return True


def private_text(root):
    """[(relative path, marker)] for text files under root that name a private path."""
    hits = []
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.suffix == '.img':
            continue
        data = p.read_bytes()
        if is_text(data):
            hits += [(p.relative_to(root).as_posix(), m.decode()) for m in PRIVATE_MARKERS if m in data]
    return hits


def ota_metadata(z):
    meta = {}
    for line in z.read('META-INF/com/android/metadata').decode().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            meta[k.strip()] = v.strip()
    return meta


def stage(release, work, gates_path):
    release = Path(release)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    signing = json.loads((release / 'check-signing.json').read_text())
    if signing.get('vbmeta_flags') != 3 or not str(signing.get('recovery_avb', '')).startswith('our key'):
        raise BuildError('check-signing.json does not show a flags 3 vbmeta and a recovery signed with our key')
    files = {}
    for name in ('boot', 'recovery', 'vbmeta'):
        dest = work / 'images' / f'{name}.img'
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(release / f'{name}.img', dest)
        files[f'images/{name}.img'] = sha256_file(dest)
    with zipfile.ZipFile(one(release, '*-signed-target_files.zip')) as tf:
        for name in ('system', 'product'):
            files[f'images/{name}.img'] = extract(tf, f'IMAGES/{name}.img', work / 'images' / f'{name}.img')
    with zipfile.ZipFile(one(release, '*-signed-ota.zip')) as ota:
        meta = ota_metadata(ota)
        if meta.get('pre-device') != 'titan_pocket':
            raise BuildError(f'the OTA is for {meta.get("pre-device")}')
        for name in ('boot', 'recovery'):
            with ota.open(f'{name}.img') as f:
                h = hashlib.sha256()
                for block in iter(lambda: f.read(CHUNK), b''):
                    h.update(block)
            if h.hexdigest() != files[f'images/{name}.img']:
                raise BuildError(f'the OTA {name}.img differs from the release folder: not the same release')
        payload = [n for n in ota.namelist() if n.startswith('pocket/payload/') and not n.endswith('/')]
        for n in payload + ['pocket/pocket_vendor.sh']:
            rel = Path(n).relative_to('pocket')
            if rel.is_absolute() or '..' in rel.parts:
                raise BuildError(f'bad path {n} in the OTA')
            files[f'vendor/{rel.as_posix()}'] = extract(ota, n, work / 'vendor' / rel)
    payload_manifest = public_payload_manifest(work / 'vendor/payload/manifest.json')
    files['vendor/payload/manifest.json'] = sha256_file(work / 'vendor/payload/manifest.json')
    (work / 'tools').mkdir()
    for rel in TOOL_FILES:
        shutil.copyfile(TOOLS / rel, work / 'tools' / rel)
        files[f'tools/{rel}'] = sha256_file(work / 'tools' / rel)
    (work / 'configs').mkdir()
    shutil.copyfile(ROOT / 'configs/stock-backup.json', work / 'configs/stock-backup.json')
    shutil.copyfile(gates_path, work / 'configs/release-gates.json')
    for rel in ('configs/stock-backup.json', 'configs/release-gates.json'):
        files[rel] = sha256_file(work / rel)
    for rel in LAUNCHERS:
        data = (TEMPLATES / rel).read_bytes().replace(b'\r\n', b'\n')
        if rel.endswith('.bat') or rel.endswith('.txt'):
            data = data.replace(b'\n', b'\r\n')
        (work / rel).write_bytes(data)
        files[rel] = hashlib.sha256(data).hexdigest()

    cfg = json.loads((ROOT / 'configs/stock-backup.json').read_text())
    known = unihertz_hashes(cfg, payload_manifest)
    bad = [f'{rel} is {known[h]}' for rel, h in files.items() if h in known]
    if bad:
        raise BuildError('Unihertz files in the installer:\n  ' + '\n  '.join(bad))

    hits = private_text(work)
    if hits:
        raise BuildError('private paths in the installer:\n  ' + '\n  '.join(f'{f}: {m}' for f, m in hits))

    gates = json.loads(Path(gates_path).read_text())
    plan = {'schema': 1, 'product': 'Titan_pocket', 'stock_firmware': gates['supported_stock_firmware'][0],
            'data_action': 'wipe', 'format': ['userdata', 'md_udc'], 'avb_qualified': True,
            'images': [{'partition': p, 'file': f'images/{p}.img', 'sha256': files[f'images/{p}.img'], 'mode': m}
                       for p, m in PLAN]}
    validator = runpy.run_path(str(TOOLS / 'validate-pocket-install.py'))
    closed = copy.deepcopy(gates)
    closed['qualified'] = {k: True for k in validator['REQUIRED_GATES']}
    validator['validate'](plan, work, closed)
    try:
        validator['validate'](plan, work, gates)
        gates_open = []
    except validator['InvalidPlan'] as e:
        gates_open = [str(e)]
    stamp = datetime.fromtimestamp(int(meta['post-timestamp']), timezone.utc)
    manifest = {
        'schema': 1,
        'release': {'name': stamp.strftime('%Y%m%d') + '-' + meta.get('post-build-incremental', ''),
                    'post_build': meta.get('post-build'), 'post_timestamp': int(meta['post-timestamp']),
                    'security_patch': meta.get('post-security-patch-level'),
                    'avb_key_sha1': signing.get('avb_key_sha1'), 'vendor_payload': payload_manifest.get('version')},
        'device': DEVICE,
        'plan': plan,
        'files': dict(sorted(files.items())),
    }
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest, gates_open


def write_zip(work, out, top):
    tmp = out.with_name(out.name + '.part')
    paths = sorted(p for p in work.rglob('*') if p.is_file())
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for p in paths:
            rel = p.relative_to(work).as_posix()
            info = zipfile.ZipInfo(f'{top}/{rel}', date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((0o100755 if rel in EXECUTABLE else 0o100644) << 16)
            with open(p, 'rb') as src, z.open(info, 'w', force_zip64=True) as dst:
                for block in iter(lambda: src.read(CHUNK), b''):
                    dst.write(block)
    os.replace(tmp, out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('release', type=Path, help='signed release folder')
    ap.add_argument('out', type=Path, help='the installer zip to write')
    ap.add_argument('--work', type=Path, help='staging folder; default build/pocket-installer/<name>')
    ap.add_argument('--gates', type=Path, default=ROOT / 'configs/release-gates.json',
                    help='release gates to ship; only tests give another one')
    ap.add_argument('--keep-work', action='store_true')
    args = ap.parse_args()
    out = args.out.resolve()
    top = out.stem
    work = args.work or ROOT / 'build/pocket-installer' / top
    try:
        manifest, gates_open = stage(args.release, work, args.gates)
        out.parent.mkdir(parents=True, exist_ok=True)
        write_zip(work, out, top)
    except (BuildError, OSError, KeyError, ValueError, zipfile.BadZipFile) as e:
        ap.exit(1, f'installer not made: {e}\n')
    finally:
        if not args.keep_work and work.exists():
            shutil.rmtree(work)
    print(f'{out}: {out.stat().st_size} bytes, release {manifest["release"]["name"]}, '
          f'{len(manifest["files"])} files')
    for g in gates_open:
        print(f'note: the installer refuses to run until this is fixed: {g}')


if __name__ == '__main__':
    main()
