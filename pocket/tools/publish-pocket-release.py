#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage a release for the owner repo (roge-rm/titan-pocket-lineage). Dry run only.

  publish-pocket-release.py RELEASE_DIR INSTALLER.zip --owner-clone CLONE --qualifications FILE

RELEASE_DIR is the signed release folder (tools/sign-pocket-release.py), INSTALLER.zip comes
from tools/make-pocket-installer.py. Writes build/pocket-release/<tag>/ with the assets to
upload (OTA zip, installer zip, SHA256SUMS), RELEASE_NOTES.md, the updated updates/titan_pocket.json
and CHANGELOG.md for the owner repo, and commands.txt. The feed and changelog are built from your
clone of the owner repo (--owner-clone, up to date with its main branch), so earlier releases stay in
them. The LineageOS version and release type are read from the OTA's product build.prop. The gh and git commands are printed, never
run: nothing here touches the network or GitHub.

Refuses while the release gates in configs/release-gates.json are open, a qualification the feed
contract needs isn't signed off in --qualifications (a JSON object like the release metadata's
"qualifications"), or the reviewed platform sources changed (--allow-open-gates skips all three, for
tests). Also refuses when a file in either zip is a known Unihertz file or a text file names a private path,
when the installer isn't made from this release, and when the feed entry's sha256 or size doesn't
match the staged asset.
"""
import pocket_paths
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
CHUNK = 1024 * 1024
TEXT_LIMIT = 8 * CHUNK
MARK = '.pocket-release-staging'
KEEP_ENTRIES = 10
MARKER = '<!-- new entries go here -->'

installer = runpy.run_path(str(TOOLS / 'make-pocket-installer.py'))
feed = runpy.run_path(str(TOOLS / 'prepare-pocket-update-feed.py'))
PRIVATE_MARKERS = installer['PRIVATE_MARKERS']
REPO = feed['OWNER_REPO']
ASSET_PREFIX = feed['ASSET_PREFIX']
ASSET_LIMIT = feed['ASSET_LIMIT']
REQUIRED_GATES = feed['REQUIRED_GATES']
QUALIFICATIONS = feed['QUALIFICATIONS']


class Refused(RuntimeError):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def check_qualifications(quals):
    require(isinstance(quals, dict), 'the qualifications file must be a JSON object')
    bad = []
    for name in sorted(QUALIFICATIONS):
        q = quals.get(name)
        if not (isinstance(q, dict) and q.get('qualified') is True and isinstance(q.get('evidence_sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', q['evidence_sha256'])):
            bad.append(name)
    require(not bad, 'qualifications not signed off: ' + ', '.join(bad))


def check_source_pins(platform):
    try:
        feed['check_sources'](platform)
    except (feed['InvalidRelease'], OSError) as e:
        raise Refused(str(e))


def prepare_staging(path):
    """Only an empty or missing folder, or one this tool made, may be replaced."""
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), f'{path} is not a folder')
        require(not any(path.iterdir()) or (path / MARK).is_file(),
                f'{path} is not empty and was not made by this tool; give another --out')
        shutil.rmtree(path)
    path.mkdir(parents=True)
    (path / MARK).write_text('made by publish-pocket-release.py\n')


def product_build_prop(path):
    """The Lineage properties from the signed target-files zip's product build.prop."""
    with zipfile.ZipFile(installer['one'](path, '*-signed-target_files.zip')) as z:
        text = z.read('PRODUCT/etc/build.prop').decode()
    props = dict(l.split('=', 1) for l in text.splitlines() if '=' in l and not l.startswith('#'))
    return props


def sha256_file(path):
    return installer['sha256_file'](path)


def stream_hash(z, name):
    h = hashlib.sha256()
    with z.open(name) as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def check_gates(gates, allow_open):
    open_gates = sorted(k for k in REQUIRED_GATES if gates.get('qualified', {}).get(k) is not True)
    require(not open_gates or allow_open, 'release gates are open: ' + ', '.join(open_gates))
    require(gates.get('supported_stock_firmware'), 'no supported stock firmware in the gates')
    return open_gates


def scan_zip(z, label, known, skip=()):
    """Refuses a member that is a known Unihertz file or a text file naming a private path."""
    for info in z.infolist():
        if info.is_dir() or info.filename in skip:
            continue
        h = stream_hash(z, info)
        require(h not in known, f'Unihertz file in {label}: {info.filename} is {known.get(h)}')
        if info.file_size <= TEXT_LIMIT and not info.filename.endswith('.img'):
            data = z.read(info)
            if installer['is_text'](data):
                for m in PRIVATE_MARKERS:
                    require(m not in data, f'private path in {label}: {info.filename}: {m.decode()}')


def check_installer(path, release, ota_meta, release_hashes, known_cfg):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        require(len(names) == len(set(names)), 'duplicate members in the installer zip')
        tops = {n.split('/', 1)[0] for n in names}
        require(len(tops) == 1 and all('/' in n for n in names), 'the installer zip needs exactly one top folder')
        top = tops.pop()
        manifest = json.loads(z.read(f'{top}/manifest.json'))
        rel = manifest.get('release', {})
        require(rel.get('post_timestamp') == int(ota_meta['post-timestamp']),
                'the installer is made from another release than the OTA')
        files = manifest['files']
        for name in ('boot', 'recovery', 'vbmeta'):
            require(files.get(f'images/{name}.img') == release_hashes[name],
                    f'the installer {name}.img is not the release folder one')
        for rel_path, expected in files.items():
            require(stream_hash(z, f'{top}/{rel_path}') == expected, f'hash mismatch in the installer: {rel_path}')
        extra = set(names) - {f'{top}/{p}' for p in files} - {f'{top}/manifest.json'}
        require(not extra, 'files in the installer zip that its manifest does not list: ' + ', '.join(sorted(extra)[:5]))
        payload = json.loads(z.read(f'{top}/vendor/payload/manifest.json'))
        known = installer['unihertz_hashes'](known_cfg, payload)
        scan_zip(z, 'the installer', known)
        return manifest, json.loads(z.read(f'{top}/configs/release-gates.json')), known


def check_ota(path, known, cert):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        require(len(names) == len(set(names)), 'duplicate members in the OTA')
        require('payload.bin' not in names, 'an A/B payload is not an A-only OTA')
        meta = installer['ota_metadata'](z)
        scan_zip(z, 'the OTA', known)
    require(meta.get('pre-device') == 'titan_pocket' and meta.get('ota-type') == 'BLOCK',
            'the OTA is not an A-only BLOCK package for titan_pocket')
    require(not any(k in meta for k in ('pre-build', 'pre-build-incremental', 'ota-wipe', 'ota-downgrade')),
            'only full, non-wipe, non-downgrade OTAs are published')
    require(meta.get('post-sdk-level') == '36', 'the OTA is not Android 16')
    if cert:
        feed['verify_ota_signature'](path, cert)
    return meta


def feed_entry(meta, version, filename, url, sha, size):
    patch = meta['post-security-patch-level']
    return {'datetime': int(meta['post-timestamp']),
            'files': [{'filename': filename, 'os_patch_level': patch, 'os_sdk_level': 36,
                       'sha256': sha, 'size': size, 'url': url}],
            'type': 'unofficial', 'version': version}


def check_feed(entries, staged):
    """Every entry for a staged asset must match that file's sha256 and size."""
    for e in entries:
        f = e['files'][0]
        url = f['url']
        require(url.startswith(ASSET_PREFIX) and re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9._-]*/' + re.escape(f['filename']), url[len(ASSET_PREFIX):]),
            f'feed url is not a Release asset of {REPO}: {url}')
        require(f['size'] <= ASSET_LIMIT, f'{f["filename"]} is over the 2 GiB Release asset limit')
        asset = staged.get(f['filename'])
        if asset is not None:
            require(asset.is_file() and asset.stat().st_size == f['size'],
                    f'feed size of {f["filename"]} does not match the asset')
            require(sha256_file(asset) == f['sha256'], f'feed sha256 of {f["filename"]} does not match the asset')


def read_feed(owner):
    path = owner / 'updates/titan_pocket.json'
    require(path.is_file(), f'{path} is missing: --owner-clone is not a clone of the owner repo')
    entries = json.loads(path.read_text())
    require(isinstance(entries, list), f'{path} is not a list')
    return entries


def changelog(owner, tag, when, version, meta, firmware, notes, extra):
    path = owner / 'CHANGELOG.md'
    require(path.is_file(), f'{path} is missing: --owner-clone is not a clone of the owner repo')
    text = path.read_text()
    require(MARKER in text, f'{path} has no "{MARKER}" line')
    require(f'## {tag} ' not in text, f'{tag} is already in the changelog')
    lines = [f'## {tag} ({when:%Y-%m-%d})', '',
             f'- LineageOS {version}, Android 16, security patch {meta["post-security-patch-level"]}.',
             f'- Needs Unihertz stock {firmware} to install.']
    lines += [f'- {n}' for n in notes]
    lines += [f'- {n}' for n in extra]
    return text.replace(MARKER, MARKER + '\n\n' + '\n'.join(lines), 1)


def release_notes(tag, when, version, meta, firmware, ota_name, inst_name, sums, notes, extra):
    out = [f'LineageOS {version} for the Unihertz Titan Pocket, build of {when:%Y-%m-%d}, security patch '
           f'{meta["post-security-patch-level"]}.', '', 'Changes']
    out += [f'- {n}' for n in notes + extra] or ['- None listed.']
    out += ['', 'Which file',
            f'- {inst_name}: first install, from Unihertz stock {firmware}. It erases the phone. '
            'Unzip it and follow README.txt inside, or the steps in the repo README.',
            f'- {ota_name}: update from an earlier build of this ROM. The Updater app in Settings finds it by itself.',
            '', 'SHA256']
    out += [f'    {s}  {n}' for n, s in sums]
    return '\n'.join(out) + '\n'


def q(s):
    s = str(s)
    if s.startswith('~' + '/'):
        return '"$HOME"' + q(s[1:])
    return "'" + s.replace("'", "'\\''") + "'"


def commands(tag, title, notes_path, assets, staging, clone, test_only=False):
    owner = staging / 'owner-repo'
    gh = [f'gh release create {q(tag)} \\', f'  --repo {REPO} \\', f'  --title {q(title)} \\',
          f'  --notes-file {q(notes_path)} \\']
    gh += [f'  {q(a)} \\' for a in assets[:-1]] + [f'  {q(assets[-1])}']
    git = [f'git -C {q(clone)} pull --ff-only origin main',
           f'cp {q(owner / "updates/titan_pocket.json")} {q(Path(str(clone)) / "updates/titan_pocket.json")}',
           f'cp {q(owner / "CHANGELOG.md")} {q(Path(clone) / "CHANGELOG.md")}',
           f'git -C {q(clone)} add updates/titan_pocket.json CHANGELOG.md',
           f'git -C {q(clone)} commit -m {q("Release " + tag)}',
           f'git -C {q(clone)} push origin main']
    lines = ['# 1. Create the Release with the assets (the feed urls need them first).'] + gh + \
           ['', '# 2. Then publish the feed and changelog (the Updater sees the build when this lands).'] + git
    if test_only:
        lines = ['# TEST ONLY: staged with open release gates. Do not run any of this.'] + \
                ['# ' + l if l else '#' for l in lines]
    return lines


def stage(args):
    release = args.release.resolve()
    inst = args.installer.resolve()
    gates = json.loads((ROOT / 'configs/release-gates.json').read_text())
    open_gates = check_gates(gates, args.allow_open_gates)
    if not args.allow_open_gates:
        require(args.qualifications, '--qualifications FILE is needed')
        check_qualifications(json.loads(args.qualifications.read_text()))
        check_source_pins(args.platform_source)
    props = product_build_prop(release)
    version = props.get('ro.lineage.build.version', '')
    require(re.fullmatch(r'\d+\.\d+', version), 'the build has no ro.lineage.build.version')
    require(props.get('ro.lineage.releasetype') == 'UNOFFICIAL',
            'ro.lineage.releasetype is not UNOFFICIAL, the feed type')
    require(props.get('ro.lineage.device') == 'titan_pocket', 'ro.lineage.device is not titan_pocket')
    require(args.lineage_version in (None, version), f'--lineage-version {args.lineage_version} is not the build\'s {version}')
    args.lineage_version = version
    ota_src = installer['one'](release, '*-signed-ota.zip')
    require(re.fullmatch(r'titan-pocket-installer-[A-Za-z0-9._-]+\.zip', inst.name), f'odd installer name {inst.name}')
    for p in (ota_src, inst):
        require(p.is_file() and not p.is_symlink(), f'{p} is not a regular file')
        require(p.stat().st_size <= ASSET_LIMIT, f'{p.name} is over the 2 GiB Release asset limit')
    cfg = json.loads((ROOT / 'configs/stock-backup.json').read_text())
    signing = json.loads((release / 'check-signing.json').read_text())
    require(signing.get('vbmeta_flags') == 3 and str(signing.get('recovery_avb', '')).startswith('our key'),
            'check-signing.json does not show release-key signing')
    release_hashes = {n: sha256_file(release / f'{n}.img') for n in ('boot', 'recovery', 'vbmeta')}

    with zipfile.ZipFile(ota_src) as z:
        meta = installer['ota_metadata'](z)
    manifest, inst_gates, known = check_installer(inst, release, meta, release_hashes, cfg)
    meta = check_ota(ota_src, known, args.ota_cert)
    firmware = manifest['plan']['stock_firmware']
    require(firmware in gates['supported_stock_firmware'], f'stock firmware {firmware} is not in the gates')
    if not args.allow_open_gates:
        require(all(inst_gates.get('qualified', {}).get(k) is True for k in REQUIRED_GATES),
                'the installer carries open release gates; it would refuse to run')

    when = datetime.fromtimestamp(int(meta['post-timestamp']), timezone.utc)
    stamp = when.strftime('%Y%m%d-%H%M%S')
    tag = f'lineage-{args.lineage_version}-{stamp}'
    ota_name = f'lineage-{args.lineage_version}-{stamp}-UNOFFICIAL-titan_pocket.zip'
    staging = (args.out or ROOT / 'build/pocket-release' / tag).resolve()
    prepare_staging(staging)
    assets = staging / 'assets'
    assets.mkdir()

    staged = {}
    for src, name in ((ota_src, ota_name), (inst, inst.name)):
        shutil.copyfile(src, assets / name)
        staged[name] = assets / name
    sums = [(n, sha256_file(p)) for n, p in staged.items()]
    (assets / 'SHA256SUMS').write_text(''.join(f'{s}  {n}\n' for n, s in sums))

    owner = args.owner_clone.resolve()
    entries = read_feed(owner)
    require(all(e['datetime'] < int(meta['post-timestamp']) for e in entries),
            'the feed already has this build or a newer one')
    require(not any(e['files'][0]['filename'] == ota_name for e in entries), f'{ota_name} is already in the feed')
    sha, size = dict(sums)[ota_name], staged[ota_name].stat().st_size
    new = feed_entry(meta, args.lineage_version, ota_name, f'{ASSET_PREFIX}{tag}/{ota_name}', sha, size)
    new_feed = [new] + entries[:KEEP_ENTRIES - 1]
    (staging / 'owner-repo/updates').mkdir(parents=True)
    feed_path = staging / 'owner-repo/updates/titan_pocket.json'
    feed_path.write_text(json.dumps(new_feed, indent=2) + '\n')
    # Read the written file back and compare it with the staged asset, not with the values above.
    check_feed(json.loads(feed_path.read_text()), staged)

    notes = [l.strip() for l in args.notes.read_text().splitlines() if l.strip()] if args.notes else []
    extra = ['TEST ONLY: release gates are open; not for publishing.'] if open_gates else []
    (staging / 'owner-repo/CHANGELOG.md').write_text(
        changelog(owner, tag, when, args.lineage_version, meta, firmware, notes, extra))
    notes_path = staging / 'RELEASE_NOTES.md'
    notes_path.write_text(release_notes(tag, when, args.lineage_version, meta, firmware, ota_name, inst.name,
                                        sums, notes, extra))
    title = f'LineageOS {args.lineage_version} {when:%Y-%m-%d}'
    lines = commands(tag, title, notes_path, [staged[ota_name], staged[inst.name], assets / 'SHA256SUMS'],
                     staging, args.owner_clone.resolve(), bool(open_gates))
    (staging / 'commands.txt').write_text('\n'.join(lines) + '\n')
    return {'tag': tag, 'staging': staging, 'commands': lines, 'open_gates': open_gates, 'feed': new_feed}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('release', type=Path, help='signed release folder')
    ap.add_argument('installer', type=Path, help='titan-pocket-installer-*.zip from make-pocket-installer.py')
    ap.add_argument('--lineage-version', help='checked against the build\'s ro.lineage.build.version; default is that')
    ap.add_argument('--out', type=Path, help='staging folder, new or empty; default build/pocket-release/<tag>')
    ap.add_argument('--owner-clone', type=Path, required=True,
                    help='your clone of the owner repo, up to date; the feed and changelog are built from it')
    ap.add_argument('--qualifications', type=Path, help='JSON of the signed-off qualifications (see UPDATE_FEED_CONTRACT.md)')
    ap.add_argument('--platform-source', type=Path, default=pocket_paths.platform_source(), help='reviewed platform tree')
    ap.add_argument('--notes', type=Path, help='text file, one change per line')
    ap.add_argument('--ota-cert', type=Path, help='public OTA certificate (PEM) to verify the OTA signature with')
    ap.add_argument('--allow-open-gates', action='store_true', help='tests only: stage while release gates are open')
    args = ap.parse_args()
    try:
        r = stage(args)
    except (Refused, installer['BuildError'], OSError, KeyError, ValueError, zipfile.BadZipFile,
            feed['InvalidRelease']) as e:
        ap.exit(1, f'not staged: {e}\n')
    print(f'Staged {r["tag"]} in {r["staging"]}. Dry run: nothing was uploaded or run.')
    if r['open_gates']:
        print('WARNING: release gates are open (' + ', '.join(r['open_gates']) + '); test staging only.')
    print('\nCommands to run yourself, in this order:\n')
    print('\n'.join(r['commands']))


if __name__ == '__main__':
    main()
