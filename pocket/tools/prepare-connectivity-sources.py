#!/usr/bin/env python3
"""Verify pinned GPL source files and stage external connectivity module builds.

--fetch downloads pinned GitHub source archives only when a local source is
missing. It never runs target code, changes the kernel tree, or contacts a phone.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(root, component):
    archive = root / 'tools/downloads' / ('connectivity-' + component['commit'] + '.tar.gz')
    archive.parent.mkdir(parents=True, exist_ok=True)
    repo = component['repository'].removeprefix('https://github.com/')
    url = f'https://codeload.github.com/{repo}/tar.gz/{component["commit"]}'
    if not archive.exists():
        partial = archive.with_suffix('.partial')
        print(f'Downloading {url}', flush=True)
        with urllib.request.urlopen(url, timeout=120) as response, partial.open('wb') as target:
            shutil.copyfileobj(response, target)
        partial.rename(archive)
    wanted = {item['path']: item['sha256'] for item in component['files']}
    prefix = component['subtree'] + '/'
    with tarfile.open(archive, 'r|gz') as source:
        for member in source:
            relative = member.name.partition('/')[2]
            if not relative.startswith(prefix):
                continue
            relative = relative[len(prefix):]
            if relative not in wanted:
                continue
            if not member.isfile():
                raise ValueError(f'Expected regular source file: {relative}')
            data = source.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != wanted[relative]:
                raise ValueError(f'Downloaded source hash mismatch: {relative}')
            target = root / component['source_dir'] / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    lock = root / 'connectivity-sources.json'
    if not lock.is_file():
        parser.error(f'{lock} is missing; it lists the pins and the patches to stage')
    lock_data = json.loads(lock.read_text())
    listed = lock_data.get('patches', {})
    applied = listed.get('applied', [])
    skipped = [item['path'] for item in listed.get('not_applied_for_5.10', [])]
    missing = [name for name in applied + skipped if not (root / name).is_file()]
    if missing:
        parser.error('Listed patch files missing: ' + ', '.join(missing))
    unlisted = sorted(str(p.relative_to(root)) for p in (root / 'patches/connectivity').glob('*.patch')
                      if str(p.relative_to(root)) not in applied + skipped)
    if unlisted:
        parser.error('Patches in neither patches.applied nor patches.not_applied_for_5.10: ' + ', '.join(unlisted))
    components = lock_data['components']
    output = root / 'tools/kernel-build-config/connectivity'
    record = []
    for component in components:
        if any(not (root / component['source_dir'] / item['path']).is_file() for item in component['files']):
            if not args.fetch:
                parser.error(f'{component["name"]} source missing; rerun with --fetch')
            fetch(root, component)
        for item in component['files']:
            relative = Path(item['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('Invalid locked source path')
            source = root / component['source_dir'] / relative
            if source.is_symlink() or digest(source) != item['sha256']:
                raise ValueError(f'Pinned source mismatch: {source}')
            target = output / component['name'] / relative
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            record.append({'component': component['name'], 'path': str(relative),
                           'upstream_sha256': item['sha256'], 'staged_sha256': digest(target)})
        print(f'{component["name"]}: verified {len(component["files"])} pinned files', flush=True)
    patches = []
    # Only patches listed under patches.applied in the lock file are staged.
    for patch in (root / name for name in applied):
        command = ['patch', '--batch', '--force', '-p1', '-d', str(output)]
        content = patch.read_text()
        # Check reversal first: an insertion-only patch can apply again at an
        # offset even when it is already present.
        reverse = subprocess.run(command + ['--dry-run', '-R'], input=content,
                                 text=True, capture_output=True)
        if reverse.returncode:
            forward = subprocess.run(command + ['--dry-run'], input=content,
                                     text=True, capture_output=True)
            if forward.returncode:
                raise ValueError(f'Cannot apply or verify staged patch: {patch}')
            subprocess.run(command, input=content, text=True, check=True)
        patches.append({'path': str(patch.relative_to(root)), 'sha256': digest(patch)})
    for item in record:
        item['staged_sha256'] = digest(output / item['component'] / item['path'])
    evidence = root / 'evidence/connectivity'
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'staged-sources.json').write_text(json.dumps({
        'lock_sha256': digest(lock), 'output': str(output), 'files': record, 'patches': patches,
        'limitations': ['Existing staged edits are recorded, not overwritten',
                        'Compilation and hardware compatibility remain separate']}, indent=2) + '\n')


if __name__ == '__main__':
    main()
