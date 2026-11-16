#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dry-run test of tools/publish-pocket-release.py on a real signed release and installer zip.

  check-pocket-publish.py RELEASE_DIR INSTALLER.zip

Stages with --allow-open-gates into build/pocket-release-test/, checks what it wrote and that the
tool refuses the cases it should. Nothing is uploaded and no gh or git command is run.
"""
import pocket_paths
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
MARKFILE = '.pocket-release-staging'


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    release, inst = Path(sys.argv[1]), Path(sys.argv[2])
    tool = ROOT / 'tools/publish-pocket-release.py'
    m = runpy.run_path(str(tool))
    Refused = m['Refused']
    scratch = Path(tempfile.mkdtemp(prefix='pocket-publish-test-', dir=ROOT / 'build'))
    try:
        checks = run(release, inst, tool, m, Refused, scratch)
    finally:
        shutil.rmtree(scratch)
    print(json.dumps({'checks': checks, 'uploaded': False, 'commands_run': False}, indent=2))


def run(release, inst, tool, m, Refused, scratch):
    out = scratch / 'out'
    clone = scratch / 'clone'
    shutil.copytree(ROOT / 'owner-repo', clone)
    (clone / 'updates/titan_pocket.json').write_text('[]\n')
    base = [sys.executable, str(tool), str(release), str(inst), '--owner-clone', str(clone)]
    checks = 0

    def refused(call, text):
        nonlocal checks
        try:
            call()
        except Refused as e:
            assert text in str(e), f'wrong refusal: {e}'
            checks += 1
            return
        raise AssertionError('accepted: ' + text)

    # Gates: the real ones are open, so no flag means no staging.
    r = subprocess.run(base + ['--out', str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and 'release gates are open' in r.stderr and not out.exists(), r.stderr
    checks += 1

    # Qualifications and a staging folder that isn't ours.
    refused(lambda: m['check_qualifications']({}), 'not signed off')
    good = {n: {'qualified': True, 'evidence_sha256': '1' * 64} for n in m['QUALIFICATIONS']}
    m['check_qualifications'](good)
    refused(lambda: m['check_qualifications'](dict(good, optional_magisk_survival={'qualified': True, 'evidence_sha256': 'x'})),
            'optional_magisk_survival')
    m['check_source_pins'](pocket_paths.platform_source())
    refused(lambda: m['check_source_pins'](scratch), 'No such file')
    other = scratch / 'other'
    other.mkdir()
    (other / 'precious.txt').write_text('x')
    r = subprocess.run(base + ['--out', str(other), '--allow-open-gates'], capture_output=True, text=True)
    assert r.returncode == 1 and 'not empty' in r.stderr and (other / 'precious.txt').exists(), r.stderr
    checks += 1

    try:
        cert = Path(pocket_paths.release_keys() / 'releasekey.x509.pem')
    except SystemExit:
        cert = Path('/nonexistent')
    cmd = base + ['--out', str(out), '--allow-open-gates']
    if cert.is_file():
        cmd += ['--ota-cert', str(cert)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert '# gh release create' in r.stdout and '# git -C' in r.stdout and 'WARNING: release gates are open' in r.stdout
    checks += 1
    feed = json.loads((out / 'owner-repo/updates/titan_pocket.json').read_text())
    f = feed[0]['files'][0]
    ota = out / 'assets' / f['filename']
    assert f['size'] == ota.stat().st_size and f['sha256'] == m['sha256_file'](ota)
    assert f['url'].startswith('https://github.com/roge-rm/titan-pocket-lineage/releases/download/lineage-23.2-')
    assert feed[0]['type'] == 'unofficial' and len(feed) == 1
    sums = (out / 'assets/SHA256SUMS').read_text()
    assert f['sha256'] in sums and inst.name in sums
    assert 'TEST ONLY' in (out / 'RELEASE_NOTES.md').read_text()
    assert '## lineage-23.2-' in (out / 'owner-repo/CHANGELOG.md').read_text()
    cmds = (out / 'commands.txt').read_text().splitlines()
    assert cmds[0].startswith('# TEST ONLY') and all(l.startswith('#') for l in cmds)
    assert any('gh release create' in l for l in cmds)
    assert (out / MARKFILE).is_file()
    checks += 1

    # The feed must match the asset.
    staged = {f['filename']: ota}
    m['check_feed'](feed, staged)
    for key, value in (('sha256', '0' * 64), ('size', f['size'] + 1)):
        bad = copy.deepcopy(feed)
        bad[0]['files'][0][key] = value
        refused(lambda: m['check_feed'](bad, staged), 'does not match the asset')
    bad = copy.deepcopy(feed)
    bad[0]['files'][0]['url'] = bad[0]['files'][0]['url'].replace('roge-rm', 'someone')
    refused(lambda: m['check_feed'](bad, staged), 'not a Release asset')
    bad = copy.deepcopy(feed)
    bad[0]['files'][0]['size'] = m['ASSET_LIMIT'] + 1
    refused(lambda: m['check_feed'](bad, staged), '2 GiB')

    # Unihertz hashes and private paths in a zip.
    secret = b'pretend stock file'
    known = {hashlib.sha256(secret).hexdigest(): 'stock test file'}
    def zipped(name, data):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            z.writestr(name, data)
        return zipfile.ZipFile(b)
    refused(lambda: m['scan_zip'](zipped('a/b.bin', secret), 'the test zip', known), 'Unihertz file')
    refused(lambda: m['scan_zip'](zipped('a/b.sh', b'cd /s' + b'rv/downloads/build\n'), 'the test zip', {}), 'private path')
    refused(lambda: m['scan_zip'](zipped('a/b.txt', b'/ho' + b'me/dan/x'), 'the test zip', {}), 'private path')
    m['scan_zip'](zipped('a/b.txt', b'fine'), 'the test zip', known)
    checks += 1

    # An installer from another release.
    if True:
        tmp = scratch / 'tmp'
        tmp.mkdir()
        meta = {'post-timestamp': '1'}
        with zipfile.ZipFile(inst) as z:
            top = z.namelist()[0].split('/')[0]
            manifest = json.loads(z.read(f'{top}/manifest.json'))
        hashes = {n: m['sha256_file'](release / f'{n}.img') for n in ('boot', 'recovery', 'vbmeta')}
        cfg = json.loads((ROOT / 'configs/stock-backup.json').read_text())
        refused(lambda: m['check_installer'](inst, release, meta, hashes, cfg), 'another release')
        wrong = dict(hashes, boot='0' * 64)
        refused(lambda: m['check_installer'](inst, release, {'post-timestamp': str(manifest['release']['post_timestamp'])},
                                              wrong, cfg), 'boot.img is not the release folder one')
        # A clone whose feed already has this build, and a second release that keeps the first's entry.
        shutil.copyfile(out / 'owner-repo/updates/titan_pocket.json', clone / 'updates/titan_pocket.json')
        shutil.copyfile(out / 'owner-repo/CHANGELOG.md', clone / 'CHANGELOG.md')
        r = subprocess.run(base + ['--out', str(tmp / 'again'), '--allow-open-gates'], capture_output=True, text=True)
        assert r.returncode == 1 and 'already has this build' in r.stderr, r.stderr
        newer = json.loads((clone / 'updates/titan_pocket.json').read_text())
        newer[0]['datetime'] -= 100
        old = newer[0]['files'][0]
        old['url'] = old['url'].replace(old['filename'], 'older.zip')
        old['filename'] = 'older.zip'
        (clone / 'updates/titan_pocket.json').write_text(json.dumps(newer))
        shutil.copyfile(ROOT / 'owner-repo/CHANGELOG.md', clone / 'CHANGELOG.md')
        r = subprocess.run(base + ['--out', str(tmp / 'second'), '--allow-open-gates'], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        both = json.loads((tmp / 'second/owner-repo/updates/titan_pocket.json').read_text())
        assert [e['files'][0]['filename'] for e in both][1:] == ['older.zip'] and len(both) == 2
        checks += 1
        shutil.rmtree(tmp / 'second')
    return checks


if __name__ == '__main__':
    main()
