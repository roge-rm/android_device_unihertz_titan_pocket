#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test the real feed validator with disposable signatures and non-installable ZIPs."""
import pocket_paths
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    module = runpy.run_path(str(ROOT / 'tools/prepare-pocket-update-feed.py'))
    validate, invalid = module['validate'], module['InvalidRelease']
    platform = pocket_paths.platform_source()
    module['check_sources'](platform)
    checks = 1
    with tempfile.TemporaryDirectory(prefix='pocket-feed-tests-') as tmp:
        root = Path(tmp)

        def openssl(*args, data=None):
            return module['run_openssl'](*args, data=data)

        key, cert, pub = [root / name for name in ('test-key.pem', 'test-cert.pem', 'test-public.pem')]
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                '-out', cert, '-subj', '/CN=Disposable non-installable feed test/', '-days', '1')
        pub.write_bytes(openssl('pkey', '-in', key, '-pubout'))
        cert_hash = hashlib.sha256(openssl('x509', '-in', cert, '-outform', 'DER')).hexdigest()
        ota = root / 'synthetic.zip'
        ota_fields = {'pre-device': 'titan_pocket', 'ota-type': 'BLOCK',
                      'post-timestamp': '2000000000', 'post-sdk-level': '36',
                      'post-security-patch-level': '2026-10-01'}

        def package(fields=ota_fields, duplicate=False, payload=False, signed=True):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                metadata = '\n'.join(k + '=' + v for k, v in fields.items()) + '\n'
                archive.writestr('META-INF/com/android/metadata', metadata)
                archive.writestr('META-INF/com/google/android/update-binary',
                                 b'TEST TEXT ONLY: deliberately not executable; no installer')
                archive.writestr('META-INF/com/google/android/updater-script',
                                 b'TEST TEXT ONLY: deliberately not an update script')
                if payload:
                    # Empty marker tests rejection; no payload implementation.
                    archive.writestr('payload.bin', b'')
                if duplicate:
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        archive.writestr('META-INF/com/android/metadata', metadata)
            raw = buffer.getvalue()
            if signed:
                content = root / 'test-content'
                content.write_bytes(raw[:-2])
                cms = openssl('cms', '-sign', '-binary', '-noattr', '-md', 'sha256',
                              '-in', content, '-signer', cert, '-inkey', key, '-outform', 'DER')
                length = len(cms) + 6
                footer = length.to_bytes(2, 'little') + b'\xff\xff' + length.to_bytes(2, 'little')
                raw = raw[:-2] + length.to_bytes(2, 'little') + cms + footer
            ota.write_bytes(raw)

        package()
        gates = {'schema': 1, 'product': 'Titan_pocket',
                 'supported_stock_firmware': ['synthetic-baseline'],
                 'qualified': {key: True for key in module['REQUIRED_GATES']}}
        release = {'schema': 1, 'product': 'Titan_pocket', 'device': 'titan_pocket',
                   'stock_firmware': 'synthetic-baseline', 'slot_scheme': 'a-only',
                   'ota_type': 'BLOCK', 'data_action': 'preserve',
                   'root_policy': 'optional-magisk-preserve',
                   'qualifications': {name: {'qualified': True, 'evidence_sha256': '1' * 64}
                                      for name in module['QUALIFICATIONS']},
                   'version': '23.2', 'type': 'unofficial', 'datetime': 2000000000,
                   'size': ota.stat().st_size, 'sha256': module['digest'](ota),
                   'filename': 'synthetic.zip', 'url': 'https://github.com/roge-rm/titan-pocket-lineage/releases/download/v1/synthetic.zip',
                   'feed_url': 'https://raw.githubusercontent.com/roge-rm/titan-pocket-lineage/main/updates/titan_pocket.json',
                   'os_sdk_level': 36, 'os_patch_level': '2026-10-01', 'ota_cert_sha256': cert_hash}

        def check(record=release, local_gates=gates):
            return validate(record, ota, cert, local_gates, '23.2', 1900000000)

        def reject(call):
            nonlocal checks
            try:
                call()
            except invalid:
                checks += 1
                return
            raise AssertionError('Invalid release accepted')

        feed = check()
        assert isinstance(feed, list) and len(feed) == 1 and feed[0]['files'][0]['sha256'] == release['sha256']
        assert set(feed[0]) == {'datetime', 'files', 'type', 'version'}
        assert 'ota_property_files' not in feed[0]['files'][0]
        checks += 1
        for field, value in [('schema', 2), ('schema', True), ('product', 'other'), ('device', 'other'),
                             ('stock_firmware', 'other'), ('slot_scheme', 'a/b'),
                             ('ota_type', 'AB'), ('data_action', 'wipe'), ('root_policy', 'repatch-manually'),
                             ('version', '24.0'), ('type', 'nightly'), ('datetime', 1900000000),
                             ('datetime', True), ('size', True), ('sha256', '0' * 64),
                             ('filename', '../synthetic.zip'), ('os_sdk_level', 35),
                             ('os_patch_level', '2026-10-1'), ('ota_cert_sha256', '0' * 64),
                             ('qualifications', []), ('qualifications', {'a_only_recovery_install': None})]:
            record = copy.deepcopy(release)
            record[field] = value
            reject(lambda: check(record))
        G = 'https://github.com/roge-rm/titan-pocket-lineage/releases/download/v1/'
        for url in [G + 'other.zip', G + 'synthetic.zip?x=1', G.replace('v1/', '') + 'synthetic.zip',
                    G.replace('roge-rm', 'someone') + 'synthetic.zip', 'https://test.invalid/v1/synthetic.zip',
                    'http://test.invalid/synthetic.zip', 'https://user@test.invalid/synthetic.zip',
                    'https://test.invalid/synthetic.zip#fragment', 'https://test.invalid:80/synthetic.zip',
                    'https://test.invalid/other.zip', 'https://test.invalid/synthetic.zip?x=1',
                    'https://test.invalid/\nsynthetic.zip', 'https://test.invalid/{device}.zip']:
            record = copy.deepcopy(release)
            record['url'] = url
            reject(lambda: check(record))
        record = copy.deepcopy(release)
        record['feed_url'] = 'https://test.invalid/titan_pocket.json'
        reject(lambda: check(record))
        record = copy.deepcopy(release)
        record['size'] = module['ASSET_LIMIT'] + 1
        reject(lambda: check(record))
        for name in module['REQUIRED_GATES']:
            local_gates = copy.deepcopy(gates)
            local_gates['qualified'][name] = False
            reject(lambda: check(local_gates=local_gates))
        for name in module['QUALIFICATIONS']:
            record = copy.deepcopy(release)
            record['qualifications'][name]['qualified'] = False
            reject(lambda: check(record))
            record['qualifications'][name] = {'qualified': True, 'evidence_sha256': ''}
            reject(lambda: check(record))
        real_gates = module['strict_json']((ROOT / 'configs/release-gates.json').read_bytes())
        reject(lambda: check(local_gates=real_gates))
        for field, value in [('pre-device', 'other'), ('ota-type', 'AB'), ('ota-wipe', 'yes'),
                             ('ota-downgrade', 'yes'), ('pre-build', 'incremental'),
                             ('post-timestamp', '1999999999'), ('post-sdk-level', '35')]:
            fields = dict(ota_fields)
            fields[field] = value
            package(fields)
            record = dict(release, size=ota.stat().st_size, sha256=module['digest'](ota))
            reject(lambda: check(record))
        for option in ({'duplicate': True}, {'payload': True}, {'signed': False}):
            package(**option)
            record = dict(release, size=ota.stat().st_size, sha256=module['digest'](ota))
            reject(lambda: check(record))
        package()
        original = ota.read_bytes()
        corrupted = bytearray(original)
        corrupted[45] ^= 1
        ota.write_bytes(corrupted)
        record = dict(release, sha256=module['digest'](ota))
        reject(lambda: check(record))  # Matching hash cannot bypass the actual signature.
        ota.write_bytes(original)
        path, signature = root / 'release.json', root / 'release.sig'
        path.write_text(json.dumps(release))
        signature.write_bytes(openssl('dgst', '-sha256', '-sign', key, path))
        assert module['signed_metadata'](path, signature, pub) == release
        checks += 1
        original_cert = cert.read_bytes()
        cert.write_bytes(original_cert * 2)
        reject(lambda: check())
        cert.write_bytes(original_cert)
        other_key, other_cert, other_pub = [root / name for name in ('other-key', 'other-cert', 'other-public')]
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', other_key,
                '-out', other_cert, '-subj', '/CN=Wrong disposable test key/', '-days', '1')
        other_pub.write_bytes(openssl('pkey', '-in', other_key, '-pubout'))
        reject(lambda: module['signed_metadata'](path, signature, other_pub))
        wrong_cert_release = dict(release, ota_cert_sha256=hashlib.sha256(
            openssl('x509', '-in', other_cert, '-outform', 'DER')).hexdigest())
        reject(lambda: validate(wrong_cert_release, ota, other_cert, gates, '23.2', 1900000000))
        path.write_text(json.dumps(dict(release, device='other')))
        reject(lambda: module['signed_metadata'](path, signature, pub))
        path.write_text('{"device":"titan_pocket","device":"other"}')
        signature.write_bytes(openssl('dgst', '-sha256', '-sign', key, path))
        reject(lambda: module['signed_metadata'](path, signature, pub))
        # CLI always reads the real closed gates; no switch bypasses them.
        path.write_text(json.dumps(dict(release, stock_firmware='Titan_pocket_20240514')))
        signature.write_bytes(openssl('dgst', '-sha256', '-sign', key, path))
        output = root / 'must-not-exist.json'
        result = subprocess.run(['python3', str(ROOT / 'tools/prepare-pocket-update-feed.py'),
                                 '--release', str(path), '--signature', str(signature),
                                 '--metadata-key', str(pub), '--ota', str(ota), '--ota-cert', str(cert),
                                 '--output', str(output), '--platform-source', str(platform),
                                 '--current-version', '23.2', '--current-timestamp', '1900000000'],
                                capture_output=True, text=True)
        assert result.returncode == 1 and 'Local release gates remain open' in result.stderr and not output.exists()
        checks += 1
    print(json.dumps({'checks': checks, 'source_contract_checked': True,
                      'synthetic_non_installable_inputs_only': True,
                      'disposable_keys_removed': True, 'device_accessed': False,
                      'published': False, 'actual_release_gates_unchanged': True}, indent=2))


if __name__ == '__main__':
    main()
