#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate an explicitly supplied signed release and write a local Updater feed.

No downloads, publishing, device access, signing, or installation are implemented.
"""
import pocket_paths
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit, unquote
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PINS = {
    'packages/apps/Updater/app/src/main/java/org/lineageos/updater/data/source/network/NetworkUpdate.kt':
        '23481770215a8b61dec9446cc2601340d7cce762feab450afafaa4a7cd9f853c',
    'packages/apps/Updater/app/src/main/java/org/lineageos/updater/data/source/network/UpdatesNetworkDataSource.kt':
        '0e502ebf5ea332d22993491488aeffe4aee0097efb892a9522166772910597c0',
    'packages/apps/Updater/app/src/main/java/org/lineageos/updater/controller/UpdateInstaller.java':
        'b4526ea3b65389277fe6737e5c802290336e1612b3b9a18df3eac20cae44b5d8',
    'bootable/recovery/otautil/verifier.cpp':
        'f54d70b5b1a16b8898af5bc20f1ce7fedfbe143a35848e96eecc1927932feb34',
    'build/make/tools/releasetools/non_ab_ota.py':
        '3e2688cd79c84f73b4ac1edad1c0c82e23cb5df0e76893bf986f6edf4feb8de3',
    'build/make/tools/releasetools/edify_generator.py':
        '146748263ca9b004fb7bc875edc2c50f84c835c72738cb76f561f793ff946815',
    'vendor/lineage/prebuilt/common/bin/backuptool.sh':
        '528c470df7ab62489474844bf65ea8fa17e3e8320115e91be3017a7b9153a244',
}
REQUIRED_GATES = {'kernel_board_boot', 'ufs_encryption', 'vndk_fcm_compatibility',
                  'combined_enforcing_policy', 'keyboard_and_hardware_parity',
                  'installer_recovery_rollback'}
OWNER_REPO = 'roge-rm/titan-pocket-lineage'
# The Updater's updater_server_url resolves to this (device/unihertz/titan_pocket/updater).
FEED_URL = 'https://raw.githubusercontent.com/' + OWNER_REPO + '/main/updates/titan_pocket.json'
ASSET_PREFIX = 'https://github.com/' + OWNER_REPO + '/releases/download/'
ASSET_LIMIT = 2 * 1024 ** 3 - 1  # GitHub's limit is 2 GiB per release asset
QUALIFICATIONS = {'settings_update_encrypted_data', 'a_only_recovery_install',
                  'optional_magisk_survival', 'ota_avb_key_continuity'}


class InvalidRelease(ValueError):
    pass


def require(value, message):
    if not value:
        raise InvalidRelease(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run_openssl(*args, data=None):
    result = subprocess.run(['openssl', *map(str, args)], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, 'OpenSSL verification/format check failed: ' +
            result.stderr.decode(errors='replace').strip())
    return result.stdout


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field: ' + key)
            result[key] = value
        return result
    def reject_number(value):
        raise InvalidRelease('Invalid JSON number: ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=reject_number)


def check_sources(platform):
    for relative, expected in SOURCE_PINS.items():
        require(digest(Path(platform) / relative) == expected,
                'Reviewed platform source changed: ' + relative)


def https_url(value):
    require(isinstance(value, str) and value and
            all(ord(c) > 32 and ord(c) < 127 for c in value) and '\\' not in value,
            'URL must be printable ASCII without whitespace or backslashes')
    url = urlsplit(value)
    require(url.scheme == 'https' and url.hostname and not url.username and
            not url.password and not url.fragment and '{' not in value and '}' not in value,
            'An explicit HTTPS URL without credentials, fragments or templates is required')
    require(url.port in (None, 443), 'Only the HTTPS default port is supported')
    return url


def signed_metadata(path, signature, public_key):
    # Verify the exact input bytes; do not reserialize before verification.
    require(Path(path).stat().st_size <= 128 * 1024, 'Release metadata is oversized')
    run_openssl('dgst', '-sha256', '-verify', public_key, '-signature', signature, path)
    release = strict_json(Path(path).read_bytes())
    require(isinstance(release, dict), 'Release metadata must be an object')
    return release


def verify_ota_signature(ota, certificate):
    """Check recovery's signed byte range and verify its detached CMS signature.

    This is an additional host check, not a substitute for the actual recovery
    verifier or AVB qualification. Only the explicitly supplied certificate can
    supply the CMS signer; certificates embedded in an untrusted ZIP are ignored.
    """
    size = ota.stat().st_size
    require(size >= 28, 'OTA is too short for an Android whole-file signature')
    with ota.open('rb') as stream:
        stream.seek(-6, 2)
        footer = stream.read(6)
        start = int.from_bytes(footer[:2], 'little')
        comment = int.from_bytes(footer[4:], 'little')
        require(footer[2:4] == b'\xff\xff' and 6 < start <= comment and comment + 22 <= size,
                'Missing or invalid Android whole-file signature footer')
        stream.seek(-comment - 22, 2)
        eocd = stream.read()
        require(eocd[:4] == b'PK\x05\x06' and b'PK\x05\x06' not in eocd[4:] and
                int.from_bytes(eocd[20:22], 'little') == comment,
                'Ambiguous or invalid signed ZIP end record')
        signature = eocd[-start:-6]
        signed_length = size - comment - 2
        # OpenSSL needs seekable detached content. Keep only temporary host data.
        with tempfile.TemporaryDirectory(prefix='pocket-ota-verify-') as tmp:
            content = Path(tmp) / 'content'
            sig = Path(tmp) / 'signature.der'
            sig.write_bytes(signature)
            stream.seek(0)
            remaining = signed_length
            with content.open('wb') as output:
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    require(block, 'Truncated OTA signed content')
                    output.write(block)
                    remaining -= len(block)
            run_openssl('cms', '-verify', '-binary', '-inform', 'DER', '-in', sig,
                        '-content', content, '-certfile', certificate, '-nointern',
                        '-noverify', '-out', os.devnull)


def ota_metadata(ota):
    with zipfile.ZipFile(ota) as package:
        names = package.namelist()
        require(len(names) == len(set(names)), 'Duplicate ZIP members are forbidden')
        require('payload.bin' not in names, 'A/B payloads are outside the A-only contract')
        name = 'META-INF/com/android/metadata'
        require(name in names and package.getinfo(name).file_size <= 64 * 1024,
                'Missing or oversized OTA metadata')
        require('META-INF/com/google/android/update-binary' in names and
                'META-INF/com/google/android/updater-script' in names,
                'Recovery update-binary and updater-script are required')
        fields = {}
        for line in package.read(name).decode('utf-8').splitlines():
            require('=' in line, 'Malformed OTA metadata line')
            key, value = line.split('=', 1)
            require(key and key not in fields, 'Duplicate/empty OTA metadata key')
            fields[key] = value
        return fields


def validate(release, ota, certificate, gates, current_version, current_timestamp):
    require(isinstance(release, dict) and isinstance(gates, dict), 'Release and gates must be objects')
    require(type(release.get('schema')) is int and release['schema'] == 1 and
            type(gates.get('schema')) is int and gates['schema'] == 1, 'Unsupported release/gates schema')
    require(release.get('product') == gates.get('product') == 'Titan_pocket' and
            release.get('device') == 'titan_pocket', 'Wrong product/device')
    require(release.get('stock_firmware') in gates.get('supported_stock_firmware', []),
            'Unqualified stock firmware baseline')
    require(isinstance(gates.get('qualified'), dict) and
            all(gates['qualified'].get(key) is True for key in REQUIRED_GATES),
            'Local release gates remain open')
    require(release.get('slot_scheme') == 'a-only' and release.get('ota_type') == 'BLOCK',
            'Only A-only BLOCK packages are supported')
    require(release.get('data_action') == 'preserve' and
            release.get('root_policy') == 'optional-magisk-preserve',
            'Encrypted-data preservation and optional Magisk survival must be explicit')
    require(isinstance(release.get('qualifications'), dict), 'Qualifications must be an object')
    for name in QUALIFICATIONS:
        qualification = release['qualifications'].get(name, {})
        require(isinstance(qualification, dict) and qualification.get('qualified') is True and
                isinstance(qualification.get('evidence_sha256'), str) and
                re.fullmatch('[0-9a-f]{64}', qualification['evidence_sha256']),
                'Missing signed qualification/evidence hash: ' + name)
    require(isinstance(current_version, str) and re.fullmatch(r'\d+\.\d+', current_version) and
            release.get('version') == current_version,
            'Routine updates must match the current LineageOS version')
    require(release.get('type') == 'unofficial', 'Only the unofficial release channel is supported')
    timestamp = release.get('datetime')
    require(type(timestamp) is int and 0 < current_timestamp < timestamp <= 2**63 - 1,
            'Update must be newer than the explicitly supplied current build')
    require(type(release.get('size')) is int and release['size'] > 0, 'Invalid release size')
    require(isinstance(release.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', release['sha256']),
            'Invalid package SHA256')
    name = release.get('filename')
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip', name),
            'Invalid package filename')
    url = https_url(release.get('url'))
    https_url(release.get('feed_url'))
    require(release['feed_url'] == FEED_URL, 'feed_url must be ' + FEED_URL)
    require(release['url'].startswith(ASSET_PREFIX) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*/' + re.escape(name), release['url'][len(ASSET_PREFIX):]),
            'url must be a Release asset: ' + ASSET_PREFIX + '<tag>/' + name)
    require(release['size'] <= ASSET_LIMIT, 'Package is over the 2 GiB GitHub Release asset limit')
    require(unquote(url.path.rsplit('/', 1)[-1]) == name and not url.query,
            'Package HTTPS URL must end in its filename without a query')
    require(type(release.get('os_sdk_level')) is int and release['os_sdk_level'] == 36,
            'Only reviewed Android 16/API 36 releases are supported')
    patch = release.get('os_patch_level', '')
    require(isinstance(patch, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', patch), 'Invalid security patch date')
    datetime.date.fromisoformat(patch)
    require(ota.is_file() and not ota.is_symlink() and ota.stat().st_size == release['size'] and
            digest(ota) == release['sha256'], 'Package is not a matching regular file')
    pem = certificate.read_bytes()
    require(len(pem) <= 64 * 1024 and
            re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*', pem),
            'Exactly one public PEM OTA certificate is required')
    der = run_openssl('x509', '-in', certificate, '-outform', 'DER')
    require(hashlib.sha256(der).hexdigest() == release.get('ota_cert_sha256'),
            'Public OTA certificate does not match signed release metadata')
    verify_ota_signature(ota, certificate)
    metadata = ota_metadata(ota)
    expected = {'pre-device': 'titan_pocket', 'ota-type': 'BLOCK',
                'post-timestamp': str(timestamp), 'post-sdk-level': '36',
                'post-security-patch-level': patch}
    require(all(metadata.get(key) == value for key, value in expected.items()),
            'Signed OTA metadata does not match the release/device/A-only contract')
    require(not any(key in metadata for key in ('pre-build', 'pre-build-incremental',
                'ota-wipe', 'ota-downgrade', 'spl-downgrade', 'ota-retrofit-dynamic-partitions')),
            'Only full non-wipe, non-downgrade updates are supported')
    # A-only feed deliberately omits A/B byte ranges (ota_property_files).
    return [{'datetime': timestamp, 'files': [{key: release[key] for key in
             ('filename', 'os_patch_level', 'os_sdk_level', 'sha256', 'size', 'url')}],
             'type': release['type'], 'version': release['version']}]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('release', 'signature', 'metadata-key', 'ota', 'ota-cert', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--platform-source', type=Path,
                        default=pocket_paths.platform_source())
    parser.add_argument('--current-version', required=True)
    parser.add_argument('--current-timestamp', type=int, required=True)
    args = parser.parse_args()
    try:
        check_sources(args.platform_source)
        release = signed_metadata(args.release, args.signature, args.metadata_key)
        gates = strict_json((ROOT / 'configs/release-gates.json').read_bytes())
        feed = validate(release, args.ota, args.ota_cert, gates,
                        args.current_version, args.current_timestamp)
        # Exclusive create prevents accidentally replacing another release feed.
        with args.output.open('x') as output:
            output.write(json.dumps(feed, indent=2) + '\n')
    except (InvalidRelease, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) + '\n')
    print('Validated local feed written; no publication or device access performed.')


if __name__ == '__main__':
    main()
