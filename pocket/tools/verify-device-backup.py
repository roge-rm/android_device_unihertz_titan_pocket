#!/usr/bin/env python3
"""Verify a copied Pocket backup against device hashes and gzip readback.

Offline only; this tool never connects to or changes a phone.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.directory.resolve()
    source = directory / 'manifest.json'
    data = source.read_bytes()
    manifest = json.loads(data)
    if manifest['status'] != 'verified':
        parser.error('Source backup is not marked verified')
    records, names = [], set()
    for item in manifest['partitions']:
        filename = item['file']
        if Path(filename).name != filename or not filename.endswith('.img.gz') or filename in names:
            raise ValueError('Unexpected or duplicate backup filename')
        names.add(filename)
        path = directory / filename
        if path.is_symlink() or not item['verified']:
            raise ValueError(f'Unverified or linked backup: {filename}')
        expected = item['raw_sha256']
        if expected != item['device_sha256_before'] or expected != item['device_sha256_after']:
            raise ValueError(f'Device data changed while backing up: {filename}')
        stored, raw, count = hashlib.sha256(), hashlib.sha256(), 0
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                stored.update(block)
        if stored.hexdigest() != item['stored_sha256'] or path.stat().st_size != item['stored_bytes']:
            raise ValueError(f'Compressed file transfer check failed: {filename}')
        with gzip.open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                count += len(block)
                raw.update(block)
        if count != item['bytes'] or raw.hexdigest() != expected:
            raise ValueError(f'Decompressed readback failed: {filename}')
        records.append({'file': filename, 'bytes': count, 'stored_bytes': item['stored_bytes'],
                        'stored_sha256': stored.hexdigest(), 'raw_sha256': raw.hexdigest(), 'verified': True})
        print(f'{item["name"]}: local compressed and raw readback verified', flush=True)
    report = {'status': 'verified', 'verified_utc': datetime.now(timezone.utc).isoformat(),
              'manifest_sha256': hashlib.sha256(data).hexdigest(), 'files': records,
              'raw_bytes': sum(x['bytes'] for x in records),
              'stored_bytes': sum(x['stored_bytes'] for x in records),
              'limitations': ['Verifies only manifest-selected stable images, not rejected/partial attempts',
                              'Not an atomic multi-partition snapshot or a tested restore procedure',
                              'User/app data and hardware bootloader LUNs are excluded']}
    target = directory / 'local-verification.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(target)
    print(f'All {len(records)} local backups verified: {target}', flush=True)


if __name__ == '__main__':
    main()
