#!/usr/bin/env python3
"""Extract the verified Pocket backup with existing Lineage/AOSP tools, offline.

Retains raw images as the metadata authority. Host filesystem dumps are for
analysis and do not preserve every Android owner, label, capability or hardlink.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def layout(path):
    """Validate primary LP checksums, ranges and linear single-device extents."""
    with path.open('rb') as stream:
        def read(offset, size):
            stream.seek(offset)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError('LP structure exceeds image')
            return data
        geometry = bytearray(read(4096, 52))
        magic, length = struct.unpack_from('<II', geometry)
        if magic != 0x616c4467 or length != 52:
            raise ValueError('Unsupported LP geometry')
        expected = bytes(geometry[8:40])
        geometry[8:40] = bytes(32)
        if hashlib.sha256(geometry).digest() != expected:
            raise ValueError('LP geometry checksum mismatch')
        maximum, slots, block = struct.unpack_from('<III', geometry, 40)
        if slots not in (1, 2) or not 128 <= maximum <= 1024**2 or block != 4096:
            raise ValueError('Unexpected LP metadata geometry')
        header_offset = 4096 * 3
        fields = struct.unpack('<IHHI32sI32s', read(header_offset, 80))
        magic, major, minor, size, header_hash, table_size, table_hash = fields
        if magic != 0x414c5030 or major != 10 or minor > 2 or size not in (128, 256):
            raise ValueError('Unsupported LP header')
        if size + table_size > maximum:
            raise ValueError('LP tables exceed metadata slot')
        header = bytearray(read(header_offset, size))
        header[12:44] = bytes(32)
        tables = read(header_offset + size, table_size)
        if hashlib.sha256(header).digest() != header_hash or hashlib.sha256(tables).digest() != table_hash:
            raise ValueError('LP header/table checksum mismatch')
        def table(index, fmt):
            start, count, width = struct.unpack_from('<III', header, 80 + index * 12)
            if width != struct.calcsize(fmt) or start + count * width > table_size:
                raise ValueError('Invalid LP table descriptor')
            return list(struct.iter_unpack(fmt, tables[start:start + count * width]))
        parts = table(0, '<36sIIII')
        extents = table(1, '<QIQI')
        groups = table(2, '<36sIQ')
        devices = table(3, '<QIIQ36sI')
        if len(devices) != 1 or devices[0][3] != path.stat().st_size:
            raise ValueError('Expected one physical super device with matching size')
        result, used = [], []
        for name, attrs, first, count, group in parts:
            name = name.rstrip(b'\0').decode('ascii')
            if name not in {'system', 'vendor', 'product'} or group != 1 or first + count > len(extents) or count == 0:
                raise ValueError('Unexpected Pocket partition layout')
            ranges = []
            for sectors, kind, start, source in extents[first:first + count]:
                offset, length = start * 512, sectors * 512
                if kind != 0 or source != 0 or not length or offset + length > path.stat().st_size:
                    raise ValueError('Unsupported/nonlinear LP extent')
                if offset < header_offset + 2 * maximum * slots:
                    raise ValueError('LP extent overlaps metadata')
                ranges.append({'offset': offset, 'bytes': length})
                used.append((offset, offset + length))
            result.append({'name': name, 'attributes': attrs, 'group': group,
                           'bytes': sum(x['bytes'] for x in ranges), 'ranges': ranges})
        if {x['name'] for x in result} != {'system', 'vendor', 'product'} or len(result) != 3:
            raise ValueError('Missing/duplicate Pocket logical partition')
        ordered = sorted(used)
        if any(right > next_left for (_, right), (next_left, _) in zip(ordered, ordered[1:])):
            raise ValueError('LP extents overlap')
        return {'geometry': {'metadata_max_bytes': maximum, 'slots': slots, 'block_bytes': block},
                'primary_geometry_header_tables_sha256_verified': True, 'partitions': result,
                'groups': [{'name': x[0].rstrip(b'\0').decode(), 'flags': x[1], 'max_bytes': x[2]} for x in groups]}


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, default=root / 'backups/stock-20261029T001105.670723Z')
    parser.add_argument('--output', type=Path, default=root / 'firmware/installed-20230105')
    args = parser.parse_args()
    backup, output = args.backup.resolve(), args.output.resolve()
    manifest_path = backup / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    verified = json.loads((backup / 'local-verification.json').read_text())
    if manifest['status'] != 'verified' or verified['status'] != 'verified' or sha(manifest_path) != verified['manifest_sha256']:
        parser.error('Backup verification does not match the manifest')
    if output.exists():
        parser.error('Choose a new output directory; existing extraction is preserved')
    os.umask(0o077)
    output.mkdir(parents=True)
    evidence = root / 'evidence/installed-20230105'
    evidence.mkdir(parents=True, exist_ok=True)
    records = {'status': 'in_progress', 'created_utc': datetime.now(timezone.utc).isoformat(),
               'backup_manifest_sha256': sha(manifest_path), 'output': str(output),
               'source_build': manifest['build'], 'images': [],
               'tools': {'extract_utils_commit': subprocess.run(['git', '-C', str(root / 'tools/extract-utils'), 'rev-parse', 'HEAD'],
                             check=True, capture_output=True, text=True).stdout.strip(),
                         'lp_sha256': sha(root / 'tools/extract-utils/extract_utils/lp.py'),
                         'unpack_bootimg_sha256': sha(root / 'tools/unpack_bootimg.py')},
               'limitations': ['REA firmware extraction backend was unavailable; existing Lineage/AOSP tools reused',
                               'Filesystem dumps do not preserve all Android metadata; images remain authoritative',
                               'No image mounted, modified, flashed or booted; no platform download/sync performed']}
    report_path = evidence / 'extraction.json'
    def save():
        report_path.write_text(json.dumps(records, indent=2) + '\n')
    def run(command, name):
        with (evidence / name).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f'Extraction tool failed: {name}')
    save()
    try:
        by_name = {x['name']: x for x in manifest['partitions']}
        for name in ['super', 'boot', 'recovery', 'dtbo', 'vbmeta', 'vbmeta_system', 'vbmeta_vendor']:
            item = by_name[name]
            source = backup / item['file']
            if Path(item['file']).name != item['file'] or sha(source) != item['stored_sha256']:
                raise ValueError('Source backup file checksum mismatch')
            destination = output / (name + ('.raw.img' if name == 'super' else '.img'))
            print(f'Decompressing verified {name}', flush=True)
            digest, count = hashlib.sha256(), 0
            with gzip.open(source, 'rb') as stream, destination.open('wb') as target:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    count += len(block)
                    if count > item['bytes']:
                        raise ValueError('Decompressed backup exceeds manifest size')
                    digest.update(block)
                    target.write(block)
            if count != item['bytes'] or digest.hexdigest() != item['raw_sha256']:
                raise ValueError('Decompressed source checksum mismatch')
            records['images'].append({'name': name, 'path': str(destination), 'bytes': count, 'sha256': digest.hexdigest()})
        super_path = output / 'super.raw.img'
        metadata = layout(super_path)
        (evidence / 'super-layout.json').write_text(json.dumps(metadata, indent=2) + '\n')
        sys.path.insert(0, str(root / 'tools/extract-utils'))
        from extract_utils.lp import LpImage
        with super_path.open('rb') as source:
            image = LpImage(source)
            if set(image.get_partition_names()) != {'system', 'vendor', 'product'}:
                raise ValueError('LP parser partition names disagree')
            for part in metadata['partitions']:
                name = part['name']
                target = output / (name + '.img')
                print(f'Extracting logical partition {name}', flush=True)
                image.extract_partition(name, str(target))
                expected = hashlib.sha256()
                for extent in part['ranges']:
                    source.seek(extent['offset'])
                    remaining = extent['bytes']
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ValueError('Short source extent read')
                        expected.update(block)
                        remaining -= len(block)
                if target.stat().st_size != part['bytes'] or sha(target) != expected.hexdigest():
                    raise ValueError('Extracted LP partition does not match its source extents')
                with target.open('rb') as stream:
                    stream.seek(1080)
                    if stream.read(2) != b'\x53\xef':
                        raise ValueError('Expected ext4 logical partition')
                records['images'].append({'name': name, 'path': str(target), 'bytes': part['bytes'],
                                          'sha256': expected.hexdigest(), 'extent_readback_verified': True})
                dump = output / 'rootfs' / name
                dump.mkdir(parents=True)
                run(['/usr/sbin/debugfs', '-R', f'rdump / {dump}', str(target)], name + '-extraction.log')
                diagnostics = (evidence / (name + '-extraction.log')).read_text().splitlines()
                unexpected = [x for x in diagnostics if x and not x.startswith('debugfs ') and
                              'Operation not permitted while changing ownership' not in x]
                if unexpected:
                    raise ValueError(f'Unexpected debugfs diagnostics for {name}: {unexpected[:3]}')
        for name in ['boot', 'recovery']:
            run([sys.executable, str(root / 'tools/unpack_bootimg.py'), '--boot_img',
                 str(output / (name + '.img')), '--out', str(output / name)], name + '-header.txt')
        kernel = gzip.decompress((output / 'boot/kernel').read_bytes())
        (output / 'boot/Image').write_bytes(kernel)
        start = kernel.index(b'IKCFG_ST') + 8
        end = kernel.index(b'IKCFG_ED', start)
        (output / 'boot/kernel.config').write_bytes(gzip.decompress(kernel[start:end]))
        files = []
        for path in sorted((output / 'rootfs').rglob('*')):
            relative = str(path.relative_to(output / 'rootfs'))
            if path.is_symlink():
                files.append({'path': relative, 'kind': 'symlink', 'target': os.readlink(path)})
            elif path.is_file():
                files.append({'path': relative, 'kind': 'file', 'bytes': path.stat().st_size, 'sha256': sha(path)})
        (evidence / 'rootfs-manifest.json').write_text(json.dumps(files, indent=2) + '\n')
        records.update({'status': 'complete', 'regular_files': sum(x['kind'] == 'file' for x in files),
                        'symlinks': sum(x['kind'] == 'symlink' for x in files),
                        'finished_utc': datetime.now(timezone.utc).isoformat()})
        save()
        print(f'Extraction complete: {report_path}', flush=True)
    except BaseException as error:
        records.update({'status': 'partial', 'error': str(error)})
        save()
        raise


if __name__ == '__main__':
    main()
