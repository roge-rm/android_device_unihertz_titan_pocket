#!/usr/bin/env python3
"""Read and verify private Pocket partition backups through an authorized root ADB shell.

Never writes to a phone partition, creates phone files, reboots, or flashes.
Userdata is excluded. These files contain private device provisioning material.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

REQUIRED = ['boot', 'recovery', 'dtbo', 'vbmeta', 'vbmeta_system', 'vbmeta_vendor',
            'nvram', 'nvdata', 'nvcfg', 'persist', 'protect1', 'protect2', 'proinfo']
OPTIONAL = ['lk', 'lk2', 'tee1', 'tee2', 'seccfg', 'sec1', 'frp', 'para', 'boot_para',
            'md_udc', 'metadata', 'md1img', 'spmfw', 'scp1', 'scp2', 'sspm_1', 'sspm_2',
            'cam_vpu1', 'cam_vpu2', 'cam_vpu3', 'gz1', 'gz2', 'logo']


def sha_file(path, compressed=False):
    digest = hashlib.sha256()
    opener = gzip.open if compressed else open
    with opener(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--include-super', action='store_true', help='Also preserve the installed system/vendor/product container')
    parser.add_argument('--only', nargs='+', metavar='NAME', help='Back up just these by-name partitions, all required')
    parser.add_argument('--output-root', type=Path,
                        default=Path(__file__).resolve().parent.parent / 'backups')
    args = parser.parse_args()
    adb = shutil.which('adb') or str(Path.home() / 'Android/Sdk/platform-tools/adb')
    base = [adb, '-s', args.serial]

    def shell(command, root=False, timeout=180):
        if root:
            command = 'su -c ' + shlex.quote(command)
        result = subprocess.run(base + ['shell', command], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f'ADB read failed: {result.stderr.strip()[:300]}')
        return result.stdout.strip()

    identity = shell('getprop ro.product.model; getprop ro.product.device; getprop ro.product.manufacturer')
    normalized = re.sub('[^a-z0-9]', '', identity.lower())
    if 'titanpocket' not in normalized or 'unihertz' not in normalized:
        parser.error('Target is not identified as a Unihertz Titan Pocket')
    if not shell('id', root=True).startswith('uid=0('):
        parser.error('Phone root access is required')
    # Magisk may allocate a PTY for exec-out, converting LF to CRLF. The ADB
    # shell protocol with -T is verified byte-for-byte before reading blocks.
    probe = 'printf ' + shlex.quote(''.join(f'\\{value:03o}' for value in range(256)))
    test = subprocess.run(base + ['shell', '-T', 'su -c ' + shlex.quote(probe)],
                          capture_output=True, timeout=30)
    if test.returncode or test.stdout != bytes(range(256)):
        parser.error('Rooted ADB binary transport failed the all-byte-values probe')
    os.umask(0o077)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output = args.output_root.resolve() / ('stock-' + stamp)
    output.mkdir(parents=True, mode=0o700)
    manifest_path = output / 'manifest.json'
    manifest = {'status': 'in_progress', 'started_utc': stamp, 'serial': args.serial,
                'identity': identity, 'kernel': shell('uname -a'),
                'build': shell('getprop ro.agui.real_version; getprop ro.build.fingerprint'),
                'partitions': [], 'missing_optional': [],
                'binary_transport': 'adb shell -T su -c; all 256 byte values verified before reads',
                'limitations': ['Live reads, not an atomic snapshot across partitions',
                                'Userdata/app data and bootloader hardware LUNs are not included',
                                'Checksum verification does not prove a working restore procedure']}

    def save():
        temporary = manifest_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(manifest, indent=2) + '\n')
        temporary.replace(manifest_path)

    def resolve(name):
        alias = '/dev/block/by-name/' + name
        result = shell(f'if [ -b {alias} ]; then readlink -f {alias}; fi', root=True)
        if not result:
            return None
        if not re.fullmatch(r'/dev/block/(?:sd[a-z]+[0-9]+|mmcblk[0-9]+p[0-9]+)', result):
            raise ValueError(f'Expected a physical partition, not a disk/mapper: {name}')
        size = int(shell('blockdev --getsize64 ' + result, root=True))
        ceiling = 8 * 1024**3 if name == 'super' else 512 * 1024**2
        if not 0 < size <= ceiling:
            raise ValueError(f'Unexpected size for {name}: {size}')
        return {'name': name, 'source': result, 'bytes': size}

    def device_hash(path):
        value = shell('sha256sum ' + path, root=True).split()[0]
        if not re.fullmatch('[0-9a-f]{64}', value):
            raise ValueError('Invalid device checksum')
        return value

    try:
        save()
        (output / 'partition-map.txt').write_text(shell('ls -l /dev/block/by-name; cat /proc/partitions', root=True) + '\n')
        names = args.only or REQUIRED + OPTIONAL + (['super'] if args.include_super else [])
        for name in names:
            item = resolve(name)
            if item is None:
                if args.only or name in REQUIRED or name == 'super':
                    raise ValueError(f'Required partition missing: {name}')
                manifest['missing_optional'].append(name)
            else:
                manifest['partitions'].append(item)
        if shutil.disk_usage(output).free < sum(x['bytes'] for x in manifest['partitions']) + 256 * 1024**2:
            raise ValueError('Insufficient space for a conservative uncompressed-size budget')
        save()
        print(f'Backup directory: {output}', flush=True)
        print(f'Validated {len(manifest["partitions"])} partition targets before reads', flush=True)
        for item in manifest['partitions']:
            name, source, size = item['name'], item['source'], item['bytes']
            current = resolve(name)
            if current != {key: item[key] for key in ['name', 'source', 'bytes']}:
                raise ValueError('Partition map changed before backup')
            for attempt in range(1, 4):
                print(f'{name}: {size} bytes; checksum before read (attempt {attempt})', flush=True)
                before = device_hash(source)
                partial = output / (name + '.img.gz.partial')
                raw_hash, count = hashlib.sha256(), 0
                command = 'su -c ' + shlex.quote('cat ' + source)
                with (output / (name + '.stderr.txt')).open('wb') as errors:
                    process = subprocess.Popen(base + ['shell', '-T', command], stdout=subprocess.PIPE, stderr=errors)
                    try:
                        with gzip.open(partial, 'wb', compresslevel=1) as target:
                            for block in iter(lambda: process.stdout.read(1024 * 1024), b''):
                                count += len(block)
                                if count > size:
                                    raise ValueError('Device stream exceeded validated partition size')
                                raw_hash.update(block)
                                target.write(block)
                        code = process.wait(timeout=30)
                    except BaseException:
                        process.kill()
                        process.wait()
                        raise
                    finally:
                        process.stdout.close()
                if code or count != size:
                    raise ValueError(f'Incomplete partition read: {name}, bytes={count}, status={code}')
                print(f'{name}: checking device stability and compressed readback', flush=True)
                after = device_hash(source)
                actual = raw_hash.hexdigest()
                if before != actual or actual != after:
                    partial.rename(output / f'{name}.unstable-attempt-{attempt}.img.gz')
                    item.setdefault('unstable_attempts', []).append({'before': before, 'stream': actual, 'after': after})
                    save()
                    if attempt == 3:
                        raise ValueError(f'Partition changed during all reads: {name}')
                    continue
                if sha_file(partial, compressed=True) != actual:
                    raise ValueError(f'Compressed backup readback failed: {name}')
                final = output / (name + '.img.gz')
                partial.rename(final)
                item.update({'file': final.name, 'raw_sha256': actual, 'device_sha256_before': before,
                             'device_sha256_after': after, 'stored_sha256': sha_file(final),
                             'stored_bytes': final.stat().st_size, 'verified': True})
                save()
                print(f'{name}: verified', flush=True)
                break
        manifest['status'] = 'verified'
        manifest['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save()
        print(f'All {len(manifest["partitions"])} backups verified: {manifest_path}', flush=True)
    except BaseException as error:
        manifest['status'] = 'partial'
        manifest['error'] = str(error)
        save()
        raise


if __name__ == '__main__':
    main()
