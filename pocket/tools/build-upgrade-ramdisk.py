#!/usr/bin/env python3
"""Cross-build a static RAM-only init and a deterministic newc/gzip ramdisk."""
import pocket_paths
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def entry(stream, name, data, mode, inode):
    encoded = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, len(data),
              0, 0, 0, 0, len(encoded), 0]
    stream.write(b'070701' + ''.join(f'{x:08x}' for x in fields).encode() + encoded)
    stream.write(b'\0' * (-stream.tell() % 4))
    stream.write(data)
    stream.write(b'\0' * (-stream.tell() % 4))


def build(source, out, evidence_path, extra_sources=(), include_dirs=()):
    out.mkdir(parents=True, exist_ok=True)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    command = [clang, '--target=aarch64-linux-android30', '-static',
               '-Os', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=sha1',
               *[f'-I{d}' for d in include_dirs], str(source), '-o', str(out / 'init')]
    subprocess.run(command, check=True)
    binary = (out / 'init').read_bytes()
    assert binary[:5] == b'\x7fELF\x02'
    assert struct.unpack_from('<HH', binary, 16) == (2, 183), 'Expected ARM64 ET_EXEC'
    offset = struct.unpack_from('<Q', binary, 32)[0]
    size, count = struct.unpack_from('<HH', binary, 54)
    assert all(struct.unpack_from('<I', binary, offset + i*size)[0] != 3 for i in range(count)), 'Unexpected interpreter'
    archive = io.BytesIO()
    directories = ['dev', 'proc', 'sys']
    for i, name in enumerate(directories, 1):
        entry(archive, name, b'', stat.S_IFDIR | 0o755, i)
    entry(archive, 'init', binary, stat.S_IFREG | 0o755, 4)
    entry(archive, 'TRAILER!!!', b'', 0, 5)
    raw = archive.getvalue()
    # Independently walk the generated newc records and verify all contents.
    cursor, members = 0, {}
    while cursor < len(raw):
        assert raw[cursor:cursor+6] == b'070701'
        fields = [int(raw[cursor+6+8*i:cursor+14+8*i], 16) for i in range(13)]
        cursor += 110
        name = raw[cursor:cursor+fields[11]-1].decode()
        cursor = (cursor + fields[11] + 3) & ~3
        data = raw[cursor:cursor+fields[6]]
        cursor = (cursor + fields[6] + 3) & ~3
        if name == 'TRAILER!!!': break
        members[name] = data
    assert set(members) == {'dev', 'proc', 'sys', 'init'} and members['init'] == binary
    (out / 'ramdisk.cpio').write_bytes(raw)
    compressed = gzip.compress(raw, mtime=0)
    assert gzip.decompress(compressed) == raw
    (out / 'ramdisk.cpio.gz').write_bytes(compressed)
    record = {'command': command, 'target_executed': False,
              'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'source_inputs': [{'path': str(p.relative_to(ROOT)),
                                'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                               for p in dict.fromkeys([source, ROOT / 'kernel-upgrade/ram-probe/init.c',
                                                       ROOT / 'kernel-upgrade/ram-probe/commands.h', *extra_sources])],
              'members': sorted(members),
              'files': [{'path': str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p), 'bytes': p.stat().st_size,
                         'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                        for p in [out / name for name in ['init', 'ramdisk.cpio', 'ramdisk.cpio.gz']]],
              'scope': 'Static ARM64 ELF and archive checks only; init/gadget not run on the phone'}
    evidence_path.write_text(json.dumps(record, indent=2) + '\n')
    print(f'Static ARM64 init and checked RAM disk built: {len(compressed)} compressed bytes; no target execution')
    return record


def main():
    build(ROOT / 'kernel-upgrade/ram-probe/init.c', ROOT / 'artifacts/kernel-upgrade/ram-probe',
          ROOT / 'evidence/kernel-upgrade/ramdisk-validation.json')


if __name__ == '__main__':
    main()
