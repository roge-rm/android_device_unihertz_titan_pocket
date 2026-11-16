#!/usr/bin/env python3
"""Build the configfs link fix as a new AVB-wrapped recovery; no phone access."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    output = ROOT / 'artifacts/kernel-upgrade/recovery-configfs-link'
    evidence = ROOT / 'evidence/kernel-upgrade/recovery-configfs-link-preparation'
    if (output / 'recovery.img').exists():
        raise RuntimeError('Candidate already exists; verify it without overwriting')
    builder = runpy.run_path(str(ROOT / 'tools/build-diagnostic-recovery.py'), run_name='recovery_builder')['build']
    record = builder(evidence, output)
    raw = (ROOT / record['diagnostic_image']['path']).read_bytes()
    size = record['diagnostic_image']['unpadded_bytes']
    assert not any(raw[size:])
    image = output / 'recovery.img'
    image.write_bytes(raw[:size])
    salt = hashlib.sha256(raw[:size]).hexdigest()
    avbtool = ROOT / 'tools/avbtool.py'
    subprocess.run([sys.executable, '-B', str(avbtool), 'add_hash_footer', '--image', str(image),
                    '--partition_name', 'recovery', '--partition_size', '33554432',
                    '--algorithm', 'NONE', '--hash_algorithm', 'sha256', '--salt', salt,
                    '--rollback_index', '0'], check=True)
    data = image.read_bytes()
    assert len(data) == 33554432 and data[:size] == raw[:size]
    footer = struct.unpack('>4sIIQQQ28s', data[-64:])
    assert footer[0] == b'AVBf' and footer[1] == 1 and footer[3] == size and not any(footer[-1])
    offset = footer[4]
    assert data[offset:offset+4] == b'AVB0'
    assert struct.unpack_from('>II', data, offset+4) == (1, 0)
    assert struct.unpack_from('>I', data, offset+28)[0] == 0
    assert struct.unpack_from('>I', data, offset+120)[0] == 0
    for operation in ['info_image', 'verify_image']:
        checked = subprocess.run([sys.executable, '-B', str(avbtool), operation, '--image', str(image)],
                                 capture_output=True, text=True, check=True)
        (evidence / (operation + '.txt')).write_text(checked.stdout + checked.stderr)
    result = {'state': 'Locally built; not staged or flashed',
              'candidate': {'path': str(image.relative_to(ROOT)), 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()},
              'restore_image': record['restore_image'], 'raw_package': 'package-validation.json',
              'payload_bytes': size, 'preserved_components': record['preserved_components'],
              'logger_sources': record['logger_sources'],
              'change': 'Correct configfs ACM link target to functions/acm.usb0; log link errors',
              'unchanged': 'Stock kernel, DTB, embedded recovery DTBO, 120-second return timer, USB identity, command parser',
              'avb': {'algorithm': 'NONE', 'flags': 0, 'rollback_index': 0,
                      'required_libavb': [1, 0], 'salt': salt, 'metadata_offset': offset},
              'limits': ['Host checks are not device USB qualification',
                         'Previously proven restart timer does not guarantee every future failure returns',
                         'Only final recovery.img is a candidate; raw diagnostic-recovery.img lacks AVB metadata']}
    (evidence / 'candidate-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Configfs-fix recovery packaged with valid unsigned AVB metadata: ' + result['candidate']['sha256'])


if __name__ == '__main__':
    main()
