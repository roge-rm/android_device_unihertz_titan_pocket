#!/usr/bin/env python3
"""Add valid, unsigned AVB metadata to the preserved recovery probe, offline."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TESTED_SHA = '3def378efeee41b045ddb3802315acad735a41a82fcb5abe5f17fc22770e9a94'


def main():
    record = json.loads((ROOT / 'evidence/kernel-upgrade/recovery-probe-preparation/package-validation.json').read_text())
    original = (ROOT / record['diagnostic_image']['path']).read_bytes()
    assert hashlib.sha256(original).hexdigest() == TESTED_SHA
    size = record['diagnostic_image']['unpadded_bytes']
    assert len(original) == 33554432 and not any(original[size:])
    out = ROOT / 'artifacts/kernel-upgrade/recovery-probe-avb'
    evidence = ROOT / 'evidence/kernel-upgrade/recovery-offline-audit'
    out.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    # avbtool resolves the hash descriptor's partition name to this basename.
    image = out / 'recovery.img'
    image.write_bytes(original[:size])
    avbtool = ROOT / 'tools/avbtool.py'
    salt = hashlib.sha256(original[:size]).hexdigest()
    command = [sys.executable, '-B', str(avbtool), 'add_hash_footer', '--image', str(image),
               '--partition_name', 'recovery', '--partition_size', '33554432',
               '--algorithm', 'NONE', '--hash_algorithm', 'sha256', '--salt', salt,
               '--rollback_index', '0']
    subprocess.run(command, check=True)
    data = image.read_bytes()
    assert len(data) == len(original) and data[:size] == original[:size]
    footer = struct.unpack('>4sIIQQQ28s', data[-64:])
    magic, major, minor, original_size, metadata_offset, metadata_size, reserved = footer
    assert magic == b'AVBf' and major == 1 and original_size == size
    assert not any(reserved) and data[metadata_offset:metadata_offset+4] == b'AVB0'
    # LK's embedded verifier advertises support through required libavb 1.1.
    required_major, required_minor = struct.unpack_from('>II', data, metadata_offset + 4)
    assert required_major == 1 and required_minor <= 1
    assert struct.unpack_from('>I', data, metadata_offset + 28)[0] == 0  # Algorithm NONE.
    assert struct.unpack_from('>I', data, metadata_offset + 120)[0] == 0  # No disable flags.
    info = subprocess.run([sys.executable, '-B', str(avbtool), 'info_image', '--image', str(image)],
                          check=True, capture_output=True, text=True)
    verify = subprocess.run([sys.executable, '-B', str(avbtool), 'verify_image', '--image', str(image)],
                            check=True, capture_output=True, text=True)
    (evidence / 'candidate-avb-info.txt').write_text(info.stdout)
    (evidence / 'candidate-avb-verify.txt').write_text(verify.stdout + verify.stderr)
    result = {'state': 'Offline candidate only; not staged or flashed',
              'original_tested_sha256': TESTED_SHA,
              'candidate': {'path': str(image.relative_to(ROOT)), 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()},
              'payload_bytes': size, 'payload_byte_identical_to_tested_image': True,
              'avb': {'algorithm': 'NONE', 'signed': False, 'salt': salt, 'flags': 0,
                      'rollback_index': 0, 'required_libavb': [required_major, required_minor],
                      'metadata_offset': metadata_offset, 'metadata_bytes': metadata_size},
              'command': command, 'avbtool_sha256': hashlib.sha256(avbtool.read_bytes()).hexdigest(),
              'limits': ['No OEM signature or new trust configuration',
                         'Only embedded recovery metadata changes; no separate vbmeta write',
                         'Host verification does not establish bootloader acceptance or USB execution']}
    (evidence / 'candidate-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Unsigned recovery AVB candidate built and hash-verified; original boot payload unchanged')
    print('No phone accessed, no target executed: ' + result['candidate']['sha256'])


if __name__ == '__main__':
    main()
