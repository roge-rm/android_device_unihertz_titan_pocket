#!/usr/bin/env python3
"""Exercise AOSP libavb on local recovery images; never executes target code."""
import pocket_paths
import hashlib
import json
import argparse
from pathlib import Path
import subprocess
import sys
import os
import struct
import tempfile

ROOT = Path(__file__).resolve().parent.parent
AVB = pocket_paths.platform_source()/'external/avb'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-validation', type=Path,
                        default=ROOT / 'evidence/kernel-upgrade/recovery-offline-audit/candidate-validation.json')
    args = parser.parse_args()
    validation = json.loads(args.candidate_validation.read_text())
    candidate = ROOT / validation['candidate']['path']
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == validation['candidate']['sha256']
    evidence = args.candidate_validation.resolve().parent
    evidence.mkdir(parents=True, exist_ok=True)
    sources = sorted((AVB / 'libavb').glob('*.c')) + sorted((AVB / 'libavb/crypto').glob('*_impl.c'))
    inputs = sources + sorted((AVB / 'libavb').rglob('*.h'))
    hashes = {str(p.relative_to(AVB)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    out = candidate.parent
    binary = out / 'host-avb-check'
    # The signed-stock control exposes an unrelated signed-promotion shift in
    # reference RSA byte decoding. Normalize that expression in a LOCAL copy;
    # do not suppress UBSan or edit the shared checkout. AVB loading stays exact.
    rsa = AVB / 'libavb/avb_rsa.c'
    old = '(inout[((key->len - 1 - i) * 4) + 0] << 24)'
    new = '((uint32_t)inout[((key->len - 1 - i) * 4) + 0] << 24)'
    text = rsa.read_text()
    assert text.count(old) == 1
    local_rsa = out / 'host-source/avb_rsa.c'
    local_rsa.parent.mkdir(parents=True, exist_ok=True)
    local_rsa.write_text(text.replace(old, new))
    compiled_sources = [local_rsa if p == rsa else p for p in sources]
    clang = str(pocket_paths.ndk_bin() / 'clang')
    command = [clang, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-DAVB_COMPILATION', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', '-I' + str(AVB), '-I' + str(AVB / 'libavb'),
               '-I' + str(AVB / 'libavb/crypto'),
               str(ROOT / 'tools/recovery-avb-check.c'), *map(str, compiled_sources), '-o', str(binary)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    if compiled.returncode:
        raise RuntimeError(compiled.stderr)
    stock = ROOT / validation['restore_image']['path'] if 'restore_image' in validation else ROOT / 'artifacts/kernel-upgrade/recovery-probe/stock-recovery-restore.img'
    # Derive a no-metadata negative control from this exact candidate, rather
    # than depending on an earlier private diagnostic attempt.
    data = candidate.read_bytes(); footer = struct.unpack('>4sIIQQQ28s',data[-64:]);assert footer[0]==b'AVBf'
    tested = out/'no-avb-control.img';tested.write_bytes(data[:footer[3]]+b'\0'*(len(data)-footer[3]))
    cases = []
    for name, image, mode, expected, loaded in [
        ('signed_stock_unlocked_synthetic_key_trust', stock, 'unlocked', 'OK', True),
        ('signed_stock_locked_synthetic_key_trust', stock, 'locked', 'OK', True),
        ('no_footer_unlocked', tested, 'unlocked', 'ERROR_INVALID_METADATA', False),
        ('no_footer_locked', tested, 'locked', 'ERROR_INVALID_METADATA', False),
        ('unsigned_valid_metadata_unlocked', candidate, 'unlocked', 'ERROR_VERIFICATION', True),
        ('unsigned_valid_metadata_locked', candidate, 'locked', 'ERROR_VERIFICATION', False),
    ]:
        result = subprocess.run([str(binary), str(image), mode], check=True, capture_output=True, text=True)
        assert 'runtime error:' not in result.stderr and 'AddressSanitizer' not in result.stderr, result.stderr
        observed = json.loads(result.stdout)
        assert observed['status'] == expected and observed['slot_data'] == loaded, (name, observed)
        if loaded:
            assert observed['loaded_partitions'] == 1 and observed['loaded_bytes_match']
        cases.append({'case': name, 'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                      'mode': mode, 'observed': observed, 'stderr': result.stderr})
    # Negative control: a payload error must fail the independent descriptor check.
    with tempfile.TemporaryDirectory() as directory:
        image = Path(directory) / 'recovery.img'
        corrupted = bytearray(candidate.read_bytes())
        corrupted[4096] ^= 1
        image.write_bytes(corrupted)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/avbtool.py'),
                                 'verify_image', '--image', str(image)], capture_output=True, text=True)
        assert result.returncode != 0 and 'digest' in result.stdout + result.stderr
        cases.append({'case': 'corrupted_payload_descriptor_check', 'rejected': True,
                      'stdout': result.stdout, 'stderr': result.stderr})
    assert hashes == {str(p.relative_to(AVB)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    result = {'state': 'Host-only corroboration; device bootloader behavior remains separately qualified',
              'source': str(AVB), 'source_revision': subprocess.check_output(
                  ['git', '-C', str(AVB), 'rev-parse', 'HEAD'], text=True).strip(),
              'source_version': 'AOSP libavb 1.3 reference; installed LK supports through required 1.1',
              'source_hashes_before_and_after_match': True, 'source_sha256': hashes,
              'local_host_rsa_normalization': {'path': str(local_rsa.relative_to(ROOT)) if local_rsa.is_relative_to(ROOT) else str(local_rsa),
                  'sha256': hashlib.sha256(local_rsa.read_bytes()).hexdigest(),
                  'original_expression': old, 'normalized_expression': new,
                  'reason': 'Define unsigned high-byte shift for stock RSA control; original reference triggered UBSan at avb_rsa.c:506. No shared source, loader, trust or device change.'},
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'harness_sha256': hashlib.sha256((ROOT / 'tools/recovery-avb-check.c').read_bytes()).hexdigest(),
              'build_command': command, 'cases': cases,
              'limits': ['Host uses synthetic key trust and GUIDs; not an OEM trust test',
                         'No partition or rollback-index writes; all write callbacks are NULL',
                         'Current AOSP library corroborates the independently traced older LK path',
                         'No ARM code, phone kernel or phone firmware executed']}
    (evidence / 'host-avb-check.json').write_text(json.dumps(result, indent=2) + '\n')
    print('7 host cases passed with ASan/UBSan: missing metadata is fatal; valid unsigned metadata loads only in unlocked mode; corrupted payload rejected')


if __name__ == '__main__':
    main()
