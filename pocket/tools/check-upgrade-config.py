#!/usr/bin/env python3
"""Reject a probe configuration that silently dropped any requested setting."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def settings(text):
    result = {}
    for line in text.splitlines():
        if match := re.fullmatch(r'(CONFIG_\w+)=(.*)', line):
            result[match[1]] = match[2]
        elif match := re.fullmatch(r'# (CONFIG_\w+) is not set', line):
            result[match[1]] = 'n'
    return result


def main():
    fragment = ROOT / 'configs/kernel-upgrade-5.10.fragment'
    config = ROOT / 'tools/kernel-build-config/upgrade-5.10/.config'
    requested, actual = settings(fragment.read_text()), settings(config.read_text())
    differences = [{'option': key, 'requested': value, 'actual': actual.get(key)}
                   for key, value in requested.items() if actual.get(key) != value]
    record = {'requested_option_count': len(requested), 'differences': differences,
              'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
              'fragment_sha256': hashlib.sha256(fragment.read_bytes()).hexdigest(),
              'scope': 'Requested probe options only; not full Android/Pocket product conformance'}
    (ROOT / 'evidence/kernel-upgrade/config-fragment-check.json').write_text(json.dumps(record, indent=2) + '\n')
    if differences:
        raise SystemExit(json.dumps(differences, indent=2))
    print(f'All {len(requested)} requested configuration settings match')


if __name__ == '__main__':
    main()
