#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the Pocket 30.0.compat.cil override, without editing baseline.

Upstream gives mlsvendorcompat to every app domain that isn't a core domain. That always
includes the platform's vzwomatrigger_app, so domain.te's fork neverallow fails for any
API 30 vendor. The override leaves mlsvendorcompat empty. With the Pocket vendor this
compiles to the same policy as the V14 scoped expression, which names three stock vendor
app domains that the build's own compat test can't resolve.
"""
import pocket_paths
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = pocket_paths.platform_source()
RELATIVE = 'system/sepolicy/private/compat/30.0/30.0.compat.cil'
OVERRIDE = ROOT / 'artifacts/build-overrides/sepolicy-30.0.compat.cil'
PATCH = ROOT / 'patches/android/0003-pocket-sepolicy-30.0-mlsvendorcompat.patch'
UPSTREAM = '(typeattributeset mlsvendorcompat (and appdomain vendordomain))\n'
POCKET = ';; Pocket: no members, as domain.te forbids any.\n'


def main():
    old = (BASE / RELATIVE).read_text()
    assert old.count(UPSTREAM) == 1, 'Upstream mlsvendorcompat line changed'
    new = old.replace(UPSTREAM, POCKET, 1)
    OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
    OVERRIDE.write_text(new)
    PATCH.parent.mkdir(parents=True, exist_ok=True)
    PATCH.write_text(''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                  fromfile='a/' + RELATIVE, tofile='b/' + RELATIVE)))
    with tempfile.TemporaryDirectory(prefix='sepolicy-patch-') as tmp:
        p = Path(tmp) / RELATIVE
        p.parent.mkdir(parents=True)
        p.write_text(old)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)],
                       check=True, capture_output=True)
        assert p.read_text() == new
    record = {'file': RELATIVE, 'original_sha256': hashlib.sha256(old.encode()).hexdigest(),
              'override_sha256': hashlib.sha256(new.encode()).hexdigest(),
              'patch': str(PATCH.relative_to(ROOT)), 'replay_exact': True,
              'shared_source_modified': False, 'used_by': 'tools/run-pocket-product-build.py',
              'limits': ['Only the 30.0 vendor compat file; other API levels are untouched',
                         'Not loaded or tested on the device']}
    evidence = ROOT / 'evidence/kernel-upgrade/sepolicy-compat-patch.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(record, indent=2) + '\n')
    print('30.0.compat.cil override replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
