#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the FMRadio jni patch for the MT6631 driver, without editing baseline.

Two layouts in Lineage's fm.h differ from our fmradio_drv (OPPO MT6765, as stock) and the
stock libfmjni: fm_tune_parm lacks deemphasis (6 bytes, the driver copies 8 back on TUNE)
and the RDS block's group counters are unsigned long (824 bytes, the driver's read gives
688). The patch makes both match the driver (WIFI_PORT.md, milestone 10).
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
BASE = pocket_paths.platform_source() / 'packages/apps/FMRadio'
PATCH = ROOT / 'patches/android/0005-fmradio-mtk-tune-parm.patch'
OUTPUT = ROOT / 'artifacts/build-overrides/FMRadio'
FM_H = 'jni/fmr/fm.h'


def edit(text, old, new):
    assert text.count(old) == 1, old[:70]
    return text.replace(old, new, 1)


def main():
    old = (BASE / FM_H).read_text()
    new = edit(old, 'struct fm_tune_parm {\n    uint8_t err;\n    uint8_t band;\n    uint8_t space;\n    uint8_t hilo;\n    uint16_t freq;',
               'struct fm_tune_parm {\n    uint8_t err;\n    uint8_t band;\n    uint8_t space;\n    uint8_t hilo;\n'
               '    uint8_t deemphasis; // MT6631 driver and stock libfmjni layout, 8 bytes\n    uint16_t freq;')
    # The driver's read() returns 688 bytes of RDS (stock libfmjni reads 688); unsigned long
    # counters make Lineage's struct 824 bytes on arm64, so every RDS read came up short.
    new = edit(new, 'struct rds_group_cnt {\n    unsigned long total;\n    unsigned long groupA[16]; // RDS groupA counter\n'
               '    unsigned long groupB[16]; // RDS groupB counter\n};',
               'struct rds_group_cnt {\n    unsigned int total; // 32-bit as in the driver\n    unsigned int groupA[16]; // RDS groupA counter\n'
               '    unsigned int groupB[16]; // RDS groupB counter\n};')
    files = {FM_H: (old, new)}
    diff, hashes = [], {}
    for name, (a, b) in files.items():
        p = OUTPUT / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(b)
        full = 'packages/apps/FMRadio/' + name
        diff += difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile='a/' + full, tofile='b/' + full)
        hashes[name] = {'original': hashlib.sha256(a.encode()).hexdigest(), 'modified': hashlib.sha256(b.encode()).hexdigest()}
    for p in OUTPUT.rglob('*'):
        if p.is_file() and str(p.relative_to(OUTPUT)) not in files:
            p.unlink()
    PATCH.write_text(''.join(diff))
    with tempfile.TemporaryDirectory(prefix='fmradio-patch-') as tmp:
        tree = Path(tmp)
        for name, (a, b) in files.items():
            p = tree / 'packages/apps/FMRadio' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(a)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)], check=True, capture_output=True)
        for name, (a, b) in files.items():
            assert (tree / 'packages/apps/FMRadio' / name).read_text() == b
    out = ROOT / 'evidence/connectivity/fmradio-patch.json'
    out.write_text(json.dumps({'files': hashes, 'patch': str(PATCH.relative_to(ROOT)), 'replay_exact': True,
                               'shared_source_modified': False, 'runtime_tested': False}, indent=2) + '\n')
    print('FMRadio jni patch replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
