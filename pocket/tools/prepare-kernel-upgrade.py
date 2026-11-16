#!/usr/bin/env python3
"""Copy the existing pinned 5.10 reference into an independent Pocket workspace.

No network access or shared Git/source changes. Materialized files are copied,
not hard-linked, and the shared .git link is excluded.
"""
import pocket_paths
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = pocket_paths.platform_source() / 'kernel/motorola/sm6450'
COMMIT = '9708121d5855e50a16df8787228d1edd6ed6f99c'
DESTINATION = ROOT / 'tools/kernel-source/upgrade-5.10'


def main():
    actual = subprocess.run(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'],
                            check=True, capture_output=True, text=True).stdout.strip()
    if actual != COMMIT:
        raise SystemExit('Shared reference revision differs from the audited pin')
    if DESTINATION.exists():
        raise SystemExit('Destination already exists; refusing to overwrite the workspace')
    print('Copying pinned local reference into ' + str(DESTINATION), flush=True)
    shutil.copytree(SOURCE, DESTINATION, symlinks=True,
                    ignore=shutil.ignore_patterns('.git'), copy_function=shutil.copy2)
    # The Qualcomm vendor-DT checkout is a separate Boston project. The Pocket
    # probe does not build those trees; keep all local links inside this copy.
    vendor_link = DESTINATION / 'arch/arm64/boot/dts/vendor'
    if not vendor_link.is_symlink() or str(vendor_link.readlink()) != '../../../../../sm6450-devicetrees':
        raise SystemExit('Unexpected vendor DT layout; review before building')
    vendor_link.unlink()
    (vendor_link / 'bindings').mkdir(parents=True)
    source_make = hashlib.sha256((SOURCE / 'Makefile').read_bytes()).hexdigest()
    assert hashlib.sha256((DESTINATION / 'Makefile').read_bytes()).hexdigest() == source_make
    assert not (DESTINATION / '.git').exists()
    escaped = []
    for path in DESTINATION.rglob('*'):
        if path.is_symlink() and not path.resolve().is_relative_to(DESTINATION):
            escaped.append({'path': str(path.relative_to(DESTINATION)), 'target': str(path.readlink())})
    evidence = ROOT / 'evidence/kernel-upgrade'
    evidence.mkdir(parents=True, exist_ok=True)
    record = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': str(SOURCE),
              'commit': COMMIT, 'destination': str(DESTINATION), 'copy_mode': 'independent file copies; .git excluded',
              'makefile_sha256': source_make, 'external_symlinks': escaped,
              'vendor_dt_adjustment': 'Replaced Qualcomm external vendor-DT link with empty local directory; no Qualcomm DT build coverage claimed',
              'scope': '5.10.257 generic API reference, not a Pocket BSP or bootable target'}
    (evidence / 'workspace.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Copy complete; external symlinks: ' + str(len(escaped)))
    if escaped:
        raise SystemExit('Review external symlinks before building')


if __name__ == '__main__':
    main()
