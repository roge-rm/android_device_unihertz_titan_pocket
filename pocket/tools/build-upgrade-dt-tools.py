#!/usr/bin/env python3
"""Build the existing shared DTC overlay utility into a project-local output."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = pocket_paths.platform_source() / 'external/dtc'


def main():
    output = ROOT / 'artifacts/kernel-upgrade'
    include = output / 'host-include'
    include.mkdir(parents=True, exist_ok=True)
    makefile = (SOURCE / 'Makefile').read_text()
    version = '.'.join(re.search(r'^' + key + r'\s*=\s*(\d+)', makefile, re.M)[1]
                       for key in ['VERSION', 'PATCHLEVEL', 'SUBLEVEL'])
    (include / 'version_gen.h').write_text('#define DTC_VERSION "DTC ' + version + ' (offline host probe)"\n')
    sources = ['fdtoverlay.c', 'util.c'] + ['libfdt/' + name for name in [
        'fdt.c', 'fdt_ro.c', 'fdt_wip.c', 'fdt_sw.c', 'fdt_rw.c', 'fdt_strerror.c',
        'fdt_empty_tree.c', 'fdt_addresses.c', 'fdt_overlay.c', 'fdt_check.c']]
    command = ['cc', '-O2', '-I' + str(include), '-I' + str(SOURCE), '-I' + str(SOURCE / 'libfdt'),
               *[str(SOURCE / name) for name in sources], '-o', str(output / 'fdtoverlay')]
    result = subprocess.run(command, capture_output=True, text=True)
    record = {'command': command, 'returncode': result.returncode, 'stderr': result.stderr,
              'version': version, 'binary_sha256': hashlib.sha256((output / 'fdtoverlay').read_bytes()).hexdigest() if result.returncode == 0 else None,
              'inputs': [{'path': str(SOURCE / name), 'sha256': hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()} for name in sources],
              'scope': 'Host utility only; shared source read without build writes'}
    (ROOT / 'evidence/kernel-upgrade/dt-host-tools.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Host overlay utility return code', result.returncode)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
