#!/usr/bin/env python3
"""Compile/apply the prototype overlay to a local preserved FDT, then compare.

Only the two reviewed pinctrl resource properties may change. No phone access.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    ledger = json.loads((ROOT / 'evidence/kernel-upgrade/pinctrl-resources.json').read_text())
    source = ROOT / 'kernel-upgrade/dts/pocket-pinctrl-resources.dtso'
    original = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
    assert hashlib.sha256(original.read_bytes()).hexdigest() == ledger['live_fdt_sha256']
    out = ROOT / 'artifacts/kernel-upgrade'
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    commands = [[str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(out / 'pinctrl-resources.dtbo'), str(source)],
                [str(out / 'fdtoverlay'), '-i', str(original), '-o', str(out / 'pinctrl-resource-probe.dtb'),
                 str(out / 'pinctrl-resources.dtbo')]]
    runs = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
        runs.append({'command': command, 'returncode': result.returncode,
                     'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr)
    spec = importlib.util.spec_from_file_location('inspect_fdt', ROOT / 'tools/inspect-fdt.py')
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    before = parser.decode(original.read_bytes())['nodes']
    after = parser.decode((out / 'pinctrl-resource-probe.dtb').read_bytes())['nodes']
    assert before.keys() == after.keys(), 'Overlay changed node inventory'
    changed = []
    for path in before:
        for name in set(before[path]) | set(after[path]):
            if before[path].get(name) != after[path].get(name):
                changed.append({'node': path, 'property': name})
    expected = [{'node': ledger['target_path'], 'property': name} for name in ['reg', 'reg-names']]
    assert sorted(changed, key=str) == sorted(expected, key=str), changed
    properties = after[ledger['target_path']]
    assert properties['reg']['cells'] == [cell for resource in ledger['resources'] for cell in resource['reg_cells']]
    assert properties['reg-names']['strings'] == [resource['name'] for resource in ledger['resources']]
    result = {'commands': runs, 'before_nodes': len(before), 'after_nodes': len(after), 'changed': changed,
              'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
              'derived_sha256': hashlib.sha256((out / 'pinctrl-resource-probe.dtb').read_bytes()).hexdigest(),
              'status': 'Local resource-conversion checks passed',
              'scope': 'Only pinctrl MMIO resources; not a complete 5.10 device tree or hardware binding test'}
    (ROOT / 'evidence/kernel-upgrade/pinctrl-overlay-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Overlay applied locally; all', len(after), 'nodes retained, only reg/reg-names changed')
    for run in runs:
        if run['stderr']:
            print(run['stderr'])


if __name__ == '__main__':
    main()
