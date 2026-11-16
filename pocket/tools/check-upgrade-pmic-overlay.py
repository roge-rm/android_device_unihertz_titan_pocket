#!/usr/bin/env python3
"""Apply pinctrl+PMIC overlays only to a preserved local FDT and check scope."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    out = ROOT / 'artifacts/kernel-upgrade'
    original = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
    assert hashlib.sha256(original.read_bytes()).hexdigest() == 'd6d1b6a89e13ad130022ad31b9394e5b7def449c88a181d40cfcc47ec452763f'
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    overlay = ROOT / 'kernel-upgrade/dts/pocket-pmic-handoff.dtso'
    subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(out / 'pmic-handoff.dtbo'), str(overlay)], check=True)
    derived = out / 'pinctrl-pmic-resource-probe.dtb'
    subprocess.run([str(out / 'fdtoverlay'), '-i', str(original), '-o', str(derived),
                    str(out / 'pinctrl-resources.dtbo'), str(out / 'pmic-handoff.dtbo')], check=True)
    spec = importlib.util.spec_from_file_location('inspect_fdt', ROOT / 'tools/inspect-fdt.py')
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    before = parser.decode(original.read_bytes())['nodes']
    after = parser.decode(derived.read_bytes())['nodes']
    assert before.keys() == after.keys()
    expected = {('/1000b000.pinctrl', 'reg'), ('/1000b000.pinctrl', 'reg-names'),
                ('/pwrap@1000d000', 'compatible'), ('/pwrap@1000d000/mt6358-pmic', 'compatible')}
    changed = {(p, k) for p in before for k in set(before[p]) | set(after[p])
               if before[p].get(k) != after[p].get(k)}
    assert changed == expected, changed
    assert after['/pwrap@1000d000']['compatible']['strings'] == ['mediatek,mt6771-pwrap']
    assert after['/pwrap@1000d000/mt6358-pmic']['compatible']['strings'] == ['mediatek,mt6358']
    record = {'nodes': len(after), 'changes': sorted(changed),
              'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
              'derived_sha256': hashlib.sha256(derived.read_bytes()).hexdigest(),
              'overlay_sha256': hashlib.sha256(overlay.read_bytes()).hexdigest(),
              'scope': 'Local binding/resource conversion only; PMIC IRQ, regulator, cold-init and runtime behavior unvalidated'}
    (ROOT / 'evidence/kernel-upgrade/pmic-overlay-validation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'{len(after)} nodes retained; only the four intended pinctrl/PMIC properties changed')


if __name__ == '__main__':
    main()
