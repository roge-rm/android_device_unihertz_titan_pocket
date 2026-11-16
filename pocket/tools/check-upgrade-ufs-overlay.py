#!/usr/bin/env python3
"""Validate combined provider conversions without changing the saved stock FDT."""
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
    overlay = ROOT / 'kernel-upgrade/dts/pocket-ufs-foundation.dtso'
    subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(out / 'ufs-foundation.dtbo'), str(overlay)], check=True)
    derived = out / 'pinctrl-pmic-ufs-resource-probe.dtb'
    subprocess.run([str(out / 'fdtoverlay'), '-i', str(original), '-o', str(derived),
                    str(out / 'pinctrl-resources.dtbo'), str(out / 'pmic-handoff.dtbo'),
                    str(out / 'ufs-foundation.dtbo')], check=True)
    spec = importlib.util.spec_from_file_location('inspect_fdt', ROOT / 'tools/inspect-fdt.py')
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    before = parser.decode(original.read_bytes())['nodes']
    after = parser.decode(derived.read_bytes())['nodes']
    assert before.keys() == after.keys()
    expected = {('/1000b000.pinctrl', 'reg'), ('/1000b000.pinctrl', 'reg-names'),
                ('/pwrap@1000d000', 'compatible'), ('/pwrap@1000d000/mt6358-pmic', 'compatible'),
                ('/infracfg_ao@10001000', '#reset-cells')}
    expected |= {('/ufs_mphy@11fa0000', p) for p in ['compatible', 'clocks', 'clock-names', '#phy-cells']}
    changed = {(p, k) for p in before for k in set(before[p]) | set(after[p])
               if before[p].get(k) != after[p].get(k)}
    assert changed == expected, changed
    infra = before['/infracfg_ao@10001000']
    assert infra['phandle']['cells'] == [21] and infra['#clock-cells']['cells'] == [1]
    assert 'syscon' in infra['compatible']['strings']
    host = before['/ufshci@11270000']
    # Prove the PHY gates are precisely the original host UniPro/MP gates.
    clocks = host['clocks']['cells']
    names = host['clock-names']['strings']
    selected = []
    for name in ['ufs0-unipro-clk', 'ufs0-mp-clk']:
        i = names.index(name)
        selected += clocks[2*i:2*i+2]
    assert after['/ufs_mphy@11fa0000']['clocks']['cells'] == selected
    assert after['/ufshci@11270000'] == host, 'This overlay must not claim a host port'
    record = {'nodes': len(after), 'changes': sorted(changed),
              'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
              'derived_sha256': hashlib.sha256(derived.read_bytes()).hexdigest(),
              'overlay_sha256': hashlib.sha256(overlay.read_bytes()).hexdigest(),
              'scope': 'Local provider binding conversion only; no UFS host/PHY/power/reset hardware qualification'}
    (ROOT / 'evidence/kernel-upgrade/ufs-overlay-validation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'{len(after)} nodes retained; exactly 9 provider properties changed; host binding unchanged')


if __name__ == '__main__':
    main()
