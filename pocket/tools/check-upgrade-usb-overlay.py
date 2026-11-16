#!/usr/bin/env python3
"""Validate the peripheral USB diagnostic overlay against the captured FDT."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    decode = runpy.run_path(str(ROOT / 'tools/inspect-fdt.py'))['decode']
    original = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
    assert sha(original) == 'd6d1b6a89e13ad130022ad31b9394e5b7def449c88a181d40cfcc47ec452763f'
    out = ROOT / 'artifacts/kernel-upgrade'
    base = out / 'pinctrl-pmic-ufs-resource-probe.dtb'
    base_record = ROOT / 'evidence/kernel-upgrade/ufs-overlay-validation.json'
    assert sha(base) == json.loads(base_record.read_text())['derived_sha256']
    source = ROOT / 'tools/kernel-source/upgrade-5.10'
    bindings = source / 'include/dt-bindings/clock/mt6771-clk.h'
    clocks = source / 'drivers/clk/mediatek/clk-mt6771.c'
    # The PHY's explicit reference is the named 26 MHz USB gate, not the
    # controller's unrelated UniPro clock or a newly invented fixed clock.
    assert re.search(r'^#define\s+APMIXED_SSUSB26M\s+12$', bindings.read_text(), re.M)
    assert re.search(r'GATE_APMIXED\(APMIXED_SSUSB26M,\s*"apmixed_ssusb26m",\s*"f_f26m_ck",\s*4\)', clocks.read_text())
    assert re.search(r'FIXED_CLK\(TOP_CLK26M,\s*"f_f26m_ck",\s*"clk26m",\s*26000000\)', clocks.read_text())
    overlay = ROOT / 'kernel-upgrade/dts/pocket-usb-diagnostic.dtso'
    compiled = out / 'usb-diagnostic.dtbo'
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    result = subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(compiled), str(overlay)],
                            check=True, capture_output=True, text=True)
    evidence = ROOT / 'evidence/kernel-upgrade/usb-overlay-validation.json'
    evidence.with_suffix('.dtc.txt').write_text(result.stdout + result.stderr)
    derived = out / 'pinctrl-pmic-ufs-usb-diagnostic.dtb'
    subprocess.run([str(out / 'fdtoverlay'), '-i', str(base), '-o', str(derived), str(compiled)], check=True)
    before = decode(base.read_bytes())['nodes']
    after = decode(derived.read_bytes())['nodes']
    stock = decode(original.read_bytes())['nodes']
    assert before.keys() == after.keys() == stock.keys()
    expected = {('/usb0phy@11f40000', 'clocks'), ('/usb0phy@11f40000', 'clock-names'),
                ('/usb3@11200000', 'dr_mode'), ('/usb3_xhci@11200000', 'status')}
    changed = {(p, k) for p in before for k in set(before[p]) | set(after[p])
               if before[p].get(k) != after[p].get(k)}
    assert changed == expected, changed
    apmixed = stock['/apmixed@1000c000']
    assert apmixed['phandle']['cells'] == [0x64] and apmixed['#clock-cells']['cells'] == [1]
    phy = after['/usb0phy@11f40000']
    assert phy['clocks']['cells'] == [0x64, 12] and phy['clock-names']['strings'] == ['ref_clk']
    assert phy['#phy-cells']['cells'] == [1]
    controller = after['/usb3@11200000']
    assert controller['phys']['cells'] == [phy['phandle']['cells'][0], 0]
    assert controller['clock-names']['strings'] == ['sys_ck', 'rel_clk']
    assert controller['clocks']['cells'] == stock['/usb3@11200000']['clocks']['cells']
    assert controller['dr_mode']['strings'] == ['peripheral']
    assert after['/usb3_xhci@11200000']['status']['strings'] == ['disabled']
    for node in ['/usb0phy@11f40000', '/usb3@11200000', '/usb3_xhci@11200000']:
        for prop in ['reg', 'reg-names', 'interrupts', 'phys', 'phy-names']:
            assert stock[node].get(prop) == after[node].get(prop)
    all_changes = {(p, k) for p in stock for k in set(stock[p]) | set(after[p])
                   if stock[p].get(k) != after[p].get(k)}
    assert all_changes == expected | {tuple(p) for p in json.loads(base_record.read_text())['changes']}
    record = {'nodes': len(after), 'usb_changes': sorted(changed), 'total_provider_and_usb_changes': len(all_changes),
              'inputs': {str(p.relative_to(ROOT)): sha(p) for p in [original, base, overlay, bindings, clocks]},
              'derived': {'path': str(derived.relative_to(ROOT)), 'sha256': sha(derived)},
              'phy_clock': {'provider': '/apmixed@1000c000', 'id': 12, 'name': 'apmixed_ssusb26m',
                            'parent': 'f_f26m_ck', 'nominal_hz': 26000000, 'gate_bit': 4},
              'dtc_diagnostics': str(evidence.with_suffix('.dtc.txt').relative_to(ROOT)),
              'limits': ['Captured live FDT derivative; not a shipping board DT or Android boot image',
                         'Source-proven USB gate selection; hardware clock, PHY and signal behavior untested',
                         'Peripheral diagnostics only; host/OTG, Type-C, wake and charging remain open',
                         'No regulator supply or power-domain conversion claimed; bootloader handoff still matters',
                         'No phone modifications or shared-source changes']}
    evidence.write_text(json.dumps(record, indent=2) + '\n')
    print(f'{len(after)} nodes retained; exactly 4 USB properties and {len(all_changes)} total properties changed')


if __name__ == '__main__':
    main()
