#!/usr/bin/env python3
"""Validate the standard ramoops prefix without changing its reserved extent."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence = ROOT / 'evidence/kernel-upgrade/pstore-review'
    layout = json.loads((evidence / 'layout.json').read_text())
    decode = runpy.run_path(str(ROOT / 'tools/inspect-fdt.py'))['decode']
    usb = json.loads((ROOT / 'evidence/kernel-upgrade/usb-overlay-validation.json').read_text())
    base = ROOT / usb['derived']['path']
    assert sha(base) == usb['derived']['sha256']
    overlay = ROOT / layout['overlay']['path']
    assert sha(overlay) == layout['overlay']['sha256']
    output = ROOT / 'artifacts/kernel-upgrade'
    compiled = output / 'pstore-prefix.dtbo'
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    check = subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(compiled), str(overlay)],
                           check=True, capture_output=True, text=True)
    (evidence / 'overlay-dtc.txt').write_text(check.stdout + check.stderr)
    derived = output / 'pinctrl-pmic-ufs-usb-pstore-diagnostic.dtb'
    subprocess.run([str(output / 'fdtoverlay'), '-i', str(base), '-o', str(derived), str(compiled)], check=True)
    before, after = decode(base.read_bytes())['nodes'], decode(derived.read_bytes())['nodes']
    node = '/reserved-memory/mblock-10-pstore'
    tail_node = '/reserved-memory/pstore-vendor-tail@5449f000'
    assert set(after) - set(before) == {tail_node} and not set(before) - set(after)
    changed = {(p,k) for p in before for k in set(before[p]) | set(after[p])
               if before[p].get(k) != after[p].get(k)}
    assert changed == {(node,p) for p in ['reg', 'compatible', 'record-size', 'console-size',
                                        'ftrace-size', 'pmsg-size', 'ecc-size', 'mem-type']}
    assert before['/reserved-memory']['#address-cells']['cells'] == [2]
    assert before['/reserved-memory']['#size-cells']['cells'] == [2]
    prefix, tail = layout['prefix'], layout['tail']
    assert after[node]['reg']['cells'] == [0, prefix['base'], 0, prefix['bytes']]
    assert after[tail_node]['reg']['cells'] == [0, tail['base'], 0, tail['bytes']]
    assert 'no-map' in after[node] and 'no-map' in after[tail_node]
    assert prefix['base'] + prefix['bytes'] == tail['base']
    assert tail['base'] + tail['bytes'] == layout['stock_parameters']['mem_address'] + layout['stock_parameters']['mem_size']
    assert after[node]['compatible']['strings'] == ['ramoops']
    for prop in ['ftrace-size', 'pmsg-size', 'ecc-size', 'mem-type']:
        assert after[node][prop]['cells'] == [0]
    assert after[node]['record-size']['cells'] == [4096]
    assert after[node]['console-size']['cells'] == [262144]
    assert after['/reserved-memory/mblock-9-ram_console'] == before['/reserved-memory/mblock-9-ram_console']
    of_source = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/of/platform.c'
    assert '.compatible = "ramoops"' in of_source.read_text()
    result = {'nodes': len(after), 'existing_property_changes': sorted(changed), 'new_node': tail_node,
              'reserved_memory_union_preserved': True, 'binary_ram_console_region_unchanged': True,
              'prefix': prefix, 'tail': tail,
              'derived': {'path': str(derived.relative_to(ROOT)), 'sha256': sha(derived)},
              'inputs': {str(p.relative_to(ROOT)): sha(p) for p in [base, overlay, of_source]},
              'limits': ['Offline DT application, not a bootloader-ready image/table',
                         'The vendor tail remains reserved without a ramoops frontend',
                         'Existing vendor pstore node name is retained in this diagnostic derivative',
                         'No device mapping or warm-reset retention/readback tested']}
    (evidence / 'overlay-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'{len(after)} nodes: eight pstore properties changed, one reserved tail added; original reserved extent preserved')


if __name__ == '__main__':
    main()
