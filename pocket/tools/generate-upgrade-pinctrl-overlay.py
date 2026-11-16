#!/usr/bin/env python3
"""Derive named 5.10 pinctrl resources from captured Pocket phandles.

Produces an offline DT overlay and resource ledger. Never contacts the handset.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    source = ROOT / 'evidence/device/20261029T000648.917229Z/live-device-tree.json'
    data = json.loads(source.read_text())
    nodes = data['nodes']
    lookup = {value['phandle']['cells'][0]: (path, value) for path, value in nodes.items()
              if 'phandle' in value}
    matches = [(path, value) for path, value in nodes.items()
               if 'mediatek,mt6771-pinctrl' in value.get('compatible', {}).get('strings', [])]
    if len(matches) != 1:
        raise SystemExit('Ambiguous pinctrl identity')
    nodepath, pinctrl = matches[0]
    phandles = pinctrl['reg_bases']['cells']
    if len(phandles) != 9 or nodes['/']['#address-cells']['cells'] != [2] or nodes['/']['#size-cells']['cells'] != [2]:
        raise SystemExit('Unexpected register binding or cell widths')
    resources = []
    for index, handle in enumerate(phandles + pinctrl['reg_base_eint']['cells']):
        path, provider = lookup[handle]
        cells = provider['reg']['cells']
        if len(cells) != 4 or not (cells[2] or cells[3]):
            raise SystemExit('Unexpected or empty register range')
        name = 'gpio' if index == 0 else ('eint' if index == 9 else 'iocfg' + str(index-1))
        resources.append({'index': index, 'name': name, 'provider': path, 'phandle': handle,
                          'reg_cells': cells})
    registers = ',\n\t\t\t\t'.join('<' + ' '.join(f'0x{x:x}' for x in r['reg_cells']) + '>' for r in resources)
    names = ', '.join('"' + r['name'] + '"' for r in resources)
    text = f'''// SPDX-License-Identifier: GPL-2.0
// Derived from the captured Pocket register-bank ordering, not another SoC.
/dts-v1/;
/plugin/;
/ {{
\tfragment@0 {{
\t\ttarget-path = "{nodepath}";
\t\t#address-cells = <2>;
\t\t#size-cells = <2>;
\t\t__overlay__ {{
\t\t\treg = {registers};
\t\t\treg-names = {names};
\t\t}};
\t}};
}};
'''
    destination = ROOT / 'kernel-upgrade/dts/pocket-pinctrl-resources.dtso'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text)
    ledger = {'source': str(source), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'live_fdt_sha256': data['input_sha256'], 'target_path': nodepath,
              'resources': resources, 'overlay_source': str(destination),
              'overlay_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
              'scope': 'Named MMIO resource conversion only; original pin, GPIO/IRQ and interrupt-cell properties retained; not hardware validated'}
    (ROOT / 'evidence/kernel-upgrade/pinctrl-resources.json').write_text(json.dumps(ledger, indent=2) + '\n')
    print('Generated 9 GPIO/IOCFG banks plus EINT from live phandles')


if __name__ == '__main__':
    main()
