#!/usr/bin/env python3
"""Derive a standard ramoops prefix from measured stock layout; local only."""
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parent.parent


def main():
    evidence = ROOT / 'evidence/kernel-upgrade/pstore-review'
    captured = evidence / 'stock-parameters.json'
    measurements = json.loads(captured.read_text())['records']
    values = {}
    for item in measurements:
        assert item['returncode'] == 0
        values[item['name']] = int(item['stdout'].strip(), 0)
    assert values == {'mem_address': 0x54410000, 'mem_size': 0xe0000,
                      'record_size': 0x1000, 'console_size': 0x40000,
                      'pmsg_size': 0x10000, 'ftrace_size': 0x1000, 'mem_type': 0, 'ecc': 0}
    fdt = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
    tree = runpy.run_path(str(ROOT / 'tools/inspect-fdt.py'))['decode'](fdt.read_bytes())['nodes']
    assert tree['/reserved-memory/mblock-10-pstore']['reg']['cells'] == [0, values['mem_address'], 0, values['mem_size']]
    dump_size = values['mem_size'] - 2 * values['console_size'] - values['pmsg_size'] - values['ftrace_size']
    assert dump_size > 0 and dump_size % values['record_size'] == 0
    prefix_size = dump_size + values['console_size']
    tail_base = values['mem_address'] + prefix_size
    tail_size = values['mem_size'] - prefix_size
    assert prefix_size == 0x8f000 and tail_base == 0x5449f000 and tail_size == 0x51000
    regions = []
    cursor = values['mem_address']
    for name, size in [('dmesg', dump_size), ('console', values['console_size']),
                       ('bconsole', values['console_size']), ('ftrace', values['ftrace_size']),
                       ('pmsg', values['pmsg_size'])]:
        regions.append({'name': name, 'base': cursor, 'bytes': size})
        cursor += size
    assert cursor == values['mem_address'] + values['mem_size']
    overlay = ROOT / 'kernel-upgrade/dts/pocket-pstore-prefix.dtso'
    overlay.write_text('''// SPDX-License-Identifier: GPL-2.0
// Captured Pocket layout only. Keep vendor bconsole/ftrace/pmsg tail reserved.
/dts-v1/;
/plugin/;
/ {
    fragment@0 {
        target-path = "/reserved-memory";
        __overlay__ {
            #address-cells = <2>;
            #size-cells = <2>;
            mblock-10-pstore {
                compatible = "ramoops";
                reg = <0 0x54410000 0 0x8f000>;
                record-size = <0x1000>;
                console-size = <0x40000>;
                ftrace-size = <0>;
                pmsg-size = <0>;
                ecc-size = <0>;
                mem-type = <0>;
            };
            pstore-vendor-tail@5449f000 {
                reg = <0 0x5449f000 0 0x51000>;
                no-map;
            };
        };
    };
};
''')
    result = {'stock_parameters': values, 'stock_regions': regions,
              'dump_records': dump_size // values['record_size'],
              'prefix': {'base': values['mem_address'], 'bytes': prefix_size},
              'tail': {'base': tail_base, 'bytes': tail_size},
              'console_payload_capacity': values['console_size'] - 12,
              'inputs': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [captured, fdt]},
              'overlay': {'path': str(overlay.relative_to(ROOT)), 'sha256': hashlib.sha256(overlay.read_bytes()).hexdigest()},
              'limits': ['Address/layout measured on this stock handset, not all firmware/board variants',
                         'No device DT installed and no RAM written',
                         'Unchanged reserved-memory union; standard ramoops owns only dump/console prefix',
                         'Warm-reset retention, early registration and stock readback remain hardware gates']}
    (evidence / 'layout.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Derived 79 dump records and stock console address; 0x8f000 prefix, 0x51000 untouched vendor tail')


if __name__ == '__main__':
    main()
