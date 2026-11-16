#!/usr/bin/env python3
"""Compare stock config selections with definitions in an extracted source tree.

This lexical audit does not evaluate Kconfig dependencies or establish that a
driver builds, binds, or works. A name search cannot rule out renamed code.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('stock_config', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not (source / 'Makefile').is_file():
        parser.error('source must be the extracted kernel root')
    config_bytes = args.stock_config.read_bytes()
    stock = dict(re.findall(r'^CONFIG_(\w+)=(.*)$', config_bytes.decode(), re.M))
    definitions = {}
    count = 0
    for path in sorted(source.rglob('Kconfig*')):
        if not path.is_file() or path.is_symlink():
            continue
        count += 1
        for symbol in re.findall(r'^\s*(?:menu)?config\s+(\w+)',
                                 path.read_text(errors='replace'), re.M):
            definitions.setdefault(symbol, []).append(str(path.relative_to(source)))
    missing = {name: value for name, value in stock.items()
               if name not in definitions and value != 'n'}
    selected = ['MTK_PLATFORM', 'CUSTOM_KERNEL_LCM', 'CUSTOM_KERNEL_IMGSENSOR',
                'KEYBOARD_MTK', 'TOUCHSCREEN_MTK_GT1151QM',
                'TOUCHSCREEN_MTK_GT1151', 'TOUCHSCREEN_MTK_SYNAPTICS_DSX',
                'MTK_FINGERPRINT_SUPPORT', 'AGOLD_FINGERPRINT_SELECT',
                'NFC_ST54_SPI', 'MODVERSIONS', 'IKCONFIG', 'BPF_SYSCALL']
    result = {
        'source': str(source),
        'stock_config_sha256': hashlib.sha256(config_bytes).hexdigest(),
        'kconfig_files_scanned': count,
        'defined_symbols': len(definitions),
        'stock_selected_symbols': len(stock),
        'stock_selections_without_definition': missing,
        'selected_hardware_symbols': {
            name: {'stock': stock.get(name), 'definition_paths': definitions.get(name, [])}
            for name in selected
        },
        'limitations': ['Lexical symbol definitions only; dependencies and generated definitions not evaluated',
                        'Missing names may have equivalents under other symbols',
                        'No compile, module ABI, driver binding or hardware validation'],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'{count} Kconfig files; {len(missing)} stock selections without a matching definition')
    for name in selected:
        entry = result['selected_hardware_symbols'][name]
        print(f'{name}: stock={entry["stock"]}, definitions={entry["definition_paths"]}')


if __name__ == '__main__':
    main()
