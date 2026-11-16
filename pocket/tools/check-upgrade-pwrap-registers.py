#!/usr/bin/env python3
"""Check the closest PWRAP register-map donor against the MT6771 BSP."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def main():
    old = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/misc/mediatek/pmic_wrap/mt6771/pwrap_hal.h'
    new = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/soc/mediatek/mtk-pmic-wrap.c'
    bsp = {m[1]: int(m[2], 16) for m in re.finditer(
        r'^#define\s+PMIC_WRAP_(\w+)\s+.*?PMIC_WRAP_BASE\s*\+\s*(0x[0-9a-fA-F]+)', old.read_text(), re.M)}
    body = re.search(r'static int mt8183_regs\[\]\s*=\s*\{(.*?)\n\};', new.read_text(), re.S)[1]
    donor = {m[1]: int(m[2], 16) for m in re.finditer(r'\[PWRAP_(\w+)\]\s*=\s*(0x[0-9a-fA-F]+)', body)}
    aliases = {'HIPRIO_ARB_EN': 'HPRIO_ARB_EN', 'INT_EN': 'INT0_EN', 'INT_FLG': 'INT0_FLG',
               'INT_CLR': 'INT0_CLR', 'WDT_SRC_EN': 'WDT_SRC_EN_0'}
    comparisons = []
    for name, value in donor.items():
        original = aliases.get(name, name)
        assert original in bsp, ('Unmapped field', name)
        assert value == bsp[original], (name, value, bsp[original])
        comparisons.append({'field': name, 'bsp_field': original, 'offset': value,
                            'explicit_name_alias': name in aliases})
    assert len(comparisons) == 48
    record = {'donor': '5.10 mt8183_regs', 'fields_verified': 48,
              'explicit_name_aliases': aliases, 'comparisons': comparisons,
              'inputs': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in [old, new]],
              'remaining': ['MT6771 initialization/timing/encryption and IRQ behavior',
                            'BSP arbitration mask0x3fa65 differs from MT8183 descriptor0x3fa75',
                            'BSP interrupt1 enable mask0xffffffff differs from MT8183 descriptor0xeef7ffff',
                            'PMIC core/regulator/IRQ child bindings and power-management compatibility',
                            'Actual hardware communication and reset/resume tests'],
              'scope': 'Register-map donor only; does not establish complete MT8183/Pocket compatibility or implement a PWRAP port'}
    (ROOT / 'evidence/kernel-upgrade/pwrap-donor-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print('All 48 donor register offsets match the MT6771 definitions with 5 explicit name aliases')


if __name__ == '__main__':
    main()
