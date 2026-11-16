#!/usr/bin/env python3
"""Verify new reset IDs reach the BSP's UFS SET/CLR registers and bits."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def main():
    old = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/scsi/ufs/mediatek/mt6771/ufs-mtk-platform.h'
    new = ROOT / 'tools/kernel-source/upgrade-5.10/include/dt-bindings/reset/mt6771-resets.h'
    provider = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/clk/mediatek/reset.c'
    clock = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/clk/mediatek/clk-mt6771.c'
    original = {m[1]: int(m[2], 0) for m in re.finditer(r'(REG_\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', old.read_text())}
    ids = {m[1]: int(m[2]) for m in re.finditer(r'#define MT6771_(\w+)_SW_RST\s+(\d+)', new.read_text())}
    # Tie the arithmetic below to the real helper and its registered base/bank count.
    code = provider.read_text()
    assert 'data->regofs + ((id / 32) << 4)' in code
    assert 'data->regofs + ((id / 32) << 4) + 0x4' in code
    assert 'regmap_write(data->regmap, reg, BIT(id % 32))' in code
    assert 'mtk_register_reset_controller_set_clr(node, 3, 0x120)' in clock.read_text()
    rows = []
    for name, reset_id in ids.items():
        set_offset = 0x120 + (reset_id // 32) * 0x10
        clear_offset = set_offset + 4
        bit = reset_id % 32
        assert 0 <= reset_id < 96
        assert set_offset == original[f'REG_{name}_SW_RST_SET']
        assert clear_offset == original[f'REG_{name}_SW_RST_CLR']
        assert bit == original[f'REG_{name}_SW_RST_SET_BIT'] == original[f'REG_{name}_SW_RST_CLR_BIT']
        rows.append({'name': name, 'id': reset_id, 'set': set_offset, 'clear': clear_offset, 'bit': bit})
    assert len(rows) == 3
    record = {'resets': rows, 'inputs': [{'path': str(p.relative_to(ROOT)),
               'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in [old, new, provider, clock]],
              'scope': 'Source register/bit mapping only; reset ordering, power state and hardware untested'}
    (ROOT / 'evidence/kernel-upgrade/ufs-reset-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print('All 3 UFS reset IDs match the BSP SET/CLR addresses and bit positions')


if __name__ == '__main__':
    main()
