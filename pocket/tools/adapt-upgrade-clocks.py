#!/usr/bin/env python3
"""Adapt the MT6771 mux initializer without passing signed sentinels to gates."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    path = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/clk/mediatek/clk-mt6771.c'
    text = path.read_text()
    if 'MT6771_MUX_CLR_SET_UPD(' in text:
        raise SystemExit('Mux adapter already applied; refusing to overwrite edits')
    text = text.replace('MUX_CLR_SET_UPD(', 'MT6771_MUX_CLR_SET_UPD(')
    macro = r'''
/* The BSP used gate=-1 for an ungated mux. The 5.10 gate field is u8:
 * choose the non-gating ops explicitly instead of shifting by 255.
 */
#define MT6771_MUX_CLR_SET_UPD(_id, _name, _parents, _mux_ofs, \
                _set, _clr, _shift, _width, _gate, _upd_ofs, _upd) { \
        .id = (_id), .name = (_name), .parent_names = (_parents), \
        .num_parents = ARRAY_SIZE(_parents), .flags = CLK_SET_RATE_PARENT, \
        .mux_ofs = (_mux_ofs), .set_ofs = (_set), .clr_ofs = (_clr), \
        .upd_ofs = (_upd_ofs), .mux_shift = (_shift), .mux_width = (_width), \
        .gate_shift = ((_gate) < 0 ? 0 : (_gate)), .upd_shift = (_upd), \
        .ops = ((_gate) < 0 ? &mtk_mux_clr_set_upd_ops : \
                              &mtk_mux_gate_clr_set_upd_ops), \
}

'''
    marker = '#include <dt-bindings/clock/mt6771-clk.h>\n'
    assert text.count(marker) == 1
    path.write_text(text.replace(marker, marker + macro, 1))
    print('Adapted mux descriptors; ungated sentinel uses non-gating operations')


if __name__ == '__main__':
    main()
