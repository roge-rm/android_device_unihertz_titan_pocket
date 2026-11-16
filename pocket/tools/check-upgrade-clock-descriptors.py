#!/usr/bin/env python3
"""Compare actual ARM64 ELF clock descriptors across the 4.14/5.10 builds.

Resolves pointer relocations, names and parent arrays without executing either
target object. Checks tables and sentinel adaptation, not clock hardware.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent


class Elf:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        assert self.data[:6] == b'\x7fELF\x02\x01'
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.data)
        assert header[1] == 1 and header[2] == 183 and header[11] == 64
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', self.data, header[6] + i*64)
                         for i in range(header[12])]
        symbol_sections = [s for s in self.sections if s[1] == 2]
        assert len(symbol_sections) == 1
        table = symbol_sections[0]
        strings = self.content(table[6])
        self.symbols = []
        for name, info, other, index, value, size in struct.iter_unpack('<IBBHQQ', self.raw(table)):
            self.symbols.append({'name': self.string(strings, name), 'section': index,
                                 'value': value, 'size': size})
        self.relocations = {}
        for section in self.sections:
            if section[1] != 4:
                continue
            for offset, info, addend in struct.iter_unpack('<QQq', self.raw(section)):
                self.relocations[section[7], offset] = (info & 0xffffffff, self.symbols[info >> 32], addend)

    def raw(self, section):
        assert section[4] + section[5] <= len(self.data)
        return self.data[section[4]:section[4]+section[5]]

    def content(self, index):
        return self.raw(self.sections[index])

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b'\0', offset)].decode()

    def pointer(self, section, offset):
        kind, symbol, addend = self.relocations[section, offset]
        assert kind == 257, ('Expected AArch64 ABS64 relocation', kind)
        return symbol, symbol['value'] + addend

    def pointer_string(self, section, offset):
        symbol, target = self.pointer(section, offset)
        assert symbol['section'] > 0
        return self.string(self.content(symbol['section']), target)

    def muxes(self, original):
        symbols = [s for s in self.symbols if s['name'] == 'top_muxes']
        assert len(symbols) == 1
        symbol = symbols[0]
        # LP64 mtk_mux layout in both audited headers; pointer fields relocated.
        layout = struct.Struct('<I4xQQIIIIIbbbbQb7x')
        assert layout.size == 64 and symbol['size'] % layout.size == 0
        records = []
        data = self.content(symbol['section'])
        for i in range(symbol['size'] // layout.size):
            offset = symbol['value'] + i*layout.size
            values = layout.unpack_from(data, offset)
            parent_symbol, parent_start = self.pointer(symbol['section'], offset + 16)
            ops, _ = self.pointer(symbol['section'], offset + 48)
            gate = values[10]
            records.append({'id': values[0], 'name': self.pointer_string(symbol['section'], offset+8),
                            'parents': [self.pointer_string(parent_symbol['section'], parent_start+j*8)
                                        for j in range(values[13])],
                            'flags': values[3], 'mux_ofs': values[4], 'set_ofs': values[5],
                            'clr_ofs': values[6], 'upd_ofs': values[7], 'mux_shift': values[8],
                            'mux_width': values[9], 'raw_gate_shift': gate, 'upd_shift': values[11],
                            'ops': ops['name'],
                            'gate': None if (original and gate < 0) or
                                   (not original and ops['name'] == 'mtk_mux_clr_set_upd_ops') else gate})
        return records


def main():
    paths = [ROOT / 'tools/kernel-build-config/some00/drivers/clk/mediatek/clk-mt6771.o',
             ROOT / 'tools/kernel-build-config/upgrade-5.10/drivers/clk/mediatek/clk-mt6771.o']
    original, upgraded = [Elf(path).muxes(i == 0) for i, path in enumerate(paths)]
    assert len(original) == len(upgraded) and len(original) > 20
    changes = []
    for before, after in zip(original, upgraded):
        for key in before:
            if key not in ['ops', 'raw_gate_shift']:
                assert before[key] == after[key], (before['id'], key, before[key], after[key])
        if before['gate'] is None:
            assert before['raw_gate_shift'] == -1 and after['raw_gate_shift'] == 0
            assert after['ops'] == 'mtk_mux_clr_set_upd_ops'
            changes.append({'id': before['id'], 'name': before['name'],
                            'before_ops': before['ops'], 'after_ops': after['ops'],
                            'reason': 'Preserve ungated behavior without unsigned -1 shift'})
        else:
            assert before['ops'] == after['ops'] and before['raw_gate_shift'] == after['raw_gate_shift']
    record = {'descriptors': len(original), 'all_ids_names_parents_flags_register_fields_match': True,
              'intentional_ungated_adaptations': changes, 'original': original, 'upgraded': upgraded,
              'inputs': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],
              'scope': 'Static compiled top-mux descriptors only; not runtime operations, PLL/gate-table coverage or hardware validation'}
    (ROOT / 'evidence/kernel-upgrade/clock-descriptor-comparison.json').write_text(json.dumps(record, indent=2) + '\n')
    print(len(original), 'compiled clock descriptors match; ungated adaptations:', len(changes))


if __name__ == '__main__':
    main()
