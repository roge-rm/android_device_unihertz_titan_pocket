#!/usr/bin/env python3
"""Recover a candidate Pocket keyboard matrix from a decompressed stock Image.

Uses the reference KEY_STATE layout: 12 bytes of name/padding, then four
little-endian 32-bit integers (code, state, row, column), stride 28.
The record layout is inferred; this does not observe live scan codes.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def recover(data):
    def entry(offset):
        if offset < 0 or offset + 28 > len(data):
            return None
        raw = data[offset:offset + 12]
        name, separator, padding = raw.partition(b'\0')
        if not separator or any(padding) or not re.fullmatch(rb'[A-Z0-9_-]{1,9}', name):
            return None
        code, state, row, column = struct.unpack_from('<4i', data, offset + 12)
        if not (0 < code < 768 and state == 0 and 0 <= row < 8 and 0 <= column < 8):
            return None
        return {'name': name.decode(), 'code': code, 'row': row, 'column': column,
                'file_offset': offset}

    candidates = {}
    for anchor in re.finditer(rb'SPACE\x00', data):
        current = entry(anchor.start())
        if not current or current['code'] != 57:
            continue
        start = anchor.start()
        while entry(start - 28):
            start -= 28
        rows = []
        offset = start
        while (current := entry(offset)) is not None:
            rows.append(current)
            offset += 28
        letters = {r['name'] for r in rows if len(r['name']) == 1}
        positions = {(r['row'], r['column']) for r in rows}
        if len(rows) == 35 and len(positions) == 35 and set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') <= letters:
            candidates[start] = rows
    if len(candidates) != 1:
        raise ValueError(f'Expected one 35-key matrix; found {len(candidates)}')
    return next(iter(candidates.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    offset, rows = recover(data)
    table = data[offset:offset + len(rows) * 28]
    result = {'image': str(args.image), 'image_sha256': hashlib.sha256(data).hexdigest(),
              'offset': offset, 'stride': 28, 'bytes': len(table),
              'table_sha256': hashlib.sha256(table).hexdigest(), 'rows': rows,
              'limitations': ['Record layout inferred from a reference structure and contiguous byte consistency',
                              'No runtime driver binding or physical key event observations']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Recovered {len(rows)} entries at Image offset {offset:#x}')


if __name__ == '__main__':
    main()
