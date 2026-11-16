#!/usr/bin/env python3
"""Decode the first embedded flattened device tree into JSON for offline audit.

Does not apply overlays or infer hardware behavior. Hex cells remain raw values;
phandles and GPIO encodings require the relevant provider bindings to interpret.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


def decode(data):
    offset = data.find(b'\xd0\x0d\xfe\xed')
    if offset < 0:
        raise ValueError('No embedded FDT magic')
    blob = data[offset:]
    _, total, structure, strings, _, version, _, _, string_size, struct_size = struct.unpack_from('>10I', blob)
    if total > len(blob) or strings + string_size > total or structure + struct_size > total:
        raise ValueError('FDT ranges exceed input')
    names = blob[strings:strings + string_size]
    cursor = structure
    stack = []
    nodes = {}
    while cursor < structure + struct_size:
        token, = struct.unpack_from('>I', blob, cursor)
        cursor += 4
        if token == 1:
            end = blob.index(0, cursor)
            stack.append(blob[cursor:end].decode())
            cursor = (end + 4) & ~3
            nodes['/'.join(stack) or '/'] = {}
        elif token == 2:
            stack.pop()
        elif token == 3:
            size, name_offset = struct.unpack_from('>II', blob, cursor)
            cursor += 8
            if cursor + size > structure + struct_size:
                raise ValueError('FDT property exceeds structure')
            value = blob[cursor:cursor + size]
            cursor = (cursor + size + 3) & ~3
            end = names.index(0, name_offset)
            name = names[name_offset:end].decode()
            decoded = {'hex': value.hex()}
            if len(value) % 4 == 0:
                decoded['cells'] = list(struct.unpack('>' + 'I' * (len(value) // 4), value))
            if value and 32 <= value[0] < 127 and value[-1] == 0 and all(x == 0 or 32 <= x < 127 for x in value):
                decoded['strings'] = value.rstrip(b'\0').decode().split('\0')
            nodes['/'.join(stack) or '/'][name] = decoded
        elif token == 4:
            continue
        elif token == 9:
            if stack:
                raise ValueError('Unbalanced FDT nodes')
            return {'offset': offset, 'bytes': total, 'version': version, 'nodes': nodes}
        else:
            raise ValueError(f'Unknown FDT token {token}')
    raise ValueError('FDT end token missing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    result = {'input': str(args.image), 'input_sha256': hashlib.sha256(data).hexdigest(), **decode(data)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Decoded {len(result["nodes"])} nodes at offset {result["offset"]}')


if __name__ == '__main__':
    main()
