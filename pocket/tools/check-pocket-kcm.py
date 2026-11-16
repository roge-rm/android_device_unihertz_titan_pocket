#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks the Pocket keyboard character maps resolve to the behaviour in configs/keyboard-kcm-expected.json.

  check-pocket-kcm.py                     check the two device files
  check-pocket-kcm.py --write-expected F  write the resolved table of kcm file F as the expected one
  check-pocket-kcm.py --overlap STOCK     also print how much of the device map is the same text as STOCK

The base map (rootdir/usr/keychars/aw9523-key.kcm, type ALPHA) is the source. The layout overlay
(keyboard-layout/res/raw/aw9523_key.kcm, type OVERLAY) must have the same keys. A key's lines
resolve in order, with the lines of one `a, b: x` list treated as a set, and `label` kept apart.
"""
import argparse
import json
import sys

import pocket_paths

ROOT = pocket_paths.ROOT
EXPECTED = ROOT / 'configs/keyboard-kcm-expected.json'
BASE = pocket_paths.DEVICE_TREE / 'rootdir/usr/keychars/aw9523-key.kcm'
OVERLAY = pocket_paths.DEVICE_TREE / 'keyboard-layout/res/raw/aw9523_key.kcm'


def strip_comment(line):
    quoted = False
    for i, c in enumerate(line):
        if c == "'" and (i == 0 or line[i - 1] != '\\'):
            quoted = not quoted
        elif c == '#' and not quoted:
            return line[:i]
    return line


def value(text):
    text = text.strip()
    if text == 'none':
        return None
    assert text[0] == text[-1] == "'", text
    body, out, i = text[1:-1], '', 0
    while i < len(body):
        if body[i] == '\\':
            n = body[i + 1]
            if n == 'u':
                out += chr(int(body[i + 2:i + 6], 16))
                i += 6
                continue
            out += {'n': '\n', 't': '\t', '\\': '\\', "'": "'", '"': '"'}[n]
            i += 2
        else:
            out += body[i]
            i += 1
    assert len(out) == 1, text
    return out


def parse(path):
    """{'type': str, 'keys': {name: {'label': char|None, 'rules': [[sorted modifier sets], char|None]}}}"""
    result = {'type': None, 'keys': {}}
    current = None
    for number, raw in enumerate(path.read_text().split('\n'), 1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith('type '):
            assert result['type'] is None, f'{path}:{number}: second type'
            result['type'] = line.split()[1]
        elif line.startswith('key ') and line.endswith('{'):
            name = line[4:-1].strip()
            assert current is None and name not in result['keys'], f'{path}:{number}: {name}'
            current = result['keys'][name] = {'label': None, 'rules': []}
        elif line == '}':
            assert current is not None, f'{path}:{number}'
            current = None
        else:
            assert current is not None, f'{path}:{number}: {line}'
            props, val = line.split(':', 1)
            props = sorted(p.strip() for p in props.split(','))
            if props == ['label']:
                current['label'] = value(val)
            else:
                current['rules'].append([props, value(val)])
    assert current is None, f'{path}: unterminated key'
    return result


def resolved(parsed):
    keys = {k: {'label': v['label'], 'rules': v['rules']} for k, v in sorted(parsed['keys'].items())}
    return json.loads(json.dumps(keys))


def overlap(path, stock_path):
    """(lines of path that also appear in stock, lines counted, longest run of identical consecutive lines)"""
    def lines(p):
        out = []
        for raw in p.read_text().split('\n'):
            s = ' '.join(raw.split())
            if s and s not in ('{', '}') and not s.startswith('#'):
                out.append(s)
        return out
    a, b = lines(path), lines(stock_path)
    same = sum(1 for x in a if x in set(b))
    best = 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0] * (len(b) + 1)
        for j, y in enumerate(b, 1):
            if x == y:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
    return same, len(a), best


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--write-expected', type=__import__('pathlib').Path)
    ap.add_argument('--overlap', type=__import__('pathlib').Path, help='stock aw9523-key.kcm')
    args = ap.parse_args()
    if args.write_expected:
        EXPECTED.write_text(json.dumps({'schema': 1, 'keys': resolved(parse(args.write_expected))}, indent=1, sort_keys=True) + '\n')
        print(f'wrote {EXPECTED.relative_to(ROOT)}')
        return 0
    expected = json.loads(EXPECTED.read_text())['keys']
    base, overlay = parse(BASE), parse(OVERLAY)
    assert base['type'] == 'ALPHA', f'base type is {base["type"]}'
    assert overlay['type'] == 'OVERLAY', f'overlay type is {overlay["type"]}'
    for name, p in (('base', base), ('overlay', overlay)):
        got = resolved(p)
        assert sorted(got) == sorted(expected), f'{name}: keys differ: {sorted(set(got) ^ set(expected))}'
        for k in expected:
            assert got[k] == expected[k], f'{name}: key {k} resolves differently: {got[k]} != {expected[k]}'
    assert resolved(base) == resolved(overlay)
    print(f'keyboard maps: {len(expected)} keys resolve as expected in both files')
    if args.overlap:
        for p in (BASE, OVERLAY):
            same, total, run = overlap(p, args.overlap)
            print(f'{p.name}: {same}/{total} lines also in stock ({100 * same / total:.1f}%), longest identical run {run}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
