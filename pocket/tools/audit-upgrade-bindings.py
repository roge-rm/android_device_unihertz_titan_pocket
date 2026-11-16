#!/usr/bin/env python3
"""Index exact C compatible declarations for the captured live Pocket tree.

Source declarations are leads, not proof a driver builds, binds or implements
the hardware. Macro-generated/nonliteral declarations can escape this index.
"""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'tools/kernel-source/upgrade-5.10'
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*', re.S)
MATCH = re.compile(r'\.(?:of_)?compatible\s*=\s*"([^"\n]+)"|\b\w*(?:OF_DECLARE|CHIP_DECLARE)(?:_DRIVER)?\s*\(\s*[^,]+,\s*"([^"\n]+)"')


def main():
    source = ROOT / 'evidence/device/20261029T000648.917229Z/live-device-tree.json'
    nodes = json.loads(source.read_text())['nodes']
    wanted = {s for value in nodes.values() for s in value.get('compatible', {}).get('strings', [])}
    index = {}
    file_count = 0
    for top in ['drivers', 'arch/arm64']:
        for path in (SOURCE / top).rglob('*'):
            if not path.is_file() or path.is_symlink() or path.suffix not in ['.c', '.h']:
                continue
            file_count += 1
            text = path.read_text(errors='replace')
            # Preserve C string literals while dropping comments.
            clean = TOKEN.sub(lambda m: m[0] if m[0].startswith('"') else ' ' * len(m[0]), text)
            for match in MATCH.finditer(clean):
                compatible = match[1] or match[2]
                if compatible in wanted:
                    index.setdefault(compatible, []).append({'path': str(path.relative_to(SOURCE)),
                        'line': clean[:match.start()].count('\n') + 1,
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

    def available(path):
        while True:
            if nodes.get(path, {}).get('status', {}).get('strings', ['okay'])[0] not in ['ok', 'okay']:
                return False
            if path == '/':
                return True
            path = path.rpartition('/')[0] or '/'

    rows = []
    critical = re.compile(r'psci|interrupt-controller|timer$|sysirq|topckgen|infracfg|scpsys|gpio@|pinctrl$|apmixed|pwrap@|ufshci@|serial@|uart@|m4u@')
    for path, value in nodes.items():
        compatibles = value.get('compatible', {}).get('strings', [])
        if not compatibles:
            continue
        rows.append({'node': path, 'compatible': compatibles, 'effective_dt_available': available(path),
                     'boot_foundation_lead': bool(critical.search(path)),
                     'declarations': {s: index.get(s, []) for s in compatibles},
                     'exact_declaration_found': any(s in index for s in compatibles)})
    result = {'source': str(SOURCE), 'source_files_scanned': file_count,
              'live_tree': str(source), 'nodes': rows,
              'limits': ['C literal declarations only, comments removed; not a preprocessed/configuration-aware index',
                         'No exact match does not rule out reusable hardware logic under another binding',
                         'Presence does not prove pin/clock/IRQ/MMIO/API compatibility or runtime binding']}
    output = ROOT / 'evidence/kernel-upgrade/live-binding-coverage.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    foundation = [r for r in rows if r['boot_foundation_lead'] and r['effective_dt_available']]
    print('Scanned', file_count, 'source files;', len(foundation), 'available boot-foundation leads')
    for row in foundation:
        print('declaration' if row['exact_declaration_found'] else 'review binding/provider', row['node'], ','.join(row['compatible']))


if __name__ == '__main__':
    main()
