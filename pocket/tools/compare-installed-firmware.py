#!/usr/bin/env python3
"""Compare extracted Pocket file payloads, declared contracts and ZIP members.

Uses extraction manifests as hash inventories. It does not infer behavioral
equivalence from filenames, VINTF declarations, or matching ioctl numbers.
"""
import collections
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parent.parent
    evidence = root / 'evidence/installed-20230105'
    installed = root / 'firmware/installed-20230105/rootfs'
    factory = root / 'firmware/analysis/rootfs'
    def load(path):
        return json.loads(path.read_text())
    def save(name, value):
        (evidence / name).write_text(json.dumps(value, indent=2) + '\n')
    a = {x['path']: x for x in load(root / 'evidence/firmware/rootfs-manifest.json')}
    b = {x['path']: x for x in load(evidence / 'rootfs-manifest.json')}
    same, changed, added, removed = [], [], [], []
    for name in sorted(a.keys() | b.keys()):
        if name not in a:
            added.append(name)
        elif name not in b:
            removed.append(name)
        else:
            x, y = a[name], b[name]
            field = 'sha256' if x['kind'] == 'file' else 'target'
            equal = x['kind'] == y['kind'] and x.get(field) == y.get(field)
            (same if equal else changed).append(name)
    report = {'baseline': 'January 2023 installed backup', 'comparison': 'May 2024 factory extraction',
              'same': same, 'changed': [{'path': n, 'installed': b[n], 'factory': a[n]} for n in changed],
              'added': added, 'removed': removed,
              'counts': {'same': len(same), 'changed': len(changed), 'added': len(added), 'removed': len(removed)},
              'by_partition': {p: {kind: sum(n.startswith(p + '/') for n in names)
                                     for kind, names in [('same', same), ('changed', changed), ('added', added), ('removed', removed)]}
                               for p in ['system', 'vendor', 'product']},
              'changed_suffix_counts': dict(collections.Counter(Path(x).suffix for x in changed)),
              'limitations': ['File payloads and symlink targets only; original images retain ext4/AVB metadata']}
    save('factory-file-comparison.json', report)
    selectors = {
        'vintf': lambda p: '/etc/vintf/' in p,
        'selinux': lambda p: '/etc/selinux/' in p,
        'vendor_firmware': lambda p: p.startswith('vendor/firmware/'),
        'vendor_native_hal': lambda p: (p.startswith('vendor/lib/hw/') or p.startswith('vendor/lib64/hw/')) and p.endswith('.so'),
        'trustlets': lambda p: p.startswith('vendor/app/t6/') and p.endswith('.ta'),
        'oem_input': lambda p: any(n in p for n in ['AguiSpaceBarKey', 'AguiNavControl', 'AguiKeyBoardShortcut', 'AguiShortcutKey']) and p.endswith('.apk'),
        'framework_jars': lambda p: p in { 'system/system/framework/' + n for n in ['framework.jar', 'services.jar', 'mediatek-framework.jar', 'mediatek-telephony-common.jar']},
        'ims_apk': lambda p: '/ImsService/' in p and p.endswith('.apk'),
    }
    groups = {}
    for kind, selector in selectors.items():
        rows = []
        for name, item in b.items():
            if item['kind'] == 'file' and selector(name):
                digest = a.get(name, {}).get('sha256')
                rows.append({'path': name, 'installed_sha256': item['sha256'],
                             'factory_sha256': digest, 'identical': digest == item['sha256']})
        groups[kind] = {'count': len(rows), 'identical': sum(x['identical'] for x in rows),
                        'changed': [x['path'] for x in rows if not x['identical']], 'files': rows}
    save('contract-file-groups.json', groups)
    archives = []
    for name in changed:
        if not name.endswith('.jar') and not (name.endswith('.apk') and selectors['oem_input'](name)):
            continue
        with zipfile.ZipFile(installed / name) as current, zipfile.ZipFile(factory / name) as previous:
            ca, pa = set(current.namelist()), set(previous.namelist())
            equal, different = [], []
            for member in sorted(ca & pa):
                if current.getinfo(member).is_dir():
                    continue
                matches = hashlib.sha256(current.read(member)).digest() == hashlib.sha256(previous.read(member)).digest()
                (equal if matches else different).append(member)
            dex = [x for x in ca | pa if x.startswith('classes') and x.endswith('.dex')]
            archives.append({'path': name, 'same_member_count': len(equal), 'changed_members': different,
                             'added_members': sorted(ca - pa), 'removed_members': sorted(pa - ca),
                             'dex_members_identical': bool(dex) and all(x in equal for x in dex),
                             'limitations': ['A changed signature container does not establish a changed signing certificate',
                                             'DEX identity does not establish resource, privilege or target-framework compatibility']})
    save('framework-input-archive-comparison.json', archives)
    print('Compared payloads:', report['counts'])
    print('Contract groups:', {k: f'{v["identical"]}/{v["count"]} identical' for k, v in groups.items()})


if __name__ == '__main__':
    main()
