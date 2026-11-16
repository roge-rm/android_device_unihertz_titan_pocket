#!/usr/bin/env python3
"""Stage six rebuilt connectivity modules after verifying the saved ABI audit.

Creates a local compile checkpoint only. No install, boot image or flashing.
"""
import hashlib
import json
from pathlib import Path
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    audit_path = root / 'evidence/connectivity/integrated-abi.json'
    audit = json.loads(audit_path.read_text())
    if sha(Path(audit['symbol_table'])) != audit['symbol_table_sha256']:
        raise ValueError('Kernel symbol table changed; rerun module audit')
    ordered = ['wmt_drv.ko', 'wmt_chrdev_wifi.ko', 'wlan_drv_gen3.ko',
               'bt_drv.ko', 'gps_drv.ko', 'fmradio_drv.ko']
    staged = root / 'artifacts/connectivity'
    records, loaded, versions, pending = [], set(), set(), []
    for name in ordered:
        item = audit['candidate'][name]
        result = item['against_built_kernel']
        if not result['all_recorded_crcs_match'] or not result['all_strong_imports_available']:
            raise ValueError(f'Unresolved ABI audit: {name}')
        source = Path(item['path'])
        if not source.is_absolute():
            source = root / source
        if sha(source) != item['sha256']:
            raise ValueError(f'Module changed; rerun module audit: {name}')
        dependencies = {value for value in item['modinfo'].get('depends', [''])[0].split(',') if value}
        if not dependencies <= loaded:
            raise ValueError(f'Unstaged dependency: {name}: {dependencies - loaded}')
        versions.update(item['modinfo']['vermagic'])
        loaded.add(name.removesuffix('.ko'))
        target = staged / 'vendor/lib/modules' / name
        pending.append((source, target))
        records.append({'path': str(target.relative_to(staged)), 'bytes': source.stat().st_size,
                        'sha256': item['sha256'], 'depends': sorted(dependencies),
                        'requires_wmt_ready': name != 'wmt_drv.ko'})
    if len(versions) != 1:
        raise ValueError('Mixed vermagic in module set')
    for source, target in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    image = root / 'tools/kernel-build-config/some00/arch/arm64/boot/Image.gz'
    manifest = {'status': 'Compile checkpoint; no boot or hardware testing',
                'modules': records, 'vermagic': versions.pop(),
                'kernel_image': {'path': str(image), 'sha256': sha(image)},
                'source_lock_sha256': sha(root / 'connectivity-sources.json'),
                'source_stage_manifest_sha256': sha(root / 'evidence/connectivity/staged-sources.json'),
                'abi_audit_sha256': sha(audit_path),
                'loading': 'Load WMT first; retain stock wmt_loader/wmt_launcher and wait for vendor.connsys.driver.ready=yes. Wi-Fi character interface precedes WLAN.',
                'limitations': ['Not a flashable image or installation package',
                                'Userspace, firmware, SELinux, device-tree and runtime compatibility remain unverified']}
    temporary = staged / 'manifest.json.tmp'
    temporary.write_text(json.dumps(manifest, indent=2) + '\n')
    temporary.replace(staged / 'manifest.json')
    print(f'Staged {len(records)} verified modules: {staged / "manifest.json"}')


if __name__ == '__main__':
    main()
