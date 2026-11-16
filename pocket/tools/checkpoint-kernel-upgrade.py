#!/usr/bin/env python3
"""Record and link the verified isolated 5.10 object-build checkpoint."""
import pocket_paths
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    evidence = root / 'evidence/kernel-upgrade'
    output = root / 'tools/kernel-build-config/upgrade-5.10'
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    config_hash = digest(output / '.config')
    builds = []
    objects = []
    foundation = []
    for target in ('bootbase', 'android-core', 'pmic', 'ufs-phy', 'usb', 'pstore'):
        path = sorted(evidence.glob('*-' + target + '.json'))[-1]
        record = json.loads(path.read_text())
        assert record['returncode'] == 0, path
        assert record['config_sha256'] == config_hash, 'Rebuild with the current configuration'
        assert record['fragment_sha256'] == digest(root / 'configs/kernel-upgrade-5.10.fragment')
        builds.append({'record': str(path.relative_to(root)), 'sha256': digest(path)})
        paths = [arg for arg in record['commands'][0]['command'] if arg.endswith('.o')]
        for name in paths:
            obj = output / name
            objects.append({'path': str(obj.relative_to(root)), 'sha256': digest(obj)})
            if name.startswith(('drivers/pinctrl/', 'drivers/clk/')):
                foundation.append(obj)
    assert len(objects) == 37 and len(foundation) == 10
    llvm = pocket_paths.ndk_bin()
    linked = root / 'artifacts/kernel-upgrade/mt6771-foundation.o'
    subprocess.run([str(llvm / 'ld.lld'), '-r', '-o', str(linked), *map(str, foundation)], check=True)
    undefined = subprocess.run([str(llvm / 'llvm-nm'), '-u', str(linked)], check=True,
                               capture_output=True, text=True).stdout
    (evidence / 'foundation-undefined-symbols.txt').write_text(undefined)
    assert not any(line.split()[-1].startswith('mtk_') for line in undefined.splitlines())
    link = {'objects': objects[:10], 'linked_object': str(linked.relative_to(root)),
            'sha256': digest(linked), 'undefined_symbol_count': len(undefined.splitlines()),
            'scope': 'Relocatable link only; generic kernel imports remain; not vmlinux or a module'}
    (evidence / 'foundation-link.json').write_text(json.dumps(link, indent=2) + '\n')
    record = {'recorded_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'linked_engineering_kernel_image_not_device_qualified',
              'kernel_reference': '5.10.257',
              'reference_commit': '9708121d5855e50a16df8787228d1edd6ed6f99c',
              'config_sha256': config_hash, 'builds': builds, 'objects': objects,
              'foundation_link': link,
              'patches': [{'path': str(p.relative_to(root)), 'sha256': digest(p)}
                          for p in sorted((root / 'patches/kernel-upgrade-5.10').glob('*.patch'))],
              'phone_accessed': False, 'shared_source_modified': False,
              'limitations': ['Full Image/vmlinux link only; no Android boot image or coherent Pocket board DT',
                              'No target execution or hardware validation',
                              'PMIC cold-init, power domains, UFS host, graphics, TEE and other board drivers remain',
                              'USB code compiles but enumeration, signal integrity and role switching remain untested',
                              'Android configuration is a probe, not product conformance']}
    image_record = sorted(evidence.glob('*-image.json'))[-1]
    image_build = json.loads(image_record.read_text())
    assert image_build['returncode'] == 0 and image_build['config_sha256'] == config_hash
    assert not image_build['forward_port_source_changed_during_build']
    for name, expected in image_build['forward_port_source_sha256'].items():
        assert digest(root / 'tools/kernel-source/upgrade-5.10' / name) == expected, name
    record['image_build'] = {'record': str(image_record.relative_to(root)), 'sha256': digest(image_record)}
    record['linked_files'] = [{'path': str(p.relative_to(root)), 'bytes': p.stat().st_size, 'sha256': digest(p)}
                              for p in (output / 'vmlinux', output / 'arch/arm64/boot/Image', output / 'System.map')]
    record['isolated_compile_probes'] = []
    for target, relative in [('ufs-fw', 'drivers/scsi/ufs/ufs-mediatek.o'),
                             ('ufs-clock', 'drivers/clk/mediatek/clk-mt6358-ufs.o')]:
        probes = sorted(evidence.glob('*-' + target + '.json'))
        if not probes:
            continue
        probe_path = probes[-1]
        probe = json.loads(probe_path.read_text())
        assert probe['returncode'] == 0 and probe['engineering_config_unchanged']
        assert probe['baseline_engineering_config_sha256'] == config_hash
        for name, expected in probe['forward_port_source_sha256'].items():
            assert digest(root / 'tools/kernel-source/upgrade-5.10' / name) == expected, name
        obj = Path(probe['output']) / relative
        record['isolated_compile_probes'].append({
            'record': str(probe_path.relative_to(root)), 'sha256': digest(probe_path),
            'object': str(obj.relative_to(root)), 'object_sha256': digest(obj),
            'enabled_in_engineering_image': False,
            'scope': 'Separate-config component compile only; not part of the 37-object engineering qualification set'})
    destination = evidence / 'prototype-checkpoint.json'
    destination.write_text(json.dumps(record, indent=2) + '\n')
    print(f'Recorded {len(objects)} compiled objects and {len(foundation)}-object relocatable link: {destination}')


if __name__ == '__main__':
    main()
