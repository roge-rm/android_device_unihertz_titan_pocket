#!/usr/bin/env python3
"""Preserve the unqualified linked Image with header/symbol/hash checks."""
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct

ROOT = Path(__file__).resolve().parent.parent


def main():
    output = ROOT / 'tools/kernel-build-config/upgrade-5.10'
    destination = ROOT / 'artifacts/kernel-upgrade/linked-image'
    destination.mkdir(parents=True, exist_ok=True)
    build_path = sorted((ROOT / 'evidence/kernel-upgrade').glob('*-image.json'))[-1]
    build = json.loads(build_path.read_text())
    assert build['returncode'] == 0 and not build['forward_port_source_changed_during_build']
    assert hashlib.sha256((output / '.config').read_bytes()).hexdigest() == build['config_sha256']
    for name, digest in build['forward_port_source_sha256'].items():
        assert hashlib.sha256((ROOT / 'tools/kernel-source/upgrade-5.10' / name).read_bytes()).hexdigest() == digest
    image = output / 'arch/arm64/boot/Image'
    data = image.read_bytes()
    assert data[56:60] == b'ARM\x64'
    symbols = {line.split()[-1] for line in (output / 'System.map').read_text().splitlines()}
    required = ['mt6771_pinctrl_probe', 'pwrap_mt6771_validate_handoff', 'mt6771_ufs_phy_data',
                'mtk_infracfg_ao_init', 'usb_mtkphy_io_read', 'mtu3_probe', 'mtk_usb_phy_probe',
                'ramoops_probe', 'persistent_ram_new']
    assert all(name in symbols for name in required)
    for source, name in [(image, 'Image'), (output / '.config', 'config'), (output / 'System.map', 'System.map')]:
        shutil.copyfile(source, destination / name)
    with (destination / 'Image.gz').open('wb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
            compressed.write(data)
    record = {'status': 'linked_engineering_image_not_device_boot_qualified',
              'build_record': str(build_path.relative_to(ROOT)),
              'arm64_header': {'magic': 'ARM64', 'text_offset': struct.unpack_from('<Q', data, 8)[0],
                               'image_size': struct.unpack_from('<Q', data, 16)[0]},
              'files': [{'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
                         'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(destination.iterdir())],
              'required_symbols_present': required, 'boot_image_packaged': False,
              'limits': ['No bootloader, board DT, Android ramdisk or AVB compatibility validation',
                         'Not an installable Android boot image; no target execution']}
    (ROOT / 'evidence/kernel-upgrade/linked-image-validation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Image preserved: {len(data)} raw bytes, {(destination / "Image.gz").stat().st_size} gzip bytes; not device qualified')


if __name__ == '__main__':
    main()
