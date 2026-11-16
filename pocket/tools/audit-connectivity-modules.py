#!/usr/bin/env python3
"""Compare ARM64 Linux module imports/CRCs with a built kernel's symbol table.

Static ELF64 little-endian metadata only. No module is loaded or executed.
CRC/name agreement does not establish behavioral compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def module_metadata(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError(f'Expected little-endian ELF64 AArch64: {path}')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    if header[1] != 1:
        raise ValueError(f'Expected relocatable kernel module: {path}')
    offset, size, count, names_index = header[6], header[11], header[12], header[13]
    if size != 64 or not count or names_index >= count or offset + size * count > len(data):
        raise ValueError(f'Unsupported or invalid section table: {path}')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + size * i) for i in range(count)]

    def content(section):
        start, length = section[4:6]
        if start + length > len(data):
            raise ValueError('Section exceeds file')
        return data[start:start + length]

    def cstring(blob, start):
        end = blob.find(b'\0', start)
        if start >= len(blob) or end < 0:
            raise ValueError('Unterminated ELF string')
        return blob[start:end].decode('ascii')

    names = content(sections[names_index])
    by_name = {cstring(names, section[0]): section for section in sections}
    info = {}
    for item in content(by_name['.modinfo']).split(b'\0'):
        if b'=' in item:
            key, value = item.decode('utf-8').split('=', 1)
            info.setdefault(key, []).append(value)
    imports = []
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= count:
            raise ValueError('Invalid ELF64 symbol table')
        strings = content(sections[section[6]])
        for name, flags, _, index, _, _ in struct.iter_unpack('<IBBHQQ', content(section)):
            if index == 0 and name:
                imports.append({'name': cstring(strings, name), 'weak': flags >> 4 == 2})
    versions = {}
    if '__versions' in by_name:
        blob = content(by_name['__versions'])
        if len(blob) % 64:
            raise ValueError('Unsupported modversion_info layout')
        for start in range(0, len(blob), 64):
            crc = struct.unpack_from('<Q', blob, start)[0]
            name = cstring(blob[start + 8:start + 64], 0)
            if name in versions:
                raise ValueError('Duplicate module version entry')
            versions[name] = f'0x{crc:08x}'
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
            'bytes': len(data), 'modinfo': info, 'imports': sorted(imports, key=lambda x: x['name']),
            'versions': versions}


def compare(module, symbols):
    absent, mismatched, matched = [], [], []
    for name, expected in module['versions'].items():
        found = symbols.get(name)
        if found is None:
            absent.append(name)
        elif found['crc'] != expected:
            mismatched.append({'name': name, 'module_crc': expected, 'kernel_crc': found['crc']})
        else:
            matched.append(name)
    unresolved = [x['name'] for x in module['imports'] if not x['weak'] and x['name'] not in symbols]
    return {'matched_crc_count': len(matched), 'missing_version_symbols': sorted(absent),
            'crc_mismatches': sorted(mismatched, key=lambda x: x['name']),
            'unresolved_strong_imports': sorted(unresolved),
            'all_recorded_crcs_match': bool(module['versions']) and not absent and not mismatched,
            'all_strong_imports_available': not unresolved}


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', type=Path, default=root / 'firmware/analysis/rootfs/vendor/lib/modules')
    parser.add_argument('--build-dir', type=Path, default=root / 'tools/kernel-build-config/some00')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extra-module-dir', type=Path, action='append', default=[])
    args = parser.parse_args()
    symbol_file = args.build_dir / 'Module.symvers'
    symbols = {}
    for line in symbol_file.read_text().splitlines():
        crc, name, provider, export, *_ = line.split()
        if name in symbols:
            raise ValueError(f'Duplicate exported symbol: {name}')
        symbols[name] = {'crc': f'0x{int(crc, 16):08x}', 'provider': provider, 'export': export}
    stock, candidate = {}, {}
    selected = {'bt_drv.ko', 'gps_drv.ko', 'fmradio_drv.ko', 'wmt_drv.ko',
                'wmt_chrdev_wifi.ko', 'wlan_drv_gen3.ko'}
    directories = [(args.stock_dir, stock), (args.build_dir, candidate)]
    directories.extend((path, candidate) for path in args.extra_module_dir)
    for directory, target in directories:
        for path in sorted(directory.rglob('*.ko')):
            if path.name in selected:
                if path.name in target:
                    raise ValueError(f'Duplicate module basename: {path.name}')
                module = module_metadata(path)
                module['against_built_kernel'] = compare(module, symbols)
                target[path.name] = module
    result = {'symbol_table': str(symbol_file), 'symbol_table_sha256': hashlib.sha256(symbol_file.read_bytes()).hexdigest(),
              'stock': stock, 'candidate': candidate,
              'limitations': ['Static metadata comparison; no modules loaded',
                              'Provider availability includes modules that must be loaded in dependency order',
                              'CRC agreement is not a guarantee of compatible behavior or hardware operation',
                              'Vermagic, userspace ioctls, firmware and runtime behavior require separate checks']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    for group in ['stock', 'candidate']:
        for name, item in result[group].items():
            comparison = item['against_built_kernel']
            print(group, name, 'matched CRCs:', comparison['matched_crc_count'],
                  'mismatches:', len(comparison['crc_mismatches']),
                  'missing:', len(comparison['unresolved_strong_imports']))


if __name__ == '__main__':
    main()
