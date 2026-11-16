#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate retained split contexts against an all-checks policy reconstruction.

Build upstream context validators against the same modern libsepol as secilc.
Nothing is written to the source checkout, product output or connected device.
"""
import pocket_paths
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SOURCE = pocket_paths.platform_source()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compile-record', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.compile_record.read_text())
    if record['returncode'] or record['assertion_failures'] or record['neverallow_disabled']:
        raise ValueError('An all-checks successful compilation is required')
    for name, expected in record['combined_input_hashes'].items():
        if digest(Path(name)) != expected:
            raise ValueError('Compilation input changed: ' + name)
    policy = args.compile_record.parent / 'policy'
    if digest(policy) != record['binary']['sha256']:
        raise ValueError('Compiled policy binary changed')
    if args.output.exists():
        raise ValueError('Output already exists; preserve previous evidence')
    args.output.mkdir(parents=True)
    library = ROOT / 'tools/selinux-host-source/libsepol/src/libsepol.a'
    headers = ROOT / 'tools/selinux-host-source/libsepol/include'
    compiler = Path(shutil.which('cc')).resolve()
    hashes = {str(compiler): digest(compiler), str(library): digest(library),
              str(args.compile_record.resolve()): digest(args.compile_record),
              str(policy.resolve()): digest(policy)}
    hashes.update({str(path): digest(path) for path in headers.rglob('*.h')})
    builds, tests = [], []
    for binary, source, flags, libs in [
        ('checkfc', 'checkfc.c', [], ['-lselinux']),
        ('checkseapp', 'check_seapp.c', ['-DLINK_SEPOL_STATIC', '-DPCRE2_CODE_UNIT_WIDTH=8'], ['-lpcre2-8'])]:
        src = SOURCE / 'system/sepolicy/tools' / source
        output = args.output / binary
        backend_sources = []
        if binary == 'checkfc':
            selinux = SOURCE / 'external/selinux/libselinux'
            flags += ['-DBUILD_HOST', '-DUSE_PCRE2', '-DPCRE2_CODE_UNIT_WIDTH=8', '-D_GNU_SOURCE',
                      '-DNO_MEDIA_BACKEND', '-DNO_X_BACKEND', '-DNO_DB_BACKEND',
                      '-DNO_PERSISTENTLY_STORED_PATTERNS', '-I' + str(selinux / 'include'),
                      '-I' + str(selinux / 'src')]
            backend_sources = [selinux / 'src' / name for name in [
                'label.c', 'label_backends_android.c', 'label_support.c', 'callbacks.c',
                'label_file.c', 'regex.c', 'sha1.c', 'matchpathcon.c', 'hashtab.c']]
            hashes.update({str(path): digest(path) for path in backend_sources})
            hashes.update({str(path): digest(path) for directory in ['include', 'src']
                           for path in (selinux / directory).rglob('*.h')})
            libs += ['-lpcre2-8']
        command = [str(compiler), '-O2', '-Wall', '-Werror', '-I' + str(headers)] + flags + [
            '-o', str(output), str(src)] + list(map(str, backend_sources)) + [str(library)] + libs
        completed = subprocess.run(command, capture_output=True, text=True)
        builds.append(dict(command=command, returncode=completed.returncode,
                           output=completed.stdout + completed.stderr))
        if completed.returncode:
            raise RuntimeError('Context validator build failed: ' + completed.stderr)
        hashes[str(src)] = digest(src)
        hashes[str(output.resolve())] = digest(output)

    def run(command, context=None, expected_success=True, name=None):
        if context:
            hashes[str(context.resolve())] = digest(context)
        completed = subprocess.run(list(map(str, command)), capture_output=True, text=True)
        text = completed.stdout + completed.stderr
        tests.append(dict(name=name or context.name, command=list(map(str, command)),
                          returncode=completed.returncode, output=text,
                          expected_success=expected_success,
                          passed=(completed.returncode == 0) == expected_success))

    stock = ROOT / 'firmware/installed-20230105/rootfs'
    install = args.compile_record.parent / 'install'
    if install.exists():
        for name, expected in record['install_shaped_files'].items():
            if digest(install / name) != expected:
                raise ValueError('Install-shaped composition changed: ' + name)
    vendor_contexts = (install / 'vendor/etc/selinux' if install.exists() else stock / 'vendor/etc/selinux')
    extension_contexts = (install / 'system_ext/etc/selinux' if install.exists() else stock / 'system/system/system_ext/etc/selinux')
    for base, prefix, vendor in [(vendor_contexts, 'vendor', True),
                                 (extension_contexts, 'system_ext', False)]:
        for suffix, flag in [('file_contexts', None), ('property_contexts', '-p'),
                             ('service_contexts', '-s'), ('hwservice_contexts', '-l')]:
            context = base / (prefix + '_' + suffix)
            run([args.output / 'checkfc', '-e'] + ([flag] if flag else []) + [policy, context], context)
        context = base / (prefix + '_seapp_contexts')
        run([args.output / 'checkseapp', '-p', policy] + (['-c'] if vendor else []) + [context], context)
        mac = base / (prefix + '_mac_permissions.xml')
        ET.parse(mac)
        hashes[str(mac.resolve())] = digest(mac)
    context = vendor_contexts / 'vndservice_contexts'
    run([args.output / 'checkfc', '-e', '-v', policy, context], context)
    context = pocket_paths.DEVICE_TREE / 'sepolicy/system_ext/private/service_contexts'
    run([args.output / 'checkfc', '-s', policy, context], context)
    for name, content in [('positive-service', 'mtkIms u:object_r:radio_service:s0\n'),
                          ('unknown-type', 'invalid u:object_r:pocket_missing_type:s0\n'),
                          ('wrong-type-role', 'invalid u:object_r:system_file:s0\n')]:
        context = args.output / name
        context.write_text(content)
        run([args.output / 'checkfc', '-s', policy, context], context,
            expected_success=name == 'positive-service', name=name)
    result = dict(schema=1, tool_sha256=digest(Path(__file__)), input_hashes=hashes,
                  builds=builds, tests=tests, all_checks_passed=all(test['passed'] for test in tests),
                  device_accessed=False, firmware_executed=False,
                  scope='Retained vendor/system_ext plus original IMS service context; compiled type/role and syntax checks',
                  limits=['Does not prove full packaged modern context merge or file-label collision priority',
                          'MAC XML parse is not signing/permission or package identity qualification',
                          'Does not qualify live labels, service execution or hardware behavior'])
    (args.output / 'record.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Context checks:', sum(test['passed'] for test in tests), '/', len(tests))
    for test in tests:
        if not test['passed']:
            print(test['name'], test['output'][:1600])
    raise SystemExit(0 if result['all_checks_passed'] else 1)


if __name__ == '__main__':
    main()
