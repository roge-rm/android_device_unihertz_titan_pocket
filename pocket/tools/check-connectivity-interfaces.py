#!/usr/bin/env python3
"""Check compiled FM ioctl encoding and selected MT6771 GPS branches offline.

Reuses the exact locally generated Kbuild compiler commands. Builds only an
ARM64 data probe and preprocesses source; it does not load modules or use a phone.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    stage = root / 'tools/kernel-build-config/connectivity'
    kernel = root / 'tools/kernel-build-config/some00'
    evidence = root / 'evidence/connectivity'
    evidence.mkdir(parents=True, exist_ok=True)
    clang = Path.home() / 'Android/Sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
    env = os.environ.copy()
    env['PATH'] = f'{root}/tools/build-deps/usr/bin:{clang}:' + env.get('PATH', '')
    env['LD_LIBRARY_PATH'] = f'{root}/tools/build-deps/usr/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')

    def command(path):
        first = path.read_text().splitlines()[0].split(' := ', 1)[1]
        args = shlex.split(first)
        if not args[-1].endswith('.c') or ';' in args or '-c' not in args:
            raise ValueError('Expected one Kbuild C compilation command')
        if Path(args[0]).resolve() != (clang / 'clang').resolve():
            raise ValueError('Unexpected compiler in generated command')
        return args

    def run(args, log):
        result = subprocess.run(args, cwd=kernel, env=env, capture_output=True, text=True)
        log.write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'Compiler check failed; see {log}')

    header = (stage / 'fmradio/inc/fm_ioctl.h').read_text()
    names = re.findall(r'^#define\s+(FM_IOCTL_[A-Z0-9_]+)\s+_IO\w*\(', header, re.M)
    if not names or len(names) != len(set(names)):
        raise ValueError('Expected unique FM ioctl definitions')
    probe = evidence / 'fm-request-probe.c'
    probe.write_text('#include "' + str(stage / 'fmradio/core/fm_module.c') + '"\n'
                     'const unsigned int titan_fm_requests[] '
                     '__attribute__((section(".titan_fm_requests"), used)) = {\n' +
                     ',\n'.join(names) + '\n};\n')
    args = command(stage / 'fmradio/core/.fm_module.o.cmd')
    obj = evidence / 'fm-request-probe.o'
    args[args.index('-o') + 1] = str(obj)
    args[-1] = str(probe)
    run(args, evidence / 'fm-request-probe.log')
    raw = evidence / 'fm-request-values.bin'
    subprocess.run([str(clang / 'llvm-objcopy'), '--dump-section',
                    f'.titan_fm_requests={raw}', str(obj)], check=True)
    values = struct.unpack('<' + 'I' * len(names), raw.read_bytes())
    requests = [{'name': name, 'request_arm64': f'0x{value:08x}'}
                for name, value in zip(names, values)]
    (evidence / 'fm-compiled-requests.json').write_text(json.dumps({
        'method': 'AArch64 data probe with actual module flags/headers; ELF section dump',
        'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
        'requests': requests,
        'limitations': ['Encoding only; not every payload layout or operation verified']}, indent=2) + '\n')
    stock_pseudocode = evidence / 'stock-fm-ioctl.pseudo.c'
    if stock_pseudocode.exists():
        stock_text = stock_pseudocode.read_text()
        stock_requests = set()
        # Ghidra lists holes in the jump table as case labels leading to default.
        pattern = r'((?:  case -?0x[0-9a-f]+:\n)+)(.*?)(?=\n  (?:case |default:)|\Z)'
        for match in re.finditer(pattern, stock_text, re.S):
            if match[2].lstrip().startswith('goto switchD_00107488_caseD_c008f503;'):
                continue
            stock_requests.update(int(value, 16) & 0xffffffff for value in
                                  re.findall(r'case (-?0x[0-9a-f]+):', match[1]))
        stock_requests.update(int(value, 16) & 0xffffffff for value in
                              re.findall(r'param_2 == (-?0x[0-9a-f]+)', stock_text))
        # Verified branch: != RESTORE_SEARCH jumps to default; fallthrough calls fm_restore_search.
        if 'if (param_2 != -0x3ffb0ad2) goto switchD_00107488_caseD_c008f503;' not in stock_text:
            raise ValueError('Stock FM restore-search branch changed; re-audit required')
        stock_requests.add((-0x3ffb0ad2) & 0xffffffff)
        handlers = set(re.findall(r'case (FM_IOCTL_[A-Z0-9_]+)\s*:',
                                 (stage / 'fmradio/core/fm_module.c').read_text()))
        candidate = {int(item['request_arm64'], 16): item['name']
                     for item in requests if item['name'] in handlers}
        (evidence / 'fm-request-comparison.json').write_text(json.dumps({
            'stock_evidence_id': 'ev_5108e187a232e940ba3e0ba3c5d92b44e2ea8112ce345b64963897f036bc0aeb',
            'method': 'Stock decompiler switch/default groups and direct comparisons; source handlers mapped to compiled ARM64 constants',
            'stock_handled_requests': [f'0x{x:08x}' for x in sorted(stock_requests)],
            'candidate_handled_requests': [{'request': f'0x{x:08x}', 'name': name}
                                           for x, name in sorted(candidate.items())],
            'stock_requests_absent_from_candidate': [f'0x{x:08x}' for x in sorted(stock_requests - candidate.keys())],
            'candidate_extras': [f'0x{x:08x}' for x in sorted(candidate.keys() - stock_requests)],
            'limitations': ['Request dispatch agreement only; full payload, behavior and error-return parity unverified',
                            'Decompiler-generated switch holes leading directly to default are excluded']}, indent=2) + '\n')

    args = command(stage / 'gps/gps_stp/.stp_chrdev_gps.o.cmd')
    args[args.index('-c')] = '-E'
    preprocessed = evidence / 'gps-preprocessed.c'
    args[args.index('-o') + 1] = str(preprocessed)
    run(args, evidence / 'gps-preprocess.log')
    text = preprocessed.read_text()
    start = text.index('long GPS_unlocked_ioctl(')
    end = text.index('long GPS_compat_ioctl(', start)
    cases = list(map(int, re.findall(r'case\s+(\d+)\s*:', text[start:end])))
    (evidence / 'gps-compiled-cases.json').write_text(json.dumps({
        'method': 'Actual MT6771 kernel/module flags and preprocessed source',
        'ioctl_cases': cases,
        'limitations': ['Selected compile-time branches; no runtime execution']}, indent=2) + '\n')
    print(f'FM: compiled {len(requests)} request values; GPS selected cases: {cases}')


if __name__ == '__main__':
    main()
