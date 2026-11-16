#!/usr/bin/env python3
"""Run bounded offline kernel build checks with project-local host dependencies.

Uses the existing NDK 27 Clang 18 for diagnostics, not the stock Clang 11.
No image packaging, flashing, or remote device operations are performed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=root / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad')
    parser.add_argument('--output', type=Path, default=root / 'tools/kernel-build-config/some00')
    parser.add_argument('--target', choices=['config', 'prepare', 'keyboard', 'kernel', 'connectivity'], required=True)
    parser.add_argument('--module', choices=['bt', 'gps', 'fmradio', 'all'], default='all')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--fragment', type=Path, help='Merge after defconfig and resolve with olddefconfig')
    parser.add_argument('--diagnostic-warnings', action='store_true', help='Demote two newer-compiler diagnostics for investigation')
    args = parser.parse_args()
    if args.fragment and args.target != 'config':
        parser.error('--fragment is only valid for config')
    source, output = args.source.resolve(), args.output.resolve()
    if not (source / 'Makefile').is_file():
        parser.error('Kernel source Makefile missing')
    if args.jobs < 1:
        parser.error('jobs must be positive')
    deps = root / 'tools/build-deps'
    clang_dir = Path.home() / 'Android/Sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
    clang = clang_dir / 'clang'
    env = os.environ.copy()
    env['PATH'] = f'{deps}/usr/bin:{clang_dir}:' + env.get('PATH', '')
    env['LD_LIBRARY_PATH'] = f'{deps}/usr/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
    env['BISON_PKGDATADIR'] = str(deps / 'usr/share/bison')
    targets = {'config': ['titanpocket_defconfig'], 'prepare': ['prepare', 'scripts'],
               'keyboard': ['drivers/misc/mediatek/aw9523/aw9523_key.o'],
               'kernel': ['Image.gz', 'modules'], 'connectivity': ['modules']}[args.target]
    command = ['make', '-C', str(source), f'O={output}', 'ARCH=arm64',
               f'CC={clang}', 'HOSTCC=gcc', f'LD={clang_dir}/ld.lld',
               f'CROSS_COMPILE={deps}/usr/bin/aarch64-linux-gnu-',
               'CLANG_TRIPLE=aarch64-linux-gnu-',
               f'-j{args.jobs}', *targets]
    if args.diagnostic_warnings:
        command.insert(-len(targets), 'KCFLAGS=-Wno-error=strict-prototypes -Wno-error=unused-but-set-variable')
    commands = [command]
    if args.target == 'connectivity':
        stage = root / 'tools/kernel-build-config/connectivity'
        selected = ['bt', 'gps', 'fmradio'] if args.module == 'all' else [args.module]
        commands = []
        for name in selected:
            if not (stage / name / 'Makefile').is_file():
                parser.error('Run tools/prepare-connectivity-sources.py first')
            module_name = {'bt': 'bt_drv', 'gps': 'gps_drv', 'fmradio': 'fmradio_drv'}[name]
            commands.append(command[:-len(targets)] + [
                f'M={stage / name}', f'MODULE_NAME={module_name}',
                f'AUTOCONF_H={output}/include/generated/autoconf.h',
                f'WMT_SRC_FOLDER={source}/drivers/misc/mediatek/connectivity/wmt_drv',
                f'GPS_SRC_FOLDER={stage}/gps', 'MTK_PLATFORM=mt6771',
                'CONFIG_MTK_EXTRA_CONN_DRV_BUILD_IN=n', 'CFG_FM_CHIP=mt6631',
                'CFG_FM_CHIP_ID=6771', 'CFG_BUILD_CONNAC2=false', *targets])
    if args.fragment:
        commands.extend([
            ['bash', str(source / 'scripts/kconfig/merge_config.sh'), '-m', '-O', str(output),
             str(output / '.config'), str(args.fragment.resolve())],
            command[:-len(targets)] + ['olddefconfig']])
    logdir = root / 'evidence/build'
    logdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    label = args.target + ('-' + args.module if args.target == 'connectivity' else '')
    log = logdir / f'{stamp}-{label}.log'
    print(f'Running {args.target}; log: {log}', flush=True)
    started = datetime.now(timezone.utc).isoformat()
    with log.open('w') as stream:
        for item in commands:
            process = subprocess.run(item, env=env, stdout=stream, stderr=subprocess.STDOUT)
            if process.returncode:
                break
    config = output / '.config'
    record = {'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
              'target': args.target, 'commands': commands, 'returncode': process.returncode,
              'connectivity_module': args.module if args.target == 'connectivity' else None,
              'fragment_sha256': hashlib.sha256(args.fragment.read_bytes()).hexdigest() if args.fragment else None,
              'log': str(log), 'compiler': subprocess.run([str(clang), '--version'],
                  capture_output=True, text=True, check=True).stdout,
              'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None,
              'limitations': ['Diagnostic Clang 18 differs from stock Clang 11',
                              'A successful build does not establish module ABI or device compatibility']}
    log.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Exit status: {process.returncode}', flush=True)
    print('\n'.join(log.read_text(errors='replace').splitlines()[-45:]), flush=True)
    raise SystemExit(process.returncode)


if __name__ == '__main__':
    main()
