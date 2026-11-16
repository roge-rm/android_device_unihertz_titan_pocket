#!/usr/bin/env python3
"""Build isolated 5.10 probes, including an experimental unqualified raw Image."""
import pocket_paths
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=['config', 'prepare', 'pinctrl', 'clocks', 'core', 'bootbase', 'android-core', 'pmic', 'ufs-phy', 'ufs-fw', 'ufs-clock', 'usb-phy', 'usb', 'pstore', 'image', 'dtc'])
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    source = root / 'tools/kernel-source/upgrade-5.10'
    output = root / 'tools/kernel-build-config/upgrade-5.10'
    baseline_config = output / '.config'
    baseline_hash = hashlib.sha256(baseline_config.read_bytes()).hexdigest() if baseline_config.exists() else None
    if args.target in ('ufs-fw', 'ufs-clock'):
        # Compile the disabled host driver in its own configuration. The
        # engineering Image must not acquire storage binding as a side effect.
        output = root / ('tools/kernel-build-config/upgrade-5.10-' + args.target)
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(baseline_config, output / '.config')
    deps = root / 'tools/build-deps'
    clang = pocket_paths.ndk_bin()
    if not source.is_dir() or (source / '.git').exists():
        parser.error('An independent prepared kernel workspace is required')
    env = os.environ.copy()
    env['PATH'] = f'{deps}/usr/bin:{clang}:' + env.get('PATH', '')
    env['LD_LIBRARY_PATH'] = f'{deps}/usr/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
    env['BISON_PKGDATADIR'] = str(deps / 'usr/share/bison')
    base = ['make', '-C', str(source), f'O={output}', 'ARCH=arm64', 'LLVM=1', 'LLVM_IAS=1',
            f'CC={clang}/clang', f'LD={clang}/ld.lld', 'HOSTCC=gcc', 'HOSTCXX=g++',
            f'CROSS_COMPILE={deps}/usr/bin/aarch64-linux-gnu-', f'-j{args.jobs}']
    fragment = root / 'configs/kernel-upgrade-5.10.fragment'
    groups = runpy.run_path(str(root / 'tools/export-kernel-upgrade-patches.py'),
                            run_name='kernel_patch_catalog')['GROUPS']
    tracked = sorted({name for names in groups.values() for name in names})
    def source_hashes():
        return {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                for name in tracked}
    before_source = source_hashes()
    targets = {
        'prepare': ['prepare', 'scripts'],
        'pinctrl': ['drivers/pinctrl/mediatek/pinctrl-mt6771.o',
                    'drivers/pinctrl/mediatek/pinctrl-paris.o',
                    'drivers/pinctrl/mediatek/pinctrl-mtk-common-v2.o',
                    'drivers/pinctrl/mediatek/mtk-eint.o'],
        'clocks': ['drivers/clk/mediatek/clk-mt6771.o',
                   'drivers/clk/mediatek/clk-mtk.o', 'drivers/clk/mediatek/clk-gate.o',
                   'drivers/clk/mediatek/clk-mux.o', 'drivers/clk/mediatek/clk-pll.o',
                   'drivers/clk/mediatek/reset.o'],
        'dtc': ['scripts_dtc'],
    }
    targets['core'] = targets['pinctrl'] + targets['clocks']
    targets['bootbase'] = targets['core'] + [
        'drivers/firmware/psci/psci.o', 'drivers/irqchip/irq-gic-v3.o',
        'drivers/clocksource/arm_arch_timer.o', 'drivers/tty/serial/8250/8250_mtk.o']
    targets['android-core'] = ['drivers/android/binder.o', 'kernel/bpf/syscall.o',
                              'security/selinux/ss/avtab.o', 'drivers/md/dm-default-key.o',
                              'block/blk-crypto.o', 'block/blk-crypto-fallback.o',
                              'fs/crypto/keyring.o']
    targets['pmic'] = ['drivers/soc/mediatek/mtk-pmic-wrap.o',
                       'drivers/mfd/mt6397-core.o', 'drivers/mfd/mt6358-irq.o',
                       'drivers/regulator/mt6358-regulator.o']
    targets['image'] = ['Image']
    targets['ufs-phy'] = ['drivers/phy/mediatek/phy-mtk-ufs.o']
    targets['ufs-fw'] = ['drivers/scsi/ufs/ufs-mediatek.o']
    targets['ufs-clock'] = ['drivers/clk/mediatek/clk-mt6358-ufs.o']
    targets['usb-phy'] = ['drivers/phy/mediatek/phy-mt6771-core.o',
                           'drivers/phy/mediatek/phy-mtk-mt6771.o']
    targets['usb'] = targets['usb-phy'] + [f'drivers/usb/mtu3/{name}.o' for name in
        ['mtu3_plat', 'mtu3_core', 'mtu3_gadget_ep0', 'mtu3_gadget', 'mtu3_qmu', 'mtu3_debugfs']]
    targets['pstore'] = ['fs/pstore/platform.o', 'fs/pstore/ram.o', 'fs/pstore/ram_core.o']
    commands = [base + targets[args.target]] if args.target != 'config' else [
        base + ['defconfig'],
        ['bash', str(source / 'scripts/kconfig/merge_config.sh'), '-m', '-O', str(output),
         str(output / '.config'), str(fragment)],
        base + ['olddefconfig'],
    ]
    if args.target in ('ufs-fw', 'ufs-clock'):
        commands = [
            ['bash', str(source / 'scripts/config'), '--file', str(output / '.config'),
             '--enable', ('SCSI_UFS_MEDIATEK' if args.target == 'ufs-fw' else 'COMMON_CLK_MT6358_UFS')],
            base + ['olddefconfig'], base + ['prepare', 'scripts'],
            base + targets[args.target],
        ]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    log = root / 'evidence/kernel-upgrade' / (stamp + '-' + args.target + '.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    print('Running ' + args.target + '; log: ' + str(log), flush=True)
    started = datetime.now(timezone.utc).isoformat()
    results = []
    with log.open('w') as stream:
        for command in commands:
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
            results.append({'command': command, 'returncode': result.returncode})
            if result.returncode:
                break
    config = output / '.config'
    record = {'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
              'target': args.target, 'commands': results, 'returncode': result.returncode,
              'source': str(source), 'output': str(output),
              'forward_port_source_sha256': before_source,
              'forward_port_source_changed_during_build': before_source != source_hashes(),
              'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None,
              'fragment_sha256': hashlib.sha256(fragment.read_bytes()).hexdigest(),
              'compiler': subprocess.run([str(clang / 'clang'), '--version'], capture_output=True,
                                         text=True, check=True).stdout,
              'scope': 'Compile/configuration probe only; not a complete Pocket kernel, DT or boot test'}
    if args.target in ('ufs-fw', 'ufs-clock'):
        record['baseline_engineering_config_sha256'] = baseline_hash
        record['engineering_config_unchanged'] = baseline_hash == hashlib.sha256(baseline_config.read_bytes()).hexdigest()
        record['scope'] = 'Isolated storage component compile; not enabled in engineering Image or integrated with MT6771 host'
        if not record['engineering_config_unchanged']:
            record['returncode'] = 1
    if record['forward_port_source_changed_during_build']:
        record['returncode'] = 1
        print('Forward-port source changed during build; rerun before using this result', flush=True)
    log.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Return code ' + str(record['returncode']), flush=True)
    raise SystemExit(record['returncode'])


if __name__ == '__main__':
    main()
