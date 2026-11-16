#!/usr/bin/env python3
"""Compile/link opt-in UFS and PMIC/reset suppliers independently, never an Image."""
import pocket_paths
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'tools/kernel-source/upgrade-5.10'
CLANG = pocket_paths.ndk_bin()
OBJECTS = [
    'drivers/scsi/ufs/ufshcd.o', 'drivers/scsi/ufs/ufs-sysfs.o',
    'drivers/scsi/ufs/ufs-debugfs.o', 'drivers/scsi/ufs/ufshcd-pltfrm.o',
    'drivers/scsi/ufs/ufs-mediatek.o', 'drivers/phy/mediatek/phy-mtk-ufs.o',
    'drivers/clk/mediatek/clk-mt6358-ufs.o', 'block/blk-crypto.o',
    'block/blk-crypto-fallback.o', 'block/keyslot-manager.o',
    'drivers/md/dm-default-key.o', 'drivers/md/dm-crypt.o',
    'fs/crypto/inline_crypt.o', 'fs/crypto/keyring.o',
    'drivers/mfd/mt6397-core.o', 'drivers/clk/mediatek/clk-mt6771.o',
    'drivers/clk/mediatek/reset.o', 'drivers/clk/mediatek/clk-mtk.o',
    'drivers/clk/mediatek/clk-gate.o', 'drivers/clk/mediatek/clk-mux.o',
    'drivers/clk/mediatek/clk-pll.o']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=6)
    parser.add_argument('--hardware-crypto-compile', action='store_true',
                        help='Compile generic UFS crypto too; never registers an MT6771 key callback')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    objects = OBJECTS + (['drivers/scsi/ufs/ufshcd-crypto.o']
                         if args.hardware_crypto_compile else [])
    baseline = ROOT / 'tools/kernel-build-config/upgrade-5.10/.config'
    protected = [baseline, ROOT / 'configs/kernel-upgrade-5.10.fragment']
    # Enumerate configuration roots, not every generated object/header recursively.
    protected += [p / '.config' for p in (ROOT / 'tools/kernel-build-config').iterdir()
                  if p.is_dir() and ('ram' in p.name or 'probe' in p.name)]
    bulk = pocket_paths.build_root()
    protected += [p / '.config' for p in bulk.glob('kernel-diagnostic-*') if p.is_dir()]
    before_configs = {str(p): digest(p) for p in protected if p.is_file()}
    profile = 'generic-crypto' if args.hardware_crypto_compile else 'software-crypto'
    output = pocket_paths.build_root() / ('out/ufs-engineering-' + profile)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(baseline, output / '.config')
    tracked = set((SOURCE / 'drivers/scsi/ufs').glob('*.c'))
    tracked.update((SOURCE / 'drivers/scsi/ufs').glob('*.h'))
    tracked.update(SOURCE / name.replace('.o', '.c') for name in objects)
    tracked.update(SOURCE / name for name in [
        'drivers/clk/mediatek/clk-mt6358-ufs.c',
        'drivers/clk/mediatek/clk-mt6358-ufs.h',
        'drivers/phy/mediatek/phy-mtk-ufs.c', 'drivers/scsi/ufs/Makefile',
        'drivers/scsi/ufs/Kconfig', 'drivers/clk/mediatek/Kconfig',
        'drivers/mfd/mt6397-core.c'])
    source_hashes = {str(p.relative_to(SOURCE)): digest(p) for p in sorted(tracked)}
    deps = ROOT / 'tools/build-deps'
    env = os.environ.copy()
    env['PATH'] = f'{deps}/usr/bin:{CLANG}:' + env.get('PATH', '')
    env['LD_LIBRARY_PATH'] = f'{deps}/usr/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
    env['BISON_PKGDATADIR'] = str(deps / 'usr/share/bison')
    base = ['make', '-C', str(SOURCE), f'O={output}', 'ARCH=arm64', 'LLVM=1',
            'LLVM_IAS=1', f'CC={CLANG}/clang', f'LD={CLANG}/ld.lld',
            'HOSTCC=gcc', 'HOSTCXX=g++',
            f'CROSS_COMPILE={deps}/usr/bin/aarch64-linux-gnu-', f'-j{args.jobs}']
    changes = ['bash', str(SOURCE / 'scripts/config'), '--file', str(output / '.config')]
    required = ['SCSI_UFS_MEDIATEK', 'COMMON_CLK_MT6358_UFS', 'DEBUG_FS',
                'BLK_INLINE_ENCRYPTION', 'BLK_INLINE_ENCRYPTION_FALLBACK',
                'DM_DEFAULT_KEY', 'DM_CRYPT', 'FS_ENCRYPTION_INLINE_CRYPT',
                'MFD_MT6397', 'MFD_SYSCON', 'REGMAP_MMIO', 'COMMON_CLK_MT6771',
                'COMMON_CLK_MT6771_HANDOFF', 'RESET_CONTROLLER']
    for name in required:
        changes += ['--enable', name]
    changes += ['--enable' if args.hardware_crypto_compile else '--disable', 'SCSI_UFS_CRYPTO']
    changes += ['--disable', 'SCSI_UFS_BSG', '--disable', 'SCSI_UFS_HPB']
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    log = ROOT / 'evidence/kernel-upgrade' / (stamp + '-ufs-engineering-' + profile + '.log')
    record = {'profile': profile, 'source': str(SOURCE), 'output': str(output),
              'tool_sha256': digest(Path(__file__)),
              'source_sha256': source_hashes, 'protected_config_sha256': before_configs,
              'commands': [], 'device_accessed': False, 'image_built': False,
              'scope': 'Selected ARM64 objects and relocatable-link closure only',
              'limits': ['No module modpost or complete kernel link',
                        'Undefined generic kernel APIs are expected and retained',
                        'Opt-in engineering match/MFD clock binding compiled; no production PM or keyslot registration',
                        'No boot, block I/O, encryption, HIE, TEE, RPMB or suspend qualification']}
    result_code = 0
    print(str(log), flush=True)
    with log.open('w') as stream:
        for command in [changes, base + ['olddefconfig'], base + ['prepare', 'scripts'], base + objects]:
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
            record['commands'].append({'command': command, 'returncode': result.returncode})
            if result.returncode:
                result_code = result.returncode
                break
        if not result_code:
            config = (output / '.config').read_text()
            missing = [name for name in required if 'CONFIG_' + name + '=y\n' not in config]
            expected_crypto = ('CONFIG_SCSI_UFS_CRYPTO=y\n' if args.hardware_crypto_compile
                               else '# CONFIG_SCSI_UFS_CRYPTO is not set\n')
            record['required_settings_match'] = not missing and expected_crypto in config
            record['objects'] = {name: digest(output / name) for name in objects}
            linked = output / 'ufs-dependency-group.o'
            command = [str(CLANG / 'ld.lld'), '-r', '-o', str(linked)] + [str(output / p) for p in objects]
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
            record['commands'].append({'command': command, 'returncode': result.returncode})
            result_code = result.returncode
            if not result_code:
                symbols = subprocess.run([str(CLANG / 'llvm-nm'), '--undefined-only', str(linked)],
                                         capture_output=True, text=True, check=True).stdout
                unresolved = [line.split()[-1] for line in symbols.splitlines() if line.split()]
                # Internal UFS/variant calls must resolve in this group. External
                # kernel, SCSI, DMA, regmap and CCF APIs deliberately remain open.
                internal = [name for name in unresolved if name.startswith(
                    ('ufshcd_', 'ufs_', 'blk_crypto_', 'blk_ksm_', 'mtk_clk_', 'mtk_register_reset_'))]
                record.update(linked_sha256=digest(linked), undefined_symbols=unresolved,
                              unresolved_ufs_internal_symbols=internal)
                result_code = int(bool(internal) or not record['required_settings_match'])
    record['protected_configs_unchanged'] = all(digest(Path(p)) == sha for p, sha in before_configs.items())
    record['tracked_sources_unchanged'] = all(digest(SOURCE / p) == sha for p, sha in source_hashes.items())
    record['config_sha256'] = digest(output / '.config')
    record['returncode'] = result_code or int(not record['protected_configs_unchanged'] or not record['tracked_sources_unchanged'])
    log.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Return code ' + str(record['returncode']), flush=True)
    raise SystemExit(record['returncode'])


if __name__ == '__main__':
    main()
