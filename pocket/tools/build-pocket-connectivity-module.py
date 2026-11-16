#!/usr/bin/env python3
"""Build one connectivity module out of tree against the first-boot 5.10 kernel build.

Copies the staged sources (tools/prepare-connectivity-sources.py, with its
patches) to build/connectivity/<module>/ and runs kbuild there with M=, using the
kernel output dir and toolchain of tools/build-pocket-firstboot-kernel.py. The
kernel build needs a Module.symvers: run `make modules` in that output dir once
after the image stage. Run this through `heavy build`. No device operations.
"""
import pocket_paths
import argparse, hashlib, json, os, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
SOURCE = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
KERNEL_OUT = BULK / 'kernel-firstboot-5.10'
STAGE = ROOT / 'tools/kernel-build-config/connectivity'
# module: staged component, subdirectory, extra make variables.
# TARGET_BUILD_VARIANT=user as stock: its wmt_step_init is a bare return and
# wmt_dbg has no 0xDB9DB9 unlock, so CFG_WMT_STEP and WMT_DBG_SUPPORT were off.
# The Wi-Fi modules take the WMT headers from $(TOP)/vendor/mediatek/kernel_modules/
# connectivity/common, which build/connectivity/top links to the staged common.
# DRIVER_BUILD_DATE is fixed so the build is reproducible; stock has the build
# time there (2.0.1.1-20230105200105 in its version reply).
MODULES = {'wmt_drv': ('wifi', 'common', ['TARGET_BUILD_VARIANT=user'], []),
           'wmt_chrdev_wifi': ('wifi', 'wlan/adaptor', ['TARGET_BUILD_VARIANT=user'], ['wmt_drv']),
           'wlan_drv_gen3': ('wifi', 'wlan/core/gen3', ['TARGET_BUILD_VARIANT=user', 'DRIVER_BUILD_DATE=19700101000000'],
                             ['wmt_drv', 'wmt_chrdev_wifi']),
           # Radios that sit on WMT and STP only. User variant as stock: bt_drv gets PM_QOS_CONTROL=0 (no pm_qos
           # import in stock), fmradio_drv gets CONFIG_MTK_USER_BUILD (the FM_USER_LOAD switch in its Makefile),
           # FM is the MT6631 on the legacy WMT path (CFG_BUILD_CONNAC2 not true).
           'bt_drv': ('bt', '.', ['TARGET_BUILD_VARIANT=user'], ['wmt_drv']),
           'gps_drv': ('gps', '.', ['TARGET_BUILD_VARIANT=user'], ['wmt_drv']),
           'fmradio_drv': ('fmradio', '.', ['TARGET_BUILD_VARIANT=user', 'CONFIG_FM_USER_LOAD=1', 'CFG_FM_CHIP=mt6631',
                                            'CFG_BUILD_CONNAC2=false'], ['wmt_drv'])}
# A line each patch must have put in the staged source: module: (patch, file, text).
# wmt_chrdev_wifi builds on 5.10 as pinned.
MARKERS = {'wmt_drv': ('0003', 'common_main/linux/stp_dbg.c', '.validate = GENL_DONT_VALIDATE_STRICT'),
           'wlan_drv_gen3': ('0004', 'os/linux/plat/mt6771/plat_priv.c', 'freq_qos_add_request'),
           'bt_drv': ('0005', 'dbg_bt.c', 'BT_DBG_OPPO_EXTRA'),
           'gps_drv': ('0006', 'stp_chrdev_gps.c', 'ktime_get_real_ts64'),
           'fmradio_drv': ('0007', 'core/fm_module.c', 'struct proc_ops fm_proc_ops')}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def toolchain():
    """Environment and make prefix of the first-boot kernel build."""
    deps = ROOT / 'tools/build-deps'
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk')))
    llvm = sdk / 'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
    env = os.environ.copy()
    env['PATH'] = f'{deps}/usr/bin:{llvm}:' + env.get('PATH', '')
    env['LD_LIBRARY_PATH'] = f'{deps}/usr/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
    env.update(KBUILD_BUILD_USER='pocket-builder', KBUILD_BUILD_HOST='pocket-firstboot',
               KBUILD_BUILD_TIMESTAMP='Thu Jan 1 00:00:00 UTC 1970', KBUILD_BUILD_VERSION='1', SOURCE_DATE_EPOCH='0')
    base = ['make', '-C', str(SOURCE), f'O={KERNEL_OUT}', 'ARCH=arm64', 'LLVM=1', 'LLVM_IAS=1',
            f'CC={llvm}/clang', f'LD={llvm}/ld.lld', 'HOSTCC=gcc', 'HOSTCXX=g++',
            f'CROSS_COMPILE={deps}/usr/bin/aarch64-linux-gnu-']
    return env, base


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--module', choices=sorted(MODULES), default='wmt_drv')
    parser.add_argument('--jobs', type=int, default=10)
    parser.add_argument('--refresh-symvers', action='store_true',
                        help='run make modules in the kernel output dir first, to rewrite its Module.symvers; '
                             'fails if that leaves vmlinux newer than Image.gz')
    parser.add_argument('--keep-going', action='store_true', help='make -k, to list every error at once')
    args = parser.parse_args()
    component, subdir, extra, needs = MODULES[args.module]
    env, base = toolchain()
    if args.refresh_symvers:
        rc = subprocess.run(base + [f'-j{args.jobs}', 'modules'], env=env).returncode
        if rc:
            raise SystemExit(f'make modules in {KERNEL_OUT} failed: {rc}')
        # make modules relinks vmlinux when the kernel changed; the symvers must match the flashed image.
        image = KERNEL_OUT / 'arch/arm64/boot/Image.gz'
        vmlinux = KERNEL_OUT / 'vmlinux'
        if not image.is_file() or not vmlinux.is_file() or image.stat().st_mtime < vmlinux.stat().st_mtime:
            raise SystemExit(f'{image} is missing or older than vmlinux; rebuild the kernel image first '
                             '(tools/build-pocket-firstboot-kernel.py)')
    staged = STAGE / component / subdir
    if not staged.is_dir():
        parser.error('Run tools/prepare-connectivity-sources.py first')
    if not (KERNEL_OUT / 'Module.symvers').is_file():
        parser.error(f'{KERNEL_OUT}/Module.symvers missing; run make modules in the kernel output dir')
    vmlinux = KERNEL_OUT / 'vmlinux'
    if not vmlinux.is_file():
        parser.error(f'{vmlinux} missing; build the kernel first')
    if (KERNEL_OUT / 'Module.symvers').stat().st_mtime < vmlinux.stat().st_mtime:
        parser.error(f'{KERNEL_OUT}/Module.symvers is older than vmlinux; run make modules in the kernel output dir')
    patch, marked, text = MARKERS.get(args.module, (None, None, None))
    if patch and text not in (staged / marked).read_text():
        parser.error(f'Patch {patch} is not applied to the staged source; run tools/prepare-connectivity-sources.py')
    # Modules this one imports from, built first; their Module.symvers go to modpost.
    extra_symbols = []
    for need in needs:
        symvers = ROOT / 'build/connectivity' / need / 'Module.symvers'
        ko = symvers.with_name(need + '.ko')
        if not ko.is_file() or not symvers.is_file() or symvers.stat().st_mtime < (KERNEL_OUT / 'Module.symvers').stat().st_mtime:
            parser.error(f'Build {need} first (missing, or older than the kernel Module.symvers)')
        # A dependency built before its staged sources last changed has stale symbol CRCs.
        need_src = STAGE / MODULES[need][0] / MODULES[need][1]
        times = [f.stat().st_mtime for f in need_src.rglob('*') if f.is_file()] if need_src.is_dir() else []
        if not times:
            parser.error(f'No staged sources for {need} in {need_src}; run tools/prepare-connectivity-sources.py')
        newest = max(times)
        if symvers.stat().st_mtime < newest:
            parser.error(f'{need} is older than its staged sources in {need_src}; rebuild it first')
        extra_symbols.append(str(symvers))
    top = ROOT / 'build/connectivity/top'
    common = top / 'vendor/mediatek/kernel_modules/connectivity/common'
    if common.is_symlink():
        if common.resolve() != (STAGE / 'wifi/common').resolve():
            common.unlink()
    elif common.exists():
        parser.error(f'{common} is a real file or directory; remove it, it must be a symlink to {STAGE / "wifi/common"}')
    if not common.is_symlink():
        common.parent.mkdir(parents=True, exist_ok=True)
        common.symlink_to(STAGE / 'wifi/common')
    work = ROOT / 'build/connectivity' / args.module
    # The build copy is rebuilt from scratch so no stale file or mtime stays.
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(staged, work)
    command = base + [f'-j{args.jobs}', *(['-k'] if args.keep_going else []), f'M={work}', f'TOP={top}',
               f'AUTOCONF_H={KERNEL_OUT}/include/generated/autoconf.h', f'KBUILD_EXTRA_SYMBOLS={" ".join(extra_symbols)}',
               *extra, 'modules']
    log = BULK / 'logs' / f'connectivity-{args.module}-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")}.log'
    log.parent.mkdir(parents=True, exist_ok=True)
    print('Log: ' + str(log), flush=True)
    with log.open('w') as stream:
        rc = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT).returncode
    record = {'utc': datetime.now(timezone.utc).isoformat(), 'module': args.module, 'returncode': rc,
              'staged': str(staged), 'work': str(work), 'kernel_out': str(KERNEL_OUT), 'log': str(log),
              'command': command, 'module_symvers_sha256': digest(KERNEL_OUT / 'Module.symvers'),
              'staged_record_sha256': digest(ROOT / 'evidence/connectivity/staged-sources.json'),
              'device_accessed': False}
    ko = work / (args.module + '.ko')
    if rc == 0 and ko.is_file():
        record['ko'] = {'path': str(ko), 'bytes': ko.stat().st_size, 'sha256': digest(ko)}
    evidence = ROOT / 'evidence/connectivity'
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f'build-{args.module}.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record.get('ko', {}), indent=1))
    print(args.module, 'exit', rc)
    raise SystemExit(rc)


if __name__ == '__main__':
    main()
