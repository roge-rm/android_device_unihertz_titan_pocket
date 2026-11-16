#!/usr/bin/env python3
"""Checks the 5.10 videocodec driver against stock's /dev/Vcodec contract (CAMERA_PORT.md milestone V).

Source: the headers (include/, include/kernel/, mt6771/*.h, mt6771/common/drv/inc/) are T's, byte for byte, and the
driver's COMPAT_* structs and its compat_ioctl case list are T's.

Ioctls: every VCODEC_* command is _IOW('M', nr, unsigned int) = 0x40044dNN, so 32 and 64-bit callers send the same
number. Each one REA found in stock libvcodec_utility.so (evidence/camera/video-codec.md) has a case in the native
ioctl switch, and the pointer-carrying ones (HW lock, power, ISR, memory, frame info) have a compat_ioctl case.

Layouts: built with the NDK clang for armv7a (the 32-bit OMX libs) and aarch64 (the kernel). For the translated
structs the kernel's COMPAT_* layout must equal the 32-bit caller's native layout, field by field. The structs that
pass through untranslated (CPU loading, core loading, CPU OPP limit) must be the same on both ABIs. VAL_MEMORY_T
differs in stock too (u4MemSign and 64-bit unions the COMPAT struct lacks); its two ioctls do nothing in T, so that
is reported, not failed.

Build: System.map has stock's vcodec symbols (embedded.kallsyms names) and the build record is this tree's.
DT: both board dtbs have /vdec@16020000 and /venc@17020000 okay with stock's reg and IRQ, and vdec_gcon@16000000
okay with stock's five clocks.
Vendor: stock init.mt6771.rc sets /dev/Vcodec to media:system 0660 on post-fs-data and vendor_file_contexts labels it
Vcodec_device; the driver's node name is Vcodec.

Host only: no build and no phone access. Writes evidence/camera/vcodec-check.json.
"""
import pocket_paths
import hashlib, json, os, re, runpy, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BUILD = BULK / 'kernel-firstboot-5.10'
BUILD_RECORD = ROOT / 'evidence/kernel-upgrade/firstboot-kernel-build.json'
U = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
T = ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5dd7fac4fdba5d5fd451ad6649c51250c'
VC = 'drivers/misc/mediatek/videocodec'
DRIVER = VC + '/mt6771/videocodec_kernel_driver.c'
HEADERS = ['include/hal_types_private.h', 'include/hal_types_public.h', 'include/val_types_private.h',
           'include/val_types_public.h', 'include/kernel/hal_api.h', 'include/kernel/val_api_private.h',
           'include/kernel/val_api_public.h', 'mt6771/videocodec_kernel_driver.h',
           'mt6771/common/drv/inc/drv_api.h', 'mt6771/common/drv/inc/dvfs_v2.h']
KALLSYMS = ROOT / 'evidence/kernel-upgrade/stock-native-slices/embedded.kallsyms'
BOARD = BULK / 'artifacts/firstboot-5.10/board'
VENDOR = ROOT / 'firmware/analysis/rootfs/vendor'
OUT = ROOT / 'evidence/camera/vcodec-check.json'
LLVM = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk'))) / \
    'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
# Commands REA found as movw/movt pairs in stock libvcodec_utility.so (evidence/camera/video-codec.md).
REA_NRS = [0x0b, 0x0d, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x27, 0x29, 0x30, 0x31, 0x32, 0x33, 0x34,
           0x35, 0x37]
# compat struct -> (native struct, ioctls that use it)
TRANSLATED = {'COMPAT_VAL_HW_LOCK_T': ('VAL_HW_LOCK_T', ['VCODEC_LOCKHW', 'VCODEC_UNLOCKHW']),
              'COMPAT_VAL_POWER_T': ('VAL_POWER_T', ['VCODEC_INC_PWR_USER', 'VCODEC_DEC_PWR_USER']),
              'COMPAT_VAL_ISR_T': ('VAL_ISR_T', ['VCODEC_WAITISR']),
              'COMPAT_VAL_MEMORY_T': ('VAL_MEMORY_T', ['VCODEC_ALLOC_NON_CACHE_BUFFER', 'VCODEC_FREE_NON_CACHE_BUFFER']),
              'COMPAT_VAL_FRAME_INFO_T': ('VAL_FRAME_INFO_T', ['VCODEC_SET_FRAME_INFO'])}
STOCK_MISMATCH_OK = {'COMPAT_VAL_MEMORY_T': 'T has the same mismatch; ALLOC/FREE_NON_CACHE_BUFFER handlers are empty'}
PASSTHROUGH = {'VAL_VCODEC_CPU_LOADING_INFO_T': ['_cpu_idle_time', '_thread_cpu_time', '_sched_clock', '_inst_count'],
               'VAL_VCODEC_CORE_LOADING_T': ['CPUid', 'Loading'],
               'VAL_VCODEC_CPU_OPP_LIMIT_T': ['limited_freq', 'limited_cpu', 'enable']}
SYMBOLS = ['vcodec_probe', 'vcodec_unlocked_ioctl', 'vcodec_unlocked_compat_ioctl', 'vcodec_mmap', 'video_intr_dlr',
           'video_intr_dlr2', 'vdec_power_on', 'venc_power_on', 'vcodec_driver_init']
NODES = {'/vdec@16020000': ([0, 0x16020000, 0, 0x10000], [0, 0xfa, 8]),
         '/venc@17020000': ([0, 0x17020000, 0, 0x1000], [0, 0xf7, 8])}
GCON_CLOCKS = ['MT_SCP_SYS_DIS', 'MT_SCP_SYS_VDE', 'MT_SCP_SYS_VEN', 'MT_CG_VDEC', 'MT_CG_VENC']

checks = []


def check(name, ok, detail=''):
    checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(('OK   ' if ok else 'FAIL ') + name + (f': {detail}' if detail else ''))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def struct_body(text, name):
    m = re.search(r'struct ' + name + r' \{(.*?)\n\};', text, re.S)
    return m.group(1) if m else None


def fields(body):
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    return [m.group(1) for m in re.finditer(r'(\w+)(?:\[\w+\])?;', body)]


def case_list(text, func):
    start = text.index('static long ' + func)
    end = text.index('\n}\n', start)
    return re.findall(r'case (\w+):', text[start:end])


def layouts(target, source, items):
    """{label: value} from a const array clang emits for the target, read off its -S output."""
    with tempfile.TemporaryDirectory() as d:
        c = Path(d) / 'probe.c'
        c.write_text(source + '\nconst unsigned int probe_values[] = {\n' +
                     ''.join(f'  (unsigned int)({expr}),\n' for _, expr in items) + '};\n')
        s = Path(d) / 'probe.s'
        subprocess.run([str(LLVM / 'clang'), '--target=' + target, '-ffreestanding', '-nostdinc',
                        '-isystem', str(next((LLVM.parent / 'lib/clang').glob('*/include'))),
                        '-I', str(U / VC / 'include'), '-S', '-O0', '-o', str(s), str(c)], check=True)
        asm = s.read_text()
    body = asm[asm.index('probe_values:'):]
    words = [int(m.group(2), 0) for m in re.finditer(r'\.(long|word)\s+(-?\w+)', body)][:len(items)]
    assert len(words) == len(items), (target, len(words), len(items))
    return {label: v for (label, _), v in zip(items, words)}


def main():
    # 1. Source
    for h in HEADERS:
        check('header is T\'s: ' + h, sha(U / VC / h) == sha(T / VC / h))
    u_text, t_text = (U / DRIVER).read_text(), (T / DRIVER).read_text()
    for comp in TRANSLATED:
        body = struct_body(u_text, comp)
        check('COMPAT struct is T\'s: ' + comp, body is not None and body == struct_body(t_text, comp))
    native_cases = case_list(u_text, 'vcodec_unlocked_ioctl')
    compat_cases = case_list(u_text, 'vcodec_unlocked_compat_ioctl')
    check('native ioctl cases are T\'s', native_cases == case_list(t_text, 'vcodec_unlocked_ioctl'),
          f'{len(native_cases)} cases')
    check('compat ioctl cases are T\'s', compat_cases == case_list(t_text, 'vcodec_unlocked_compat_ioctl'),
          f'{len(compat_cases)} cases')

    # 2. Ioctl numbers
    header = (U / VC / 'mt6771/videocodec_kernel_driver.h').read_text()
    magic = re.search(r"#define MFV_IOC_MAGIC\s+'(.)'", header).group(1)
    defs = {m.group(1): int(m.group(2), 16) for m in
            re.finditer(r'#define (VCODEC_\w+)\s+_IOW\(MFV_IOC_MAGIC,\s*(0x[0-9a-fA-F]+),\s*unsigned int\)', header)}
    numbers = {n: (1 << 30) | (4 << 16) | (ord(magic) << 8) | nr for n, nr in defs.items()}
    check('every VCODEC_* is _IOW(\'M\', nr, 4)', magic == 'M' and all(v & 0xffffff00 == 0x40044d00
          for v in numbers.values()), f'{len(numbers)} commands')
    by_nr = {nr: n for n, nr in defs.items()}
    for nr in REA_NRS:
        name = by_nr.get(nr)
        check(f'REA ioctl 0x{0x40044d00 | nr:08x} handled', name in native_cases, name or 'not defined')
    for comp, (_, cmds) in TRANSLATED.items():
        check('compat_ioctl translates ' + ', '.join(cmds), all(c in compat_cases for c in cmds))
    passthrough = [c for c in native_cases if c not in compat_cases]

    # 3. Layouts
    src = '#include <stddef.h>\n#include "val_types_private.h"\n'
    compat_src = 'typedef unsigned int compat_uptr_t, compat_uint_t, compat_ulong_t;\n' + ''.join('struct ' + c + ' {' + struct_body(u_text, c) + '\n};\n'
                                                 for c in TRANSLATED)
    items32, items64 = [], []
    for comp, (native, _) in TRANSLATED.items():
        names = fields(struct_body(u_text, comp))
        items32 += [(f'{native}.size', f'sizeof(struct {native})')] + \
                   [(f'{native}.{f}', f'offsetof(struct {native}, {f})') for f in names
                    if re.search(r'\b' + f + r'\b', struct_body((U / VC / 'include/val_types_public.h').read_text() +
                                 (U / VC / 'include/val_types_private.h').read_text(), native) or '')]
        items64 += [(f'{comp}.size', f'sizeof(struct {comp})')] + \
                   [(f'{comp}.{f}', f'offsetof(struct {comp}, {f})') for f in names]
    for native, names in PASSTHROUGH.items():
        items32 += [(f'{native}.size', f'sizeof(struct {native})')] + \
                   [(f'{native}.{f}', f'offsetof(struct {native}, {f})') for f in names]
    arm32 = layouts('armv7a-linux-androideabi30', src, items32)
    arm64 = layouts('aarch64-linux-android30', src, items32)
    compat64 = layouts('aarch64-linux-android30', src + compat_src, items64)
    layout_record = {}
    for comp, (native, cmds) in TRANSLATED.items():
        names = fields(struct_body(u_text, comp))
        rows = {f: (compat64[f'{comp}.{f}'], arm32.get(f'{native}.{f}')) for f in names}
        size = (compat64[f'{comp}.size'], arm32[f'{native}.size'])
        same = size[0] == size[1] and all(a == b for a, b in rows.values())
        layout_record[comp] = {'native': native, 'ioctls': cmds, 'size_compat_vs_arm32': size,
                               'offsets_compat_vs_arm32': rows, 'native_aarch64_size': arm64[f'{native}.size'],
                               'match': same}
        if comp in STOCK_MISMATCH_OK and not same:
            check(f'{comp} vs 32-bit {native}', True, 'differs as in T: ' + STOCK_MISMATCH_OK[comp])
        else:
            check(f'{comp} == 32-bit {native}', same, f'size {size[0]}/{size[1]}')
    for native, names in PASSTHROUGH.items():
        a = [arm32[f'{native}.size']] + [arm32[f'{native}.{f}'] for f in names]
        b = [arm64[f'{native}.size']] + [arm64[f'{native}.{f}'] for f in names]
        layout_record[native] = {'arm32': a, 'aarch64': b, 'match': a == b}
        check(f'{native} same on both ABIs (passed through)', a == b, f'size {a[0]}/{b[0]}')

    # 4. Build
    record = json.loads(BUILD_RECORD.read_text())
    current = all(sha(U / p) == h for p, h in record['source_hashes'].items())
    check('build record matches this tree', current and record.get('returncode') == 0 and record['stage'] == 'image')
    system_map = (BUILD / 'System.map').read_text()
    have = {s for s in SYMBOLS if re.search(r' [tT] ' + s + r'$', system_map, re.M)}
    stock = KALLSYMS.read_text() if KALLSYMS.exists() else ''
    check('System.map has stock\'s vcodec symbols', have == set(SYMBOLS), ', '.join(sorted(set(SYMBOLS) - have)) or
          f'{len(have)} symbols, all in stock kallsyms: {all(s in stock for s in SYMBOLS)}')
    config = (BUILD / '.config').read_text()
    check('CONFIG_MTK_VIDEOCODEC_DRIVER=y, mainline mtk-vcodec off',
          'CONFIG_MTK_VIDEOCODEC_DRIVER=y' in config and 'CONFIG_VIDEO_MEDIATEK_VCODEC=y' not in config)

    # 5. DT
    tree = runpy.run_path(str(ROOT / 'tools/prepare-pocket-diagnostic-tree.py'), run_name='vcodec_check')
    decode, values, text, enabled = tree['DECODE'], tree['values'], tree['text'], tree['enabled']
    boards = {}
    for name in ['keyboard.dtb', 'keyboard-modem-on.dtb']:
        nodes = decode((BOARD / name).read_bytes())['nodes']
        ok = all(enabled(nodes, p) and values(nodes[p]['reg']) == reg and values(nodes[p]['interrupts']) == irq
                 for p, (reg, irq) in NODES.items())
        g = nodes['/vdec_gcon@16000000']
        ok = ok and enabled(nodes, '/vdec_gcon@16000000') and text(g['clock-names']) == GCON_CLOCKS
        boards[name] = sha(BOARD / name)
        check(f'{name}: vdec, venc and vdec_gcon okay as stock', ok)

    # 6. Vendor
    rc = (VENDOR / 'etc/init/hw/init.mt6771.rc').read_text()
    ctx = (VENDOR / 'etc/selinux/vendor_file_contexts').read_text()
    check('driver node is Vcodec', '#define VCODEC_DEVNAME     "Vcodec"' in u_text)
    check('stock rc sets /dev/Vcodec media:system 0660',
          'chmod 0660 /dev/Vcodec' in rc and 'chown media system /dev/Vcodec' in rc)
    check('stock vendor_file_contexts labels /dev/Vcodec', re.search(r'^/dev/Vcodec\(/\.\*\)\?\s+u:object_r:Vcodec_device:s0',
                                                                    ctx, re.M) is not None)

    failed = [c for c in checks if not c['ok']]
    OUT.write_text(json.dumps({'ioctls': {n: f'0x{v:08x}' for n, v in sorted(numbers.items(), key=lambda x: x[1])},
                               'native_cases': native_cases, 'compat_cases': compat_cases, 'passthrough': passthrough,
                               'rea_numbers': [f'0x{0x40044d00 | n:08x}' for n in REA_NRS], 'layouts': layout_record,
                               'boards': boards, 'checks': checks, 'failures': len(failed),
                               'phone_accessed': False}, indent=2) + '\n')
    print(f'checks {len(checks)} failures {len(failed)} report {OUT}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
