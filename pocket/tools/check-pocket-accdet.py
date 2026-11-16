#!/usr/bin/env python3
"""Checks the first-boot kernel against stock's headset contract (AUDIO_PORT.md milestone 5).

Build: vmlinux must be the build of the current tree (the build record's source and fragment
hashes).

Links: the ACCDET driver and the legacy MT6358 calls are in vmlinux, pmic_get_auxadc_value is
defined only in pmic_legacy.o (not in any linked sound/soc/mediatek object, as the old stand-in
was), dc_trim_thread calls accdet_late_init, and mt_accdet_probe asks for INT_ACCDET (133) and
INT_ACCDET_EINT0 (134) as stock's Image does (AUDIO_PORT.md, milestone 5 result).

Input device: the KEY and SW bits accdet.c sets must be the ones in T's accdet.c, and the bitmaps
they make must equal the ACCDET lines of stock's /proc/bus/input/devices
(evidence/device/20261029T000648.917229Z/root-input.txt).

/dev/accdet: ACCDET_INIT, SET_CALL_STATE and GET_BUTTON_STATUS from accdet.h must be T's, and
ACCDET_INIT must be 0x4100, the ioctl the HAL sends (evidence/audio/hal-contract.md). The fops
have no compat_ioctl, as stock.

sysfs: the platform driver is Accdet_Driver with a read-only state attribute, so
/sys/bus/platform/drivers/Accdet_Driver/state exists once it registers.

Host only: no build and no phone access.
"""
import pocket_paths
import hashlib, importlib.util, json, os, re, runpy, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
VMLINUX = BULK / 'kernel-firstboot-5.10/vmlinux'
BUILD = BULK / 'kernel-firstboot-5.10'
BUILD_RECORD = ROOT / 'evidence/kernel-upgrade/firstboot-kernel-build.json'
FRAGMENT = ROOT / 'configs/kernel-firstboot-5.10.fragment'
U = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
T = ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5dd7fac4fdba5d5fd451ad6649c51250c'
ACCDET = 'drivers/misc/mediatek/accdet'
STOCK_INPUT = ROOT / 'evidence/device/20261029T000648.917229Z/root-input.txt'
HAL_CONTRACT = ROOT / 'evidence/audio/hal-contract.md'
LLVM = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk'))) / \
    'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
SYMBOLS = ['mt_accdet_probe', 'accdet_late_init', 'accdet_mod_init', 'accdet_int_handler', 'accdet_eint_handler',
           'pmic_get_auxadc_value', 'pmic_Read_Efuse_HPOffset', 'pmic_register_interrupt_callback',
           'pmic_enable_interrupt', 'pwrap_node_to_regmap', 'mt6358_pmic_legacy_ready',
           'mt6358_otp_lock', 'mt6358_otp_unlock']
STRINGS = [b'Accdet_Driver\0', b'ACCDET\0', b'accdet\0', b'accdet_eint0\0', b'mediatek,pmic-accdet\0']
# pmic_get_auxadc_value must come from the shim, not the codec's old stand-in.
SHIM_OBJ = 'drivers/misc/mediatek/pmic/mt6358/pmic_legacy.o'
CODEC_DIR = 'sound/soc/mediatek'
BITS = {'KEY': 0x300, 'SW': 0x11}  # KEY_CNT, SW_CNT in 5.10 input-event-codes.h


def load_elf():
    spec = importlib.util.spec_from_file_location('audio_contract', ROOT / 'tools/check-pocket-audio-contract.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Elf(VMLINUX.read_bytes())


def set_bits(source):
    """EV_*, KEY_* and SW_* names accdet.c sets on the input device, in order."""
    found = {'EV': [], 'KEY': [], 'SW': []}
    for kind, name in re.findall(r'__set_bit\(((EV|KEY|SW)_[A-Z_]+),\s*accdet_input_dev->(?:ev|key|sw)bit\)', source):
        found[name].append(kind)
    return found


def codes():
    text = (U / 'include/uapi/linux/input-event-codes.h').read_text()
    return {m[0]: int(m[1], 0) for m in re.findall(r'#define\s+((?:EV|KEY|SW)_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|\d+)\b', text)}


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_current():
    """Problems if vmlinux isn't the build of the current tree: the build record's source and fragment hashes."""
    rec = json.loads(BUILD_RECORD.read_text())
    groups = runpy.run_path(str(ROOT / 'tools/export-kernel-upgrade-patches.py'), run_name='catalog')['GROUPS']
    names = sorted({p for v in groups.values() for p in v})
    out = []
    if rec.get('returncode') != 0 or rec.get('stage') != 'image':
        out.append(f"last build was stage {rec.get('stage')} exit {rec.get('returncode')}")
    if sorted(rec.get('source_hashes', {})) != names:
        out.append('the exported file list changed since the build')
    stale = [p for p in names if rec.get('source_hashes', {}).get(p) != digest(U / p)]
    if stale:
        out.append(f'{len(stale)} source files changed since the build, first {stale[0]}')
    if rec.get('fragment_sha256') != digest(FRAGMENT):
        out.append('the config fragment changed since the build')
    if VMLINUX.stat().st_mtime > BUILD_RECORD.stat().st_mtime:
        out.append('vmlinux is newer than the build record')
    return out


def defined_in(objects, symbol):
    """Objects among these that define symbol (llvm-nm)."""
    out = []
    for o in objects:
        r = subprocess.run([str(LLVM / 'llvm-nm'), '--defined-only', str(o)], capture_output=True, text=True)
        if re.search(r'^\S*\s+[TtWw]\s+' + re.escape(symbol) + r'$', r.stdout, re.M):
            out.append(str(o.relative_to(BUILD)))
    return out


def proc_bitmap(numbers, count):
    """The bitmap as /proc/bus/input/devices prints it: 64-bit words, top non-zero word first."""
    words = [0] * ((count + 63) // 64)
    for n in numbers:
        words[n // 64] |= 1 << (n % 64)
    while len(words) > 1 and not words[-1]:
        words.pop()
    return ' '.join(f'{w:x}' for w in reversed(words))


def stock_bitmaps():
    lines = STOCK_INPUT.read_text().splitlines()
    i = next(i for i, l in enumerate(lines) if l.strip() == 'N: Name="ACCDET"')
    block = []
    for l in lines[i:]:
        if not l.strip():
            break
        block.append(l)
    return {m[0]: m[1].strip() for l in block for m in re.findall(r'^B: (KEY|SW|EV)=(.*)$', l)}


def io(magic, nr):
    return (ord(magic) << 8) | nr  # _IO: no direction, no size


def ioctls(header):
    text = header.read_text()
    magic = re.search(r"#define\s+ACCDET_IOC_MAGIC\s+'(.)'", text)[1]
    return {n: io(magic, int(v)) for n, v in re.findall(r'#define\s+(\w+)\s+_IO\(ACCDET_IOC_MAGIC,\s*(\d+)\)', text)}


def calls(syms, function, targets):
    """bl targets inside function, by name, from the NDK llvm-objdump."""
    text = subprocess.run([str(LLVM / 'llvm-objdump'), '-d', '--no-show-raw-insn', f'--disassemble-symbols={function}',
                           str(VMLINUX)], capture_output=True, text=True, check=True).stdout
    names = {a: n for n, a in syms.items() if n in targets}
    out = []
    for line in text.splitlines():
        m = re.search(r'\bbl\s+0x([0-9a-f]+)', line)
        if m and int(m[1], 16) in names:
            out.append(names[int(m[1], 16)])
    return out, text


def main():
    fails = []
    data = VMLINUX.read_bytes()
    elf = load_elf()
    syms = {n: v[0] for n, v in elf.symbols().items()}

    # Links
    missing = [s for s in SYMBOLS if s not in syms]
    print(f'symbols: {len(SYMBOLS) - len(missing)} of {len(SYMBOLS)} in vmlinux' + (f', missing {missing}' if missing else ''))
    if missing:
        fails.append(f'symbols missing: {missing}')
    absent = [s.rstrip(b'\0').decode() for s in STRINGS if s not in data]
    print(f'strings: {len(STRINGS) - len(absent)} of {len(STRINGS)} in vmlinux' + (f', missing {absent}' if absent else ''))
    if absent:
        fails.append(f'strings missing: {absent}')
    stale = build_current()
    print('vmlinux is the build of the current tree' if not stale else 'vmlinux is stale: ' + '; '.join(stale))
    fails += stale
    shim = defined_in([BUILD / SHIM_OBJ], 'pmic_get_auxadc_value')
    # the objects linked from sound/soc/mediatek (its thin built-in.a), not stale ones left in the build tree
    members = subprocess.run([str(LLVM / 'llvm-ar'), 't', str(BUILD / CODEC_DIR / 'built-in.a')],
                             capture_output=True, text=True, check=True).stdout.split()
    codec = defined_in([BUILD / m for m in members], 'pmic_get_auxadc_value')
    print(f'pmic_get_auxadc_value defined in {shim + codec} ({len(members)} sound/soc/mediatek objects checked)')
    if not shim or codec or not members:
        fails.append('pmic_get_auxadc_value must come only from pmic_legacy.o')
    if not missing:
        trim, _ = calls(syms, 'dc_trim_thread', {'accdet_late_init'}) if 'dc_trim_thread' in syms else ([], '')
        print(f"dc_trim_thread calls accdet_late_init: {'yes' if trim else 'no'}")
        if not trim:
            fails.append('dc_trim_thread does not call accdet_late_init')
        probe, text = calls(syms, 'mt_accdet_probe', {'pmic_register_interrupt_callback', 'pmic_enable_interrupt',
                                                                  'mt6358_pmic_legacy_ready'})
        print(f'mt_accdet_probe calls: {probe}')
        want = ['mt6358_pmic_legacy_ready', 'pmic_register_interrupt_callback', 'pmic_register_interrupt_callback',
                'pmic_enable_interrupt', 'pmic_enable_interrupt']
        if probe != want:
            fails.append(f'mt_accdet_probe calls {probe}, want {want}')
        # the w0 loaded just before each interrupt call: 133 and 134, as stock's Image
        nums = []
        last = None
        for line in text.splitlines():
            m = re.search(r'\bmov\s+w0,\s*#(0x[0-9a-f]+|\d+)\b', line)
            if m:
                last = int(m[1], 0)
            b = re.search(r'\bbl\s+0x([0-9a-f]+)', line)
            if b and int(b[1], 16) in (syms['pmic_register_interrupt_callback'], syms['pmic_enable_interrupt']):
                nums.append(last)
            if b:
                last = None  # w0 is gone after any call
        print(f'interrupt numbers passed: {nums}')
        if nums != [133, 134, 133, 134]:
            fails.append(f'interrupt numbers {nums}, want [133, 134, 133, 134]')

    # Input device bits
    ours = set_bits((U / ACCDET / 'mt6358/accdet.c').read_text())
    stock_src = set_bits((T / ACCDET / 'mt6358/accdet.c').read_text())
    print(f"accdet.c events {ours['EV']}, keys {ours['KEY']}, switches {ours['SW']}")
    if ours != stock_src:
        fails.append(f'key/switch bits differ from T: {stock_src}')
    c = codes()
    live = stock_bitmaps()
    for kind in ('KEY', 'SW'):
        built = proc_bitmap([c[n] for n in ours[kind]], BITS[kind])
        ok = built == live.get(kind)
        print(f"{'ok  ' if ok else 'DIFF'} B: {kind}={built}" + ('' if ok else f'  (stock: {live.get(kind)})'))
        if not ok:
            fails.append(f'{kind} bitmap')
    ev = proc_bitmap([c['EV_SYN']] + [c[n] for n in ours['EV']], c['EV_MAX'] + 1)  # input core sets EV_SYN
    print(f"{'ok  ' if ev == live.get('EV') else 'DIFF'} B: EV={ev}")
    if ev != live.get('EV'):
        fails.append('EV bitmap')

    # /dev/accdet ioctls
    ours_io, stock_io = ioctls(U / ACCDET / 'mt6358/accdet.h'), ioctls(T / ACCDET / 'mt6358/accdet.h')
    print('ioctls: ' + ', '.join(f'{n} 0x{v:x}' for n, v in ours_io.items()))
    hal = re.search(r'`/dev/accdet`[^\n]*?(0x[0-9a-f]+) `_IO\(\'A\',0\)`', HAL_CONTRACT.read_text())
    if ours_io != stock_io or ours_io.get('ACCDET_INIT') != 0x4100 or not hal or int(hal[1], 16) != 0x4100:
        fails.append(f'ioctls differ: ours {ours_io}, T {stock_io}, HAL {hal and hal[1]}')
    drv = (U / ACCDET / 'accdet_drv.c').read_text()
    if 'compat_ioctl' in drv or 'compat_ioctl' in (T / ACCDET / 'accdet_drv.c').read_text():
        fails.append('compat_ioctl differs from stock (none)')

    # sysfs
    src = (U / ACCDET / 'mt6358/accdet.c').read_text()
    attrs = re.findall(r'static DRIVER_ATTR_(R[OW]|WO)\((\w+)\);', src)
    print('driver attributes: ' + ', '.join(f'{n} ({m})' for m, n in attrs))
    if ('RO', 'state') not in attrs or '.name = "Accdet_Driver"' not in drv or 'driver_attr_state' not in syms:
        fails.append('Accdet_Driver/state')

    if fails:
        print('FAIL: ' + '; '.join(fails))
        sys.exit(1)
    print('PASS')


if __name__ == '__main__':
    main()
