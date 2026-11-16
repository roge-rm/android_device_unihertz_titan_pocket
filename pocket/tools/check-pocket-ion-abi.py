#!/usr/bin/env python3
"""Check the ported 4.14 legacy ION ABI and heap selection; no device operations.

1. Compiles a host program from the 5.10 tree's drivers/staging/android/uapi/ion.h and
   ion/mtk/mtk_ion.h and checks the ioctl numbers, struct sizes and heap masks against
   what gralloc needs (DISPLAY_HAL_CONTRACT.md, evidence/display-hal/gralloc-ion-failure.md).
   The same checks also run as static asserts in an arm64 compile of the same source.
2. Reads ion_drv_platform_heaps out of the built vmlinux, keeps the heaps ion_drv_probe
   registers with the secure options off, and runs ion_alloc's heap walk for each mask.
"""
import pocket_paths
import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
OUTPUT = pocket_paths.build_root() / 'kernel-firstboot-5.10'
LLVM = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk'))) / 'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'

# Values gralloc and libion use on the phone (legacy ION, arm64).
IOCTLS = {
    'ION_IOC_ALLOC': (0xc0204900, 'struct ion_allocation_data', 32),
    'ION_IOC_FREE': (0xc0044901, 'struct ion_handle_data', 4),
    'ION_IOC_SHARE': (0xc0084904, 'struct ion_fd_data', 8),
    'ION_IOC_IMPORT': (0xc0084905, 'struct ion_fd_data', 8),
    'ION_IOC_SYNC': (0xc0084907, 'struct ion_fd_data', 8),
    'ION_IOC_CUSTOM': (0xc0104906, 'struct ion_custom_data', 16),
}
MASKS = {'ION_HEAP_CAMERA_MASK': 0x1000, 'ION_HEAP_FB_MASK': 0x800, 'ION_HEAP_MULTIMEDIA_MASK': 0x400}
# Gralloc's asks: normal buffers heap 12, retry heap 10; HW_FB buffers heap 11 first.
# Expected heap for each mask with stock's heap table (no FB heap is registered).
SELECT = {0x1000: 12, 0x800: None, 0x400: 10}

HEADER = '''
#include <stddef.h>
#define BIT(n) (1U << (n))
#include "uapi/ion.h"
#include "ion/mtk/mtk_ion.h"
'''


def program():
    lines = [HEADER]
    lines.append('#ifdef ARM64_CHECK')
    for name, (value, st, size) in IOCTLS.items():
        lines.append(f'_Static_assert({name} == {value:#x}u, "{name}");')
        lines.append(f'_Static_assert(sizeof({st}) == {size}, "{st}");')
    for name, value in MASKS.items():
        lines.append(f'_Static_assert({name} == {value:#x}u, "{name}");')
    lines.append('#else\n#include <stdio.h>\nint main(void)\n{')
    for name, (value, st, size) in IOCTLS.items():
        lines.append(f'\tprintf("%s %#lx %zu\\n", "{name}", (unsigned long){name}, sizeof({st}));')
    for name in MASKS:
        lines.append(f'\tprintf("%s %#lx 0\\n", "{name}", (unsigned long){name});')
    lines.append('\treturn 0;\n}\n#endif\n')
    return '\n'.join(lines)


def read_heaps(vmlinux):
    """Return (type, id, name) for each ion_drv_platform_heaps entry in vmlinux."""
    nm = subprocess.check_output([str(LLVM / 'llvm-nm'), '-S', str(vmlinux)], text=True)
    symbol = None
    for line in nm.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] == 'ion_drv_platform_heaps':
            symbol = (int(parts[0], 16), int(parts[1], 16))
    assert symbol, 'ion_drv_platform_heaps not in vmlinux'
    data = vmlinux.read_bytes()
    # ELF64 section headers, to turn virtual addresses into file offsets.
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', data, 0x3a)
    sections = []
    for i in range(shnum):
        _, kind, _, addr, offset, size = struct.unpack_from('<IIQQQQ', data, shoff + i * shentsize)
        if kind != 8 and addr:  # skip NOBITS
            sections.append((addr, offset, size))

    def at(address, length):
        for addr, offset, size in sections:
            if addr <= address and address + length <= addr + size:
                return data[offset + address - addr:offset + address - addr + length]
        raise KeyError(hex(address))

    def string(address):
        raw = b''
        while not raw.endswith(b'\0'):
            raw += at(address + len(raw), 1)
        return raw[:-1].decode()

    entry = 48  # enum type, id, name, base, size, align, priv on arm64
    address, size = symbol
    assert size % entry == 0, size
    heaps = []
    for i in range(size // entry):
        kind, ident, name = struct.unpack_from('<IIQ', at(address + i * entry, entry))
        heaps.append((kind, ident, string(name)))
    return heaps


def registered(heaps):
    """Heaps ion_drv_probe adds with the secure options off (from the source)."""
    keep = []
    for kind, ident, name in heaps:
        if kind == 13:
            # ION_HEAP_TYPE_MULTIMEDIA_SEC: ion_sec_heap_create returns NULL without
            # MTK_TRUSTED_MEMORY_SUBSYSTEM, MTK_SECURE_MEM_SUPPORT or the in-house TEE.
            continue
        # The carveout heap needs a base from the mediatek,ion-carveout-heap reserved-memory
        # node; the live DT has one (0x5000), so it's kept here. Whether the region is found
        # at boot isn't checked offline.
        keep.append((kind, ident, name))
    return keep


def select(heaps, mask):
    """ion_alloc's walk: plist by -id (highest id first), first heap whose bit is in the mask."""
    if mask == 0xffffffff:
        mask = 0x400
    for kind, ident, name in sorted(heaps, key=lambda h: -h[1]):
        if (1 << ident) & mask:
            return ident, name
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--vmlinux', type=Path, default=OUTPUT / 'vmlinux')
    args = parser.parse_args()
    failures = 0

    def report(ok, text):
        nonlocal failures
        failures += not ok
        print(('OK   ' if ok else 'FAIL ') + text)

    staging = SOURCE / 'drivers/staging/android'
    with tempfile.TemporaryDirectory(prefix='ion-abi-') as temporary:
        work = Path(temporary)
        (work / 'ion-abi.c').write_text(program())
        subprocess.run(['gcc', '-Wall', '-Werror', '-I', str(staging), '-o', str(work / 'ion-abi'),
                        str(work / 'ion-abi.c')], check=True)
        values = {}
        for line in subprocess.check_output([str(work / 'ion-abi')], text=True).splitlines():
            name, value, size = line.split()
            values[name] = (int(value, 16), int(size))
        # The NDK sysroot has the arm64 bionic and UAPI headers userspace builds with.
        arm64 = subprocess.run([str(LLVM / 'clang'), '--target=aarch64-linux-android30', '-fsyntax-only',
                                '-DARM64_CHECK', '-Wall', '-Werror', '-I', str(staging),
                                str(work / 'ion-abi.c')], capture_output=True, text=True)
    for name, (value, st, size) in IOCTLS.items():
        got = values[name]
        report(got == (value, size), f'{name} {got[0]:#x} ({st}, {got[1]} bytes); want {value:#x}, {size}')
    for name, value in MASKS.items():
        report(values[name][0] == value, f'{name} {values[name][0]:#x}; want {value:#x}')
    report(arm64.returncode == 0, 'arm64 compile of the same header asserts the same values'
           + ('' if arm64.returncode == 0 else ': ' + arm64.stderr.strip()))

    heaps = read_heaps(args.vmlinux)
    print('vmlinux ion_drv_platform_heaps: ' + ', '.join(f'{i} {n} (type {t})' for t, i, n in heaps))
    report(not any(i == 11 for _, i, _ in heaps), 'no heap id 11 (FB) in the table, as in stock')
    live = registered(heaps)
    print('registered with secure options off: ' + ', '.join(f'{i} {n}' for _, i, n in live))
    for mask, want in SELECT.items():
        got = select(live, mask)
        ident = got[0] if got else None
        text = f'heap_id_mask {mask:#x} -> ' + (f'heap {got[0]} {got[1]}' if got else 'no heap (-ENODEV)')
        report(ident == want, text + ('' if want is None else f'; want heap {want}'))
    got = select(live, 0xffffffff)
    report(got and got[0] == 10, 'heap_id_mask ~0 -> ' + (f'heap {got[0]} {got[1]}' if got else 'none') + ' (MTK maps ~0 to multimedia)')
    print(f'checks {failures and "failed" or "passed"}: {failures} failing')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
