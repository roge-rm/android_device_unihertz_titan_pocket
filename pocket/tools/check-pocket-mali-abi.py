#!/usr/bin/env python3
"""Check the ported Mali r25p0 kbase ioctl ABI; no device operations.

Compiles a probe for arm64 with the NDK clang (Android sysroot, as the user side builds) from the
5.10 tree's mali_kbase_ioctl.h, which pulls in jm/mali_kbase_jm_ioctl.h. The probe holds each
KBASE_IOCTL_* value as data, with static asserts on the wanted values and on BASE_UK_VERSION
11.27; the values are read back from the generated assembly.

Wanted values are evidence/display-hal/kernel-ioctl-match.txt: the 4.14 kernel list (40) and the
26 that libGLES_mali.so (lib64) sends. The 40 were compiled from T's copy of the same headers, which
the port leaves unchanged, so matching them only shows the headers weren't edited; the 26 from the
vendor library are the real test.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
KBASE = SOURCE / 'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard'
LLVM = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk'))) / 'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
MATCH = ROOT / 'evidence/display-hal/kernel-ioctl-match.txt'
UK = (11, 27)


def sections():
    out, cur = {}, None
    for line in MATCH.read_text().splitlines():
        if line.startswith('#'):
            cur = line
            out[cur] = {}
        elif cur and len(line.split()) == 2 and line.split()[1].startswith('KBASE_IOCTL_'):
            value, name = line.split()
            out[cur][name] = int(value, 16)
    kmd = next(v for k, v in out.items() if 'mali-r25p0' in k)
    user = next(v for k, v in out.items() if 'libGLES_mali.so' in k)
    return kmd, user


def main():
    kmd, user = sections()
    assert len(kmd) == 40 and len(user) == 26, (len(kmd), len(user))
    assert all(kmd[n] == v for n, v in user.items()), 'user list disagrees with the kernel list'
    names = sorted(kmd)
    probe = ['#include "mali_kbase_ioctl.h"',
             f'_Static_assert(BASE_UK_VERSION_MAJOR == {UK[0]} && BASE_UK_VERSION_MINOR == {UK[1]}, "UK version");',
             'const unsigned long long uk[2] = {BASE_UK_VERSION_MAJOR, BASE_UK_VERSION_MINOR};']
    probe += [f'_Static_assert({n} == {kmd[n]:#x}u, "{n}");' for n in names]
    probe.append('const unsigned long long values[] = {' + ', '.join(names) + '};')
    with tempfile.TemporaryDirectory(prefix='mali-abi-') as tmp:
        src = Path(tmp) / 'probe.c'
        src.write_text('\n'.join(probe) + '\n')
        asm = Path(tmp) / 'probe.s'
        subprocess.run([str(LLVM / 'clang'), '--target=aarch64-linux-android30', '-std=gnu11', '-O0', '-S',
                        f'-I{KBASE}', '-o', str(asm), str(src)], check=True)
        text = asm.read_text()
    words = [int(w, 0) for w in re.findall(r'^\s*\.xword\s+(\S+)', text, re.M)]
    assert len(words) == 2 + len(names), len(words)
    got_uk, got = tuple(words[:2]), dict(zip(names, words[2:]))
    bad = {n: (hex(got[n]), hex(kmd[n])) for n in names if got[n] != kmd[n]}
    if bad or got_uk != UK:
        print('mismatch:', bad, got_uk, file=sys.stderr)
        sys.exit(1)
    for n in sorted(user, key=user.get):
        print(f'{got[n]:08x} {n}')
    print(f'arm64: BASE_UK_VERSION {got_uk[0]}.{got_uk[1]}; all {len(user)} libGLES_mali.so ioctls match '
          f'kernel-ioctl-match.txt (and the {len(kmd)} kernel values from the unchanged T headers)')


if __name__ == '__main__':
    main()
