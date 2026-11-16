#!/usr/bin/env python3
"""Lists which weak stand-ins in U's mtk-soc-pending-stubs.c are still weak in the first-boot vmlinux.

Reads the __weak names from the stub file and runs llvm-nm on vmlinux. A symbol shown as W still
links to the stub; T means a strong definition replaced it. AUDIO_PORT.md milestone 2 brings the
count to 0 and then deletes the stub file. No build or phone access.

--max-weak N fails when more than N are still weak (milestone 2 runs it with 0).
"""
import pocket_paths
import argparse, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STUBS = ROOT / 'tools/kernel-source/upgrade-5.10/sound/soc/mediatek/common_int/mtk-soc-pending-stubs.c'
BULK = pocket_paths.build_root()
VMLINUX = BULK / 'kernel-firstboot-5.10/vmlinux'
SDK = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk')))
NM = SDK / 'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm'


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--vmlinux', type=Path, default=VMLINUX)
    p.add_argument('--max-weak', type=int)
    a = p.parse_args()
    if not STUBS.exists():
        print(f'{STUBS.name} is gone, nothing to check')
        return 0
    names = re.findall(r'__weak\s+[^;{]*?\b(\w+)\s*\(', STUBS.read_text())
    assert names, 'no __weak symbols found in the stub file'
    out = subprocess.run([str(NM), str(a.vmlinux)], check=True, capture_output=True, text=True).stdout
    types = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[2] in names:
            types.setdefault(f[2], set()).add(f[1])
    weak = [n for n in names if types.get(n, set()) & {'W', 'w'}]
    missing = [n for n in names if n not in types]
    for n in names:
        print(f"{''.join(sorted(types[n])) if n in types else 'missing'} {n}")
    print(f'{len(weak)} of {len(names)} still weak, {len(missing)} missing')
    if missing:
        print('FAIL: not in vmlinux: ' + ', '.join(missing))
        return 1
    if a.max_weak is not None and len(weak) > a.max_weak:
        print(f'FAIL: more than {a.max_weak} weak')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
