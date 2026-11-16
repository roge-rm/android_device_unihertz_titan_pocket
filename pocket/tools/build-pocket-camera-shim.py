#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the camera static metadata shim and its camerahalserver launcher.

libpocketcammeta.so wraps sort_camera_metadata() to fix camera 0's RAW_SENSOR
durations; camerahalserver-pocket links it and runs the stock camerahalserver's
main() in-process (CAMERA_PORT.md, "RAW durations"). Both go into vendor overlay v11.
Output: build/camera-shim/, with record.json.
"""
import pocket_paths
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SRC = pocket_paths.DEVICE_TREE / 'camera'
OUT = ROOT / 'build/camera-shim'
LLVM = pocket_paths.ndk_bin()
# Vendor is Android 11; libc, libdl and liblog are LLNDK there.
TARGET = 'aarch64-linux-android30'
FLAGS = ['-O2', '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
         '-Wl,--build-id=sha1', '-Wl,-z,relro,-z,now', '-Wl,--hash-style=gnu']
OUTPUTS = {
    # -z global sets DF_1_GLOBAL: bionic's global group is the main executable, LD_PRELOADs and
    # libraries with that flag, and it is searched first for every symbol lookup. A plain DT_NEEDED
    # of the launcher isn't in it, so without the flag libmtkcam_metastore would bind to the VNDK copy.
    'libpocketcammeta.so': (['pocket_cammeta.c'], ['-shared', '-fPIC', '-Wl,-soname,libpocketcammeta.so',
                                                  '-Wl,-z,global', '-ldl', '-llog']),
    'camerahalserver-pocket': (['camerahalserver_pocket.c'], ['-fPIE', '-pie', '-Wl,--no-as-needed',
                                                              '-L{out}', '-lpocketcammeta', '-ldl', '-llog']),
}


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def needed(path):
    """(DT_NEEDED list, defined global functions, DT_FLAGS_1 words) from llvm-readelf."""
    out = subprocess.run([LLVM / 'llvm-readelf', '-d', '--dyn-syms', path], capture_output=True, text=True,
                         check=True).stdout
    libs = [l.split('[', 1)[1].rstrip(']') for l in out.splitlines() if '(NEEDED)' in l]
    exported = sorted({l.split()[-1] for l in out.splitlines()
                       if ' FUNC ' in l and ' GLOBAL ' in l and ' UND ' not in l})
    flags1 = next((l.split('(FLAGS_1)', 1)[1].split() for l in out.splitlines() if '(FLAGS_1)' in l), [])
    return libs, exported, flags1


def global_group_definer(exe, libs, symbol):
    """First object that defines `symbol` in bionic's global group for this launcher.

    Models linker_main.cpp (the main executable gets DF_1_GLOBAL) and
    android_namespace_t::get_global_group (main executable, LD_PRELOADs, DF_1_GLOBAL
    libraries, in load order; the launcher has no LD_PRELOAD). Lookups from any later
    library search this group before their own local group.
    """
    group = [exe] + [n for n in libs[exe]['needed'] if n in libs and 'GLOBAL' in libs[n]['flags1']]
    return next((o for o in group if symbol in libs[o]['exported']), None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--output', type=Path, default=OUT)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    record = {'schema': 1, 'clang': str(LLVM / 'clang'), 'target': TARGET, 'outputs': {}}
    for name, (sources, extra) in OUTPUTS.items():
        dst = args.output / name
        cmd = [str(LLVM / 'clang'), f'--target={TARGET}', *FLAGS, *[str(SRC / s) for s in sources],
               *[x.format(out=args.output) for x in extra], '-o', str(dst)]
        subprocess.run(cmd, check=True)
        subprocess.run([LLVM / 'llvm-strip', '--strip-unneeded', dst], check=True)
        libs, exported, flags1 = needed(dst)
        bad = set(libs) - {'libc.so', 'libdl.so', 'liblog.so', 'libm.so', 'libpocketcammeta.so'}
        if bad:
            raise SystemExit(f'{name} needs {sorted(bad)}, which is neither LLNDK nor the shim')
        if not name.endswith('.so') and libs[:1] != ['libpocketcammeta.so']:
            raise SystemExit(f'{name} needs {libs}; the shim has to come first')
        if name.endswith('.so') and exported != ['sort_camera_metadata']:
            raise SystemExit(f'{name} exports {exported}; only sort_camera_metadata is expected')
        if name.endswith('.so') and 'GLOBAL' not in flags1:
            raise SystemExit(f'{name} has DT_FLAGS_1 {flags1}, without GLOBAL it is not in the global group')
        record['outputs'][name] = {'path': str(dst), 'sha256': sha256(dst), 'bytes': dst.stat().st_size,
                                   'needed': libs, 'exported': exported, 'flags1': flags1,
                                   'sources': {str(SRC / s): sha256(SRC / s) for s in sources}}
    objs = {n: {'needed': o['needed'], 'exported': o['exported'], 'flags1': o['flags1']}
            for n, o in record['outputs'].items()}
    definer = global_group_definer('camerahalserver-pocket', objs, 'sort_camera_metadata')
    if definer != 'libpocketcammeta.so':
        raise SystemExit(f'sort_camera_metadata resolves first to {definer} in the global group, not the shim')
    record['global_group_sort_camera_metadata'] = definer
    (args.output / 'record.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record, indent=1))


if __name__ == '__main__':
    main()
