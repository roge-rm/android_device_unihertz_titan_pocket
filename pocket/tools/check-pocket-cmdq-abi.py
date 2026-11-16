#!/usr/bin/env python3
"""Check the ported 4.14 CMDQ v3 and mdp_sync ioctl ABI; no device operations.

Compiles a probe against the ported headers in the 5.10 tree with the exact arm64 kernel
flags kbuild used for cmdq_driver.o, cmdq_helper_ext.o, mdp_ioctl_ex.o and mdp_fence.o (read
from their .cmd files in the first-boot build output), so the sizes are the arm64 ones;
compat sizes are not checked. The probe holds each ioctl number and its struct size, and the
CMDQ thread layout, as data, with static asserts on the wanted values; the values are read
back from the generated assembly on the host.

Wanted values are what libdpframework.so sends (evidence/display-hal/cmdq-open-and-secure-paths.md
and vendor-callsite-scan.txt). Run the first-boot image build first.
"""
import pocket_paths
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
OUTPUT = pocket_paths.build_root() / 'kernel-firstboot-5.10'
MTK = 'drivers/misc/mediatek'

# name: (vendor value or None if the vendor scan couldn't resolve it, struct or type, size)
GROUPS = {
    # /dev/mtk_cmdq ioctls handled in cmdq_driver.c, defined in cmdq/v3/cmdq_driver.h
    f'{MTK}/cmdq/v3/cmdq_driver.o': ('#include "cmdq_driver.h"', {
        'CMDQ_IOCTL_QUERY_USAGE': (0x40fc7804, 'struct cmdqUsageInfoStruct', 252),
        'CMDQ_IOCTL_QUERY_DTS': (0x5790780b, 'struct cmdqDTSDataStruct', 6032),
        'CMDQ_IOCTL_NOTIFY_ENGINE': (0x4008780c, 'uint64_t', 8),
    }),
    # /dev/mtk_cmdq MDP ioctls handled in mdp/mdp_ioctl_ex.c, defined in mdp/mdp_def_ex.h
    # (on top of cmdq_def.h, as mdp_ioctl_ex.c includes them)
    # Stock's thread layout (secure path on there): threads 8 to 10 for the secure world,
    # dynamic threads from 11, MDP_THREAD_START 10. Ours keeps it with the secure path off.
    # The shipped stock kernel loops mailbox channels to 24 and defaults to 16 threads
    # (cmdq_helper_mbox_register, cmdq_dev_init_device_tree in stock-recovered.elf); T has 56.
    f'{MTK}/cmdq/v3/cmdq_helper_ext.o': ('#include "cmdq_helper_ext.h"\n#include "cmdq_mdp_common.h"', {
        'CMDQ_DYNAMIC_THREAD_ID_START': (11, 'int', 4),
        'MDP_THREAD_START': (10, 'int', 4),
        'CMDQ_MAX_THREAD_COUNT': (24, 'int', 4),
        'CMDQ_DEFAULT_THREAD_COUNT': (16, 'int', 4),
    }),
    f'{MTK}/mdp/mdp_ioctl_ex.o': ('#include "cmdq_def.h"\n#include "mdp_def_ex.h"\n#include "mdp_ioctl_ex.h"', {
        'CMDQ_DYNAMIC_THREAD_ID_START': (11, 'int', 4),
        'CMDQ_IOCTL_ASYNC_EXEC': (0x41587814, 'struct mdp_submit', 344),
        'CMDQ_IOCTL_ASYNC_WAIT': (0x80307815, 'struct mdp_wait', 48),
        'CMDQ_IOCTL_ALLOC_READBACK_SLOTS': (0x40087816, 'struct mdp_readback', 8),
        'CMDQ_IOCTL_FREE_READBACK_SLOTS': (None, 'struct mdp_readback', 8),
        'CMDQ_IOCTL_READ_READBACK_SLOTS': (None, 'struct mdp_read_readback', None),
    }),
    # /dev/mdp_sync ioctls, defined in cmdq/mdp_sync/mdp_fence.c itself
    f'{MTK}/cmdq/mdp_sync/mdp_fence.o': (f'#include "{SOURCE}/{MTK}/cmdq/mdp_sync/mdp_fence.c"', {
        'MDP_SYNC_IOC_CREATE_FENCE': (0xc0285700, 'struct mdp_sync_create_fence_data', 40),
        'MDP_SYNC_IOC_INC': (0x40045701, '__u32', 4),
    }),
}


def kernel_command(obj):
    """The clang command kbuild used for obj, as a list, without the dep file and output."""
    cmd = (OUTPUT / obj).parent / ('.' + Path(obj).name + '.cmd')
    line = cmd.read_text().splitlines()[0]
    line = line.split(':=', 1)[1]
    words = shlex.split(line)
    out = []
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word.startswith('-Wp,-MMD'):
            continue
        if word == '-o':
            skip = True
            continue
        if word == '-c':
            continue
        out.append(word)
    assert out[-1].endswith('.c'), out[-1]
    return out[:-1]


def probe(header, checks):
    lines = [header, '']
    for name, (value, kind, size) in checks.items():
        if value is not None:
            lines.append(f'_Static_assert({name} == {value:#x}u, "{name}");')
        if size is not None:
            lines.append(f'_Static_assert(sizeof({kind}) == {size}, "{kind}");')
        lines.append(f'const unsigned long abi_{name}[2] __attribute__((used)) = '
                     f'{{ {name}, sizeof({kind}) }};')
    return '\n'.join(lines) + '\n'


def read_values(assembly):
    values = {}
    label = None
    for line in assembly.splitlines():
        m = re.match(r'^abi_(\w+):', line)
        if m:
            label = m.group(1)
            values[label] = []
            continue
        m = re.match(r'^\s+\.xword\s+(\d+)', line)
        if label and m:
            values[label].append(int(m.group(1)))
            if len(values[label]) == 2:
                label = None
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args()
    failures = 0

    def report(ok, text):
        nonlocal failures
        failures += not ok
        print(('OK   ' if ok else 'FAIL ') + text)

    with tempfile.TemporaryDirectory(prefix='cmdq-abi-') as temporary:
        work = Path(temporary)
        for obj, (header, checks) in GROUPS.items():
            source = work / (Path(obj).stem + '-abi.c')
            source.write_text(probe(header, checks))
            command = kernel_command(obj) + ['-S', '-o', '-', str(source)]
            result = subprocess.run(command, cwd=OUTPUT, capture_output=True, text=True)
            report(result.returncode == 0, f'arm64 compile with the {Path(obj).name} flags and static asserts'
                   + ('' if result.returncode == 0 else ':\n' + result.stderr.strip()))
            if result.returncode:
                continue
            values = read_values(result.stdout)
            for name, (value, kind, size) in checks.items():
                got = values.get(name)
                if not got or len(got) != 2:
                    report(False, f'{name} not found in the probe output')
                    continue
                text = f'{name} {got[0]:#010x} ({kind}, {got[1]} bytes)'
                if value is None:
                    print(f'INFO {text}; no vendor value to compare')
                    continue
                report((got[0], got[1]) == (value, size), f'{text}; want {value:#010x}, {size}')
    print(f'checks {failures and "failed" or "passed"}: {failures} failing')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
