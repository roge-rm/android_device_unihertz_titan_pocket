#!/usr/bin/env python3
"""Check the ported 4.14 /dev/mtk_disp_mgr and fb0 ioctl ABI; no device operations.

Compiles a probe against the ported video/include/disp_session.h and mtkfb.h with the exact
arm64 kernel flags kbuild used for mtk_disp_mgr.o and mtkfb.o (from their .cmd files in the
first-boot build output), so the sizes are the arm64 ones; compat sizes are not checked. The
probe holds each ioctl number and its struct size as data, with static asserts on the wanted
values, read back from the generated assembly. The helpers are the CMDQ ABI check's.

Wanted values are what the vendor HWC and fb users send (DISPLAY_HAL_CONTRACT.md: 17 disp_mgr
ioctls in 15 table rows, and the two fb0 ioctls). Run the first-boot image build first.
"""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('cmdq_abi', ROOT / 'tools/check-pocket-cmdq-abi.py')
cmdq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmdq)
VIDEO = 'drivers/misc/mediatek/video/mt6771/videox'

GROUPS = {
    # /dev/mtk_disp_mgr, handled in mtk_disp_mgr.c
    f'{VIDEO}/mtk_disp_mgr.o': ('#include <linux/ioctl.h>\n#include "disp_session.h"', {
        'DISP_IOCTL_CREATE_SESSION': (0x40244fc9, 'struct disp_session_config', 36),
        'DISP_IOCTL_DESTROY_SESSION': (0x40244fca, 'struct disp_session_config', 36),
        'DISP_IOCTL_TRIGGER_SESSION': (0x40244fcb, 'struct disp_session_config', 36),
        'DISP_IOCTL_PREPARE_INPUT_BUFFER': (0x40244fcc, 'struct disp_buffer_info', 36),
        'DISP_IOCTL_PREPARE_OUTPUT_BUFFER': (0x40244fcd, 'struct disp_buffer_info', 36),
        'DISP_IOCTL_SET_INPUT_BUFFER': (0x46c04fce, 'struct disp_session_input_config', 1728),
        'DISP_IOCTL_SET_OUTPUT_BUFFER': (0x40584fcf, 'struct disp_session_output_config', 88),
        'DISP_IOCTL_GET_SESSION_INFO': (0x40544fd0, 'struct disp_session_info', 84),
        'DISP_IOCTL_SET_SESSION_MODE': (0x40244fd1, 'struct disp_session_config', 36),
        'DISP_IOCTL_WAIT_FOR_VSYNC': (0x40184fd5, 'struct disp_session_vsync_config', 24),
        'DISP_IOCTL_GET_PRESENT_FENCE': (0x400c4fd9, 'struct disp_present_fence', 12),
        'DISP_IOCTL_GET_DISPLAY_CAPS': (0x409c4fdb, 'struct disp_caps_info', 156),
        'DISP_IOCTL_FRAME_CONFIG': (0x40584fdd, 'struct disp_session_output_config', 88),
        'DISP_IOCTL_QUERY_VALID_LAYER': (0x40484fde, 'struct disp_layer_info', 72),
        'DISP_IOCTL_WAIT_ALL_JOBS_DONE': (0x40044fe0, 'unsigned int', 4),
        'DISP_IOCTL_WAIT_DISP_SELF_REFRESH': (0x40044fe3, 'unsigned int', 4),
        'DISP_IOCTL_GET_MULTI_CONFIGS': (0x80244fe7, 'struct multi_configs', 36),
    }),
    # /dev/graphics/fb0, handled in mtkfb.c
    f'{VIDEO}/mtkfb.o': ('#include <linux/fb.h>\n#include "mtkfb.h"', {
        'FBIOBLANK': (0x4611, 'int', 4),
        'MTKFB_SET_AOD_POWER_MODE': (0x40044f1c, 'unsigned int', 4),
    }),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args()
    failures = 0

    def report(ok, text):
        nonlocal failures
        failures += not ok
        print(('OK   ' if ok else 'FAIL ') + text)

    with tempfile.TemporaryDirectory(prefix='disp-abi-') as temporary:
        work = Path(temporary)
        for obj, (header, checks) in GROUPS.items():
            source = work / (Path(obj).stem + '-abi.c')
            source.write_text(cmdq.probe(header, checks))
            command = cmdq.kernel_command(obj) + ['-S', '-o', '-', str(source)]
            result = subprocess.run(command, cwd=cmdq.OUTPUT, capture_output=True, text=True)
            report(result.returncode == 0, f'arm64 compile with the {Path(obj).name} flags and static asserts'
                   + ('' if result.returncode == 0 else ':\n' + result.stderr.strip()))
            if result.returncode:
                continue
            values = cmdq.read_values(result.stdout)
            for name, (value, kind, size) in checks.items():
                got = values.get(name)
                if not got or len(got) != 2:
                    report(False, f'{name} not found in the probe output')
                    continue
                report((got[0], got[1]) == (value, size),
                       f'{name} {got[0]:#010x} ({kind}, {got[1]} bytes); want {value:#010x}, {size}')
    print(f'checks {failures and "failed" or "passed"}: {failures} failing')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
