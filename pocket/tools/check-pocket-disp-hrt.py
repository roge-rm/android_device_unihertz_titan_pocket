#!/usr/bin/env python3
"""Check that the built DISP layering rule picks stock's HRT table and level; no device operations.

Stock (MTK_DRAMC on, LPDDR4X, 2 EMI channels, 3600 data rate, 720x720 panel) picks
HRT_BOUND_TYPE_LP4_HD ({900, 900, 900, 1350}) and max_hrt_level HRT_LEVEL_LEVEL2. Without MTK_DRAMC the
layering rule keeps HRT_BOUND_TYPE_LP4 ({500, 600, 600, 600}) and level 3.

Reads the first-boot build's layering_rule.o:
- preprocessed with its own kbuild flags, the get_ddr_type() and dram_steps_freq() branches are in
- layering_rule_senario_decision stores 5 (LP4_HD) when the width is under 800, with no
  get_ddr_type or get_emi_ch_num call left (the mtk_dramc.h answers fold in)
- layering_rule_set_max_hrt_level sets the flag with no branch, and layering_rule_get_max_hrt_level
  turns a set flag into 2 (LEVEL2)
Run the first-boot image build first.
"""
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('cmdq_abi', ROOT / 'tools/check-pocket-cmdq-abi.py')
cmdq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmdq)
OBJ = 'drivers/misc/mediatek/video/mt6771/videox/layering_rule.o'
LLVM = Path.home() / 'Android/Sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'


def function(dis, name):
    m = re.search(r'^[0-9a-f]+ <%s>:\n(.*?)(?=^[0-9a-f]+ <|\Z)' % re.escape(name), dis, re.M | re.S)
    assert m, name
    return [l.split(None, 1)[1] for l in m.group(1).splitlines() if re.match(r'\s+[0-9a-f]+:\s', l)], m.group(1)


def main():
    failures = 0

    def report(ok, text):
        nonlocal failures
        failures += not ok
        print(('OK   ' if ok else 'FAIL ') + text)

    command = cmdq.kernel_command(OBJ)
    source = cmdq.SOURCE / OBJ.replace('.o', '.c')
    pre = subprocess.run(command + ['-E', '-o', '-', str(source)], cwd=cmdq.OUTPUT, capture_output=True,
                         text=True, check=True).stdout
    report('get_ddr_type() == TYPE_LPDDR3' in pre and 'dram_steps_freq(0) == 3600' in pre,
           'CONFIG_MTK_DRAMC branches compiled in')

    dis = subprocess.run([str(LLVM / 'llvm-objdump'), '-dr', '--no-show-raw-insn', str(cmdq.OUTPUT / OBJ)],
                         capture_output=True, text=True, check=True).stdout
    insns, body = function(dis, 'layering_rule_senario_decision')
    report('get_ddr_type' not in body and 'get_emi_ch_num' not in body, 'DRAM queries folded to constants')
    text = '\n'.join(insns)
    report(re.search(r'cmp\s+w0, #0x320\n\s*b\.ge\s+\S+ <[^>]+>\n\s*mov\s+w8, #0x5\b', text) is not None,
           'width under 800 picks bound table 5 (HRT_BOUND_TYPE_LP4_HD)')
    insns, _ = function(dis, 'layering_rule_set_max_hrt_level')
    report(not any(re.match(r'(b|bl|b\.\w+|cbn?z|tbn?z)\s', i) for i in insns)
           and any(re.match(r'mov\s+w\d+, #0x1\b', i) for i in insns),
           'layering_rule_set_max_hrt_level sets the LEVEL2 flag unconditionally')
    insns, _ = function(dis, 'layering_rule_get_max_hrt_level')
    report(any(re.match(r'mov\s+w8, #0x2\b', i) for i in insns) and any(re.match(r'cinc\s+w0, w8, eq', i) for i in insns),
           'layering_rule_get_max_hrt_level returns 2 (HRT_LEVEL_LEVEL2) once set, 3 before')
    print(f'checks {failures and "failed" or "passed"}: {failures} failing')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
