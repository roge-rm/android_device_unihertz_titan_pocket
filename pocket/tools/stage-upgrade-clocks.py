#!/usr/bin/env python3
"""Stage the pinned MT6771 clock source for an isolated 5.10 compile probe."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad'
NEW = ROOT / 'tools/kernel-source/upgrade-5.10'


def main():
    files = ['drivers/clk/mediatek/clk-mt6771.c', 'include/dt-bindings/clock/mt6771-clk.h']
    if any((NEW / p).exists() for p in files):
        raise SystemExit('Clock prototype already staged; refusing to overwrite edits')
    for p in files:
        shutil.copyfile(OLD / p, NEW / p)
    path = NEW / 'drivers/clk/mediatek/Kconfig'
    text = path.read_text()
    if text.count('\nendmenu\n') != 1:
        raise SystemExit('Unexpected clock Kconfig layout')
    text = text.replace('\nendmenu\n', '\nconfig COMMON_CLK_MT6771\n\tbool "MT6771 clocks (forward-port probe)"\n\tdepends on ARCH_MEDIATEK || COMPILE_TEST\n\tselect COMMON_CLK_MEDIATEK\n\thelp\n\t  Experimental port; power/domain/boot behavior remains unqualified.\n\nendmenu\n')
    path.write_text(text)
    with (NEW / 'drivers/clk/mediatek/Makefile').open('a') as f:
        f.write('\nobj-$(CONFIG_COMMON_CLK_MT6771) += clk-mt6771.o\n')
    record = {'source_pin': OLD.name, 'workspace': str(NEW),
              'initial_imports': [{'path': p, 'sha256': hashlib.sha256((NEW / p).read_bytes()).hexdigest()} for p in files],
              'status': 'Unmodified source imported; compile/API adaptation pending'}
    (ROOT / 'evidence/kernel-upgrade/clocks-staging.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Imported MT6771 clock definitions and source; compile probe pending')


if __name__ == '__main__':
    main()
