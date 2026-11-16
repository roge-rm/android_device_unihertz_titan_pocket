#!/usr/bin/env python3
"""Stage the first MT6771 pinctrl forward port in the isolated 5.10 copy.

Preserves the SoC pin/register tables and atomic SET/CLR/MWR semantics from the
pinned 4.14 source. The staged driver requires a reviewed DT resource overlay.
"""
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad'
NEW = ROOT / 'tools/kernel-source/upgrade-5.10'
REL = Path('drivers/pinctrl/mediatek')


def main():
    if not NEW.is_dir() or (NEW / '.git').exists():
        raise SystemExit('Prepare independent workspace first')
    driver = NEW / REL / 'pinctrl-mt6771.c'
    if driver.exists():
        raise SystemExit('MT6771 driver already staged; refusing to overwrite edits')
    originals = {}

    def edit(relative, old, new):
        path = NEW / relative
        text = path.read_text()
        originals.setdefault(str(relative), text)
        if text.count(old) != 1:
            raise ValueError('Ambiguous edit in ' + str(relative))
        path.write_text(text.replace(old, new, 1))

    for filename in ['pinctrl-mt6771.c', 'pinctrl-mtk-mt6771.h']:
        shutil.copyfile(OLD / REL / filename, NEW / REL / filename)
        originals[str(REL / filename)] = ''

    edit(REL / 'pinctrl-mt6771.c', '#include "pinctrl-mtk-mt6771.h"',
         '#include <linux/module.h>\n\n#include "pinctrl-mtk-mt6771.h"')

    header = REL / 'pinctrl-mtk-common-v2.h'
    edit(header, '\tbool\t\t\t\ties_present;',
         '\tbool\t\t\t\ties_present;\n\t/* MT6771 GPIO SET/CLR and MODE modification-write registers. */\n\tbool\t\t\t\trace_free_access;')

    old_common = (OLD / REL / 'pinctrl-mtk-common-v2.c').read_text()
    functions = []
    for name in ['mtk_hw_set_value_race_free', 'mtk_hw_set_mode_race_free']:
        start = old_common.index('void ' + name + '(')
        end = old_common.index('\n}\n', start) + 3
        body = 'static ' + old_common[start:end]
        for macro in ['SET_OFFSET', 'CLR_OFFSET', 'MWR_OFFSET']:
            body = body.replace(macro, 'MT6771_GPIO_' + macro)
        functions.append(body)
    addition = ('/* Preserved from the pinned MT6771 BSP; enabled only per SoC. */\n'
                '#define MT6771_GPIO_SET_OFFSET 0x4\n'
                '#define MT6771_GPIO_CLR_OFFSET 0x8\n'
                '#define MT6771_GPIO_MWR_OFFSET 0xc\n\n' + '\n'.join(functions) + '\n')
    common = REL / 'pinctrl-mtk-common-v2.c'
    edit(common, 'static int mtk_hw_pin_field_lookup(', addition + 'static int mtk_hw_pin_field_lookup(')
    edit(common,
         '\tif (!pf.next)\n\t\tmtk_rmw(hw, pf.index, pf.offset, pf.mask << pf.bitpos,\n\t\t\t(value & pf.mask) << pf.bitpos);\n\telse',
         '\tif (!pf.next) {\n\t\tif (hw->soc->race_free_access) {\n\t\t\tif (field == PINCTRL_PIN_REG_MODE)\n\t\t\t\tmtk_hw_set_mode_race_free(hw, &pf, value);\n\t\t\telse\n\t\t\t\tmtk_hw_set_value_race_free(hw, &pf, value);\n\t\t} else {\n\t\t\tmtk_rmw(hw, pf.index, pf.offset, pf.mask << pf.bitpos,\n\t\t\t\t(value & pf.mask) << pf.bitpos);\n\t\t}\n\t} else')
    # Names match the generated resource overlay, in the original reg_bases order.
    edit(REL / 'pinctrl-mt6771.c', 'static const struct mtk_pin_soc mt6771_data = {',
         'static const char * const mt6771_base_names[] = {\n\t"gpio", "iocfg0", "iocfg1", "iocfg2", "iocfg3",\n\t"iocfg4", "iocfg5", "iocfg6", "iocfg7",\n};\n\nstatic const struct mtk_pin_soc mt6771_data = {')
    edit(REL / 'pinctrl-mt6771.c', '\t.race_free_access = true,',
         '\t.race_free_access = true,\n\t.ies_present = true,\n\t.base_names = mt6771_base_names,\n\t.nbase_names = ARRAY_SIZE(mt6771_base_names),')
    for old, new in [('mtk_pinconf_drive_set_direct_val', 'mtk_pinconf_drive_set_raw'),
                     ('mtk_pinconf_drive_get_direct_val', 'mtk_pinconf_drive_get_raw'),
                     ('mtk_eint_pm_ops_v2', 'mtk_paris_pinctrl_pm_ops')]:
        edit(REL / 'pinctrl-mt6771.c', old, new)
    with driver.open('a') as stream:
        stream.write('\nMODULE_LICENSE("GPL v2");\nMODULE_DESCRIPTION("MediaTek MT6771 pinctrl forward-port probe");\n')
    edit(REL / 'Kconfig', '\nendmenu\n',
         '\nconfig PINCTRL_MT6771\n\tbool "MediaTek MT6771 pin control (forward-port probe)"\n\tdepends on OF && (ARM64 || COMPILE_TEST)\n\tselect PINCTRL_MTK_PARIS\n\thelp\n\t  Experimental MT6771 port; requires the reviewed Pocket DT resources.\n\nendmenu\n')
    makefile = NEW / REL / 'Makefile'
    originals[str(REL / 'Makefile')] = makefile.read_text()
    with makefile.open('a') as stream:
        stream.write('\nobj-$(CONFIG_PINCTRL_MT6771) += pinctrl-mt6771.o\n')

    patch = []
    for relative, before in originals.items():
        after = (NEW / relative).read_text()
        patch.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                      fromfile='a/' + relative if before else '/dev/null', tofile='b/' + relative))
    patchdir = ROOT / 'patches/kernel-upgrade-5.10'
    patchdir.mkdir(parents=True, exist_ok=True)
    patchpath = patchdir / '0001-mt6771-pinctrl-forward-port.patch'
    patchpath.write_text(''.join(patch))
    record = {'source_pin': OLD.name, 'workspace': str(NEW), 'patch': str(patchpath),
              'patch_sha256': hashlib.sha256(patchpath.read_bytes()).hexdigest(),
              'changes': [{'path': p, 'sha256': hashlib.sha256((NEW / p).read_bytes()).hexdigest()}
                          for p in originals],
              'scope': 'Pinctrl prototype; no complete SoC support, hardware test or boot claim'}
    (ROOT / 'evidence/kernel-upgrade/pinctrl-staging.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Staged MT6771 pinctrl, original tables and atomic register writes; patch exported')


if __name__ == '__main__':
    main()
