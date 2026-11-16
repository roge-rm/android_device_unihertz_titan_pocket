#!/usr/bin/env python3
"""Table check for the MT6370 port (charger milestone 2); no build, image or phone access.

Checks, from the sources and the stock DT:
- every MFD cell compatible in U's mt6370_pmu_subdevs.c has a stock /mt6370_pmu_dts child,
  and each built subdevice driver lists that compatible;
- the i2c driver matches the stock subpmic_pmu@34 node and nothing else in U claims these compatibles;
- the DSV driver reads the mt6370_dsvp and mt6370_dsvn children, whose regulator-name is
  dsv_pos and dsv_neg, the names T's display bias code (lcm_pmic.c) asks for with regulator_get(NULL, ...);
- U's regulator core resolves a NULL-device get by the rdev name, which is constraints->name
  (regulator-name) first;
- what keeps the panel bias on until a consumer exists.
Writes evidence/kernel-upgrade/mt6370-dsv-check.json.
"""
import pocket_paths
import glob, hashlib, json, os, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
U = ROOT / 'tools/kernel-source/upgrade-5.10'
T = Path(glob.glob(str(ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5*'))[0])
DEFAULT_DTS = ROOT / 'evidence/device-tree/stock-dt-match/dts/live-fdt-20230105.dts'
# POCKET_MT6370_STOCK_DTS points the check at another copy (a doctored one to test it); no record is written then.
STOCK_DTS = Path(os.environ.get('POCKET_MT6370_STOCK_DTS', str(DEFAULT_DTS)))
BOARD_DTS = pocket_paths.build_root() / 'artifacts/firstboot-5.10/board/keyboard.dts'
FRAGMENT = ROOT / 'configs/kernel-firstboot-5.10.fragment'
PACKAGER = ROOT / 'tools/package-pocket-boot.py'
RECORD = ROOT / 'evidence/kernel-upgrade/mt6370-dsv-check.json'
MT = 'drivers/misc/mediatek/pmic/mt6370/'
DRIVERS = {'mediatek,mt6370_pmu_core': 'mt6370_pmu_core.c', 'mediatek,mt6370_pmu_fled1': 'mt6370_pmu_fled.c',
           'mediatek,mt6370_pmu_fled2': 'mt6370_pmu_fled.c', 'mediatek,mt6370_pmu_ldo': 'mt6370_pmu_ldo.c',
           'mediatek,mt6370_pmu_rgbled': 'mt6370_pmu_rgbled.c', 'mediatek,mt6370_pmu_bled': 'mt6370_pmu_bled.c',
           'mediatek,mt6370_pmu_dsv': 'mt6370_pmu_dsv.c', 'mediatek,mt6370_pmu_charger': 'mt6370_pmu_charger.c'}
LEFT_OUT = {}

results = []
def check(name, ok, detail=''):
    results.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(('OK  ' if ok else 'FAIL') + ' ' + name + (': ' + detail if detail else ''))

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def block(text, header):
    """Body of the first node whose line is header + ' {', by brace depth."""
    start = text.index(header + ' {')
    depth = 0
    for i in range(start, len(text)):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: return text[start:i + 1]
    raise ValueError(header)

def children(body):
    """Direct child nodes of a dts block: name -> body."""
    out = {}
    inner = body[body.index('{') + 1:]
    i = 0
    while True:
        m = re.search(r'\n\t+([A-Za-z0-9_,@.-]+) \{', inner[i:])
        if not m: return out
        s = i + m.start(); depth = 0
        for j in range(s, len(inner)):
            if inner[j] == '{': depth += 1
            elif inner[j] == '}':
                depth -= 1
                if depth == 0: break
        out[m.group(1)] = inner[s:j + 1]; i = j + 1

def own_props(body):
    """Properties of the block's own node (depth 1 only): name -> raw value, or True for a flag."""
    out = {}; depth = 0
    for line in body.split('\n'):
        s = line.strip()
        if s.endswith('{'):
            depth += 1; continue
        if s.startswith('}'):
            depth -= 1; continue
        if depth == 1 and s.endswith(';'):
            name, _, value = s[:-1].partition(' = ')
            out[name] = value if value else True
    return out

def subtree(body, path=''):
    """Every node in the block, the block itself first: (path, body)."""
    out = [(path or '.', body)]
    for n, b in children(body).items():
        out += subtree(b, (path + '/' if path else '') + n)
    return out

def okay(body):
    return own_props(body).get('status', '"okay"') == '"okay"'

def prop(body, name):
    m = re.search(r'\n\t+' + re.escape(name) + r' = "([^"]*)";', body)
    return m.group(1) if m else None

def main():
    stock = STOCK_DTS.read_text()
    pmu = block(stock, '\tmt6370_pmu_dts')
    kids = children(pmu)
    stock_compat = {prop(b, 'compatible'): n for n, b in kids.items() if prop(b, 'compatible')}
    check('stock /mt6370_pmu_dts is okay and an interrupt controller',
          okay(pmu) and own_props(pmu).get('interrupt-controller') is True, str(own_props(pmu).get('status')))
    off = [p for p, b in subtree(pmu)[1:] if not okay(b)]
    check('stock children and their regulator nodes are okay', not off, ', '.join(off))

    cells = re.findall(r'\.of_compatible = "([^"]+)"', (U / MT / 'mt6370_pmu_subdevs.c').read_text())
    check('U subdevs cells match the stock children', sorted(set(cells)) == sorted(stock_compat), ', '.join(cells))
    for c in cells:
        if c in LEFT_OUT:
            check('cell ' + c + ' left out', not (U / MT / 'mt6370_pmu_charger.c').exists(), LEFT_OUT[c]); continue
        src = (U / MT / DRIVERS[c]).read_text()
        # fled1/fled2 bind by platform id name; the rest by of_match_table
        ok = ('.compatible = "%s"' % c) in src or (c.startswith('mediatek,mt6370_pmu_fled') and '"mt6370_pmu_fled"' in src)
        check('driver for ' + c, ok, DRIVERS[c])

    i2c = (U / MT / 'mt6370_pmu_i2c.c').read_text()
    bus = block(stock, '\ti2c@11017000')
    node = children(bus)['subpmic_pmu@34']
    check('i2c driver matches stock subpmic_pmu@34', '.compatible = "%s"' % prop(node, 'compatible') in i2c
          and 'of_find_node_by_name(NULL, "mt6370_pmu_dts")' in i2c, prop(node, 'compatible'))
    others = []
    for path in list(U.glob('drivers/**/*.c')) + list(U.glob('arch/arm64/boot/dts/**/*.dts*')):
        rel = str(path.relative_to(U))
        if rel.startswith(MT): continue
        text = path.read_text(errors='ignore')
        if 'mediatek,subpmic_pmu' in text or 'mediatek,mt6370' in text or '"mt6370_pmu' in text:
            others.append(rel)
    check('no other U driver or dts claims the MT6370 compatibles', not others, ', '.join(others))

    dsv = kids['dsv']; dk = children(dsv)
    src = (U / MT / 'mt6370_pmu_dsv.c').read_text()
    for child, name in (('mt6370_dsvp', 'dsv_pos'), ('mt6370_dsvn', 'dsv_neg')):
        check('DSV reads child ' + child, '"%s"' % child in src)
        check(child + ' regulator-name is ' + name, prop(dk[child], 'regulator-name') == name)
        flags = [f for f in ('regulator-boot-on', 'regulator-always-on') if f in dk[child]]
        check(child + ' has no boot-on or always-on in stock DT', not flags)
    check('DSV registers through of_get_regulator_init_data', 'of_get_regulator_init_data(dev, sub_np, NULL)' in src)

    lcm = (T / 'drivers/misc/mediatek/lcm/lcm_pmic.c').read_text()
    gets = re.findall(r'regulator_get\(NULL, "([^"]+)"\)', lcm)
    check('T lcm_pmic.c looks up dsv_pos and dsv_neg with a NULL device', sorted(set(gets)) == ['dsv_neg', 'dsv_pos'], ', '.join(gets))
    check('T lcm_pmic.c defines agold_display_bias_enable', 'int agold_display_bias_enable(int pos_factor, int neg_factor)' in lcm)
    r63308 = (T / 'drivers/misc/mediatek/lcm/R63308_CASCADEMDZ40/R63308_CASCADEMDZ40.c').read_text()
    check('R63308 LCM calls agold_display_bias_enable', 'agold_display_bias_enable(' in r63308)

    core = (U / 'drivers/regulator/core.c').read_text()
    look = core[core.index('static struct regulator_dev *regulator_dev_lookup('):]
    look = look[:look.index('\n}\n')]
    check('U regulator_dev_lookup falls back to regulator_lookup_by_name', 'r = regulator_lookup_by_name(supply);' in look
          and 'if (dev && dev->of_node)' in look)
    check('U regulator_match compares rdev_get_name', 'return strcmp(rdev_get_name(r), data) == 0;' in core)
    check('U rdev_get_name prefers constraints->name',
          re.search(r'if \(rdev->constraints && rdev->constraints->name\)\s*return rdev->constraints->name;', core) is not None)
    of_reg = (U / 'drivers/regulator/of_regulator.c').read_text()
    check('U of_regulator gives status control unless always-on',
          re.search(r'if \(!constraints->always_on\)[^\n]*\n\s*constraints->valid_ops_mask \|= REGULATOR_CHANGE_STATUS;', of_reg) is not None)

    # What keeps the bias on until a consumer exists
    board = BOARD_DTS.read_text()
    bk = children(block(board, '\tmt6370_pmu_dts'))
    on = 'status = [6f 6b 61 79 00]'
    dsv_on = on in bk['dsv'] and on in block(board, '\tmt6370_pmu_dts').split('\t\tcore {')[0]
    bus_on = on in block(board, '\ti2c@11017000').split('usb_type_c@4e')[0]
    check('first-boot board: i2c5, /mt6370_pmu_dts and dsv are enabled, so dsv_pos and dsv_neg register', dsv_on and bus_on)
    check('first-boot cmdline keeps regulator_ignore_unused', 'regulator_ignore_unused' in PACKAGER.read_text()
          and 'CONFIG_DEBUG_KERNEL=y' in FRAGMENT.read_text())

    failed = [r for r in results if not r['ok']]
    if STOCK_DTS != DEFAULT_DTS:
        print(f'checks {len(results)} failures {len(failed)} (test copy {STOCK_DTS}, no record)')
        raise SystemExit(1 if failed else 0)
    RECORD.write_text(json.dumps({
        'inputs': {str(p.relative_to(ROOT)) if str(p).startswith(str(ROOT)) else str(p): sha(p) for p in
                   [STOCK_DTS, BOARD_DTS, U / MT / 'mt6370_pmu_subdevs.c', U / MT / 'mt6370_pmu_dsv.c', U / MT / 'mt6370_pmu_i2c.c',
                    T / 'drivers/misc/mediatek/lcm/lcm_pmic.c', U / 'drivers/regulator/core.c', U / 'drivers/regulator/of_regulator.c']},
        'checks': results, 'failures': len(failed), 'phone_accessed': False,
        'limits': ['Source and DT text only; nothing built into a test or run on the phone',
                   'Bias stays on today because nothing registers it; once the DT is enabled, regulator_ignore_unused or the display consumer must hold it']},
        indent=2) + '\n')
    print(f'checks {len(results)} failures {len(failed)} report {RECORD}')
    raise SystemExit(1 if failed else 0)

if __name__ == '__main__':
    main()
