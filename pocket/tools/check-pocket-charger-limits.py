#!/usr/bin/env python3
"""Check the ported charger limits against CHARGER_PORT.md; offline, no phone access.

- the first-boot board (keyboard.dtb) /charger and /mt6370_pmu_dts/charger values equal the
  "Stock charging limits" table: currents, MIVR, VBUS max, the 0/6 and 53/59 C cut-offs
- mtk_charger.c sets the stock overrides (CV 4.4 V, DCP 2 A / 2 A, TA 2 A, SDP 500 mA) after the DT
  reads, and nothing else can raise CV (software JEITA off in DT, no BIF so no dynamic CV)
- the agold current steps in mtk_switch_charging.c, compiled on the host with a small harness,
  lower each charger type's limit to 800 mA from 41 C, 80 mA from 45 C above 75 %, the thermal
  limit only above 58 C and 400 mA below 15 C, never raising one; the board thermistor
  (SoC AUXADC channel 0, NTC table 7) gives m C, or 41 C when the read fails
- the same constants in the built objects, and that the built probes are not cut short
Writes evidence/kernel-upgrade/charger-limits-check.json.
"""
import pocket_paths
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb'
U = ROOT / 'tools/kernel-source/upgrade-5.10'
CHG = U / 'drivers/power/supply/mediatek/charger'
DOC = ROOT / 'CHARGER_PORT.md'
RECORD = ROOT / 'evidence/kernel-upgrade/charger-limits-check.json'

checks = []


def check(name, ok, detail=''):
    checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(('OK   ' if ok else 'FAIL ') + name + (': ' + str(detail) if detail else ''))


def table():
    """The limits table from CHARGER_PORT.md, as {setting: [numbers]}."""
    text = DOC.read_text()
    section = text.split('## Stock charging limits', 1)[1].split('\n## ', 1)[0]
    rows = {}
    for line in section.splitlines():
        m = re.match(r'\| ([^|]+) \| ([^|]+) \|$', line)
        if m and not m.group(1).startswith(('Setting', '---')):
            rows[m.group(1).strip()] = [int(n) for n in re.findall(r'\d+', m.group(2))]
    return rows, section


def board_values():
    os.environ.setdefault('POCKET_DIAGNOSTIC_VARIANT', 'v4')
    tree = runpy.run_path(str(ROOT / 'tools/prepare-pocket-diagnostic-tree.py'), run_name='charger_limits_helpers')
    nodes = tree['DECODE'](BOARD.read_bytes())['nodes']
    return nodes, tree['values'], tree['enabled']


HARNESS = r'''
#include <stdio.h>
#define min(a, b) ((a) < (b) ? (a) : (b))
struct charger_data { int input_current_limit, charging_current_limit, thermal_charging_current_limit,
                      input_current_limit_by_aicl; };
static int bts_now, soc_now, temp_now;
static int mtkts_bts_get_hw_temp(void) { return bts_now; }
static int battery_get_bat_soc(void) { return soc_now; }
static int oz8806_get_charger_temp(void) { return temp_now; }
static void steps(struct charger_data *pdata)
{
	int bts = 0;
STEPS
}
int main(void)
{
	int in, chg, bts, soc, temp, thermal;
	while (scanf("%d %d %d %d %d %d", &in, &chg, &bts, &soc, &temp, &thermal) == 6) {
		struct charger_data d = { in, chg, thermal, -1 };
		bts_now = bts; soc_now = soc; temp_now = temp;
		steps(&d);
		printf("%d %d %d\n", d.input_current_limit, d.charging_current_limit, d.input_current_limit_by_aicl);
	}
	return 0;
}
'''

# Start limits per charger type (input, charge) from the stock table, after the probe overrides
TYPES = {'SDP': (500000, 500000), 'NONSTD': (500000, 500000), 'CDP': (1500000, 1500000),
         'DCP': (2000000, 2000000), 'APPLE_1_0A': (650000, 650000), 'APPLE_2_1A': (800000, 800000)}


def expected(inp, chg, bts, soc, temp, thermal):
    """The steps as CHARGER_PORT.md describes them: each step only lowers a limit."""
    if bts >= 41000:
        inp, chg = min(inp, 800000), min(chg, 800000)
        if bts >= 45000 and soc >= 76:
            inp, chg = min(inp, 80000), min(chg, 80000)
    if thermal != -1 and thermal < chg:
        if 41000 <= bts <= 58000:
            chg = min(chg, 800000)
        elif bts > 58000:
            chg = thermal
    if temp < 15:
        inp, chg = min(inp, 400000), min(chg, 400000)
    return inp, chg, inp


OBJ = BULK / 'kernel-firstboot-5.10/drivers/power/supply/mediatek'
OBJDUMP = pocket_paths.ndk_bin() / 'llvm-objdump'


def consts(obj, fn):
    """Immediates built by mov/movk and compared by cmp in one function, and its size in bytes."""
    out = subprocess.run([str(OBJDUMP), '-d', '--no-show-raw-insn', f'--disassemble-symbols={fn}', str(obj)],
                         capture_output=True, text=True, check=True).stdout
    body = out.split(f'<{fn}>:\n', 1)[1].split('\n\n', 1)[0].splitlines()
    regs, vals = {}, set()
    for line in body:
        m = re.search(r'\t(mov|movk|cmp)\t([wx]\d+|wzr), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?', line)
        if not m:
            continue
        op, r, imm, sh = m.groups()
        imm, sh = int(imm, 0), int(sh or 0)
        if op == 'mov':
            regs[r] = imm
        elif op == 'movk':
            regs[r] = (regs.get(r, 0) & ~(0xffff << sh)) | (imm << sh)
        else:
            vals.add(imm)
            continue
        vals.add(regs[r])
    return vals, 4 * len([l for l in body if re.match(r'\s+[0-9a-f]+:\s', l)])


def main():
    rows, section = table()
    nodes, values, enabled = board_values()
    c = nodes['/charger']
    v = lambda k: values(c[k]) if k in c else None
    check('/charger enabled on the board', enabled(nodes, '/charger'))
    check('/mt6370_pmu_dts/charger enabled on the board', enabled(nodes, '/mt6370_pmu_dts/charger'))
    pairs = [
        ('battery_cv (DT)', ['battery_cv']),
        ('usb_charger_current (SDP)', ['usb_charger_current']),
        ('usb_charger_current_unconfigured / configured / suspend',
         ['usb_charger_current_unconfigured', 'usb_charger_current_configured', 'usb_charger_current_suspend']),
        ('charging_host_charger_current (CDP)', ['charging_host_charger_current']),
        ('non_std_ac_charger_current', ['non_std_ac_charger_current']),
        ('apple_1_0a / apple_2_1a', ['apple_1_0a_charger_current', 'apple_2_1a_charger_current']),
        ('max_charger_voltage', ['max_charger_voltage']),
        ('max_charge_temp / back below', ['max_charge_temp', 'max_charge_temp_minus_x_degree']),
        ('min_charge_temp / back above', ['min_charge_temp', 'min_charge_temp_plus_x_degree']),
    ]
    for row, keys in pairs:
        want = rows[row][:len(keys)]
        got = [v(k)[0] if v(k) else None for k in keys]
        check('DT ' + ', '.join(keys), got == want, f'{got} vs table {want}')
    # DCP and TA rows list the DT value first, then the override
    dcp = rows['ac_charger_current / ac_charger_input_current (DCP, DT)']
    check('DT ac_charger_current, ac_charger_input_current',
          [v('ac_charger_current')[0], v('ac_charger_input_current')[0]] == dcp[:2], dcp)
    ta = rows['ta_ac_charger_current (DT)']
    check('DT ta_ac_charger_current', v('ta_ac_charger_current')[0] == ta[0], ta)
    # MIVR: the row reads "min_charger_voltage, _1, _2 (MIVR) | 4600000, 4400000, 4200000; ... max_dmivr 1400000"
    mivr = [n for n in rows['min_charger_voltage, _1, _2 (MIVR)'] if n >= 100000]
    got = [v(k)[0] for k in ('min_charger_voltage', 'min_charger_voltage_1', 'min_charger_voltage_2',
                             'max_dmivr_charger_current')]
    check('DT MIVR and max_dmivr', got == mivr, f'{got} vs {mivr}')
    check('DT enable_min_charge_temp set', 'enable_min_charge_temp' in c)
    check('DT enable_sw_jeita absent (software JEITA off, so no JEITA CV)', 'enable_sw_jeita' not in c)
    check('DT enable_dynamic_mivr set', 'enable_dynamic_mivr' in c)
    m = nodes['/mt6370_pmu_dts/charger']
    mv = lambda k: values(m[k])[0]
    got = {k: mv(k) for k in ('ichg', 'aicr', 'cv', 'ieoc', 'mivr', 'safety_timer', 'dc_wdt', 'ircmp_resistor', 'ircmp_vclamp')}
    want = {'ichg': 2000000, 'aicr': 500000, 'cv': 4350000, 'ieoc': 150000, 'mivr': 4400000,
            'safety_timer': 12, 'dc_wdt': 4000000, 'ircmp_resistor': 25000, 'ircmp_vclamp': 32000}
    doc_ok = all(s in section for s in ('ichg 2000000', 'aicr 500000', 'cv 4350000', 'ieoc 150000', 'mivr 4400000',
                                       'safety timer 12 h', '25 mΩ / 32 mV'))
    check('MT6370 charger node as the table', got == want and doc_ok and 'enable_wdt' in m and 'enable_te' in m, got)

    # Overrides in mtk_charger_parse_dt, after the last DT read
    src = (CHG / 'mtk_charger.c').read_text()
    parse = src[src.index('static int mtk_charger_parse_dt('):]
    parse = parse[:parse.index('\n}\n')]
    over = parse[parse.index('Stock (agold) sets these'):]
    want = {'battery_cv': 4400000, 'ac_charger_current': 2000000, 'ac_charger_input_current': 2000000,
            'ta_ac_charger_current': 2000000, 'usb_charger_current': 500000}
    got = {k: int(n) for k, n in re.findall(r'info->data\.(\w+) = (\d+);', over)}
    check('probe overrides', got == want, got)
    check('overrides come after every of_property_read', 'of_property_read' not in over)
    check('table says CV is overridden to 4400000', rows['battery_cv (DT)'][1] == 4400000)
    check('table DCP and TA overrides', dcp[2:4] == [2000000, 2000000] and ta[1] == 2000000)
    writes = re.findall(r'data\.battery_cv\s*=\s*([^;]+);', src)
    check('battery_cv is only set from DT, its default or 4400000',
          sorted(writes) == sorted(['val', 'BATTERY_CV', '4400000']), writes)
    dyn = src[src.index('int mtk_get_dynamic_cv('):]
    glue = (CHG / 'mtk_charger_glue.c').read_text()
    check('dynamic CV (4608000) needs BIF, and pmic_is_bif_exist() returns 0',
          'if (pmic_is_bif_exist()) {' in dyn[:600] and re.search(r'int pmic_is_bif_exist\(void\)\n\{\n\treturn 0;\n\}', glue))
    fn = glue[glue.index('int mtkts_bts_get_hw_temp(void)'):]
    fn = fn[:fn.index('\n}\n')]
    check('board thermistor reads AUXADC channel 0 (iio "bts"), 41000 on a failed read, returns whole degrees times 1000',
          'iio_read_channel_processed(chan, &mv)' in fn and 'return POCKET_BTS_NO_READING;' in fn
          and 'return t * 1000;' in fn and 'oz8806' not in fn
          and '#define POCKET_BTS_NO_READING\t41000' in glue
          and re.search(r'iio_channel_get\([^;]*"bts"\)', glue), fn[:200])
    tmp = (CHG / 'mtk_charger.c').read_text()
    check('charger_check_status stops charging below min and at max temperature',
          'if (temperature < thermal->min_charge_temp) {' in tmp and 'if (temperature >= thermal->max_charge_temp) {' in tmp)

    # Host-compiled steps
    sw = (CHG / 'mtk_switch_charging.c').read_text()
    start = sw.index('\tbts = mtkts_bts_get_hw_temp();')
    end = sw.index('\tpdata->input_current_limit_by_aicl = pdata->input_current_limit;', start)
    end = sw.index('\n', end) + 1
    body = sw[start:end]
    cases = [(i, ch, b, s, t, th) for i, ch in TYPES.values()
             for b in (25000, 40999, 41000, 44999, 45000, 58000, 58001, 70000)
             for s in (50, 75, 76) for t in (-1, 14, 15, 30) for th in (-1, 500000, 1200000, 3000000)]
    with tempfile.TemporaryDirectory() as d:
        cfile = Path(d) / 'steps.c'
        cfile.write_text(HARNESS.replace('STEPS', body))
        subprocess.run(['cc', '-O0', '-Wall', '-Werror', '-o', str(Path(d) / 'steps'), str(cfile)], check=True)
        out = subprocess.run([str(Path(d) / 'steps')], input=''.join('%d %d %d %d %d %d\n' % k for k in cases),
                             capture_output=True, text=True, check=True).stdout.split('\n')
    res = [tuple(int(x) for x in out[i].split()) for i in range(len(cases))]
    bad = [(k, res[i]) for i, k in enumerate(cases) if res[i] != expected(*k)]
    check(f'agold steps, {len(cases)} host cases over {len(TYPES)} charger types', not bad, bad[:5])
    for name, (i0, c0) in TYPES.items():
        mine = [(k, res[i]) for i, k in enumerate(cases) if k[:2] == (i0, c0)]
        raised = [(k, r) for k, r in mine if r[0] > i0 or r[1] > c0]
        check(f'{name}: no case ends above its own stock limit', not raised, raised[:3])
        hot = [(k, r) for k, r in mine if k[2] >= 41000 and (r[0] > 800000 or r[1] > 800000)]
        check(f'{name}: nothing above 800 mA from 41 C', not hot, hot[:3])
    stub = [(k, r) for k, r in zip(cases, res) if k[2] == 41000 and k[4] >= 15 and k[5] == -1]
    check('at 41 C (also the no-reading value), every type gets min(own limit, 800 mA)',
          all(r[:2] == (min(k[0], 800000), min(k[1], 800000)) for k, r in stub), len(stub))

    # The same constants in the built objects
    vals, size = consts(OBJ / 'charger/mtk_switch_charging.o', 'swchg_select_charging_current_limit')
    want = {41000, 45000, 58001, 76, 14, 80000, 400000, 800000}
    check('built steps use 41000, 45000, 58001 (>58000), 76, 14 (<15), 80/400/800 mA',
          want <= vals, sorted(want - vals))
    vals, size = consts(OBJ / 'charger/mtk_charger_glue.o', 'mtkts_bts_get_hw_temp')
    check('built thermistor stand-in has the 41000 no-reading value', 41000 in vals, sorted(vals))
    vals, size = consts(OBJ / 'charger/mtk_charger.o', 'mtk_charger_probe')
    check('built probe has the CV 4400000, 2 A and 500 mA overrides and is not cut short',
          {4400000, 2000000, 500000} <= vals and size > 1024, f'{size} bytes')
    vals, size = consts(OBJ / 'misc/mtk_gauge_time_service.o', 'gauge_timer_service_probe')
    check('built gauge timer probe is not cut short', size > 64, f'{size} bytes')
    doc_steps = 'each step only lowers a limit' in DOC.read_text() and all(s in section for s in (
                                          '41 °C or more: input and charge current 800 mA',
                                          '45 °C or more with SOC 76 % or more: 80 mA',
                                          'used only above 58 °C', 'below 15 °C: 400 mA'))
    check('steps as CHARGER_PORT.md words them', doc_steps)

    failures = [c for c in checks if not c['ok']]
    RECORD.write_text(json.dumps({'board': str(BOARD), 'checks': checks, 'failures': len(failures),
                                  'scope': 'Offline table, source and host-compiled check; not run on the phone'},
                                 indent=2) + '\n')
    print(f'checks {len(checks)} failures {len(failures)} report {RECORD}')
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()
