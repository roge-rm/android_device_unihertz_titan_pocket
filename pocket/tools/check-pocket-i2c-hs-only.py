#!/usr/bin/env python3
"""Host check for mediatek,hs_only in U's MT6771 i2c driver; no build, image or phone access.

Compiles the timing functions straight out of both sources with host gcc:
T's mtk_i2c_calculate_speed and i2c_set_speed (stock DT i2c_common: cnt_constraint, set_ltiming,
check_max_freq, ver 2), and U's mtk_i2c_vendor_cnt and mtk_i2c_chan_timing. For 3.4 MHz with
hs_only, and for 400 and 100 kHz, it compares TIMING (with TIMEOUT_EN), LTIMING, HS and HW_TIMEOUT
at the 124.8 MHz i2c_sel clock over the DT clock-div. It also checks the board DT: every bus that has
hs_only, and that only i2c5 runs above 1 MHz, so the hs_only paths in U leave the other buses alone.
The interrupt mask, CONTROL and EXT_CONF are a table check: the bit values match by name between T and U,
and the source lines that build them are matched by pattern on both sides, not compiled.
Writes evidence/kernel-upgrade/i2c-hs-only-check.json.
"""
import pocket_paths
import glob, hashlib, json, re, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
U = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/i2c/busses/i2c-mt65xx.c'
TDIR = Path(glob.glob(str(ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5*'))[0])
TC = TDIR / 'drivers/i2c/busses/i2c-mtk.c'
TH = TDIR / 'drivers/i2c/busses/i2c-mtk.h'
BOARD_DTS = pocket_paths.build_root() / 'artifacts/firstboot-5.10/board/keyboard.dts'
RECORD = ROOT / 'evidence/kernel-upgrade/i2c-hs-only-check.json'
MAIN_CLK = 124800000  # i2c_sel, as 0013's mt6771 clk line logs it
FS_PLUS = 1000000


def function(src, name):
    m = re.search(r'^static int ' + name + r'\(.*?\n\{', src, re.S | re.M)
    assert m, name
    depth, i = 0, m.end() - 1
    while True:
        depth += {'{': 1, '}': -1}.get(src[i], 0)
        i += 1
        if depth == 0:
            return src[m.start():i]


def defines(src, names):
    out = []
    for n in names:
        m = re.search(r'^#define\s+' + n + r'\s+(.*)$', src, re.M)
        assert m, n
        out.append(f'#define {n} ' + re.sub(r'/\*.*', '', m.group(1)).strip())
    return '\n'.join(out)


def harness(speeds):
    tc, th, uc = TC.read_text(), TH.read_text(), U.read_text()
    t_defs = defines(th, ['MAX_SAMPLE_CNT_DIV', 'MAX_STEP_CNT_DIV', 'MAX_HS_STEP_CNT_DIV', 'MAX_FS_MODE_SPEED',
                          'MAX_FS_PLUS_MODE_SPEED', 'MAX_HS_MODE_SPEED', 'I2C_DEFAUT_SPEED', 'HALF_DUTY_CYCLE',
                          'DUTY_CYCLE', 'I2C_TIMING_SAMPLE_COUNT_MASK', 'I2C_TIMING_STEP_DIV_MASK',
                          'I2C_HS_HOLD_TIME', 'I2C_HS_HOLD_SEL', 'I2C_TIME_DEFAULT_VALUE', 'I2C_HS_SPEED',
                          'I2C_TIME_CLR_VALUE', 'I2C_TIMEOUT_EN', 'MAX_SCL_LOW_TIME', 'LSTEP_MSK', 'LSAMPLE_MSK'])
    u_defs = defines(uc, ['MAX_SAMPLE_CNT_DIV', 'MAX_STEP_CNT_DIV', 'MAX_HS_STEP_CNT_DIV', 'I2C_CHAN_SCL_LOW_MS',
                          'I2C_CHAN_TIMEOUT_EN'])
    t_body = function(tc, 'mtk_i2c_calculate_speed') + '\n' + function(tc, 'i2c_set_speed')
    u_body = function(uc, 'mtk_i2c_vendor_cnt') + '\n' + function(uc, 'mtk_i2c_chan_timing')
    rows = ',\n'.join(f'{{{s},{h}}}' for s, h in speeds)
    return f'''#include <stdio.h>
#include <stdbool.h>
#define ENOTSUPP 524
#define EINVAL 22
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define dev_dbg(...) do {{}} while (0)
#define I2C_MAX_STANDARD_MODE_FREQ 100000
#define I2C_MAX_FAST_MODE_FREQ 400000
struct comp {{ int check_max_freq, cnt_constraint, set_ltiming; }};
static const struct comp stock_common = {{ 1, 1, 1 }};
/* T */
{t_defs}
struct mt_i2c {{ const struct comp *dev_comp; struct {{ int isEnable; unsigned int timing; }} ext_data;
	unsigned int speed_hz; bool hs_only; unsigned short timing_reg, high_speed_reg, ltiming_reg; void *dev; }};
{t_body}
static void t_regs(unsigned int clk, unsigned int speed, bool hs_only, unsigned int *r)
{{
	struct mt_i2c i2c = {{ .dev_comp = &stock_common, .speed_hz = speed, .hs_only = hs_only }};
	unsigned int tv1, tv2;
	r[4] = i2c_set_speed(&i2c, clk);
	r[0] = i2c.timing_reg | I2C_TIMEOUT_EN;
	r[1] = i2c.ltiming_reg;
	r[2] = i2c.high_speed_reg;
	/* mt_i2c_do_transfer, ver 2 with a non-zero ltiming_reg */
	tv1 = clk / 1000 * MAX_SCL_LOW_TIME;
	tv2 = (((i2c.ltiming_reg & LSTEP_MSK) + 1) * (((i2c.ltiming_reg & LSAMPLE_MSK) >> 6) + 1));
	r[3] = i2c.ltiming_reg ? DIV_ROUND_UP(tv1, tv2) & 0xFFFF : 0;
}}
#undef MAX_SAMPLE_CNT_DIV
#undef MAX_STEP_CNT_DIV
#undef MAX_HS_STEP_CNT_DIV
/* U */
{u_defs}
struct mtk_i2c {{ unsigned int speed_hz; bool hs_only; unsigned short chan_timing, chan_ltiming, chan_hw_timeout; }};
{u_body}
static void u_regs(unsigned int clk, unsigned int speed, bool hs_only, unsigned int *r)
{{
	struct mtk_i2c i2c = {{ .speed_hz = speed, .hs_only = hs_only }};
	r[4] = mtk_i2c_chan_timing(&i2c, clk);
	r[0] = i2c.chan_timing | I2C_CHAN_TIMEOUT_EN;
	r[1] = i2c.chan_ltiming;
	r[2] = 0; /* ac_timing.hs: I2C_TIME_CLR_VALUE on the hs_only and channel paths */
	r[3] = i2c.chan_hw_timeout;
}}
int main(void)
{{
	static const unsigned int cases[][2] = {{ {rows} }};
	unsigned int i, t[5], u[5];
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {{
		unsigned int clk = {MAIN_CLK} / 5;
		t_regs(clk, cases[i][0], cases[i][1], t);
		u_regs(clk, cases[i][0], cases[i][1], u);
		printf("%u %u %d %#x %#x %#x %#x %d %#x %#x %#x %#x\\n", cases[i][0], cases[i][1],
		       (int)t[4], t[0], t[1], t[2], t[3], (int)u[4], u[0], u[1], u[2], u[3]);
	}}
	return 0;
}}
'''


def board_buses():
    text = BOARD_DTS.read_text()
    buses = {}
    for m in re.finditer(r'^\ti2c@([0-9a-f]+) \{\n(.*?)^\t\};', text, re.S | re.M):
        body = '\n'.join(l for l in m.group(2).splitlines() if re.match(r'^\t\t[^\t]', l))
        freq = re.search(r'clock-frequency = \[([0-9a-f ]+)\]', body)
        buses[m.group(1)] = {'hs_only': 'mediatek,hs_only;' in body,
                             'clock_frequency': int(freq.group(1).replace(' ', ''), 16) if freq else None}
    return buses


def main():
    speeds = [(3400000, 1), (400000, 1), (400000, 0), (100000, 0)]
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / 'hs_only.c'
        c.write_text(harness(speeds))
        subprocess.run(['gcc', '-Wall', '-Wno-unused-function', '-o', str(Path(tmp) / 'hs'), str(c)], check=True)
        out = subprocess.run([str(Path(tmp) / 'hs')], check=True, capture_output=True, text=True).stdout
    names = ['ret', 'timing', 'ltiming', 'hs', 'hw_timeout']
    cases = []
    for line in out.split('\n'):
        if not line:
            continue
        f = line.split()
        t = dict(zip(names, [int(x, 0) for x in f[2:7]]))
        u = dict(zip(names, [int(x, 0) for x in f[7:12]]))
        cases.append({'speed_hz': int(f[0]), 'hs_only': f[1] == '1', 'stock': t, 'upgrade': u, 'match': t == u})
        print(f'{f[0]} Hz hs_only={f[1]}: stock {t} upgrade {u}', 'match' if t == u else 'DIFFER')
    assert all(c['match'] for c in cases), 'timing differs'
    hs = cases[0]['stock']
    assert (hs['ret'], hs['timing'], hs['ltiming'], hs['hs'], hs['hw_timeout']) == (0, 0x5, 0x4, 0, 0x2700), hs

    uc = U.read_text()
    # Every hs_only branch in U is behind i2c->hs_only, which parse_dt only sets above 1 MHz on MT6771.
    gate = re.search(r'i2c->hs_only = i2c->dev_comp->dt_clk_div &&\s+i2c->speed_hz > I2C_MAX_FAST_MODE_PLUS_FREQ &&\s+'
                     r'of_property_read_bool\(np, "mediatek,hs_only"\);', uc)
    assert gate, 'hs_only gate in parse_dt'
    uses = len(re.findall(r'hs_only', uc))

    # Table check of the bits stock writes on this path, against the same names in U (T name, U name).
    th, tc = TH.read_text(), TC.read_text()
    def val(src, n):
        expr = defines(src, [n]).split(None, 2)[2]
        assert re.fullmatch(r'[0-9a-fA-Fx()<| ]+', expr), (n, expr)
        return eval(expr)
    bits = {}
    for tn, un in [('I2C_HS_NACKERR', 'I2C_HS_NACKERR'), ('I2C_ACKERR', 'I2C_ACKERR'), ('I2C_TRANSAC_COMP', 'I2C_TRANSAC_COMP'),
                   ('I2C_ARB_LOST', 'I2C_ARB_LOST'), ('I2C_BUS_ERR', 'I2C_BUS_ERR'), ('I2C_TIMEOUT', 'I2C_HW_TIMEOUT'),
                   ('I2C_CONTROL_ACKERR_DET_EN', 'I2C_CONTROL_ACKERR_DET_EN'), ('I2C_CONTROL_RS', 'I2C_CONTROL_RS'),
                   ('I2C_CONTROL_CLK_EXT_EN', 'I2C_CONTROL_CLK_EXT_EN'), ('I2C_CONTROL_DMA_EN', 'I2C_CONTROL_DMA_EN'),
                   ('I2C_CONTROL_DMAACK_EN', 'I2C_CONTROL_DMAACK_EN'), ('I2C_CONTROL_ASYNC_MODE', 'I2C_CONTROL_ASYNC_MODE'),
                   ('I2C_CONTROL_DIR_CHANGE', 'I2C_CONTROL_DIR_CHANGE'), ('I2C_FS_PLUS_START_CON', 'I2C_FS_PLUS_START_CON'),
                   ('I2C_DELAY_LEN', 'I2C_CHAN_DELAY_LEN'), ('I2C_TIMEOUT_EN', 'I2C_CHAN_TIMEOUT_EN')]:
        tv, uv = val(th, tn), val(uc, un)
        assert tv == uv, (tn, tv, un, uv)
        bits[tn] = tv
    # Stock: ver 2 int_reg, CONTROL above 400 kHz, EXT_CONF above 1 MHz, the error check.
    for pat in [r'int_reg = I2C_HS_NACKERR \| I2C_ACKERR \|\s+I2C_TRANSAC_COMP \| I2C_ARB_LOST;',
                r'if \(i2c->dev_comp->ver == 0x2\)\s+int_reg \|= I2C_BUS_ERR \| I2C_TIMEOUT;',
                r'if \(speed_hz > 400000\)\s+control_reg = I2C_CONTROL_ACKERR_DET_EN;',
                r'if \(speed_hz > 400000\)\s+control_reg \|= I2C_CONTROL_RS;',
                r'else if \(speed_hz > MAX_FS_PLUS_MODE_SPEED\) \{\s+i2c_writew\(I2C_FS_PLUS_START_CON',
                r'I2C_TIMEOUT \| I2C_BUS_ERR \| I2C_IBI\)\) \{']:
        assert re.search(pat, tc), pat
    # U on the hs_only path: the same mask, CONTROL without CLK_EXT_EN, EXT_CONF, the error return.
    for pat in [r'intr_mask = restart_flag \| I2C_HS_NACKERR \| I2C_ACKERR \|\s+I2C_ARB_LOST \| I2C_TRANSAC_COMP;',
                r'if \(i2c->hs_only\)\s+intr_mask \|= I2C_BUS_ERR \| I2C_HW_TIMEOUT;',
                r'control_reg = I2C_CONTROL_ACKERR_DET_EN;\s+if \(!i2c->hs_only\)\s+control_reg \|= I2C_CONTROL_CLK_EXT_EN;',
                r'if \(\(i2c->speed_hz > I2C_MAX_FAST_MODE_PLUS_FREQ\) \|\| \(left_num >= 1\)\)\s+control_reg \|= I2C_CONTROL_RS;',
                r'i2c->hs_only \? I2C_FS_PLUS_START_CON :',
                r'if \(i2c->hs_only && \(i2c->irq_stat & \(I2C_BUS_ERR \| I2C_HW_TIMEOUT\)\)\) \{.*?return -EREMOTEIO;',
                r'if \(i2c->hs_only\)\s+i2c->auto_restart = 0;']:
        assert re.search(pat, uc, re.S), pat
    mask = bits['I2C_HS_NACKERR'] | bits['I2C_ACKERR'] | bits['I2C_TRANSAC_COMP'] | bits['I2C_ARB_LOST'] | bits['I2C_BUS_ERR'] | bits['I2C_TIMEOUT']
    control = bits['I2C_CONTROL_ACKERR_DET_EN'] | bits['I2C_CONTROL_RS']
    print(f'mask {mask:#x}, CONTROL {control:#x} (+DMA bits, +DIR_CHANGE for WRRD), EXT_CONF {bits["I2C_FS_PLUS_START_CON"]:#x} in both')

    buses = board_buses()
    with_hs = sorted(a for a, b in buses.items() if b['hs_only'])
    fast = sorted(a for a, b in buses.items() if b['hs_only'] and (b['clock_frequency'] or 0) > FS_PLUS)
    assert fast == ['11017000'], fast
    print(f'board: {len(with_hs)} buses have hs_only; above 1 MHz only {fast}')

    record = {'stock_source': str(TC.relative_to(ROOT)), 'upgrade_source': str(U.relative_to(ROOT)),
              'upgrade_sha256': hashlib.sha256(U.read_bytes()).hexdigest(),
              'clk_src_hz': MAIN_CLK // 5, 'cases': cases, 'hs_only_mentions_in_upgrade': uses,
              'hs_only_intr_mask': mask, 'hs_only_control_fifo': control, 'bits': bits,
              'board_dts': str(BOARD_DTS), 'board_hs_only_buses': with_hs, 'board_hs_only_above_1mhz': fast}
    RECORD.write_text(json.dumps(record, indent=1) + '\n')
    print('stock and upgrade timing match; wrote', RECORD.relative_to(ROOT))


if __name__ == '__main__':
    main()
