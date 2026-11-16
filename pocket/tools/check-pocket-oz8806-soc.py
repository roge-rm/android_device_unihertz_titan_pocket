#!/usr/bin/env python3
"""Host test of the OZ8806 level core; no kernel build, image or phone access.

Builds drivers/power/supply/oz8806_bmulib.c for the host twice, read-only and with
CONFIG_OZ8806_WRITE, against a small C harness with a fake chip, then checks:
- the NTC header is what tools/make-pocket-oz8806-ntc.py writes, and the OCV table is
  in order;
- one_latitude_table and calculate_soc_result against a Python model, on hand-worked
  points and a grid;
- the polling steps on register sequences (boot from CAR, power-on OCV, sleep OCV and the
  shutdown-voltage check, CAR at 5 mAh or less with the RTC SOC, discharge by the
  counter, 1 % held above the end voltage, end of discharge, charge to full at the end
  point, the OCV correction after a rest and the counted charge across CAR writes);
- that the read-only build gives the same level trace as the write build on a chip that
  takes the writes, and that the read-only build makes no write call at all.
The OCV table is oz8806_ocv.h when it is there, else the placeholder oz8806_ocv_generic.h,
as in the driver. Writes evidence/kernel-upgrade/oz8806-soc-check.json; with --supply DIR it
tests the driver files in DIR instead and writes no record.
"""
import argparse, hashlib, importlib.util, json, random, re, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
U = ROOT / 'tools/kernel-source/upgrade-5.10'
_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--supply', type=Path, help='driver folder to test, default the kernel working tree')
ARGS = _ap.parse_args()
SUPPLY = ARGS.supply.resolve() if ARGS.supply else U / 'drivers/power/supply'
OCV_FILE = SUPPLY / 'oz8806_ocv.h' if (SUPPLY / 'oz8806_ocv.h').is_file() else SUPPLY / 'oz8806_ocv_generic.h'
RECORD = ROOT / 'evidence/kernel-upgrade/oz8806-soc-check.json'

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oz8806_bmulib.h"

/* fake chip: values in mV, mA and raw words */
static struct {
	int volt, curr, temp_mv, ocv_mv, ocv_flags, board_raw, op;
	int dead, zero;		/* no answer (-ENXIO), or every register reads 0 */
	unsigned short car_raw;
	int writes, takes_writes, other_writes, last_write_ms, wrote, early_accept;
} chip;
static unsigned int clock_ms;
static int adapter, rtc_spare = 101, save_cap = -2;
static struct oz8806_bmu bmu;

static int enc_mv(int mv) { return (mv * 100 / 250) * 16; }
static int enc_curr(int ma)
{
	static int last_ma = 1 << 30, last_raw;
	int raw, best = 0;
	if (ma == last_ma) return last_raw;
	for (raw = -32768; raw < 32768; raw++) {
		int t = raw * 781 / 10; t /= 100;
		if (t / 4 == ma) { best = raw; if (ma >= 0) break; }
	}
	last_ma = ma; last_raw = best;
	return best;
}

int oz8806_hw_read_byte(struct oz8806_bmu *b, u8 reg)
{
	static const int id[4] = { 0x38, 0xb4, 0x02, 0xb3 };
	if (chip.dead) return -6;
	if (chip.zero) return 0;
	if (reg < 4) return id[reg];
	if (reg == 8) return 3;
	if (reg == 9) return chip.op;
	return 0;
}
int oz8806_hw_read_word(struct oz8806_bmu *b, u8 reg)
{
	if (chip.dead) return -6;
	if (chip.zero) return 0;
	switch (reg) {
	case 0x03: return 0x3eb3;
	case 0x0c: return (unsigned short)enc_mv(chip.temp_mv);
	case 0x0e: return (unsigned short)enc_mv(chip.volt);
	case 0x10: return (unsigned short)(enc_mv(chip.ocv_mv) | chip.ocv_flags);
	case 0x12: return (unsigned short)enc_curr(chip.curr);
	case 0x14: return chip.car_raw;
	case 0x18: return chip.board_raw;
	}
	return 0;
}
int oz8806_hw_write_byte(struct oz8806_bmu *b, u8 reg, u8 v)
{
	chip.writes++;
	if (reg != 9) chip.other_writes++;
	chip.wrote = 1; chip.last_write_ms = clock_ms;
	if (chip.takes_writes && reg == 9) chip.op = v;
	return 0;
}
#ifdef CONFIG_OZ8806_WRITE
int oz8806_hw_write_word(struct oz8806_bmu *b, u8 reg, u16 v)
{
	chip.writes++;
	chip.other_writes++;
	if (chip.takes_writes && reg == 0x14) chip.car_raw = v;
	if (chip.takes_writes && reg == 0x18) chip.board_raw = v;
	return 0;
}
#endif
void oz8806_hw_set_addr(struct oz8806_bmu *b, u8 a) {}
void oz8806_hw_msleep(struct oz8806_bmu *b, unsigned int ms) { clock_ms += ms; }
unsigned int oz8806_hw_boot_ms(struct oz8806_bmu *b) { return clock_ms; }
static unsigned int pon_base;
unsigned int oz8806_hw_power_on_ms(struct oz8806_bmu *b) { return clock_ms - pon_base; }
void oz8806_hw_reset_power_on_base(struct oz8806_bmu *b) { pon_base = clock_ms; }
long long oz8806_hw_now_sec(struct oz8806_bmu *b) { return clock_ms / 1000; }
long long oz8806_hw_boottime_sec(struct oz8806_bmu *b) { return clock_ms / 1000; }
int oz8806_hw_adapter(struct oz8806_bmu *b) { return adapter; }
int oz8806_hw_soc_from_ext(struct oz8806_bmu *b) { return rtc_spare - 1; }
int oz8806_hw_save_capacity(struct oz8806_bmu *b) { return save_cap; }

/* what the battery supply gives for capacity: -ENODATA unless data_ok */
#define NODATA (-61)
static int reported(void) { return bmu.data_ok ? oz8806_report_soc(&bmu) : NODATA; }

/* a reading accepted inside 2250 ms of an OP_CTRL write is a failure */
static int accept(int valid)
{
	if (valid > 0 && chip.wrote && clock_ms - chip.last_write_ms < 2250)
		chip.early_accept++;
	return valid;
}

static void dump(const char *tag)
{
	printf("{\"tag\":\"%s\",\"rep\":%d,\"data_ok\":%d,\"asleep\":%d,\"frozen\":%d,"
	       "\"temp_ok\":%d,\"temp_valid\":%d,\"i2c_errors\":%d,",
	       tag, reported(), bmu.data_ok, bmu.asleep, bmu.volt_frozen, bmu.temp_ok, bmu.temp_valid, bmu.bi.i2c_errors);
	printf("\"soc\":%d,\"rc\":%d,\"car\":%d,\"volt\":%d,\"curr\":%d,\"temp\":%d,"
	       "\"init_ok\":%d,\"chg_end\":%d,\"dis_end\":%d,\"init_soc\":%d,\"flag_ocv_boot\":%d,"
	       "\"flag_ocv_ok\":%d,\"ocv\":%d,\"writes\":%d,\"other_writes\":%d,\"early\":%d,\"op\":%d,\"chip_car_raw\":%d,\"clock\":%u,"
	       "\"cc\":%lld,\"rest_soc\":%d,\"rest_ocv\":%d}\n",
	       bmu.bi.soc, bmu.bi.rc, bmu.bi.car, bmu.bi.volt, bmu.bi.curr, bmu.bi.temp,
	       bmu.gg.init_ok, bmu.gg.chg_end, bmu.gg.dis_end, bmu.init_soc, bmu.flag_ocv_boot,
	       bmu.flag_ocv_ok, bmu.bi.ocv, chip.writes, chip.other_writes, chip.early_accept, chip.op, (short)chip.car_raw, clock_ms,
	       bmu.cc_uah, bmu.rest_soc, bmu.rest_ocv_mv);
}

/* boot as stock: init at 3.38 s, first poll, then every 2 s until init is done */
static void boot(int car_mah, int volt, int curr, int temp_mv, int ocv_mv, int flags)
{
	memset(&chip, 0, sizeof(chip));
	chip.takes_writes = 1;
	chip.volt = volt; chip.curr = curr; chip.temp_mv = temp_mv;
	chip.ocv_mv = ocv_mv; chip.ocv_flags = flags; chip.board_raw = 38; chip.op = 0x21;
	chip.car_raw = (unsigned short)(car_mah * 2);
	clock_ms = 3380;
	bmu.hw = NULL;
	oz8806_bmu_setup(&bmu, 24000);
	bmulib_init_chip(&bmu);
	bmu_polling_loop(&bmu);
	while (!bmu.gg.init_ok && clock_ms < 60000) {
		clock_ms += 2000;
		bmu_polling_loop(&bmu);
	}
	dump("init");
}

/* coulombs into the chip, then one steady poll 10 s later, tracked as the driver does */
static void step(int dmah, const char *tag)
{
	chip.car_raw = (unsigned short)(chip.car_raw + dmah * 2);
	clock_ms += 10000;
	oz8806_track_valid_core(&bmu, oz8806_poll(&bmu));
	dump(tag);
}

/* as step(), in 0.5 mAh CAR units */
static void step_raw(int draw, const char *tag)
{
	chip.car_raw = (unsigned short)(chip.car_raw + draw);
	clock_ms += 10000;
	oz8806_track_valid_core(&bmu, oz8806_poll(&bmu));
	dump(tag);
}

/* the driver's start: no init until oz8806_check_chip passes (2 s apart),
 * then the init poll and the 2 s polls until init is done */
static void gated_boot(int car_mah, int volt, int curr, int op, int dead, int zero, const char *tag)
{
	int k;

	memset(&chip, 0, sizeof(chip));
	chip.takes_writes = strcmp(tag, "g_asleep") != 0;
	chip.volt = volt; chip.curr = curr; chip.temp_mv = 529;
	chip.ocv_mv = volt; chip.board_raw = 38; chip.op = op;
	chip.dead = dead; chip.zero = zero;
	chip.car_raw = (unsigned short)(car_mah * 2);
	clock_ms = 3380;
	pon_base = 0;
	memset(&bmu, 0, sizeof(bmu));
	oz8806_wakeup_full_power(&bmu);		/* the probe */
	for (k = 0; k < 5; k++) {
		oz8806_bmu_setup(&bmu, 24000);
		if (accept(oz8806_check_chip(&bmu)))
			break;
		clock_ms += 2000;
	}
	if (k < 5) {
		bmulib_init_chip(&bmu);
		oz8806_track_valid_core(&bmu, accept(oz8806_poll(&bmu)));
		while (!bmu.gg.init_ok && clock_ms < 60000) {
			clock_ms += 2000;
			oz8806_track_valid_core(&bmu, accept(oz8806_poll(&bmu)));
		}
	}
	if (!strcmp(tag, "g_shutdown")) {
		/* the driver stops polling after shutdown; a stray poll must not wake the chip */
		oz8806_chip_sleep(&bmu);
		clock_ms += 10000;
		oz8806_poll(&bmu);
		oz8806_check_chip(&bmu);
	}
	dump(tag);
}

int main(int argc, char **argv)
{
	char line[256];
	int i;

	if (argc > 1 && !strcmp(argv[1], "calc")) {
		oz8806_bmu_setup(&bmu, 24000);
		while (fgets(line, sizeof(line), stdin)) {
			int a, b2, c;
			if (sscanf(line, "O %d", &a) == 1)
				printf("%d\n", one_latitude_table(OZ8806_OCV_N, oz8806_ocv, a));
			else if (sscanf(line, "N %d", &a) == 1)
				printf("%d\n", one_latitude_table(OZ8806_NTC_N, oz8806_ntc, a));
			else if (sscanf(line, "C %d %d %d", &a, &b2, &c) == 3) {
				bmu.bi.volt = a; bmu.bi.curr = b2; bmu.bi.temp = c;
				printf("%d\n", calculate_soc_result(&bmu));
			}
		}
		return 0;
	}
	/* temperature: 529 mV on the NTC reads 23 C with the 24 kOhm pull-up */
	boot(2000, 3800, -300, 529, 3800, 0);
	adapter = 0;
	for (i = 0; i < 40; i++) step(-10, "dis");

	boot(100, 3500, -300, 529, 3500, 0);
	chip.volt = 3300;			/* below the end voltage */
	for (i = 0; i < 20; i++) step(-10, "low");
	/* counted to empty at 3800 mV: 1 % is held */
	boot(100, 3800, -300, 529, 3800, 0);
	for (i = 0; i < 20; i++) step(-10, "hold");

	/* rest at -5 mA for 2.5 h, the CAR moving 0.5 mAh every 6 min: after
	 * 30 min the level moves to the OCV one point a minute; then a load,
	 * and the same at 50 C, where nothing moves */
	boot(2000, 3900, -5, 529, 3900, 0);
	for (i = 0; i < 900; i++) step_raw(i % 36 == 35 ? -1 : 0, "rest");
	chip.curr = -300;
	step(-1, "rest_load");
	boot(2000, 3900, -5, 250, 3900, 0);
	for (i = 0; i < 200; i++) step_raw(i % 36 == 35 ? -1 : 0, "rest_hot");

	adapter = 1;
	boot(OZ8806_DESIGN_MAH * 94 / 100, 4300, 1000, 529, 4300, 0);
	for (i = 0; i < 40; i++) step(20, "chg");
	chip.volt = 4400; chip.curr = 400;	/* at CV, above the end current */
	for (i = 0; i < 40; i++) step(7, "cv");
	chip.curr = 250;			/* under the end current: full */
	step(1, "taper");
	step(0, "full");
	/* the driver's full detection does this too */
	bmu.gg.chg_end = 1;
	charge_end_process(&bmu);
	step(0, "full");
	adapter = 0;

	boot(2000, 3900, -300, 529, 3900, 1);	/* power-on OCV, RTC 101 */
	boot(2000, 3700, -300, 529, 3700, 2);	/* sleep OCV, shutdown-voltage check */
	rtc_spare = 51;
	boot(2, 3800, -300, 529, 3800, 0);	/* CAR 2 mAh, RTC SOC 50 */

	/* port validity: no answer, all zero, asleep */
	gated_boot(2000, 3800, -300, 0x21, 1, 0, "g_dead");
	gated_boot(2000, 3800, -300, 0x21, 0, 1, "g_zero");
	gated_boot(2000, 3800, -300, 0x61, 0, 0, "g_asleep");	/* write doesn't take */
	gated_boot(2000, 3800, -300, 0x21, 0, 0, "g_shutdown");	/* sleep write, then a poll: no wake */
	gated_boot(2000, 3800, -300, 0x61, 0, 0, "g_wake");	/* wake takes: one write, valid after 2250 ms */
	/* reads stop after a valid start: data drops on the 3rd bad poll, comes back on a good one */
	gated_boot(2000, 3800, -300, 0x21, 0, 0, "g_good");
	chip.dead = 1;
	for (i = 0; i < 3; i++) step(0, "g_fail");
	chip.dead = 0;
	step(-1, "g_back");
	/* the NTC stops answering: temp_ok drops */
	chip.temp_mv = 9999;
	step(-1, "g_ntc");
	/* the charger temperature: valid again, then open (0 mV) and past the table (cold) */
	chip.temp_mv = 529;
	step(-1, "g_ntc_back");
	chip.temp_mv = 0;
	step(-1, "g_ntc_open");
	chip.temp_mv = 1790;
	step(-1, "g_ntc_cold");
	/* CAR 1..5 mAh with RTC SOC 50: the counter says empty, the OCV level is taken */
	for (i = 1; i <= 5; i++) gated_boot(i, 3800, -300, 0x21, 0, 0, "g_car");
	gated_boot(2, 3400, -300, 0x21, 0, 0, "g_car_3400");
	/* a load spike ends the discharge at 3300 mV; a rest at 3750 mV then
	 * brings the level back up */
	boot(2000, 3900, -5, 529, 3900, 0);
	chip.volt = 3300; chip.curr = -800;
	for (i = 0; i < 12; i++) step(-150, "spike");
	for (i = 0; i < 40 && !bmu.gg.dis_end; i++) step(-20, "spike");
	chip.volt = 3750; chip.curr = -5;
	for (i = 0; i < 900; i++) step_raw(i % 36 == 35 ? -1 : 0, "spike_rest");
	return 0;
}
'''


def tdiv(a, b):
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q

def pairs(path, name):
    m = re.search(r'%s\[\d+\] = \{(.*?)\};' % name, path.read_text(), re.S)
    v = [int(x) for x in re.findall(r'-?\d+', m.group(1))]
    return list(zip(v[0::2], v[1::2]))

NTC, OCV = pairs(SUPPLY / 'oz8806_ntc.h', 'oz8806_ntc'), pairs(OCV_FILE, 'oz8806_ocv')
cap = re.search(r'#define OZ8806_OCV_CAPACITY_MAH\s+(\d+)', OCV_FILE.read_text())
DESIGN = int(cap.group(1)) if cap else 4000
ONEPCT, RI, CV, END_V, END_I = DESIGN // 100, 18, 4400, 3450, 300
REST_S, DEADBAND = 1800, 3

def one_lat(t, x):
    if x < t[0][0] or t[0][0] == x: return t[0][1]
    i = 1
    while True:
        if i == len(t): return t[-1][1]
        if t[i][0] == x: return t[i][1]
        if t[i][0] >= x: break
        i += 1
    num = (x - t[i-1][0]) * (t[i][1] - t[i-1][1])
    return (tdiv(num, t[i][0] - t[i-1][0]) if t[i][0] != t[i-1][0] else num) + t[i-1][1]

def calc_soc(volt, curr, temp):
    if curr < 0:
        return one_lat(OCV, volt - tdiv(curr * RI, 1000))
    return one_lat(OCV, volt - tdiv(curr * (RI + 100), 1000))

def build(tmp, write):
    stub = tmp / 'stub/linux'; stub.mkdir(parents=True, exist_ok=True)
    (stub / 'types.h').write_text('#include <stdint.h>\n')
    (tmp / 'harness.c').write_text(HARNESS)
    exe = tmp / ('soc-write' if write else 'soc-ro')
    cmd = ['gcc', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror', '-std=gnu11',
           '-I', str(tmp / 'stub'), '-I', str(SUPPLY)] + (['-DCONFIG_OZ8806_WRITE'] if write else []) + \
          [str(SUPPLY / 'oz8806_bmulib.c'), str(tmp / 'harness.c'), '-o', str(exe)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    nm = subprocess.run(['nm', str(exe)], check=True, capture_output=True, text=True).stdout
    return exe, nm

def main():
    checks = {}
    spec = importlib.util.spec_from_file_location('ntc', ROOT / 'tools/make-pocket-oz8806-ntc.py')
    ntc = importlib.util.module_from_spec(spec); spec.loader.exec_module(ntc)
    checks['ntc_header_is_generated'] = (SUPPLY / 'oz8806_ntc.h').read_text() == ntc.header()
    spec = importlib.util.spec_from_file_location('ocv', ROOT / 'tools/make-pocket-oz8806-ocv.py')
    ocv = importlib.util.module_from_spec(spec); spec.loader.exec_module(ocv)
    checks['placeholder_ocv_is_generated'] = (SUPPLY / 'oz8806_ocv_generic.h').read_text() == ocv.generic_header()
    checks['ocv_table_in_order'] = all(b[0] > a[0] and b[1] >= a[1] for a, b in zip(OCV, OCV[1:])) and \
        OCV[0][1] == 0 and OCV[-1][1] == 100
    with tempfile.TemporaryDirectory(prefix='oz8806-soc-') as t:
        tmp = Path(t)
        ro, ro_nm = build(tmp, False)
        wr, wr_nm = build(tmp, True)
        checks['read_only_build_has_no_write_hooks'] = 'oz8806_hw_write_word' not in ro_nm and 'oz8806_hw_write_word' in wr_nm

        mid = OCV[len(OCV) // 2][0]
        hand = [('O %d' % (OCV[0][0] - 100), str(OCV[0][1])), ('O %d' % (OCV[-1][0] + 100), str(OCV[-1][1])),
                ('O %d' % mid, str(OCV[len(OCV) // 2][1])),     # exact point
                ('N 8932', '25'), ('N 10796', '20'),           # exact points of the Beta table
                ('N 9864', '23'),     # (9864-8932)*(20-25)/1864 = -2 (truncated), + 25
                ('C 3800 0 25', str(one_lat(OCV, 3800))),      # charging side: OCV table at 3800 - 0
                ('C 3800 -1000 25', str(one_lat(OCV, 3818)))]  # discharging: + 1000 mA * 18 mOhm
        grid = []
        rnd = random.Random(8806)
        for _ in range(300):
            v, i, tc = rnd.randint(3300, 4400), rnd.randint(-2500, 2500), rnd.randint(-15, 45)
            grid.append(('C %d %d %d' % (v, i, tc), str(calc_soc(v, i, tc))))
        for _ in range(200):
            x = rnd.randint(500, 90000); grid.append(('N %d' % x, str(one_lat(NTC, x))))
            x = rnd.randint(3000, 4450); grid.append(('O %d' % x, str(one_lat(OCV, x))))
        cases = hand + grid
        got = subprocess.run([str(ro), 'calc'], input='\n'.join(c for c, _ in cases) + '\n',
                             check=True, capture_output=True, text=True).stdout.split('\n')
        bad = [(c, w, g) for (c, w), g in zip(cases, got) if w != g]
        checks['hand_worked_points'] = not [b for b in bad if b[0] in dict(hand)]
        checks['reference_grid_%d_points' % len(grid)] = not bad
        assert not bad, bad[:5]

        runs = {}
        for name, exe in (('read_only', ro), ('write', wr)):
            out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
            runs[name] = [json.loads(l) for l in out.splitlines()]
    ro_run, wr_run = runs['read_only'], runs['write']
    key = ('soc', 'rc', 'car', 'init_ok', 'chg_end', 'dis_end', 'init_soc', 'cc', 'rest_soc')
    skip = ('g_asleep', 'g_wake', 'g_shutdown')
    checks['read_only_trace_equals_write_trace'] = [[r[k] for k in key] for r in ro_run if r['tag'] not in skip] == \
        [[r[k] for k in key] for r in wr_run if r['tag'] not in skip]
    checks['read_only_makes_no_writes'] = all(r['writes'] == 0 for r in ro_run if r['tag'] not in skip)
    checks['write_build_writes_car'] = any(r['writes'] > 0 for r in wr_run)
    tag = lambda n: [r for r in ro_run if r['tag'] == n]
    b1, b2, b3, b4, b5, b6, b7, b8, b9 = tag('init')[:9]

    # 1: chip CAR 2000 mAh is trusted: rc 2000, soc 2000*100/DESIGN; init at the first poll past 5 s
    checks['boot_from_car'] = (b1['rc'], b1['soc'], b1['init_ok']) == (2000, 2000 * 100 // DESIGN, 1) and b1['clock'] >= 5000
    checks['ntc_23c'] = b1['temp'] == 23
    dis = tag('dis')
    checks['discharge_counts_car'] = [(r['soc'], r['rc']) for r in dis] == \
        [(tdiv((2000 - 10 * k) * 100, DESIGN), 2000 - 10 * k) for k in range(1, len(dis) + 1)]
    checks['counted_charge_discharge'] = [r['cc'] for r in dis] == [-10000 * k for k in range(1, len(dis) + 1)]
    # 2: CAR 100 mAh; at 3300 mV discharging ends at soc 0 with rc = DESIGN/100 - 1
    low = tag('low')
    checks['boot_low'] = (b2['rc'], b2['soc']) == (100, 100 * 100 // DESIGN)
    checks['end_of_discharge'] = low[-1]['soc'] == 0 and low[-1]['rc'] == ONEPCT - 1 and low[-1]['dis_end'] == 1
    checks['counted_charge_across_car_writes'] = low[-1]['cc'] == -10000 * len(low)
    # 3: counted to 0 at 3800 mV: held at 1 % (rc one percent), no end of discharge
    hold = tag('hold')
    checks['holds_1pct_above_end_voltage'] = all(r['soc'] >= 1 and r['dis_end'] == 0 for r in hold) and \
        hold[-1]['soc'] == 1 and hold[-1]['rc'] == ONEPCT and hold[-1]['rep'] == 1
    # 4: rest at -5 mA: after REST_S the level is the OCV level (if 3 % or more away), once
    rest = tag('rest')
    s_ocv = one_lat(OCV, 3900)
    moved = abs(s_ocv - b4['soc']) >= DEADBAND
    want = max(1, min(s_ocv, 99)) if moved else b4['soc']
    t0 = rest[0]['clock'] // 1000
    before = [r for r in rest if r['clock'] // 1000 - t0 < REST_S]
    after = [r for r in rest if r['clock'] // 1000 - t0 >= REST_S]
    # before REST_S only the counter moves it (one point at most at -5 mA)
    checks['rest_waits'] = all(abs(r['soc'] - b4['soc']) <= 1 and r['rest_soc'] == -1 for r in before)
    socs = [before[-1]['soc']] + [r['soc'] for r in after]
    moves = [k for k in range(1, len(socs)) if socs[k] != socs[k - 1]]
    if not moved:
        want = socs[0]
    checks['rest_slews_to_ocv_level'] = all(r['rest_soc'] == s_ocv for r in after) and after[0]['rest_ocv'] == 3900 and \
        rest[-1]['soc'] == want and all(abs(socs[k] - socs[k - 1]) == 1 for k in moves) and \
        all(b - a >= 6 for a, b in zip(moves, moves[1:])) and \
        all((socs[k] - socs[k - 1]) * (want - socs[0]) > 0 for k in moves) and len(moves) == abs(want - socs[0])
    checks['rest_keeps_counted_charge'] = all(r['cc'] == -500 * ((k + 1) // 36) for k, r in enumerate(rest))
    spike, spike_rest = tag('spike'), tag('spike_rest')
    s_spike = max(1, min(one_lat(OCV, 3750), 99))
    checks['rest_above_empty_clears_end'] = spike[-1]['dis_end'] == 1 and spike[-1]['soc'] == 0 and \
        spike_rest[-1]['dis_end'] == 0 and spike_rest[-1]['soc'] == s_spike
    rest_hot = tag('rest_hot')
    checks['no_rest_correction_at_50c'] = rest_hot[-1]['temp'] == 50 and all(abs(r['soc'] - b5['soc']) <= 1 and r['rest_soc'] == -1 for r in rest_hot)
    # 5: charging from 94 % rises, holds 99 % at CV above the end current, then 100 % at the
    # end point with rc = DESIGN + DESIGN/100 - 1
    chg, cv, taper, full = tag('chg'), tag('cv'), tag('taper'), tag('full')
    c6 = DESIGN * 94 // 100
    checks['boot_charging'] = (b6['rc'], b6['soc']) == (c6, c6 * 100 // DESIGN)
    checks['charge_rises'] = all(b['rc'] >= a['rc'] for a, b in zip(chg, chg[1:]))
    checks['holds_99_above_end_current'] = cv[-1]['soc'] == 99 and all(r['soc'] <= 99 and r['chg_end'] == 0 for r in cv)
    lim = DESIGN + DESIGN // 100 - 1
    checks['full_at_end_point'] = taper[0]['soc'] == 100 and taper[0]['chg_end'] == 1 and \
        all(r['soc'] == 100 and r['rc'] == lim and r['chg_end'] == 1 for r in full)
    # 6: power-on OCV 3900; RTC 101 gives ext 100, s = 100 and |init_soc - 100| >= 21 while
    # discharging, so rc = init_cap = init_soc * DESIGN / 100
    i7 = calc_soc(3900, -300, 23)
    checks['power_on_ocv'] = b7['flag_ocv_boot'] == 1 and b7['init_soc'] == i7 and \
        b7['rc'] == i7 * DESIGN // 100 and b7['soc'] == b7['rc'] * 100 // DESIGN
    # 7: sleep OCV 3700; CAR says 47, more than 20 above max(OCV level, init_soc), so soc drops to that
    s8 = max(one_lat(OCV, 3700), calc_soc(3700, -300, 23))
    checks['shutdown_voltage_check'] = b8['flag_ocv_ok'] == 1 and b1['soc'] - s8 > 20 and \
        b8['soc'] == s8 and b8['rc'] == s8 * DESIGN // 100
    # 8: CAR 2 mAh: the RTC path gives rc 2 (soc 0), but 3800 mV is above the end voltage,
    # so the OCV level (init_soc) is taken
    i9 = calc_soc(3800, -300, 23)
    checks['low_car_takes_ocv_level'] = (b9['soc'], b9['rc'], b9['dis_end']) == (i9, i9 * DESIGN // 100, 0)

    # reading checks (not in stock): the supply gives -ENODATA (-61) for a chip that doesn't
    # answer, reads 0 or is asleep, and the core never runs init on those
    g = {t: tag(t) for t in ('g_dead', 'g_zero', 'g_asleep', 'g_wake', 'g_shutdown', 'g_good', 'g_fail',
                             'g_back', 'g_ntc', 'g_ntc_back', 'g_ntc_open', 'g_ntc_cold', 'g_car', 'g_car_3400')}
    nodata = lambda r: r['rep'] == -61 and r['data_ok'] == 0 and r['init_ok'] == 0
    checks['no_answer_nodata'] = nodata(g['g_dead'][0])
    checks['reads_zero_nodata'] = nodata(g['g_zero'][0])
    checks['asleep_nodata'] = nodata(g['g_asleep'][0]) and g['g_asleep'][0]['asleep'] == 1
    checks['wake_write_then_valid'] = g['g_wake'][0]['data_ok'] == 1 and g['g_wake'][0]['writes'] == 1 and g['g_wake'][0]['early'] == 0 and g['g_wake'][0]['other_writes'] == 0 and \
        g['g_asleep'][0]['early'] == 0 and g['g_asleep'][0]['other_writes'] == 0 and \
        g['g_shutdown'][0]['writes'] == 1 and g['g_shutdown'][0]['op'] == 0x60 and \
        g['g_asleep'][0]['writes'] >= 2
    checks['valid_start_reports'] = g['g_good'][0]['data_ok'] == 1 and g['g_good'][0]['rep'] == 2000 * 100 // DESIGN
    checks['failed_polls_drop_data'] = [r['data_ok'] for r in g['g_fail']] == [1, 1, 0] and \
        g['g_fail'][-1]['rep'] == -61 and g['g_back'][0]['data_ok'] == 1
    checks['ntc_fail_temp_nodata'] = g['g_ntc'][0]['temp_ok'] == 0 and g['g_back'][0]['temp_ok'] == 1
    # oz8806_get_charger_temp(): bi.temp only with data_ok, temp_ok and temp_valid, else -1
    ctemp = lambda r: r['temp'] if r['data_ok'] and r['temp_ok'] and r['temp_valid'] else -1
    checks['charger_temp_valid_ntc'] = [ctemp(g['g_good'][0]), ctemp(g['g_ntc_back'][0])] == [23, 23]
    checks['charger_temp_not_ready'] = all(ctemp(r) == -1 for r in [g['g_dead'][0], g['g_zero'][0], g['g_fail'][-1],
                                                                    g['g_ntc'][0], g['g_ntc_open'][0], g['g_ntc_cold'][0]])
    checks['ntc_open_keeps_25c_for_soc'] = g['g_ntc_open'][0]['temp'] == 25 and g['g_ntc_open'][0]['temp_ok'] == 1
    # the fake chip gives the same raw words every poll at -300 mA: flagged from the 3rd
    checks['frozen_readings_flagged'] = [r['frozen'] for r in dis[:4]] == [0, 0, 1, 1] and \
        not g['g_back'][0]['frozen']
    wr_car = [r for r in wr_run if r['tag'] == 'g_car']
    i_car = calc_soc(3800, -300, 23)
    checks['car_1_to_5_takes_ocv_level'] = all(r['soc'] == i_car and r['rep'] == i_car for r in g['g_car'] + wr_car)
    checks['car_low_at_3400_reads_0'] = g['g_car_3400'][0]['soc'] == 0 and g['g_car_3400'][0]['rep'] == 0

    ok = all(checks.values())
    record = {'source': {p: hashlib.sha256((SUPPLY / p).read_bytes()).hexdigest() for p in
                         ['oz8806_bmulib.c', 'oz8806_bmulib.h', 'oz8806_ntc.h', OCV_FILE.name]},
              'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'checks': checks, 'passed': ok,
              'traces': {'validity': g, 'init': tag('init'), 'discharge_last': dis[-1], 'low_last': low[-1],
                         'hold_last': hold[-1], 'rest_last': rest[-1], 'charge_last': chg[-1], 'cv_last': cv[-1], 'full': full},
              'limits': ['Host build of the level core only; the i2c driver, timing and the chip itself are not exercised',
                         'The fake chip counts CAR in 16 bits with wrap; whether the OZ8806 wraps or saturates is unknown']}
    if not ARGS.supply:
        RECORD.parent.mkdir(parents=True, exist_ok=True)
        RECORD.write_text(json.dumps(record, indent=2) + '\n')
    print('OCV table', OCV_FILE.name, '%d points' % len(OCV))
    for k, v in checks.items():
        print(('ok   ' if v else 'FAIL ') + k)
    print('%d checks, %s' % (len(checks), 'all pass' if ok else 'failures'))
    raise SystemExit(0 if ok else 1)

if __name__ == '__main__':
    main()
