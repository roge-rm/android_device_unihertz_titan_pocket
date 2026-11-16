#!/usr/bin/env python3
"""Make the OZ8806 driver's OCV table (drivers/power/supply/oz8806_ocv.h) from an OCV run log.

The log is the CSV pocket_battlog writes on the phone (/data/misc/pocket_battlog/):
phase,step,t_s,volt_mv,curr_ma,cc_uah,chip_ocv_mv,temp_c,soc,rc_mah,adapter,rest_s
with phase rest or load, and # lines for events. The run starts at full and alternates rests
and loads down to the stop voltage.

For each rest it takes the voltage and current over its last 2 minutes and the counted charge
at its end. The cell resistance comes from the voltage step at each load to rest change
(median), and takes the IR drop of the rest current out. Level is the charge counted from the
end of the first rest (100 %) to the end of the last (0 %); that charge is the capacity. The
points are made monotonic and resampled to --points levels evenly spaced.

With more than one log it uses the newest that makes a table (the names sort by date) and
says why it skipped the newer ones.

--generic writes the placeholder oz8806_ocv_generic.h instead: a smooth model curve for a
4.4 V Li-ion cell, 3400 mV empty to 4400 mV full, not measured. The driver uses it only when
there is no oz8806_ocv.h, so the level is approximate until a measured table is added.

  python3 tools/make-pocket-oz8806-ocv.py battlog.csv          write the header
  python3 tools/make-pocket-oz8806-ocv.py battlog-*.csv        the newest complete run
  python3 tools/make-pocket-oz8806-ocv.py battlog.csv --out F  write it somewhere else
  python3 tools/make-pocket-oz8806-ocv.py --generic            write the placeholder
  python3 tools/make-pocket-oz8806-ocv.py --generic --check    exit 1 if it differs
  python3 tools/make-pocket-oz8806-ocv.py --self-test          run on a made-up discharge
"""
import argparse, csv, hashlib, math, statistics, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/power/supply/oz8806_ocv.h'
GENERIC_OUT = OUT.with_name('oz8806_ocv_generic.h')
FIELDS = ['phase', 'step', 't_s', 'volt_mv', 'curr_ma', 'cc_uah', 'chip_ocv_mv', 'temp_c',
          'soc', 'rc_mah', 'adapter', 'rest_s']
END_WINDOW_S = 120	# rest end: the last 2 minutes
MIN_REST_S = 1200	# shorter rests are left out
STEP_WINDOW_S = 30	# load to rest change: the samples at most this far apart
MIN_POINTS = 8


class RunError(Exception):
    pass


def read_rows(path):
    rows = []
    with open(path, newline='') as f:
        for line in csv.reader(l for l in f if l.strip() and not l.startswith('#')):
            if line[0] == 'phase':
                continue
            if len(line) != len(FIELDS):
                raise RunError('%s: %d fields, want %d: %s' % (path, len(line), len(FIELDS), ','.join(line)))
            r = dict(zip(FIELDS, line))
            for k in FIELDS[1:]:
                r[k] = int(r[k])
            rows.append(r)
    if not rows:
        raise RunError('%s: no samples' % path)
    return rows


def groups(rows):
    """[(phase, step, [rows])] for runs of rows with the same phase and step."""
    out = []
    for r in rows:
        if out and out[-1][0] == r['phase'] and out[-1][1] == r['step']:
            out[-1][2].append(r)
        else:
            out.append((r['phase'], r['step'], [r]))
    return out


def resistance(gs):
    """Median ohms of the voltage step from the last load sample to the first rest sample."""
    rs = []
    for (p0, _, a), (p1, _, b) in zip(gs, gs[1:]):
        if p0 != 'load' or p1 != 'rest':
            continue
        x, y = a[-1], b[0]
        di = y['curr_ma'] - x['curr_ma']
        if y['t_s'] - x['t_s'] <= STEP_WINDOW_S and di > 100:
            rs.append((y['volt_mv'] - x['volt_mv']) / di)
    if not rs:
        raise RunError('no load to rest change to take the cell resistance from')
    return min(max(statistics.median(rs), 0.0), 0.5), len(rs)


def rest_points(gs, ohm):
    """[(cc_uah, ocv_mv, temp_c)] at the end of each rest, in run order."""
    pts, skipped = [], 0
    for phase, step, g in gs:
        if phase != 'rest':
            continue
        if g[-1]['t_s'] - g[0]['t_s'] < MIN_REST_S:
            skipped += 1
            continue
        tail = [r for r in g if r['t_s'] >= g[-1]['t_s'] - END_WINDOW_S]
        v = statistics.median(r['volt_mv'] for r in tail)
        i = statistics.mean(r['curr_ma'] for r in tail)
        pts.append((g[-1]['cc_uah'], v - i * ohm, g[-1]['temp_c']))
    return pts, skipped


def monotonic(ys):
    """Pool adjacent violators: the closest non-decreasing sequence."""
    blocks = []
    for y in ys:
        blocks.append([y, 1])
        while len(blocks) > 1 and blocks[-2][0] > blocks[-1][0]:
            y2, n2 = blocks.pop()
            blocks[-1] = [(blocks[-1][0] * blocks[-1][1] + y2 * n2) / (blocks[-1][1] + n2), blocks[-1][1] + n2]
    return [y for y, n in blocks for _ in range(n)]


def interp(xs, ys, x):
    for k in range(1, len(xs)):
        if x <= xs[k]:
            f = (x - xs[k - 1]) / (xs[k] - xs[k - 1]) if xs[k] != xs[k - 1] else 0
            return ys[k - 1] + f * (ys[k] - ys[k - 1])
    return ys[-1]


def make_table(rows, points):
    if any(r['adapter'] for r in rows):
        raise RunError('the charger was in during the run; start again from full')
    gs = groups(rows)
    ohm, steps = resistance(gs)
    pts, skipped = rest_points(gs, ohm)
    if len(pts) < MIN_POINTS:
        raise RunError('%d rests of %d s or more, want at least %d' % (len(pts), MIN_REST_S, MIN_POINTS))
    full, empty = pts[0][0], pts[-1][0]
    cap = full - empty
    if cap < 1000000:
        raise RunError('only %d mAh counted from the first rest to the last' % (cap // 1000))
    soc = [100.0 * (cc - empty) / cap for cc, _, _ in pts]
    if any(b > a for a, b in zip(soc, soc[1:])):
        raise RunError('the counted charge rose between rests')
    soc, mv = soc[::-1], monotonic([v for _, v, _ in pts][::-1])
    grid = [100.0 * k / (points - 1) for k in range(points)]
    table = []
    for s in grid:
        v = round(interp(soc, mv, s))
        if table and v <= table[-1][0]:
            v = table[-1][0] + 1
        table.append((v, round(s)))
    info = {'capacity_mah': round(cap / 1000), 'ohm': ohm, 'ohm_steps': steps, 'rests': len(pts),
            'rests_skipped': skipped, 'temp_min': min(t for _, _, t in pts), 'temp_max': max(t for _, _, t in pts),
            'measured': list(zip([round(v, 1) for v in mv], [round(s, 1) for s in soc]))}
    return table, info


def header(table, info, digest):
    rows = ['\t' + ' '.join('{%d, %d},' % p for p in table[i:i + 4]) for i in range(0, len(table), 4)]
    return ('/* SPDX-License-Identifier: GPL-2.0 */\n'
            '/*\n'
            ' * Generated by tools/make-pocket-oz8806-ocv.py, do not edit.\n'
            ' * OCV (mV) to level (%%) measured on a Titan Pocket: %d rests at %d to %d C,\n'
            ' * cell resistance %.3f Ohm from %d load steps. Log sha256 %s.\n'
            ' */\n'
            '#ifndef OZ8806_OCV_H\n'
            '#define OZ8806_OCV_H\n\n'
            '/* charge counted from the first rest to the last, mAh */\n'
            '#define OZ8806_OCV_CAPACITY_MAH %d\n\n'
            'static const struct oz8806_pair oz8806_ocv[%d] = {\n'
            '%s\n'
            '};\n\n'
            '#endif\n') % (info['rests'], info['temp_min'], info['temp_max'], info['ohm'], info['ohm_steps'],
                           digest, info['capacity_mah'], len(table), '\n'.join(rows))


def generate(log, out, points):
    table, info = make_table(read_rows(log), points)
    text = header(table, info, hashlib.sha256(Path(log).read_bytes()).hexdigest())
    Path(out).write_text(text)
    return table, info


# ---- placeholder table ----

def generic_ocv(s):
    """Model 4.4 V cell OCV in mV, s from 0 to 1: a steep knee near empty, then a rise that
    gets steeper towards full. 3400 mV at 0, about 3915 mV at 0.5, 4400 mV at 1."""
    return 3400 + 180 * (1 - math.exp(-s / 0.03)) + 520 * s + 300 * s * s


def generic_header(points=21):
    table = [(round(generic_ocv(k / (points - 1))), round(100 * k / (points - 1))) for k in range(points)]
    rows = ['\t' + ' '.join('{%d, %d},' % p for p in table[i:i + 4]) for i in range(0, len(table), 4)]
    return ('/* SPDX-License-Identifier: GPL-2.0 */\n'
            '/*\n'
            ' * Generated by tools/make-pocket-oz8806-ocv.py --generic, do not edit.\n'
            ' * Placeholder OCV (mV) to level (%%): a smooth model curve for a 4.4 V Li-ion\n'
            ' * cell, not measured. Used only when there is no oz8806_ocv.h; the level is\n'
            ' * approximate until a measured table is added.\n'
            ' */\n'
            '#ifndef OZ8806_OCV_GENERIC_H\n'
            '#define OZ8806_OCV_GENERIC_H\n\n'
            'static const struct oz8806_pair oz8806_ocv[%d] = {\n'
            '%s\n'
            '};\n\n'
            '#endif\n') % (len(table), '\n'.join(rows))


# ---- self-test on a made-up cell, not a real one ----

def true_ocv(s):
    """A smooth made-up OCV curve, s from 0 to 1."""
    return 3500 + 400 * s + 300 * s * s + 120 * (1 - math.exp(-12 * s))


def synthetic_log(path, cap_mah=4100, ohm=0.12, rest_ma=-35, load_ma=-500, rest_s=3600):
    """A stepped discharge as the logger runs it: rest, then 5 % loads with rests, to 3500 mV under load."""
    tau, pol_ohm = 600.0, 0.05
    s, t, cc, pol, step = 1.0, 0, 0.0, 0.0, 0
    lines = ['# start full', ','.join(FIELDS)]

    def sample(phase, i):
        v = true_ocv(s) + i * ohm + pol
        lines.append('%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d' % (
            phase, step, t, round(v / 2.5) * 2.5, i, round(cc), -1, 24, round(s * 100), round(s * cap_mah), 0, 0))
        return v

    def advance(i, dt):
        nonlocal s, t, cc, pol
        s -= i * -1 * dt / 3600 / cap_mah
        cc += i * dt / 3.6
        pol = pol * math.exp(-dt / tau) + i * pol_ohm * (1 - math.exp(-dt / tau))
        t += dt

    while True:
        for _ in range(rest_s // 10):
            sample('rest', rest_ma)
            advance(rest_ma, 10)
        sample('rest', rest_ma)
        step += 1
        start, stop = cc, False
        while cc > start - cap_mah * 1000 * 0.05:
            advance(load_ma, 10)
            if sample('load', load_ma) < 3500:
                stop = True
                break
        advance(rest_ma, 10)
        if stop:
            for _ in range(rest_s // 10):
                sample('rest', rest_ma)
                advance(rest_ma, 10)
            sample('rest', rest_ma)
            lines.append('# stop at the load voltage')
            break
    Path(path).write_text('\n'.join(lines) + '\n')
    return cap_mah


def self_test(points):
    ok = True
    with tempfile.TemporaryDirectory(prefix='oz8806-ocv-') as d:
        log, out = Path(d) / 'battlog.csv', Path(d) / 'oz8806_ocv.h'
        cap_true = synthetic_log(log)
        rows = read_rows(log)
        table, info = generate(log, out, points)
        text = out.read_text()
        # 100 % is the end of the first rest and 0 % where the run stopped: map the table's
        # level back to the made-up cell's, which starts at 1 with the counted charge at 0
        first_end = groups(rows)[0][2][-1]['cc_uah']
        s_first = 1.0 + first_end / 1000.0 / cap_true
        q = info['capacity_mah']
        errs = []
        for mv, g in table:
            s_true = s_first - (1 - g / 100.0) * q / cap_true
            errs.append(abs(mv - true_ocv(s_true)))
        checks = {
            'points': len(table) == points and table[0][1] == 0 and table[-1][1] == 100,
            'mv_rising': all(b[0] > a[0] for a, b in zip(table, table[1:])),
            'within_10_mv': max(errs) <= 10,
            'resistance': abs(info['ohm'] - 0.12) < 0.03,
            'capacity_define': ('#define OZ8806_OCV_CAPACITY_MAH %d' % q) in text and ('OZ8806_OCV_' + 'STOCK') not in text,
            'rests': info['rests'] >= 15,
        }
        bad_log = Path(d) / 'charger.csv'
        bad_log.write_text(log.read_text().replace(',0,0\n', ',1,0\n', 1))
        try:
            make_table(read_rows(bad_log), points)
            checks['refuses_charger'] = False
        except RunError:
            checks['refuses_charger'] = True
        for k, v in checks.items():
            print(('ok   ' if v else 'FAIL ') + k)
            ok &= v
        print('largest error %.1f mV, resistance %.3f Ohm, %d rests, capacity %d mAh of %d' %
              (max(errs), info['ohm'], info['rests'], q, cap_true))
    print('self-test', 'passes' if ok else 'fails')
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('logs', nargs='*', help='the CSV from the phone; with several, the newest complete run')
    ap.add_argument('--out', type=Path)
    ap.add_argument('--points', type=int, default=21, help='table points, evenly spaced levels (default 21)')
    ap.add_argument('--generic', action='store_true', help='write the placeholder table')
    ap.add_argument('--check', action='store_true', help='with --generic, compare instead of writing')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.points < 3:
        ap.error('--points needs at least 3')
    if a.self_test:
        sys.exit(0 if self_test(a.points) else 1)
    if a.generic:
        out, text = a.out or GENERIC_OUT, generic_header(a.points)
        if a.check:
            same = out.is_file() and out.read_text() == text
            print('%s %s' % (out, 'matches' if same else 'differs'))
            sys.exit(0 if same else 1)
        out.write_text(text)
        print('wrote %s, %d points' % (out, a.points))
        return
    if not a.logs:
        ap.error('give the log, --generic or --self-test')
    for log in sorted(a.logs, reverse=True):
        try:
            table, info = generate(log, a.out or OUT, a.points)
            break
        except RunError as e:
            print('%s: %s' % (log, e), file=sys.stderr)
    else:
        sys.exit('no log made a table')
    print('wrote %s from %s: %d points, %d rests (%d too short), %d to %d C, %.3f Ohm, %d mAh' % (
        a.out or OUT, log, len(table), info['rests'], info['rests_skipped'], info['temp_min'], info['temp_max'],
        info['ohm'], info['capacity_mah']))
    for v, s in info['measured']:
        print('  measured %7.1f mV  %5.1f %%' % (v, s))


if __name__ == '__main__':
    main()
