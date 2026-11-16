#!/usr/bin/env python3
"""Host check for the mtk-kpd port (patch 0029); no build, image or phone access.

- Board dtb (firstboot-5.10/board/keyboard.dtb): /kp@10010000 and the MT6358 mt-pmic node are
  enabled, with the stock live DT properties, and mt-pmic's pwrkey, pwrkey_r, homekey and homekey_r
  IRQs are MT6358_IRQ_PWRKEY, _PWRKEY_R, _HOMEKEY and _HOMEKEY_R in U's mt6358 core.h.
- The key bits mtk-kpd sets from that DT (stock's probe rules: sw-pwrkey, hw map with slot 8 and
  every ninth slot from 17 cleared, sw-rstkey, KEY_RESTART) equal the mtk-kpd keys stock reports in
  the saved getevent capture.
- U's kpd.c keeps stock's input name and IDs (mtk-kpd, BUS_HOST, 2454:6500 v0010).
- The long-press reset fields match the 4.14 upmu_hw.h (TOP_RST_MISC 0x14c, bits 8, 9, 12-13),
  and the resolved .config (if built) has stock's KPD options.
Writes evidence/kernel-upgrade/mtk-kpd-check.json.
"""
import pocket_paths
import glob, hashlib, json, os, re, runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
U = ROOT / 'tools/kernel-source/upgrade-5.10'
KPD = U / 'drivers/input/keyboard/mediatek'
TDIR = Path(glob.glob(str(ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5*'))[0])
UPMU = TDIR / 'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/upmu_hw.h'
BULK = pocket_paths.build_root()
BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb'
CONFIG = BULK / 'kernel-firstboot-5.10/.config'
LIVE = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
STOCK_CAPS = ROOT / 'evidence/stock-input/20261029T020115.401065Z-typing/input-capabilities.txt'
RECORD = ROOT / 'evidence/kernel-upgrade/mtk-kpd-check.json'
KP = '/kp@10010000'
MT_PMIC = '/pwrap@1000d000/mt6358-pmic/mt-pmic'
KEY_NAMES = {102: 'KEY_HOME', 114: 'KEY_VOLUMEDOWN', 115: 'KEY_VOLUMEUP', 116: 'KEY_POWER', 0x198: 'KEY_RESTART'}
NUM_KEYS = 72


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    os.environ.setdefault('POCKET_DIAGNOSTIC_VARIANT', 'v4')
    tree = runpy.run_path(str(ROOT / 'tools/prepare-pocket-diagnostic-tree.py'), run_name='kpd_check_helpers')
    decode, values, text, enabled = tree['DECODE'], tree['values'], tree['text'], tree['enabled']
    board = decode(BOARD.read_bytes())['nodes']
    live = decode(LIVE.read_bytes())['nodes']
    checks = {}

    for p in (KP, MT_PMIC):
        checks[p + ' enabled'] = enabled(board, p)
        checks[p + ' as stock live'] = ({k: v for k, v in board[p].items() if k != 'status'} ==
                                        {k: v for k, v in live[p].items() if k != 'status'})

    core = (U / 'include/linux/mfd/mt6358/core.h').read_text()
    m = re.search(r'MT6358_IRQ_PWRKEY = (\d+),\s*MT6358_IRQ_HOMEKEY,\s*MT6358_IRQ_PWRKEY_R,\s*MT6358_IRQ_HOMEKEY_R,', core)
    assert m, 'MT6358 PSC IRQ enum moved'
    base = int(m.group(1))
    hw = {'pwrkey': base, 'homekey': base + 1, 'pwrkey_r': base + 2, 'homekey_r': base + 3}
    names = text(board[MT_PMIC]['interrupt-names'])
    irqs = values(board[MT_PMIC]['interrupts'])
    dt = {n: irqs[2 * names.index(n)] for n in hw}
    checks['mt-pmic key IRQs are the MT6358 enum'] = dt == hw
    pmic = MT_PMIC.rsplit('/', 1)[0]
    checks['MT6358 is a 2-cell interrupt controller'] = ('interrupt-controller' in board[pmic] and
                                                      values(board[pmic]['#interrupt-cells']) == [2])

    kp = board[KP]
    one = lambda k: values(kp[k])[0]
    keymap = values(kp['mediatek,kpd-hw-init-map'])[:one('mediatek,kpd-hw-map-num')]
    keymap += [0] * (NUM_KEYS - len(keymap))
    keymap[8] = 0
    if not one('mediatek,kpd-use-extend-type'):
        for i in range(17, NUM_KEYS, 9):
            keymap[i] = 0
    bits = {one('mediatek,kpd-sw-pwrkey')} | {k for k in keymap if k} | {one('mediatek,kpd-sw-rstkey'), 0x198}
    ours = sorted(KEY_NAMES.get(k, '%04x' % k) for k in bits)
    caps = STOCK_CAPS.read_text()
    block = caps[caps.index('name:     "mtk-kpd"'):]
    block = block[:block.index('input props')]
    stock = sorted(re.findall(r'\b(KEY_\w+|[0-9a-f]{4})\b', block.split('KEY (0001):', 1)[1]))
    checks['key bits match stock getevent'] = ours == stock

    src = (KPD / 'kpd.c').read_text()
    checks['input name and IDs as stock'] = all(s in src for s in (
        '#define KPD_NAME\t"mtk-kpd"', 'BUS_HOST', 'id.vendor = 0x2454', 'id.product = 0x6500', 'id.version = 0x0010'))

    upmu = UPMU.read_text()
    field = lambda n: (re.search(r'#define PMIC_%s_ADDR\s+(\w+)' % n, upmu).group(1),
                       int(re.search(r'#define PMIC_%s_MASK\s+(\w+)' % n, upmu).group(1), 16),
                       int(re.search(r'#define PMIC_%s_SHIFT\s+(\w+)' % n, upmu).group(1)))
    glue = (KPD / 'kpd-mt6358.c').read_text()
    checks['TOP_RST_MISC fields as upmu_hw.h'] = (
        field('RG_HOMEKEY_RST_EN') == ('MT6358_TOP_RST_MISC', 1, 8) and
        field('RG_PWRKEY_RST_EN') == ('MT6358_TOP_RST_MISC', 1, 9) and
        field('RG_PWRKEY_RST_TD') == ('MT6358_TOP_RST_MISC', 3, 12) and
        'MT6358_TOP_RST_MISC  ((unsigned int)(PMIC_BASE+0x14c))' in upmu and
        all(s in glue for s in ('MT6358_TOP_RST_MISC\t\t0x014c', 'RG_HOMEKEY_RST_EN\t\tBIT(8)',
                                'RG_PWRKEY_RST_EN\t\tBIT(9)', 'RG_PWRKEY_RST_TD_SHIFT\t\t12')))

    want = {'CONFIG_KEYBOARD_MTK': 'y', 'CONFIG_KPD_PWRKEY_USE_PMIC': 'y', 'CONFIG_ONEKEY_REBOOT_NORMAL_MODE': 'y',
            'CONFIG_ONEKEY_REBOOT_OTHER_MODE': 'y', 'CONFIG_KPD_PMIC_LPRST_TD': '0', 'CONFIG_MTK_MRDUMP_KEY': 'y'}
    if CONFIG.exists():
        conf = dict(re.findall(r'^(CONFIG_\w+)=(.*)$', CONFIG.read_text(), re.M))
        checks['.config has the stock KPD options'] = all(conf.get(k) == v for k, v in want.items())
        checks['.config has no TWOKEY reset'] = not any(conf.get(k) == 'y' for k in
                                                         ('CONFIG_TWOKEY_REBOOT_NORMAL_MODE', 'CONFIG_TWOKEY_REBOOT_OTHER_MODE'))

    record = {'board_dtb': {'path': str(BOARD), 'sha256': sha(BOARD)}, 'live_dtb_sha256': sha(LIVE),
              'stock_capabilities': str(STOCK_CAPS.relative_to(ROOT)), 'keys': ours, 'pmic_key_hwirqs': dt,
              'checks': checks, 'config_checked': CONFIG.exists(),
              'limits': ['Static only: the keypad matrix, the MT6358 key IRQs and the long-press reset are not run on the phone']}
    RECORD.write_text(json.dumps(record, indent=2) + '\n')
    for k, v in checks.items():
        print(('OK  ' if v else 'FAIL') + ' ' + k)
    print('keys:', ' '.join(ours))
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == '__main__':
    main()
