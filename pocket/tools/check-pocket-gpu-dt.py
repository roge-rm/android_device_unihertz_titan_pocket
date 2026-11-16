#!/usr/bin/env python3
"""Check the GPU overlay against the v9 board and the captured stock DT; no phone access.

Applies kernel-upgrade/dts/pocket-mm-providers.dtso, pocket-display.dtso and pocket-gpu.dtso to the
v9 board the keyboard board tool starts from (artifacts/diagnostic-5.10-v9/board/diagnostic.dtb)
and checks:
- the GPU targets (mfgcfg, gpufreq, mali, fhctl) are disabled there, and the overlay changes only
  their status, plus vgpu-supply and vsram_gpu-supply on /gpufreq (stock has neither), each the
  phandle of the regulator with that name
- each is enabled in the stock live DT, with the other properties as captured
- every provider they name (clocks, interrupt-parent, ...) is enabled with the overlays applied
- the vgpu and vsram_gpu regulators gpufreq asks for by name are enabled and the MT6358 regulator
  driver is built
- no built 5.10 driver outside the ported GPU, gpufreq, freq hopping, clock and syscon code
  matches their compatibles, and panfrost, lima and the SSPM freq hopping aren't built
- the first-boot board (artifacts/firstboot-5.10/board/keyboard.dtb) has each GPU node exactly as
  the overlay leaves it, plus a phandle and #cooling-cells on /gpufreq
Writes evidence/kernel-upgrade/gpu-dt-check.json.
"""
import pocket_paths
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BASE = BULK / 'artifacts/diagnostic-5.10-v9/board/diagnostic.dtb'
BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb'
BUILD = BULK / 'kernel-firstboot-5.10'
LIVE = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
LIVE_SHA = 'd6d1b6a89e13ad130022ad31b9394e5b7def449c88a181d40cfcc47ec452763f'
U = ROOT / 'tools/kernel-source/upgrade-5.10'
EARLIER = ['pocket-mm-providers.dtso', 'pocket-display.dtso']
OVERLAY = 'pocket-gpu.dtso'
OUT = ROOT / 'artifacts/kernel-upgrade'
RECORD = ROOT / 'evidence/kernel-upgrade/gpu-dt-check.json'
OWNERS = ('drivers/misc/mediatek/gpu/', 'drivers/misc/mediatek/base/power/mt6771/',
          'drivers/misc/mediatek/freqhopping/', 'drivers/clk/mediatek/clk-mt6771', 'drivers/mfd/syscon.c')
# Drivers that would take the GPU if built, and stock's SSPM freq hopping, which isn't ported.
OTHERS = ['drivers/gpu/drm/panfrost', 'drivers/gpu/drm/lima',
          'drivers/misc/mediatek/freqhopping/mt6771/mtk_freqhopping_sspm.o']
# gpufreq's devm_regulator_get(dev, "vgpu" / "vsram_gpu"). The overlay's -supply properties make
# 5.10 resolve them by phandle and defer until the MT6358 regulators register; without them it would
# fall back to the name and, before mt6397 probes, hand out a dummy.
REGULATORS = {'vgpu': '/pwrap@1000d000/mt6358-pmic/mt6358regulator/buck_vgpu',
              'vsram_gpu': '/pwrap@1000d000/mt6358-pmic/mt6358regulator/ldo_vsram_gpu'}
# The only properties the overlay adds besides status.
SUPPLIES = {('/gpufreq', 'vgpu-supply'): 'vgpu', ('/gpufreq', 'vsram_gpu-supply'): 'vsram_gpu'}
# Added to /gpufreq on the first-boot board only, by prepare-pocket-keyboard-board.py.
BOARD_COOLING = {'phandle', '#cooling-cells'}
PHANDLE_PROPS = {'clocks': '#clock-cells', 'vgpu-supply': None, 'vsram_gpu-supply': None, 'mboxes': '#mbox-cells', 'power-domains': '#power-domain-cells',
                 'iommus': '#iommu-cells', 'interrupt-parent': None}


def load_parser():
    spec = importlib.util.spec_from_file_location('inspect_fdt', ROOT / 'tools/inspect-fdt.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def enabled(node):
    v = node.get('status')
    return not v or v['strings'][0] in ('okay', 'ok')


def providers(nodes, path):
    by = {n['phandle']['cells'][0]: p for p, n in nodes.items() if 'phandle' in n}
    out = set()
    for k, v in nodes[path].items():
        cells = v.get('cells') if isinstance(v, dict) else None
        if not cells or not (k in PHANDLE_PROPS or re.fullmatch(r'pinctrl-\d+', k)):
            continue
        size = PHANDLE_PROPS.get(k)
        i = 0
        while i < len(cells):
            prov = by[cells[i]]
            out.add((k, prov))
            i += 1 + (nodes[prov][size]['cells'][0] if size else 0)
        assert i == len(cells), (path, k)
    return out


def built(rel):
    p = BUILD / rel
    return any(p.glob('*.o')) if p.is_dir() else p.exists()


def main():
    assert hashlib.sha256(LIVE.read_bytes()).hexdigest() == LIVE_SHA
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    OUT.mkdir(parents=True, exist_ok=True)
    dtbos = []
    for name in EARLIER + [OVERLAY]:
        dtbo = OUT / name.replace('.dtso', '.dtbo')
        subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(dtbo),
                        str(ROOT / 'kernel-upgrade/dts' / name)], check=True)
        dtbos.append(str(dtbo))
    targets = re.findall(r'target-path = "([^"]+)"', (ROOT / 'kernel-upgrade/dts' / OVERLAY).read_text())
    earlier = {t for n in EARLIER for t in re.findall(r'target-path = "([^"]+)"', (ROOT / 'kernel-upgrade/dts' / n).read_text())}
    assert len(targets) == len(set(targets)) and not earlier & set(targets)
    before_dtb = OUT / 'gpu-board-before.dtb'
    derived = OUT / 'gpu-board-probe.dtb'
    subprocess.run([str(OUT / 'fdtoverlay'), '-i', str(BASE), '-o', str(before_dtb)] + dtbos[:-1], check=True)
    subprocess.run([str(OUT / 'fdtoverlay'), '-i', str(before_dtb), '-o', str(derived), dtbos[-1]], check=True)
    fdt = load_parser()
    live = fdt.decode(LIVE.read_bytes())['nodes']
    before = fdt.decode(before_dtb.read_bytes())['nodes']
    after = fdt.decode(derived.read_bytes())['nodes']
    board = fdt.decode(BOARD.read_bytes())['nodes']
    assert before.keys() == after.keys()

    assert not [t for t in targets if enabled(before[t])], 'targets already enabled on the base board'
    changed = {(p, k) for p in before for k in set(before[p]) | set(after[p]) if before[p].get(k) != after[p].get(k)}
    assert changed == {(t, 'status') for t in targets} | set(SUPPLIES), changed
    by_phandle = {n['phandle']['cells'][0]: p for p, n in after.items() if 'phandle' in n}
    for (t, k), name in SUPPLIES.items():
        assert k not in live[t] and k not in before[t], (t, k)
        assert len(after[t][k]['cells']) == 1 and by_phandle[after[t][k]['cells'][0]] == REGULATORS[name], (t, k)
    for t in targets:
        assert enabled(after[t]) and enabled(live[t]), t
        drop = {'status'} | {k for p, k in SUPPLIES if p == t}
        assert {k: v for k, v in live[t].items() if k not in drop} == \
               {k: v for k, v in after[t].items() if k not in drop}, ('not as captured', t)

    edges = sorted((t, k, p) for t in targets for k, p in providers(after, t))
    off = [e for e in edges if not enabled(after[e[2]])]
    assert not off, off

    for name, path in REGULATORS.items():
        n = after[path]
        assert n['regulator-name']['strings'] == [name] and enabled(n) and enabled(live[path]), path
    assert built('drivers/regulator/mt6358-regulator.o')
    src = (U / 'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq_core.c').read_text()
    assert 'devm_regulator_get(&pdev->dev, "vgpu")' in src and 'devm_regulator_get(&pdev->dev, "vsram_gpu")' in src
    assert 'regulator_ignore_unused' in (ROOT / 'tools/package-pocket-boot.py').read_text()

    compats = sorted({c for t in targets for c in after[t].get('compatible', {}).get('strings', [])})
    matches = {}
    for f in (U / 'drivers').rglob('*.c'):
        text = f.read_text(errors='replace').lower()
        hit = [c for c in compats if f'"{c.lower()}"' in text]
        rel = f.relative_to(U)
        if hit and built(rel.with_suffix('.o')):
            matches[str(rel)] = hit
    strays = {f: c for f, c in matches.items() if not f.startswith(OWNERS)}
    assert not strays, strays
    others = [o for o in OTHERS if built(o)]
    assert not others, others
    for m in ('mali_kbase_core_linux.c', 'mtk_gpufreq_core.c', 'mtk_freqhopping_drv.c'):
        assert any(f.endswith(m) for f in matches), ('not built', m)

    # The keyboard board tool also makes /gpufreq a cooling device (POWER_PORT.md P5b).
    for t in targets:
        extra = BOARD_COOLING if t == '/gpufreq' else set()
        assert extra <= set(board[t]) and not extra & set(after[t]), (t, 'cooling properties')
        assert {k: v for k, v in board[t].items() if k not in extra} == after[t], ('first-boot board differs from the overlay', t)
    state = 'applied'

    record = {
        'base_board_sha256': hashlib.sha256(BASE.read_bytes()).hexdigest(),
        'board_sha256': hashlib.sha256(BOARD.read_bytes()).hexdigest(),
        'board_overlay': state,
        'live_sha256': LIVE_SHA,
        'derived_sha256': hashlib.sha256(derived.read_bytes()).hexdigest(),
        'overlay_sha256': hashlib.sha256((ROOT / 'kernel-upgrade/dts' / OVERLAY).read_bytes()).hexdigest(),
        'enabled_nodes': sorted(targets),
        'providers': [list(e) for e in edges],
        'regulators': REGULATORS,
        'compatible_owners': matches,
        'scope': 'Offline DT and source check; probing is untested',
    }
    RECORD.write_text(json.dumps(record, indent=2) + '\n')
    print(f'{len(targets)} GPU nodes enabled as captured, {len(edges)} provider links all enabled, '
          f'vgpu and vsram_gpu enabled, {len(matches)} built matching sources all ported; first-boot board: {state}')


if __name__ == '__main__':
    main()
