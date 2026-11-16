#!/usr/bin/env python3
"""Check the display overlays against the first-boot board and the captured stock DT; no phone access.

Applies kernel-upgrade/dts/pocket-mm-providers.dtso and pocket-display.dtso to the v9 board the
keyboard board tool starts from (artifacts/diagnostic-5.10-v9/board/diagnostic.dtb) and checks:
- every targeted node is disabled there, and the overlays change only their status
- each is enabled in the stock live DT, with the other properties as captured
- the first-boot board (artifacts/firstboot-5.10/board/keyboard.dtb) has each of them as the
  overlays leave them
- every provider those nodes name (each phandle in clocks, pinctrl-*, interrupt-parent, mboxes,
  power-domains, iommus) is enabled on the first-boot board, but for gce_mbox_svp (below)
- no built 5.10 driver outside the ported DISP, M4U, SMI, CMDQ, clock, videocodec, camera ISP and JPEG code matches their
  compatibles, and drm/mediatek, pwm-mtk-disp and simplefb aren't built
- LK's atag,videolfb in the live /chosen points at mblock-12-framebuffer, and the board has no
  reserved-memory node of its own over it
Writes evidence/kernel-upgrade/disp-dt-check.json.
"""
import pocket_paths
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BASE = BULK / 'artifacts/diagnostic-5.10-v9/board/diagnostic.dtb'
BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb'
BUILD = BULK / 'kernel-firstboot-5.10'
LIVE = ROOT / 'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
LIVE_SHA = 'd6d1b6a89e13ad130022ad31b9394e5b7def449c88a181d40cfcc47ec452763f'
U = ROOT / 'tools/kernel-source/upgrade-5.10'
OVERLAYS = ['pocket-mm-providers.dtso', 'pocket-display.dtso']
OUT = ROOT / 'artifacts/kernel-upgrade'
RECORD = ROOT / 'evidence/kernel-upgrade/disp-dt-check.json'
# Source files allowed to match the enabled compatibles: the ported stock drivers, the clocks and
# syscon, which makes its regmap when a driver asks for it, as in stock.
OWNERS = ('drivers/misc/mediatek/video/', 'drivers/misc/mediatek/leds/', 'drivers/misc/mediatek/m4u/',
          'drivers/misc/mediatek/smi/', 'drivers/misc/mediatek/cmdq/', 'drivers/clk/mediatek/clk-mt6771',
          'drivers/memory/mtk-smi.c', 'drivers/mailbox/mtk-cmdq-mailbox.c', 'drivers/mfd/syscon.c',
          'drivers/misc/mediatek/scp/',
          # stock's videocodec driver binds vdec_gcon as stock (CAMERA_PORT.md milestone V)
          'drivers/misc/mediatek/videocodec/',
          # camera_isp binds camsys and camera_dip imgsys as stock (with their clock drivers); both only look
          # mmsys_config up, ISP to see it's there, DIP's of_iomap is under #if 0 (CAMERA_PORT.md milestone C3)
          'drivers/misc/mediatek/cameraisp/',
          # jpeg_driver names venc_gcon only under JPEG_PM_DOMAIN_ENABLE, which mt6771 doesn't build; it takes the
          # venc_jpg node and its venc_gcon JPGENC clock through the device tree (CAMERA_PORT.md milestone C6)
          'drivers/misc/mediatek/jpeg/')
# Mainline drivers that would take the display or the framebuffer if built. mtk-mmsys is built but
# lists only mediatek,mtXXXX-mmsys, so the compatible search covers it.
MAINLINE = ['drivers/gpu/drm/mediatek', 'drivers/pwm/pwm-mtk-disp.o',
            'drivers/video/fbdev/simplefb.o', 'drivers/gpu/drm/tiny/simpledrm.o']
# Phandle lists and the provider property giving each entry's argument count (None: no arguments).
PHANDLE_PROPS = {'clocks': '#clock-cells', 'mboxes': '#mbox-cells', 'power-domains': '#power-domain-cells',
                 'iommus': '#iommu-cells', 'interrupt-parent': None}
# /gce mboxes threads 8 to 10 to the disabled gce_mbox_svp (mediatek,mailbox-gce-svp, which nothing
# here binds). Milestone 4 keeps those threads off with the secure path off, so they're never asked for.
KNOWN_DISABLED = {('/gce@10238000', 'mboxes', '/gce_mbox_svp@10238000')}


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


def built_object(src):
    obj = BUILD / src.relative_to(U).with_suffix('.o')
    return obj.exists()


def main():
    assert hashlib.sha256(LIVE.read_bytes()).hexdigest() == LIVE_SHA
    dtc = ROOT / 'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
    OUT.mkdir(parents=True, exist_ok=True)
    targets = []
    dtbos = []
    for name in OVERLAYS:
        src = ROOT / 'kernel-upgrade/dts' / name
        dtbo = OUT / name.replace('.dtso', '.dtbo')
        subprocess.run([str(dtc), '-@', '-I', 'dts', '-O', 'dtb', '-o', str(dtbo), str(src)], check=True)
        dtbos.append(str(dtbo))
        targets += re.findall(r'target-path = "([^"]+)"', src.read_text())
    assert len(targets) == len(set(targets))
    derived = OUT / 'display-board-probe.dtb'
    subprocess.run([str(OUT / 'fdtoverlay'), '-i', str(BASE), '-o', str(derived)] + dtbos, check=True)
    fdt = load_parser()
    live = fdt.decode(LIVE.read_bytes())['nodes']
    before = fdt.decode(BASE.read_bytes())['nodes']
    derived_nodes = fdt.decode(derived.read_bytes())['nodes']
    after = fdt.decode(BOARD.read_bytes())['nodes']
    assert before.keys() == derived_nodes.keys()

    assert not [t for t in targets if enabled(before[t])], 'targets already enabled on the base board'
    changed = {(p, k) for p in before for k in set(before[p]) | set(derived_nodes[p])
               if before[p].get(k) != derived_nodes[p].get(k)}
    assert changed == {(t, 'status') for t in targets}, changed
    for t in targets:
        assert enabled(derived_nodes[t]) and enabled(live[t]), t
        drop = {'status'}
        assert {k: v for k, v in live[t].items() if k not in drop} == \
               {k: v for k, v in derived_nodes[t].items() if k not in drop}, ('not as captured', t)
        assert after[t] == derived_nodes[t], ('first-boot board differs from the overlays', t)

    edges = {(t, k, p) for t in targets for k, p in providers(after, t) if not enabled(after[p])}
    assert edges == KNOWN_DISABLED, sorted(edges)

    compats = sorted({c for t in targets for c in after[t].get('compatible', {}).get('strings', [])})
    matches = {}
    for src in (U / 'drivers').rglob('*.c'):
        text = src.read_text(errors='replace').lower()
        hit = [c for c in compats if f'"{c.lower()}"' in text]
        if hit and built_object(src):
            matches[str(src.relative_to(U))] = hit
    strays = {f: c for f, c in matches.items() if not f.startswith(OWNERS)}
    assert not strays, strays
    mainline_built = [m for m in MAINLINE if (BUILD / m).exists() and
                      (not (BUILD / m).is_dir() or any((BUILD / m).glob('*.o')))]
    assert not mainline_built, mainline_built
    assert not any('simple-framebuffer' in n.get('compatible', {}).get('strings', []) for n in after.values())

    # LK's tag: u64 fb_base, u32 islcmfound, u32 fps, u32 vram, then the LCM name, little endian.
    raw = struct.pack('>%dI' % len(live['/chosen']['atag,videolfb']['cells']), *live['/chosen']['atag,videolfb']['cells'])
    fb_base, found, fps, vram = struct.unpack_from('<QIII', raw)
    lcm = raw[20:].split(b'\0')[0].decode()
    fb = live['/reserved-memory/mblock-12-framebuffer']
    cells = fb['reg']['cells']
    base, size = cells[0] << 32 | cells[1], cells[2] << 32 | cells[3]
    assert 'no-map' in fb and (fb_base, vram) == (base, size) and found == 1 and lcm == 'R63308_CASCADEMDZ40'
    board_rsv = [p for p in after if p.startswith('/reserved-memory/') and p.count('/') == 2 and 'reg' in after[p]]
    overlaps = []
    for p in board_rsv:
        c = after[p]['reg']['cells']
        b, s = c[0] << 32 | c[1], c[2] << 32 | c[3]
        if b < base + size and base < b + s:
            overlaps.append(p)
    assert not overlaps, overlaps
    assert not any('mblock' in p for p in after), 'the board should leave mblock nodes to LK'

    record = {
        'base_board_sha256': hashlib.sha256(BASE.read_bytes()).hexdigest(),
        'board_sha256': hashlib.sha256(BOARD.read_bytes()).hexdigest(),
        'known_disabled_providers': sorted(KNOWN_DISABLED),
        'live_sha256': LIVE_SHA,
        'derived_sha256': hashlib.sha256(derived.read_bytes()).hexdigest(),
        'overlays': {n: hashlib.sha256((ROOT / 'kernel-upgrade/dts' / n).read_bytes()).hexdigest() for n in OVERLAYS},
        'enabled_nodes': sorted(t for t, _ in changed),
        'compatible_owners': matches,
        'videolfb': {'fb_base': hex(fb_base), 'vram': hex(vram), 'islcmfound': found, 'fps_x100': fps, 'lcm': lcm,
                     'mblock_12': [hex(base), hex(size)]},
        'scope': 'Offline DT and source check; the board has to apply these overlays, and probing is untested',
    }
    RECORD.write_text(json.dumps(record, indent=2) + '\n')
    print(f'{len(changed)} nodes enabled from the base board, as on the first-boot board; providers enabled but '
          f'gce_mbox_svp (threads 8 to 10, unused), {len(matches)} built matching sources all ported, '
          f'videolfb {hex(fb_base)}+{hex(vram)} = mblock-12, LCM {lcm}')


if __name__ == '__main__':
    main()
