#!/usr/bin/env python3
"""Check the zone-movable CMA (ZMC) port offline: the DT node the stock LK hands over, the board dtb it is
copied from, the 5.10 reserved-memory path and the ZMC hook in vmlinux. No phone access."""
import pocket_paths
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
LIVE = ROOT / 'evidence/device/20261029T000648.917229Z/live-device-tree.json'
LEDGER = ROOT / 'evidence/device-tree/stock-dt-match/diff-ledger.json'
STOCK_LOG = ROOT / 'evidence/kernel-upgrade/recovery-configfs-trial-20261029T210738Z/capture/kernel.log'
SOURCE = ROOT / 'tools/kernel-source/upgrade-5.10'
COMPATIBLE = 'mediatek,zone_movable_cma'
SIZE, ALIGN = 0x2d000000, 0x1000000

results = []


def check(ok, what):
    results.append((bool(ok), what))
    print(('OK   ' if ok else 'FAIL ') + what)


def cells(prop):
    value = bytes.fromhex(prop['hex'])
    return [int.from_bytes(value[i:i + 8], 'big') for i in range(0, len(value), 8)]


def zmc_node(nodes, path, where, enabled):
    node = nodes.get(path)
    check(node is not None, f'{where}: {path} present')
    if node is None:
        return
    check(node.get('compatible', {}).get('strings') == [COMPATIBLE], f'{where}: compatible {COMPATIBLE}')
    status = node.get('status', {}).get('strings', ['okay'])[0]
    check((status in ('okay', 'ok')) == enabled, f'{where}: status {status}')
    check('no-map' not in node and 'reusable' not in node, f'{where}: no no-map and no reusable, so 5.10 memblock_reserve()s it')
    check('reg' not in node, f'{where}: no reg, a dynamic region placed by the kernel')
    check(cells(node['size']) == [SIZE], f'{where}: size 0x{SIZE:x}')
    check(cells(node['alignment']) == [ALIGN], f'{where}: alignment 0x{ALIGN:x}')
    check(cells(node['alloc-ranges']) == [0xc0000000, 0x180000000], f'{where}: alloc-ranges 0xc0000000 + 0x180000000')


def of_table_compatible(vmlinux, symbol_address):
    """Read struct of_device_id.compatible (name[32], type[32], compatible[128]) at an address in vmlinux."""
    data = vmlinux.read_bytes()
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', data, 0x3a)
    for i in range(shnum):
        _, kind, _, address, offset, size = struct.unpack_from('<IIQQQQ', data, shoff + i * shentsize)
        if kind == 1 and address <= symbol_address < address + size:
            start = offset + symbol_address - address + 64
            return data[start:start + 128].split(b'\0')[0].decode()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', default=BULK / 'kernel-firstboot-5.10')
    ap.add_argument('--board', default=BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb')
    a = ap.parse_args()
    out = Path(a.out)

    zmc_node(json.loads(LIVE.read_text())['nodes'], '/reserved-memory/zone-movable-cma-memory', 'live DT', True)
    live = json.loads(LIVE.read_text())['nodes'].get('/reserved-memory/zmc-default', {})
    check(live.get('status', {}).get('strings') == ['disabled'], 'live DT: zmc-default disabled')

    spec = importlib.util.spec_from_file_location('inspect_fdt', ROOT / 'tools/inspect-fdt.py')
    fdt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fdt)
    board = fdt.decode(Path(a.board).read_bytes())['nodes']
    zmc_node(board, '/reserved-memory/zmc-default', 'board dtb', True)
    ledger = LEDGER.read_text()
    check('/reserved-memory/zone-movable-cma-memory' in ledger and 'zmc-default disabled' in ledger,
          'stock LK adds zone-movable-cma-memory and disables zmc-default (diff ledger, observed on stock)')

    log = STOCK_LOG.read_text(errors='replace')
    check('zmc_memory_init, name: zone-movable-cma-memory, base: 0x0000000192000000, size: 0x000000002d000000' in log
          and 'initialized node zone-movable-cma-memory, compatible id mediatek,zone_movable_cma' in log,
          'stock log: ZMC took the region at 0x192000000 through the same compatible')

    rmem = (SOURCE / 'drivers/of/of_reserved_mem.c').read_text()
    check('return memblock_reserve(base, size);' in rmem, '5.10 reserves a dynamic region without no-map in memblock.reserved')
    check(re.search(r'if \(err != 0 && err != -ENOENT\)', rmem) is not None,
          '5.10 keeps a region whose init returns 0 as the init left it')
    single = (SOURCE / 'drivers/misc/mediatek/zone_movable_cma/single_cma.c').read_text()
    check('memblock_free(rmem->base, rmem->size);\n\t\tmemblock_add(rmem->base, rmem->size);' in single,
          'zmc_memory_init puts the rest of the region back into memblock')
    check('#ifdef CONFIG_MTK_SSMR\n\t\t&memory_ssmr_registration,' in single,
          'the only movable-zone user is SSMR, left out, so the whole region goes back')

    config = (out / '.config').read_text()
    for symbol in ('CONFIG_CMA=y', 'CONFIG_ZONE_MOVABLE_CMA=y', '# CONFIG_DMA_CMA is not set', '# CONFIG_MTK_SSMR'):
        check(symbol in config if symbol != '# CONFIG_MTK_SSMR' else 'CONFIG_MTK_SSMR=y' not in config,
              f'.config: {symbol if symbol != "# CONFIG_MTK_SSMR" else "MTK_SSMR off"}')

    vmlinux = out / 'vmlinux'
    single_o = out / 'drivers/misc/mediatek/zone_movable_cma/single_cma.o'
    fresh = vmlinux.exists() and vmlinux.stat().st_mtime >= single_o.stat().st_mtime
    check(fresh, 'vmlinux is linked and newer than single_cma.o')
    if fresh:
        symbols = {}
        for line in subprocess.run(['nm', str(vmlinux)], capture_output=True, text=True, check=True).stdout.splitlines():
            parts = line.split()
            if len(parts) == 3:
                symbols[parts[2]] = (int(parts[0], 16), parts[1])
        for name in ('zmc_memory_init', '__of_table_zone_movable_cma_init', 'fix_up_normal_zone', 'cma_alloc_range_ok',
                     'zmc_cma_alloc', 'zmc_notifier_call_chain', 'cma_init_reserved_mem'):
            check(name in symbols, f'vmlinux: {name}')
        if '__of_table_zone_movable_cma_init' in symbols:
            found = of_table_compatible(vmlinux, symbols['__of_table_zone_movable_cma_init'][0])
            check(found == COMPATIBLE, f'vmlinux: reserved-memory table entry compatible {found}')

    failures = sum(not ok for ok, _ in results)
    print(f'checks {len(results)} failures {failures}')
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()
