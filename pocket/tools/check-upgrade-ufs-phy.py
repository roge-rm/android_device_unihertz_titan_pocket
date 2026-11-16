#!/usr/bin/env python3
"""Compare real PHY register-write traces to MT6771 BSP and untouched MT8183."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BASE = pocket_paths.platform_source() / 'kernel/motorola/sm6450'


def extract(source, name):
    pos = source.index(name + '(')
    start = source.rfind('\n', 0, pos) + 1
    brace = source.index('{', pos)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    relative = Path('drivers/phy/mediatek/phy-mtk-ufs.c')
    current = ROOT / 'tools/kernel-source/upgrade-5.10' / relative
    old = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/scsi/ufs/mediatek/mt6771/ufs-mtk-platform.c'
    source, baseline, bsp = current.read_text(), (BASE / relative).read_text(), old.read_text()
    header = source[source.index('/* mphy register'):source.index('struct ufs_mtk_phy {')]
    active = extract(bsp, 'ufs_mtk_pltfrm_resume')
    active = active[active.index('/* Step 2:'):active.rindex('return ret;')]
    inactive = extract(bsp, 'ufs_mtk_pltfrm_suspend')
    inactive = inactive[inactive.index('/* Step 1:'):inactive.index('/* Step 7:')]
    bodies = ''
    for name in ('mphy_readl', 'mphy_writel', 'mphy_set_bit', 'mphy_clr_bit',
                 'ufs_mtk_phy_set_active', 'ufs_mtk_phy_set_deep_hibern'):
        bodies += extract(source, name) + '\n'
    for name in ('ufs_mtk_phy_set_active', 'ufs_mtk_phy_set_deep_hibern'):
        bodies += extract(baseline, name).replace(name, 'baseline_' + name) + '\n'
    code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(n) (1U << (n))
static unsigned char memory[0xc000];
static void *ufs_mtk_mmio_base_ufs_mphy = memory;
struct write { unsigned offset; u32 value; };
static struct write trace[64], expected[64];
static unsigned count;
static u32 readl(void *address) {
    uintptr_t offset = (unsigned char *)address - memory;
    assert(offset < sizeof(memory) && !(offset & 3));
    u32 value; memcpy(&value, memory + offset, 4); return value;
}
static void writel(u32 value, void *address) {
    uintptr_t offset = (unsigned char *)address - memory;
    assert(offset < sizeof(memory) && !(offset & 3) && count < 64);
    trace[count++] = (struct write){offset, value};
    memcpy(memory + offset, &value, 4);
}
static void udelay(unsigned us) { assert(us == 1); }
'''
    code += header + r'''
struct ufs_mtk_phy { void *mmio; const struct ufs_mtk_phy_data *data; };
'''
    code += bodies
    code += 'static void bsp_active(void) { u32 reg;\n' + active + '\n}\n'
    code += 'static void bsp_inactive(void) { u32 reg;\n' + inactive + '\n}\n'
    code += r'''
static void initialize(unsigned seed) {
    for (unsigned i = 0; i < sizeof(memory); i++) {
        seed = seed * 1664525U + 1013904223U;
        memory[i] = seed >> 24;
    }
    count = 0;
    memset(trace, 0, sizeof(trace));
}
int main(void) {
    struct ufs_mtk_phy phy = {.mmio = memory};
    unsigned cases = 0;
    for (unsigned soc = 0; soc < 2; soc++) {
        phy.data = soc ? &mt8183_ufs_phy_data : &mt6771_ufs_phy_data;
        for (unsigned off = 0; off < 2; off++) {
            for (unsigned seed = 0; seed < 1024; seed++) {
                initialize(seed);
                if (soc) {
                    if (off) baseline_ufs_mtk_phy_set_deep_hibern(&phy);
                    else baseline_ufs_mtk_phy_set_active(&phy);
                } else {
                    if (off) bsp_inactive(); else bsp_active();
                }
                unsigned n = count;
                memcpy(expected, trace, sizeof(trace));
                initialize(seed);
                if (off) ufs_mtk_phy_set_deep_hibern(&phy);
                else ufs_mtk_phy_set_active(&phy);
                assert(count == n);
                assert(memcmp(expected, trace, n * sizeof(trace[0])) == 0);
                cases++;
            }
        }
    }
    printf("%u PHY power-sequence write traces match MT6771 BSP / MT8183 baseline\n", cases);
    return 0;
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/ufs-phy-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    result = subprocess.run([str(out / 'check')], check=True, capture_output=True, text=True)
    record = {'cases': 4096, 'result': result.stdout.strip(),
              'inputs': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in (current, BASE / relative, old)],
              'scope': 'Extracted real MMIO sequence bodies; mocks exclude real clocks, timing, firmware calls, voltages and PHY behavior'}
    (ROOT / 'evidence/kernel-upgrade/ufs-phy-comparison.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
