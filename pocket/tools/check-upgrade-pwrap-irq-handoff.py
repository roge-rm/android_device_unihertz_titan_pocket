#!/usr/bin/env python3
"""Check shipped MT6771 IRQ masks and exercise the actual probe setup block."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    path = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/soc/mediatek/mtk-pmic-wrap.c'
    source = path.read_text()
    descriptor = re.search(r'static const struct pmic_wrapper_type pwrap_mt6771 = \{(.*?)\n\};', source, re.S)[1]
    masks = [int(re.search(r'\.' + name + r'\s*=\s*(0x[0-9a-f]+)', descriptor)[1], 16)
             for name in ['int_en_all', 'int1_en_all']]
    assert masks == [0x0c0001ff, 0xeef7ffff], masks
    native_path = ROOT / 'evidence/kernel-upgrade/stock-native-slices/stock-mt6771-descriptor.json'
    native = json.loads(native_path.read_text())['structuredContent']
    raw = bytes.fromhex(native['normalized_result']['bytes_hex'])
    assert [int.from_bytes(raw[i:i + 4], 'little') for i in (24, 28)] == masks
    assert masks[1] & 0x10080000 == 0  # Both sources seen in the V3 log are excluded.
    begin = source.index('\t/* Initialize watchdog, may not be done by the bootloader */')
    end = source.index('\n\tirq = platform_get_irq', begin)
    helper = 'static void pwrap_configure_irq(struct pmic_wrapper *wrp)\n{\n' + source[begin:end] + '\n}'
    assert source.count(source[begin:end]) == 1
    # Undefined reads, resets and PMIC transactions must fail the host compile.
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
#define PWRAP_CAP_WDT_SRC1 1
#define PWRAP_CAP_INT1_EN 2
#define HAS_CAP(caps, cap) ((caps) & (cap))
enum { PWRAP_WDT_UNIT, PWRAP_WDT_SRC_EN, PWRAP_WDT_SRC_EN_1,
       PWRAP_TIMER_EN, PWRAP_INT_EN, PWRAP_INT1_EN };
struct pmic_wrapper_type {
    bool bootloader_only;
    u32 caps, wdt_src, int_en_all, int1_en_all;
};
struct pmic_wrapper { const struct pmic_wrapper_type *master; };
struct write { int reg; u32 value; };
static struct write writes[6];
static unsigned count;
static void pwrap_writel(struct pmic_wrapper *wrp, u32 value, int reg)
{
    assert(wrp && wrp->master);
    assert(count < sizeof(writes) / sizeof(writes[0]));
    writes[count++] = (struct write){ reg, value };
}
'''
    code += f'\n#define MT6771_INT0 {masks[0]}u\n#define MT6771_INT1 {masks[1]}u\n'
    code += helper + r'''
static void expect(unsigned index, int reg, u32 value)
{
    assert(index < count);
    assert(writes[index].reg == reg);
    assert(writes[index].value == value);
}
int main(void)
{
    unsigned cases = 0;
    for (unsigned caps = 0; caps < 4; caps++) {
        for (unsigned pattern = 0; pattern < 5; pattern++) {
            static const u32 values[] = {0, 0xffffffff, 0xeef7ffff, 0x10080000};
            struct pmic_wrapper_type master = {
                .bootloader_only = true, .caps = caps,
                .wdt_src = values[pattern % 4],
                .int_en_all = pattern == 4 ? MT6771_INT0 : values[(pattern + 1) % 4],
                .int1_en_all = pattern == 4 ? MT6771_INT1 : values[(pattern + 2) % 4],
            };
            struct pmic_wrapper wrp = { .master = &master };
            count = 0;
            pwrap_configure_irq(&wrp);
            unsigned i = 0;
            expect(i++, PWRAP_WDT_UNIT, 15);
            expect(i++, PWRAP_WDT_SRC_EN, master.wdt_src);
            if (caps & PWRAP_CAP_WDT_SRC1)
                expect(i++, PWRAP_WDT_SRC_EN_1, master.wdt_src);
            expect(i++, PWRAP_TIMER_EN, 1);
            expect(i++, PWRAP_INT_EN, master.int_en_all);
            if (caps & PWRAP_CAP_INT1_EN)
                expect(i++, PWRAP_INT1_EN, master.int1_en_all);
            assert(count == i);
            cases++;
        }
    }
    printf("%u wrapper IRQ setup cases passed\n", cases);
    return 0;
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/pwrap-irq-handoff-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-g', str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    result = subprocess.run([str(out / 'check')], check=True, capture_output=True, text=True)
    record = {
        'source': str(path.relative_to(ROOT)),
        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'tested_source': 'Unmodified IRQ setup block in pwrap_probe, wrapped for host compilation', 'cases': 20,
        'native_evidence_id': native['evidence_id'], 'bank_masks': [hex(mask) for mask in masks],
        'result': result.stdout.strip(), 'sanitizers': ['address', 'undefined'],
        'scope': 'Actual probe IRQ setup block and descriptor values, traced MMIO writes; native static mask comparison, no phone execution or hardware IRQ suppression proof',
    }
    (ROOT / 'evidence/kernel-upgrade/pwrap-irq-handoff-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
