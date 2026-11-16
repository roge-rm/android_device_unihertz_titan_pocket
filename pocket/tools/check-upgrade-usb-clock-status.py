#!/usr/bin/env python3
"""Check the real MTU3 clock-status function over mocked status registers."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    source = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/usb/mtu3/mtu3_plat.c'
    header = source.with_name('mtu3_hw_regs.h')
    old = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/usb/mtu3/mtu3_plat_v2.c'
    assert 'check_val = ex_clks | SSUSB_SYS125_RST_B_STS;' in old.read_text()
    text = source.read_text()
    helper = text[text.index('int ssusb_check_clocks('):text.index('static int ssusb_phy_init(')]
    names = ['SSUSB_SYS125_RST_B_STS', 'SSUSB_SYSPLL_STABLE', 'SSUSB_REF_RST_B_STS',
             'SSUSB_U2_MAC_SYS_RST_B_STS']
    defines = '\n'.join('#define ' + n + ' ' + re.search(r'^#define\s+' + n + r'\s+(BIT\(\d+\))',
                        header.read_text(), re.M).group(1) for n in names)
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define __iomem
#define BIT(n) (1U << (n))
struct device_node { bool mt6771; };
struct device { struct device_node *of_node; };
struct ssusb_mtk { struct device *dev; void *ippc_base; };
static u32 regs[2];
static unsigned polls, errors;
#define U3D_SSUSB_IP_PW_STS1 0
#define U3D_SSUSB_IP_PW_STS2 4
#define dev_err(dev, ...) ((void)(dev), errors++)
static bool of_device_is_compatible(struct device_node *node, const char *name) {
    assert(!strcmp(name,"mediatek,mt6771-mtu3")); return node->mt6771;
}
#define readl_poll_timeout(address, value, condition, delay, timeout) \
    (assert((delay)==100 && ((timeout)==10000 || (timeout)==20000)), \
     polls++, (value)=*(u32 *)(address), (condition) ? 0 : -ETIMEDOUT)
'''
    code += defines + '\n' + helper + r'''
int main(void) {
    struct device_node node;
    struct device dev = { &node };
    struct ssusb_mtk ssusb = { &dev, regs };
    const u32 bits[] = {SSUSB_SYS125_RST_B_STS, SSUSB_SYSPLL_STABLE,
                        SSUSB_REF_RST_B_STS, BIT(27)};
    unsigned cases = 0;
    for (unsigned soc=0; soc<2; soc++) for (unsigned extra=0; extra<8; extra++)
    for (unsigned status=0; status<16; status++) for (unsigned mac=0; mac<2; mac++) {
        node.mt6771 = soc;
        u32 ex = ((extra&1) ? bits[1] : 0) | ((extra&2) ? bits[2] : 0) |
                 ((extra&4) ? bits[3] : 0);
        u32 required = ex | bits[0] | (soc ? 0 : bits[1] | bits[2]);
        regs[0] = 0;
        for (unsigned i=0; i<4; i++) if (status & BIT(i)) regs[0] |= bits[i];
        regs[1] = mac ? SSUSB_U2_MAC_SYS_RST_B_STS : 0;
        bool first = (regs[0] & required) == required;
        polls = errors = 0;
        int result = ssusb_check_clocks(&ssusb, ex);
        if (soc) {
            /* MT6771 logs each timeout and carries on, as its v2 BSP does */
            assert(result == 0);
            assert(polls == 2U);
            assert(errors == (first ? 0U : 1U) + (mac ? 0U : 1U));
        } else {
            assert(result == (first && mac ? 0 : -ETIMEDOUT));
            assert(polls == (first ? 2U : 1U));
            assert(errors == (first && mac ? 0U : 1U));
        }
        cases++;
    }
    printf("%u MTU3 clock-status cases passed; generic and caller bits preserved; generic timeouts propagate, MT6771 timeouts are logged\n",cases);
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/usb-clock-status-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    checked = subprocess.run([str(out / 'check')], check=True, capture_output=True, text=True)
    assert 'runtime error:' not in checked.stderr and 'AddressSanitizer' not in checked.stderr
    record = {'inputs': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [source, header, old]}, 'result': checked.stdout.strip(),
              'limits': ['Actual function with one-sample mocked polling, not hardware timing',
                         'MT6771 status mask and log-and-continue follow the v2 BSP; generic error propagation is retained',
                         'No phone write or target execution']}
    (ROOT / 'evidence/kernel-upgrade/usb-clock-status-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(checked.stdout, end='')


if __name__ == '__main__':
    main()
