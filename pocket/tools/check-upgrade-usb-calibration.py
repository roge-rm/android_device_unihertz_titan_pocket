#!/usr/bin/env python3
"""Exercise the real USB calibration parser against captured and malformed tags."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    source = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/phy/mediatek/phy-mtk-mt6771.c'
    text = source.read_text()
    helper = text[text.index('static int mt6771_usb_read_calibration('):text.index('static int mtk_phy_drv_init(')]
    tree = json.loads((ROOT / 'evidence/device/20261029T000648.917229Z/live-device-tree.json').read_text())
    tag = bytes.fromhex(tree['nodes']['/chosen']['atag,devinfo']['hex'])
    assert len(tag) == 804 and int.from_bytes(tag[:4], 'little') == 200
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint8_t u8;
struct device_node { int unused; };
struct mtk_phy_drv { u32 devinfo107, devinfo108; };
static struct device_node node;
static int length, missing_node, missing_tag, puts_count;
static unsigned char tag[804];
static u32 get_unaligned_le32(const void *p) {
    const u8 *b = p; return b[0] | ((u32)b[1]<<8) | ((u32)b[2]<<16) | ((u32)b[3]<<24);
}
static struct device_node *of_find_node_by_path(const char *p)
{ (void)p; return missing_node ? NULL : &node; }
static const void *of_get_property(struct device_node *n, const char *p, int *len)
{ (void)n; (void)p; *len = length; return missing_tag ? NULL : tag; }
static void of_node_put(struct device_node *n) { assert(n == &node); puts_count++; }
'''
    code += helper
    code += '\nstatic const unsigned char captured[] = {' + ','.join(str(x) for x in tag) + '};\n'
    code += r'''
int main(void) {
    unsigned cases = 0;
    const u32 counts[] = {0, 108, 109, 199, 200, 201, UINT32_MAX};
    struct mtk_phy_drv phy;
    for (unsigned i = 0; i < sizeof(counts)/sizeof(counts[0]); i++) {
        memcpy(tag, captured, sizeof(tag));
        u32 count = counts[i];
        for (unsigned j = 0; j < 4; j++) tag[j] = count >> (8*j);
        for (length = -1; length <= (int)sizeof(tag); length++) {
            puts_count = 0;
            phy.devinfo107 = phy.devinfo108 = 0xdeadbeef;
            int result = mt6771_usb_read_calibration(&phy);
            int valid = length >= 4 && count >= 109 && count <= (unsigned)(length-4)/4;
            assert(result == (valid ? 0 : -EINVAL));
            assert(puts_count == 1);
            assert(phy.devinfo107 == (valid ? get_unaligned_le32(captured + 4 + 107*4) : 0xdeadbeef));
            assert(phy.devinfo108 == (valid ? get_unaligned_le32(captured + 4 + 108*4) : 0xdeadbeef));
            cases++;
        }
    }
    memcpy(tag, captured, sizeof(tag)); length = sizeof(tag);
    missing_tag = 1; assert(mt6771_usb_read_calibration(&phy) == -EINVAL); cases++;
    missing_tag = 0; missing_node = 1;
    assert(mt6771_usb_read_calibration(&phy) == -ENODEV); cases++;
    missing_node = 0; assert(mt6771_usb_read_calibration(&phy) == 0); cases++;
    printf("%u USB calibration tag/bounds cases passed\n", cases);
    return 0;
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/usb-calibration-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    result = subprocess.run([str(out / 'check')], check=True, capture_output=True, text=True)
    record = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'captured_tag_sha256': hashlib.sha256(tag).hexdigest(),
              'result': result.stdout.strip(), 'captured_values_logged': False,
              'scope': 'Actual parser with mocked OF access; not live calibration or USB electrical qualification'}
    (ROOT / 'evidence/kernel-upgrade/usb-calibration-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
