#!/usr/bin/env python3
"""Compare extracted BSP/forward-port GPIO write helpers with mocked MMIO."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    old = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/pinctrl/mediatek/pinctrl-mtk-common-v2.c'
    new = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/pinctrl/mediatek/pinctrl-mtk-common-v2.c'
    bodies = []
    for path, prefix in [(old, 'original_'), (new, 'upgrade_')]:
        text = path.read_text()
        for name in ['mtk_hw_set_value_race_free', 'mtk_hw_set_mode_race_free']:
            start = text.index('void ' + name + '(')
            end = text.index('\n}\n', start) + 3
            bodies.append('static ' + text[start:end].replace(name, prefix + name))
    code = r'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint32_t u32;
struct mtk_pinctrl { void *dev; };
struct mtk_pin_field { unsigned char index, bitpos; u32 offset, mask; };
struct write_record { u32 bank, offset, value; };
static struct write_record writes[4]; static unsigned int count;
#define dev_notice(...) ((void)0)
#define SET_OFFSET 4
#define CLR_OFFSET 8
#define MWR_OFFSET 12
#define MT6771_GPIO_SET_OFFSET 4
#define MT6771_GPIO_CLR_OFFSET 8
#define MT6771_GPIO_MWR_OFFSET 12
static void mtk_w32(struct mtk_pinctrl *p, unsigned char bank, u32 reg, u32 value) {
 (void)p; assert(count<4); writes[count++]=(struct write_record){bank,reg,value};
}
''' + '\n'.join(bodies) + r'''
int main(void) {
 unsigned int cases=0;
 struct mtk_pinctrl hw={0};
 for (unsigned int bank=0;bank<9;bank++) {
  for (unsigned int width=1;width<=4;width++) {
   for (unsigned int bit=0;bit+width<=32;bit++) {
    struct mtk_pin_field f={bank,bit,0x100,(1U<<width)-1};
    for (unsigned int value=0;value<=f.mask;value++) {
     struct write_record expected[4]; count=0;
     original_mtk_hw_set_value_race_free(&hw,&f,value);
     unsigned int n=count; memcpy(expected,writes,n*sizeof(*writes)); count=0;
     upgrade_mtk_hw_set_value_race_free(&hw,&f,value);
     assert(count==n && !memcmp(expected,writes,n*sizeof(*writes))); cases++;
    }
   }
  }
  for (unsigned int bit=0;bit<32;bit+=4) {
   struct mtk_pin_field f={bank,bit,0x300,15};
   for (unsigned int value=0;value<8;value++) {
    struct write_record expected[4]; count=0;
    original_mtk_hw_set_mode_race_free(&hw,&f,value);
    unsigned int n=count; memcpy(expected,writes,n*sizeof(*writes)); count=0;
    upgrade_mtk_hw_set_mode_race_free(&hw,&f,value);
    assert(count==n && !memcmp(expected,writes,n*sizeof(*writes))); cases++;
   }
  }
 }
 printf("%u GPIO register-write cases match\n",cases);
 return 0;
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/gpio-write-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    compiler = str(pocket_paths.ndk_bin() / 'clang')
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
               '-fsanitize=address,undefined', str(out / 'check.c'), '-o', str(out / 'check')]
    subprocess.run(command, check=True)
    result = subprocess.run([str(out / 'check')], capture_output=True, text=True, check=True)
    record = {'command': command, 'stdout': result.stdout, 'stderr': result.stderr,
              'returncode': result.returncode, 'cases': 8604,
              'inputs': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in [old,new]],
              'scope': 'Host-executed source helper logic with mocked MMIO; no real GPIO, ordering, concurrency or hardware validation'}
    assert result.stdout == '8604 GPIO register-write cases match\n'
    (ROOT / 'evidence/kernel-upgrade/gpio-write-comparison.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
