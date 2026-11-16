#!/usr/bin/env python3
"""Exercise actual handoff-validation source with mock wrapper/PMIC reads."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def function(source, name):
    start = source.index('static int ' + name + '(')
    begin = source.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    path = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/soc/mediatek/mtk-pmic-wrap.c'
    source = path.read_text()
    helper = function(source, 'pwrap_mt6771_validate_handoff')
    # The validator must not directly reset or write wrapper/PMIC state.
    assert 'pwrap_write' not in helper and 'reset_' not in helper
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
enum { PMIC_MT6358, PMIC_OTHER };
enum { PWRAP_INIT_DONE2, PWRAP_WACS2_RDATA, PWRAP_WRAP_EN,
       PWRAP_WACS2_EN, PWRAP_DEW_READ_TEST };
#define PWRAP_STATE_INIT_DONE0 (1 << 21)
#define PWRAP_DEW_READ_TEST_VAL 0x5aa5
struct slave { int type; u32 dew_regs[8]; };
struct pmic_wrapper { struct slave *slave; };
static u32 registers[8], value;
static int transaction_result, transactions;
static u32 pwrap_readl(struct pmic_wrapper *wrp, int reg)
{ (void)wrp; return registers[reg]; }
static int pwrap_read(struct pmic_wrapper *wrp, u32 address, u32 *result)
{
    (void)wrp;
    assert(address == 0x40e);
    transactions++;
    *result = value;
    return transaction_result;
}
'''
    code += helper + r'''
int main(void)
{
    struct slave slave = { .type = PMIC_MT6358,
                          .dew_regs = { [PWRAP_DEW_READ_TEST] = 0x40e } };
    struct pmic_wrapper wrp = { .slave = &slave };
    unsigned cases = 0;
    for (unsigned flags = 0; flags < 16; flags++) {
        registers[PWRAP_INIT_DONE2] = (flags & 1) ? 1 : 2;
        registers[PWRAP_WACS2_RDATA] = (flags & 2) ? PWRAP_STATE_INIT_DONE0 : 0;
        registers[PWRAP_WRAP_EN] = (flags & 4) ? 1 : 2;
        registers[PWRAP_WACS2_EN] = (flags & 8) ? 1 : 2;
        for (int kind = 0; kind < 2; kind++) {
            slave.type = kind;
            for (int failure = 0; failure < 3; failure++) {
                transactions = 0;
                transaction_result = failure == 1 ? -ETIMEDOUT : 0;
                value = failure == 2 ? 0xffff : PWRAP_DEW_READ_TEST_VAL;
                int actual = pwrap_mt6771_validate_handoff(&wrp);
                int ready = flags == 15 && kind == PMIC_MT6358;
                int expected = !ready ? -ENODEV :
                    failure == 1 ? -ETIMEDOUT : failure == 2 ? -EIO : 0;
                assert(actual == expected);
                assert(transactions == ready);
                cases++;
            }
        }
    }
    printf("%u PMIC handoff state/error cases passed\n", cases);
    return 0;
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/pmic-handoff-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-g', str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    result = subprocess.run([str(out / 'check')], check=True, capture_output=True, text=True)
    record = {'source': str(path.relative_to(ROOT)),
              'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'cases': 96, 'result': result.stdout.strip(),
              'scope': 'Actual validator function with mocked reads; not real bus/MMIO, cold initialization or hardware qualification'}
    (ROOT / 'evidence/kernel-upgrade/pmic-handoff-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
