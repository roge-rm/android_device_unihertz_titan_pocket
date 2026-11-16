#!/usr/bin/env python3
"""Run actual MTK watchdog handoff/probe and core worker predicate with host mocks."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUT = pocket_paths.build_root() / 'artifacts/diagnostic-5.10-v2/watchdog-check'


def function(text, name):
    match = re.search(r'^static (?:inline )?(?:int|bool|void|ktime_t) ' + name + r'\(', text, re.M)
    assert match, name
    start = text.index('{', match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


def main():
    source = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/watchdog/mtk_wdt.c'
    core = source.with_name('watchdog_dev.c')
    text = source.read_text()
    assert '.compatible = "mediatek,mt6771-wdt", .data = &mt6771_data' in text
    assert re.search(r'mt6771_data = \{\s*\.adopt_boot_watchdog = true,\s*\}', text)
    assert 'wdt_data->toprgu_sw_rst_num > 0' in text
    core_text = core.read_text()
    assert 'if (handle_boot_enabled)\n\t\t\thrtimer_start' in core_text
    assert 'IS_ENABLED(CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED)' in core_text
    assert 'data->open_deadline = open_timeout ?' in core_text
    defines = '\n'.join(line for line in text.splitlines() if line.startswith('#define WDT_'))
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define __iomem
#define IS_ENABLED(x) (boot_enabled)
#define WDOG_HW_RUNNING 1
#define GFP_KERNEL 0
#define IS_ERR(x) ((x) == (void *)-1)
#define PTR_ERR(x) (-ENXIO)
#define unlikely(x) (x)
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
struct device { int dummy; };
struct platform_device { struct device dev; void *data; };
struct watchdog_device { unsigned timeout, max_timeout, min_timeout, max_hw_heartbeat_ms; unsigned long status; void *parent, *data; const void *info, *ops; bool active; struct watchdog_core_data *wd_data; };
struct mtk_wdt_dev { struct watchdog_device wdt_dev; void *wdt_base; };
struct mtk_wdt_data { int toprgu_sw_rst_num; bool adopt_boot_watchdog; };
static const int mtk_wdt_info, mtk_wdt_ops;
static const struct mtk_wdt_data profile = {0, true}, old_profile = {32, false};
static const struct mtk_wdt_data *match;
static struct mtk_wdt_dev storage;
static u32 regs[8];
static unsigned writes, pings, mode_writes, registrations, reset_registrations;
static bool boot_enabled, bad_length, bad_mode, alloc_fail, map_fail;
static int init_error, register_error, reset_error;
static bool nowayout;
static unsigned timeout;
static u32 readl(void *p) { u32 value = *(u32 *)p; if (p == (void *)&regs[1] && bad_length) value ^= 0x800; if (p == (void *)&regs[0] && bad_mode && mode_writes) value ^= 1; return value; }
static void writel(u32 value, void *p) { writes++; if(p == (void *)&regs[0]) { assert((value & 0xff000000)==0x22000000); mode_writes++; value &= 0xffffff; } if(p == (void *)&regs[2]) { assert(value==0x1971); pings++; } *(u32 *)p=value; }
#define iowrite32 writel
#define ioread32 readl
static void set_bit(unsigned bit, unsigned long *p) { *p |= 1UL << bit; }
static bool watchdog_hw_running(struct watchdog_device *d) { return d->status & (1UL << WDOG_HW_RUNNING); }
static bool watchdog_active(struct watchdog_device *d) { return d->active; }
static void *watchdog_get_drvdata(struct watchdog_device *d) { return d->data; }
static void watchdog_set_drvdata(struct watchdog_device *d, void *p) { d->data=p; }
static void *devm_kzalloc(struct device *d, size_t n, int g) { (void)d; (void)g; assert(n==sizeof(storage)); memset(&storage,0,n); return alloc_fail ? NULL : &storage; }
static void platform_set_drvdata(struct platform_device *p, void *d) { p->data=d; }
static void *devm_platform_ioremap_resource(struct platform_device *p, int n) { (void)p; assert(n==0); return map_fail ? (void *)-1 : regs; }
static const void *of_device_get_match_data(struct device *d) { (void)d; return match; }
static int watchdog_init_timeout(struct watchdog_device *w, unsigned t, struct device *d) { (void)d; if(t)w->timeout=t; return init_error; }
static void watchdog_set_nowayout(struct watchdog_device *d, bool n) { (void)d; (void)n; }
static void watchdog_set_restart_priority(struct watchdog_device *d, int n) { (void)d; assert(n==128); }
static void watchdog_stop_on_reboot(struct watchdog_device *d) { (void)d; }
static int devm_watchdog_register_device(struct device *d, struct watchdog_device *w) { (void)d; registrations++; if(match==&profile && (regs[0]&1)) assert(watchdog_hw_running(w)); return register_error; }
static int toprgu_register_reset_controller(struct platform_device *p, int n) { (void)p; assert(n==32); reset_registrations++; return reset_error; }
'''
    code += defines + '\n'
    for name in ['mtk_wdt_ping', 'mtk_wdt_set_timeout', 'mtk_wdt_stop', 'mtk_wdt_start', 'mtk_wdt_boot_handoff', 'mtk_wdt_probe']:
        code += function(text, name) + '\n'
    code += r'''
typedef int64_t ktime_t;
struct watchdog_core_data { ktime_t open_deadline, last_keepalive; };
static ktime_t now;
static unsigned open_timeout;
#define KTIME_MAX INT64_MAX
static ktime_t ktime_get(void) { return now; }
static ktime_t ktime_set(unsigned seconds, unsigned ns) { return (ktime_t)seconds*1000000000+ns; }
static bool ktime_after(ktime_t a,ktime_t b) { return a>b; }
static bool ktime_before(ktime_t a,ktime_t b) { return a<b; }
static ktime_t ktime_add(ktime_t a,ktime_t b) { return a+b; }
static ktime_t ktime_sub(ktime_t a,ktime_t b) { return a-b; }
static ktime_t ms_to_ktime(unsigned ms) { return (ktime_t)ms*1000000; }
static unsigned min_not_zero(unsigned a,unsigned b) { return !a?b:!b?a:a<b?a:b; }
'''
    for name in ['watchdog_set_open_deadline','watchdog_past_open_deadline','watchdog_next_keepalive']:
        code += function(core_text,name)+'\n'
    code += function(core_text, 'watchdog_need_worker') + r'''
static void reset(void) { memset(regs,0,sizeof(regs)); writes=pings=mode_writes=registrations=reset_registrations=0; boot_enabled=true; bad_length=bad_mode=alloc_fail=map_fail=false; init_error=register_error=reset_error=0; timeout=0; match=&profile; }
int main(void) {
    struct platform_device p={0}; unsigned cases=0;
    for(unsigned adopt=0; adopt<2; adopt++) for(unsigned enabled=0; enabled<2; enabled++)
    for(unsigned bits=0; bits<256; bits++) for(unsigned t=1;t<=31;t++) {
        reset(); match=adopt?&profile:&old_profile; timeout=t;
        u32 original=(bits<<1)|enabled; regs[0]=original;
        assert(mtk_wdt_probe(&p)==0);
        assert(storage.wdt_dev.timeout==t && registrations==1);
        assert(reset_registrations==(adopt?0U:1U));
        if(adopt && enabled) {
            assert(regs[0]==(original & ~(8U|64U)));
            assert(regs[1]==((t<<11)|8U));
            assert(pings==2 && mode_writes==1 && watchdog_hw_running(&storage.wdt_dev));
            assert(watchdog_need_worker(&storage.wdt_dev));
        } else {
            assert(!watchdog_hw_running(&storage.wdt_dev));
            assert(!watchdog_need_worker(&storage.wdt_dev));
            assert(regs[0]==(adopt?original:original&~1U));
            assert(writes==(adopt?0U:1U));
        }
        /* Actual start/stop preserve every unrelated mode bit for both profiles. */
        assert(mtk_wdt_start(&storage.wdt_dev)==0);
        assert(regs[0]==((original&~(8U|64U))|1U));
        assert(mtk_wdt_stop(&storage.wdt_dev)==0);
        assert(regs[0]==(original&~(1U|8U|64U)));
        cases++;
    }
    for(unsigned fault=0;fault<10;fault++) {
        reset(); regs[0]=0xdd;
        int expected;
        switch(fault) {
        case 0: boot_enabled=false; expected=-EINVAL; break;
        case 1: timeout=32; expected=-EINVAL; break;
        case 2: bad_length=true; expected=-EIO; break;
        case 3: bad_mode=true; expected=-EIO; break;
        case 4: alloc_fail=true; expected=-ENOMEM; break;
        case 5: map_fail=true; expected=-ENXIO; break;
        case 6: init_error=-EINVAL; expected=-EINVAL; break;
        case 7: register_error=-EBUSY; expected=-EBUSY; break;
        case 8: match=&old_profile; reset_error=-EIO; expected=-EIO; break;
        default: match=NULL; expected=0; break;
        }
        assert(mtk_wdt_probe(&p)==expected);
        if(fault<7) assert(registrations==0);
        if(fault<2 || (fault>=4 && fault<=6)) assert(writes==0);
        if(fault<8) assert(regs[0]&1); /* Never disables rescue on adoption failure. */
        cases++;
    }
    reset(); regs[0]=0; boot_enabled=false; assert(mtk_wdt_probe(&p)==0 && writes==0);
    struct watchdog_device w={.timeout=31};
    assert(!watchdog_need_worker(&w));
    set_bit(WDOG_HW_RUNNING,&w.status); assert(watchdog_need_worker(&w));
    w.active=true; assert(!watchdog_need_worker(&w));
    w.max_hw_heartbeat_ms=30000; assert(watchdog_need_worker(&w));
    w.timeout=0; w.active=false; assert(!watchdog_need_worker(&w));
    struct watchdog_core_data wd={0};
    w=(struct watchdog_device){.timeout=31,.wd_data=&wd};
    now=0; open_timeout=90; watchdog_set_open_deadline(&wd);
    assert(wd.open_deadline==90000000000LL);
    assert(watchdog_next_keepalive(&w)==15500000000LL);
    now=58500000000LL; assert(watchdog_next_keepalive(&w)==500000000LL);
    now=59000000000LL; assert(watchdog_next_keepalive(&w)==0);
    now=90000000000LL; assert(!watchdog_past_open_deadline(&wd));
    now++; assert(watchdog_past_open_deadline(&wd));
    now=0; open_timeout=0; watchdog_set_open_deadline(&wd);
    assert(wd.open_deadline==KTIME_MAX && watchdog_next_keepalive(&w)==15500000000LL);
    printf("%u handoff/probe cases passed; actual start/stop and core worker predicate plus 7 finite/open-deadline boundary assertions passed\n",cases+6);
}
'''
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-g', str(OUT/'check.c'), '-o', str(OUT/'check')], check=True)
    result = subprocess.run([str(OUT/'check')], capture_output=True, text=True, check=True)
    assert not result.stderr, result.stderr
    record = {'inputs': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [source, core]}, 'result':result.stdout.strip(), 'limits':['Actual extracted driver functions and core worker predicate; MMIO and watchdog registration mocked.', 'Actual deadline/next-keepalive arithmetic tested at 90-second boundary; timer scheduling is mocked, not run as kernel code.', 'Requires CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y and watchdog.handle_boot_enabled must not be disabled at boot.', 'Worker open_timeout follows CONFIG_WATCHDOG_OPEN_TIMEOUT/watchdog.open_timeout; zero permits indefinite pre-userspace feeding.', 'No hardware execution, MMIO timing, reset success, firmware timeout or RAM retention proof.']}
    (OUT/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(result.stdout,end='')


if __name__=='__main__':
    main()
