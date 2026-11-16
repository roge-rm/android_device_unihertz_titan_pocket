#!/usr/bin/env python3
"""Fault-inject the actual USB PHY resource init and clock lifetime helpers.

Compiles extracted functions with mocked kernel APIs in a temporary directory.
No kernel build, MMIO, phone access, or retained build output is performed.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/phy/mediatek/phy-mtk-mt6771.c'


def main():
    text = SOURCE.read_text()
    init_exit = text[text.index('static int mtk_phy_drv_init('):
                     text.index('static int phy_inst_init(')]
    clock = text[text.index('static bool usb_enable_clock('):
                 text.index('static void u3phywrite32(')]
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define EPROBE_DEFER 517
#define IORESOURCE_MEM 1
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define phy_printk(...) ((void)0)
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
struct device { int unused; };
struct platform_device { struct device dev; };
struct clk { int unused; };
struct resource { unsigned long start, size; };
struct mtk_phy_drv { void *phy_base, *ippc_base; struct clk *clk; int clock_users; };
static struct resource resources[] = {{0x1000, 0x100}, {0x2000, 0x80}};
static struct clk reference;
static int calibration_error, missing_resource, failed_map, clock_error;
static int calibration_calls, resource_calls, map_calls, clock_calls, error_calls;
static int enable_error, enables, disables, prepare_lock, locked;
static int mt6771_usb_read_calibration(struct mtk_phy_drv *phy)
{ assert(phy); calibration_calls++; return calibration_error; }
static struct resource *platform_get_resource_byname(struct platform_device *p, int type, const char *name)
{
    assert(p && type == IORESOURCE_MEM);
    unsigned index = resource_calls++;
    assert(index < 2 && !strcmp(name, index ? "ippc" : "sif_base"));
    return missing_resource == (int)index + 1 ? NULL : &resources[index];
}
static unsigned long resource_size(struct resource *r) { return r->size; }
static void *devm_ioremap(struct device *dev, unsigned long start, unsigned long size)
{
    assert(dev);
    unsigned index = map_calls++;
    assert(index < 2 && start == resources[index].start && size == resources[index].size);
    return failed_map == (int)index + 1 ? NULL : (void *)(uintptr_t)start;
}
static struct clk *devm_clk_get(struct device *dev, const char *name)
{ assert(dev && !strcmp(name, "ref_clk")); clock_calls++; return clock_error ? ERR_PTR(clock_error) : &reference; }
static int dev_err_probe(struct device *dev, int err, const char *fmt, ...)
{ assert(dev && !strcmp(fmt, "failed to get mandatory ref_clk\n")); error_calls++; return err; }
static void mutex_lock(int *lock) { assert(lock == &prepare_lock && !locked); locked = 1; }
static void mutex_unlock(int *lock) { assert(lock == &prepare_lock && locked); locked = 0; }
static int clk_prepare_enable(struct clk *clk)
{ assert(clk == &reference && locked); enables++; return enable_error; }
static void clk_disable_unprepare(struct clk *clk)
{ assert(clk == &reference); disables++; }
'''
    code += clock + init_exit + r'''
int main(void)
{
    struct platform_device pdev = {0};
    struct mtk_phy_drv phy;
    unsigned cases = 0;
    /* Every init stage is failed in turn; later resource access must stop. */
    const struct {int cal, resource, map, clk, result, resources, maps, clocks;} faults[] = {
        {-ENODEV,0,0,0,-ENODEV,0,0,0}, {-EINVAL,0,0,0,-EINVAL,0,0,0},
        {0,1,0,0,-EINVAL,1,0,0}, {0,0,1,0,-ENOMEM,1,1,0},
        {0,2,0,0,-EINVAL,2,1,0}, {0,0,2,0,-ENOMEM,2,2,0},
        {0,0,0,-ENOENT,-ENOENT,2,2,1},
        {0,0,0,-EPROBE_DEFER,-EPROBE_DEFER,2,2,1},
        {0,0,0,-ENOMEM,-ENOMEM,2,2,1}, {0,0,0,-EINVAL,-EINVAL,2,2,1},
        {0,0,0,0,0,2,2,1},
    };
    for (unsigned i = 0; i < sizeof(faults)/sizeof(faults[0]); i++) {
        memset(&phy, 0, sizeof(phy));
        calibration_error=faults[i].cal; missing_resource=faults[i].resource;
        failed_map=faults[i].map; clock_error=faults[i].clk;
        calibration_calls=resource_calls=map_calls=clock_calls=error_calls=0;
        assert(mtk_phy_drv_init(&pdev, &phy) == faults[i].result);
        assert(calibration_calls == 1 && resource_calls == faults[i].resources);
        assert(map_calls == faults[i].maps && clock_calls == faults[i].clocks);
        assert(error_calls == (clock_error != 0));
        assert(phy.clock_users == 0 && enables == 0 && disables == 0);
        assert(mtk_phy_drv_exit(&pdev, &phy) == 0 && disables == 0);
        if (!faults[i].result) {
            assert(phy.phy_base == (void *)0x1000 && phy.ippc_base == (void *)0x2000);
            assert(phy.clk == &reference);
        }
        cases++;
    }
    /* An enable failure must release the lock and leave the refcount at zero. */
    phy.clk = &reference;
    enable_error = -EIO;
    assert(!usb_enable_clock(&phy, true));
    assert(!locked && phy.clock_users == 0 && enables == 1 && disables == 0);
    enable_error = 0;
    assert(usb_enable_clock(&phy, true) && phy.clock_users == 1);
    assert(usb_enable_clock(&phy, true) && phy.clock_users == 2 && enables == 2);
    assert(usb_enable_clock(&phy, false) && phy.clock_users == 1 && disables == 0);
    assert(usb_enable_clock(&phy, false) && phy.clock_users == 0 && disables == 1);
    assert(usb_enable_clock(&phy, false) && phy.clock_users == 0 && disables == 1);
    assert(usb_enable_clock(&phy, true) && phy.clock_users == 1 && enables == 3);
    assert(mtk_phy_drv_exit(&pdev, &phy) == 0 && phy.clock_users == 0 && disables == 2);
    assert(mtk_phy_drv_exit(&pdev, &phy) == 0 && disables == 2);
    phy.clk = NULL;
    assert(!usb_enable_clock(&phy, true) && !locked);
    printf("%u USB PHY resource cases and clock enable/failure/release lifecycle passed\n", cases);
}
'''
    compiler = os.environ.get('CC') or shutil.which('clang') or shutil.which('cc')
    if not compiler:
        raise SystemExit('A host C compiler is required (set CC).')
    with tempfile.TemporaryDirectory(prefix='pocket-usb-phy-check-') as tmp:
        source = Path(tmp) / 'check.c'
        binary = Path(tmp) / 'check'
        source.write_text(code)
        subprocess.run([compiler, '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-fsanitize=address,undefined',
                        str(source), '-o', str(binary)], check=True)
        checked = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    if checked.stderr:
        raise SystemExit(checked.stderr)
    print(json.dumps({'source': str(SOURCE.relative_to(ROOT)),
                      'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                      'result': checked.stdout.strip(),
                      'limits': 'Actual functions with mocked resource/clock APIs; no hardware or timing qualification'},
                     indent=2))


if __name__ == '__main__':
    main()
