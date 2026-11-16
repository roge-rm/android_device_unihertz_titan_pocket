#!/usr/bin/env python3
"""Exercise the actual UFS init capability boundary, without any firmware I/O."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs/ufs-mediatek.c'


def main():
    extract = runpy.run_path(str(ROOT / 'tools/check-upgrade-ufs-firmware.py'))['function']
    body = extract(SOURCE.read_text(), 'ufs_mtk_init')
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define GFP_KERNEL 0
#define UFSHCD_CAP_CLK_GATING (1U<<0)
#define UFSHCD_CAP_RPM_AUTOSUSPEND (1U<<6)
#define UFSHCD_CAP_WB_EN (1U<<7)
#define UFSHCD_CAP_CRYPTO (1U<<8)
#define UFSHCD_CAP_HIBERN8_WITH_CLK_GATING (1U<<10)
#define UFSHCI_QUIRK_SKIP_MANUAL_WB_FLUSH_CTRL (1U<<12)
#define UFS_MTK_CAP_DISABLE_AH8 2U
#define UFS_WB_BUF_REMAIN_PERCENT(x) (x)
struct device { int unused; };
struct settings { unsigned wb_flush_threshold; };
struct ufs_hba;
struct ufs_mtk_host { struct ufs_hba *hba;unsigned caps;bool clk_phy_voted,ram_probe;void *mphy; };
struct ufs_hba { struct device *dev;struct ufs_mtk_host *variant;unsigned caps,quirks;struct settings *vps; };
struct of_device_id { int unused; };
static struct of_device_id ufs_mtk_of_match[1];
static struct ufs_mtk_host host;
static bool legacy,ram_probe;
static int failure;
static void *devm_kzalloc(struct device *dev,unsigned long n,int flags) {
 (void)dev;(void)flags;assert(n==sizeof(host));memset(&host,0,sizeof(host));return failure==1?NULL:&host;
}
static void ufshcd_set_variant(struct ufs_hba *h,struct ufs_mtk_host *v) { h->variant=v; }
static const struct of_device_id *of_match_device(const struct of_device_id *ids,struct device *dev) {
 (void)dev;return failure==2?NULL:ids;
}
static int ufs_mtk_init_host_caps(struct ufs_hba *h) { h->variant->ram_probe=legacy&&ram_probe;return failure==3?-EIO:0; }
static int ufs_mtk_bind_mphy(struct ufs_hba *h) { (void)h;return failure==4?-EIO:0; }
static void ufs_mtk_init_reset(struct ufs_hba *h) { (void)h; }
static int ufs_mt6771_init_reset(struct ufs_hba *h) { (void)h;return 0; }
static int ufs_mtk_mphy_power_on(struct ufs_hba *h,bool on) { (void)h;return on&&failure==5?-EIO:0; }
static int ufs_mtk_setup_clocks(struct ufs_hba *h,bool on,int stage) { (void)h;(void)on;(void)stage;return failure==6?-EIO:0; }
static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *h) { (void)h;return legacy; }
static int phy_power_off(void *p) { (void)p;assert(false);return -EIO; }
#define POST_CHANGE 1
#define dev_info(dev,...) do { (void)(dev); } while(0)
#define dev_warn(dev,...) do { (void)(dev); } while(0)
''' + body + r'''
int main(void) {
 struct device dev={0};struct settings settings={0};struct ufs_hba h={.dev=&dev,.vps=&settings};
 unsigned count=0;
 for(int profile=0;profile<2;profile++)for(int probe=0;probe<2;probe++)for(unsigned initial=0;initial<65536;initial++) {
  legacy=profile;ram_probe=probe;failure=0;h.caps=initial;h.quirks=0;
  assert(!ufs_mtk_init(&h)&&h.variant==&host);
  unsigned expected=initial|UFSHCD_CAP_CLK_GATING|UFSHCD_CAP_RPM_AUTOSUSPEND|UFSHCD_CAP_WB_EN;
  expected=legacy?expected&~UFSHCD_CAP_CRYPTO:expected|UFSHCD_CAP_CRYPTO;
  if(legacy&&ram_probe)expected&=~(UFSHCD_CAP_CLK_GATING|UFSHCD_CAP_RPM_AUTOSUSPEND|UFSHCD_CAP_WB_EN|UFSHCD_CAP_HIBERN8_WITH_CLK_GATING);
  assert(h.caps==expected);count++;
 }
 unsigned failed=0;
 for(int profile=0;profile<2;profile++)for(int stage=1;stage<7;stage++)for(int crypto=0;crypto<2;crypto++) {
  legacy=profile;failure=stage;h.caps=crypto?UFSHCD_CAP_CRYPTO:0;h.variant=NULL;
  int ret=ufs_mtk_init(&h);assert(ret<0&&!h.variant);
  assert(h.caps==(crypto?UFSHCD_CAP_CRYPTO:0));failed++;
 }
 printf("%u actual-init profile/capability cases and %u failure publication cases passed\n",count,failed);
}
'''
    with tempfile.TemporaryDirectory(prefix='ufs-crypto-cap-') as tmp:
        p = Path(tmp)
        (p / 'check.c').write_text(code)
        clang = str(pocket_paths.ndk_bin() / 'clang')
        subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        str(p / 'check.c'), '-o', str(p / 'check')], check=True)
        result = subprocess.run([str(p / 'check')], capture_output=True, text=True, check=True)
    record = {'result': result.stdout.strip(), 'successful_init_capability_cases': 262144,
              'failed_init_publication_cases': 24,
              'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              'device_accessed': False,
              'limits': ['Supplier, power, clock and firmware operations mocked',
                        'Capability suppression is not an encryption or hardware crypto implementation',
                        'MT6771 engineering match requires explicit opt-in; no key callback registered']}
    (ROOT / 'evidence/kernel-upgrade/ufs-crypto-capability-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
