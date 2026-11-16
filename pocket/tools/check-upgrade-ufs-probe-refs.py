#!/usr/bin/env python3
"""Run the actual MediaTek UFS probe against device/node lifetime mocks."""
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
    text = SOURCE.read_text()
    start = text.index('static void ufs_mt6771_release_pm_vote(')
    end = text.index('\n}', start) + 2
    body = text[start:end] + '\n' + extract(text, 'ufs_mtk_probe')
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#define EPROBE_DEFER 517
#define DL_FLAG_AUTOPROBE_CONSUMER 1
#define DL_STATE_DORMANT 0
struct device { int refs;struct device_node *of_node; };
struct device_node { int refs; };
struct platform_device { struct device dev; };
struct device_link { int status; };
static bool legacy_probe,probe_opt_in;
static bool of_device_is_compatible(struct device_node *n,const char *name) { (void)n;(void)name;return legacy_probe; }
static bool of_property_read_bool(struct device_node *n,const char *name) { (void)n;(void)name;return probe_opt_in; }
static struct platform_device supplier;
static struct device_node node;
static struct device_link managed_link;
static bool has_node,has_supplier,linked;
static int link_mode, generic_ret, generic_calls,device_puts,lookups,ufs_hba_mtk_vops;
static int pm_votes,action_error;
static void (*managed_action)(void *);static void *managed_data;
static void pm_runtime_get_noresume(struct device *d) { assert(d);pm_votes++; }
static void pm_runtime_put_noidle(void *d) { assert(d&&pm_votes>0);pm_votes--; }
static int devm_add_action_or_reset(struct device *d,void (*fn)(void *),void *data) {
 assert(d==data&&!managed_action);if(action_error){fn(data);return action_error;}
 managed_action=fn;managed_data=data;return 0;
}
static struct device_node *of_find_compatible_node(void *a,void *b,const char *c) {
 (void)a;(void)b;(void)c;if(!has_node)return NULL;node.refs++;return &node;
}
static struct platform_device *of_find_device_by_node(struct device_node *n) {
 assert(n==&node);if(!has_supplier)return NULL;lookups++;supplier.dev.refs++;return &supplier;
}
static struct device_link *device_link_add(struct device *consumer,struct device *s,int flags) {
 assert(consumer&&s==&supplier.dev&&flags==DL_FLAG_AUTOPROBE_CONSUMER);
 if(!link_mode)return NULL;
 if(!linked){supplier.dev.refs++;linked=true;}
 managed_link.status=link_mode==1?DL_STATE_DORMANT:1;return &managed_link;
}
static void put_device(struct device *d) { assert(d==&supplier.dev&&d->refs>1);d->refs--;device_puts++; }
static void of_node_put(struct device_node *n) { if(n){assert(n==&node&&n->refs==2);n->refs--;} }
static int ufshcd_pltfrm_init(struct platform_device *p,void *ops) {
 assert(p&&ops==&ufs_hba_mtk_vops);generic_calls++;return generic_ret;
}
#define dev_notice(dev,...) do { (void)(dev); } while(0)
#define dev_info(dev,...) do { (void)(dev); } while(0)
''' + body + r'''
int main(void) {
 struct platform_device consumer={0};unsigned count=0;
 const int errors[]={0,-5,-12,-517};
 for(int n=0;n<2;n++)for(int s=0;s<2;s++)for(int l=0;l<3;l++)for(int e=0;e<4;e++) {
  has_node=n;has_supplier=s;link_mode=l;generic_ret=errors[e];linked=false;
  node.refs=1;supplier.dev.refs=1;lookups=device_puts=generic_calls=0;
  for(int retry=0;retry<100;retry++) {
   int expected=n&&s&&l==1?-EPROBE_DEFER:generic_ret;
   assert(ufs_mtk_probe(&consumer)==expected);
   assert(node.refs==1&&supplier.dev.refs==1+(linked?1:0));
   assert(device_puts==lookups);
   assert(generic_calls==(n&&s&&l==1?0:retry+1));count++;
  }
  if(linked)supplier.dev.refs--; /* managed-link teardown owns its own ref */
  assert(supplier.dev.refs==1);
 }
 legacy_probe=true;
 for(int opt=0;opt<2;opt++)for(int e=0;e<4;e++) {
  probe_opt_in=opt;generic_ret=errors[e];generic_calls=lookups=device_puts=0;
  assert(ufs_mtk_probe(&consumer)==(opt?generic_ret:-ENODEV));
  assert(!lookups&&!device_puts&&generic_calls==opt&&node.refs==1&&supplier.dev.refs==1);
  assert(pm_votes==opt);
  if(managed_action){managed_action(managed_data);managed_action=NULL;}
  assert(!pm_votes);count++;
 }
 probe_opt_in=true;action_error=-ENOMEM;generic_calls=0;
 assert(ufs_mtk_probe(&consumer)==-ENOMEM&&!pm_votes&&!generic_calls&&!managed_action);count++;
 printf("%u actual-probe lifetime/error/retry and opt-in cases passed\n",count);
}
'''
    with tempfile.TemporaryDirectory(prefix='ufs-probe-ref-') as tmp:
        p = Path(tmp)
        (p / 'check.c').write_text(code)
        clang = str(pocket_paths.ndk_bin() / 'clang')
        subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        str(p / 'check.c'), '-o', str(p / 'check')], check=True)
        result = subprocess.run([str(p / 'check')], capture_output=True, text=True, check=True)
    reference = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/base/core.c'
    of_platform = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/of/platform.c'
    record = {'result': result.stdout.strip(), 'actual_probe_cases': 4809,
              'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              'generic_device_link_source_sha256': hashlib.sha256(reference.read_bytes()).hexdigest(),
              'of_lookup_source_sha256': hashlib.sha256(of_platform.read_bytes()).hexdigest(),
              'device_accessed': False,
              'limits': ['Mocked nodes, supplier refs, managed links and generic probe',
                        'Does not qualify generic probe, hardware startup or actual deferred-probe scheduling',
                        'Engineering MT6771 probe opt-in covered; not a real clock/firmware/block operation']}
    (ROOT / 'evidence/kernel-upgrade/ufs-probe-reference-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
