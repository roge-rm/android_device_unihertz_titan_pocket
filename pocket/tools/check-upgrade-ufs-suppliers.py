#!/usr/bin/env python3
"""Fault-inject actual opt-in MFD, reset and legacy reference-clock helpers."""
import pocket_paths
import hashlib,json,runpy,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
K=ROOT/'tools/kernel-source/upgrade-5.10'
def main():
 extract=runpy.run_path(str(ROOT/'tools/check-upgrade-ufs-firmware.py'))['function']
 host=K/'drivers/scsi/ufs/ufs-mediatek.c';mfd=K/'drivers/mfd/mt6397-core.c'
 actual='\n'.join(extract(host.read_text(),n) for n in ['ufs_mt6771_init_ref_clk','ufs_mt6771_init_reset','ufs_mt6771_setup_ref_clk'])
 actual+='\n'+extract(mfd.read_text(),'mt6358_add_ufs_clock')
 code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define EPROBE_DEFER 517
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ENABLED(x) config_enabled
#define PLATFORM_DEVID_NONE -1
#define UFS_VENDOR_SAMSUNG 0x1ce
#define UFS_VENDOR_TOSHIBA 0x198
struct device_node {int refs;};
struct device {struct device_node *of_node;};
struct platform_device {struct device dev;};
struct clk {int unused;};
struct reset_control {int unused;};
struct mfd_cell {int unused;};
static const struct mfd_cell mt6358_ufs_clock_dev;
struct ufs_mtk_host {struct clk *legacy_ref_clk;struct reset_control *hci_reset,*unipro_reset,*crypto_reset;bool ref_clk_enabled;};
struct ufs_hba {struct device *dev;struct ufs_mtk_host *variant;struct {unsigned wmanufacturerid;} dev_info;};
static struct device_node child={1};static struct clk clock;static struct reset_control resets[3];
static bool present,available,config_enabled;
static int clk_error,mfd_error,enable_error,reset_error,reset_fail;
static unsigned node_gets,node_puts,clkgets,mfdcalls,resetcalls,enables,delays,delay_us;
static struct ufs_mtk_host *ufshcd_get_variant(struct ufs_hba *h) {return h->variant;}
static struct device_node *get_child(void) {node_gets++;if(!present)return NULL;child.refs++;return &child;}
static struct device_node *of_get_child_by_name(struct device_node *p,const char *name) {assert(p&&!strcmp(name,"reference-clock"));return get_child();}
static struct device_node *of_get_compatible_child(struct device_node *p,const char *name) {assert(p&&!strcmp(name,"mediatek,mt6358-ufs-clock"));return get_child();}
static bool of_device_is_available(struct device_node *n) {assert(n==&child);return available;}
static void of_node_put(struct device_node *n) {if(n){assert(n==&child&&child.refs==2);node_puts++;child.refs--;}}
static struct clk *devm_get_clk_from_child(struct device *d,struct device_node *n,const char *name) {assert(d&&n==&child&&!strcmp(name,"ref_clk"));clkgets++;return clk_error?ERR_PTR(clk_error):&clock;}
static struct reset_control *devm_reset_control_get_exclusive(struct device *d,const char *name) {static const char *names[]={"hci_rst","unipro_rst","crypto_rst"};assert(d&&resetcalls<3&&!strcmp(name,names[resetcalls]));unsigned index=resetcalls++;return reset_fail==(int)index+1?ERR_PTR(reset_error):&resets[index];}
static int devm_mfd_add_devices(struct device *d,int id,const struct mfd_cell *cell,unsigned n,void *res,int base,void *domain) {assert(d&&id==-1&&cell==&mt6358_ufs_clock_dev&&n==1&&!res&&!base&&!domain);mfdcalls++;return mfd_error;}
static int clk_prepare_enable(struct clk *c) {assert(c==&clock);enables++;return enable_error;}
static void udelay(unsigned value) {delays++;delay_us=value;}
''' + actual + r'''
int main(void) {
 struct device_node parent={1};struct platform_device p={.dev={&parent}};
 struct ufs_mtk_host host={0};struct ufs_hba h={.dev=&p.dev,.variant=&host};
 const int errors[]={0,-EIO,-ENOMEM,-EPROBE_DEFER};unsigned cases=0;
 for(int config=0;config<2;config++)for(int exists=0;exists<2;exists++)for(int active=0;active<2;active++)for(unsigned e=0;e<4;e++) {
  config_enabled=config;present=exists;available=active;mfd_error=errors[e];node_gets=node_puts=mfdcalls=0;
  assert(mt6358_add_ufs_clock(&p)==(config&&exists&&active?mfd_error:0));
  assert(node_gets==(unsigned)config&&node_puts==(unsigned)(config&&exists));
  assert(mfdcalls==(unsigned)(config&&exists&&active)&&child.refs==1);cases++;
 }
 for(int exists=0;exists<2;exists++)for(int active=0;active<2;active++)for(unsigned e=0;e<4;e++) {
  present=exists;available=active;clk_error=errors[e];node_gets=node_puts=clkgets=0;host.legacy_ref_clk=NULL;
  assert(ufs_mt6771_init_ref_clk(&h)==(!exists||!active?-ENODEV:clk_error));
  assert(node_gets==1&&node_puts==(unsigned)exists&&clkgets==(unsigned)(exists&&active)&&child.refs==1);cases++;
 }
 for(int stage=0;stage<=3;stage++)for(unsigned e=1;e<4;e++) {
  resetcalls=0;reset_fail=stage;reset_error=errors[e];
  assert(ufs_mt6771_init_reset(&h)==(stage?reset_error:0));
  assert(resetcalls==(unsigned)(stage?stage:3));cases++;
 }
 const unsigned vendors[]={0,UFS_VENDOR_TOSHIBA,UFS_VENDOR_SAMSUNG,0x1ad,0xabcd};
 for(unsigned v=0;v<5;v++)for(int initial=0;initial<2;initial++)for(int on=0;on<2;on++)for(int exists=0;exists<2;exists++)for(unsigned e=0;e<4;e++) {
  h.dev_info.wmanufacturerid=vendors[v];host.ref_clk_enabled=initial;host.legacy_ref_clk=exists?&clock:NULL;
  enables=delays=delay_us=0;enable_error=errors[e];int result=ufs_mt6771_setup_ref_clk(&h,on);cases++;
  if(!v||initial==on) {assert(!result&&!enables&&!delays&&host.ref_clk_enabled==initial);continue;}
  if(!exists) {assert(result==-ENODEV&&!enables&&!delays&&host.ref_clk_enabled==initial);continue;}
  if(!on) {assert(result==-EOPNOTSUPP&&!enables&&!delays&&host.ref_clk_enabled==initial);continue;}
  assert(result==enable_error&&enables==1);
  assert(delays==(unsigned)!enable_error&&host.ref_clk_enabled==(enable_error?initial:true));
  if(!enable_error)assert(delay_us==((v==1||v==2)?32U:30U));
 }
 printf("%u actual MFD/refclock/reset resource and fault cases passed\n",cases);
}
'''
 with tempfile.TemporaryDirectory(prefix='ufs-supplier-') as tmp:
  p=Path(tmp);(p/'test.c').write_text(code)
  cc=str(pocket_paths.ndk_bin() / 'clang')
  subprocess.run([cc,'-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'result':result.stdout.strip(),'source_sha256':{str(p.relative_to(K)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [host,mfd]},'phone_accessed':False,'limits':['Actual helper source with resource/clock/reset/MFD mocks; no hardware operation','Clock-off remains explicitly unsupported until SPM ownership is integrated','No rate model or complete kernel/DT/PM qualification']}
 (ROOT/'evidence/kernel-upgrade/ufs-supplier-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
