#!/usr/bin/env python3
"""Execute actual UFS power/init functions with resource and failure models."""
import pocket_paths
import hashlib,json,runpy,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs/ufs-mediatek.c'
HEADER=SOURCE.with_suffix('.h')
BASE=pocket_paths.platform_source() / 'kernel/motorola/sm6450/drivers/scsi/ufs/ufs-mediatek.c'
def main():
 function=runpy.run_path(str(ROOT/'tools/check-upgrade-ufs-firmware.py'))['function']
 text=SOURCE.read_text()
 core=SOURCE.with_name('ufshcd.c');core_text=core.read_text()
 assert core_text.index('ret = ufshcd_vops_suspend(hba, pm_op);') < core_text.index('ufshcd_setup_clocks(hba, false);',core_text.index('ret = ufshcd_vops_suspend(hba, pm_op);'))
 resume=core_text.index('static int ufshcd_resume(')
 assert core_text.index('ret = ufshcd_setup_clocks(hba, true);',resume) < core_text.index('ret = ufshcd_vops_resume(hba, pm_op);',resume)
 names=['ufs_mtk_is_va09_supported','ufs_mtk_mphy_power_off','ufs_mtk_mphy_power_on','ufs_mtk_init_va09_pwr_ctrl','ufs_mtk_init_host_caps','ufs_mtk_setup_clocks','ufs_mtk_init','ufs_mtk_suspend','ufs_mtk_resume']
 actual='\n'.join(function(text,name) for name in names)
 original=function(BASE.read_text(),'ufs_mtk_mphy_power_on').replace('ufs_mtk_mphy_power_on(', 'original_power_on(',1).replace('ufs_mtk_va09_pwr_ctrl(res,','ufs_mtk_va09_pwr_ctrl(hba, res,')
 code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define EPROBE_DEFER 517
#define GFP_KERNEL 0
#define UFS_MTK_CAP_VA09_PWR_CTRL 1U
#define UFS_MTK_CAP_DISABLE_AH8 2U
#define UFS_MTK_CAP_BROKEN_VCC 4U
#define UFSHCD_CAP_RPM_AUTOSUSPEND 1U
#define UFSHCD_CAP_CLK_GATING 2U
#define UFSHCD_CAP_CRYPTO 4U
#define UFSHCD_CAP_WB_EN 8U
#define UFSHCD_CAP_HIBERN8_WITH_CLK_GATING 16U
#define UFSHCI_QUIRK_SKIP_MANUAL_WB_FLUSH_CTRL 1U
#define UFS_WB_BUF_REMAIN_PERCENT(n) (n)
#define VS_LINK_HIBERN8 3
#define IS_ERR(p) ((intptr_t)(p)<0 && (intptr_t)(p)>-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define dev_info(dev,...) do { (void)(dev); } while(0)
#define dev_warn(dev,...) do { (void)(dev); warnings++; } while(0)
enum ufs_notify_change_status { PRE_CHANGE, POST_CHANGE };
struct phy { int unused; };struct regulator { int unused; };
struct ufs_hba;
struct ufs_mtk_host {
 struct ufs_hba *hba;struct phy *mphy;struct regulator *reg_va09;
 unsigned caps;bool mphy_powered_on,mphy_enabled,va09_reg_enabled,va09_fw_requested,clk_phy_voted,ref_clk_enabled,ram_probe;
};
struct device_node { bool va09; };struct device { struct device_node *of_node; };
struct settings { int wb_flush_threshold; };
enum ufs_pm_op { SYSTEM_PM };
struct ufs_hba { int link;struct device *dev;struct ufs_mtk_host *host;unsigned caps,quirks;struct settings *vps; };
struct of_device_id { int unused; };
struct arm_smccc_res { unsigned long a0; };
static const struct of_device_id ufs_mtk_of_match[]={{0}};
static struct ufs_mtk_host storage;
static struct phy phy;static struct regulator regulator;
static int phy_count,reg_count,fw_request,trace[128],length,warnings;
static unsigned faults;
static bool persistent, legacy;
static bool alloc_fails,match_fails,phy_present;
static int supply_error,bind_error;
static void event(int value) { assert(length<128);trace[length++]=value; }
// Distinct errors allow assertions that rollback never replaces primary failure.
static int error(int operation) {
 if(faults&(1U<<operation)) { if(!persistent)faults&=~(1U<<operation);return -100-operation; }
 return 0;
}
static struct ufs_mtk_host *ufshcd_get_variant(struct ufs_hba *h) { return h->host; }
static void ufshcd_set_variant(struct ufs_hba *h,struct ufs_mtk_host *host) { h->host=host; }
static int regulator_enable(struct regulator *r) {
 assert(r==&regulator);event(10);int ret=error(0);if(!ret){assert(reg_count==0);reg_count++;}return ret;
}
static int regulator_disable(struct regulator *r) {
 assert(r==&regulator);event(15);int ret=error(5);if(!ret){assert(reg_count==1&&!fw_request&&!phy_count);reg_count--;}return ret;
}
static int phy_power_on(struct phy *p) {
 assert(p==&phy);event(12);int ret=error(2);if(!ret){assert(phy_count<2);phy_count++;}return ret;
}
static int phy_power_off(struct phy *p) {
 assert(p==&phy);event(13);int ret=error(3);if(!ret){assert(phy_count>0);phy_count--;}return ret;
}
static int request_fw(struct ufs_hba *h,struct arm_smccc_res *r,int on) {
 (void)h;event(on?11:14);int ret=error(on?1:4);
 if(!ret){assert(reg_count==1);if(!on)assert(!phy_count);fw_request=on;}
 // Decoded successful dispatch; firmware result encoding is checked separately.
 r->a0=0;return ret;
}
#define ufs_mtk_va09_pwr_ctrl(h,r,on) request_fw(h,&(r),on)
static void usleep_range(unsigned low,unsigned high) { assert(low==200&&high==210);event(16); }
static struct regulator *devm_regulator_get_optional(struct device *d,const char *name) {
 (void)d;assert(!strcmp(name,"va09"));return supply_error?(struct regulator *)(intptr_t)supply_error:&regulator;
}
static bool of_property_read_bool(struct device_node *n,const char *name) {
 return !strcmp(name,"mediatek,ufs-support-va09") && n->va09;
}
static void ufs_mtk_init_boost_crypt(struct ufs_hba *h) { (void)h; }
static void ufs_mtk_boost_crypt(struct ufs_hba *h,bool on) { (void)h;event(on?21:20); }
static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *h) { (void)h;return legacy; }
/* Resource acquisition body is separately covered by legacy refclk controls. */
static int ufs_mt6771_init_ref_clk(struct ufs_hba *h) { (void)h;return 0; }
static bool ufshcd_is_link_off(struct ufs_hba *h) { return h->link==0; }
static bool ufshcd_is_link_hibern8(struct ufs_hba *h) { return h->link==1; }
static bool ufshcd_is_link_active(struct ufs_hba *h) { return h->link==2; }
static void ufshcd_set_link_off(struct ufs_hba *h) { h->link=0; }
static int ufs_mtk_link_set_lpm(struct ufs_hba *h) { (void)h;return error(7); }
static int ufs_mtk_link_set_hpm(struct ufs_hba *h) { h->link=2;return error(8); }
static void ufs_mtk_vreg_set_lpm(struct ufs_hba *h,bool lpm) { (void)h;(void)lpm; }
static int ufshcd_link_recovery(struct ufs_hba *h) { (void)h;return -EIO; }
static int mock_reset(struct ufs_hba *h,int on,struct arm_smccc_res *r) { (void)h;(void)on;r->a0=0;return 0; }
#define ufs_mtk_device_reset_ctrl(h,on,res) mock_reset(h,on,&(res))
static bool ufshcd_can_hibern8_during_gating(struct ufs_hba *h) { (void)h;return true; }
static bool ufshcd_is_auto_hibern8_enabled(struct ufs_hba *h) { (void)h;return false; }
static int ufs_mtk_wait_link_state(struct ufs_hba *h,int state,int timeout) { (void)h;(void)state;(void)timeout;return 0; }
static int ufs_mtk_setup_ref_clk(struct ufs_hba *h,bool on) {
 event(on?23:22);int ret=error(6);if(!ret)h->host->ref_clk_enabled=on;return ret;
}
static void *devm_kzalloc(struct device *d,unsigned long size,int flags) {
 (void)d;(void)flags;assert(size==sizeof(storage));if(alloc_fails)return NULL;memset(&storage,0,sizeof(storage));return &storage;
}
static const struct of_device_id *of_match_device(const struct of_device_id *table,struct device *d) {
 (void)d;assert(table==ufs_mtk_of_match);return match_fails?NULL:table;
}
static int ufs_mtk_bind_mphy(struct ufs_hba *h) {
 if(bind_error)return bind_error;h->host->mphy=phy_present?&phy:NULL;return 0;
}
static void ufs_mtk_init_reset(struct ufs_hba *h) { (void)h; }
static int ufs_mt6771_init_reset(struct ufs_hba *h) { (void)h;return 0; }
'''+actual+'\n'+original+r'''
static void reset(struct ufs_hba *h,bool va09,bool present,bool initial) {
 memset(&storage,0,sizeof(storage));memset(trace,0,sizeof(trace));length=warnings=0;faults=0;persistent=false;legacy=false;h->link=0;
 alloc_fails=match_fails=false;supply_error=bind_error=0;phy_present=present;
 h->host=&storage;storage.hba=h;storage.mphy=present?&phy:NULL;storage.reg_va09=&regulator;
 storage.caps=va09?UFS_MTK_CAP_VA09_PWR_CTRL:0;
 storage.mphy_enabled=storage.mphy_powered_on=present&&initial;
 storage.va09_reg_enabled=storage.va09_fw_requested=present&&initial&&va09;
 phy_count=present&&initial;reg_count=fw_request=present&&initial&&va09;
 h->caps=h->quirks=0x8000;h->vps->wb_flush_threshold=42;h->dev->of_node->va09=va09;
}
static void consistent(void) {
 assert(reg_count==(int)storage.va09_reg_enabled);
 assert(fw_request==(int)storage.va09_fw_requested);
 assert(phy_count==(int)storage.mphy_enabled+(int)storage.clk_phy_voted);
 assert(!fw_request||reg_count);
 assert(storage.mphy_powered_on==(storage.mphy_enabled&&(!(storage.caps&1)||(reg_count&&fw_request))));
}
int main(void) {
 struct device_node node={0};struct device dev={&node};struct settings settings={0};
 struct ufs_hba h={.dev=&dev,.vps=&settings};unsigned normal=0,sequences=0,init_cases=0,calls=0;
 // Pristine success traces remain identical for all valid base-power initial states.
 for(int va09=0;va09<2;va09++)for(int present=0;present<2;present++)for(int initial=0;initial<2;initial++)for(int on=0;on<2;on++) {
  reset(&h,va09,present,initial);int old=original_power_on(&h,on),old_length=length,old_trace[128];bool old_power=storage.mphy_powered_on;
  memcpy(old_trace,trace,sizeof(trace));reset(&h,va09,present,initial);
  assert(ufs_mtk_mphy_power_on(&h,on)==old && length==old_length && !memcmp(trace,old_trace,sizeof(trace)) && storage.mphy_powered_on==old_power);consistent();normal++;
 }
 const bool requests[]={true,true,false,false,true,false,true,true,false,false,true,false};
 for(int persist=0;persist<2;persist++)for(int va09=0;va09<2;va09++)for(int present=0;present<2;present++)for(unsigned mask=0;mask<64;mask++) {
  reset(&h,va09,present,false);faults=mask;persistent=persist;
  for(unsigned j=0;j<sizeof(requests)/sizeof(requests[0]);j++) {
   length=0;int ret=ufs_mtk_mphy_power_on(&h,requests[j]);assert(ret<=0);consistent();calls++;
  }
  faults=0;length=0;assert(!ufs_mtk_mphy_power_on(&h,false));consistent();assert(!phy_count&&!reg_count&&!fw_request);calls++;sequences++;
 }
 // Primary PHY failure survives a distinct secure-request rollback failure.
 reset(&h,true,true,false);faults=(1U<<2)|(1U<<4);
 assert(ufs_mtk_mphy_power_on(&h,true)==-102);consistent();assert(reg_count==1&&fw_request==1&&!phy_count);
 length=0;assert(!ufs_mtk_mphy_power_on(&h,true));consistent();assert(phy_count==1&&reg_count==1); // No duplicate enable vote.
 length=0;assert(!ufs_mtk_mphy_power_on(&h,false));consistent();
 // Early init errors propagate and clear the published variant pointer.
 for(int stage=0;stage<5;stage++) {
  reset(&h,true,true,false);h.host=NULL;
  if(stage==0)alloc_fails=true;if(stage==1)match_fails=true;if(stage==2)supply_error=-EPROBE_DEFER;if(stage==3)bind_error=-EPROBE_DEFER;if(stage==4)supply_error=-ENODEV;
  int ret=ufs_mtk_init(&h);assert(ret==(stage==0?-ENOMEM:stage==1?-EINVAL:stage==4?-ENODEV:-EPROBE_DEFER));
  assert(!h.host && h.caps==0x8000 && h.quirks==0x8000 && h.vps->wb_flush_threshold==42 && !phy_count&&!reg_count&&!fw_request);init_cases++;
 }
 // Real init + power helper + clock callback, including persistent cleanup failures.
 for(int persist=0;persist<2;persist++)for(int va09=0;va09<2;va09++)for(unsigned mask=0;mask<128;mask++) {
  reset(&h,va09,true,false);h.host=NULL;faults=mask;persistent=persist;
  int ret=ufs_mtk_init(&h);consistent();
  if(ret)assert(!h.host && h.caps==0x8000 && h.quirks==0x8000 && h.vps->wb_flush_threshold==42);
  else assert(h.host==&storage && (h.caps&15)==15 && phy_count==2);
  // Explicit fixture cleanup, not a claim generic UFS remove/PM is integrated.
  faults=0;length=0;h.host=&storage;assert(!ufs_mtk_setup_clocks(&h,false,PRE_CHANGE));assert(!ufs_mtk_mphy_power_on(&h,false));consistent();assert(!phy_count&&!reg_count&&!fw_request);init_cases++;
 }
 unsigned pm_cycles=0;
 for(int link=0;link<2;link++) {
  reset(&h,true,true,false);legacy=true;h.host=NULL;assert(!ufs_mtk_init(&h));consistent();
  for(int cycle=0;cycle<100;cycle++) {
   h.link=link;length=0;assert(!ufs_mtk_suspend(&h,SYSTEM_PM));consistent();assert(!phy_count&&!reg_count&&!fw_request);
   assert(!ufs_mtk_setup_clocks(&h,false,PRE_CHANGE));consistent();assert(!phy_count); // Generic core's later call is idempotent.
   length=0;assert(!ufs_mtk_setup_clocks(&h,true,POST_CHANGE));consistent();assert(phy_count==2&&reg_count==1&&fw_request);
   assert(!ufs_mtk_resume(&h,SYSTEM_PM));consistent();assert(phy_count==2);pm_cycles++;
  }
  h.link=0;length=0;assert(!ufs_mtk_suspend(&h,SYSTEM_PM));consistent();
 }

 storage.ram_probe=true;length=0;
 assert(ufs_mtk_suspend(&h,SYSTEM_PM)==-EOPNOTSUPP);
 assert(ufs_mtk_resume(&h,SYSTEM_PM)==-EOPNOTSUPP);
 assert(!length&&!phy_count&&!reg_count&&!fw_request);
 printf("%u pristine traces, %u power fault sequences (%u calls), 1 distinct-error retry scenario and %u init cases and %u PM cycles passed\n",normal,sequences,calls,init_cases,pm_cycles);
}
'''
 with tempfile.TemporaryDirectory(prefix='ufs-power-') as temp:
  p=Path(temp);(p/'test.c').write_text(code)
  clang=str(pocket_paths.ndk_bin() / 'clang')
  subprocess.run([clang,'-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'result':result.stdout.strip(),'pristine_traces':16,'power_fault_sequences':512,'power_calls':6656,'distinct_error_retry_scenarios':1,'init_cases':517,'pm_cycles':200,'core_sha256':hashlib.sha256(core.read_bytes()).hexdigest(),'sanitizers':['address','undefined'],'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),'reference_sha256':hashlib.sha256(BASE.read_bytes()).hexdigest(),'device_accessed':False,'limits':['Host resource/one-shot and persistent error models, not hardware/firmware qualification','Firmware result decoding has separate binary/host evidence; these state flags do not prove voltage','PM fixture follows inspected generic callback order, with mocked firmware/link operations; remove/exit remains open','Cleanup errors can leave power requested; warnings do not prove physical recovery','Engineering PM callbacks explicitly reject before resource operations; normal PM model is not hardware qualification']}
 (ROOT/'evidence/kernel-upgrade/ufs-power-init-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
