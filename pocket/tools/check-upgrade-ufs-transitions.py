#!/usr/bin/env python3
"""Execute actual UFS clock sequencing with PHY/refclk failure injection."""
import pocket_paths
import hashlib,json,runpy,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs/ufs-mediatek.c'
BASE=pocket_paths.platform_source() / 'kernel/motorola/sm6450/drivers/scsi/ufs/ufs-mediatek.c'
def main():
 function=runpy.run_path(str(ROOT/'tools/check-upgrade-ufs-firmware.py'))['function']
 current=function(SOURCE.read_text(),'ufs_mtk_setup_clocks')
 original=function(BASE.read_text(),'ufs_mtk_setup_clocks').replace('ufs_mtk_setup_clocks(', 'original_setup_clocks(',1)
 code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
enum ufs_notify_change_status { PRE_CHANGE, POST_CHANGE };
#define VS_LINK_HIBERN8 3
struct ufs_mtk_host { void *mphy; bool ref_clk_enabled, clk_phy_voted, mphy_powered_on; };
struct ufs_hba { struct ufs_mtk_host *host; void *dev; int link; bool can_hibern8, auto_hibern8; };
static int phy_on_error,phy_off_error,ref_error,rollback_error,wait_error,ref_count,warnings;
static int trace[32],length;
static void add(int event) { assert(length<32);trace[length++]=event; }
static struct ufs_mtk_host *ufshcd_get_variant(struct ufs_hba *h) { return h->host; }
static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *h) { (void)h;return false; }
static int ufs_mtk_mphy_power_on(struct ufs_hba *h,bool on) { (void)h;(void)on;return 0; }
static bool ufshcd_is_link_off(struct ufs_hba *h) { return h->link==0; }
static bool ufshcd_is_link_hibern8(struct ufs_hba *h) { return h->link==1; }
static bool ufshcd_can_hibern8_during_gating(struct ufs_hba *h) { return h->can_hibern8; }
static bool ufshcd_is_auto_hibern8_enabled(struct ufs_hba *h) { return h->auto_hibern8; }
static int ufs_mtk_wait_link_state(struct ufs_hba *h,int state,int timeout) {
 (void)h;assert(state==3 && timeout==15);add(1);return wait_error;
}
static void ufs_mtk_boost_crypt(struct ufs_hba *h,bool on) { (void)h;add(on?3:2); }
static int ufs_mtk_setup_ref_clk(struct ufs_hba *h,bool on) {
 add(on?5:4);int ret=ref_count++?rollback_error:ref_error;
 if(!ret)h->host->ref_clk_enabled=on;return ret;
}
static int phy_power_on(void *phy) { (void)phy;add(6);return phy_on_error; }
static int phy_power_off(void *phy) { (void)phy;add(7);return phy_off_error; }
#define dev_warn(dev,...) do { (void)(dev);warnings++; } while(0)
static void reset(void) {
 phy_on_error=phy_off_error=ref_error=rollback_error=wait_error=ref_count=warnings=length=0;
 memset(trace,0,sizeof(trace));
}
'''+original+'\n'+current+r'''
int main(void) {
 struct ufs_mtk_host host={0};struct ufs_hba h={.host=&host};unsigned normal=0,faults=0;
 for(int on=0;on<2;on++) for(int status=0;status<2;status++) for(int link=0;link<3;link++)
 for(int can=0;can<2;can++) for(int auto_h=0;auto_h<2;auto_h++) {
  h.link=link;h.can_hibern8=can;h.auto_hibern8=auto_h;host.ref_clk_enabled=!on;host.clk_phy_voted=!on;reset();
  int expected=original_setup_clocks(&h,on,status),old_length=length,old_trace[32];bool old_state=host.ref_clk_enabled;
  memcpy(old_trace,trace,sizeof(trace));host.ref_clk_enabled=!on;host.clk_phy_voted=!on;reset();
  assert(ufs_mtk_setup_clocks(&h,on,status)==expected && host.ref_clk_enabled==old_state && length==old_length && !memcmp(trace,old_trace,sizeof(trace)));normal++;
 }
 h.host=NULL;reset();assert(!ufs_mtk_setup_clocks(&h,true,POST_CHANGE)&&!length);normal++;h.host=&host;
 const int errors[]={-EIO,-ETIMEDOUT,-EOPNOTSUPP};
 for(unsigned i=0;i<3;i++) {
  reset();host.clk_phy_voted=false;phy_on_error=errors[i];assert(ufs_mtk_setup_clocks(&h,true,POST_CHANGE)==errors[i]);assert(length==1&&trace[0]==6);faults++;
  for(int rollback=0;rollback<2;rollback++) {
   reset();host.clk_phy_voted=false;ref_error=errors[i];phy_off_error=rollback?-EBUSY:0;host.ref_clk_enabled=false;
   assert(ufs_mtk_setup_clocks(&h,true,POST_CHANGE)==errors[i]);
   assert(length==3&&trace[0]==6&&trace[1]==5&&trace[2]==7&&warnings==rollback&&!host.ref_clk_enabled);faults++;
   reset();host.clk_phy_voted=true;h.link=0;ref_error=errors[i];host.ref_clk_enabled=true;
   assert(ufs_mtk_setup_clocks(&h,false,PRE_CHANGE)==errors[i]);
   assert(length==3&&trace[0]==2&&trace[1]==4&&trace[2]==3&&host.ref_clk_enabled);faults++;
   for(int initial=0;initial<2;initial++) {
    reset();host.clk_phy_voted=true;h.link=0;phy_off_error=errors[i];rollback_error=rollback?-EBUSY:0;host.ref_clk_enabled=initial;
    assert(ufs_mtk_setup_clocks(&h,false,PRE_CHANGE)==errors[i]);
    assert(length==5&&trace[0]==2&&trace[1]==4&&trace[2]==7&&trace[3]==(initial?5:4)&&trace[4]==3&&warnings==rollback);
    assert(host.ref_clk_enabled==(rollback?false:initial));faults++;
   }
  }
  reset();h.link=1;wait_error=errors[i];assert(ufs_mtk_setup_clocks(&h,false,PRE_CHANGE)==errors[i]);assert(length==1&&trace[0]==1);faults++;
 }
 reset();host.clk_phy_voted=false;host.ref_clk_enabled=false;ref_error=-EIO;phy_off_error=-EBUSY;
 assert(ufs_mtk_setup_clocks(&h,true,POST_CHANGE)==-EIO && host.clk_phy_voted);
 reset();assert(!ufs_mtk_setup_clocks(&h,true,POST_CHANGE));assert(length==2&&trace[0]==5&&trace[1]==3&&host.clk_phy_voted);
 reset();assert(!ufs_mtk_setup_clocks(&h,true,POST_CHANGE));assert(length==2&&trace[0]==5&&trace[1]==3);
 reset();h.link=0;assert(!ufs_mtk_setup_clocks(&h,false,PRE_CHANGE));assert(length==3&&trace[0]==2&&trace[1]==4&&trace[2]==7&&!host.clk_phy_voted);
 reset();assert(!ufs_mtk_setup_clocks(&h,false,PRE_CHANGE));assert(length==2&&trace[0]==2&&trace[1]==4);
 printf("%u success/null-host traces, %u failure/rollback cases and 4 vote retry cases passed\n",normal,faults);
}
'''
 with tempfile.TemporaryDirectory(prefix='ufs-transitions-') as temp:
  p=Path(temp);(p/'test.c').write_text(code)
  clang=str(pocket_paths.ndk_bin() / 'clang')
  subprocess.run([clang,'-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'result':result.stdout.strip(),'success_traces':49,'failure_cases':30,'vote_retry_cases':4,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'reference_sha256':hashlib.sha256(BASE.read_bytes()).hexdigest(),'phone_accessed':False,'limits':['Clock callback only; init and mphy-power lifecycle checks are recorded separately','Rollback is best-effort with warnings, not hardware-state proof','Crypto boost helper remains void and can log internal failures','All PHY, clock and link operations mocked; host remains disabled']}
 (ROOT/'evidence/kernel-upgrade/ufs-transition-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
