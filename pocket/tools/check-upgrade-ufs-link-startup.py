#!/usr/bin/env python3
"""Execute actual legacy HCE/link/power callbacks against shipped trace contracts."""
import pocket_paths
import hashlib,json,runpy,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs/ufs-mediatek.c'
def main():
 extract=runpy.run_path(str(ROOT/'tools/check-upgrade-ufs-firmware.py'))['function']
 actual='\n'.join(extract(SOURCE.read_text(),name) for name in ['ufs_mtk_hce_enable_notify','ufs_mt6771_pre_link','ufs_mt6771_post_link','ufs_mtk_pre_pwr_change'])
 code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(x) (1U<<(x))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define MTK_SIP_SMC_CMD(x) (0xc2000000UL+(x))
#define UFSHCD_CAP_CRYPTO BIT(8)
#define UFS_MTK_CAP_DISABLE_AH8 BIT(2)
#define REG_AUTO_HIBERNATE_IDLE_TIMER 0x18
#define MASK_AUTO_HIBERN8_SUPPORT BIT(23)
#define REG_UFS_REFCLK_CTRL 0x144
#define VS_UNIPROPOWERDOWNCONTROL 0xd0a8
#define VS_SAVEPOWERCONTROL 0xd0a6
#define UFS_MT6771_PA_SCRAMBLING 0x1585
#define PA_LOCAL_TX_LCC_ENABLE 0x155e
#define PA_PWRMODEUSERDATA0 0x15b0
#define PA_TXHSADAPTTYPE 0x15d4
#define PA_INITIAL_ADAPT 1
#define PA_NO_ADAPT 3
#define UIC_ARG_MIB(x) ((u32)(x)<<16)
#define UFS_HS_G3 3
#define UFS_HS_G4 4
#define UFS_MTK_LIMIT_NUM_LANES_TX 2
#define UFS_MTK_LIMIT_NUM_LANES_RX 2
#define UFS_MTK_LIMIT_HSGEAR_RX 4
#define UFS_MTK_LIMIT_HSGEAR_TX 4
#define UFS_MTK_LIMIT_PWMGEAR_RX 4
#define UFS_MTK_LIMIT_PWMGEAR_TX 4
#define UFS_MTK_LIMIT_RX_PWR_PWM 2
#define UFS_MTK_LIMIT_TX_PWR_PWM 2
#define UFS_MTK_LIMIT_RX_PWR_HS 1
#define UFS_MTK_LIMIT_TX_PWR_HS 1
#define UFS_MTK_LIMIT_HS_RATE 2
#define UFS_MTK_LIMIT_DESIRED_MODE 1
#define spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
#define pr_info(...) ((void)0)
#define dev_warn(dev,...) do{(void)(dev);warnings++;}while(0)
enum ufs_notify_change_status {PRE_CHANGE,POST_CHANGE};
struct device {int unused;};
struct settings {unsigned hba_enable_delay_us;};
struct ufs_mtk_host {bool unipro_lpm;unsigned caps;struct {unsigned major;} hw_ver;};
struct host {void *host_lock;};
struct ufs_hba {struct device *dev;struct settings *vps;struct host *host;struct ufs_mtk_host *variant;unsigned caps,capabilities,ahit,lanes_per_direction;};
struct ufs_pa_layer_attr {unsigned gear_tx,gear_rx,lane_tx,lane_rx;};
struct ufs_dev_params {unsigned tx_lanes,rx_lanes,hs_rx_gear,hs_tx_gear,pwm_rx_gear,pwm_tx_gear,rx_pwr_pwm,tx_pwr_pwm,rx_pwr_hs,tx_pwr_hs,hs_rate,desired_working_mode;};
struct arm_smccc_res {unsigned long a0,a1,a2,a3;};
static bool legacy;static unsigned resets,crypto,smcs,mmios,warnings,cg,dmes,fail_at;
static unsigned power_value,save_value,helper_error;
static u32 attributes[16],values[16];
static struct ufs_dev_params last_cap;
static struct ufs_mtk_host *ufshcd_get_variant(struct ufs_hba *h) {return h->variant;}
static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *h) {(void)h;return legacy;}
static void ufs_mtk_host_reset(struct ufs_hba *h) {(void)h;resets++;}
static void ufs_mtk_crypto_enable(struct ufs_hba *h) {(void)h;crypto++;}
static void arm_smccc_smc(unsigned long fn,unsigned long cmd,unsigned long a2,unsigned long a3,unsigned long a4,unsigned long a5,unsigned long a6,unsigned long a7,struct arm_smccc_res *r) {assert(fn==0xc2000270UL&&cmd==4&&!a2&&!a3&&!a4&&!a5&&!a6&&!a7);smcs++;r->a0=0x12345678;}
static void ufshcd_writel(struct ufs_hba *h,u32 value,unsigned offset) {(void)h;assert(!value&&(offset==0x144||offset==0x18));mmios++;}
static int ufshcd_dme_get(struct ufs_hba *h,u32 attr,u32 *value) {(void)h;assert(dmes<16);attributes[dmes]=attr;values[dmes]=0xffffffff;dmes++;if(dmes==fail_at)return -EIO;assert(attr==UIC_ARG_MIB(VS_UNIPROPOWERDOWNCONTROL)||attr==UIC_ARG_MIB(VS_SAVEPOWERCONTROL));*value=attr==UIC_ARG_MIB(VS_UNIPROPOWERDOWNCONTROL)?power_value:save_value;return 0;}
static int ufshcd_dme_set(struct ufs_hba *h,u32 attr,u32 value) {(void)h;assert(dmes<16);attributes[dmes]=attr;values[dmes]=value;dmes++;return dmes==fail_at?-EIO:0;}
static void ufs_mtk_cfg_unipro_cg(struct ufs_hba *h,bool on) {(void)h;assert(on);cg++;}
static int ufshcd_get_pwr_dev_param(struct ufs_dev_params *cap,struct ufs_pa_layer_attr *max,struct ufs_pa_layer_attr *req) {last_cap=*cap;req->gear_tx=max->gear_tx<cap->hs_tx_gear?max->gear_tx:cap->hs_tx_gear;req->gear_rx=max->gear_rx<cap->hs_rx_gear?max->gear_rx:cap->hs_rx_gear;req->lane_tx=max->lane_tx<cap->tx_lanes?max->lane_tx:cap->tx_lanes;req->lane_rx=max->lane_rx<cap->rx_lanes?max->lane_rx:cap->rx_lanes;return helper_error?-EINVAL:0;}
''' + actual + r'''
int main(void) {
 struct device dev={0};struct settings settings={0};struct host shost={0};struct ufs_mtk_host variant={.hw_ver={2}};
 struct ufs_hba h={.dev=&dev,.vps=&settings,.host=&shost,.variant=&variant};unsigned cases=0;
 for(int soc=0;soc<2;soc++)for(int low=0;low<2;low++)for(int crypt=0;crypt<2;crypt++)for(int ah8=0;ah8<2;ah8++)for(int stage=0;stage<3;stage++) {
  legacy=soc;variant.unipro_lpm=low;variant.caps=ah8?UFS_MTK_CAP_DISABLE_AH8:0;h.caps=crypt?UFSHCD_CAP_CRYPTO:0;h.capabilities=MASK_AUTO_HIBERN8_SUPPORT;h.ahit=123;
  resets=crypto=smcs=mmios=0;settings.hba_enable_delay_us=999;
  assert(!ufs_mtk_hce_enable_notify(&h,stage));
  assert(resets==(unsigned)(!soc&&!stage&&!low));assert(crypto==(unsigned)(!soc&&!stage&&crypt));
  assert(smcs==(unsigned)(soc&&stage==1));assert(mmios==(unsigned)((!stage&&ah8)+(soc&&stage==1)));
  if(!stage)assert(settings.hba_enable_delay_us==(low?0U:600U));
  if(!stage&&ah8)assert(!h.ahit&&!(h.capabilities&MASK_AUTO_HIBERN8_SUPPORT));cases++;
 }
 for(unsigned state=0;state<3;state++)for(unsigned save=0;save<256;save++)for(unsigned fault=0;fault<7;fault++) {
  power_value=state;save_value=save;fail_at=fault;dmes=0;variant.unipro_lpm=true;
  int ret=ufs_mt6771_pre_link(&h);unsigned total=state==1?5:4;
  assert(ret==(fault&&fault<=total?-EIO:0));assert(dmes==(fault&&fault<=total?fault:total));
  if(!ret){unsigned pos=state==1?3:2;assert(attributes[pos]==UIC_ARG_MIB(VS_SAVEPOWERCONTROL)&&values[pos]==(save&~BIT(6)));assert(attributes[total-1]==UIC_ARG_MIB(UFS_MT6771_PA_SCRAMBLING)&&!values[total-1]);assert(!variant.unipro_lpm);}cases++;
 }
 for(unsigned fault=0;fault<3;fault++) {fail_at=fault;dmes=cg=warnings=0;assert(!ufs_mt6771_post_link(&h));assert(dmes==1&&cg==1&&warnings==(unsigned)(fault==1));assert(attributes[0]==UIC_ARG_MIB(PA_LOCAL_TX_LCC_ENABLE)&&!values[0]);cases++;}
 struct ufs_pa_layer_attr max={4,4,2,2},req={0};legacy=true;
 static const unsigned timing[]={0x1fff,0xffff,0x7fff,0x1fff,0xffff,0x7fff};
 for(unsigned lane=0;lane<4;lane++)for(unsigned gear=1;gear<=4;gear++)for(unsigned error=0;error<2;error++)for(unsigned fault=0;fault<8;fault++) {
  h.lanes_per_direction=lane;max.gear_tx=max.gear_rx=gear;helper_error=error;fail_at=fault;dmes=0;
  int ret=ufs_mtk_pre_pwr_change(&h,&max,&req);
  if(lane<1||lane>2||error){assert(ret==-EINVAL&&!dmes);cases++;continue;}
  assert(last_cap.tx_lanes==lane&&last_cap.rx_lanes==lane&&last_cap.hs_tx_gear==3&&last_cap.hs_rx_gear==3);
  assert(req.gear_tx==(gear<3?gear:3)&&req.lane_tx==lane);
  assert(ret==(fault&&fault<=6?-EIO:0));assert(dmes==(fault&&fault<=6?fault:6));
  for(unsigned i=0;i<dmes;i++)assert(attributes[i]==UIC_ARG_MIB(PA_PWRMODEUSERDATA0+i)&&values[i]==timing[i]);cases++;
 }
 printf("%u actual HCE/link/power contract and fault cases passed\n",cases);
}
'''
 with tempfile.TemporaryDirectory(prefix='ufs-link-') as temp:
  p=Path(temp);(p/'test.c').write_text(code)
  cc=str(pocket_paths.ndk_bin() / 'clang')
  subprocess.run([cc,'-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 records={}
 for name in ['hce-notify-native','link-startup-native','pwr-change-native']:
  p=ROOT/'evidence/kernel-upgrade/ufs-engineering-rea'/(name+'.json');d=json.loads(p.read_text());assert d['subject']['digest']['sha256']=='4155c6d5315471656002a433878ade88683f344a7c3f5cc3a47cced41f3f628b';records[name]={'evidence_id':d['evidence_id'],'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
 report={'result':result.stdout.strip(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'native_evidence':records,'phone_accessed':False,'limits':['Actual functions with mocked DME/SMC/MMIO, not hardware qualification','Legacy0x270 restore follows shipped call and ignores its undocumented reply; no new keyslot callback','Pwr timing failures stop engineering operation; optional post-link LCC failure follows shipped report-and-continue behavior']}
 (ROOT/'evidence/kernel-upgrade/ufs-link-contract-check.json').write_text(json.dumps(report,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
