#!/usr/bin/env python3
"""Compare a nonexecuting HIE wire planner with the actual BSP key callback."""
import pocket_paths
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
OLD=ROOT/'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/scsi/ufs/ufs-mtk.c'
HEADER=ROOT/'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs/ufs-mt6771-hie.h'
def function(text,name):
 m=re.search(r'static (?:u8|int) '+name+r'\(',text);assert m
 end=text.index('{',m.start())+1;depth=1
 while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[m.start():end]
def main():
 old=OLD.read_text();original=function(old,'ufshcd_crypto_gie_get_mode')+'\n'+function(old,'ufs_mtk_program_key')
 code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef uint8_t u8;
#include "ufs-mt6771-hie.h"
#define BC_AES_128_XTS (1U<<3)
#define BC_AES_256_XTS (1U<<5)
#define UFS_HIE_PARAM_OFS_CFG_ID 24
#define UFS_HIE_PARAM_OFS_MODE 16
#define UFS_HIE_PARAM_OFS_KEY_TOTAL_BYTE 8
#define MTK_SIP_KERNEL_CRYPTO_HIE_CFG_REQUEST 0xc2000274U
#define le32_to_cpu(v) (v)
#define spin_lock_irqsave(lock,flags) do { (void)(lock);(flags)=0; } while(0)
#define spin_unlock_irqrestore(lock,flags) do { (void)(lock);(void)(flags); } while(0)
union ufs_crypto_cfg_entry { u32 reg_val[32];struct {u8 key[64],data_unit_size,crypto_cap_idx,reserved,config_enable;}; };
struct host {void *host_lock;};struct ufs_hba {struct host *host;};
static unsigned count;static u32 captured[6][3];
static int mt_secure_call(u32 service,u32 a,u32 b,u32 c,u32 zero) {
 assert(service==0xc2000274U && zero==0 && count<6);
 captured[count][0]=a;captured[count][1]=b;captured[count++][2]=c;return 0;
}
'''+original+r'''
int main(void) {
 struct host host={0};struct ufs_hba h={&host};unsigned cases=0;
 for(int slot=0;slot<256;slot++)for(unsigned cap=0;cap<2;cap++)for(unsigned enabled=0;enabled<2;enabled++)for(unsigned seed=0;seed<64;seed++) {
  union ufs_crypto_cfg_entry cfg={0};for(unsigned i=0;i<32;i++)cfg.reg_val[i]=0x12345678U^(seed*0x9e3779b9U)^(i*0x01010101U);
  cfg.crypto_cap_idx=cap;cfg.config_enable=enabled?0x80:0;u32 plan[6][3];count=0;
  assert(!ufs_mtk_program_key(&h,&cfg,slot));assert(count==6);
  assert(!ufs_mt6771_hie_plan(cfg.reg_val,slot,cap,enabled,plan));assert(!memcmp(plan,captured,sizeof(plan)));cases++;
 }
 const int invalid[]={-1,256,2147483647};u32 words[17]={0},plan[6][3];
 for(unsigned i=0;i<3;i++)assert(ufs_mt6771_hie_plan(words,invalid[i],0,true,plan)==-EINVAL);
 for(unsigned cap=2;cap<256;cap++)assert(ufs_mt6771_hie_plan(words,0,cap,true,plan)==-EINVAL);
 printf("%u BSP-equivalent synthetic key plans; 257 invalid slot/capability cases rejected\n",cases);
}
'''
 with tempfile.TemporaryDirectory(prefix='ufs-hie-') as tmp:
  p=Path(tmp);(p/'test.c').write_text(code)
  clang=str(pocket_paths.ndk_bin() / 'clang')
  subprocess.run([clang,'-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(HEADER.parent),str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'result':result.stdout.strip(),'valid_plans':65536,'invalid_cases':257,'source_hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [HEADER,OLD]},'secure_calls_executed':False,'keyslot_callback_registered':False,'limits':['Synthetic host data only; no device/user key material','BSP sends 68 payload bytes with a 64-byte header length, including cfg dword16; secure consumption is not established','Actual capability array ordering, status, locking, reset/reprogram and eviction remain integration gates','Not encryption, TEE/RPMB or data-compatibility qualification']}
 (ROOT/'evidence/kernel-upgrade/ufs-hie-plan-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
