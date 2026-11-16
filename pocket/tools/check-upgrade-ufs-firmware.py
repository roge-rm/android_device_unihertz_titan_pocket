#!/usr/bin/env python3
"""Host-check actual UFS firmware dispatch and reference-clock callbacks."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/scsi/ufs'
BASE = pocket_paths.platform_source() / 'kernel/motorola/sm6450/drivers/scsi/ufs'


def function(source, name):
    match = re.search(r'^static (?:bool|int) ' + name + r'\(', source, re.M)
    assert match, name
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    source = WORK / 'ufs-mediatek.c'
    header = WORK / 'ufs-mediatek-fw.h'
    old_header = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/misc/mediatek/include/mt-plat/mtk_secure_api.h'
    old_platform = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/drivers/scsi/ufs/mediatek/mt6771/ufs-mtk-platform.c'
    old_api = old_header.read_text()
    assert re.search(r'MTK_SIP_KERNEL_UFS_CTL\s*\\\n\s*\(0x82000276 \| MTK_SIP_SMC_AARCH_BIT\)', old_api)
    assert 'mt_secure_call(MTK_SIP_KERNEL_UFS_CTL, 1, 1, 0, 0)' in old_platform.read_text()
    assert 'mt_secure_call(MTK_SIP_KERNEL_UFS_CTL, 2, 0, 0, 0)' in old_platform.read_text()
    text = source.read_text()
    match_table = text[text.index('static const struct of_device_id'):text.index('static bool ufs_mtk_is_boost')]
    assert 'mt6771-ufshci' in match_table and 'unihertz,ram-storage-probe' in text, 'Engineering match must keep explicit probe opt-in'
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
#include "ufs-mediatek-fw.h"
#define MTK_SIP_UFS_CONTROL 0xc2000276UL
#define UFS_MTK_SIP_REF_CLK_NOTIFICATION 8
#define REG_UFS_REFCLK_CTRL 0x144
#define REFCLK_REQUEST 1
#define REFCLK_ACK 2
#define REFCLK_RELEASE 0
#define REFCLK_REQ_TIMEOUT_US 3000
typedef long long ktime_t;
struct device_node { bool legacy; };
struct device { struct device_node *of_node; };
struct ufs_mtk_host { bool ref_clk_enabled; unsigned ref_clk_ungating_wait_us, ref_clk_gating_wait_us; };
struct ufs_hba { struct device *dev; struct ufs_mtk_host *variant; };
struct arm_smccc_res { unsigned long a0,a1,a2,a3; };
struct event { unsigned long kind,a,b; };
static struct event events[64];
static unsigned count, smcs, mmios, delays;
static unsigned long reply, second_reply;
static bool sequenced;
static u32 reg_value;
static bool ack_ok;
static ktime_t clock_tick;
static void add(unsigned kind,unsigned long a,unsigned long b) {
    assert(count<64); events[count++]=(struct event){kind,a,b};
}
static bool of_device_is_compatible(struct device_node *node,const char *name) {
    assert(!strcmp(name,"mediatek,mt6771-ufshci")); return node->legacy;
}
static void arm_smccc_smc(unsigned long fn,unsigned long command,unsigned long value,
    unsigned long a3,unsigned long a4,unsigned long a5,unsigned long a6,unsigned long a7,
    struct arm_smccc_res *res) {
    assert(fn==0xc2000276UL && !a3 && !a4 && !a5 && !a6 && !a7);
    smcs++; add(1,command,value); *res=(struct arm_smccc_res){sequenced && smcs==2 ? second_reply : reply,11,22,33};
}
static struct ufs_mtk_host *ufshcd_get_variant(struct ufs_hba *hba) { return hba->variant; }
static void ufshcd_delay_us(unsigned us,unsigned delta) { delays++; add(2,us,delta); }
static void usleep_range(unsigned a,unsigned b) { delays++; add(3,a,b); }
static void ufshcd_writel(struct ufs_hba *hba,u32 value,unsigned offset) {
    (void)hba; assert(offset==0x144); mmios++;reg_value=value; add(4,value,offset);
}
static u32 ufshcd_readl(struct ufs_hba *hba,unsigned offset) {
    (void)hba; assert(offset==0x144); mmios++;
    u32 ack=(reg_value&1)<<1; if(!ack_ok) ack^=2; add(5,reg_value|ack,offset);return reg_value|ack;
}
static ktime_t ktime_get(void) { clock_tick+=1000;return clock_tick; }
static ktime_t ktime_add_us(ktime_t a,unsigned b) { return a+b; }
static bool ktime_before(ktime_t a,ktime_t b) { return a<b; }
static void ufshcd_hba_stop(struct ufs_hba *hba) { (void)hba;add(7,0,0); }
static void dev_info(struct device *dev,const char *format,...) { (void)dev;(void)format;add(8,0,0); }
static void dev_err(struct device *dev,const char *format,...) { (void)dev;(void)format;add(6,0,0); }
/* Legacy CCF callback is fault-injected here; its actual body has a separate test. */
static int ufs_mt6771_setup_ref_clk(struct ufs_hba *hba,bool on) { (void)hba;(void)on;return -EOPNOTSUPP; }
'''
    code += function(text, 'ufs_mtk_uses_mt6771_fw') + '\n'
    code += function(text, 'ufs_mtk_smc') + '\n'
    code += function(text, 'ufs_mtk_smc_checked') + '\n'
    code += '#define ufs_mtk_device_reset_ctrl(hba,on,res) ufs_mtk_smc_checked(hba,2,on,&(res))\n'
    code += function(text, 'ufs_mtk_device_reset') + '\n'
    code += '#define ufs_mtk_ref_clk_notify(hba,on,res) ufs_mtk_smc(hba,8,on,&(res))\n'
    code += function(text, 'ufs_mtk_setup_ref_clk') + '\n'
    original = function((BASE / 'ufs-mediatek.c').read_text(), 'ufs_mtk_setup_ref_clk')
    original = original.replace('ufs_mtk_setup_ref_clk(', 'original_setup_ref_clk(').replace('ufs_mtk_ref_clk_notify(', 'original_notify(')
    code += '#define original_notify(on,res) arm_smccc_smc(MTK_SIP_UFS_CONTROL,8,on,0,0,0,0,0,&(res))\n'
    code += original + '\n'
    code += r'''
static void reset_trace(void) {
    memset(events,0,sizeof(events));count=smcs=mmios=delays=0;clock_tick=0;reg_value=0;
}
int main(void) {
    struct device_node node={0};struct device dev={&node};
    struct ufs_mtk_host host={.ref_clk_gating_wait_us=32,.ref_clk_ungating_wait_us=15};
    struct ufs_hba hba={&dev,&host};
    unsigned vectors=0, callbacks=0, statuses=0, resets=0;
    for(unsigned soc=0;soc<2;soc++) for(unsigned failure=0;failure<3;failure++) {
        reset_trace();node.legacy=soc;sequenced=true;
        reply=failure==1?(unsigned long)-2:0;second_reply=failure==2?(unsigned long)-2:0;
        bool failed=soc && failure;assert(ufs_mtk_device_reset(&hba)==(failed?-EINVAL:0));
        assert(smcs==(soc && failure==1?1:2));
        assert(delays==(failed?(failure==1?0:1):2));
        assert(events[0].kind==7);resets++;
    }
    sequenced=false;
    const u32 values[]={0,1,2,255,UINT32_MAX};
    const unsigned long replies[]={0,(unsigned long)-1,(unsigned long)-2,7};
    for(unsigned soc=0;soc<2;soc++) for(unsigned command=0;command<259;command++)
    for(unsigned v=0;v<5;v++) for(unsigned response=0;response<4;response++) {
        u32 cmd=command<256?command:command==256?0x10000:command==257?0x80000000:UINT32_MAX;
        u32 value=values[v];node.legacy=soc;reply=replies[response];reset_trace();
        struct arm_smccc_res result={99,99,99,99};
        int expected=value>1 ? -EINVAL :
            (cmd==1 || cmd==2) ? 0 : (cmd==4 || cmd==8) ? (soc ? -EOPNOTSUPP : 0) : -EINVAL;
        int ret=ufs_mtk_smc(&hba,cmd,value,&result);assert(ret==expected);
        if(expected) assert(smcs==0 && result.a0==(unsigned long)expected && !result.a1 && !result.a2 && !result.a3);
        else assert(smcs==1 && result.a0==reply && result.a1==11 && result.a2==22 && result.a3==33 &&
                    events[0].a==cmd && events[0].b==value);
        vectors++;
    }
    const uint64_t statuses_raw[]={0,0xffffffffULL,UINT64_MAX,0xfffffffeULL,UINT64_MAX-1,
        0xfffffffdULL,UINT64_MAX-2,0xfffffffcULL,UINT64_MAX-3,1,7,0x100000000ULL,
        0x1fffffffeULL,0xffffffff00000000ULL};
    const int statuses_expected[]={0,-EOPNOTSUPP,-EOPNOTSUPP,-EINVAL,-EINVAL,-ERANGE,
        -ERANGE,-EACCES,-EACCES,-EIO,-EIO,-EIO,-EIO,-EIO};
    for(unsigned i=0;i<sizeof(statuses_raw)/sizeof(statuses_raw[0]);i++) {
        assert(ufs_mt6771_fw_result(statuses_raw[i])==statuses_expected[i]);
        for(unsigned soc=0;soc<2;soc++) for(unsigned cmd=1;cmd<=2;cmd++) for(unsigned value=0;value<2;value++) {
            node.legacy=soc;reply=statuses_raw[i];reset_trace();struct arm_smccc_res result={0};
            assert(ufs_mtk_smc_checked(&hba,cmd,value,&result)==(soc?statuses_expected[i]:0));
            assert(smcs==1 && result.a0==reply);statuses++;
        }
    }
    for(unsigned on=0;on<2;on++) for(unsigned initial=0;initial<2;initial++) {
        node.legacy=true;host.ref_clk_enabled=initial;reset_trace();
        assert(ufs_mtk_setup_ref_clk(&hba,on)==-EOPNOTSUPP);
        assert(!smcs && !mmios && !delays && host.ref_clk_enabled==initial);callbacks++;
    }
    for(unsigned on=0;on<2;on++) for(unsigned initial=0;initial<2;initial++) for(unsigned ack=0;ack<2;ack++) {
        node.legacy=false;ack_ok=ack;reply=0;host.ref_clk_enabled=initial;reset_trace();
        int old=original_setup_ref_clk(&hba,on);bool old_state=host.ref_clk_enabled;
        struct event reference[64];memcpy(reference,events,sizeof(reference));unsigned old_count=count;
        host.ref_clk_enabled=initial;reset_trace();int now=ufs_mtk_setup_ref_clk(&hba,on);
        assert(old==now && old_state==host.ref_clk_enabled && old_count==count && !memcmp(reference,events,sizeof(reference)));
        callbacks++;
    }
    printf("%u firmware vectors, %u checked statuses, %u reset sequences and %u real callback cases passed; MT8183 traces unchanged; legacy callback failure propagates before newer MMIO\n",vectors,statuses,resets,callbacks);
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/ufs-firmware-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-I'+str(WORK),
                    str(out/'check.c'), '-o', str(out/'check')], check=True)
    checked = subprocess.run([str(out/'check')], capture_output=True, text=True)
    if checked.returncode or 'runtime error:' in checked.stderr or 'AddressSanitizer' in checked.stderr:
        raise RuntimeError(checked.stderr)
    inputs = [source, header, WORK/'ufs-mediatek.h', BASE/'ufs-mediatek.c', old_header, old_platform]
    result = {'result': checked.stdout.strip(), 'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
              'mt6771_engineering_host_match_enabled': True,
              'limits': ['All SMC, clocks, delays and MMIO are host mocks; no device firmware called',
                         'Installed ATF static evidence supports legacy SiP status translation; newer SoC replies remain unchanged',
                         'No MT6771 hardware probe, reference-clock or encryption implementation qualified']}
    (ROOT/'evidence/kernel-upgrade/ufs-firmware-protocol-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(checked.stdout,end='')


if __name__ == '__main__':
    main()
