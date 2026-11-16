#!/usr/bin/env python3
"""Check actual TrustKernel headers, proc version writes and PM notifier code."""
import pocket_paths
import hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
TREE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/misc/mediatek/tkcore'
BSP=ROOT/'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5dd7fac4fdba5d5fd451ad6649c51250c/drivers/misc/mediatek/tkcore'
CLANG=str(pocket_paths.ndk_bin() / 'clang')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 headers=['include/linux/tee_ioc.h','include/linux/tee_client_api.h','include/arm_common/teesmc.h','include/arm_common/teesmc_st.h']
 for name in headers:assert (TREE/name).read_bytes()==(BSP/name).read_bytes(),name
 abi=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/tee_ioc.h>
_Static_assert(TEE_QUERY_DRV_FEATURE_IOC == 0x800474b7UL, "feature ioctl");
_Static_assert(TEE_OPEN_SESSION_IOC == 0xc03074a1UL, "session ioctl");
_Static_assert(TEE_INVOKE_COMMAND_IOC == 0xc03074a3UL, "invoke ioctl");
_Static_assert(TEE_ALLOC_SHM_IOC == 0xc01874a5UL, "shm ioctl");
_Static_assert(TEE_ALLOC_SHM_PERM_IOC == 0xc01874a6UL, "permanent shm ioctl");
_Static_assert(sizeof(struct tee_cmd_io) == 48, "command envelope");
_Static_assert(sizeof(struct tee_shm_io) == 24, "shm envelope");
_Static_assert(offsetof(struct tee_cmd_io, fd_sess) == 12, "sessionfd");
_Static_assert(offsetof(struct tee_cmd_io, uuid) == 16, "uuid");
_Static_assert(offsetof(struct tee_cmd_io, data) == 24, "data");
_Static_assert(offsetof(struct tee_cmd_io, op) == 32, "operation pointer");
_Static_assert(offsetof(struct TEEC_Context, fd) == 0x100, "context fd");
_Static_assert(offsetof(struct TEEC_Operation, session) == 0x68, "operation session");
_Static_assert(sizeof(struct TEEC_Operation) == 280, "operation object");
int main(void) { puts("5 ioctl constants and 9 LP64 object layouts passed"); }
'''
 proc=(TREE/'core/tee_procfs.c').read_text();a=proc.index('static ssize_t teed_version_write(');b=proc.index('\nstatic const struct proc_ops teed_version_ops',a);function=proc[a:b]
 pm=(TREE/'core/pm.c').read_text();a=pm.index('static int tee_pm_suspend_notifier(');b=pm.index('static int tee_pm_wake_notifier(',a);notifier=pm[a:b]
 controls=r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define __user
#define TEED_VERSION_SIZE 50
struct file { int unused; };
struct { char text[51]; unsigned char guard; } stored;
#define teed_version stored.text
static size_t residue;
static size_t copy_from_user(void *to, const void *from, size_t count)
{ assert(residue <= count); memcpy(to, from, count-residue); return residue; }
struct notifier_block { int unused; };
#define PM_SUSPEND_PREPARE 3
#define NOTIFY_DONE 0
#define NOTIFY_OK 1
#define NOTIFY_BAD 0x8002
static int prepared, prepare_result;
static int tee_prepare_suspend(void) { prepared++; return prepare_result; }
'''+function+notifier+r'''
int main(void) {
    char input[51], before[51]; memset(input, 'a', sizeof(input));
    unsigned cases=0;
    for (size_t count=0; count<=50; count++) {
        for (residue=0; residue<=count; residue++) {
            memset(stored.text, 'z', sizeof(stored.text)); memcpy(before, stored.text, sizeof(before)); stored.guard=0xab;
            ssize_t r=teed_version_write(NULL,input,count,NULL);
            assert(stored.guard==0xab);
            if (residue) { assert(r==-EFAULT); assert(!memcmp(stored.text,before,sizeof(before))); }
            else { assert(r==(ssize_t)count); assert(stored.text[count]==0); assert(!memcmp(stored.text,input,count)); }
            cases++;
        }
    }
    residue=0;
    assert(teed_version_write(NULL,input,51,NULL)==-ENOMEM);cases++;
    for (unsigned event=0;event<256;event++) for (int error=0;error<2;error++) {
        prepared=0; prepare_result=error ? -EBUSY : 0;
        int r=tee_pm_suspend_notifier(NULL,event,NULL);
        assert(prepared==(event==PM_SUSPEND_PREPARE));
        assert(r==(event==PM_SUSPEND_PREPARE ? (error ? NOTIFY_BAD : NOTIFY_OK) : NOTIFY_DONE));cases++;
    }
    printf("%u actual-function proc-write/error/boundary and PM event cases passed\n",cases);
}
'''
 results=[]
 with tempfile.TemporaryDirectory(prefix='pocket-tkcore-contract-') as tmp:
  for name,code in [('abi',abi),('controls',controls)]:
   source=Path(tmp)/(name+'.c');binary=Path(tmp)/name;source.write_text(code)
   command=[CLANG,'-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined','-I'+str(TREE/'include'),'-I'+str(TREE/'include/linux'),str(source),'-o',str(binary)]
   subprocess.run(command,check=True);run=subprocess.run([str(binary)],capture_output=True,text=True,check=True);assert not run.stderr;results.append(run.stdout.strip())
   if name=='abi':
    for target in ['aarch64-linux-android30','armv7a-linux-androideabi30']:
     subprocess.run([CLANG,'--target='+target,'--sysroot='+str(Path(CLANG).parent.parent/'sysroot'),'-fsyntax-only','-I'+str(TREE/'include'),str(source)],check=True)
     results.append(target+': actual header constants/layout assertions passed (compile only)')
 record={'source_sha256':{name:digest(TREE/name) for name in headers+['core/tee_procfs.c','core/pm.c']},'unchanged_ABI_headers':headers,'results':results,'sanitizers':['address','undefined'],'device_accessed':False,'limits':['Host LP64 and ARM32/ARM64 header compile ABI, copied actual functions with mocked user-copy/PM APIs; no compat32 translation execution, DMA, SMC, locking or device execution qualification']}
 (ROOT/'evidence/kernel-upgrade/tkcore-contract-check.json').write_text(json.dumps(record,indent=2)+'\n');print('\n'.join(results))
if __name__=='__main__':main()
