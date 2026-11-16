#!/usr/bin/env python3
"""Build an isolated allnoconfig RAM diagnostic with the SHM ownership guard.

Produces kernel build artifacts only. Does not package, stage or access a phone.
"""
import pocket_paths
import datetime, hashlib, json, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
out=BULK/'kernel-tkcore-ram-probe-5.10';out.mkdir(parents=True,exist_ok=True)
llvm=pocket_paths.ndk_bin();deps=ROOT/'tools/build-deps'
env=os.environ.copy();env.update(PATH=str(deps/'usr/bin')+':'+str(llvm)+':'+env.get('PATH',''),LD_LIBRARY_PATH=str(deps/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH',''),BISON_PKGDATADIR=str(deps/'usr/share/bison'),KBUILD_BUILD_USER='pocket-builder',KBUILD_BUILD_HOST='pocket-tkcore-probe',KBUILD_BUILD_TIMESTAMP='Thu Jan 1 00:00:00 UTC 1970',KBUILD_BUILD_VERSION='1',SOURCE_DATE_EPOCH='0')
base=['make','-C',str(SOURCE),'O='+str(out),'ARCH=arm64','LLVM=1','LLVM_IAS=1','CC='+str(llvm/'clang'),'LD='+str(llvm/'ld.lld'),'HOSTCC=gcc','HOSTCXX=g++','CROSS_COMPILE='+str(deps/'usr/bin/aarch64-linux-gnu-'),'-j6']
fragments=[ROOT/'configs/kernel-diagnostic-5.10-v4.fragment',ROOT/'configs/kernel-tkcore-ram-probe.fragment']
commands=[base+['allnoconfig'],['bash',str(SOURCE/'scripts/kconfig/merge_config.sh'),'-m','-O',str(out),str(out/'.config'),*map(str,fragments)],base+['olddefconfig'],base+['Image']]
owned=[p for p in (SOURCE/'drivers/misc/mediatek/tkcore').rglob('*') if p.is_file()];before={str(p.relative_to(SOURCE)):digest(p) for p in owned};baseline=ROOT/'tools/kernel-build-config/upgrade-5.10/.config';baseline_sha=digest(baseline)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ');log=ROOT/'evidence/kernel-upgrade'/(stamp+'-tkcore-ram-probe.log');rc=0
print(log,flush=True)
with log.open('w') as f:
 for command in commands:
  result=subprocess.run(command,env=env,stdout=f,stderr=subprocess.STDOUT);rc=result.returncode
  if rc:break
actual=(out/'.config').read_text().splitlines();required=['CONFIG_TRUSTKERNEL_TEE_SUPPORT=y','CONFIG_TRUSTKERNEL_TEE_FP_SUPPORT=y','CONFIG_TRUSTKERNEL_TEE_RAM_DIAGNOSTIC=y','CONFIG_ARCH_KEEP_MEMBLOCK=y','# CONFIG_TRUSTKERNEL_TEE_RPMB_SUPPORT is not set','# CONFIG_TEE is not set','# CONFIG_BLOCK is not set','# CONFIG_MODULES is not set','# CONFIG_NET is not set']
record={'returncode':rc,'commands':commands,'log':str(log),'output':str(out),'required_config_entries':required,'config_matches':all(x in actual for x in required),'config_sha256':digest(out/'.config'),'source_sha256':before,'source_unchanged':all(digest(SOURCE/p)==v for p,v in before.items()),'engineering_config_unchanged':digest(baseline)==baseline_sha,'fragments':{str(p.relative_to(ROOT)):digest(p) for p in fragments},'phone_access':False,'packaged':False}
if not all(record[x] for x in ['config_matches','source_unchanged','engineering_config_unchanged']):record['returncode']=1
if rc==0:
 imports=subprocess.check_output([str(llvm/'llvm-nm'),'-u',str(out/'drivers/misc/mediatek/tkcore/core/tee_core.o')],text=True)
 record['proc_logger_registration_omitted']='tee_init_procfs' not in imports
 if not record['proc_logger_registration_omitted']:record['returncode']=1
 record['artifacts']={str(p):{'sha256':digest(p),'bytes':p.stat().st_size} for p in [out/'vmlinux',out/'arch/arm64/boot/Image']}
log.with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k!='source_sha256'},indent=2));raise SystemExit(record['returncode'])
