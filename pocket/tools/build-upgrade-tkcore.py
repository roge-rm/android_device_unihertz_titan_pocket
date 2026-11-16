#!/usr/bin/env python3
"""Build the isolated stock TrustKernel forward port; no phone access."""
import pocket_paths
import argparse,datetime,hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10'
BULK=pocket_paths.build_root()
LLVM=pocket_paths.ndk_bin()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jobs',type=int,default=8);p.add_argument('--image',action='store_true',help='Also link an isolated engineering kernel Image with TrustKernel enabled');a=p.parse_args();assert a.jobs>0
 output=BULK/'kernel-tkcore-5.10';output.mkdir(parents=True,exist_ok=True)
 baseline=ROOT/'tools/kernel-build-config/upgrade-5.10/.config';baseline_sha=digest(baseline)
 if not (output/'.config').exists():shutil.copyfile(baseline,output/'.config')
 deps=ROOT/'tools/build-deps';env=os.environ.copy();env['PATH']=str(deps/'usr/bin')+':'+str(LLVM)+':'+env.get('PATH','');env['LD_LIBRARY_PATH']=str(deps/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','');env['BISON_PKGDATADIR']=str(deps/'usr/share/bison')
 base=['make','-C',str(SOURCE),'O='+str(output),'ARCH=arm64','LLVM=1','LLVM_IAS=1','CC='+str(LLVM/'clang'),'LD='+str(LLVM/'ld.lld'),'HOSTCC=gcc','HOSTCXX=g++','CROSS_COMPILE='+str(deps/'usr/bin/aarch64-linux-gnu-'),'-j'+str(a.jobs)]
 changes=['bash',str(SOURCE/'scripts/config'),'--file',str(output/'.config'),'--disable','TEE','--enable','TRUSTKERNEL_TEE_SUPPORT','--enable','TRUSTKERNEL_TEE_FP_SUPPORT','--disable','TRUSTKERNEL_TEE_RPMB_SUPPORT','--enable','COMPAT']
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ');log=ROOT/'evidence/kernel-upgrade'/(stamp+'-tkcore.log');print(str(log),flush=True)
 tracked=[p for p in (SOURCE/'drivers/misc/mediatek/tkcore').rglob('*') if p.is_file()]+[SOURCE/'drivers/misc/Kconfig',SOURCE/'drivers/misc/Makefile'];before={str(p.relative_to(SOURCE)):digest(p) for p in tracked}
 commands=[];rc=0
 with log.open('w') as f:
  for cmd in [changes,base+['olddefconfig'],base+['prepare','scripts'],base+['drivers/misc/mediatek/tkcore/']]+([base+['Image']] if a.image else []):
   p=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT);commands.append({'command':cmd,'returncode':p.returncode});rc=p.returncode
   if rc:break
 record={'utc':stamp,'source':str(SOURCE),'output':str(output),'returncode':rc,'commands':commands,'engineering_config_unchanged':digest(baseline)==baseline_sha,'config_sha256':digest(output/'.config'),'tool_sha256':digest(Path(__file__)),'source_sha256':before,'source_changed_during_build':any(digest(SOURCE/p)!=sha for p,sha in before.items()),'device_accessed':False,'image_built':bool(a.image and rc==0),'scope':'Isolated TrustKernel5.10 compile; ABI/runtime/SMC/securekeys remain qualification gates'}
 actual=(output/'.config').read_text().splitlines();required=['CONFIG_TRUSTKERNEL_TEE_SUPPORT=y','CONFIG_TRUSTKERNEL_TEE_FP_SUPPORT=y','CONFIG_COMPAT=y','CONFIG_DMA_SHARED_BUFFER=y','# CONFIG_TRUSTKERNEL_TEE_RPMB_SUPPORT is not set','# CONFIG_TEE is not set']
 record['required_config_entries']=required;record['required_config_entries_match']=all(line in actual for line in required)
 if rc==0:
  archives=[output/'drivers/misc/mediatek/tkcore/core/built-in.a',output/'drivers/misc/mediatek/tkcore/armtz/built-in.a'];linked=output/'tkcore-group.o'
  subprocess.run([str(LLVM/'ld.lld'),'-r','--whole-archive',*map(str,archives),'--no-whole-archive','-o',str(linked)],check=True)
  unresolved=subprocess.check_output([str(LLVM/'llvm-nm'),'-u',str(linked)],text=True);internal=[line.split()[-1] for line in unresolved.splitlines() if line.split()[-1].startswith(('tee_','tkcore_','TEEC_','trustedui_'))]
  record['relocatable_link']={'archives':{str(p):digest(p) for p in archives},'linked_sha256':digest(linked),'unresolved_generic_symbols':unresolved.splitlines(),'unresolved_custom_internal_symbols':internal}
  if internal:rc=1
  if a.image:
   files=[output/'vmlinux',output/'System.map',output/'arch/arm64/boot/Image'];record['artifacts']={str(p):{'sha256':digest(p),'bytes':p.stat().st_size} for p in files}
   symbols=['tee_internal_ioctl','tee_session_internal_ioctl','TEEC_InvokeCommand','tz_start','tee_clkmgr_handle','tee_spi_transfer'];text=(output/'System.map').read_text();record['required_symbols']=symbols;record['required_symbols_present']=all(any(line.endswith(' '+name) for line in text.splitlines()) for name in symbols)
   if not record['required_symbols_present']:rc=1
 if record['source_changed_during_build'] or not record['engineering_config_unchanged'] or not record['required_config_entries_match']:rc=1
 record['returncode']=rc;record['image_built']=bool(a.image and rc==0)
 log.with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n');print('Return code',rc);raise SystemExit(rc)
if __name__=='__main__':main()
