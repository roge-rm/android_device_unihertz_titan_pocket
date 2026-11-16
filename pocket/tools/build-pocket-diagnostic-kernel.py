#!/usr/bin/env python3
"""Build an independent allnoconfig-based RAM diagnostic; no device operations."""
import pocket_paths
import argparse,hashlib,json,os,runpy,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Diagnostic variant must be v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11 or v12')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
SOURCE=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--jobs',type=int,default=6);a=parser.parse_args();assert a.jobs>0
 output=BULK/('kernel-diagnostic-5.10'+SUFFIX);output.mkdir(parents=True,exist_ok=True)
 fragment=ROOT/('configs/kernel-diagnostic-5.10'+SUFFIX+'.fragment');deps=ROOT/'tools/build-deps';sdk=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')));llvm=sdk/'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
 env=os.environ.copy();env['PATH']=str(deps/'usr/bin')+':'+str(llvm)+':'+env.get('PATH','');env['LD_LIBRARY_PATH']=str(deps/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','');env['BISON_PKGDATADIR']=str(deps/'usr/share/bison');env.update(KBUILD_BUILD_USER='pocket-builder',KBUILD_BUILD_HOST='pocket-diagnostic',KBUILD_BUILD_TIMESTAMP='Thu Jan 1 00:00:00 UTC 1970',KBUILD_BUILD_VERSION='1',SOURCE_DATE_EPOCH='0')
 base=['make','-C',str(SOURCE),'O='+str(output),'ARCH=arm64','LLVM=1','LLVM_IAS=1','CC='+str(llvm/'clang'),'LD='+str(llvm/'ld.lld'),'HOSTCC=gcc','HOSTCXX=g++','CROSS_COMPILE='+str(deps/'usr/bin/aarch64-linux-gnu-'),'-j'+str(a.jobs)]
 commands=[base+['allnoconfig'],['bash',str(SOURCE/'scripts/kconfig/merge_config.sh'),'-m','-O',str(output),str(output/'.config'),str(fragment)],base+['olddefconfig']]
 groups=runpy.run_path(str(ROOT/'tools/export-kernel-upgrade-patches.py'),run_name='catalog')['GROUPS'];names=sorted({p for v in groups.values() for p in v});before={p:digest(SOURCE/p) for p in names}
 baseline=ROOT/'tools/kernel-build-config/upgrade-5.10/.config';baseline_hash=digest(baseline)
 log=BULK/'logs'/('diagnostic-kernel-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'.log');log.parent.mkdir(parents=True,exist_ok=True)
 print('Diagnostic kernel log: '+str(log),flush=True)
 with log.open('w') as f:
  for cmd in commands:subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  actual=(output/'.config').read_text().splitlines();requested=[s for s in fragment.read_text().splitlines() if s.startswith('CONFIG_') or s.startswith('# CONFIG_')]
  configured={s.split('=',1)[0]:s.split('=',1)[1] for s in actual if s.startswith('CONFIG_')}
  missing=[s for s in requested if (s.startswith('CONFIG_') and s not in actual) or (s.startswith('# CONFIG_') and configured.get(s.split()[1],'n')!='n')];assert not missing,'Unmet diagnostic configuration: '+str(missing)
  needed=['CONFIG_ARM_PSCI_FW=y','CONFIG_ARM_GIC_V3=y','CONFIG_ARM_ARCH_TIMER=y','CONFIG_OF=y','CONFIG_REGULATOR=y','CONFIG_GENERIC_PHY=y','CONFIG_MFD_SYSCON=y','CONFIG_REGMAP_MMIO=y']
  assert all(s in actual for s in needed),[s for s in needed if s not in actual]
  cmd=base+['Image','scripts_dtc'];commands.append(cmd);p=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
 assert digest(baseline)==baseline_hash,'Engineering configuration changed'
 assert {p:digest(SOURCE/p) for p in names}==before,'Kernel source changed during build'
 record={'utc':datetime.now(timezone.utc).isoformat(),'returncode':p.returncode,'source':str(SOURCE),'output':str(output),'log':str(log),'commands':commands,'source_hashes':before,'fragment_sha256':digest(fragment),'builder_sha256':digest(Path(__file__)),'compiler':subprocess.check_output([str(llvm/'clang'),'--version'],text=True),'build_identity':{k:env[k] for k in ['KBUILD_BUILD_USER','KBUILD_BUILD_HOST','KBUILD_BUILD_TIMESTAMP','KBUILD_BUILD_VERSION','SOURCE_DATE_EPOCH']},'config_sha256':digest(output/'.config'),'requested_config_entries':len(requested),'engineering_config_unchanged':True,'device_accessed':False,'limitations':['Minimal single-CPU RAM/USB diagnostic only; not Android, storage, suspend or device qualification','Bootloader load/DT rewriting and physical USB/PMIC behavior remain hardware gates']}
 if p.returncode==0:
  files=[output/'arch/arm64/boot/Image',output/'vmlinux',output/'System.map'];record['artifacts']={str(f):{'bytes':f.stat().st_size,'sha256':digest(f)} for f in files}
 (ROOT/('evidence/kernel-upgrade/diagnostic-kernel-build'+SUFFIX+'.json')).write_text(json.dumps(record,indent=2)+'\n');print('Diagnostic kernel build exit',p.returncode);raise SystemExit(p.returncode)
if __name__=='__main__':main()
