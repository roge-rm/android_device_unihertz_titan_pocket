#!/usr/bin/env python3
"""Configure and build the first-boot 5.10 kernel (allnoconfig plus the firstboot fragment); no device operations.

--stage config runs allnoconfig, merges the fragment, runs olddefconfig and the audit.
--stage image also builds Image and scripts_dtc and writes a deterministic Image.gz.
--variant enforcing adds configs/kernel-firstboot-5.10-enforcing.fragment (CONFIG_DEVTMPFS off, for the
enforcing boot image without the wrapper) and builds in kernel-firstboot-5.10-enforcing/.
--objects builds only the named objects (e.g. drivers/power/supply/oz8806.o) on that config, without the
config audit, and writes no build record. Run the image stage and --objects through `heavy build`.
"""
import pocket_paths
import argparse,gzip,hashlib,json,os,runpy,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
SOURCE=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
FRAGMENT=ROOT/'configs/kernel-firstboot-5.10.fragment'
ENFORCING_FRAGMENT=ROOT/'configs/kernel-firstboot-5.10-enforcing.fragment'
# Boot partition size (partition-size:boot=2000000) and the low staging check in package-pocket-diagnostic.py.
BOOT_PARTITION=0x2000000
LOW_STAGING_LIMIT=0x40200000-0x40008000-2048

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
 parser.add_argument('--stage',choices=['config','image'],default='config');parser.add_argument('--variant',choices=['wrapper','enforcing'],default='wrapper');parser.add_argument('--jobs',type=int,default=10);parser.add_argument('--objects',nargs='+',metavar='OBJ',help='build only these objects, no record');a=parser.parse_args();assert a.jobs>0
 enf=a.variant=='enforcing'
 OUTPUT=BULK/('kernel-firstboot-5.10-enforcing' if enf else 'kernel-firstboot-5.10')
 RECORD=ROOT/'evidence/kernel-upgrade'/('firstboot-kernel-build-enforcing.json' if enf else 'firstboot-kernel-build.json')
 AUDIT_REPORT=ROOT/'evidence/kernel-upgrade'/('firstboot-config-audit-enforcing.json' if enf else 'firstboot-config-audit.json')
 fragments=[FRAGMENT]+([ENFORCING_FRAGMENT] if enf else [])
 OUTPUT.mkdir(parents=True,exist_ok=True)
 deps=ROOT/'tools/build-deps';sdk=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')));llvm=sdk/'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
 env=os.environ.copy();env['PATH']=str(deps/'usr/bin')+':'+str(llvm)+':'+env.get('PATH','');env['LD_LIBRARY_PATH']=str(deps/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','');env['BISON_PKGDATADIR']=str(deps/'usr/share/bison');env.update(KBUILD_BUILD_USER='pocket-builder',KBUILD_BUILD_HOST='pocket-firstboot',KBUILD_BUILD_TIMESTAMP='Thu Jan 1 00:00:00 UTC 1970',KBUILD_BUILD_VERSION='1',SOURCE_DATE_EPOCH='0')
 base=['make','-C',str(SOURCE),'O='+str(OUTPUT),'ARCH=arm64','LLVM=1','LLVM_IAS=1','CC='+str(llvm/'clang'),'LD='+str(llvm/'ld.lld'),'HOSTCC=gcc','HOSTCXX=g++','CROSS_COMPILE='+str(deps/'usr/bin/aarch64-linux-gnu-'),'-j'+str(a.jobs)]
 commands=[base+['allnoconfig'],['bash',str(SOURCE/'scripts/kconfig/merge_config.sh'),'-m','-O',str(OUTPUT),str(OUTPUT/'.config')]+[str(f) for f in fragments],base+['olddefconfig']]
 groups=runpy.run_path(str(ROOT/'tools/export-kernel-upgrade-patches.py'),run_name='catalog')['GROUPS'];names=sorted({p for v in groups.values() for p in v});before={p:digest(SOURCE/p) for p in names}
 log=BULK/'logs'/('firstboot-kernel-'+a.stage+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'.log');log.parent.mkdir(parents=True,exist_ok=True)
 print('First-boot kernel log: '+str(log),flush=True)
 rc=0
 with log.open('w') as f:
  for cmd in commands:subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  if a.objects:
   rc=subprocess.run(base+a.objects,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
   assert {p:digest(SOURCE/p) for p in names}==before,'Kernel source changed during build'
   print('Objects',' '.join(a.objects),'exit',rc,'log',log);raise SystemExit(rc)
  audit=subprocess.run([sys.executable,'-B',str(ROOT/'tools/audit-pocket-firstboot-config.py'),'--config',str(OUTPUT/'.config'),'--variant',a.variant],env=env)
  if audit.returncode!=0:print('Audit found unexpected gaps; image not built');raise SystemExit(audit.returncode)
  writes=subprocess.run([sys.executable,'-B',str(ROOT/'tools/check-pocket-ufs-write-path.py')],env=env)
  if writes.returncode!=0:print('UFS write-path check failed; image not built');raise SystemExit(writes.returncode)
  if a.stage=='image':
   cmd=base+['Image','scripts_dtc'];commands.append(cmd);rc=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
 assert {p:digest(SOURCE/p) for p in names}==before,'Kernel source changed during build'
 record={'utc':datetime.now(timezone.utc).isoformat(),'stage':a.stage,'returncode':rc,'source':str(SOURCE),'output':str(OUTPUT),'log':str(log),'commands':commands,'source_hashes':before,'variant':a.variant,'fragment_sha256':digest(FRAGMENT),'fragment_sha256s':{str(f):digest(f) for f in fragments},'builder_sha256':digest(Path(__file__)),'config_sha256':digest(OUTPUT/'.config'),'audit':str(AUDIT_REPORT),'build_identity':{k:env[k] for k in ['KBUILD_BUILD_USER','KBUILD_BUILD_HOST','KBUILD_BUILD_TIMESTAMP','KBUILD_BUILD_VERSION','SOURCE_DATE_EPOCH']},'device_accessed':False,'boot_image_built':False,
  'cmdline_for_packager':'clk_ignore_unused regulator_ignore_unused (boot image header; CONFIG_CMDLINE stays empty; no maxcpus, so all 8 CPUs boot at smp_init)',
  'ufs_write_path':'Engineering binding with no block-write gate; checked by tools/check-pocket-ufs-write-path.py (evidence/kernel-upgrade/ufs-write-path-check.json)',
  'limitations':['Not boot-tested; UFS writes, mounts, keymaster, BPF loading and SELinux policy load are unverified on the phone']}
 if a.stage=='image' and rc==0:
  compiler=subprocess.check_output([str(llvm/'clang'),'--version'],text=True);record['compiler']=compiler
  raw=OUTPUT/'arch/arm64/boot/Image';gz=OUTPUT/'arch/arm64/boot/Image.gz';gz.write_bytes(gzip.compress(raw.read_bytes(),mtime=0))
  files=[raw,gz,OUTPUT/'vmlinux',OUTPUT/'System.map'];record['artifacts']={str(p):{'bytes':p.stat().st_size,'sha256':digest(p)} for p in files}
  size=gz.stat().st_size
  record['sizes']={'image_bytes':raw.stat().st_size,'image_gz_bytes':size,'boot_partition_bytes':BOOT_PARTITION,'image_gz_share_of_boot_partition':round(size/BOOT_PARTITION,4),'low_staging_limit_bytes':LOW_STAGING_LIMIT,'fits_low_staging_check':size<=LOW_STAGING_LIMIT}
  print(json.dumps(record['sizes'],indent=1))
 RECORD.write_text(json.dumps(record,indent=2)+'\n');print('First-boot kernel',a.stage,'exit',rc);raise SystemExit(rc)
if __name__=='__main__':main()
