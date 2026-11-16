#!/usr/bin/env python3
"""Build pinned SELinux host tools in a small independent source copy."""
import pocket_paths
import hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BASE=pocket_paths.platform_source() / 'external/selinux'
DEST=ROOT/'tools/selinux-host-source'
def main():
 if not DEST.exists():
  DEST.mkdir()
  for name in ['libsepol','secilc','checkpolicy']:shutil.copytree(BASE/name,DEST/name,ignore=shutil.ignore_patterns('.git'))
  shutil.copyfile(BASE/'VERSION',DEST/'VERSION')
 env=os.environ.copy();env['PATH']=str(ROOT/'tools/build-deps/usr/bin')+':'+env['PATH'];env['LD_LIBRARY_PATH']=str(ROOT/'tools/build-deps/usr/lib/x86_64-linux-gnu')
 env['BISON_PKGDATADIR']=str(ROOT/'tools/build-deps/usr/share/bison')
 log=ROOT/'evidence/kernel-upgrade/policy-tools-build.log'
 commands=[['make','-C',str(DEST/'libsepol/src'),'-j8','libsepol.a','CFLAGS=-O2 -Wall -Wextra'],['make','-C',str(DEST/'secilc'),'-j8','secilc','CFLAGS=-O2 -Wall -Wextra','CPPFLAGS=-I'+str(DEST/'libsepol/include'),'LDFLAGS=-L'+str(DEST/'libsepol/src')],['make','-C',str(DEST/'checkpolicy'),'-j8','checkpolicy','CFLAGS=-O2 -Wall -Wextra','CPPFLAGS=-I'+str(DEST/'libsepol/include'),'LIBSEPOLA='+str(DEST/'libsepol/src/libsepol.a')]]
 print('Policy host-tool log: '+str(log),flush=True)
 with log.open('w') as f:
  for command in commands:subprocess.run(command,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 files=[DEST/'secilc/secilc',DEST/'checkpolicy/checkpolicy',DEST/'libsepol/src/libsepol.a']
 record={'source_revision':subprocess.check_output(['git','-C',str(BASE),'rev-parse','HEAD'],text=True).strip(),'commands':commands,'outputs':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},'shared_source_modified':False,'device_accessed':False}
 (ROOT/'evidence/kernel-upgrade/policy-tools-build.json').write_text(json.dumps(record,indent=2)+'\n');print('Pinned secilc/checkpolicy built independently',flush=True)
if __name__=='__main__':main()
