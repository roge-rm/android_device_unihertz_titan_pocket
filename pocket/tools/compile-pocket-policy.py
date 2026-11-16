#!/usr/bin/env python3
"""Compile preserved split policy, optionally testing modern platform replacement."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
STOCK=ROOT/'firmware/installed-20230105/rootfs'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--modern-platform',type=Path);p.add_argument('--modern-mapping',type=Path);p.add_argument('--system-ext',type=Path);p.add_argument('--extra-mapping',type=Path,action='append',default=[]);p.add_argument('--label');a=p.parse_args()
 if bool(a.modern_platform)!=bool(a.modern_mapping):p.error('Modern platform and mapping must be supplied together')
 out=ROOT/'artifacts/m2/policy';out.mkdir(parents=True,exist_ok=True)
 files=[a.modern_platform or STOCK/'system/system/etc/selinux/plat_sepolicy.cil',a.modern_mapping or STOCK/'system/system/etc/selinux/mapping/30.0.cil',STOCK/'vendor/etc/selinux/plat_pub_versioned.cil',STOCK/'vendor/etc/selinux/vendor_sepolicy.cil',a.system_ext or STOCK/'system/system/system_ext/etc/selinux/system_ext_sepolicy.cil',STOCK/'system/system/system_ext/etc/selinux/mapping/30.0.cil']
 files=files[:2]+a.extra_mapping+files[2:]
 label=a.label or ('modern-combined' if a.modern_platform else 'stock-rebuilt')
 if not re.fullmatch(r'[a-z0-9-]+',label):p.error('Invalid output label')
 binary=out/(label+'.policy');compiler=ROOT/'tools/selinux-host-source/secilc/secilc';checker=ROOT/'tools/selinux-host-source/checkpolicy/checkpolicy'
 command=[str(compiler),'-m','-M','true','-G','-c','30','-o',str(binary),'-f',str(out/(label+'-file_contexts'))]+list(map(str,files))
 result=subprocess.run(command,capture_output=True,text=True);log=ROOT/'evidence/kernel-upgrade'/(label+'-policy-compile.log');log.write_text(result.stdout+result.stderr)
 record={'label':label,'returncode':result.returncode,'command':command,'input_hashes':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files},'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'neverallow_disabled':False,'device_accessed':False,'log':str(log.relative_to(ROOT)),'limits':['Compile/parse only, not kernel load or enforcement','Modern replacement experiment is not the final Lineage product policy','No policy relaxations or permissive-domain additions applied']}
 if not result.returncode:
  dump=out/(label+'-roundtrip.cil');checked=subprocess.run([str(checker),'-b','-C','-M','-o',str(dump),str(binary)],capture_output=True,text=True,check=True)
  text=dump.read_text();record.update(binary={'path':str(binary.relative_to(ROOT)),'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},capabilities=re.findall(r'\(policycap\s+(\w+)\)',text),permissive_domains=re.findall(r'\(typepermissive\s+(\w+)\)',text),binary_roundtrip_parsed=True)
 (ROOT/'evidence/kernel-upgrade'/(label+'-policy-compile.json')).write_text(json.dumps(record,indent=2)+'\n')
 print(label+' policy compile exit '+str(result.returncode));print((result.stdout+result.stderr)[-1200:])
 raise SystemExit(result.returncode)
if __name__=='__main__':main()
