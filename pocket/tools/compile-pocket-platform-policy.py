#!/usr/bin/env python3
"""Compile a bounded platform-only policy fixture using the recorded audit flags."""
import pocket_paths
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=pocket_paths.platform_source() / 'system/sepolicy'
def main():
 variables=pocket_paths.build_root() / 'out/soong/soong.titan_pocket_policy_audit.variables'
 config=json.loads(variables.read_text());out=ROOT/'artifacts/m2/policy';out.mkdir(parents=True,exist_ok=True)
 (out/'modern-platform-build-variables.json').write_text(json.dumps(config,indent=2)+'\n')
 order=['flagging_macros','security_classes','initial_sids','access_vectors','global_macros','neverallow_macros','mls_macros','mls_decl','mls','policy_capabilities','te_macros','ioctl_defines','ioctl_macros','nlmsg_defines','nlmsg_macros','attributes','*.te','roles_decl','roles','users','initial_sid_contexts','fs_use','genfs_contexts','port_contexts']
 files=[]
 for pattern in order:
  for directory in ['flagging','public','private']:
   files.extend(sorted((SOURCE/directory).glob(pattern)))
 assert len(files)==len(set(files))
 board=config.get('VendorApiLevel') or config['BuildFlags'].get('RELEASE_BOARD_API_LEVEL') or '202504'
 flags={'mls_num_sens':'1','mls_num_cats':'1024','target_arch':'arm64','target_with_asan':'false','target_with_dexpreopt':'true','target_with_native_coverage':'false','target_build_variant':'userdebug','target_full_treble':'true','target_compatible_property':'true','target_treble_sysprop_neverallow':'true','target_enforce_sysprop_owner':'true','target_exclude_build_test':'false','target_requires_insecure_execmem_for_swiftshader':'false','target_enforce_debugfs_restriction':'true','target_recovery':'false','target_board_api_level':str(board)}
 flags.update({'target_flag_'+key:str(value) for key,value in config['BuildFlags'].items()})
 conf=out/'modern-platform.conf';m4=pocket_paths.platform_source() / 'prebuilts/build-tools/linux-x86/bin/m4'
 cmd=[str(m4),'--fatal-warnings']+['-D'+key+'='+value for key,value in flags.items()]+['-s']+list(map(str,files))
 log=ROOT/'evidence/kernel-upgrade/modern-platform-policy-compile.log'
 with conf.open('w') as f:p=subprocess.run(cmd,stdout=f,stderr=subprocess.PIPE,text=True)
 log.write_text(p.stderr)
 if p.returncode:raise RuntimeError('Policy m4 failed: '+p.stderr[-1500:])
 compiler=ROOT/'tools/selinux-host-source/checkpolicy/checkpolicy';cil=out/'modern-platform.cil'
 p=subprocess.run([str(compiler),'-C','-M','-c','30','-o',str(cil),str(conf)],capture_output=True,text=True);log.write_text(log.read_text()+p.stdout+p.stderr)
 record={'returncode':p.returncode,'flags':{k:v for k,v in flags.items() if not k.startswith('target_flag_')},'build_flags':config['BuildFlags'],'build_flag_count':len(config['BuildFlags']),'config_sha256':hashlib.sha256(variables.read_bytes()).hexdigest(),'source_hashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'neverallow_disabled':False,'device_accessed':False,'limits':['Manual platform-only fixture using recorded release flags; not a full product Soong output','No Lineage device-specific policy, vendor compatibility or runtime enforcement qualified']}
 if not p.returncode:
  debt=SOURCE/'private/technical_debt.cil'
  if debt.exists():cil.write_text(cil.read_text()+'\n'+debt.read_text());record['technical_debt_sha256']=hashlib.sha256(debt.read_bytes()).hexdigest()
  record['cil']={'path':str(cil.relative_to(ROOT)),'sha256':hashlib.sha256(cil.read_bytes()).hexdigest()}
 (ROOT/'evidence/kernel-upgrade/modern-platform-policy-compile.json').write_text(json.dumps(record,indent=2)+'\n');print('Modern platform policy compile exit',p.returncode);print((p.stdout+p.stderr)[-1400:])
 raise SystemExit(p.returncode)
if __name__=='__main__':main()
