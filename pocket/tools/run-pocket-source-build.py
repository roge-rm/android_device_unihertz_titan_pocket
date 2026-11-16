#!/usr/bin/env python3
"""Run allowlisted source audits with the Boston baseline mounted read-only."""
import pocket_paths
import argparse,hashlib,json,os,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SHARED=pocket_paths.platform_source()
BULK=pocket_paths.build_root()
KERNEL=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
ALLOW={'plat_30.0.cil','30.0.compat.cil','plat_pub_policy.cil','plat_sepolicy.cil','secilc','checkpolicy','PocketInputCore','PocketInputEditorAdapter','PocketInputSettings','nothing','LatinIME'}
def check_fmradio(fmradio,shared=None):
 """Stop unless the FMRadio override holds exactly the files recorded in fmradio-patch.json and the shared source still has the originals."""
 shared=shared or SHARED
 record=json.loads((ROOT/'evidence/connectivity/fmradio-patch.json').read_text())['files']
 digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 have={str(p.relative_to(fmradio)) for p in fmradio.rglob('*') if p.is_file()} if fmradio.is_dir() else set()
 if have!=set(record) or any(digest(fmradio/n)!=h['modified'] or digest(shared/'packages/apps/FMRadio'/n)!=h['original'] for n,h in record.items()):
  raise SystemExit('FMRadio override is missing or stale; run tools/stage-pocket-fmradio.py')
def check_override(override,target,record_name,tool,shared=None):
 """Stop unless an override holds exactly the files in its evidence record and the shared source still has the originals."""
 shared=shared or SHARED
 record=json.loads((ROOT/'evidence/connectivity'/record_name).read_text())['files']
 digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 have={str(p.relative_to(override)) for p in override.rglob('*') if p.is_file()} if override.is_dir() else set()
 if have!=set(record) or any(digest(override/n)!=h['modified'] or digest(shared/target/n)!=h['original'] for n,h in record.items()):
  raise SystemExit(f'{override.name} override is missing or stale; run {tool}')

def command(targets,probe=False):
 for p in [BULK/'source',BULK/'out',BULK/'tmp',BULK/'home',BULK/'logs']:p.mkdir(parents=True,exist_ok=True)
 view=BULK/'source'
 args=['bwrap','--ro-bind','/','/','--bind',str(BULK),str(BULK),'--tmpfs',str(view),'--unshare-user','--unshare-pid','--unshare-net','--proc','/proc','--dev','/dev','--bind',str(BULK/'tmp'),'/tmp']
 for item in sorted(SHARED.iterdir()):
  if item.name not in {'out','device','kernel','packages'}:args.extend(['--ro-bind',str(item.resolve()),str(view/item.name)])
 args.extend(['--bind',str(BULK/'out'),str(view/'out')])
 def overlay(relative,children):
  dest=view/relative;args.extend(['--tmpfs',str(dest)])
  original=SHARED/relative
  if original.exists():
   for child in sorted(original.iterdir()):
    if child.name in children:continue
    args.extend(['--ro-bind',str(child.resolve()),str(dest/child.name)])
  for name,source in children.items():
   if source is None:args.extend(['--dir',str(dest/name)])
   else:args.extend(['--ro-bind',str(source),str(dest/name)])
 overlay('device',{'unihertz':None})
 args.extend(['--ro-bind',str(pocket_paths.DEVICE_TREE),str(view/'device/unihertz/titan_pocket')])
 overlay('kernel',{'unihertz':None})
 args.extend(['--ro-bind',str(KERNEL),str(view/'kernel/unihertz/mt6771')])
 overlay('packages',{'apps':None})
 # app directory is already covered by the parent tmpfs; bind existing children.
 for child in sorted((SHARED/'packages/apps').iterdir()):
  if child.name!='PocketInput':args.extend(['--ro-bind',str(child.resolve()),str(view/'packages/apps'/child.name)])
 if not pocket_paths.EXPORTED_LAYOUT:args.extend(['--ro-bind',str(pocket_paths.INPUT_PACKAGE),str(view/'packages/apps/PocketInput')])  # the exported device tree already holds PocketInput
 override=ROOT/'artifacts/build-overrides/hardware-lineage-compat.Android.bp'
 if override.exists():args.extend(['--ro-bind',str(override),str(view/'hardware/lineage/compat/Android.bp')])
 ime=ROOT/'artifacts/build-overrides/LatinIME'
 if ime.exists():
  for item in sorted(ime.rglob('*')):
   if item.is_file():args.extend(['--ro-bind',str(item),str(view/'packages/inputmethods/LatinIME'/item.relative_to(ime))])
 # FMRadio jni with the MT6631 fm_tune_parm, from tools/stage-pocket-fmradio.py.
 fmradio=ROOT/'artifacts/build-overrides/FMRadio'
 check_fmradio(fmradio)
 for item in sorted(fmradio.rglob('*')):
  if item.is_file():args.extend(['--ro-bind',str(item),str(view/'packages/apps/FMRadio'/item.relative_to(fmradio))])
 # gd controller skips READ_DEFAULT_ERRONEOUS_DATA_REPORTING on request, from tools/stage-pocket-bluetooth.py.
 bluetooth=ROOT/'artifacts/build-overrides/Bluetooth'
 check_override(bluetooth,'packages/modules/Bluetooth','bluetooth-patch.json','tools/stage-pocket-bluetooth.py')
 for item in sorted(bluetooth.rglob('*')):
  if item.is_file():args.extend(['--ro-bind',str(item),str(view/'packages/modules/Bluetooth'/item.relative_to(bluetooth))])
 # Charging control fetches the health HAL again after it restarts, from tools/stage-pocket-lineage-health.py.
 health=ROOT/'artifacts/build-overrides/lineage-sdk'
 check_override(health,'lineage-sdk','lineage-health-patch.json','tools/stage-pocket-lineage-health.py')
 for item in sorted(health.rglob('*')):
  if item.is_file():args.extend(['--ro-bind',str(item),str(view/'lineage-sdk'/item.relative_to(health))])
 # Audio policy swaps the vendor Bluetooth module for sysbta, from tools/stage-pocket-audiopolicy.py.
 audiopolicy=ROOT/'artifacts/build-overrides/frameworks-av'
 check_override(audiopolicy,'frameworks/av','audiopolicy-patch.json','tools/stage-pocket-audiopolicy.py')
 for item in sorted(audiopolicy.rglob('*')):
  if item.is_file():args.extend(['--ro-bind',str(item),str(view/'frameworks/av'/item.relative_to(audiopolicy))])
 # hal_audio's vndbinder and /proc rules leave out coredomain, for the same sysbta HAL.
 halaudio=ROOT/'artifacts/build-overrides/system-sepolicy'
 check_override(halaudio,'system/sepolicy','audiopolicy-sepolicy-patch.json','tools/stage-pocket-audiopolicy.py')
 for item in sorted(halaudio.rglob('*')):
  if item.is_file():args.extend(['--ro-bind',str(item),str(view/'system/sepolicy'/item.relative_to(halaudio))])
 # Pocket key hook in frameworks/base, from tools/stage-pocket-framework.py. The policy
 # directory gets a tmpfs so the new PocketKeyHooks.java has somewhere to go.
 framework=ROOT/'artifacts/build-overrides/frameworks-base'
 if framework.exists():
  policy='services/core/java/com/android/server/policy'
  overlay('frameworks/base/'+policy,{p.name:p for p in sorted((framework/policy).iterdir()) if p.is_file()})
  for item in sorted(framework.rglob('*')):
   if item.is_file() and item.parent!=framework/policy:args.extend(['--ro-bind',str(item),str(view/'frameworks/base'/item.relative_to(framework))])
 for name,value in {'PATH':os.environ.get('POCKET_HOST_TOOLS',str(ROOT/'tools/build-deps/usr/bin'))+':'+os.environ.get('PATH',''),'OUT_DIR':'out','TMPDIR':str(BULK/'tmp'),'HOME':str(BULK/'home'),'TARGET_PRODUCT':'titan_pocket_policy_audit','TARGET_BUILD_VARIANT':'userdebug','TARGET_RELEASE':'bp4a','PYTHONDONTWRITEBYTECODE':'1','BUILD_USERNAME':'pocket-builder','BUILD_HOSTNAME':'pocket-source-audit','USE_RBE':'false','ALLOW_MISSING_DEPENDENCIES':'false'}.items():args.extend(['--setenv',name,value])
 args.extend(['--chdir',str(view)])
 if probe:
  args+=['python3','-B','-c',"import errno,os; p='build/.pocket-read-only-probe';\ntry: f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\nexcept OSError as e: assert e.errno==errno.EROFS,e; print('Shared source mount is read-only')\nelse: os.close(f); os.unlink(p); raise RuntimeError('Source mount unexpectedly writable')"]
 else:args+=['build/soong/soong_ui.bash','--make-mode','-j12']+targets
 return args

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('targets',nargs='*');parser.add_argument('--probe',action='store_true');a=parser.parse_args()
 if not a.probe and (not a.targets or set(a.targets)-ALLOW):parser.error('Only source/policy/input audit targets are allowed; images, OTA and flashing are gated')
 script_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 args=command(a.targets,a.probe);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ');log=BULK/'logs'/(stamp+'.log')
 print('Isolated source build log: '+str(log),flush=True)
 with log.open('w') as f:result=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 record={'utc':stamp,'targets':a.targets,'probe':a.probe,'returncode':result.returncode,'log':str(log),'source_read_only':True,'network_isolated':True,'shared_source':str(SHARED),'output':str(BULK/'out'),'device_accessed':False,'script_sha256':script_hash}
 log.with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n')
 print('Exit '+str(result.returncode),flush=True);raise SystemExit(result.returncode)
if __name__=='__main__':main()
