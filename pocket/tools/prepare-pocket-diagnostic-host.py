#!/usr/bin/env python3
"""Read-only stock-phone preflight and host staging; no reboot or partition write."""
import argparse,base64,hashlib,json,os,shlex,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Unknown diagnostic variant')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
BOOT_SHA='065e115909e1c92d26d85d1d24873f333aeb3a67c00ba65d565b56d176f8cd51'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--host',required=True);p.add_argument('--user',default='lab');p.add_argument('--identity',type=Path,required=True);p.add_argument('--serial',required=True);a=p.parse_args()
 ev=ROOT/('evidence/kernel-upgrade/diagnostic-package'+SUFFIX);package=json.loads((ev/'candidate-validation.json').read_text());avb=json.loads((ev/'host-avb-check.json').read_text());capture=json.loads((ROOT/'evidence/kernel-upgrade/diagnostic-capture-check.json').read_text())
 assert len(avb['cases'])==7 and avb['source_hashes_before_and_after_match'];assert capture['cases']==(84 if VARIANT=='v12' else 77 if VARIANT=='v11' else 70 if VARIANT=='v10' else 63 if VARIANT=='v9' else 56)
 assert digest(ROOT/'tools/check-recovery-avb.py')==avb['runner_sha256']
 ram=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-ramdisk'+SUFFIX+'.json')).read_text())
 for item in ram['source_inputs']:assert digest(ROOT/item['path'])==item['sha256']
 board=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-board'+SUFFIX+'.json')).read_text());assert digest(ROOT/'tools/prepare-pocket-diagnostic-tree.py')==board['generator_sha256']
 for name,expected in board.get('generator_inputs',{}).items():assert digest(ROOT/name)==expected
 candidate=package['candidate'];restore=package['restore_image']
 for info in [candidate,restore]:assert Path(info['path']).stat().st_size==info['bytes']==33554432 and digest(Path(info['path']))==info['sha256']
 assert any(case.get('image_sha256')==candidate['sha256'] and case.get('observed',{}).get('slot_data') for case in avb['cases'])
 for name,expected in capture['source_hashes'].items():assert digest(ROOT/name)==expected
 for name,expected in package['components'].items():assert digest(Path(name))==expected
 build=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-kernel-build'+SUFFIX+'.json')).read_text());assert build['returncode']==0
 for name,expected in build['source_hashes'].items():assert digest(Path(build['source'])/name)==expected
 assert digest(ROOT/'tools/package-pocket-diagnostic.py')==package['builder_sha256']
 if VARIANT!='v1':
  readiness=json.loads((ev/'readiness.json').read_text());assert readiness['offline_preparation_complete'] and readiness['candidate']==candidate
  for name,expected in readiness['evidence_sha256'].items():assert digest(Path(name))==expected,name
 options=['-i',str(a.identity),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=10'];target=a.user+'@'+a.host;records=[]
 def host(args):
  r=subprocess.run(['ssh',*options,target,shlex.join(args)],capture_output=True,text=True,timeout=45);records.append({'args':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});(ev/'host-preflight-commands.json').write_text(json.dumps(records,indent=2)+'\n');r.check_returncode();return r.stdout.strip()
 def phone(command):return host(['adb','-s',a.serial,'shell',shlex.join(['su','-c',command])])
 assert 'dialout' in host(['id']);assert host(['adb','-s',a.serial,'get-state'])=='device'
 assert phone('getprop ro.agui.real_version')=='Titan_pocket_20230105_1943';assert phone('getprop sys.boot_completed')=='1';assert 'uid=0(root)' in phone('id')
 actual={row.split()[1].rsplit('/',1)[-1]:row.split()[0] for row in phone('sha256sum /dev/block/by-name/boot /dev/block/by-name/recovery').splitlines()};assert actual=={'boot':BOOT_SHA,'recovery':restore['sha256']}
 assert phone('readlink -f /dev/block/by-name/recovery')=='/dev/block/sdc2';assert int(phone('cat /sys/class/block/sdc2/size'))*512==33554432
 bcb=base64.b64decode(phone('dd if=/dev/block/by-name/para bs=32 count=1 2>/dev/null | base64'));assert bcb==b'\0'*32,'Boot-control command not empty; stop'
 assert phone('sha256sum /vendor/etc/recovery.img').split()[0]==restore['sha256']
 battery=phone('dumpsys battery');level=next(int(row.split(':',1)[1]) for row in battery.splitlines() if row.strip().startswith('level:'));assert level>=50,'Charge the phone before an attended trial'
 remote='/var/lib/lab/titan-pocket/diagnostic-5.10-'+candidate['sha256'][:12];host(['mkdir','-p',remote+'/tools']);staged=[]
 for src,dest in [(Path(candidate['path']),remote+'/recovery.img'),(Path(restore['path']),remote+'/stock-recovery-restore.img'),(ROOT/'tools/capture-pocket-diagnostic.py',remote+'/tools/capture-pocket-diagnostic.py'),(ROOT/'tools/capture-recovery-probe.py',remote+'/tools/capture-recovery-probe.py'),(ROOT/'tools/collect-pocket-diagnostic-return.py',remote+'/tools/collect-pocket-diagnostic-return.py')]+([(ROOT/'tools/pocket-partition-hashes.py',remote+'/tools/pocket-partition-hashes.py')] if VARIANT in ('v8','v9','v10','v11','v12') else []):
  subprocess.run(['scp',*options,str(src),target+':'+dest],check=True,timeout=60);assert host(['sha256sum',dest]).split()[0]==digest(src);host(['chmod','600',dest]);staged.append({'path':dest,'sha256':digest(src),'bytes':src.stat().st_size})
 host(['python3',remote+'/tools/capture-pocket-diagnostic.py','--help'])
 release_header=(Path(build['output'])/'include/generated/utsrelease.h').read_text();release=release_header.split('"')[1]
 result={'utc':datetime.now(timezone.utc).isoformat(),'host':a.host,'serial':a.serial,'battery_percent':level,'expected_kernel_release':release,'usb_identity':package['usb_identity'],'variant':VARIANT,'stock_hashes':actual,'bcb_empty':True,'offline_checks_passed':True,'host_preflight_passed':True,'staged':staged,'owner_presence_confirmed':False,'phone_rebooted':False,'partitions_written':False,'hardware_qualified':False}
 (ev/'host-preflight.json').write_text(json.dumps(result,indent=2)+'\n');print('Stock/root/hash/BCB/battery gates passed; candidate, exact restore and passive capturer staged; phone unchanged')
if __name__=='__main__':main()
