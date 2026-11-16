#!/usr/bin/env python3
"""Read pstore first, then stock-return metadata. Never reboots or writes a device."""
import argparse,base64,hashlib,io,json,re,shlex,subprocess,tarfile
from datetime import datetime,timezone
from pathlib import Path

def digest(data):return hashlib.sha256(data).hexdigest()
def inspect_archive(data,release):
 if len(data)>16*1024*1024:raise ValueError('pstore archive exceeds diagnostic limit')
 files=[]
 pattern=re.compile(rb'(?:^|\n)(?:<\d+>)?(?:\[\s*[\d.]+\]\s*)?Linux version '+re.escape(release.encode())+rb'(?:\s|$)')
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
  members=archive.getmembers()
  if len(members)>512:raise ValueError('Too many pstore members')
  total=0
  for member in members:
   path=Path(member.name)
   if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):raise ValueError('Unsafe pstore archive member')
   if member.isdir():continue
   total+=member.size
   if total>16*1024*1024:raise ValueError('Expanded pstore exceeds diagnostic limit')
   stream=archive.extractfile(member);content=stream.read()
   files.append({'name':member.name,'bytes':len(content),'sha256':digest(content),'matching_kernel_banner':bool(pattern.search(content))})
 return files

# The return boot's preloader starts about 5 s after a fastboot reboot when LK
# didn't enter recovery; a recovery boot that ran adds LK (about 7 s) plus the
# kernel's run time before the next preloader.
RECOVERY_GAP_SECONDS=15
def recovery_entry(pl_lk,reboot_utc):
 found=re.search(rb'Current RTC time:\[(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)\]',pl_lk)
 if not found or reboot_utc is None:return {'verdict':'unknown','reason':'no preloader RTC time or reboot time'}
 rtc=datetime(*map(int,found.groups()),tzinfo=timezone.utc);gap=(rtc-reboot_utc).total_seconds()
 gauge=re.search(rb'fg_curr_time (\d+).*?shutdown_pmic_time (\d+)',pl_lk)
 mode=re.search(rb'lk boot mode = (\d+)',pl_lk)
 row={'preloader_rtc_utc':rtc.isoformat(),'seconds_after_reboot':gap,'gauge_gap_seconds':int(gauge[1])-int(gauge[2]) if gauge else None,'lk_boot_mode':mode[1].decode() if mode else None}
 row['verdict']='recovery_not_entered' if 0<=gap<RECOVERY_GAP_SECONDS else 'reboot_gap_allows_recovery'
 return row

def collect(adb,serial,output,release,boot_sha,recovery_sha,reboot_utc=None):
 output.mkdir(mode=0o700,parents=True,exist_ok=False);commands=[]
 def read(label,command):
  started=datetime.now(timezone.utc).isoformat()
  try:
   p=subprocess.run([adb,'-s',serial,'exec-out',shlex.join(['su','-c',command+' | base64'])],capture_output=True,timeout=120)
   wire=p.stdout;error=p.stderr;code=p.returncode
   if code==0:
    try:data=base64.b64decode(b''.join(wire.split()),validate=True)
    except ValueError:
     data=wire;code=None;error+=b'Invalid base64 transport; decoded evidence unavailable'
   else:data=wire
   (output/(label+'.wire')).write_bytes(wire)
  except subprocess.TimeoutExpired as exc:
   data=exc.stdout or b'';error=exc.stderr or b'';code=None
  (output/(label+'.bin')).write_bytes(data)
  row={'label':label,'command':command,'utc':started,'returncode':code,'stdout_bytes':len(data),'stdout_sha256':digest(data),'stderr':error.decode(errors='replace')};commands.append(row)
  (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  return data if code==0 else None
 # Preserve retained logs before any slower partition hash/readback work.
 archive=read('pstore','tar -C /sys/fs/pstore -cf - .')
 result={'recorded_utc':datetime.now(timezone.utc).isoformat(),'device_writes':False,'reboots_requested':False,'transport':'Phone-side base64 and strict host decoding; binary output is not trusted through raw su/ADB streams','pstore_files':[],'matching_banner_in_saved_pstore':False,'stock_return_verified':False,'boot_control_empty':False,'errors':[],'limits':['Read-only collection; never restores or clears boot control','Absent logs do not disprove execution; retained logs may be stale','Banner presence alone does not qualify the board or USB/reset behavior']}
 if archive is not None:
  try:result['pstore_files']=inspect_archive(archive,release);result['matching_banner_in_saved_pstore']=any(f['matching_kernel_banner'] for f in result['pstore_files'])
  except (ValueError,tarfile.TarError,EOFError) as exc:result['errors'].append('pstore: '+str(exc))
 else:result['errors'].append('pstore read failed')
 pl_lk=read('pl_lk','cat /proc/pl_lk')
 if pl_lk is None:result['errors'].append('pl_lk read failed')
 else:result['recovery_entry']=recovery_entry(pl_lk,reboot_utc)
 expdb=read('expdb','cat /dev/block/by-name/expdb')
 if expdb is None:result['errors'].append('expdb read failed')
 else:result['expdb']={'bytes':len(expdb),'sha256':digest(expdb)}
 for label,command in [('bootreason','getprop ro.boot.bootreason'),('kernel','uname -a'),('root','id'),('firmware','getprop ro.agui.real_version'),('boot_completed','getprop sys.boot_completed'),('hashes','sha256sum /dev/block/by-name/boot /dev/block/by-name/recovery'),('bcb','dd if=/dev/block/by-name/para bs=32 count=1 2>/dev/null | base64')]:
  data=read(label,command)
  if data is None:result['errors'].append(label+' read failed');continue
  result[label]=data.decode(errors='replace').strip()
 try:
  hashes={row.split()[1].rsplit('/',1)[-1]:row.split()[0] for row in result.get('hashes','').splitlines()}
  result['stock_return_verified']=hashes=={'boot':boot_sha,'recovery':recovery_sha} and 'uid=0(root)' in result.get('root','') and result.get('boot_completed')=='1' and result.get('firmware')=='Titan_pocket_20230105_1943'
  result['boot_control_empty']=base64.b64decode(result.get('bcb',''),validate=True)==b'\0'*32
 except (ValueError,IndexError) as exc:result['errors'].append('metadata: '+str(exc))
 result['collection_complete']=len(commands)==10 and all(c['returncode']==0 for c in commands) and not result['errors']
 (output/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--adb',default='adb');p.add_argument('--serial',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--kernel-release',required=True);p.add_argument('--boot-sha256',required=True);p.add_argument('--recovery-sha256',required=True);p.add_argument('--reboot-utc',type=datetime.fromisoformat,help='UTC time the candidate reboot was requested');a=p.parse_args()
 if not re.fullmatch(r'5\.10\.[A-Za-z0-9_.+\-]+',a.kernel_release):p.error('Expected exact 5.10 diagnostic release')
 if not all(re.fullmatch('[0-9a-f]{64}',s) for s in [a.boot_sha256,a.recovery_sha256]):p.error('Expected complete SHA-256 hashes')
 if a.reboot_utc and a.reboot_utc.tzinfo is None:p.error('--reboot-utc needs a timezone')
 result=collect(a.adb,a.serial,a.output,a.kernel_release,a.boot_sha256,a.recovery_sha256,a.reboot_utc)
 print(json.dumps({k:result[k] for k in ['collection_complete','recovery_entry','matching_banner_in_saved_pstore','stock_return_verified','boot_control_empty','errors']},indent=2))
 raise SystemExit(0 if result['collection_complete'] and result['stock_return_verified'] and result['boot_control_empty'] else 2)
if __name__=='__main__':main()
