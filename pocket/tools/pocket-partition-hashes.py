#!/usr/bin/env python3
"""Stock-side partition hashes for comparison with the v8 to v12 diagnostics' part-hash lines.

commands  print the phone-side commands (read-only: blockdev, sha256sum, head)
stock     run them on stock Android through adb and su, and save JSON
compare   check a kernel log or console against the saved stock JSON; for v12 also the six
          protected partitions hashed before and after teed, against the stock backup manifest
"""
import argparse,json,re,shlex,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
# Same names and order as hash_targets in kernel-upgrade/diagnostic-probe-v8/init.c.
PARTITIONS=['lk','dtbo','vbmeta','boot','recovery','super']
# The diagnostic logs a prefix hash at every 1 GiB of a larger partition.
CHECKPOINT=1<<30
NAME=re.compile(r'[a-z0-9_]+')
# v12 hashes these before and after the teed run (tp12_protected in diagnostic-probe-v12/probes.h).
PROTECTED=['protect1','protect2','persist','nvdata','nvcfg','proinfo']
MANIFEST=ROOT/'backups/stock-20261029T001105.670723Z/manifest.json'
# nvcfg changed during that backup on stock Android, so for it the in-log pair is the verdict.
BACKUP_MAY_DIFFER={'nvcfg'}

def node(name):
 assert NAME.fullmatch(name),name
 return '/dev/block/by-name/'+name

def size_command(name):return 'blockdev --getsize64 '+node(name)
def hash_command(name):return 'sha256sum '+node(name)
def prefix_command(name,count):
 assert isinstance(count,int) and count>0
 return 'head -c %d %s | sha256sum'%(count,node(name))

def prefixes(size,extra=()):
 return sorted({k for k in range(CHECKPOINT,size,CHECKPOINT)}|{int(x) for x in extra if 0<int(x)<size})

def commands(sizes=None,extra=()):
 rows=[]
 for name in PARTITIONS:
  rows+= [size_command(name),hash_command(name)]
  if name=='super':rows+=[prefix_command(name,k) for k in prefixes((sizes or {}).get(name,0),extra)]
 return rows

def parse_log(text):
 """Collects part-hash lines from a kernel log, console or kmsg stream."""
 result={}
 for line in text.splitlines():
  m=re.search(r'TP510-RAM-V(?:8|9|10|11|12): part-hash name=([a-z0-9_]+) (.*)$',line)
  if not m:continue
  name,rest=m.groups();fields=dict(re.findall(r'([a-z_0-9]+)=([^ ]+)',rest));entry=result.setdefault(name,{'prefixes':{}})
  if 'bytes' in fields and 'sha256' in fields and 'partial' not in rest:entry.update(bytes=int(fields['bytes']),sha256=fields['sha256'])
  elif 'prefix_bytes' in fields and 'sha256' in fields:
   entry['prefixes'][int(fields['prefix_bytes'])]=fields['sha256']
   if 'partial' in rest:entry['partial']={'prefix_bytes':int(fields['prefix_bytes']),'of':int(fields.get('of',0)),'reason':'deadline' if 'stopped_at_deadline' in fields else 'read_error'}
  elif 'bytes' in fields and 'gpt_index' in fields:entry['gpt_bytes']=int(fields['bytes'])
  if 'match' in fields:entry['kernel_partition_match']=fields['match']=='1'
  if 'mibps' in fields:entry['mibps']=float(fields['mibps'])
  if 'read_mibps' in fields:entry['read_mibps']=float(fields['read_mibps'])
 return result

def parse_protected(text):
 """v12: the protected hashes of each pass (after a "part-hash pass=before-teed" or "after-teed"
 line) and the init's own tk-hash compare lines."""
 passes={'before':{},'after':{}};tk={};total=None;current=None
 for line in text.splitlines():
  m=re.search(r'TP510-RAM-V12: (part-hash|tk-hash) (.*)$',line)
  if not m:continue
  kind,rest=m.groups();fields=dict(re.findall(r'([a-z_0-9]+)=([^ ]+)',rest))
  if kind=='part-hash':
   if 'pass' in fields:current={'before-teed':'before','after-teed':'after'}.get(fields['pass']);continue
   name=fields.get('name')
   if current and name in PROTECTED and 'partial' not in rest and 'bytes' in fields and 'sha256' in fields:
    passes[current][name]={'bytes':int(fields['bytes']),'sha256':fields['sha256']}
  elif 'name' in fields:tk[fields['name']]={'before':fields.get('before'),'after':fields.get('after'),'match':fields.get('match')=='1'}
  elif 'compared' in fields:total={'compared':int(fields['compared']),'unchanged':int(fields.get('unchanged',-1))}
 return passes,tk,total

def compare_protected(manifest,passes,tk):
 """Per partition: unchanged (pair equal, and equal to the backup except nvcfg), changed (the pair
 differs), backup_mismatch (pair equal, backup differs), incomplete (a pass missing) or missing."""
 backup={p['name']:p for p in manifest['partitions']}
 rows={}
 for name in PROTECTED:
  b=passes['before'].get(name);a=passes['after'].get(name);s=backup.get(name);row={'before':b is not None,'after':a is not None,'backup':s is not None}
  if s:
   for k,v in (('before',b),('after',a)):
    if v:row['backup_'+k+'_match']=v['sha256']==s['raw_sha256'] and v['bytes']==s['bytes']
  if b and a:
   row['pair_match']=b==a
   # The init's tk-hash line must say the same as the two hash lines.
   t=tk.get(name);row['tk_hash_agrees']=bool(t) and t['before']==b['sha256'] and t['after']==a['sha256'] and t['match']==row['pair_match']
   if not row['pair_match']:row['verdict']='changed'
   elif s and not row['backup_after_match'] and name not in BACKUP_MAY_DIFFER:row['verdict']='backup_mismatch'
   else:row['verdict']='unchanged'
  else:row['verdict']='incomplete' if (b or a) else 'missing'
  rows[name]=row
 return rows

def compare(stock,device,candidate_sha=None):
 """Recovery holds the diagnostic during the trial, so its expected hash is the candidate's."""
 rows={}
 for name in PARTITIONS:
  s=stock.get(name);d=device.get(name);row={'device':d is not None,'stock':s is not None}
  if s and d:
   expected=candidate_sha if name=='recovery' and candidate_sha else s['sha256']
   row['bytes_match']=d.get('gpt_bytes',d.get('bytes'))==s['bytes']
   if 'sha256' in d:row['whole_match']=d['sha256']==expected
   row['prefix_matches']={str(k):s.get('prefixes',{}).get(str(k))==v if str(k) in s.get('prefixes',{}) else None for k,v in d['prefixes'].items()}
   row['verdict']='match' if row['bytes_match'] and row.get('whole_match',True) and all(v is not False for v in row['prefix_matches'].values()) and ('sha256' in d or any(row['prefix_matches'].values())) else 'mismatch'
   if 'sha256' not in d and not any(row['prefix_matches'].values()):row['verdict']='incomplete'
  else:row['verdict']='missing'
  rows[name]=row
 return rows

def main():
 p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter);sub=p.add_subparsers(dest='mode',required=True)
 c=sub.add_parser('commands');c.add_argument('--super-bytes',type=int,default=0);c.add_argument('--prefix',type=int,action='append',default=[])
 s=sub.add_parser('stock');s.add_argument('--serial',required=True);s.add_argument('--adb',default='adb');s.add_argument('--output',type=Path,required=True);s.add_argument('--prefix',type=int,action='append',default=[],help='extra super prefix byte count, for a partial diagnostic read')
 m=sub.add_parser('compare');m.add_argument('--stock',type=Path,required=True);m.add_argument('--log',type=Path,required=True);m.add_argument('--candidate-sha256');m.add_argument('--manifest',type=Path,default=MANIFEST,help='stock backup manifest for the v12 protected partitions')
 a=p.parse_args()
 if a.mode=='commands':
  print('\n'.join(commands({'super':a.super_bytes},a.prefix)));return
 if a.mode=='stock':
  if a.output.exists():raise SystemExit('Refuse to overwrite '+str(a.output))
  def phone(command):
   r=subprocess.run([a.adb,'-s',a.serial,'shell',shlex.join(['su','-c',command])],capture_output=True,text=True,timeout=900);r.check_returncode();return r.stdout.strip()
  result={'recorded_utc':datetime.now(timezone.utc).isoformat(),'serial':a.serial,'device_writes':False,'firmware':phone('getprop ro.agui.real_version'),'partitions':{}}
  for name in PARTITIONS:
   size=int(phone(size_command(name)));digest=phone(hash_command(name)).split()[0];assert re.fullmatch('[0-9a-f]{64}',digest)
   row={'bytes':size,'sha256':digest,'prefixes':{}}
   if name=='super':
    for k in prefixes(size,a.prefix):row['prefixes'][str(k)]=phone(prefix_command(name,k)).split()[0]
   result['partitions'][name]=row;print(name,size,digest,flush=True)
  a.output.write_text(json.dumps(result,indent=2)+'\n');return
 text=a.log.read_text(errors='replace');stock=json.loads(a.stock.read_text())['partitions'];device=parse_log(text)
 candidate=a.candidate_sha256
 if not candidate:
  # The candidate record of the variant that wrote the log.
  m=re.search(r'TP510-RAM-V(\d+): part-hash',text)
  record=ROOT/f'evidence/kernel-upgrade/diagnostic-package-v{m.group(1) if m else 9}/candidate-validation.json'
  candidate=json.loads(record.read_text())['candidate']['sha256'] if record.exists() else None
 rows=compare(stock,device,candidate);result={'device':device,'compare':rows};failed=any(r['verdict']=='mismatch' for r in rows.values())
 if 'TP510-RAM-V12: part-hash' in text:
  passes,tk,total=parse_protected(text);protected=compare_protected(json.loads(a.manifest.read_text()),passes,tk)
  result['protected']={'passes':passes,'tk_hash_total':total,'compare':protected}
  failed=failed or any(r['verdict'] in ('changed','backup_mismatch') or r.get('tk_hash_agrees') is False for r in protected.values())
 print(json.dumps(result,indent=2))
 if failed:sys.exit(1)
if __name__=='__main__':main()
