#!/usr/bin/env python3
"""Validate an installation plan locally. This tool has no device-write path.

The images list is the write order. Recovery, when in the plan, comes first (LK), then the
fastbootd images, then the other LK images. vbmeta must be an AVB image with flags 3
(verification and hashtree off), the only vbmeta LK is known to boot our images with.
data_action wipe needs format to list exactly userdata and md_udc (/metadata); preserve
allows no format.
"""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
ALLOWED={'boot':33554432,'recovery':33554432,'vbmeta':8388608,'system':4829741056,'vendor':4829741056,'product':4829741056}
LOGICAL={'system','vendor','product'}
FORMAT={'userdata','md_udc'}
# Group size of the dynamic partitions in super.
LOGICAL_LIMIT=4829741056
REQUIRED_GATES={'kernel_board_boot','ufs_encryption','vndk_fcm_compatibility','combined_enforcing_policy','keyboard_and_hardware_parity','installer_recovery_rollback'}
class InvalidPlan(ValueError):pass
def digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
 return h.hexdigest()

def vbmeta_flags(path):
 """Flags of an AVB vbmeta image, or None. The flags word is big-endian at offset 120."""
 with path.open('rb') as f:head=f.read(124)
 if len(head)<124 or head[:4]!=b'AVB0':return None
 return struct.unpack('>I',head[120:124])[0]

def validate(plan,image_root,gates):
 def require(condition,reason):
  if not condition:raise InvalidPlan(reason)
 require(plan.get('schema')==1 and gates.get('schema')==1,'Unsupported plan/gate schema')
 require(plan.get('product')==gates.get('product')=='Titan_pocket','Wrong product')
 require(plan.get('stock_firmware') in gates.get('supported_stock_firmware',[]),'Unqualified stock firmware')
 require(plan.get('data_action') in ['preserve','wipe'],'Data action must be explicit')
 fmt=plan.get('format',[])
 require(isinstance(fmt,list) and all(isinstance(n,str) for n in fmt),'Invalid format list')
 if plan['data_action']=='wipe':require(len(fmt)==len(FORMAT) and set(fmt)==FORMAT,'A wipe formats exactly userdata and md_udc')
 else:require(not fmt,'Format listed but data is preserved')
 missing=sorted(k for k in REQUIRED_GATES if gates.get('qualified',{}).get(k) is not True)
 require(not missing,'Release gates remain open: '+', '.join(missing))
 require(plan.get('avb_qualified') is True,'AVB/signing compatibility must be qualified')
 files=plan.get('images');require(isinstance(files,list) and 0<len(files)<=len(ALLOWED),'Invalid image list')
 root=Path(image_root).resolve();seen=set();logical=0;checked=[]
 for k,image in enumerate(files):
  require(isinstance(image,dict),'Invalid image record');partition=image.get('partition')
  require(isinstance(partition,str) and partition in ALLOWED and partition not in seen,'Protected, unknown or duplicate partition')
  seen.add(partition);relative=image.get('file');require(isinstance(relative,str) and bool(relative),'Missing image path')
  relative=Path(relative);require(not relative.is_absolute() and '..' not in relative.parts,'Image path escapes package')
  path=root/relative;require(not path.is_symlink() and path.is_file(),'Image must be a regular package file')
  require(path.resolve().is_relative_to(root),'Image target escapes package')
  size=path.stat().st_size;require(0<size<=ALLOWED[partition],'Image is empty or oversized')
  require(digest(path)==image.get('sha256'),'Image checksum mismatch')
  expected_mode='fastbootd' if partition in LOGICAL else 'bootloader'
  require(image.get('mode')==expected_mode,'Incorrect fastboot mode for partition')
  if partition=='recovery':require(k==0,'Recovery must be the first write')
  if partition=='vbmeta':require(vbmeta_flags(path)==3,'vbmeta must be an AVB image with flags 3')
  if partition in LOGICAL:logical+=size
  checked.append({'partition':partition,'bytes':size,'mode':expected_mode})
 # After recovery, every fastbootd write comes before the other LK writes.
 modes=[c['mode'] for c in checked if c['partition']!='recovery']
 require(modes==sorted(modes,key=lambda m:m!='fastbootd'),'fastbootd writes must come before the other LK writes')
 require(logical<=LOGICAL_LIMIT,'Logical images exceed dynamic partition group')
 return {'valid':True,'images':checked,'format':list(fmt),'device_accessed':False,'write_commands_generated':False,'limits':['Geometry/hash/gate checks only; signed image contents and actual installation still require qualification']}

def main():
 p=argparse.ArgumentParser(description=__doc__.splitlines()[0]);p.add_argument('--plan',type=Path,required=True);p.add_argument('--images',type=Path,required=True)
 p.add_argument('--gates',type=Path,default=ROOT/'configs/release-gates.json');a=p.parse_args()
 plan=json.loads(a.plan.read_text());plan=plan.get('plan',plan)
 try:result=validate(plan,a.images,json.loads(a.gates.read_text()))
 except (InvalidPlan,KeyError,TypeError) as e:p.exit(1,str(e)+'\n')
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
