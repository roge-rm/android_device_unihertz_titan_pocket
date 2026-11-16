#!/usr/bin/env python3
"""Exercise rejection boundaries with synthetic images and synthetic release gates."""
import copy,hashlib,json,runpy,struct,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def main():
 (ROOT/'evidence/kernel-upgrade').mkdir(parents=True,exist_ok=True)
 module=runpy.run_path(str(ROOT/'tools/validate-pocket-install.py'));validate=module['validate'];Invalid=module['InvalidPlan'];count=0
 with tempfile.TemporaryDirectory(prefix='pocket-plan-') as tmp:
  root=Path(tmp);image=root/'boot.img';image.write_bytes(b'not-a-real-boot-image')
  gates={'schema':1,'product':'Titan_pocket','supported_stock_firmware':['test-baseline'],'qualified':{key:True for key in module['REQUIRED_GATES']}}
  plan={'schema':1,'product':'Titan_pocket','stock_firmware':'test-baseline','data_action':'preserve','avb_qualified':True,'images':[{'partition':'boot','file':'boot.img','sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'mode':'bootloader'}]}
  assert validate(plan,root,gates)['valid'];count+=1
  def reject(p,g):
   try:validate(p,root,g)
   except Invalid:return
   raise AssertionError('Accepted invalid plan')
  for key,value in [('schema',2),('product','other'),('stock_firmware','other'),('data_action','implicit'),('avb_qualified',False)]:
   p=copy.deepcopy(plan);p[key]=value;reject(p,gates);count+=1
  for partition in ['nvram','nvdata','nvcfg','protect1','protect2','persist','seccfg','preloader','tee1','tee2','para','userdata','super','bootloader','vbmeta_system','vbmeta_vendor','md_udc','lk','recovery_a']:
   p=copy.deepcopy(plan);p['images'][0]['partition']=partition;reject(p,gates);count+=1
  for key in module['REQUIRED_GATES']:
   g=copy.deepcopy(gates);g['qualified'][key]=False;reject(plan,g);count+=1
  for field,value in [('file','../boot.img'),('file','/boot.img'),('file','missing.img'),('sha256','0'*64),('mode','fastbootd')]:
   p=copy.deepcopy(plan);p['images'][0][field]=value;reject(p,gates);count+=1
  p=copy.deepcopy(plan);p['images']*=2;reject(p,gates);count+=1
  def avb(flags):return b'AVB0'+bytes(116)+struct.pack('>I',flags)+bytes(4096-124)
  def rec(name,data,mode):
   f=root/(name+'.img');f.write_bytes(data);return {'partition':name,'file':f.name,'sha256':hashlib.sha256(data).hexdigest(),'mode':mode}
  vb=rec('vbmeta',avb(3),'bootloader');rc=rec('recovery',b'recovery',"bootloader");sy=rec('system',b'system','fastbootd')
  full=copy.deepcopy(plan);full['images']=[rc,sy,full['images'][0],vb];full['data_action']='wipe';full['format']=['userdata','md_udc']
  assert validate(full,root,gates)['valid'];count+=1
  p=copy.deepcopy(full);p['images']=[rc,sy,vb];p['data_action']='preserve';p['format']=[];assert validate(p,root,gates)['valid'];count+=1
  for images in ([sy,rc,vb],[rc,vb,sy],[vb,sy]):
   p=copy.deepcopy(full);p['images']=images;reject(p,gates);count+=1
  for data in (avb(0),avb(2),b'not avb'+bytes(200)):
   p=copy.deepcopy(full);p['images']=[rc,rec('vbmeta',data,'bootloader')];reject(p,gates);count+=1
  p=copy.deepcopy(full);p['images'][3]=dict(vb,mode='fastbootd');reject(p,gates);count+=1
  for action,fmt in [('wipe',[]),('wipe',['userdata']),('wipe',['userdata','md_udc','metadata']),('wipe',['userdata','userdata']),('preserve',['userdata','md_udc']),('wipe',['userdata','nvdata'])]:
   p=copy.deepcopy(full);p['data_action']=action;p['format']=fmt;reject(p,gates);count+=1
  rec('vbmeta',avb(3),'bootloader')
  link=root/'linked.img';link.symlink_to(image);p=copy.deepcopy(plan);p['images'][0]['file']='linked.img';reject(p,gates);count+=1
  image.write_bytes(b'');reject(plan,gates);count+=1
  image.write_bytes(b'not-a-real-boot-image');reject(plan,json.loads((ROOT/'configs/release-gates.json').read_text()));count+=1
 record={'checks':count,'device_accessed':False,'synthetic_inputs_only':True,'real_release_gates_open':True,'no_write_path':True}
 (ROOT/'evidence/kernel-upgrade/install-plan-check.json').write_text(json.dumps(record,indent=2)+'\n');print(str(count)+' installation-plan validation cases passed; no device writes')
if __name__=='__main__':main()
