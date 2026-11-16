#!/usr/bin/env python3
"""Prepare checked DT table components, never an installable 5.10 boot image."""
import hashlib,json,runpy,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
MAGIC=0xd7b7ab1e

def parse_table(data):
 if len(data)<32: raise ValueError('short header')
 magic,total,header,entry_size,count,offset,page,version=struct.unpack_from('>8I',data)
 if magic!=MAGIC or total!=len(data) or header!=32 or entry_size!=32 or version!=0 or count!=1 or offset<header or offset+count*entry_size>total or page!=2048:
  raise ValueError('unsupported/invalid table header')
 entries=[]; ranges=[]
 for i in range(count):
  size,start,*identity=struct.unpack_from('>8I',data,offset+i*entry_size)
  if size<40 or start<offset+count*entry_size or start+size>total: raise ValueError('invalid entry range')
  blob=data[start:start+size]
  if struct.unpack_from('>I',blob)[0]!=0xd00dfeed or struct.unpack_from('>I',blob,4)[0]!=size: raise ValueError('invalid FDT entry')
  if any(start<b and start+size>a for a,b in ranges): raise ValueError('overlap')
  ranges.append((start,start+size));entries.append({'size':size,'offset':start,'identity':identity,'blob':blob})
 return {'page_size':page,'version':version,'entries':entries}

def pack(blob,identity):
 return struct.pack('>8I',MAGIC,64+len(blob),32,32,1,32,2048,0)+struct.pack('>8I',len(blob),64,*identity)+blob

def main():
 out=ROOT/'artifacts/kernel-upgrade/boot-layout';out.mkdir(parents=True,exist_ok=True)
 ev=ROOT/'evidence/kernel-upgrade';decode=runpy.run_path(str(ROOT/'tools/inspect-fdt.py'))['decode']
 stock={};roundtrips=[]
 for name in ['dtb','recovery_dtbo']:
  path=ROOT/'firmware/installed-20230105/recovery'/name;data=path.read_bytes();parsed=parse_table(data);entry=parsed['entries'][0]
  assert pack(entry['blob'],entry['identity'])==data
  stock[name]=parsed;roundtrips.append({'component':name,'sha256':hashlib.sha256(data).hexdigest(),'fdt_bytes':entry['size'],'identity':entry['identity'],'byte_exact_table_roundtrip':True})
  (out/('stock-'+name+'.fdt')).write_bytes(entry['blob'])
 # The bootloader overlay and already-overlaid live capture must not be combined twice.
 merged=out/'stock-applied.dtb'
 subprocess.run([str(ROOT/'artifacts/kernel-upgrade/fdtoverlay'),'-i',str(out/'stock-dtb.fdt'),'-o',str(merged),str(out/'stock-recovery_dtbo.fdt')],check=True)
 base=ROOT/'artifacts/kernel-upgrade/pinctrl-pmic-ufs-usb-pstore-diagnostic.dtb';blob=base.read_bytes()
 table=out/'diagnostic-dtb.table';table.write_bytes(pack(blob,stock['dtb']['entries'][0]['identity']))
 empty=out/'identity-overlay.dts';empty.write_text('/dts-v1/;\n/plugin/;\n/ {};\n')
 empty_dtb=out/'identity-overlay.dtbo'
 dtc=ROOT/'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
 subprocess.run([str(dtc),'-@','-I','dts','-O','dtb','-o',str(empty_dtb),str(empty)],check=True)
 overlay_table=out/'diagnostic-identity-dtbo.table';overlay_table.write_bytes(pack(empty_dtb.read_bytes(),stock['recovery_dtbo']['entries'][0]['identity']))
 identity_result=out/'identity-applied.dtb'
 subprocess.run([str(ROOT/'artifacts/kernel-upgrade/fdtoverlay'),'-i',str(base),'-o',str(identity_result),str(empty_dtb)],check=True)
 assert decode(identity_result.read_bytes())['nodes']==decode(blob)['nodes']
 assert parse_table(table.read_bytes())['entries'][0]['blob']==blob
 assert parse_table(overlay_table.read_bytes())['entries'][0]['blob']==empty_dtb.read_bytes()
 # Reject truncated headers, bad fields, out-of-bounds metadata and entry ranges.
 malformed=[b'',table.read_bytes()[:31],table.read_bytes()[:-1]]
 for offset,value in [(0,0),(8,0),(12,64),(16,0),(20,0xfffffff0),(24,4096),(28,1),(32,0xffffffff),(36,0)]:
  data=bytearray(table.read_bytes());struct.pack_into('>I',data,offset,value);malformed.append(bytes(data))
 for bad in malformed:
  try:parse_table(bad)
  except ValueError:pass
  else:raise AssertionError('accepted malformed input')
 before=decode(merged.read_bytes())['nodes']; live=decode((ROOT/'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb').read_bytes())['nodes']
 images=json.loads((ev/'linked-image-validation.json').read_text())
 kernel=ROOT/images['files'][0]['path'];head=kernel.read_bytes()[:64]
 text_offset,image_size=struct.unpack_from('<QQ',head,8)
 # Header v2 placement derived from the stock recovery header, not a boot endorsement.
 regions=[('kernel',0x40080000,max(kernel.stat().st_size,image_size)),('dtb',0x54000000,len(table.read_bytes())),('ramdisk',0x55000000,0x100000)]
 assert all(a+size<=b or b+other<=a for j,(_,a,size) in enumerate(regions) for _,b,other in regions[j+1:])
 record={'stock_tables':roundtrips,'malformed_rejected':len(malformed),'identity_overlay_preserves_all_nodes':True,'diagnostic_nodes':len(decode(blob)['nodes']),'stock_applied_nodes':len(before),'stock_vs_live_added_nodes':sorted(set(live)-set(before)),'stock_vs_live_removed_nodes':sorted(set(before)-set(live)), 'runtime_property_differences':sum(before[p].get(k)!=live[p].get(k) for p in before.keys()&live.keys() for k in before[p].keys()|live[p].keys()),'arm64_header':{'text_offset':text_offset,'image_size':image_size},'nonoverlapping_candidate_regions':[{'name':n,'base':a,'size':s} for n,a,s in regions],'files':[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [table,overlay_table]],'boot_image_packaged':False,'device_accessed':False,'blocked_by':['PMIC/regulator handoff and unported board dependencies','DT schema/binding audit and private runtime properties','RAM logger USB hardware validation','Kernel physical entry/relocation and bootloader handoff validation'],'scope':'Local DT container/identity-overlay fixtures only; not public board DTS, shipping tables, or installation artifacts'}
 (ev/'boot-layout-preparation.json').write_text(json.dumps(record,indent=2)+'\n')
 print(f'DT tables round-trip exactly; {len(malformed)} malformed inputs rejected; identity overlay preserves {record["diagnostic_nodes"]} nodes; no boot image created')
if __name__=='__main__':main()
