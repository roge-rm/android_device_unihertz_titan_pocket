#!/usr/bin/env python3
"""Restrict the stock pre-LK tree for RAM diagnostics; never use a live FDT."""
import pocket_paths
import copy,hashlib,json,os,runpy,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Diagnostic variant must be v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11 or v12')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
OUT=BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/board')
DECODE=runpy.run_path(str(ROOT/'tools/inspect-fdt.py'))['decode']
TABLE=runpy.run_path(str(ROOT/'tools/prepare-upgrade-boot-layout.py'))

def cells(*values):return {'hex':struct.pack('>'+'I'*len(values),*values).hex()}
def strings(*values):return {'hex':b''.join(s.encode()+b'\0' for s in values).hex()}
def raw(value):return bytes.fromhex(value['hex'])
def values(value):
 b=raw(value);assert len(b)%4==0;return list(struct.unpack('>'+'I'*(len(b)//4),b))
def text(value):return raw(value).rstrip(b'\0').decode().split('\0')
def enabled(nodes,path):
 while True:
  if text(nodes[path].get('status',strings('okay')))[0] not in ['okay','ok']:return False
  if path=='/':return True
  path=path.rpartition('/')[0] or '/'

def derive(original):
 n=copy.deepcopy(original)
 assert not any(p.startswith('/reserved-memory/mblock-') for p in n),'Reject an already bootloader-populated/live FDT'
 active={'/','/chosen','/memory','/cpus','/psci','/timer','/clocks','/interrupt-controller@0c000000','/intpol-controller@0c530620','/topckgen@10000000','/infracfg_ao@10001000','/apmixed@1000c000','/1000b000.pinctrl','/pwrap@1000d000','/pwrap@1000d000/mt6358-pmic','/usb0phy@11f40000','/usb3@11200000','/reserved-memory'}
 for p in n:
  if p.startswith(('/cpus/cpu@','/cpus/cpu-map','/clocks/','/reserved-memory/','/pwrap@1000d000/mt6358-pmic/mt6358regulator')):active.add(p)
 if VARIANT!='v1':active.add('/toprgu@10007000')
 assert active<=n.keys(),active-n.keys()
 for p,v in n.items():
  if p in {'/','/aliases','/__symbols__','/__fixups__','/__local_fixups__'} or p.startswith('/__local_fixups__/'):continue
  if p.startswith('/reserved-memory/'):continue
  # Keep the full pre-LK topology so LK's board fixups can still find nodes.
  v['status']=strings('okay' if p in active else 'disabled')
 for p in n:
  if p.startswith('/cpus/cpu@'):
   n[p]={k:v for k,v in n[p].items() if k in {'compatible','reg','device_type','enable-method','phandle','status'}}
 pin=n['/1000b000.pinctrl']
 resource_paths=['/gpio@10005000']+[next(p for p in original if p.startswith('/iocfg_'+str(i)+'@')) for i in range(8)]+['/apirq@1000b000']
 pin['reg']={'hex':b''.join(raw(original[p]['reg']) for p in resource_paths).hex()}
 pin['reg-names']=strings('gpio',*[f'iocfg{i}' for i in range(8)],'eint')
 for name in ['reg_bases','reg_base_eint']:pin.pop(name,None)
 pin['#interrupt-cells']=cells(2)
 # The native descriptor contains GPIO0..191. EINT182 maps to GPIO190.
 pin['gpio-ranges']=cells(values(pin['phandle'])[0],0,0,192)
 n['/pwrap@1000d000']['compatible']=strings('mediatek,mt6771-pwrap')
 pmic=n['/pwrap@1000d000/mt6358-pmic'];pmic['compatible']=strings('mediatek,mt6358')
 assert values(pmic['interrupts'])==[182,4,190,0]
 pmic['interrupts']=cells(182,4)
 for k in ['mediatek,num-pmic-irqs','mediatek,pmic-irqs','interrupt-names']:pmic.pop(k,None)
 phy=n['/usb0phy@11f40000'];phy['clocks']=cells(values(n['/apmixed@1000c000']['phandle'])[0],12);phy['clock-names']=strings('ref_clk')
 usb=n['/usb3@11200000'];usb['dr_mode']=strings('peripheral');usb.pop('extcon',None)
 supply='/pwrap@1000d000/mt6358-pmic/mt6358regulator/ldo_vusb'
 assert text(n[supply]['regulator-name'])==['vusb']
 usb['vusb33-supply']=n[supply]['phandle']
 for k in ['kaslr-seed','rng-seed','linux,initrd-start','linux,initrd-end']:n['/chosen'].pop(k,None)
 # LK bootargs.c asserts that fdt_getprop(chosen, bootargs) is non-NULL.
 # An empty NUL-terminated string avoids stale arguments without removing the ABI.
 n['/chosen']['bootargs']=strings('')
 if VARIANT!='v1':
  n['/toprgu@10007000']['compatible']=strings('mediatek,mt6771-wdt')
  n['/ramoops@54410000']={'compatible':strings('unihertz,titan-pocket-ramoops-diagnostic','ramoops'),'reg':cells(0,0x54410000,0,0x8f000),'record-size':cells(0x1000),'console-size':cells(0x40000),'ftrace-size':cells(0),'pmsg-size':cells(0),'mem-type':cells(0),'status':strings('okay')}
 return n

def render(nodes,reservations):
 lines=['/dts-v1/;','// PRIVATE stock-derived diagnostic; not a public board DTS.']
 for address,size in reservations:lines.append(f'/memreserve/ 0x{address:x} 0x{size:x};')
 children={}
 for p in nodes:
  if p!='/':children.setdefault(p.rpartition('/')[0] or '/',[]).append(p)
 def emit(path,depth):
  indent='\t'*depth;lines.append(indent+('/' if path=='/' else path.rsplit('/',1)[1])+' {')
  for name,value in nodes[path].items():
   b=raw(value);data=' '.join(f'{x:02x}' for x in b)
   lines.append(indent+'\t'+name+(f' = [{data}];' if b else ';'))
  for child in children.get(path,[]):emit(child,depth+1)
  lines.append(indent+'};')
 emit('/',0);return '\n'.join(lines)+'\n'

def validate(nodes):
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v};edges=[]
 def require(handle,consumer,prop):
  assert handle in handles,(consumer,prop,'unknown phandle',handle)
  target=handles[handle];assert enabled(nodes,target),(consumer,prop,'disabled provider',target)
  edges.append([consumer,prop,target]);return target
 for p,v in nodes.items():
  if not enabled(nodes,p):continue
  for prop in ['clocks','phys']:
   data=values(v[prop]) if prop in v else [];index=0
   while index<len(data):
    provider=require(data[index],p,prop);count=values(nodes[provider]['#clock-cells' if prop=='clocks' else '#phy-cells'])[0]
    assert index+1+count<=len(data),(p,prop,'truncated specifier');index+=1+count
  for prop in v:
   if prop.endswith('-supply') or prop=='interrupt-parent':
    data=values(v[prop]);assert len(data)==1;require(data[0],p,prop)
  if 'interrupts' in v:
   parent=p
   while 'interrupt-parent' not in nodes[parent]:parent=parent.rpartition('/')[0] or '/'
   provider=require(values(nodes[parent]['interrupt-parent'])[0],p,'interrupts')
   width=values(nodes[provider]['#interrupt-cells'])[0];assert len(values(v['interrupts']))%width==0,(p,'IRQ width')
 # Do not expose any storage, radio, graphics, charging or input controller to this probe.
 for p in ['/ufshci@11270000','/msdc@11230000','/msdc@11240000','/usb3_xhci@11200000','/scpsys@10001000']:
  assert p in nodes and not enabled(nodes,p),p
 assert not any('linux,initrd-' in k or k in ['kaslr-seed','rng-seed'] for k in nodes['/chosen'])
 assert raw(nodes['/chosen']['bootargs'])==b'\0','LK requires a present, valid bootargs string; use empty instead of stale stock arguments'
 return edges

def main():
 if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12'):
  raise SystemExit('Combined '+VARIANT+' requires tools/prepare-pocket-storage-tree.py --diagnostic-variant '+VARIANT+'; refusing to overwrite it with a USB-only tree')
 OUT.mkdir(parents=True,exist_ok=True)
 source=ROOT/'firmware/installed-20230105/recovery';base=OUT/'stock-base.dtb';overlay=OUT/'stock-overlay.dtbo'
 inputs={}
 for name,dest in [('dtb',base),('recovery_dtbo',overlay)]:
  original=(source/name).read_bytes();inputs[name]=hashlib.sha256(original).hexdigest();table=TABLE['parse_table'](original);dest.write_bytes(table['entries'][0]['blob'])
 applied=OUT/'stock-applied.dtb';subprocess.run([str(ROOT/'artifacts/kernel-upgrade/fdtoverlay'),'-i',str(base),'-o',str(applied),str(overlay)],check=True)
 original=DECODE(applied.read_bytes())['nodes'];nodes=derive(original);edges=validate(nodes)
 blob=applied.read_bytes();offset=struct.unpack_from('>I',blob,16)[0];reservations=[]
 while True:
  address,size=struct.unpack_from('>QQ',blob,offset);offset+=16
  if not address and not size:break
  reservations.append((address,size))
 dts=OUT/'diagnostic.dts';dts.write_text(render(nodes,reservations));dtb=OUT/'diagnostic.dtb'
 dtc=ROOT/'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc';p=subprocess.run([str(dtc),'-I','dts','-O','dtb','-o',str(dtb),str(dts)],capture_output=True,text=True,check=True);(OUT/'dtc.log').write_text(p.stdout+p.stderr)
 result=DECODE(dtb.read_bytes())['nodes'];assert set(result)==set(original)|({'/ramoops@54410000'} if VARIANT!='v1' else set())
 assert {p:{k:raw(v) for k,v in vals.items()} for p,vals in result.items()}=={p:{k:raw(v) for k,v in vals.items()} for p,vals in nodes.items()}
 assert validate(result)==edges
 active=[p for p in nodes if enabled(nodes,p)];changed=[(p,k) for p in original for k in original[p].keys()|nodes[p].keys() if original[p].get(k,{}).get('hex')!=nodes[p].get(k,{}).get('hex')]
 record={'stock_inputs':inputs,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'nodes':len(nodes),'active_nodes':active,'provider_edges':edges,'changes':changed,'memreserve_entries':reservations,'board_dtb':{'path':str(dtb),'sha256':hashlib.sha256(dtb.read_bytes()).hexdigest(),'bytes':dtb.stat().st_size},'device_accessed':False,'kernel_booted':False,'source_tree_preserves_lk_fixup_topology':True,'runtime_memory_reservations':'Must be freshly generated by LK; do not preinsert captured mblock nodes','pstore':('Guarded 0x8f000 prefix; requires fresh exact LK 0xe0000 reservation; vendor tail excluded' if VARIANT!='v1' else 'No ramoops node; USB only'),'remaining':['Compile a dedicated minimal kernel and validate exact built-in driver dependencies','Check bootloader fixups and package layout against selected image','Physical PMIC/USB/clock behavior and kernel handoff require attended device qualification']}
 (ROOT/('evidence/kernel-upgrade/diagnostic-board'+SUFFIX+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(f'{len(nodes)} pre-LK nodes retained; {len(active)} active; {len(edges)} checked provider edges; no boot image or phone access')
if __name__=='__main__':main()
