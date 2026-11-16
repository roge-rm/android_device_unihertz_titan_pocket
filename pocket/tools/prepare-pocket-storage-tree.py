#!/usr/bin/env python3
"""Derive an explicit RAM storage-probe tree from saved pre-LK stock inputs.

No image packaging or phone access. The graph excludes Android and unrelated
hardware; the opt-in UFS profile rejects unimplemented production power states.
"""
import pocket_paths
import argparse,copy,hashlib,json,os,runpy,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
def validate_providers(nodes,values,enabled):
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v};edges=[]
 def require(handle,consumer,prop):
  assert handle in handles,(consumer,prop,'unknown phandle',handle)
  provider=handles[handle];assert enabled(nodes,provider),(consumer,prop,'disabled provider',provider)
  edges.append([consumer,prop,provider]);return provider
 for path,props in nodes.items():
  if not enabled(nodes,path):continue
  for prop,width_name in [('clocks','#clock-cells'),('phys','#phy-cells'),('resets','#reset-cells')]:
   cells=values(props[prop]) if prop in props else [];index=0
   while index<len(cells):
    provider=require(cells[index],path,prop);width=values(nodes[provider][width_name])[0]
    assert index+1+width<=len(cells),(path,prop,'truncated specifier');index+=1+width
  for prop,value in props.items():
   if prop.endswith('-supply') or prop=='interrupt-parent':
    cell=values(value);assert len(cell)==1;require(cell[0],path,prop)
  if 'interrupts' in props:
   parent=path
   while 'interrupt-parent' not in nodes[parent]:parent=parent.rpartition('/')[0] or '/'
   irq=require(values(nodes[parent]['interrupt-parent'])[0],path,'interrupts')
   assert len(values(props['interrupts']))%values(nodes[irq]['#interrupt-cells'])[0]==0
 for path in ['/msdc@11230000','/msdc@11240000','/usb3_xhci@11200000','/scpsys@10001000']:
  assert not enabled(nodes,path),path
 return edges

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--diagnostic-variant',choices=['v5','v6','v7','v8','v9','v10','v11','v12']);args=parser.parse_args()
 os.environ['POCKET_DIAGNOSTIC_VARIANT']='v4'
 tree=runpy.run_path(str(ROOT/'tools/prepare-pocket-diagnostic-tree.py'),run_name='storage_tree_helpers')
 decode=tree['DECODE'];cells=tree['cells'];strings=tree['strings'];values=tree['values']
 original=BULK/'artifacts/diagnostic-5.10-v4/board/stock-applied.dtb'
 parsed=decode(original.read_bytes());before=parsed['nodes']
 assert not any(p.startswith('/reserved-memory/mblock-') for p in before),'Never use captured live FDT as boot input'
 nodes=tree['derive'](before)
 host='/ufshci@11270000';phy='/ufs_mphy@11fa0000';pmic='/pwrap@1000d000/mt6358-pmic'
 assert values(before[host]['reg'])==[0,0x11270000,0,0x2300]
 assert values(before[host]['interrupts'])==[0,80,8]
 assert values(before[phy]['reg'])==[0,0x11fa0000,0,0xc000]
 assert before[host]['clock-names']['strings']==['ufs0-clock','ufs0-unipro-clk','ufs0-mp-clk','ufs0-aes-clk']
 assert values(before[host]['clocks'])==[21,79,21,62,21,64,21,80]
 assert values(before[host]['freq-table-hz'])==[0]*8,'Do not invent target rates'
 assert values(before[host]['lanes-per-direction'])==[1]
 assert 'highspeed-gear' not in before[host],'Captured stock defaults to HSG3B'
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v}
 next_handle=max(handles)+1
 def handle():
  nonlocal next_handle
  result=next_handle;next_handle+=1;assert result<0xffffffff and result not in handles;handles.add(result);return result
 phy_handle=values(nodes[phy]['phandle'])[0] if 'phandle' in nodes[phy] else handle()
 nodes[phy].update({'status':strings('okay'),'compatible':strings('mediatek,mt6771-ufsphy'),
  'phandle':cells(phy_handle),'#phy-cells':cells(0),'clocks':cells(21,62,21,64),'clock-names':strings('unipro','mp')})
 clock=pmic+'/ufs-reference-clock';clock_handle=handle()
 assert clock not in nodes
 nodes[clock]={'compatible':strings('mediatek,mt6358-ufs-clock'),'#clock-cells':cells(0),'phandle':cells(clock_handle),'status':strings('okay')}
 # The captured fixed VA09 node is nested in a vendor regulator container.
 # Keep its path for LK, but instantiate its fixed model at the root.
 old_supply=pmic+'/mt6358regulator/ldo_va09';new_supply='/regulator-ufs-va09'
 assert values(before[old_supply]['phandle'])==[143]
 assert values(before[old_supply]['regulator-min-microvolt'])==[900000]
 assert values(before[old_supply]['regulator-max-microvolt'])==[900000]
 assert before[old_supply]['compatible']['strings']==['regulator-fixed']
 nodes[new_supply]=copy.deepcopy(nodes[old_supply]);va09_handle=handle()
 nodes[new_supply]['phandle']=cells(va09_handle)
 nodes[old_supply]['status']=strings('disabled')
 assert set(before)<=set(nodes),'Retain every original node path for LK fixups'
 i2c_buses={}
 if args.diagnostic_variant in ('v8','v9','v10','v11','v12'):
  # Only the buses with ID-read targets: i2c0 touch, i2c3 amp, i2c6 touchpad and fuel gauge.
  # Stock reg, IRQ, clocks (bus gate + AP DMA gate) and clock-div stay as captured; the
  # nodes have no pinctrl on stock, so the pins keep the bootloader's mux. Children stay disabled.
  for path,alias,clock in [('/i2c@11007000',0,11),('/i2c@1100f000',3,14),('/i2c@11005000',6,88)]:
   bus=nodes[path]
   assert tree['text'](bus['compatible'])==['mediatek,i2c'] and values(bus['id'])==[alias]
   assert values(bus['clocks'])==[21,clock,21,43] and tree['text'](bus['clock-names'])==['main','dma']
   assert values(bus['clock-div'])==[5] and values(bus['clock-frequency'])==[400000]
   assert 'pinctrl-0' not in bus and 'mediatek,use-push-pull' not in bus
   # The recovery dtb's /aliases has only spi0-5, so adapter numbers are dynamic; init looks them up by path.
   assert 'i2c'+str(alias) not in nodes['/aliases']
   bus['compatible']=strings('mediatek,mt6771-i2c');bus['status']=strings('okay')
   i2c_buses[path]={'stock_bus_id':alias,'adapter_number':'dynamic','reg':values(bus['reg']),'interrupts':values(bus['interrupts']),'clocks':values(bus['clocks'])}
 if args.diagnostic_variant in ('v9','v10','v11','v12'):
  # i2c4 (aw9523 keyboard) is a multi-channel bus shared with the camera CCU. Stock reg, IRQ and
  # its three clocks (I2C1 gate, AP DMA gate, I2C1 arbiter gate) stay as captured. The AP channel
  # is at +0x100 (stock ch_offset_default; the stock boot log shows ch_offset:0x100), passed to
  # patch 0013 as mediatek,ch-offset. Children stay disabled.
  path='/i2c@11008000';bus=nodes[path]
  assert tree['text'](bus['compatible'])==['mediatek,i2c'] and values(bus['id'])==[4]
  assert values(bus['reg'])==[0,0x11008000,0,0x1000,0,0x11000100,0,0x80]
  assert values(bus['interrupts'])==[0,82,8]
  assert values(bus['clocks'])==[21,12,21,43,21,72] and tree['text'](bus['clock-names'])==['main','dma','arb']
  assert values(bus['clock-div'])==[5] and values(bus['clock-frequency'])==[400000]
  assert values(bus['ch_offset_default'])==[0x100]
  assert 'pinctrl-0' not in bus and 'mediatek,use-push-pull' not in bus and 'mediatek,ch-offset' not in bus
  assert 'i2c4' not in nodes['/aliases']
  children=[c for c in nodes if c.startswith(path+'/')]
  assert children and all(not tree['enabled'](nodes,c) for c in children)
  bus['compatible']=strings('mediatek,mt6771-i2c');bus['status']=strings('okay');bus['mediatek,ch-offset']=cells(0x100)
  i2c_buses[path]={'stock_bus_id':4,'adapter_number':'dynamic','reg':values(bus['reg']),'interrupts':values(bus['interrupts']),'clocks':values(bus['clocks']),'ch_offset':0x100}
 nodes['/infracfg_ao@10001000']['#reset-cells']=cells(1)
 nodes[host].update({'status':strings('okay'),'compatible':strings('mediatek,mt6771-ufshci'),
  'phys':cells(phy_handle),'phy-names':strings('ufsphy'),
  'resets':cells(21,14,21,68,21,47),'reset-names':strings('hci_rst','unipro_rst','crypto_rst'),
  'va09-supply':cells(va09_handle),'mediatek,ufs-support-va09':cells(),
  'mediatek,ufs-disable-ah8':cells(),'unihertz,ram-storage-probe':cells()})
 nodes[host+'/reference-clock']={'clocks':cells(clock_handle),'clock-names':strings('ref_clk'),'status':strings('okay')}
 assert nodes[host]['clocks']==before[host]['clocks'] and nodes[host]['freq-table-hz']==before[host]['freq-table-hz']
 assert bytes.fromhex(nodes['/chosen']['bootargs']['hex'])==b'\0'
 assert not any(p.startswith('/reserved-memory/mblock-') for p in nodes)
 assert len([p for p,v in nodes.items() if 'phandle' in v and values(v['phandle'])==[143]])==1
 assert nodes[old_supply]['phandle']==before[old_supply]['phandle']
 # Generic validator also verifies live supplies, reset/PHY and clock providers.
 edges=validate_providers(nodes,values,tree['enabled']);active=[p for p in nodes if tree['enabled'](nodes,p)]
 output=BULK/('artifacts/diagnostic-5.10-'+args.diagnostic_variant+'/board' if args.diagnostic_variant else 'artifacts/storage-probe-5.10/board');output.mkdir(parents=True,exist_ok=True)
 dts=output/'storage.dts';dtb=output/('diagnostic.dtb' if args.diagnostic_variant else 'storage.dtb');blob=original.read_bytes();offset=struct.unpack_from('>I',blob,16)[0];reservations=[]
 while True:
  address,size=struct.unpack_from('>QQ',blob,offset);offset+=16
  if not address and not size:break
  reservations.append((address,size))
 dts.write_text(tree['render'](nodes,reservations))
 dtc=ROOT/'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
 command=[str(dtc),'-I','dts','-O','dtb','-o',str(dtb),str(dts)]
 result=subprocess.run(command,capture_output=True,text=True)
 (output/'dtc.stderr.txt').write_text(result.stderr);result.check_returncode()
 after=decode(dtb.read_bytes())['nodes'];assert set(after)==set(nodes)
 for p in nodes:
  assert {k:v['hex'] for k,v in after[p].items()}=={k:v['hex'] for k,v in nodes[p].items()},p
 sources=[Path(__file__),ROOT/'tools/prepare-pocket-diagnostic-tree.py',ROOT/'tools/inspect-fdt.py']
 record={'i2c_buses':i2c_buses,'source_tree':str(original),'source_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),
  'generator_inputs':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
  'output':str(dtb),'sha256':hashlib.sha256(dtb.read_bytes()).hexdigest(),'nodes':len(nodes),'active':active,'provider_edges':edges,
  'fixed_supply_provider':{'stock_node_preserved':old_supply,'new_root_provider':new_supply,'stock_phandle':143,'provider_phandle':va09_handle,'captured_fixed_voltage_ramp_boot_properties_preserved':True},
  'host_controller_reg_irq_clocks_frequency_table_preserved':True,'block_data_writes_requested':False,'image_packaged':False,'phone_accessed':False,
  'limits':['RAM engineering binding only, not a production board tree','No runtime storage, reset, rail, clock mode/rate, DMA/IOMMU or PM qualification','Probe flag disables autosuspend/clock gating/WriteBooster; unsupported off/PM paths fail','Read-only block I/O is an init policy, not a claim all UFS configuration commands are reads']}
 if args.diagnostic_variant in (None,'v5'):(ROOT/'evidence/kernel-upgrade/storage-engineering-board.json').write_text(json.dumps(record,indent=2)+'\n')
 if args.diagnostic_variant:
  record['board_dtb']={'path':str(dtb),'sha256':record['sha256'],'bytes':dtb.stat().st_size}
  record['generator_sha256']=hashlib.sha256((ROOT/'tools/prepare-pocket-diagnostic-tree.py').read_bytes()).hexdigest()
  (ROOT/('evidence/kernel-upgrade/diagnostic-board-'+args.diagnostic_variant+'.json')).write_text(json.dumps(record,indent=2)+'\n')
 print(f'{len(nodes)} pre-LK nodes; explicit UFS/PHY/reset/PMIC/fixed-supply graph round-trips; no image or phone operation')
if __name__=='__main__':main()
