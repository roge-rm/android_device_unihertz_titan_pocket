#!/usr/bin/env python3
"""Audit captured MT6358 rails, consumer phandles and 5.10 ownership offline."""
import hashlib,json,re,runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
OLD=ROOT/'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad'
NEW=ROOT/'tools/kernel-source/upgrade-5.10'
def main():
 fdt=ROOT/'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
 nodes=runpy.run_path(str(ROOT/'tools/inspect-fdt.py'))['decode'](fdt.read_bytes())['nodes']
 driver=NEW/'drivers/regulator/mt6358-regulator.c'; text=driver.read_text()
 matches=set(re.findall(r'MT6358_(?:BUCK|LDO|LDO1|REG_FIXED)\("([^"]+)"',text))
 parent='/pwrap@1000d000/mt6358-pmic/mt6358regulator'
 rails={p:n for p,n in nodes.items() if p.startswith(parent+'/') and p.count('/')==4}
 def cells(n,k):return n.get(k,{}).get('cells',[])
 handles={cells(n,'phandle')[0]:p for p,n in rails.items()}
 consumers=[]
 for path,node in nodes.items():
  for prop,value in node.items():
   if prop.endswith('-supply') and value.get('cells') and value['cells'][0] in handles:
    consumers.append({'consumer':path,'property':prop,'provider':handles[value['cells'][0]],'phandle':value['cells'][0]})
 missing=set(p.rsplit('/',1)[1] for p in rails)-matches
 assert missing=={'ldo_va09'},missing
 assert matches==set(p.rsplit('/',1)[1] for p in rails)-missing
 # All register constants referenced in the 5.10 regulator implementation.
 newh=NEW/'include/linux/mfd/mt6358/registers.h'
 oldh=OLD/'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/upmu_hw.h'
 nvalues={m[1]:int(m[2],16) for m in re.finditer(r'^#define\s+(MT6358_\w+)\s+(0x[\da-fA-F]+)\s*$',newh.read_text(),re.M)}
 ovalues={m[1]:int(m[2],16) for m in re.finditer(r'^#define\s+(MT6358_\w+).*?PMIC_BASE\s*\+\s*(0x[\da-fA-F]+)',oldh.read_text(),re.M)}
 used=set(re.findall(r'\bMT6358_\w+\b',text)) & nvalues.keys()
 comparisons=[{'name':n,'new':nvalues[n],'old':ovalues.get(n),'equal':nvalues[n]==ovalues.get(n)} for n in sorted(used)]
 assert comparisons and all(v['equal'] for v in comparisons),[v for v in comparisons if not v['equal']]
 report={'fdt_sha256':hashlib.sha256(fdt.read_bytes()).hexdigest(),'matched_rails':len(matches),'unmatched_rails':sorted(missing),'register_comparisons':comparisons,'consumer_edges':consumers,'rails':[{'path':p,'name':n['regulator-name']['strings'][0],'phandle':cells(n,'phandle')[0],'minimum_uv':cells(n,'regulator-min-microvolt'),'maximum_uv':cells(n,'regulator-max-microvolt'),'driver_matched':p.rsplit('/',1)[1] in matches} for p,n in rails.items()], 'inputs':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [driver,newh,oldh]},'no_new_regulator_c_required_for_named_rails':True,'device_accessed':False,'limits':['Voltage selection/mode/runtime IRQ behavior not tested','VA09 requires separate fixed/secure-world ownership; no fake PMIC descriptor added','Unported consumers can cause regulator late-cleanup to disable bootloader rails; board boot gate remains closed','Stock regulator-fixed compatibility on handled rails must not create duplicate platform providers']}
 (ROOT/'evidence/kernel-upgrade/regulator-integration-audit.json').write_text(json.dumps(report,indent=2)+'\n')
 print(f'{len(matches)} stock rails match existing 5.10 driver; {len(comparisons)} register addresses match BSP; {len(consumers)} consumer edges resolved; VA09 separate')
if __name__=='__main__': main()
