#!/usr/bin/env python3
"""Remove only duplicate platform attribute contributions from a private fixture."""
import hashlib,json,runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent

def main():
 forms=runpy.run_path(str(ROOT/'tools/audit-pocket-policy-imports.py'))['forms']
 base=ROOT/'firmware/installed-20230105/rootfs/system/system/etc/selinux/plat_sepolicy.cil'
 original=ROOT/'firmware/installed-20230105/rootfs/system/system/system_ext/etc/selinux/system_ext_sepolicy.cil'
 def memberships(document):
  values={}
  for statement in document:
   if statement and statement[0]=='typeattributeset' and all(isinstance(t,str) for t in statement[2]):values.setdefault(statement[1],set()).update(statement[2])
  return values
 base_document=forms(base.read_text());base_sets=memberships(base_document);base_forms={json.dumps(s,separators=(',',':')) for s in base_document};out=[];changes=[];duplicates={}
 for statement in forms(original.read_text()):
  if json.dumps(statement,separators=(',',':')) in base_forms:
   duplicates[statement[0]]=duplicates.get(statement[0],0)+1
   continue
  if statement and statement[0]=='typeattributeset' and all(isinstance(t,str) for t in statement[2]):
   before=statement[2];members=[name for name in before if name not in base_sets.get(statement[1],set())]
   if members!=before:
    changes.append({'attribute':statement[1],'duplicate_members_removed':len(before)-len(members)})
    if not members:continue
    statement=[statement[0],statement[1],members]
  out.append(statement)
 def encode(value):return value if isinstance(value,str) else '('+' '.join(encode(v) for v in value)+')'
 destination=ROOT/'artifacts/m2/policy/system_ext-delta.cil';destination.write_text('\n'.join(map(encode,out))+'\n')
 result={'inputs':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [base,original]},'output':str(destination.relative_to(ROOT)),'changes':changes,'exact_duplicate_forms_removed':duplicates,'method':'Subtract exact duplicate stock-platform forms and exact duplicate flat attribute members; no unique rule or compound set removed','stock_equivalence_verified':False,'publicly_exported':False,'device_accessed':False,'limits':['Private compile fixture only; not installed or shipping policy','Must prove stock recompilation equivalence before interpreting modern results']}
 (ROOT/'evidence/kernel-upgrade/system-ext-policy-delta.json').write_text(json.dumps(result,indent=2)+'\n');print(len(changes),'duplicate platform attribute contributions removed from private fixture; stock-equivalence check pending')
if __name__=='__main__':main()
