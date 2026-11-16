#!/usr/bin/env python3
"""Locate unresolved type-attribute members without editing/relaxing old policy."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent

def forms(text):
 tokens=re.findall(r';[^\n]*|"(?:\\.|[^"\\])*"|[()]|[^\s();]+',text)
 stack=[];top=[]
 for token in tokens:
  if token.startswith(';'):continue
  if token=='(':
   value=[]
   if stack:stack[-1].append(value)
   else:top.append(value)
   stack.append(value)
  elif token==')':
   if not stack:raise ValueError('Unbalanced CIL')
   stack.pop()
  else:
   if not stack:raise ValueError('Unexpected CIL token')
   stack[-1].append(token)
 if stack:raise ValueError('Unclosed CIL')
 return top

def main():
 path=ROOT/'evidence/kernel-upgrade/modern-combined-policy-compile.json';record=json.loads(path.read_text())
 documents={name:forms(Path(name).read_text()) for name in record['input_hashes']}
 declared=set()
 for document in documents.values():
  for statement in document:
   if statement and statement[0] in {'type','typeattribute','typealias'}:declared.add(statement[1])
 def atoms(value):
  if isinstance(value,str):yield value
  else:
   for child in value:yield from atoms(child)
 missing=[]
 for name,document in documents.items():
  for statement in document:
   if statement and statement[0]=='typeattributeset':
    unknown=sorted(set(atoms(statement[2]))-declared-{'and','or','not','xor','all'})
    if unknown:missing.append({'file':name,'attribute':statement[1],'undefined_members':unknown})
 result={'compiler_returncode':record['returncode'],'unresolved_attribute_sets':missing,'undefined_type_names':sorted({name for m in missing for name in m['undefined_members']}),'policy_changed':False,'neverallow_disabled':False,'limits':['Direct top-level CIL type/attribute/alias inventory, not full semantic resolution','Imported stock system_ext includes old platform memberships; these require a source-level policy rebuild','The manual mapping fixture is not the final Soong compatibility mapping']}
 (ROOT/'evidence/kernel-upgrade/policy-import-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(len(result['undefined_type_names']),'undefined imported type names in',len(missing),'attribute sets; no rules changed')
if __name__=='__main__':main()
