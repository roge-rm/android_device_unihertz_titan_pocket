#!/usr/bin/env python3
"""Inventory saved split-CIL contracts; optional diagnostic-only absent assertions."""
import argparse,collections,hashlib,json,re
from pathlib import Path

def forms(text):
 tokens=re.findall(r';[^\n]*|"(?:\\.|[^"\\])*"|[()]|[^\s();]+',text);stack=[];top=[]
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

def atoms(value):
 if isinstance(value,str):yield value
 else:
  for child in value:yield from atoms(child)
def encode(value):return value if isinstance(value,str) else '('+' '.join(encode(v) for v in value)+')'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inventory(documents,extension):
 declared={s[1] for d in documents.values() for s in d if s and s[0] in ['type','typeattribute','typealias']}
 ext=documents[extension];own_types={s[1] for s in ext if s and s[0]=='type'}
 defined_elsewhere={s[1] for name,d in documents.items() if name!=extension for s in d if s and s[0]=='type'}
 endpoints=[]
 for line,s in enumerate(ext,1):
  if s and s[0] in ['allow','neverallow','dontaudit','auditallow','typetransition','allowx','neverallowx']:
   missing=sorted({a for x in s[1:3] for a in atoms(x)}-declared-{'self','and','or','not','xor','all'})
   if missing:endpoints.append({'form':line,'kind':s[0],'missing':missing,'statement':s})
 refs={name:set(atoms(d)) for name,d in documents.items() if name!=extension}
 memberships=collections.defaultdict(set);versioned_aliases=collections.defaultdict(set)
 for name,d in documents.items():
  for s in d:
   if s and s[0]=='typeattributeset' and len(s)==3 and isinstance(s[2],list) and all(isinstance(x,str) for x in s[2]):
    for t in s[2]:
     if t in own_types:
      memberships[t].add(s[1])
      if s[2]==[t] and s[1].endswith('_30_0'):versioned_aliases[t].add(s[1])
 contracts=[]
 for t in sorted(own_types):
  aliases=versioned_aliases[t];consumers={name:sorted(({t}|aliases)&a) for name,a in refs.items() if ({t}|aliases)&a}
  contracts.append({'type':t,'also_declared_elsewhere':t in defined_elsewhere,'attribute_memberships':sorted(memberships[t]),'versioned_aliases':sorted(aliases),'other_fragment_references':consumers})
 generated={s[1] for s in ext if s[0]=='typeattribute' and s[1].startswith('base_typeattr_')}
 other_attrs={s[1] for name,d in documents.items() if name!=extension for s in d if s[0]=='typeattribute'}
 missing={x for row in endpoints for x in row['missing']}
 missing_refs=[{'fragment':name,'form':i,'kind':s[0],'missing':sorted(set(atoms(s))&missing)} for name,d in documents.items() for i,s in enumerate(d,1) if set(atoms(s))&missing]
 return {'generated_attribute_collisions':sorted(generated&other_attrs),'missing_type_references':missing_refs,'extension_forms':len(ext),'extension_operation_counts':dict(collections.Counter(s[0] for s in ext)),'extension_types':len(own_types),'extension_unique_types':len(own_types-defined_elsewhere),'unresolved_rule_endpoints':endpoints,'type_contracts':contracts}

def project_absent_assertions(documents,extension,report):
 # Diagnostic only: absent domains contribute no members to assertion-only sets.
 missing={x for row in report['unresolved_rule_endpoints'] for x in row['missing']}
 candidates={row['form'] for row in report['unresolved_rule_endpoints'] if row['kind'] in ['neverallow','neverallowx']}
 if any(row['kind'] not in ['neverallow','neverallowx'] for row in report['unresolved_rule_endpoints']):raise ValueError('Unresolved grant/transition; projection forbidden')
 edits={}
 for name,d in documents.items():
  for line,s in enumerate(d,1):
   if not set(atoms(s))&missing or (name==extension and line in candidates):continue
   if name!=extension or s[0]!='typeattributeset':raise ValueError('Missing type has other references; projection forbidden')
   attr=s[1]
   for other_name,other_doc in documents.items():
    for other in other_doc:
     if attr not in set(atoms(other)):continue
     if other_name!=extension or (other[0] not in ['neverallow','neverallowx','typeattribute','expandtypeattribute'] and other!=s):raise ValueError('Affected set has nonassertion uses; projection forbidden')
   expr=s[2];negative=len(expr)==2 and expr[0]=='not' and isinstance(expr[1],list)
   members=expr[1] if negative else expr
   if not all(isinstance(x,str) and x not in ['and','or','not','xor','all'] for x in members):raise ValueError('Unsupported compound expression')
   kept=[x for x in members if x not in missing]
   if not kept:raise ValueError('Empty projected expression')
   edits[line]=[s[0],attr,['not',kept] if negative else kept]
 original=documents[extension];projected=[edits.get(line,s) for line,s in enumerate(original,1) if line not in candidates]
 grants={'allow','allowx','auditallow','dontaudit','dontauditx','typetransition','typechange','typemember'}
 assert [s for s in projected if s[0] in grants]==[s for s in original if s[0] in grants]
 report['diagnostic_assertion_set_edits']=[{'form':i,'before':original[i-1],'after':after} for i,after in edits.items()]
 return projected

def rename_private_attributes(documents,extension):
 original=documents[extension]
 names={s[1] for s in original if s[0]=='typeattribute' and re.fullmatch(r'base_typeattr_[0-9]+',s[1])}
 for fragment,document in documents.items():
  if fragment==extension:continue
  local={s[1] for s in document if s[0]=='typeattribute'}
  if (names&set(atoms(document)))-local:raise ValueError('Generated attributes have external references without their own declaration; rename forbidden')
 replacements={name:name.replace('base_typeattr_','base_typeattr_pocket_oem_') for name in sorted(names)}
 if set(replacements.values())&set(atoms(list(documents.values()))):raise ValueError('Rename destination already used')
 def visit(value):return replacements.get(value,value) if isinstance(value,str) else [visit(v) for v in value]
 renamed=visit(original)
 inverse={v:k for k,v in replacements.items()}
 def undo(value):return inverse.get(value,value) if isinstance(value,str) else [undo(v) for v in value]
 assert undo(renamed)==original
 return renamed,replacements

def service_evidence(stock_system,documents,extension,report):
 types={s[1] for s in documents[extension] if s[0]=='type'}
 labels=[];inputs={};file_labels=[]
 for base in [stock_system/'etc/selinux',stock_system/'system_ext/etc/selinux']:
  for path in sorted(base.glob('*_contexts')):
   text=path.read_text();inputs[str(path)]=digest(path)
   for line,textline in enumerate(text.splitlines(),1):
    if textline.lstrip().startswith('#'):continue
    match=re.search(r'u:(?:object_r|r):([^:]+):s0',textline)
    if not match:continue
    label=match[1]
    if label in types:labels.append({'file':str(path),'line':line,'type':label,'key':textline.split()[0]})
    if path.name.endswith('file_contexts'):file_labels.append((textline.split()[0],label))
 transitions={}
 for s in documents[extension]:
  if len(s)==5 and s[0]=='typetransition' and s[1]=='init' and s[3]=='process':transitions.setdefault(s[2],[]).append(s[4])
 services=[]
 for base in [stock_system/'etc/init',stock_system/'system_ext/etc/init']:
  for path in sorted(base.rglob('*.rc')):
   text=path.read_text();inputs[str(path)]=digest(path)
   for line,textline in enumerate(text.splitlines(),1):
    parts=textline.split()
    if len(parts)<3 or parts[0]!='service':continue
    binary=parts[2];matched=set()
    for pattern,label in file_labels:
     try:
      if re.fullmatch(pattern,binary):matched.add(label)
     except re.error:continue
    domains=sorted({t for label in matched for t in transitions.get(label,[])})
    if domains or any(label in types for label in matched):services.append({'file':str(path),'line':line,'service':parts[1],'binary':binary,'exec_labels':sorted(matched),'extension_domains':domains})
 report['stock_context_references']=labels;report['stock_init_services_with_extension_labels']=services;report['context_init_input_hashes']=inputs

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compile-record',type=Path,required=True);p.add_argument('--extension',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--project-absent-assertions',type=Path);p.add_argument('--rename-private-attributes',type=Path);p.add_argument('--stock-system',type=Path);a=p.parse_args()
 record=json.loads(a.compile_record.read_text());documents={}
 for name,expected in record['input_hashes'].items():
  path=Path(name).resolve();assert digest(path)==expected,'Input changed: '+str(path);documents[str(path)]=forms(path.read_text())
 extension=str(a.extension.resolve());assert extension in documents
 report=inventory(documents,extension);report.update(input_hashes={name:digest(Path(name)) for name in documents},source_sha256=digest(Path(__file__)),device_accessed=False,shipping_policy=False,limits=['Direct CIL inventory; no runtime enforcement or service-retention decision','Mappings and all fragments must come from the intended build','Optional absent-assertion projection is diagnostic only; not an installation policy'])
 if a.stock_system:service_evidence(a.stock_system,documents,extension,report)
 if a.rename_private_attributes:
  renamed,replacements=rename_private_attributes(documents,extension);dest=a.rename_private_attributes;dest.parent.mkdir(parents=True,exist_ok=True)
  if dest.exists():raise ValueError('Refuse to overwrite renamed fixture')
  dest.write_text('\n'.join(encode(s) for s in renamed)+'\n');report['attribute_rename']={'path':str(dest),'sha256':digest(dest),'replacements':replacements,'invertible_ast_transform':True,'rules_removed':0}
 if a.project_absent_assertions:
  projected=project_absent_assertions(documents,extension,report);dest=a.project_absent_assertions;dest.parent.mkdir(parents=True,exist_ok=True)
  if dest.exists():raise ValueError('Refuse to overwrite projection')
  dest.write_text('\n'.join(encode(s) for s in projected)+'\n');report['diagnostic_projection']={'path':str(dest),'sha256':digest(dest),'all_grant_and_transition_forms_preserved':True,'omitted_assertions':report['unresolved_rule_endpoints']}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(str(report['extension_types'])+' OEM types ('+str(report['extension_unique_types'])+' private); '+str(len(report['unresolved_rule_endpoints']))+' unresolved rule endpoints')
if __name__=='__main__':main()
