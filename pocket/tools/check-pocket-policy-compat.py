#!/usr/bin/env python3
"""Host controls for invertible CIL renaming and diagnostic projection refusal."""
import runpy
from pathlib import Path
C=runpy.run_path(str(Path(__file__).with_name('audit-pocket-policy-compat.py')),run_name='audit')
F=C['forms']
def main():
 cases=0
 for bad in ['(type x','(type x))','x']:
  try:F(bad)
  except ValueError:cases+=1
  else:raise AssertionError('Invalid CIL accepted')
 d={'modern':F('(type domain_t) (type file_t) (typeattribute base_typeattr_1)'), 'oem':F('(type oem_t) (typeattribute base_typeattr_1) (typeattributeset base_typeattr_1 (oem_t)) (allow oem_t file_t (file (read))) (neverallow removed_t file_t (file (write)))')}
 renamed,names=C['rename_private_attributes'](d,'oem');assert names=={'base_typeattr_1':'base_typeattr_pocket_oem_1'} and renamed[-2:]==d['oem'][-2:];cases+=1
 for additional in ['(allow base_typeattr_1 file_t (file (read)))','(typeattribute base_typeattr_pocket_oem_1)']:
  bad=dict(d);bad['vendor']=F(additional)
  try:C['rename_private_attributes'](bad,'oem')
  except ValueError:cases+=1
  else:raise AssertionError('Unsafe rename accepted')
 projection=C['project_absent_assertions'](d,'oem',C['inventory'](d,'oem'));assert projection==d['oem'][:-1];cases+=1
 for extra in ['(allow removed_t file_t (file (read)))','(typetransition removed_t file_t process oem_t)','(typeattributeset attr (removed_t))','(typeattributeset attr (not (oem_t removed_t))) (allow attr file_t (file (write)))','(typeattributeset attr (and (oem_t) (not (removed_t))))']:
  bad=dict(d);bad['oem']=d['oem']+F(extra)
  try:C['project_absent_assertions'](bad,'oem',C['inventory'](bad,'oem'))
  except ValueError:cases+=1
  else:raise AssertionError('Unsafe projection accepted')
 good=dict(d);good['oem']=d['oem']+F('(typeattribute attr) (typeattributeset attr (not (oem_t removed_t))) (neverallow attr file_t (file (write)))');report=C['inventory'](good,'oem');projected=C['project_absent_assertions'](good,'oem',report);assert ['typeattributeset','attr',['not',['oem_t']]] in projected and len(report['diagnostic_assertion_set_edits'])==1;cases+=1
 # External use of a missing name blocks projection even when local endpoints look safe.
 bad=dict(d);bad['vendor']=F('(typeattributeset other (removed_t))')
 try:C['project_absent_assertions'](bad,'oem',C['inventory'](bad,'oem'))
 except ValueError:cases+=1
 else:raise AssertionError('External missing-name reference accepted')
 d={'oem':F('(type private_t) (type public_t) (typeattributeset domain (private_t public_t))'), 'mapping':F('(type public_t) (typeattribute public_t_30_0) (typeattributeset public_t_30_0 (public_t))'), 'vendor':F('(allow public_t_30_0 domain (process (getattr)))')}
 contracts=C['inventory'](d,'oem')['type_contracts'];by_name={v['type']:v for v in contracts}
 assert 'vendor' in by_name['public_t']['other_fragment_references'] and 'vendor' not in by_name['private_t']['other_fragment_references'];cases+=1
 print(str(cases)+' parser, private-attribute rename and diagnostic refusal cases passed')
if __name__=='__main__':main()
