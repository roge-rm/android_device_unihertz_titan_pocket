#!/usr/bin/env python3
"""Check the observed LK bootargs property ABI with real libfdt, no device access."""
import pocket_paths
import ctypes,hashlib,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v3')
if VARIANT not in ('v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Bootargs check requires corrected v3, v4, v5, v6, v7, v8, v9, v10, v11 or v12')
def main():
 libpath=BULK/('artifacts/diagnostic-5.10-'+VARIANT+'/lk-fixup-check/libfdt-check.so');lib=ctypes.CDLL(str(libpath));ptr=ctypes.c_void_p
 lib.fdt_open_into.argtypes=[ptr,ptr,ctypes.c_int];lib.fdt_path_offset.argtypes=[ptr,ctypes.c_char_p];lib.fdt_getprop.argtypes=[ptr,ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(ctypes.c_int)];lib.fdt_getprop.restype=ptr
 lib.fdt_setprop.argtypes=[ptr,ctypes.c_int,ctypes.c_char_p,ptr,ctypes.c_int];lib.fdt_delprop.argtypes=[ptr,ctypes.c_int,ctypes.c_char_p];lib.fdt_del_node.argtypes=[ptr,ctypes.c_int]
 def prepare(path):
  blob=path.read_bytes();buf=ctypes.create_string_buffer(len(blob)+65536);assert lib.fdt_open_into(blob,buf,len(buf))==0;return buf
 def probe(buf):
  node=lib.fdt_path_offset(buf,b'/chosen');length=ctypes.c_int();p=lib.fdt_getprop(buf,node,b'bootargs',ctypes.byref(length)) if node>=0 else None
  data=ctypes.string_at(p,length.value) if p and length.value>=0 else None
  return {'chosen_present':node>=0,'getprop_nonnull':bool(p),'property_bytes':length.value if p else None,'empty_c_string':data==b'\0'}
 old=BULK/'artifacts/diagnostic-5.10-v2/board/diagnostic.dtb';stock=BULK/'artifacts/diagnostic-5.10-v2/board/stock-applied.dtb';new=BULK/('artifacts/diagnostic-5.10-'+VARIANT+'/board/diagnostic.dtb');cases=[]
 for name,path,accepted,empty in [('stock_reference',stock,True,False),('failed_v2',old,False,False),('corrected_'+VARIANT,new,True,True)]:
  observed=probe(prepare(path));assert observed['getprop_nonnull']==accepted and observed['empty_c_string']==empty,(name,observed);cases.append({'name':name,'observed':observed})
 for name,data,accepted,empty in [('absent',None,False,False),('zero_length',b'',True,False),('unterminated',b'abc',True,False),('embedded_nul',b'a\0b\0',True,False),('stale_arguments',b'console=ttyS0\0',True,False),('empty_string',b'\0',True,True)]:
  buf=prepare(new);node=lib.fdt_path_offset(buf,b'/chosen')
  if data is None:assert lib.fdt_delprop(buf,node,b'bootargs')==0
  else:assert lib.fdt_setprop(buf,node,b'bootargs',ctypes.create_string_buffer(data),len(data))==0
  observed=probe(buf);assert observed['getprop_nonnull']==accepted and observed['empty_c_string']==empty,(name,observed);cases.append({'name':name,'observed':observed})
 buf=prepare(new);node=lib.fdt_path_offset(buf,b'/chosen');assert lib.fdt_del_node(buf,node)==0;observed=probe(buf);assert not observed['chosen_present'] and not observed['getprop_nonnull'];cases.append({'name':'missing_chosen','observed':observed})
 record={'cases':cases,'input_hashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [old,stock,new,libpath,Path(__file__)]},'native_evidence':'Retained LK panic bootargs.c:98; REA FUN_56028114 reads /chosen/bootargs and panics on NULL','device_accessed':False,'limits':['Real libfdt property semantics and diagnostic string contract; not LK emulation','A present empty C string addresses the observed assertion; later LK/kernel behavior remains unqualified','Malformed non-NULL strings are rejected by diagnostic preparation; LK only checks pointer before formatting']}
 (ROOT/('evidence/kernel-upgrade/lk-bootargs-check'+('' if VARIANT=='v3' else '-'+VARIANT)+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(str(len(cases))+' LK bootargs ABI/string controls passed; failed v2 reproduced, corrected '+VARIANT+' passes')
if __name__=='__main__':main()
