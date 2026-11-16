#!/usr/bin/env python3
"""Exercise libfdt reservation insertion on pre-LK and live trees, not LK code."""
import pocket_paths
import ctypes,hashlib,json,os,runpy,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
SOURCE=pocket_paths.platform_source()/'external/dtc/libfdt'
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Unknown diagnostic variant')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
def main():
 out=BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/lk-fixup-check');out.mkdir(parents=True,exist_ok=True)
 names=['fdt.c','fdt_ro.c','fdt_wip.c','fdt_sw.c','fdt_rw.c','fdt_strerror.c','fdt_empty_tree.c','fdt_addresses.c','fdt_overlay.c','fdt_check.c'];library=out/'libfdt-check.so'
 command=['cc','-shared','-fPIC','-O2','-I'+str(SOURCE),*[str(SOURCE/n) for n in names],'-o',str(library)];subprocess.run(command,check=True)
 lib=ctypes.CDLL(str(library));lib.fdt_open_into.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];lib.fdt_path_offset.argtypes=[ctypes.c_void_p,ctypes.c_char_p];lib.fdt_add_subnode.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_char_p]
 decode=runpy.run_path(str(ROOT/'tools/inspect-fdt.py'))['decode'];live=ROOT/'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb';nodes=decode(live.read_bytes())['nodes'];reserved=sorted([p.rsplit('/',1)[1] for p in nodes if p.startswith('/reserved-memory/mblock-')]);assert len(reserved)==19
 cases=[]
 for path,duplicate in [(BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/board/diagnostic.dtb'),False),(live,True)]:
  blob=path.read_bytes();buffer=ctypes.create_string_buffer(len(blob)+65536);assert lib.fdt_open_into(blob,buffer,len(buffer))==0
  codes=[]
  for name in reserved:
   parent=lib.fdt_path_offset(buffer,b'/reserved-memory');assert parent>=0
   code=lib.fdt_add_subnode(buffer,parent,name.encode());codes.append(code)
   assert (code==-2) if duplicate else (code>=0),(name,code)
  cases.append({'input':str(path),'sha256':hashlib.sha256(blob).hexdigest(),'insertion_count':len(codes),'all_expected_results':True,'expected':'FDT_ERR_EXISTS for live tree' if duplicate else 'Fresh insertion succeeds'})
 record={'cases':cases,'command':command,'source_hashes':{str(SOURCE/n):hashlib.sha256((SOURCE/n).read_bytes()).hexdigest() for n in names},'limits':['Native libfdt behavior only; not execution/emulation of LK','Insertion names taken from one captured boot; real reservations are regenerated each boot','Other LK property/overlay fixups and physical kernel placement remain independently checked or unqualified'],'device_accessed':False}
 (ROOT/('evidence/kernel-upgrade/diagnostic-lk-fixup-check'+SUFFIX+'.json')).write_text(json.dumps(record,indent=2)+'\n');print('19 fresh reservation insertions succeed; all 19 captured-live insertions reject with FDT_ERR_EXISTS')
if __name__=='__main__':main()
