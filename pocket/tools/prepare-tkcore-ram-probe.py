#!/usr/bin/env python3
"""Prepare isolated TK query materials, without packaging or shared-init mutation.

No kernel/ramdisk/image packaging, phone access, DT edits or shared-init mutation.
"""
import pocket_paths
import argparse, hashlib, json, os, shutil, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=BULK/'artifacts/tkcore-ram-probe-materials');args=p.parse_args()
out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
# Reuse the reviewed pre-LK tree byte for byte. The driver self-registers tzdrv;
# adding a trustkernel DT node or a static SHM reservation would invent an ABI.
tree=BULK/'artifacts/diagnostic-5.10-v4/board/diagnostic.dtb'
sha=digest(tree);shutil.copyfile(tree,out/'diagnostic.dtb')
for name in ('feature_query.h','query_main.c'):
 shutil.copyfile(ROOT/'kernel-upgrade/tkcore-probe'/name,out/name)
shutil.copyfile(ROOT/'configs/kernel-tkcore-ram-probe.fragment',out/'kernel.fragment')
compiler=pocket_paths.ndk_bin() / 'aarch64-linux-android30-clang'
command=[str(compiler),'-std=gnu11','-Wall','-Wextra','-Werror','-static','-O2',str(out/'query_main.c'),'-o',str(out/'tkcore-feature-query')]
subprocess.run(command,check=True)
guardcheck=subprocess.run(['python3',str(ROOT/'tools/check-tkcore-shm-guard.py')],text=True,capture_output=True,check=True)
check=subprocess.run(['python3',str(ROOT/'tools/check-tkcore-feature-probe.py')],text=True,capture_output=True,check=True)
assert digest(tree)==sha and digest(out/'diagnostic.dtb')==sha
report={'ready_for_packaging':False,'phone_access':False,'shared_init_changed':False,'tree_modified':False,'tree_source':str(tree),'tree_sha256':sha,'compiler_command':command,'feature_query_test':json.loads(check.stdout),'shm_guard_test':json.loads(guardcheck.stdout),'runtime_gate':'Static SHM ownership is established and guarded; combined parent-init integration and target execution remain separate checks. Enabling TKcore performs secure negotiation and, after guard acceptance, mapping and RoT before userspace.','files':{x.name:digest(x) for x in out.iterdir() if x.is_file() and x.name!='report.json'}}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
