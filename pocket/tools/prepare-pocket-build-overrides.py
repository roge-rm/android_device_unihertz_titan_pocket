#!/usr/bin/env python3
"""Prepare the audit-view-only duplicate-module override from existing source."""
import pocket_paths
import difflib,hashlib,json,os,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BASE=pocket_paths.platform_source()
def main():
 original=BASE/'hardware/lineage/compat/Android.bp';text=original.read_text();canonical=(BASE/'prebuilts/misc/protobuf_vendorcompat/Android.bp').read_text()
 names=['libprotobuf-cpp-full-3.9.1-vendorcompat','libprotobuf-cpp-lite-3.9.1-vendorcompat','libprotobuf-cpp-full-21.12-vendorcompat','libprotobuf-cpp-lite-21.12-vendorcompat'];modified=text
 for name in names:
  assert 'name: "'+name+'"' in canonical,'Canonical provider missing: '+name
  match=re.search(r'(?m)^cc_prebuilt_library_shared \{\n\s*name: "'+re.escape(name)+r'",',modified);assert match,name
  end=modified.index('{',match.start())+1;depth=1
  while depth:depth+=(modified[end]=='{')-(modified[end]=='}');end+=1
  modified=modified[:match.start()]+modified[end:]
 out=ROOT/'artifacts/build-overrides';out.mkdir(parents=True,exist_ok=True);target=out/'hardware-lineage-compat.Android.bp';target.write_text(modified)
 patch=ROOT/'patches/android/0001-deduplicate-protobuf-audit-view.patch';patch.parent.mkdir(parents=True,exist_ok=True);patch.write_text(''.join(difflib.unified_diff(text.splitlines(True),modified.splitlines(True),fromfile='a/hardware/lineage/compat/Android.bp',tofile='b/hardware/lineage/compat/Android.bp')))
 evidence=ROOT/'evidence/kernel-upgrade';evidence.mkdir(parents=True,exist_ok=True);(evidence/'build-view-overrides.json').write_text(json.dumps({'removed_duplicate_modules':names,'reason':'Retain canonical prebuilts/misc/protobuf_vendorcompat definitions for source audit only','original_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'override_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'shared_source_modified':False},indent=2)+'\n');print('Four duplicate declarations removed only in private audit override')
if __name__=='__main__':main()
