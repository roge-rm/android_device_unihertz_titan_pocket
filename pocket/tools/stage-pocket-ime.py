#!/usr/bin/env python3
"""Prepare and replay-check a LatinIME integration patch, without editing baseline."""
import pocket_paths
import difflib,hashlib,json,subprocess,tempfile,os
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BASE=pocket_paths.platform_source()/'packages/inputmethods/LatinIME'
def main():
 (ROOT/'evidence/kernel-upgrade').mkdir(parents=True,exist_ok=True)
 relative='java/src/com/android/inputmethod/latin/LatinIME.java';old=(BASE/relative).read_text();new=old
 new=new.replace('    static final String TAG = LatinIME.class.getSimpleName();','    private org.lineageos.pocketinput.PocketInputRuntime mPocketInput;\n    static final String TAG = LatinIME.class.getSimpleName();',1)
 new=new.replace('        super.onCreate();\n\n        mHandler.onCreate();','        super.onCreate();\n        mPocketInput = new org.lineageos.pocketinput.PocketInputRuntime(this);\n\n        mHandler.onCreate();',1)
 new=new.replace('\n    public void onDestroy() {','\n    public void onDestroy() {\n        if (mPocketInput != null) mPocketInput.close();',1)
 new=new.replace('\n    public void onStartInput(final EditorInfo editorInfo, final boolean restarting) {','\n    public void onStartInput(final EditorInfo editorInfo, final boolean restarting) {\n        if (mPocketInput != null) mPocketInput.startEditor(getCurrentInputConnection(), editorInfo, false);',1)
 new=new.replace('\n    public void onFinishInput() {','\n    public void onFinishInput() {\n        if (mPocketInput != null) mPocketInput.finishEditor();',1)
 new=new.replace('\n    public boolean onKeyDown(final int keyCode, final KeyEvent keyEvent) {','\n    public boolean onKeyDown(final int keyCode, final KeyEvent keyEvent) {\n        if (mPocketInput != null && mPocketInput.onKeyDown(keyEvent)) return true;',1)
 new=new.replace('\n    public boolean onKeyUp(final int keyCode, final KeyEvent keyEvent) {','\n    public boolean onKeyUp(final int keyCode, final KeyEvent keyEvent) {\n        if (mPocketInput != null && mPocketInput.onKeyUp(keyEvent)) return true;',1)
 for call in ['onKeyDown','onKeyUp','startEditor','finishEditor','close']:
  assert new.count('mPocketInput.'+call+'(')==1,call
 assert new.count('new org.lineageos.pocketinput.PocketInputRuntime(this)')==1
 files={relative:(old,new)}
 name='java/Android.bp';old=(BASE/name).read_text();files[name]=(old,old.replace('    static_libs: [','    static_libs: [\n        "PocketInputEditorAdapter",',1))
 name='java/AndroidManifest.xml';old=(BASE/name).read_text();files[name]=(old,old.replace('    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>','    <uses-permission android:name="org.lineageos.pocketinput.permission.READ_SETTINGS"/>\n    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>',1))
 output=ROOT/'artifacts/build-overrides/LatinIME';output.mkdir(parents=True,exist_ok=True);diff=[];hashes={}
 for name,(old,new) in files.items():
  assert old!=new,name;p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(new)
  full='packages/inputmethods/LatinIME/'+name
  diff+=list(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+full,tofile='b/'+full))
  hashes[name]={'original':hashlib.sha256(old.encode()).hexdigest(),'modified':hashlib.sha256(new.encode()).hexdigest()}
 patch=ROOT/'patches/android/0002-pocket-input-latinime.patch';patch.write_text(''.join(diff))
 with tempfile.TemporaryDirectory(prefix='ime-patch-') as tmp:
  tree=Path(tmp)
  for name,(old,new) in files.items():
   p=tree/'packages/inputmethods/LatinIME'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(old)
  subprocess.run(['patch','--batch','--fuzz=0','-p1','-d',tmp,'-i',str(patch)],check=True,capture_output=True)
  for name,(old,new) in files.items():assert (tree/'packages/inputmethods/LatinIME'/name).read_text()==new
 (ROOT/'evidence/kernel-upgrade/pocket-ime-patch.json').write_text(json.dumps({'files':hashes,'patch':str(patch.relative_to(ROOT)),'replay_exact':True,'shared_source_modified':False,'runtime_tested':False,'limits':['LatinIME integration only; all its locales/resources retained','Global pad routing and ambient/HAL policy still require framework/device hooks','No image/product installation or typing qualification']},indent=2)+'\n');print('LatinIME integration patch replays exactly; shared source unchanged')
if __name__=='__main__':main()
