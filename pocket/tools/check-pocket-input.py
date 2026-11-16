#!/usr/bin/env python3
"""Compile and execute the owned keyboard core without a device or Android build."""
import hashlib,json,subprocess,tempfile,zipfile,os
import pocket_paths
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent

def main():
 (ROOT/'evidence/kernel-upgrade').mkdir(parents=True,exist_ok=True)
 package=pocket_paths.INPUT_PACKAGE
 core=sorted(package.glob('src/**/*.java'))
 sources=core+sorted(package.glob('tests/**/*.java'))
 native=sorted(package.glob('pad/pad_gesture*'))
 android=sorted(package.glob('android/**/*.java'))
 sdk=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')))/'platforms/android-36/android.jar'
 with tempfile.TemporaryDirectory(prefix='pocket-api26-') as old:
  subprocess.run(['javac','-source','8','-target','8','-bootclasspath',str(sdk.parent.parent/'android-26/android.jar'),'-Xlint:all,-options','-Werror','-d',old]+[str(p) for p in core],check=True)
 with tempfile.TemporaryDirectory(prefix='pocket-input-') as tmp:
  subprocess.run(['javac','--release','11','-Xlint:all','-Werror','-d',tmp]+[str(p) for p in sources],check=True)
  result=subprocess.run(['java','-ea','-cp',tmp,'org.lineageos.pocketinput.KeyboardControllerTest'],capture_output=True,text=True,check=True)
  guard=subprocess.run(['java','-ea','-cp',tmp,'org.lineageos.pocketinput.PadKeyGuardTest'],capture_output=True,text=True,check=True)
  # Framework key policy (light, FUNC1/FUNC2 presses, pad key guard) for PocketKeyHooks.
  keys=subprocess.run(['java','-ea','-cp',tmp,'org.lineageos.pocketinput.PocketKeyPolicyTest'],capture_output=True,text=True,check=True)
  # Display mode table, custom limits and confirm or revert for PocketDisplayMode.
  modes=subprocess.run(['java','-ea','-cp',tmp,'org.lineageos.pocketinput.DisplayModesTest'],capture_output=True,text=True,check=True)
  # Swipe-scroll gesture of the native pad daemon, built and run on the host.
  pad=package/'pad'
  subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror','-o',tmp+'/pad_gesture_test',str(pad/'pad_gesture.cpp'),str(pad/'pad_gesture_test.cpp')],check=True)
  gesture=subprocess.run([tmp+'/pad_gesture_test'],capture_output=True,text=True,check=True)
  result.stdout+=guard.stdout+keys.stdout+modes.stdout+gesture.stdout
  subprocess.run(['javac','--release','11','-Xlint:all','-Werror','-cp',str(sdk)+':'+tmp,'-d',tmp]+[str(p) for p in android],check=True)
  artifact=ROOT/'artifacts/pocket-input/PocketInput.jar';artifact.parent.mkdir(parents=True,exist_ok=True)
  with zipfile.ZipFile(artifact,'w',compression=zipfile.ZIP_DEFLATED) as archive:
   for p in sorted(Path(tmp).rglob('*.class')):
    if p.name.startswith(('KeyboardControllerTest','PadKeyGuardTest','PocketKeyPolicyTest','DisplayModesTest')):continue
    item=zipfile.ZipInfo(str(p.relative_to(tmp)),date_time=(1980,1,1,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED
    archive.writestr(item,p.read_bytes())
 record={'result':result.stdout.strip(),'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources+android+native},'android_sdk_adapter_compile':str(sdk),'artifact':{'path':str(artifact.relative_to(ROOT)),'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()},'core_light_api26_compile':True,'android_platform_build':False,'device_accessed':False,'limits':['Host-tested core and SDK-compiled adapter only: no input service, IME integration, settings UI or hardware backend installed','No optical latency, battery, international IME or application compatibility qualification']}
 (ROOT/'evidence/kernel-upgrade/pocket-input-core-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
