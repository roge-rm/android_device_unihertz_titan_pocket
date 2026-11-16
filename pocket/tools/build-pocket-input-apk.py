#!/usr/bin/env python3
"""Build and verify a local test settings APK; never installs or publishes it."""
import hashlib,json,os,subprocess,tempfile,zipfile
import pocket_paths
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SDK=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')))
def main():
 (ROOT/'evidence/kernel-upgrade').mkdir(parents=True,exist_ok=True)
 package=pocket_paths.INPUT_PACKAGE;out=ROOT/'artifacts/pocket-input';out.mkdir(parents=True,exist_ok=True)
 tools=SDK/'build-tools/36.1.0';android=SDK/'platforms/android-36/android.jar'
 sources=sorted(package.glob('src/**/*.java'))+sorted(package.glob('android/**/*.java'))+sorted(package.glob('settings/**/*.java'))
 with tempfile.TemporaryDirectory(prefix='pocket-settings-') as tmp:
  p=Path(tmp);classes=p/'classes';classes.mkdir();dex=p/'dex';dex.mkdir()
  subprocess.run(['javac','--release','11','-Xlint:all','-Werror','-cp',str(android),'-d',str(classes)]+list(map(str,sources)),check=True)
  subprocess.run([str(tools/'d8'),'--lib',str(android),'--min-api','30','--output',str(dex)]+list(map(str,sorted(classes.rglob('*.class')))),check=True)
  unsigned=out/'PocketInputSettings-unsigned.apk'
  subprocess.run([str(tools/'aapt2'),'link','-I',str(android),'--manifest',str(package/'settings/AndroidManifest.xml'),'-o',str(unsigned),'--min-sdk-version','30','--target-sdk-version','36'],check=True)
  with zipfile.ZipFile(unsigned,'a') as z:
   info=zipfile.ZipInfo('classes.dex',date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,(dex/'classes.dex').read_bytes())
  aligned=out/'PocketInputSettings-aligned.apk';subprocess.run([str(tools/'zipalign'),'-f','4',str(unsigned),str(aligned)],check=True)
 key=out/'local-test-signing.jks'
 if not key.exists():
  subprocess.run(['keytool','-genkeypair','-keystore',str(key),'-storepass','android','-keypass','android','-alias','pocket-test','-keyalg','RSA','-keysize','2048','-validity','10000','-dname','CN=Pocket local test only'],check=True,capture_output=True);key.chmod(0o600)
 signed=out/'PocketInputSettings-local-test.apk'
 subprocess.run([str(tools/'apksigner'),'sign','--ks',str(key),'--ks-key-alias','pocket-test','--ks-pass','pass:android','--key-pass','pass:android','--out',str(signed),str(aligned)],check=True)
 verify=subprocess.run([str(tools/'apksigner'),'verify','--verbose',str(signed)],check=True,capture_output=True,text=True)
 record={'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources+[package/'settings/AndroidManifest.xml']},'artifacts':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [unsigned,aligned,signed]},'sdk_inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [android,tools/'aapt2',tools/'d8']},'signature_verification':verify.stdout,'installed':False,'published':False,'signing':'Local disposable test certificate, not a platform/release key','limits':['SDK build, not Soong product build or UI/runtime test','Settings/provider only; keyboard service, IME hook and authorized lighting backend need integration']}
 (ROOT/'evidence/kernel-upgrade/pocket-input-apk-build.json').write_text(json.dumps(record,indent=2)+'\n');print('Settings APK compiled, aligned and signature-verified; not installed')
if __name__=='__main__':main()
