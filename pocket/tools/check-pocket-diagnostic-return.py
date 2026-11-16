#!/usr/bin/env python3
"""Exercise the read-only collector with host ADB fixtures and hostile archives."""
import base64,io,json,runpy,shlex,tarfile,tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent.parent
C=runpy.run_path(str(ROOT/'tools/collect-pocket-diagnostic-return.py'),run_name='collector')
def archive(name='console-ramoops',body=b'Linux version 5.10.257-test (builder)\n',kind=tarfile.REGTYPE):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w') as t:
  info=tarfile.TarInfo(name);info.type=kind;info.size=len(body) if kind==tarfile.REGTYPE else 0;t.addfile(info,io.BytesIO(body) if info.size else None)
 return out.getvalue()
def main():
 cases=0
 for content,expected in [(b'Linux version 5.10.257-test (builder)\n',True),(b'<6>[    0.000000] Linux version 5.10.257-test (builder)\n',True),(b'Linux version 5.10.257-test-other\n',False),(b'bootargs=Linux version 5.10.257-test\n',False)]:
  assert C['inspect_archive'](archive(body=content),'5.10.257-test')[0]['matching_kernel_banner']==expected;cases+=1
 for name,kind in [('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('device',tarfile.CHRTYPE)]:
  try:C['inspect_archive'](archive(name=name,kind=kind),'5.10.257-test')
  except ValueError:cases+=1
  else:raise AssertionError('Accepted hostile member')
 with tempfile.TemporaryDirectory() as tmp:
  for scenario in ['okay','changed_recovery','nonempty_bcb','root_denied','bad_archive','pstore_failed','stock_banner','invalid_transport','crlf_transport']:
   calls=[]
   def fake(args,**kwargs):
    assert args[:4]==['fixture-adb','-s','fixture','exec-out'] and len(args)==5;remote=shlex.split(args[4]);assert remote[:2]==['su','-c'] and len(remote)==3;assert remote[2].endswith(' | base64');command=remote[2][:-9];calls.append(command)
    responses={'tar -C /sys/fs/pstore -cf - .':archive(body=b'Linux version 4.14-stock\n') if scenario=='stock_banner' else b'bad' if scenario=='bad_archive' else archive(),'getprop ro.boot.bootreason':b'PMIC_cold_reboot\n','uname -a':b'Linux stock\n','id':b'uid=2000(shell)\n' if scenario=='root_denied' else b'uid=0(root)\n','getprop ro.agui.real_version':b'Titan_pocket_20230105_1943\n','getprop sys.boot_completed':b'1\n','sha256sum /dev/block/by-name/boot /dev/block/by-name/recovery':(('a'*64)+'  /dev/block/by-name/boot\n'+(('c' if scenario=='changed_recovery' else 'b')*64)+'  /dev/block/by-name/recovery\n').encode(),'dd if=/dev/block/by-name/para bs=32 count=1 2>/dev/null | base64':base64.b64encode(b'x'*32 if scenario=='nonempty_bcb' else b'\0'*32)}
    assert command in responses,'Unexpected device command'
    encoded=base64.b64encode(responses[command])
    if scenario=='invalid_transport' and command.startswith('tar '):encoded=b'*** invalid transport ***'
    if scenario=='crlf_transport':encoded=b'\r\n'.join(encoded[i:i+76] for i in range(0,len(encoded),76))
    return SimpleNamespace(returncode=1 if scenario=='pstore_failed' and command.startswith('tar ') else 0,stdout=encoded,stderr=b'')
   with patch('subprocess.run',side_effect=fake):result=C['collect']('fixture-adb','fixture',Path(tmp)/scenario,'5.10.257-test','a'*64,'b'*64)
   assert calls[0].startswith('tar ') and len(calls)==8
   assert result['stock_return_verified']==(scenario not in ['changed_recovery','root_denied'])
   assert result['boot_control_empty']==(scenario!='nonempty_bcb')
   assert result['collection_complete']==(scenario not in ['bad_archive','pstore_failed','invalid_transport'])
   assert not result['device_writes'] and not result['reboots_requested'];cases+=1
 print(str(cases)+' collector/archive cases passed; fixture verified exact read-only commands and pstore-first order')
if __name__=='__main__':main()
