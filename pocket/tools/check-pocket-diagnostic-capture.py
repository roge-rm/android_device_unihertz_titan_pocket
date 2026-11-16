#!/usr/bin/env python3
"""Check real passive-reader fragmentation and strict USB identity selection."""
import hashlib,json,os,pty,runpy,select,tempfile,termios,threading,time,tty
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
C=runpy.run_path(str(ROOT/'tools/capture-pocket-diagnostic.py'),run_name='capture')
def echo_checks():
 """A simulated v9 device reads the PTY master, hashes each line and logs it back."""
 import re
 serial='TP510-RAM-V9';release='5.10.257-titanpocket-ramdiag-v9';cases=0
 with tempfile.TemporaryDirectory() as tmp:
  for corrupt,immediate in [(False,False),(True,False),(False,True)]:
   # The phone starts with 75 junk bytes in its line buffer; the leading newline must isolate them.
   # The slave starts with default termios (ECHO on); capture must make it raw
   # before the device writes, or the device would read its own log back.
   # Immediate: the port is raw at open, as main() does, and the banner is already
   # queued for the host when capture starts; its flush must not drop it.
   master,slave=pty.openpty();received=bytearray();output=Path(tmp)/f'echo{int(corrupt)}{int(immediate)}.log'
   banner=b'\n'+serial.encode()+b' Linux '+release.encode()+b'\n'
   if immediate:
    tty.setraw(slave,termios.TCSANOW);os.write(master,banner)
    assert select.select([slave],[],[],2)[0],'Banner never reached the host side'
   def device():
    if not immediate:time.sleep(.05);os.write(master,banner)
    line=bytearray(b'x'*75);count=0;end=time.monotonic()+3
    while time.monotonic()<end and count<4:
     ready=select.select([master],[],[],.1)[0]
     if not ready:continue
     for byte in os.read(master,4096):
      received.append(byte)
      if byte!=10:line.append(byte);continue
      count+=1;digest=hashlib.sha256(bytes(line)).hexdigest()
      if corrupt and count==3:digest='0'*64
      os.write(master,f'6,{count},0,-;{serial}: acm-echo line={count} bytes={len(line)} sha256={digest}\n'.encode());line.clear()
   thread=threading.Thread(target=device);thread.start()
   result=C['capture'](slave,output,2.5,release,serial,echo=True,echo_delay=.1);thread.join()
   lines=C['echo_lines']()
   assert bytes(received)==b'\n'+b''.join(x+b'\n' for x in lines),'Echo test sent bytes other than a bare newline and the fixed lines'
   assert all(not re.fullmatch(rb'reboot(-bootloader)?',x) for x in lines);cases+=1
   assert result['echo_test']['matched']==(not corrupt) and result['commands_sent'] is False;cases+=1
   assert result['diagnostic_kernel_banner_seen'] and output.read_bytes().startswith(banner),'Banner lost from the capture';cases+=1
   os.close(slave);os.close(master)
 # Stray input logged as earlier echo lines must not hide the fixed lines.
 lines=C['echo_lines']();log=b'6,1,0,-;'+serial.encode()+b': acm-echo line=1 bytes=7 sha256='+b'1'*64+b'\n'
 log+=b''.join(b'6,%d,0,-;%s: acm-echo line=%d bytes=%d sha256=%s\n'%(i+2,serial.encode(),i+2,len(x),hashlib.sha256(x).hexdigest().encode()) for i,x in enumerate(lines))
 assert C['check_echo'](log,serial,lines)['matched'];cases+=1
 assert not C['check_echo'](log.replace(hashlib.sha256(lines[2]).hexdigest().encode(),b'2'*64),serial,lines)['matched'];cases+=1
 try:C['capture'](0,Path('/nonexistent'),.1,release,'TP510-RAM-V7',echo=True)
 except ValueError:cases+=1
 else:raise AssertionError('Echo test accepted a pre-v8 serial')
 return cases

def firstboot_checks():
 """A fake phone that enumerates three times on PTYs, with gaps, a stale sysfs entry and no commands expected."""
 cases=0;serial=C['FIRSTBOOT_SERIAL'];assert serial=='TP510-FIRSTBOOT-V2'
 with tempfile.TemporaryDirectory() as tmp:
  root=Path(tmp);sysroot=root/'tty';sysroot.mkdir();usb=root/'usb0';(usb/'ttyACM0').mkdir(parents=True)
  for field,value in [('idVendor','1d6b'),('idProduct','0104'),('serial',serial),('devnum','7')]:(usb/field).write_text(value)
  (sysroot/'ttyACM0').symlink_to(usb/'ttyACM0')
  port,key=C['find_enumeration'](sysroot,root/'dev',serial);assert port==root/'dev'/'ttyACM0' and key[1]=='7';(usb/'devnum').write_text('8')
  assert C['find_enumeration'](sysroot,root/'dev',serial)[1]!=key;cases+=1  # new bus address, new key
  assert C['find_enumeration'](sysroot,root/'dev','TP510-RAM-V12') is None;cases+=1
  payloads=[b'TP510-FIRSTBOOT-V2 banner\n6,1,0,-;Linux version 5.10.257-test\n\x00\xff',b'',b'again\nsecond enumeration\n']
  state={'cur':None};sent=[];stray=[]
  def phone():
   for i,data in enumerate(payloads):
    master,slave=pty.openpty();tty.setraw(slave,termios.TCSANOW);state['cur']=(os.ttyname(slave),('bus',str(i)))
    time.sleep(.3)
    for j in range(0,len(data),7):os.write(master,data[j:j+7]);time.sleep(.01)
    time.sleep(.4)
    if select.select([master],[],[],0)[0]:stray.append(os.read(master,100))
    os.close(master);sent.append(data)
    time.sleep(.8)  # stale: the same key stays visible after the port hangs up
    os.close(slave);state['cur']=None;time.sleep(.3)
  thread=threading.Thread(target=phone);thread.start();out=root/'cap'
  t0=time.monotonic();stop=threading.Event()
  def stopper():
   thread.join();time.sleep(.5);stop.set()
  threading.Thread(target=stopper).start()
  out.mkdir();result=C['capture_firstboot'](out,30,5,serial,find=lambda:(Path(state['cur'][0]),state['cur'][1]) if state['cur'] else None,stop=stop,expected_release='5.10.257-test');thread.join()
  assert result['end_reason']=='stopped' and time.monotonic()-t0<25;cases+=1
  names=sorted(x.name for x in out.iterdir());assert names==['acm-001.log','acm-001.times.jsonl','acm-002.log','acm-002.times.jsonl','acm-003.log','acm-003.times.jsonl','capture.json'],names;cases+=1
  for i,data in enumerate(payloads,1):
   assert (out/('acm-%03d.log'%i)).read_bytes()==data,i;cases+=1
   rows=[json.loads(x) for x in (out/('acm-%03d.times.jsonl'%i)).read_text().splitlines()]
   assert sum(r['bytes'] for r in rows)==len(data) and [r['offset'] for r in rows]==sorted(r['offset'] for r in rows) and all(r['utc'] for r in rows);cases+=1
  saved=json.loads((out/'capture.json').read_text())
  assert [e['bytes'] for e in saved['enumerations']]==[len(x) for x in payloads] and saved['total_bytes']==sum(map(len,payloads));cases+=1
  assert [e['end_reason'] for e in saved['enumerations']]==['disconnected']*3 and saved['commands_sent'] is False and not stray;cases+=1
  assert [e.get('kernel_release_seen') for e in saved['enumerations']]==[True,False,False];cases+=1
  assert saved['enumerations'][0]['sha256']==hashlib.sha256(payloads[0]).hexdigest() and saved['enumerations'][0]['first_line']=='TP510-FIRSTBOOT-V2 banner';cases+=1
  # No gadget at all: gives up after the wait and says so.
  out2=root/'cap2';out2.mkdir();t0=time.monotonic();r=C['capture_firstboot'](out2,30,.5,serial,find=lambda:None)
  assert r['end_reason']=='no gadget' and r['enumerations']==[] and time.monotonic()-t0<5;cases+=1
  # The total timeout ends a capture that is still connected.
  master,slave=pty.openpty();tty.setraw(slave,termios.TCSANOW);os.write(master,b'still here\n')
  out3=root/'cap3';out3.mkdir();t0=time.monotonic();r=C['capture_firstboot'](out3,1.5,5,serial,find=lambda:(Path(os.ttyname(slave)),('bus','x')))
  assert r['end_reason']=='deadline' and r['enumerations'][0]['end_reason']=='deadline' and (out3/'acm-001.log').read_bytes()==b'still here\n' and 1.4<time.monotonic()-t0<4;cases+=1
  os.close(master);os.close(slave)
  # A port with default termios (echo on): open_raw leaves it raw and read-only, and nothing comes back.
  import fcntl
  master,slave=pty.openpty();assert termios.tcgetattr(slave)[3]&termios.ECHO
  fd=C['open_raw'](os.ttyname(slave))
  assert not termios.tcgetattr(fd)[3]&(termios.ECHO|termios.ICANON) and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY;cases+=1
  os.write(master,b'log line\n');time.sleep(.2);assert os.read(fd,100)==b'log line\n'
  assert not select.select([master],[],[],.2)[0],'echoed to the phone';cases+=1
  os.close(fd);os.close(master);os.close(slave)
  # Not a tty: setraw fails and the fd it opened is closed.
  plain=root/'not-a-tty';plain.write_text('');before=sorted(os.listdir('/proc/self/fd'))
  try:C['open_raw'](plain)
  except termios.error:pass
  else:raise AssertionError('open_raw accepted a regular file')
  assert sorted(os.listdir('/proc/self/fd'))==before,'fd left open';cases+=1
  # capture_firstboot on a cooked port: the phone sends once the port is raw and gets nothing back.
  master,slave=pty.openpty();stray=[]
  def cooked_phone():
   deadline=time.monotonic()+5
   while termios.tcgetattr(slave)[3]&termios.ECHO and time.monotonic()<deadline:time.sleep(.01)
   os.write(master,b'cooked port\n');time.sleep(.4)
   if select.select([master],[],[],0)[0]:stray.append(os.read(master,100))
  thread=threading.Thread(target=cooked_phone);thread.start()
  out4=root/'cap4';out4.mkdir();r=C['capture_firstboot'](out4,1.5,5,serial,find=lambda:(Path(os.ttyname(slave)),('bus','y')));thread.join()
  assert (out4/'acm-001.log').read_bytes()==b'cooked port\n' and not stray and r['commands_sent'] is False;cases+=1
  os.close(master);os.close(slave)
 return cases

def main():
 cases=0
 for serial in ['TP510-RAM','TP510-RAM-V2','TP510-RAM-V3','TP510-RAM-V4','TP510-RAM-V5','TP510-RAM-V6','TP510-RAM-V7','TP510-RAM-V8','TP510-RAM-V9','TP510-RAM-V10','TP510-RAM-V11','TP510-RAM-V12']:
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);sysroot=root/'tty';sysroot.mkdir();devroot=root/'dev'
   for i,entry_serial in enumerate(['TP-RECOVERY',serial,'TP510-RAM' if serial=='TP510-RAM-V2' else 'TP510-RAM-V2']):
    usb=root/f'usb{i}';(usb/f'ttyACM{i}').mkdir(parents=True)
    for field,value in [('idVendor','1d6b'),('idProduct','0104'),('serial',entry_serial)]: (usb/field).write_text(value)
    (sysroot/f'ttyACM{i}').symlink_to(usb/f'ttyACM{i}')
   assert C['find_port'](sysroot,devroot,serial)==devroot/'ttyACM1';cases+=1
   (root/'usb2/serial').write_text(serial)
   try:C['find_port'](sysroot,devroot,serial)
   except RuntimeError:cases+=1
   else:raise AssertionError('Accepted two matching gadgets')
   (root/'usb1/serial').write_text('other');(root/'usb2/serial').write_text('other');assert C['find_port'](sysroot,devroot,serial) is None;cases+=1
   release='5.10.257-titanpocket-ramdiag'
   for i,payload in enumerate([b'\n'+serial.encode()+b' Linux '+release.encode()+b'\nlog\x00\xff\n',b'\nTP-RECOVERY Linux 4.14.186-stock\n',b'\n'+serial.encode()+b' Linux 5.10.1-wrong\n',b'noise '+serial.encode()+b' Linux '+release.encode()+b'\n']):
    master,slave=pty.openpty();output=root/f'capture{i}.log'
    def writer(data=payload):
     time.sleep(.02)
     for byte in data:os.write(master,bytes([byte]))
    thread=threading.Thread(target=writer);thread.start()
    result=C['capture'](slave,output,.15,release,serial);thread.join()
    assert output.read_bytes()==payload and result['sha256']==hashlib.sha256(payload).hexdigest()
    assert result['diagnostic_kernel_banner_seen']==(i==0) and result['commands_sent'] is False
    os.set_blocking(master,False)
    try:assert not os.read(master,1024),'Reader transmitted data'
    except BlockingIOError:pass
    os.close(slave);os.close(master);cases+=1
 echo_cases=echo_checks();firstboot_cases=firstboot_checks()
 record={'cases':cases,'echo_cases':echo_cases,'firstboot_cases':firstboot_cases,'result':'Strict identity, duplicate/no-match, fragmented bytes and exact-release banner checks passed; opt-in echo test sends only the fixed lines and checks their hashes; the firstboot variant saves each enumeration to its own file across disconnects and stops on timeout or signal','commands_sent':False,'source_hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'tools/capture-pocket-diagnostic.py',ROOT/'tools/capture-recovery-probe.py']},'device_accessed':False,'limits':['PTY/synthetic USB topology only; not physical serial enumeration or modem-line behavior']}
 (ROOT/'evidence/kernel-upgrade/diagnostic-capture-check.json').write_text(json.dumps(record,indent=2)+'\n');print(f'{cases} diagnostic passive-capture cases, {echo_cases} echo-test cases and {firstboot_cases} firstboot cases passed')
if __name__=='__main__':main()
