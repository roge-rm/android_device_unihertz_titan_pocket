#!/usr/bin/env python3
"""Capture only the identified TP510 diagnostic ACM gadget and require the expected kernel release. Passive unless --echo-test is given.
The firstboot serial instead saves every enumeration to its own file and keeps running across disconnects."""
import argparse,errno,hashlib,json,os,re,runpy,select,signal,termios,threading,time,tty
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
# Reuse the stock-tested byte reader; its stock-banner interpretation is discarded.
READ=runpy.run_path(str(ROOT/'tools/capture-recovery-probe.py'),run_name='reader')['capture']
SERIAL='TP510-RAM'
def find_matches(sysroot=Path('/sys/class/tty'),devroot=Path('/dev'),serial=SERIAL):
 """Return (device node, USB device sysfs path) for each ttyACM of this gadget identity."""
 matches=[]
 for entry in sysroot.glob('ttyACM*'):
  for ancestor in entry.resolve().parents:
   try:identity=tuple((ancestor/f).read_text().strip() for f in ['idVendor','idProduct','serial'])
   except OSError:continue
   if identity==('1d6b','0104',serial):matches.append((devroot/entry.name,ancestor))
   break
 return matches

def find_port(sysroot=Path('/sys/class/tty'),devroot=Path('/dev'),serial=SERIAL):
 matches=find_matches(sysroot,devroot,serial)
 if len(matches)>1:raise RuntimeError('Multiple matching diagnostic gadgets; refuse an arbitrary port')
 return matches[0][0] if matches else None

# First-flash v2 variant (POCKET_DIAGNOSTIC_VARIANT=firstboot, or --usb-serial TP510-FIRSTBOOT-V2).
# The wrapper /init in the ROM boot image uses this exact USB serial; change both together.
FIRSTBOOT_SERIAL='TP510-FIRSTBOOT-V2'
VARIANT_SERIALS={'firstboot':FIRSTBOOT_SERIAL}

def find_enumeration(sysroot=Path('/sys/class/tty'),devroot=Path('/dev'),serial=FIRSTBOOT_SERIAL):
 """Return (port, key) or None. The key changes on every USB enumeration (the bus address is new each time)."""
 matches=find_matches(sysroot,devroot,serial)
 if len(matches)>1:raise RuntimeError('Multiple matching diagnostic gadgets; refuse an arbitrary port')
 if not matches:return None
 port,usb=matches[0]
 try:devnum=(usb/'devnum').read_text().strip()
 except OSError:devnum=''
 return port,(str(usb),devnum)

# Opt-in ACM input test for v8 and later. The diagnostic hashes each received
# line and never executes it; these lines are not commands.
ECHO_SERIALS=('TP510-RAM-V8','TP510-RAM-V9','TP510-RAM-V10','TP510-RAM-V11','TP510-RAM-V12')
ECHO_BODY=b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-titan-pocket-acm-input-check-'*6
def echo_lines():return [b'TP510-ECHO %d '%i+ECHO_BODY for i in range(3)]
assert all(line not in (b'reboot',b'reboot-bootloader') and b'\n' not in line for line in echo_lines())

def send_echo(fd,lines,delay=.5):
 """Write a bare newline to end any partial junk line on the phone, then each fixed line plus a newline; select() bounds the wait for a non-blocking port."""
 for line in [b'']+list(lines):
  data=line+b'\n';deadline=time.monotonic()+5
  while data:
   if time.monotonic()>=deadline:raise TimeoutError('ACM port did not accept the echo test')
   if not select.select([],[fd],[],.2)[1]:continue
   try:data=data[os.write(fd,data):]
   except BlockingIOError:continue
  time.sleep(delay)

def check_echo(data,serial,lines):
 # Line numbers are not compared: stray input before the test also opens the window and is hashed.
 found=[(int(a),int(b),c.decode()) for a,b,c in re.findall(rb'(?:^|\n)[^\n]*'+serial.encode()+rb': acm-echo line=(\d+) bytes=(\d+) sha256=([0-9a-f]{64})',data)]
 expected=[(len(line),hashlib.sha256(line).hexdigest()) for line in lines];logged={(b,h) for _,b,h in found}
 return {'sent_lines':len(lines),'sent_bytes':sum(len(x)+1 for x in lines),'expected':expected,'logged':found,'matched':all(e in logged for e in expected)}

def capture(fd,output,seconds,expected_release,serial=SERIAL,echo=False,echo_delay=1.0):
 writer=None
 if echo:
  if serial not in ECHO_SERIALS:raise ValueError('Echo test needs a v8 or later diagnostic')
  # Raw before anything arrives, so the host tty never echoes log bytes back to the phone.
  tty.setraw(fd,termios.TCSANOW);termios.tcflush(fd,termios.TCOFLUSH)
  writer=threading.Thread(target=send_echo,args=(fd,echo_lines()),kwargs={'delay':.5});writer.daemon=True
  timer=threading.Timer(echo_delay,writer.start);timer.start()
 result=READ(fd,output,seconds);data=output.read_bytes()
 if writer:timer.cancel();writer.join(5) if writer.is_alive() else None
 pattern=rb'(?:^|\n)'+serial.encode()+rb' Linux ([^\r\n ]+)'
 releases=[x.decode('ascii',errors='replace') for x in re.findall(pattern,data)]
 result.pop('stock_kernel_banner_seen',None)
 result.update(expected_kernel_release=expected_release,kernel_release=releases[0] if releases else None,diagnostic_kernel_banner_seen=expected_release in releases,commands_sent=False)
 if echo:result['echo_test']=check_echo(data,serial,echo_lines())
 return result

def read_enumeration(fd,data_file,times_file,deadline,stop,clock=time.monotonic):
 """Read one ACM enumeration until the device goes away, the deadline passes or stop is set; no bytes are sent.
 Each chunk also gets a line in times_file with its UTC time, byte offset and length."""
 digest=hashlib.sha256();total=0;head=b'';reason='deadline'
 while clock()<deadline and not stop.is_set():
  if not select.select([fd],[],[],.5)[0]:continue
  try:chunk=os.read(fd,65536)
  except OSError as e:
   if e.errno in (errno.EIO,errno.ENODEV):reason='disconnected';break
   if e.errno in (errno.EAGAIN,errno.EINTR):continue
   raise
  if not chunk:reason='disconnected';break
  data_file.write(chunk);data_file.flush()
  times_file.write(json.dumps({'utc':datetime.now(timezone.utc).isoformat(),'offset':total,'bytes':len(chunk)})+'\n');times_file.flush()
  if len(head)<200:head+=chunk[:200-len(head)]
  total+=len(chunk);digest.update(chunk)
 else:reason='stopped' if stop.is_set() else 'deadline'
 return {'bytes':total,'sha256':digest.hexdigest(),'end_reason':reason,'first_line':head.split(b'\n',1)[0][:120].decode('ascii','replace').strip()}

def open_raw(port):
 """Open read-only and make raw (no echo) as the very next call, closing the fd if that fails.
 A new ttyACM number starts with echo on (cdc-acm init_termios), so bytes that land between the two
 calls could still be echoed; later opens of that number keep the raw settings (tty_save_termios)."""
 fd=os.open(port,os.O_RDONLY|os.O_NOCTTY|os.O_NONBLOCK)
 try:tty.setraw(fd,termios.TCSANOW)
 except BaseException:os.close(fd);raise
 if termios.tcgetattr(fd)[3]&termios.ECHO:os.close(fd);raise termios.error('echo still on')
 return fd

def capture_firstboot(output,seconds,wait,serial=FIRSTBOOT_SERIAL,find=None,stop=None,expected_release=None):
 """Save every enumeration of the firstboot gadget to its own acm-NNN.log (plus acm-NNN.times.jsonl) in output.
 Keeps going across disconnects until seconds have passed since the start or stop is set, and writes
 capture.json after each enumeration. It never writes to the port; open_raw has the echo window."""
 find=find or (lambda:find_enumeration(serial=serial));stop=stop or threading.Event()
 started=time.monotonic();deadline=started+seconds;enums=[];last_key=None
 def write(reason):
  result={'variant':'firstboot','usb_serial':serial,'expected_kernel_release':expected_release,'enumerations':enums,'total_bytes':sum(e['bytes'] for e in enums),'end_reason':reason,'seconds':round(time.monotonic()-started,2),'commands_sent':False,'recorded_utc':datetime.now(timezone.utc).isoformat()}
  (output/'capture.json').write_text(json.dumps(result,indent=2)+'\n');return result
 while time.monotonic()<deadline and not stop.is_set():
  found=find()
  if not found:last_key=None
  if not found or found[1]==last_key:
   if not enums and time.monotonic()-started>=wait:return write('no gadget')
   time.sleep(.2);continue
  port,last_key=found;n=len(enums)+1;name='acm-%03d'%n
  try:fd=open_raw(port)
  except (OSError,termios.error):last_key=None;time.sleep(.2);continue  # node vanished between find and open
  begin=datetime.now(timezone.utc).isoformat();mono=time.monotonic()
  try:
   with (output/(name+'.log')).open('xb') as data,(output/(name+'.times.jsonl')).open('x') as times:
    os.chmod(output/(name+'.log'),0o600);info=read_enumeration(fd,data,times,deadline,stop)
  finally:os.close(fd)
  info.update(index=n,file=name+'.log',times_file=name+'.times.jsonl',port=str(port),start_utc=begin,end_utc=datetime.now(timezone.utc).isoformat(),seconds=round(time.monotonic()-mono,2))
  if expected_release:
   info['kernel_release_seen']=expected_release.encode() in (output/(name+'.log')).read_bytes()
  enums.append(info);write('running')
 return write('stopped' if stop.is_set() else 'deadline')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--kernel-release');p.add_argument('--usb-serial',choices=['TP510-RAM','TP510-RAM-V2','TP510-RAM-V3','TP510-RAM-V4','TP510-RAM-V5','TP510-RAM-V6','TP510-RAM-V7','TP510-RAM-V8','TP510-RAM-V9','TP510-RAM-V10','TP510-RAM-V11','TP510-RAM-V12',FIRSTBOOT_SERIAL],default=VARIANT_SERIALS.get(os.environ.get('POCKET_DIAGNOSTIC_VARIANT'),SERIAL));p.add_argument('--wait',type=float,default=90,help='firstboot: give up if no gadget has appeared after this long');p.add_argument('--seconds',type=float,default=40,help='firstboot: total run time, across disconnects');p.add_argument('--echo-test',action='store_true',help='v8 and later: send three fixed lines and check their logged SHA-256; never commands');a=p.parse_args()
 firstboot=a.usb_serial==FIRSTBOOT_SERIAL
 if firstboot:
  if a.echo_test:p.error('--echo-test is not available for the firstboot gadget')
  if not 0<a.wait<=3600 or not 0<a.seconds<=3600:p.error('Invalid wait/total duration (1 to 3600 seconds)')
  if a.kernel_release and not re.fullmatch(r'5\.10\.[A-Za-z0-9_.+\-]+',a.kernel_release):p.error('Expected release must identify the 5.10 kernel')
  a.output.mkdir(mode=0o700,parents=True,exist_ok=False);stop=threading.Event()
  for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:stop.set())
  print('Waiting for 1d6b:0104 / '+a.usb_serial+'; one file per enumeration, runs until '+str(int(a.seconds))+' s or a signal; passive capture only',flush=True)
  result=capture_firstboot(a.output,a.seconds,a.wait,a.usb_serial,stop=stop,expected_release=a.kernel_release);print(json.dumps(result,indent=2))
  if not result['total_bytes']:raise SystemExit('No bytes received from '+a.usb_serial+'; no commands sent')
  return
 if not a.kernel_release:p.error('--kernel-release is required for the diagnostic serials')
 if not 0<a.wait<=180 or not 0<a.seconds<=300:p.error('Invalid wait/capture duration')
 if a.echo_test and a.usb_serial not in ECHO_SERIALS:p.error('--echo-test needs a v8 or later diagnostic serial ('+', '.join(ECHO_SERIALS)+')')
 if not re.fullmatch(r'5\.10\.[A-Za-z0-9_.+\-]+',a.kernel_release):p.error('Expected release must identify the 5.10 diagnostic')
 a.output.mkdir(mode=0o700,parents=True,exist_ok=False);print('Waiting for 1d6b:0104 / '+a.usb_serial+('; echo test lines only, no commands' if a.echo_test else '; passive capture only'),flush=True);deadline=time.monotonic()+a.wait
 while True:
  port=find_port(serial=a.usb_serial)
  if port:break
  if time.monotonic()>=deadline:raise SystemExit('No matching gadget; no commands sent')
  time.sleep(.2)
 fd=os.open(port,os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK);tty.setraw(fd,termios.TCSANOW)
 try:result=capture(fd,a.output/'kernel.log',a.seconds,a.kernel_release,a.usb_serial,echo=a.echo_test)
 finally:os.close(fd)
 result.update(port=str(port),recorded_utc=datetime.now(timezone.utc).isoformat());(a.output/'capture.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 if not result['diagnostic_kernel_banner_seen']:raise SystemExit('Expected diagnostic kernel banner absent; test did not pass')
 if a.echo_test and not result['echo_test']['matched']:raise SystemExit('Echo test hashes did not match')
if __name__=='__main__':main()
