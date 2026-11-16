#!/usr/bin/env python3
"""Run the v13 attended trial checks over adb and pull every result into a timestamped folder.
Run it where the phone is attached (adb root is used). --dry-run needs no device: it prints each command and runs the cpufreq logic on canned readings.
Sections run in the order below; --only picks some. Manual steps are printed as prompts and wait for Enter."""
import argparse,json,re,shlex,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
CPU='/sys/devices/system/cpu/cpufreq'
MCU='/sys/devices/platform/c530000.mcucfg'
THERM='/sys/devices/platform/1100b000.therm_ctrl/sensors'
OPPS=[1417000,1248000,1014000,793000]   # kHz, the OPP tables in CPUFREQ_PORT.md
POLICIES=[('policy0','LL',0),('policy4','L',1)]   # cpufreq policy, cluster, index of its PLL in fmeter and pll_rates
TOL=.03                                 # relative difference accepted between a measured and an expected kHz
SECTIONS={}  # name -> (function, description), in run order

def section(name,desc):
 def wrap(f):SECTIONS[name]=(f,desc);return f
 return wrap

class Stop(Exception):pass

class Trial:
 """Device access and output. All device commands go through sh(); dry-run prints them and answers from a canned model."""
 def __init__(s,a,out):
  s.a=a;s.out=out;s.dry=a.dry_run;s.setspeed={};s.gov={};s.log=[]
  base=['adb']+(['-s',a.serial] if a.serial else [])
  s.adb=base
 def wrap(s,argv):
  # With --ssh the whole adb command runs on that host.
  return ['ssh',s.a.ssh,shlex.join(argv)] if s.a.ssh else argv
 def run(s,argv,timeout=60,check=False):
  if s.dry:print('[dry-run]',shlex.join(argv));return ''
  r=subprocess.run(s.wrap(argv),stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout)
  if check and r.returncode:raise SystemExit('Command failed: '+shlex.join(argv)+'\n'+r.stderr)
  return r.stdout+r.stderr
 def sh(s,cmd,timeout=60):
  """Run a shell command on the phone as root; returns stdout and stderr."""
  if s.dry:print('[dry-run] adb shell',cmd);return s.canned(cmd)
  return s.run(s.adb+['shell',cmd],timeout)
 def canned(s,cmd):
  m=re.search(r'echo (\d+) > \S*(policy\d)/scaling_setspeed',cmd)
  if m:s.setspeed[m.group(2)]=int(m.group(1))
  m=re.search(r'echo (\w+) > \S*(policy\d)/scaling_governor',cmd)
  if m:s.gov[m.group(2)]=m.group(1)
  ll=s.setspeed.get('policy0',1417000);l=s.setspeed.get('policy4',1417000)
  if 'cat '+MCU+'/fmeter' in cmd:return 'abist 22 (armpll_ll) %d kHz\nabist 20 (armpll_l) %d kHz\n'%(ll,l)
  if 'cat '+MCU+'/pll_rates' in cmd:
   return ''.join('%s con1 0x0 postdiv 1 pll %d kHz mcucfg 0x0 sel 1 ckdiv 8 out %d kHz\n'%(n,f,f) for n,f in [('armpll_ll',ll),('armpll_l',l),('ccipll',1196000)])
  if 'cat /sys/class/regulator' in cmd or 'regulator' in cmd and 'name' in cmd:return 'vproc11 800000\nvproc12 825000\nvsram_proc11 900000\nvsram_proc12 900000\n'
  return ''
 def save(s,name,text):
  p=s.out/name
  if s.dry:return p
  p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 def get(s,name,cmd,timeout=60):
  """Run cmd on the phone and save the output as a file in the results folder."""
  text=s.sh(cmd,timeout);s.save(name,text);return text
 def prompt(s,text):
  print('\n>> '+text,flush=True)
  if s.dry or s.a.yes:print('   (continuing without waiting)');return
  input('   Enter when done: ')
 def note(s,text):
  print(text,flush=True);s.log.append(text)
 def sleep(s,t):
  if not s.dry:time.sleep(t)

# ---- cpufreq (CPUFREQ_PORT.md, first attended test) ----
def khz(text,pattern):return [int(x) for x in re.findall(pattern,text)]
def read_clocks(t):
 """Return (fmeter kHz list, pll_rates PLL kHz list, pll_rates out kHz list) and save raw text."""
 f=t.sh('cat '+MCU+'/fmeter',10);p=t.sh('cat '+MCU+'/pll_rates',10)
 return f,p,khz(f,r'(\d+) kHz'),khz(p,r' pll (\d+) kHz'),khz(p,r' out (\d+) kHz')
def close(a,b):return b>0 and abs(a-b)/b<=TOL
def regs(t):
 return t.sh('for r in /sys/class/regulator/regulator.*; do echo $(cat $r/name) $(cat $r/microvolts); done 2>&1 | grep -E "vproc|vsram"')
def thermal(t):
 return t.sh('for z in /sys/class/thermal/thermal_zone*; do echo $(cat $z/type) $(cat $z/temp); done; cat '+THERM+' 2>&1')
def restore(t):
 for pol,_,_ in POLICIES:t.sh('echo performance > %s/%s/scaling_governor'%(CPU,pol))
def check_step(t,label,expect):
 """Record fmeter, pll_rates, regulators and thermal; raise Stop on any mismatch. expect is {cluster index: kHz}."""
 f,p,fm,pl,out=read_clocks(t);r=regs(t);th=thermal(t)
 t.save('cpufreq/%s.txt'%label,'== fmeter\n%s\n== pll_rates\n%s\n== regulators\n%s\n== thermal\n%s\n'%(f,p,r,th))
 if t.dry and not fm:return
 problems=[]
 if len(fm)<2 or len(pl)<2:problems.append('could not read two fmeter and two pll_rates values (format changed?)')
 else:
  for idx,want in expect.items():
   if not close(fm[idx],pl[idx]) and not close(fm[idx],out[idx]):problems.append('cluster %d: fmeter %d kHz differs from pll_rates pll %d / out %d kHz'%(idx,fm[idx],pl[idx],out[idx]))
   if not close(fm[idx],want):problems.append('cluster %d: fmeter %d kHz differs from the requested %d kHz'%(idx,fm[idx],want))
 volts=dict(re.findall(r'^(\S+) (\d+)$',r,re.M))
 if volts.get('vproc12') and int(volts['vproc12'])<825000:problems.append('vproc12 %s uV is below 825000'%volts['vproc12'])
 if problems:
  t.note('MISMATCH at '+label+': '+'; '.join(problems));raise Stop(label)
 t.note('%s: ok, fmeter %s kHz, regulators %s'%(label,fm,' '.join('%s=%s'%kv for kv in sorted(volts.items()))))

@section('cpufreq','performance first, fmeter against pll_rates, userspace stepping each OPP, schedutil last')
def cpufreq(t):
 t.get('cpufreq/dmesg-cpufreq.txt','dmesg | grep -iE "mcucfg|cpufreq|\\[FH\\]|opp"')
 for pol,_,_ in POLICIES:
  t.get('cpufreq/%s-info.txt'%pol,'cd %s/%s && for f in scaling_available_frequencies scaling_available_governors scaling_governor scaling_cur_freq; do echo $f: $(cat $f); done'%(CPU,pol))
 t.get('cpufreq/cooling-devices.txt','for c in /sys/class/thermal/cooling_device*; do echo $c $(cat $c/type) $(cat $c/cur_state) $(cat $c/max_state); done')
 try:
  for pol,_,_ in POLICIES:t.sh('echo performance > %s/%s/scaling_governor'%(CPU,pol))
  check_step(t,'1-performance-top',{0:OPPS[0],1:OPPS[0]})
  for pol,_,_ in POLICIES:t.sh('echo userspace > %s/%s/scaling_governor'%(CPU,pol))
  # Both clusters step together to the same OPP; the A53s step first, as vproc12 must stay at or above 825 mV.
  for n,opp in enumerate(OPPS,2):
   for pol,_,_ in POLICIES:t.sh('echo %d > %s/%s/scaling_setspeed'%(opp,CPU,pol))
   t.sleep(.5);check_step(t,'%d-userspace-%d'%(n,opp),{0:opp,1:opp})
  for pol,_,_ in POLICIES:t.sh('echo %d > %s/%s/scaling_setspeed'%(OPPS[0],CPU,pol))
  for pol,_,_ in POLICIES:t.sh('echo schedutil > %s/%s/scaling_governor'%(CPU,pol))
  t.sleep(2);t.get('cpufreq/schedutil-idle.txt','cat %s/policy0/scaling_cur_freq %s/policy4/scaling_cur_freq; cat %s/fmeter; cat %s/pll_rates'%(CPU,CPU,MCU,MCU))
  t.note('schedutil idle readings saved (frequencies there are not checked, they follow load)')
 except Stop:
  t.note('Stopped: restoring performance on both policies.')
  raise
 finally:
  restore(t);t.get('cpufreq/governors-after.txt','cat %s/policy0/scaling_governor %s/policy4/scaling_governor'%(CPU,CPU))
  t.note('performance governor restored on policy0 and policy4')

# ---- gauge and charger (CHARGER_PORT.md, "CAR write and battery status") ----
GAUGE_POLL='''for p in /sys/class/power_supply/*; do n=${p##*/}; echo "$n cap=$(cat $p/capacity 2>/dev/null) volt=$(cat $p/voltage_now 2>/dev/null) cur=$(cat $p/current_now 2>/dev/null) status=$(cat $p/status 2>/dev/null) temp=$(cat $p/temp 2>/dev/null) online=$(cat $p/online 2>/dev/null) type=$(cat $p/type 2>/dev/null)"; done
echo "charger input_current=$(cat /sys/devices/platform/charger/input_current 2>/dev/null) chg1_current=$(cat /sys/devices/platform/charger/chg1_current 2>/dev/null) adc_vbus=$(cat /sys/devices/platform/charger/ADC_Charger_Voltage 2>/dev/null)"
for r in $(find /sys/devices -name registers -path "*oz8806*" 2>/dev/null); do echo "gauge registers $r"; head -c 2000 $r; done'''
POLL_FILE='/data/local/tmp/v13-charger-poll.txt'
def start_poll(t,seconds,every):
 """The cable is the adb link, so the phone logs by itself and the log is read once the cable is back."""
 import base64
 script='end=$(( $(date +%%s) + %d ))\nwhile [ $(date +%%s) -lt $end ]; do\necho "--- $(date -u +%%H:%%M:%%S)"\n%s\nsleep %d\ndone\necho "--- poll done"\n'%(seconds,GAUGE_POLL,every)
 b=base64.b64encode(script.encode()).decode()
 t.sh('echo %s | base64 -d > /data/local/tmp/v13-charger-poll.sh; rm -f %s'%(b,POLL_FILE))
 t.sh('nohup sh /data/local/tmp/v13-charger-poll.sh > %s 2>&1 < /dev/null &'%POLL_FILE,20)
def wait_adb(t,seconds=180):
 """Wait for adb after the cable comes back, then make sure it is root."""
 if t.dry:return True
 try:t.run(t.adb+['wait-for-device'],seconds);t.run(t.adb+['root'],30);t.run(t.adb+['wait-for-device'],60)
 except subprocess.TimeoutExpired:t.note('adb did not come back within %d s'%seconds);return False
 return t.sh('id -u').strip()=='0'

@section('charger','gauge and charger polled over a plug and unplug prompt')
def charger(t):
 t.get('charger/dmesg-charger.txt','dmesg | grep -iE "oz8806|mtk_charger|mt6370|CAR|charger|battery|gauge"')
 t.get('charger/uevents.txt','for p in /sys/class/power_supply/*; do echo == $p; cat $p/uevent; done')
 # Phases are about poll_seconds each; host times of each prompt are kept to split the phone's log.
 total=3*t.a.poll_seconds+240;marks=[]
 t.prompt('Charger test: the phone logs by itself for about %d s. Keep the cable IN until the next prompt.'%total)
 start_poll(t,total,t.a.poll_every)
 def mark(label):marks.append('%s %s'%(datetime.now(timezone.utc).strftime('%H:%M:%S'),label))
 t.prompt('UNPLUG the cable now and leave it out for about %d s (baseline). Press Enter when you unplug.'%t.a.poll_seconds);mark('unplugged-before')
 t.prompt('PLUG the cable in, press Enter as you do. Status should read Charging straight away.');mark('plugged')
 if not t.dry:time.sleep(t.a.poll_seconds)
 t.prompt('UNPLUG the cable now, press Enter as you do. Status should read Discharging straight away.');mark('unplugged-after')
 t.prompt('After about %d s, plug the cable back in for adb and press Enter.'%t.a.poll_seconds);mark('replugged')
 ok=wait_adb(t)
 if not ok:raise Stop('no root adb after the charger test')
 if not t.dry:
  end=time.time()+total+600
  while time.time()<end:
   try:
    if 'poll done' in t.sh('tail -1 %s'%POLL_FILE):break
   except Exception:pass
   time.sleep(5)
  else:print('poll done not seen before the deadline, saving what is there')
 text='\n'.join('# '+m for m in marks)+'\n'+t.sh('cat %s'%POLL_FILE,60)
 t.save('charger/poll.txt',text)
 t.prompt('Optional: with 4307 to 4347 mV and 230 to 490 mA in, the level should be about 88 to 92 %, not 100. Check capacity against voltage in charger/poll.txt.')

# ---- keyboard and touchpad (KEYBOARD_PORT.md, TOUCHPAD_PORT.md) ----
KEY_GROUPS=['Q to P (top row)','A to Del','Z to Enter','Shift, Alt, Sym, Space','Back, recents, the (6,1) key, Home','Volume up and down','The side key']
@section('input','getevent -lp, dumpsys input, guided key press capture, pad_scroll and pocket_padd')
def inputs(t):
 t.get('input/getevent-lp.txt','getevent -lp')
 t.get('input/dumpsys-input.txt','dumpsys input',90)
 t.get('input/idc-and-kl-files.txt','ls -l /system/usr/idc /system/usr/keylayout /system/usr/keychars 2>&1 | head -80')
 t.get('input/dumpsys-input-grep.txt','dumpsys input | grep -iE "mtk-pad|mtk-kpd|aw9523|pocket-pad|KeyboardType|DeviceMode|Mapper|IdcFile|KeyLayoutFile|KeyCharacterMapFile"')
 t.get('input/pad-state.txt','echo pad_scroll=$(getprop persist.sys.pocket.pad_scroll); echo init.svc.pocket_padd=$(getprop init.svc.pocket_padd); echo pad_guard=$(getprop sys.pocket.pad_guard); ps -A | grep -i pocket_padd')
 t.get('input/pad-load-status.txt','cat /sys/module/pad_setting/parameters/pad_load_status')
 t.get('input/logcat-pad.txt','logcat -d | grep -iE "pocket_padd|pocket-pad|mtk-pad|avc: denied" | tail -200')
 t.prompt('Key capture: getevent -lt starts now. At each prompt press every key in the group once, then Enter.')
 log=t.out/'input'/'getevent-keys.txt';marks=[]
 proc=None
 if t.dry:print('[dry-run] adb shell getevent -lt > '+str(log))
 else:
  log.parent.mkdir(parents=True,exist_ok=True)
  proc=subprocess.Popen(t.wrap(t.adb+['shell','getevent -lt']),stdin=subprocess.DEVNULL,stdout=log.open('w'),stderr=subprocess.STDOUT)
 try:
  for g in KEY_GROUPS:
   marks.append('%s %s'%(time.time(),g));t.prompt('Press: '+g)
  marks.append('%s done'%time.time())
 finally:
  if proc:proc.terminate();proc.wait(10)
 t.save('input/key-groups.txt','\n'.join(marks)+'\n')
 t.prompt('Scroll check: in Pocket Keyboard choose Scroll and save, then swipe over the keys in Settings. Press Enter after.')
 t.get('input/pad-state-after-scroll.txt','echo pad_scroll=$(getprop persist.sys.pocket.pad_scroll); echo init.svc.pocket_padd=$(getprop init.svc.pocket_padd); echo pad_guard=$(getprop sys.pocket.pad_guard); getevent -lp | grep -A12 pocket-pad-scroll')
 t.get('input/logcat-pad-after.txt','logcat -d | grep -iE "pocket_padd|Reading /dev/input|avc: denied" | tail -200')

# ---- system state ----
@section('system','SSPM state, thermal sensors, online CPUs, bootreason, dmesg and logcat dumps')
def system(t):
 t.get('system/sspm.txt','dmesg | grep -iE "sspm"; ls /sys/devices/platform | grep -i sspm; for d in /sys/devices/platform/*sspm*; do echo == $d; ls $d; done 2>&1')
 t.get('system/thermal-sensors.txt','cat '+THERM)
 t.get('system/thermal-zones.txt','for z in /sys/class/thermal/thermal_zone*; do echo $z $(cat $z/type) $(cat $z/temp); done')
 t.get('system/cpu-online.txt','cd /sys/devices/system/cpu && echo online=$(cat online) possible=$(cat possible) present=$(cat present)')
 t.get('system/bootreason.txt','getprop | grep -iE "bootreason|bootmode|boot_mode"; cat /proc/cmdline; cat /sys/class/BOOT/BOOT/boot/boot_mode 2>&1')
 t.get('system/version.txt','uname -a; getprop ro.build.fingerprint; cat /proc/uptime')
 t.get('system/dmesg.txt','dmesg',120)
 t.get('system/logcat.txt','logcat -d',120)
 t.get('system/proc-stat.txt','cat /proc/stat | head -12')

# ---- charger mode (CHARGER_MODE.md): no adb there, so manual steps plus the stream capture ----
@section('charger-mode','manual KPOC steps; saves the ACM stream with capture-pocket-diagnostic.py')
def charger_mode(t):
 steps='''Charger mode has no adb. Do these by hand while the stream capture below runs:
 1. Power the phone off with USB in (or plug into the off phone) so it boots into charger mode.
 2. Keep the log: mt_charger_probe KPOC(1), boot_mode lines, init "processing action (charger)", "starting service 'charger'", charger type, CHG_EN, ICHG, AICR, gauge voltage and current, avc denials for scontext=u:r:charger:s0.
 3. The charger screen should show the animation. Pull USB at about 40 s, time it: the phone should go dark and stay off.
 4. Power on and note androidboot.bootreason (the system section saves it).
 5. Once more with USB left in: hold Power 10 s and note the next boot's bootreason.
 6. After the rc is in the build: unplug should shut down within 10 s, a 2 s Power hold should boot normal with ro.bootmode=normal.'''
 print(steps);t.save('charger-mode/manual-steps.txt',steps+'\n')
 cmd=[sys.executable,str(ROOT/'tools/capture-pocket-diagnostic.py'),'--usb-serial',t.a.stream_serial,'--output',str(t.out/'charger-mode'/'stream'),'--wait',str(t.a.stream_wait),'--seconds',str(t.a.stream_seconds)]
 if t.a.stream_kernel:cmd+=['--kernel-release',t.a.stream_kernel]
 t.prompt('Start the capture below, then follow the steps. It waits up to %d s for the gadget and runs %d s.'%(t.a.stream_wait,t.a.stream_seconds))
 if t.dry:print('[dry-run]',shlex.join(cmd));return
 (t.out/'charger-mode').mkdir(parents=True,exist_ok=True)
 r=subprocess.run(cmd);t.note('stream capture exit code %d'%r.returncode)

# ---- ADD NEW CHECKS BELOW THIS LINE ----
# One function per check, registered with @section('name','one-line description').
# Use t.get('dir/file.txt','shell command') to run on the phone and save the output, t.prompt('text') for a manual step,
# t.note('text') for a line in summary.txt. Sections run in the order they are defined, and --only name picks them.
#
# @section('example','what it checks')
# def example(t):
#  t.get('example/value.txt','cat /sys/class/leds/button-backlight/brightness')

def bg(t,cmd,path):
 """Start an adb command in the background with its output going to a file in the results folder; returns the process or None (dry-run)."""
 if t.dry:print('[dry-run] adb %s > %s'%(cmd,path));return None
 f=t.out/path;f.parent.mkdir(parents=True,exist_ok=True)
 return subprocess.Popen(t.wrap(t.adb+cmd.split(' ',1)[:1]+([cmd.split(' ',1)[1]] if ' ' in cmd else [])),stdin=subprocess.DEVNULL,stdout=f.open('w'),stderr=subprocess.STDOUT)
def stop(procs):
 for p in procs:
  if p:p.terminate();p.wait(10)
def count(t,name,cmd):
 """Save the output of cmd and return its first line as an int (or None)."""
 m=re.search(r'\d+',t.get(name,cmd));return int(m.group()) if m else None
def verdict(t,label,ok,detail):
 if t.dry:return
 t.note('%s: %s (%s)'%('PASS' if ok else 'FAIL',label,detail))

# ---- log spam (KERNEL_UPGRADE_STATUS.md, "What the trial should check") ----
@section('logspam','SpeechMessengerNormal, audio HAL load, log_buf_len, IVirtualHal, face and fingerprint features, HexToBytes and IRadio counts')
def logspam(t):
 n=count(t,'logspam/speechmessenger-count.txt','logcat -d | grep -c SpeechMessengerNormal')
 prop=t.get('logspam/speechmessenger-prop.txt','getprop log.tag.SpeechMessengerNormal').strip()
 verdict(t,'SpeechMessengerNormal lines in logcat is 0',n==0,'count %s'%n)
 verdict(t,'log.tag.SpeechMessengerNormal is S',prop=='S','got %r'%prop)
 svc=t.get('logspam/audio-hal-service.txt','getprop init.svc.vendor.audio-hal').strip()
 t.get('logspam/audio-hal-top.txt','top -b -n 1 | grep -i audio')
 verdict(t,'vendor.audio-hal running',svc=='running','got %r'%svc)
 t.prompt('Read logspam/audio-hal-top.txt: the audio HAL load should be low (a few percent, not a busy loop).')
 cmd=t.get('logspam/cmdline.txt','cat /proc/cmdline')
 verdict(t,'log_buf_len=4M in /proc/cmdline','log_buf_len=4M' in cmd,'')
 first=t.get('logspam/dmesg-first-line.txt','dmesg | head -1')
 m=re.search(r'\[\s*([\d.]+)\]',first)
 verdict(t,'dmesg starts near 0 s',bool(m) and float(m.group(1))<5,first.strip())
 n=count(t,'logspam/ivirtualhal-count.txt','dmesg | grep -c IVirtualHal')
 verdict(t,'IVirtualHal lines in dmesg is 0',n==0,'count %s'%n)
 feat=t.get('logspam/face-fingerprint-features.txt','pm list features | grep -E "face|fingerprint"').strip()
 verdict(t,'no face or fingerprint features',feat=='','got %r'%feat[:80])
 svcs=t.get('logspam/face-fingerprint-services.txt','dumpsys -l | grep -E "face|fingerprint"').strip()
 verdict(t,'no FaceService or FingerprintService',svcs=='','got %r'%svcs[:80])
 for tag in ('HexToBytes','IRadio'):
  n=count(t,'logspam/%s-count.txt'%tag.lower(),'dmesg | grep -c %s'%tag)
  t.note('%s lines in dmesg: %s (how much is left; no limit set)'%(tag,n))

# ---- battery temperature (CHARGER_PORT.md, "Battery temperature in place of the 41 C stand-in") ----
@section('battemp','battery temp against the charger limit, current steps at 15 to 40 C, temperature while charging at 2 A')
def battemp(t):
 temp=t.get('battemp/battery-temp.txt','cat /sys/class/power_supply/battery/temp').strip()
 verdict(t,'battery temp is a room value (250 to 350 in 0.1 C)',temp.lstrip('-').isdigit() and 250<=int(temp)<=350,'got %r'%temp)
 t.get('battemp/dmesg-charger.txt','dmesg | grep -iE "mtk_charger|setting:|AICR|temp|oz8806|mt6370"')
 t.prompt('Plug in a CDP or DCP charger (a wall charger) with the battery at 15 to 40 C, then press Enter.')
 text=poll_phase(t,'charging',t.a.poll_seconds,t.a.poll_every);t.save('battemp/poll-charging.txt',text)
 log=t.get('battemp/charger-limit-log.txt','dmesg | grep -iE "setting:|AICR|input_current|SwitchCharging|temp" | tail -60')
 m=re.findall(r'setting:\s*(\d+)',log)
 if m:verdict(t,'charger setting is 1500 or 2000, not 800',m[-1] in('1500','2000'),'last setting:%s'%m[-1])
 t.get('battemp/mt6370-dump.txt','dmesg | grep -E "AICR|ICHG|MIVR" | tail -30')
 t.prompt('Check battemp/mt6370-dump.txt: AICR = 1500mA or more, not 800. A PC port may sag to MIVR (AICL about 450 mA), see evidence/charger/battery-level-aicr.md.')
 t.prompt('Charge at 2 A and watch battery/temp (battemp/poll-charging.txt): it should stay under 41 C (410), or the limit should drop to 800 mA when it gets there.')
 t.get('battemp/temp-after.txt','cat /sys/class/power_supply/battery/temp; grep -E "temp" /sys/class/power_supply/battery/uevent')

# ---- keyboard light and shortcut keys (KEYBOARD_PORT.md, "Framework key hook") ----
LED='/sys/devices/platform/odm/odm:led@5/leds/button-backlight'
@section('keylight','ro.pocket.input_policy, button-backlight node and owner, light on key press, timeout, avc denials')
def keylight(t):
 pol=t.get('keylight/input-policy.txt','getprop ro.pocket.input_policy').strip()
 verdict(t,'ro.pocket.input_policy is true',pol=='true','got %r'%pol)
 t.get('keylight/logcat-pocketkeys.txt','logcat -d | grep -E "PocketKeys|PocketKeyHooks"')
 t.get('keylight/node.txt','ls -lZ %s/brightness /sys/class/leds/button-backlight/brightness 2>&1'%LED)
 t.get('keylight/avc.txt','logcat -d | grep -E "avc: denied" | grep -E "hal_light|system_server|pocket_pad_guard_prop|pocket_input_config_prop"; dmesg | grep -E "avc: denied" | grep -E "hal_light|system_server|pocket_pad_guard_prop|pocket_input_config_prop"')
 t.prompt('Check keylight/node.txt: owner system, label sysfs_leds. keylight/avc.txt should be empty.')
 t.prompt('Screen on and idle. Touch the screen only (no keys) and Enter. The keys must stay dark.')
 t.get('keylight/brightness-touch-only.txt','cat %s/brightness'%LED)
 t.prompt('Now press one key and press Enter within 1 s. The keys should have lit at once.')
 t.get('keylight/brightness-after-key.txt','cat %s/brightness'%LED)
 t.prompt('Optional: run tools/stock-light-probe.c style timing to compare with stock 0.45 to 0.54 s. Press a key and note when they light.')
 t.prompt('Press a key, then wait: the light should go off 3.5 s after the last key. Press Enter about 6 s after the last key.')
 t.get('keylight/brightness-after-timeout.txt','cat %s/brightness'%LED)
 t.prompt('In Pocket Keyboard change Light idle timeout and Keyboard lighting, then repeat the key press and wait; check the new timeout applies.')
 t.get('keylight/brightness-after-setting.txt','cat %s/brightness'%LED)
 t.prompt('Press a key, then turn the screen off with Power. The keys should go off at once.')
 t.get('keylight/brightness-screen-off.txt','cat %s/brightness'%LED)

@section('shortcutkeys','F13 and F14 codes, FUNC1 and FUNC2 short and long press, nothing reaches the app, letter keys blocked during a pad drag')
def shortcutkeys(t):
 t.get('shortcutkeys/getevent-keys.txt','getevent -lp | grep -E "KEY_F13|KEY_F14|aw9523|mtk-kpd|name"')
 t.prompt('Expected key codes: FUNC1 is F13 (183) and FUNC2 is F14 (250). Check them in getevent-keys.txt.')
 t.prompt('In Pocket Keyboard bind FUNC1 to Flashlight press and Camera long press (FUNC2 as you like). Focus a text app, then Enter.')
 procs=[bg(t,'shell logcat -v monotonic','shortcutkeys/logcat.txt'),bg(t,'shell getevent -lt','shortcutkeys/getevent.txt')]
 try:
  t.prompt('Tap FUNC1: the torch should toggle. Hold FUNC1 (500 ms or more): the camera should open. Nothing may be typed in the app.')
  t.prompt('Same for FUNC2 with its settings. Then Enter.')
  t.prompt('Letter-key guard: turn swipe Scroll on. In the launcher and in Settings (no editor), rest a finger on a letter during a swipe: no key may act. About 200 ms after a swipe, typing should work.')
  t.prompt('Note which letters were blocked, then Enter.')
 finally:stop(procs)
 t.get('shortcutkeys/pad-guard.txt','echo pad_scroll=$(getprop persist.sys.pocket.pad_scroll); echo pad_guard=$(getprop sys.pocket.pad_guard); getprop ro.pocket.input_policy')
 t.get('shortcutkeys/logcat-after.txt','logcat -d | grep -E "PocketKeys|PocketKeyHooks|avc: denied" | tail -100')

# ---- power-key wake timing (POWER_OFF.md, "Slow screen on and off with the power key") ----
@section('powerkey','getevent -lt, logcat -v monotonic, dmesg, top and kpd debugfs around one sleep and one wake; time from key to backlight on')
def powerkey(t):
 t.get('powerkey/input-devices.txt','getevent -pl | grep -B2 KEY_POWER')
 ev=t.sh("for d in /sys/class/input/event*; do grep -q mtk-kpd $d/device/name && echo ${d##*/}; done").strip().split()
 dev='/dev/input/'+(ev[0] if ev else 'eventN')
 if not ev and not t.dry:t.note('mtk-kpd event node not found; see powerkey/input-devices.txt, capturing every device')
 t.sh('echo 1 > /sys/kernel/debug/keypad/debug');t.sh('logcat -c; dmesg -C')
 procs=[bg(t,'shell getevent -lt'+(' '+dev if ev else ''),'powerkey/getevent.txt'),bg(t,'shell logcat -b all -v monotonic','powerkey/logcat.txt'),bg(t,'shell top -b -d 1 -n 20 -m 12','powerkey/top.txt')]
 try:
  t.prompt('Let the boot settle. Then press Power once to sleep, wait 5 s, press Power to wake, wait 5 s. Enter when done (top runs for 20 s).')
  t.sleep(max(0,20))
 finally:stop(procs)
 t.get('powerkey/dmesg.txt','dmesg')
 t.get('powerkey/dmesg-kpd.txt','dmesg | grep -E "kpd|Power Key|PWM|dsv|agold_gpio|gt1151|lcm"')
 t.get('powerkey/kpd-debug.txt','cat /sys/kernel/debug/keypad/debug 2>&1')
 if not t.dry:
  pat=r'Waking up|Going to sleep|interceptKey|PowerManagerService|DisplayPowerController|Blocking screen|Unblocked screen|SF.setDisplayPowerMode|Setting power mode|Finished setting power mode|SW_WDT|lights-service|KeyguardServiceDelegate|screen_toggled'
  lg=(t.out/'powerkey'/'logcat.txt');lg=lg.read_text(errors='replace') if lg.exists() else ''
  t.save('powerkey/logcat-grep.txt','\n'.join(l for l in lg.splitlines() if re.search(pat,l))+'\n')
  ge=(t.out/'powerkey'/'getevent.txt');ge=ge.read_text(errors='replace') if ge.exists() else ''
  keys=re.findall(r'\[\s*([\d.]+)\].*KEY_POWER\s+DOWN',ge)
  dm=t.out/'powerkey'/'dmesg.txt';dm=dm.read_text(errors='replace')
  bl=[float(x) for x in re.findall(r'\[\s*([\d.]+)\][^\n]*(?:backlight|PWM)',dm)]
  for k in keys:
   k=float(k);later=[b for b in bl if b>=k]
   t.note('power key down at %.3f s boot time; first backlight/PWM line after it: %s'%(k,'%.3f s (+%.3f)'%(later[0],later[0]-k) if later else 'none found'))
  if not keys:t.note('no KEY_POWER DOWN in powerkey/getevent.txt; time the press by hand from powerkey/')
 t.prompt('Read powerkey/logcat-grep.txt and dmesg-kpd.txt: on the monotonic clock the key IRQ, PowerManager, the display power calls and the backlight lines line up. Note the time from key to backlight on, for both wake and sleep.')
 t.sh('echo 0 > /sys/kernel/debug/keypad/debug')

def boot(t,name,kinds,pat):
 """Lines matching pat from the dmesg or logcat the system section saved plus a live read (powerkey clears the buffers, so boot lines live only in the saved file). Saved to name and returned."""
 seen=[];keep=set()
 for k in kinds:
  f=t.out/'system'/(k+'.txt');txt=f.read_text(errors='replace') if not t.dry and f.exists() else ''
  txt+='\n'+t.sh(k+(' -d' if k=='logcat' else ''),120)
  for l in txt.splitlines():
   if l not in keep and re.search(pat,l,re.I):keep.add(l);seen.append(l)
 out='\n'.join(seen)+'\n';t.save(name,out);return out
def needroot(t,label):
 if not back(t):raise Stop(label+': no adb root')

# ---- torch (FLASHLIGHT_PORT.md, "Trial checks") ----
TORCH='/sys/devices/virtual/leds/torch'
@section('torch','torch LED node, owner and label, pocket_torch settings, LED value following the setting, key and tile prompts, avc denials')
def torch(t):
 needroot(t,'torch')
 boot(t,'torch/dmesg-torch.txt',['dmesg'],r'pocket_torch|mt6370.*fled|set dual torch|flashlight')
 t.get('torch/node.txt','ls -lZ %s/ %s/brightness 2>&1; ls -ld %s; cat %s/max_brightness'%(TORCH,TORCH,TORCH,TORCH))
 ex=t.sh('[ -e %s/brightness ] && echo yes || echo no'%TORCH).strip()
 verdict(t,'%s/brightness exists'%TORCH,ex=='yes',ex)
 st=t.get('torch/brightness-owner.txt','stat -c "%U:%G %a" '+TORCH+'/brightness 2>&1').strip()
 verdict(t,'brightness is system:system 660 (init.pocket.torch.rc)',st=='system:system 660',st)
 lab=t.get('torch/brightness-label.txt','ls -Z %s/brightness 2>&1'%TORCH)
 verdict(t,'brightness label is sysfs_pocket_torch','sysfs_pocket_torch' in lab,lab.strip()[:80])
 av=t.get('torch/props.txt','echo available=$(settings get global pocket_torch_available); echo torch=$(settings get global pocket_torch)')
 verdict(t,'pocket_torch_available is 1',re.search(r'available=1\b',av) is not None,av.replace('\n',' '))
 verdict(t,'pocket_torch is 0 after boot',re.search(r'torch=0\b',av) is not None,av.replace('\n',' '))
 try:
  for v in (1,0):
   t.sh('settings put global pocket_torch %d'%v);t.sleep(1)
   b=t.get('torch/brightness-setting-%d.txt'%v,'cat %s/brightness'%TORCH).strip()
   verdict(t,'LED brightness follows pocket_torch %d'%v,b==str(v),'got %r'%b)
   if v:t.prompt('The torch should be lit now (setting 1). Look at the back, then Enter.')
  t.prompt('Press the FUNC key bound to Flashlight (or hold Power for the Lineage long press torch, or use the quick settings tile). The torch should toggle, and the tile should follow. Press it again to turn it off, then Enter.')
  t.get('torch/after-keys.txt','echo torch=$(settings get global pocket_torch) led=$(cat %s/brightness)'%TORCH)
  t.prompt('Optional: torch on, screen off for a minute (it should stay on). Turn it off after.')
 finally:t.sh('settings put global pocket_torch 0; echo 0 > %s/brightness'%TORCH)
 boot(t,'torch/dmesg-after.txt',['dmesg'],r'pocket_torch|set dual torch|mt6370.*fled')
 boot(t,'torch/avc.txt',['logcat','dmesg'],r'avc: denied.*torch')

# ---- vibrator (VIBRATOR_PORT.md, "Trial checks") ----
VIB='/sys/class/leds/vibrator'
VREG='for r in /sys/class/regulator/regulator.*; do [ "$(cat $r/name)" = vibr ] && echo $(cat $r/microvolts) $(cat $r/state); done'
@section('vibrator','probe line, led node and labels, regulator state, raw and HAL buzzes (short, long, 15 s cap), OC interrupt count, no over-current in dmesg')
def vibrator(t):
 needroot(t,'vibrator')
 pr=boot(t,'vibrator/dmesg-probe.txt',['dmesg'],r'vibr|mtk_vibrator')
 verdict(t,'probe line has 3000000 uV, vosel 0xb, timer 25 ms, limit 9 ms, oc irq N','3000000 uV' in pr and '0xb' in pr and 'timer 25' in pr and 'limit 9' in pr and re.search(r'oc irq [1-9]',pr) is not None,'see vibrator/dmesg-probe.txt')
 verdict(t,'no "VIBR was on at probe"','VIBR was on at probe' not in pr,'')
 t.get('vibrator/node.txt','ls -lZ %s/ 2>&1; readlink -f %s'%(VIB,VIB))
 rg=t.get('vibrator/regulator-before.txt',VREG).strip()
 verdict(t,'regulator vibr is 3000000 and disabled',rg=='3000000 disabled',rg)
 t.sh('echo 300 > %s/duration; echo 1 > %s/activate'%(VIB,VIB))
 a=t.get('vibrator/activate-during.txt','cat %s/activate'%VIB).strip()
 verdict(t,'activate reads 1 during a 300 ms buzz',a=='1','got %r'%a)
 t.prompt('A 300 ms buzz just ran from sysfs. Did you feel it? Note yes or no, then Enter.')
 t.sleep(1)
 a=t.get('vibrator/activate-after.txt','cat %s/activate'%VIB).strip()
 verdict(t,'activate reads 0 after 1 s',a=='0','got %r'%a)
 rg=t.get('vibrator/regulator-after-raw.txt',VREG).strip()
 verdict(t,'regulator disabled after the buzz',rg.endswith('disabled'),rg)
 t.sh('echo 15 > %s/duration; echo 1 > %s/activate'%(VIB,VIB))
 t.prompt('Short request: duration 15 ms (stretched to 25 ms). Did you feel a tick? Enter.')
 t.sh('echo 20000 > %s/duration; echo 1 > %s/activate'%(VIB,VIB));t.sleep(2)
 t.sh('echo 0 > %s/activate'%VIB);t.sleep(.5)
 a=t.get('vibrator/activate-stopped.txt','cat %s/activate'%VIB).strip()
 verdict(t,'echo 0 > activate stops a long buzz at once',a=='0','got %r'%a)
 t.prompt('The 20 s request was stopped after 2 s. Did the buzz stop at once? Enter.')
 t.sh('echo 20000 > %s/duration; echo 1 > %s/activate'%(VIB,VIB))
 t.prompt('A 20 s request is running. It should stop by itself at 15 s. Time it, then Enter after it stops.')
 a=t.get('vibrator/activate-after-cap.txt','cat %s/activate'%VIB).strip()
 verdict(t,'long request stopped by itself (activate 0)',a=='0','got %r'%a)
 t.sh('cmd vibrator_manager synced -f oneshot 500');t.sleep(1)
 t.get('vibrator/dumpsys-vibrator.txt','dumpsys vibrator_manager | head -60')
 t.get('vibrator/logcat-hal.txt','logcat -d | grep -i vibrator | tail -80')
 t.prompt('HAL path: a 500 ms buzz via cmd vibrator_manager just ran. Did you feel it? Enter.')
 t.sh('cmd vibrator_manager synced -f oneshot 3000');t.sleep(1)
 a=t.get('vibrator/activate-hal-long.txt','cat %s/activate'%VIB).strip()
 t.note('vibrator: activate while a 3 s HAL oneshot runs: %r (observed, no limit set)'%a)
 t.prompt('A 3 s buzz is running. Did it last about 3 s? Enter.');t.sleep(2)
 t.get('vibrator/regulator-final.txt',VREG)
 t.get('vibrator/oc-interrupt.txt','grep vibr_oc /proc/interrupts')
 oc=boot(t,'vibrator/dmesg-after.txt',['dmesg'],r'vibr|over-?current')
 verdict(t,'no over-current line in dmesg',re.search(r'over-?current',oc,re.I) is None,'see vibrator/dmesg-after.txt')
 t.prompt('Optional: key presses in LatinIME with vibrate on, a long press on the home screen. Do they buzz? The 10 s buzz then "adb shell reboot -p" check is left for a manual run.')

# ---- MTP and PTP over FunctionFS (USB_GADGET.md, "Trial checks") ----
GADGET='/config/usb_gadget/g1'
def usbstate(t,label):
 """Save the sys.usb props, gadget functions, UDC and the mtp/ptp ffs nodes."""
 return t.get('mtp/state-%s.txt'%label,'getprop | grep -E "sys\\.usb\\.|init\\.svc\\.adbd|persist\\.sys\\.usb"; echo UDC=$(cat %s/UDC); echo config=$(cat %s/configs/b.1/strings/0x409/configuration); ls -l %s/configs/b.1 %s/functions; ls -l /dev/usb-ffs/mtp /dev/usb-ffs/ptp 2>&1'%(GADGET,GADGET,GADGET,GADGET))
def back(t,secs=30):
 """Wait for adb after a USB switch, then check root. If it does not come back, ask the person to replug, up to 3 times. Returns True when adb answers as root."""
 if t.dry:print('[dry-run] adb wait-for-device');return True
 for n in range(4):
  try:
   t.run(t.adb+['wait-for-device'],secs)
   if t.sh('id -u',10).strip()!='0':t.run(t.adb+['root'],30);t.run(t.adb+['wait-for-device'],secs)
   if t.sh('id -u',10).strip()=='0':return True
  except subprocess.TimeoutExpired:pass
  if n<3:t.prompt('adb did not come back. Unplug and replug the USB cable, wait a few seconds, then Enter (try %d of 3).'%(n+1))
 return False
def usbswitch(t,fn,label):
 """Run svc usb setFunctions fn (adb may drop at once, so the call is fire and forget), wait for adb, save the state."""
 try:t.sh('svc usb setFunctions %s'%fn,15)
 except subprocess.TimeoutExpired:t.note('mtp: svc usb setFunctions %s timed out (adb dropped?)'%fn)
 t.sleep(3);ok=back(t);verdict(t,'adb answers as root after switching to %s'%label,ok,'')
 if ok:usbstate(t,label)
 return ok
@section('mtp','USB to mtp then ptp then adb through svc usb setFunctions; sys.usb props, gadget functions and UDC saved each time; always ends with adb only')
def mtp(t):
 needroot(t,'mtp')
 usbstate(t,'0-start')
 t.get('mtp/lsusb-note.txt',"echo 'host side: run lsusb on the PC; expect 0e8d:201c (adb), 0e8d:201d (mtp,adb)'")
 try:
  for fn in ('mtp','ptp'):
   ok=usbswitch(t,fn,'1-'+fn)
   if not ok:t.note('mtp: adb lost after switching to %s; ffs.%s may not have come up'%(fn,fn));break
   t.get('mtp/logcat-%s.txt'%fn,'logcat -d | grep -iE "UsbDeviceManager|MtpServer|could not open control|usb-ffs" | tail -60')
   t.get('mtp/dmesg-%s.txt'%fn,'dmesg | grep -iE "gadget|configfs|functionfs|ffs|mtu3|udc" | tail -40')
   verdict(t,'UDC is 11201000.usb3 in %s'%fn,'UDC=11201000.usb3' in t.get('mtp/udc-%s.txt'%fn,'echo UDC=$(cat %s/UDC)'%GADGET),'')
   t.prompt('Host side with %s: lsusb should show the %s,adb id (mtp: 0e8d:201d); mtp-detect, gphoto2 --auto-detect or gio mount -l should see the phone. adb should still list it (it may drop for about a second). Note what you saw, then Enter.'%(fn,fn))
 finally:
  # Always back to adb only. The wait is in back(); a replug prompt is the fallback.
  t.note('mtp: restoring adb only')
  try:t.sh('svc usb setFunctions',15)
  except subprocess.TimeoutExpired:pass
  t.sleep(3)
  ok=back(t)
  verdict(t,'adb answers as root after the restore',ok,'')
  if not ok:t.note('mtp: adb did not come back; set USB to adb by hand');raise Stop('mtp: adb lost')
  s=usbstate(t,'9-restored');verdict(t,'config is adb after restore',re.search(r'sys\.usb\.config\]: \[adb\]',s) is not None,'see mtp/state-9-restored.txt')
  t.get('mtp/adb-alive.txt','id -u; getprop sys.usb.state')

# ---- suspend (SUSPEND_PORT.md, s2idle only; keep last) ----
SPW='/sys/power'
@section('suspend','s2idle: mem_sleep, wakeup_sources and suspend_stats before and after, pm_test steps, screen off with USB unplugged and wake with Power, dmesg PM lines (run last)')
def suspend(t):
 needroot(t,'suspend')
 boot(t,'suspend/boot-dmesg.txt',['dmesg'],r'psci: SYSTEM_SUSPEND|PM: |Watchdog|Adopted boot watchdog')
 for n in ('state','mem_sleep'):t.get('suspend/%s.txt'%n,'cat %s/%s'%(SPW,n))
 ms=t.get('suspend/mem_sleep-check.txt','cat %s/mem_sleep'%SPW).strip()
 verdict(t,'mem_sleep is [s2idle] only',ms=='[s2idle]',ms)
 snap='cat %s/suspend_stats/success %s/suspend_stats/fail; cat /sys/kernel/debug/suspend_stats 2>&1; cat /sys/kernel/debug/wakeup_sources | sort -k6 -n -r | head -20; cat /proc/sys/kernel/random/boot_id'%(SPW,SPW)
 before=t.get('suspend/before.txt',snap)
 t.sh('echo 1 > %s/pm_print_times; echo 1 > %s/pm_debug_messages'%(SPW,SPW))
 try:
  # pm_test steps return by themselves after about 5 s
  for step in ('freezer','devices'):
   o=t.get('suspend/pm-test-%s.txt'%step,'echo %s > %s/pm_test; echo rc_pm_test=$?; echo mem > %s/state; echo rc_state=$?'%(step,SPW,SPW),40)
   t.note('suspend: pm_test %s: %s'%(step,' '.join(o.split())))
   if step=='devices':back(t,30)
  t.sh('echo none > %s/pm_test'%SPW)
  pm=t.get('suspend/pm_test-after.txt','cat %s/pm_test'%SPW)
  verdict(t,'pm_test reads back [none]','[none]' in pm,pm.strip())
  if not t.dry and '[none]' not in pm:raise Stop('suspend: pm_test not none, no real suspend')
  t.get('suspend/dmesg-pm-test.txt',"dmesg | grep -E 'PM: |suspend|resume|failed to suspend|returns -|Transfer while suspended' | tail -60")
  t.prompt('Real suspend, USB out. Now: unplug the USB cable, turn the screen off with Power, wait 120 s (over 3 watchdog timeouts), press Power to wake, plug USB back in, then Enter. adb drops while suspended.')
  if not back(t,60):t.note('suspend: adb did not come back after the wake; check the phone by hand')
  else:
   after=t.get('suspend/after.txt',snap)
   b1=re.findall(r'^[0-9a-f-]{36}$',before,re.M);b2=re.findall(r'^[0-9a-f-]{36}$',after,re.M)
   if b1 and b2:verdict(t,'boot_id is the same (no restart)',b1[-1]==b2[-1],'%s / %s'%(b1[-1],b2[-1]))
   t.get('suspend/uptime-and-wakeup-irq.txt','cat /proc/uptime; cat %s/pm_wakeup_irq 2>&1; cat %s/wakeup_count'%(SPW,SPW))
   t.get('suspend/dmesg-pm.txt',"dmesg | grep -E 'PM: (suspend|resume)|s2idle|Freezing|Restarting|wakeup|Transfer while suspended' | tail -60")
   t.get('suspend/thermal-sensors.txt','cat '+THERM)
   t.get('suspend/interrupts.txt','cat /proc/interrupts')
   t.get('suspend/dumpsys-suspend.txt','dumpsys suspend_control_internal 2>&1 | head -60')
   t.prompt('Read suspend/dmesg-pm.txt and after.txt: success should have risen, boot_id should match, thermal sensors should still read. Note the wake IRQ from uptime-and-wakeup-irq.txt against interrupts.txt.')
 finally:
  t.sh('echo none > %s/pm_test'%SPW)
  t.sh('echo 0 > %s/pm_print_times; echo 0 > %s/pm_debug_messages'%(SPW,SPW))

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--only',help='comma separated sections to run; default all (see --list)')
 p.add_argument('--list',action='store_true',help='list the sections and exit')
 p.add_argument('--dry-run',action='store_true',help='no device: print the commands and run the cpufreq logic on canned readings')
 p.add_argument('--output',type=Path,default=Path('trial-v13'),help='parent folder; a timestamped folder is made inside')
 p.add_argument('--serial',help='adb serial when more than one device is attached')
 p.add_argument('--ssh',help='run adb on this host over ssh (name not stored in the repo)')
 p.add_argument('--yes',action='store_true',help='do not wait at prompts (for unattended parts only)')
 p.add_argument('--poll-seconds',type=int,default=60,help='charger: seconds polled in each plug state');p.add_argument('--poll-every',type=int,default=5)
 p.add_argument('--stream-serial',default='TP510-FIRSTBOOT-V2',help='charger-mode: USB serial of the log gadget');p.add_argument('--stream-kernel',help='charger-mode: expected kernel release')
 p.add_argument('--stream-wait',type=float,default=120);p.add_argument('--stream-seconds',type=float,default=240)
 a=p.parse_args()
 if a.list:
  for n,(_,d) in SECTIONS.items():print('%-12s %s'%(n,d))
  return
 names=[x for x in (a.only.split(',') if a.only else SECTIONS) if x]
 bad=[n for n in names if n not in SECTIONS]
 if bad:p.error('Unknown section(s) '+', '.join(bad)+'; --list shows them')
 names=[n for n in SECTIONS if n in names]
 out=a.output/('trial-v13-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
 t=Trial(a,out)
 if not a.dry_run:out.mkdir(parents=True,exist_ok=False)
 else:print('[dry-run] results would go to',out)
 if not a.dry_run:
  t.run(t.adb+['wait-for-device'],120);t.run(t.adb+['root'],30);t.run(t.adb+['wait-for-device'],120)
  who=t.sh('id -u').strip()
  if who!='0':raise SystemExit('adb root did not give root (id -u = %r)'%who)
 else:print('[dry-run] adb root')
 results={};failed=False
 for n in names:
  print('\n=== %s: %s'%(n,SECTIONS[n][1]),flush=True)
  try:SECTIONS[n][0](t);results[n]='done'
  except Stop:results[n]='stopped on mismatch';failed=True;break   # later sections wait until the mismatch is understood
  except KeyboardInterrupt:results[n]='interrupted';failed=True;restore(t);break
  except Exception as e:results[n]='error: %r'%e;failed=True;print('Section failed:',repr(e))
 summary={'utc':datetime.now(timezone.utc).isoformat(),'sections':results,'notes':t.log,'dry_run':a.dry_run}
 if not a.dry_run:(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');(out/'summary.txt').write_text('\n'.join('%s: %s'%kv for kv in results.items())+'\n\n'+'\n'.join(t.log)+'\n')
 print('\n'+json.dumps(summary,indent=2))
 if not a.dry_run:print('Results in',out)
 if failed:raise SystemExit(1)
if __name__=='__main__':main()
