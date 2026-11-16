#!/usr/bin/env python3
"""Host test of the touchpad report decoder (drivers/input/misc/pocket-touchpad-report.h).

Builds the header into a small C program and checks:
- F12: packets rebuilt from the stock getevent capture of mtk-pad give back the
  same event stream, event for event (needs the private stock-input evidence;
  skipped with a note if it's missing).
- F11: fixed packets give the bit layout and event order of the stock driver.
No device access.
"""
import os,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
HEADER=SOURCE/'drivers/input/misc/pocket-touchpad-report.h'
CODES=SOURCE/'include/uapi/linux/input-event-codes.h'
CAPTURE=ROOT/'evidence/stock-input/20261029T021206.791961Z-pad/events.txt'

HARNESS=r'''
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned short u16;
#include "input-event-codes.h"
#include "pocket-touchpad-report.h"
/* The input core drops key events that don't change the key's state, as getevent shows. */
static int keys[KEY_CNT];
static void out(void *ctx, unsigned int t, unsigned int c, int v)
{
	if (t == EV_KEY) {
		if (keys[c] == !!v) return;
		keys[c] = !!v;
	}
	printf("%04x %04x %08x\n", t, c, (unsigned int)v);
}
int main(void)
{
	struct pocket_pad_sink s = { out, 0 };
	u8 present = 0, p[16];
	char kind[8];
	while (scanf("%7s", kind) == 1) {
		int n = !strcmp(kind, "f12") ? 7 : 5, i;
		unsigned int b;
		for (i = 0; i < n; i++) { scanf("%x", &b); p[i] = b; }
		if (!strcmp(kind, "f12")) {
			/* data15 bit 0 mirrors object 0; stock then takes the max with present */
			unsigned int count = (p[0] & 1) ? 1 : 0;
			if (count < present) count = present;
			if (!count) pocket_pad_report_none(&s);
			else pocket_pad_report_f12(&s, p, count, &present);
		} else if (!strcmp(kind, "f11")) {
			pocket_pad_report_f11_finger(&s, p);
			pocket_pad_report_f11_end(&s, 1);
		} else {
			pocket_pad_report_f11_end(&s, 0);
		}
	}
	return 0;
}
'''

def run(binary,stdin):return subprocess.run([str(binary)],input=stdin,capture_output=True,text=True,check=True).stdout.split('\n')[:-1]

def frames(lines):
 cur=[]
 for l in lines:
  cur.append(l)
  if l=='0000 0000 00000000':yield cur;cur=[]

def main():
 with tempfile.TemporaryDirectory(prefix='pocket-pad-test-') as tmp:
  tmp=Path(tmp);(tmp/'t.c').write_text(HARNESS)
  (tmp/'input-event-codes.h').write_text(CODES.read_text());(tmp/'pocket-touchpad-report.h').write_text(HEADER.read_text())
  subprocess.run(['gcc','-Wall','-Werror','-O1','-o',str(tmp/'t'),str(tmp/'t.c')],check=True)
  t=tmp/'t'

  # F11: x = hi << 4 | lo nibble, y = hi << 4 | high nibble, wx/wy nibbles of byte 3.
  got=run(t,'f11 2d 16 9a 74 30\nf11end 0 0 0 0 0\n')
  want=['0001 0145 00000001','0003 0035 000002da','0003 0036 00000169','0003 0030 00000007','0003 0031 00000004',
        '0000 0002 00000000','0000 0000 00000000','0001 0145 00000000','0000 0002 00000000','0000 0000 00000000']
  # Stock F11 never sends BTN_TOUCH 1, so the input core drops its BTN_TOUCH 0.
  assert got==want,got
  print('F11: bit layout and event order match the stock driver')

  # F12 with wy > wx: MAJOR is max(wx, wy), MINOR min(wx, wy) (stock f12_abs_report).
  got=run(t,'f12 1 d0 02 68 01 03 09\n')
  want=['0003 0039 00000000','0001 014a 00000001','0001 0145 00000001','0003 0035 000002d0','0003 0036 00000168',
        '0003 0030 00000009','0003 0031 00000003','0000 0002 00000000','0000 0000 00000000']
  assert got==want,got
  print('F12: wx and wy go to MAJOR and MINOR by size, x and y little-endian')

  if not CAPTURE.exists():
   print(f'F12: {CAPTURE.relative_to(ROOT)} not here (private evidence); skipped');return
  ref=[' '.join(l.split()[-3:]) for l in CAPTURE.read_text().splitlines() if l.startswith('[')]
  packets=[]
  for f in frames(ref):
   v={l.split()[1]:int(l.split()[2],16) for l in f if l.startswith('0003')}
   if '0035' in v:
    x,y,wx,wy=v['0035'],v['0036'],v['0030'],v['0031']
    packets.append('f12 1 %x %x %x %x %x %x'%(x&0xff,x>>8,y&0xff,y>>8,wx,wy))
   else:packets.append('f12 0 0 0 0 0 0 0')
  got=run(t,'\n'.join(packets)+'\n')
  assert got==ref,next((i,a,b) for i,(a,b) in enumerate(zip(got,ref)) if a!=b) if len(got)==len(ref) else (len(got),len(ref))
  print(f'F12: {len(packets)} frames rebuilt from the stock capture give back all {len(ref)} events exactly')

if __name__=='__main__':main()
