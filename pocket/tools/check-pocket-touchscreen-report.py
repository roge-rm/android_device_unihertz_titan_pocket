#!/usr/bin/env python3
"""Host test of the touchscreen report decoder (drivers/input/touchscreen/pocket-gt1151-report.h).

Builds the header into a small C program and feeds it GT1151QM coordinate
packets. Each expected event stream is written out by hand from the stock
gt1151qm_touch_event_handler, touch_down and touch_up (evidence/rea-blockers/
input-drivers/pseudo/). There is no stock touchscreen capture to replay.
No device access.
"""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
HEADER=SOURCE/'drivers/input/touchscreen/pocket-gt1151-report.h'
CODES=SOURCE/'include/uapi/linux/input-event-codes.h'

HARNESS=r'''
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned short u16;
#include "input-event-codes.h"
#include "pocket-gt1151-report.h"
/* The input core drops key events that don't change the key's state. */
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
	struct pocket_gt_sink s = { out, 0 };
	struct pocket_gt_state st = { 0, 0 };
	u8 p[POCKET_GT_PACKET_MAX];
	unsigned int n, b, i;
	while (scanf("%u", &n) == 1) {
		for (i = 0; i < POCKET_GT_PACKET_LEN(n); i++) { scanf("%x", &b); p[i] = b; }
		if (pocket_gt_checksum(p, POCKET_GT_PACKET_LEN(n))) { printf("checksum\n"); continue; }
		pocket_gt_report(&s, p, n, &st);
		printf("-- %04x %04x\n", st.pre_event, st.pre_index);
	}
	return 0;
}
'''

def packet(status,fingers=(),key=0,bad=False):
 """Status byte, fingers as (id, x, y, w), key byte, checksum making the sum 0."""
 b=[status|len(fingers)]
 for i,x,y,w in fingers:b+=[i,x&0xff,x>>8,y&0xff,y>>8,w&0xff,w>>8,0]
 b+=[key];b.append((-sum(b)+(1 if bad else 0))&0xff)
 return '%d %s'%(len(fingers),' '.join('%x'%v for v in b))

def ev(t,c,v):return '%04x %04x %08x'%(t,c,v&0xffffffff)
EV_SYN,EV_KEY,EV_ABS=0,1,3
BTN_TOUCH,MAJOR,TRACK,X,Y=0x14a,0x30,0x39,0x35,0x36
MT_SYNC,SYN=ev(EV_SYN,2,0),ev(EV_SYN,0,0)
def down(x,y,w,i,touch=True):
 e=[ev(EV_KEY,BTN_TOUCH,1)] if touch else []
 e+=[ev(EV_ABS,MAJOR,100)] if not w and not i else [ev(EV_ABS,MAJOR,w),ev(EV_ABS,TRACK,i)]
 return e+[ev(EV_ABS,X,x),ev(EV_ABS,Y,y),MT_SYNC]
UP=[ev(EV_KEY,BTN_TOUCH,0),MT_SYNC]

def run(binary,packets):
 return subprocess.run([str(binary)],input='\n'.join(packets)+'\n',capture_output=True,text=True,check=True).stdout.split('\n')[:-1]

def main():
 with tempfile.TemporaryDirectory(prefix='pocket-tpd-test-') as tmp:
  tmp=Path(tmp);(tmp/'t.c').write_text(HARNESS)
  (tmp/'input-event-codes.h').write_text(CODES.read_text());(tmp/'pocket-gt1151-report.h').write_text(HEADER.read_text())
  subprocess.run(['gcc','-Wall','-Werror','-O1','-o',str(tmp/'t'),str(tmp/'t.c')],check=True)
  t=tmp/'t'

  # One finger, a move, then the lift. BTN_TOUCH 1 goes once, x and y raw, little-endian.
  got=run(t,[packet(0x80,[(0,0x2d0,0x168,20)]),packet(0x80,[(0,301,302,21)]),packet(0x80)])
  want=down(0x2d0,0x168,20,0)+[SYN,'-- 0001 0001']+down(301,302,21,0,False)+[SYN,'-- 0001 0001']+UP+[SYN,'-- 0000 0000']
  assert got==want,got
  print('one finger: down, move and lift in stock order, coordinates raw')

  # Two fingers, ids 1 and 4, then 4 alone: reported by id, tracking id is the slot number.
  got=run(t,[packet(0x80,[(1,10,20,5),(4,30,40,6)]),packet(0x80,[(4,31,41,6)]),packet(0x80)])
  want=down(10,20,5,1)+down(30,40,6,4,False)+[SYN,'-- 0001 0012']+down(31,41,6,4,False)+[SYN,'-- 0001 0010']+UP+[SYN,'-- 0000 0000']
  assert got==want,got
  print('two fingers: per-id downs, one sync per frame, lift once all are up')

  # Finger id 0 with size 0 looks like a key to stock: TOUCH_MAJOR 100, no TRACKING_ID.
  got=run(t,[packet(0x80,[(0,5,6,0)]),packet(0x80)])
  assert got==down(5,6,0,0)+[SYN,'-- 0001 0001']+UP+[SYN,'-- 0000 0000'],got
  print('size 0 on id 0: sent as stock sends a key, MAJOR 100 and no tracking id')

  # Chip keys come out as touches at y=765, x 60/300/180/420, and only with no finger down.
  for key,x in [(1,60),(2,300),(4,180),(8,420)]:
   got=run(t,[packet(0x90,key=key),packet(0x80)])
   assert got==down(x,765,0,0)+[SYN,'-- 0002 0000']+UP+[SYN,'-- 0000 0000'],(key,got)
  got=run(t,[packet(0x90,[(2,7,8,9)],key=1)])
  assert got==down(7,8,9,2)+[SYN,'-- 0001 0004'],got
  print('keys: reported as touches at the stock points, ignored while a finger is down')

  # Stylus key bits: stock would sync a pen device; with none there are no events.
  got=run(t,[packet(0x90,key=0x10),packet(0x80)])
  assert got==['-- 0008 0000','-- 0000 0000'],got
  # A frame with nothing new and nothing before sends nothing (stock "Additional Int Pulse").
  got=run(t,[packet(0x80)])
  assert got==['-- 0000 0000'],got
  # A bad checksum is caught before reporting.
  assert run(t,[packet(0x80,[(0,1,2,3)],bad=True)])==['checksum']
  print('stylus keys, empty frames and bad checksums send no events')

if __name__=='__main__':main()
