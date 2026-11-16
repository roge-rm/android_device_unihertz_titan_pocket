#!/usr/bin/env python3
"""Execute the actual EXTBUF7 transaction with regmap/error/timing mocks."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'tools/kernel-source/upgrade-5.10/drivers/clk/mediatek/clk-mt6358-ufs.h'
SOURCE=r'''
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
struct regmap { unsigned int value, address, data; int read_error, write_error, reads, writes, delays; };
static struct regmap *active;
static int regmap_read(struct regmap *m, unsigned int reg, unsigned int *v) {
 assert(reg==0x7a2); m->reads++; *v=m->value; return m->read_error;
}
static int regmap_write(struct regmap *m, unsigned int reg, unsigned int v) {
 m->writes++; m->address=reg; m->data=v;
 if(m->write_error) return m->write_error;
 if(reg==0x7a4) m->value|=v; else { assert(reg==0x7a6); m->value&=~v; } return 0;
}
static void usleep_range(unsigned int lo,unsigned int hi) { assert(lo==400 && hi>=lo); active->delays++; }
#include "clk-mt6358-ufs.h"
int main(void) {
 unsigned int count=0;
 for(unsigned int original=0;original<65536;original++) for(int on=0;on<2;on++) {
  struct regmap m={.value=original}; active=&m;
  int result=mt6358_ufs_set(&m,on); count++;
  assert(m.reads==1);
  if(original & (3U<<11)) { assert(result==-EOPNOTSUPP); assert(!m.writes && !m.delays); assert(m.value==original); }
  else { assert(!result && m.writes==1); assert(m.data==(1U<<13)); assert(m.address==(on?0x7a4:0x7a6)); assert(m.delays==on); assert(m.value==(on?(original|(1U<<13)):(original&~(1U<<13)))); }
 }
 int errors[]={-EIO,-ETIMEDOUT,-EAGAIN};
 for(unsigned int e=0;e<3;e++) for(int on=0;on<2;on++) for(int stage=0;stage<2;stage++) {
  struct regmap m={.value=0x4001,.read_error=stage?0:errors[e],.write_error=stage?errors[e]:0}; active=&m;
  assert(mt6358_ufs_set(&m,on)==errors[e]); assert(m.value==0x4001 && !m.delays); assert(m.writes==stage); count++;
 }
 printf("%u register/mode/error cases passed\n",count); return 0;
}
'''
def main():
 with tempfile.TemporaryDirectory(prefix='ufs-clock-') as temp:
  p=Path(temp); (p/'test.c').write_text(SOURCE)
  subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(HEADER.parent),str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'cases':131084,'result':result.stdout.strip(),'sanitizers':['address','undefined'],'actual_header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),'phone_accessed':False,'limitations':['Mocked bus/timing only','No CCF lifetime/concurrency or hardware settling qualification','Provider not wired into host or MFD']}
 (ROOT/'evidence/kernel-upgrade/ufs-clock-backend-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()
